"""Terminal output with Rich. Everything that shows collected data goes through the PrivacyGuard.

Remote text (error messages, profile bios, DNS records, page titles, step ids from a third-party
workflow) is never interpreted: it is either wrapped in a ``rich.text.Text`` (no markup parsing) or
passed through ``rich_safe`` (markup escaped), and always stripped of terminal control sequences.
"""

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, Optional, Tuple

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from secure_osint.core.privacy import PrivacyGuard
from secure_osint.core.workflow import StepResult, StepStatus
from secure_osint.utils.terminal import rich_safe, safe_text

if TYPE_CHECKING:
    from secure_osint.utils.cache import CacheEntry

STATUS_STYLES: Dict[StepStatus, str] = {
    StepStatus.SUCCESS: 'green',
    StepStatus.DEGRADED: 'yellow',
    StepStatus.ERROR: 'red',
    StepStatus.UNAVAILABLE: 'magenta',
    StepStatus.SKIPPED: 'dim',
}

# Username verdicts, in display order: what was found first, what still needs attention next.
_FOUND, _FAILED, _MANUAL, _NOT_FOUND = 'FOUND', 'check failed', 'manual check', 'not found'
_VERDICT_ORDER = {_FOUND: 0, _FAILED: 1, _MANUAL: 2, _NOT_FOUND: 3}
_VERDICT_STYLES = {_FOUND: 'bold green', _FAILED: 'red', _MANUAL: 'yellow', _NOT_FOUND: 'dim'}
_CALIBRATION_STYLES = {'passed': 'green', 'soft404': 'yellow', 'control_error': 'red', 'not_applicable': 'dim'}
_STATS_KEYS = ('automated', 'checked', 'found', 'failed')
_PARTIAL_TITLE = 'PARTIAL RESULTS: some checks did not complete'


def _plain(value: Any, guard: Optional[PrivacyGuard] = None, style: str = '') -> Text:
    """A table cell that renders ``value`` literally: redacted (with a guard), no markup, no controls."""
    text = '' if value is None else str(value)
    if guard is not None:
        text = guard.redact(text)
    return Text(safe_text(text, single_line=True), style=style)


def results_table(
    results: Mapping[str, StepResult], title: Optional[str] = None, guard: Optional[PrivacyGuard] = None
) -> Table:
    """One row per step. Error text comes from external sources: it is redacted (with a guard) and inert."""
    table = Table(title=rich_safe(title, single_line=True) if title else None, header_style='bold')
    table.add_column('Step')
    table.add_column('Status')
    table.add_column('Time', justify='right')
    table.add_column('Tries', justify='right')
    table.add_column('Detail', overflow='fold')
    for step_id, result in results.items():
        detail = 'cached' if result.cached else (result.error_message or '')
        table.add_row(
            _plain(step_id),
            f'[{STATUS_STYLES[result.status]}]{result.status.value}[/]',  # trusted enum value
            f'{result.execution_time:.1f}s',
            str(result.attempts),
            _plain(detail, guard),
        )
    return table


def data_panels(results: Mapping[str, StepResult], guard: PrivacyGuard) -> RenderableType:
    """One panel per step with data: highlighted, already redacted JSON.

    ``json.dumps`` escapes every control character (``ensure_ascii``), so values cannot reach the terminal raw.
    """
    panels = []
    for step_id, result in results.items():
        if not result.data:
            continue
        body = json.dumps(guard.redact_value(result.data), indent=2, default=str)
        panels.append(
            Panel(
                Syntax(body, 'json', theme='ansi_dark', background_color='default'),
                title=_plain(step_id),
                title_align='left',
                border_style=STATUS_STYLES[result.status],
            )
        )
    return Group(*panels)


def platform_verdict(entry: Mapping[str, Any]) -> str:
    """``FOUND``, ``check failed``, ``manual check`` or ``not found`` for one username platform entry."""
    exists = entry.get('exists')
    if exists is True:
        return _FOUND
    if exists is False:
        return _NOT_FOUND
    return _MANUAL if entry.get('confidence') == 'MANUAL' else _FAILED


def username_rows(data: Mapping[str, Any]) -> List[Tuple[str, Mapping[str, Any], str]]:
    """``(name, entry, verdict)`` per platform: found first, then failed, manual check, not found."""
    platforms = data.get('platforms')
    rows: List[Tuple[str, Mapping[str, Any], str]] = [
        (str(name), entry, platform_verdict(entry))
        for name, entry in (platforms.items() if isinstance(platforms, dict) else [])
        if isinstance(entry, dict)
    ]
    rows.sort(key=lambda row: _VERDICT_ORDER[row[2]])
    return rows


def is_partial(data: Any) -> bool:
    """True if a source flagged its data as incomplete (contract C2)."""
    return isinstance(data, dict) and data.get('partial') is True


def stats_line(data: Mapping[str, Any]) -> str:
    """``automated N | checked N | found N | failed N`` from C4 ``stats`` (or what older output has)."""
    stats = data.get('stats')
    if not isinstance(stats, dict):  # before C4: derive what the older output has
        stats = {'checked': data.get('checked'), 'found': data.get('profiles_found')}
    return ' | '.join(f'{key} {stats[key]}' for key in _STATS_KEYS if isinstance(stats.get(key), int))


def username_table(data: Mapping[str, Any], guard: PrivacyGuard, title: Optional[str] = None) -> Table:
    """Per-platform username verdicts with confidence, calibration and error kind (contract C4).

    Rows are ordered found, failed, manual check, not found. A partial result is flagged in the title
    and the caption so it cannot be mistaken for a complete negative.
    """
    partial = is_partial(data)

    heading = Text(safe_text(f'Username checks: {title}' if title else 'Username checks', single_line=True))
    if partial:
        heading.append('  [PARTIAL - results are INCOMPLETE]', style='bold yellow')
    caption = Text(stats_line(data))
    if partial:
        caption.append('  Some platforms could not be checked: "not found" is not proven.', style='yellow')

    table = Table(title=heading, caption=caption, header_style='bold', border_style='yellow' if partial else None)
    # Enum columns never shrink below their longest value: 'control_e...' would hide the reason.
    table.add_column('Platform', overflow='fold')
    table.add_column('Result', min_width=len(_FAILED))
    table.add_column('Confidence', min_width=len('MEDIUM'))
    table.add_column('Calibration', min_width=len('not_applicable'))
    table.add_column('Error kind', min_width=len('rate_limited'))
    table.add_column('Detail', overflow='fold', ratio=1)
    for name, entry, verdict in username_rows(data):
        calibration = entry.get('calibration')
        detail = entry.get('error') or (entry.get('url') if verdict == _FOUND else '')
        table.add_row(
            _plain(entry.get('label') or name, guard),
            Text(verdict, style=_VERDICT_STYLES[verdict]),
            _plain(entry.get('confidence') or '-', guard),
            _plain(calibration or '-', guard, style=_CALIBRATION_STYLES.get(str(calibration), '')),
            _plain(entry.get('error_kind') or '-', guard, style='red' if entry.get('error_kind') else ''),
            _plain(detail, guard),
        )
    return table


def _step_errors(data: Any) -> List[str]:
    """The source's own error notes (C2 ``errors`` list, or the older per-key dict)."""
    errors = data.get('errors') if isinstance(data, dict) else None
    if isinstance(errors, dict):
        return [f'{key}: {value}' for key, value in errors.items()]
    if isinstance(errors, list):
        return [str(e) for e in errors]
    return []


def partial_notice(results: Mapping[str, StepResult], guard: PrivacyGuard) -> Optional[RenderableType]:
    """A warning panel listing DEGRADED / partial steps and their (redacted) errors, or None if all is complete."""
    lines: List[Text] = []
    for step_id, result in results.items():
        partial = is_partial(result.data)
        if result.status != StepStatus.DEGRADED and not partial:
            continue
        lines.append(_plain(f'{step_id} ({result.status.value})', style='bold'))
        notes = _step_errors(result.data) or ([result.error_message] if result.error_message else [])
        lines.extend(_plain(f'  - {note}', guard) for note in notes)
    if not lines:
        return None
    lines.append(Text('Missing data is unknown, not absent. Re-run later or check these sources manually.'))
    return Panel(Group(*lines), title=Text(_PARTIAL_TITLE, style='bold yellow'), border_style='yellow')


def cache_table(entries: Iterable['CacheEntry']) -> Table:
    """Render cache-audit entries as a Rich table."""
    table = Table(title='Cache contents', header_style='bold')
    for column in ('Key', 'Source', 'Input (redacted)', 'Stored (UTC)', 'Expires (UTC)', 'Bytes', 'PII in data'):
        table.add_column(column)
    for e in entries:
        pii = ', '.join(f'{k}:{v}' for k, v in sorted(e.pii.items())) or '-'
        table.add_row(
            _plain(e.key),
            _plain(e.source),
            _plain(e.input),
            _utc(e.stored_at),
            _utc(e.expires_at),
            str(e.size),
            _plain(pii, style='yellow' if e.pii else ''),
        )
    return table


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


class ProgressObserver:
    """An overall bar plus one spinner row for every running step."""

    def __init__(self, console: Console, total_steps: int):
        """Initialize ProgressObserver."""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn('{task.description}'),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        self._overall = self.progress.add_task('workflow', total=total_steps)
        self._running: Dict[str, TaskID] = {}

    def __enter__(self) -> 'ProgressObserver':
        self.progress.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.progress.stop()

    def step_started(self, step_id: str, step_type: str) -> None:
        """Add a spinner row for a step that has started."""
        description = f'{rich_safe(step_id, single_line=True)} [dim]({rich_safe(step_type, single_line=True)})[/dim]'
        self._running[step_id] = self.progress.add_task(description, total=None)

    def step_finished(self, step_id: str, result: StepResult) -> None:
        """Remove the step's row and advance the overall progress bar."""
        task = self._running.pop(step_id, None)
        if task is not None:
            self.progress.remove_task(task)
        self.progress.advance(self._overall)
