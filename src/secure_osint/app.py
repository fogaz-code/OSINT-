"""Local web interface (Gradio) for non-technical users: investigators, HR, auditors.

It is a thin wrapper around the same components as the CLI (input sanitising and auto-detection,
safe workflow loading, PrivacyGuard, WorkflowEngine, ReportGenerator). Nothing of the engine is
reimplemented: behaviour, redaction included, is identical to ``secure-osint run``.

Ethical gate: the Run button stays disabled until the user accepts the Acceptable Use Policy. A
disabled button is only client side and Gradio exposes every event over HTTP too, so
``run_investigation`` refuses to run unless ``agreed`` is exactly True. The server-side check is the
real gate; the button is UX.

Network exposure: see ``secure_osint.gui_security`` (credentials from ``SECURE_OSINT_GUI_AUTH``,
login lockout, Host/Origin guard against DNS rebinding and CSRF, anti-framing headers).

Install: pip install "secure-osint[gui]"      Start: secure-osint gui  (or python -m secure_osint.app)
"""

import html
import ipaddress
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from secure_osint.cli import (
    DEFAULT_WORKFLOW_DIR,
    EXPORT_FILENAMES,
    EXPORT_FORMATS,
    _load,
    _open_cache,
    _resolve,
    load_exporter,
    privacy_categories,
)
from secure_osint.core.graph import DEFAULT_FILTERS, FILTERS  # graph.py does not import pyvis at module level
from secure_osint.core.privacy import PrivacyGuard, register_sensitive_values
from secure_osint.core.reporter import ReportGenerator
from secure_osint.core.validator import IMAGE_EXTENSIONS, is_unc_path
from secure_osint.utils.logging_config import ensure_redacted_logging
from secure_osint.gui_security import ALLOWED_HOSTS_ENV as GUI_ALLOWED_HOSTS_ENV
from secure_osint.gui_security import AUTH_ENV as GUI_AUTH_ENV
from secure_osint.gui_security import (
    LOGIN_LOCKOUT_SECONDS,
    MAX_LOGIN_FAILURES,
    HostGuardMiddleware,
    auth_checker,
    gui_credentials,
    server_app_kwargs,
)
from secure_osint.sources.username_source import _USERNAME
from secure_osint.ui import is_partial, stats_line, username_rows
from secure_osint.utils.log_redaction import redacting_logger
from secure_osint.utils.markdown import md_code, md_text

__all__ = [
    'GUI_ALLOWED_HOSTS_ENV',
    'GUI_AUTH_ENV',
    'LOGIN_LOCKOUT_SECONDS',
    'MAX_LOGIN_FAILURES',
    'GuiOptions',
    'HostGuardMiddleware',
    'build_ui',
    'gui_credentials',
    'launch',
    'main',
    'run_investigation',
]

# Every record is fully redacted at the logger (all privacy categories), whatever the UI flags.
logger = redacting_logger(__name__)

# GUI-side names of the security helpers.
_auth_checker = auth_checker
_server_app_kwargs = server_app_kwargs

# 'image' is CLI only: the web UI never reads files on the machine it runs on (see _investigate).
WORKFLOW_CHOICES = ('auto', 'username', 'domain', 'email', 'phone', 'wallet')

# Labels of the graph filter checkboxes, in the same order as core.graph.FILTERS.
FILTER_LABELS = (
    'Show existing accounts',
    'Show platforms requiring manual check',
    'Show not-found platforms',
    'Show infrastructure',
    'Show domains/emails',
    'Show suggested pivots',
)

EXPORT_LABELS: Dict[str, str] = {
    'graphml': 'GraphML (Gephi, yEd)',
    'gexf': 'GEXF (Gephi)',
    'maltego_csv': 'Maltego CSV',
    'json': 'JSON',
}

AUP_AGREEMENT_LABEL = 'I agree to the Acceptable Use Policy and will use this tool for authorized purposes only'

AUP_SUMMARY = """\
### Acceptable Use Policy (summary)

This tool gathers **publicly available information only**, for **authorized purposes**: a self-audit
of your own identifiers, a licensed or authorized investigation, or corporate due diligence.

**Strictly prohibited:** stalking, illegal doxxing, harassment, and any unauthorized access to
systems or accounts.

**You are solely responsible** for having a lawful basis and for complying with local privacy law
(e.g. GDPR, CCPA). Findings are provided "as is" and **must be independently verified**.

Read the full policy in `ACCEPTABLE_USE_POLICY.md`.
"""

GATE_REFUSAL = (
    '**Blocked:** you must accept the Acceptable Use Policy before running an investigation. '
    'This tool is for authorized purposes only.'
)

GUI_MISSING_MSG = (
    'The web interface requires the optional "gui" extra. Install it with: pip install "secure-osint[gui]"'
)

IMAGE_REFUSAL = (
    'local image files can only be analyzed from the command line (CLI): secure-osint run <path>. '
    'The web interface never reads files from the machine it runs on.'
)


def _looks_like_local_file(target: str) -> bool:
    """Refused whether or not the file exists, so the GUI is no file-existence oracle.

    Covers every extension the validator would ``stat`` (same set, so the lists cannot drift) and
    network paths, which must never reach the filesystem (SMB / NTLM on Windows).
    """
    value = target.strip()
    return is_unc_path(value) or os.path.splitext(value)[1].lower() in IMAGE_EXTENSIONS


# Force the dark theme: Gradio applies it through the __theme=dark query parameter.
_FORCE_DARK_JS = """
() => {
  const url = new URL(window.location);
  if (url.searchParams.get('__theme') !== 'dark') {
    url.searchParams.set('__theme', 'dark');
    window.location.replace(url.href);
  }
}
"""

# Gradio copies returned files into its cache: purge them hourly (files older than one hour), since
# they are reports about a target and must not linger in the temp directory.
_CACHE_PURGE = (3600, 3600)


@dataclass(frozen=True)
class GuiOptions:
    """Server-side settings of the web UI (from ``secure-osint gui`` options, never from the browser)."""

    output_dir: str = 'reports'
    cache_ttl: int = 3600
    host: str = '127.0.0.1'


Outcome = Tuple[str, Optional[List[str]], str, Optional[Dict[str, Any]]]


def _error(message: str) -> Outcome:
    return f'**Error:** {message}', None, '', None


def _graph_notice(message: str) -> str:
    return (
        '<div style="padding:12px 16px;border-radius:8px;background:#1b1f2a;color:#e6e8ee">'
        f'{html.escape(message)}</div>'
    )


def _graph_iframe(page: str) -> str:
    # sandbox WITHOUT allow-same-origin: the graph's JavaScript runs in an opaque origin and can neither
    # read nor touch the Gradio page. allow-popups(+escape): a double click opens the profile in a normal
    # new tab (with noopener: that tab has no access to the graph).
    return (
        '<iframe title="Investigation graph" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox" '
        'style="width:100%;height:760px;border:0;border-radius:8px;background:#0b0d12" '
        f'srcdoc="{html.escape(page, quote=True)}"></iframe>'
    )


def _render_graph(model: Dict[str, Any], filters: Optional[Iterable[str]], path: Path) -> str:
    """Filter the model, (re)write the standalone HTML at ``path`` and return the iframe panel."""
    from secure_osint.core.graph import filter_model, network_from_model, save_graph_html

    save_graph_html(network_from_model(filter_model(model, filters)), path)
    return _graph_iframe(path.read_text(encoding='utf-8'))


def _graph_panel(
    reporter: ReportGenerator,
    results: Any,
    resolved_input: str,
    guard: PrivacyGuard,
    run_dir: Path,
    case_id: Any,
    filters: Optional[Iterable[str]],
) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    """Graph from the report's (already redacted) correlations: (panel HTML, file path, model)."""
    try:
        from secure_osint.core.graph import ensure_graph_support, graph_filename, graph_model

        ensure_graph_support()
        model = graph_model(reporter.correlations(results, resolved_input), guard=guard)
        path = run_dir / graph_filename(case_id if isinstance(case_id, str) else None)
        return _render_graph(model, filters, path), str(path), model
    except RuntimeError as e:  # missing 'graph' extra, or HTML with external resources refused
        return _graph_notice(str(e)), None, None
    except Exception as e:  # a failed graph must not cost the user the report
        logger.exception('graph generation failed')
        return _graph_notice(f'Graph could not be generated ({type(e).__name__}): {guard.redact(str(e))}'), None, None


def _export_formats(value: Any) -> Optional[List[str]]:
    """Validated, de-duplicated export formats; None if anything is not a known format name."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        return None
    if not all(isinstance(fmt, str) and fmt in EXPORT_FORMATS for fmt in value):
        return None
    return list(dict.fromkeys(value))


def _write_exports(
    reporter: ReportGenerator, results: Any, resolved_input: str, formats: List[str], run_dir: Path
) -> Tuple[List[str], List[str]]:
    """Export the (already redacted) correlations: (written file paths, notices for the user)."""
    try:
        exporter = load_exporter()
    except RuntimeError as e:  # core.export not available in this build
        return [], [str(e)]
    try:
        correlations = reporter.correlations(results, resolved_input)
    except Exception as e:  # failing correlations must not cost the user the report
        logger.exception('GUI export: correlations could not be built')
        return [], [f'Export failed ({type(e).__name__}).']
    written: List[str] = []
    notices: List[str] = []
    for fmt in formats:
        try:
            written.append(str(exporter(correlations, fmt, run_dir / EXPORT_FILENAMES[fmt])))
        except Exception as e:  # one failed export must not hide the others
            logger.exception('GUI export failed', extra={'export_format': fmt})
            notices.append(f'Export to {fmt} failed ({type(e).__name__}).')
    return written, notices


def run_investigation(
    target: Any,
    workflow: Any = 'auto',
    case_id: Any = '',
    keep_network: Any = False,
    agreed: Any = False,
    generate_graph: Any = False,
    output_dir: str = 'reports',
    workflow_dir: str = DEFAULT_WORKFLOW_DIR,
    graph_filters: Optional[Iterable[str]] = None,
    keep_location: Any = False,
    keep_crypto: Any = False,
    keep_device: Any = False,
    export_formats: Any = None,
    cache_ttl: int = 3600,
) -> Tuple[str, Optional[List[str]], str]:
    """Run one investigation through the existing engine.

    Never raises: every failure becomes a readable Markdown error for the UI.

    Args:
        target: Username, domain, email, phone number or wallet address to investigate.
        workflow: One of ``WORKFLOW_CHOICES``; ``auto`` detects it from the target.
        case_id: Optional case ID stamped on the reports.
        keep_network: Do not redact IP addresses (same as ``--keep-network``). Only a real ``True`` counts.
        agreed: Must be exactly ``True`` (Acceptable Use Policy accepted), otherwise nothing runs.
        generate_graph: Also build the interactive investigation graph (needs the ``graph`` extra).
        output_dir: Base directory for reports; each run gets its own subdirectory.
        workflow_dir: Directory of workflow YAML files.
        graph_filters: Graph categories to show (see ``core.graph.FILTERS``); None = defaults.
        keep_location: Do not redact GPS coordinates (``--keep-location``).
        keep_crypto: Do not redact wallet addresses (``--keep-crypto``).
        keep_device: Do not redact camera/lens serial numbers (``--keep-device``).
        export_formats: Correlation export formats (subset of ``EXPORT_FORMATS``), offered as downloads.
        cache_ttl: Lifetime of cached source results in seconds (0 = do not store).

    Returns:
        ``(markdown, files, graph_html)``: the Markdown report (or an error message), the report
        file paths (plus graph HTML and exports when generated) or ``None``, and the graph panel HTML
        (empty when no graph was requested).
    """
    markdown, files, graph_html, _ = _investigate(
        target,
        workflow,
        case_id,
        keep_network,
        agreed,
        generate_graph,
        output_dir,
        workflow_dir,
        graph_filters,
        keep_location=keep_location,
        keep_crypto=keep_crypto,
        keep_device=keep_device,
        export_formats=export_formats,
        cache_ttl=cache_ttl,
    )
    return markdown, files, graph_html


def _investigate(
    target: Any,
    workflow: Any,
    case_id: Any,
    keep_network: Any,
    agreed: Any,
    generate_graph: Any,
    output_dir: str,
    workflow_dir: str,
    graph_filters: Optional[Iterable[str]],
    keep_location: Any = False,
    keep_crypto: Any = False,
    keep_device: Any = False,
    export_formats: Any = None,
    cache_ttl: int = 3600,
) -> Outcome:
    """``run_investigation`` plus the session state the GUI keeps for re-filtering the graph."""
    # Server-side ethical gate: only the boolean True, not "truthy" strings sent through the API.
    if agreed is not True:
        return GATE_REFUSAL, None, '', None
    if not isinstance(target, str) or not target.strip():
        return _error('please enter a target (username, domain, email, phone number or wallet address).')
    if workflow not in WORKFLOW_CHOICES:
        return _error(f'unknown workflow {workflow!r}. Choose one of: {", ".join(WORKFLOW_CHOICES)}.')
    formats = _export_formats(export_formats)
    if formats is None:
        return _error(f'unknown export format. Choose from: {", ".join(EXPORT_FORMATS)}.')
    if _looks_like_local_file(target):
        return _error(IMAGE_REFUSAL)

    guard = PrivacyGuard(categories=privacy_categories(keep_network, keep_location, keep_crypto, keep_device))
    register_sensitive_values([target])  # logs mask the run's target, as in the CLI

    try:
        resolved_input, resolved_workflow = _resolve(target, workflow, quiet=True)
        register_sensitive_values([resolved_input])  # the normalised form too
        if resolved_workflow == 'image':  # an existing local file: CLI only, never from the browser
            return _error(IMAGE_REFUSAL)
        wf = _load(resolved_workflow, workflow_dir)
    except ValueError as e:
        return _error(guard.redact(str(e)))

    from secure_osint.core.engine import WorkflowEngine

    result_cache = _open_cache(cache_ttl)
    try:
        # No interactive prompt in the GUI: steps that require confirmation are skipped.
        engine = WorkflowEngine(
            allow_partial_results=True, confirm=lambda step: False, cache=result_cache, cache_ttl=cache_ttl
        )
        results = engine.execute(wf, resolved_input)
    except Exception as e:  # the GUI must never fall over: the (redacted) error is shown to the user
        logger.exception('GUI investigation failed')
        return _error(f'investigation failed ({type(e).__name__}): {guard.redact(str(e))}')
    finally:
        if result_cache is not None:
            result_cache.close()

    # One subdirectory per run: two runs never overwrite each other's reports.
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run_dir = Path(output_dir) / 'gui' / f'{stamp}-{uuid.uuid4().hex[:8]}'
    json_path = str(run_dir / 'latest.json')
    md_path = str(run_dir / 'latest.md')
    try:
        reporter = ReportGenerator(guard, case_id=case_id if isinstance(case_id, str) else None)
        reporter.generate_json(results, resolved_input, resolved_workflow, json_path)
        reporter.generate_markdown(results, resolved_input, resolved_workflow, md_path)
        markdown = Path(md_path).read_text(encoding='utf-8')
    except Exception as e:  # disk full, permissions...: shown to the user, traceback in the (redacted) log
        logger.exception('could not write the reports')
        return _error(f'could not write the reports ({type(e).__name__}): {guard.redact(str(e))}')
    files = [json_path, md_path]
    graph_html, graph_path, model = '', None, None
    if generate_graph is True:
        graph_html, graph_path, model = _graph_panel(
            reporter, results, resolved_input, guard, run_dir, case_id, graph_filters
        )
        if graph_path:
            files.append(graph_path)
    if formats:
        written, notices = _write_exports(reporter, results, resolved_input, formats, run_dir)
        files.extend(written)
        markdown += ''.join(f'\n\n> **Note:** {html.escape(notice)}' for notice in notices)
    # Session state (server side) to re-filter the graph without re-running the investigation.
    state = {'files': files, 'panel': graph_html, 'model': model, 'path': graph_path}
    return markdown, files, graph_html, state


def _active_filters(flags: Iterable[Any]) -> List[str]:
    from secure_osint.core.graph import FILTERS

    return [name for name, on in zip(FILTERS, flags) if on is True]


def _ui_run(
    target: Any,
    workflow: Any,
    case_id: Any,
    keep_network: Any,
    agreed: Any,
    make_graph: Any,
    *flags: Any,
    options: Optional[GuiOptions] = None,
    keep_location: Any = False,
    keep_crypto: Any = False,
    keep_device: Any = False,
    export_formats: Any = None,
) -> Outcome:
    """Run button handler: the gated investigation with the graph filters currently ticked.

    ``options`` come from the server (``secure-osint gui``), never from the browser.
    """
    options = options or GuiOptions()
    return _investigate(
        target,
        workflow,
        case_id,
        keep_network,
        agreed,
        make_graph,
        options.output_dir,
        DEFAULT_WORKFLOW_DIR,
        _active_filters(flags),
        keep_location=keep_location,
        keep_crypto=keep_crypto,
        keep_device=keep_device,
        export_formats=export_formats,
        cache_ttl=options.cache_ttl,
    )


def _ui_filter(state: Any, *flags: Any) -> Tuple[str, Optional[List[str]]]:
    """Filter handler: re-render the graph from this session's saved (already redacted) model.

    It never runs an investigation or touches the network; the state lives on the server, so a
    client cannot inject a model. The standalone HTML is rewritten to match what is on screen.
    """
    if not isinstance(state, dict):
        return '', None
    if not state.get('model') or not state.get('path'):
        return state.get('panel', ''), state.get('files')
    try:
        return _render_graph(state['model'], _active_filters(flags), Path(state['path'])), state['files']
    except Exception as e:  # the previous graph stays usable; details go to the (redacted) log
        logger.exception('graph filter update failed')
        return _graph_notice(f'Graph could not be updated ({type(e).__name__}).'), state['files']


def _is_loopback(host: str) -> bool:
    if host.strip().lower() == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host.strip('[]')).is_loopback
    except ValueError:
        return False


# --- partial results and username summary (display only, from the redacted JSON report) ---


_md_text = md_text
_md_code = md_code


def _report_steps(report: Optional[Mapping[str, Any]]) -> List[Tuple[str, Mapping[str, Any]]]:
    results = (report or {}).get('results')
    if not isinstance(results, dict):
        return []
    return [(str(step_id), step) for step_id, step in results.items() if isinstance(step, dict)]


def _step_notes(data: Any) -> List[str]:
    errors = data.get('errors') if isinstance(data, dict) else None
    if isinstance(errors, dict):
        return [f'{key}: {value}' for key, value in errors.items()]
    if isinstance(errors, list):
        return [str(e) for e in errors]
    return []


def _partial_banner(report: Optional[Mapping[str, Any]]) -> str:
    """Markdown warning listing DEGRADED / partial steps and their errors; empty if the run is complete."""
    lines: List[str] = []
    for step_id, step in _report_steps(report):
        data = step.get('data')
        if step.get('status') != 'DEGRADED' and not is_partial(data):
            continue
        notes = '; '.join(_md_text(note) for note in _step_notes(data)) or 'incomplete'
        lines.append(f'> - {_md_code(step_id)} ({_md_text(step.get("status", ""))}): {notes}')
    if not lines:
        return ''
    head = (
        '> **Partial results:** some checks did not complete. Missing data is *unknown*, not absent: '
        're-run later or check these sources manually.\n>'
    )
    return '\n'.join([head, *lines])


def _username_markdown(report: Optional[Mapping[str, Any]]) -> str:
    """Per-platform username table (C4: calibration, error kind, stats) for every username step."""
    sections: List[str] = []
    for step_id, step in _report_steps(report):
        data = step.get('data')
        if not isinstance(data, dict) or not isinstance(data.get('platforms'), dict):
            continue
        title = f'### Username checks: {_md_code(step_id)}'
        if is_partial(data):
            title += ' **(PARTIAL: results are incomplete)**'
        rows = [
            '| Platform | Result | Confidence | Calibration | Error kind | Detail |',
            '| --- | --- | --- | --- | --- | --- |',
        ]
        for name, entry, verdict in username_rows(data):
            detail = entry.get('error') or (entry.get('url') if verdict == 'FOUND' else '') or ''
            cells = (
                entry.get('label') or name,
                verdict,
                entry.get('confidence') or '-',
                entry.get('calibration') or '-',
                entry.get('error_kind') or '-',
                detail,
            )
            rows.append('| ' + ' | '.join(_md_text(cell) for cell in cells) + ' |')
        stats = stats_line(data)
        sections.append('\n'.join([title, '', *rows] + (['', f'_{_md_text(stats)}_'] if stats else [])))
    return '\n\n'.join(sections)


# --- presentation (UI only: no investigation logic) ---

_ASSETS = Path(__file__).resolve().parent / 'assets'
_SYSTEM_FONTS = ['ui-sans-serif', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif']
_MONO_FONTS = ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'Liberation Mono', 'monospace']

_SHIELD_SVG = (
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="rgba(255,255,255,.18)" stroke="#fff" '
    'stroke-width="1.6"/><path d="M8.5 12l2.4 2.4 4.6-4.8" stroke="#fff" stroke-width="1.8" fill="none" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)

# Same content as AUP_SUMMARY, laid out as a legal document.
AUP_HTML = """
<div class="so-aup-head"><span aria-hidden="true">&#9888;&#65039;</span><b>Acceptable Use Policy</b></div>
<ol>
  <li><b>Public information only</b>, for <b>authorized purposes</b>: a self-audit of your own identifiers, a licensed
  or authorized investigation, or corporate due diligence.</li>
  <li><b>Strictly prohibited:</b> stalking, illegal doxxing, harassment, and any unauthorized access to systems or
  accounts.</li>
  <li><b>You are solely responsible</b> for having a lawful basis and for complying with local privacy law
  (e.g. GDPR, CCPA).</li>
  <li>Findings are provided "as is" and <b>must be independently verified</b>. A username found on a platform does not
  prove who owns the account.</li>
</ol>
<div class="so-aup-foot">Full policy: <code>ACCEPTABLE_USE_POLICY.md</code>, included with the source code.</div>
"""

_EMPTY_REPORT = '_No investigation yet. Run one from the **Investigation** tab; the report will appear here._'
_EMPTY_GRAPH = '<div class="so-empty">The investigation graph appears here after a run with "Generate Interactive Graph" enabled.</div>'
_NO_GRAPH = '<div class="so-empty">No graph for this run ("Generate Interactive Graph" was off).</div>'
_EMPTY_PIVOTS = '_Run an investigation to see suggested pivots._'

_GRAPH_LEGEND = """
<div class="so-legend">
  <span><i class="sw" style="background:#e5484d"></i>Target</span>
  <span><i class="ln"></i>High confidence</span>
  <span><i class="ln dash"></i>Medium confidence</span>
  <span><i class="ln dot"></i>Low confidence</span>
  <span><i class="sw" style="background:#f5c451;border-radius:2px;transform:rotate(45deg)"></i>Manual check</span>
  <span><i class="sw" style="background:#6b7280"></i>Not found</span>
  <span><i class="sw" style="background:#30a46c;border-radius:2px"></i>Domain / email</span>
  <span><i class="sw" style="background:#f5a524;border-radius:0;clip-path:polygon(50% 0,100% 100%,0 100%)"></i>
  Infrastructure</span>
  <span><i class="sw" style="border:1px dashed #9ca3af;border-radius:2px"></i>Suggested pivot</span>
</div>
"""

_PIVOT_INTRO = """
<p class="so-note">Suggested pivots are selectors found during this investigation that you <b>may</b> look into
next. The tool <b>never runs them</b>. Each one is a separate investigation that needs its own lawful basis.
Only usernames can be investigated here; names and emails are for your own manual research (emails stay
redacted).</p>
"""


def _app_version() -> str:
    try:
        from importlib.metadata import version

        return version('secure-osint')
    except ImportError:  # PackageNotFoundError (running from a source checkout) is an ImportError
        return 'dev'


def _load_css() -> str:
    """The stylesheet shipped with the package (empty if missing: the UI still works unstyled)."""
    try:
        return (_ASSETS / 'custom.css').read_text(encoding='utf-8')
    except OSError:
        return ''


def _header_html(version: str) -> str:
    return (
        '<div id="so-header"><div class="so-brand">'
        f'<div class="so-logo">{_SHIELD_SVG}</div>'
        f'<div><h1>Secure OSINT <span class="so-badge">v{html.escape(version)}</span></h1>'
        '<p class="so-tagline">Local investigation console for authorized, public-data OSINT</p></div></div>'
        '<div class="so-chips"><span class="so-chip"><i></i>Runs locally</span>'
        '<span class="so-chip">Private by default</span><span class="so-chip">Redacted reports</span></div></div>'
    )


def _footer_html(version: str, host: str = '127.0.0.1') -> str:
    if _is_loopback(host):
        where = 'listening on localhost only'
    else:
        where = f'listening on {html.escape(host)}, password protected'
    return (
        f'<div id="so-footer"><span><b>Secure OSINT</b> v{html.escape(version)} &middot; reports stay on this machine'
        f' &middot; {where}</span>'
        '<span>Acceptable Use Policy: summary on the Investigation tab; full text in '
        '<code>ACCEPTABLE_USE_POLICY.md</code></span></div>'
    )


def _report_json(files: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    """The JSON report this run already wrote (redacted), for the collapsible viewer."""
    if not files:
        return None
    try:
        data = json.loads(Path(files[0]).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _report_pivots(report: Optional[Dict[str, Any]]) -> List[str]:
    correlations = (report or {}).get('correlations')
    pivots = correlations.get('suggested_pivots') if isinstance(correlations, dict) else None
    return [p for p in pivots if isinstance(p, str)] if isinstance(pivots, list) else []


def _pivot_targets(pivots: Iterable[str]) -> List[str]:
    """Pivots this tool can investigate: valid usernames only (names and redacted emails cannot be run)."""
    targets = []
    for pivot in pivots:
        if pivot.startswith('Username: '):
            value = pivot[len('Username: ') :].strip()
            if _USERNAME.match(value) and value not in targets:
                targets.append(value)
    return targets


# A "**Data:**" block followed by a JSON code fence (the fence may be longer than ``` when the content
# contains one: see ReportGenerator.generate_markdown).
_STEP_DATA = re.compile(r'^\*\*Data:\*\*\n(?P<fence>`{3,})json\n(?P<body>.*?)\n(?P=fence)$', re.MULTILINE | re.DOTALL)
_HEADER_LINE = re.compile(r'^(\*\*(?:Generated|Case ID|Input|Status|Error):\*\*.*)$', re.MULTILINE)


def _display_report(markdown: str) -> str:
    """On-screen version of the report: each step's raw JSON collapsed, header fields on their own lines.

    Display only: the downloadable latest.md is untouched (its SHA-256 integrity hash covers the file).
    """

    def collapse(match: 're.Match[str]') -> str:
        fence = match.group('fence')
        return (
            '<details><summary>Raw data for this step (JSON)</summary>\n\n'
            f'{fence}json\n{match.group("body")}\n{fence}\n\n</details>'
        )

    return _HEADER_LINE.sub(r'\1  ', _STEP_DATA.sub(collapse, markdown))


def _pivots_markdown(pivots: List[str]) -> str:
    if not pivots:
        return '_No pivots suggested for this investigation._'
    return '\n'.join(f'- {_md_code(p)}' for p in pivots)


def build_ui(options: Optional[GuiOptions] = None) -> Any:
    """Build the Gradio Blocks app. Raises RuntimeError if the optional gradio extra is missing."""
    try:
        import gradio as gr
    except ImportError as e:
        raise RuntimeError(GUI_MISSING_MSG) from e

    options = options or GuiOptions()
    version = _app_version()

    # analytics_enabled=False: Gradio sends telemetry by default; a privacy-first tool does not.
    with gr.Blocks(title='Secure OSINT', analytics_enabled=False, delete_cache=_CACHE_PURGE) as demo:
        gr.HTML(_header_html(version))
        with gr.Tabs(selected='investigate', elem_id='so-tabs') as tabs:
            with gr.Tab('Investigation', id='investigate'):
                with gr.Row(equal_height=False):
                    with gr.Column(scale=3, elem_classes='so-card'):
                        gr.HTML('<p class="so-section-title">New investigation</p>')
                        target = gr.Textbox(
                            label='Target',
                            placeholder='Enter a username, email, domain, phone number (+E.164) or wallet address',
                            elem_id='so-target',
                        )
                        with gr.Row():
                            workflow = gr.Dropdown(list(WORKFLOW_CHOICES), value='auto', label='Workflow')
                            case_id = gr.Textbox(
                                label='Case ID (optional)', placeholder='ACME-2026-014', elem_id='so-case-id'
                            )
                        gr.HTML('<p class="so-section-title" style="margin-top:14px">Options</p>')
                        keep_network = gr.Checkbox(label='Keep network data (do not redact IP addresses)', value=False)
                        keep_location = gr.Checkbox(
                            label='Keep location data (do not redact GPS coordinates and map links)', value=False
                        )
                        keep_crypto = gr.Checkbox(
                            label='Keep crypto data (do not redact wallet addresses)', value=False
                        )
                        keep_device = gr.Checkbox(
                            label='Keep device data (do not redact camera serial numbers)', value=False
                        )
                        make_graph = gr.Checkbox(label='Generate Interactive Graph', value=True)
                        exports = gr.CheckboxGroup(
                            choices=[(EXPORT_LABELS[fmt], fmt) for fmt in EXPORT_FORMATS],
                            value=[],
                            label='Also export the redacted correlations (downloads)',
                        )
                        gr.HTML(
                            '<p class="so-note">Local image files (EXIF analysis) can only be analyzed from the '
                            'command line: the web interface never reads files from this machine.</p>'
                        )
                    with gr.Column(scale=2, elem_classes='so-card'):
                        gr.HTML(AUP_HTML, elem_id='so-aup')
                        agreed = gr.Checkbox(label=AUP_AGREEMENT_LABEL, value=False, elem_id='so-gate')
                        run_button = gr.Button(
                            'Run Investigation', variant='primary', interactive=False, size='lg', elem_id='so-run'
                        )
                        gr.HTML('<p class="so-hint">Accept the policy above to enable the investigation.</p>')
            with gr.Tab('Report', id='report'):
                with gr.Column(elem_classes='so-card'):
                    report = gr.Markdown(_EMPTY_REPORT, elem_id='so-report')
                with gr.Accordion('Raw JSON report (redacted)', open=False):
                    json_view = gr.JSON(value=None, show_label=False)
                files = gr.File(
                    label='Download reports (JSON, Markdown, graph HTML and exports)',
                    file_count='multiple',
                    interactive=False,
                )
            with gr.Tab('Graph', id='graph'):
                gr.HTML(_GRAPH_LEGEND)
                with gr.Row(elem_classes='so-filters'):
                    filter_boxes = [
                        gr.Checkbox(
                            label=label, value=name in DEFAULT_FILTERS, elem_classes='so-filter', container=False
                        )
                        for name, label in zip(FILTERS, FILTER_LABELS)
                    ]
                graph_view = gr.HTML(_EMPTY_GRAPH, elem_id='so-graph')
            with gr.Tab('Pivots', id='pivots'):
                with gr.Column(elem_classes='so-card'):
                    gr.HTML(_PIVOT_INTRO)
                    pivot_list = gr.Markdown(_EMPTY_PIVOTS, elem_id='so-pivot-list')
                    pivot_choice = gr.Radio(choices=[], label='Usernames you can investigate next')
                    use_pivot = gr.Button('Start a new investigation with this username', elem_id='so-use-pivot')
                    gr.HTML(
                        '<p class="so-note">This only fills in the Target on the Investigation tab. Nothing runs until '
                        'you review it and press <b>Run Investigation</b>.</p>'
                    )
        gr.HTML(_footer_html(version, options.host))
        session = gr.State(None)  # the session's graph model: it stays on the server

        def run_and_show(
            target: Any,
            workflow: Any,
            case_id: Any,
            keep_network: Any,
            keep_location: Any,
            keep_crypto: Any,
            keep_device: Any,
            exports: Any,
            agreed: Any,
            make_graph: Any,
            *flags: Any,
        ) -> Tuple[Any, ...]:
            """Run (through the gated _ui_run) and fill every tab from what this run already wrote."""
            markdown, run_files, graph_html, state = _ui_run(
                target,
                workflow,
                case_id,
                keep_network,
                agreed,
                make_graph,
                *flags,
                options=options,
                keep_location=keep_location,
                keep_crypto=keep_crypto,
                keep_device=keep_device,
                export_formats=exports,
            )
            data = _report_json(run_files)
            pivots = _report_pivots(data)
            graph_panel = graph_html or (_NO_GRAPH if run_files else _EMPTY_GRAPH)
            summary = [part for part in (_partial_banner(data), _username_markdown(data)) if part]
            return (
                '\n\n'.join([*summary, _display_report(markdown)]),
                run_files,
                graph_panel,
                state,
                data,
                _pivots_markdown(pivots) if run_files else _EMPTY_PIVOTS,
                gr.update(choices=_pivot_targets(pivots), value=None),
                gr.Tabs(selected='report'),
            )

        def prefill_pivot(choice: Any) -> Tuple[Any, ...]:
            """Pre-fill the Target with a suggested username. Never starts an investigation."""
            if not isinstance(choice, str) or not choice:
                return gr.update(), gr.update(), gr.update()
            return gr.update(value=choice), gr.update(value='username'), gr.Tabs(selected='investigate')

        # api_visibility='private': these events are not exposed as an API; the server-side gate stays.
        agreed.change(
            lambda accepted: gr.update(interactive=accepted is True),
            inputs=agreed,
            outputs=run_button,
            api_visibility='private',
        )
        run_button.click(
            run_and_show,
            # Input order follows run_and_show's positional parameters.
            inputs=[
                target,
                workflow,
                case_id,
                keep_network,
                keep_location,
                keep_crypto,
                keep_device,
                exports,
                agreed,
                make_graph,
                *filter_boxes,
            ],
            outputs=[report, files, graph_view, session, json_view, pivot_list, pivot_choice, tabs],
            api_visibility='private',
        )
        for box in filter_boxes:  # reactive filters: redraw the graph without re-running the investigation
            box.change(
                _ui_filter, inputs=[session, *filter_boxes], outputs=[graph_view, files], api_visibility='private'
            )
        use_pivot.click(prefill_pivot, inputs=pivot_choice, outputs=[target, workflow, tabs], api_visibility='private')
    return demo


def launch(
    host: str = '127.0.0.1',
    port: int = 7860,
    open_browser: bool = True,
    output_dir: str = 'reports',
    cache_ttl: int = 3600,
) -> None:
    """Start the local web interface (loopback only by default, no public share link).

    Raises:
        RuntimeError: the gradio extra is missing, ``SECURE_OSINT_GUI_AUTH`` is malformed or weak, or
            ``host`` is not a loopback address and no credentials are configured.
    """
    ensure_redacted_logging()  # no-op after `secure-osint gui`; needed for `python -m secure_osint.app`
    credentials = gui_credentials()  # first: a weak or malformed value is refused before anything starts
    if credentials is None and not _is_loopback(host):
        raise RuntimeError(
            f'Refusing to listen on {host}: anyone who can reach this address could run investigations and read '
            f'reports. Set {GUI_AUTH_ENV}=user:password (password of at least 12 characters) in the environment, '
            'or use the default 127.0.0.1.'
        )
    options = GuiOptions(output_dir=output_dir, cache_ttl=cache_ttl, host=host)
    demo = build_ui(options)  # raises RuntimeError with the install hint when gradio is missing
    import gradio as gr

    if not _is_loopback(host):
        print(
            f'WARNING: listening on {host}: the interface is reachable from the network and protected only by the '
            f'{GUI_AUTH_ENV} login. Prefer 127.0.0.1 (or an SSH tunnel) unless you need this.',
            file=sys.stderr,
        )
    demo.queue().launch(
        server_name=host,
        server_port=port,
        share=False,  # never a public *.gradio.live link: reports stay on this machine
        mcp_server=False,  # explicit: an environment variable must not be able to switch it on
        run_history=False,  # no on-screen history of targets
        ssr_mode=False,  # no Node front server: every request reaches Python and the Host guard
        strict_cors=True,
        auth=auth_checker(*credentials) if credentials else None,
        auth_message='Secure OSINT: sign in with the credentials from SECURE_OSINT_GUI_AUTH.',
        app_kwargs=server_app_kwargs(host),  # Host/Origin guard: DNS rebinding and CSRF protection
        footer_links=['gradio', 'settings'],  # no "Use via API" link: the public API is empty
        inbrowser=open_browser,
        # System fonts: nothing downloaded from Google Fonts (the tool stays local).
        theme=gr.themes.Base(primary_hue='blue', neutral_hue='slate', font=_SYSTEM_FONTS, font_mono=_MONO_FONTS).set(
            body_background_fill_dark='#0a1020',
            background_fill_primary_dark='#111a2f',
            background_fill_secondary_dark='#0d1528',
            block_background_fill_dark='#111a2f',
            block_border_color_dark='#24314d',
            input_background_fill_dark='#0d1528',
            border_color_primary_dark='#24314d',
        ),
        css=_load_css(),
        js=_FORCE_DARK_JS,
    )


def main() -> None:
    """Entry point for ``python -m secure_osint.app``."""
    try:
        launch()
    except RuntimeError as e:
        print(f'Error: {e}', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
