import io
from unittest.mock import Mock

from rich.console import Console
from typer.testing import CliRunner

from secure_osint.cli import app
from secure_osint.core.privacy import PrivacyGuard
from secure_osint.core.workflow import StepResult, StepStatus
from secure_osint.ui import STATUS_STYLES, data_panels, results_table

RESULTS = {
    'dns_lookup': StepResult(status=StepStatus.SUCCESS, data={'A': ['93.184.215.14']}, execution_time=0.12, attempts=1),
    'rdap_lookup': StepResult(status=StepStatus.DEGRADED, data={'handle': 'X'}, execution_time=1.5, attempts=1),
    'host_search': StepResult(
        status=StepStatus.ERROR, error_message='api.hackertarget.com: ConnectTimeout', execution_time=30.0, attempts=2
    ),
    'wayback_urls': StepResult(status=StepStatus.UNAVAILABLE, error_message='web.archive.org HTTP 404'),
    'subdomain_enum': StepResult(status=StepStatus.SKIPPED, error_message='Confirmation not given'),
}


def _render(renderable, color=True) -> str:
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=100,
        force_terminal=color,
        color_system='standard' if color else None,
        legacy_windows=False,
    )
    console.print(renderable)
    return buffer.getvalue()


def test_every_status_has_a_style():
    assert set(STATUS_STYLES) == set(StepStatus)
    assert STATUS_STYLES[StepStatus.SUCCESS] == 'green'
    assert STATUS_STYLES[StepStatus.DEGRADED] == 'yellow'
    assert STATUS_STYLES[StepStatus.ERROR] == 'red'


def test_results_table_plain_snapshot(snapshot):
    snapshot.snapshot_dir = 'tests/snapshots'
    snapshot.assert_match(_render(results_table(RESULTS), color=False), 'results_table_plain.txt')


def test_results_table_ansi_snapshot(snapshot):
    snapshot.snapshot_dir = 'tests/snapshots'
    snapshot.assert_match(_render(results_table(RESULTS)), 'results_table_ansi.txt')


def test_data_panels_are_redacted_and_highlighted():
    output = _render(data_panels(RESULTS, PrivacyGuard()))
    assert '93.184.215.14' not in output
    assert '[REDACTED]' in output
    assert '\x1b[' in output  # syntax highlighting is present


def test_data_panels_skip_steps_without_data():
    output = _render(data_panels(RESULTS, PrivacyGuard()), color=False)
    assert 'dns_lookup' in output
    assert 'host_search' not in output


def _patched_run(monkeypatch, tmp_path, args):
    source = Mock()
    source.fetch.return_value = {'A': ['93.184.215.14'], 'contact': 'admin@example.com'}
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': source})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: only\n    type: dns\n',
        encoding='utf-8',
    )
    return CliRunner().invoke(
        app,
        [
            'run',
            'example.com',
            '--workflow',
            'generic',
            '--workflow-dir',
            str(wf_dir),
            '--output-dir',
            str(tmp_path / 'out'),
            *args,
        ],
    )


def test_run_prints_results_table(monkeypatch, tmp_path):
    result = _patched_run(monkeypatch, tmp_path, [])
    assert result.exit_code == 0, result.output
    assert 'SUCCESS' in result.output
    assert 'only' in result.output


def test_run_quiet_prints_nothing(monkeypatch, tmp_path):
    result = _patched_run(monkeypatch, tmp_path, ['--quiet'])
    assert result.exit_code == 0, result.output
    assert result.output == ''
    assert (tmp_path / 'out' / 'latest.json').exists()


def test_run_show_data_is_redacted(monkeypatch, tmp_path):
    result = _patched_run(monkeypatch, tmp_path, ['--show-data'])
    assert result.exit_code == 0, result.output
    assert 'admin@example.com' not in result.output
    assert '[REDACTED]' in result.output


# --- terminal injection: remote text must not drive the terminal ---

OSC8 = '\x1b]8;;http://evil.example/\x1b\\click\x1b]8;;\x1b\\'
HOSTILE = 'bio [link=http://evil.example]x[/link] ' + OSC8 + ' \x9b2J \u202etxt.exe \x1b]52;c;ZXZpbA==\x07'


def _assert_inert(output: str) -> None:
    assert '\x1b]' not in output  # no OSC (hyperlink, clipboard, title) sequence
    assert '\x9b' not in output and '\u202e' not in output and '\x07' not in output


def test_results_table_strips_escape_sequences_from_errors():
    results = {'s': StepResult(status=StepStatus.ERROR, error_message=HOSTILE)}
    _assert_inert(_render(results_table(results, guard=PrivacyGuard(categories=set()))))
    # Same for the step id (workflow YAML may come from a third party).
    _assert_inert(_render(results_table({OSC8: StepResult(status=StepStatus.SUCCESS)})))


def test_results_table_title_is_sanitized():
    _assert_inert(_render(results_table({}, title='t ' + OSC8)))


def test_data_panel_titles_cannot_inject_markup():
    results = {'[link=http://evil.example]s[/link]' + OSC8: StepResult(status=StepStatus.SUCCESS, data={'k': 'v'})}
    _assert_inert(_render(data_panels(results, PrivacyGuard())))
    assert '[link=http://evil.example]s[/link]' in _render(data_panels(results, PrivacyGuard()), color=False)


def test_data_panels_escape_control_chars_in_values():
    results = {'s': StepResult(status=StepStatus.SUCCESS, data={'bio': HOSTILE})}
    _assert_inert(_render(data_panels(results, PrivacyGuard(categories=set()))))


def test_progress_rows_cannot_inject_markup():
    from secure_osint.ui import ProgressObserver

    observer = ProgressObserver(Console(file=io.StringIO()), total_steps=1)
    observer.step_started('[link=http://evil.example]s[/link]', 'dns' + OSC8)
    description = observer.progress.tasks[-1].description
    assert '\\[link=http://evil.example]' in description and '\x1b' not in description


def test_cache_table_is_sanitized():
    from secure_osint.ui import cache_table

    entry = Mock(key='k' + OSC8, source='[bold]src', input=HOSTILE, stored_at=0, expires_at=0, size=1, pii={})
    _assert_inert(_render(cache_table([entry])))
    assert '[bold]src' in _render(cache_table([entry]), color=False)


# --- C4 username display ---


def _username_data(partial=False):
    data = {
        'username': 'jroe',
        'profiles_found': 1,
        'checked': 3,
        'platforms': {
            'github': {
                'exists': True,
                'error': None,
                'url': 'https://github.com/jroe',
                'label': 'GitHub',
                'confidence': 'HIGH',
                'calibration': 'not_applicable',
                'error_kind': None,
                'profile': {'bio': HOSTILE},
            },
            'gitlab': {
                'exists': None,
                'error': 'timed out after 10s',
                'url': 'https://gitlab.com/jroe',
                'label': 'GitLab',
                'confidence': None,
                'calibration': 'control_error',
                'error_kind': 'timeout',
            },
            'medium': {
                'exists': None,
                'error': 'page looks the same for a random username',
                'url': 'https://medium.com/@jroe',
                'label': 'Medium',
                'confidence': 'MANUAL',
                'calibration': 'soft404',
                'error_kind': None,
            },
            'instagram': {
                'exists': None,
                'error': 'Requires login: check manually',
                'url': 'https://www.instagram.com/jroe',
                'label': 'Instagram',
                'confidence': 'MANUAL',
                'calibration': 'not_applicable',
                'error_kind': 'auth_wall',
            },
            'pypi': {
                'exists': False,
                'error': None,
                'url': 'https://pypi.org/user/jroe',
                'label': 'PyPI',
                'confidence': 'HIGH',
                'calibration': 'passed',
                'error_kind': None,
            },
        },
        'stats': {'automated': 4, 'checked': 3, 'found': 1, 'failed': 1},
    }
    if partial:
        data.update(partial=True, errors=['gitlab: timeout'])
    return data


def test_username_table_shows_error_kind_calibration_and_stats():
    from secure_osint.ui import username_table

    output = _render(username_table(_username_data(), PrivacyGuard()), color=False)
    for text in ('GitHub', 'FOUND', 'timeout', 'control_error', 'soft404', 'auth_wall', 'manual check', 'not found'):
        assert text in output, text
    assert 'automated 4' in output and 'checked 3' in output and 'found 1' in output and 'failed 1' in output
    _assert_inert(_render(username_table(_username_data(), PrivacyGuard())))
    # Found first, then failures, then manual checks, then not found.
    assert output.index('GitHub') < output.index('GitLab') < output.index('Instagram') < output.index('PyPI')


def test_username_table_marks_partial_results():
    from secure_osint.ui import username_table

    output = _render(username_table(_username_data(partial=True), PrivacyGuard()), color=False)
    assert 'PARTIAL' in output and 'INCOMPLETE' in output


def test_username_table_without_c4_fields_still_renders():
    from secure_osint.ui import username_table

    data = {'platforms': {'github': {'exists': True, 'url': 'https://github.com/x', 'label': 'GitHub'}}}
    output = _render(username_table(data, PrivacyGuard()), color=False)
    assert 'GitHub' in output and 'FOUND' in output


def test_partial_notice_lists_degraded_steps_and_their_errors():
    from secure_osint.ui import partial_notice

    results = {
        'fine': StepResult(status=StepStatus.SUCCESS, data={'a': 1}),
        'users': StepResult(status=StepStatus.DEGRADED, data={'partial': True, 'errors': ['gitlab: timeout' + OSC8]}),
        'dns': StepResult(status=StepStatus.DEGRADED, data={'errors': {'MX': 'SERVFAIL for admin@example.com'}}),
    }
    notice = partial_notice(results, PrivacyGuard())
    assert notice is not None
    output = _render(notice, color=False)
    assert 'PARTIAL RESULTS' in output and 'users' in output and 'gitlab: timeout' in output and 'dns' in output
    assert 'fine' not in output
    assert 'admin@example.com' not in output
    _assert_inert(_render(notice))


def test_partial_notice_is_none_when_everything_is_complete():
    from secure_osint.ui import partial_notice

    assert partial_notice({'ok': StepResult(status=StepStatus.SUCCESS, data={})}, PrivacyGuard()) is None


def test_results_table_renders_on_a_cp1252_console():
    from secure_osint.utils.terminal import ensure_console_encoding

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding='cp1252')
    ensure_console_encoding(stream)
    results = {'s': StepResult(status=StepStatus.ERROR, error_message='\u65e5\u672c \u2713 \U0001f600')}
    Console(file=stream, width=80, legacy_windows=False).print(results_table(results))
    stream.flush()
    assert b'ERROR' in raw.getvalue()


def _patched_username_run(monkeypatch, tmp_path, data):
    source = Mock()
    source.fetch.return_value = data
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'username': source})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: users\n    type: username\n',
        encoding='utf-8',
    )
    out = str(tmp_path / 'o')
    return CliRunner().invoke(
        app, ['run', 'jroe', '--workflow', 'generic', '--workflow-dir', str(wf_dir), '--output-dir', out]
    )


def test_run_prints_the_username_table(monkeypatch, tmp_path):
    result = _patched_username_run(monkeypatch, tmp_path, _username_data())
    assert result.exit_code == 0, result.output
    assert 'control_error' in result.output and 'timeout' in result.output
    _assert_inert(result.output)


def test_run_makes_partial_results_unmistakable(monkeypatch, tmp_path):
    result = _patched_username_run(monkeypatch, tmp_path, _username_data(partial=True))
    assert result.exit_code == 0, result.output
    assert 'PARTIAL RESULTS' in result.output
