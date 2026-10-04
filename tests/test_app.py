import logging
import sys
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secure_osint import app as gui_app
from secure_osint.app import AUP_AGREEMENT_LABEL, GATE_REFUSAL, GUI_MISSING_MSG, run_investigation
from secure_osint.core.validator import IMAGE_EXTENSIONS
from tests.owner_only import assert_owner_only

FAKE_RESULTS = {'dns': {'status': 'SUCCESS', 'data': {'A': ['93.184.216.34'], 'NS': ['ns1.example.com']}}}


class FakeEngine:
    """Stands in for WorkflowEngine: records how it was built and returns canned results."""

    instances: list = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.executed = None
        FakeEngine.instances.append(self)

    def execute(self, wf, input_str):
        self.executed = (wf.name, input_str)
        return FAKE_RESULTS


@pytest.fixture
def engine(monkeypatch):
    FakeEngine.instances = []
    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', FakeEngine)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)  # no cache in ~/.cache during tests
    return FakeEngine


def _run(tmp_path, **kwargs):
    params = {'target': 'example.com', 'agreed': True, 'output_dir': str(tmp_path)}
    params.update(kwargs)
    return run_investigation(**params)


# --- ethical gate (server-side, the one that actually protects) ---


def test_gate_blocks_when_policy_not_accepted(tmp_path, engine):
    markdown, files, _ = _run(tmp_path, agreed=False)
    assert markdown == GATE_REFUSAL
    assert files is None
    assert engine.instances == []  # the engine was never even built
    assert not any(tmp_path.iterdir())  # and no report was written


@pytest.mark.parametrize('truthy', ['true', 'True', 1, 'yes', [True], None])
def test_gate_rejects_anything_but_boolean_true(tmp_path, engine, truthy):
    # Via the HTTP API a client could send a truthy non-bool: only the literal True passes.
    markdown, files, _ = _run(tmp_path, agreed=truthy)
    assert markdown == GATE_REFUSAL and files is None
    assert engine.instances == []


def test_gui_run_registers_its_target_for_log_masking(tmp_path, engine):
    from secure_osint.core.privacy import clear_sensitive_values, log_guard

    clear_sensitive_values()
    try:
        _run(tmp_path, target='gui-target-example.org')
        assert 'gui-target-example.org' not in log_guard().redact('contacting gui-target-example.org now')
    finally:
        clear_sensitive_values()


# --- input validation ---


@pytest.mark.parametrize('target', ['', '   ', None, 123])
def test_empty_or_non_string_target_is_an_error(tmp_path, engine, target):
    markdown, files, _ = _run(tmp_path, target=target)
    assert markdown.startswith('**Error:**') and files is None
    assert engine.instances == []


@pytest.mark.parametrize('workflow', ['../../etc/passwd', 'ip', 'generic', '', None])
def test_workflow_outside_choices_is_rejected(tmp_path, engine, workflow):
    markdown, files, _ = _run(tmp_path, workflow=workflow)
    assert markdown.startswith('**Error:** unknown workflow') and files is None
    assert engine.instances == []


def test_oversized_input_is_an_error_not_a_crash(tmp_path, engine):
    markdown, files, _ = _run(tmp_path, target='a' * 1000)
    assert markdown.startswith('**Error:**') and 'maximum length' in markdown
    assert files is None


# --- successful run through the existing engine ---


def test_successful_run_returns_report_and_downloadable_files(tmp_path, engine):
    markdown, files, _ = _run(tmp_path, case_id='PI-2026-7')
    assert '# OSINT Report: domain' in markdown
    assert '## Entity Correlation Summary' in markdown
    assert '**Case ID:** PI-2026-7' in markdown
    assert [Path(f).name for f in files] == ['latest.json', 'latest.md']
    for f in files:
        assert_owner_only(f)  # same owner-only permissions as the CLI (POSIX mode bits or Windows DACL)
    # It really used the existing engine and the auto-detected workflow.
    assert engine.instances[0].executed == ('domain_recon', 'example.com')


def test_each_run_gets_its_own_directory(tmp_path, engine):
    _, first, _ = _run(tmp_path)
    _, second, _ = _run(tmp_path)
    assert first[0] != second[0]
    for files in (first, second):
        run_dir = Path(files[0]).parent
        assert run_dir.parent == tmp_path / 'gui'


def test_network_data_redacted_by_default(tmp_path, engine):
    markdown, _, _ = _run(tmp_path)
    assert '93.184.216.34' not in markdown
    assert '[REDACTED]' in markdown


def test_keep_network_reveals_ips(tmp_path, engine):
    markdown, _, _ = _run(tmp_path, keep_network=True)
    assert '93.184.216.34' in markdown


def test_keep_network_requires_real_boolean(tmp_path, engine):
    markdown, _, _ = _run(tmp_path, keep_network='true')
    assert '93.184.216.34' not in markdown


def test_confirmation_steps_are_declined_in_the_gui(tmp_path, engine):
    _run(tmp_path)
    confirm = engine.instances[0].kwargs['confirm']
    assert confirm(object()) is False  # no interactive prompt: risky steps are skipped, never auto-run


def test_engine_crash_becomes_a_redacted_error(tmp_path, monkeypatch):
    class Exploding:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            raise RuntimeError('boom while contacting admin@example.com')

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', Exploding)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    markdown, files, _ = _run(tmp_path)
    assert markdown.startswith('**Error:** investigation failed (RuntimeError)')
    assert 'admin@example.com' not in markdown  # error text goes through the PrivacyGuard too
    assert files is None


def _formatted_log(caplog) -> str:
    """Records as a handler would emit them, traceback included."""
    formatter = logging.Formatter('%(message)s')
    return '\n'.join(formatter.format(r) for r in caplog.records)


def test_engine_crash_is_logged_with_traceback_and_redacted(tmp_path, monkeypatch, caplog):
    class Exploding:
        def __init__(self, **kwargs):
            pass

        def execute(self, wf, input_str):
            raise RuntimeError('boom while contacting admin@example.com from 203.0.113.9')

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine', Exploding)
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: None)
    with caplog.at_level(logging.ERROR, logger='secure_osint.app'):
        _run(tmp_path, keep_network=True)  # the UI flag must not weaken log redaction
    records = [r for r in caplog.records if r.name == 'secure_osint.app']
    assert records and records[0].exc_info is not None or records[0].exc_text
    text = _formatted_log(caplog)
    assert 'RuntimeError' in text and 'Traceback' in text
    assert 'admin@example.com' not in text and '203.0.113.9' not in text


def test_report_write_failure_is_logged_and_shown(tmp_path, engine, monkeypatch, caplog):
    def broken(self, *args, **kwargs):
        raise OSError('disk full writing for admin@example.com')

    monkeypatch.setattr(gui_app.ReportGenerator, 'generate_json', broken)
    with caplog.at_level(logging.ERROR, logger='secure_osint.app'):
        markdown, files, _ = _run(tmp_path)
    assert markdown.startswith('**Error:** could not write the reports (OSError)') and files is None
    assert 'admin@example.com' not in markdown
    assert 'could not write the reports' in _formatted_log(caplog)
    assert 'admin@example.com' not in _formatted_log(caplog)


def test_graph_failure_is_logged_and_report_kept(tmp_path, engine, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise ValueError('layout exploded')

    monkeypatch.setattr('secure_osint.core.graph.ensure_graph_support', lambda: None)
    monkeypatch.setattr('secure_osint.core.graph.graph_model', broken)
    with caplog.at_level(logging.ERROR, logger='secure_osint.app'):
        markdown, files, panel = _run(tmp_path, generate_graph=True)
    assert '# OSINT Report' in markdown and len(files) == 2
    assert 'Graph could not be generated (ValueError)' in panel
    assert 'Traceback' in _formatted_log(caplog)


def test_graph_filter_failure_is_logged(tmp_path, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise KeyError('nodes')

    monkeypatch.setattr(gui_app, '_render_graph', broken)
    state = {'files': ['a'], 'panel': 'p', 'model': {'nodes': []}, 'path': str(tmp_path / 'g.html')}
    with caplog.at_level(logging.ERROR, logger='secure_osint.app'):
        panel, files = gui_app._ui_filter(state, True)
    assert 'Graph could not be updated (KeyError)' in panel and files == ['a']
    assert 'Traceback' in _formatted_log(caplog)


def test_module_has_a_logger_and_no_bare_broad_excepts():
    import ast
    import inspect

    assert isinstance(gui_app.logger, logging.Logger) and gui_app.logger.name == 'secure_osint.app'
    tree = ast.parse(inspect.getsource(gui_app))
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == 'Exception':
            calls = [
                n.func.attr
                for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'exception'
            ]
            assert calls, f'broad except at line {node.lineno} does not call logger.exception'


# --- configurable output dir / cache TTL, keep flags, image refusal ---


def test_cache_ttl_is_configurable(tmp_path, engine, monkeypatch):
    ttls = []
    monkeypatch.setattr(gui_app, '_open_cache', lambda ttl: ttls.append(ttl))
    _run(tmp_path, cache_ttl=120)
    assert ttls == [120] and engine.instances[0].kwargs['cache_ttl'] == 120


def test_ui_run_uses_the_configured_output_dir(tmp_path, engine):
    options = gui_app.GuiOptions(output_dir=str(tmp_path / 'custom'), cache_ttl=60)
    _, files, _, _ = gui_app._ui_run('example.com', 'auto', '', False, True, False, options=options)
    assert Path(files[0]).parent.parent == tmp_path / 'custom' / 'gui'
    assert engine.instances[0].kwargs['cache_ttl'] == 60


@pytest.mark.parametrize(
    'kwargs,kept',
    [
        ({}, set()),
        ({'keep_location': True}, {'location'}),
        ({'keep_crypto': True}, {'crypto'}),
        ({'keep_device': True}, {'device'}),
        ({'keep_location': 'true', 'keep_crypto': 1}, set()),  # only a real boolean counts
        ({'keep_network': True, 'keep_location': True, 'keep_crypto': True}, {'network', 'location', 'crypto'}),
    ],
)
def test_keep_flags_select_privacy_categories(tmp_path, engine, monkeypatch, kwargs, kept):
    from secure_osint import cli

    full = frozenset({'secrets', 'personal', 'network', 'location', 'crypto', 'device'})
    monkeypatch.setattr(cli, 'CATEGORIES', full)
    seen = []
    real = gui_app.PrivacyGuard

    def spy(categories=full, **kw):
        seen.append(set(categories))
        return real(categories=set(categories) & {'secrets', 'personal', 'network'}, **kw)

    monkeypatch.setattr(gui_app, 'PrivacyGuard', spy)
    _run(tmp_path, **kwargs)
    assert seen[0] == full - kept


def _no_stat(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError('the GUI must not touch the filesystem for a target')

    monkeypatch.setattr('secure_osint.core.validator.os.stat', boom)


@pytest.mark.parametrize('ext', sorted(IMAGE_EXTENSIONS))
def test_local_image_paths_are_refused_in_the_gui(tmp_path, engine, monkeypatch, ext):
    # Same refusal for an existing and a missing file, and no stat at all: no file-existence oracle.
    existing = tmp_path / f'photo{ext}'
    existing.write_bytes(b'\xff\xd8\xff')
    missing = tmp_path / f'missing{ext.upper()}'
    _no_stat(monkeypatch)
    outcomes = [_run(tmp_path, target=str(path)) for path in (existing, missing)]
    assert outcomes[0][0] == outcomes[1][0]
    for markdown, files, _ in outcomes:
        assert markdown.startswith('**Error:**') and 'CLI' in markdown and files is None
    assert engine.instances == []


@pytest.mark.parametrize('target', [r'\\host\share\x', r'\/host/share/x', r'/\host\share\x', r'\??\UNC\host\s\x'])
def test_network_paths_are_refused_in_the_gui(tmp_path, engine, monkeypatch, target):
    _no_stat(monkeypatch)
    markdown, files, _ = _run(tmp_path, target=target)
    assert markdown.startswith('**Error:**') and files is None
    assert engine.instances == []


def test_wallet_workflow_is_offered():
    assert 'wallet' in gui_app.WORKFLOW_CHOICES and 'image' not in gui_app.WORKFLOW_CHOICES


# --- C7 export downloads ---


@pytest.fixture
def fake_export(monkeypatch):
    calls = []

    def export_correlations(correlations, fmt, path):
        calls.append((fmt, Path(path)))
        Path(path).write_text(fmt, encoding='utf-8')
        return Path(path)

    module = types.ModuleType('secure_osint.core.export')
    module.export_correlations = export_correlations  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, 'secure_osint.core.export', module)
    return calls


def test_exports_are_offered_as_downloads(tmp_path, engine, fake_export):
    markdown, files, _ = _run(tmp_path, export_formats=['graphml', 'maltego_csv'])
    assert [fmt for fmt, _ in fake_export] == ['graphml', 'maltego_csv']
    assert [str(path) for _, path in fake_export] == files[2:]
    assert all(Path(f).parent == Path(files[0]).parent for f in files)


@pytest.mark.parametrize('formats', [['pdf'], ['../../x'], 'graphml', [1]])
def test_unknown_export_formats_are_rejected(tmp_path, engine, fake_export, formats):
    markdown, files, _ = _run(tmp_path, export_formats=formats)
    assert markdown.startswith('**Error:** unknown export format') and files is None
    assert engine.instances == [] and fake_export == []


def test_export_failure_keeps_the_report(tmp_path, engine, fake_export, caplog):
    def broken(correlations, fmt, path):
        raise OSError('disk full')

    sys.modules['secure_osint.core.export'].export_correlations = broken  # type: ignore[attr-defined]
    with caplog.at_level(logging.ERROR, logger='secure_osint.app'):
        markdown, files, _ = _run(tmp_path, export_formats=['json'])
    assert '# OSINT Report' in markdown and 'Export to json failed (OSError)' in markdown
    assert len(files) == 2
    assert 'Traceback' in _formatted_log(caplog)


def test_export_module_missing_is_a_notice_not_a_crash(tmp_path, engine, monkeypatch):
    monkeypatch.setitem(sys.modules, 'secure_osint.core.export', None)
    markdown, files, _ = _run(tmp_path, export_formats=['json'])
    assert '# OSINT Report' in markdown and 'export is not available' in markdown.lower()
    assert len(files) == 2


# --- partial results banner ---


def test_partial_banner_names_degraded_steps():
    report = {
        'results': {
            'users': {'status': 'DEGRADED', 'data': {'partial': True, 'errors': ['gitlab: timeout']}},
            'dns`<b>': {'status': 'SUCCESS', 'data': {}},
        }
    }
    banner = gui_app._partial_banner(report)
    assert 'Partial results' in banner and '`users`' in banner and 'gitlab: timeout' in banner
    assert gui_app._partial_banner({'results': {'a': {'status': 'SUCCESS'}}}) == ''
    assert gui_app._partial_banner(None) == ''


def test_partial_banner_escapes_markdown_and_html():
    report = {'results': {'x`y': {'status': 'DEGRADED', 'data': {'errors': ['<img src=x onerror=alert(1)> | `']}}}}
    banner = gui_app._partial_banner(report)
    assert '<img' not in banner and '&lt;img' in banner


def test_username_markdown_shows_c4_fields():
    report = {
        'results': {
            'users': {
                'status': 'SUCCESS',
                'data': {
                    'platforms': {
                        'gitlab': {
                            'label': 'GitLab',
                            'exists': None,
                            'error': 'x|y <b>',
                            'calibration': 'control_error',
                            'error_kind': 'timeout',
                        },
                        'github': {'label': 'GitHub', 'exists': True, 'calibration': 'not_applicable'},
                    },
                    'stats': {'automated': 2, 'checked': 1, 'found': 1, 'failed': 1},
                },
            }
        }
    }
    text = gui_app._username_markdown(report)
    assert 'timeout' in text and 'control_error' in text and 'GitHub' in text
    assert 'automated 2' in text and 'failed 1' in text
    assert '<b>' not in text and 'x\\|y' in text
    assert gui_app._username_markdown({'results': {}}) == ''


# --- gradio is optional ---


def test_build_ui_without_gradio_gives_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, 'gradio', None)  # simulates the extra not being installed
    with pytest.raises(RuntimeError, match=r'secure-osint\[gui\]'):
        gui_app.build_ui()


def test_cli_gui_without_gradio_exits_cleanly(monkeypatch):
    from secure_osint.cli import app

    monkeypatch.setitem(sys.modules, 'gradio', None)
    result = CliRunner().invoke(app, ['gui', '--no-open-browser'])
    assert result.exit_code == 1
    assert GUI_MISSING_MSG in result.output


@pytest.mark.parametrize(
    'host,expected', [('127.0.0.1', True), ('::1', True), ('localhost', True), ('0.0.0.0', False), ('10.0.0.5', False)]
)
def test_loopback_detection(host, expected):
    assert gui_app._is_loopback(host) is expected


class FakeTheme:
    """Stands in for gr.themes.Base: records its fonts, .set() returns itself."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def set(self, **kwargs):
        return self


GOOD_AUTH = 'auditor:correct-horse-battery'


@pytest.fixture
def fake_launch(monkeypatch):
    """Fake gradio + fake Blocks: returns the kwargs passed to demo.launch() and the options build_ui got."""
    pytest.importorskip('starlette')
    captured = {}

    class FakeDemo:
        def queue(self):
            return self

        def launch(self, **kwargs):
            captured.update(kwargs)

    def fake_build_ui(options=None):
        captured['_options'] = options
        return FakeDemo()

    monkeypatch.setitem(sys.modules, 'gradio', types.SimpleNamespace(themes=types.SimpleNamespace(Base=FakeTheme)))
    monkeypatch.setattr(gui_app, 'build_ui', fake_build_ui)
    monkeypatch.delenv(gui_app.GUI_AUTH_ENV, raising=False)
    monkeypatch.delenv(gui_app.GUI_ALLOWED_HOSTS_ENV, raising=False)
    return captured


def test_launch_uses_safe_server_settings(fake_launch):
    gui_app.launch(open_browser=False)
    captured = fake_launch
    assert captured['server_name'] == '127.0.0.1'  # loopback by default
    assert captured['share'] is False  # never a public *.gradio.live link
    assert captured['mcp_server'] is False  # an env var must not be able to switch it on
    assert captured['run_history'] is False
    assert captured['ssr_mode'] is False  # Python serves requests itself: the Host guard sees them all
    assert captured['strict_cors'] is True
    assert captured['auth'] is None  # loopback without SECURE_OSINT_GUI_AUTH: no login page
    assert 'api' not in captured['footer_links']
    assert '__theme' in captured['js'] and 'dark' in captured['js']  # dark theme forced
    assert 'so-run' in captured['css']  # the packaged stylesheet is loaded
    fonts = captured['theme'].kwargs['font'] + captured['theme'].kwargs['font_mono']
    assert all(isinstance(f, str) for f in fonts)  # system fonts only: no Google Fonts download


def test_launch_installs_the_host_guard(fake_launch):
    gui_app.launch(open_browser=False)
    (middleware,) = fake_launch['app_kwargs']['middleware']
    assert middleware.cls is gui_app.HostGuardMiddleware
    assert set(middleware.kwargs['allowed_hosts']) == {'localhost', '127.0.0.1', '::1'}
    assert middleware.kwargs['allow_ip_literals'] is False


def test_launch_passes_gui_options(fake_launch, tmp_path):
    gui_app.launch(open_browser=False, output_dir=str(tmp_path), cache_ttl=5)
    assert fake_launch['_options'] == gui_app.GuiOptions(output_dir=str(tmp_path), cache_ttl=5)


@pytest.mark.parametrize('host', ['0.0.0.0', '10.0.0.5', '::', 'example.lan'])
def test_launch_refuses_non_loopback_without_credentials(fake_launch, host):
    with pytest.raises(RuntimeError, match=gui_app.GUI_AUTH_ENV):
        gui_app.launch(host=host, open_browser=False)
    assert 'server_name' not in fake_launch  # nothing was started


@pytest.mark.parametrize(
    'value', ['nocolon', ':password-long-enough', 'user:short', 'user:', 'user:' + ' ' * 3 + 'x' * 8]
)
def test_malformed_or_weak_credentials_are_refused(fake_launch, monkeypatch, value):
    monkeypatch.setenv(gui_app.GUI_AUTH_ENV, value)
    with pytest.raises(RuntimeError, match=gui_app.GUI_AUTH_ENV):
        gui_app.launch(host='0.0.0.0', open_browser=False)
    assert 'server_name' not in fake_launch


def test_non_loopback_with_credentials_starts_with_login(fake_launch, monkeypatch, capsys):
    monkeypatch.setenv(gui_app.GUI_AUTH_ENV, GOOD_AUTH)
    gui_app.launch(host='0.0.0.0', open_browser=False)
    check = fake_launch['auth']
    assert callable(check)
    assert check('auditor', 'correct-horse-battery') is True
    assert check('auditor', 'correct-horse-batterx') is False
    assert check('admin', 'correct-horse-battery') is False
    assert check(None, None) is False
    assert 'correct-horse-battery' not in repr(fake_launch)  # the password itself is never handed out
    assert 'WARNING' in capsys.readouterr().err
    (middleware,) = fake_launch['app_kwargs']['middleware']
    assert middleware.kwargs['allow_ip_literals'] is True  # wildcard bind: reached by LAN IP


def test_loopback_with_credentials_also_requires_login(fake_launch, monkeypatch):
    monkeypatch.setenv(gui_app.GUI_AUTH_ENV, GOOD_AUTH)
    gui_app.launch(open_browser=False)
    assert callable(fake_launch['auth'])


def test_password_containing_colons_is_kept_whole(monkeypatch):
    monkeypatch.setenv(gui_app.GUI_AUTH_ENV, 'me:pa:ss:word:long')
    assert gui_app.gui_credentials() == ('me', 'pa:ss:word:long')


def test_extra_allowed_hosts_come_from_the_environment(fake_launch, monkeypatch):
    monkeypatch.setenv(gui_app.GUI_AUTH_ENV, GOOD_AUTH)
    monkeypatch.setenv(gui_app.GUI_ALLOWED_HOSTS_ENV, 'osint.lan, Box.Example ,')
    gui_app.launch(host='10.0.0.5', open_browser=False)
    (middleware,) = fake_launch['app_kwargs']['middleware']
    assert {'10.0.0.5', 'osint.lan', 'box.example'} <= set(middleware.kwargs['allowed_hosts'])
    assert middleware.kwargs['allow_ip_literals'] is False


def test_login_is_throttled_after_repeated_failures():
    clock = [1000.0]
    check = gui_app._auth_checker('auditor', 'correct-horse-battery', clock=lambda: clock[0])
    for _ in range(gui_app.MAX_LOGIN_FAILURES):
        assert check('auditor', 'wrong-password-123') is False
    assert check('auditor', 'correct-horse-battery') is False  # locked out, even with the right password
    clock[0] += gui_app.LOGIN_LOCKOUT_SECONDS + 1
    assert check('auditor', 'correct-horse-battery') is True


# --- Host / Origin guard (DNS rebinding, cross-site requests) ---


def _guarded_client(allowed_hosts=('localhost', '127.0.0.1', '::1'), allow_ip_literals=False):
    pytest.importorskip('httpx')
    pytest.importorskip('starlette')
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route, WebSocketRoute
    from starlette.testclient import TestClient

    async def ok(request):
        return PlainTextResponse('ok')

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text('hi')
        await websocket.close()

    inner = Starlette(routes=[Route('/', ok, methods=['GET', 'POST']), WebSocketRoute('/ws', ws)])
    guarded = gui_app.HostGuardMiddleware(inner, allowed_hosts=allowed_hosts, allow_ip_literals=allow_ip_literals)
    return TestClient(guarded, base_url='http://127.0.0.1:7860')


@pytest.mark.parametrize('host', ['127.0.0.1:7860', 'localhost:7860', 'LOCALHOST', '[::1]:7860', 'localhost.'])
def test_host_guard_accepts_loopback_names(host):
    response = _guarded_client().get('/', headers={'host': host})
    assert response.status_code == 200 and response.text == 'ok'


@pytest.mark.parametrize(
    'host', ['rebind.attacker.example:7860', 'attacker.example', '192.168.1.5:7860', '', 'localhost.attacker.example']
)
def test_host_guard_rejects_dns_rebinding_hosts(host):
    response = _guarded_client().get('/', headers={'host': host})
    assert response.status_code == 400


@pytest.mark.parametrize('origin', ['http://attacker.example', 'null', 'http://localhost.attacker.example:7860'])
def test_host_guard_rejects_cross_site_origins(origin):
    response = _guarded_client().post('/', headers={'host': '127.0.0.1:7860', 'origin': origin})
    assert response.status_code == 400


def test_host_guard_accepts_same_site_origin():
    response = _guarded_client().post('/', headers={'host': '127.0.0.1:7860', 'origin': 'http://127.0.0.1:7860'})
    assert response.status_code == 200


def test_wildcard_bind_accepts_ip_literals_but_not_names():
    client = _guarded_client(allow_ip_literals=True)
    assert client.get('/', headers={'host': '192.168.1.5:7860'}).status_code == 200
    assert client.get('/', headers={'host': '[fe80::1]:7860'}).status_code == 200
    assert client.get('/', headers={'host': 'rebind.attacker.example:7860'}).status_code == 400


def test_host_guard_closes_rebound_websockets():
    pytest.importorskip('starlette')  # GUI extra: skipped in the no-extras CI job
    from starlette.websockets import WebSocketDisconnect

    client = _guarded_client()
    with client.websocket_connect('/ws', headers={'host': '127.0.0.1:7860'}) as ws:
        assert ws.receive_text() == 'hi'
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws', headers={'host': 'attacker.example'}) as ws:
            ws.receive_text()


def test_real_gradio_app_is_protected_against_dns_rebinding():
    pytest.importorskip('gradio')
    from gradio.routes import App
    from starlette.testclient import TestClient

    demo = gui_app.build_ui()
    app = App.create_app(demo, app_kwargs=gui_app._server_app_kwargs('127.0.0.1'))
    client = TestClient(app, base_url='http://127.0.0.1:7860')
    assert client.get('/config', headers={'host': '127.0.0.1:7860'}).status_code == 200
    assert client.get('/config', headers={'host': 'rebind.attacker.example:7860'}).status_code == 400
    assert client.get('/', headers={'host': 'rebind.attacker.example:7860'}).status_code == 400


# --- UI construction (only where the gradio extra is installed) ---


def test_ui_builds_with_run_button_locked(monkeypatch):
    gr = pytest.importorskip('gradio')
    demo = gui_app.build_ui()
    assert isinstance(demo, gr.Blocks)
    run = next(b for b in demo.blocks.values() if isinstance(b, gr.Button) and b.elem_id == 'so-run')
    assert run.interactive is False  # locked until the AUP is accepted
    tabs = [b.id for b in demo.blocks.values() if isinstance(b, gr.Tab)]
    assert tabs == ['investigate', 'report', 'graph', 'pivots']
    labels = [c.label for c in demo.blocks.values() if isinstance(c, gr.Checkbox)]
    assert AUP_AGREEMENT_LABEL in labels
    assert any('location' in label.lower() for label in labels)
    assert any('crypto' in label.lower() for label in labels)
    groups = [c for c in demo.blocks.values() if isinstance(c, gr.CheckboxGroup)]
    assert any(set(gui_app.EXPORT_FORMATS) <= {choice[1] for choice in g.choices} for g in groups)
    assert demo.analytics_enabled is False


def test_footer_reflects_the_listening_address():
    assert 'localhost only' in gui_app._footer_html('1.0.0')
    shown = gui_app._footer_html('1.0.0', host='0.0.0.0<b>')
    assert 'password protected' in shown and '0.0.0.0&lt;b&gt;' in shown and '0.0.0.0<b>' not in shown
