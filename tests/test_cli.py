import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest
import typer
from typer.testing import CliRunner

from secure_osint import cli
from secure_osint.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ['--help'])
    assert result.exit_code == 0
    assert 'Secure OSINT' in result.stdout


def test_cli_dry_run():
    result = runner.invoke(app, ['dry-run', 'example.com'])
    assert result.exit_code == 0
    assert 'Dry run' in result.stdout


def test_cli_validate_invalid():
    result = runner.invoke(app, ['validate', 'nonexistent.yaml'])
    assert result.exit_code != 0


def test_cli_rejects_workflow_path_traversal():
    result = runner.invoke(app, ['dry-run', 'example.com', '--workflow', '../../etc/passwd'])
    assert result.exit_code != 0


def test_cli_dry_run_empty_input_is_clean_error():
    result = runner.invoke(app, ['dry-run', '   '])
    assert result.exit_code == 1
    assert 'Traceback' not in result.output


def test_cli_ip_routes_to_ip_workflow():
    result = runner.invoke(app, ['dry-run', '8.8.8.8'])
    assert result.exit_code == 0
    assert 'workflow: ip' in result.stdout


# --- English, encoding-safe help (open source; cp1252 Windows consoles) ---


def _all_help_texts():
    group = typer.main.get_command(app)
    yield 'app', group.help or ''
    for name, command in group.commands.items():
        yield name, command.help or ''
        for param in command.params:
            yield f'{name} {param.name}', getattr(param, 'help', None) or ''


ITALIAN = ('Mostra', 'Esegue', 'Elenca', 'Avvia', 'Directory dei', 'Porta', 'Indirizzo', 'Conferma', 'redigere')


@pytest.mark.parametrize('where,text', list(_all_help_texts()))
def test_help_is_english_and_ascii(where, text):
    assert text.isascii(), f'{where}: {text!r}'  # renders on any console code page
    assert not any(word in text for word in ITALIAN), f'{where}: {text!r}'


def test_cli_callback_makes_console_encoding_safe(monkeypatch):
    called = []
    monkeypatch.setattr(cli, 'ensure_console_encoding', lambda *a: called.append(a))
    runner.invoke(app, ['keys'])
    assert called


def test_error_messages_cannot_drive_the_terminal():
    result = runner.invoke(app, ['dry-run', 'example.com', '--workflow-dir', 'x\x1b]8;;http://evil\x1b\\y'])
    assert result.exit_code == 1
    assert '\x1b' not in result.output


# --- C6: new input types ---


def test_new_input_types_map_to_their_workflows():
    assert cli.WORKFLOW_BY_TYPE['image_file'] == 'image'
    assert cli.WORKFLOW_BY_TYPE['wallet'] == 'wallet'


@pytest.mark.parametrize(
    'raw,expected',
    [
        ('0xAbCdEf0123456789aBCDef0123456789ABCDef01', '0xabcdef0123456789abcdef0123456789abcdef01'),
        ('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
        ('1BoatSLRHtKNngkdXEeobR76b53LETtpyT', '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'),  # base58 is case-sensitive
        ('TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7', 'TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7'),
    ],
)
def test_wallet_addresses_are_normalized(raw, expected):
    assert cli._normalize_input(raw, 'wallet') == expected


def test_image_paths_are_made_absolute(tmp_path, monkeypatch):
    image = tmp_path / 'photo.jpg'
    image.write_bytes(b'\xff\xd8\xff')
    monkeypatch.chdir(tmp_path)
    assert cli._normalize_input('photo.jpg', 'image_file') == str(image.resolve())


def test_auto_detection_routes_wallets(monkeypatch):
    monkeypatch.setattr(cli, 'detect_input_type', lambda s: 'wallet')
    assert cli._resolve('0xABCDEF0123456789ABCDEF0123456789ABCDEF01', 'auto', quiet=True) == (
        '0xabcdef0123456789abcdef0123456789abcdef01',
        'wallet',
    )


# --- C3: privacy categories ---


def test_privacy_categories_remove_only_what_is_kept(monkeypatch):
    monkeypatch.setattr(cli, 'CATEGORIES', frozenset({'secrets', 'personal', 'network', 'location', 'crypto'}))
    assert cli.privacy_categories() == {'secrets', 'personal', 'network', 'location', 'crypto'}
    assert cli.privacy_categories(keep_location=True, keep_crypto=True) == {'secrets', 'personal', 'network'}
    assert cli.privacy_categories(keep_network=True) == {'secrets', 'personal', 'location', 'crypto'}


def test_privacy_categories_tolerate_categories_not_yet_defined(monkeypatch):
    monkeypatch.setattr(cli, 'CATEGORIES', frozenset({'secrets', 'personal', 'network'}))
    assert cli.privacy_categories(keep_location=True, keep_crypto=True) == {'secrets', 'personal', 'network'}


def test_privacy_categories_need_a_real_boolean():
    assert cli.privacy_categories(keep_network='true') == cli.CATEGORIES  # type: ignore[arg-type]


def _run(monkeypatch, tmp_path, *args):
    source = Mock()
    source.fetch.return_value = {'A': ['93.184.215.14']}
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': source})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir(exist_ok=True)
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: only\n    type: dns\n',
        encoding='utf-8',
    )
    out = tmp_path / 'out'
    result = runner.invoke(
        app,
        ['run', 'example.com', '--workflow', 'generic', '--workflow-dir', str(wf_dir), '--output-dir', str(out), *args],
    )
    return result, source, out


@pytest.mark.parametrize(
    'flags,kept',
    [
        ([], set()),
        (['--keep-location'], {'location'}),
        (['--keep-crypto'], {'crypto'}),
        (['--keep-network', '--keep-location', '--keep-crypto'], {'network', 'location', 'crypto'}),
        (['--keep-device'], {'device'}),
    ],
)
def test_run_keep_flags_select_privacy_categories(monkeypatch, tmp_path, flags, kept):
    full = frozenset({'secrets', 'personal', 'network', 'location', 'crypto', 'device'})
    monkeypatch.setattr(cli, 'CATEGORIES', full)
    seen = []

    class SpyGuard(cli.PrivacyGuard):
        def __init__(self, categories=full, **kwargs):
            seen.append(set(categories))
            super().__init__(categories=set(categories) & {'secrets', 'personal', 'network'}, **kwargs)

    monkeypatch.setattr(cli, 'PrivacyGuard', SpyGuard)
    result, _, _ = _run(monkeypatch, tmp_path, '--quiet', *flags)
    assert result.exit_code == 0, result.output
    assert seen[0] == full - kept


# --- C7: --export ---


@pytest.fixture
def fake_export(monkeypatch):
    calls = []

    def export_correlations(correlations, fmt, path):
        calls.append((correlations, fmt, Path(path)))
        Path(path).write_text(fmt, encoding='utf-8')
        return Path(path)

    module = types.ModuleType('secure_osint.core.export')
    module.export_correlations = export_correlations  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, 'secure_osint.core.export', module)
    return calls


def test_export_writes_each_format_into_the_report_dir(monkeypatch, tmp_path, fake_export):
    result, _, out = _run(monkeypatch, tmp_path, '--export', 'graphml', '--export', 'maltego_csv', '--export', 'json')
    assert result.exit_code == 0, result.output
    assert [fmt for _, fmt, _ in fake_export] == ['graphml', 'maltego_csv', 'json']
    for _, fmt, path in fake_export:
        assert path.parent == out and path.exists()
    assert len({path for _, _, path in fake_export}) == 3  # one file per format, never overwritten
    assert all(isinstance(corr, dict) for corr, _, _ in fake_export)
    assert 'graphml' in result.output


def test_export_input_is_the_redacted_correlations(monkeypatch, tmp_path, fake_export):
    result, _, _ = _run(monkeypatch, tmp_path, '--quiet', '--export', 'json')
    assert result.exit_code == 0, result.output
    assert '93.184.215.14' not in repr(fake_export[0][0])


def test_export_format_repeated_is_written_once(monkeypatch, tmp_path, fake_export):
    result, _, _ = _run(monkeypatch, tmp_path, '--quiet', '--export', 'gexf', '--export', 'gexf')
    assert result.exit_code == 0, result.output
    assert [fmt for _, fmt, _ in fake_export] == ['gexf']


def test_export_rejects_unknown_formats(monkeypatch, tmp_path, fake_export):
    result, source, _ = _run(monkeypatch, tmp_path, '--export', 'pdf')
    assert result.exit_code == 2  # usage error from the CLI parser
    source.fetch.assert_not_called()


def test_export_without_the_module_fails_before_any_network_call(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, 'secure_osint.core.export', None)
    result, source, _ = _run(monkeypatch, tmp_path, '--export', 'json')
    assert result.exit_code == 1
    assert 'export' in result.output.lower() and 'Traceback' not in result.output
    source.fetch.assert_not_called()


def test_export_failure_keeps_the_reports_and_exits_nonzero(monkeypatch, tmp_path, fake_export):
    def broken(correlations, fmt, path):
        raise OSError('disk full')

    sys.modules['secure_osint.core.export'].export_correlations = broken  # type: ignore[attr-defined]
    result, _, out = _run(monkeypatch, tmp_path, '--export', 'json')
    assert result.exit_code == 1
    assert 'disk full' in result.output
    assert (out / 'latest.json').exists() and (out / 'latest.md').exists()


def test_report_paths_are_printed_literally(monkeypatch, tmp_path):
    source = Mock()
    source.fetch.return_value = {'A': ['1.1.1.1']}
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': source})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: only\n    type: dns\n',
        encoding='utf-8',
    )
    out = tmp_path / '[red]out'
    result = runner.invoke(
        app, ['run', 'example.com', '--workflow', 'generic', '--workflow-dir', str(wf_dir), '--output-dir', str(out)]
    )
    assert result.exit_code == 0, result.output
    assert '[red]out' in result.output.replace('\n', '')


# --- gui command ---


def test_gui_passes_output_dir_and_cache_ttl(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr('secure_osint.app.launch', lambda **kwargs: captured.update(kwargs))
    result = runner.invoke(
        app, ['gui', '--no-open-browser', '--output-dir', str(tmp_path), '--cache-ttl', '120', '--port', '9000']
    )
    assert result.exit_code == 0, result.output
    assert captured == {
        'host': '127.0.0.1',
        'port': 9000,
        'open_browser': False,
        'output_dir': str(tmp_path),
        'cache_ttl': 120,
    }


def test_gui_never_takes_credentials_on_the_command_line():
    command = typer.main.get_command(app).commands['gui']
    names = {opt for param in command.params for opt in getattr(param, 'opts', [])}
    assert '--host' in names  # the options were really inspected
    assert not any('auth' in n or 'pass' in n or 'user' in n for n in names)


def test_gui_refuses_non_loopback_without_credentials(monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_GUI_AUTH', raising=False)
    result = runner.invoke(app, ['gui', '--host', '0.0.0.0', '--no-open-browser'])
    assert result.exit_code == 1
    assert 'SECURE_OSINT_GUI_AUTH' in result.output


def test_confirmation_prompt_cannot_carry_escape_sequences(tmp_path):
    # A third-party workflow file controls the step type shown in the prompt.
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n'
        # YAML double-quoted escapes: \e is ESC, \a is BEL (an OSC 8 hyperlink terminator).
        '  - id: only\n    type: "dns\\e]8;;http://evil.example/\\ax"\n    require_confirmation: true\n',
        encoding='utf-8',
    )
    result = runner.invoke(
        app,
        ['run', 'example.com', '--workflow', 'generic', '--workflow-dir', str(wf_dir), '--output-dir', str(tmp_path)],
        input='n\n',
    )
    assert 'requires confirmation' in result.output
    assert '\x1b' not in result.output


def test_explicit_wallet_workflow_canonicalises_uppercase_bech32():
    from secure_osint.cli import _resolve

    value, workflow = _resolve('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'wallet', quiet=True)
    assert (value, workflow) == ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'wallet')


def test_image_run_never_writes_the_analysts_local_path(tmp_path):
    pytest.importorskip('exifread')
    from tests.test_image_exif import make_jpeg

    case_dir = tmp_path / 'secret-case-ACME'
    case_dir.mkdir()
    image = case_dir / 'p.jpg'
    image.write_bytes(make_jpeg())
    out = tmp_path / 'out'
    result = runner.invoke(
        app,
        [
            'run',
            str(image),
            '--output-dir',
            str(out),
            '--no-cache',
            '--quiet',
            '--yes',
            '--graph',
            '--export',
            'graphml',
            '--export',
            'maltego_csv',
            '--export',
            'json',
        ],
    )
    assert result.exit_code == 0, result.output
    written = [p for p in out.rglob('*') if p.is_file()]
    assert any(p.name == 'latest.json' for p in written)
    for path in written:
        text = path.read_text(encoding='utf-8', errors='replace')
        assert 'secret-case-ACME' not in text and str(tmp_path) not in text, path.name
