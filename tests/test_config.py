import logging
import os

import pytest
from typer.testing import CliRunner

from secure_osint import config
from secure_osint.core.privacy import PrivacyGuard
from secure_osint.utils import secure_fs
from tests.owner_only import assert_owner_only, make_permissive

VT_KEY = 'a' * 20 + '0123456789abcdef' * 2 + 'b' * 12  # 64 hex
SHODAN_KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz123456'  # 32 alnum
SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
MD5 = 'd41d8cd98f00b204e9800998ecf8427e'


def _write_env(content: str, owner_only: bool = True):
    path = config.env_file_path()
    secure_fs.write_private(path, content)
    if not owner_only:
        make_permissive(path)
    return path


# --- .env loading ---


def test_env_path_under_xdg_config(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'cfg'))
    assert config.env_file_path() == tmp_path / 'cfg' / 'secure_osint' / '.env'


def test_loads_allowed_keys(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    _write_env(f'VIRUSTOTAL_API_KEY={VT_KEY}\nSECURE_OSINT_USER_AGENT=test-agent\n')
    loaded = config.load_env_file()
    assert set(loaded) == {'VIRUSTOTAL_API_KEY', 'SECURE_OSINT_USER_AGENT'}
    assert os.environ['VIRUSTOTAL_API_KEY'] == VT_KEY


def test_does_not_override_existing_env(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'from-shell-wins')
    _write_env(f'VIRUSTOTAL_API_KEY={VT_KEY}\n')
    assert config.load_env_file() == []
    assert os.environ['VIRUSTOTAL_API_KEY'] == 'from-shell-wins'


def test_ignores_variables_outside_allowlist(monkeypatch, caplog):
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('HTTPS_PROXY', raising=False)
    _write_env('SSL_CERT_FILE=/tmp/evil-ca.pem\nHTTPS_PROXY=http://evil:8080\nPATH=/evil\n')
    with caplog.at_level(logging.WARNING):
        assert config.load_env_file() == []
    assert 'SSL_CERT_FILE' not in os.environ
    assert 'HTTPS_PROXY' not in os.environ
    assert os.environ['PATH'] != '/evil'
    assert 'SSL_CERT_FILE' in caplog.text


def test_never_reads_env_from_current_directory(tmp_path, monkeypatch):
    monkeypatch.delenv('URLSCAN_API_KEY', raising=False)
    (tmp_path / 'project').mkdir()
    (tmp_path / 'project' / '.env').write_text('URLSCAN_API_KEY=planted-by-cwd-0123456789\n')
    monkeypatch.chdir(tmp_path / 'project')
    config.load_env_file()
    assert 'URLSCAN_API_KEY' not in os.environ


def test_missing_file_is_fine():
    assert not config.env_file_path().exists()
    assert config.load_env_file() == []


def test_warns_on_permissive_permissions_and_restricts_the_file(caplog):
    path = _write_env('SHODAN_API_KEY=x\n', owner_only=False)
    with caplog.at_level(logging.WARNING):
        config.load_env_file()
    assert 'readable by other accounts' in caplog.text
    assert_owner_only(path)


def test_no_permission_warning_for_an_owner_only_env_file(caplog):
    # Regression: on Windows st_mode is always 0o666, so the old mode-bit check warned on every run.
    _write_env('SHODAN_API_KEY=x\n')
    with caplog.at_level(logging.WARNING):
        config.load_env_file()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING], caplog.text


def test_no_permission_warning_for_env_file_inheriting_from_secured_config_dir(caplog):
    # A user editing .env with a normal editor inside the (owner-only) config dir: nobody else can read it.
    secure_fs.secure_dir(config.config_dir())
    config.env_file_path().write_text('SHODAN_API_KEY=x\n', encoding='utf-8')
    if os.name != 'nt':
        os.chmod(config.env_file_path(), 0o600)
    with caplog.at_level(logging.WARNING):
        config.load_env_file()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING], caplog.text


def test_env_file_that_cannot_be_restricted_still_loads_with_a_warning(monkeypatch, caplog):
    monkeypatch.delenv('SHODAN_API_KEY', raising=False)
    _write_env('SHODAN_API_KEY=abcdefgh12345678\n', owner_only=False)
    monkeypatch.setattr(secure_fs, '_apply_owner_only', lambda path, is_dir: None)
    with caplog.at_level(logging.WARNING):
        assert config.load_env_file() == ['SHODAN_API_KEY']
    assert 'could not restrict' in caplog.text.lower()
    assert 'abcdefgh12345678' not in caplog.text


def test_no_interpolation(monkeypatch):
    monkeypatch.setenv('HOME_SECRET_SOURCE', 'leaked')
    monkeypatch.delenv('ALIENVAULT_API_KEY', raising=False)
    _write_env('ALIENVAULT_API_KEY=${HOME_SECRET_SOURCE}\n')
    config.load_env_file()
    assert os.environ['ALIENVAULT_API_KEY'] == '${HOME_SECRET_SOURCE}'


# --- key access ---


def test_get_api_key(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', f'  {VT_KEY}  ')
    monkeypatch.setenv('URLSCAN_API_KEY', '   ')
    assert config.get_api_key('VIRUSTOTAL_API_KEY') == VT_KEY
    assert config.get_api_key('URLSCAN_API_KEY') is None
    with pytest.raises(KeyError):
        config.get_api_key('RANDOM_THING')


def test_supported_keys_listed():
    assert {'VIRUSTOTAL_API_KEY', 'ALIENVAULT_API_KEY', 'URLSCAN_API_KEY', 'SHODAN_API_KEY', 'GITHUB_TOKEN'} <= set(
        config.API_KEYS
    )


def test_secret_values_from_env(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', VT_KEY)
    monkeypatch.setenv('SOMETHING_TOKEN', 'tok-0123456789')
    monkeypatch.setenv('MY_SECRET', 'short')  # troppo corto: redigerlo romperebbe testo normale
    monkeypatch.setenv('SECURE_OSINT_CACHE_KEY', 'c' * 44)
    monkeypatch.setenv('NOT_SENSITIVE', 'value-0123456789')
    values = config.secret_values()
    assert VT_KEY in values and 'tok-0123456789' in values and 'c' * 44 in values
    assert 'short' not in values and 'value-0123456789' not in values


# --- redaction ---


def test_configured_key_values_redacted_anywhere(monkeypatch):
    monkeypatch.setenv('SHODAN_API_KEY', SHODAN_KEY)
    text = f'request failed for https://api.example/?k={SHODAN_KEY}&x=1 ({SHODAN_KEY})'
    out = PrivacyGuard().redact(text)
    assert SHODAN_KEY not in out
    assert out.count('[REDACTED]') == 2


@pytest.mark.parametrize(
    'text',
    [
        f'apikey={VT_KEY}',
        f'x-apikey: {VT_KEY}',
        f'"x-apikey": "{VT_KEY}"',
        f'key={SHODAN_KEY}',
        f'API-Key: {SHODAN_KEY}',
    ],
)
def test_contextual_key_patterns(text):
    out = PrivacyGuard(categories={'secrets'}).redact(text)
    assert VT_KEY not in out and SHODAN_KEY not in out


@pytest.mark.parametrize(
    'text', [f'sha256 {SHA256}', f'md5: {MD5}', f'https://en.gravatar.com/{MD5}.json', f'{{"sha256": "{SHA256}"}}']
)
def test_bare_hashes_are_not_redacted(text):
    assert PrivacyGuard().redact(text) == text


def test_logging_filter_redacts_secrets(monkeypatch, caplog):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', VT_KEY)
    logger = logging.getLogger('secure_osint.test')
    handler_filter = config.SecretRedactingFilter()
    logger.addFilter(handler_filter)
    try:
        with caplog.at_level(logging.INFO):
            logger.info('calling with key %s', VT_KEY)
            logger.info('extra field', extra={'header': VT_KEY})
    finally:
        logger.removeFilter(handler_filter)
    assert VT_KEY not in caplog.text
    assert all(VT_KEY not in str(getattr(r, 'header', '')) for r in caplog.records)


def test_http_client_errors_do_not_leak_headers(monkeypatch):
    import httpx

    from secure_osint.sources.base import TransientSourceError
    from secure_osint.utils.http_client import SafeHttpClient
    from secure_osint.utils.resilience import HostPolicies

    client = SafeHttpClient(policies=HostPolicies())

    def boom(*args, **kwargs):
        raise httpx.ConnectError(f'failed with headers x-apikey={VT_KEY}')

    monkeypatch.setattr(client._client, 'stream', boom)
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1'])
    with pytest.raises(TransientSourceError) as info:
        client.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', headers={'x-apikey': VT_KEY})
    assert VT_KEY not in str(info.value)


# --- CLI ---


def test_cli_loads_env_file_and_keys_command_masks_values(monkeypatch):
    from secure_osint.cli import app

    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    monkeypatch.delenv('SHODAN_API_KEY', raising=False)
    _write_env(f'VIRUSTOTAL_API_KEY={VT_KEY}\n')
    result = CliRunner().invoke(app, ['keys'])
    assert result.exit_code == 0, result.output
    assert VT_KEY not in result.output
    lines = {line.split()[0]: line for line in result.output.splitlines() if line.strip()}
    assert 'set' in lines['VIRUSTOTAL_API_KEY'] and 'not set' not in lines['VIRUSTOTAL_API_KEY']
    assert 'not set' in lines['SHODAN_API_KEY']
    assert_owner_only(config.env_file_path())


def test_json_logs_redact_secrets_in_tracebacks(monkeypatch):
    import io
    import json

    from secure_osint.utils.logging_config import configure_logging

    monkeypatch.setenv('URLSCAN_API_KEY', 'urlscan-key-0123456789abcdef')
    stream = io.StringIO()
    configure_logging('INFO', json_logs=True)
    handler = logging.getLogger().handlers[0]
    handler.setStream(stream)  # type: ignore[attr-defined]
    try:
        raise RuntimeError('auth failed for urlscan-key-0123456789abcdef')
    except RuntimeError:
        logging.getLogger('secure_osint.test').exception('boom with %s', 'urlscan-key-0123456789abcdef')
    finally:
        logging.getLogger().handlers.clear()
    output = stream.getvalue()
    assert 'urlscan-key-0123456789abcdef' not in output
    record = json.loads(output.strip().splitlines()[-1])
    assert 'RuntimeError' in record['exc'] and '[REDACTED]' in record['exc']
