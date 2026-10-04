import logging
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig
from secure_osint.sources.base import SourceUnavailable
from secure_osint.utils import secure_fs
from secure_osint.utils.cache import ResultCache, load_or_create_key
from secure_osint.utils.secure_fs import InsecurePermissionsError
from tests.owner_only import assert_owner_only, make_permissive

PARAMS = {'input': 'target.example.com', 'upstream': {}}
DATA = {'contact': 'admin@target.example.com', 'A': ['93.184.215.14']}


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def key():
    return Fernet.generate_key()


@pytest.fixture
def cache(tmp_path, key):
    c = ResultCache(tmp_path / 'cache', key=key, default_ttl=3600, clock=Clock())
    yield c
    c.close()


def _all_bytes(directory: Path) -> bytes:
    return b''.join(p.read_bytes() for p in directory.rglob('*') if p.is_file())


def test_roundtrip(cache):
    cache.set('dns', PARAMS, DATA)
    assert cache.get('dns', PARAMS) == DATA


def test_miss_on_different_source_or_params(cache):
    cache.set('dns', PARAMS, DATA)
    assert cache.get('rdap', PARAMS) is None
    assert cache.get('dns', {**PARAMS, 'input': 'other.example.com'}) is None


def test_param_order_does_not_matter(cache):
    cache.set('dns', {'a': 1, 'input': 'x.example.com'}, DATA)
    assert cache.get('dns', {'input': 'x.example.com', 'a': 1}) == DATA


def test_nothing_stored_in_plaintext(cache, tmp_path):
    cache.set('dns', PARAMS, DATA)
    cache.close()
    raw = _all_bytes(tmp_path / 'cache')
    for needle in (b'target.example.com', b'admin@', b'93.184.215.14', b'"dns"'):
        assert needle not in raw


def test_expiry(cache):
    cache.set('dns', PARAMS, DATA, ttl=60)
    cache.clock.now += 59
    assert cache.get('dns', PARAMS) == DATA
    cache.clock.now += 2
    assert cache.get('dns', PARAMS) is None


def test_zero_ttl_does_not_store(cache):
    cache.set('dns', PARAMS, DATA, ttl=0)
    assert cache.get('dns', PARAMS) is None
    assert len(cache.audit()) == 0


def test_wrong_key_is_a_miss_not_a_crash(tmp_path, key):
    first = ResultCache(tmp_path / 'cache', key=key)
    first.set('dns', PARAMS, DATA)
    first.close()
    other = ResultCache(tmp_path / 'cache', key=Fernet.generate_key())
    assert other.get('dns', PARAMS) is None
    other.close()


def _break_enforcement(monkeypatch):
    """Simulate a filesystem where owner-only cannot be applied (FAT32, SMB share, foreign owner...)."""
    monkeypatch.setattr(secure_fs, '_apply_owner_only', lambda path, is_dir: None)
    monkeypatch.setattr(secure_fs, 'is_owner_only', lambda path: False)


def test_wrong_key_never_deletes_entries(tmp_path, key, caplog):
    # Regression: an undecryptable entry used to be deleted, so a rotated/lost key silently wiped the cache.
    first = ResultCache(tmp_path / 'cache', key=key)
    first.set('dns', PARAMS, DATA)
    first.close()
    other = ResultCache(tmp_path / 'cache', key=Fernet.generate_key())
    with caplog.at_level(logging.WARNING):
        assert other.get('dns', PARAMS) is None
        assert other.audit() == []
    other.close()
    again = ResultCache(tmp_path / 'cache', key=key)
    assert again.get('dns', PARAMS) == DATA
    again.close()


def test_undecryptable_entry_warns_once_without_target_data(tmp_path, key, caplog):
    first = ResultCache(tmp_path / 'cache', key=key)
    first.set('dns', PARAMS, DATA)
    first.set('email', {'input': 'someone@example.org'}, {'email_domain': 'example.org'})
    first.close()
    other = ResultCache(tmp_path / 'cache', key=Fernet.generate_key())
    with caplog.at_level(logging.WARNING):
        other.audit()
        other.audit()
    other.close()
    warnings = [r for r in caplog.records if 'decrypt' in r.getMessage()]
    assert len(warnings) == 1
    for needle in ('target.example.com', 'someone@example.org', 'admin@', 'dns'):
        assert needle not in caplog.text


def test_audit_reports_undecryptable_count(tmp_path, key):
    first = ResultCache(tmp_path / 'cache', key=key)
    first.set('dns', PARAMS, DATA)
    first.set('email', {'input': 'someone@example.org'}, {'email_domain': 'example.org'})
    first.close()
    other = ResultCache(tmp_path / 'cache', key=Fernet.generate_key())
    other.set('rdap', PARAMS, DATA)
    report = other.audit()
    assert [e.source for e in report] == ['rdap']
    assert report.undecryptable == 2
    other.close()


def test_audit_undecryptable_is_zero_when_all_readable(cache):
    cache.set('dns', PARAMS, DATA)
    assert cache.audit().undecryptable == 0


def test_directory_is_private(cache, tmp_path):
    assert_owner_only(tmp_path / 'cache')


def test_existing_permissive_cache_directory_is_resecured(tmp_path, key):
    directory = tmp_path / 'cache'
    directory.mkdir()
    make_permissive(directory)
    ResultCache(directory, key=key).close()
    assert_owner_only(directory)


@pytest.mark.skipif(os.name != 'nt', reason='Windows: bypass-traverse lets others open files by path')
def test_existing_cache_files_granting_other_accounts_are_resecured(tmp_path, key):
    directory = tmp_path / 'cache'
    first = ResultCache(directory, key=key)
    first.set('dns', PARAMS, DATA)
    first.close()
    db = directory / 'cache.db'
    # An explicit Everyone:read ACE survives the directory's owner-only inheritance.
    secure_fs._apply_sddl(db, f'D:P(A;;FA;;;{secure_fs.current_user_sid()})(A;;FR;;;WD)')
    assert not secure_fs.grants_only_current_user(db)
    ResultCache(directory, key=key).close()
    assert secure_fs.grants_only_current_user(db)


def test_cache_directory_that_cannot_be_secured_fails_closed(tmp_path, key, monkeypatch):
    _break_enforcement(monkeypatch)
    with pytest.raises(InsecurePermissionsError):
        ResultCache(tmp_path / 'cache', key=key)


def test_key_file_created_private_and_reused(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)
    key_path = tmp_path / 'config' / 'cache.key'
    first = load_or_create_key(key_path)
    assert_owner_only(key_path)
    assert_owner_only(key_path.parent)
    assert load_or_create_key(key_path) == first
    Fernet(first)  # chiave valida


def test_existing_permissive_key_warns_and_is_resecured(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)
    key_path = tmp_path / 'config' / 'cache.key'
    first = load_or_create_key(key_path)
    make_permissive(key_path)
    with caplog.at_level(logging.WARNING):
        assert load_or_create_key(key_path) == first
    assert 'compromised' in caplog.text
    assert first.decode() not in caplog.text
    assert_owner_only(key_path)


def test_key_that_cannot_be_secured_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)
    _break_enforcement(monkeypatch)
    key_path = tmp_path / 'config' / 'cache.key'
    with pytest.raises(InsecurePermissionsError):
        load_or_create_key(key_path)
    assert not key_path.exists()  # never leave a key behind with unverified permissions


def test_existing_key_that_cannot_be_resecured_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)
    key_path = tmp_path / 'config' / 'cache.key'
    load_or_create_key(key_path)
    make_permissive(key_path)
    monkeypatch.setattr(secure_fs, '_apply_owner_only', lambda path, is_dir: None)
    with pytest.raises(InsecurePermissionsError):
        load_or_create_key(key_path)


@pytest.mark.skipif(os.name == 'nt', reason='symlink creation needs a privilege on Windows')
def test_key_path_that_is_a_symlink_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)
    real = tmp_path / 'elsewhere.key'
    real.write_bytes(Fernet.generate_key())
    os.chmod(real, 0o600)
    key_path = tmp_path / 'config' / 'cache.key'
    key_path.parent.mkdir(mode=0o700)
    key_path.symlink_to(real)
    with pytest.raises(InsecurePermissionsError):
        load_or_create_key(key_path)


def test_key_from_environment_wins(tmp_path, monkeypatch, key):
    monkeypatch.setenv('SECURE_OSINT_CACHE_KEY', key.decode())
    assert load_or_create_key(tmp_path / 'never-created.key') == key
    assert not (tmp_path / 'never-created.key').exists()


def test_key_must_not_live_inside_cache_dir(tmp_path, key):
    with pytest.raises(ValueError):
        ResultCache(tmp_path / 'cache', key_path=tmp_path / 'cache' / 'cache.key')


def test_clear(cache):
    cache.set('dns', PARAMS, DATA)
    assert cache.clear() == 1
    assert cache.get('dns', PARAMS) is None


def test_audit_reports_entries_without_leaking_pii(cache):
    cache.set('dns', PARAMS, DATA)
    cache.set('email', {'input': 'someone@example.org'}, {'email_domain': 'example.org'})
    entries = {e.source: e for e in cache.audit()}
    assert set(entries) == {'dns', 'email'}
    assert entries['dns'].input == 'target.example.com'
    assert entries['email'].input == '[REDACTED]'
    assert entries['dns'].pii == {'email': 1, 'ipv4': 1}
    assert entries['dns'].expires_at - entries['dns'].stored_at == 3600
    assert entries['dns'].size > 0


# --- integrazione con l'engine ---


def _wf(**kw):
    return WorkflowConfig(
        name='t', description='d', input_type='g', risk='low', steps=[StepConfig(id='a', type='x', **kw)]
    )


def test_engine_cache_hit_skips_fetch(cache):
    src = Mock(cacheable=True)
    src.fetch.return_value = DATA
    engine = WorkflowEngine(catalog={'x': src}, cache=cache, backoff=lambda a: 0)
    first = engine.execute(_wf(), 'target.example.com')['a']
    second = engine.execute(_wf(), 'target.example.com')['a']
    assert src.fetch.call_count == 1
    assert (first.cached, second.cached) == (False, True)
    assert second.status == StepStatus.SUCCESS and second.data == DATA


def test_engine_does_not_cache_failures(cache):
    src = Mock(cacheable=True)
    src.fetch.side_effect = SourceUnavailable('down')
    engine = WorkflowEngine(catalog={'x': src}, cache=cache, backoff=lambda a: 0)
    engine.execute(_wf(), 'in')
    engine.execute(_wf(), 'in')
    assert src.fetch.call_count == 2


def test_engine_respects_non_cacheable_sources(cache):
    src = Mock(cacheable=False)
    src.fetch.return_value = DATA
    engine = WorkflowEngine(catalog={'x': src}, cache=cache)
    engine.execute(_wf(), 'in')
    engine.execute(_wf(), 'in')
    assert src.fetch.call_count == 2


# --- CLI ---


def _cli_env(tmp_path, monkeypatch, key):
    monkeypatch.setenv('SECURE_OSINT_CACHE_DIR', str(tmp_path / 'cache'))
    monkeypatch.setenv('SECURE_OSINT_CACHE_KEY', key.decode())
    src = Mock(cacheable=True)
    src.fetch.return_value = DATA
    monkeypatch.setattr('secure_osint.sources.tool_catalog.tool_catalog', {'dns': src})
    wf_dir = tmp_path / 'wf'
    wf_dir.mkdir()
    (wf_dir / 'generic.yaml').write_text(
        'name: g\ndescription: d\ninput_type: generic\nrisk: low\nsteps:\n  - id: only\n    type: dns\n'
    )
    return src, ['--workflow', 'generic', '--workflow-dir', str(wf_dir), '--output-dir', str(tmp_path / 'out'), '-q']


def test_cli_caches_by_default_and_no_cache_bypasses(tmp_path, monkeypatch, key):
    from secure_osint.cli import app

    src, args = _cli_env(tmp_path, monkeypatch, key)
    runner = CliRunner()
    for extra in ([], [], ['--no-cache']):
        assert runner.invoke(app, ['run', 'example.com', *args, *extra]).exit_code == 0
    assert src.fetch.call_count == 2  # 1 miss, 1 hit, 1 bypass


def test_cli_audit_and_clear(tmp_path, monkeypatch, key):
    from secure_osint.cli import app

    _, args = _cli_env(tmp_path, monkeypatch, key)
    runner = CliRunner()
    runner.invoke(app, ['run', 'example.com', *args])
    audit = runner.invoke(app, ['cache-audit'])
    assert audit.exit_code == 0
    assert 'dns' in audit.output and 'email' in audit.output  # categoria PII rilevata
    assert 'admin@target.example.com' not in audit.output
    assert 'could not be decrypted' not in audit.output
    cleared = runner.invoke(app, ['cache-clear'])
    assert cleared.exit_code == 0 and '1' in cleared.output
    assert 'No cached entries' in runner.invoke(app, ['cache-audit']).output


@pytest.mark.parametrize('command', ['cache-audit', 'cache-clear'])
def test_cli_cache_commands_fail_cleanly_when_cache_cannot_be_secured(monkeypatch, command):
    from secure_osint.cli import app

    def refuse(*args, **kwargs):
        raise InsecurePermissionsError('cannot restrict the cache directory to the current user')

    monkeypatch.setattr('secure_osint.utils.cache.ResultCache', refuse)
    result = CliRunner().invoke(app, [command])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)  # typer.Exit, not an uncaught traceback
    assert 'Error: cache unavailable (cannot restrict the cache directory' in result.output


def test_engine_does_not_cache_partial_results(cache):
    src = Mock(cacheable=True)
    src.fetch.return_value = {'A': ['1.1.1.1'], 'errors': {'TXT': 'timeout'}}
    engine = WorkflowEngine(catalog={'x': src}, cache=cache)
    engine.execute(_wf(), 'in')
    engine.execute(_wf(), 'in')
    assert src.fetch.call_count == 2


def test_cli_audit_shows_undecryptable_entries(tmp_path, monkeypatch, key):
    from secure_osint.cli import app

    _, args = _cli_env(tmp_path, monkeypatch, key)
    runner = CliRunner()
    runner.invoke(app, ['run', 'example.com', *args])
    monkeypatch.setenv('SECURE_OSINT_CACHE_KEY', Fernet.generate_key().decode())
    audit = runner.invoke(app, ['cache-audit'])
    assert audit.exit_code == 0
    assert '1 cached entries could not be decrypted' in audit.output


def test_cli_run_disables_cache_when_it_cannot_be_secured(tmp_path, monkeypatch, key):
    from secure_osint.cli import app

    src, args = _cli_env(tmp_path, monkeypatch, key)
    _break_enforcement(monkeypatch)
    monkeypatch.setattr('secure_osint.core.reporter._write_private', lambda path, content: None)
    result = CliRunner().invoke(app, ['run', 'example.com', *args])
    assert result.exit_code == 0, result.output
    assert 'cache disabled' in result.output
    assert src.fetch.call_count == 1
