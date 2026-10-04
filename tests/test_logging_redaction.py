"""Logs are always fully redacted: every PrivacyGuard category, regardless of --keep-* flags.

Regression tests for the leak where the report redacted a resolved IP while stderr printed it raw,
username runs logged ``GET https://www.instagram.com/<target>/`` and email runs logged the Gravatar MD5.
"""

import io
import json
import logging
import sys
from unittest import mock

import httpx
import pytest
from typer.testing import CliRunner

from secure_osint import config
from secure_osint.core import privacy
from secure_osint.utils.logging_config import DEBUG_HTTP_ENV, configure_logging

IP = '93.184.216.34'
EMAIL = 'john.target@example.com'
TRON = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
MD5 = 'd41d8cd98f00b204e9800998ecf8427e'
USERNAME = 'john_target_x'
HTTP_LOGGERS = ('httpx', 'httpcore')


@pytest.fixture(autouse=True)
def restore_logging(monkeypatch):
    monkeypatch.delenv(DEBUG_HTTP_ENV, raising=False)
    privacy.clear_sensitive_values()  # targets registered by earlier CLI tests in the same process
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    saved_http = {name: logging.getLogger(name).level for name in HTTP_LOGGERS}
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    for name, level in saved_http.items():
        logging.getLogger(name).setLevel(level)
    privacy.clear_sensitive_values()


def _capture(level: str = 'INFO', json_logs: bool = False) -> io.StringIO:
    # The handler binds sys.stderr when it is created, so patch it around configure_logging: records
    # emitted by configure_logging itself (the SECURE_OSINT_DEBUG_HTTP warning) are captured too.
    stream = io.StringIO()
    with mock.patch.object(sys, 'stderr', stream):
        configure_logging(level, json_logs)
    return stream


log = logging.getLogger('secure_osint.test_logging')


# --- PrivacyGuard categories in every part of the record ---


def test_message_and_args_are_redacted():
    stream = _capture()
    log.info('resolved %s for %s, wallet %s', IP, EMAIL, TRON)
    log.info(f'inline {IP} and {EMAIL}')
    out = stream.getvalue()
    assert IP not in out and EMAIL not in out and TRON not in out
    assert out.count('[REDACTED]') == 5


def test_extra_fields_are_redacted_including_structures_and_location_keys():
    stream = _capture(json_logs=True)
    log.info(
        'step data',
        extra={'target_ip': IP, 'emails': [EMAIL], 'gps': {'latitude': 45.4642}, 'latitude': 45.4642, 'n': 3},
    )
    record = json.loads(stream.getvalue().strip())
    assert IP not in stream.getvalue() and EMAIL not in stream.getvalue() and '45.4642' not in stream.getvalue()
    assert record['target_ip'] == '[REDACTED]'
    assert record['emails'] == ['[REDACTED]']
    assert record['gps'] == '[REDACTED]' and record['latitude'] == '[REDACTED]'
    assert record['n'] == 3


def test_tracebacks_are_redacted():
    stream = _capture()
    try:
        raise ValueError(f'lookup failed for {EMAIL} at {IP}')
    except ValueError:
        log.exception('boom')
    out = stream.getvalue()
    assert 'ValueError' in out and 'Traceback' in out
    assert EMAIL not in out and IP not in out


def test_stack_info_is_redacted():
    stream = _capture()

    def inner(target: str) -> None:
        log.info('trace %s', target, stack_info=True)

    inner(EMAIL)
    assert EMAIL not in stream.getvalue() and 'Stack (most recent call last)' in stream.getvalue()


def test_bad_format_args_do_not_crash_the_caller():
    stream = _capture()
    log.info('%s and %s', IP)  # one argument short
    assert IP not in stream.getvalue()


def test_secret_values_still_scrubbed(monkeypatch):
    monkeypatch.setenv('URLSCAN_API_KEY', 'urlscan-key-0123456789abcdef')
    stream = _capture()
    log.info('auth with %s', 'urlscan-key-0123456789abcdef')
    assert 'urlscan-key-0123456789abcdef' not in stream.getvalue()


def test_filter_redacts_all_categories_even_when_a_run_keeps_some():
    # The filter has no category knob: --keep-network/--keep-location/--keep-crypto only affect reports.
    record = logging.makeLogRecord({'msg': 'ip %s at 45.464211, 9.190031 %s', 'args': (IP, TRON)})
    config.SecretRedactingFilter().filter(record)
    assert record.getMessage() == 'ip [REDACTED] at [REDACTED] [REDACTED]'


# --- log-only rules: URL paths, hosts, hashes, registered targets ---


@pytest.mark.parametrize(
    'url, kept, hidden',
    [
        (f'https://www.instagram.com/{USERNAME}/', 'www.instagram.com', USERNAME),
        (f'https://github.com/{USERNAME}?tab=repos', 'github.com', USERNAME),
        (f'https://{USERNAME}.tumblr.com/', 'tumblr.com', USERNAME),
        (f'https://en.gravatar.com/{MD5}.json', 'gravatar.com', MD5),
        (f'https://user:hunter2pass@example.com/x/{USERNAME}', 'example.com', 'hunter2pass'),
        (f'http://{IP}:8080/{USERNAME}', ':8080', IP),
    ],
)
def test_url_paths_and_target_subdomains_are_hidden(url, kept, hidden):
    stream = _capture()
    log.warning('request failed: GET %s', url)
    out = stream.getvalue()
    assert hidden not in out and USERNAME not in out
    assert kept in out


def test_bare_hashes_are_redacted_in_logs_only():
    stream = _capture()
    log.info('gravatar hash %s', MD5)
    assert MD5 not in stream.getvalue()
    # Reports keep hashes (VirusTotal SHA-256, Gravatar MD5 are legitimate OSINT data).
    assert privacy.PrivacyGuard().redact(MD5) == MD5


def test_registered_targets_are_scrubbed_case_insensitively():
    privacy.register_sensitive_values([USERNAME, 'ab', '  '])  # too-short values are ignored
    stream = _capture()
    log.info('no profile for %s / %s / %s', USERNAME, USERNAME.upper(), 'about')
    out = stream.getvalue()
    assert USERNAME not in out and USERNAME.upper() not in out
    assert 'about' in out  # 'ab' was not registered: would shred ordinary words


def test_registered_target_url_encoded_form_is_scrubbed():
    privacy.register_sensitive_values(['john doe+osint'])
    stream = _capture()
    log.info('query john%20doe%2Bosint and john doe+osint')
    assert 'john%20doe%2Bosint' not in stream.getvalue() and 'john doe+osint' not in stream.getvalue()


# --- HTTP client loggers ---


def test_http_loggers_forced_to_warning_even_at_debug():
    configure_logging('DEBUG')
    assert logging.getLogger().level == logging.DEBUG
    for name in HTTP_LOGGERS:
        assert logging.getLogger(name).getEffectiveLevel() == logging.WARNING


def _mock_request(url: str) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(404, request=request))
    with httpx.Client(transport=transport) as client:
        client.get(url)


def test_debug_level_run_emits_no_target_url():
    stream = _capture('DEBUG')
    _mock_request(f'https://www.instagram.com/{USERNAME}/')
    _mock_request(f'https://en.gravatar.com/{MD5}.json')
    out = stream.getvalue()
    assert USERNAME not in out and MD5 not in out and 'instagram' not in out


def test_debug_http_env_reenables_http_logs_with_a_warning(monkeypatch):
    monkeypatch.setenv(DEBUG_HTTP_ENV, '1')
    stream = _capture('DEBUG')
    for name in HTTP_LOGGERS:
        assert logging.getLogger(name).getEffectiveLevel() == logging.DEBUG
    _mock_request(f'https://en.gravatar.com/{MD5}.json?email={EMAIL}')
    out = stream.getvalue()
    assert DEBUG_HTTP_ENV in out and 'WARNING' in out
    assert 'HTTP Request: GET https://en.gravatar.com/' in out  # URLs are what this mode is for
    # ...but PII categories and hashes stay redacted even in HTTP debug mode.
    assert MD5 not in out and EMAIL not in out


def test_debug_http_env_other_values_do_not_enable(monkeypatch):
    monkeypatch.setenv(DEBUG_HTTP_ENV, 'yes')
    configure_logging('DEBUG')
    assert logging.getLogger('httpx').getEffectiveLevel() == logging.WARNING


# --- end to end through the CLI ---


def test_cli_debug_run_with_keep_network_logs_nothing_identifying(monkeypatch, tmp_path):
    from secure_osint.cli import app
    from secure_osint.core.workflow import StepResult, StepStatus

    def fake_execute(self, wf, target):
        _mock_request(f'https://www.instagram.com/{target}/')
        logging.getLogger('secure_osint.sources.fake').info('resolved %s for %s', IP, target)
        logging.getLogger('secure_osint.sources.fake').warning('profile %s returned 404', target)
        return {'username_check': StepResult(status=StepStatus.SUCCESS, data={'platforms': []})}

    monkeypatch.setattr('secure_osint.core.engine.WorkflowEngine.execute', fake_execute)
    result = CliRunner().invoke(
        app,
        [
            'run',
            USERNAME,
            '--workflow',
            'username',
            '--log-level',
            'DEBUG',
            '--keep-network',
            '--no-cache',
            '-q',
            '--output-dir',
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert 'profile [REDACTED] returned 404' in result.stderr
    assert USERNAME not in result.stderr
    assert IP not in result.stderr  # --keep-network reveals IPs in the report, never in logs
    assert 'instagram' not in result.stderr


def test_non_serialisable_extra_objects_are_stringified_and_redacted():
    class Target:
        def __str__(self) -> str:
            return f'Target({EMAIL}, {IP})'

    stream = _capture(json_logs=True)
    log.warning('lookup', extra={'target': Target()})
    record = json.loads(stream.getvalue().strip())
    assert record['target'] == 'Target([REDACTED], [REDACTED])'


def test_ensure_redacted_logging_installs_the_filter_once(monkeypatch):
    import logging

    from secure_osint.config import SecretRedactingFilter
    from secure_osint.utils.logging_config import ensure_redacted_logging

    root = logging.getLogger()
    monkeypatch.setattr(root, 'handlers', [])
    ensure_redacted_logging()
    assert len(root.handlers) == 1
    assert any(isinstance(f, SecretRedactingFilter) for f in root.handlers[0].filters)
    first = root.handlers[0]
    ensure_redacted_logging()
    assert root.handlers == [first]  # an existing redacting handler is kept, not replaced


def test_gui_launch_installs_redacting_logging_before_anything_else(monkeypatch):
    import logging

    from secure_osint import app as gui_app
    from secure_osint.config import SecretRedactingFilter

    root = logging.getLogger()
    monkeypatch.setattr(root, 'handlers', [])

    def stop(*args, **kwargs):
        raise RuntimeError('stop before starting the server')

    monkeypatch.setattr(gui_app, 'build_ui', stop)
    try:
        gui_app.launch(open_browser=False)
    except RuntimeError:
        pass
    assert any(isinstance(f, SecretRedactingFilter) for h in root.handlers for f in h.filters)
