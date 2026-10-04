import logging
import sys

from secure_osint.config import SecretRedactingFilter
from secure_osint.utils.log_redaction import THIRD_PARTY_LOGGERS, protect_third_party_loggers, redacting_logger


def _record(msg, args=None, exc_info=None, **extra):
    record = logging.LogRecord('t', logging.ERROR, __file__, 1, msg, args, exc_info)
    record.__dict__.update(extra)
    return record


def test_message_and_args_are_redacted():
    record = _record('contacting %s', ('admin@example.com',))
    assert SecretRedactingFilter().filter(record) is True
    assert 'admin@example.com' not in record.getMessage() and record.args is None


def test_traceback_and_extra_fields_are_redacted():
    try:
        raise RuntimeError('boom for admin@example.com at 203.0.113.9')
    except RuntimeError:
        record = _record('failed', exc_info=sys.exc_info(), target='admin@example.com')
    SecretRedactingFilter().filter(record)
    text = logging.Formatter('%(message)s %(target)s').format(record)
    assert 'Traceback' in text and 'RuntimeError' in text
    assert 'admin@example.com' not in text and '203.0.113.9' not in text


def test_broken_format_string_keeps_the_record_without_leaking_args():
    record = _record('bad %d format for admin@example.com', ('not-a-number',))
    assert SecretRedactingFilter().filter(record) is True
    assert 'admin@example.com' not in record.getMessage()


def test_logs_are_always_fully_redacted():
    record = _record('ip 203.0.113.9 wallet 0x52908400098527886E0F7030069857D2E4169EE7')
    SecretRedactingFilter().filter(record)  # no --keep-* flag reaches the log filter
    assert '203.0.113.9' not in record.getMessage() and '0x5290' not in record.getMessage()


def test_a_second_pass_on_the_same_record_is_a_no_op(monkeypatch):
    from secure_osint.core import privacy

    record = _record('ip 203.0.113.9')
    SecretRedactingFilter().filter(record)
    calls = []
    monkeypatch.setattr(privacy, 'log_guard', lambda: calls.append(1))
    SecretRedactingFilter().filter(record)  # logger filter, then root handler filter
    assert calls == []


def test_redacting_logger_attaches_one_filter():
    first = redacting_logger('secure_osint.test_log_redaction')
    second = redacting_logger('secure_osint.test_log_redaction')
    assert first is second
    assert sum(isinstance(f, SecretRedactingFilter) for f in first.filters) == 1


def test_third_party_loggers_with_their_own_handlers_are_redacted(monkeypatch):
    # uvicorn configures its own handlers and does not propagate: the root handler never sees it.
    protect_third_party_loggers()
    protect_third_party_loggers()
    for name in THIRD_PARTY_LOGGERS:
        assert sum(isinstance(f, SecretRedactingFilter) for f in logging.getLogger(name).filters) == 1
    logger = logging.getLogger('uvicorn.error')
    seen = []

    class Capture(logging.Handler):
        def emit(self, record):
            seen.append(self.format(record))

    monkeypatch.setattr(logger, 'handlers', [Capture()])
    monkeypatch.setattr(logger, 'propagate', False)
    logger.error('request for admin@example.com from 203.0.113.9')
    assert seen and 'admin@example.com' not in seen[0] and '203.0.113.9' not in seen[0]
