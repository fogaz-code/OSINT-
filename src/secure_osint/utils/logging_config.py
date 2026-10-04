import json
import logging
import os
import sys
from datetime import datetime, timezone

from secure_osint.config import SecretRedactingFilter

_STANDARD_ATTRS = set(vars(logging.makeLogRecord({}))) | {'message', 'asctime'}

# HTTP client loggers print every request URL at INFO/DEBUG, and a target inside a URL path
# (https://site/<username>/) has no shape a regex can recognise: they stay at WARNING unless this is '1'.
DEBUG_HTTP_ENV = 'SECURE_OSINT_DEBUG_HTTP'
HTTP_LOGGERS = ('httpx', 'httpcore')


class JsonFormatter(logging.Formatter):
    """One JSON line per event; fields passed with `extra=` become top-level keys."""

    def format(self, record: logging.LogRecord) -> str:
        """Render the log record as a single JSON line."""
        payload = {
            'ts': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'msg': record.getMessage(),
        }
        payload.update({k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS})
        # exc_text and stack_info have already been redacted by SecretRedactingFilter.
        if record.exc_text:
            payload['exc'] = record.exc_text
        elif record.exc_info:
            payload['exc'] = self.formatException(record.exc_info)
        if record.stack_info:
            payload['stack'] = record.stack_info
        return json.dumps(payload, default=str)


def configure_logging(level: str = 'WARNING', json_logs: bool = False) -> None:
    """Configure root logging. Every record is fully redacted (see SecretRedactingFilter).

    The ``httpx``/``httpcore`` loggers are forced to WARNING whatever ``level`` is, unless the
    environment sets SECURE_OSINT_DEBUG_HTTP=1 (then they follow ``level`` and a warning is logged).

    Args:
        level: Log level name.
        json_logs: If True, emit one JSON object per line.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter() if json_logs else logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    )
    handler.addFilter(SecretRedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Same filter on loggers that keep their own handlers (uvicorn under the GUI) and bypass the root one.
    from secure_osint.utils.log_redaction import protect_third_party_loggers

    protect_third_party_loggers()

    debug_http = os.environ.get(DEBUG_HTTP_ENV) == '1'
    for name in HTTP_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET if debug_http else logging.WARNING)
    if debug_http:
        logging.getLogger(__name__).warning(
            '%s=1: HTTP client logging is enabled; request hosts and investigation targets may appear in logs '
            '(URL paths, PII and hashes are still redacted)',
            DEBUG_HTTP_ENV,
        )


def ensure_redacted_logging(level: str = 'WARNING') -> None:
    """Install the redacting root handler unless one is already there.

    Without any root handler Python prints WARNING+ records through ``logging.lastResort``, which bypasses
    SecretRedactingFilter: an engine traceback would reach stderr with target data in clear. Entry points
    that may run without ``configure_logging`` (the GUI started as ``python -m secure_osint.app``) call this.
    """
    root = logging.getLogger()
    if any(isinstance(f, SecretRedactingFilter) for h in root.handlers for f in h.filters):
        return
    configure_logging(level)
