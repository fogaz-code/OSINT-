"""Where the project's single log filter (``config.SecretRedactingFilter``) gets attached.

Exceptions raised while investigating a target carry the target's data in their message (``boom while
contacting admin@example.com``) and therefore in the traceback. ``configure_logging`` puts the filter on
the root handler; that is not enough on its own:

* a record from a module logger is printed by ``logging.lastResort`` when no handler is configured
  (library use, ``python -m secure_osint.app``): ``redacting_logger`` attaches the filter to the logger
  itself, so its records are redacted before any handler sees them;
* third-party loggers with their own handlers and ``propagate=False`` (uvicorn, which serves the GUI)
  never reach the root handler: ``protect_third_party_loggers`` attaches the filter to them.

There is one filter class, so every path redacts exactly the same way: secrets, every privacy
category, the log-only rules (hashes, URL paths) and the run's targets.
"""

import logging

from secure_osint.config import SecretRedactingFilter

# Loggers that install their own handlers and may not propagate to the root handler. Logger filters
# apply only to records created on that exact logger, so each name is listed.
THIRD_PARTY_LOGGERS = (
    'uvicorn',
    'uvicorn.error',
    'uvicorn.access',
    'gradio',
    'httpx',
    'httpcore',
    'fastapi',
    'starlette',
)


def _attach(logger: logging.Logger) -> logging.Logger:
    if not any(isinstance(f, SecretRedactingFilter) for f in logger.filters):
        logger.addFilter(SecretRedactingFilter())
    return logger


def redacting_logger(name: str) -> logging.Logger:
    """``logging.getLogger(name)`` with exactly one ``SecretRedactingFilter`` attached."""
    return _attach(logging.getLogger(name))


def protect_third_party_loggers() -> None:
    """Attach the filter to every logger in ``THIRD_PARTY_LOGGERS`` (idempotent)."""
    for name in THIRD_PARTY_LOGGERS:
        _attach(logging.getLogger(name))
