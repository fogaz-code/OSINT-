"""Configurazione da ambiente e da ~/.config/secure_osint/.env (mai dalla directory corrente).

Il file .env può impostare solo le API key note e le variabili SECURE_OSINT_*: variabili come
SSL_CERT_FILE o HTTPS_PROXY cambierebbero il comportamento di rete e vengono ignorate.
Le variabili già presenti nell'ambiente hanno sempre la precedenza.
"""

import logging
import weakref
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import dotenv_values

from secure_osint.utils import secure_fs

logger = logging.getLogger(__name__)

# Nome variabile -> uso. Solo queste (più SECURE_OSINT_*) possono arrivare dal file .env.
API_KEYS: Dict[str, str] = {
    'GITHUB_TOKEN': 'github: optional, raises the API rate limit',
    'VIRUSTOTAL_API_KEY': 'virustotal: required (free tier 4 req/min)',
    'ALIENVAULT_API_KEY': 'alienvault_otx: required',
    'URLSCAN_API_KEY': 'urlscan: required',
    'SHODAN_API_KEY': 'reserved for the full Shodan API (shodan_internetdb needs no key)',
}
SECRET_SUFFIXES = ('_API_KEY', '_TOKEN', '_SECRET')
EXTRA_SECRET_VARS = ('SECURE_OSINT_CACHE_KEY',)
# Valori più corti non vengono redatti: sostituirli ovunque romperebbe testo normale.
MIN_SECRET_LENGTH = 8


def config_dir() -> Path:
    """Return the per-user config directory for the tool."""
    base = os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config'
    return Path(base) / 'secure_osint'


def env_file_path() -> Path:
    """Return the path of the user .env file (never read from the current directory)."""
    return config_dir() / '.env'


def _allowed(name: str) -> bool:
    return name in API_KEYS or name.startswith('SECURE_OSINT_')


def _restrict_env_file(path: Path) -> None:
    """Warn if the .env (API keys) is readable by other accounts and restrict it to the current user.

    Uses the effective ACL on Windows, where mode bits are meaningless (st_mode is always 0o666).
    Never blocks loading: the keys are already exposed, refusing them would only break the run.
    """
    if secure_fs.grants_only_current_user(path):
        return
    logger.warning('%s is readable by other accounts but contains API keys: restricting it to the current user', path)
    try:
        secure_fs.secure_file(path)
    except OSError as e:
        logger.warning('Could not restrict %s to the current user (%s): fix its permissions manually', path, e)


def load_env_file(path: Optional[Path] = None) -> List[str]:
    """Carica il .env della configurazione utente. Restituisce i nomi effettivamente impostati."""
    path = path or env_file_path()
    if not path.is_file():
        return []
    _restrict_env_file(path)

    loaded = []
    for name, value in dotenv_values(path, interpolate=False).items():
        if value is None:
            continue
        if not _allowed(name):
            logger.warning('Ignoring %s from %s: only API keys and SECURE_OSINT_* variables are allowed', name, path)
            continue
        if name in os.environ:
            continue
        os.environ[name] = value
        loaded.append(name)
    return loaded


def get_api_key(name: str) -> Optional[str]:
    """Return the value of a known API-key variable, or None if unset/blank.

    Raises:
        KeyError: If ``name`` is not a recognised API-key variable.
    """
    if name not in API_KEYS:
        raise KeyError(f'Unknown API key variable: {name}')
    return os.environ.get(name, '').strip() or None


def secret_values() -> List[str]:
    """Valori di tutte le variabili sensibili presenti ora, dal più lungo (per sostituzioni corrette)."""
    values = set()
    for name, value in os.environ.items():
        if name.endswith(SECRET_SUFFIXES) or name in EXTRA_SECRET_VARS:
            value = value.strip()
            if len(value) >= MIN_SECRET_LENGTH:
                values.add(value)
    return sorted(values, key=len, reverse=True)


def scrub(text: str, secrets: List[str]) -> str:
    """Return ``text`` with every known secret value replaced by the placeholder."""
    if not secrets:
        return text
    return re.sub('|'.join(map(re.escape, secrets)), '[REDACTED]', text)


_STANDARD_LOG_ATTRS = set(vars(logging.makeLogRecord({}))) | {'message', 'asctime'}


# Records already redacted by a SecretRedactingFilter: the same record usually meets the filter twice
# (on its logger and on the root handler), and the second pass would only repeat the work.
_redacted_records: 'weakref.WeakSet[logging.LogRecord]' = weakref.WeakSet()


class SecretRedactingFilter(logging.Filter):
    """Redact every log record: API-key values plus EVERY PrivacyGuard category and the log-only rules.

    The one log filter of the project. Attach it to handlers (``configure_logging`` puts it on the root
    handler) and to loggers that may emit without reaching that handler (``redacting_logger``, and
    third-party loggers with their own handlers). Applying it twice to a record is a no-op.

    Logs are always fully redacted, whatever --keep-network/--keep-location/--keep-crypto/--keep-device
    say: those flags only shape reports. Message, arguments, ``extra`` fields, traceback and stack are
    all covered.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact the record in place; always returns True (keeps the record)."""
        if record in _redacted_records:
            return True
        from secure_osint.core.privacy import log_guard  # lazy: privacy imports this module

        guard = log_guard()
        try:
            message = record.getMessage()
        except Exception:
            # Bad format arguments: logging would print them raw from Handler.handleError.
            message = f'{record.msg} (unformattable log arguments: {record.args!r})'
        record.msg = guard.redact(message)
        record.args = None
        for key, value in list(vars(record).items()):
            if key in _STANDARD_LOG_ATTRS:
                continue
            if not isinstance(value, (str, int, float, bool, type(None), dict, list, tuple, set, frozenset)):
                value = str(value)  # formatters would str() it anyway, unredacted
            setattr(record, key, guard.redact_field(key, value))
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = guard.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = guard.redact(record.stack_info)
        _redacted_records.add(record)
        return True


def describe_keys() -> List[Dict[str, Any]]:
    """Return a list of {name, set, usage} describing each known API key."""
    return [{'name': name, 'set': get_api_key(name) is not None, 'usage': usage} for name, usage in API_KEYS.items()]
