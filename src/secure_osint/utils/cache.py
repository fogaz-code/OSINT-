"""Cache persistente e cifrata dei risultati delle fonti.

- Chiavi: HMAC-SHA256(segreto, sorgente + parametri). Un SHA-256 semplice permetterebbe a chi ha la
  directory di verificare se un target è stato indagato calcolando l'hash dei candidati.
- Valori: sempre cifrati con Fernet (AES-128-CBC + HMAC). Cifrare "solo se ci sono PII" non regge:
  il rilevamento via regex non vede username e nomi, e renderebbe riconoscibili le voci sensibili.
- La chiave sta fuori dalla directory della cache (o in SECURE_OSINT_CACHE_KEY): protegge da copie,
  backup e sync della cache, NON da chi ha già accesso all'utente locale.
- Key file and cache directory are owner-only on every platform (see utils.secure_fs: on Windows
  os.chmod is a no-op, so a DACL is applied). If that cannot be guaranteed the cache refuses to open
  (fail closed) instead of writing a key other accounts could read.
- An entry that cannot be decrypted (key rotated or lost) is a miss and is never deleted: restoring
  the key brings it back, otherwise diskcache evicts it when its TTL runs out.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

import diskcache
from cryptography.fernet import Fernet, InvalidToken

from secure_osint.core.privacy import PrivacyGuard
from secure_osint.utils import secure_fs
from secure_osint.utils.secure_fs import InsecurePermissionsError
from secure_osint.utils.safe_disk import SafeDisk

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]
_SCHEMA = 1
_LABEL = re.compile(r'\[REDACTED:(\w+)\]')


def default_cache_dir() -> Path:
    """Return the cache directory (env override, else XDG, else ~/.cache)."""
    if os.environ.get('SECURE_OSINT_CACHE_DIR'):
        return Path(os.environ['SECURE_OSINT_CACHE_DIR']).expanduser()
    base = os.environ.get('XDG_CACHE_HOME') or Path.home() / '.cache'
    return Path(base) / 'secure_osint'


def default_key_path() -> Path:
    """Return the default path of the cache encryption key file."""
    base = os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config'
    return Path(base) / 'secure_osint' / 'cache.key'


def load_or_create_key(path: PathLike) -> bytes:
    """Return the Fernet key from SECURE_OSINT_CACHE_KEY, else from an owner-only key file (created if missing).

    Raises:
        InsecurePermissionsError: If the key file or its directory cannot be made owner-only, or the
            key path is not a regular file (e.g. a symlink). Never returns a key other accounts can read.
        ValueError: If the key is not a valid Fernet key.
    """
    env_key = os.environ.get('SECURE_OSINT_CACHE_KEY')
    if env_key:
        Fernet(env_key.encode())  # solleva ValueError se non valida
        return env_key.encode()
    path = Path(path).expanduser()
    secure_fs.secure_dir(path.parent)
    try:
        with secure_fs.create_private_exclusive(path) as f:
            key = Fernet.generate_key()
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        return key
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_file():
        raise InsecurePermissionsError(f'The cache key {path} is not a regular file: refusing to use it.')
    if not secure_fs.is_owner_only(path):
        logger.warning(
            'SECURITY: the cache key %s was readable by other accounts and may be compromised. '
            'Restricting it to the current user now; to rotate it, run cache-clear and delete the key file.',
            path,
        )
        secure_fs.secure_file(path)
    key = path.read_bytes().strip()
    Fernet(key)
    return key


@dataclass
class CacheEntry:
    """A decrypted summary of one cache entry, for the audit command."""

    key: str
    source: str
    input: str
    stored_at: float
    expires_at: float
    size: int
    pii: Dict[str, int] = field(default_factory=dict)


class AuditReport(List[CacheEntry]):
    """The readable entries (a plain list, sorted by storage time) plus how many could not be decrypted."""

    def __init__(self, entries: Iterable[CacheEntry] = (), undecryptable: int = 0):
        """Initialize AuditReport."""
        super().__init__(entries)
        self.undecryptable = undecryptable


class _Undecryptable:
    """Sentinel: the entry exists but cannot be decrypted with the current key."""


_UNDECRYPTABLE = _Undecryptable()


class ResultCache:
    """Encrypted on-disk cache of source results, keyed by a per-secret HMAC."""

    def __init__(
        self,
        directory: Optional[PathLike] = None,
        key: Optional[bytes] = None,
        key_path: Optional[PathLike] = None,
        default_ttl: int = 3600,
        clock: Callable[[], float] = time.time,
    ):
        """Initialize ResultCache."""
        self.directory = Path(directory).expanduser() if directory else default_cache_dir()
        if key is None:
            resolved_key_path = Path(key_path).expanduser() if key_path else default_key_path()
            if resolved_key_path.resolve().is_relative_to(self.directory.resolve()):
                raise ValueError('The cache key must not be stored inside the cache directory.')
            key = load_or_create_key(resolved_key_path)
        self._fernet = Fernet(key)
        self._key_secret = hmac.new(key, b'secure-osint cache key v1', hashlib.sha256).digest()
        self.default_ttl = default_ttl
        self.clock = clock
        self._warned_undecryptable = False
        # Secure the directory (and repair anything already in it) BEFORE diskcache creates files there,
        # so its database is born owner-only. Raises InsecurePermissionsError: the caller runs uncached.
        secure_fs.secure_tree(self.directory)
        # SafeDisk: a tampered cache row must not unpickle (CVE-2025-69872) or touch files outside the cache.
        self._cache = diskcache.Cache(str(self.directory), disk=SafeDisk)

    def _key(self, source: str, params: Dict[str, Any]) -> str:
        canonical = json.dumps([_SCHEMA, source, params], sort_keys=True, default=str, separators=(',', ':'))
        return hmac.new(self._key_secret, canonical.encode(), hashlib.sha256).hexdigest()

    def _decrypt(self, key: str) -> Union[Dict[str, Any], _Undecryptable, None]:
        token = self._cache.get(key)
        if token is None:
            return None
        try:
            envelope = json.loads(self._fernet.decrypt(token))
            expires_at = float(envelope['expires_at'])
        except (InvalidToken, TypeError, ValueError, KeyError):
            # Key rotated/lost or entry damaged: a miss, never a delete (restoring the key recovers it,
            # and diskcache evicts it at its TTL anyway). Nothing about the entry is logged.
            if not self._warned_undecryptable:
                self._warned_undecryptable = True
                logger.warning(
                    'Some cache entries could not be decrypted with the current key (was the key rotated or '
                    'lost?): they are treated as misses and kept until they expire.'
                )
            return _UNDECRYPTABLE
        if self.clock() >= expires_at:
            self._cache.delete(key)
            return None
        return dict(envelope)

    def _read(self, key: str) -> Optional[Dict[str, Any]]:
        envelope = self._decrypt(key)
        return envelope if isinstance(envelope, dict) else None

    def get(self, source: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the cached data for (source, params), or None on miss/expiry/undecryptable entry."""
        envelope = self._read(self._key(source, params))
        return envelope['data'] if envelope else None

    def set(self, source: str, params: Dict[str, Any], data: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Encrypt and store the data for (source, params) with a TTL (0 = do not store)."""
        ttl = self.default_ttl if ttl is None else ttl
        if ttl <= 0:
            return
        now = self.clock()
        envelope = {
            'source': source,
            'input': str(params.get('input', '')),
            'stored_at': now,
            'expires_at': now + ttl,
            'data': data,
        }
        token = self._fernet.encrypt(json.dumps(envelope, default=str).encode())
        # expire di diskcache serve solo all'eviction; la scadenza autorevole è quella nell'envelope.
        self._cache.set(self._key(source, params), token, expire=ttl)

    def clear(self) -> int:
        """Delete every cache entry and return how many were removed."""
        return int(self._cache.clear())

    def audit(self) -> AuditReport:
        """Decrypt and describe the stored entries (redacted input, PII categories found in the data).

        Entries that cannot be decrypted are not listed (nor deleted): only their number is reported,
        in ``AuditReport.undecryptable``.
        """
        guard = PrivacyGuard()
        labeller = PrivacyGuard(label=True)
        entries = []
        undecryptable = 0
        for key in list(self._cache.iterkeys()):
            envelope = self._decrypt(key)
            if envelope is _UNDECRYPTABLE:
                undecryptable += 1
                continue
            if not isinstance(envelope, dict):
                continue
            labelled = labeller.redact(json.dumps(envelope['data'], default=str))
            entries.append(
                CacheEntry(
                    key=key[:12],
                    source=envelope['source'],
                    input=guard.redact(envelope['input']),
                    stored_at=envelope['stored_at'],
                    expires_at=envelope['expires_at'],
                    size=len(self._cache.get(key) or b''),
                    pii=dict(Counter(_LABEL.findall(labelled))),
                )
            )
        return AuditReport(sorted(entries, key=lambda e: e.stored_at), undecryptable=undecryptable)

    def close(self) -> None:
        """Close the underlying cache."""
        self._cache.close()
