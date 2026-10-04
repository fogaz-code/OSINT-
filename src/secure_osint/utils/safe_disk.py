"""A diskcache serializer that does not trust the contents of the cache directory.

diskcache's default ``Disk`` decides how to deserialise a value from the ``mode`` column of its SQLite
database and resolves value files from the ``filename`` column. Anyone able to write to the cache
directory can therefore:

- set ``mode`` to pickle and run arbitrary code when the entry is read (CVE-2025-69872,
  PYSEC-2026-2447: no fixed diskcache release exists);
- point ``filename`` outside the directory (an absolute path, ``..``, or a symlinked sub-directory) so
  that the file is read and then deleted when the entry is removed. ``ResultCache`` removes every entry
  it cannot decrypt, so a planted row turns into deletion of any file the user can write.

Encrypting values does not help: diskcache deserialises the row before the Fernet token is checked.
``SafeDisk`` never pickles or unpickles anything (``ResultCache`` stores ``str`` keys and ``bytes``
tokens only) and confines value files to diskcache's own naming scheme inside the cache directory.
A row that breaks either rule raises :class:`UnsafeCacheEntry`, an ``OSError``, which diskcache's
``get`` already treats as a miss.
"""

import logging
import os
import re
from typing import Any, Optional, Tuple

import diskcache
from diskcache.core import MODE_PICKLE, UNKNOWN

logger = logging.getLogger(__name__)

# Types diskcache stores without pickling (ints only within SQLite's 64-bit range, checked by diskcache).
_RAW_TYPES = (str, bytes, int, float)
# Disk.filename(): two levels of 2-hex-digit directories, then 28 hex digits + '.val'.
_VALUE_FILE = re.compile(r'[0-9a-f]{2}[/\\][0-9a-f]{2}[/\\][0-9a-f]{28}\.val')


class UnsafeCacheEntry(OSError):
    """A cache row that would need unpickling or points outside the cache directory (tampering)."""


class SafeDisk(diskcache.Disk):  # type: ignore[misc]  # diskcache ships no type hints
    """diskcache ``Disk`` with pickling disabled and value files confined to the cache directory."""

    def put(self, key: Any) -> Tuple[Any, bool]:
        """Convert a key for storage; refuse any key diskcache would pickle."""
        if isinstance(key, _RAW_TYPES):
            db_key, raw = super().put(key)
            if raw:
                return db_key, raw
        raise TypeError(f'SafeDisk does not pickle: unsupported cache key {type(key).__name__}')

    def get(self, key: Any, raw: bool) -> Any:
        """Convert a stored key back; a pickled key is never loaded."""
        if not raw:
            logger.warning('refusing a pickled cache key: the cache directory may have been tampered with')
            raise UnsafeCacheEntry('pickled cache key refused')
        return super().get(key, raw)

    def store(self, value: Any, read: bool, key: Any = UNKNOWN) -> Tuple[Any, ...]:
        """Convert a value for storage; refuse any value diskcache would pickle."""
        if not read and not isinstance(value, _RAW_TYPES):
            raise TypeError(f'SafeDisk does not pickle: unsupported cache value {type(value).__name__}')
        size, mode, filename, db_value = super().store(value, read, key)
        if mode == MODE_PICKLE:  # e.g. an int outside SQLite's range
            raise TypeError('SafeDisk does not pickle: value cannot be stored raw')
        return size, mode, filename, db_value

    def fetch(self, mode: int, filename: Optional[str], value: Any, read: bool) -> Any:
        """Convert a stored value back; a pickled value or a file outside the cache is never loaded."""
        if mode == MODE_PICKLE:
            logger.warning('refusing a pickled cache value: the cache directory may have been tampered with')
            raise UnsafeCacheEntry('pickled cache value refused')
        if filename is not None:
            self._check_filename(filename)
        return super().fetch(mode, filename, value, read)

    def remove(self, file_path: str) -> None:
        """Delete a value file, but only one that diskcache could have created inside the cache directory."""
        try:
            self._check_filename(file_path)
        except UnsafeCacheEntry:
            return  # never delete outside the cache; the check already logged the warning
        super().remove(file_path)

    def _check_filename(self, filename: Any) -> None:
        if isinstance(filename, str) and _VALUE_FILE.fullmatch(filename):
            # realpath: a sub-directory replaced by a symlink must not lead outside either.
            root = os.path.realpath(self._directory)
            full = os.path.realpath(os.path.join(root, filename))
            try:
                if os.path.commonpath([root, full]) == root:
                    return
            except ValueError:  # Windows: different drives
                pass
        logger.warning('refusing a cache value file outside the cache directory: possible tampering')
        raise UnsafeCacheEntry('cache value file outside the cache directory refused')
