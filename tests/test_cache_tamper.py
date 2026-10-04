"""A tampered cache directory must not turn into code execution or arbitrary file deletion.

diskcache (CVE-2025-69872 / PYSEC-2026-2447, no fixed release) trusts its SQLite rows: the `mode`
column decides whether a value is unpickled, and `filename` is joined to the cache directory, read,
and deleted when the entry goes away. Fernet does not help, because diskcache deserialises the row
before ResultCache ever sees the token. The cache directory is assumed to be copied, backed up or
synced (see utils/cache.py), and on Windows its 0700 mode is not enforced, so it is not trusted.
"""

import os
import pickle
import sqlite3
from pathlib import Path
from typing import Any, Tuple

import pytest
from cryptography.fernet import Fernet
from diskcache.core import MODE_BINARY, MODE_PICKLE

from secure_osint.utils.cache import ResultCache
from secure_osint.utils.safe_disk import SafeDisk, UnsafeCacheEntry

PARAMS = {'input': 'example.com'}


class _MkdirOnUnpickle:
    """Pickle payload: unpickling it creates ``marker`` (stands in for arbitrary code)."""

    def __init__(self, marker: Path):
        self.marker = marker

    def __reduce__(self) -> Tuple[Any, ...]:
        return (os.mkdir, (str(self.marker),))


def _cache(tmp_path: Path) -> ResultCache:
    return ResultCache(directory=tmp_path / 'cache', key=Fernet.generate_key())


def _tamper(tmp_path: Path, sql: str, args: Tuple[Any, ...] = ()) -> None:
    with sqlite3.connect(str(tmp_path / 'cache' / 'cache.db')) as db:
        db.execute(sql, args)


def test_pickled_value_in_a_tampered_row_is_never_unpickled(tmp_path):
    cache = _cache(tmp_path)
    cache.set('dns', PARAMS, {'A': ['192.0.2.1']})
    marker = tmp_path / 'code-ran'
    payload = pickle.dumps(_MkdirOnUnpickle(marker))
    _tamper(tmp_path, 'UPDATE Cache SET mode = ?, filename = NULL, value = ?', (MODE_PICKLE, payload))

    assert cache.get('dns', PARAMS) is None  # a tampered entry is a miss
    assert not marker.exists()


def test_pickled_key_in_a_tampered_row_is_never_unpickled(tmp_path):
    cache = _cache(tmp_path)
    cache.set('dns', PARAMS, {'A': ['192.0.2.1']})
    marker = tmp_path / 'code-ran'
    payload = pickle.dumps(_MkdirOnUnpickle(marker))
    _tamper(tmp_path, 'UPDATE Cache SET key = ?, raw = 0', (payload,))

    with pytest.raises(UnsafeCacheEntry):
        cache.audit()  # iterates the keys: the tampering is reported, not silently skipped
    assert not marker.exists()


@pytest.mark.parametrize('relative', [False, True], ids=['absolute', 'traversal'])
def test_filename_outside_the_cache_is_neither_read_nor_deleted(tmp_path, relative):
    cache = _cache(tmp_path)
    cache.set('dns', PARAMS, {'A': ['192.0.2.1']})
    victim = tmp_path / 'victim.txt'
    victim.write_text('do not delete', encoding='utf-8')
    filename = os.path.join('..', 'victim.txt') if relative else str(victim)
    _tamper(tmp_path, 'UPDATE Cache SET mode = ?, filename = ?, value = NULL', (MODE_BINARY, filename))

    assert cache.get('dns', PARAMS) is None
    cache.clear()
    assert victim.read_text(encoding='utf-8') == 'do not delete'


def test_large_values_stored_as_files_still_round_trip_and_are_cleaned_up(tmp_path):
    cache = _cache(tmp_path)
    data = {'urls': [f'https://example.com/{i:06d}' for i in range(5000)]}  # well above 32 KiB
    cache.set('wayback', PARAMS, data)
    value_files = list((tmp_path / 'cache').rglob('*.val'))
    assert value_files, 'expected diskcache to store this value in a file'

    assert cache.get('wayback', PARAMS) == data
    assert cache.clear() == 1
    assert not any(path.exists() for path in value_files)


def test_safe_disk_refuses_to_pickle_anything(tmp_path):
    disk = SafeDisk(str(tmp_path))
    with pytest.raises(TypeError):
        disk.put(('tuple', 'key'))
    with pytest.raises(TypeError):
        disk.store({'a': 1}, read=False)
    assert disk.put('plain-key') == ('plain-key', True)


def test_result_cache_uses_the_safe_disk(tmp_path):
    assert isinstance(_cache(tmp_path)._cache.disk, SafeDisk)
