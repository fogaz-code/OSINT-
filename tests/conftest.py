import os

import pytest


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path_factory, monkeypatch):
    """Nessun test deve leggere o scrivere la cache/chiave reale dell'utente."""
    base = tmp_path_factory.mktemp('home')
    monkeypatch.setenv('SECURE_OSINT_CACHE_DIR', str(base / 'cache'))
    monkeypatch.setenv('XDG_CONFIG_HOME', str(base / 'config'))
    monkeypatch.delenv('SECURE_OSINT_CACHE_KEY', raising=False)


@pytest.fixture(autouse=True)
def restore_environ():
    """Il loader .env scrive direttamente in os.environ: ripristinalo dopo ogni test."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)
