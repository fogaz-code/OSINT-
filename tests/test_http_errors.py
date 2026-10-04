"""Descriptive, typed errors for HTTP failures (Phase 2 robustness)."""

import httpx
import pytest

from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.utils.http_client import HttpResponse, SafeHttpClient, raise_for_status
from secure_osint.utils.resilience import HostPolicies


def _resp(code: int) -> HttpResponse:
    return HttpResponse(code, b'', {})


def test_rate_limit_message():
    with pytest.raises(TransientSourceError, match='rate limited'):
        raise_for_status(_resp(429), 'example.com')


@pytest.mark.parametrize('code', [500, 502, 503])
def test_server_error_message(code):
    with pytest.raises(TransientSourceError, match='server error'):
        raise_for_status(_resp(code), 'example.com')


def test_not_found_and_other_4xx():
    with pytest.raises(SourceUnavailable, match='not found'):
        raise_for_status(_resp(404), 'example.com')
    with pytest.raises(SourceUnavailable, match='request rejected'):
        raise_for_status(_resp(403), 'example.com')


def test_success_does_not_raise():
    raise_for_status(_resp(200), 'example.com')


def _client():
    return SafeHttpClient(policies=HostPolicies(), timeout=7.0)


def test_timeout_message_includes_seconds(monkeypatch):
    client = _client()
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1'])

    def boom(*a, **k):
        raise httpx.ReadTimeout('slow')

    monkeypatch.setattr(client._client, 'stream', boom)
    with pytest.raises(TransientSourceError, match='timed out after 7s'):
        client.get('https://example.com/x')


def test_transport_error_message(monkeypatch):
    client = _client()
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1'])

    def boom(*a, **k):
        raise httpx.ConnectError('down')

    monkeypatch.setattr(client._client, 'stream', boom)
    with pytest.raises(TransientSourceError, match='connection error'):
        client.get('https://example.com/x')
