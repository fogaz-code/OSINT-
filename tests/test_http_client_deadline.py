"""C1: every request issued by SafeHttpClient is bounded by the enclosing step deadline."""

import time

import httpcore
import httpx
import pytest

from secure_osint.sources.base import TransientSourceError
from secure_osint.utils.deadline import DeadlineExceeded, deadline_scope
from secure_osint.utils.http_client import GuardedNetworkBackend, SafeHttpClient
from secure_osint.utils.resilience import HostPolicies
from tests.http_test_server import PUBLIC_ALIAS, alias_public_host, serve


class _Limiter:
    def __init__(self, grant=True):
        self.grant = grant
        self.timeouts = []

    def acquire(self, timeout=None):
        self.timeouts.append(timeout)
        return self.grant


class _Policies(HostPolicies):
    def __init__(self, limiter):
        super().__init__()
        self._limiter = limiter

    def limiter(self, host):
        return self._limiter


class _Recorder:
    """Stands in for httpx.Client.stream and records the timeout of each call."""

    def __init__(self, exc=None, sleep=0.0):
        self.timeouts = []
        self.exc = exc
        self.sleep = sleep

    def __call__(self, method, url, **kwargs):
        self.timeouts.append(kwargs.get('timeout'))
        if self.sleep:
            time.sleep(self.sleep)
        if self.exc is not None:
            raise self.exc
        return _Ctx(httpx.Response(200, content=b'ok', request=httpx.Request(method, url)))


class _Ctx:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, *exc):
        return False


def _client(limiter=None, timeout=15.0):
    return SafeHttpClient(policies=_Policies(limiter or _Limiter()), timeout=timeout)


def test_no_scope_keeps_configured_timeout(monkeypatch):
    client = _client(timeout=7.0)
    rec = _Recorder()
    monkeypatch.setattr(client._client, 'stream', rec)
    client.get('https://example.com/')
    assert rec.timeouts == [7.0]


def test_request_timeout_clamped_to_remaining_budget(monkeypatch):
    limiter = _Limiter()
    client = _client(limiter, timeout=15.0)
    rec = _Recorder()
    monkeypatch.setattr(client._client, 'stream', rec)
    with deadline_scope(2.0):
        client.get('https://example.com/')
    assert 0 < rec.timeouts[0] <= 2.0
    assert 0 < limiter.timeouts[0] <= 2.0


def test_expired_budget_raises_before_any_io(monkeypatch):
    limiter = _Limiter()
    client = _client(limiter)
    rec = _Recorder()
    monkeypatch.setattr(client._client, 'stream', rec)
    with deadline_scope(0):
        with pytest.raises(DeadlineExceeded):
            client.get('https://example.com/')
    assert rec.timeouts == [] and limiter.timeouts == []


def test_rate_limit_wait_cut_short_by_deadline_is_deadline_exceeded(monkeypatch):
    client = _client(_Limiter(grant=False), timeout=15.0)
    monkeypatch.setattr(client._client, 'stream', _Recorder())
    with deadline_scope(0.5):
        with pytest.raises(DeadlineExceeded):
            client.get('https://example.com/')


def test_rate_limit_wait_without_deadline_stays_transient(monkeypatch):
    client = _client(_Limiter(grant=False))
    monkeypatch.setattr(client._client, 'stream', _Recorder())
    with pytest.raises(TransientSourceError, match='rate limit'):
        client.get('https://example.com/')


def test_deadline_exceeded_from_transport_propagates_unchanged(monkeypatch):
    client = _client()
    monkeypatch.setattr(client._client, 'stream', _Recorder(exc=DeadlineExceeded('step time budget exhausted')))
    with pytest.raises(DeadlineExceeded) as info:
        client.get('https://example.com/')
    assert not isinstance(info.value, TransientSourceError)
    assert client.policies.breaker('example.com')._failures == 0


def test_timeout_after_budget_is_spent_is_deadline_not_transient(monkeypatch):
    client = _client()
    monkeypatch.setattr(client._client, 'stream', _Recorder(exc=httpx.ReadTimeout('slow'), sleep=0.15))
    with deadline_scope(0.1):
        with pytest.raises(DeadlineExceeded):
            client.get('https://example.com/')
    assert client.policies.breaker('example.com')._failures == 0


def test_connect_timeout_clamped_per_attempt(monkeypatch):
    seen = []

    def connect(self, host, port, timeout=None, **kwargs):
        seen.append(timeout)
        raise httpcore.ConnectError('refused')

    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1', '1.0.0.1'])
    monkeypatch.setattr(httpcore.SyncBackend, 'connect_tcp', connect)
    with deadline_scope(1.0):
        with pytest.raises(httpcore.ConnectError):
            GuardedNetworkBackend().connect_tcp('public.test', 443, timeout=10.0)
    assert len(seen) == 2 and all(0 < t <= 1.0 for t in seen)


def test_connect_with_spent_budget_raises_deadline(monkeypatch):
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1'])
    with deadline_scope(0):
        with pytest.raises(DeadlineExceeded):
            GuardedNetworkBackend().connect_tcp('public.test', 443, timeout=10.0)


def _slow_drip(handler, stats):
    """Never trips a per-read timeout: one byte every 50 ms, forever (capped at 20 s)."""
    handler.send_response(200)
    handler.end_headers()
    for _ in range(400):
        handler.wfile.write(b'x')
        handler.wfile.flush()
        stats.wrote(1)
        time.sleep(0.05)


def test_slow_drip_body_is_cut_at_the_deadline(monkeypatch):
    """httpx timeouts are per read, so the body loop itself must watch the deadline."""
    alias_public_host(monkeypatch)
    client = SafeHttpClient(policies=HostPolicies(), timeout=5.0)
    with serve(_slow_drip) as (port, _stats):
        start = time.monotonic()
        with deadline_scope(0.6):
            with pytest.raises(DeadlineExceeded):
                client.get(f'http://{PUBLIC_ALIAS}:{port}/drip')
        assert time.monotonic() - start < 3.0
