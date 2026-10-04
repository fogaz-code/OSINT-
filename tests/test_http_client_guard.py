"""The SSRF guard must be wired into the transport actually used, and fail CLOSED if it is not."""

import ast
import logging
import socket
from pathlib import Path

import httpcore
import httpx
import pytest

from secure_osint.security.ssrf_guard import SSRFError
from secure_osint.sources.base import SourceUnavailable
from secure_osint.utils.http_client import GuardedNetworkBackend, SafeHttpClient
from secure_osint.utils.resilience import HostPolicies

SRC = Path(__file__).resolve().parents[1] / 'src' / 'secure_osint'


def _client(**kwargs):
    return SafeHttpClient(policies=HostPolicies(), timeout=5, **kwargs)


def test_real_client_pool_uses_guarded_backend():
    client = _client()
    transport = client._client._transport
    assert isinstance(transport, httpx.HTTPTransport)
    assert isinstance(transport._pool, httpcore.ConnectionPool)
    assert isinstance(transport._pool._network_backend, GuardedNetworkBackend)
    assert client._client._mounts == {}  # no proxy route that would skip the guarded transport


@pytest.fixture
def listener():
    """A loopback socket that would accept a connection if the guard let one through."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    sock.listen(5)
    sock.settimeout(0.3)
    yield sock
    sock.close()


def _resolve_to(ip):
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host == 'intranet.example':
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            return [(family, socket.SOCK_STREAM, 6, '', (ip, port))]
        return real(host, port, *args, **kwargs)

    return fake


def test_end_to_end_hostname_resolving_to_loopback_is_refused(listener, monkeypatch):
    """Real SafeHttpClient, real pool, real resolver path: only getaddrinfo is faked."""
    port = listener.getsockname()[1]
    client = _client()
    monkeypatch.setattr(socket, 'getaddrinfo', _resolve_to('127.0.0.1'))
    with pytest.raises(SourceUnavailable, match='SSRF'):
        client.get(f'http://intranet.example:{port}/admin')
    with pytest.raises(OSError):  # socket.timeout is an OSError: nothing ever connected
        listener.accept()


@pytest.mark.parametrize('ip', ['::127.0.0.1', '::ffff:127.0.0.1', '::ffff:0:127.0.0.1', '64:ff9b::7f00:1'])
def test_end_to_end_ipv6_encoded_loopback_is_refused(listener, monkeypatch, ip):
    port = listener.getsockname()[1]
    client = _client()
    monkeypatch.setattr(socket, 'getaddrinfo', _resolve_to(ip))
    with pytest.raises(SourceUnavailable, match='SSRF'):
        client.get(f'http://intranet.example:{port}/admin')
    with pytest.raises(OSError):
        listener.accept()


def test_construction_fails_closed_if_httpx_renames_the_pool(monkeypatch):
    """If httpx stops calling it `_pool`, assigning `_pool` would create a dead attribute."""
    original_init = httpx.HTTPTransport.__init__

    def renamed_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._connection_pool = self.__dict__.pop('_pool')

    def renamed_handle(self, request):
        raise AssertionError('the probe must not reach a transport whose pool was not replaced')

    monkeypatch.setattr(httpx.HTTPTransport, '__init__', renamed_init)
    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', renamed_handle)
    with pytest.raises(RuntimeError, match='SSRF'):
        _client()


def test_construction_fails_closed_if_httpcore_renames_the_backend(monkeypatch):
    original_init = httpcore.ConnectionPool.__init__

    def renamed_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._backend = self.__dict__.pop('_network_backend')

    monkeypatch.setattr(httpcore.ConnectionPool, '__init__', renamed_init)
    with pytest.raises(RuntimeError, match='SSRF'):
        _client()


def test_construction_fails_closed_if_requests_bypass_the_guarded_pool(monkeypatch):
    """Structure looks right but requests go elsewhere: the live probe must notice."""

    def elsewhere(self, request):
        raise httpx.ConnectError('sent through some other connection path')

    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', elsewhere)
    with pytest.raises(RuntimeError, match='SSRF'):
        _client()


def test_guard_probe_never_touches_the_resolver(monkeypatch):
    def no_dns(*args, **kwargs):
        raise AssertionError('the construction-time probe must not resolve anything')

    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    _client()


def test_unix_socket_connections_refused():
    with pytest.raises(SSRFError):
        GuardedNetworkBackend().connect_unix_socket('/var/run/docker.sock', timeout=1)


def test_connect_with_no_address_raises_connect_error_not_assertion(monkeypatch):
    """Regression: `assert last_error is not None` became `raise None` (TypeError) under python -O."""
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: [])
    with pytest.raises(httpcore.ConnectError):
        GuardedNetworkBackend().connect_tcp('public.test', 80, timeout=1)


def test_connect_reraises_last_error_after_trying_every_address(monkeypatch):
    tried = []

    def refuse(self, host, port, **kwargs):
        tried.append(host)
        raise httpcore.ConnectError(f'refused {host}')

    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1', '1.0.0.1'])
    monkeypatch.setattr(httpcore.SyncBackend, 'connect_tcp', refuse)
    with pytest.raises(httpcore.ConnectError, match='1.0.0.1'):
        GuardedNetworkBackend().connect_tcp('public.test', 443, timeout=1)
    assert tried == ['1.1.1.1', '1.0.0.1']


@pytest.mark.parametrize('module', ['utils/http_client.py', 'security/ssrf_guard.py'])
def test_no_assert_statements_in_security_code(module):
    """`assert` vanishes under `python -O`: security checks must use explicit exceptions."""
    tree = ast.parse((SRC / module).read_text(encoding='utf-8'))
    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)] == []


def test_trust_env_logs_ssrf_downgrade_warning_once_per_client(monkeypatch, caplog):
    monkeypatch.setattr('secure_osint.utils.http_client.resolve_public_addresses', lambda h, p: ['1.1.1.1'])
    with caplog.at_level(logging.WARNING, logger='secure_osint.utils.http_client'):
        client = _client(trust_env=True)
        client._client = _StubClient()  # never touch the network
        client.get('https://example.com/a')
        client.get('https://example.com/b')
    warnings = [
        r for r in caplog.records if r.levelno == logging.WARNING and 'SECURE_OSINT_TRUST_ENV' in r.getMessage()
    ]
    assert len(warnings) == 1
    assert 'SSRF' in warnings[0].getMessage()


def test_default_client_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger='secure_osint.utils.http_client'):
        _client()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_trust_env_still_prechecks_every_redirect_hop(monkeypatch):
    """With a proxy the connect-time pin is gone, so each hop is resolved and checked before sending."""
    import secure_osint.utils.http_client as http_client

    sent = []

    def handler(request):
        sent.append(str(request.url))
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/latest/meta-data/'})

    monkeypatch.setattr(http_client, 'resolve_public_addresses', _fake_public('example.com'))
    client = _client(trust_env=True)
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(SourceUnavailable, match='SSRF'):
        client.get('http://example.com/start')
    assert sent == ['http://example.com/start']


def _fake_public(*public_hosts):
    from secure_osint.security.ssrf_guard import resolve_public_addresses

    def fake(host, port=443):
        return ['93.184.215.14'] if host in public_hosts else resolve_public_addresses(host, port)

    return fake


class _StubStream:
    def __init__(self):
        self.response = httpx.Response(200, content=b'ok', request=httpx.Request('GET', 'https://example.com/'))

    def __enter__(self):
        return self.response

    def __exit__(self, *exc):
        return False


class _StubClient:
    def stream(self, *args, **kwargs):
        return _StubStream()

    def close(self):
        pass
