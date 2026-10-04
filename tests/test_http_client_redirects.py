"""Redirect handling: bounded, never downgraded, re-checked, and never reading redirect bodies."""

import httpx
import pytest

from secure_osint.sources.base import SourceUnavailable
from secure_osint.utils.http_client import SafeHttpClient
from secure_osint.utils.resilience import HostPolicies
from tests.http_test_server import PUBLIC_ALIAS, alias_public_host, serve


def _mock_client(handler, **kwargs):
    client = SafeHttpClient(policies=HostPolicies(), timeout=5, **kwargs)
    # Swap only the transport: redirect logic, body reading and error mapping stay the real ones.
    client._client._transport = httpx.MockTransport(handler)
    return client


class _Site:
    """Routes for the mock transport; records every request it receives."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        status, headers, body = self.routes[str(request.url)]
        return httpx.Response(status, headers=headers, content=body)


def test_https_to_http_downgrade_refused():
    site = _Site(
        {
            'https://public.test/start': (302, {'Location': 'http://public.test/plain'}, b''),
            'http://public.test/plain': (200, {}, b'leaked over cleartext'),
        }
    )
    with pytest.raises(SourceUnavailable, match='https to http'):
        _mock_client(site).get('https://public.test/start')
    assert [str(r.url) for r in site.requests] == ['https://public.test/start']


def test_downgrade_refused_at_a_later_hop():
    site = _Site(
        {
            'https://a.test/1': (301, {'Location': 'https://b.test/2'}, b''),
            'https://b.test/2': (307, {'Location': 'http://b.test/3'}, b''),
            'http://b.test/3': (200, {}, b'no'),
        }
    )
    with pytest.raises(SourceUnavailable, match='https to http'):
        _mock_client(site).get('https://a.test/1')
    assert [str(r.url) for r in site.requests] == ['https://a.test/1', 'https://b.test/2']


def test_http_to_https_upgrade_and_relative_locations_followed():
    site = _Site(
        {
            'http://public.test/a': (301, {'Location': 'https://public.test/b'}, b''),
            'https://public.test/b': (302, {'Location': '/c?x=1'}, b''),
            'https://public.test/c?x=1': (302, {'Location': '//other.test/d'}, b''),
            'https://other.test/d': (200, {}, b'final'),
        }
    )
    response = _mock_client(site).get('http://public.test/a')
    assert response.status_code == 200 and response.text == 'final'


@pytest.mark.parametrize('location', ['file:///etc/passwd', 'ftp://public.test/x', 'gopher://public.test/'])
def test_redirect_to_non_http_scheme_refused(location):
    site = _Site({'https://public.test/start': (302, {'Location': location}, b'')})
    with pytest.raises(SourceUnavailable, match='scheme'):
        _mock_client(site).get('https://public.test/start')
    assert len(site.requests) == 1


def test_cross_origin_redirect_drops_credentials_and_custom_headers():
    site = _Site(
        {
            'https://api.test/x': (302, {'Location': 'https://elsewhere.test/y'}, b''),
            'https://elsewhere.test/y': (200, {}, b'ok'),
        }
    )
    headers = {'Authorization': 'Bearer secret', 'x-apikey': 'k3y', 'Accept': 'application/json', 'Cookie': 'a=b'}
    _mock_client(site).get('https://api.test/x', headers=headers)
    first, second = site.requests
    assert first.headers['authorization'] == 'Bearer secret' and first.headers['x-apikey'] == 'k3y'
    assert 'authorization' not in second.headers
    assert 'x-apikey' not in second.headers
    assert 'cookie' not in second.headers
    assert second.headers['accept'] == 'application/json'


def test_same_origin_redirect_keeps_headers():
    site = _Site(
        {
            'https://api.test/x': (302, {'Location': '/y'}, b''),
            'https://api.test/y': (200, {}, b'ok'),
        }
    )
    _mock_client(site).get('https://api.test/x', headers={'x-apikey': 'k3y'})
    assert site.requests[1].headers['x-apikey'] == 'k3y'


def test_303_turns_post_into_bodyless_get():
    site = _Site(
        {
            'https://api.test/rpc': (303, {'Location': '/result'}, b''),
            'https://api.test/result': (200, {}, b'ok'),
        }
    )
    _mock_client(site).post('https://api.test/rpc', b'<methodCall/>', headers={'Content-Type': 'text/xml'})
    second = site.requests[1]
    assert second.method == 'GET'
    assert second.content == b''
    assert 'content-type' not in second.headers


def test_307_preserves_post_and_body():
    site = _Site(
        {
            'https://api.test/rpc': (307, {'Location': '/rpc2'}, b''),
            'https://api.test/rpc2': (200, {}, b'ok'),
        }
    )
    _mock_client(site).post('https://api.test/rpc', b'<methodCall/>')
    second = site.requests[1]
    assert second.method == 'POST' and second.content == b'<methodCall/>'


def test_malformed_location_is_a_permanent_error():
    site = _Site({'https://api.test/x': (302, {'Location': 'http://[::1'}, b'')})
    with pytest.raises(SourceUnavailable, match='redirect'):
        _mock_client(site).get('https://api.test/x')


def _redirect_loop(handler, stats):
    n = int(handler.path.rsplit('/', 1)[1])
    handler.send_response(302)
    handler.send_header('Location', f'/r/{n + 1}')
    handler.send_header('Content-Length', '0')
    handler.end_headers()


def test_redirect_count_bounded_end_to_end(monkeypatch):
    alias_public_host(monkeypatch)
    client = SafeHttpClient(policies=HostPolicies(), timeout=5, max_redirects=3)
    with serve(_redirect_loop) as (port, stats):
        with pytest.raises(SourceUnavailable, match='too many redirects'):
            client.get(f'http://{PUBLIC_ALIAS}:{port}/r/0')
    assert stats.hits == ['/r/0', '/r/1', '/r/2', '/r/3']  # the initial request + max_redirects hops


_REDIRECT_BODY_CAP = 200 * 1024 * 1024


def _redirect_with_endless_body(handler, stats):
    if handler.path == '/final':
        handler.send_response(200)
        handler.send_header('Content-Length', '2')
        handler.end_headers()
        handler.wfile.write(b'ok')
        return
    handler.send_response(302)
    handler.send_header('Location', '/final')
    handler.end_headers()  # HTTP/1.0, no Content-Length: the body runs until the server closes
    block = b'A' * 65536
    while stats.bytes_written < _REDIRECT_BODY_CAP:
        handler.wfile.write(block)
        stats.wrote(len(block))


def test_redirect_body_is_never_read(monkeypatch):
    """httpx reads every redirect body in full (unbounded, decoded) before following it."""
    alias_public_host(monkeypatch)
    client = SafeHttpClient(policies=HostPolicies(), timeout=10, max_response_size=1024 * 1024)
    with serve(_redirect_with_endless_body) as (port, stats):
        response = client.get(f'http://{PUBLIC_ALIAS}:{port}/start')
    assert response.text == 'ok'
    assert stats.bytes_written < 50 * 1024 * 1024


@pytest.mark.parametrize(
    'location', ['https://secure-osint-guard-probe.invalid/', 'https://SECURE-OSINT-GUARD-PROBE.invalid./x']
)
def test_redirect_to_the_reserved_guard_probe_host_is_a_source_error(location):
    # The guarded backend raises a private marker for this name (construction-time self-check). Reached
    # through a redirect it must stay a SourceError, or one platform would fail a whole username sweep.
    site = _Site({'https://public.test/start': (302, {'Location': location}, b'')})
    with pytest.raises(SourceUnavailable, match='reserved host'):
        _mock_client(site).get('https://public.test/start')
    assert len(site.requests) == 1


def test_request_to_the_reserved_guard_probe_host_is_refused():
    with pytest.raises(SourceUnavailable, match='reserved host'):
        SafeHttpClient(policies=HostPolicies(), timeout=5).get('https://secure-osint-guard-probe.invalid/')
