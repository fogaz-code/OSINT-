import ipaddress
import socket
from unittest.mock import patch

import pytest

from secure_osint.security.ssrf_guard import SSRFError, is_public_ip, is_safe_url, resolve_public_addresses


def _gai(*ips):
    def fake(host, port, *a, **k):
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port)) for ip in ips]

    return fake


@pytest.mark.parametrize(
    'ip',
    [
        '127.0.0.1',
        '10.0.0.1',
        '192.168.1.1',
        '169.254.169.254',
        '0.0.0.0',
        '100.64.0.1',
        '224.0.0.1',
        '255.255.255.255',
        '::1',
        'fd00::1',
        'fe80::1',
        '::ffff:127.0.0.1',
        '::ffff:169.254.169.254',
        '2002:7f00:1::',
        '64:ff9b::a00:1',
        'fd00:ec2::254',
        'ff02::1',
        '2001::1',
    ],
)
def test_non_public_ips_blocked(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize('ip', ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])
def test_public_ips_allowed(ip):
    assert is_public_ip(ip)


# --- IPv6 encodings that carry an IPv4 address -------------------------------------------------
# Python's ipaddress reports several of these as global (e.g. '::127.0.0.1'), and its verdict on the
# others changes between 3.10 and 3.13, so the guard must decide them explicitly.


def _v4_embeddings(v4: str) -> dict:
    """Every IPv6 form that routes to (or names) the given IPv4 address."""
    n = int(ipaddress.IPv4Address(v4))
    return {
        'ipv4-mapped': ipaddress.IPv6Address((0xFFFF << 32) | n),
        'ipv4-translated': ipaddress.IPv6Address((0xFFFF << 48) | n),
        'ipv4-compatible': ipaddress.IPv6Address(n),
        '6to4': ipaddress.IPv6Address((0x2002 << 112) | (n << 80) | 1),
        'nat64-well-known': ipaddress.IPv6Address((0x0064FF9B << 96) | n),
        'nat64-local-use': ipaddress.IPv6Address((0x0064FF9B0001 << 80) | n),
    }


@pytest.mark.parametrize(
    'ip',
    [
        # IPv4-compatible (deprecated, ::/96) - reported global by Python: the verified bypass.
        '::127.0.0.1',
        '::7f00:1',
        '::169.254.169.254',
        '::10.0.0.1',
        '::192.168.0.1',
        '::0.0.0.2',
        # IPv4-translated (SIIT, ::ffff:0:0:0/96) - also reported global by Python.
        '::ffff:0:127.0.0.1',
        '::ffff:0:a9fe:a9fe',
        '::ffff:0:10.0.0.1',
        # IPv4-mapped, 6to4 and NAT64 well-known prefix carrying a private IPv4.
        '::ffff:10.0.0.1',
        '2002:a9fe:a9fe::1',
        '2002:c0a8:101::',
        '64:ff9b::127.0.0.1',
        '64:ff9b::169.254.169.254',
        # NAT64 local-use prefix (RFC 8215) is never globally reachable, whatever it embeds.
        '64:ff9b:1::808:808',
        '64:ff9b:1::7f00:1',
        # Deprecated site-local (fec0::/10) and SRv6 SIDs (5f00::/16): Python reports both as global.
        'fec0::1',
        'fec0:0:0:ffff::1',
        '5f00::1',
        # Teredo (embeds an obfuscated client IPv4) stays rejected, as does the documentation range.
        '2001:0:4136:e378:8000:63bf:3fff:fdd2',
        '3fff::1',
    ],
)
def test_ipv6_embeddings_of_non_public_ipv4_blocked(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize(
    'ip',
    [
        '::ffff:8.8.8.8',  # IPv4-mapped public
        '::ffff:0:8.8.8.8',  # IPv4-translated public
        '::8.8.8.8',  # IPv4-compatible public
        '2002:808:808::1',  # 6to4 public
        '64:ff9b::808:808',  # DNS64/NAT64 synthesised AAAA on IPv6-only networks: must keep working
    ],
)
def test_ipv6_embeddings_of_public_ipv4_allowed(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize('v4', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1', '100.64.0.1', '0.0.0.0'])
def test_every_embedding_of_private_ipv4_blocked(v4):
    for kind, v6 in _v4_embeddings(v4).items():
        assert not is_public_ip(v6), f'{kind} embedding {v6} of {v4} was accepted'
        assert not is_public_ip(str(v6)), f'{kind} embedding {v6} of {v4} was accepted (str)'


@pytest.mark.parametrize('host', ['::127.0.0.1', '::7f00:1', '::ffff:0:127.0.0.1', '::169.254.169.254', 'fec0::1'])
def test_ipv4_compatible_literals_rejected_by_url_check_and_backend(host):
    from secure_osint.utils.http_client import GuardedNetworkBackend

    assert not is_safe_url(f'http://[{host}]/')
    with pytest.raises(SSRFError):
        GuardedNetworkBackend().connect_tcp(host, 80, timeout=1)


def test_hostname_resolving_to_ipv4_compatible_loopback_rejected():
    with patch('socket.getaddrinfo', _gai('::127.0.0.1')):
        with pytest.raises(SSRFError):
            resolve_public_addresses('compat.example', 80)


_NON_PUBLIC_V4_NETS = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
]

try:
    from hypothesis import assume, given, settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    given = None  # type: ignore[assignment]

if given is not None:

    @st.composite
    def _non_public_v4(draw):
        net = ipaddress.IPv4Network(draw(st.sampled_from(_NON_PUBLIC_V4_NETS)))
        addr = net[draw(st.integers(0, net.num_addresses - 1))]
        # A few addresses inside special blocks are global on recent Pythons (e.g. 192.0.0.9).
        assume(not is_public_ip(addr))
        return addr

    @settings(max_examples=500, deadline=None)
    @given(v4=_non_public_v4(), low_bits=st.integers(0, 2**80 - 1))
    def test_property_no_ipv6_embedding_of_non_public_ipv4_is_public(v4, low_bits):
        assert not is_public_ip(v4)
        for kind, v6 in _v4_embeddings(str(v4)).items():
            assert not is_public_ip(v6), f'{kind}: {v6}'
        n = int(v4)
        # 6to4 with arbitrary subnet/interface bits still routes to the embedded IPv4.
        assert not is_public_ip(ipaddress.IPv6Address((0x2002 << 112) | (n << 80) | low_bits))

    @settings(max_examples=500, deadline=None)
    @given(n=st.integers(0, 2**32 - 1))
    def test_property_embedding_verdict_matches_ipv4_verdict(n):
        v4 = ipaddress.IPv4Address(n)
        expected = is_public_ip(v4)
        for kind, v6 in _v4_embeddings(str(v4)).items():
            if kind == 'nat64-local-use':
                assert not is_public_ip(v6)
            else:
                assert is_public_ip(v6) is expected, f'{kind}: {v6}'


def test_dual_stack_private_aaaa_blocked():
    # Il vecchio controllo guardava solo il record A (gethostbyname).
    with patch('socket.getaddrinfo', _gai('93.184.215.14', '::1')):
        with pytest.raises(SSRFError):
            resolve_public_addresses('dual.example', 443)


def test_any_private_address_rejects_whole_set():
    with patch('socket.getaddrinfo', _gai('8.8.8.8', '10.0.0.5')):
        assert not is_safe_url('https://mixed.example/')


@pytest.mark.parametrize(
    'url',
    [
        'http://127.1/',
        'http://2130706433/',
        'http://0x7f000001/',
        'http://[::1]/',
        'file:///etc/passwd',
        'gopher://example.com/',
        'http:///nohost',
    ],
)
def test_url_forms_blocked(url):
    assert not is_safe_url(url)


def test_guarded_backend_checks_ip_at_connect_time():
    """DNS rebinding: il primo lookup è pubblico, quello usato per la connect no."""
    from secure_osint.utils.http_client import GuardedNetworkBackend

    answers = iter([_gai('93.184.215.14'), _gai('127.0.0.1')])

    def rebinding(host, port, *a, **k):
        return next(answers)(host, port)

    with patch('socket.getaddrinfo', rebinding):
        assert is_safe_url('http://rebind.example/')
        with pytest.raises(SSRFError):
            GuardedNetworkBackend().connect_tcp('rebind.example', 80, timeout=1)


@pytest.fixture
def local_server():
    """Server HTTP su loopback: /redirect rimanda a /secret, che non deve mai essere raggiunto."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/secret')
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'internal data')

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_port, hits
    server.shutdown()


def _client():
    from secure_osint.utils.http_client import SafeHttpClient
    from secure_osint.utils.resilience import HostPolicies

    return SafeHttpClient(policies=HostPolicies(), timeout=5)


def test_client_blocks_loopback_before_sending(local_server):
    from secure_osint.sources.base import SourceUnavailable

    port, hits = local_server
    with pytest.raises(SourceUnavailable, match='SSRF'):
        _client().get(f'http://127.0.0.1:{port}/secret')
    assert hits == []


def test_client_post_blocks_loopback_before_sending(local_server):
    """POST (used for PyPI XML-RPC) goes through the same SSRF guard as GET."""
    from secure_osint.sources.base import SourceUnavailable

    port, hits = local_server
    with pytest.raises(SourceUnavailable, match='SSRF'):
        _client().post(f'http://127.0.0.1:{port}/rpc', b'<methodCall/>')
    assert hits == []


def test_client_blocks_redirect_to_internal(local_server):
    """Il vecchio client seguiva i redirect senza ricontrollarli."""
    import secure_osint.utils.http_client as http_client
    from secure_osint.sources.base import SourceUnavailable

    port, hits = local_server
    real = http_client.resolve_public_addresses

    def allow_entry_host(host, port_):
        # Simula un host pubblico che in realtà serve un redirect verso la rete interna.
        return ['127.0.0.1'] if host == 'public.test' else real(host, port_)

    with patch.object(http_client, 'resolve_public_addresses', allow_entry_host):
        with pytest.raises(SourceUnavailable, match='SSRF'):
            _client().get(f'http://public.test:{port}/redirect')
    assert hits == ['/redirect']  # /secret mai richiesto
