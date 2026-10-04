"""Response bodies: the size cap applies to DECODED bytes and memory stays bounded while decoding."""

import gzip
import time
import tracemalloc
import zlib

import httpx
import pytest

from secure_osint.sources.base import SourceUnavailable
from secure_osint.utils.http_client import HttpResponse, SafeHttpClient
from secure_osint.utils.resilience import HostPolicies
from tests.http_test_server import PUBLIC_ALIAS, alias_public_host, serve

MB = 1024 * 1024


def _gzip_stream(total: int, block: int = MB, level: int = 9) -> bytes:
    """gzip of `total` zero bytes, built incrementally so the test itself never holds `total` bytes."""
    comp = zlib.compressobj(level, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    zeros = bytes(block)
    out = [comp.compress(zeros) for _ in range(total // block)]
    out.append(comp.flush())
    return b''.join(out)


def _mock_client(handler, **kwargs):
    client = SafeHttpClient(policies=HostPolicies(), timeout=5, **kwargs)
    client._client._transport = httpx.MockTransport(handler)
    return client


def _streamed(body: bytes, status: int = 200, **headers) -> httpx.Response:
    """A response whose body has NOT been read yet (like a real network response)."""
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


# --- headers ----------------------------------------------------------------------------------


def test_http_response_headers_lower_cased():
    response = HttpResponse(429, b'', {'Retry-After': '30', 'X-RateLimit-Remaining': '0'})
    assert response.headers == {'retry-after': '30', 'x-ratelimit-remaining': '0'}


def test_client_response_headers_lower_cased():
    client = _mock_client(lambda r: _streamed(b'{}', **{'X-RateLimit-Remaining': '0', 'Retry-After': '7'}))
    response = client.get('https://api.test/')
    assert response.headers['x-ratelimit-remaining'] == '0'
    assert response.headers['retry-after'] == '7'
    assert all(k == k.lower() for k in response.headers)


# --- decoding -----------------------------------------------------------------------------------


def test_only_decodable_encodings_are_advertised():
    seen = []

    def handler(request):
        seen.append(request.headers.get('accept-encoding'))
        return _streamed(b'ok')

    _mock_client(handler).get('https://api.test/')
    assert seen == ['gzip, deflate']


def test_gzip_body_decoded():
    body = gzip.compress(b'{"ok": true}')
    client = _mock_client(lambda r: _streamed(body, **{'content-encoding': 'gzip'}))
    assert client.get('https://api.test/').json() == {'ok': True}


@pytest.mark.parametrize('wbits', [zlib.MAX_WBITS, -zlib.MAX_WBITS], ids=['zlib-wrapped', 'raw'])
def test_deflate_body_decoded_in_both_framings(wbits):
    comp = zlib.compressobj(6, zlib.DEFLATED, wbits)
    body = comp.compress(b'hello deflate' * 100) + comp.flush()
    client = _mock_client(lambda r: _streamed(body, **{'content-encoding': 'deflate'}))
    assert client.get('https://api.test/').content == b'hello deflate' * 100


def test_stacked_encodings_decoded_in_reverse_order():
    inner = gzip.compress(b'layered')
    comp = zlib.compressobj(6, zlib.DEFLATED, zlib.MAX_WBITS)
    body = comp.compress(inner) + comp.flush()
    client = _mock_client(lambda r: _streamed(body, **{'content-encoding': 'gzip, deflate'}))
    assert client.get('https://api.test/').content == b'layered'


def test_unsupported_encoding_refused():
    client = _mock_client(lambda r: _streamed(b'\x8b\x00', **{'content-encoding': 'br'}))
    with pytest.raises(SourceUnavailable, match='content-encoding'):
        client.get('https://api.test/')


def test_corrupt_gzip_is_a_permanent_error():
    client = _mock_client(lambda r: _streamed(b'\x1f\x8b\x08\x00garbage', **{'content-encoding': 'gzip'}))
    with pytest.raises(SourceUnavailable, match='gzip'):
        client.get('https://api.test/')


# --- size cap -----------------------------------------------------------------------------------


def test_identity_body_over_cap_refused():
    client = _mock_client(lambda r: _streamed(b'x' * (MB + 1)), max_response_size=MB)
    with pytest.raises(SourceUnavailable, match='exceeds'):
        client.get('https://api.test/')


def test_body_exactly_at_cap_accepted():
    client = _mock_client(lambda r: _streamed(b'x' * MB), max_response_size=MB)
    assert len(client.get('https://api.test/').content) == MB


def test_cap_applies_to_decoded_bytes_not_wire_bytes():
    body = _gzip_stream(5 * MB)
    assert len(body) < MB // 10  # tiny on the wire
    client = _mock_client(lambda r: _streamed(body, **{'content-encoding': 'gzip'}), max_response_size=MB)
    with pytest.raises(SourceUnavailable, match='exceeds'):
        client.get('https://api.test/')


def test_declared_content_length_over_cap_refused_without_reading():
    class Exploding(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError('body must not be read when Content-Length is already over the cap')

    def handler(request):
        return httpx.Response(200, headers={'content-length': str(50 * MB)}, stream=Exploding())

    with pytest.raises(SourceUnavailable, match='exceeds'):
        _mock_client(handler, max_response_size=MB).get('https://api.test/')


def test_double_gzip_bomb_does_not_explode_memory():
    """One small wire chunk of gzip-in-gzip expands to hundreds of MB in a single decompress call.

    httpx's decoder inflates each chunk without an output bound, so the cap was only checked AFTER
    the whole expansion sat in memory.
    """
    inner = _gzip_stream(256 * MB)
    bomb = gzip.compress(inner, compresslevel=9)
    assert len(bomb) < 64 * 1024

    client = _mock_client(lambda r: _streamed(bomb, **{'content-encoding': 'gzip, gzip'}), max_response_size=MB)
    tracemalloc.start()
    try:
        with pytest.raises(SourceUnavailable, match='exceeds'):
            client.get('https://api.test/')
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 32 * MB, f'peak {peak / MB:.0f} MB while decoding'


# --- end to end over a real socket --------------------------------------------------------------

_WIRE_CAP = 64 * MB


def _endless_gzip(handler, stats):
    """A never-ending gzip stream of zeros (about 1000:1); stops on its own after 64 MB on the wire."""
    comp = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    header = comp.compress(bytes(MB)) + comp.flush(zlib.Z_FULL_FLUSH)
    # After a full flush the compressor holds no history, so this block can be repeated verbatim.
    block = comp.compress(bytes(4 * MB)) + comp.flush(zlib.Z_FULL_FLUSH)
    handler.send_response(200)
    handler.send_header('Content-Encoding', 'gzip')
    handler.end_headers()
    handler.wfile.write(header)
    stats.wrote(len(header))
    while stats.bytes_written < _WIRE_CAP:
        handler.wfile.write(block)
        stats.wrote(len(block))


def test_endless_gzip_stream_read_stops_at_decoded_cap(monkeypatch):
    alias_public_host(monkeypatch)
    client = SafeHttpClient(policies=HostPolicies(), timeout=10, max_response_size=2 * MB)
    with serve(_endless_gzip) as (port, stats):
        start = time.monotonic()
        with pytest.raises(SourceUnavailable, match='exceeds'):
            client.get(f'http://{PUBLIC_ALIAS}:{port}/bomb')
        elapsed = time.monotonic() - start
    assert elapsed < 5.0
    # 64 MB on the wire would be ~64 GB decoded: the client hung up long before.
    assert stats.bytes_written < _WIRE_CAP


def test_truncated_gzip_body_is_a_permanent_error():
    """Regression: zlib's flush() accepted a stream cut short and returned a silent prefix."""
    full = gzip.compress(b'complete body' * 1000)
    client = _mock_client(lambda r: _streamed(full[: len(full) // 2], **{'content-encoding': 'gzip'}))
    with pytest.raises(SourceUnavailable, match='gzip'):
        client.get('https://api.test/')


def test_empty_body_with_gzip_encoding_is_accepted():
    client = _mock_client(lambda r: _streamed(b'', **{'content-encoding': 'gzip'}))
    assert client.get('https://api.test/').content == b''
