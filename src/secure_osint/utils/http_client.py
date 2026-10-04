import json
import logging
import os
import threading
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import httpcore
import httpx

from secure_osint.security.ssrf_guard import SSRFError, resolve_public_addresses
from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.utils.deadline import DeadlineExceeded, clamp_timeout, remaining
from secure_osint.utils.resilience import CircuitOpenError, HostPolicies, host_policies

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = 'SecureOSINT-Tool/1.0'

# Only encodings this module decodes itself with a bounded output (see `_BoundedDecoder`).
ACCEPT_ENCODING = 'gzip, deflate'
_MAX_ENCODING_LAYERS = 2

# Headers that may follow a redirect to a different origin. Everything else a caller set
# (Authorization, API-key headers, cookies, content headers) is dropped on a cross-origin hop.
_CROSS_ORIGIN_SAFE_HEADERS = frozenset({'accept', 'accept-language', 'user-agent'})

# A reserved (.invalid, RFC 2606) name that `GuardedNetworkBackend` recognises without resolving it.
# Each client sends one request to it at construction to prove the guard sits on the live path.
_GUARD_PROBE_HOST = 'secure-osint-guard-probe.invalid'


class _GuardProbeReached(Exception):
    """Raised by the guarded backend for the construction-time probe; never escapes the client."""


def _bounded_timeout(timeout: Optional[float]) -> Optional[float]:
    """`timeout` clamped to the step deadline (C1); raises DeadlineExceeded once the budget is spent."""
    if timeout is not None:
        return clamp_timeout(timeout)
    left = remaining()
    if left is not None and left <= 0:
        raise DeadlineExceeded('step time budget exhausted')
    return left


class GuardedNetworkBackend(httpcore.SyncBackend):
    """Resolve the name, require every address to be public, then connect to a verified IP.

    The check runs at connect time (for every redirect hop too), which closes the DNS-rebinding
    TOCTOU window and the dual-stack case (a private AAAA next to a public A). TLS/SNI still uses
    the hostname because httpcore passes `server_hostname` separately.
    """

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        """Resolve the host, verify every address is public, and connect to a verified IP.

        Raises:
            SSRFError: If the name resolves to any non-public address.
            DeadlineExceeded: If the step deadline expires between connection attempts.
            httpcore.ConnectError / httpcore.ConnectTimeout: If no verified address accepts.
        """
        if host == _GUARD_PROBE_HOST:
            raise _GuardProbeReached()
        last_error: Optional[Exception] = None
        for ip in resolve_public_addresses(host, port):
            try:
                return super().connect_tcp(
                    ip,
                    port,
                    timeout=_bounded_timeout(timeout),
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                last_error = e
        if last_error is None:
            raise httpcore.ConnectError(f'No verified address to connect to for {host}')
        raise last_error

    def connect_unix_socket(self, path: str, timeout: Optional[float] = None, socket_options: Any = None) -> Any:
        """Unix sockets bypass IP checks entirely (e.g. the Docker socket): never allowed."""
        raise SSRFError('Unix socket connections are not allowed')


def _guarded_transport(limits: httpx.Limits) -> httpx.HTTPTransport:
    """An HTTPTransport whose connection pool connects only through `GuardedNetworkBackend`.

    httpx does not expose `network_backend`, so the private `_pool` is replaced (httpx is pinned
    <0.29). If httpx ever renames that attribute the assignment would silently create a dead
    attribute and every request would bypass the guard, so this fails CLOSED instead.
    """
    transport = httpx.HTTPTransport(limits=limits)
    if not isinstance(getattr(transport, '_pool', None), httpcore.ConnectionPool):
        raise RuntimeError(
            'SSRF guard cannot be installed: httpx.HTTPTransport no longer keeps its connection pool in '
            '`_pool`. Refusing to run without connect-time address checks.'
        )
    transport._pool = httpcore.ConnectionPool(
        ssl_context=httpx.create_ssl_context(),
        max_connections=limits.max_connections,
        max_keepalive_connections=limits.max_keepalive_connections,
        keepalive_expiry=limits.keepalive_expiry,
        network_backend=GuardedNetworkBackend(),
    )
    backend = getattr(transport._pool, '_network_backend', None)
    if not isinstance(backend, GuardedNetworkBackend):
        raise RuntimeError(
            'SSRF guard cannot be installed: httpcore.ConnectionPool no longer keeps its backend in '
            '`_network_backend`. Refusing to run without connect-time address checks.'
        )
    return transport


@dataclass
class HttpResponse:
    """A minimal HTTP response (status, decoded body bytes, headers).

    Header names are always lower-cased (e.g. 'retry-after', 'x-ratelimit-remaining'), whatever
    case the server or the caller used, so lookups never depend on the server's spelling.
    """

    status_code: int
    content: bytes
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.headers = {str(k).lower(): v for k, v in self.headers.items()}

    @property
    def text(self) -> str:
        """The body decoded as UTF-8 (replacing invalid bytes)."""
        return self.content.decode('utf-8', errors='replace')

    def json(self) -> Any:
        """Parse the body as JSON.

        Raises:
            SourceUnavailable: If the body is not valid JSON.
        """
        try:
            return json.loads(self.content)
        except ValueError as e:
            raise SourceUnavailable(f'Invalid JSON response: {e}') from e


def raise_for_status(response: HttpResponse, host: str = '') -> None:
    """Raise a typed error for a non-success HTTP status, with a descriptive message.

    Args:
        response: The response to inspect.
        host: Hostname used in the error message (never the full URL, which may carry target data).

    Raises:
        TransientSourceError: On 429 (rate limited) or 5xx (server error); worth retrying.
        SourceUnavailable: On 404 (not found) or any other 4xx (permanent for this request).
    """
    code = response.status_code
    if code == 429:
        raise TransientSourceError(f'{host}: rate limited (HTTP 429); back off and retry later')
    if code >= 500:
        raise TransientSourceError(f'{host}: server error (HTTP {code}); retry later')
    if code == 404:
        raise SourceUnavailable(f'{host}: not found (HTTP 404)')
    if code >= 400:
        raise SourceUnavailable(f'{host}: request rejected (HTTP {code})')


class _BodyTooLarge(Exception):
    pass


class _Inflater:
    """One Content-Encoding layer (gzip or deflate) that never emits more than `limit` bytes per call."""

    def __init__(self, encoding: str):
        self.encoding = encoding
        gzip_framed = encoding in ('gzip', 'x-gzip')
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS if gzip_framed else zlib.MAX_WBITS)
        # 'deflate' is zlib-framed per RFC 9110, but servers often send raw deflate: retry once raw.
        self._may_fall_back_to_raw = not gzip_framed
        self._started = False
        self._fed = False

    def decompress(self, data: bytes, limit: int) -> bytes:
        self._fed = self._fed or bool(data)
        out: List[bytes] = []
        size = 0
        pending = data
        while pending:
            try:
                # max_length bounds the output of THIS call: a tiny chunk can no longer expand
                # into gigabytes before the size check runs. max_length=0 would mean unbounded.
                chunk = self._d.decompress(pending, limit - size + 1)
            except zlib.error:
                if self._may_fall_back_to_raw and not self._started:
                    self._may_fall_back_to_raw = False
                    self._d = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise
            self._started = True
            size += len(chunk)
            if size > limit:
                raise _BodyTooLarge()
            out.append(chunk)
            pending = self._d.unconsumed_tail
        return b''.join(out)

    def flush(self, limit: int) -> bytes:
        tail = self._d.flush()
        if len(tail) > limit:
            raise _BodyTooLarge()
        # zlib's flush() never complains about a truncated stream: an incomplete header or a body
        # cut short would otherwise decode silently to nothing (or to a prefix).
        if self._fed and not self._d.eof:
            raise zlib.error(f'truncated {self.encoding} stream')
        return tail


class _BoundedDecoder:
    """Decode a Content-Encoding chain incrementally with a hard cap on the DECODED size.

    httpx's own decoders inflate every network chunk without an output bound, so one 64 KiB chunk
    of gzip-in-gzip can expand to gigabytes in memory before any size check can run.
    """

    def __init__(self, content_encoding: str, limit: int, host: str):
        layers = [e.strip().lower() for e in content_encoding.split(',') if e.strip()]
        layers = [e for e in layers if e != 'identity']
        unsupported = sorted({e for e in layers if e not in ('gzip', 'x-gzip', 'deflate')})
        if unsupported:
            raise SourceUnavailable(f'{host}: unsupported content-encoding {", ".join(unsupported)}')
        if len(layers) > _MAX_ENCODING_LAYERS:
            raise SourceUnavailable(f'{host}: too many content-encoding layers ({len(layers)})')
        # Encodings are listed in the order they were applied: undo them in reverse.
        self._layers = [_Inflater(e) for e in reversed(layers)]
        self._limit = limit
        self._size = 0
        self._host = host

    def feed(self, data: bytes) -> bytes:
        return self._account(self._run(data, flush=False))

    def finish(self) -> bytes:
        return self._account(self._run(b'', flush=True))

    def _run(self, data: bytes, flush: bool) -> bytes:
        budget = self._limit - self._size
        try:
            for layer in self._layers:
                data = layer.decompress(data, budget) if data else b''
                if flush:
                    data += layer.flush(budget - len(data))
        except zlib.error as e:
            raise SourceUnavailable(f'{self._host}: invalid {self._encodings()} response body') from e
        return data

    def _account(self, data: bytes) -> bytes:
        self._size += len(data)
        if self._size > self._limit:
            raise _BodyTooLarge()
        return data

    def _encodings(self) -> str:
        return ', '.join(layer.encoding for layer in reversed(self._layers)) or 'identity'


def _origin(url: httpx.URL) -> tuple:
    return url.scheme, url.host, url.port


class SafeHttpClient:
    """Shared HTTP client: anti-SSRF DNS pinning, size limit enforced while streaming, per-host rate
    limit and circuit breaker, step deadline (C1). Raises SourceError, never httpx exceptions."""

    def __init__(
        self,
        timeout: float = 15.0,
        max_redirects: int = 3,
        max_response_size: int = 10 * 1024 * 1024,
        user_agent: str = DEFAULT_USER_AGENT,
        policies: Optional[HostPolicies] = None,
        trust_env: bool = False,
    ):
        """Initialize SafeHttpClient.

        Raises:
            RuntimeError: If the SSRF guard cannot be proven to sit on the request path.
        """
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size
        self.policies = policies or host_policies
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=10, keepalive_expiry=30.0)
        # Redirects are followed by `_send`, not by httpx: httpx reads every redirect body in full
        # (unbounded) and forwards custom credential headers to other origins.
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={'User-Agent': user_agent, 'Accept-Encoding': ACCEPT_ENCODING},
            transport=None if trust_env else _guarded_transport(limits),
            trust_env=trust_env,
        )
        self._trust_env = trust_env
        if trust_env:
            logger.warning(
                'SECURE_OSINT_TRUST_ENV=1: HTTP proxies from the environment are honoured, so the proxy '
                'resolves host names and connect-time SSRF address pinning is DISABLED. Only a '
                'pre-flight DNS check runs before each hop, which DNS rebinding can defeat. Unset it '
                'unless you need a proxy.'
            )
        else:
            self._verify_guard_on_request_path()

    def _verify_guard_on_request_path(self) -> None:
        """Send one request to a reserved name and require the guarded backend to be the one that sees it.

        The structural check in `_guarded_transport` proves the attribute exists; this proves the
        client really routes through it (mounts, transport selection, pool), without any DNS lookup.
        """
        try:
            with self._client.stream('GET', f'http://{_GUARD_PROBE_HOST}/', timeout=5.0):
                pass
        except _GuardProbeReached:
            return
        except Exception as e:
            raise RuntimeError(
                f'SSRF guard is not on the request path ({type(e).__name__}); refusing to run unguarded'
            ) from e
        raise RuntimeError('SSRF guard is not on the request path; refusing to run unguarded')

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        """Perform a guarded GET and return the response.

        Args:
            url: Absolute http(s) URL.
            params: Optional query parameters.
            headers: Optional request headers.
            timeout: Per-request timeout (defaults to the client timeout), clamped to the step deadline.

        Returns:
            The HttpResponse.

        Raises:
            SourceUnavailable: Blocked URL or redirect, oversized body, or open circuit.
            TransientSourceError: Timeout, connection error, or local rate-limit wait exceeded.
            DeadlineExceeded: The enclosing step's time budget ran out.
        """
        return self._request('GET', url, params=params, headers=headers, timeout=timeout)

    def post(
        self,
        url: str,
        content: bytes,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        """Perform a guarded POST with a raw body (same SSRF, size, rate-limit and circuit guards as GET).

        Raises:
            SourceUnavailable: Blocked URL or redirect, oversized body, or open circuit.
            TransientSourceError: Timeout, connection error, or local rate-limit wait exceeded.
            DeadlineExceeded: The enclosing step's time budget ran out.
        """
        return self._request('POST', url, headers=headers, timeout=timeout, content=content)

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        content: Optional[bytes] = None,
    ) -> HttpResponse:
        # Single path for every method: no request skips the checks.
        parsed = urlparse(url)
        host = parsed.hostname or ''
        if parsed.scheme not in ('http', 'https') or not host:
            raise SourceUnavailable('URL blocked: unsupported scheme or missing host')
        if host.lower().rstrip('.') == _GUARD_PROBE_HOST:
            raise SourceUnavailable('URL blocked: reserved host')
        if self._trust_env:
            self._preflight(host, parsed.port or (443 if parsed.scheme == 'https' else 80))

        breaker = self.policies.breaker(host)
        try:
            breaker.before_call()
        except CircuitOpenError as e:
            raise SourceUnavailable(f'{host}: circuit open after repeated failures') from e
        base_timeout = timeout or self.timeout
        # C1: raises DeadlineExceeded before any I/O once the step budget is spent.
        wait_timeout = clamp_timeout(base_timeout)
        if not self.policies.limiter(host).acquire(timeout=wait_timeout):
            if wait_timeout < base_timeout:
                raise DeadlineExceeded(f'{host}: step time budget exhausted waiting for the local rate limit')
            raise TransientSourceError(f'{host}: local rate limit wait exceeded')
        effective_timeout = clamp_timeout(base_timeout)

        try:
            result = self._send(method, url, params, headers, content, base_timeout, host)
        except SSRFError as e:
            # A redirect to an internal address lands here. It does not count as a host failure.
            raise SourceUnavailable(f'URL blocked by SSRF guard: {e}') from e
        except _GuardProbeReached as e:  # belt and braces: the construction-time marker never leaves the client
            raise SourceUnavailable(f'{host}: reserved host refused') from e
        except httpx.TimeoutException as e:
            left = remaining()
            if left is not None and left <= 0.05:
                # The timeout was the step deadline, not the host: retrying cannot help.
                raise DeadlineExceeded(f'{host}: step time budget exhausted') from e
            breaker.record_failure()
            # Only the error type and host: the full URL may carry target data.
            raise TransientSourceError(f'{host}: timed out after {effective_timeout:g}s ({type(e).__name__})') from e
        except httpx.TransportError as e:
            breaker.record_failure()
            raise TransientSourceError(f'{host}: connection error ({type(e).__name__})') from e

        if result.status_code == 429 or result.status_code >= 500:
            breaker.record_failure()
        else:
            breaker.record_success()
        return result

    def _preflight(self, host: str, port: int) -> None:
        """Resolve-and-check used only with trust_env, where the proxy (not us) connects."""
        try:
            resolve_public_addresses(host, port)
        except SSRFError as e:
            raise SourceUnavailable(f'URL blocked by SSRF guard: {e}') from e

    def _send(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]],
        content: Optional[bytes],
        base_timeout: float,
        host: str,
    ) -> HttpResponse:
        """Send the request and follow at most `max_redirects` redirects, one guarded hop at a time."""
        hop_url: str = url
        hop_params = params
        hop_headers: Dict[str, str] = dict(headers or {})
        hop_content = content
        for _ in range(self.max_redirects + 1):
            try:
                with self._client.stream(
                    method,
                    hop_url,
                    params=hop_params,
                    headers=hop_headers,
                    content=hop_content,
                    timeout=clamp_timeout(base_timeout),
                    follow_redirects=False,
                ) as response:
                    if not response.has_redirect_location:
                        body = self._read_body(response, host, base_timeout)
                        return HttpResponse(response.status_code, body, dict(response.headers))
                    current = response.request.url
                    target = self._redirect_target(current, response.headers['location'], host)
                    status = response.status_code
                    # Leaving the block closes the redirect response WITHOUT reading its body.
            except httpx.RemoteProtocolError as e:
                # httpx parses Location (to build `next_request`) even when not following redirects.
                # A malformed one is the server's deterministic answer, not a flaky connection.
                if 'location header' in str(e).lower():
                    raise SourceUnavailable(f'{host}: invalid redirect location') from e
                raise

            if status in (302, 303) and method != 'HEAD':
                new_method = 'GET'
            elif status == 301 and method == 'POST':
                new_method = 'GET'
            else:
                new_method = method
            if new_method != method:
                hop_content = None
                hop_headers = {k: v for k, v in hop_headers.items() if not k.lower().startswith('content-')}
            if _origin(target) != _origin(current):
                hop_headers = {k: v for k, v in hop_headers.items() if k.lower() in _CROSS_ORIGIN_SAFE_HEADERS}
            if self._trust_env:
                self._preflight(target.host, target.port or (443 if target.scheme == 'https' else 80))
            method, hop_url, hop_params = new_method, str(target), None
        raise SourceUnavailable(f'{host}: too many redirects (more than {self.max_redirects})')

    @staticmethod
    def _redirect_target(current: httpx.URL, location: str, host: str) -> httpx.URL:
        """Resolve a Location header against the current URL and refuse unsafe targets."""
        try:
            target = httpx.URL(location)
        except httpx.InvalidURL as e:
            raise SourceUnavailable(f'{host}: invalid redirect location') from e
        if target.scheme and not target.host:
            target = target.copy_with(host=current.host)
        if target.is_relative_url:
            target = current.join(target)
        if target.scheme not in ('http', 'https'):
            raise SourceUnavailable(f'{host}: refused redirect to unsupported scheme {target.scheme!r}')
        if current.scheme == 'https' and target.scheme == 'http':
            raise SourceUnavailable(f'{host}: refused redirect from https to http (TLS downgrade)')
        if target.host.lower().rstrip('.') == _GUARD_PROBE_HOST:
            raise SourceUnavailable(f'{host}: refused redirect to a reserved host')
        return target

    def _read_body(self, response: httpx.Response, host: str, base_timeout: float) -> bytes:
        """Read the body with the size cap applied to DECODED bytes and the step deadline enforced per chunk."""
        limit = self.max_response_size
        too_large = SourceUnavailable(f'{host}: response exceeds {limit} bytes')
        declared = response.headers.get('content-length', '')
        if declared.isdigit() and int(declared) > limit:
            raise too_large
        raw: Iterable[bytes]
        if response.is_stream_consumed:
            # Already read upstream (mock transports): httpx decoded it, only the cap remains to apply.
            raw, decoder = [response.content], _BoundedDecoder('', limit, host)
        else:
            raw, decoder = (
                response.iter_raw(),
                _BoundedDecoder(response.headers.get('content-encoding', ''), limit, host),
            )
        chunks: List[bytes] = []
        wire = 0
        try:
            for chunk in raw:
                # httpx timeouts are per read: a server dripping one byte at a time would never trip
                # them, so the step deadline is checked between chunks too.
                clamp_timeout(base_timeout)
                wire += len(chunk)
                if wire > limit:
                    raise too_large
                chunks.append(decoder.feed(chunk))
            chunks.append(decoder.finish())
        except _BodyTooLarge:
            raise too_large from None
        return b''.join(chunks)

    def close(self) -> None:
        """Close the underlying HTTP client and its connection pool."""
        self._client.close()


_shared: Optional[SafeHttpClient] = None
_shared_lock = threading.Lock()


def shared_client() -> SafeHttpClient:
    """One client (and one connection pool) per process, reused by every source."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = SafeHttpClient(
                user_agent=os.environ.get('SECURE_OSINT_USER_AGENT', DEFAULT_USER_AGENT),
                trust_env=os.environ.get('SECURE_OSINT_TRUST_ENV', '') == '1',
            )
        return _shared
