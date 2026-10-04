"""Hardening for the local web UI: credentials from the environment, login throttling, Host/Origin guard.

Threat model
------------
* **Exposed bind** (``--host 0.0.0.0``, a LAN address or a host name): anyone who can reach the port
  could run investigations and download reports. ``secure-osint gui`` refuses to listen on a
  non-loopback address unless ``SECURE_OSINT_GUI_AUTH=user:password`` is set (password of at least
  ``MIN_PASSWORD_LENGTH`` characters). Credentials come from the environment only: a command-line
  argument would be visible to every local user in the process list. When the variable is set, the
  login is required on loopback too.
* **Password guessing**: Gradio's ``/login`` has no rate limit. ``auth_checker`` compares in constant
  time and, after ``MAX_LOGIN_FAILURES`` failures within ``LOGIN_LOCKOUT_SECONDS``, refuses every
  attempt (even a correct one) for that user name until the window has passed. Unknown user names
  share one separate bucket, so guessing names cannot lock the real user out.
* **DNS rebinding against the loopback UI**: a website the user visits can re-point its own name to
  127.0.0.1 and then talk to the UI as a *same-origin* page, so CORS does not help. Gradio 6 does not
  validate the Host header (its ``CustomCORSMiddleware`` only chooses CORS headers), so
  ``HostGuardMiddleware`` refuses (HTTP 400, or WebSocket close 1008) any request whose Host is not
  ``localhost``/``127.0.0.1``/``[::1]``, the configured ``--host`` or a name listed in
  ``SECURE_OSINT_GUI_ALLOWED_HOSTS``. On a wildcard bind (``0.0.0.0``/``::``) the address users type
  is unknown, so IP literals are accepted too: rebinding always arrives with the attacker's DNS name
  in Host, never with an IP literal.
* **Cross-site request forgery**: a page on another origin can still send requests to 127.0.0.1.
  A request that carries ``Origin`` must be exactly same-origin with its Host (scheme default ports
  normalised); ``Origin: null`` (sandboxed frames, ``file://``) and other local ports are refused.
* **Clickjacking**: responses get ``X-Frame-Options: DENY`` and ``frame-ancestors 'none'``, so no
  other site can frame the UI and trick the user into accepting the policy and pressing Run.

The guard is a dependency-free ASGI middleware, installed on Gradio's FastAPI app through
``launch(app_kwargs=server_app_kwargs(host))``; ``launch`` also sets ``ssr_mode=False`` so every
request reaches Python (and the guard) directly.
"""

import hmac
import ipaddress
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any, Awaitable, Callable, Deque, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

AUTH_ENV = 'SECURE_OSINT_GUI_AUTH'
ALLOWED_HOSTS_ENV = 'SECURE_OSINT_GUI_ALLOWED_HOSTS'
MIN_PASSWORD_LENGTH = 12
MAX_LOGIN_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 300.0

LOOPBACK_HOSTS: FrozenSet[str] = frozenset({'localhost', '127.0.0.1', '::1'})
# Bind addresses meaning "every interface": no browser sends them in Host.
WILDCARD_HOSTS: FrozenSet[str] = frozenset({'', '0.0.0.0', '::'})

_SECURITY_HEADERS: Tuple[Tuple[bytes, bytes], ...] = (
    (b'x-frame-options', b'DENY'),
    # img-src: defence in depth against image beacons in rendered reports (remote text is escaped too).
    (b'content-security-policy', b"frame-ancestors 'none'; img-src 'self' data: blob:"),
    (b'x-content-type-options', b'nosniff'),
    (b'referrer-policy', b'no-referrer'),
)
_DEFAULT_PORTS = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443}
_UNKNOWN_USER = object()  # failure bucket shared by every wrong user name

Scope = Dict[str, Any]
Message = Dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


# --- credentials (C11) ---


def gui_credentials(env: Optional[Mapping[str, str]] = None) -> Optional[Tuple[str, str]]:
    """``(user, password)`` from ``SECURE_OSINT_GUI_AUTH=user:password`` (``os.environ`` by default), or None.

    The value is split on the first colon, so the password may contain colons.

    Raises:
        RuntimeError: The value is malformed or the password is shorter than ``MIN_PASSWORD_LENGTH``.
            The message never contains the password.
    """
    raw = (os.environ if env is None else env).get(AUTH_ENV, '')
    if not raw:
        return None
    user, sep, password = raw.partition(':')
    if not sep or not user.strip():
        raise RuntimeError(f'{AUTH_ENV} must have the form user:password.')
    if len(password.strip()) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(f'{AUTH_ENV}: the password must be at least {MIN_PASSWORD_LENGTH} characters long.')
    return user.strip(), password


def auth_checker(
    user: str,
    password: str,
    max_failures: int = MAX_LOGIN_FAILURES,
    lockout_seconds: float = LOGIN_LOCKOUT_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[Any, Any], bool]:
    """A Gradio ``auth`` callable: constant-time check plus a lockout after repeated failures.

    The closure keeps the secret; only the callable is handed to Gradio, so the password never
    appears in launch arguments or their repr.
    """
    expected_user, expected_password = user.encode('utf-8'), password.encode('utf-8')
    failures: Dict[object, Deque[float]] = defaultdict(deque)
    lock = threading.Lock()

    def check(username: Any, candidate: Any) -> bool:
        if not isinstance(username, str) or not isinstance(candidate, str):
            return False
        # Both comparisons always run: the timing does not reveal which half was wrong.
        user_ok = hmac.compare_digest(username.encode('utf-8'), expected_user)
        password_ok = hmac.compare_digest(candidate.encode('utf-8'), expected_password)
        bucket: object = expected_user if user_ok else _UNKNOWN_USER
        with lock:
            recent = failures[bucket]
            cutoff = clock() - lockout_seconds
            while recent and recent[0] <= cutoff:
                recent.popleft()
            if len(recent) >= max_failures:
                return False  # locked out: not even the right password gets in until the window passes
            if user_ok and password_ok:
                recent.clear()
                return True
            recent.append(clock())
            return False

    return check


# --- allowed hosts ---


def _normal_host(name: str) -> str:
    """Lower-case host name without a trailing dot or IPv6 brackets."""
    return name.strip().lower().rstrip('.').strip('[]')


def is_ip_literal(value: str) -> bool:
    """True if ``value`` (brackets allowed) is an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value.strip('[]'))
        return True
    except ValueError:
        return False


def allowed_hosts(server_host: str, env: Optional[Mapping[str, str]] = None) -> FrozenSet[str]:
    """Host header values the UI answers to: loopback names, the bind host and ``SECURE_OSINT_GUI_ALLOWED_HOSTS``."""
    names = set(LOOPBACK_HOSTS)
    host = _normal_host(server_host)
    if host not in WILDCARD_HOSTS:
        names.add(host)
    extra = (os.environ if env is None else env).get(ALLOWED_HOSTS_ENV, '')
    names.update(_normal_host(n) for n in extra.split(',') if n.strip())
    return frozenset(names)


def allows_ip_literals(server_host: str) -> bool:
    """A wildcard bind is reached through addresses we cannot list: accept any IP literal in Host."""
    return _normal_host(server_host) in WILDCARD_HOSTS


def _split_authority(authority: str) -> Optional[Tuple[str, Optional[int]]]:
    """``(hostname, port)`` of a bare ``host[:port]`` authority, or None if it is not one."""
    if not authority or any(c in authority for c in '@/\\?# \t'):
        return None
    try:
        parts = urlsplit(f'//{authority}')
        port = parts.port
    except ValueError:
        return None
    if not parts.hostname:
        return None
    return _normal_host(parts.hostname), port


# --- the ASGI guard ---


class HostGuardMiddleware:
    """ASGI middleware: Host allow-list, same-origin check and anti-framing headers."""

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str] = LOOPBACK_HOSTS, allow_ip_literals: bool = False):
        """Wrap ``app``; ``allowed_hosts`` are names or addresses, ``allow_ip_literals`` accepts any IP too."""
        self.app = app
        self.allowed_hosts = frozenset(_normal_host(h) for h in allowed_hosts)
        self.allow_ip_literals = allow_ip_literals

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process one ASGI connection."""
        kind = scope.get('type')
        if kind not in ('http', 'websocket'):
            await self.app(scope, receive, send)  # lifespan
            return
        if not self._request_allowed(self._headers(scope)):
            await self._refuse(kind, send)
            return
        if kind == 'websocket':
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message.get('type') == 'http.response.start':
                headers = list(message.get('headers', []))
                present = {bytes(k).lower() for k, _ in headers}
                headers.extend((k, v) for k, v in _SECURITY_HEADERS if k not in present)
                message = {**message, 'headers': headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)

    @staticmethod
    def _headers(scope: Scope) -> Dict[str, List[str]]:
        headers: Dict[str, List[str]] = defaultdict(list)
        for key, value in scope.get('headers', []):
            headers[bytes(key).decode('latin-1').lower()].append(bytes(value).decode('latin-1'))
        return headers

    def host_allowed(self, hostname: str) -> bool:
        """True if a (normalised) Host name may reach the UI."""
        return hostname in self.allowed_hosts or (self.allow_ip_literals and is_ip_literal(hostname))

    def _request_allowed(self, headers: Mapping[str, List[str]]) -> bool:
        hosts = headers.get('host', [])
        if len(hosts) != 1:
            return False
        host = _split_authority(hosts[0])
        if host is None or not self.host_allowed(host[0]):
            return False
        origins = headers.get('origin', [])
        if not origins:
            return True  # same-origin GETs and non-browser clients: Host was enough
        return len(origins) == 1 and self._same_origin(origins[0], host)

    @staticmethod
    def _same_origin(origin: str, host: Tuple[str, Optional[int]]) -> bool:
        try:
            parts = urlsplit(origin.strip())
            origin_port = parts.port
        except ValueError:
            return False
        if parts.scheme not in _DEFAULT_PORTS or not parts.hostname or parts.path not in ('', '/'):
            return False
        default = _DEFAULT_PORTS[parts.scheme]
        host_name, host_port = host
        return _normal_host(parts.hostname) == host_name and (origin_port or default) == (host_port or default)

    @staticmethod
    async def _refuse(kind: str, send: Send) -> None:
        if kind == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})  # policy violation
            return
        headers = [(b'content-type', b'text/plain; charset=utf-8'), *_SECURITY_HEADERS]
        await send({'type': 'http.response.start', 'status': 400, 'headers': headers})
        await send({'type': 'http.response.body', 'body': b'Bad request: unexpected Host or Origin header.'})


def server_app_kwargs(server_host: str, env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """``app_kwargs`` for ``gradio.Blocks.launch``: installs ``HostGuardMiddleware`` on the FastAPI app."""
    from starlette.middleware import Middleware  # gradio depends on starlette

    guard = Middleware(
        HostGuardMiddleware,
        allowed_hosts=sorted(allowed_hosts(server_host, env)),
        allow_ip_literals=allows_ip_literals(server_host),
    )
    return {'middleware': [guard]}
