"""Web UI hardening: GUI credentials (C11), login lockout and the Host/Origin guard (DNS rebinding, CSRF).

The guard is a plain ASGI middleware, so these tests drive it directly with asyncio: no gradio,
starlette or network needed. End-to-end checks through Starlette and Gradio live in test_app.py.
"""

import asyncio
from typing import Any, Dict, List, Optional, Tuple

import pytest

from secure_osint.gui_security import (
    ALLOWED_HOSTS_ENV,
    AUTH_ENV,
    MIN_PASSWORD_LENGTH,
    HostGuardMiddleware,
    allowed_hosts,
    allows_ip_literals,
    auth_checker,
    gui_credentials,
)

# --- credentials from the environment (C11) ---


def test_credentials_absent_is_none():
    assert gui_credentials({}) is None
    assert gui_credentials({AUTH_ENV: ''}) is None


def test_credentials_default_to_the_process_environment(monkeypatch):
    monkeypatch.setenv(AUTH_ENV, 'analyst:correct-horse-battery')
    assert gui_credentials() == ('analyst', 'correct-horse-battery')


def test_credentials_are_split_on_the_first_colon():
    assert gui_credentials({AUTH_ENV: 'analyst:correct:horse:battery'}) == ('analyst', 'correct:horse:battery')


@pytest.mark.parametrize('value', ['no-colon-at-all', ':longenoughpassword', '   :longenoughpassword'])
def test_malformed_credentials_are_rejected(value):
    with pytest.raises(RuntimeError, match=AUTH_ENV):
        gui_credentials({AUTH_ENV: value})


def test_short_password_is_rejected_without_echoing_it():
    with pytest.raises(RuntimeError) as excinfo:
        gui_credentials({AUTH_ENV: 'analyst:short-pw'})
    assert str(MIN_PASSWORD_LENGTH) in str(excinfo.value)
    assert 'short-pw' not in str(excinfo.value)  # the secret never ends up in an error or a log


def test_whitespace_padding_does_not_count_towards_the_length():
    with pytest.raises(RuntimeError):
        gui_credentials({AUTH_ENV: 'analyst:' + ' ' * 10 + 'ab'})


def test_password_of_exactly_the_minimum_length_is_accepted():
    password = 'x' * MIN_PASSWORD_LENGTH
    assert gui_credentials({AUTH_ENV: f'analyst:{password}'}) == ('analyst', password)


# --- login lockout ---


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_checker_accepts_only_the_exact_pair():
    check = auth_checker('analyst', 'correct-horse-battery', clock=Clock())
    assert check('analyst', 'correct-horse-battery') is True
    assert check('Analyst', 'correct-horse-battery') is False
    assert check('analyst', 'correct-horse-battery ') is False
    assert check(None, 'correct-horse-battery') is False
    assert check('analyst', b'correct-horse-battery') is False


def test_success_resets_the_failure_count():
    check = auth_checker('analyst', 'correct-horse-battery', max_failures=2, clock=Clock())
    assert check('analyst', 'wrong-password-1') is False
    assert check('analyst', 'correct-horse-battery') is True
    assert check('analyst', 'wrong-password-1') is False
    assert check('analyst', 'correct-horse-battery') is True


def test_guessing_user_names_does_not_lock_out_the_real_user():
    check = auth_checker('analyst', 'correct-horse-battery', max_failures=3, clock=Clock())
    for name in ('root', 'admin', 'guest', 'test'):
        assert check(name, 'correct-horse-battery') is False
    assert check('analyst', 'correct-horse-battery') is True


def test_the_real_user_is_locked_out_after_repeated_failures():
    clock = Clock()
    check = auth_checker('analyst', 'correct-horse-battery', max_failures=2, lockout_seconds=60, clock=clock)
    check('root', 'x' * 12)  # unknown names fill their own bucket, not the real user's
    assert check('analyst', 'wrong-password-1') is False
    assert check('analyst', 'wrong-password-2') is False
    assert check('analyst', 'correct-horse-battery') is False  # locked: even the right password waits
    clock.now += 61
    assert check('analyst', 'correct-horse-battery') is True


# --- allowed hosts ---


def test_loopback_bind_allows_only_loopback_names():
    assert allowed_hosts('127.0.0.1', {}) == frozenset({'localhost', '127.0.0.1', '::1'})
    assert allows_ip_literals('127.0.0.1') is False


def test_configured_host_name_is_normalised():
    assert 'osint-box.lan' in allowed_hosts('Osint-Box.LAN.', {})
    assert '::1' in allowed_hosts('[::1]', {})


@pytest.mark.parametrize('host', ['0.0.0.0', '::', '[::]'])
def test_wildcard_bind_accepts_ip_literals_but_adds_no_name(host):
    assert allowed_hosts(host, {}) == frozenset({'localhost', '127.0.0.1', '::1'})
    assert allows_ip_literals(host) is True


def test_extra_names_from_the_environment():
    names = allowed_hosts('0.0.0.0', {ALLOWED_HOSTS_ENV: ' osint.example.org , ,Box '})
    assert {'osint.example.org', 'box'} <= names


# --- the ASGI guard ---


async def _ok_app(scope, receive, send):
    if scope['type'] == 'websocket':
        await send({'type': 'websocket.accept'})
        return
    await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'text/plain')]})
    await send({'type': 'http.response.body', 'body': b'ok'})


def _call(
    guard: HostGuardMiddleware,
    host: Optional[str] = '127.0.0.1:7860',
    origin: Optional[str] = None,
    method: str = 'GET',
    kind: str = 'http',
    extra_headers: Optional[List[Tuple[bytes, bytes]]] = None,
) -> List[Dict[str, Any]]:
    headers: List[Tuple[bytes, bytes]] = []
    if host is not None:
        headers.append((b'host', host.encode('latin-1')))
    if origin is not None:
        headers.append((b'origin', origin.encode('latin-1')))
    headers.extend(extra_headers or [])
    scope = {'type': kind, 'method': method, 'path': '/', 'headers': headers, 'client': ('127.0.0.1', 50000)}
    sent: List[Dict[str, Any]] = []

    async def receive():
        return {'type': 'websocket.connect'} if kind == 'websocket' else {'type': 'http.request', 'body': b''}

    async def send(message):
        sent.append(message)

    asyncio.run(guard(scope, receive, send))
    return sent


def _status(sent: List[Dict[str, Any]]) -> int:
    return next(m['status'] for m in sent if m['type'] == 'http.response.start')


def _headers(sent: List[Dict[str, Any]]) -> Dict[str, str]:
    start = next(m for m in sent if m['type'] == 'http.response.start')
    return {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in start['headers']}


@pytest.fixture
def guard():
    return HostGuardMiddleware(_ok_app, allowed_hosts=allowed_hosts('127.0.0.1', {}))


@pytest.mark.parametrize(
    'host',
    [
        'attacker.example:7860',  # DNS rebinding: the browser sends the attacker's name
        'localhost.attacker.example:7860',
        '127.0.0.1.nip.io:7860',
        '192.168.1.20:7860',  # loopback bind: not even a LAN address
        'user@127.0.0.1:7860',
        '127.0.0.1:7860/evil',
        '127.0.0.1:notaport',
        '',
        None,
    ],
)
def test_foreign_or_malformed_host_is_refused(guard, host):
    sent = _call(guard, host=host)
    assert _status(sent) == 400
    assert not any(m.get('body') == b'ok' for m in sent)  # the app was never reached


def test_duplicate_host_headers_are_refused(guard):
    assert _status(_call(guard, extra_headers=[(b'host', b'attacker.example')])) == 400


@pytest.mark.parametrize('origin', ['http://127.0.0.1:7860', 'http://127.0.0.1:7860/'])
def test_same_origin_requests_pass(guard, origin):
    assert _status(_call(guard, origin=origin, method='POST')) == 200


@pytest.mark.parametrize(
    'origin',
    [
        'https://attacker.example',  # cross-site request forgery against the loopback UI
        'http://127.0.0.1:9999',  # another local service on another port
        'http://localhost:7860',  # a different origin, even if it is also loopback
        'http://127.0.0.1:7860/path',
        'null',  # sandboxed iframe or file:// page
        'not a url',
    ],
)
def test_cross_origin_requests_are_refused(guard, origin):
    assert _status(_call(guard, origin=origin, method='POST')) == 400


def test_duplicate_origin_headers_are_refused(guard):
    sent = _call(guard, origin='http://127.0.0.1:7860', extra_headers=[(b'origin', b'https://attacker.example')])
    assert _status(sent) == 400


def test_default_port_origin_matches_portless_host(guard):
    assert _status(_call(guard, host='localhost', origin='http://localhost')) == 200
    assert _status(_call(guard, host='localhost:80', origin='http://localhost')) == 200


def test_websocket_with_foreign_host_is_closed(guard):
    assert _call(guard, host='attacker.example:7860', kind='websocket') == [{'type': 'websocket.close', 'code': 1008}]


def test_websocket_same_origin_is_accepted(guard):
    assert _call(guard, origin='http://127.0.0.1:7860', kind='websocket') == [{'type': 'websocket.accept'}]


def test_lifespan_passes_through():
    reached = []

    async def app(scope, receive, send):
        reached.append(scope['type'])

    asyncio.run(HostGuardMiddleware(app, allowed_hosts=())({'type': 'lifespan'}, None, None))
    assert reached == ['lifespan']


def test_security_headers_are_added(guard):
    headers = _headers(_call(guard))
    assert headers['x-frame-options'] == 'DENY'  # no clickjacking of the Run button from another site
    assert "frame-ancestors 'none'" in headers['content-security-policy']
    assert headers['x-content-type-options'] == 'nosniff'
    assert headers['referrer-policy'] == 'no-referrer'


def test_refusals_carry_the_security_headers_too(guard):
    assert _headers(_call(guard, host='attacker.example'))['x-frame-options'] == 'DENY'


def test_existing_security_headers_are_not_duplicated():
    async def app(scope, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'X-Frame-Options', b'SAMEORIGIN')]})
        await send({'type': 'http.response.body', 'body': b''})

    sent = _call(HostGuardMiddleware(app, allowed_hosts={'127.0.0.1'}))
    start = next(m for m in sent if m['type'] == 'http.response.start')
    assert [v for k, v in start['headers'] if k.lower() == b'x-frame-options'] == [b'SAMEORIGIN']
