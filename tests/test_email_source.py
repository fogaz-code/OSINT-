"""Email source: real MX lookup (dnspython, deadline-clamped) and keyless Gravatar profile parsing.

No live network: HTTP goes through a routing fake, DNS through an injected resolver that returns
real dnspython rdata objects.
"""

import hashlib
import json
import socket
import threading
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dns.exception
import dns.rdata
import dns.resolver
import pytest

from secure_osint.sources.base import SourceError, SourceUnavailable, TransientSourceError
from secure_osint.sources.email_source import EmailSource
from secure_osint.utils.deadline import deadline_scope
from secure_osint.utils.http_client import HttpResponse

EMAIL = 'Alice.Example@Example.COM'
NORMALISED = 'alice.example@example.com'
SHA256 = hashlib.sha256(NORMALISED.encode()).hexdigest()
GRAVATAR_URL = f'https://api.gravatar.com/v3/profiles/{SHA256}'
KICKBOX_URL = 'https://open.kickbox.com/v1/disposable/example.com'

Reply = Union[HttpResponse, Exception]


def ok(body: Any, status: int = 200) -> HttpResponse:
    content = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    return HttpResponse(status, content, {})


class RoutingClient:
    def __init__(self, routes: Dict[str, Reply]):
        self.routes = routes
        self.calls: List[Dict[str, Any]] = []

    def get(
        self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: Optional[float] = None
    ) -> HttpResponse:
        self.calls.append({'url': url, 'timeout': timeout})
        if url not in self.routes:
            raise AssertionError(f'unexpected request to {url}')
        reply = self.routes[url]
        if isinstance(reply, Exception):
            raise reply
        return reply


def mx(*records: str) -> List[Any]:
    return [dns.rdata.from_text('IN', 'MX', r) for r in records]


def a(*ips: str) -> List[Any]:
    return [dns.rdata.from_text('IN', 'A', ip) for ip in ips]


class FakeResolver:
    """Answers (name, rdtype) from a table; values are rdata lists or dnspython exceptions."""

    def __init__(self, table: Dict[Tuple[str, str], Union[List[Any], Exception]]):
        self.table = table
        self.calls: List[Tuple[str, str, float]] = []
        self._lock = threading.Lock()

    def __call__(self, name: str, rdtype: str, lifetime: float) -> List[Any]:
        with self._lock:
            self.calls.append((name, rdtype, lifetime))
        answer = self.table.get((name, rdtype), dns.resolver.NoAnswer())
        if isinstance(answer, Exception):
            raise answer
        return answer


PROFILE = {
    'hash': SHA256,
    'display_name': 'Alice Example',
    'profile_url': 'https://gravatar.com/alicex',
    'avatar_url': f'https://0.gravatar.com/avatar/{SHA256}',
    'location': 'Golden, CO',
    'description': 'Call me on +1 415 555 2671 or alice@private.example',
    'job_title': 'Engineer',
    'company': 'ACME',
    'contact_info': {'email': 'alice@private.example', 'cell_phone': '+14155552671'},
    'verified_accounts': [
        {'service_type': 'github', 'service_label': 'GitHub', 'url': 'https://github.com/alicex', 'is_hidden': False},
        {'service_type': 'twitter', 'service_label': 'X', 'url': 'https://x.com/alicex', 'is_hidden': True},
        {'service_type': 'mastodon', 'service_label': 'Mastodon', 'url': 'mailto:alice@private.example'},
        {'service_type': 'weird', 'service_label': 'Weird', 'url': 'javascript:alert(1)'},
        'garbage',
    ],
}


def source(
    routes: Optional[Dict[str, Reply]] = None, table: Optional[Dict[Tuple[str, str], Any]] = None
) -> Tuple[EmailSource, RoutingClient, FakeResolver]:
    client = RoutingClient(
        routes if routes is not None else {GRAVATAR_URL: ok('', 404), KICKBOX_URL: ok({'disposable': False})}
    )
    resolver = FakeResolver(
        table
        if table is not None
        else {
            ('example.com', 'MX'): mx('20 mx2.example.com.', '10 mx1.example.com.'),
            ('example.com', 'A'): a('93.184.215.14'),
        }
    )
    return EmailSource(cast(Any, client), resolver=resolver), client, resolver


# --- MX (real lookup, not getaddrinfo) ---


def test_mx_hosts_sorted_by_preference_and_existing_keys_kept():
    src, _, resolver = source()
    data = src.fetch({'input': EMAIL})
    assert data['mx'] == ['mx1.example.com', 'mx2.example.com']
    assert data['has_mx'] is True
    assert data['email_domain'] == 'example.com'
    assert data['domain_resolves'] is True
    assert data['disposable_domain'] is False
    assert data['gravatar_profile_exists'] is False and data['gravatar'] is None
    assert ('example.com', 'MX') in {(n, t) for n, t, _ in resolver.calls}
    assert 'partial' not in data and 'errors' not in data


def test_no_mx_record_means_has_mx_false():
    src, _, _ = source(table={('example.com', 'A'): a('93.184.215.14')})
    data = src.fetch({'input': EMAIL})
    assert data['mx'] == [] and data['has_mx'] is False
    assert data['domain_resolves'] is True


def test_null_mx_rfc7505_means_no_mail():
    src, _, _ = source(table={('example.com', 'MX'): mx('0 .'), ('example.com', 'A'): a('93.184.215.14')})
    data = src.fetch({'input': EMAIL})
    assert data['mx'] == [] and data['has_mx'] is False
    assert any('RFC 7505' in note for note in data['notes'])


def test_nxdomain_domain_does_not_resolve():
    nx = dns.resolver.NXDOMAIN()
    src, _, _ = source(table={('example.com', t): nx for t in ('MX', 'A', 'AAAA')})
    data = src.fetch({'input': EMAIL})
    assert data['mx'] == [] and data['has_mx'] is False
    assert data['domain_resolves'] is False
    assert 'partial' not in data


def test_mx_timeout_is_partial_not_a_false_negative():
    src, _, _ = source(table={('example.com', 'MX'): dns.exception.Timeout(), ('example.com', 'A'): a('1.1.1.1')})
    data = src.fetch({'input': EMAIL})
    assert data['mx'] is None and data['has_mx'] is None
    assert data['partial'] is True
    assert any('MX' in e for e in data['errors'])


def test_servfail_is_an_error_not_an_empty_answer():
    fail = dns.resolver.NoNameservers()
    src, _, _ = source(table={('example.com', t): fail for t in ('MX', 'A', 'AAAA')})
    data = src.fetch({'input': EMAIL})
    assert data['has_mx'] is None and data['domain_resolves'] is None
    assert data['partial'] is True and len(data['errors']) == 3


def test_disposable_check_failure_is_partial():
    routes = {GRAVATAR_URL: ok('', 404), KICKBOX_URL: TransientSourceError('open.kickbox.com: timed out')}
    src, _, _ = source(routes=routes)
    data = src.fetch({'input': EMAIL})
    assert data['disposable_domain'] is None
    assert data['partial'] is True and any('disposable' in e for e in data['errors'])


@pytest.mark.parametrize('status', [429, 503])
def test_disposable_check_http_error_is_partial_not_silent(status):
    # Regression: a rate-limited or failing kickbox answer used to vanish into disposable_domain=None
    # with no error, so the engine reported a complete (cacheable) result.
    src, _, _ = source(routes={GRAVATAR_URL: ok('', 404), KICKBOX_URL: ok('', status)})
    data = src.fetch({'input': EMAIL})
    assert data['disposable_domain'] is None
    assert data['partial'] is True and any('disposable' in e for e in data['errors'])


@pytest.mark.parametrize('body', [{}, {'disposable': 'yes'}, ['x'], 'not json'])
def test_disposable_unexpected_body_is_partial_not_false(body):
    src, _, _ = source(routes={GRAVATAR_URL: ok('', 404), KICKBOX_URL: ok(body)})
    data = src.fetch({'input': EMAIL})
    assert data['disposable_domain'] is None
    assert data['partial'] is True


def test_mx_only_domain_still_resolves():
    src, _, _ = source(table={('example.com', 'MX'): mx('10 mx1.example.com.')})
    assert src.fetch({'input': EMAIL})['domain_resolves'] is True


def test_never_uses_getaddrinfo(monkeypatch):
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError('getaddrinfo bypasses the timeout and the deadline')

    monkeypatch.setattr(socket, 'getaddrinfo', boom)
    src, _, _ = source()
    assert src.fetch({'input': EMAIL})['has_mx'] is True


def test_dns_lifetime_and_http_timeouts_clamped_by_deadline():
    src, client, resolver = source()
    with deadline_scope(2.0):
        src.fetch({'input': EMAIL})
    assert resolver.calls and all(lifetime <= 2.0 for _, _, lifetime in resolver.calls)
    assert client.calls and all(c['timeout'] is not None and c['timeout'] <= 2.0 for c in client.calls)


def test_spent_deadline_stops_before_any_lookup():
    src, client, resolver = source()
    with deadline_scope(0):
        with pytest.raises(SourceError):
            src.fetch({'input': EMAIL})
    assert client.calls == [] and resolver.calls == []


def test_default_resolver_uses_dnspython_with_lifetime(monkeypatch):
    seen: List[Tuple[str, str, float]] = []

    def fake_resolve(name: str, rdtype: str, lifetime: float = 0.0, **kwargs: Any) -> List[Any]:
        seen.append((name, rdtype, lifetime))
        if rdtype == 'MX':
            return mx('10 mx1.example.com.')
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver, 'resolve', fake_resolve)
    client = RoutingClient({GRAVATAR_URL: ok('', 404), KICKBOX_URL: ok({'disposable': False})})
    data = EmailSource(client).fetch({'input': EMAIL})
    assert data['mx'] == ['mx1.example.com']
    assert {(n, t) for n, t, _ in seen} == {('example.com', 'MX'), ('example.com', 'A'), ('example.com', 'AAAA')}
    assert all(0 < lifetime <= 5.0 for _, _, lifetime in seen)


# --- Gravatar (keyless v3 profile, sha256) ---


def test_gravatar_profile_parsed_and_minimised():
    src, client, _ = source(routes={GRAVATAR_URL: ok(PROFILE), KICKBOX_URL: ok({'disposable': False})})
    data = src.fetch({'input': EMAIL})
    assert data['gravatar_profile_exists'] is True
    assert data['gravatar'] == {
        'display_name': 'Alice Example',
        'profile_url': 'https://gravatar.com/alicex',
        'verified_accounts': [{'service': 'GitHub', 'url': 'https://github.com/alicex'}],
    }
    blob = json.dumps(data)
    # Data minimisation: no contact data, no free text that may carry it, no hidden accounts.
    assert 'private.example' not in blob and '555' not in blob and '+1415' not in blob
    assert 'x.com/alicex' not in blob and 'javascript:' not in blob
    # Keyless: no Authorization header, and the sha256 (not md5) identifier is used.
    assert client.calls[0]['url'] == GRAVATAR_URL


def test_gravatar_request_carries_no_api_key():
    seen: Dict[str, Any] = {}

    class HeaderClient(RoutingClient):
        def get(self, url, params=None, headers=None, timeout=None):  # type: ignore[override]
            if url == GRAVATAR_URL:
                seen['headers'] = headers
            return super().get(url, params, headers, timeout)

    client = HeaderClient({GRAVATAR_URL: ok(PROFILE), KICKBOX_URL: ok({'disposable': False})})
    EmailSource(client, resolver=FakeResolver({})).fetch({'input': EMAIL})
    assert not seen['headers'] or 'Authorization' not in seen['headers']


def test_gravatar_profile_url_must_be_gravatar_https():
    profile = dict(PROFILE, profile_url='https://evil.example/phish', display_name='x' * 1000)
    src, _, _ = source(routes={GRAVATAR_URL: ok(profile), KICKBOX_URL: ok({'disposable': False})})
    gravatar = src.fetch({'input': EMAIL})['gravatar']
    assert gravatar['profile_url'] is None
    assert len(gravatar['display_name']) <= 256


@pytest.mark.parametrize(
    'url,account_kept',
    [
        ('https://github.com/a\nmailto:alice@private.example', False),
        ('https://user:pw@evil.example/x', False),
        ('ftp://files.example/a', False),
        # A verified account may live on any https host; only profile_url must be on gravatar.com.
        ('https://gravatar.com.evil.example/a', True),
    ],
)
def test_suspicious_account_and_profile_urls_dropped(url, account_kept):
    profile = dict(PROFILE, profile_url=url, verified_accounts=[{'service_label': 'S', 'url': url}])
    src, _, _ = source(routes={GRAVATAR_URL: ok(profile), KICKBOX_URL: ok({'disposable': False})})
    gravatar = src.fetch({'input': EMAIL})['gravatar']
    assert gravatar['profile_url'] is None
    assert gravatar['verified_accounts'] == ([{'service': 'S', 'url': url}] if account_kept else [])


def test_gravatar_rate_limit_is_partial():
    src, _, _ = source(routes={GRAVATAR_URL: ok('slow down', 429), KICKBOX_URL: ok({'disposable': False})})
    data = src.fetch({'input': EMAIL})
    assert data['gravatar_profile_exists'] is None and data['gravatar'] is None
    assert data['partial'] is True and any('gravatar' in e.lower() for e in data['errors'])


def test_gravatar_transport_error_is_partial():
    routes = {GRAVATAR_URL: TransientSourceError('api.gravatar.com: timed out'), KICKBOX_URL: ok({'disposable': True})}
    src, _, _ = source(routes=routes)
    data = src.fetch({'input': EMAIL})
    assert data['gravatar'] is None and data['disposable_domain'] is True
    assert data['partial'] is True


def test_gravatar_malformed_body_is_partial():
    src, _, _ = source(routes={GRAVATAR_URL: ok('<html>'), KICKBOX_URL: ok({'disposable': False})})
    data = src.fetch({'input': EMAIL})
    assert data['gravatar'] is None and data['partial'] is True


def test_opsec_note_about_hashing_is_kept():
    import inspect

    import secure_osint.sources.email_source as module

    text = inspect.getsource(module)
    assert 'OPSEC' in text and 'sha256' in text.lower()


# --- input validation ---


@pytest.mark.parametrize('raw', ['not-an-email', 'a@b@c.com', '@example.com', 'x' * 65 + '@example.com'])
def test_invalid_email_never_reaches_network(raw):
    src, client, resolver = source(routes={})
    with pytest.raises(SourceUnavailable):
        src.fetch({'input': raw})
    assert client.calls == [] and resolver.calls == []
