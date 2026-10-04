"""Email footprint: mail exchangers (real MX lookup), domain resolution, disposable-domain check and the
public Gravatar profile.

DNS goes through dnspython with every lifetime clamped to the step deadline (never the unbounded
``socket.getaddrinfo``). HTTP goes through ``SafeHttpClient``. A sub-check that fails for a
transient reason is reported in ``errors`` with ``partial=True`` instead of being presented as a
negative answer.
"""

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

import dns.exception
import dns.name
import dns.resolver

from secure_osint.security.input_sanitizer import normalize_domain
from secure_osint.sources.base import BaseSource, SourceError, SourceUnavailable
from secure_osint.sources.registry import register_source
from secure_osint.utils.deadline import DeadlineExceeded, clamp_timeout, submit_in_context
from secure_osint.utils.http_client import SafeHttpClient, raise_for_status, shared_client

# Always used with fullmatch: `$` would also accept a trailing newline.
_EMAIL = re.compile(r'[A-Za-z0-9._%+-]{1,64}@[^@\s]{1,253}')
_GRAVATAR_PROFILE = re.compile(r'https://(?:[a-z0-9-]+\.)?gravatar\.com/[A-Za-z0-9._~%/-]{1,200}')
_HTTP_URL = re.compile(r'https?://[^\s/?#@]+(?:[/?#]\S*)?', re.I)
_MAX_TEXT = 256
_MAX_ACCOUNTS = 50

# (name, rdtype, lifetime) -> iterable of rdata. Raises dnspython exceptions.
Resolver = Callable[[str, str, float], Any]


def _dnspython_resolve(name: str, rdtype: str, lifetime: float) -> Any:
    return dns.resolver.resolve(name, rdtype, lifetime=lifetime)


def _text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:_MAX_TEXT] if value else None


def _parse_gravatar(profile: Any) -> Dict[str, Any]:
    """Keep only display name, profile URL and visible verified accounts (http/https links).

    Data minimisation: contact info, location, description, job and any e-mail/phone fields
    are never read, even when the profile exposes them publicly.
    """
    if not isinstance(profile, dict):
        raise SourceUnavailable('api.gravatar.com: unexpected profile response')
    url = _text(profile.get('profile_url'))
    accounts: List[Dict[str, str]] = []
    raw_accounts = profile.get('verified_accounts')
    for item in raw_accounts if isinstance(raw_accounts, list) else []:
        if not isinstance(item, dict) or item.get('is_hidden') is True:
            continue
        link = _text(item.get('url'))
        service = _text(item.get('service_label')) or _text(item.get('service_type'))
        if service and link and len(link) <= 2048 and _HTTP_URL.fullmatch(link):
            accounts.append({'service': service, 'url': link})
        if len(accounts) >= _MAX_ACCOUNTS:
            break
    return {
        'display_name': _text(profile.get('display_name')),
        'profile_url': url if url and _GRAVATAR_PROFILE.fullmatch(url) else None,
        'verified_accounts': accounts,
    }


@register_source('email')
class EmailSource(BaseSource):
    """Email footprint checks: MX records, domain resolution, disposable domain, Gravatar profile."""

    HTTP_TIMEOUT = 10.0

    def __init__(
        self, client: Optional[SafeHttpClient] = None, resolver: Optional[Resolver] = None, dns_timeout: float = 5.0
    ):
        """Initialize EmailSource.

        Args:
            client: HTTP client (defaults to the shared SafeHttpClient).
            resolver: DNS lookup ``(name, rdtype, lifetime) -> rdata``; defaults to dnspython.
            dns_timeout: Upper bound for each DNS query, further clamped by the step deadline.
        """
        self.client = client or shared_client()
        self.resolver: Resolver = resolver or _dnspython_resolve
        self.dns_timeout = dns_timeout

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query the email footprint and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            ``email_domain``, ``mx`` (hosts by preference), ``has_mx``, ``domain_resolves``,
            ``disposable_domain``, ``gravatar_profile_exists``, ``gravatar`` and ``notes``; plus
            ``partial``/``errors`` when a sub-check failed and its answer is unknown.

        Raises:
            SourceUnavailable: Invalid email address.
            DeadlineExceeded: The step budget was already spent.
        """
        email = self.require_input(params).lower()
        if not _EMAIL.fullmatch(email):
            raise SourceUnavailable('No valid email provided')
        try:
            domain = normalize_domain(email.split('@', 1)[1])
        except ValueError as e:
            raise SourceUnavailable(str(e)) from e
        clamp_timeout(self.HTTP_TIMEOUT)  # fail fast on an already-spent budget

        out: Dict[str, Any] = {'email_domain': domain, 'notes': []}
        errors: List[str] = []
        self._dns(domain, out, errors)
        self._gravatar(email, out, errors)
        self._disposable(domain, out, errors)
        if errors:
            out['partial'] = True
            out['errors'] = errors
        return out

    # --- DNS ---

    def _lookup(self, domain: str, rdtype: str) -> Tuple[str, Any]:
        """('ok', rdata list) | ('nxdomain', None) | ('empty', None) | ('error', message)."""
        try:
            answer = self.resolver(domain, rdtype, clamp_timeout(self.dns_timeout))
        except dns.resolver.NXDOMAIN:
            return 'nxdomain', None
        except dns.resolver.NoAnswer:
            return 'empty', None
        except dns.resolver.NoNameservers:
            # Every server answered SERVFAIL/REFUSED: unknown, not "no records".
            return 'error', f'{rdtype}: no nameserver could answer'
        except dns.exception.Timeout:
            return 'error', f'{rdtype}: DNS timeout'
        except dns.exception.DNSException as e:
            return 'error', f'{rdtype}: {type(e).__name__}'
        return 'ok', list(answer)

    def _dns(self, domain: str, out: Dict[str, Any], errors: List[str]) -> None:
        rdtypes = ('MX', 'A', 'AAAA')
        # In parallel: the worst case is one DNS lifetime, not three. submit_in_context carries
        # the step deadline into the worker threads so clamp_timeout still applies there.
        with ThreadPoolExecutor(max_workers=len(rdtypes)) as pool:
            futures = [submit_in_context(pool, self._lookup, domain, rdtype) for rdtype in rdtypes]
            outcomes = dict(zip(rdtypes, (f.result() for f in futures)))

        kind, value = outcomes['MX']
        if kind == 'ok':
            records = sorted(value, key=lambda r: (r.preference, r.exchange.to_text(omit_final_dot=True)))
            hosts = [r.exchange.to_text(omit_final_dot=True) for r in records if r.exchange != dns.name.root]
            if len(hosts) < len(records):
                out['notes'].append('Null MX (RFC 7505): the domain explicitly accepts no email.')
            out['mx'] = hosts
            out['has_mx'] = bool(hosts)
        elif kind in ('empty', 'nxdomain'):
            out['mx'] = []
            out['has_mx'] = False
        else:
            out['mx'] = None
            out['has_mx'] = None
            errors.append(value)

        kinds = [k for k, _ in outcomes.values()]
        if 'ok' in kinds:
            out['domain_resolves'] = True
        elif 'nxdomain' in kinds:
            out['domain_resolves'] = False
        elif 'error' in kinds:
            out['domain_resolves'] = None
            errors.extend(v for k, v in (outcomes['A'], outcomes['AAAA']) if k == 'error')
        else:
            out['domain_resolves'] = False

    # --- HTTP checks ---

    def _gravatar(self, email: str, out: Dict[str, Any], errors: List[str]) -> None:
        # OPSEC: Gravatar receives a sha256 of the address. Hashing is NOT anonymisation: anyone who
        # already knows (or can enumerate) the email can recompute it, so Gravatar learns which
        # address is being looked up. Keyless v3 endpoint: GET /v3/profiles/<sha256>, 404 = no profile.
        digest = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()
        out['gravatar_profile_exists'] = None
        out['gravatar'] = None
        try:
            resp = self.client.get(
                f'https://api.gravatar.com/v3/profiles/{digest}', timeout=clamp_timeout(self.HTTP_TIMEOUT)
            )
            if resp.status_code == 404:
                out['gravatar_profile_exists'] = False
                return
            raise_for_status(resp, 'api.gravatar.com')
            out['gravatar'] = _parse_gravatar(resp.json())
            out['gravatar_profile_exists'] = True
        except DeadlineExceeded:
            raise
        except SourceError as e:
            errors.append(f'gravatar: {e}')

    def _disposable(self, domain: str, out: Dict[str, Any], errors: List[str]) -> None:
        out['disposable_domain'] = None
        try:
            resp = self.client.get(
                f'https://open.kickbox.com/v1/disposable/{domain}', timeout=clamp_timeout(self.HTTP_TIMEOUT)
            )
            # A 429/5xx leaves the answer unknown: report it in errors (partial), never silently drop it.
            raise_for_status(resp, 'open.kickbox.com')
            data = resp.json()
            if not isinstance(data, dict) or not isinstance(data.get('disposable'), bool):
                raise SourceUnavailable('open.kickbox.com: unexpected response')
            out['disposable_domain'] = data['disposable']
        except DeadlineExceeded:
            raise
        except SourceError as e:
            errors.append(f'disposable check: {e}')
