"""Manual search-engine queries (GHDB-style "dorks") for the selectors a report already shows (C8).

The tool NEVER runs these queries and never contacts a search engine: they are text and links in
the report, for the investigator to run by hand if they have a lawful basis, exactly like the
suggested pivots.

Privacy and scope rules enforced here:

* Built from the REDACTED correlations (``ReportGenerator.correlations()``): a selector the report
  hides (an email, a phone number without ``--keep-network``) never ends up in a query.
* No query targets paste, leak or breach sites, and none uses credential terms (password, leak,
  dump, combolist...): the product does not search for leaked data. Templates are constants
  checked by the tests; platform hosts used for ``site:`` scoping are checked at run time.
* ``site:`` scoping only uses platforms where the username was FOUND, never "manual" or "not found".
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from secure_osint.core.validator import detect_input_type
from secure_osint.utils.markdown import md_code, md_text

ENGINES: Tuple[Tuple[str, str, str], ...] = (
    ('google', 'Google', 'https://www.google.com/search?'),
    ('bing', 'Bing', 'https://www.bing.com/search?'),
    ('duckduckgo', 'DuckDuckGo', 'https://duckduckgo.com/?'),
)

# At most this many found platforms are used for site: scoping (one query each, plus one exclusion).
MAX_SITE_SCOPES = 10
_MAX_VALUE = 100
# At most this many domains get the domain dorks (the investigated domain counts as one).
MAX_DOMAINS = 5
# Shared mailbox providers: an address there does not make the provider part of the investigation.
WEBMAIL_DOMAINS = frozenset(
    {
        'gmail.com',
        'googlemail.com',
        'outlook.com',
        'hotmail.com',
        'live.com',
        'msn.com',
        'yahoo.com',
        'icloud.com',
        'me.com',
        'aol.com',
        'proton.me',
        'protonmail.com',
        'gmx.com',
        'gmx.net',
        'gmx.de',
        'mail.com',
        'yandex.com',
        'yandex.ru',
        'zoho.com',
        'libero.it',
        'virgilio.it',
        'tutanota.com',
        'fastmail.com',
    }
)

# Never in a template, never in a scoping host. Lower-case substrings.
FORBIDDEN_TERMS: Tuple[str, ...] = (
    'password',
    'passwd',
    'credential',
    'leak',
    'dump',
    'combolist',
    'combo list',
    'breach',
    'paste',
    'pwned',
    'hacked',
)
FORBIDDEN_SITES: Tuple[str, ...] = (
    'pastebin',
    'ghostbin',
    'hastebin',
    'controlc',
    'justpaste',
    'rentry',
    'privatebin',
    'throwbin',
    'raidforums',
    'breachforums',
    'leakbase',
    'dehashed',
    'snusbase',
    'intelx',
    'leakcheck',
)

_USERNAME = (('"{u}"', 'Exact mentions of the username anywhere'),)
_USERNAME_SCOPED = ('"{u}" site:{host}', 'Mentions of the username on {label}, beyond the profile page')
_USERNAME_ELSEWHERE = ('"{u}" {excluded}', 'Mentions of the username outside the platforms already found')
_EMAIL = (
    ('"{e}"', 'Exact mentions of the email address'),
    ('"{e}" -site:{d}', 'Mentions of the email address outside its own domain'),
)
_DOMAIN = (
    ('site:{d}', 'Pages of the domain indexed by the search engine'),
    ('site:{d} -site:www.{d}', 'Indexed subdomains other than www'),
    ('"{d}" -site:{d}', 'Third-party pages that mention the domain'),
    (
        'site:{d} (filetype:pdf OR filetype:docx OR filetype:pptx)',
        'Public documents published on the domain (review their metadata by hand)',
    ),
)
_PHONE = ('{alternatives}', 'Mentions of the phone number in any of its known formats')
_NAME = (
    ('"{n}"', 'Exact mentions of the display name'),
    ('"{n}" "{u}"', 'Pages where the display name and the username appear together'),
)

# Every template, for the "no leak or credential terms" test.
TEMPLATE_TEXT: Tuple[str, ...] = tuple(
    text
    for pair in (*_USERNAME, _USERNAME_SCOPED, _USERNAME_ELSEWHERE, *_EMAIL, *_DOMAIN, _PHONE, *_NAME)
    for text in pair
)

_HOST_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')


def _value(raw: Any) -> Optional[str]:
    """A selector safe to put between quotes, or None (redacted, empty, too long)."""
    if not isinstance(raw, str) or '[REDACTED' in raw:
        return None
    text = ' '.join(raw.replace('"', ' ').replace('`', ' ').split())
    return text if text and len(text) <= _MAX_VALUE else None


def _allowed(text: str) -> bool:
    lowered = text.lower()
    return not any(term in lowered for term in FORBIDDEN_TERMS + FORBIDDEN_SITES)


def _host(url: Any) -> Optional[str]:
    """Host of a found profile URL usable for site: scoping (https, real hostname, not a paste site)."""
    if not isinstance(url, str) or not url.startswith('https://'):
        return None
    try:
        host = (urlparse(url).hostname or '').lower()
    except ValueError:
        return None
    host = host.removeprefix('www.')
    return host if _HOST_RE.match(host) and _allowed(host) else None


def _kind(value: str) -> str:
    try:
        return detect_input_type(value, allow_files=False)
    except ValueError:
        return 'generic'


class _Builder:
    def __init__(self) -> None:
        self.dorks: List[Dict[str, str]] = []
        self._seen: set = set()

    def add(self, entity: str, template: Tuple[str, str], **fields: str) -> None:
        query_template, purpose_template = template
        if not _allowed(query_template):  # defence in depth: the templates are constants
            return
        query = query_template.format(**fields)
        if query in self._seen:
            return
        self._seen.add(query)
        purpose = purpose_template.format(**fields)
        for engine, _, base in ENGINES:
            url = base + urlencode({'q': query})
            self.dorks.append({'entity': entity, 'engine': engine, 'query': query, 'url': url, 'purpose': purpose})


def _found_accounts(correlations: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for account in correlations.get('accounts') or []:
        if isinstance(account, dict) and account.get('status') == 'found':
            yield account


def build_dorks(correlations: Dict[str, Any]) -> List[Dict[str, str]]:
    """Manual search queries ``[{entity, engine, query, url, purpose}]`` for the visible selectors.

    Args:
        correlations: Redacted correlations (``ReportGenerator.correlations()``).

    Returns:
        One entry per (query, engine), in a stable order. Nothing is executed.
    """
    builder = _Builder()
    target = _value(correlations.get('primary_target'))
    target_kind = _kind(target) if target else 'generic'

    # Usernames, scoped to the platforms where each was found.
    hosts: Dict[str, List[Tuple[str, str]]] = {}
    for account in _found_accounts(correlations):
        username, host = _value(account.get('username')), _host(account.get('url'))
        if username and host and len(hosts.setdefault(username, [])) < MAX_SITE_SCOPES:
            label = _value(account.get('label')) or host
            if all(host != known for known, _ in hosts[username]):
                hosts[username].append((host, label))
    usernames = [u for u in (_value(v) for v in correlations.get('usernames') or []) if u]
    if target and target_kind == 'username' and target not in usernames:
        usernames.insert(0, target)
    for username in usernames:
        for template in _USERNAME:
            builder.add(username, template, u=username)
        scoped = hosts.get(username, [])
        for host, label in scoped:
            builder.add(username, _USERNAME_SCOPED, u=username, host=host, label=label)
        if scoped:
            excluded = ' '.join(f'-site:{host}' for host, _ in scoped)
            builder.add(username, _USERNAME_ELSEWHERE, u=username, excluded=excluded)

    # Display names exposed by the found profiles, paired with the username they were found under.
    for account in _found_accounts(correlations):
        raw_profile = account.get('profile')
        profile: Dict[str, Any] = raw_profile if isinstance(raw_profile, dict) else {}
        name, username = _value(profile.get('display_name')), _value(account.get('username'))
        if not name:
            continue
        builder.add(name, _NAME[0], n=name)
        if username and username.lower() != name.lower():
            builder.add(name, _NAME[1], n=name, u=username)

    # Emails: only when the report shows them (the email rule redacts them by default).
    emails = [e for e in (_value(v) for v in correlations.get('emails') or []) if e and _kind(e) == 'email']
    if target and target_kind == 'email' and target not in emails:
        emails.insert(0, target)
    for email in emails:
        domain = email.rsplit('@', 1)[1].lower()
        for template in _EMAIL:
            builder.add(email, template, e=email, d=domain)

    # Domains: the investigated one first, then the associated ones (capped). Shared webmail
    # providers are skipped: 'site:gmail.com' says nothing about the target.
    domains: List[str] = []
    if target and target_kind == 'domain':
        domains.append(target.lower().rstrip('.'))
    for raw in correlations.get('domains') or []:
        value = _value(raw)
        domain = value.lower().rstrip('.') if value else ''
        if domain and _HOST_RE.match(domain) and domain not in domains and domain not in WEBMAIL_DOMAINS:
            domains.append(domain)
    for domain in domains[:MAX_DOMAINS]:
        for template in _DOMAIN:
            builder.add(domain, template, d=domain)

    # Phone: every visible format of the number in one OR query (correlated formats first).
    phones: List[str] = []
    extra = [correlations.get('primary_target')] if target_kind == 'phone' else []
    for value in list(correlations.get('phones') or []) + extra:
        phone = _value(value)
        if phone and phone not in phones:
            phones.append(phone)
    if phones:
        alternatives = ' OR '.join(f'"{p}"' for p in phones[:4])
        builder.add(phones[0], _PHONE, alternatives=alternatives)
    return builder.dorks


def _cell(text: str) -> str:
    return md_text(text)  # entity/purpose can carry a remote display name: never live Markdown


def format_dork_lines(dorks: List[Dict[str, str]]) -> List[str]:
    """Markdown 'Manual search queries' section: one row per query, one link per engine."""
    lines = [
        '## Manual search queries',
        '',
        '_Search-engine queries you may run by hand, only with a lawful basis. The tool never runs them and '
        'never contacts a search engine. Selectors redacted in this report are left out._',
        '',
    ]
    rows: Dict[str, Dict[str, Any]] = {}
    names = {engine: name for engine, name, _ in ENGINES}
    for dork in dorks:
        row = rows.setdefault(dork['query'], {'entity': dork['entity'], 'purpose': dork['purpose'], 'links': []})
        row['links'].append(f'[{names.get(dork["engine"], dork["engine"])}]({dork["url"]})')
    if not rows:
        lines.append('_No selectors to search for._')
        return lines
    lines.extend(['| Entity | Query | Purpose | Search |', '| --- | --- | --- | --- |'])
    for query, row in rows.items():
        lines.append(
            f'| {_cell(row["entity"])} | {md_code(query)} | {_cell(row["purpose"])} | {" · ".join(row["links"])} |'
        )
    return lines
