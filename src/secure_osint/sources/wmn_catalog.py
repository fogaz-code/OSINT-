"""WhatsMyName (WMN) adapter: turn a LOCAL ``wmn-data.json`` into extra username-sweep platforms.

Attribution and licence
    WhatsMyName is a community project by Micah Hoffman (WebBreacher) and contributors,
    https://github.com/WebBreacher/WhatsMyName. Its ``wmn-data.json`` is licensed under
    Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0). This module contains no WMN data:
    the dataset is NOT vendored and is NEVER downloaded at runtime. The user supplies a copy they
    fetched and reviewed themselves (workflow param ``wmn_path`` or env ``SECURE_OSINT_WMN_PATH``),
    and every report produced from it carries the attribution in the ``catalog`` block.

Why the guard rails
    * Supply chain: a remote catalog would let whoever controls it decide which hosts the tool
      contacts and with which target data. Local file only, size-capped, strictly validated.
    * Honesty: a WMN signature is a string match on a page; on its own it is the classic source of
      false positives. Entries become MEDIUM-confidence web platforms that ALWAYS go through the
      sweep's soft-404 calibration (a username that cannot exist must not match too).
    * Product rules: entries needing a POST body or custom headers (closer to form probing) are
      skipped, as are entries whose check URI is a signup / username-availability / login /
      recovery endpoint (a registration oracle even over GET), auth-walled platforms and, by
      default, the NSFW category. Only ``https`` check
      URIs on a DNS name and the default port are accepted.

This module never imports an HTTP client (enforced by a test).
"""

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from secure_osint.sources.base import SourceUnavailable

WMN_ENV = 'SECURE_OSINT_WMN_PATH'
# The upstream file is under 1 MiB today; the cap leaves room for growth and bounds parsing work.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_SITES = 5000

WMN_NAME = 'WhatsMyName'
WMN_LICENSE = 'CC BY-SA 4.0'
WMN_PROJECT = 'https://github.com/WebBreacher/WhatsMyName'
WMN_ATTRIBUTION = 'Site signatures from the WhatsMyName project (WebBreacher and contributors), CC BY-SA 4.0.'

NSFW_CATEGORY = 'xx nsfw xx'

# Platforms that need an authenticated session to show a profile: never probed, whatever the catalog says.
AUTH_WALLED_DOMAINS: Tuple[str, ...] = (
    'linkedin.com',
    'instagram.com',
    'facebook.com',
    'fb.com',
    'x.com',
    'twitter.com',
)

PLACEHOLDER = '{account}'
_SAMPLE = 'wmnplaceholder'
_HOST_LABEL = re.compile(r'^(?!-)[a-z0-9_-]{1,63}(?<!-)$')
_TLD = re.compile(r'^[a-z]{2,63}$|^xn--[a-z0-9-]{1,59}$')
_SLUG = re.compile(r'[^a-z0-9]+')
_TAG = re.compile(r'<[^>]+>')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
# Check URIs that ask a signup, username-availability, login or recovery endpoint instead of a public
# profile. Querying those with the target's name is a registration oracle (product rule), even over GET.
_REGISTRATION_PROBE = re.compile(
    r'sign[-_]?up|regist(?:er|ration)|validat|availab|check[-_]?(?:user|nick|name|account)'
    r'|user(?:name)?[-_]?(?:exists|available|check)|(?:^|[./])auth[./]|(?:^|[./])login[./]'
    r'|passw(?:or)?d|reset|recover',
    re.IGNORECASE,
)


class WmnCatalogError(SourceUnavailable):
    """The WMN file is missing, too large or malformed. Permanent: fix the file and run again."""


class _WmnSite(BaseModel):
    """One ``sites[]`` entry. Strict: no type coercion (``"200"`` is not a status code)."""

    model_config = ConfigDict(strict=True, extra='ignore')

    name: str = Field(min_length=1, max_length=120)
    uri_check: str = Field(min_length=1, max_length=2048)
    uri_pretty: Optional[str] = Field(default=None, max_length=2048)
    e_code: int = Field(ge=100, le=599)
    # An empty "exists" string matches every page: the textbook false positive. Rejected.
    e_string: str = Field(min_length=1, max_length=2000)
    m_code: int = Field(ge=100, le=599)
    m_string: str = Field(default='', max_length=2000)
    cat: str = Field(default='', max_length=120)
    post_body: Optional[str] = Field(default=None, max_length=10_000)
    headers: Optional[Dict[str, str]] = None
    strip_bad_char: Optional[str] = Field(default=None, max_length=32)
    valid: Optional[bool] = None


class _WmnFile(BaseModel):
    model_config = ConfigDict(strict=True, extra='ignore')

    sites: List[Any]


@dataclass(frozen=True)
class WmnEntry:
    """A validated WMN site, mapped to the sweep's vocabulary (templates use ``{u}``)."""

    key: str
    label: str
    check_template: str
    profile_template: str
    exists_code: int
    exists_string: str
    missing_code: int
    missing_string: str
    strip_chars: str = ''
    category: str = ''

    def check_url(self, account: str) -> str:
        """The URL that is requested for ``account``."""
        return fill_template(self.check_template, account, self.strip_chars)

    def profile_url(self, account: str) -> str:
        """The human-facing profile URL for ``account``."""
        return fill_template(self.profile_template, account, self.strip_chars)


@dataclass(frozen=True)
class WmnCatalog:
    """The usable entries plus provenance (licence, file digest, skip counts) for the report."""

    entries: Tuple[WmnEntry, ...]
    info: Dict[str, Any] = field(default_factory=dict)


def fill_template(template: str, account: str, strip_chars: str = '') -> str:
    """Substitute the account into a ``{u}`` template, URL-encoded (never a path or query injection)."""
    if strip_chars:
        account = account.translate({ord(c): None for c in strip_chars})
    return template.format(u=quote(account, safe=''))


def host_key(template: str) -> str:
    """Host used to deduplicate platforms: lower-case, no ``www.``, no per-user subdomain label."""
    sample = template.replace(PLACEHOLDER, _SAMPLE).replace('{u}', _SAMPLE)
    try:
        host = (urlsplit(sample).hostname or '').rstrip('.')
    except ValueError:
        return ''
    labels = [label for label in host.split('.') if _SAMPLE not in label]
    if labels and labels[0] == 'www':
        labels = labels[1:]
    return '.'.join(labels)


def _is_auth_walled(host: str) -> bool:
    return any(host == domain or host.endswith('.' + domain) for domain in AUTH_WALLED_DOMAINS)


def _safe_template(uri: Optional[str]) -> Optional[str]:
    """``uri`` as a ``{u}`` template if it is an https URL on a DNS name with the placeholder, else None."""
    if not isinstance(uri, str) or PLACEHOLDER not in uri:
        return None
    if any(ch.isspace() for ch in uri) or _CONTROL.search(uri):
        return None
    try:
        parts = urlsplit(uri.replace(PLACEHOLDER, _SAMPLE))
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or '').rstrip('.')
    if parts.scheme != 'https' or parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443) or not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # IP literals: a catalog has no business pointing at addresses
    except ValueError:
        pass
    labels = host.split('.')
    if len(labels) < 2 or not all(_HOST_LABEL.match(label) for label in labels) or not _TLD.match(labels[-1]):
        return None
    # Escape every other brace so str.format only ever substitutes the account.
    return uri.replace('{', '{{').replace('}', '}}').replace('{{account}}', '{u}')


def _label(name: str) -> str:
    cleaned = ' '.join(_CONTROL.sub('', _TAG.sub(' ', name)).split())
    return cleaned[:80] or 'WhatsMyName site'


def _key(name: str, used: set) -> str:
    base = 'wmn_' + (_SLUG.sub('_', name.lower()).strip('_')[:48] or 'site')
    key, n = base, 2
    while key in used:
        key, n = f'{base}_{n}', n + 1
    used.add(key)
    return key


def resolve_wmn_path(value: Any) -> Optional[Path]:
    """Path from the workflow param, else from ``SECURE_OSINT_WMN_PATH``, else None (not configured)."""
    if value is not None and not isinstance(value, str):
        raise WmnCatalogError('wmn_path must be a string path to a local wmn-data.json')
    raw = (value or '').strip() or os.environ.get(WMN_ENV, '').strip()
    return Path(raw).expanduser() if raw else None


def _read_capped(path: Path) -> bytes:
    # Only the file name in messages: the full path can carry the analyst's account name.
    try:
        info = path.stat()
    except OSError as e:
        raise WmnCatalogError(f'WhatsMyName file {path.name!r} cannot be read ({type(e).__name__})') from e
    if not stat.S_ISREG(info.st_mode):
        raise WmnCatalogError(f'WhatsMyName file {path.name!r} is not a regular file')
    if info.st_size > MAX_FILE_BYTES:
        raise WmnCatalogError(f'WhatsMyName file is too large (limit {MAX_FILE_BYTES} bytes)')
    try:
        with open(path, 'rb') as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError as e:
        raise WmnCatalogError(f'WhatsMyName file {path.name!r} cannot be read ({type(e).__name__})') from e
    if len(raw) > MAX_FILE_BYTES:
        raise WmnCatalogError(f'WhatsMyName file is too large (limit {MAX_FILE_BYTES} bytes)')
    return raw


def load_wmn_catalog(
    path: Path,
    *,
    include_nsfw: bool = False,
    exclude_hosts: Iterable[str] = (),
    max_sites: int = MAX_SITES,
) -> WmnCatalog:
    """Load and validate a local WMN file. Never touches the network.

    Args:
        path: Local ``wmn-data.json``.
        include_nsfw: Keep the ``XX NSFW XX`` category (off by default).
        exclude_hosts: ``host_key`` values already covered (the built-in platforms): skipped.
        max_sites: Upper bound on ``sites`` entries (bounds the sweep and the parsing work).

    Raises:
        WmnCatalogError: Missing/non-regular/oversized file, invalid JSON or top-level shape.
            Individual bad entries are skipped and counted, never fatal.
    """
    raw = _read_capped(Path(path))
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as e:  # RecursionError: pathological nesting
        raise WmnCatalogError('WhatsMyName file is not valid JSON') from e
    try:
        parsed = _WmnFile.model_validate(document)
    except ValidationError as e:
        # Never echo pydantic's message: it quotes the offending input.
        raise WmnCatalogError('WhatsMyName file has an unexpected shape (expected an object with a sites list)') from e
    if len(parsed.sites) > max_sites:
        raise WmnCatalogError(f'WhatsMyName file lists too many sites (limit {max_sites})')

    excluded: FrozenSet[str] = frozenset(h for h in exclude_hosts if h)
    seen_hosts: set = set()
    used_keys: set = set()
    entries: List[WmnEntry] = []
    skipped: Dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for item in parsed.sites:
        try:
            site = _WmnSite.model_validate(item)
        except ValidationError:
            skip('invalid')
            continue
        if site.valid is False:
            skip('disabled')
            continue
        if site.post_body:
            skip('post_body')
            continue
        if site.headers:
            skip('custom_headers')
            continue
        if site.cat.strip().lower() == NSFW_CATEGORY and not include_nsfw:
            skip('nsfw')
            continue
        check = _safe_template(site.uri_check)
        if check is None:
            skip('unsafe_uri')
            continue
        if _REGISTRATION_PROBE.search(check.split('://', 1)[-1]):
            skip('registration_probe')
            continue
        host = host_key(check)
        if _is_auth_walled(host):
            skip('auth_required')
            continue
        if host in excluded or host in seen_hosts:
            skip('duplicate_host')
            continue
        seen_hosts.add(host)
        pretty = _safe_template(site.uri_pretty) or check
        label = _label(site.name)
        entries.append(
            WmnEntry(
                key=_key(label, used_keys),
                label=label,
                check_template=check,
                profile_template=pretty,
                exists_code=site.e_code,
                exists_string=site.e_string,
                missing_code=site.m_code,
                missing_string=site.m_string,
                strip_chars=site.strip_bad_char or '',
                category=site.cat.strip()[:60],
            )
        )

    info: Dict[str, Any] = {
        'name': WMN_NAME,
        'license': WMN_LICENSE,
        'project': WMN_PROJECT,
        'attribution': WMN_ATTRIBUTION,
        'sha256': digest,
        'sites_in_file': len(parsed.sites),
        'loaded': len(entries),
        'skipped': skipped,
    }
    return WmnCatalog(tuple(entries), info)
