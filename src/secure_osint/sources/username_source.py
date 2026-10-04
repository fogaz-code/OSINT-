import html
import logging
import re
import secrets
import xmlrpc.client
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from secure_osint.config import get_api_key
from secure_osint.sources.base import BaseSource, SourceError, SourceUnavailable, TransientSourceError
from secure_osint.sources.registry import register_source
from secure_osint.sources.wmn_catalog import (
    WmnCatalogError,
    WmnEntry,
    fill_template,
    host_key,
    load_wmn_catalog,
    resolve_wmn_path,
)
from secure_osint.utils.deadline import DeadlineExceeded, clamp_timeout, remaining, submit_in_context
from secure_osint.utils.http_client import HttpResponse, SafeHttpClient, shared_client

logger = logging.getLogger(__name__)

# Regex prudente e comune: esclude '/', '?', '#', '%', spazi (niente path/query injection negli URL).
_USERNAME = re.compile(r'^[A-Za-z0-9_.]{1,38}[A-Za-z0-9_]$|^[A-Za-z0-9_]$')

# Per-request cap; inside a step every request is further clamped to the step's remaining budget.
REQUEST_TIMEOUT = 10.0
# Bounded concurrency: enough to finish the built-in sweep well inside the step budget, low enough
# not to look like a burst against any single provider (each host also has its own rate limiter).
DEFAULT_MAX_WORKERS = 8
MAX_WORKERS_CAP = 16

PLATFORM_SETS = ('builtin', 'wmn', 'all')

# C4 taxonomy: why a platform could not be determined (None = nothing failed).
ERROR_KINDS = ('timeout', 'rate_limited', 'blocked', 'connection', 'http_status', 'auth_wall', 'deadline', 'other')
# C4 calibration outcome of a platform (the soft-404 control probe).
CALIBRATION_PASSED, CALIBRATION_SOFT404, CALIBRATION_CONTROL_ERROR, CALIBRATION_NA = (
    'passed',
    'soft404',
    'control_error',
    'not_applicable',
)

# C2: a sweep is reported partial (not cached, step DEGRADED) when more than this share of the
# automated platforms failed, or when any API-backed (HIGH) platform failed transiently.
PARTIAL_FAILURE_RATIO = 0.25
_MAX_ERRORS_LISTED = 50

# HTTP che indicano "bloccato/limitato dalla piattaforma", non "utente assente": UNAVAILABLE con nota.
# 429 = rate limit (classified as rate_limited before this set is consulted), 451 = legal reasons,
# 999 = LinkedIn-style block.
BLOCK_CODES = frozenset({429, 451, 999})

# 401/403 su una piattaforma pubblica = muro di autenticazione o anti-bot: verifica manuale, non
# un falso "assente" e non un semplice "bloccato".
AUTH_WALL_CODES = frozenset({401, 403})

# Piattaforme che richiedono sempre una sessione autenticata per vedere un profilo. Per scelta NON
# le interroghiamo affatto: niente scraping, niente aggiramenti dei ToS. L'investigatore riceve una
# valutazione onesta ("automatizzabile" vs "verifica manuale").
AUTH_REQUIRED = frozenset({'linkedin', 'instagram', 'facebook', 'x'})
AUTH_REQUIRED_MSG = 'Platform requires authenticated session; manual verification recommended.'

# Affidabilità di un esito "esiste".
# HIGH: API JSON con semantica netta (404/lista vuota = assente).
# MEDIUM: pagina web (HTML) confrontata con uno username inesistente (vedi `_calibrate`).
# LOW: match ambiguo (ricerca per nome) o calibrazione non riuscita: verificare a mano.
# MANUAL: non determinabile automaticamente (login, blocco, anti-bot, soft 404).
HIGH, MEDIUM, LOW, MANUAL = 'HIGH', 'MEDIUM', 'LOW', 'MANUAL'
CONFIDENCE_LEVELS = (HIGH, MEDIUM, LOW, MANUAL)

SOFT_404_MSG = 'Soft 404: the platform answers the same way for a username that does not exist; verify manually.'
UNCALIBRATED_MSG = 'Could not compare with a non-existent username (calibration failed); verify manually.'
CHALLENGE_MSG = 'Anti-bot challenge page instead of a profile; verify manually.'
PYPI_NO_PACKAGES_MSG = 'No packages owned (a PyPI account without packages cannot be detected).'
RATE_LIMITED_MSG = 'Rate limited by the platform; retry later.'
GITHUB_RATE_LIMITED_MSG = 'rate limited — retry later or set GITHUB_TOKEN'
GITHUB_BAD_TOKEN_MSG = 'GitHub rejected GITHUB_TOKEN (HTTP 401); check or unset it.'
WMN_NO_MATCH_MSG = 'Response matched neither the "exists" nor the "missing" signature; verify manually.'

_GITHUB_API_HOST = 'api.github.com'
_RATE_LIMIT_TEXT = re.compile(r'rate[\s_-]?limit', re.IGNORECASE)

_TELEGRAM_MARKER = 'tgme_page_title'  # presente nella pagina t.me di un profilo/canale pubblico esistente

# Pagine di challenge anti-bot servite con HTTP 200 (PyPI, Cloudflare): non sono profili.
_CHALLENGE_MARKERS = ('<title>client challenge</title>', '<title>just a moment...</title>', 'cf-browser-verification')

_BIO_MAX = 280
_TAG = re.compile(r'<[^>]+>')
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


@dataclass(frozen=True)
class Platform:
    """How to check one platform: its URLs, detection kind and reliability."""

    check_url: Optional[str]  # None per le piattaforme auth-required (nessuna richiesta)
    profile_url: str
    kind: str  # nome dell'handler `_kind_<kind>`, oppure 'auth_required' / 'pypi'
    confidence: str = HIGH  # affidabilità quando il controllo dà una risposta netta
    calibrate: bool = False  # pagina web: confrontare con uno username inesistente (anti soft-404)
    # Testo che, in una risposta 200, significa "utente assente". Best-effort: queste pagine cambiano
    # spesso e non sono verificabili da qui; la rete di sicurezza vera è la calibrazione.
    not_found_markers: Tuple[str, ...] = ()
    # Catalog platforms (WhatsMyName) only: display name, origin and the response signatures.
    label: Optional[str] = None
    catalog: Optional[str] = None
    exists_code: Optional[int] = None
    exists_string: str = ''
    missing_code: Optional[int] = None
    missing_string: str = ''
    strip_chars: str = ''

    def url_for(self, template: Optional[str], username: str) -> str:
        """``template`` filled with the URL-encoded username."""
        assert template is not None
        return fill_template(template, username, self.strip_chars)


@dataclass
class Outcome:
    """Result of one platform check."""

    exists: Optional[bool]
    error: Optional[str] = None
    confidence: Optional[str] = None
    profile: Dict[str, Any] = field(default_factory=dict)
    error_kind: Optional[str] = None  # one of ERROR_KINDS when the check failed
    transient: bool = False  # the failure may clear up on a later run (timeout, rate limit, 5xx...)
    calibration: str = CALIBRATION_NA


def _failure(kind: str, message: str, transient: bool = False) -> Outcome:
    """An undetermined result (``exists`` None, MANUAL) with its C4 error kind."""
    return Outcome(None, message, MANUAL, error_kind=kind, transient=transient)


def _unexpected_status(code: int) -> Outcome:
    return _failure('http_status', f'Unexpected HTTP {code}', transient=code >= 500)


def _request_failure(error: SourceError) -> Outcome:
    """Map a client error to (error_kind, human message) without leaking the raw text.

    The raw message can carry hosts, resolved addresses or errno details; only the category leaves
    this function.
    """
    if isinstance(error, DeadlineExceeded):
        return _failure('deadline', 'Not checked: the step time budget ran out first.', transient=True)
    text = str(error).lower()
    if 'ssrf guard' in text:
        if 'cannot resolve' in text or 'no addresses' in text:
            return _failure('connection', 'DNS resolution failed for the platform host.', transient=True)
        return _failure('blocked', 'Request blocked by the SSRF guard (host resolves to a non-public address).')
    if 'circuit open' in text:
        return _failure('connection', 'Not checked: host circuit breaker is open after repeated failures.', True)
    if 'local rate limit' in text:
        return _failure('rate_limited', 'Local rate limit wait exceeded; retry later.', transient=True)
    if 'timed out' in text:
        return _failure('timeout', 'Timed out waiting for the platform.', transient=True)
    if 'too many redirects' in text:
        return _failure('other', 'Too many redirects.')
    if 'response exceeds' in text:
        return _failure('other', 'Response too large.')
    if 'connection error' in text:
        return _failure('connection', 'Connection failed (network, DNS or TLS error).', transient=True)
    if error.transient:
        return _failure('connection', 'Network error.', transient=True)
    return _failure('other', 'Request failed.')


def _is_rate_limited(resp: HttpResponse) -> bool:
    """429, or a 403 carrying rate-limit signals (GitHub's primary/secondary limits answer 403)."""
    if resp.status_code == 429:
        return True
    if resp.status_code != 403:
        return False
    headers = {str(k).lower(): str(v).strip() for k, v in resp.headers.items()}
    if headers.get('x-ratelimit-remaining') == '0' or 'retry-after' in headers:
        return True
    return bool(_RATE_LIMIT_TEXT.search(resp.content[:4096].decode('utf-8', errors='replace')))


@dataclass(frozen=True)
class _Sweep:
    """Per-run state, passed explicitly: the source instance is shared across concurrent runs."""

    username: str
    canary: str  # control username for the soft-404 calibration: random per run, cannot exist
    github_token: Optional[str] = field(default=None, repr=False)


def _web(url: str, profile: str, kind: str = 'status', markers: Tuple[str, ...] = ()) -> Platform:
    """A platform checked through its public web page: MEDIUM confidence, calibrated."""
    return Platform(url, profile, kind, confidence=MEDIUM, calibrate=True, not_found_markers=markers)


PLATFORMS: Dict[str, Platform] = {
    'github': Platform('https://api.github.com/users/{u}', 'https://github.com/{u}', 'github'),
    'keybase': Platform(
        'https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}', 'https://keybase.io/{u}', 'keybase'
    ),
    'reddit': Platform('https://www.reddit.com/user/{u}/about.json', 'https://www.reddit.com/user/{u}', 'status'),
    'hackernews': Platform(
        'https://hacker-news.firebaseio.com/v0/user/{u}.json', 'https://news.ycombinator.com/user?id={u}', 'hackernews'
    ),
    'telegram': _web('https://t.me/{u}', 'https://t.me/{u}', kind='telegram'),
    # TikTok e Pinterest rispondono 200 anche per utenti inesistenti (soft 404, confermato dal vivo).
    'tiktok': _web(
        'https://www.tiktok.com/@{u}',
        'https://www.tiktok.com/@{u}',
        markers=("couldn't find this account", 'couldn&#39;t find this account', 'couldn&#x27;t find this account'),
    ),
    'pinterest': _web(
        'https://www.pinterest.com/{u}/',
        'https://www.pinterest.com/{u}/',
        markers=("sorry! we couldn't find that page", 'sorry! we couldn&#39;t find that page', 'user not found'),
    ),
    # GitLab: la API pubblica elenca gli utenti per username; lista non vuota = esiste.
    'gitlab': Platform('https://gitlab.com/api/v4/users?username={u}', 'https://gitlab.com/{u}', 'gitlab'),
    'bitbucket': Platform('https://api.bitbucket.org/2.0/users/{u}', 'https://bitbucket.org/{u}/', 'bitbucket'),
    'medium': _web('https://medium.com/@{u}', 'https://medium.com/@{u}'),
    'devto': Platform('https://dev.to/api/users/by_username?url={u}', 'https://dev.to/{u}', 'devto'),
    # Stack Overflow non ha username univoci: filter=total conta gli utenti il cui nome contiene il termine.
    'stackoverflow': Platform(
        'https://api.stackexchange.com/2.3/users?inname={u}&site=stackoverflow&filter=total',
        'https://stackoverflow.com/users?tab=Reputation&q={u}',
        'stackoverflow',
        confidence=LOW,
    ),
    # Piattaforme developer/portfolio pubbliche. Escluse per policy le piattaforme che bloccano le
    # richieste non autenticate; se una di queste risponde 401/403 scatta la verifica manuale.
    'codepen': _web('https://codepen.io/{u}', 'https://codepen.io/{u}'),
    'dockerhub': Platform('https://hub.docker.com/v2/users/{u}/', 'https://hub.docker.com/u/{u}', 'dockerhub'),
    # PyPI: le pagine utente rispondono 200 con una challenge anti-bot per QUALUNQUE username (verificato
    # dal vivo). `/pypi/<nome>/json` è l'API dei PROGETTI, non degli utenti. Si usa l'XML-RPC pubblico
    # `user_packages`: pacchetti > 0 = l'account esiste (HIGH).
    'pypi': Platform('https://pypi.org/pypi', 'https://pypi.org/user/{u}/', 'pypi'),
    'hackaday': _web('https://hackaday.io/{u}', 'https://hackaday.io/{u}'),
    # Mastodon è federato: controlliamo solo l'istanza pubblica principale (mastodon.social).
    'mastodon': _web('https://mastodon.social/@{u}', 'https://mastodon.social/@{u}'),
    'aboutme': _web('https://about.me/{u}', 'https://about.me/{u}'),
    'sourceforge': _web('https://sourceforge.net/u/{u}/', 'https://sourceforge.net/u/{u}/'),
    # Piattaforme "link in bio" / blog personale. Nessun marcatore not-found verificato dal vivo per
    # queste: ci si affida solo alla calibrazione (v1.1.0), che è la vera rete di sicurezza contro i
    # falsi positivi, non i marcatori (best-effort quando noti).
    'tumblr': _web('https://{u}.tumblr.com/', 'https://{u}.tumblr.com/'),  # blog: sottodominio per utente
    # Profilo community di wordpress.org (host fisso), non un blog su wordpress.com (sottodominio per
    # utente, meno affidabile come segnale di esistenza): esiste per chi ha mai avuto un account lì.
    'wordpress': _web('https://profiles.wordpress.org/{u}/', 'https://profiles.wordpress.org/{u}/'),
    'gravatar': _web('https://gravatar.com/{u}', 'https://gravatar.com/{u}'),
    'soundcloud': _web('https://soundcloud.com/{u}', 'https://soundcloud.com/{u}'),
    'flickr': _web('https://www.flickr.com/photos/{u}/', 'https://www.flickr.com/photos/{u}/'),
    'linktree': _web('https://linktr.ee/{u}', 'https://linktr.ee/{u}'),
    'carrd': _web('https://{u}.carrd.co', 'https://{u}.carrd.co'),  # sito: sottodominio per utente
    # Auth-required: nessuna check_url, sempre verifica manuale.
    'linkedin': Platform(None, 'https://www.linkedin.com/in/{u}/', 'auth_required', confidence=MANUAL),
    'instagram': Platform(None, 'https://www.instagram.com/{u}/', 'auth_required', confidence=MANUAL),
    'facebook': Platform(None, 'https://www.facebook.com/{u}', 'auth_required', confidence=MANUAL),
    'x': Platform(None, 'https://x.com/{u}', 'auth_required', confidence=MANUAL),
}

# Nomi leggibili per report e grafo.
PLATFORM_LABELS: Dict[str, str] = {
    'github': 'GitHub',
    'keybase': 'Keybase',
    'reddit': 'Reddit',
    'hackernews': 'Hacker News',
    'telegram': 'Telegram',
    'tiktok': 'TikTok',
    'pinterest': 'Pinterest',
    'gitlab': 'GitLab',
    'bitbucket': 'Bitbucket',
    'medium': 'Medium',
    'devto': 'Dev.to',
    'stackoverflow': 'Stack Overflow',
    'codepen': 'CodePen',
    'dockerhub': 'Docker Hub',
    'pypi': 'PyPI',
    'hackaday': 'Hackaday',
    'mastodon': 'Mastodon',
    'aboutme': 'about.me',
    'sourceforge': 'SourceForge',
    'tumblr': 'Tumblr',
    'wordpress': 'WordPress.org',
    'gravatar': 'Gravatar',
    'soundcloud': 'SoundCloud',
    'flickr': 'Flickr',
    'linktree': 'Linktree',
    'carrd': 'Carrd',
    'linkedin': 'LinkedIn',
    'instagram': 'Instagram',
    'facebook': 'Facebook',
    'x': 'X',
}

# Piattaforme dove "exists" NON è un match esatto dello username: Stack Overflow cerca gli utenti il
# cui nome *contiene* il termine. Confidenza LOW.
INEXACT_MATCH = frozenset({'stackoverflow'})


def _as_dict(value: Any) -> Dict[str, Any]:
    """The value if it is a dict, else an empty dict (API payloads are untrusted)."""
    return value if isinstance(value, dict) else {}


def _text(value: Any, limit: int = 120) -> Optional[str]:
    """A short, clean public-profile string (no control characters, no HTML), or None."""
    if not isinstance(value, str):
        return None
    # Unescape first, then strip: stripping first turns '&lt;img onerror=...&gt;' back into live markup.
    cleaned = _CONTROL.sub('', _TAG.sub(' ', html.unescape(value))).replace('<', ' ').replace('>', ' ')
    cleaned = ' '.join(cleaned.split())
    return cleaned[:limit] or None


def _timestamp(value: Any) -> Optional[str]:
    """ISO date from an ISO string or a Unix timestamp."""
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return _text(value, 40)


def _profile(
    display_name: Any = None, bio: Any = None, created_at: Any = None, avatar_url: Any = None, **extra: Any
) -> Dict[str, Any]:
    """Public metadata worth recording. The avatar is kept as a URL only: never downloaded."""
    avatar = avatar_url if isinstance(avatar_url, str) and avatar_url.startswith('https://') else None
    fields = {
        'display_name': _text(display_name),
        'bio': _text(bio, _BIO_MAX),
        'created_at': _timestamp(created_at),
        'avatar_url': avatar[:500] if avatar else None,
        **extra,
    }
    return {k: v for k, v in fields.items() if v not in (None, '')}


def _max_workers(value: Any) -> int:
    """The ``max_workers`` param, clamped to [1, MAX_WORKERS_CAP]; anything invalid means the default."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return DEFAULT_MAX_WORKERS
    return min(value, MAX_WORKERS_CAP)


def _platform_from_wmn(entry: WmnEntry) -> Platform:
    """A WhatsMyName site as a web platform: MEDIUM at most and always calibrated against soft 404s."""
    return Platform(
        entry.check_template,
        entry.profile_template,
        'wmn',
        confidence=MEDIUM,
        calibrate=True,
        label=entry.label,
        catalog='wmn',
        exists_code=entry.exists_code,
        exists_string=entry.exists_string,
        missing_code=entry.missing_code,
        missing_string=entry.missing_string,
        strip_chars=entry.strip_chars,
    )


def _builtin_hosts() -> List[str]:
    """Hosts the built-in platforms already cover (check and profile URLs), for WMN deduplication."""
    hosts: List[str] = []
    for platform in PLATFORMS.values():
        hosts.extend(host_key(url) for url in (platform.check_url, platform.profile_url) if url)
    return hosts


@register_source('username')
class UsernameSource(BaseSource):
    """Presenza di uno username sulle principali piattaforme pubbliche.

    Pensato per self-audit e indagini autorizzate. Per ogni piattaforma restituisce
    ``{'exists', 'error', 'url', 'exact', 'label', 'confidence', 'calibration', 'error_kind'}``
    (+ ``profile`` quando la fonte espone metadati pubblici): ``exists`` None significa "non
    determinabile" (bloccato, errore, login, soft 404), mai un falso "assente". LinkedIn, Instagram,
    Facebook e X non vengono interrogate.

    Le pagine web (confidenza MEDIUM) vengono calibrate: se anche uno username sicuramente
    inesistente risulta "trovato", la piattaforma non dà segnale (soft 404) e l'esito diventa
    verifica manuale invece di un falso positivo. Nessun avatar viene scaricato: solo l'URL.

    The checks run on a bounded thread pool; every request is clamped to the step deadline and any
    check still pending when the budget runs out is reported as ``error_kind: deadline``. A sweep
    with too many failures is returned with ``partial: True`` and ``errors`` (C2), never as a clean
    result. Optional WhatsMyName platforms come from a local, user-supplied file (``wmn_catalog``).
    """

    PLATFORMS = PLATFORMS

    def __init__(self, client: Optional[SafeHttpClient] = None):
        """Initialize UsernameSource."""
        self.client = client or shared_client()

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query username presence across public platforms and return the collected data.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.
                Optional: ``platform_set`` (builtin | wmn | all, default builtin), ``max_workers``,
                ``wmn_path`` (local wmn-data.json, else env SECURE_OSINT_WMN_PATH) and
                ``wmn_include_nsfw`` (default False).

        Returns:
            A dict of results specific to this source.

        Raises:
            SourceUnavailable: Permanent failure (invalid input or params, unusable WMN file).
            TransientSourceError: No platform could be checked at all.
        """
        username = self.require_input(params)
        if not _USERNAME.match(username) or username in ('.', '..'):
            raise SourceUnavailable('Invalid username')
        platform_set = params.get('platform_set', 'builtin')
        if platform_set not in PLATFORM_SETS:
            raise SourceUnavailable(f'Invalid platform_set (expected one of: {", ".join(PLATFORM_SETS)})')
        include_nsfw = params.get('wmn_include_nsfw', False)
        if not isinstance(include_nsfw, bool):
            raise SourceUnavailable('wmn_include_nsfw must be true or false')

        platforms, catalog_info = self._select_platforms(platform_set, params.get('wmn_path'), include_nsfw)
        sweep = _Sweep(username, f'zz{secrets.token_hex(6)}q', get_api_key('GITHUB_TOKEN'))
        outcomes = self._sweep(platforms, sweep, _max_workers(params.get('max_workers')))

        entries: Dict[str, Dict[str, Any]] = {}
        for name, platform in platforms.items():
            outcome = outcomes[name]
            entry: Dict[str, Any] = {
                'exists': outcome.exists,
                'error': outcome.error,
                'url': platform.url_for(platform.profile_url, username),
                'exact': name not in INEXACT_MATCH,
                'label': platform.label or PLATFORM_LABELS.get(name, name),
                'confidence': outcome.confidence,
                'calibration': outcome.calibration,
                'error_kind': outcome.error_kind,
            }
            if platform.catalog:
                entry['catalog'] = platform.catalog
            if outcome.profile:
                entry['profile'] = outcome.profile
            entries[name] = entry

        automated = [name for name, p in platforms.items() if p.kind != 'auth_required']
        if all(entries[name]['exists'] is None for name in automated):
            if automated and all(outcomes[name].error_kind == 'deadline' for name in automated):
                raise DeadlineExceeded('step time budget exhausted before any platform could be checked')
            raise TransientSourceError('No platform could be checked (all unavailable)')

        failed = [name for name in automated if outcomes[name].error_kind is not None]
        checked = sum(1 for name in automated if entries[name]['exists'] is not None)
        found = sum(1 for entry in entries.values() if entry['exists'] is True)
        api_failed_transiently = any(outcomes[name].transient and platforms[name].confidence == HIGH for name in failed)
        partial = bool(failed) and (len(failed) / len(automated) > PARTIAL_FAILURE_RATIO or api_failed_transiently)

        result: Dict[str, Any] = {
            'username': username,
            'profiles_found': found,
            'checked': checked,
            'needs_manual': sorted(AUTH_REQUIRED),
            'platform_set': platform_set,
            'stats': {'automated': len(automated), 'checked': checked, 'found': found, 'failed': len(failed)},
            'partial': partial,
            'platforms': entries,
        }
        # C2: 'errors' alone keeps the status but skips the cache, so a re-run re-checks platforms that
        # failed transiently instead of replaying the failure for the whole cache TTL. Stable failures
        # (auth walls, SSRF blocks, odd status codes) do not by themselves prevent caching.
        if partial or any(outcomes[name].transient for name in failed):
            errors = [f'{entries[name]["label"]}: {entries[name]["error"]}' for name in failed]
            if len(errors) > _MAX_ERRORS_LISTED:
                errors = errors[:_MAX_ERRORS_LISTED] + [f'... and {len(errors) - _MAX_ERRORS_LISTED} more']
            result['errors'] = errors
        if catalog_info is not None:
            result['catalog'] = catalog_info
        return result

    # --- platform selection ---

    def _select_platforms(
        self, platform_set: str, wmn_path: Any, include_nsfw: bool
    ) -> Tuple[Dict[str, Platform], Optional[Dict[str, Any]]]:
        """The platforms to sweep, in a stable order, plus the WMN provenance block when used."""
        if platform_set == 'builtin':
            return dict(self.PLATFORMS), None
        path = resolve_wmn_path(wmn_path)
        if path is None:
            raise WmnCatalogError(
                'WhatsMyName data not configured: set the wmn_path param or SECURE_OSINT_WMN_PATH to a local '
                'wmn-data.json (it is never downloaded by the tool)'
            )
        catalog = load_wmn_catalog(
            path,
            include_nsfw=include_nsfw,
            exclude_hosts=_builtin_hosts() if platform_set == 'all' else (),
        )
        if not catalog.entries and platform_set == 'wmn':
            raise WmnCatalogError('WhatsMyName file has no usable entries after validation')
        wmn = {entry.key: _platform_from_wmn(entry) for entry in catalog.entries}
        if platform_set == 'all':
            return {**self.PLATFORMS, **wmn}, catalog.info
        # WMN only: still list the auth-walled platforms as manual checks (they cost no request).
        manual = {name: p for name, p in self.PLATFORMS.items() if p.kind == 'auth_required'}
        return {**wmn, **manual}, catalog.info

    # --- sweep ---

    def _sweep(self, platforms: Dict[str, Platform], sweep: _Sweep, max_workers: int) -> Dict[str, Outcome]:
        """Check every platform on a bounded pool, within the step deadline. Order follows ``platforms``."""
        outcomes: Dict[str, Outcome] = {}
        futures: Dict[str, 'Future[Outcome]'] = {}
        automated = {name: p for name, p in platforms.items() if p.kind != 'auth_required'}
        if automated:
            executor = ThreadPoolExecutor(
                max_workers=min(max_workers, len(automated)), thread_name_prefix='osint-username'
            )
            try:
                for name, platform in automated.items():
                    futures[name] = submit_in_context(executor, self._check, platform, sweep)
                left = remaining()
                wait(list(futures.values()), timeout=None if left is None else max(0.0, left))
            finally:
                # Never block on a check that outlived the budget: queued ones are cancelled, running
                # ones finish (bounded by their clamped timeout) and their result is discarded.
                executor.shutdown(wait=False, cancel_futures=True)

        for name, platform in platforms.items():
            if platform.kind == 'auth_required':
                outcomes[name] = Outcome(None, AUTH_REQUIRED_MSG, MANUAL)
                continue
            future = futures[name]
            if future.done() and not future.cancelled():
                error = future.exception()
                if error is None:
                    outcomes[name] = future.result()
                elif isinstance(error, SourceError):
                    outcomes[name] = _request_failure(error)
                else:  # a handler bug: confine it to this platform instead of failing the whole sweep
                    logger.warning(
                        'platform check raised unexpectedly',
                        extra={'platform': name, 'error_type': type(error).__name__},
                    )
                    outcomes[name] = _failure('other', f'Check failed unexpectedly ({type(error).__name__}).')
            else:
                outcomes[name] = _request_failure(DeadlineExceeded('step time budget exhausted'))
            if outcomes[name].error_kind is not None:
                logger.debug('platform check failed', extra={'platform': name, 'error_kind': outcomes[name].error_kind})
        return outcomes

    # --- checking ---

    def _check(self, platform: Platform, sweep: _Sweep) -> Outcome:
        if platform.kind == 'pypi':
            outcome = self._check_pypi(platform, sweep)
        else:
            outcome = self._probe(platform, sweep.username, sweep)
            if outcome.exists is True and platform.calibrate:
                outcome = self._calibrate(platform, outcome, sweep)
        if outcome.confidence is None:
            outcome.confidence = platform.confidence if outcome.exists is not None else MANUAL
        return outcome

    @staticmethod
    def _headers(url: str, sweep: _Sweep) -> Optional[Dict[str, str]]:
        """Extra headers: only for the GitHub API, the only host that ever receives GITHUB_TOKEN."""
        parts = urlsplit(url)
        if parts.scheme != 'https' or parts.hostname != _GITHUB_API_HOST:
            return None
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if sweep.github_token:
            headers['Authorization'] = f'Bearer {sweep.github_token}'
        return headers

    def _probe(self, platform: Platform, username: str, sweep: _Sweep) -> Outcome:
        """One GET against the platform's check URL, interpreted by its handler."""
        url = platform.url_for(platform.check_url, username)
        try:
            resp = self.client.get(url, headers=self._headers(url, sweep), timeout=clamp_timeout(REQUEST_TIMEOUT))
        except SourceError as e:
            return _request_failure(e)
        code = resp.status_code
        if _is_rate_limited(resp):
            github_hint = urlsplit(url).hostname == _GITHUB_API_HOST and not sweep.github_token
            return _failure('rate_limited', GITHUB_RATE_LIMITED_MSG if github_hint else RATE_LIMITED_MSG, True)
        if platform.kind == 'wmn' and code in (platform.exists_code, platform.missing_code):
            return self._kind_wmn(resp, platform)  # the catalog's own signature for this code wins
        if code in AUTH_WALL_CODES:
            if code == 401 and sweep.github_token and urlsplit(url).hostname == _GITHUB_API_HOST:
                return _failure('auth_wall', GITHUB_BAD_TOKEN_MSG)
            # Forbidden/Unauthorized su una piattaforma pubblica: muro di auth/anti-bot -> verifica manuale.
            return _failure('auth_wall', AUTH_REQUIRED_MSG)
        if code in BLOCK_CODES:
            return _failure('blocked', f'Blocked by platform (HTTP {code})')
        handler: Callable[[HttpResponse, Platform], Outcome] = getattr(self, f'_kind_{platform.kind}')
        return handler(resp, platform)

    def _calibrate(self, platform: Platform, found: Outcome, sweep: _Sweep) -> Outcome:
        """Anti soft-404: the same check with a username that cannot exist must NOT come back "found".

        Costs no extra request beyond the control probe itself, and only for platforms that looked found.
        """
        control = self._probe(platform, sweep.canary, sweep)
        if control.exists is False:  # la piattaforma distingue
            return Outcome(True, None, platform.confidence, found.profile, calibration=CALIBRATION_PASSED)
        if control.exists is True:  # risponde "trovato" a chiunque: nessun segnale
            return Outcome(None, SOFT_404_MSG, MANUAL, calibration=CALIBRATION_SOFT404)
        # Controllo fallito: non fidarsi.
        return Outcome(True, UNCALIBRATED_MSG, LOW, found.profile, calibration=CALIBRATION_CONTROL_ERROR)

    def _check_pypi(self, platform: Platform, sweep: _Sweep) -> Outcome:
        assert platform.check_url is not None
        body = xmlrpc.client.dumps((sweep.username,), 'user_packages').encode()
        try:
            resp = self.client.post(
                platform.check_url, body, headers={'Content-Type': 'text/xml'}, timeout=clamp_timeout(REQUEST_TIMEOUT)
            )
        except SourceError as e:
            return _request_failure(e)
        if _is_rate_limited(resp):
            return _failure('rate_limited', RATE_LIMITED_MSG, transient=True)
        if resp.status_code in AUTH_WALL_CODES:
            return _failure('auth_wall', AUTH_REQUIRED_MSG)
        if resp.status_code in BLOCK_CODES:
            return _failure('blocked', f'Blocked by platform (HTTP {resp.status_code})')
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        try:
            (packages,), _ = xmlrpc.client.loads(resp.content)
        except Exception:  # risposta non XML-RPC (API cambiata/dismessa): mai un falso esito
            return _failure('other', 'Unexpected PyPI response; verify manually')
        if not isinstance(packages, list):
            return _failure('other', 'Unexpected PyPI response; verify manually')
        if packages:
            return Outcome(True, None, HIGH, _profile(packages=len(packages)))
        return Outcome(False, PYPI_NO_PACKAGES_MSG, MEDIUM)

    # --- response handlers ---

    @staticmethod
    def _json_or_none(resp: HttpResponse) -> Any:
        """Parsed JSON body, or None if the body is empty or not valid JSON (never raises)."""
        if not resp.content.strip():
            return None
        try:
            return resp.json()
        except SourceError:
            return None

    @staticmethod
    def _page_says(resp: HttpResponse, markers: Tuple[str, ...]) -> bool:
        text = resp.text.lower()
        return any(marker in text for marker in markers)

    @staticmethod
    def _kind_status(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code == 200:
            if UsernameSource._page_says(resp, _CHALLENGE_MARKERS):
                return _failure('blocked', CHALLENGE_MSG)
            if UsernameSource._page_says(resp, platform.not_found_markers):
                return Outcome(False)
            return Outcome(True)
        if resp.status_code in (404, 410):
            return Outcome(False)
        return _unexpected_status(resp.status_code)

    @staticmethod
    def _kind_wmn(resp: HttpResponse, platform: Platform) -> Outcome:
        """WhatsMyName semantics: exists = e_code AND e_string; missing = m_code AND m_string (case-sensitive)."""
        text = resp.text
        if resp.status_code == platform.exists_code and platform.exists_string in text:
            if UsernameSource._page_says(resp, _CHALLENGE_MARKERS):
                return _failure('blocked', CHALLENGE_MSG)
            return Outcome(True)
        if resp.status_code == platform.missing_code and platform.missing_string in text:
            return Outcome(False)
        if resp.status_code not in (platform.exists_code, platform.missing_code):
            return _unexpected_status(resp.status_code)
        if UsernameSource._page_says(resp, _CHALLENGE_MARKERS):
            return _failure('blocked', CHALLENGE_MSG)
        return _failure('other', WMN_NO_MATCH_MSG)

    @staticmethod
    def _json_profile(resp: HttpResponse, build: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Outcome:
        if resp.status_code == 404:
            return Outcome(False)
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        data = UsernameSource._json_or_none(resp)
        return Outcome(True, profile=build(data) if isinstance(data, dict) else {})

    @staticmethod
    def _kind_github(resp: HttpResponse, platform: Platform) -> Outcome:
        return UsernameSource._json_profile(
            resp,
            lambda d: _profile(d.get('name'), d.get('bio'), d.get('created_at'), d.get('avatar_url')),
        )

    @staticmethod
    def _kind_bitbucket(resp: HttpResponse, platform: Platform) -> Outcome:
        def build(d: Dict[str, Any]) -> Dict[str, Any]:
            avatar = _as_dict(_as_dict(d.get('links')).get('avatar'))
            return _profile(d.get('display_name'), None, d.get('created_on'), avatar.get('href'))

        return UsernameSource._json_profile(resp, build)

    @staticmethod
    def _kind_devto(resp: HttpResponse, platform: Platform) -> Outcome:
        return UsernameSource._json_profile(
            resp,
            lambda d: _profile(d.get('name'), d.get('summary'), d.get('joined_at'), d.get('profile_image')),
        )

    @staticmethod
    def _kind_dockerhub(resp: HttpResponse, platform: Platform) -> Outcome:
        # Solo nome e data: niente gravatar_email (minimizzazione dei dati).
        return UsernameSource._json_profile(resp, lambda d: _profile(d.get('full_name'), None, d.get('date_joined')))

    @staticmethod
    def _kind_keybase(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        data = UsernameSource._json_or_none(resp)
        them = data.get('them') if isinstance(data, dict) else None
        if not them or not isinstance(them, list) or not isinstance(them[0], dict):
            return Outcome(False)
        user = them[0]
        profile, basics = _as_dict(user.get('profile')), _as_dict(user.get('basics'))
        primary = _as_dict(_as_dict(user.get('pictures')).get('primary'))
        return Outcome(
            True,
            profile=_profile(profile.get('full_name'), profile.get('bio'), basics.get('ctime'), primary.get('url')),
        )

    @staticmethod
    def _kind_hackernews(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        data = UsernameSource._json_or_none(resp)
        if data is None:
            return Outcome(False)
        details = data if isinstance(data, dict) else {}
        return Outcome(True, profile=_profile(None, details.get('about'), details.get('created')))

    @staticmethod
    def _kind_telegram(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        return Outcome(_TELEGRAM_MARKER in resp.text)

    @staticmethod
    def _kind_gitlab(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        data = UsernameSource._json_or_none(resp)
        if not isinstance(data, list):
            return _failure('other', 'Unexpected response shape')
        if not data:
            return Outcome(False)
        user = data[0] if isinstance(data[0], dict) else {}
        return Outcome(True, profile=_profile(user.get('name'), None, None, user.get('avatar_url')))

    @staticmethod
    def _kind_stackoverflow(resp: HttpResponse, platform: Platform) -> Outcome:
        if resp.status_code != 200:
            return _unexpected_status(resp.status_code)
        data = UsernameSource._json_or_none(resp)
        total = data.get('total') if isinstance(data, dict) else None
        if not isinstance(total, int):
            return Outcome(False)
        return Outcome(total > 0)
