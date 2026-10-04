"""Redaction of secrets and personal data in reports, terminal output, the cache audit and logs.

API-key strategy (project decision, also documented in the README):

1. Exact values: the value of every environment variable ending in _API_KEY, _TOKEN, _SECRET (plus the
   cache key) is removed wherever it appears, in any format. This is the main protection because it
   does not depend on how the key shows up in the text.
2. Contextual patterns: keys that are not configured here (e.g. 64 hex VirusTotal-style, 32
   alphanumeric Shodan-style) are redacted only next to a key name (apikey=, x-apikey:, key:).

"Blind" regexes for 64 hex or 32 alphanumerics are NOT used in reports: they are indistinguishable from
SHA-256 and MD5 hashes, which are legitimate OSINT data (VirusTotal file reputation, Gravatar URLs) and
would be destroyed. Logs are different: there a bare hash is only a leak (a Gravatar MD5 is reversible
for a known address), so :func:`log_guard` adds log-only rules for hashes, URL paths and the run targets.

ReDoS: every pattern runs over attacker-controlled text (remote bios, DNS TXT, HTML). Each rule is
written so a match can only start at the beginning of a run of its own characters (negative
lookbehind) and every repetition is either bounded or followed by a disjoint character, which keeps the
scan linear. ``tests/test_privacy_redos.py`` times every rule against adversarial near-miss inputs.
Strings longer than :data:`MAX_FIELD_CHARS` are truncated (after exact-value secret scrubbing).
"""

import hashlib
import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Pattern, Tuple, Union
from urllib.parse import quote, quote_plus

from secure_osint import config

# 'device': camera/lens/body serial numbers (one physical device, links photos across accounts).
CATEGORIES: FrozenSet[str] = frozenset({'secrets', 'personal', 'network', 'location', 'crypto', 'device'})

# Upper bound on the characters of a single string that the regex rules scan. Larger values are cut at a
# whitespace boundary and marked: no legitimate report field is this big, an attacker-supplied one can be.
MAX_FIELD_CHARS = 100_000
_TRUNCATE_WINDOW = 256

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_CLASS = '1-9A-HJ-NP-Za-km-z'
_TRON_VERSION = 0x41


def _luhn_ok(match: str) -> bool:
    digits = [int(c) for c in match if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(match: str) -> bool:
    iban = match.replace(' ', '').upper()
    if not 15 <= len(iban) <= 34:
        return False
    rearranged = iban[4:] + iban[:4]
    return int(''.join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def _base58check_payload(match: str) -> Optional[bytes]:
    """Decode a 25-byte base58check string (version + 20-byte hash + checksum); None if invalid."""
    num = 0
    for c in match:
        index = _B58.find(c)
        if index < 0:
            return None
        num = num * 58 + index
    if num.bit_length() > 200:
        return None
    raw = num.to_bytes(25, 'big')
    if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        return None
    return raw


def _base58check_ok(match: str) -> bool:
    return _base58check_payload(match) is not None


def _tron_ok(match: str) -> bool:
    """A TRON address: 'T' + 33 base58 chars that decode to version byte 0x41 with a valid checksum."""
    if len(match) != 34 or not match.startswith('T'):
        return False
    raw = _base58check_payload(match)
    return raw is not None and raw[0] == _TRON_VERSION


def _ip_ok(match: str) -> bool:
    try:
        ipaddress.ip_address(match)
        return True
    except ValueError:
        return False


def _phone_digits_ok(match: str) -> bool:
    return 8 <= sum(c.isdigit() for c in match) <= 15


_DECIMAL = re.compile(r'-?\d+\.\d+')


def _coordinate_pair_ok(match: str) -> bool:
    """Latitude within ±90, longitude within ±180, and not two fractions below 1 (scores, ratios)."""
    numbers = _DECIMAL.findall(match)
    if len(numbers) != 2:
        return False
    lat, lon = (float(n) for n in numbers)
    return abs(lat) <= 90 and abs(lon) <= 180 and (abs(lat) >= 1 or abs(lon) >= 1)


def _coordinate_value_ok(match: str) -> bool:
    numbers = _DECIMAL.findall(match)
    return len(numbers) == 1 and abs(float(numbers[0])) <= 180


@dataclass(frozen=True)
class Rule:
    """A single redaction rule: a category, a compiled pattern and an optional validator."""

    name: str
    category: str
    pattern: Pattern[str]
    validator: Optional[Callable[[str], bool]] = None
    keep_group: int = 0  # >0: keep the captured prefix (e.g. "api_key=") and redact the rest


# A decimal degree with at least 4 decimals (~11 m): fewer is a city, not a person's position.
_DEG = r'-?\d{1,3}\.\d{4,15}(?!\d)'
# One DMS component: 45°27'51.1"N, 45° 27′ 51″ N, N 45°27.851', 33°52'S, 45.4642° N. Minutes or a
# hemisphere are mandatory, so temperatures (45°C) and headings (270°) are left alone.
_DMS = (
    r'(?<![\w.])(?:[NSEW] ?)?\d{1,3}(?:\.\d{1,10})? ?° ?'
    r"(?:\d{1,2}(?:\.\d{1,10})? ?['′](?: ?\d{1,2}(?:\.\d{1,10})? ?(?:\"|″|''))?(?: ?[NSEW](?!\w))?"
    r'|[NSEW](?!\w))'
)

# Order matters: specific patterns first, generic ones (phone) last.
RULES = (
    Rule(
        'private_key',
        'secrets',
        # The body stops at the next '-----' (END or another BEGIN): an unterminated header cannot make
        # the scan run to the end of the text once per header.
        re.compile(
            r'-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----(?:(?!-----)[\s\S])*(?:-----END [A-Z ]{0,40}PRIVATE KEY-----)?'
        ),
    ),
    Rule('jwt', 'secrets', re.compile(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')),
    Rule('github_token', 'secrets', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})')),
    Rule('llm_api_key', 'secrets', re.compile(r'(?<![A-Za-z0-9_-])sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}')),
    Rule('aws_access_key', 'secrets', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    Rule('slack_token', 'secrets', re.compile(r'(?<![A-Za-z0-9-])xox[abprs]-[A-Za-z0-9-]{10,}')),
    Rule('google_api_key', 'secrets', re.compile(r'\bAIza[0-9A-Za-z_-]{35}')),
    Rule('stripe_key', 'secrets', re.compile(r'\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}')),
    # 64 hex (VirusTotal) and 32 alphanumerics (Shodan) ONLY next to a key name: on their own they are
    # indistinguishable from SHA-256 and MD5, which are legitimate OSINT data and must not be destroyed.
    Rule(
        'api_key_param',
        'secrets',
        re.compile(
            r'(?i)((?:\bx-)?\bapi[_-]?key["\']?\s{0,10}[:=]\s{0,10}["\']?|\bkey["\']?\s{0,10}[:=]\s{0,10}["\']?)'
            r'[A-Za-z0-9]{32,64}\b'
        ),
        keep_group=1,
    ),
    Rule(
        'generic_secret',
        'secrets',
        re.compile(
            r'(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|passw(?:or)?d)\b\s{0,10}[:=]\s{0,10})'
            r'["\']?[^\s"\',;]{8,}'
        ),
        keep_group=1,
    ),
    # Location before the numeric personal/network rules, so a coordinate pair is redacted as one unit.
    Rule(
        'coordinate_field',
        'location',
        re.compile(
            r'(?i)((?<![\w-])(?:gps[_ ]?)?(?:latitude|longitude|lat|lon|lng|long|mlat|mlon)["\']?\s{0,3}[:=]\s{0,3}["\']?)'
            r'-?\d{1,3}\.\d{1,15}(?!\d)'
        ),
        _coordinate_value_ok,
        keep_group=1,
    ),
    Rule(
        'coordinates',
        'location',
        re.compile(rf'(?<![\w.:-]){_DEG}(?:\s{{0,3}}[,;]\s{{0,3}}|%2[Cc]|\s{{1,3}}){_DEG}(?!\.\d)'),
        _coordinate_pair_ok,
    ),
    Rule('dms_coordinates', 'location', re.compile(_DMS)),
    # The lookbehind makes a match start only at the beginning of a run of address characters: without it
    # 'a.a.a.a...' (no '@') was scanned to its end once per character, quadratic on a 50 kB bio.
    Rule('email', 'personal', re.compile(r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')),
    Rule('iban', 'personal', re.compile(r'\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b'), _iban_ok),
    Rule('payment_card', 'personal', re.compile(r'(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])'), _luhn_ok),
    Rule('codice_fiscale', 'personal', re.compile(r'\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b')),
    Rule(
        'btc_address',
        'crypto',
        # bech32 is case-insensitive (BIP-173: all-uppercase is the QR-code form); base58 is not.
        re.compile(rf'\b(?:(?i:bc1[ac-hj-np-z02-9]{{11,71}})|[13][{_B58_CLASS}]{{25,34}})\b'),
        lambda m: m[:3].lower() == 'bc1' or _base58check_ok(m),
    ),
    Rule('eth_address', 'crypto', re.compile(r'\b0x[a-fA-F0-9]{40}\b')),
    Rule(
        'tron_address', 'crypto', re.compile(rf'(?<![{_B58_CLASS}])T[{_B58_CLASS}]{{33}}(?![{_B58_CLASS}])'), _tron_ok
    ),
    Rule('ipv4', 'network', re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'), _ip_ok),
    Rule('ipv6', 'network', re.compile(r'(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])'), _ip_ok),
    # Phone via regex is approximate (use `phonenumbers` for precision). Category 'network': like an IP,
    # the number is a contact identifier, redacted by default and revealed with --keep-network.
    # International form: one digit per iteration with optional separators/parentheses, so a digit run
    # can be split in exactly one way (the old '\d{1,4}' groups backtracked over every split of the run).
    Rule(
        'phone',
        'network',
        re.compile(
            r'(?<![\w+])\+\d(?:[ .-]?\(?\d\)?){7,17}(?![\w-])'
            r'|(?<![\w.:/-])(?:\(?0\d{1,4}\)?|3\d{2})[ .-]\d{3,4}[ .-]?\d{3,4}(?![\w.-])'
        ),
        _phone_digits_ok,
    ),
)

# Structured keys whose (non-empty) value is a position: redacted whole, whatever the value looks like.
LOCATION_KEYS: FrozenSet[str] = frozenset(
    {
        'latitude',
        'longitude',
        'lat',
        'lon',
        'lng',
        'gps',
        'altitude',
        'altitudem',
        'mapsurl',
        'coordinates',
        'coords',
        'latlng',
        'latlon',
        'xmplocation',  # image_exif: XMP place names (IPTC/Photoshop) and drone altitude
    }
)
_KEY_NAMESPACE = re.compile(r'[\s:/.]+')

# Spellings of one parsed phone number (phone source, ``formats``). Some of them (bare digits, US/FR
# national layouts) cannot be matched by a regex without destroying timestamps and counts, so a dict
# that carries an 'e164' key is treated as a phone record: these keys are redacted whole ('network').
PHONE_FORMAT_KEYS: FrozenSet[str] = frozenset({'e164', 'international', 'national', 'rfc3966', 'digits'})


def is_location_key(key: Any) -> bool:
    """True for keys such as latitude, GPSLatitude, exif:GPSLongitude, 'GPS GPSAltitude', maps_url."""
    if not isinstance(key, str):
        return False
    norm = key.strip().lower()
    last = _KEY_NAMESPACE.split(norm)[-1]
    if last.startswith('gps'):
        return True
    return any(k.replace('_', '').replace('-', '') in LOCATION_KEYS for k in (norm, last))


# Photographer names: the image_exif 'authorship' record and the XMP Dublin Core creator/rights fields.
AUTHORSHIP_KEYS = frozenset({'artist', 'owner', 'copyright'})
XMP_AUTHOR_KEYS = frozenset({'dc:creator', 'dc:rights', 'xmprights:owner', 'photoshop:credit', 'photoshop:author'})


def is_author_key(key: Any, authorship_record: bool = False) -> bool:
    """True for keys that hold a photographer's or owner's name: personal data, redacted by default.

    Plain 'artist'/'owner'/'copyright' only inside an authorship record (a dict made of those keys), so
    unrelated data that happens to use the same words is left alone.
    """
    if not isinstance(key, str):
        return False
    name = key.lower()
    return name in XMP_AUTHOR_KEYS or (authorship_record and name in AUTHORSHIP_KEYS)


def is_device_serial_key(key: Any, device_record: bool = False) -> bool:
    """True for EXIF/XMP serial keys (BodySerialNumber, aux:SerialNumber, ...) and, inside a camera
    record (a dict with make/model), its plain 'serial' key. A device serial links photos across
    accounts ('device' category, shown with --keep-device); a DNS SOA 'serial' is not in a camera record."""
    if not isinstance(key, str):
        return False
    last = _KEY_NAMESPACE.split(key.strip().lower())[-1]
    return last.endswith('serialnumber') or (device_record and last == 'serial')


def _carries_no_position(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, (str, dict, list, tuple, set, frozenset)):
        return not value
    return False


class PrivacyGuard:
    """Redaction of secrets and personal data.

    `categories` chooses what to redact: 'secrets', 'personal', 'network', 'location', 'crypto', 'device'
    (all by default). Note: for domain recon the IPs are the result itself; drop 'network' to keep the
    report useful (--keep-network), likewise --keep-location, --keep-crypto and --keep-device.
    """

    def __init__(
        self,
        categories: Iterable[str] = CATEGORIES,
        placeholder: str = '[REDACTED]',
        label: bool = False,
        secrets: Optional[Iterable[str]] = None,
    ):
        """Initialize PrivacyGuard."""
        categories = set(categories)
        unknown = categories - CATEGORIES
        if unknown:
            raise ValueError(f'Unknown redaction categories: {sorted(unknown)}')
        self.categories: FrozenSet[str] = frozenset(categories)
        self.rules = tuple(r for r in RULES if r.category in categories)
        self.placeholder = placeholder
        self.label = label
        # Exact values of the configured API keys: the real protection, independent of the format.
        known = list(config.secret_values() if secrets is None else secrets)
        known = sorted({s for s in known if s}, key=len, reverse=True)
        self._secret_values = re.compile('|'.join(map(re.escape, known))) if known and 'secrets' in categories else None
        self._replacements = {rule.name: self._replacement(rule) for rule in self.rules}

    def _token(self, name: str) -> str:
        return f'[REDACTED:{name}]' if self.label else self.placeholder

    def _replacement(self, rule: Rule) -> Callable[['re.Match[str]'], str]:
        token = self._token(rule.name)

        def replace(m: 're.Match[str]') -> str:
            """Redact one regex match, honouring the rule's validator and kept prefix."""
            candidate = m.group(0)[len(m.group(rule.keep_group)) :] if rule.keep_group else m.group(0)
            if rule.validator and not rule.validator(candidate.strip()):
                return m.group(0)
            return (m.group(rule.keep_group) if rule.keep_group else '') + token

        return replace

    def redact(self, text: Any) -> Any:
        """Redact sensitive data in a string. Non-string values are returned unchanged."""
        if not isinstance(text, str):
            return text
        if self._secret_values is not None:
            # Before truncation: a configured key straddling the cut must not survive as a fragment.
            text = self._secret_values.sub(self._token('api_key'), text)
        if len(text) > MAX_FIELD_CHARS:
            text = _truncate(text)
        for rule in self.rules:
            text = rule.pattern.sub(self._replacements[rule.name], text)
        return text

    def redact_field(self, key: Any, value: Any) -> Any:
        """Redact the value stored under ``key``: a non-empty location key hides the whole value."""
        if 'location' in self.categories and is_location_key(key) and not _carries_no_position(value):
            return self._token('location')
        return self.redact_value(value)

    def redact_value(self, value: Any) -> Any:
        """Redact recursively through dicts (keys included), lists, tuples and sets."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, dict):
            phone_record = 'network' in self.categories and 'e164' in value
            device_record = 'make' in value or 'model' in value
            authorship_record = bool(value) and set(value) <= AUTHORSHIP_KEYS
            redact_personal = 'personal' in self.categories
            redact_device = 'device' in self.categories
            out = {}
            for k, v in value.items():
                if phone_record and k in PHONE_FORMAT_KEYS and isinstance(v, str) and v:
                    out[self.redact(k)] = self._token('phone')
                elif redact_device and isinstance(v, str) and v and is_device_serial_key(k, device_record):
                    out[self.redact(k)] = self._token('device_serial')
                elif redact_personal and v and is_author_key(k, authorship_record):
                    out[self.redact(k)] = self._token('author')
                else:
                    out[self.redact(k)] = self.redact_field(k, v)
            return out
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self.redact_value(v) for v in value]
        return value

    def redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Return a deep copy of ``data`` with strings (and keys) redacted."""
        if not isinstance(data, dict):
            return data
        return self.redact_value(data)

    def contains_secrets(self, text: str) -> bool:
        """Detect whether a string contains potential secrets (regardless of the active categories)."""
        if not isinstance(text, str):
            return False
        guard = PrivacyGuard(categories={'secrets'})
        return guard.redact(text) != text


def _truncate(text: str) -> str:
    """Cut ``text`` to MAX_FIELD_CHARS, preferring a whitespace boundary so no half token is left."""
    head = text[:MAX_FIELD_CHARS]
    boundary = max(head.rfind(' '), head.rfind('\n'), head.rfind('\t'))
    if boundary >= MAX_FIELD_CHARS - _TRUNCATE_WINDOW:
        head = head[:boundary]
    return f'{head} [TRUNCATED {len(text) - len(head)} chars]'


# --- Log-only redaction -------------------------------------------------------------------------------
#
# Logs are always fully redacted (every category, whatever --keep-* says) and get extra rules that would
# damage reports: URL paths/queries (a username in https://site/<user> has no recognisable shape), target
# subdomains, bare hashes, and the exact values the run is investigating.

MIN_SENSITIVE_LENGTH = 3
_sensitive_lock = threading.Lock()
_sensitive_values: set = set()
_sensitive_pattern: Optional[Pattern[str]] = None
_sensitive_version = 0

_URL = re.compile(r'(?i)\b((?:https?|wss?|ftps?)://)([^\s/?#"\'<>\\]*)([^\s"\'<>]*)')
_HEX_HASH = re.compile(r'(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])')
_SECOND_LEVEL = frozenset({'co', 'com', 'net', 'org', 'gov', 'ac', 'edu'})
_INFRA_LABELS = frozenset({'www', 'www2', 'api', 'm', 'mobile', 'cdn', 'static'})
_LANGUAGE_LABEL = re.compile(r'[a-z]{2}')
_LOG_TOKEN = '[REDACTED]'


def register_sensitive_values(values: Iterable[Optional[str]]) -> None:
    """Scrub these exact values (the run's targets) from every log line, case-insensitively.

    Values shorter than MIN_SENSITIVE_LENGTH are ignored: replacing them everywhere would shred ordinary
    words. URL-encoded forms are registered too, since targets travel in query strings.
    """
    global _sensitive_pattern, _sensitive_version
    with _sensitive_lock:
        for value in values:
            value = (value or '').strip()
            if len(value) < MIN_SENSITIVE_LENGTH:
                continue
            _sensitive_values.update({value, quote(value, safe=''), quote_plus(value)})
        ordered = sorted(_sensitive_values, key=len, reverse=True)
        _sensitive_pattern = re.compile('|'.join(map(re.escape, ordered)), re.IGNORECASE) if ordered else None
        _sensitive_version += 1


def clear_sensitive_values() -> None:
    """Forget every registered value (tests, or a GUI session ending)."""
    global _sensitive_pattern, _sensitive_version
    with _sensitive_lock:
        _sensitive_values.clear()
        _sensitive_pattern = None
        _sensitive_version += 1


def _mask_host(host: str) -> str:
    """Keep the registrable domain and infrastructure labels; hide other subdomains (user.tumblr.com)."""
    if host.startswith('[') or _ip_ok(host):
        return _LOG_TOKEN
    labels = host.split('.')
    keep = 3 if len(labels) >= 3 and labels[-2].lower() in _SECOND_LEVEL and len(labels[-1]) == 2 else 2
    if len(labels) <= keep:
        return host
    masked = [
        label if label.lower() in _INFRA_LABELS or _LANGUAGE_LABEL.fullmatch(label.lower()) else _LOG_TOKEN
        for label in labels[:-keep]
    ]
    return '.'.join(masked + labels[-keep:])


def _mask_url(m: 're.Match[str]') -> str:
    scheme, authority, rest = m.group(1), m.group(2), m.group(3)
    userinfo, _, hostport = authority.rpartition('@')
    if hostport.startswith('['):
        host, _, port = hostport[1:].partition(']')
        host, port = f'[{host}]', port
    else:
        host, sep, port = hostport.partition(':')
        port = sep + port
    out = scheme + (_LOG_TOKEN + '@' if userinfo else '') + _mask_host(host) + port
    if rest and rest != '/':
        out += '/' + _LOG_TOKEN
    return out + ('/' if rest == '/' else '')


def log_only_patterns() -> List[Tuple[Pattern[str], Union[str, Callable[['re.Match[str]'], str]]]]:
    """Patterns applied to log lines only, in order: URLs, registered run targets, bare hashes."""
    patterns: List[Tuple[Pattern[str], Union[str, Callable[['re.Match[str]'], str]]]] = [(_URL, _mask_url)]
    if _sensitive_pattern is not None:
        patterns.append((_sensitive_pattern, _LOG_TOKEN))
    patterns.append((_HEX_HASH, _LOG_TOKEN))
    return patterns


class _LogGuard(PrivacyGuard):
    """Every category plus the log-only rules. Never used for reports."""

    def __init__(self, secrets: Iterable[str]):
        super().__init__(categories=CATEGORIES, secrets=secrets)
        self._log_patterns = log_only_patterns()

    def redact(self, text: Any) -> Any:
        """Redact a log string: secrets, log-only rules, then every PrivacyGuard category."""
        if not isinstance(text, str):
            return text
        if self._secret_values is not None:
            text = self._secret_values.sub(self.placeholder, text)
        for pattern, replacement in self._log_patterns:
            text = pattern.sub(replacement, text)
        return super().redact(text)


_log_guard_lock = threading.Lock()
_log_guard_cache: Optional[Tuple[Tuple[Tuple[str, ...], int], _LogGuard]] = None


def log_guard() -> PrivacyGuard:
    """The guard applied to every log record: all categories, current secrets, registered targets."""
    global _log_guard_cache
    key = (tuple(config.secret_values()), _sensitive_version)
    with _log_guard_lock:
        if _log_guard_cache is None or _log_guard_cache[0] != key:
            _log_guard_cache = (key, _LogGuard(secrets=key[0]))
        return _log_guard_cache[1]
