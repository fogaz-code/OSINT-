"""Investigation timeline built ONLY from dates the workflow steps already collected (C9).

Zero new requests: every event comes from a field a source returned (account creation dates on
public profiles, RDAP registration events, the earliest crt.sh certificate when present, EXIF
timestamps of a local image, first/last on-chain activity of a wallet). Each event carries the
step and field it came from, so a reader can check it against the raw results.

Honesty of the model: the timeline is only as complete as what the sources exposed. Most
platforms do not publish a creation date, so ``timeline_coverage`` states how many of the
platforms where the username was found gave one, and the Markdown section says plainly that
this is not a complete history. Dates that cannot be parsed unambiguously are dropped, never
guessed: a date-only value stays date-only, and a local time without a zone stays naive.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from secure_osint.utils.markdown import md_text

_ISO = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})'
    r'(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?\s*(Z|[+-]\d{2}:?\d{2})?)?$',
    re.IGNORECASE,
)
_EXIF = re.compile(r'^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?$')
_OFFSET = re.compile(r'^([+-])(\d{2}):?(\d{2})$')
# English month names as Dev.to prints them ("Mar 3, 2020"). Parsed by hand: strptime's %b depends
# on the process locale.
_MONTHS = {
    name: index
    for index, names in enumerate(
        (
            ('jan', 'january'),
            ('feb', 'february'),
            ('mar', 'march'),
            ('apr', 'april'),
            ('may',),
            ('jun', 'june'),
            ('jul', 'july'),
            ('aug', 'august'),
            ('sep', 'sept', 'september'),
            ('oct', 'october'),
            ('nov', 'november'),
            ('dec', 'december'),
        ),
        start=1,
    )
    for name in names
}
_TEXT_DATE = re.compile(r'^([A-Za-z]{3,9})\.? (\d{1,2}),? (\d{4})$')

_MIN_YEAR, _MAX_YEAR = 1900, 2100
# Unix timestamps below this (1973-03-03) are far more likely counters or garbage than a real date.
_MIN_UNIX, _MAX_UNIX = 100_000_000, 4_102_444_800

# Profile fields of the username source that carry an account creation date.
_PROFILE_DATE = 'created_at'

# RDAP eventAction -> (domain wording, IP network wording). Registry housekeeping such as
# 'last update of RDAP database' describes the registry, not the target: it is skipped.
_RDAP_EVENTS = {
    'registration': ('Domain registered', 'IP network registered'),
    'reregistration': ('Domain re-registered', 'IP network re-registered'),
    'transfer': ('Domain transferred', 'IP network transferred'),
    'last changed': ('Domain registration record last changed', 'IP network record last changed'),
    'expiration': ('Domain registration expires', 'IP network registration expires'),
}

_EXIF_EVENTS = (
    ('original', 'Photo taken (EXIF DateTimeOriginal)'),
    ('digitized', 'Image digitized (EXIF)'),
    ('modified', 'Image file modified (EXIF DateTime)'),
)
_CHAINS = {'btc': 'BTC', 'eth': 'ETH', 'tron': 'TRON'}


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _offset(text: Any) -> Optional[timezone]:
    """A fixed UTC offset from '+02:00' / '-0530' / 'Z', or None."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if text.upper() == 'Z':
        return timezone.utc
    match = _OFFSET.match(text)
    if not match:
        return None
    sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
    if hours > 14 or minutes > 59:
        return None
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(-delta if sign == '-' else delta)


def _build(parts: Tuple[str, ...], tz: Optional[timezone]) -> Optional[str]:
    try:
        y, mo, d, h, mi, sec = ([int(p) for p in parts] + [0, 0, 0])[:6]
        moment = datetime(y, mo, d, h, mi, sec)
    except ValueError:  # month 0, day 31 in February, zeroed EXIF fields...
        return None
    if not _MIN_YEAR <= moment.year <= _MAX_YEAR:
        return None
    if tz is not None:
        return _utc(moment.replace(tzinfo=tz))
    return moment.strftime('%Y-%m-%dT%H:%M:%S')


def normalize_date(value: Any) -> Optional[str]:
    """ISO 8601 text for a date a source returned, or None when it is not unambiguous.

    * Unix seconds and zoned timestamps become UTC (``YYYY-MM-DDTHH:MM:SSZ``).
    * A timestamp without a zone stays naive (``YYYY-MM-DDTHH:MM:SS``): no zone is invented.
    * A date without a time stays a date (``YYYY-MM-DD``): no time of day is invented.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not _MIN_UNIX <= value <= _MAX_UNIX:
            return None
        return _utc(datetime.fromtimestamp(value, tz=timezone.utc))
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = _ISO.match(text)
    if match:
        date_parts = match.group(1, 2, 3)
        if match.group(4) is None:
            built = _build(date_parts, None)
            return built[:10] if built else None
        time_parts = (match.group(4), match.group(5), match.group(6) or '0')
        zone = match.group(7)
        tz = _offset(zone) if zone else None
        if zone and tz is None:
            return None
        return _build(date_parts + time_parts, tz)
    match = _TEXT_DATE.match(text)
    if match:
        month = _MONTHS.get(match.group(1).lower())
        if month is None:
            return None
        built = _build((match.group(3), str(month), match.group(2)), None)
        return built[:10] if built else None
    return None


def _exif_date(value: Any, offset: Optional[timezone]) -> Optional[str]:
    """EXIF 'YYYY:MM:DD HH:MM:SS' (or ISO) local time, made UTC only when the offset is known."""
    if not isinstance(value, str):
        return None
    match = _EXIF.match(value.strip())
    if match:
        return _build(match.groups(), offset)
    normalized = normalize_date(value)
    if normalized and offset is not None and len(normalized) == 19:  # naive ISO: apply the EXIF offset
        return _utc(datetime.fromisoformat(normalized).replace(tzinfo=offset))
    return normalized


def _step_items(results: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for step_id, step in results.items():
        data = step.get('data') if isinstance(step, dict) else None
        if isinstance(data, dict):
            yield str(step_id), data


def _event(date: str, platform: str, event: str, source: str) -> Dict[str, str]:
    return {'date': date, 'platform': platform, 'event': event, 'source': source}


def _account_events(step_id: str, data: Dict[str, Any], found: List[str]) -> List[Dict[str, str]]:
    platforms = data.get('platforms')
    events: List[Dict[str, str]] = []
    if not isinstance(platforms, dict):
        return events
    for name, info in platforms.items():
        if not isinstance(info, dict) or info.get('exists') is not True:
            continue
        found.append(f'{step_id}:{name}')
        raw_profile = info.get('profile')
        profile: Dict[str, Any] = raw_profile if isinstance(raw_profile, dict) else {}
        date = normalize_date(profile.get(_PROFILE_DATE))
        if date:
            label = str(info.get('label') or name)
            events.append(
                _event(date, label, 'Account created', f'{step_id}: platforms.{name}.profile.{_PROFILE_DATE}')
            )
    return events


def _rdap_events(step_id: str, data: Dict[str, Any]) -> List[Dict[str, str]]:
    events = data.get('events')
    if not isinstance(events, dict):
        return []
    is_ip = 'startAddress' in data or 'endAddress' in data
    out = []
    for action, raw in events.items():
        wording = _RDAP_EVENTS.get(str(action).strip().lower())
        date = normalize_date(raw)
        if wording and date:
            out.append(_event(date, 'RDAP', wording[1 if is_ip else 0], f'{step_id}: events.{action}'))
    return out


def _crt_events(step_id: str, data: Dict[str, Any]) -> List[Dict[str, str]]:
    earliest = data.get('earliest_certificate')
    raw = earliest.get('not_before') if isinstance(earliest, dict) else earliest
    date = normalize_date(raw)
    if not date:
        return []
    return [_event(date, 'crt.sh', 'Earliest certificate logged (not before)', f'{step_id}: earliest_certificate')]


def _exif_events(step_id: str, data: Dict[str, Any]) -> List[Dict[str, str]]:
    stamps = data.get('timestamps')
    if not isinstance(stamps, dict) or not isinstance(data.get('file'), dict):
        return []
    offset = _offset(stamps.get('offset'))
    out = []
    for key, wording in _EXIF_EVENTS:
        date = _exif_date(stamps.get(key), offset)
        if date:
            out.append(_event(date, 'Image EXIF', wording, f'{step_id}: timestamps.{key}'))
    gps = data.get('gps')
    if isinstance(gps, dict):
        # The GPS time stamp is UTC by definition (EXIF GPSTimeStamp/GPSDateStamp).
        date = _exif_date(gps.get('timestamp'), timezone.utc)
        if date:
            out.append(_event(date, 'Image EXIF', 'GPS fix recorded (UTC)', f'{step_id}: gps.timestamp'))
    return out


def _chain_events(step_id: str, data: Dict[str, Any]) -> List[Dict[str, str]]:
    chain = _CHAINS.get(str(data.get('chain', '')).lower())
    if chain is None or not isinstance(data.get('address'), str):
        return []
    explorer = data.get('explorer')
    platform = f'{chain} ({explorer})' if isinstance(explorer, str) and explorer.strip() else chain
    out = []
    for key, wording in (
        ('first_seen', 'First on-chain transaction'),
        ('last_seen', 'Most recent on-chain transaction'),
    ):
        date = normalize_date(data.get(key))
        if date:
            out.append(_event(date, platform, wording, f'{step_id}: {key}'))
    return out


def build_timeline(results: Dict[str, Any]) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Ascending events ``[{date, platform, event, source}]`` and the username date coverage.

    Args:
        results: Mapping step_id -> plain result dict (status/data/error), raw.

    Returns:
        ``(timeline, {'platforms_with_dates': n, 'platforms_found': m})``.
    """
    events: List[Dict[str, str]] = []
    found: List[str] = []
    for step_id, data in _step_items(results):
        account_events = _account_events(step_id, data, found)
        events.extend(account_events)
        events.extend(_rdap_events(step_id, data))
        events.extend(_crt_events(step_id, data))
        events.extend(_exif_events(step_id, data))
        events.extend(_chain_events(step_id, data))
    unique: List[Dict[str, str]] = []
    for item in events:
        if item not in unique:
            unique.append(item)
    unique.sort(key=lambda e: (e['date'], e['platform'].lower(), e['event']))
    with_dates = {e['source'] for e in unique if e['event'] == 'Account created'}
    return unique, {'platforms_with_dates': len(with_dates), 'platforms_found': len(found)}


def _cell(value: Any) -> str:
    return md_text(' '.join(str(value).split()))  # platform/event text can be remote: never live Markdown


def format_timeline_lines(correlations: Dict[str, Any]) -> List[str]:
    """Markdown 'Timeline' section from (redacted) correlations, with an explicit coverage caveat."""
    timeline = correlations.get('timeline') or []
    coverage = correlations.get('timeline_coverage') or {}
    found = coverage.get('platforms_found') or 0
    caveat = '_Built only from dates the sources exposed; this is not a complete history. A missing event '
    caveat += 'means it was not observed, not that it did not happen.'
    if found:
        caveat += (
            f' {coverage.get("platforms_with_dates", 0)} of {found} platforms where the username was found '
            'exposed a date.'
        )
    lines = ['## Timeline', '', caveat + '_', '']
    if not timeline:
        lines.append('_No dated events in the collected data._')
        return lines
    lines.extend(['| Date | Platform | Event | Source |', '| --- | --- | --- | --- |'])
    for event in timeline:
        cells = (event.get('date', ''), event.get('platform', ''), event.get('event', ''), event.get('source', ''))
        lines.append('| ' + ' | '.join(_cell(c) for c in cells) + ' |')
    return lines
