"""Entity correlation: sintetizza le entità osservate nei dati GIÀ raccolti dagli step.

Nessuna chiamata di rete e nessuna nuova fonte: puro parsing locale dei risultati. L'obiettivo è
dare al report la stessa chiarezza "chi è collegato a cosa" delle piattaforme enterprise, restando
100% locale e privacy-first.

Onestà del modello: queste sono entità *osservate per co-occorrenza* nei dati raccolti, non un
collegamento di identità verificato. Il report lo dichiara esplicitamente per non promettere una
"entity resolution" che non stiamo facendo.

Le entità vengono estratte dai dati grezzi (prima della redaction) e poi il reporter le fa passare
per lo stesso PrivacyGuard del resto del report: email/IP finiscono `[REDACTED]` di default e sono
svelati solo con `--keep-network` (per gli IP), esattamente come nel corpo del report.
"""

import ipaddress
import math
import re
from typing import Any, Dict, List, Optional

from secure_osint.core.timeline import build_timeline, format_timeline_lines
from secure_osint.core.validator import detect_input_type
from secure_osint.utils.markdown import md_text

__all__ = [
    'ACCOUNT_STATUSES',
    'CONFIDENCE_ORDER',
    'DEVICE_SERIAL_RE',
    'ENTITY_BUCKETS',
    'build_correlations',
    'collection_summary',
    'format_collection_lines',
    'format_pivot_lines',
    'format_summary_lines',
    'format_timeline_lines',
]

# Email: stesso pattern della redaction, così ciò che qui è un'email è anche ciò che lì viene redatto.
_EMAIL_RE = re.compile(r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
# Dominio registrabile plausibile: etichette punto-separate + TLD alfabetico. Esclude percorsi e IP.
_DOMAIN_RE = re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$')
# Local part of an emitted mailbox: the SAME character set the redaction rule matches, with no
# leading/trailing/double dot. A wider set would let the redaction match only a suffix of the
# address and leak the rest (e.g. 'a!b@x.org' -> 'a![REDACTED]').
_LOCAL_PART_RE = re.compile(r'^[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*$')
_SAFE_URL = re.compile(r'^https://[^\s"\'<>]+$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')

# Chiavi note (case-insensitive) da cui estrarre in modo mirato, evitando il rumore: NON raccogliamo
# domini dagli URL dei 23 profili username, ma solo dai campi che rappresentano davvero un'entità.
_USERNAME_KEYS = frozenset({'username', 'user', 'login', 'handle', 'screen_name'})
_DOMAIN_KEYS = frozenset({'domain', 'email_domain', 'fqdn'})
_IP_KEYS = frozenset({'a', 'aaaa', 'ip', 'ips', 'address', 'addresses'})
# 'mx': plain host list of the email source (C5); DNS MX records are dicts with 'exchange'.
_HOST_KEYS = frozenset({'ns', 'cname', 'exchange', 'mname', 'hostname', 'host', 'target', 'mx'})

_BUCKETS = ('usernames', 'emails', 'domains', 'infrastructure', 'phones', 'locations', 'devices', 'wallets')
ENTITY_BUCKETS = _BUCKETS

# Phone formats worth showing (and searching for): the others are re-spellings of the same number.
_PHONE_FORMATS = ('e164', 'international', 'national')
_CHAINS = {'btc': 'BTC', 'eth': 'ETH', 'tron': 'TRON'}
# Device entity: '<make> <model>' plus ' (serial <s>)' when EXIF carries a body serial number. The
# reporter redacts the serial (a unique identifier) through this pattern.
DEVICE_SERIAL_RE = re.compile(r' \(serial (.+)\)$')


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _classify(key: str, value: str, acc: Dict[str, set]) -> None:
    value = value.strip()
    if not value:
        return

    # Email ovunque compaiano (il valore verrà comunque redatto dal reporter: qui serve a segnalarne
    # la presenza). Non deriviamo il dominio da email sparse nel testo, per non svelare domini che il
    # report altrimenti non mostrerebbe.
    for match in _EMAIL_RE.findall(value):
        acc['emails'].add(match.lower())

    # IP: dai campi A/AAAA/address o da un valore che è un IP valido di per sé.
    if _is_ip(value):
        acc['infrastructure'].add(value)
        return

    if key in _USERNAME_KEYS and '@' not in value and not _DOMAIN_RE.match(value):
        acc['usernames'].add(value)
    if key in _DOMAIN_KEYS and _DOMAIN_RE.match(value.rstrip('.')):
        acc['domains'].add(value.rstrip('.').lower())
    if key in _HOST_KEYS and _DOMAIN_RE.match(value.rstrip('.')):
        acc['infrastructure'].add(value.rstrip('.').lower())


def _walk(node: Any, key: str, acc: Dict[str, set]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, str(k).lower(), acc)
    elif isinstance(node, (list, tuple, set, frozenset)):
        for item in node:
            _walk(item, key, acc)  # gli elementi di lista ereditano la chiave del genitore (es. A: [...])
    elif isinstance(node, str):
        _classify(key, node, acc)
    # numeri, bool e None non contengono entità: ignorati.


def _seed_from_input(input_data: str, acc: Dict[str, set]) -> None:
    """Semina il bucket giusto dal target primario, in base al tipo rilevato."""
    value = input_data.strip()
    if not value:
        return
    kind = detect_input_type(value, allow_files=False)
    if kind == 'email':
        acc['emails'].add(value.lower())
        acc['domains'].add(value.split('@', 1)[1].lower())
    elif kind == 'domain':
        acc['domains'].add(value.lower())
    elif kind in ('ipv4', 'ipv6'):
        acc['infrastructure'].add(value)
    elif kind == 'username':
        acc['usernames'].add(value)
    elif kind == 'github_repo':
        acc['usernames'].add(value.split('/', 1)[0])
    elif kind == 'phone':
        acc['phones'].add(value)


def _clean_text(value: Any, limit: int = 80) -> str:
    """A short single-line string from untrusted metadata (EXIF, API payloads), or ''."""
    if not isinstance(value, str):
        return ''
    return ' '.join(_CONTROL.sub(' ', value).split())[:limit]


def _coordinate(value: Any, limit: float) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and abs(number) <= limit else None


def _location(gps: Any) -> Optional[str]:
    """'lat, lon' (6 decimals, ~0.1 m) from an EXIF ``gps`` dict; None if absent or implausible."""
    if not isinstance(gps, dict):
        return None
    lat, lon = _coordinate(gps.get('latitude'), 90), _coordinate(gps.get('longitude'), 180)
    if lat is None or lon is None or (lat == 0 and lon == 0):  # 0,0 is a placeholder, not a fix
        return None
    return f'{lat:.6f}, {lon:.6f}'


def _device(camera: Any) -> Optional[str]:
    """'<make> <model> (serial <s>)' from an EXIF ``camera`` dict, without repeating the make."""
    if not isinstance(camera, dict):
        return None
    make, model, serial = (_clean_text(camera.get(key)) for key in ('make', 'model', 'serial'))
    if model and make and model.lower().startswith(make.lower()):
        name = model
    else:
        name = ' '.join(part for part in (make, model) if part)
    if not name:
        return None
    return f'{name} (serial {serial})' if serial else name


def _is_exif(data: Dict[str, Any]) -> bool:
    return isinstance(data.get('file'), dict) and isinstance(data.get('timestamps'), dict)


def _wallet(data: Dict[str, Any]) -> Optional[str]:
    chain = _CHAINS.get(str(data.get('chain', '')).lower())
    address = _clean_text(data.get('address'), 120)
    return f'{chain} {address}' if chain and address and ' ' not in address else None


def _evidence(data: Dict[str, Any], acc: Dict[str, set]) -> None:
    """C5 keys the generic walk cannot classify: GPS, camera, wallet, phone formats."""
    if _is_exif(data):
        location, device = _location(data.get('gps')), _device(data.get('camera'))
        if location:
            acc['locations'].add(location)
        if device:
            acc['devices'].add(device)
    wallet = _wallet(data)
    if wallet:
        acc['wallets'].add(wallet)
    formats = data.get('formats')
    if isinstance(formats, dict):
        for key in _PHONE_FORMATS:
            value = _clean_text(formats.get(key), 40)
            if value:
                acc['phones'].add(value)


def _soa_mailbox(rname: Any) -> Optional[str]:
    """The email address encoded in a DNS SOA RNAME (RFC 1035 section 8), or None.

    The first UNESCAPED dot separates the local part from the domain; ``\\.`` is a literal dot and
    ``\\DDD`` a decimal-coded character. The result is only returned if it is a syntactically valid
    address that the redaction rule matches as a whole.
    """
    if not isinstance(rname, str):
        return None
    text = rname.strip()
    labels: List[str] = []
    current: List[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == '\\':
            digits = text[i + 1 : i + 4]
            if len(digits) == 3 and digits.isdigit():
                if int(digits) > 255:
                    return None
                current.append(chr(int(digits)))
                i += 4
            elif i + 1 < len(text):
                current.append(text[i + 1])
                i += 2
            else:
                return None  # dangling escape
            continue
        if char == '.':
            labels.append(''.join(current))
            current = []
        else:
            current.append(char)
        i += 1
    labels.append(''.join(current))
    if labels[-1] == '':
        labels.pop()  # trailing root dot
    if len(labels) < 3 or any(not label for label in labels):
        return None
    local, domain = labels[0], '.'.join(labels[1:]).lower()
    if not _LOCAL_PART_RE.match(local) or not _DOMAIN_RE.match(domain):
        return None
    address = f'{local}@{domain}'
    return address if _EMAIL_RE.fullmatch(address) else None


# Esito per piattaforma: found = username esistente; manual = non determinabile automaticamente (login
# richiesto, bloccato, anti-bot, soft 404); not_found = verificato come assente. La certezza di un
# "found" sta in `confidence`: HIGH (API), MEDIUM (pagina web calibrata), LOW (match ambiguo).
ACCOUNT_STATUSES = ('found', 'manual', 'not_found')
CONFIDENCE_ORDER = ('HIGH', 'MEDIUM', 'LOW', 'MANUAL')

# Relazioni che i dati DNS dimostrano davvero (record del dominio target): niente relazioni inventate.
_DNS_RELATIONS = (('A', 'resolves to'), ('AAAA', 'resolves to'), ('CNAME', 'alias of'), ('NS', 'nameserver'))

_PROFILE_FIELDS = ('display_name', 'bio', 'created_at', 'avatar_url', 'packages')


def _step_data(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for step in results.values():
        data = step.get('data') if isinstance(step, dict) else None
        if isinstance(data, dict):
            out.append(data)
    return out


def _confidence(info: Dict[str, Any], exists: Any) -> str:
    """Confidence reported by the source; derived for results that predate the field (e.g. cache)."""
    value = info.get('confidence')
    if value in CONFIDENCE_ORDER:
        return str(value)
    if exists is None:
        return 'MANUAL'
    return 'LOW' if info.get('exact') is False else 'MEDIUM'


def _accounts(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Esito per piattaforma dai dati di presenza username (chiave ``platforms``)."""
    accounts = []
    for data in _step_data(results):
        platforms = data.get('platforms')
        if not isinstance(platforms, dict):
            continue
        username = data.get('username') if isinstance(data.get('username'), str) else ''
        for name, info in platforms.items():
            if not isinstance(info, dict) or 'exists' not in info:
                continue
            exists = info.get('exists')
            status = 'found' if exists is True else 'not_found' if exists is False else 'manual'
            raw_profile = info['profile'] if isinstance(info.get('profile'), dict) else {}
            profile = {k: raw_profile[k] for k in _PROFILE_FIELDS if raw_profile.get(k) not in (None, '')}
            account: Dict[str, Any] = {
                'platform': str(name),
                'label': str(info.get('label') or name),
                'username': username,
                'status': status,
                'confidence': _confidence(info, exists),
                'url': info.get('url') if isinstance(info.get('url'), str) else '',
                'note': str(info.get('error') or ''),
            }
            if profile:
                account['profile'] = profile
            accounts.append(account)
    status_order = {status: i for i, status in enumerate(ACCOUNT_STATUSES)}
    confidence_order = {level: i for i, level in enumerate(CONFIDENCE_ORDER)}
    return sorted(
        accounts,
        key=lambda a: (status_order[a['status']], confidence_order.get(a['confidence'], 9), a['label'].lower()),
    )


def _pivots(input_data: str, acc: Dict[str, set], accounts: List[Dict[str, Any]], results: Dict[str, Any]) -> List[str]:
    """Selettori da indagare SEPARATAMENTE, a discrezione dell'investigatore. Mai eseguiti in automatico.

    Nomi pubblici dai profili trovati, altri username, email osservate (anche il contatto del record
    SOA di un dominio). Le email restano redatte nel report come ovunque.
    """
    target = input_data.strip().lower() if isinstance(input_data, str) else ''
    pivots: List[str] = []

    def add(kind: str, value: str, source: str = '') -> None:
        value = value.strip()
        if not value or value.lower() == target:
            return
        item = f'{kind}: {value}' + (f' ({source})' if source else '')
        if item not in pivots:
            pivots.append(item)

    names: Dict[str, List[str]] = {}
    for account in accounts:
        name = (account.get('profile') or {}).get('display_name')
        if account['status'] == 'found' and isinstance(name, str) and name.strip():
            names.setdefault(name.strip(), []).append(account['label'])
    linked: List[str] = []
    for data in _step_data(results):
        gravatar = data.get('gravatar')
        if not isinstance(gravatar, dict):
            continue
        name = _clean_text(gravatar.get('display_name'))
        if name:
            names.setdefault(name, []).append('Gravatar')
        verified = gravatar.get('verified_accounts')
        for item in verified if isinstance(verified, list) else []:
            service = _clean_text(item.get('service'), 40) if isinstance(item, dict) else ''
            url = item.get('url') if isinstance(item, dict) else None
            if service and isinstance(url, str) and _SAFE_URL.match(url) and len(url) <= 300:
                linked.append(f'{service} {url}')
    for name, sources in names.items():
        add('Name', name, 'from ' + ', '.join(sources))
    for username in sorted(acc['usernames']):
        add('Username', username)
    for email in sorted(acc['emails']):
        add('Email', email)
    for item in linked:
        add('Linked account', item, 'from Gravatar')
    for data in _step_data(results):
        soa = data.get('SOA')
        mailbox = _soa_mailbox(soa.get('rname') if isinstance(soa, dict) else None)
        if mailbox:
            add('Email', mailbox, 'DNS SOA contact')
    return pivots


def _normalize_host(value: str) -> str:
    value = value.strip()
    return value if _is_ip(value) else value.rstrip('.').lower()


def _relations(input_data: str, results: Dict[str, Any]) -> List[Dict[str, str]]:
    """Relazioni dimostrate dai dati: record DNS del dominio target, dominio di un'email target."""
    target = input_data.strip() if isinstance(input_data, str) else ''
    if not target:
        return []
    kind = detect_input_type(target, allow_files=False)
    relations: List[Dict[str, str]] = []
    source = target.lower()
    for data in _step_data(results):
        if kind == 'domain':
            # Record DNS (sorgente dns): appartengono al dominio target, che è l'input del workflow.
            for key, relation in _DNS_RELATIONS:
                values = data.get(key)
                for value in [values] if isinstance(values, str) else values if isinstance(values, list) else []:
                    if isinstance(value, str) and value.strip():
                        relations.append({'from': source, 'to': _normalize_host(value), 'type': relation})
            mx_records = data.get('MX')
            for mx in mx_records if isinstance(mx_records, list) else []:
                host = mx.get('exchange') if isinstance(mx, dict) else None
                if isinstance(host, str) and host.strip():
                    relations.append({'from': source, 'to': _normalize_host(host), 'type': 'mail server'})
        elif kind == 'email' and isinstance(data.get('email_domain'), str):
            relations.append({'from': source, 'to': data['email_domain'].lower(), 'type': 'uses domain'})
            mx_hosts = data.get('mx')
            for host in mx_hosts if isinstance(mx_hosts, list) else []:
                if isinstance(host, str) and _DOMAIN_RE.match(host.strip().rstrip('.')):
                    relations.append({'from': source, 'to': _normalize_host(host), 'type': 'mail server'})
        if _is_exif(data):
            # The EXIF data describes the image the workflow was run on (C5 image_exif source).
            location, device = _location(data.get('gps')), _device(data.get('camera'))
            if location:
                relations.append({'from': source, 'to': location, 'type': 'photo taken at'})
            if device:
                relations.append({'from': source, 'to': device, 'type': 'taken with'})
    unique: List[Dict[str, str]] = []
    for item in relations:
        if item not in unique:
            unique.append(item)
    return unique


def build_correlations(input_data: str, results: Dict[str, Any]) -> Dict[str, Any]:
    """Sintetizza le entità uniche osservate nell'input e nei dati grezzi degli step.

    Args:
        input_data: Il target primario dell'indagine (non ancora redatto).
        results: Mapping step_id -> risultato in forma di dict semplice (status/data/error), grezzo.

    Returns:
        A dict with ``primary_target``; the sorted entity lists ``usernames``, ``emails``,
        ``domains``, ``infrastructure``, ``phones``, ``locations`` (EXIF GPS), ``devices`` (EXIF
        camera) and ``wallets``; the per-platform outcomes ``accounts`` (with ``confidence`` and
        ``profile``); the relations the data demonstrates ``relations``; the ``suggested_pivots``
        (suggestions only, never run); and the dated ``timeline`` with its ``timeline_coverage``.
        Values are NOT redacted yet: the reporter applies the PrivacyGuard.
    """
    acc: Dict[str, set] = {bucket: set() for bucket in _BUCKETS}
    if isinstance(input_data, str):
        _seed_from_input(input_data, acc)
    for data in _step_data(results):
        _walk(data, '', acc)
        _evidence(data, acc)
    out: Dict[str, Any] = {'primary_target': input_data}
    for bucket in _BUCKETS:
        out[bucket] = sorted(acc[bucket])
    out['accounts'] = _accounts(results)
    out['relations'] = _relations(input_data, results)
    out['suggested_pivots'] = _pivots(input_data, acc, out['accounts'], results)
    out['timeline'], out['timeline_coverage'] = build_timeline(results)
    return out


# Values of the C4 contract: anything else is ignored rather than counted under a made-up key.
_CALIBRATIONS = ('passed', 'soft404', 'control_error', 'not_applicable')
_ERROR_KINDS = ('timeout', 'rate_limited', 'blocked', 'connection', 'http_status', 'auth_wall', 'deadline', 'other')
_STATS = ('automated', 'checked', 'found', 'failed')


def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _username_summary(data: Dict[str, Any]) -> Dict[str, Any]:
    platforms = {k: v for k, v in data['platforms'].items() if isinstance(v, dict)}
    raw_stats = data.get('stats') if isinstance(data.get('stats'), dict) else None
    if raw_stats is not None:
        stats = {key: _count(raw_stats.get(key)) for key in _STATS}
    else:  # results that predate C4 (e.g. from the cache): derive what can be derived, nothing else
        stats = {
            'automated': None,
            'checked': sum(1 for p in platforms.values() if p.get('exists') is not None),
            'found': sum(1 for p in platforms.values() if p.get('exists') is True),
            'failed': None,
        }
    calibration = {key: 0 for key in _CALIBRATIONS}
    error_kinds: Dict[str, int] = {}
    for info in platforms.values():
        if info.get('calibration') in calibration:
            calibration[info['calibration']] += 1
        kind = info.get('error_kind')
        if kind in _ERROR_KINDS:
            error_kinds[kind] = error_kinds.get(kind, 0) + 1
    return {'stats': stats, 'calibration': calibration, 'error_kinds': dict(sorted(error_kinds.items()))}


def collection_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """How complete the collection was: username stats/calibration (C4) and partial steps (C2).

    Args:
        results: Mapping step_id -> plain result dict (status/data/error), raw.

    Returns:
        ``{'username': {'stats', 'calibration', 'error_kinds'} or None, 'partial_steps': [...]}``
        where each partial step is ``{'step', 'status', 'errors'}``. Values are not redacted yet.
    """
    username: Optional[Dict[str, Any]] = None
    partial: List[Dict[str, Any]] = []
    for step_id, step in results.items():
        if not isinstance(step, dict):
            continue
        raw_data = step.get('data')
        data: Dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
        status = str(step.get('status') or '').upper()
        if username is None and isinstance(data.get('platforms'), dict):
            username = _username_summary(data)
        if data.get('partial') is True or status == 'DEGRADED':
            raw_errors = data.get('errors')
            errors = [str(e) for e in raw_errors if isinstance(e, str)] if isinstance(raw_errors, list) else []
            partial.append({'step': str(step_id), 'status': status or 'UNKNOWN', 'errors': errors[:20]})
    return {'username': username, 'partial_steps': partial}


def format_collection_lines(summary: Dict[str, Any]) -> List[str]:
    """Markdown 'Collection Coverage' section, or [] when there is nothing to report."""
    username = summary.get('username')
    partial = summary.get('partial_steps') or []
    if not username and not partial:
        return []
    lines = ['## Collection Coverage', '']
    if username:
        stats = username.get('stats') or {}
        shown = ', '.join(f'{stats[key]} {key}' for key in _STATS if stats.get(key) is not None)
        lines.append(f'- **Username platforms:** {shown or "_no statistics_"}')
        calibration = username.get('calibration') or {}
        if any(calibration.get(key) for key in ('passed', 'soft404', 'control_error')):
            lines.append(
                f'- **Soft-404 calibration** (control check with a random non-existent username): '
                f'{calibration.get("passed", 0)} passed, {calibration.get("soft404", 0)} soft 404 '
                f'(reported as manual check), {calibration.get("control_error", 0)} control check failed'
            )
        kinds = username.get('error_kinds') or {}
        if kinds:
            lines.append('- **Checks that failed, by cause:** ' + ', '.join(f'{v} {k}' for k, v in kinds.items()))
    for step in partial:
        errors = '; '.join(step.get('errors') or []) or 'no detail given'
        lines.append(f'- **Partial result:** step `{step.get("step")}` ({step.get("status")}): {errors}')
    if partial:
        lines.append('- _A partial step is incomplete: missing data there is not evidence of absence._')
    return lines


def format_summary_lines(correlations: Dict[str, Any]) -> List[str]:
    """Rende la sezione Markdown 'Entity Correlation Summary' a partire dalle correlazioni redatte."""

    def fmt(items: List[str]) -> str:
        return ', '.join(f'`{item}`' for item in items) if items else '_none identified_'

    domains_emails = list(correlations.get('domains', []))
    for email in correlations.get('emails', []):
        if email not in domains_emails:
            domains_emails.append(email)

    lines = [
        '## Entity Correlation Summary',
        '',
        '_Entities observed across the collected data (co-occurrence, not verified identity links)._',
        '',
        f'- **Primary Target:** {correlations.get("primary_target", "")}',
        f'- **Associated Usernames:** {fmt(correlations.get("usernames", []))}',
        f'- **Associated Domains/Emails:** {fmt(domains_emails)}',
        f'- **Associated Infrastructure:** {fmt(correlations.get("infrastructure", []))}',
    ]
    # C5 entities: shown only when present, so reports of other workflows are unchanged.
    for bucket, caption in (
        ('phones', 'Phone Numbers'),
        ('locations', 'Locations (image GPS)'),
        ('devices', 'Devices (image camera)'),
        ('wallets', 'Crypto Wallets'),
    ):
        if correlations.get(bucket):
            lines.append(f'- **{caption}:** {fmt(correlations[bucket])}')
    accounts = correlations.get('accounts') or []
    if accounts:
        found = [a for a in accounts if a.get('status') == 'found']
        by_level = {level: [a['label'] for a in found if a.get('confidence') == level] for level in CONFIDENCE_ORDER}
        counts = ', '.join(f'{len(by_level[lvl])} {lvl.title()}' for lvl in ('HIGH', 'MEDIUM', 'LOW') if by_level[lvl])
        lines.append(
            f'- **Username found on:** {len(found)} platform(s)' + (f' ({counts} confidence)' if counts else '')
        )
        for level, text in (('HIGH', 'High confidence'), ('MEDIUM', 'Medium confidence'), ('LOW', 'Low confidence')):
            if by_level[level]:
                suffix = ' (verify manually)' if level == 'LOW' else ''
                lines.append(f'  - {text}{suffix}: {fmt(by_level[level])}')
        manual = [a['label'] for a in accounts if a.get('status') == 'manual']
        lines.append(f'- **Manual verification needed:** {fmt(manual)}')
        not_found = [a for a in accounts if a.get('status') == 'not_found']
        lines.append(f'- **Checked, not found:** {len(not_found)} platform(s)')
        lines.append('- _A username existing on a platform does not prove the target owns that account._')
    return lines


def format_pivot_lines(correlations: Dict[str, Any]) -> List[str]:
    """Sezione Markdown 'Suggested Pivots': suggerimenti, mai eseguiti automaticamente."""
    pivots = correlations.get('suggested_pivots') or []
    lines = [
        '## Suggested Pivots',
        '',
        '_Selectors you may investigate next. The tool does **not** run them: each pivot is a separate '
        'investigation that needs its own lawful basis (data minimisation)._',
        '',
    ]
    if pivots:
        lines.extend(f'- {md_text(pivot)}' for pivot in pivots)  # remote text: never live Markdown
    else:
        lines.append('_none identified_')
    return lines
