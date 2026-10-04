"""Public on-chain activity of a BTC, ETH or TRON address from keyless block explorers.

Endpoints (all public, no API key, verified 2026-10):

- BTC: Blockstream Esplora ``blockstream.info/api``, falling back to the Esplora-compatible
  ``mempool.space/api`` on a transient failure.
- ETH: Blockscout ``eth.blockscout.com/api/v2``.
- TRON: TronGrid ``api.trongrid.io/v1`` (keyless calls are throttled hard, hence the 1-token bucket).

The address is validated offline (checksums included) before any request, so a typo never reaches
a third party. Output is minimised to account-level facts: no transaction ids, no counterparties,
no amounts per transaction. Every request goes through ``SafeHttpClient`` with its timeout clamped
to the step deadline.
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from secure_osint.core.validator import is_eth_address
from secure_osint.sources.base import BaseSource, SourceError, SourceUnavailable, TransientSourceError
from secure_osint.sources.registry import register_source
from secure_osint.utils.deadline import DeadlineExceeded, clamp_timeout
from secure_osint.utils.http_client import HttpResponse, SafeHttpClient, raise_for_status, shared_client

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
# Always used with fullmatch: `$` would also accept a trailing newline.
_B58_RE = re.compile(r'[1-9A-HJ-NP-Za-km-z]+')
_ETH_RE = re.compile(r'0x[0-9a-fA-F]{40}')
_BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_BECH32_CONST, _BECH32M_CONST = 1, 0x2BC830A3

BTC_EXPLORERS = ('blockstream.info', 'mempool.space')
BLOCKSCOUT = 'eth.blockscout.com'
TRONGRID = 'api.trongrid.io'

# Esplora returns confirmed history 25 transactions per page. Paging back to the first transaction
# is only worth it for small histories: beyond this budget first_seen is left unknown, never guessed.
ESPLORA_PAGE = 25
ESPLORA_MAX_EXTRA_PAGES = 4


# --- offline address validation ---


def _b58decode(text: str) -> Optional[bytes]:
    if not _B58_RE.fullmatch(text):
        return None
    num = 0
    for char in text:
        num = num * 58 + _B58.index(char)
    body = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    pad = len(text) - len(text.lstrip('1'))
    return b'\x00' * pad + body


def _b58check_payload(text: str) -> Optional[bytes]:
    """The 21-byte versioned payload of a valid 25-byte base58check string, else None."""
    if not 26 <= len(text) <= 35:
        return None
    raw = _b58decode(text)
    if raw is None or len(raw) != 25:
        return None
    if hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] != raw[21:]:
        return None
    return raw[:21]


def _bech32_polymod(values: List[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _convert_bits(data: List[int], from_bits: int, to_bits: int) -> Optional[List[int]]:
    acc = bits = 0
    out: List[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    # BIP173: leftover padding must be shorter than a group and all zeros.
    if bits >= from_bits or (acc << (to_bits - bits)) & maxv:
        return None
    return out


def _valid_segwit(address: str) -> bool:
    """BIP173/BIP350 mainnet segwit address (bech32 for v0, bech32m for v1+)."""
    if address.lower() != address and address.upper() != address:
        return False  # mixed case is invalid bech32
    address = address.lower()
    if len(address) > 90 or not address.startswith('bc1'):
        return False
    hrp, data_part = 'bc', address[3:]
    if len(data_part) < 7 or any(c not in _BECH32_CHARSET for c in data_part):
        return False
    data = [_BECH32_CHARSET.index(c) for c in data_part]
    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = _bech32_polymod(hrp_expanded + data)
    if const not in (_BECH32_CONST, _BECH32M_CONST):
        return False
    version, payload = data[0], data[1:-6]
    if version > 16:
        return False
    program = _convert_bits(payload, 5, 8)
    if program is None or not 2 <= len(program) <= 40:
        return False
    if version == 0:
        return const == _BECH32_CONST and len(program) in (20, 32)
    return const == _BECH32M_CONST


def detect_chain(address: str) -> Optional[str]:
    """Return 'btc', 'eth' or 'tron' for a valid MAINNET address (checksum verified), else None.

    ETH: all-lower/all-upper hex is accepted; a mixed-case address must pass its EIP-55 checksum
    (same rule as input detection in core.validator).
    """
    if not isinstance(address, str) or not address or len(address) > 90:
        return None
    if _ETH_RE.fullmatch(address):
        return 'eth' if is_eth_address(address) else None
    if address[:3].lower() == 'bc1':
        return 'btc' if _valid_segwit(address) else None
    payload = _b58check_payload(address)
    if payload is None:
        return None
    version = payload[0]
    if version in (0x00, 0x05) and address[0] in '13':
        return 'btc'  # P2PKH / P2SH
    if version == 0x41 and address[0] == 'T':
        return 'tron'
    return None


# --- formatting helpers ---


def format_units(amount: int, decimals: int) -> str:
    """Integer base units to an exact decimal string ('125000000', 8 -> '1.25'). No float rounding."""
    sign = '-' if amount < 0 else ''
    digits = str(abs(amount)).rjust(decimals + 1, '0')
    whole, fraction = digits[:-decimals], digits[-decimals:].rstrip('0')
    return f'{sign}{whole}.{fraction}' if fraction else f'{sign}{whole}'


def _iso_from_epoch(seconds: Any) -> Optional[str]:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (OverflowError, OSError, ValueError):
        return None


def _iso_from_text(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + '+00:00' if value.endswith('Z') else value
    # Python 3.10 fromisoformat only takes 0, 3 or 6 fractional digits: drop the fraction entirely.
    text = re.sub(r'\.\d+', '', text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


@register_source('chain')
class ChainSource(BaseSource):
    """Balance, transaction count and first/last activity of a BTC, ETH or TRON address."""

    def __init__(self, client: Optional[SafeHttpClient] = None, timeout: float = 15.0):
        """Initialize ChainSource."""
        self.client = client or shared_client()
        self.timeout = timeout

    # --- HTTP plumbing ---

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> HttpResponse:
        # Clamp first: an exhausted step budget must stop before the request is even issued.
        return self.client.get(url, params=params, timeout=clamp_timeout(self.timeout))

    def _get_json(self, url: str, host: str, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self._get(url, params)
        raise_for_status(resp, host)
        return resp.json()

    # --- entry point ---

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query keyless block explorers for the address and return account-level activity.

        Args:
            params: Step parameters; always includes ``input`` (the target) and ``upstream``.

        Returns:
            A dict with address, chain, explorer, tx_count, first_seen, last_seen, balance,
            balance_unit, explorer_url and notes; plus ``partial``/``errors`` when a secondary
            query failed.

        Raises:
            SourceUnavailable: Permanent failure (invalid address, malformed response, blocked).
            TransientSourceError: Temporary failure worth retrying (timeout, 429, 5xx).
        """
        raw = self.require_input(params)
        chain = detect_chain(raw)
        if chain is None:
            raise SourceUnavailable('Not a valid mainnet BTC, ETH or TRON address')
        clamp_timeout(self.timeout)  # fail fast on an already-spent budget
        if chain == 'btc':
            address = raw.lower() if raw[:3].lower() == 'bc1' else raw
            out, errors = self._btc(address)
        elif chain == 'eth':
            out, errors = self._eth(raw)
        else:
            out, errors = self._tron(raw)
        if errors:
            out['partial'] = True
            out['errors'] = errors
        return out

    @staticmethod
    def _result(address: str, chain: str, explorer: str, unit: str, url: str) -> Dict[str, Any]:
        return {
            'address': address,
            'chain': chain,
            'explorer': explorer,
            'tx_count': None,
            'first_seen': None,
            'last_seen': None,
            'balance': '0',
            'balance_unit': unit,
            'explorer_url': url,
            'notes': [],
        }

    # --- BTC (Esplora) ---

    def _btc(self, address: str) -> Tuple[Dict[str, Any], List[str]]:
        stats: Any = None
        host = ''
        failures: List[str] = []
        for host in BTC_EXPLORERS:
            try:
                resp = self._get(f'https://{host}/api/address/{address}')
                if resp.status_code == 429 or resp.status_code >= 500:
                    raise_for_status(resp, host)
            except TransientSourceError as e:
                failures.append(str(e))
                continue
            raise_for_status(resp, host)
            stats = resp.json()
            break
        if stats is None:
            raise TransientSourceError('; '.join(failures) or 'BTC explorers unavailable')

        chain_stats = stats.get('chain_stats') if isinstance(stats, dict) else None
        if not isinstance(chain_stats, dict):
            raise SourceUnavailable(f'{host}: unexpected address response')
        tx_count = _as_int(chain_stats.get('tx_count'))
        funded = _as_int(chain_stats.get('funded_txo_sum'))
        spent = _as_int(chain_stats.get('spent_txo_sum'))
        if tx_count is None or funded is None or spent is None:
            raise SourceUnavailable(f'{host}: unexpected address response')
        mempool = stats.get('mempool_stats')
        mempool_txs = _as_int(mempool.get('tx_count')) if isinstance(mempool, dict) else None

        out = self._result(address, 'btc', host, 'BTC', f'https://{host}/address/{address}')
        out['tx_count'] = tx_count
        out['balance'] = format_units(funded - spent, 8)
        out['notes'].append('Balance and tx_count cover confirmed transactions only.')
        if tx_count == 0 and not mempool_txs:
            return out, []

        errors: List[str] = []
        times: List[int] = []
        try:
            page = self._get_json(f'https://{host}/api/address/{address}/txs', host)
        except DeadlineExceeded:
            raise
        except SourceError as e:
            return out, [f'transaction history: {e}']
        confirmed = self._confirmed(page)
        times.extend(t for _, t in confirmed)

        if len(confirmed) < tx_count:
            if tx_count > len(confirmed) + ESPLORA_PAGE * ESPLORA_MAX_EXTRA_PAGES:
                out['notes'].append(
                    f'first_seen not determined: {tx_count} transactions exceed the paging budget; see the explorer.'
                )
                out['last_seen'] = _iso_from_epoch(max(times)) if times else None
                return out, errors
            seen, pages = len(confirmed), 0
            last_txid = confirmed[-1][0] if confirmed else None
            # Bounded by request count, not by tx_count: an explorer serving tiny pages cannot make us loop.
            while last_txid and seen < tx_count and pages < ESPLORA_MAX_EXTRA_PAGES:
                pages += 1
                url = f'https://{host}/api/address/{address}/txs/chain/{last_txid}'
                try:
                    older = self._confirmed(self._get_json(url, host))
                except DeadlineExceeded:
                    raise
                except SourceError as e:
                    errors.append(f'older transaction history: {e}')
                    break
                if not older:
                    break
                times.extend(t for _, t in older)
                seen += len(older)
                last_txid = older[-1][0]
            complete = seen >= tx_count and not errors
        else:
            complete = True

        if times:
            out['last_seen'] = _iso_from_epoch(max(times))
            out['first_seen'] = _iso_from_epoch(min(times)) if complete else None
        return out, errors

    @staticmethod
    def _confirmed(page: Any) -> List[Tuple[str, int]]:
        """(txid, block_time) of confirmed transactions, in page order. txids stay internal (paging only)."""
        if not isinstance(page, list):
            raise SourceUnavailable('unexpected transaction list response')
        rows: List[Tuple[str, int]] = []
        for tx in page:
            if not isinstance(tx, dict):
                continue
            status = tx.get('status')
            txid = tx.get('txid')
            block_time = _as_int(status.get('block_time')) if isinstance(status, dict) else None
            if isinstance(status, dict) and status.get('confirmed') and isinstance(txid, str) and block_time:
                if re.fullmatch(r'[0-9A-Za-z]{1,128}', txid):
                    rows.append((txid, block_time))
        return rows

    # --- ETH (Blockscout) ---

    def _eth(self, address: str) -> Tuple[Dict[str, Any], List[str]]:
        base = f'https://{BLOCKSCOUT}/api/v2/addresses/{address}'
        out = self._result(address, 'eth', BLOCKSCOUT, 'ETH', f'https://{BLOCKSCOUT}/address/{address}')
        resp = self._get(base)
        if resp.status_code == 404:
            # Blockscout answers 404 for an address it has never indexed: an unused account.
            out['tx_count'] = 0
            return out, []
        raise_for_status(resp, BLOCKSCOUT)
        account = resp.json()
        if not isinstance(account, dict) or 'coin_balance' not in account:
            raise SourceUnavailable(f'{BLOCKSCOUT}: unexpected address response')
        out['balance'] = format_units(_as_int(account.get('coin_balance')) or 0, 18)
        out['notes'].append('tx_count counts transactions only (not token transfers or internal calls).')

        errors: List[str] = []
        try:
            counters = self._get_json(f'{base}/counters', BLOCKSCOUT)
            out['tx_count'] = _as_int(counters.get('transactions_count')) if isinstance(counters, dict) else None
        except DeadlineExceeded:
            raise
        except SourceError as e:
            errors.append(f'transaction count: {e}')
        if out['tx_count'] == 0:
            return out, errors

        for key, query in (('last_seen', None), ('first_seen', {'sort': 'block_number', 'order': 'asc'})):
            try:
                page = self._get_json(f'{base}/transactions', BLOCKSCOUT, query)
            except DeadlineExceeded:
                raise
            except SourceError as e:
                errors.append(f'{key}: {e}')
                continue
            items = page.get('items') if isinstance(page, dict) else None
            if isinstance(items, list) and items and isinstance(items[0], dict):
                out[key] = _iso_from_text(items[0].get('timestamp'))
        return out, errors

    # --- TRON (TronGrid) ---

    def _tron(self, address: str) -> Tuple[Dict[str, Any], List[str]]:
        base = f'https://{TRONGRID}/v1/accounts/{address}'
        out = self._result(address, 'tron', TRONGRID, 'TRX', f'https://tronscan.org/#/address/{address}')
        out['notes'].append('tx_count unknown: no keyless TRON endpoint exposes a total.')
        body = self._get_json(base, TRONGRID)
        data = body.get('data') if isinstance(body, dict) else None
        if not isinstance(data, list):
            raise SourceUnavailable(f'{TRONGRID}: unexpected account response')
        if not data or not isinstance(data[0], dict):
            out['notes'].append('Account not activated on chain.')
            return out, []

        account = data[0]
        out['balance'] = format_units(_as_int(account.get('balance')) or 0, 6)
        created = _as_int(account.get('create_time'))
        out['first_seen'] = _iso_from_epoch(created / 1000) if created else None
        # TronGrid's own (misspelt) field name.
        latest = [t for t in (_as_int(account.get('latest_opration_time')),) if t]

        errors: List[str] = []
        try:
            txs = self._get_json(f'{base}/transactions', TRONGRID, {'limit': 1, 'only_confirmed': 'true'})
            rows = txs.get('data') if isinstance(txs, dict) else None
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                stamp = _as_int(rows[0].get('block_timestamp'))
                if stamp:
                    latest.append(stamp)
        except DeadlineExceeded:
            raise
        except SourceError as e:
            errors.append(f'latest transaction: {e}')
        out['last_seen'] = _iso_from_epoch(max(latest) / 1000) if latest else None
        return out, errors
