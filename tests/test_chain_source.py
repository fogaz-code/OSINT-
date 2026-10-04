"""Wallet/address lookups against keyless public block explorers (all HTTP mocked)."""

import json
from typing import Any, Dict, List, Optional, Union

import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.workflow import load_workflow_from_file
from secure_osint.sources.base import SourceError, SourceUnavailable, TransientSourceError
from secure_osint.sources.chain_source import ChainSource, detect_chain, format_units
from secure_osint.sources.tool_catalog import build_catalog
from secure_osint.utils.deadline import deadline_scope
from secure_osint.utils.http_client import HttpResponse
from secure_osint.utils.resilience import HostPolicies

GENESIS = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
P2SH = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
BECH32 = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
TAPROOT = 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297'
ETH = '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe'
TRON = 'TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW'
TRON_ZERO = 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb'

Reply = Union[HttpResponse, Exception]


def ok(body: Any, status: int = 200) -> HttpResponse:
    content = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    return HttpResponse(status, content, {})


class RoutingClient:
    """Answers by the longest matching URL prefix; records every call. Unknown URLs fail loudly."""

    def __init__(self, routes: Dict[str, Union[Reply, List[Reply]]]):
        self.routes = routes
        self.calls: List[Dict[str, Any]] = []

    def get(
        self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: Optional[float] = None
    ) -> HttpResponse:
        self.calls.append({'url': url, 'params': params, 'timeout': timeout})
        matches = [prefix for prefix in self.routes if url == prefix or url.startswith(prefix)]
        if not matches:
            raise AssertionError(f'unexpected request to {url}')
        route = self.routes[max(matches, key=len)]
        reply = route.pop(0) if isinstance(route, list) else route
        if isinstance(reply, Exception):
            raise reply
        return reply


def _esplora_stats(tx_count: int, funded: int, spent: int, mempool_txs: int = 0) -> Dict[str, Any]:
    return {
        'address': GENESIS,
        'chain_stats': {'funded_txo_sum': funded, 'spent_txo_sum': spent, 'tx_count': tx_count},
        'mempool_stats': {'funded_txo_sum': 0, 'spent_txo_sum': 0, 'tx_count': mempool_txs},
    }


def _esplora_tx(txid: str, block_time: Optional[int]) -> Dict[str, Any]:
    status: Dict[str, Any] = {'confirmed': block_time is not None}
    if block_time is not None:
        status['block_time'] = block_time
    # Counterparty data (vin/vout) is present in real responses and must never reach the output.
    return {'txid': txid, 'vin': [{'prevout': {'scriptpubkey_address': '1Counterparty'}}], 'vout': [], 'status': status}


# --- address validation (offline, before any request) ---


@pytest.mark.parametrize(
    'address,chain',
    [
        (GENESIS, 'btc'),
        (P2SH, 'btc'),
        (BECH32, 'btc'),
        (BECH32.upper(), 'btc'),
        (TAPROOT, 'btc'),
        (ETH, 'eth'),
        (ETH.lower(), 'eth'),
        (TRON, 'tron'),
        (TRON_ZERO, 'tron'),
    ],
)
def test_detect_chain_accepts_valid_addresses(address, chain):
    assert detect_chain(address) == chain


@pytest.mark.parametrize(
    'address',
    [
        GENESIS[:-1] + 'b',  # base58check checksum broken
        P2SH[:-1] + 'z',
        BECH32[:-1] + 'p',  # bech32 checksum broken
        'bc1qAr0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',  # mixed case is invalid bech32
        'tb1qw508d6qejxtdg4c5r3zapmj9h3pqkzq5ztm6dp',  # testnet: mainnet explorers only
        'bc1zw508d6qejxtdg4c5r3zapmj9h3pqkzq5hj9hu',  # v2 program encoded with bech32 (not bech32m)
        '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BA',  # 39 hex
        '0xZZ0B295669a9FD93d5F28D9Ec85E40f4cb697BAe',
        '0xDe0B295669a9FD93d5F28D9Ec85E40f4cb697BAe',  # mixed case with a broken EIP-55 checksum
        TRON[:-1] + 'N',
        'T' + GENESIS[1:],  # right length, wrong version byte / checksum
        GENESIS.replace('1', 'T', 1),
        '',
        'not-an-address',
        ' ' + GENESIS + '/../x',
    ],
)
def test_detect_chain_rejects_invalid_addresses(address):
    assert detect_chain(address) is None


def test_invalid_address_never_reaches_the_network():
    client = RoutingClient({})
    with pytest.raises(SourceUnavailable):
        ChainSource(client).fetch({'input': GENESIS[:-1] + 'b'})
    assert client.calls == []


def test_whitespace_around_address_is_tolerated():
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(1, 5000, 0)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok([_esplora_tx('a', 1231006505)]),
        }
    )
    assert ChainSource(client).fetch({'input': f'  {GENESIS}\n'})['address'] == GENESIS


# --- BTC (Esplora) ---


def test_btc_small_history_reports_balance_and_dates():
    txs = [_esplora_tx('m', None), _esplora_tx('c', 1700000000), _esplora_tx('b', 1600000000)]
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(2, 150_000_000, 25_000_000, 1)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok(txs),
        }
    )
    data = ChainSource(client).fetch({'input': GENESIS})
    assert data['address'] == GENESIS and data['chain'] == 'btc'
    assert data['explorer'] == 'blockstream.info'
    assert data['tx_count'] == 2
    assert data['balance'] == '1.25' and data['balance_unit'] == 'BTC'
    assert data['first_seen'] == '2020-09-13T12:26:40Z'
    assert data['last_seen'] == '2023-11-14T22:13:20Z'
    assert data['explorer_url'] == f'https://blockstream.info/address/{GENESIS}'
    assert 'partial' not in data or data['partial'] is False
    # Data minimisation: no transaction ids, no counterparties.
    blob = json.dumps(data)
    assert '1Counterparty' not in blob and '"txid"' not in blob


def test_btc_large_history_pages_back_to_first_tx():
    page1 = [_esplora_tx(f't{i}', 1700000000 - i) for i in range(25)]
    page2 = [_esplora_tx('old', 1500000000)]
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(26, 1, 0)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok(page1),
            f'https://blockstream.info/api/address/{GENESIS}/txs/chain/t24': ok(page2),
        }
    )
    data = ChainSource(client).fetch({'input': GENESIS})
    assert data['first_seen'] == '2017-07-14T02:40:00Z'
    assert data['last_seen'] == '2023-11-14T22:13:20Z'
    assert data['balance'] == '0.00000001'


def test_btc_huge_history_does_not_page_and_says_so():
    page1 = [_esplora_tx(f't{i}', 1700000000 - i) for i in range(25)]
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(66670, 5_747_914_894, 0)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok(page1),
        }
    )
    data = ChainSource(client).fetch({'input': GENESIS})
    assert len(client.calls) == 2  # stats + newest page only
    assert data['tx_count'] == 66670
    assert data['first_seen'] is None
    assert data['last_seen'] == '2023-11-14T22:13:20Z'
    assert data['balance'] == '57.47914894'
    assert any('first_seen' in note for note in data['notes'])


def test_btc_falls_back_to_mempool_space_on_transient_error():
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{BECH32}': TransientSourceError('blockstream.info: timed out'),
            f'https://mempool.space/api/address/{BECH32}': ok(_esplora_stats(0, 0, 0)),
            f'https://mempool.space/api/address/{BECH32}/txs': ok([]),
        }
    )
    data = ChainSource(client).fetch({'input': BECH32.upper()})
    assert data['address'] == BECH32  # bech32 normalised to lowercase
    assert data['explorer'] == 'mempool.space'
    assert data['explorer_url'] == f'https://mempool.space/address/{BECH32}'
    assert data['tx_count'] == 0 and data['balance'] == '0'
    assert data['first_seen'] is None and data['last_seen'] is None


def test_btc_both_explorers_down_is_transient():
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok('oops', 503),
            f'https://mempool.space/api/address/{GENESIS}': ok('oops', 502),
        }
    )
    with pytest.raises(TransientSourceError):
        ChainSource(client).fetch({'input': GENESIS})


def test_btc_tx_page_failure_returns_partial_result():
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(3, 10, 0)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok('busy', 429),
        }
    )
    data = ChainSource(client).fetch({'input': GENESIS})
    assert data['tx_count'] == 3 and data['balance'] == '0.0000001'
    assert data['first_seen'] is None and data['last_seen'] is None
    assert data['partial'] is True
    assert data['errors'] and all(isinstance(e, str) for e in data['errors'])


def test_btc_malformed_stats_is_unavailable():
    client = RoutingClient({f'https://blockstream.info/api/address/{GENESIS}': ok({'unexpected': True})})
    with pytest.raises(SourceUnavailable):
        ChainSource(client).fetch({'input': GENESIS})


# --- ETH (Blockscout) ---


def _blockscout_routes(balance: Optional[str], count: str, newest: List[str], oldest: List[str]) -> Dict[str, Any]:
    base = f'https://eth.blockscout.com/api/v2/addresses/{ETH}'
    return {
        base: ok({'hash': ETH, 'coin_balance': balance, 'is_contract': False}),
        f'{base}/counters': ok({'transactions_count': count, 'token_transfers_count': '7'}),
        f'{base}/transactions': [
            ok({'items': [{'timestamp': t, 'from': {'hash': '0xabc'}} for t in newest], 'next_page_params': None}),
            ok({'items': [{'timestamp': t} for t in oldest], 'next_page_params': None}),
        ],
    }


def test_eth_reports_balance_count_and_dates():
    client = RoutingClient(
        _blockscout_routes(
            '5774491790776062094343', '3266', ['2026-09-18T04:28:23.000000Z'], ['2015-08-08T15:44:00.000000Z']
        )
    )
    data = ChainSource(client).fetch({'input': ETH})
    assert data['chain'] == 'eth' and data['explorer'] == 'eth.blockscout.com'
    assert data['address'] == ETH
    assert data['tx_count'] == 3266
    assert data['balance'] == '5774.491790776062094343' and data['balance_unit'] == 'ETH'
    assert data['last_seen'] == '2026-09-18T04:28:23Z'
    assert data['first_seen'] == '2015-08-08T15:44:00Z'
    assert data['explorer_url'] == f'https://eth.blockscout.com/address/{ETH}'
    # Newest page is the default order, oldest page is an explicit ascending sort.
    tx_calls = [c for c in client.calls if c['url'].endswith('/transactions')]
    assert tx_calls[0]['params'] in (None, {})
    assert tx_calls[1]['params'] == {'sort': 'block_number', 'order': 'asc'}
    assert '0xabc' not in json.dumps(data)


def test_eth_unused_address_skips_transaction_queries():
    routes = _blockscout_routes(None, '0', [], [])
    client = RoutingClient(routes)
    data = ChainSource(client).fetch({'input': ETH})
    assert data['tx_count'] == 0 and data['balance'] == '0'
    assert data['first_seen'] is None and data['last_seen'] is None
    assert not any(c['url'].endswith('/transactions') for c in client.calls)


def test_eth_unknown_address_404_is_an_empty_account():
    base = f'https://eth.blockscout.com/api/v2/addresses/{ETH}'
    client = RoutingClient({base: ok({'message': 'Not found'}, 404)})
    data = ChainSource(client).fetch({'input': ETH})
    assert data['tx_count'] == 0 and data['balance'] == '0'


def test_eth_counter_failure_is_partial():
    routes = _blockscout_routes('1', '0', [], [])
    routes[f'https://eth.blockscout.com/api/v2/addresses/{ETH}/counters'] = TransientSourceError('timed out')
    data = ChainSource(RoutingClient(routes)).fetch({'input': ETH})
    assert data['balance'] == '0.000000000000000001'
    assert data['tx_count'] is None
    assert data['partial'] is True and data['errors']


def test_eth_server_error_on_account_is_transient():
    client = RoutingClient({f'https://eth.blockscout.com/api/v2/addresses/{ETH}': ok('bad gateway', 502)})
    with pytest.raises(TransientSourceError):
        ChainSource(client).fetch({'input': ETH})


# --- TRON (TronGrid) ---


def test_tron_reports_balance_and_dates():
    client = RoutingClient(
        {
            f'https://api.trongrid.io/v1/accounts/{TRON}': ok(
                {
                    'data': [{'balance': 1100001, 'create_time': 1561986168000, 'latest_opration_time': 1691745792000}],
                    'success': True,
                }
            ),
            f'https://api.trongrid.io/v1/accounts/{TRON}/transactions': ok(
                {'data': [{'block_timestamp': 1790163330000, 'raw_data': {'contract': []}}], 'success': True}
            ),
        }
    )
    data = ChainSource(client).fetch({'input': TRON})
    assert data['chain'] == 'tron' and data['explorer'] == 'api.trongrid.io'
    assert data['balance'] == '1.100001' and data['balance_unit'] == 'TRX'
    assert data['first_seen'] == '2019-07-01T13:02:48Z'
    assert data['last_seen'] == '2026-09-23T11:35:30Z'  # UTC, newer than latest_opration_time
    # No keyless endpoint exposes a total: unknown, never guessed.
    assert data['tx_count'] is None
    assert data['explorer_url'] == f'https://tronscan.org/#/address/{TRON}'
    tx_call = [c for c in client.calls if c['url'].endswith('/transactions')][0]
    assert tx_call['params'] == {'limit': 1, 'only_confirmed': 'true'}


def test_tron_inactive_account():
    client = RoutingClient(
        {
            f'https://api.trongrid.io/v1/accounts/{TRON_ZERO}': ok({'data': [], 'success': True}),
            f'https://api.trongrid.io/v1/accounts/{TRON_ZERO}/transactions': ok({'data': [], 'success': True}),
        }
    )
    data = ChainSource(client).fetch({'input': TRON_ZERO})
    assert data['balance'] == '0' and data['first_seen'] is None and data['last_seen'] is None


def test_tron_rate_limit_is_transient():
    body = {'Error': 'request rate of (getAccount) exceeded the allowed_rps(1)'}
    client = RoutingClient({f'https://api.trongrid.io/v1/accounts/{TRON}': ok(body, 429)})
    with pytest.raises(TransientSourceError):
        ChainSource(client).fetch({'input': TRON})


def test_tron_last_seen_falls_back_to_account_field_when_tx_query_fails():
    client = RoutingClient(
        {
            f'https://api.trongrid.io/v1/accounts/{TRON}': ok(
                {'data': [{'create_time': 1561986168000, 'latest_opration_time': 1691745792000}]}
            ),
            f'https://api.trongrid.io/v1/accounts/{TRON}/transactions': TransientSourceError('rate limited'),
        }
    )
    data = ChainSource(client).fetch({'input': TRON})
    assert data['balance'] == '0'
    assert data['last_seen'] == '2023-08-11T09:23:12Z'
    assert data['partial'] is True and data['errors']


# --- cross-cutting ---


def test_request_timeouts_are_clamped_by_the_step_deadline():
    client = RoutingClient(
        {
            f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(0, 0, 0)),
            f'https://blockstream.info/api/address/{GENESIS}/txs': ok([]),
        }
    )
    with deadline_scope(2.0):
        ChainSource(client).fetch({'input': GENESIS})
    assert all(c['timeout'] is not None and c['timeout'] <= 2.0 for c in client.calls)


def test_expired_deadline_stops_before_any_request():
    client = RoutingClient({})
    with deadline_scope(0):
        with pytest.raises(SourceError):
            ChainSource(client).fetch({'input': GENESIS})
    assert client.calls == []


def test_conservative_host_rate_limits():
    policies = HostPolicies()
    assert policies.limiter('api.trongrid.io').rate <= 0.5
    assert policies.limiter('api.trongrid.io').capacity == 1
    for host in ('blockstream.info', 'mempool.space', 'eth.blockscout.com'):
        assert policies.limiter(host).rate <= 1.0


def test_registered_and_wallet_workflow():
    assert 'chain' in build_catalog(load_plugins=False)
    wf = load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/wallet.yaml')
    assert wf.name == 'wallet'
    assert wf.input_type == 'wallet'
    assert [s.type for s in wf.steps] == ['chain']


CONTRACT_KEYS = {
    'address',
    'chain',
    'explorer',
    'tx_count',
    'first_seen',
    'last_seen',
    'balance',
    'balance_unit',
    'explorer_url',
}


@pytest.mark.parametrize('address', [GENESIS + '\n', ETH + '\n', TRON + '\n', BECH32 + '\n', GENESIS + '\x00'])
def test_detect_chain_rejects_trailing_newline_without_crashing(address):
    # Regression: `$` matches before a trailing newline, and the base58 decoder then raised ValueError.
    assert detect_chain(address) is None


def test_btc_paging_is_bounded_by_pages_not_by_tx_count():
    # A hostile or quirky explorer returning one transaction per page must not trigger ~100 requests.
    page1 = [_esplora_tx(f't{i}', 1700000000 - i) for i in range(25)]
    routes: Dict[str, Any] = {
        f'https://blockstream.info/api/address/{GENESIS}': ok(_esplora_stats(120, 1, 0)),
        f'https://blockstream.info/api/address/{GENESIS}/txs': ok(page1),
    }
    previous = 't24'
    for i in range(200):
        routes[f'https://blockstream.info/api/address/{GENESIS}/txs/chain/{previous}'] = ok(
            [_esplora_tx(f'p{i}', 1600)]
        )
        previous = f'p{i}'
    client = RoutingClient(routes)
    data = ChainSource(client).fetch({'input': GENESIS})
    assert len(client.calls) <= 2 + 4
    assert data['first_seen'] is None  # history not exhausted: unknown, not guessed
    assert data['last_seen'] == '2023-11-14T22:13:20Z'


def test_output_carries_every_contract_key():
    client = RoutingClient({f'https://eth.blockscout.com/api/v2/addresses/{ETH}': ok({'message': 'Not found'}, 404)})
    assert CONTRACT_KEYS <= set(ChainSource(client).fetch({'input': ETH}))


@pytest.mark.parametrize(
    'address',
    [
        # BIP350 valid mainnet vectors (v1 taproot, v16 short program, v0 P2WSH).
        'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
        'BC1SW50QGDZ25J',
        'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',
    ],
)
def test_bip350_valid_vectors(address):
    assert detect_chain(address) == 'btc'


@pytest.mark.parametrize(
    'address',
    [
        # BIP350 invalid vectors: wrong checksum constant, bad length, bad program length.
        'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
        'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL',
        'bc1pw5dgrnzv',
        'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
    ],
)
def test_bip350_invalid_vectors(address):
    assert detect_chain(address) is None


def test_btc_client_error_does_not_fall_back():
    client = RoutingClient({f'https://blockstream.info/api/address/{GENESIS}': ok('bad request', 400)})
    with pytest.raises(SourceUnavailable):
        ChainSource(client).fetch({'input': GENESIS})
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    'amount,decimals,expected',
    [(0, 8, '0'), (1, 8, '0.00000001'), (125_000_000, 8, '1.25'), (10**18, 18, '1'), (1100001, 6, '1.100001')],
)
def test_format_units_is_exact(amount, decimals, expected):
    assert format_units(amount, decimals) == expected


@pytest.mark.parametrize(
    'raw',
    ['2015-08-08T15:44:00.000000Z', '2015-08-08T15:44:00Z', '2015-08-08T15:44:00.5Z', '2015-08-08T17:44:00+02:00'],
)
def test_blockscout_timestamps_normalised_to_utc(raw):
    client = RoutingClient(_blockscout_routes('0', '1', [raw], [raw]))
    data = ChainSource(client).fetch({'input': ETH})
    assert data['first_seen'] == data['last_seen'] == '2015-08-08T15:44:00Z'
