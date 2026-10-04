import pytest

from secure_osint.core.validator import (
    IMAGE_EXTENSIONS,
    detect_input_type,
    is_btc_address,
    is_eth_address,
    is_tron_address,
    is_unc_path,
    wallet_chain,
)
from secure_osint.utils.keccak import keccak256


@pytest.mark.parametrize(
    'value,expected',
    [
        ('example.com', 'domain'),
        ('sub.example.co.uk', 'domain'),
        ('münchen.de', 'domain'),
        ('https://example.com/x', 'url'),
        ('a@b.co', 'email'),
        ('8.8.8.8', 'ipv4'),
        ('999.999.999.999', 'generic'),
        ('2001:db8::1', 'ipv6'),
        ('::1', 'ipv6'),
        ('owner/repo', 'github_repo'),
        ('octocat', 'username'),
        ('x', 'generic'),
    ],
)
def test_detect_input_type(value, expected):
    assert detect_input_type(value) == expected


def test_empty_input():
    with pytest.raises(ValueError):
        detect_input_type('  ')


def test_docstring_only_advertises_reachable_types():
    # Regression: the docstring promised a 'hash' type that no branch ever returned.
    doc = detect_input_type.__doc__ or ''
    assert 'hash' not in doc
    for kind in ('image_file', 'wallet'):
        assert kind in doc


# --- Keccak-256 (needed for EIP-55; hashlib.sha3_256 uses different padding) ---------------------


@pytest.mark.parametrize(
    'data,digest',
    [
        (b'', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
        (b'abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    ],
)
def test_keccak256_known_vectors(data, digest):
    assert keccak256(data).hex() == digest


def test_keccak256_multi_block_input():
    # 200 bytes spans two 136-byte rate blocks: exercises the absorb loop, not only the padding.
    assert keccak256(b'a' * 200) != keccak256(b'a' * 199)
    assert len(keccak256(b'a' * 200)) == 32


# --- Wallets -----------------------------------------------------------------------------------------

BTC_VALID = [
    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',  # genesis block, P2PKH
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',  # P2PKH
    '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',  # P2SH
    'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',  # P2WPKH, bech32
    'BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ',  # bech32 is case-insensitive when not mixed
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',  # P2TR, bech32m (BIP-350)
]
ETH_VALID = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',  # EIP-55 test vectors
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed',  # all lower: no checksum to verify
    '0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED',  # all upper: no checksum to verify
]
TRON_VALID = ['TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t']


@pytest.mark.parametrize('address', BTC_VALID)
def test_btc_addresses(address):
    assert is_btc_address(address)
    assert wallet_chain(address) == 'btc'
    assert detect_input_type(address) == 'wallet'


@pytest.mark.parametrize('address', ETH_VALID)
def test_eth_addresses(address):
    assert is_eth_address(address)
    assert wallet_chain(address) == 'eth'
    assert detect_input_type(address) == 'wallet'


@pytest.mark.parametrize('address', TRON_VALID)
def test_tron_addresses(address):
    assert is_tron_address(address)
    assert wallet_chain(address) == 'tron'
    assert detect_input_type(address) == 'wallet'


def _flip_last(value: str) -> str:
    last = value[-1]
    return value[:-1] + ('2' if last != '2' else '3')


@pytest.mark.parametrize(
    'value',
    [
        _flip_last('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'),  # base58check checksum broken
        _flip_last('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'),
        'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx',  # bech32 checksum broken
        'bc1qAr0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',  # mixed case is invalid bech32
        # Witness v1 encoded with the v0 (bech32) constant must be rejected (BIP-350).
        'bc1pw508d6qejxtdg4c5r3zap8y5p6tjd6q7xkspv0',
        '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD',  # EIP-55 mixed case with one wrong letter
        '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae',  # 39 hex
        '0xZZaeb6053f3e94c9b9a09f33669435e7ef1beaed',  # not hex
        _flip_last('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'),
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7Di',  # truncated: checksum no longer matches
        'tb1qw508d6qejxtdg4c5r3zap8y5p6tjd6q7xkspv',  # testnet: out of scope
    ],
)
def test_invalid_wallets_are_rejected(value):
    assert wallet_chain(value) is None
    assert detect_input_type(value) != 'wallet'


def test_tron_prefix_with_btc_version_byte_is_not_tron():
    # A base58check string that starts with T but carries a non-0x41 version byte is not a TRON address.
    assert not is_tron_address('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
    assert not is_btc_address('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')


def test_short_btc_address_was_username_now_wallet():
    # Checksum-valid base58 addresses can be <= 30 chars and match the username pattern: wallet wins.
    assert detect_input_type('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2') == 'wallet'


@pytest.mark.parametrize('value', ['a' * 3000, '1' * 200, 'bc1' + 'q' * 200, '0x' + 'a' * 400])
def test_long_inputs_are_cheap_and_not_wallets(value):
    assert wallet_chain(value) is None


# --- Image files ---------------------------------------------------------------------------------------


def test_existing_image_file_is_detected(tmp_path):
    img = tmp_path / 'photo.JPG'
    img.write_bytes(b'\xff\xd8\xff\xd9')
    assert detect_input_type(str(img)) == 'image_file'


def test_relative_image_path_beats_domain_detection(tmp_path, monkeypatch):
    # 'photo.jpg' is also a syntactically valid domain: an existing file must win.
    (tmp_path / 'photo.jpg').write_bytes(b'\xff\xd8\xff\xd9')
    monkeypatch.chdir(tmp_path)
    assert detect_input_type('photo.jpg') == 'image_file'


def test_image_path_with_slash_beats_github_repo(tmp_path, monkeypatch):
    (tmp_path / 'pics').mkdir()
    (tmp_path / 'pics' / 'a.png').write_bytes(b'\x89PNG\r\n\x1a\n')
    monkeypatch.chdir(tmp_path)
    assert detect_input_type('pics/a.png') == 'image_file'


def test_missing_image_file_keeps_old_detection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert detect_input_type('photo.jpg') == 'domain'


def test_non_image_extension_is_not_image_file(tmp_path):
    f = tmp_path / 'notes.txt'
    f.write_text('hello', encoding='utf-8')
    assert detect_input_type(str(f)) != 'image_file'


def test_directory_with_image_extension_is_not_image_file(tmp_path):
    d = tmp_path / 'album.jpg'
    d.mkdir()
    assert detect_input_type(str(d)) != 'image_file'


UNC_FORMS = [
    r'\\attacker.example\share\x.jpg',
    '//attacker.example/share/x.jpg',
    r'\/attacker.example/share/x.jpg',  # Windows accepts any mix of separators
    r'/\attacker.example\share\x.jpg',
    r'\??\UNC\attacker.example\share\x.jpg',  # NT object-manager prefix
    r'  \\attacker.example\share\x.jfif',
]


@pytest.mark.parametrize('value', UNC_FORMS)
def test_unc_paths_are_never_touched(value, monkeypatch):
    # On Windows a stat() on a UNC path opens an SMB session and leaks the user's NTLM hash.
    def boom(*args, **kwargs):
        raise AssertionError('filesystem must not be touched for UNC paths')

    monkeypatch.setattr('secure_osint.core.validator.os.stat', boom)
    assert detect_input_type(value) != 'image_file'


def test_image_extensions_cover_exif_capable_formats():
    for ext in ('.jpg', '.jpeg', '.tif', '.tiff', '.png', '.webp', '.heic', '.dng'):
        assert ext in IMAGE_EXTENSIONS


@pytest.mark.parametrize('value', UNC_FORMS)
def test_is_unc_path_recognises_every_network_form(value):
    assert is_unc_path(value)


@pytest.mark.parametrize('value', ['C:/Users/a/x.jpg', r'C:\Users\a\x.jpg', '/home/a/x.jpg', 'x.jpg', 'a/b.png'])
def test_is_unc_path_accepts_local_paths(value):
    assert not is_unc_path(value)


def test_allow_files_false_never_touches_the_filesystem(tmp_path, monkeypatch):
    image = tmp_path / 'p.jpg'
    image.write_bytes(b'\xff\xd8\xff')

    def boom(*args, **kwargs):
        raise AssertionError('filesystem must not be touched')

    monkeypatch.setattr('secure_osint.core.validator.os.stat', boom)
    assert detect_input_type(str(image), allow_files=False) != 'image_file'
