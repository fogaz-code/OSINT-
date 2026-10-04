import pytest
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard


def test_redact_email():
    guard = PrivacyGuard()
    assert guard.redact('Contact: test@example.com') == 'Contact: [REDACTED]'


def test_redact_ip():
    guard = PrivacyGuard()
    result = guard.redact('Server at 192.168.1.1')
    assert '[REDACTED]' in result


def test_redact_api_key():
    guard = PrivacyGuard()
    result = guard.redact('api_key=sk-1234567890abcdef1234567890abcdef')
    assert '[REDACTED]' in result


def test_redact_dict():
    guard = PrivacyGuard()
    data = {'email': 'test@example.com', 'safe': 'value'}
    result = guard.redact_dict(data)
    assert result['email'] == '[REDACTED]'
    assert result['safe'] == 'value'


def test_contains_secrets_true():
    guard = PrivacyGuard()
    assert guard.contains_secrets('token=sk-1234567890abcdef1234567890abcdef') is True


def test_contains_secrets_false():
    guard = PrivacyGuard()
    assert guard.contains_secrets('normal text') is False


@pytest.mark.parametrize(
    'text',
    [
        'IBAN IT60X0542811101000000123456',
        'IBAN IT60 X054 2811 1010 0000 0123 456',
        'card 4111 1111 1111 1111',
        'btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
        'btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
        'eth 0x52908400098527886E0F7030069857D2E4169EE7',
        'CF RSSMRA85T10A562S',
        'tel +39 333 1234567',
        'cell 333 1234567',
        'AAAA 2001:db8::1',
        'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTU',
        'AKIAIOSFODNN7EXAMPLE',
        'sk-proj-abc_def-1234567890abcdefghijkl',
        '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----',
    ],
)
def test_redacts_extended_pii(text):
    result = PrivacyGuard().redact(text)
    assert '[REDACTED]' in result
    # Nessun frammento del valore originale deve sopravvivere (il vecchio regex telefono lasciava pezzi).
    assert result.split()[-1] == '[REDACTED]' or result == '[REDACTED]'


@pytest.mark.parametrize(
    'text',
    [
        '2024-03-15T10:22:33Z',
        'count 1234567890',
        'not card 4111 1111 1111 1112',
        'not btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3',
        'time 10:22:33',
        'mac aa:bb:cc:dd:ee:ff',
        'version 1.2.3.4.5',
        'https://example.com/path?id=123456789',
        'IBAN IT00X0542811101000000123456',
    ],
)
def test_no_false_positives(text):
    assert PrivacyGuard().redact(text) == text


def test_redacts_keys_and_nested_lists():
    result = PrivacyGuard().redact_dict({'a@b.co': 'x', 'l': [['c@d.co']], 't': ('1.1.1.1',)})
    assert result == {'[REDACTED]': 'x', 'l': [['[REDACTED]']], 't': ['[REDACTED]']}


def test_network_category_can_be_disabled():
    guard = PrivacyGuard(categories={'secrets', 'personal'})
    assert guard.redact('A 8.8.8.8 mail a@b.co') == 'A 8.8.8.8 mail [REDACTED]'


def test_labels():
    assert PrivacyGuard(label=True).redact('a@b.co') == '[REDACTED:email]'


# --- C3: categories contract ---

TRON = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
BTC_BASE58 = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
BTC_BECH32 = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
ETH = '0x52908400098527886E0F7030069857D2E4169EE7'


def test_categories_contract():
    assert CATEGORIES == {'secrets', 'personal', 'network', 'location', 'crypto', 'device'}


def test_unknown_category_still_rejected():
    with pytest.raises(ValueError):
        PrivacyGuard(categories={'personal', 'wallets'})


def test_default_guard_redacts_every_category():
    # 'device' has no free-text rule: serials are recognised by their key inside a camera record.
    assert {r.category for r in PrivacyGuard().rules} == set(CATEGORIES) - {'device'}


# --- C3: crypto ---


@pytest.mark.parametrize('address', [BTC_BASE58, BTC_BECH32, ETH, TRON, 'T9yED5xMV5ARV98BexN97aLZ1UUq7eKSxm'])
def test_wallet_addresses_are_crypto_category(address):
    text = f'wallet {address} seen'
    assert PrivacyGuard(categories={'crypto'}).redact(text) == 'wallet [REDACTED] seen'
    # Moved out of 'personal': keeping crypto (--keep-crypto) reveals them, nothing else does.
    assert PrivacyGuard(categories=CATEGORIES - {'crypto'}).redact(text) == text
    assert PrivacyGuard(categories={'personal'}).redact(text) == text


def test_crypto_labels():
    assert PrivacyGuard(label=True).redact(TRON) == '[REDACTED:tron_address]'
    assert PrivacyGuard(label=True).redact(ETH) == '[REDACTED:eth_address]'


@pytest.mark.parametrize(
    'text',
    [
        'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u',  # checksum broken
        'T' + 'a' * 33,  # base58 alphabet, no valid checksum
        'TRANSACTIONSPROCESSEDSUCCESSFULLYX',  # 34 chars starting with T, uppercase word
        'Tokyo-Station-0123456789abcdefghij',
    ],
)
def test_tron_needs_valid_checksum(text):
    assert PrivacyGuard().redact(text) == text


def test_tron_wrong_version_byte_not_redacted():
    # Valid base58check, but version 0x00 (a BTC P2PKH payload) under a T prefix cannot exist; the
    # BTC rule has its own prefix, so this exercises the TRON validator's version check directly.
    from secure_osint.core.privacy import _tron_ok

    assert _tron_ok(TRON) is True
    assert _tron_ok('16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu') is False


# --- C3: location (structured) ---


def test_gps_object_redacted_as_a_whole():
    data = {
        'file': {'name': 'IMG_0001.jpg', 'size_bytes': 1234},
        'camera': {'make': 'Canon', 'model': 'EOS 5D'},
        'gps': {'latitude': 45.4642, 'longitude': 9.19, 'altitude_m': 120.5, 'maps_url': 'https://maps.x/?q=1'},
    }
    out = PrivacyGuard().redact_dict(data)
    assert out['gps'] == '[REDACTED]'
    assert out['camera'] == {'make': 'Canon', 'model': 'EOS 5D'}
    assert out['file'] == {'name': 'IMG_0001.jpg', 'size_bytes': 1234}


@pytest.mark.parametrize(
    'key', ['latitude', 'longitude', 'lat', 'lon', 'lng', 'altitude', 'altitude_m', 'maps_url', 'coordinates']
)
def test_location_keys_redact_numbers_and_strings(key):
    out = PrivacyGuard().redact_dict({key: 45.4642, 'nested': [{key: '45.4642'}], 'keep': 1.5})
    assert out == {key: '[REDACTED]', 'nested': [{key: '[REDACTED]'}], 'keep': 1.5}


@pytest.mark.parametrize('key', ['Latitude', 'GPSLatitude', 'exif:GPSLongitude', 'GPS GPSAltitude', 'gps_timestamp'])
def test_location_key_matching_is_case_and_namespace_insensitive(key):
    assert PrivacyGuard().redact_dict({key: '45/1 27/1 51/1'}) == {key: '[REDACTED]'}


def test_absent_gps_stays_null():
    assert PrivacyGuard().redact_dict({'gps': None, 'latitude': '', 'has_gps': False}) == {
        'gps': None,
        'latitude': '',
        'has_gps': False,
    }


def test_location_key_label():
    assert PrivacyGuard(label=True).redact_dict({'gps': {'latitude': 1.0}}) == {'gps': '[REDACTED:location]'}


def test_keep_location_reveals_coordinates():
    guard = PrivacyGuard(categories=CATEGORIES - {'location'})
    data = {'gps': {'latitude': 45.4642, 'longitude': 9.19}, 'note': 'at 45.464211, 9.190031'}
    assert guard.redact_dict(data) == {
        'gps': {'latitude': 45.4642, 'longitude': 9.19},
        'note': 'at 45.464211, 9.190031',
    }


def test_unrelated_keys_with_lat_substring_untouched():
    data = {'platform': 'x', 'translate': 12.34567, 'flat': 1, 'longest': 'y', 'latency_ms': 12.5}
    assert PrivacyGuard().redact_dict(data) == data


# --- C3: location (free text) ---


@pytest.mark.parametrize(
    'text',
    [
        'photo taken at 45.464211, 9.190031 yesterday',
        'at -33.8688,151.2093 yesterday',
        'at 40.7128;-74.0060 yesterday',
        'https://www.google.com/maps/@45.4642035,9.1899817,15z',
        'https://maps.example/?ll=45.4642%2C9.1900 x',
        'https://www.openstreetmap.org/?mlat=45.46420&mlon=9.18998 x',
        'pin 45°27\'51.1"N 9°11\'24.2"E',
        'pin 45° 27′ 51″ N, 9° 11′ 24″ E',
        "pin N 45°27.851' E 9°11.403'",
        "pin 33°52'S 151°12'E",
        '{"latitude": 45.4642, "longitude": 9.19}',
        'lat=45.4642&lon=9.19',
    ],
)
def test_free_text_coordinates_redacted(text):
    out = PrivacyGuard(categories={'location'}).redact(text)
    for fragment in ('45.46', '9.19', '9.18', '33.86', '151.2', '40.71', '74.00', '45°', '9°', '33°', '151°'):
        assert fragment not in out, out
    assert '[REDACTED]' in out


@pytest.mark.parametrize(
    'text',
    [
        'version 1.2.3.4',
        'macOS v10.15.7',
        'release 2.0.12345',
        'ips 192.168.1.1, 10.0.0.1',
        'ts 1700000000.123456, 1700000001.654321',
        '2024-03-15T10:22:33.123456Z',
        'laps 10:22:33.1234, 10:22:34.5678',
        'temp 45°C',
        'heading 270°',
        'pi 3.14159',
        'scores 0.12345, 0.67890',
        'out of range 195.12345, 9.12345',
        'out of range 45.12345, 195.12345',
        'few decimals 45.46, 9.19',
        'sha 1.2345.6789',
        'semver 1.12345,2.3',
    ],
)
def test_location_no_false_positives(text):
    assert PrivacyGuard(categories={'location'}).redact(text) == text


def test_coordinates_not_mistaken_for_phone_or_card():
    out = PrivacyGuard(label=True).redact('at 45.464211, 9.190031')
    assert out == 'at [REDACTED:coordinates]'


# --- field length cap ---


def test_short_strings_not_truncated():
    text = 'x' * 10_000
    assert PrivacyGuard().redact(text) == text


# --- ReDoS rewrites keep their behaviour ---


def test_unterminated_private_key_body_still_redacted():
    out = PrivacyGuard().redact('leak -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n')
    assert 'MIIEvQ' not in out and out.startswith('leak [REDACTED]')


def test_two_private_keys_redacted_separately():
    key = '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----'
    assert PrivacyGuard().redact(f'{key} and {key}') == '[REDACTED] and [REDACTED]'


@pytest.mark.parametrize(
    'text', ['tel +393331234567', 'tel +1 (234) 567-8901', 'tel +44 20 7946 0958', 'tel +39 06.1234.5678']
)
def test_international_phone_formats_redacted(text):
    assert PrivacyGuard().redact(text) == 'tel [REDACTED]'


@pytest.mark.parametrize('text', ['tel +39 333', 'tel +39 333 1234567-ext', 'build +1234567'])
def test_phone_near_misses_untouched(text):
    assert PrivacyGuard().redact(text) == text


def test_device_serials_are_personal_data_in_structured_records():
    data = {
        'camera': {'make': 'Canon', 'model': 'EOS 5D', 'serial': 'SN123456789', 'lens': None},
        'xmp': {'aux:SerialNumber': 'SN987654321', 'exifEX:LensSerialNumber': 'LS555', 'dc:format': 'image/jpeg'},
        'SOA': {'serial': '2024051701', 'mname': 'ns1.example.com'},  # not a camera record: kept
    }
    redacted = PrivacyGuard().redact_dict(data)
    assert redacted['camera']['serial'] == '[REDACTED]'
    assert redacted['camera']['model'] == 'EOS 5D' and redacted['camera']['lens'] is None
    assert redacted['xmp']['aux:SerialNumber'] == '[REDACTED]'
    assert redacted['xmp']['exifEX:LensSerialNumber'] == '[REDACTED]'
    assert redacted['xmp']['dc:format'] == 'image/jpeg'
    assert redacted['SOA']['serial'] == '2024051701'
    # Only the 'personal' category hides them.
    assert PrivacyGuard(categories={'network', 'location'}).redact_dict(data) == data


def test_uppercase_bech32_btc_address_is_redacted():
    # BIP-173 allows all-uppercase bech32 (the QR-code form); it must not slip past the crypto rule.
    address = 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'
    out = PrivacyGuard().redact(f'tips: {address}')
    assert address not in out and address.lower() not in out


def test_photographer_names_are_personal_and_redacted_by_default():
    data = {
        'authorship': {'artist': 'Jane Q. Photographer', 'copyright': '(c) Jane Q. Photographer', 'owner': 'Jane'},
        'xmp': {'dc:creator': ['Jane Q. Photographer'], 'dc:format': 'image/jpeg'},
    }
    out = PrivacyGuard().redact_value(data)
    assert 'Jane' not in repr(out)
    assert out['xmp']['dc:format'] == 'image/jpeg'  # non-personal XMP is kept


def test_photographer_names_kept_when_personal_is_not_redacted():
    data = {'authorship': {'artist': 'Jane', 'copyright': None, 'owner': None}}
    out = PrivacyGuard(categories=frozenset({'secrets'})).redact_value(data)
    assert out['authorship']['artist'] == 'Jane'


def test_unrelated_artist_fields_are_left_alone():
    # 'artist' outside an authorship record (e.g. a music platform profile) is not a photographer name.
    out = PrivacyGuard().redact_value({'artist': 'Some Band', 'followers': 10})
    assert out['artist'] == 'Some Band'


def test_device_serials_are_redacted_by_default_and_kept_with_keep_device():
    data = {'camera': {'make': 'Canon', 'model': 'EOS R5', 'serial': 'SN-0123456789'}, 'aux:SerialNumber': 'L-42'}
    redacted = repr(PrivacyGuard().redact_value(data))
    assert 'SN-0123456789' not in redacted and 'L-42' not in redacted and 'Canon' in redacted
    kept = PrivacyGuard(categories=CATEGORIES - {'device'}).redact_value(data)
    assert kept['camera']['serial'] == 'SN-0123456789' and kept['aux:SerialNumber'] == 'L-42'


def test_keeping_device_does_not_reveal_other_personal_data():
    data = {'camera': {'make': 'Canon', 'serial': 'SN-1'}, 'authorship': {'artist': 'Jane', 'owner': None}}
    out = PrivacyGuard(categories=CATEGORIES - {'device'}).redact_value(data)
    assert out['camera']['serial'] == 'SN-1' and 'Jane' not in repr(out)
