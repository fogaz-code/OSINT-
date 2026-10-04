import json

from secure_osint.core.correlation import build_correlations
from secure_osint.core.privacy import CATEGORIES, PrivacyGuard
from secure_osint.core.reporter import ReportGenerator

# Risultati grezzi realistici: forme prodotte davvero da dns/username/email source.
RAW_RESULTS = {
    'usernames': {
        'status': 'SUCCESS',
        'data': {
            'username': 'examplecorp',
            'platforms': {'github': {'exists': True, 'url': 'https://github.com/examplecorp', 'error': None}},
        },
    },
    'dns': {
        'status': 'SUCCESS',
        'data': {
            'A': ['93.184.216.34'],
            'AAAA': [],
            'CNAME': [],
            'MX': [{'preference': 10, 'exchange': 'mail.example.com'}],
            'NS': ['ns1.example.com', 'ns2.example.com'],
            'TXT': [],
            'SOA': None,
            'errors': {},
        },
    },
    'email': {'status': 'SUCCESS', 'data': {'email_domain': 'example.com', 'disposable_domain': False}},
}


# --- pure extraction (no network, no redaction) ---


def test_build_correlations_extracts_each_bucket():
    corr = build_correlations('example.com', RAW_RESULTS)
    assert corr['primary_target'] == 'example.com'
    assert corr['usernames'] == ['examplecorp']
    assert corr['emails'] == []
    assert corr['domains'] == ['example.com']  # from input seed + email_domain, de-duplicated
    # A record IP + MX host + NS hosts, sorted; platform profile URL hosts are NOT dragged in.
    assert corr['infrastructure'] == ['93.184.216.34', 'mail.example.com', 'ns1.example.com', 'ns2.example.com']
    assert 'github.com' not in corr['infrastructure'] and 'github.com' not in corr['domains']


def test_build_correlations_seeds_from_email_input():
    corr = build_correlations('jane.doe@example.org', {})
    assert corr['emails'] == ['jane.doe@example.org']
    assert corr['domains'] == ['example.org']


def test_build_correlations_seeds_username_and_github_repo():
    assert build_correlations('octocat', {})['usernames'] == ['octocat']
    assert build_correlations('octocat/hello-world', {})['usernames'] == ['octocat']


# --- markdown report integration ---


def _md(tmp_path, guard=None, input_data='example.com'):
    out = tmp_path / 'r.md'
    ReportGenerator(privacy_guard=guard).generate_markdown(RAW_RESULTS, input_data, 'due_diligence', str(out))
    return out.read_text(encoding='utf-8')


def test_markdown_has_entity_correlation_summary(tmp_path):
    text = _md(tmp_path)
    assert '## Entity Correlation Summary' in text
    # The summary sits above the per-step Results, near the top of the report.
    assert text.index('## Entity Correlation Summary') < text.index('## Results')
    assert 'co-occurrence, not verified identity links' in text
    assert '- **Primary Target:** example.com' in text
    assert '`examplecorp`' in text  # associated username
    assert '`example.com`' in text  # associated domain
    assert '`mail.example.com`' in text and '`ns1.example.com`' in text  # infrastructure hosts


def test_markdown_summary_redacts_ip_by_default(tmp_path):
    text = _md(tmp_path)
    # IP is 'network' category: redacted by default, so it must not leak into the summary.
    assert '93.184.216.34' not in text
    assert '[REDACTED]' in text


def test_markdown_summary_reveals_ip_with_keep_network(tmp_path):
    guard = PrivacyGuard(categories=CATEGORIES - {'network'})
    text = _md(tmp_path, guard=guard)
    assert '93.184.216.34' in text


def test_markdown_summary_none_identified_when_empty(tmp_path):
    out = tmp_path / 'r.md'
    ReportGenerator().generate_markdown({'s': {'status': 'SUCCESS', 'data': {'k': 'v'}}}, 'plainword', 'wf', str(out))
    text = out.read_text(encoding='utf-8')
    assert '_none identified_' in text


# --- json report integration ---


def _json(tmp_path, guard=None):
    out = tmp_path / 'r.json'
    ReportGenerator(privacy_guard=guard).generate_json(RAW_RESULTS, 'example.com', 'due_diligence', str(out))
    return json.loads(out.read_text(encoding='utf-8'))


def test_json_has_root_correlations_object(tmp_path):
    report = _json(tmp_path)
    assert 'correlations' in report
    corr = report['correlations']
    assert set(corr) == {
        'primary_target',
        'usernames',
        'emails',
        'domains',
        'infrastructure',
        'phones',
        'locations',
        'devices',
        'wallets',
        'accounts',
        'relations',
        'suggested_pivots',
        'timeline',
        'timeline_coverage',
    }
    assert corr['primary_target'] == 'example.com'
    assert corr['usernames'] == ['examplecorp']
    assert 'example.com' in corr['domains']


def test_json_correlations_redacts_ip_but_keeps_hosts(tmp_path):
    corr = _json(tmp_path)['correlations']
    assert '93.184.216.34' not in corr['infrastructure']
    assert '[REDACTED]' in corr['infrastructure']
    assert 'mail.example.com' in corr['infrastructure']


def test_json_correlations_covered_by_integrity_hash(tmp_path):
    import hashlib

    from secure_osint.core.reporter import canonical_json

    report = _json(tmp_path)
    integrity = report.pop('integrity')
    # Tampering with a correlation must break the stored hash: it is part of the signed body.
    assert hashlib.sha256(canonical_json(report).encode()).hexdigest() == integrity['value']
    report['correlations']['usernames'] = ['tampered']
    assert hashlib.sha256(canonical_json(report).encode()).hexdigest() != integrity['value']


# --- DNS SOA rname -> email pivot (RFC 1035 escapes) ---


def _soa(rname):
    return {'dns': {'status': 'SUCCESS', 'data': {'SOA': {'mname': 'ns1.example.com', 'rname': rname}}}}


def _soa_pivots(rname):
    return [p for p in build_correlations('example.com', _soa(rname))['suggested_pivots'] if 'SOA' in p]


def test_soa_rname_plain_mailbox():
    assert _soa_pivots('hostmaster.example.com.') == ['Email: hostmaster@example.com (DNS SOA contact)']


def test_soa_rname_escaped_dot_stays_in_the_local_part():
    # Regression: 'first\.last.example.com.' used to become 'first\@last.example.com'.
    assert _soa_pivots('first\\.last.example.com.') == ['Email: first.last@example.com (DNS SOA contact)']


def test_soa_rname_decimal_escape_is_decoded():
    assert _soa_pivots('first\\046last.example.com') == ['Email: first.last@example.com (DNS SOA contact)']


def test_soa_rname_that_is_not_a_valid_email_is_not_emitted():
    for rname in ('hostmaster', 'host master.example.com.', 'a.b', '.example.com', 'x\\', 'a\\@b.example.com', ''):
        assert _soa_pivots(rname) == [], rname


def test_soa_rname_non_string_is_ignored():
    assert _soa_pivots(None) == [] and _soa_pivots(42) == []


# --- C5 keys: location, device, wallet, phone formats, email MX / Gravatar ---

EXIF_RESULTS = {
    'exif': {
        'status': 'SUCCESS',
        'data': {
            'file': {'name': 'IMG_0001.jpg', 'size_bytes': 10, 'sha256': 'ab' * 32, 'mime': 'image/jpeg'},
            'camera': {'make': 'Canon', 'model': 'Canon EOS R5', 'serial': '012345678', 'lens': None, 'software': None},
            'timestamps': {'original': None, 'digitized': None, 'modified': None, 'offset': None},
            'gps': {'latitude': 45.4642, 'longitude': 9.19, 'altitude_m': 120.0, 'timestamp': None, 'maps_url': None},
            'xmp': {},
            'warnings': [],
        },
    }
}


def test_exif_gps_and_camera_become_location_and_device_entities():
    corr = build_correlations('IMG_0001.jpg', EXIF_RESULTS)
    assert corr['locations'] == ['45.464200, 9.190000']
    assert corr['devices'] == ['Canon EOS R5 (serial 012345678)']  # make not repeated when in the model
    assert {'from': 'img_0001.jpg', 'to': '45.464200, 9.190000', 'type': 'photo taken at'} in corr['relations']
    assert {'from': 'img_0001.jpg', 'to': 'Canon EOS R5 (serial 012345678)', 'type': 'taken with'} in corr['relations']


def test_exif_without_gps_or_camera_adds_nothing():
    data = json.loads(json.dumps(EXIF_RESULTS))
    data['exif']['data']['gps'] = None
    data['exif']['data']['camera'] = {'make': None, 'model': None, 'serial': None, 'lens': None, 'software': None}
    corr = build_correlations('IMG_0001.jpg', data)
    assert corr['locations'] == [] and corr['devices'] == [] and corr['relations'] == []


def test_exif_gps_out_of_range_or_not_numeric_is_rejected():
    data = json.loads(json.dumps(EXIF_RESULTS))
    for gps in ({'latitude': 91.0, 'longitude': 9.19}, {'latitude': True, 'longitude': 9.19}, {'latitude': '45'}):
        data['exif']['data']['gps'] = gps
        assert build_correlations('x.jpg', data)['locations'] == [], gps


def test_device_make_is_prefixed_when_the_model_lacks_it():
    data = json.loads(json.dumps(EXIF_RESULTS))
    data['exif']['data']['camera'] = {'make': 'Apple', 'model': 'iPhone 13', 'serial': None}
    assert build_correlations('x.jpg', data)['devices'] == ['Apple iPhone 13']


WALLET_RESULTS = {
    'chain': {
        'status': 'SUCCESS',
        'data': {
            'address': '0x52908400098527886E0F7030069857D2E4169EE7',
            'chain': 'eth',
            'explorer': 'blockscout',
            'tx_count': 3,
            'first_seen': None,
            'last_seen': None,
            'balance': '0',
            'balance_unit': 'ETH',
            'explorer_url': 'https://eth.blockscout.com/address/0x52908400098527886E0F7030069857D2E4169EE7',
        },
    }
}


def test_chain_data_becomes_a_wallet_entity():
    corr = build_correlations('0x52908400098527886E0F7030069857D2E4169EE7', WALLET_RESULTS)
    assert corr['wallets'] == ['ETH 0x52908400098527886E0F7030069857D2E4169EE7']
    assert corr['infrastructure'] == []  # 'address' is not mistaken for an IP or host


def test_unknown_chain_is_not_a_wallet():
    data = json.loads(json.dumps(WALLET_RESULTS))
    data['chain']['data']['chain'] = 'doge'
    assert build_correlations('x', data)['wallets'] == []


def test_phone_formats_become_phone_entities():
    results = {
        'phone': {
            'status': 'SUCCESS',
            'data': {
                'valid': True,
                'formats': {
                    'e164': '+390612345678',
                    'international': '+39 06 1234 5678',
                    'national': '06 1234 5678',
                    'rfc3966': 'tel:+39-06-1234-5678',
                    'digits': '390612345678',
                },
            },
        }
    }
    corr = build_correlations('+390612345678', results)
    assert corr['phones'] == ['+39 06 1234 5678', '+390612345678', '06 1234 5678']


def test_email_mx_hosts_and_gravatar_feed_infrastructure_and_pivots():
    results = {
        'email': {
            'status': 'SUCCESS',
            'data': {
                'email_domain': 'example.org',
                'mx': ['mx1.example.org.', 'mx2.example.org'],
                'has_mx': True,
                'gravatar': {
                    'display_name': 'Jane Doe',
                    'profile_url': 'https://gravatar.com/janedoe',
                    'verified_accounts': [
                        {'service': 'github', 'url': 'https://github.com/janedoe'},
                        {'service': 'evil', 'url': 'javascript:alert(1)'},
                    ],
                },
            },
        }
    }
    corr = build_correlations('jane@example.org', results)
    assert corr['infrastructure'] == ['mx1.example.org', 'mx2.example.org']
    assert {'from': 'jane@example.org', 'to': 'mx1.example.org', 'type': 'mail server'} in corr['relations']
    assert 'Name: Jane Doe (from Gravatar)' in corr['suggested_pivots']
    assert 'Linked account: github https://github.com/janedoe (from Gravatar)' in corr['suggested_pivots']
    assert not any('javascript' in p for p in corr['suggested_pivots'])


# --- redaction of the new buckets in reports ---


def _corr(results, target, guard=None):
    return ReportGenerator(privacy_guard=guard).correlations(results, target)


def test_locations_wallets_redacted_by_default_and_device_serial_hidden():
    corr = _corr({**EXIF_RESULTS, **WALLET_RESULTS}, 'IMG_0001.jpg')
    assert corr['locations'] == ['[REDACTED]']
    assert corr['wallets'] == ['ETH [REDACTED]']  # the chain is not personal data, the address is
    assert corr['devices'] == ['Canon EOS R5 (serial [REDACTED])']
    text = json.dumps(corr)
    assert '45.46' not in text and '0x5290' not in text and '012345678' not in text
    # Relations are resolved on raw values, then redacted per bucket.
    relation = {'from': 'IMG_0001.jpg', 'to': '[REDACTED]', 'type': 'photo taken at', 'bucket': 'locations'}
    assert relation in corr['relations']


def test_location_and_crypto_kept_only_when_the_guard_does_not_redact_them():
    import pytest

    keep = {'location', 'crypto'}
    if not keep <= set(CATEGORIES):
        pytest.skip('C3 privacy categories (location, crypto) not merged in this branch yet')
    corr = _corr({**EXIF_RESULTS, **WALLET_RESULTS}, 'IMG_0001.jpg', PrivacyGuard(categories=CATEGORIES - keep))
    assert corr['locations'] == ['45.464200, 9.190000']
    assert corr['wallets'] == ['ETH 0x52908400098527886E0F7030069857D2E4169EE7']


def test_phones_revealed_only_with_keep_network():
    results = {'phone': {'status': 'SUCCESS', 'data': {'formats': {'e164': '+390612345678'}}}}
    assert _corr(results, 'someone')['phones'] == ['[REDACTED]']
    guard = PrivacyGuard(categories=CATEGORIES - {'network'})
    assert _corr(results, 'someone', guard)['phones'] == ['+390612345678']


# --- collection summary (C4 calibration, username stats, partial results) ---


def test_collection_summary_counts_calibration_and_error_kinds():
    from secure_osint.core.correlation import collection_summary

    def p(exists, calibration, error_kind=None):
        return {'exists': exists, 'error': None, 'calibration': calibration, 'error_kind': error_kind}

    results = {
        'username_check': {
            'status': 'DEGRADED',
            'data': {
                'username': 'jroe',
                'stats': {'automated': 5, 'checked': 3, 'found': 2, 'failed': 2},
                'platforms': {
                    'a': p(True, 'passed'),
                    'b': p(True, 'not_applicable'),
                    'c': p(None, 'soft404'),
                    'd': p(None, 'control_error', 'timeout'),
                    'e': p(None, 'passed', 'rate_limited'),
                    'f': p(False, 'bogus', 'not-a-kind'),
                },
                'partial': True,
                'errors': ['deadline reached before 2 platforms'],
            },
        },
        'dns': {'status': 'SUCCESS', 'data': {'A': []}},
    }
    summary = collection_summary(results)
    assert summary['username'] == {
        'stats': {'automated': 5, 'checked': 3, 'found': 2, 'failed': 2},
        'calibration': {'passed': 2, 'soft404': 1, 'control_error': 1, 'not_applicable': 1},
        'error_kinds': {'rate_limited': 1, 'timeout': 1},
    }
    assert summary['partial_steps'] == [
        {'step': 'username_check', 'status': 'DEGRADED', 'errors': ['deadline reached before 2 platforms']}
    ]


def test_collection_summary_derives_stats_when_the_source_predates_them():
    from secure_osint.core.correlation import collection_summary

    platforms = {'a': {'exists': True}, 'b': {'exists': None}, 'c': {'exists': False}}
    summary = collection_summary({'u': {'status': 'SUCCESS', 'data': {'username': 'x', 'platforms': platforms}}})
    assert summary['username']['stats'] == {'automated': None, 'checked': 2, 'found': 1, 'failed': None}
    assert summary['partial_steps'] == []


def test_collection_summary_empty_without_username_data():
    from secure_osint.core.correlation import collection_summary

    assert collection_summary({'dns': {'status': 'SUCCESS', 'data': {}}}) == {'username': None, 'partial_steps': []}
