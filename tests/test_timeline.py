"""C9 timeline: built only from data the steps already collected (zero new requests)."""

import json

from secure_osint.core.correlation import build_correlations, format_timeline_lines
from secure_osint.core.reporter import ReportGenerator


def _platform(label, created=None, exists=True):
    entry = {'exists': exists, 'error': None, 'url': f'https://example.test/{label}', 'label': label}
    if created is not None:
        entry['profile'] = {'created_at': created}
    return entry


USERNAME = {
    'username_check': {
        'status': 'SUCCESS',
        'data': {
            'username': 'jroe',
            'platforms': {
                'github': _platform('GitHub', '2015-03-02T10:00:00Z'),
                'keybase': _platform('Keybase', '2016-07-01T08:30:00Z'),
                'hackernews': _platform('Hacker News', '2012-01-05T00:00:00Z'),
                'devto': _platform('Dev.to', 'Mar 3, 2020'),  # Dev.to joined_at format: a date, no time
                'dockerhub': _platform('Docker Hub', 'sometime in 2019'),  # unparseable: skipped, never guessed
                'gitlab': _platform('GitLab'),  # found, but no date exposed
                'reddit': _platform('Reddit', '2011-01-01T00:00:00Z', exists=False),  # not found: ignored
            },
        },
    }
}

RDAP = {
    'rdap': {
        'status': 'SUCCESS',
        'data': {
            'handle': 'EX-1',
            'status': ['active'],
            'events': {
                'registration': '1995-08-14T04:00:00Z',
                'expiration': '2030-08-13T04:00:00Z',
                'last changed': '2024-08-14T07:01:34Z',
                'last update of RDAP database': '2026-10-01T00:00:00Z',  # about the registry, not the target
            },
            'nameservers': ['a.iana-servers.net'],
        },
    }
}

EXIF = {
    'exif': {
        'status': 'SUCCESS',
        'data': {
            'file': {'name': 'IMG_0001.jpg', 'size_bytes': 1024, 'sha256': 'ab' * 32, 'mime': 'image/jpeg'},
            'camera': {'make': 'Canon', 'model': 'Canon EOS R5', 'serial': '012345678', 'lens': None, 'software': None},
            'timestamps': {
                'original': '2023:05:01 12:34:56',
                'digitized': '2023:05:01 12:34:56',
                'modified': '0000:00:00 00:00:00',  # zeroed EXIF field: not a date
                'offset': '+02:00',
            },
            'gps': {'latitude': 45.4642, 'longitude': 9.19, 'altitude_m': 120.0, 'timestamp': None, 'maps_url': None},
            'xmp': {},
            'warnings': [],
        },
    }
}

WALLET = {
    'chain': {
        'status': 'SUCCESS',
        'data': {
            'address': '0x52908400098527886E0F7030069857D2E4169EE7',
            'chain': 'eth',
            'explorer': 'blockscout',
            'tx_count': 3,
            'first_seen': 1609459200,  # Unix seconds: 2021-01-01T00:00:00Z
            'last_seen': '2024-02-03T04:05:06Z',
            'balance': '0',
            'balance_unit': 'ETH',
            'explorer_url': 'https://eth.blockscout.com/address/0x52908400098527886E0F7030069857D2E4169EE7',
        },
    }
}


def test_account_creation_dates_become_ascending_events_with_provenance():
    timeline = build_correlations('jroe', USERNAME)['timeline']
    assert [(e['date'], e['platform']) for e in timeline] == [
        ('2012-01-05T00:00:00Z', 'Hacker News'),
        ('2015-03-02T10:00:00Z', 'GitHub'),
        ('2016-07-01T08:30:00Z', 'Keybase'),
        ('2020-03-03', 'Dev.to'),  # date-only stays date-only: no invented time of day
    ]
    github = timeline[1]
    assert github == {
        'date': '2015-03-02T10:00:00Z',
        'platform': 'GitHub',
        'event': 'Account created',
        'source': 'username_check: platforms.github.profile.created_at',
    }


def test_coverage_says_how_many_found_platforms_exposed_a_date():
    corr = build_correlations('jroe', USERNAME)
    # 6 platforms found (github, keybase, hackernews, devto, dockerhub, gitlab); only 4 gave a usable date.
    assert corr['timeline_coverage'] == {'platforms_with_dates': 4, 'platforms_found': 6}


def test_timestamps_with_an_offset_are_normalised_to_utc():
    data = {
        'u': {'status': 'SUCCESS', 'data': {'platforms': {'b': _platform('Bitbucket', '2014-02-01T01:30:00+02:00')}}}
    }
    assert build_correlations('jroe', data)['timeline'][0]['date'] == '2014-01-31T23:30:00Z'


def test_rdap_registration_events_skip_registry_housekeeping():
    timeline = build_correlations('example.com', RDAP)['timeline']
    assert [(e['date'], e['event']) for e in timeline] == [
        ('1995-08-14T04:00:00Z', 'Domain registered'),
        ('2024-08-14T07:01:34Z', 'Domain registration record last changed'),
        ('2030-08-13T04:00:00Z', 'Domain registration expires'),
    ]
    assert all(e['platform'] == 'RDAP' and e['source'].startswith('rdap: events.') for e in timeline)


def test_rdap_for_an_ip_talks_about_the_network_block():
    data = {'r': {'status': 'SUCCESS', 'data': {'startAddress': '192.0.2.0', 'events': {'registration': '2001-01-01'}}}}
    assert build_correlations('192.0.2.1', data)['timeline'][0]['event'] == 'IP network registered'


def test_earliest_crt_sh_certificate_is_used_if_present():
    data = {
        'crt': {
            'status': 'SUCCESS',
            'data': {'subdomains': [], 'earliest_certificate': {'not_before': '2014-06-01T00:00:00'}},
        }
    }
    (event,) = build_correlations('example.com', data)['timeline']
    assert event['date'] == '2014-06-01T00:00:00' and event['platform'] == 'crt.sh'
    assert event['source'] == 'crt: earliest_certificate'


def test_exif_timestamps_apply_the_offset_and_skip_zeroed_fields():
    timeline = build_correlations('IMG_0001.jpg', EXIF)['timeline']
    events = {e['event']: e for e in timeline}
    assert events['Photo taken (EXIF DateTimeOriginal)']['date'] == '2023-05-01T10:34:56Z'  # 12:34:56 +02:00
    assert 'Image digitized (EXIF)' in events
    assert not any('modified' in e['event'] for e in timeline)
    assert all(e['platform'] == 'Image EXIF' for e in timeline)


def test_exif_without_offset_keeps_local_time_without_inventing_a_zone():
    data = json.loads(json.dumps(EXIF))
    data['exif']['data']['timestamps']['offset'] = None
    events = {e['event']: e['date'] for e in build_correlations('x.jpg', data)['timeline']}
    assert events['Photo taken (EXIF DateTimeOriginal)'] == '2023-05-01T12:34:56'


def test_wallet_first_and_last_seen():
    timeline = build_correlations('0x52908400098527886E0F7030069857D2E4169EE7', WALLET)['timeline']
    assert [(e['date'], e['event']) for e in timeline] == [
        ('2021-01-01T00:00:00Z', 'First on-chain transaction'),
        ('2024-02-03T04:05:06Z', 'Most recent on-chain transaction'),
    ]
    assert timeline[0]['platform'] == 'ETH (blockscout)'


def test_everything_merges_into_one_sorted_timeline():
    results = {**USERNAME, **RDAP, **EXIF, **WALLET}
    dates = [e['date'][:10] for e in build_correlations('jroe', results)['timeline']]
    assert dates == sorted(dates)


def test_no_dates_means_empty_timeline_and_zero_coverage():
    corr = build_correlations('example.com', {})
    assert corr['timeline'] == []
    assert corr['timeline_coverage'] == {'platforms_with_dates': 0, 'platforms_found': 0}


def test_malformed_dates_are_dropped_not_guessed():
    data = {
        'r': {'status': 'SUCCESS', 'data': {'events': {'registration': 'yesterday', 'expiration': 12, 'x': None}}},
        'w': {'status': 'SUCCESS', 'data': {'address': 'x', 'chain': 'btc', 'first_seen': True, 'last_seen': -5}},
    }
    assert build_correlations('example.com', data)['timeline'] == []


# --- report rendering ---


def test_markdown_states_coverage_so_it_never_reads_as_complete(tmp_path):
    lines = format_timeline_lines(build_correlations('jroe', USERNAME))
    text = '\n'.join(lines)
    assert text.startswith('## Timeline')
    assert '4 of 6 platforms where the username was found exposed a date' in text
    assert 'not a complete history' in text
    assert (
        '| 2015-03-02T10:00:00Z | GitHub | Account created | username_check: platforms.github.profile.created_at |'
        in (text)
    )


def test_markdown_timeline_section_in_report(tmp_path):
    out = tmp_path / 'r.md'
    ReportGenerator().generate_markdown({**USERNAME, **RDAP}, 'jroe', 'username', str(out))
    text = out.read_text(encoding='utf-8')
    assert '## Timeline' in text and text.index('## Timeline') < text.index('## Results')


def test_json_report_carries_timeline_and_coverage(tmp_path):
    out = tmp_path / 'r.json'
    ReportGenerator().generate_json(USERNAME, 'jroe', 'username', str(out))
    corr = json.loads(out.read_text(encoding='utf-8'))['correlations']
    assert [e['platform'] for e in corr['timeline']] == ['Hacker News', 'GitHub', 'Keybase', 'Dev.to']
    assert corr['timeline_coverage'] == {'platforms_with_dates': 4, 'platforms_found': 6}


def test_markdown_timeline_without_username_data_still_warns(tmp_path):
    text = '\n'.join(format_timeline_lines(build_correlations('example.com', RDAP)))
    assert 'not a complete history' in text and 'platforms where the username was found' not in text


def test_markdown_timeline_escapes_table_pipes():
    corr = {'timeline': [{'date': '2020-01-01', 'platform': 'a|b', 'event': 'x', 'source': 's'}]}
    assert '| 2020-01-01 | a\\|b | x | s |' in '\n'.join(format_timeline_lines(corr))


def test_timeline_strings_pass_through_the_privacy_guard():
    data = {
        'u': {'status': 'SUCCESS', 'data': {'platforms': {'g': _platform('me@example.com', '2015-01-01T00:00:00Z')}}}
    }
    corr = ReportGenerator().correlations(data, 'jroe')
    assert corr['timeline'][0]['platform'] == '[REDACTED]'
