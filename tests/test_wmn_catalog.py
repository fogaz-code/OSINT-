"""WhatsMyName adapter: local file only, strict validation, safe URIs, always calibrated."""

import ast
import inspect
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

from secure_osint.sources import wmn_catalog
from secure_osint.sources.base import SourceUnavailable
from secure_osint.sources.username_source import PLATFORMS, SOFT_404_MSG, UsernameSource
from secure_osint.sources.wmn_catalog import (
    MAX_FILE_BYTES,
    WMN_ENV,
    WmnCatalogError,
    host_key,
    load_wmn_catalog,
    resolve_wmn_path,
)
from tests.test_sources import ok
from tests.test_username import ScriptedClient, _all_absent, only_for


def _site(name='Example', **overrides):
    site = {
        'name': name,
        'uri_check': f'https://{name.lower()}.example.net/api/users/{{account}}',
        'uri_pretty': f'https://{name.lower()}.example.net/@{{account}}',
        'e_code': 200,
        'e_string': '"username":',
        'm_code': 404,
        'm_string': 'Not Found',
        'known': ['someone'],
        'cat': 'social',
    }
    site.update(overrides)
    return site


def _write(tmp_path, sites, **top):
    doc = {'license': ['CC BY-SA 4.0'], 'authors': ['x'], 'categories': ['social'], 'sites': sites, **top}
    path = tmp_path / 'wmn-data.json'
    path.write_text(json.dumps(doc), encoding='utf-8')
    return path


# --- loading and validation ---


def test_valid_site_is_mapped_with_its_signatures(tmp_path):
    catalog = load_wmn_catalog(_write(tmp_path, [_site('Forum')]))
    assert len(catalog.entries) == 1
    entry = catalog.entries[0]
    assert entry.key == 'wmn_forum' and entry.label == 'Forum'
    assert entry.check_url('alice') == 'https://forum.example.net/api/users/alice'
    assert entry.profile_url('alice') == 'https://forum.example.net/@alice'
    assert (entry.exists_code, entry.exists_string, entry.missing_code, entry.missing_string) == (
        200,
        '"username":',
        404,
        'Not Found',
    )
    assert catalog.info['name'] == 'WhatsMyName'
    assert catalog.info['license'] == 'CC BY-SA 4.0'
    assert catalog.info['project'] == 'https://github.com/WebBreacher/WhatsMyName'
    assert catalog.info['loaded'] == 1 and catalog.info['sites_in_file'] == 1
    assert len(catalog.info['sha256']) == 64


def test_the_local_path_is_never_reported(tmp_path):
    catalog = load_wmn_catalog(_write(tmp_path, [_site()]))
    assert str(tmp_path) not in json.dumps(catalog.info)


@pytest.mark.parametrize(
    'override,reason',
    [
        ({'post_body': '{"q": "{account}"}'}, 'post_body'),
        ({'headers': {'X-Requested-With': 'XMLHttpRequest'}}, 'custom_headers'),
        ({'cat': 'XX NSFW XX'}, 'nsfw'),
        ({'uri_check': 'http://plain.example.net/{account}'}, 'unsafe_uri'),
        ({'uri_check': 'https://example.net/profile'}, 'unsafe_uri'),  # no {account} placeholder
        ({'uri_check': 'https://user:pw@example.net/{account}'}, 'unsafe_uri'),
        ({'uri_check': 'https://example.net:8443/{account}'}, 'unsafe_uri'),
        ({'uri_check': 'https://10.0.0.1/{account}'}, 'unsafe_uri'),
        ({'uri_check': 'https://[::1]/{account}'}, 'unsafe_uri'),
        ({'uri_check': 'file:///etc/passwd?{account}'}, 'unsafe_uri'),
        ({'uri_check': 'https://example.net/{account} x'}, 'unsafe_uri'),
        ({'e_code': '200'}, 'invalid'),  # strict: no string -> int coercion
        ({'e_code': True}, 'invalid'),
        ({'e_string': ''}, 'invalid'),  # an empty signature matches every page: the classic false positive
        ({'m_code': 99}, 'invalid'),
        ({'name': ''}, 'invalid'),
        ({'valid': False}, 'disabled'),
        ({'uri_check': 'https://www.instagram.com/{account}/'}, 'auth_required'),
        ({'uri_check': 'https://twitter.com/{account}'}, 'auth_required'),
        ({'uri_check': 'https://m.facebook.com/{account}'}, 'auth_required'),
        ({'uri_check': 'https://www.linkedin.com/in/{account}'}, 'auth_required'),
    ],
)
def test_unsafe_or_unsupported_entries_are_skipped(tmp_path, override, reason):
    bad = _site('Bad')
    bad.update(override)
    catalog = load_wmn_catalog(_write(tmp_path, [bad, _site('Good')]))
    assert [e.key for e in catalog.entries] == ['wmn_good']
    assert catalog.info['skipped'] == {reason: 1}


def test_nsfw_can_be_opted_in(tmp_path):
    path = _write(tmp_path, [_site('Adult', cat='XX NSFW XX')])
    assert load_wmn_catalog(path).entries == ()
    assert [e.key for e in load_wmn_catalog(path, include_nsfw=True).entries] == ['wmn_adult']


def test_entries_whose_host_is_already_covered_are_deduplicated(tmp_path):
    sites = [
        _site('GitHub', uri_check='https://github.com/{account}', uri_pretty='https://github.com/{account}'),
        _site('Tumblr', uri_check='https://{account}.tumblr.com', uri_pretty=None),
        _site('Fresh'),
    ]
    excluded = {host_key(p.profile_url) for p in PLATFORMS.values()}
    catalog = load_wmn_catalog(_write(tmp_path, sites), exclude_hosts=excluded)
    assert [e.key for e in catalog.entries] == ['wmn_fresh']
    assert catalog.info['skipped'] == {'duplicate_host': 2}


def test_host_key_normalises_www_and_per_user_subdomains():
    assert host_key('https://www.github.com/{u}') == 'github.com'
    assert host_key('https://{u}.tumblr.com/') == 'tumblr.com'
    assert host_key('https://api.github.com/users/{u}') == 'api.github.com'
    assert host_key('https://{account}.carrd.co') == 'carrd.co'


def test_duplicate_names_get_distinct_keys(tmp_path):
    sites = [
        _site('Same', uri_check='https://a.example.net/{account}'),
        _site('Same', uri_check='https://b.example.net/{account}'),
    ]
    keys = [e.key for e in load_wmn_catalog(_write(tmp_path, sites)).entries]
    assert keys == ['wmn_same', 'wmn_same_2']


def test_same_host_twice_in_the_file_is_kept_once(tmp_path):
    sites = [
        _site('One', uri_check='https://dup.example.net/{account}'),
        _site('Two', uri_check='https://dup.example.net/u/{account}'),
    ]
    catalog = load_wmn_catalog(_write(tmp_path, sites))
    assert [e.key for e in catalog.entries] == ['wmn_one']
    assert catalog.info['skipped'] == {'duplicate_host': 1}


def test_account_placeholder_is_url_encoded_and_other_braces_are_literal(tmp_path):
    site = _site('Braces', uri_check='https://braces.example.net/search?q={account}&f={"x":1}')
    entry = load_wmn_catalog(_write(tmp_path, [site])).entries[0]
    assert entry.check_url('a.b_c') == 'https://braces.example.net/search?q=a.b_c&f={"x":1}'
    assert entry.check_url('we ird/../x') == 'https://braces.example.net/search?q=we%20ird%2F..%2Fx&f={"x":1}'


def test_strip_bad_char_is_honoured(tmp_path):
    entry = load_wmn_catalog(_write(tmp_path, [_site('Strip', strip_bad_char='.')])).entries[0]
    assert entry.check_url('a.b') == 'https://strip.example.net/api/users/ab'


def test_invalid_pretty_uri_falls_back_to_the_check_uri(tmp_path):
    entry = load_wmn_catalog(_write(tmp_path, [_site('Pretty', uri_pretty='javascript:alert({account})')])).entries[0]
    assert entry.profile_url('alice') == entry.check_url('alice')


def test_label_is_sanitised(tmp_path):
    site = _site('<b>Evil</b>\x07 Site', uri_check='https://evil.example.net/{account}')
    entry = load_wmn_catalog(_write(tmp_path, [site])).entries[0]
    assert entry.label == 'Evil Site' and '<' not in entry.label
    assert entry.key == 'wmn_evil_site'


@pytest.mark.parametrize(
    'content',
    [b'not json', b'[]', b'{"sites": "nope"}', b'{"nosites": []}', b'[' * 100_000 + b']' * 100_000],
    ids=['not-json', 'list', 'sites-not-list', 'no-sites', 'deep-nesting'],
)
def test_malformed_files_are_rejected_without_echoing_content(tmp_path, content):
    path = tmp_path / 'wmn-data.json'
    path.write_bytes(content)
    with pytest.raises(WmnCatalogError) as err:
        load_wmn_catalog(path)
    assert isinstance(err.value, SourceUnavailable)
    assert str(tmp_path) not in str(err.value)
    assert 'nope' not in str(err.value)


def test_oversized_file_is_rejected(tmp_path):
    path = tmp_path / 'wmn-data.json'
    path.write_bytes(b' ' * (MAX_FILE_BYTES + 1))
    with pytest.raises(WmnCatalogError, match='too large'):
        load_wmn_catalog(path)


@pytest.mark.parametrize('kind', ['missing', 'directory'])
def test_missing_or_non_regular_file_is_rejected(tmp_path, kind):
    path = tmp_path / 'nothere.json'
    if kind == 'directory':
        path.mkdir()
    with pytest.raises(WmnCatalogError):
        load_wmn_catalog(path)


def test_too_many_sites_is_rejected(tmp_path):
    path = _write(tmp_path, [_site(f'S{i}', uri_check=f'https://s{i}.example.net/{{account}}') for i in range(3)])
    with pytest.raises(WmnCatalogError, match='too many'):
        load_wmn_catalog(path, max_sites=2)


def test_resolve_path_param_then_env(tmp_path, monkeypatch):
    monkeypatch.delenv(WMN_ENV, raising=False)
    assert resolve_wmn_path(None) is None
    assert resolve_wmn_path('') is None
    monkeypatch.setenv(WMN_ENV, str(tmp_path / 'env.json'))
    assert resolve_wmn_path(None) == tmp_path / 'env.json'
    assert resolve_wmn_path(str(tmp_path / 'param.json')) == tmp_path / 'param.json'
    with pytest.raises(WmnCatalogError):
        resolve_wmn_path(['not', 'a', 'path'])


def test_the_catalog_module_never_touches_the_network():
    # Supply chain: the dataset is user-supplied and local. The adapter must not be able to download it.
    tree = ast.parse(inspect.getsource(wmn_catalog))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or '')
    forbidden = {'httpx', 'requests', 'urllib.request', 'http.client', 'socket', 'secure_osint.utils.http_client'}
    assert not imported & forbidden
    assert 'client' not in inspect.signature(load_wmn_catalog).parameters


# --- integration with the username sweep ---


# A second, always-absent site: a sweep where NO platform could be determined is (rightly) an error.
_ANCHOR = _site('Anchor', uri_check='https://anchor.example.org/{account}', uri_pretty=None)
_ANCHOR_HOST = 'anchor.example.org'


def _wmn_sweep(tmp_path, sites, by_host, platform_set='wmn', **params):
    path = _write(tmp_path, [*sites, _ANCHOR])
    client = ScriptedClient({_ANCHOR_HOST: ok('Not Found', 404), **by_host})
    data = UsernameSource(client).fetch(
        {'input': 'alice', 'platform_set': platform_set, 'wmn_path': str(path), **params}
    )
    return data, client


def test_wmn_hit_is_calibrated_and_medium_at_most(tmp_path):
    by = {'forum.example.net': only_for('alice', ok('{"username": "alice"}'), ok('Not Found', 404))}
    data, client = _wmn_sweep(tmp_path, [_site('Forum')], by)
    entry = data['platforms']['wmn_forum']
    assert entry['exists'] is True and entry['confidence'] == 'MEDIUM'
    assert entry['calibration'] == 'passed' and entry['error_kind'] is None
    assert entry['url'] == 'https://forum.example.net/@alice' and entry['label'] == 'Forum'
    assert entry['catalog'] == 'wmn'
    assert len([u for u in client.urls_called if 'forum.example.net' in u]) == 2  # target + control probe
    assert data['platform_set'] == 'wmn'
    assert data['catalog']['license'] == 'CC BY-SA 4.0' and data['catalog']['loaded'] == 2


def test_wmn_signature_that_matches_everyone_is_a_soft_404(tmp_path):
    # The WMN false-positive class: the "exists" signature also matches a username that cannot exist.
    by = {'forum.example.net': ok('{"username": "whoever"}')}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum')], by)
    entry = data['platforms']['wmn_forum']
    assert entry['exists'] is None and entry['confidence'] == 'MANUAL'
    assert entry['error'] == SOFT_404_MSG and entry['calibration'] == 'soft404'


def test_wmn_missing_signature_means_absent(tmp_path):
    by = {'forum.example.net': ok('Not Found', 404)}
    data, client = _wmn_sweep(tmp_path, [_site('Forum')], by)
    assert data['platforms']['wmn_forum']['exists'] is False
    assert len([u for u in client.urls_called if 'forum' in u]) == 1  # absent: no control probe needed


def test_wmn_existence_needs_both_code_and_string(tmp_path):
    by = {'forum.example.net': ok('<html>some unrelated page</html>', 200)}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum')], by)
    entry = data['platforms']['wmn_forum']
    assert entry['exists'] is None and entry['confidence'] == 'MANUAL'
    assert entry['error_kind'] == 'other'


def test_wmn_string_match_is_case_sensitive_like_upstream(tmp_path):
    by = {'forum.example.net': ok('{"USERNAME": "alice"}', 200)}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum')], by)
    assert data['platforms']['wmn_forum']['exists'] is None


def test_wmn_only_set_keeps_the_manual_platforms_and_skips_builtins(tmp_path):
    by = {'forum.example.net': ok('Not Found', 404)}
    data, client = _wmn_sweep(tmp_path, [_site('Forum')], by)
    assert set(data['platforms']) == {'wmn_forum', 'wmn_anchor', 'linkedin', 'instagram', 'facebook', 'x'}
    assert {urlparse(u).hostname for u in client.urls_called} == {'forum.example.net', _ANCHOR_HOST}
    assert data['stats']['automated'] == 2


def test_all_set_merges_builtins_and_deduplicated_wmn(tmp_path):
    sites = [_site('GitHub', uri_check='https://github.com/{account}', uri_pretty=None), _site('Forum')]
    by = _all_absent()
    by['forum.example.net'] = ok('Not Found', 404)
    data, client = _wmn_sweep(tmp_path, sites, by, platform_set='all')
    assert set(PLATFORMS) < set(data['platforms'])
    assert 'wmn_forum' in data['platforms'] and 'wmn_github' not in data['platforms']
    assert 'github.com' not in {urlparse(u).hostname for u in client.urls_called}
    assert data['catalog']['skipped'] == {'duplicate_host': 1}
    assert list(data['platforms'])[: len(PLATFORMS)] == list(PLATFORMS)  # builtins first, stable order


def test_wmn_never_sends_post_or_custom_headers(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'ghp_' + 'z' * 36)
    sites = [_site('Forum'), _site('Poster', post_body='{"u":"{account}"}'), _site('Hdr', headers={'X-A': 'b'})]
    by = {'forum.example.net': ok('Not Found', 404)}
    data, client = _wmn_sweep(tmp_path, sites, by)
    assert client.posted == []
    assert all(not headers for headers in client.headers_by_url.values())
    assert set(data['platforms']) - {'linkedin', 'instagram', 'facebook', 'x'} == {'wmn_forum', 'wmn_anchor'}


def test_wmn_path_from_env(tmp_path, monkeypatch):
    path = _write(tmp_path, [_site('Forum')])
    monkeypatch.setenv(WMN_ENV, str(path))
    data = UsernameSource(ScriptedClient({'forum.example.net': ok('Not Found', 404)})).fetch(
        {'input': 'alice', 'platform_set': 'wmn'}
    )
    assert data['platforms']['wmn_forum']['exists'] is False


def test_wmn_without_a_configured_file_fails_before_any_request(monkeypatch):
    monkeypatch.delenv(WMN_ENV, raising=False)
    client = ScriptedClient({})
    with pytest.raises(SourceUnavailable, match='never downloaded'):
        UsernameSource(client).fetch({'input': 'alice', 'platform_set': 'wmn'})
    assert client.hosts_called == []


def test_wmn_bad_file_fails_before_any_request(tmp_path):
    path = Path(tmp_path / 'wmn-data.json')
    path.write_text('nope', encoding='utf-8')
    client = ScriptedClient({})
    with pytest.raises(SourceUnavailable):
        UsernameSource(client).fetch({'input': 'alice', 'platform_set': 'wmn', 'wmn_path': str(path)})
    assert client.hosts_called == []


def test_builtin_set_ignores_a_configured_wmn_file(tmp_path, monkeypatch):
    monkeypatch.setenv(WMN_ENV, str(tmp_path / 'does-not-exist.json'))
    data = UsernameSource(ScriptedClient(_all_absent())).fetch({'input': 'alice'})
    assert set(data['platforms']) == set(PLATFORMS)


def test_wmn_include_nsfw_param(tmp_path):
    sites = [_site('Adult', cat='XX NSFW XX')]
    by = {'adult.example.net': ok('Not Found', 404)}
    data, _ = _wmn_sweep(tmp_path, sites, by, wmn_include_nsfw=True)
    assert 'wmn_adult' in data['platforms']
    with pytest.raises(SourceUnavailable):
        _wmn_sweep(tmp_path, sites, by, wmn_include_nsfw='yes')


def test_wmn_server_error_is_an_http_status_failure(tmp_path):
    by = {'forum.example.net': ok('oops', 502)}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum')], by)
    entry = data['platforms']['wmn_forum']
    assert entry['exists'] is None and entry['error_kind'] == 'http_status'


def test_wmn_missing_code_403_is_read_as_missing_not_an_auth_wall(tmp_path):
    by = {'forum.example.net': ok('No such user', 403)}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum', m_code=403, m_string='No such user')], by)
    assert data['platforms']['wmn_forum']['exists'] is False


def test_wmn_rate_limit_is_classified(tmp_path):
    by = {'forum.example.net': ok('', 429)}
    data, _ = _wmn_sweep(tmp_path, [_site('Forum')], by)
    assert data['platforms']['wmn_forum']['error_kind'] == 'rate_limited'


def test_wmn_hosts_never_receive_the_github_token(tmp_path, monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'ghp_' + 'q' * 36)
    site = _site('Gh', uri_check='https://gh.example.net/api.github.com/{account}')
    by = {'gh.example.net': ok('Not Found', 404)}
    _, client = _wmn_sweep(tmp_path, [site], by)
    assert not any(client.headers_by_url.values())


# --- product rule: no registration / availability oracles ---

# Real check URIs from the upstream wmn-data.json that ask a signup or username-availability API.
REGISTRATION_PROBES = [
    'https://auth.roblox.com/v1/usernames/validate?username={account}&birthday=2019-12-31T23:00:00.000Z',
    'https://www.minds.com/api/v3/register/validate?username={account}',
    'https://issuu.com/call/signup/v2/check-username/{account}',
    'https://login.wordpress.org/wp-json/wporg/v1/username-available/{account}',
    'https://wikimapia.org/user/register/?check=username&value={account}',
    'https://www.wishlistr.com/sign-up/?rs=checkUserName&rsargs[]={account}',
    'https://quizlet.com/webapi/3.2/users/check-username?username={account}',
    'https://api.scratch.mit.edu/accounts/checkusername/{account}/',
    'https://boardgamegeek.com/api/accounts/validate/username?username={account}',
    'https://otx.alienvault.com/otxapi/auth/validate?username={account}',
    'https://znanija.com/graphql/ru?op=NickAvailability&nick={account}',
    'https://example.net/api/user-exists/{account}',
    'https://example.net/password/reset?user={account}',
    'https://example.net/account/recover?login={account}',
]


@pytest.mark.parametrize('uri', REGISTRATION_PROBES)
def test_registration_and_availability_endpoints_are_skipped(tmp_path, uri):
    catalog = load_wmn_catalog(_write(tmp_path, [_site('Probe', uri_check=uri), _site('Good')]))
    assert [e.key for e in catalog.entries] == ['wmn_good']
    assert catalog.info['skipped'] == {'registration_probe': 1}


@pytest.mark.parametrize(
    'uri',
    [
        'https://www.authorstream.com/{account}/',  # 'auth' inside a word is not an auth host
        'https://registry.npmjs.org/-/user/org.couchdb.user:{account}',  # 'registry' is not 'register'
        'https://example.net/api/users/{account}',
        'https://{account}.example.net/',
    ],
)
def test_ordinary_profile_endpoints_are_not_mistaken_for_probes(tmp_path, uri):
    catalog = load_wmn_catalog(_write(tmp_path, [_site('Fine', uri_check=uri)]))
    assert [e.key for e in catalog.entries] == ['wmn_fine']
