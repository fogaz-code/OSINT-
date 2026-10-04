import threading
from urllib.parse import urlparse

import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.workflow import load_workflow_from_file
from secure_osint.sources.base import SourceError, SourceUnavailable, TransientSourceError
from secure_osint.sources.username_source import (
    AUTH_REQUIRED,
    AUTH_REQUIRED_MSG,
    BLOCK_CODES,
    RATE_LIMITED_MSG,
    SOFT_404_MSG,
    UsernameSource,
)
from tests.test_sources import ok


class ScriptedClient:
    """Answers per host (response or exception), so tests do not depend on request order.

    Thread-safe: the sweep runs platform checks concurrently.
    """

    def __init__(self, by_host: dict):
        self.by_host = by_host
        self.hosts_called: list = []
        self.urls_called: list = []
        self.headers_by_url: dict = {}
        self.timeouts: list = []
        self.posted: list = []
        self._lock = threading.Lock()

    def get(self, url, params=None, headers=None, timeout=None):
        host = urlparse(url).hostname or ''
        with self._lock:
            self.hosts_called.append(host)
            self.urls_called.append(url)
            self.headers_by_url[url] = dict(headers or {})
            self.timeouts.append(timeout)
        outcome = self.by_host.get(host)
        if outcome is None:
            # Piattaforme con sottodominio per utente (tumblr.com, carrd.co): registrate nel test
            # dal dominio base, così la stessa entry risponde sia per lo username reale sia per
            # quello di controllo (calibrazione), che finiscono su sottodomini diversi.
            for registered, value in self.by_host.items():
                if host.endswith('.' + registered):
                    outcome = value
                    break
        if callable(outcome):  # risposta che dipende dall'URL (es. username vero vs di controllo)
            outcome = outcome(url)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome is None:
            raise AssertionError(f'unexpected request to {host}')
        return outcome

    def post(self, url, content, headers=None, timeout=None):
        with self._lock:
            self.posted.append((url, content))
        return self.get(url, headers=headers, timeout=timeout)


def xmlrpc_packages(packages):
    """A PyPI XML-RPC `user_packages` response body."""
    import xmlrpc.client

    return ok(xmlrpc.client.dumps((packages,), methodresponse=True))


def only_for(username, found, absent):
    """Answer `found` for the real username and `absent` for anything else (the calibration probe)."""
    return lambda url: found if username in url else absent


# Le piattaforme che vengono davvero interrogate (le auth-required non generano richieste).
_AUTOMATED = (
    'api.github.com',
    'keybase.io',
    'www.reddit.com',
    'hacker-news.firebaseio.com',
    't.me',
    'www.tiktok.com',
    'www.pinterest.com',
    'gitlab.com',
    'api.bitbucket.org',
    'medium.com',
    'dev.to',
    'api.stackexchange.com',
    'codepen.io',
    'hub.docker.com',
    'pypi.org',
    'hackaday.io',
    'mastodon.social',
    'about.me',
    'sourceforge.net',
    'tumblr.com',
    'profiles.wordpress.org',
    'gravatar.com',
    'soundcloud.com',
    'www.flickr.com',
    'linktr.ee',
    'carrd.co',
)


def _all_absent():
    return {
        'api.github.com': ok('', 404),
        'www.reddit.com': ok('', 404),
        'www.tiktok.com': ok('', 404),
        'www.pinterest.com': ok('', 404),
        'keybase.io': ok({'them': []}),
        'hacker-news.firebaseio.com': ok('null'),
        't.me': ok('generic page'),
        'gitlab.com': ok([]),
        'api.bitbucket.org': ok('', 404),
        'medium.com': ok('', 404),
        'dev.to': ok('', 404),
        'api.stackexchange.com': ok({'total': 0}),
        'codepen.io': ok('', 404),
        'hub.docker.com': ok('', 404),
        'pypi.org': xmlrpc_packages([]),
        'hackaday.io': ok('', 404),
        'mastodon.social': ok('', 404),
        'about.me': ok('', 404),
        'sourceforge.net': ok('', 404),
        'tumblr.com': ok('', 404),
        'profiles.wordpress.org': ok('', 404),
        'gravatar.com': ok('', 404),
        'soundcloud.com': ok('', 404),
        'www.flickr.com': ok('', 404),
        'linktr.ee': ok('', 404),
        'carrd.co': ok('', 404),
    }


def _run(by_host, username='alice'):
    client = ScriptedClient(by_host)
    return UsernameSource(client).fetch({'input': username}), client


def test_platform_set_and_auth_required_group():
    assert set(UsernameSource.PLATFORMS) == {
        'github',
        'keybase',
        'reddit',
        'hackernews',
        'telegram',
        'tiktok',
        'pinterest',
        'gitlab',
        'bitbucket',
        'medium',
        'devto',
        'stackoverflow',
        'codepen',
        'dockerhub',
        'pypi',
        'hackaday',
        'mastodon',
        'aboutme',
        'sourceforge',
        'tumblr',
        'wordpress',
        'gravatar',
        'soundcloud',
        'flickr',
        'linktree',
        'carrd',
        'linkedin',
        'instagram',
        'facebook',
        'x',
    }
    assert AUTH_REQUIRED == {'linkedin', 'instagram', 'facebook', 'x'}


@pytest.mark.parametrize('value', ['../orgs/x', 'a/b', 'has space', 'quote"', '', 'x' * 40])
def test_invalid_username_rejected_without_request(value):
    client = ScriptedClient({})
    with pytest.raises(SourceUnavailable):
        UsernameSource(client).fetch({'input': value})
    assert client.hosts_called == []


def test_auth_required_platforms_never_requested_and_report_manual():
    data, client = _run(_all_absent())
    # Nessuna richiesta verso i domini auth-required: niente scraping, niente workaround.
    for host in ('www.linkedin.com', 'www.instagram.com', 'www.facebook.com', 'x.com'):
        assert host not in client.hosts_called
    for name in AUTH_REQUIRED:
        entry = data['platforms'][name]
        assert entry['exists'] is None
        assert entry['error'] == AUTH_REQUIRED_MSG
    assert set(data['needs_manual']) == AUTH_REQUIRED


def test_status_found_and_not_found():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    by['www.tiktok.com'] = only_for('alice', ok('profile', 200), ok('', 404))
    data, _ = _run(by)
    assert data['platforms']['github']['exists'] is True
    assert data['platforms']['github']['confidence'] == 'HIGH'  # JSON API
    assert data['platforms']['tiktok']['exists'] is True
    assert data['platforms']['tiktok']['confidence'] == 'MEDIUM'  # web page, calibrated
    assert data['platforms']['reddit']['exists'] is False
    assert data['platforms']['github']['url'] == 'https://github.com/alice'
    assert data['platforms']['tiktok']['url'] == 'https://www.tiktok.com/@alice'


def test_keybase_hackernews_telegram_semantics():
    by = _all_absent()
    by['keybase.io'] = ok({'them': [{'id': '1'}]})
    by['hacker-news.firebaseio.com'] = ok({'id': 'alice'})
    by['t.me'] = only_for('alice', ok('<div class="tgme_page_title">Alice</div>'), ok('<html>no profile</html>'))
    data, _ = _run(by)
    assert data['platforms']['keybase']['exists'] is True
    assert data['platforms']['hackernews']['exists'] is True
    assert data['platforms']['telegram']['exists'] is True
    # telegram: 200 senza marcatore => assente (t.me risponde 200 anche per handle inesistenti)
    by['t.me'] = ok('<html>no profile block</html>')
    data2, _ = _run(by)
    assert data2['platforms']['telegram']['exists'] is False


@pytest.mark.parametrize('code', sorted(BLOCK_CODES - {429}))
def test_blocked_status_platform_is_unavailable(code):
    by = _all_absent()
    by['www.tiktok.com'] = ok('', code)
    data, _ = _run(by)
    entry = data['platforms']['tiktok']
    assert entry['exists'] is None
    assert entry['error'] == f'Blocked by platform (HTTP {code})'
    assert entry['error_kind'] == 'blocked'


def test_http_429_is_rate_limited_not_blocked():
    by = _all_absent()
    by['www.tiktok.com'] = ok('', 429)
    data, _ = _run(by)
    entry = data['platforms']['tiktok']
    assert entry['exists'] is None and entry['confidence'] == 'MANUAL'
    assert entry['error'] == RATE_LIMITED_MSG
    assert entry['error_kind'] == 'rate_limited'


def test_request_error_and_unexpected_status_are_notes():
    by = _all_absent()
    by['api.github.com'] = SourceError('boom')
    data, _ = _run(by)
    assert data['platforms']['github'] == {
        'exists': None,
        'error': 'Request failed.',
        'url': 'https://github.com/alice',
        'exact': True,
        'label': 'GitHub',
        'confidence': 'MANUAL',
        'calibration': 'not_applicable',
        'error_kind': 'other',
    }
    by['api.github.com'] = ok('', 500)
    data2, _ = _run(by)
    assert data2['platforms']['github']['error'] == 'Unexpected HTTP 500'
    assert data2['platforms']['github']['error_kind'] == 'http_status'


def test_summary_counts():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    by['www.pinterest.com'] = only_for('alice', ok('p', 200), ok('', 404))
    data, _ = _run(by)
    assert data['profiles_found'] == 2  # github, pinterest
    assert data['checked'] == len(_AUTOMATED)  # tutte le automatiche interrogate
    assert data['username'] == 'alice'


def test_all_automated_unavailable_raises_transient():
    by = {h: ok('', 403) for h in _AUTOMATED}
    with pytest.raises(TransientSourceError):
        _run(by)


def test_username_in_workflow():
    types = [s.type for s in load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/username.yaml').steps]
    assert 'username' in types


def test_new_platforms_found():
    by = _all_absent()
    by['gitlab.com'] = ok([{'id': 1, 'username': 'alice'}])  # non-empty JSON list => found
    by['api.bitbucket.org'] = ok({'username': 'alice'}, 200)  # 200 => found
    by['medium.com'] = only_for('alice', ok('<html>profile</html>'), ok('', 404))  # calibrated web page
    by['dev.to'] = ok({'id': 7, 'username': 'alice'}, 200)  # 200 => found
    by['api.stackexchange.com'] = ok({'total': 3})  # total>0 => found
    data, _ = _run(by)
    p = data['platforms']
    assert p['gitlab']['exists'] is True and p['gitlab']['url'] == 'https://gitlab.com/alice'
    assert p['bitbucket']['exists'] is True
    assert p['medium']['exists'] is True and p['medium']['url'] == 'https://medium.com/@alice'
    assert p['devto']['exists'] is True and p['devto']['url'] == 'https://dev.to/alice'
    assert p['stackoverflow']['exists'] is True


def test_new_platforms_absent():
    data, _ = _run(_all_absent())
    for name in ('gitlab', 'bitbucket', 'medium', 'devto', 'stackoverflow'):
        assert data['platforms'][name]['exists'] is False, name


def test_gitlab_and_stackoverflow_json_edge_cases():
    by = _all_absent()
    by['gitlab.com'] = ok('not-a-list', 200)  # unexpected shape => unknown, not a crash
    by['api.stackexchange.com'] = ok({}, 200)  # missing 'total' => treated as 0 => absent
    data, _ = _run(by)
    assert data['platforms']['gitlab']['exists'] is None
    assert data['platforms']['stackoverflow']['exists'] is False


@pytest.mark.parametrize(
    'name,host',
    [
        ('gitlab', 'gitlab.com'),
        ('bitbucket', 'api.bitbucket.org'),
        ('medium', 'medium.com'),
        ('devto', 'dev.to'),
        ('stackoverflow', 'api.stackexchange.com'),
    ],
)
def test_new_platforms_blocked_are_unavailable(name, host):
    by = _all_absent()
    by[host] = ok('', 429)
    data, _ = _run(by)
    assert data['platforms'][name]['exists'] is None
    assert data['platforms'][name]['error'] == RATE_LIMITED_MSG
    assert data['platforms'][name]['error_kind'] == 'rate_limited'


def test_curated_platforms_found():
    by = _all_absent()
    page = only_for('alice', ok('<html>profile</html>'), ok('', 404))  # 200 for alice, 404 for the probe
    by['codepen.io'] = page
    by['hub.docker.com'] = ok({'username': 'alice'}, 200)
    by['pypi.org'] = xmlrpc_packages([['Owner', 'alice-tools']])
    by['hackaday.io'] = page
    by['mastodon.social'] = page
    by['about.me'] = page
    by['sourceforge.net'] = page
    data, _ = _run(by)
    p = data['platforms']
    assert p['codepen'] == {
        'exists': True,
        'error': None,
        'url': 'https://codepen.io/alice',
        'exact': True,
        'label': 'CodePen',
        'confidence': 'MEDIUM',
        'calibration': 'passed',
        'error_kind': None,
    }
    assert p['dockerhub']['exists'] is True and p['dockerhub']['url'] == 'https://hub.docker.com/u/alice'
    assert p['pypi']['exists'] is True and p['pypi']['url'] == 'https://pypi.org/user/alice/'
    assert p['hackaday']['exists'] is True and p['hackaday']['url'] == 'https://hackaday.io/alice'
    assert p['mastodon']['exists'] is True and p['mastodon']['url'] == 'https://mastodon.social/@alice'
    assert p['aboutme']['exists'] is True and p['aboutme']['url'] == 'https://about.me/alice'
    assert p['sourceforge']['exists'] is True and p['sourceforge']['url'] == 'https://sourceforge.net/u/alice/'


def test_curated_platforms_absent():
    data, _ = _run(_all_absent())
    for name in ('codepen', 'dockerhub', 'pypi', 'hackaday', 'mastodon', 'aboutme', 'sourceforge'):
        assert data['platforms'][name]['exists'] is False, name


@pytest.mark.parametrize('code', [401, 403])
def test_curated_platform_auth_wall_is_manual(code):
    # Rule 6: a curated public platform that starts returning 401/403 => manual verification.
    by = _all_absent()
    by['codepen.io'] = ok('', code)
    data, _ = _run(by)
    entry = data['platforms']['codepen']
    assert entry['exists'] is None
    assert entry['error'] == AUTH_REQUIRED_MSG


_NEW_WEB_PLATFORMS = (
    ('tumblr', 'tumblr.com', 'https://alice.tumblr.com/'),
    ('wordpress', 'profiles.wordpress.org', 'https://profiles.wordpress.org/alice/'),
    ('gravatar', 'gravatar.com', 'https://gravatar.com/alice'),
    ('soundcloud', 'soundcloud.com', 'https://soundcloud.com/alice'),
    ('flickr', 'www.flickr.com', 'https://www.flickr.com/photos/alice/'),
    ('linktree', 'linktr.ee', 'https://linktr.ee/alice'),
    ('carrd', 'carrd.co', 'https://alice.carrd.co'),
)


def test_new_web_platforms_found_with_correct_url_and_confidence():
    by = _all_absent()
    page = only_for('alice', ok('<html>profile</html>'), ok('', 404))
    for _, host, _ in _NEW_WEB_PLATFORMS:
        by[host] = page
    data, _ = _run(by)
    p = data['platforms']
    for name, _, url in _NEW_WEB_PLATFORMS:
        assert p[name]['exists'] is True, name
        assert p[name]['url'] == url, name
        assert p[name]['confidence'] == 'MEDIUM', name  # calibrated web page, not a strict API
        assert p[name]['exact'] is True, name


def test_new_web_platforms_absent():
    data, _ = _run(_all_absent())
    for name, _, _ in _NEW_WEB_PLATFORMS:
        assert data['platforms'][name]['exists'] is False, name


def test_new_web_platform_soft_404_becomes_manual_not_a_false_positive():
    # Critical behavior (CRITICAL constraint): a platform that answers 200 for a canary username
    # that CANNOT exist must be demoted to manual verification, never reported as a false "found".
    # These platforms have no verified not-found markers, so calibration is their only safety net.
    by = _all_absent()
    by['linktr.ee'] = ok('<html>this page always answers 200</html>')  # same for real AND canary
    data, _ = _run(by)
    entry = data['platforms']['linktree']
    assert entry['exists'] is None
    assert entry['confidence'] == 'MANUAL'
    assert entry['error'] == SOFT_404_MSG


@pytest.mark.parametrize('name,host,url', _NEW_WEB_PLATFORMS)
def test_new_web_platforms_blocked_are_unavailable(name, host, url):
    by = _all_absent()
    by[host] = ok('', 429)
    data, _ = _run(by)
    assert data['platforms'][name]['exists'] is None
    assert data['platforms'][name]['error'] == RATE_LIMITED_MSG
    assert data['platforms'][name]['error_kind'] == 'rate_limited'


def test_block_codes_no_longer_include_403():
    assert 403 not in BLOCK_CODES and 401 not in BLOCK_CODES
    assert BLOCK_CODES == frozenset({429, 451, 999})


def test_stackoverflow_is_flagged_as_inexact_match():
    # Stack Overflow is a name search ("contains"), not an exact username check.
    from secure_osint.sources.username_source import INEXACT_MATCH, PLATFORM_LABELS, PLATFORMS

    assert INEXACT_MATCH == frozenset({'stackoverflow'})
    assert set(PLATFORM_LABELS) == set(PLATFORMS)  # every platform has a display name


def test_profile_text_never_turns_entity_encoded_markup_into_tags():
    from secure_osint.sources.username_source import _text

    out = _text('hi &lt;img src=x onerror=alert(1)&gt; there <b>bold</b>')
    assert '<' not in out and '>' not in out
    assert out.startswith('hi') and 'bold' in out
