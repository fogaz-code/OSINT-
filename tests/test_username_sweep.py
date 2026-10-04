"""Username sweep: bounded concurrency, step deadline, error taxonomy, rate limits, partial results."""

import json
import random
import threading
import time
from urllib.parse import urlparse

import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig, load_workflow_from_file
from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.sources.username_source import (
    AUTH_REQUIRED_MSG,
    DEFAULT_MAX_WORKERS,
    ERROR_KINDS,
    GITHUB_RATE_LIMITED_MSG,
    PLATFORMS,
    RATE_LIMITED_MSG,
    UsernameSource,
)
from secure_osint.utils import deadline
from secure_osint.utils.deadline import DeadlineExceeded, deadline_scope
from tests.test_sources import ok
from tests.test_username import _AUTOMATED, ScriptedClient, _all_absent, only_for

_AUTOMATED_COUNT = len(_AUTOMATED)


def _run(by_host, username='alice', **params):
    client = ScriptedClient(by_host)
    return UsernameSource(client).fetch({'input': username, **params}), client


def _timeout(host):
    return TransientSourceError(f'{host}: timed out after 10s (ReadTimeout)')


class SlowClient(ScriptedClient):
    """Adds latency and records how many requests are in flight at the same time."""

    def __init__(self, by_host, delay=0.05, jitter=0.0):
        super().__init__(by_host)
        self.delay, self.jitter = delay, jitter
        self.in_flight = 0
        self.max_in_flight = 0
        self.remaining_seen = []
        self._count_lock = threading.Lock()

    def get(self, url, params=None, headers=None, timeout=None):
        with self._count_lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            self.remaining_seen.append(deadline.remaining())
        try:
            time.sleep(self.delay + random.random() * self.jitter)
            return super().get(url, params=params, headers=headers, timeout=timeout)
        finally:
            with self._count_lock:
                self.in_flight -= 1


# --- concurrency, order, deadline ---


def test_sweep_runs_concurrently_with_a_bounded_pool():
    client = SlowClient(_all_absent(), delay=0.05)
    started = time.monotonic()
    UsernameSource(client).fetch({'input': 'alice'})
    elapsed = time.monotonic() - started
    assert 1 < client.max_in_flight <= DEFAULT_MAX_WORKERS == 8
    assert elapsed < _AUTOMATED_COUNT * 0.05  # strictly faster than the old sequential sweep


def test_max_workers_param_is_honoured_and_clamped():
    client = SlowClient(_all_absent(), delay=0.02)
    UsernameSource(client).fetch({'input': 'alice', 'max_workers': 2})
    assert client.max_in_flight <= 2
    client = SlowClient(_all_absent(), delay=0.01)
    UsernameSource(client).fetch({'input': 'alice', 'max_workers': 10_000})
    assert client.max_in_flight <= 16


@pytest.mark.parametrize('bad', ['many', 0, -3, True, None, 2.5])
def test_invalid_max_workers_falls_back_to_default(bad):
    client = SlowClient(_all_absent(), delay=0.0)
    data = UsernameSource(client).fetch({'input': 'alice', 'max_workers': bad})
    assert data['stats']['automated'] == _AUTOMATED_COUNT


def test_output_order_is_deterministic_despite_random_completion_order():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    client = SlowClient(by, delay=0.0, jitter=0.02)
    data = UsernameSource(client).fetch({'input': 'alice'})
    assert list(data['platforms']) == list(PLATFORMS)


def test_step_deadline_is_carried_into_worker_threads():
    client = SlowClient(_all_absent(), delay=0.0)
    with deadline_scope(30):
        UsernameSource(client).fetch({'input': 'alice'})
    assert client.remaining_seen and all(r is not None and 0 < r <= 30 for r in client.remaining_seen)
    # Every request timeout is clamped to the budget left (never above the 10s per-request cap).
    assert all(t is not None and 0 < t <= 10 for t in client.timeouts)


def test_without_a_deadline_requests_keep_the_per_request_timeout():
    client = SlowClient(_all_absent(), delay=0.0)
    UsernameSource(client).fetch({'input': 'alice'})
    assert set(client.timeouts) == {10.0}


class TimeoutRespectingClient(ScriptedClient):
    """GitHub answers at once; every other host hangs until its (clamped) timeout, then times out."""

    def get(self, url, params=None, headers=None, timeout=None):
        host = urlparse(url).hostname or ''
        if host == 'api.github.com':
            return super().get(url, params=params, headers=headers, timeout=timeout)
        with self._lock:
            self.timeouts.append(timeout)
        time.sleep(min(timeout or 10.0, 3.0))
        raise _timeout(host)

    def post(self, url, content, headers=None, timeout=None):
        return self.get(url, headers=headers, timeout=timeout)


def test_spent_budget_returns_a_partial_result_instead_of_hanging():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    client = TimeoutRespectingClient(by)
    started = time.monotonic()
    with deadline_scope(0.6):
        data = UsernameSource(client).fetch({'input': 'alice', 'max_workers': 2})
    assert time.monotonic() - started < 2.0
    platforms = data['platforms']
    assert platforms['github']['exists'] is True
    kinds = {name: p['error_kind'] for name, p in platforms.items() if name != 'github' and p['exists'] is None}
    automated_others = [n for n, p in PLATFORMS.items() if p.kind != 'auth_required' and n != 'github']
    assert set(automated_others) <= set(kinds)
    assert {kinds[n] for n in automated_others} <= {'timeout', 'deadline'}
    assert 'deadline' in kinds.values()  # queued checks were not started once the budget was gone
    assert data['partial'] is True and data['errors']
    # Tolerance: with Windows' coarse monotonic clock (t0 + 0.6) - t0 can round to 0.6000000000000227.
    assert all(t is None or t <= 0.6 + 1e-9 for t in client.timeouts)


class HangingClient(ScriptedClient):
    """Ignores its timeout entirely (a slow-drip server): the sweep must still return on time."""

    def get(self, url, params=None, headers=None, timeout=None):
        if 'github' in url:
            return super().get(url, params=params, headers=headers, timeout=timeout)
        time.sleep(3.0)
        raise AssertionError('should have been abandoned')

    def post(self, url, content, headers=None, timeout=None):
        return self.get(url, headers=headers, timeout=timeout)


def test_requests_that_ignore_their_timeout_are_abandoned_at_the_deadline():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    started = time.monotonic()
    with deadline_scope(0.5):
        data = UsernameSource(HangingClient(by)).fetch({'input': 'alice'})
    assert time.monotonic() - started < 1.5
    assert data['platforms']['github']['exists'] is True
    assert data['platforms']['reddit']['error_kind'] == 'deadline'
    assert data['partial'] is True


# --- error taxonomy (C4) ---


@pytest.mark.parametrize(
    'exc,kind,fragment',
    [
        (TransientSourceError('api.github.com: timed out after 10s (ReadTimeout)'), 'timeout', 'Timed out'),
        (TransientSourceError('api.github.com: connection error (ConnectError)'), 'connection', 'Connection failed'),
        (
            SourceUnavailable('URL blocked by SSRF guard: Cannot resolve api.github.com: [Errno -2] Name not known'),
            'connection',
            'DNS resolution failed',
        ),
        (
            SourceUnavailable('URL blocked by SSRF guard: No addresses for api.github.com'),
            'connection',
            'DNS resolution failed',
        ),
        (
            SourceUnavailable(
                'URL blocked by SSRF guard: Blocked: api.github.com resolves to non-public address 10.0.0.1'
            ),
            'blocked',
            'SSRF guard',
        ),
        (
            SourceUnavailable('URL blocked by SSRF guard: Blocked non-public address: 127.0.0.1'),
            'blocked',
            'SSRF guard',
        ),
        (SourceUnavailable('api.github.com: circuit open after repeated failures'), 'connection', 'circuit breaker'),
        (TransientSourceError('api.github.com: local rate limit wait exceeded'), 'rate_limited', 'Local rate limit'),
        (SourceUnavailable('api.github.com: too many redirects'), 'other', 'Too many redirects'),
        (SourceUnavailable('api.github.com: response exceeds 10485760 bytes'), 'other', 'Response too large'),
        (DeadlineExceeded('step time budget exhausted'), 'deadline', 'time budget'),
        (TransientSourceError('something new'), 'connection', 'Network error'),
    ],
)
def test_request_failures_get_an_error_kind_and_a_human_message(exc, kind, fragment):
    by = _all_absent()
    by['api.github.com'] = exc
    data, _ = _run(by)
    entry = data['platforms']['github']
    assert entry['exists'] is None and entry['confidence'] == 'MANUAL'
    assert entry['error_kind'] == kind and kind in ERROR_KINDS
    assert fragment in entry['error']
    assert entry['error'] != 'check failed'
    # The raw exception text (hosts, resolved IPs, errno) never leaks into the result.
    assert '10.0.0.1' not in entry['error'] and 'Errno' not in entry['error']


def test_every_entry_has_the_c4_fields():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    data, _ = _run(by)
    for name, entry in data['platforms'].items():
        assert entry['calibration'] in {'passed', 'soft404', 'control_error', 'not_applicable'}, name
        assert entry['error_kind'] is None or entry['error_kind'] in ERROR_KINDS, name
        assert {'exists', 'error', 'url', 'exact', 'label', 'confidence'} <= set(entry), name
    assert data['platforms']['github']['error_kind'] is None
    assert data['platforms']['linkedin']['error_kind'] is None  # never queried: nothing failed


def test_challenge_page_is_blocked_kind():
    by = _all_absent()
    by['codepen.io'] = ok('<html><title>Just a moment...</title></html>')
    data, _ = _run(by)
    assert data['platforms']['codepen']['error_kind'] == 'blocked'


def test_unexpected_status_kinds():
    by = _all_absent()
    by['gitlab.com'] = ok('', 502)
    by['keybase.io'] = ok('', 418)
    data, _ = _run(by)
    assert data['platforms']['gitlab']['error_kind'] == 'http_status'
    assert data['platforms']['keybase']['error_kind'] == 'http_status'


# --- GitHub rate limit vs auth wall (HIGH) ---


@pytest.mark.parametrize(
    'resp',
    [
        ok({'message': 'nope'}, 403, {'x-ratelimit-remaining': '0'}),
        ok({'message': 'nope'}, 403, {'X-RateLimit-Remaining': '0'}),
        ok('', 403, {'Retry-After': '60'}),
        ok({'message': 'API rate limit exceeded for 1.2.3.4.'}, 403),
        ok('', 429),
    ],
)
def test_github_rate_limit_is_not_reported_as_an_auth_wall(resp, monkeypatch):
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    by = _all_absent()
    by['api.github.com'] = resp
    data, _ = _run(by)
    github = data['platforms']['github']
    assert github['exists'] is None and github['confidence'] == 'MANUAL'
    assert github['error_kind'] == 'rate_limited'
    assert github['error'] == GITHUB_RATE_LIMITED_MSG == 'rate limited — retry later or set GITHUB_TOKEN'
    assert github['error'] != AUTH_REQUIRED_MSG


def test_rate_limit_message_does_not_suggest_a_token_already_set(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'ghp_' + 'a' * 36)
    by = _all_absent()
    by['api.github.com'] = ok('', 403, {'x-ratelimit-remaining': '0'})
    data, _ = _run(by)
    assert data['platforms']['github']['error'] == RATE_LIMITED_MSG


def test_real_auth_wall_stays_auth_wall():
    by = _all_absent()
    by['api.github.com'] = ok({'message': 'Forbidden'}, 403, {'x-ratelimit-remaining': '42'})
    by['codepen.io'] = ok('', 401)
    data, _ = _run(by)
    for name in ('github', 'codepen'):
        assert data['platforms'][name]['error_kind'] == 'auth_wall'
        assert data['platforms'][name]['error'] == AUTH_REQUIRED_MSG


def test_rate_limited_web_platform_without_token_hint():
    by = _all_absent()
    by['codepen.io'] = ok('Rate limit exceeded', 403)
    data, _ = _run(by)
    assert data['platforms']['codepen']['error_kind'] == 'rate_limited'
    assert data['platforms']['codepen']['error'] == RATE_LIMITED_MSG


def test_pypi_rate_limit_and_auth_wall_are_classified():
    by = _all_absent()
    by['pypi.org'] = ok('', 429)
    data, _ = _run(by)
    assert data['platforms']['pypi']['error_kind'] == 'rate_limited'
    by['pypi.org'] = ok('', 403)
    data, _ = _run(by)
    assert data['platforms']['pypi']['error_kind'] == 'auth_wall'


# --- GITHUB_TOKEN handling ---

_TOKEN = 'ghp_SuperSecretTokenValue1234567890abcd'


def test_github_token_is_sent_only_to_api_github_com(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', _TOKEN)
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    data, client = _run(by)
    github_urls = [u for u in client.urls_called if urlparse(u).hostname == 'api.github.com']
    assert github_urls
    for url in github_urls:
        assert client.headers_by_url[url]['Authorization'] == f'Bearer {_TOKEN}'
    for url, headers in client.headers_by_url.items():
        if urlparse(url).hostname != 'api.github.com':
            assert 'Authorization' not in headers and _TOKEN not in json.dumps(headers), url
    assert _TOKEN not in json.dumps(data)


def test_no_authorization_header_without_token(monkeypatch):
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    _, client = _run(_all_absent())
    assert not any('Authorization' in h for h in client.headers_by_url.values())


def test_github_token_never_leaks_into_errors_or_logs(monkeypatch, caplog):
    monkeypatch.setenv('GITHUB_TOKEN', _TOKEN)
    by = _all_absent()
    by['api.github.com'] = TransientSourceError(f'api.github.com: connection error (Authorization: Bearer {_TOKEN})')
    with caplog.at_level('DEBUG'):
        data, _ = _run(by)
    assert _TOKEN not in json.dumps(data)
    assert _TOKEN not in caplog.text


# --- partial results (C2) and stats ---


def test_one_of_26_is_partial_with_errors_and_stats():
    by = {host: _timeout(host) for host in _AUTOMATED}
    by['www.reddit.com'] = ok('', 404)
    data, _ = _run(by)
    assert data['partial'] is True
    assert isinstance(data['errors'], list) and data['errors'] and all(isinstance(e, str) for e in data['errors'])
    assert data['stats'] == {'automated': _AUTOMATED_COUNT, 'checked': 1, 'found': 0, 'failed': _AUTOMATED_COUNT - 1}
    assert data['checked'] == 1


def test_clean_run_is_complete_without_errors():
    by = _all_absent()
    by['api.github.com'] = ok({'login': 'alice'})
    data, _ = _run(by)
    assert data['partial'] is False and 'errors' not in data
    assert data['stats'] == {
        'automated': _AUTOMATED_COUNT,
        'checked': _AUTOMATED_COUNT,
        'found': 1,
        'failed': 0,
    }


def test_single_web_platform_failure_is_not_partial_but_not_cacheable():
    by = _all_absent()
    by['medium.com'] = _timeout('medium.com')
    data, _ = _run(by)
    assert data['partial'] is False
    assert data['stats']['failed'] == 1
    # C2: errors without partial keep the status but skip the cache, so the timeout is re-checked next run.
    assert any('medium' in e.lower() for e in data['errors'])


def test_stable_failure_alone_keeps_the_result_cacheable():
    by = _all_absent()
    by['api.github.com'] = ok('', 403)  # a genuine auth wall: the same answer next time
    data, _ = _run(by)
    assert data['partial'] is False and 'errors' not in data


@pytest.mark.parametrize('host', ['api.github.com', 'gitlab.com', 'keybase.io', 'pypi.org'])
def test_transient_failure_of_an_api_platform_is_partial(host):
    by = _all_absent()
    by[host] = _timeout(host)
    data, _ = _run(by)
    assert data['partial'] is True
    assert any('timed out' in e.lower() for e in data['errors'])


def test_non_transient_api_failure_alone_is_not_partial():
    by = _all_absent()
    by['api.github.com'] = ok('', 403)  # a genuine auth wall: retrying later will not help
    data, _ = _run(by)
    assert data['partial'] is False


def test_failure_ratio_threshold_is_strictly_above_a_quarter():
    web = ['medium.com', 'codepen.io', 'hackaday.io', 'mastodon.social', 'about.me', 'sourceforge.net', 'gravatar.com']
    by = _all_absent()
    for host in web[:6]:  # 6 / 26 = 0.23
        by[host] = _timeout(host)
    data, _ = _run(by)
    assert data['partial'] is False
    by[web[6]] = _timeout(web[6])
    by['soundcloud.com'] = _timeout('soundcloud.com')  # 8 / 26 = 0.31
    data, _ = _run(by)
    assert data['partial'] is True


def test_partial_result_is_not_cached_by_the_engine(tmp_path):
    from secure_osint.utils.cache import ResultCache

    by = {host: _timeout(host) for host in _AUTOMATED}
    by['www.reddit.com'] = ok('', 404)
    source = UsernameSource(ScriptedClient(by))
    cache = ResultCache(tmp_path / 'cache')
    wf = WorkflowConfig(
        name='u', description='d', input_type='username', risk='low', steps=[StepConfig(id='u', type='username')]
    )
    engine = WorkflowEngine(catalog={'username': source}, cache=cache, cache_ttl=3600)
    first = engine.execute(wf, 'alice')['u']
    assert first.status == StepStatus.DEGRADED  # C2: partial=True with errors -> DEGRADED, never cached
    assert first.data['partial'] is True
    second = engine.execute(wf, 'alice')['u']
    assert second.cached is False


# --- calibration field (C4) ---


def test_calibration_field_values():
    by = _all_absent()
    by['codepen.io'] = only_for('alice', ok('<html>alice</html>'), ok('', 404))
    by['linktr.ee'] = ok('<html>always 200</html>')
    by['www.tiktok.com'] = only_for('alice', ok('<html>alice</html>'), _timeout('www.tiktok.com'))
    by['api.github.com'] = ok({'login': 'alice'})
    data, client = _run(by)
    p = data['platforms']
    assert p['codepen']['calibration'] == 'passed'
    assert p['linktree']['calibration'] == 'soft404'
    assert p['tiktok']['calibration'] == 'control_error'
    assert p['github']['calibration'] == 'not_applicable'  # JSON API: never calibrated
    assert p['medium']['calibration'] == 'not_applicable'  # not found: no control probe was needed
    assert p['linkedin']['calibration'] == 'not_applicable'
    # Zero extra requests: only the platforms that looked found got a control probe.
    assert sum('medium.com' in u for u in client.urls_called) == 1


# --- params and workflow ---


@pytest.mark.parametrize('value', ['everything', '', 3, None])
def test_unknown_platform_set_is_rejected_before_any_request(value):
    client = ScriptedClient({})
    with pytest.raises(SourceUnavailable):
        UsernameSource(client).fetch({'input': 'alice', 'platform_set': value})
    assert client.hosts_called == []


def test_default_platform_set_is_builtin():
    data, _ = _run(_all_absent())
    assert data['platform_set'] == 'builtin'
    assert 'catalog' not in data


def test_username_workflow_has_a_realistic_budget_and_the_new_params():
    wf = load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/username.yaml')
    step = next(s for s in wf.steps if s.type == 'username')
    assert step.timeout >= 90
    assert step.params['platform_set'] == 'builtin'
    assert step.params['max_workers'] == DEFAULT_MAX_WORKERS
    assert 'wmn_path' in step.params and step.params['wmn_include_nsfw'] is False


def test_shared_source_instance_is_safe_for_concurrent_runs():
    # The registry shares one instance per process (GUI runs can overlap): no per-run state on self.
    by = _all_absent()
    by['codepen.io'] = only_for('alice', ok('<html>alice</html>'), ok('', 404))
    source = UsernameSource(ScriptedClient(by))
    results = []

    def run(name):
        results.append(source.fetch({'input': name}))

    threads = [threading.Thread(target=run, args=(n,)) for n in ('alice', 'bob')]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    by_user = {r['username']: r for r in results}
    assert by_user['alice']['platforms']['codepen']['exists'] is True
    assert by_user['bob']['platforms']['codepen']['exists'] is False


def test_rejected_github_token_is_reported_without_echoing_it(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', _TOKEN)
    by = _all_absent()
    by['api.github.com'] = ok({'message': 'Bad credentials'}, 401)
    data, _ = _run(by)
    github = data['platforms']['github']
    assert github['error_kind'] == 'auth_wall' and 'GITHUB_TOKEN' in github['error']
    assert _TOKEN not in json.dumps(data)


def test_server_error_on_an_api_platform_is_transient_and_partial():
    by = _all_absent()
    by['api.github.com'] = ok('', 503)
    data, _ = _run(by)
    assert data['platforms']['github']['error_kind'] == 'http_status'
    assert data['partial'] is True


def test_client_error_status_on_an_api_platform_is_not_partial():
    by = _all_absent()
    by['gitlab.com'] = ok('', 418)
    data, _ = _run(by)
    assert data['platforms']['gitlab']['error_kind'] == 'http_status'
    assert data['partial'] is False


def test_errors_list_is_capped(monkeypatch):
    import secure_osint.sources.username_source as us

    monkeypatch.setattr(us, '_MAX_ERRORS_LISTED', 3)
    by = {host: _timeout(host) for host in _AUTOMATED}
    by['www.reddit.com'] = ok('', 404)
    data, _ = _run(by)
    assert len(data['errors']) == 4 and data['errors'][-1] == f'... and {_AUTOMATED_COUNT - 1 - 3} more'


def test_all_checks_out_of_budget_is_a_deadline_error():
    with deadline_scope(0):
        with pytest.raises(DeadlineExceeded):
            UsernameSource(ScriptedClient(_all_absent())).fetch({'input': 'alice'})


def test_transient_failures_below_the_partial_threshold_are_not_cached(tmp_path):
    from secure_osint.utils.cache import ResultCache

    by = _all_absent()
    by['www.tiktok.com'] = _timeout('www.tiktok.com')
    by['medium.com'] = _timeout('medium.com')
    source = UsernameSource(ScriptedClient(by))
    wf = WorkflowConfig(
        name='u', description='d', input_type='username', risk='low', steps=[StepConfig(id='u', type='username')]
    )
    engine = WorkflowEngine(catalog={'username': source}, cache=ResultCache(tmp_path / 'cache'), cache_ttl=3600)
    first = engine.execute(wf, 'alice')['u']
    assert first.status == StepStatus.SUCCESS and first.data['partial'] is False
    assert engine.execute(wf, 'alice')['u'].cached is False


@pytest.mark.parametrize('username', ['a..b', '.ab'])
def test_username_that_yields_an_empty_dns_label_does_not_fail_the_sweep(username, monkeypatch):
    # tumblr/carrd put the username in the host name: 'a..b.tumblr.com' has an empty label, which the
    # IDNA codec rejects with UnicodeError. Only those platforms may fail; the others still report.
    import socket

    from secure_osint.security import ssrf_guard

    real = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if '..' in host or host.startswith('.'):
            return real(host, *args, **kwargs)  # the real IDNA error
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]

    monkeypatch.setattr(ssrf_guard.socket, 'getaddrinfo', getaddrinfo)
    with pytest.raises(ssrf_guard.SSRFError, match='Cannot resolve'):
        ssrf_guard.resolve_public_addresses(f'{username}.tumblr.com', 443)


def test_unexpected_exception_in_one_platform_is_confined_to_it(monkeypatch):
    by = _all_absent()
    source = UsernameSource(ScriptedClient(by))
    real = source._check

    def check(platform, sweep):
        if 'medium.com' in platform.profile_url:
            raise UnicodeEncodeError('idna', 'x', 0, 1, 'label empty')
        return real(platform, sweep)

    monkeypatch.setattr(source, '_check', check)
    data = source.fetch({'input': 'alice'})
    medium = data['platforms']['medium']
    assert medium['exists'] is None and medium['error_kind'] == 'other'
    assert data['stats']['checked'] == data['stats']['automated'] - 1
