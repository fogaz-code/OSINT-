import json
from typing import Any, Dict, List, Optional

import pytest

from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.sources.crt_sh_source import CRTshSource
from secure_osint.sources.github_source import GitHubSource
from secure_osint.sources.hackertarget_source import HackerTargetSource
from secure_osint.sources.rdap_source import RDAPSource
from secure_osint.sources.wayback_source import WaybackSource
from secure_osint.utils.http_client import HttpResponse


class FakeClient:
    def __init__(self, *responses: HttpResponse):
        self.responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def get(
        self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, timeout: Optional[float] = None
    ) -> HttpResponse:
        self.calls.append({'url': url, 'params': params, 'headers': headers})
        return self.responses.pop(0)


def ok(body: Any, status: int = 200, headers: Optional[dict] = None) -> HttpResponse:
    content = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    return HttpResponse(status, content, headers or {})


def test_hackertarget_hostname_containing_error_is_kept():
    client = FakeClient(ok('error.example.com,1.2.3.4\nwww.example.com,5.6.7.8'))
    data = HackerTargetSource(client).fetch({'input': 'example.com'})
    assert data['hosts_found'] == 2


def test_hackertarget_api_message_is_unavailable():
    client = FakeClient(ok('API count exceeded - Increase Quota with Membership'))
    with pytest.raises(SourceUnavailable, match='API count exceeded'):
        HackerTargetSource(client).fetch({'input': 'example.com'})


def test_input_is_url_encoded_not_interpolated():
    client = FakeClient(ok('a.example.com,1.2.3.4'))
    with pytest.raises(SourceUnavailable):
        HackerTargetSource(client).fetch({'input': 'example.com&apikey=x'})
    assert client.calls == []


def test_crtsh_filters_wildcards_and_foreign_names():
    rows = [
        {'name_value': '*.example.com\nmail.example.com'},
        {'name_value': 'example.com\nevil.org'},
        {'name_value': 'notexample.com'},
    ]
    client = FakeClient(ok(rows))
    data = CRTshSource(client).fetch({'input': 'Example.com'})
    assert data['subdomains'] == ['mail.example.com']
    assert client.calls[0]['params'] == {'q': '%.example.com', 'output': 'json'}


def test_crtsh_reports_earliest_certificate_for_the_timeline():
    rows = [
        {'name_value': 'a.example.com', 'not_before': '2019-03-01T12:00:00'},
        {'name_value': 'b.example.com', 'not_before': '2015-08-26T00:00:00'},
        {'name_value': 'c.example.com', 'not_before': 'garbage'},
        {'name_value': 'd.example.com'},
    ]
    data = CRTshSource(FakeClient(ok(rows))).fetch({'input': 'example.com'})
    assert data['earliest_certificate'] == '2015-08-26T00:00:00'

    from secure_osint.core.timeline import build_timeline

    events, _ = build_timeline({'crt': {'status': 'success', 'data': data}})
    assert [e['date'] for e in events] == ['2015-08-26T00:00:00']


def test_crtsh_without_dates_has_no_earliest_certificate():
    data = CRTshSource(FakeClient(ok([{'name_value': 'a.example.com'}]))).fetch({'input': 'example.com'})
    assert data['earliest_certificate'] is None


def test_crtsh_502_is_transient():
    with pytest.raises(TransientSourceError):
        CRTshSource(FakeClient(ok('bad gateway', 502))).fetch({'input': 'example.com'})


def test_wayback_count_is_not_capped_by_sample():
    rows = [['original']] + [[f'http://example.com/{i}'] for i in range(30)]
    data = WaybackSource(FakeClient(ok(rows))).fetch({'input': 'example.com'})
    assert data['unique_urls_returned'] == 30
    assert len(data['sample_urls']) == 20
    assert data['sample_urls'] == sorted(data['sample_urls'])


def test_rdap_ip_uses_ip_endpoint():
    client = FakeClient(ok({'handle': 'NET-8-8-8-0-1', 'name': 'GOGL', 'country': 'US'}))
    data = RDAPSource(client).fetch({'input': '8.8.8.8'})
    assert client.calls[0]['url'] == 'https://rdap.org/ip/8.8.8.8'
    assert data['name'] == 'GOGL'


def test_rdap_404_unavailable():
    with pytest.raises(SourceUnavailable):
        RDAPSource(FakeClient(ok({}, 404))).fetch({'input': 'example.com'})


def test_github_repo_input_queries_repo_endpoint():
    client = FakeClient(ok({'full_name': 'octo/hello', 'stargazers_count': 3}))
    data = GitHubSource(client).fetch({'input': 'octo/hello'})
    assert client.calls[0]['url'] == 'https://api.github.com/repos/octo/hello'
    assert data['kind'] == 'repository'


def test_github_rate_limit_not_retried():
    client = FakeClient(ok({}, 403, {'x-ratelimit-remaining': '0'}))
    with pytest.raises(SourceUnavailable, match='rate limit'):
        GitHubSource(client).fetch({'input': 'octocat'})
