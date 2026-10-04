import os

import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.workflow import load_workflow_from_file
from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.sources.shodan_internetdb_source import ShodanInternetDBSource
from secure_osint.sources.tool_catalog import build_catalog
from secure_osint.utils.resilience import HostPolicies
from tests.test_sources import FakeClient, ok

SAMPLE = {
    'ip': '8.8.8.8',
    'ports': [443, 53],
    'hostnames': ['dns.google'],
    'cpes': ['cpe:/a:isc:bind'],
    'tags': [],
    'vulns': ['CVE-2023-0002', 'CVE-2021-0001'],
}


def test_success_parses_and_sorts():
    client = FakeClient(ok(SAMPLE))
    data = ShodanInternetDBSource(client).fetch({'input': '8.8.8.8'})
    assert client.calls[0]['url'] == 'https://internetdb.shodan.io/8.8.8.8'
    assert data == {
        'ip': '8.8.8.8',
        'found': True,
        'ports': [53, 443],
        'hostnames': ['dns.google'],
        'cpes': ['cpe:/a:isc:bind'],
        'tags': [],
        'vulns': ['CVE-2021-0001', 'CVE-2023-0002'],
    }


def test_404_means_no_data_not_failure():
    # InternetDB risponde 404 {"detail": "No information available"} per IP che non ha mai visto.
    client = FakeClient(ok({'detail': 'No information available'}, 404))
    data = ShodanInternetDBSource(client).fetch({'input': '1.2.3.4'})
    assert data['found'] is False
    assert data['ports'] == [] and data['vulns'] == []


@pytest.mark.parametrize('value', ['not-an-ip', '999.1.1.1', 'example.com', '8.8.8.8/24', ''])
def test_invalid_ip_rejected_without_request(value):
    client = FakeClient()
    with pytest.raises(SourceUnavailable):
        ShodanInternetDBSource(client).fetch({'input': value})
    assert client.calls == []


@pytest.mark.parametrize('value', ['10.0.0.1', '127.0.0.1', '192.168.1.1', '::1'])
def test_non_public_ip_not_sent_to_shodan(value):
    client = FakeClient()
    with pytest.raises(SourceUnavailable, match='public'):
        ShodanInternetDBSource(client).fetch({'input': value})
    assert client.calls == []


def test_ipv6_is_normalised_in_url():
    client = FakeClient(ok({**SAMPLE, 'ip': '2001:4860:4860::8888'}))
    ShodanInternetDBSource(client).fetch({'input': '2001:4860:4860:0:0:0:0:8888'})
    assert client.calls[0]['url'] == 'https://internetdb.shodan.io/2001:4860:4860::8888'


def test_rate_limited_is_transient():
    with pytest.raises(TransientSourceError):
        ShodanInternetDBSource(FakeClient(ok({'detail': 'rate limited'}, 429))).fetch({'input': '8.8.8.8'})


def test_unexpected_shape_is_unavailable():
    with pytest.raises(SourceUnavailable):
        ShodanInternetDBSource(FakeClient(ok(['not', 'a', 'dict']))).fetch({'input': '8.8.8.8'})


def test_malformed_fields_are_tolerated():
    client = FakeClient(ok({'ip': '8.8.8.8', 'ports': 'garbage', 'vulns': None}))
    data = ShodanInternetDBSource(client).fetch({'input': '8.8.8.8'})
    assert data['ports'] == [] and data['vulns'] == [] and data['hostnames'] == []


def test_rate_limit_is_one_per_second():
    assert HostPolicies.RATES['internetdb.shodan.io'] == 1.0
    limiter = HostPolicies().limiter('internetdb.shodan.io')
    assert limiter.rate == 1.0
    assert limiter.capacity == 1  # nessun burst: al massimo 1 richiesta al secondo, sempre


def test_registered_and_in_ip_workflow():
    assert 'shodan_internetdb' in build_catalog(load_plugins=False)
    wf = load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/ip.yaml')
    assert wf.name == 'ip_recon'
    assert 'shodan_internetdb' in {s.type for s in wf.steps}


@pytest.mark.skipif(os.environ.get('SECURE_OSINT_NETWORK_TESTS') != '1', reason='live test is opt-in')
def test_live_google_dns():
    data = ShodanInternetDBSource().fetch({'input': '8.8.8.8'})
    assert data['found'] is True
    assert 53 in data['ports']
