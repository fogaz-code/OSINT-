import os
import socket
from unittest.mock import patch

import dns.exception
import dns.rdata
import dns.resolver
import pytest

from secure_osint.sources.base import SourceUnavailable, TransientSourceError
from secure_osint.sources.dns_source import DNSSource

ZONE = {
    'MX': ['10 smtp.example.com.', '20 backup.example.com.'],
    'NS': ['ns1.example.com.', 'ns2.example.com.'],
    'TXT': ['"v=spf1 -all"', '"part one" "part two"'],
    'SOA': ['ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600'],
}


def _fake_resolve(zone=ZONE, failures=None):
    failures = failures or {}

    def resolve(qname, rdtype, *args, **kwargs):
        if rdtype in failures:
            raise failures[rdtype]
        if rdtype not in zone:
            raise dns.resolver.NoAnswer()
        return [dns.rdata.from_text('IN', rdtype, text) for text in zone[rdtype]]

    return resolve


def _fake_gai(*ips):
    def gai(host, port, family=0, *args, **kwargs):
        return [
            (family, socket.SOCK_STREAM, 6, '', (ip, 0)) for ip in ips if (':' in ip) == (family == socket.AF_INET6)
        ]

    return gai


@pytest.fixture
def resolved():
    with patch('socket.getaddrinfo', _fake_gai('93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c')):
        yield


def test_returns_real_record_types(resolved):
    with patch('dns.resolver.resolve', _fake_resolve()):
        data = DNSSource().fetch({'input': 'example.com'})
    assert data['A'] == ['93.184.215.14']
    assert data['AAAA'] == ['2606:2800:21f:cb07:6820:80da:af6b:8b2c']
    assert data['MX'] == [
        {'preference': 10, 'exchange': 'smtp.example.com'},
        {'preference': 20, 'exchange': 'backup.example.com'},
    ]
    assert data['NS'] == ['ns1.example.com', 'ns2.example.com']
    assert data['TXT'] == ['v=spf1 -all', 'part onepart two']  # le stringhe multiple di un TXT vanno concatenate
    assert data['SOA'] == {
        'mname': 'ns1.example.com',
        'rname': 'hostmaster.example.com',
        'serial': 2024010101,
        'refresh': 7200,
        'retry': 3600,
        'expire': 1209600,
        'minimum': 3600,
    }
    assert data['CNAME'] == []
    assert data['errors'] == {}


def test_cname_record(resolved):
    with patch('dns.resolver.resolve', _fake_resolve({'CNAME': ['target.example.net.']})):
        data = DNSSource().fetch({'input': 'www.example.com'})
    assert data['CNAME'] == ['target.example.net']


def test_nxdomain_is_unavailable():
    with (
        patch('socket.getaddrinfo', side_effect=socket.gaierror(socket.EAI_NONAME, 'not found')),
        patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN()),
    ):
        with pytest.raises(SourceUnavailable, match='NXDOMAIN'):
            DNSSource().fetch({'input': 'does-not-exist.example'})


def test_single_record_timeout_does_not_fail_step(resolved):
    # Caso reale: risposte TXT grandi troncate su UDP con fallback TCP bloccato.
    failures = {'TXT': dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])}
    with patch('dns.resolver.resolve', _fake_resolve(failures=failures)):
        data = DNSSource().fetch({'input': 'example.com'})
    assert data['TXT'] == []
    assert 'TXT' in data['errors']
    assert data['MX']


def test_everything_times_out_is_transient():
    timeout = dns.exception.Timeout()
    with (
        patch('socket.getaddrinfo', side_effect=socket.gaierror(socket.EAI_AGAIN, 'temporary failure')),
        patch('dns.resolver.resolve', side_effect=timeout),
    ):
        with pytest.raises(TransientSourceError):
            DNSSource().fetch({'input': 'example.com'})


def test_no_records_at_all_is_unavailable():
    with (
        patch('socket.getaddrinfo', side_effect=socket.gaierror(socket.EAI_NONAME, 'no data')),
        patch('dns.resolver.resolve', side_effect=dns.resolver.NoAnswer()),
    ):
        with pytest.raises(SourceUnavailable):
            DNSSource().fetch({'input': 'empty.example.com'})


def test_no_nameservers_recorded_as_error(resolved):
    failures = {'MX': dns.resolver.NoNameservers()}
    with patch('dns.resolver.resolve', _fake_resolve(failures=failures)):
        data = DNSSource().fetch({'input': 'example.com'})
    assert data['MX'] == []
    assert 'MX' in data['errors']


def test_invalid_domain_rejected_before_any_query():
    with patch('dns.resolver.resolve') as resolve:
        with pytest.raises(SourceUnavailable):
            DNSSource().fetch({'input': 'not a domain'})
    resolve.assert_not_called()


def test_query_uses_lifetime(resolved):
    with patch('dns.resolver.resolve', side_effect=dns.resolver.NoAnswer()) as resolve:
        DNSSource(lifetime=2.5).fetch({'input': 'example.com'})
    assert all(call.kwargs.get('lifetime') == 2.5 for call in resolve.call_args_list)
    assert {call.args[1] for call in resolve.call_args_list} == {'CNAME', 'MX', 'NS', 'TXT', 'SOA'}


network = pytest.mark.skipif(
    os.environ.get('SECURE_OSINT_NETWORK_TESTS') != '1', reason='set SECURE_OSINT_NETWORK_TESTS=1 to run live DNS tests'
)


@network
@pytest.mark.parametrize('domain', ['google.com', 'cloudflare.com', 'example.com'])
def test_live_domains(domain):
    data = DNSSource().fetch({'input': domain})
    assert data['A'] or data['AAAA']
    assert data['NS']
    assert data['SOA'] is not None


def test_mx_sorted_by_preference(resolved):
    zone = {'MX': ['20 b.example.com.', '5 z.example.com.', '5 a.example.com.']}
    with patch('dns.resolver.resolve', _fake_resolve(zone)):
        data = DNSSource().fetch({'input': 'example.com'})
    assert [mx['exchange'] for mx in data['MX']] == ['a.example.com', 'z.example.com', 'b.example.com']
