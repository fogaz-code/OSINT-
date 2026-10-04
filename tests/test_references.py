import socket
from unittest.mock import Mock, patch

import dns.resolver
import pytest
from pydantic import ValidationError

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.references import Reference, UnresolvedReference, find_references, resolve
from secure_osint.core.workflow import StepConfig, StepResult, StepStatus, WorkflowConfig, load_workflow_from_file
from secure_osint.sources.base import SourceUnavailable
from secure_osint.sources.dns_source import DNSSource
from secure_osint.sources.shodan_internetdb_source import ShodanInternetDBSource
from tests.test_sources import FakeClient, ok

DATA = {
    'dns_lookup': {
        'A': ['93.184.215.14', '93.184.215.15'],
        'MX': [{'preference': 10, 'exchange': 'mx.example.com'}],
        'SOA': {'serial': 7},
        'empty': [],
    },
}


# --- parsing ---


def test_find_references_in_nested_params():
    params = {
        'input': '{{ steps.dns_lookup.data.A[0] }}',
        'nested': {'list': ['x', '{{steps.dns_lookup.data.MX[0].exchange}}']},
    }
    refs = find_references(params)
    assert [r.step_id for r in refs] == ['dns_lookup', 'dns_lookup']
    assert refs[0].path == ('A', 0)
    assert refs[1].path == ('MX', 0, 'exchange')


def test_plain_strings_have_no_references():
    assert find_references({'a': 'no template here', 'b': 3, 'c': ['{ not }']}) == []


@pytest.mark.parametrize(
    'bad',
    [
        '{{ steps.dns_lookup.A[0] }}',  # manca .data
        '{{ steps.dns_lookup.data.A[-1] }}',  # indici negativi non supportati
        '{{ steps.dns_lookup.data.A[0 }}',  # sintassi rotta
        '{{ __import__("os").system("id") }}',  # nessuna valutazione di espressioni
        '{{ steps.dns_lookup.data }}',  # serve almeno un elemento di path
    ],
)
def test_malformed_templates_rejected(bad):
    with pytest.raises(ValueError, match='reference'):
        find_references({'input': bad})


# --- resolution ---


def test_whole_string_reference_keeps_native_type():
    out = resolve({'ips': '{{ steps.dns_lookup.data.A }}', 'serial': '{{ steps.dns_lookup.data.SOA.serial }}'}, DATA)
    assert out == {'ips': ['93.184.215.14', '93.184.215.15'], 'serial': 7}


def test_index_and_nested_access():
    out = resolve(
        {'input': '{{ steps.dns_lookup.data.A[1] }}', 'mx': '{{ steps.dns_lookup.data.MX[0].exchange }}'}, DATA
    )
    assert out == {'input': '93.184.215.15', 'mx': 'mx.example.com'}


def test_embedded_reference_is_interpolated_as_text():
    out = resolve({'q': 'ip:{{ steps.dns_lookup.data.A[0] }} serial={{ steps.dns_lookup.data.SOA.serial }}'}, DATA)
    assert out == {'q': 'ip:93.184.215.14 serial=7'}


def test_embedding_non_scalar_is_an_error():
    with pytest.raises(UnresolvedReference, match='non-scalar'):
        resolve({'q': 'ips: {{ steps.dns_lookup.data.A }}'}, DATA)


def test_original_params_not_mutated():
    params = {'input': '{{ steps.dns_lookup.data.A[0] }}'}
    resolve(params, DATA)
    assert params == {'input': '{{ steps.dns_lookup.data.A[0] }}'}


@pytest.mark.parametrize(
    'template,reason',
    [
        ('{{ steps.dns_lookup.data.AAAA[0] }}', "key 'AAAA'"),
        ('{{ steps.dns_lookup.data.A[5] }}', 'index 5'),
        ('{{ steps.dns_lookup.data.empty[0] }}', 'index 0'),
        ('{{ steps.dns_lookup.data.A.first }}', "key 'first'"),
        ('{{ steps.dns_lookup.data.SOA[0] }}', 'index 0'),
    ],
)
def test_missing_path_raises_with_clear_message(template, reason):
    with pytest.raises(UnresolvedReference) as info:
        resolve({'input': template}, DATA)
    assert template.replace(' ', '') in str(info.value).replace(' ', '')
    assert reason in str(info.value)


def test_missing_step_data_raises():
    with pytest.raises(UnresolvedReference, match='no data'):
        resolve({'input': '{{ steps.other.data.A[0] }}'}, DATA)


def test_reference_str():
    assert str(Reference('dns_lookup', ('A', 0), '')) == '{{ steps.dns_lookup.data.A[0] }}'


# --- validation at load time ---


def _wf(*steps):
    return WorkflowConfig(name='t', description='d', input_type='g', risk='low', steps=list(steps))


def test_reference_to_unknown_step_fails_validation():
    with pytest.raises(ValidationError, match="unknown step 'ghost'"):
        _wf(StepConfig(id='b', type='x', params={'input': '{{ steps.ghost.data.A[0] }}'}))


def test_reference_must_be_declared_in_depends_on():
    with pytest.raises(ValidationError, match="must list 'a' in depends_on"):
        _wf(StepConfig(id='a', type='x'), StepConfig(id='b', type='x', params={'input': '{{ steps.a.data.A[0] }}'}))


def test_optional_dependency_is_not_enough():
    with pytest.raises(ValidationError, match='depends_on'):
        _wf(
            StepConfig(id='a', type='x'),
            StepConfig(id='b', type='x', optional_dependencies=['a'], params={'input': '{{ steps.a.data.x }}'}),
        )


def test_malformed_reference_fails_validation():
    with pytest.raises(ValidationError, match='reference'):
        _wf(
            StepConfig(id='a', type='x'),
            StepConfig(id='b', type='x', depends_on=['a'], params={'input': '{{ steps.a.A[0] }}'}),
        )


def test_valid_reference_passes_validation():
    _wf(
        StepConfig(id='a', type='x'),
        StepConfig(id='b', type='x', depends_on=['a'], params={'input': '{{ steps.a.data.A[0] }}'}),
    )


# --- engine semantics ---


def _engine(catalog, **kw):
    return WorkflowEngine(catalog=catalog, backoff=lambda a: 0, **kw)


def _chain():
    return _wf(
        StepConfig(id='a', type='first'),
        StepConfig(id='b', type='second', depends_on=['a'], params={'input': '{{ steps.a.data.A[0] }}'}),
    )


def test_engine_resolves_reference_into_input():
    first, second = Mock(), Mock()
    first.fetch.return_value = {'A': ['1.1.1.1']}
    second.fetch.return_value = {}
    results = _engine({'first': first, 'second': second}).execute(_chain(), 'example.com')
    assert results['b'].status == StepStatus.SUCCESS
    assert second.fetch.call_args[0][0]['input'] == '1.1.1.1'


def test_step_input_defaults_to_workflow_input():
    src = Mock()
    src.fetch.return_value = {}
    _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x')), 'example.com')
    assert src.fetch.call_args[0][0]['input'] == 'example.com'


def test_missing_path_makes_step_error_without_calling_source():
    first, second = Mock(), Mock()
    first.fetch.return_value = {'A': []}
    results = _engine({'first': first, 'second': second}).execute(_chain(), 'example.com')
    assert results['b'].status == StepStatus.ERROR
    assert 'steps.a.data.A[0]' in results['b'].error_message
    second.fetch.assert_not_called()


@pytest.mark.parametrize('allow_partial', [True, False])
def test_failed_referenced_dependency_skips_step(allow_partial):
    first, second = Mock(), Mock()
    first.fetch.side_effect = SourceUnavailable('down')
    results = _engine({'first': first, 'second': second}, allow_partial_results=allow_partial).execute(
        _chain(), 'example.com'
    )
    assert results['b'].status == StepStatus.SKIPPED
    assert "'a'" in results['b'].error_message
    second.fetch.assert_not_called()


def test_resolved_values_are_redacted_in_terminal_table():
    from secure_osint.core.privacy import PrivacyGuard
    from secure_osint.ui import results_table
    from tests.test_ui import _render

    results = {
        'b': StepResult(
            status=StepStatus.UNAVAILABLE, error_message='Not a public IP address: 10.1.2.3 (owner admin@corp.example)'
        )
    }
    output = _render(results_table(results, guard=PrivacyGuard()), color=False)
    assert '10.1.2.3' not in output and 'admin@corp.example' not in output
    assert '[REDACTED]' in output


def test_error_text_cannot_inject_rich_markup():
    from secure_osint.core.privacy import PrivacyGuard
    from secure_osint.ui import results_table
    from tests.test_ui import _render

    results = {'b': StepResult(status=StepStatus.ERROR, error_message='boom [bold]x[/bold] [link=http://evil]y')}
    output = _render(results_table(results, guard=PrivacyGuard(categories=set())), color=False)
    assert '[bold]x[/bold]' in output
    assert '[link=http://evil]y' in output


# --- end to end: dns_lookup -> shodan exposure ---


def _fake_dns(qname, rdtype, *args, **kwargs):
    raise dns.resolver.NoAnswer()


def test_end_to_end_dns_to_shodan_via_reference(tmp_path):
    workflow = tmp_path / 'chain.yaml'
    workflow.write_text(
        'name: chain\ndescription: d\ninput_type: domain\nrisk: low\nsteps:\n'
        '  - id: dns_lookup\n    type: dns\n'
        '  - id: exposure\n    type: shodan_internetdb\n    depends_on: [dns_lookup]\n'
        '    params:\n      input: "{{ steps.dns_lookup.data.A[0] }}"\n'
    )
    shodan_client = FakeClient(ok({'ip': '93.184.215.14', 'ports': [80, 443], 'vulns': []}))
    catalog = {'dns': DNSSource(), 'shodan_internetdb': ShodanInternetDBSource(shodan_client)}

    def gai(host, port, family=0, *a, **k):
        if family == socket.AF_INET6:
            raise socket.gaierror(socket.EAI_NONAME, 'no AAAA')
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 0))]

    with patch('socket.getaddrinfo', gai), patch('dns.resolver.resolve', _fake_dns):
        results = _engine(catalog).execute(load_workflow_from_file(str(workflow)), 'example.com')

    assert results['dns_lookup'].status == StepStatus.SUCCESS
    assert results['exposure'].status == StepStatus.SUCCESS, results['exposure'].error_message
    assert shodan_client.calls[0]['url'] == 'https://internetdb.shodan.io/93.184.215.14'
    assert results['exposure'].data['ports'] == [80, 443]


def test_shipped_domain_workflow_chains_dns_to_shodan():
    wf = load_workflow_from_file(f'{DEFAULT_WORKFLOW_DIR}/domain.yaml')
    exposure = next(s for s in wf.steps if s.type == 'shodan_internetdb')
    assert exposure.depends_on == ['dns_lookup']
    assert exposure.params['input'] == '{{ steps.dns_lookup.data.A[0] }}'
