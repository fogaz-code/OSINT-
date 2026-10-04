import json
import os
import socket
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import dns.resolver
import pytest

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.validator import detect_input_type
from secure_osint.core.workflow import StepStatus, ValidationError, WorkflowConfig, load_workflow_from_file
from secure_osint.sources.base import BaseSource
from secure_osint.sources.dns_source import DNSSource
from secure_osint.sources.github_source import GitHubSource
from secure_osint.sources.phone_source import PhoneSource
from secure_osint.sources.username_source import UsernameSource
from secure_osint.utils.http_client import HttpResponse

WORKFLOWS = Path(DEFAULT_WORKFLOW_DIR)


def test_valid_workflow():
    temp_file = tempfile.NamedTemporaryFile(mode='w+t', suffix='.yaml', delete=False, encoding='utf-8')
    try:
        temp_file.write(
            'name: test\ndescription: description\ninput_type: generic\nrisk: low\nsteps:\n  - id: step1\n    type: dns\n    params: {}'
        )
        temp_file.flush()
        temp_file.close()  # Windows: the file must be closed before it can be read or deleted
        workflow = load_workflow_from_file(temp_file.name)
        assert isinstance(workflow, WorkflowConfig)
    finally:
        os.unlink(temp_file.name)


def test_invalid_workflow_missing_fields():
    temp_file = tempfile.NamedTemporaryFile(mode='w+t', suffix='.yaml', delete=False, encoding='utf-8')
    try:
        temp_file.write('name: test\ndescription: description\nrisk: low')
        temp_file.flush()
        temp_file.close()
        with pytest.raises(ValidationError):
            load_workflow_from_file(temp_file.name)
    finally:
        os.unlink(temp_file.name)


# --- shipped workflows: behaviour, not just schema ---


class _AnyClient:
    """Offline HTTP client: answers every GET/POST with the same canned response and records the URLs."""

    def __init__(self, body: Any, status: int = 200):
        self.body = json.dumps(body).encode()
        self.status = status
        self.urls: List[str] = []

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None, **_: Any) -> HttpResponse:
        self.urls.append(url)
        return HttpResponse(self.status, self.body, {})

    def post(self, url: str, body: Any = None, headers: Optional[dict] = None, **_: Any) -> HttpResponse:
        self.urls.append(url)
        return HttpResponse(self.status, self.body, {})


class _Recorder(BaseSource):
    """Fake source: returns canned data and records the params each call received."""

    cacheable = False

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.calls: List[Dict[str, Any]] = []

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(dict(params))
        return self.data


def _engine(catalog: Dict[str, Any]) -> WorkflowEngine:
    return WorkflowEngine(catalog=catalog, backoff=lambda attempt: 0.0)


def _no_dns(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError('generic input must never reach a DNS lookup')


# Inputs the validator classifies as 'generic': people's names, hyphenated handles, free text.
GENERIC_INPUTS = ['John Doe', 'jane-doe', 'Acme Corp Ltd']


@pytest.mark.parametrize('target', GENERIC_INPUTS)
def test_generic_inputs_are_really_classified_generic(target):
    assert detect_input_type(target) == 'generic'


@pytest.mark.parametrize('target', GENERIC_INPUTS)
def test_generic_workflow_runs_meaningful_steps_on_generic_input(target):
    # Regression: generic.yaml used to run `dns`, which rejects every non-domain input, so the
    # workflow could only ever end UNAVAILABLE. Every step must accept a free-text target.
    client = _AnyClient({'total_count': 1, 'items': [{'login': 'jdoe', 'html_url': 'https://github.com/jdoe'}]})
    catalog = {
        'github': GitHubSource(client),  # type: ignore[arg-type]
        'username': UsernameSource(client),  # type: ignore[arg-type]
        'dns': DNSSource(),
        'phone': PhoneSource(),
    }
    wf = load_workflow_from_file(str(WORKFLOWS / 'generic.yaml'))
    with patch('socket.getaddrinfo', _no_dns), patch('dns.resolver.resolve', _no_dns):
        results = _engine(catalog).execute(wf, target)

    assert {step.type for step in wf.steps}.isdisjoint({'dns', 'rdap', 'wayback', 'crt_sh', 'hackertarget'})
    for step_id, result in results.items():
        assert result.status == StepStatus.SUCCESS, (step_id, result.error_message)
    assert client.urls, 'the generic workflow must query at least one public source'


def test_generic_workflow_github_search_yields_pivots_not_actions():
    # The user search only lists candidate accounts (suggested pivots); nothing is chained from it.
    wf = load_workflow_from_file(str(WORKFLOWS / 'generic.yaml'))
    assert all(not step.depends_on and not step.optional_dependencies for step in wf.steps)
    assert all(step.risk == 'low' and not step.require_confirmation for step in wf.steps)


def test_ip_workflow_runs_rdap_and_exposure_in_parallel():
    wf = load_workflow_from_file(str(WORKFLOWS / 'ip.yaml'))
    by_id = {step.id: step for step in wf.steps}
    assert by_id['rdap_ip'].depends_on == [] and by_id['exposure'].depends_on == []


def test_ip_workflow_forward_confirms_the_reported_hostname():
    # Shodan InternetDB data is up to a week old: the hostname it reports for the IP is re-resolved
    # (forward-confirmed reverse DNS) instead of being trusted as current.
    wf = load_workflow_from_file(str(WORKFLOWS / 'ip.yaml'))
    hostname_step = next(step for step in wf.steps if step.type == 'dns')
    assert hostname_step.depends_on == ['exposure']
    assert hostname_step.params['input'] == '{{ steps.exposure.data.hostnames[0] }}'

    rdap = _Recorder({'handle': 'NET-1', 'country': 'US'})
    shodan = _Recorder({'ip': '8.8.8.8', 'found': True, 'hostnames': ['dns.google'], 'ports': [53]})
    dns_source = _Recorder({'A': ['8.8.8.8']})
    results = _engine({'rdap': rdap, 'shodan_internetdb': shodan, 'dns': dns_source}).execute(wf, '8.8.8.8')

    assert all(r.status == StepStatus.SUCCESS for r in results.values()), results
    assert rdap.calls[0]['input'] == '8.8.8.8'
    assert shodan.calls[0]['input'] == '8.8.8.8'
    assert dns_source.calls[0]['input'] == 'dns.google'


def test_ip_workflow_without_hostname_never_calls_dns():
    wf = load_workflow_from_file(str(WORKFLOWS / 'ip.yaml'))
    shodan = _Recorder({'ip': '192.0.2.1', 'found': False, 'hostnames': [], 'ports': []})
    dns_source = _Recorder({})
    results = _engine({'rdap': _Recorder({}), 'shodan_internetdb': shodan, 'dns': dns_source}).execute(wf, '192.0.2.1')
    hostname_step = next(step.id for step in wf.steps if step.type == 'dns')
    assert dns_source.calls == []  # an unresolved reference is reported, never guessed
    assert results[hostname_step].status != StepStatus.SUCCESS
    assert results['exposure'].status == StepStatus.SUCCESS


def test_ip_workflow_hostname_check_uses_the_real_dns_source():
    wf = load_workflow_from_file(str(WORKFLOWS / 'ip.yaml'))
    shodan = _Recorder({'ip': '8.8.8.8', 'found': True, 'hostnames': ['dns.google'], 'ports': [53]})

    def gai(host: str, port: Any, family: int = 0, *a: Any, **k: Any) -> Any:
        assert host == 'dns.google'
        if family == socket.AF_INET6:
            raise socket.gaierror(socket.EAI_NONAME, 'no AAAA')
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 0))]

    def no_answer(*args: Any, **kwargs: Any) -> Any:
        raise dns.resolver.NoAnswer()

    with patch('socket.getaddrinfo', gai), patch('dns.resolver.resolve', no_answer):
        results = _engine({'rdap': _Recorder({}), 'shodan_internetdb': shodan, 'dns': DNSSource()}).execute(
            wf, '8.8.8.8'
        )
    hostname_step = next(step.id for step in wf.steps if step.type == 'dns')
    assert results[hostname_step].status == StepStatus.SUCCESS, results[hostname_step].error_message
    data = results[hostname_step].data
    assert data is not None
    assert data['A'] == ['8.8.8.8']


@pytest.mark.parametrize('name', ['domain', 'generic', 'github', 'ip'])
def test_workflow_descriptions_are_english_and_specific(name):
    wf = load_workflow_from_file(str(WORKFLOWS / f'{name}.yaml'))
    assert wf.description and wf.description.lower() != f'{name} workflow'


def test_github_workflow_never_executes_the_owner_pivot():
    # Checking the repository owner's username on other platforms is a pivot to a person: it may be
    # suggested in the report, but a shipped workflow must not run it.
    wf = load_workflow_from_file(str(WORKFLOWS / 'github.yaml'))
    assert {step.type for step in wf.steps} == {'github'}
