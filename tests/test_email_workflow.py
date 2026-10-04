"""The shipped email workflow chains the email step into a DNS step on the email domain."""

from typing import Any, Dict, List

from secure_osint.cli import DEFAULT_WORKFLOW_DIR
from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.references import find_references
from secure_osint.core.workflow import StepStatus, load_workflow_from_file
from secure_osint.sources.base import BaseSource, SourceUnavailable

WORKFLOW = f'{DEFAULT_WORKFLOW_DIR}/email.yaml'


class FakeEmail(BaseSource):
    cacheable = False

    def __init__(self, fail: bool = False):
        self.fail = fail

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if self.fail:
            raise SourceUnavailable('No valid email provided')
        return {'email_domain': params['input'].split('@', 1)[1].lower(), 'mx': [], 'has_mx': False}


class RecordingDNS(BaseSource):
    cacheable = False

    def __init__(self) -> None:
        self.inputs: List[str] = []

    def fetch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self.inputs.append(params['input'])
        return {'A': ['93.184.215.14'], 'MX': [], 'errors': {}}


def test_email_workflow_is_a_real_dag():
    wf = load_workflow_from_file(WORKFLOW)
    steps = {s.id: s for s in wf.steps}
    email = next(s for s in wf.steps if s.type == 'email')
    dns_step = next(s for s in wf.steps if s.type == 'dns')
    assert email.depends_on == []
    assert dns_step.depends_on == [email.id]
    refs = find_references(dns_step.params)
    assert [(r.step_id, r.path) for r in refs] == [(email.id, ('email_domain',))]
    assert wf.topological_order().index(email.id) < wf.topological_order().index(dns_step.id)
    assert len(steps) == 2


def test_dns_step_receives_the_domain_not_the_address():
    dns = RecordingDNS()
    engine = WorkflowEngine(catalog={'email': FakeEmail(), 'dns': dns}, backoff=lambda attempt: 0.0)
    results = engine.execute(load_workflow_from_file(WORKFLOW), 'Alice@Example.COM')
    assert dns.inputs == ['example.com']
    assert all(r.status == StepStatus.SUCCESS for r in results.values())


def test_dns_step_never_runs_on_the_raw_email_when_email_step_fails():
    dns = RecordingDNS()
    engine = WorkflowEngine(catalog={'email': FakeEmail(fail=True), 'dns': dns}, backoff=lambda attempt: 0.0)
    results = engine.execute(load_workflow_from_file(WORKFLOW), 'alice@example.com')
    assert dns.inputs == []
    dns_id = next(s.id for s in load_workflow_from_file(WORKFLOW).steps if s.type == 'dns')
    assert results[dns_id].status not in (StepStatus.SUCCESS, StepStatus.DEGRADED)
