"""Supply-chain policy for the GitHub Actions configuration, enforced as tests.

A CI workflow is code that runs with access to the repository token: a mutable action tag, an
over-broad permission or an attacker-controlled expression interpolated into a shell script are
real vulnerabilities, not style issues. These checks keep the hardening from regressing silently.
"""

import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GITHUB = ROOT / '.github'
WORKFLOW_FILES = sorted((GITHUB / 'workflows').glob('*.yml')) + sorted((GITHUB / 'workflows').glob('*.yaml'))

# `uses: owner/repo[/path]@<40-hex commit> # vX.Y.Z`: the comment is what Dependabot updates.
_PINNED = re.compile(r'^\s*-?\s*uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s*v\d+(\.\d+)*\s*$')
# Permissions a job may be granted, and the jobs (by workflow file) allowed each write scope.
_WRITE_ALLOWED = {
    'security-events': {'codeql.yml', 'scorecard.yml'},  # upload SARIF results to code scanning
    'id-token': {'scorecard.yml'},  # OIDC token to publish the Scorecard results
}
# Attacker-controlled contexts: interpolating them into `run:` is a script injection.
_UNTRUSTED = re.compile(
    r'\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits|pages)|head_ref)', re.I
)


def _load(path: Path) -> Dict[Any, Any]:
    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    assert isinstance(data, dict), path
    return data


def _triggers(workflow: Dict[Any, Any]) -> Dict[str, Any]:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    raw = workflow.get('on', workflow.get(True))
    if isinstance(raw, str):
        return {raw: None}
    if isinstance(raw, list):
        return {name: None for name in raw}
    return dict(raw or {})


def _steps(workflow: Dict[Any, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for job_id, job in workflow.get('jobs', {}).items():
        for step in job.get('steps', []):
            yield job_id, step


@pytest.fixture(scope='module')
def ci() -> Dict[Any, Any]:
    return _load(GITHUB / 'workflows' / 'ci.yml')


def test_workflow_files_exist():
    names = {p.name for p in WORKFLOW_FILES}
    assert {'ci.yml', 'codeql.yml', 'scorecard.yml'} <= names


@pytest.mark.parametrize('path', WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_sha_with_a_version_comment(path):
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if re.match(r'^\s*-?\s*uses:', line) and './' not in line:
            assert _PINNED.match(line), f'{path.name}:{number}: action not pinned to a full SHA: {line.strip()}'


@pytest.mark.parametrize('path', WORKFLOW_FILES, ids=lambda p: p.name)
def test_least_privilege_permissions(path):
    workflow = _load(path)
    # Top level grants nothing; each job asks only for what it needs.
    assert workflow.get('permissions') == {}, f'{path.name}: top-level permissions must be {{}}'
    for job_id, job in workflow['jobs'].items():
        permissions = job.get('permissions')
        assert isinstance(permissions, dict), f'{path.name}:{job_id} must declare its permissions'
        for scope, level in permissions.items():
            if level == 'write':
                assert path.name in _WRITE_ALLOWED.get(scope, set()), f'{path.name}:{job_id}: {scope}: write'
            else:
                assert level in ('read', 'none'), f'{path.name}:{job_id}: {scope}: {level}'


@pytest.mark.parametrize('path', WORKFLOW_FILES, ids=lambda p: p.name)
def test_no_dangerous_triggers_or_script_injection(path):
    workflow = _load(path)
    # pull_request_target / workflow_run run fork code with a privileged token.
    assert not {'pull_request_target', 'workflow_run'} & set(_triggers(workflow))
    for job_id, step in _steps(workflow):
        script = step.get('run', '')
        assert not _UNTRUSTED.search(script), f'{path.name}:{job_id}: untrusted context interpolated in run'


@pytest.mark.parametrize('path', WORKFLOW_FILES, ids=lambda p: p.name)
def test_checkout_does_not_persist_the_token(path):
    for job_id, step in _steps(_load(path)):
        if str(step.get('uses', '')).startswith('actions/checkout@'):
            assert (step.get('with') or {}).get('persist-credentials') is False, f'{path.name}:{job_id}'


@pytest.mark.parametrize('path', WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path):
    for job_id, job in _load(path)['jobs'].items():
        assert isinstance(job.get('timeout-minutes'), int), f'{path.name}:{job_id}'


def test_ci_cancels_superseded_runs(ci):
    concurrency = ci.get('concurrency') or {}
    assert '${{ github.ref }}' in concurrency.get('group', '')
    assert concurrency.get('cancel-in-progress')


def _job_running(ci: Dict[Any, Any], needle: str) -> List[str]:
    return [job_id for job_id, step in _steps(ci) if needle in step.get('run', '')]


def test_ci_tests_every_os_on_oldest_and_newest_python_with_all_extras(ci):
    # Without the extras, the graph/GUI security tests (offline HTML, script-injection escaping)
    # importorskip away; without Windows/macOS, OS-specific bugs (permissions, encodings) go unseen.
    jobs = _job_running(ci, 'pip install -e ".[dev,gui,graph,image]"')
    assert 'test' in jobs
    matrix = ci['jobs']['test']['strategy']['matrix']
    assert ci['jobs']['test']['strategy'].get('fail-fast') is False
    combos = {(os_name, py) for os_name in matrix['os'] for py in matrix['python-version']}
    combos |= {(extra['os'], extra['python-version']) for extra in matrix.get('include', [])}
    for os_name in ('ubuntu-latest', 'windows-latest', 'macos-latest'):
        for py in ('3.10', '3.13'):
            assert (os_name, py) in combos
    for py in ('3.11', '3.12'):
        assert ('ubuntu-latest', py) in combos


def test_ci_fails_when_an_extra_dependent_test_is_skipped(ci):
    # A silently skipped security test is worse than a failing one.
    assert any('could not import' in step.get('run', '') for _, step in _steps(ci))


def test_ci_keeps_a_minimal_job_for_the_optional_import_fallbacks(ci):
    assert _job_running(ci, 'pip install -e ".[dev]"')


def test_ci_type_checks_sources_and_tests(ci):
    assert _job_running(ci, 'mypy src tests')


def test_ci_audits_dependencies_for_known_vulnerabilities(ci):
    assert _job_running(ci, 'pip-audit')


def test_codeql_analyses_python():
    codeql = _load(GITHUB / 'workflows' / 'codeql.yml')
    init = [step for _, step in _steps(codeql) if str(step.get('uses', '')).startswith('github/codeql-action/init@')]
    assert init and init[0]['with']['languages'] == 'python'


def test_dependabot_covers_pip_and_github_actions():
    config = _load(GITHUB / 'dependabot.yml')
    assert config['version'] == 2
    ecosystems = {update['package-ecosystem'] for update in config['updates']}
    assert {'pip', 'github-actions'} <= ecosystems
