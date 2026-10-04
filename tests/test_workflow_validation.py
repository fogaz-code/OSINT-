import pytest
from pydantic import ValidationError

from secure_osint.core.workflow import StepConfig, WorkflowConfig, load_workflow_from_file


def _wf(*steps):
    return WorkflowConfig(name='t', description='d', input_type='g', risk='low', steps=list(steps))


@pytest.mark.parametrize(
    'steps',
    [
        [StepConfig(id='a', type='x'), StepConfig(id='a', type='x')],
        [StepConfig(id='a', type='x', depends_on=['ghost'])],
        [StepConfig(id='a', type='x', depends_on=['a'])],
        [StepConfig(id='a', type='x', depends_on=['b']), StepConfig(id='b', type='x', depends_on=['a'])],
    ],
)
def test_invalid_graphs_rejected(steps):
    with pytest.raises(ValidationError):
        _wf(*steps)


@pytest.mark.parametrize(
    'field', [{'timeout': -5}, {'timeout': 100000}, {'retry': 1000000}, {'risk': 'yolo'}, {'depend_on': ['typo']}]
)
def test_invalid_step_fields_rejected(field):
    with pytest.raises(ValidationError):
        StepConfig(id='a', type='x', **field)


@pytest.mark.parametrize('body', ['- a\n- b\n', '', 'just a string'])
def test_non_mapping_yaml_rejected(tmp_path, body):
    path = tmp_path / 'w.yaml'
    path.write_text(body, encoding='utf-8')
    with pytest.raises(ValueError):
        load_workflow_from_file(str(path))


def test_python_tags_not_executed(tmp_path):
    path = tmp_path / 'w.yaml'
    path.write_text('name: !!python/object/apply:os.system ["echo pwned"]\n', encoding='utf-8')
    with pytest.raises(ValueError):
        load_workflow_from_file(str(path))


def test_oversized_yaml_rejected(tmp_path):
    path = tmp_path / 'w.yaml'
    path.write_text('name: ' + 'a' * (1024 * 1024 + 10), encoding='utf-8')
    with pytest.raises(ValueError, match='exceeds'):
        load_workflow_from_file(str(path))


def test_shipped_workflows_are_valid():
    from pathlib import Path

    from secure_osint.cli import DEFAULT_WORKFLOW_DIR

    files = sorted(Path(DEFAULT_WORKFLOW_DIR).glob('*.yaml'))
    assert files
    for f in files:
        load_workflow_from_file(str(f))
