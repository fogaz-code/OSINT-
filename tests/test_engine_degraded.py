from unittest.mock import Mock

from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig


def test_engine_degraded():
    mock_source = Mock()
    mock_source.fetch.side_effect = TimeoutError('Timeout')
    mock_report = Mock()
    mock_report.fetch.return_value = {'summary': 'partial report'}
    # Catalogo iniettato: niente mutazione dello stato globale condiviso tra i test.
    catalog = {'dns': mock_source, 'report': mock_report}

    workflow_config = WorkflowConfig(
        name='test',
        description='description',
        input_type='generic',
        risk='low',
        steps=[
            StepConfig(
                id='step1',
                type='dns',
                params={},
                depends_on=[],
                optional_dependencies=[],
                timeout=10,
                retry=1,
                risk='low',
                require_confirmation=False,
            ),
            StepConfig(
                id='step2',
                type='report',
                params={},
                depends_on=['step1'],
                optional_dependencies=[],
                timeout=10,
                retry=1,
                risk='low',
                require_confirmation=False,
            ),
        ],
    )

    engine = WorkflowEngine(allow_partial_results=True, catalog=catalog)
    results = engine.execute(workflow_config, 'test_input')

    assert results['step1'].status == StepStatus.ERROR
    # step2 è stato eseguito con successo ma senza il suo input a monte: DEGRADED, non SUCCESS.
    assert results['step2'].status == StepStatus.DEGRADED
    assert results['step2'].data is not None
