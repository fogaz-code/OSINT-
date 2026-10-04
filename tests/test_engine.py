import threading
import time
from unittest.mock import Mock


from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig
from secure_osint.sources.base import SourceUnavailable, TransientSourceError


def _wf(*steps):
    return WorkflowConfig(name='t', description='d', input_type='generic', risk='low', steps=list(steps))


def _engine(catalog, **kw):
    return WorkflowEngine(catalog=catalog, backoff=lambda attempt: 0.0, **kw)


def test_source_failure_is_not_reported_as_success():
    src = Mock()
    src.fetch.side_effect = SourceUnavailable('HTTP 404')
    result = _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x', retry=3)), 'in')['a']
    assert result.status == StepStatus.UNAVAILABLE
    assert src.fetch.call_count == 1  # errori permanenti non vengono ritentati


def test_transient_errors_are_retried_then_succeed():
    src = Mock()
    src.fetch.side_effect = [TransientSourceError('503'), TransientSourceError('503'), {'ok': 1}]
    result = _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x', retry=3)), 'in')['a']
    assert result.status == StepStatus.SUCCESS
    assert result.attempts == 3


def test_transient_errors_exhaust_attempts():
    src = Mock()
    src.fetch.side_effect = TransientSourceError('timeout')
    result = _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x', retry=2)), 'in')['a']
    assert result.status == StepStatus.ERROR
    assert src.fetch.call_count == 2


def test_unexpected_exception_is_error_without_retry():
    src = Mock()
    src.fetch.side_effect = KeyError('boom')
    result = _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x', retry=5)), 'in')['a']
    assert result.status == StepStatus.ERROR
    assert src.fetch.call_count == 1


def test_non_dict_result_is_error():
    src = Mock()
    src.fetch.return_value = ['not', 'a', 'dict']
    assert _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x')), 'in')['a'].status == StepStatus.ERROR


def test_unknown_tool_is_unavailable():
    assert _engine({}).execute(_wf(StepConfig(id='a', type='nope')), 'in')['a'].status == StepStatus.UNAVAILABLE


def test_skipped_when_partial_results_disabled():
    bad, good = Mock(), Mock()
    bad.fetch.side_effect = SourceUnavailable('x')
    good.fetch.return_value = {}
    results = _engine({'bad': bad, 'good': good}, allow_partial_results=False).execute(
        _wf(StepConfig(id='a', type='bad'), StepConfig(id='b', type='good', depends_on=['a'])), 'in'
    )
    assert results['b'].status == StepStatus.SKIPPED
    good.fetch.assert_not_called()


def test_upstream_data_and_input_are_passed():
    first, second = Mock(), Mock()
    first.fetch.return_value = {'ips': ['1.1.1.1']}
    second.fetch.return_value = {}
    _engine({'f': first, 's': second}).execute(
        _wf(
            StepConfig(id='a', type='f', params={'input': 'overridden?'}),
            StepConfig(id='b', type='s', depends_on=['a'], params={'k': 'v'}),
        ),
        'target',
    )
    params = second.fetch.call_args[0][0]
    assert params['input'] == 'target'
    assert params['k'] == 'v'
    assert params['upstream'] == {'a': {'ips': ['1.1.1.1']}}


def test_forward_dependency_runs_in_graph_order():
    order = []
    src = Mock()
    src.fetch.side_effect = lambda p: order.append(p['step']) or {}
    _engine({'x': src}).execute(
        _wf(
            StepConfig(id='b', type='x', depends_on=['a'], params={'step': 'b'}),
            StepConfig(id='a', type='x', params={'step': 'a'}),
        ),
        'in',
    )
    assert order == ['a', 'b']


def test_independent_steps_run_in_parallel():
    barrier = threading.Barrier(3, timeout=5)

    class Src:
        def fetch(self, params):
            barrier.wait()  # si sblocca solo se i 3 step girano contemporaneamente
            return {}

    results = _engine({'x': Src()}).execute(_wf(*(StepConfig(id=f's{i}', type='x') for i in range(3))), 'in')
    assert all(r.status == StepStatus.SUCCESS for r in results.values())


def test_step_timeout_is_enforced():
    release = threading.Event()

    class Hang:
        def fetch(self, params):
            release.wait(10)
            return {}

    start = time.monotonic()
    result = _engine({'x': Hang()}).execute(_wf(StepConfig(id='a', type='x', timeout=1)), 'in')['a']
    release.set()
    assert result.status == StepStatus.ERROR
    assert 'timed out' in result.error_message
    assert time.monotonic() - start < 5


def test_require_confirmation():
    src = Mock()
    src.fetch.return_value = {}
    wf = _wf(StepConfig(id='a', type='x', require_confirmation=True))
    assert _engine({'x': src}).execute(wf, 'in')['a'].status == StepStatus.SKIPPED
    assert _engine({'x': src}, confirm=lambda s: True).execute(wf, 'in')['a'].status == StepStatus.SUCCESS


def test_observer_receives_start_and_finish_for_every_step():
    events = []

    class Observer:
        def step_started(self, step_id, step_type):
            events.append(('start', step_id))

        def step_finished(self, step_id, result):
            events.append(('finish', step_id, result.status))

    ok, bad = Mock(), Mock()
    ok.fetch.return_value = {}
    bad.fetch.side_effect = SourceUnavailable('x')
    _engine({'ok': ok, 'bad': bad}, observer=Observer()).execute(
        _wf(
            StepConfig(id='a', type='ok'),
            StepConfig(id='b', type='bad', depends_on=['a']),
            StepConfig(id='c', type='missing'),
        ),
        'in',
    )
    assert ('start', 'a') in events and ('finish', 'a', StepStatus.SUCCESS) in events
    assert ('start', 'b') in events and ('finish', 'b', StepStatus.UNAVAILABLE) in events
    # Anche gli step risolti senza esecuzione (tool mancante) vengono notificati come conclusi.
    assert ('finish', 'c', StepStatus.UNAVAILABLE) in events
    assert events.index(('start', 'a')) < events.index(('finish', 'a', StepStatus.SUCCESS))
