"""C2 partial results and tool resolution: honest statuses, nothing incomplete in the cache."""

from unittest.mock import Mock

from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig


def _wf(*steps):
    return WorkflowConfig(name='t', description='d', input_type='generic', risk='low', steps=list(steps))


def _cacheable(data):
    src = Mock(cacheable=True)
    src.fetch.return_value = data
    return src


def _run(src, cache=None, **kw):
    engine = WorkflowEngine(catalog={'x': src}, cache=cache, backoff=lambda a: 0.0)
    return engine.execute(_wf(StepConfig(id='a', type='x', **kw)), 'in')['a']


def test_partial_result_is_degraded_and_not_cached():
    data = {'platforms': [], 'partial': True, 'errors': ['github: timeout', 'gitlab: rate limited']}
    cache = Mock()
    cache.get.return_value = None
    result = _run(_cacheable(data), cache=cache)
    assert result.status == StepStatus.DEGRADED
    assert result.data == data
    assert result.attempts == 1
    assert 'partial' in result.error_message.lower() and '2' in result.error_message
    cache.set.assert_not_called()


def test_partial_degraded_step_still_feeds_dependents():
    partial, downstream = Mock(cacheable=False), Mock(cacheable=False)
    partial.fetch.return_value = {'partial': True, 'errors': ['x']}
    downstream.fetch.return_value = {'ok': 1}
    results = WorkflowEngine(catalog={'p': partial, 'd': downstream}, backoff=lambda a: 0.0).execute(
        _wf(StepConfig(id='a', type='p'), StepConfig(id='b', type='d', depends_on=['a'])), 'in'
    )
    assert results['a'].status == StepStatus.DEGRADED
    assert results['b'].status == StepStatus.SUCCESS
    assert downstream.fetch.call_args[0][0]['upstream'] == {'a': {'partial': True, 'errors': ['x']}}


def test_errors_without_partial_keep_status_and_skip_cache():
    cache = Mock()
    cache.get.return_value = None
    result = _run(_cacheable({'A': ['1.1.1.1'], 'errors': {'TXT': 'timeout'}}), cache=cache)
    assert result.status == StepStatus.SUCCESS
    assert result.error_message is None
    cache.set.assert_not_called()


def test_partial_flag_without_errors_is_success_but_not_cached():
    cache = Mock()
    cache.get.return_value = None
    result = _run(_cacheable({'partial': True, 'errors': []}), cache=cache)
    assert result.status == StepStatus.SUCCESS
    cache.set.assert_not_called()


def test_complete_result_is_cached():
    cache = Mock()
    cache.get.return_value = None
    result = _run(_cacheable({'A': ['1.1.1.1'], 'partial': False, 'errors': []}), cache=cache)
    assert result.status == StepStatus.SUCCESS
    cache.set.assert_called_once()


# --- tool resolution ---


class _Catalog(dict):
    def get(self, key, default=None):
        raise RuntimeError('missing API key')


def test_tool_factory_failure_is_unavailable_with_reason():
    result = WorkflowEngine(catalog=_Catalog()).execute(_wf(StepConfig(id='a', type='x')), 'in')['a']
    assert result.status == StepStatus.UNAVAILABLE
    assert result.error_message == 'Tool x failed to initialize: missing API key'


def test_unknown_tool_reason():
    result = WorkflowEngine(catalog={}).execute(_wf(StepConfig(id='a', type='nope')), 'in')['a']
    assert result.status == StepStatus.UNAVAILABLE
    assert result.error_message == 'Tool nope not found.'
