"""Step timeouts: hung workers must not block exit, budgets bound retries, statuses stay honest."""

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from secure_osint.core import engine as engine_module
from secure_osint.core.engine import WorkflowEngine
from secure_osint.core.workflow import StepConfig, StepStatus, WorkflowConfig
from secure_osint.sources.base import TransientSourceError
from secure_osint.utils import deadline

SRC_DIR = Path(__file__).resolve().parents[1] / 'src'


def _wf(*steps):
    return WorkflowConfig(name='t', description='d', input_type='generic', risk='low', steps=list(steps))


def _engine(catalog, **kw):
    kw.setdefault('backoff', lambda attempt: 0.0)
    return WorkflowEngine(catalog=catalog, **kw)


def _fast_step(timeout: float, **kw) -> StepConfig:
    """A step with a sub-second budget (the schema only allows whole seconds >= 1)."""
    return StepConfig.model_construct(id=kw.pop('id', 'a'), type=kw.pop('type', 'x'), timeout=timeout, **kw)


# --- 1. a timed-out step must not keep the process alive ---


def test_hung_step_does_not_block_process_exit():
    script = textwrap.dedent(
        """
        import time
        from secure_osint.core.engine import WorkflowEngine
        from secure_osint.core.workflow import StepConfig, WorkflowConfig

        class Sleeper:
            def fetch(self, params):
                time.sleep(30)  # not interruptible: the worker can only be abandoned
                return {}

        wf = WorkflowConfig(
            name='t', description='d', input_type='generic', risk='low',
            steps=[StepConfig(id='a', type='x', timeout=1)],
        )
        result = WorkflowEngine(catalog={'x': Sleeper()}).execute(wf, 'in')['a']
        print(result.status.value)
        """
    )
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join(p for p in (str(SRC_DIR), env.get('PYTHONPATH', '')) if p)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, '-c', script], env=env, capture_output=True, text=True, encoding='utf-8', timeout=25
        )
    except subprocess.TimeoutExpired:
        pytest.fail('process kept running after the step timed out (worker thread joined at exit)')
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == 'ERROR'
    assert elapsed < 10, f'process took {elapsed:.1f}s to exit'


def test_workers_are_daemon_threads():
    seen = {}

    class Probe:
        def fetch(self, params):
            seen['daemon'] = threading.current_thread().daemon
            return {}

    assert _engine({'x': Probe()}).execute(_wf(StepConfig(id='a', type='x')), 'in')['a'].status == StepStatus.SUCCESS
    assert seen['daemon'] is True


def test_abandoned_worker_does_not_starve_later_steps():
    """With one worker, a hung step must not leave the next step waiting for a free thread."""
    release = threading.Event()

    class Hang:
        def fetch(self, params):
            release.wait(10)
            return {}

    ok = Mock()
    ok.fetch.return_value = {'ok': True}
    try:
        results = _engine({'hang': Hang(), 'ok': ok}, max_workers=1).execute(
            _wf(
                _fast_step(0.3, id='a', type='hang'),
                _fast_step(0.5, id='b', type='ok', optional_dependencies=['a']),
            ),
            'in',
        )
    finally:
        release.set()
    assert results['a'].status == StepStatus.ERROR
    assert results['b'].status == StepStatus.DEGRADED


def test_queued_step_budget_starts_when_it_runs():
    """A step waiting for a free worker must not burn its budget while queued."""

    class Slow:
        def fetch(self, params):
            time.sleep(0.8)
            return {}

    class Quick:
        def fetch(self, params):
            return {}

    results = _engine({'slow': Slow(), 'quick': Quick()}, max_workers=1).execute(
        _wf(_fast_step(2.0, id='a', type='slow'), _fast_step(0.3, id='b', type='quick')), 'in'
    )
    assert results['a'].status == StepStatus.SUCCESS
    assert results['b'].status == StepStatus.SUCCESS


# --- 2. deadline contract (C1) ---


def test_each_attempt_runs_inside_a_deadline_scope():
    seen = []

    class Probe:
        def fetch(self, params):
            seen.append(deadline.remaining())
            return {}

    _engine({'x': Probe()}).execute(_wf(StepConfig(id='a', type='x', timeout=5)), 'in')
    assert seen and seen[0] is not None and 0 < seen[0] <= 5


def test_deadline_exceeded_is_error_without_retry():
    src = Mock()
    src.fetch.side_effect = deadline.DeadlineExceeded('step time budget exhausted')
    result = _engine({'x': src}).execute(_wf(StepConfig(id='a', type='x', retry=5)), 'in')['a']
    assert result.status == StepStatus.ERROR
    assert 'timed out' in result.error_message
    assert src.fetch.call_count == 1
    assert result.attempts == 1


def test_backoff_that_cannot_fit_the_budget_is_not_started():
    src = Mock()
    src.fetch.side_effect = TransientSourceError('503')
    start = time.monotonic()
    result = _engine({'x': src}, backoff=lambda attempt: 5.0).execute(
        _wf(StepConfig(id='a', type='x', retry=3, timeout=2)), 'in'
    )['a']
    assert time.monotonic() - start < 1.0  # gave up at once instead of sleeping into the timeout
    assert result.status == StepStatus.ERROR
    assert result.attempts == 1
    assert '503' in result.error_message
    assert src.fetch.call_count == 1


def test_no_retry_runs_after_the_step_budget():
    src = Mock()
    src.fetch.side_effect = TransientSourceError('503')
    result = _engine({'x': src}, backoff=lambda attempt: 0.1).execute(_wf(_fast_step(0.5, retry=10)), 'in')['a']
    assert result.status == StepStatus.ERROR
    calls = src.fetch.call_count
    assert 1 <= calls < 10
    time.sleep(0.4)
    assert src.fetch.call_count == calls  # no orphaned retry loop keeps hitting the source


# --- 3. a timed-out step reports how many attempts it actually made ---


def test_timeout_reports_real_attempt_count():
    release = threading.Event()
    calls = []

    class FailThenHang:
        def fetch(self, params):
            calls.append(1)
            if len(calls) == 1:
                raise TransientSourceError('503')
            release.wait(10)
            return {}

    try:
        result = _engine({'x': FailThenHang()}).execute(_wf(_fast_step(0.5, retry=3)), 'in')['a']
    finally:
        release.set()
    assert result.status == StepStatus.ERROR
    assert 'timed out' in result.error_message
    assert result.attempts == 2


# --- 4. a future that completes just before the deadline sweep keeps its result ---


def test_result_completed_before_sweep_is_not_discarded(monkeypatch):
    real_wait = engine_module.wait

    def late_wait(fs, timeout=None, return_when=None):
        # Simulate the scheduler waking up late: the step finished, but wait() reports nothing done
        # and the step's deadline has already passed when the sweep runs.
        real_wait(fs, timeout=5)
        time.sleep(0.6)
        return set(), set(fs)

    monkeypatch.setattr(engine_module, 'wait', late_wait)
    src = Mock()
    src.fetch.return_value = {'ok': True}
    result = _engine({'x': src}).execute(_wf(_fast_step(0.2)), 'in')['a']
    assert result.status == StepStatus.SUCCESS
    assert result.data == {'ok': True}
