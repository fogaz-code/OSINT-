"""The engine's daemon-thread executor: bounded, abandonable, never blocks shutdown or exit."""

import threading
import time

from secure_osint.core.engine import _DaemonExecutor


def _wait_until(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_runs_work_and_returns_result():
    ex = _DaemonExecutor(2, name_prefix='t')
    try:
        assert ex.submit(lambda a, b: a + b, 2, 3).result(timeout=5) == 5
    finally:
        ex.shutdown()


def test_exception_is_carried_by_the_future():
    ex = _DaemonExecutor(1, name_prefix='t')

    def boom():
        raise ValueError('bad')

    try:
        assert isinstance(ex.submit(boom).exception(timeout=5), ValueError)
    finally:
        ex.shutdown()


def test_concurrency_is_bounded():
    lock = threading.Lock()
    live, peak = [0], [0]
    release = threading.Event()

    def work():
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        release.wait(5)
        with lock:
            live[0] -= 1

    ex = _DaemonExecutor(2, name_prefix='t')
    try:
        futures = [ex.submit(work) for _ in range(6)]
        assert _wait_until(lambda: live[0] == 2)
        time.sleep(0.1)
        assert peak[0] == 2
        release.set()
        for f in futures:
            f.result(timeout=5)
    finally:
        ex.shutdown()
    assert peak[0] == 2


def test_abandoned_worker_frees_its_slot():
    release = threading.Event()
    ex = _DaemonExecutor(1, name_prefix='t')
    try:
        stuck = ex.submit(release.wait, 10)
        assert _wait_until(stuck.running)
        queued = ex.submit(lambda: 'next')
        time.sleep(0.1)
        assert not queued.done()  # the only slot is taken
        assert ex.abandon(stuck) is True
        assert queued.result(timeout=5) == 'next'
    finally:
        release.set()
        ex.shutdown()


def test_abandon_reports_false_for_a_finished_future():
    """The scheduler relies on this to keep a result that landed just before the timeout."""
    ex = _DaemonExecutor(1, name_prefix='t')
    try:
        done = ex.submit(lambda: 1)
        done.result(timeout=5)
        assert ex.abandon(done) is False
    finally:
        ex.shutdown()


def test_abandon_cancels_queued_work():
    release = threading.Event()
    ex = _DaemonExecutor(1, name_prefix='t')
    try:
        ex.submit(release.wait, 10)
        queued = ex.submit(lambda: 'never')
        assert ex.abandon(queued) is True
        assert queued.cancelled()
    finally:
        release.set()
        ex.shutdown()


def test_shutdown_cancels_queued_work_and_does_not_block():
    release = threading.Event()
    ex = _DaemonExecutor(1, name_prefix='t')
    running = ex.submit(release.wait, 10)
    assert _wait_until(running.running)
    queued = ex.submit(lambda: 'never')
    start = time.monotonic()
    ex.shutdown()
    assert time.monotonic() - start < 0.5
    assert queued.cancelled()
    release.set()
    assert running.result(timeout=5) is True


def test_submit_after_shutdown_is_refused():
    ex = _DaemonExecutor(1, name_prefix='t')
    ex.shutdown()
    try:
        ex.submit(lambda: 1)
    except RuntimeError:
        pass
    else:
        raise AssertionError('submit after shutdown must raise')


def test_workers_are_daemon_and_named():
    ex = _DaemonExecutor(1, name_prefix='osint-step')
    try:
        thread = ex.submit(threading.current_thread).result(timeout=5)
    finally:
        ex.shutdown()
    assert thread.daemon is True
    assert thread.name.startswith('osint-step_')


def test_work_submitted_after_abandon_on_an_empty_queue_still_runs():
    # Regression: a worker that took a queued item after finishing another left a stale "idle" token, and
    # abandon() only replaced the worker when the queue was non-empty. The next submit consumed the stale
    # token, spawned nobody, and the item sat in the queue forever behind the stuck worker.
    ex = _DaemonExecutor(1, name_prefix='t')
    release = threading.Event()
    try:
        first = ex.submit(lambda: 'a')
        stuck = ex.submit(release.wait, 10)  # queued behind `first`, then taken by the same worker
        assert first.result(timeout=5) == 'a'
        assert _wait_until(stuck.running)
        assert ex.abandon(stuck)
        assert ex.submit(lambda: 'c').result(timeout=5) == 'c'
    finally:
        release.set()
        ex.shutdown()
