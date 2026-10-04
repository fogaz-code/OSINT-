import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from secure_osint.utils import deadline


def test_unbounded_by_default():
    assert deadline.remaining() is None
    assert deadline.clamp_timeout(15.0) == 15.0


def test_scope_clamps_and_restores():
    with deadline.deadline_scope(2.0):
        assert 0 < deadline.clamp_timeout(15.0) <= 2.0
    assert deadline.remaining() is None


def test_nested_scope_never_extends_outer():
    with deadline.deadline_scope(1.0):
        with deadline.deadline_scope(60.0):
            assert deadline.remaining() <= 1.0


def test_expired_scope_raises_permanent_error():
    with deadline.deadline_scope(0.0):
        time.sleep(0.01)
        with pytest.raises(deadline.DeadlineExceeded) as exc:
            deadline.clamp_timeout(15.0)
    assert exc.value.transient is False


def test_submit_in_context_propagates_to_worker_threads():
    with ThreadPoolExecutor(max_workers=1) as pool, deadline.deadline_scope(5.0):
        plain = pool.submit(deadline.remaining).result()
        carried = deadline.submit_in_context(pool, deadline.remaining).result()
    assert plain is None
    assert carried is not None and 0 < carried <= 5.0
