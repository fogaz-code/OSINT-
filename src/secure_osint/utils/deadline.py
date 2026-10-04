"""Per-step time budget, propagated from the engine down to the HTTP layer.

The engine opens a ``deadline_scope`` around each step attempt; ``SafeHttpClient`` (and any other
blocking call that can take a timeout) clamps its own timeout with ``clamp_timeout`` so no single
request can outlive the step that issued it. This is what lets a timed-out step actually stop
instead of leaving an orphaned worker blocked on the network.

The deadline lives in a ``ContextVar``. Context does NOT flow into new threads automatically: a
source that fans out onto its own thread pool must submit work through ``submit_in_context`` (or
``contextvars.copy_context().run``) or its requests will run unbounded.
"""

import contextvars
import time
from concurrent.futures import Executor, Future
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, TypeVar

from secure_osint.sources.base import SourceError

T = TypeVar('T')

_DEADLINE: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar('secure_osint_deadline', default=None)


class DeadlineExceeded(SourceError):
    """The step's time budget is spent. Permanent for this step: retrying cannot help."""


@contextmanager
def deadline_scope(seconds: Optional[float]) -> Iterator[None]:
    """Bound everything inside the block to ``seconds`` from now (``None`` = no new bound).

    Nested scopes never extend an outer deadline: the earlier of the two wins.
    """
    if seconds is None:
        yield
        return
    new = time.monotonic() + max(0.0, seconds)
    outer = _DEADLINE.get()
    token = _DEADLINE.set(new if outer is None else min(outer, new))
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def remaining() -> Optional[float]:
    """Seconds left in the current scope, ``None`` if unbounded. May be <= 0 once expired."""
    deadline = _DEADLINE.get()
    return None if deadline is None else deadline - time.monotonic()


def clamp_timeout(timeout: float) -> float:
    """Return ``min(timeout, remaining())``; raise ``DeadlineExceeded`` if the budget is spent."""
    left = remaining()
    if left is None:
        return timeout
    if left <= 0:
        raise DeadlineExceeded('step time budget exhausted')
    return min(timeout, left)


def submit_in_context(executor: Executor, fn: Callable[..., T], *args: Any, **kwargs: Any) -> 'Future[T]':
    """``executor.submit`` that carries the caller's deadline into the worker thread."""
    ctx = contextvars.copy_context()
    return executor.submit(ctx.run, fn, *args, **kwargs)
