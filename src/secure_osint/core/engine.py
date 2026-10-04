import itertools
import logging
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, wait
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Deque, Dict, List, Mapping, Optional, Protocol, Set, Tuple

from secure_osint.core.references import UnresolvedReference, find_references, resolve
from secure_osint.core.workflow import StepConfig, StepResult, StepStatus, WorkflowConfig
from secure_osint.sources.base import BaseSource, SourceError
from secure_osint.utils.deadline import DeadlineExceeded, deadline_scope
from secure_osint.utils.resilience import backoff_delay

if TYPE_CHECKING:
    from secure_osint.utils.cache import ResultCache

logger = logging.getLogger(__name__)

OK_STATUSES = (StepStatus.SUCCESS, StepStatus.DEGRADED)
# Built-in exceptions worth retrying even when the source does not raise SourceError.
TRANSIENT_BUILTINS = (TimeoutError, ConnectionError)
# Extra time the scheduler gives a step past its budget before abandoning it, so a worker that honours the
# deadline (clamped HTTP timeouts) can report its own, more precise outcome instead of a generic timeout.
TIMEOUT_GRACE = 0.25
# A retry is only started if, after its backoff, at least this much of the step budget is left.
MIN_ATTEMPT_BUDGET = 0.1
# How often the scheduler re-checks steps that are queued behind busy workers and have no deadline yet.
QUEUED_POLL_INTERVAL = 0.05

# (status, data, error, attempts, cached)
Outcome = Tuple[StepStatus, Optional[Dict[str, Any]], Optional[str], int, bool]
_WorkItem = Tuple['Future[Any]', Callable[..., Any], Tuple[Any, ...]]


class StepObserver(Protocol):
    """Progress notifications, called from the thread running ``execute``."""

    def step_started(self, step_id: str, step_type: str) -> None:
        """Called when a step begins executing."""
        ...

    def step_finished(self, step_id: str, result: StepResult) -> None:
        """Called when a step finishes, with its result."""
        ...


class _DaemonExecutor:
    """A bounded thread pool whose workers are daemon threads.

    ``ThreadPoolExecutor`` workers are joined at interpreter exit (``threading._register_atexit``), so a
    single step stuck in an uninterruptible call keeps the whole process alive long after the run is over.
    Daemon workers do not. A step that blew its budget is *abandoned*: its thread stops counting against
    ``max_workers`` (a fresh worker takes the slot) and exits as soon as its call finally returns.
    """

    def __init__(self, max_workers: int, name_prefix: str):
        """Initialize _DaemonExecutor."""
        self._max_workers = max(1, max_workers)
        self._name_prefix = name_prefix
        # Queue, idle count and worker count change together under one lock, so "is someone free to take
        # this item?" is always answered from consistent numbers.
        self._queue: 'Deque[_WorkItem]' = deque()
        self._lock = threading.Lock()
        self._ready = threading.Condition(self._lock)
        self._idle = 0  # workers blocked waiting for an item
        self._workers = 0  # live threads counted against max_workers
        self._abandoned: Set['Future[Any]'] = set()
        self._shutdown = False
        self._names = itertools.count()

    def submit(self, fn: Callable[..., Any], *args: Any) -> 'Future[Any]':
        """Schedule ``fn(*args)`` and return its Future."""
        future: 'Future[Any]' = Future()
        with self._lock:
            if self._shutdown:
                raise RuntimeError('cannot schedule new work after shutdown')
            self._queue.append((future, fn, args))
            self._grow()
            self._ready.notify()
        return future

    def abandon(self, future: 'Future[Any]') -> bool:
        """Give up on ``future``: a queued one never runs, a running one's worker leaves the pool.

        Returns ``False`` when the future had already finished, so the caller can still use its result.
        """
        with self._lock:
            if future in self._abandoned:
                return True
            if future.cancel():  # still queued: it simply never runs
                return True
            if future.done():
                return False
            self._abandoned.add(future)
            self._workers -= 1
            self._grow()
            return True

    def shutdown(self) -> None:
        """Cancel queued work and let idle workers exit. Never blocks on running (or abandoned) work."""
        with self._lock:
            self._shutdown = True
            while self._queue:
                self._queue.popleft()[0].cancel()
            self._ready.notify_all()

    def _grow(self) -> None:
        # Caller holds self._lock. Spawn workers while queued items outnumber the workers free to take them.
        while not self._shutdown and len(self._queue) > self._idle and self._workers < self._max_workers:
            self._workers += 1
            self._idle += 1  # counted as idle from birth: it goes straight to the queue
            name = f'{self._name_prefix}_{next(self._names)}'
            threading.Thread(target=self._work, name=name, daemon=True).start()

    def _next_item(self) -> Optional[_WorkItem]:
        # Caller holds self._lock and is counted in self._idle; returns None when the pool shuts down.
        while not self._queue:
            if self._shutdown:
                self._idle -= 1
                return None
            self._ready.wait()
        self._idle -= 1
        return self._queue.popleft()

    def _work(self) -> None:
        while True:
            with self._lock:
                item = self._next_item()
            if item is None:
                return
            future, fn, args = item
            del item
            if future.set_running_or_notify_cancel():
                try:
                    result = fn(*args)
                except BaseException as e:  # mirror ThreadPoolExecutor: the Future carries every failure
                    future.set_exception(e)
                else:
                    future.set_result(result)
            with self._lock:
                if future in self._abandoned:
                    self._abandoned.discard(future)
                    return  # this thread's slot was already handed to a replacement worker
                self._idle += 1
            del future


class _StepState:
    """Progress of one step, shared between the scheduler and the worker thread running it."""

    def __init__(self, timeout: float):
        """Initialize _StepState."""
        self.timeout = timeout
        self.cancel = threading.Event()
        self._lock = threading.Lock()
        self._started: Optional[float] = None
        self._attempts = 0

    def start(self) -> float:
        """Mark the step as running (its budget starts now) and return its absolute deadline."""
        with self._lock:
            self._started = time.monotonic()
            return self._started + self.timeout

    def add_attempt(self) -> int:
        """Record that an attempt is starting and return the attempt count so far."""
        with self._lock:
            self._attempts += 1
            return self._attempts

    @property
    def started(self) -> Optional[float]:
        """Monotonic time the worker began the step, ``None`` while it is still queued."""
        with self._lock:
            return self._started

    @property
    def deadline(self) -> Optional[float]:
        """Absolute monotonic deadline, ``None`` while the step is still queued."""
        with self._lock:
            return None if self._started is None else self._started + self.timeout

    @property
    def attempts(self) -> int:
        """Attempts started so far."""
        with self._lock:
            return self._attempts


@dataclass
class _Running:
    step_id: str
    submitted: float
    degraded: bool
    state: _StepState = field(repr=False)

    def elapsed(self, now: float) -> float:
        started = self.state.started
        return now - (self.submitted if started is None else started)


class WorkflowEngine:
    """Runs the workflow DAG in parallel: each step starts as soon as its dependencies are done."""

    def __init__(
        self,
        allow_partial_results: bool = True,
        catalog: Optional[Mapping[str, BaseSource]] = None,
        max_workers: int = 8,
        confirm: Optional[Callable[[StepConfig], bool]] = None,
        backoff: Callable[[int], float] = backoff_delay,
        observer: Optional[StepObserver] = None,
        cache: Optional['ResultCache'] = None,
        cache_ttl: Optional[int] = None,
    ):
        """Initialize WorkflowEngine."""
        if catalog is None:
            from secure_osint.sources.tool_catalog import tool_catalog

            catalog = tool_catalog
        self.allow_partial_results = allow_partial_results
        self.tool_catalog = catalog
        self.max_workers = max_workers
        self.confirm = confirm
        self.backoff = backoff
        self.observer = observer
        self.cache = cache
        self.cache_ttl = cache_ttl

    def execute(self, workflow: WorkflowConfig, input_data: str) -> Dict[str, StepResult]:
        """Run the workflow as a parallel dependency DAG.

        Args:
            workflow: The validated workflow to run.
            input_data: The target the run is about.

        Returns:
            A mapping of step id to StepResult, in the workflow's declared order.
        """
        steps = {step.id: step for step in workflow.steps}
        order = workflow.topological_order()
        results: Dict[str, StepResult] = {}
        pending: List[str] = list(order)
        running: Dict['Future[Outcome]', _Running] = {}

        executor = _DaemonExecutor(self.max_workers, name_prefix='osint-step')
        try:
            while pending or running:
                self._schedule_ready(steps, pending, results, running, executor, input_data)
                if not running:
                    continue  # new synchronous results (skipped/unavailable): schedule again

                wait(list(running), timeout=self._next_wakeup(running), return_when=FIRST_COMPLETED)
                now = time.monotonic()
                for future, info in list(running.items()):
                    # A finished future always wins over its deadline, even if it completed after wait() returned.
                    if future.done():
                        running.pop(future)
                        self._finish(results, info.step_id, self._collect(future, info))
                        continue
                    deadline = info.state.deadline
                    if deadline is None or now < deadline + TIMEOUT_GRACE:
                        continue
                    running.pop(future)
                    if executor.abandon(future):
                        self._time_out(results, info, now)
                    else:  # it finished between the done() check and the abandon: keep its result
                        self._finish(results, info.step_id, self._collect(future, info))
        finally:
            for info in running.values():  # only on an exception (e.g. Ctrl-C): stop the retry loops
                info.state.cancel.set()
            executor.shutdown()

        return {step.id: results[step.id] for step in workflow.steps}

    @staticmethod
    def _next_wakeup(running: Dict['Future[Outcome]', _Running]) -> float:
        """Seconds until the earliest running step must be timed out."""
        deadlines = [info.state.deadline for info in running.values()]
        started = [d + TIMEOUT_GRACE for d in deadlines if d is not None]
        wakeup = max(0.0, min(started) - time.monotonic()) if started else QUEUED_POLL_INTERVAL
        if len(started) < len(deadlines):
            # Some step is still queued: re-check soon so its deadline is enforced once it starts.
            wakeup = min(wakeup, QUEUED_POLL_INTERVAL)
        return wakeup

    def _time_out(self, results: Dict[str, StepResult], info: _Running, now: float) -> None:
        # The thread cannot be killed: it was abandoned (pool slot released, result discarded); tell its retry
        # loop to stop so it does not keep hitting the source.
        info.state.cancel.set()
        attempts = info.state.attempts
        logger.warning('step timed out', extra={'step_id': info.step_id, 'attempts': attempts})
        self._finish(
            results,
            info.step_id,
            StepResult(
                status=StepStatus.ERROR,
                error_message=f'Step timed out after {info.state.timeout}s',
                execution_time=info.elapsed(now),
                attempts=attempts,
            ),
        )

    def _schedule_ready(
        self,
        steps: Dict[str, StepConfig],
        pending: List[str],
        results: Dict[str, StepResult],
        running: Dict['Future[Outcome]', _Running],
        executor: _DaemonExecutor,
        input_data: str,
    ) -> None:
        for step_id in list(pending):
            step = steps[step_id]
            all_deps = step.depends_on + step.optional_dependencies
            if any(dep not in results for dep in all_deps):
                continue
            pending.remove(step_id)

            referenced = sorted({ref.step_id for ref in find_references(step.params)})
            failed_referenced = [d for d in referenced if results[d].status not in OK_STATUSES]
            if failed_referenced:
                # Even with partial results: without the upstream value the step has no input to run on.
                self._finish(
                    results,
                    step_id,
                    StepResult(
                        status=StepStatus.SKIPPED,
                        error_message=f'Referenced dependencies did not succeed: {failed_referenced}',
                    ),
                )
                continue
            failed_required = [d for d in step.depends_on if results[d].status not in OK_STATUSES]
            failed_optional = [d for d in step.optional_dependencies if results[d].status not in OK_STATUSES]
            if failed_required and not self.allow_partial_results:
                self._finish(
                    results,
                    step_id,
                    StepResult(
                        status=StepStatus.SKIPPED, error_message=f'Required dependencies failed: {failed_required}'
                    ),
                )
                continue
            if step.require_confirmation and not (self.confirm and self.confirm(step)):
                self._finish(
                    results, step_id, StepResult(status=StepStatus.SKIPPED, error_message='Confirmation not given')
                )
                continue

            tool, init_error = self._load_tool(step)
            if tool is None:
                self._finish(results, step_id, StepResult(status=StepStatus.UNAVAILABLE, error_message=init_error))
                continue

            try:
                params = resolve(step.params, {d: results[d].data for d in referenced})
            except UnresolvedReference as e:
                self._finish(results, step_id, StepResult(status=StepStatus.ERROR, error_message=str(e)))
                continue
            # The workflow may set `input` (also through a reference); otherwise it is the run's target.
            params.setdefault('input', input_data)
            params['upstream'] = {d: results[d].data for d in all_deps if results[d].data is not None}
            state = _StepState(step.timeout)
            if self.observer:
                self.observer.step_started(step_id, step.type)
            future = executor.submit(self._run_with_retries, step, tool, params, state)
            running[future] = _Running(
                step_id, time.monotonic(), degraded=bool(failed_required or failed_optional), state=state
            )

    def _load_tool(self, step: StepConfig) -> Tuple[Optional[BaseSource], str]:
        """Return ``(tool, '')``, or ``(None, reason)`` when the source is missing or its factory failed."""
        try:
            tool = self.tool_catalog.get(step.type)
        except Exception as e:  # the source factory itself failed (missing key, bad config...)
            logger.exception('source init failed', extra={'step_id': step.id})
            return None, f'Tool {step.type} failed to initialize: {e}'
        if tool is None:
            return None, f'Tool {step.type} not found.'
        return tool, ''

    def _finish(self, results: Dict[str, StepResult], step_id: str, result: StepResult) -> None:
        results[step_id] = result
        if self.observer:
            self.observer.step_finished(step_id, result)

    def _collect(self, future: 'Future[Outcome]', info: _Running) -> StepResult:
        elapsed = info.elapsed(time.monotonic())
        try:
            status, data, error, attempts, cached = future.result()
        except Exception as e:  # defensive: _run_with_retries is not supposed to raise
            status, data, error, attempts, cached = (
                StepStatus.ERROR,
                None,
                f'{type(e).__name__}: {e}',
                info.state.attempts,
                False,
            )
        if status == StepStatus.SUCCESS and info.degraded:
            status = StepStatus.DEGRADED
        logger.info(
            'step finished',
            extra={
                'step_id': info.step_id,
                'status': status.value,
                'attempts': attempts,
                'cached': cached,
                'elapsed': round(elapsed, 3),
            },
        )
        return StepResult(
            status=status, data=data, error_message=error, execution_time=elapsed, attempts=attempts, cached=cached
        )

    def _run_with_retries(
        self, step: StepConfig, tool: BaseSource, params: Dict[str, Any], state: _StepState
    ) -> Outcome:
        budget_end = state.start()
        cache = self.cache if getattr(tool, 'cacheable', False) is True else None
        if cache is not None:
            hit = self._cache_call(cache.get, step.type, params)
            if isinstance(hit, dict):
                return StepStatus.SUCCESS, hit, None, 0, True

        max_attempts = max(1, step.retry)
        last_error = 'no attempt made'
        for attempt in range(max_attempts):
            if state.cancel.is_set():
                return StepStatus.ERROR, None, 'Cancelled', state.attempts, False
            left = budget_end - time.monotonic()
            if left <= 0:
                return StepStatus.ERROR, None, f'Step timed out after {step.timeout}s', state.attempts, False
            attempts = state.add_attempt()
            try:
                # Everything the source does (HTTP via clamp_timeout) is bounded by what is left of the budget.
                with deadline_scope(left):
                    data = tool.fetch(params)
            except DeadlineExceeded as e:
                # Must precede SourceError: a spent budget is a timeout, not an unavailable source.
                return StepStatus.ERROR, None, f'Step timed out after {step.timeout}s ({e})', attempts, False
            except SourceError as e:
                if not e.transient:
                    return StepStatus.UNAVAILABLE, None, str(e), attempts, False
                last_error = str(e)
            except TRANSIENT_BUILTINS as e:
                last_error = f'{type(e).__name__}: {e}'
            except Exception as e:
                # Bug in the source (parsing, KeyError...): retrying will not help.
                logger.exception('source raised unexpected error', extra={'step_id': step.id})
                return StepStatus.ERROR, None, f'{type(e).__name__}: {e}', attempts, False
            else:
                return self._accept(step, cache, params, data, attempts)

            if attempt < max_attempts - 1:
                delay = max(0.0, self.backoff(attempt))
                if time.monotonic() + delay + MIN_ATTEMPT_BUDGET > budget_end:
                    # Sleeping into the deadline would only turn a clear error into a vague timeout.
                    logger.warning('no time left to retry', extra={'step_id': step.id, 'attempt': attempts})
                    error = f'{last_error} (no time left in the {step.timeout}s budget to retry)'
                    return StepStatus.ERROR, None, error, attempts, False
                logger.warning('attempt failed, retrying', extra={'step_id': step.id, 'attempt': attempts})
                if state.cancel.wait(delay):
                    return StepStatus.ERROR, None, 'Cancelled', attempts, False
        return StepStatus.ERROR, None, last_error, state.attempts, False

    def _accept(
        self, step: StepConfig, cache: Optional['ResultCache'], params: Dict[str, Any], data: Any, attempts: int
    ) -> Outcome:
        """Turn a source's return value into an outcome, caching it only when it is complete."""
        if not isinstance(data, dict):
            return StepStatus.ERROR, None, f'Source returned {type(data).__name__}, expected dict', attempts, False
        errors = data.get('errors')
        # Incomplete results (a non-empty `errors` or a `partial` flag) are never cached: they would hide
        # the source's recovery for the whole TTL.
        if cache is not None and not errors and not data.get('partial'):
            self._cache_call(cache.set, step.type, params, data, self.cache_ttl)
        if data.get('partial') and errors:
            # Contract C2: the source says this is only part of the answer.
            count = len(errors) if isinstance(errors, (list, tuple, dict)) else 1
            message = f'Partial result: the source reported {count} error(s)'
            return StepStatus.DEGRADED, data, message, attempts, False
        return StepStatus.SUCCESS, data, None, attempts, False

    @staticmethod
    def _cache_call(operation: Callable[..., Any], *args: Any) -> Any:
        """The cache is an optimisation: a failure in it must never fail a step."""
        try:
            return operation(*args)
        except Exception:
            logger.warning('cache operation failed', exc_info=True)
            return None
