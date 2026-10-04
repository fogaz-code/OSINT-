import random
import threading
import time
from typing import Callable, Dict, Optional


class RateLimiter:
    """Token bucket thread-safe. `acquire` blocca finché un token è disponibile."""

    def __init__(
        self,
        rate_per_sec: float,
        burst: int = 1,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        """Initialize RateLimiter."""
        if rate_per_sec <= 0:
            raise ValueError('rate_per_sec must be > 0')
        self.rate = rate_per_sec
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Block until a token is available.

        Args:
            timeout: Max seconds to wait; None waits indefinitely.

        Returns:
            True if a token was acquired, False if the timeout elapsed first.
        """
        deadline = None if timeout is None else self._clock() + timeout
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return True
                wait = (1 - self._tokens) / self.rate
            if deadline is not None and self._clock() + wait > deadline:
                return False
            self._sleep(wait)


class CircuitOpenError(Exception):
    """Raised when a call is attempted while a circuit breaker is open."""

    pass


class CircuitBreaker:
    """CLOSED -> OPEN dopo `failure_threshold` errori consecutivi; dopo `reset_timeout`
    lascia passare una sola chiamata di prova (HALF_OPEN)."""

    CLOSED, OPEN, HALF_OPEN = 'closed', 'open', 'half_open'

    def __init__(
        self, failure_threshold: int = 5, reset_timeout: float = 60.0, clock: Callable[[], float] = time.monotonic
    ):
        """Initialize CircuitBreaker."""
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._clock = clock
        self._failures = 0
        self._opened_at = 0.0
        self._state = self.CLOSED
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        """The current breaker state (half-open once the reset timeout has elapsed)."""
        with self._lock:
            if self._state == self.OPEN and self._clock() - self._opened_at >= self.reset_timeout:
                return self.HALF_OPEN
            return self._state

    def before_call(self) -> None:
        """Raise CircuitOpenError if the circuit is open (probe allowed in half-open)."""
        with self._lock:
            if self._state == self.CLOSED:
                return
            if self._state == self.OPEN and self._clock() - self._opened_at >= self.reset_timeout:
                self._state = self.HALF_OPEN
                return
            raise CircuitOpenError('circuit open')

    def record_success(self) -> None:
        """Record a success, closing the circuit."""
        with self._lock:
            self._failures = 0
            self._state = self.CLOSED

    def record_failure(self) -> None:
        """Record a failure, opening the circuit past the threshold."""
        with self._lock:
            self._failures += 1
            if self._state == self.HALF_OPEN or self._failures >= self.failure_threshold:
                self._state = self.OPEN
                self._opened_at = self._clock()


def backoff_delay(
    attempt: int, base: float = 0.5, cap: float = 10.0, rand: Callable[[float, float], float] = random.uniform
) -> float:
    """Exponential backoff con full jitter (attempt parte da 0)."""
    return rand(0, min(cap, base * (2**attempt)))


class HostPolicies:
    """Registro process-wide di rate limiter e circuit breaker per host."""

    DEFAULT_RATE = 2.0
    # Limiti noti/prudenziali per le API gratuite usate.
    RATES: Dict[str, float] = {
        'api.hackertarget.com': 0.5,
        'crt.sh': 0.5,
        'web.archive.org': 1.0,
        'api.github.com': 1.0,
        'internetdb.shodan.io': 1.0,
        # Keyless block explorers and Gravatar's anonymous profile API: shared public quotas.
        'blockstream.info': 0.5,
        'mempool.space': 0.5,
        'eth.blockscout.com': 1.0,
        'api.trongrid.io': 0.3,
        'api.gravatar.com': 0.5,
    }
    DEFAULT_BURST = 2
    BURSTS: Dict[str, int] = {
        'internetdb.shodan.io': 1,
        'api.trongrid.io': 1,
        'api.gravatar.com': 1,
    }

    def __init__(self) -> None:
        """Initialize HostPolicies."""
        self._limiters: Dict[str, RateLimiter] = {}
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def limiter(self, host: str) -> RateLimiter:
        """Return the per-host rate limiter, creating it on first use."""
        with self._lock:
            if host not in self._limiters:
                self._limiters[host] = RateLimiter(
                    self.RATES.get(host, self.DEFAULT_RATE), burst=self.BURSTS.get(host, self.DEFAULT_BURST)
                )
            return self._limiters[host]

    def breaker(self, host: str) -> CircuitBreaker:
        """Return the per-host circuit breaker, creating it on first use."""
        with self._lock:
            if host not in self._breakers:
                self._breakers[host] = CircuitBreaker()
            return self._breakers[host]


host_policies = HostPolicies()
