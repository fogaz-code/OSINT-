import pytest

from secure_osint.utils.resilience import CircuitBreaker, CircuitOpenError, RateLimiter, backoff_delay


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_rate_limiter_spaces_calls():
    clock = FakeClock()
    limiter = RateLimiter(rate_per_sec=2, burst=1, clock=clock, sleep=clock.sleep)
    for _ in range(5):
        limiter.acquire()
    assert clock.now == pytest.approx(2.0)  # 1 immediato + 4 * 0.5s


def test_rate_limiter_timeout():
    clock = FakeClock()
    limiter = RateLimiter(rate_per_sec=0.1, burst=1, clock=clock, sleep=clock.sleep)
    assert limiter.acquire(timeout=1)
    assert not limiter.acquire(timeout=1)


def test_circuit_breaker_opens_and_half_opens():
    clock = FakeClock()
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10, clock=clock)
    breaker.record_failure()
    breaker.before_call()
    breaker.record_failure()
    with pytest.raises(CircuitOpenError):
        breaker.before_call()
    clock.now = 10
    breaker.before_call()  # sonda in half-open
    breaker.record_failure()
    with pytest.raises(CircuitOpenError):
        breaker.before_call()
    clock.now = 20
    breaker.before_call()
    breaker.record_success()
    assert breaker.state == CircuitBreaker.CLOSED


def test_backoff_full_jitter_bounds():
    assert backoff_delay(0, rand=lambda a, b: b) == 0.5
    assert backoff_delay(3, rand=lambda a, b: b) == 4.0
    assert backoff_delay(20, rand=lambda a, b: b) == 10.0
    assert backoff_delay(5, rand=lambda a, b: a) == 0
