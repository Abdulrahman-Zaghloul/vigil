import pytest

from vigil.api.limits import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_a_burst_is_allowed_then_requests_are_refused() -> None:
    limiter = RateLimiter(burst=3, per_second=1, clock=FakeClock())
    assert [limiter.consume("key").allowed for _ in range(4)] == [True, True, True, False]


def test_a_refusal_says_when_to_retry() -> None:
    limiter = RateLimiter(burst=1, per_second=0.25, clock=FakeClock())
    limiter.consume("key")
    decision = limiter.consume("key")
    assert not decision.allowed
    assert decision.retry_after == 4  # one token takes 4 seconds at 0.25 per second


def test_tokens_refill_steadily_but_never_beyond_the_burst() -> None:
    clock = FakeClock()
    limiter = RateLimiter(burst=2, per_second=1, clock=clock)
    limiter.consume("key")
    limiter.consume("key")
    clock.advance(1)
    assert limiter.consume("key").allowed
    assert not limiter.consume("key").allowed
    clock.advance(3_600)  # an idle hour refills only up to the burst size
    assert [limiter.consume("key").allowed for _ in range(3)] == [True, True, False]


def test_checking_does_not_use_up_a_token() -> None:
    limiter = RateLimiter(burst=1, per_second=1, clock=FakeClock())
    assert limiter.check("key").allowed
    assert limiter.check("key").allowed
    assert limiter.consume("key").allowed
    assert not limiter.check("key").allowed


def test_every_key_has_its_own_bucket() -> None:
    limiter = RateLimiter(burst=1, per_second=1, clock=FakeClock())
    assert limiter.consume("shipper").allowed
    assert limiter.consume("analyst").allowed
    assert not limiter.consume("shipper").allowed


def test_memory_is_bounded_by_forgetting_the_least_recent_key() -> None:
    limiter = RateLimiter(burst=1, per_second=1, clock=FakeClock(), max_tracked=2)
    limiter.consume("a")
    limiter.consume("b")
    limiter.consume("c")  # forgets "a"
    assert limiter.tracked == 2
    assert limiter.consume("a").allowed  # "a" starts over with a full bucket


@pytest.mark.parametrize(("burst", "per_second"), [(0, 1.0), (1, 0.0), (1, -1.0)])
def test_nonsense_settings_are_rejected(burst: int, per_second: float) -> None:
    with pytest.raises(ValueError, match="must"):
        RateLimiter(burst=burst, per_second=per_second)
