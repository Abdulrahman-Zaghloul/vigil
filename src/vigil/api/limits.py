"""Abuse limits for the API: how much any one client can make Vigil do.

The rate limiter is a *token bucket*. Each client has a bucket holding up to `burst`
tokens, refilled at `per_second`. Every request spends one token; an empty bucket means
"slow down" (HTTP 429). Short bursts are fine, but the long-run rate can never exceed
the refill rate.

Buckets live in this process's memory, which is right for a single server. Several API
servers behind a load balancer would share buckets through a store such as Redis.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Limits:
    burst: int = 50  # requests one key may make at once...
    per_second: float = 10.0  # ...refilled at this steady rate
    failed_auth_burst: int = 10  # bad or missing keys one address may present...
    failed_auth_per_second: float = 1 / 6  # ...refilled at 10 per minute
    max_body_bytes: int = 2 * 1024 * 1024  # 2 MiB: 1,000 real log lines fit easily


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    retry_after: int = 0  # whole seconds until a request would be allowed


class RateLimiter:
    def __init__(
        self,
        *,
        burst: int,
        per_second: float,
        clock: Callable[[], float] = time.monotonic,
        max_tracked: int = 100_000,
    ) -> None:
        if burst < 1:
            raise ValueError("burst must be at least 1")
        if per_second <= 0:
            raise ValueError("per_second must be greater than zero")
        self._burst = float(burst)
        self._rate = per_second
        self._clock = clock
        self._max_tracked = max_tracked
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # tokens, when
        self._lock = threading.Lock()  # FastAPI runs requests on several threads at once

    @property
    def tracked(self) -> int:
        return len(self._buckets)

    def check(self, key: str) -> Decision:
        """Would a request be allowed right now? Spends nothing."""
        with self._lock:
            return self._decide(self._tokens(key), spend=False, key=key)

    def consume(self, key: str) -> Decision:
        """Spend one token if there is one."""
        with self._lock:
            return self._decide(self._tokens(key), spend=True, key=key)

    def _tokens(self, key: str) -> float:
        now = self._clock()
        tokens, updated = self._buckets.get(key, (self._burst, now))
        return min(self._burst, tokens + (now - updated) * self._rate)

    def _decide(self, tokens: float, *, spend: bool, key: str) -> Decision:
        allowed = tokens >= 1
        if spend and allowed:
            tokens -= 1
        self._buckets[key] = (tokens, self._clock())
        self._buckets.move_to_end(key)
        while len(self._buckets) > self._max_tracked:  # forget the least recently seen
            self._buckets.popitem(last=False)
        if allowed:
            return Decision(allowed=True)
        return Decision(allowed=False, retry_after=max(1, math.ceil((1 - tokens) / self._rate)))
