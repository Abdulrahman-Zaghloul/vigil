"""Building blocks shared by detection rules: per-key sliding windows and cooldowns.

Both forget stale entries on their own, so memory stays bounded even when an attacker
rotates through millions of addresses. Otherwise the detector itself would become an
easy denial-of-service target.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from datetime import datetime, timedelta

from vigil.events import AuthEvent

_SWEEP_EVERY = 1_000  # operations between clean-ups


class SlidingWindow[K: Hashable]:
    """For each key (such as a source address), the events from the last `length`."""

    def __init__(self, length: timedelta) -> None:
        if length <= timedelta(0):
            raise ValueError("window must be longer than zero")
        self._length = length
        self._events: dict[K, deque[AuthEvent]] = {}
        self._adds = 0

    def __len__(self) -> int:
        """How many keys are currently remembered."""
        return len(self._events)

    def add(self, key: K, event: AuthEvent) -> tuple[AuthEvent, ...]:
        """Record an event and return the key's events still inside the window."""
        self._adds += 1
        if self._adds % _SWEEP_EVERY == 0:
            self._forget_idle(now=event.timestamp)
        events = self._events.setdefault(key, deque())
        events.append(event)
        self._trim(events, now=event.timestamp)
        return tuple(events)

    def recent(self, key: K, *, now: datetime) -> tuple[AuthEvent, ...]:
        """The key's events inside the window ending at `now`, without adding one."""
        events = self._events.get(key)
        if events is None:
            return ()
        self._trim(events, now=now)
        return tuple(events)

    def clear(self, key: K) -> None:
        self._events.pop(key, None)

    def _trim(self, events: deque[AuthEvent], *, now: datetime) -> None:
        while events and now - events[0].timestamp > self._length:
            events.popleft()

    def _forget_idle(self, *, now: datetime) -> None:
        self._events = {
            key: events
            for key, events in self._events.items()
            if events and now - events[-1].timestamp <= self._length
        }


class Cooldown[K: Hashable]:
    """Remembers who was alerted on recently, so one attack cannot flood analysts."""

    def __init__(self, length: timedelta) -> None:
        if length < timedelta(0):
            raise ValueError("cooldown must not be negative")
        self._length = length
        self._quiet_until: dict[K, datetime] = {}
        self._starts = 0

    def active(self, key: K, *, now: datetime) -> bool:
        until = self._quiet_until.get(key)
        return until is not None and now < until

    def start(self, key: K, *, now: datetime) -> None:
        self._starts += 1
        if self._starts % _SWEEP_EVERY == 0:
            self._quiet_until = {k: u for k, u in self._quiet_until.items() if u > now}
        self._quiet_until[key] = now + self._length
