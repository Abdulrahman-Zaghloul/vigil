"""Detect SSH brute force: many failed logins from one address in a short time.

MITRE ATT&CK T1110.001 (Brute Force: Password Guessing).

The detector is *streaming*: it receives one event at a time and keeps only the state
it needs, so the same code serves a one-off file scan and round-the-clock monitoring.
Time comes from the events themselves, never from the wall clock, so replaying last
month's logs gives exactly the answer that watching them live would have given.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import datetime, timedelta

from vigil.alerts import Alert, Severity
from vigil.events import AuthEvent, AuthOutcome, IPAddress

RULE_ID = "ssh-brute-force"
TECHNIQUE = "T1110.001"

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=1)
DEFAULT_COOLDOWN = timedelta(minutes=15)
_SWEEP_EVERY = 1_000  # events between clean-ups of addresses that went quiet


class BruteForceDetector:
    """Alert when one address fails `threshold` logins within `window`.

    After alerting, the same address stays quiet for `cooldown`, so one long attack
    produces one alert instead of burying analysts under hundreds.
    """

    def __init__(
        self,
        *,
        threshold: int = DEFAULT_THRESHOLD,
        window: timedelta = DEFAULT_WINDOW,
        cooldown: timedelta = DEFAULT_COOLDOWN,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if window <= timedelta(0):
            raise ValueError("window must be longer than zero")
        if cooldown < timedelta(0):
            raise ValueError("cooldown must not be negative")
        self._threshold = threshold
        self._window = window
        self._cooldown = cooldown
        self._recent_failures: dict[IPAddress, deque[AuthEvent]] = {}
        self._quiet_until: dict[IPAddress, datetime] = {}
        self._processed = 0

    @property
    def tracked_sources(self) -> int:
        """How many addresses the detector currently remembers."""
        return len(self._recent_failures)

    def process(self, event: AuthEvent) -> Alert | None:
        """Feed one event; returns an Alert the moment an attack is recognized."""
        self._processed += 1
        if self._processed % _SWEEP_EVERY == 0:
            self._forget_quiet_sources(now=event.timestamp)
        if event.outcome is not AuthOutcome.FAILURE:
            return None

        # Sliding window: keep only this address's failures from the last `window`.
        recent = self._recent_failures.setdefault(event.source_ip, deque())
        recent.append(event)
        while event.timestamp - recent[0].timestamp > self._window:
            recent.popleft()
        if len(recent) < self._threshold:
            return None

        quiet_until = self._quiet_until.get(event.source_ip)
        if quiet_until is not None and event.timestamp < quiet_until:
            return None  # the same attack, already reported
        self._quiet_until[event.source_ip] = event.timestamp + self._cooldown

        seconds = int(self._window.total_seconds())
        return Alert(
            rule_id=RULE_ID,
            title=(
                f"SSH brute force from {event.source_ip}: "
                f"{len(recent)} failed logins within {seconds}s"
            ),
            severity=Severity.MEDIUM,
            technique=TECHNIQUE,
            source_ip=event.source_ip,
            first_seen=recent[0].timestamp,
            last_seen=event.timestamp,
            evidence=tuple(recent),
        )

    def _forget_quiet_sources(self, *, now: datetime) -> None:
        """Drop addresses with no recent failures, so memory stays bounded.

        Without this, an attacker rotating through millions of addresses could grow
        the detector until the machine runs out of memory: a denial of service.
        """
        self._recent_failures = {
            ip: failures
            for ip, failures in self._recent_failures.items()
            if now - failures[-1].timestamp <= self._window
        }
        self._quiet_until = {ip: until for ip, until in self._quiet_until.items() if until > now}


def detect_brute_force(
    events: Iterable[AuthEvent],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
    cooldown: timedelta = DEFAULT_COOLDOWN,
) -> list[Alert]:
    """Scan a finished batch of events, oldest first, and return every alert."""
    detector = BruteForceDetector(threshold=threshold, window=window, cooldown=cooldown)
    alerts = []
    for event in sorted(events, key=lambda e: e.timestamp):
        alert = detector.process(event)
        if alert is not None:
            alerts.append(alert)
    return alerts
