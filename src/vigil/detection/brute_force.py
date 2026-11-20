"""Detect SSH brute force: many failed logins from one address in a short time.

MITRE ATT&CK T1110.001 (Brute Force: Password Guessing).

The detector is *streaming*: it receives one event at a time and keeps only the state
it needs, so the same code serves a one-off file scan and round-the-clock monitoring.
Time comes from the events themselves, never from the wall clock, so replaying last
month's logs gives exactly the answer that watching them live would have given.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from vigil.alerts import Alert, Severity
from vigil.detection.windows import Cooldown, SlidingWindow
from vigil.events import AuthEvent, AuthOutcome, IPAddress

RULE_ID = "ssh-brute-force"
TECHNIQUE = "T1110.001"

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=1)
DEFAULT_COOLDOWN = timedelta(minutes=15)


class BruteForceDetector:
    """Alert when one address fails `threshold` logins within `window`.

    After alerting, the same address stays quiet for `cooldown`, so one long attack
    produces one alert instead of burying analysts under hundreds.
    """

    rule_id = RULE_ID
    technique = TECHNIQUE

    def __init__(
        self,
        *,
        threshold: int = DEFAULT_THRESHOLD,
        window: timedelta = DEFAULT_WINDOW,
        cooldown: timedelta = DEFAULT_COOLDOWN,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        self._threshold = threshold
        self._window = window
        self._failures: SlidingWindow[IPAddress] = SlidingWindow(window)
        self._cooldown: Cooldown[IPAddress] = Cooldown(cooldown)

    @property
    def tracked_sources(self) -> int:
        """How many addresses the detector currently remembers."""
        return len(self._failures)

    def process(self, event: AuthEvent) -> Alert | None:
        """Feed one event; returns an Alert the moment an attack is recognized."""
        if event.outcome is not AuthOutcome.FAILURE:
            return None
        recent = self._failures.add(event.source_ip, event)
        if len(recent) < self._threshold:
            return None
        if self._cooldown.active(event.source_ip, now=event.timestamp):
            return None  # the same attack, already reported
        self._cooldown.start(event.source_ip, now=event.timestamp)

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
            evidence=recent,
        )


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
