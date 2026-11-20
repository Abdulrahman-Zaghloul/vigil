"""Detect a successful login that follows a run of failures from the same address.

Brute force and spraying are *attempts*. A success right after many failures suggests
the attacker found a working password, so this is the alert that matters most. It maps
to MITRE ATT&CK T1110 (Brute Force): the technique that just succeeded.
"""

from __future__ import annotations

from datetime import timedelta

from vigil.alerts import Alert, Severity
from vigil.detection.windows import SlidingWindow
from vigil.events import AuthEvent, AuthOutcome, IPAddress

RULE_ID = "ssh-success-after-failures"
TECHNIQUE = "T1110"

DEFAULT_MIN_FAILURES = 5
DEFAULT_WINDOW = timedelta(minutes=15)
PRIVILEGED_ACCOUNTS = frozenset({"root"})


class SuccessAfterFailuresDetector:
    """Alert when an address logs in after `min_failures` failures within `window`."""

    rule_id = RULE_ID
    technique = TECHNIQUE

    def __init__(
        self, *, min_failures: int = DEFAULT_MIN_FAILURES, window: timedelta = DEFAULT_WINDOW
    ) -> None:
        if min_failures < 1:
            raise ValueError("min_failures must be at least 1")
        self._min_failures = min_failures
        self._failures: SlidingWindow[IPAddress] = SlidingWindow(window)

    def process(self, event: AuthEvent) -> Alert | None:
        if event.outcome is AuthOutcome.FAILURE:
            self._failures.add(event.source_ip, event)
            return None

        failures = self._failures.recent(event.source_ip, now=event.timestamp)
        if len(failures) < self._min_failures:
            return None
        self._failures.clear(event.source_ip)  # the next login starts a fresh count

        # Context changes urgency: a compromised root account controls the whole server.
        severity = Severity.CRITICAL if event.username in PRIVILEGED_ACCOUNTS else Severity.HIGH
        return Alert(
            rule_id=RULE_ID,
            # The username is attacker-controlled: repr() quotes it and escapes oddities.
            title=(
                f"Possible compromise: {event.username!r} logged in from {event.source_ip} "
                f"after {len(failures)} failed attempts"
            ),
            severity=severity,
            technique=TECHNIQUE,
            source_ip=event.source_ip,
            first_seen=failures[0].timestamp,
            last_seen=event.timestamp,
            evidence=(*failures, event),
        )
