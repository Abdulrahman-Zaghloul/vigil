"""Detect password spraying: one address failing against many different accounts.

MITRE ATT&CK T1110.003 (Brute Force: Password Spraying).

Brute force hammers one account with many passwords, and trips lockouts and
brute-force alerts. Spraying flips that around: one or two common passwords (such as
"Winter2026!") tried slowly against many accounts, staying under every per-account
limit. The giveaway is breadth, not speed.
"""

from __future__ import annotations

from datetime import timedelta

from vigil.alerts import Alert, Severity
from vigil.detection.windows import Cooldown, SlidingWindow
from vigil.events import AuthEvent, AuthOutcome, IPAddress

RULE_ID = "ssh-password-spray"
TECHNIQUE = "T1110.003"

DEFAULT_DISTINCT_ACCOUNTS = 10
DEFAULT_WINDOW = timedelta(minutes=10)
DEFAULT_COOLDOWN = timedelta(hours=1)


class PasswordSprayDetector:
    """Alert when one address fails against `distinct_accounts` accounts within `window`."""

    rule_id = RULE_ID
    technique = TECHNIQUE

    def __init__(
        self,
        *,
        distinct_accounts: int = DEFAULT_DISTINCT_ACCOUNTS,
        window: timedelta = DEFAULT_WINDOW,
        cooldown: timedelta = DEFAULT_COOLDOWN,
    ) -> None:
        if distinct_accounts < 2:
            raise ValueError("distinct_accounts must be at least 2")
        self._distinct_accounts = distinct_accounts
        self._window = window
        self._failures: SlidingWindow[IPAddress] = SlidingWindow(window)
        self._cooldown: Cooldown[IPAddress] = Cooldown(cooldown)

    def process(self, event: AuthEvent) -> Alert | None:
        if event.outcome is not AuthOutcome.FAILURE:
            return None
        recent = self._failures.add(event.source_ip, event)
        accounts = {e.username for e in recent}
        if len(accounts) < self._distinct_accounts:
            return None
        if self._cooldown.active(event.source_ip, now=event.timestamp):
            return None
        self._cooldown.start(event.source_ip, now=event.timestamp)

        minutes = int(self._window.total_seconds() // 60)
        return Alert(
            rule_id=RULE_ID,
            title=(
                f"Password spraying from {event.source_ip}: "
                f"{len(accounts)} different accounts tried within {minutes} min"
            ),
            severity=Severity.MEDIUM,
            technique=TECHNIQUE,
            source_ip=event.source_ip,
            first_seen=recent[0].timestamp,
            last_seen=event.timestamp,
            evidence=recent,
        )
