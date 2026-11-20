"""Run many detection rules over one stream of events."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Protocol

from vigil.alerts import Alert
from vigil.detection.brute_force import BruteForceDetector
from vigil.detection.compromise import SuccessAfterFailuresDetector
from vigil.detection.password_spray import PasswordSprayDetector
from vigil.events import AuthEvent


class Rule(Protocol):
    """The shape every detection rule must have.

    Any class with these three members counts as a Rule, without inheriting from
    anything. This is called structural typing: the engine cares what a rule can do,
    not what family it belongs to.
    """

    @property
    def rule_id(self) -> str: ...

    @property
    def technique(self) -> str: ...

    def process(self, event: AuthEvent) -> Alert | None: ...


class DetectionEngine:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self._rules = tuple(rules)
        counts = Counter(rule.rule_id for rule in self._rules)
        duplicates = sorted(rule_id for rule_id, n in counts.items() if n > 1)
        if duplicates:
            raise ValueError(f"duplicate rule ids: {', '.join(duplicates)}")

    @property
    def techniques(self) -> tuple[str, ...]:
        """The ATT&CK techniques these rules can detect: the engine's coverage."""
        return tuple(sorted({rule.technique for rule in self._rules}))

    def process(self, event: AuthEvent) -> list[Alert]:
        """Show one event to every rule; return whatever alerts it triggers."""
        alerts = (rule.process(event) for rule in self._rules)
        return [alert for alert in alerts if alert is not None]

    def run(self, events: Iterable[AuthEvent]) -> list[Alert]:
        """Scan a finished batch of events, oldest first."""
        alerts: list[Alert] = []
        for event in sorted(events, key=lambda e: e.timestamp):
            alerts.extend(self.process(event))
        return alerts


def default_rules() -> list[Rule]:
    """A fresh set of the built-in rules with their default settings."""
    return [BruteForceDetector(), PasswordSprayDetector(), SuccessAfterFailuresDetector()]
