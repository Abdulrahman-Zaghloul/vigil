"""Alerts: what Vigil raises when a detection rule fires."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from vigil.events import AuthEvent, IPAddress


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position on the scale (LOW is 0, CRITICAL is 3), so severities can be compared."""
        return list(Severity).index(self)


@dataclass(frozen=True, slots=True)
class Alert:
    rule_id: str  # stable machine-readable name, e.g. "ssh-brute-force"
    title: str  # one line for a human analyst
    severity: Severity
    technique: str  # MITRE ATT&CK technique id, e.g. "T1110.001"
    source_ip: IPAddress
    first_seen: datetime
    last_seen: datetime
    evidence: tuple[AuthEvent, ...]  # the exact events that triggered the alert

    @property
    def event_count(self) -> int:
        return len(self.evidence)
