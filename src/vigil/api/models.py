"""The shapes of API requests and responses: the API's public contract.

Kept separate from the database rows, so the database can change without breaking
clients, and so internal fields can never leak into a response by accident.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from vigil.alerts import Severity
from vigil.attack import TECHNIQUES
from vigil.storage.store import StoredAlert

MAX_LINES = 1_000  # per request: a shipper sends big logs as many small batches
MAX_LINE_LENGTH = 8_192  # longer than any real syslog line


class EventBatch(BaseModel):
    """Raw log lines sent by a log shipper."""

    # Unknown fields are rejected: a typo or an unexpected field fails loudly.
    model_config = ConfigDict(extra="forbid")

    lines: list[Annotated[str, StringConstraints(max_length=MAX_LINE_LENGTH)]] = Field(
        min_length=1, max_length=MAX_LINES
    )


class IngestResult(BaseModel):
    received: int = Field(description="Lines in the request")
    parsed: int = Field(description="Lines that were SSH login attempts")
    stored: int = Field(description="Attempts not already stored (resending is safe)")


class AlertOut(BaseModel):
    id: int
    rule_id: str
    severity: Severity
    technique: str
    technique_name: str | None
    title: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime

    @classmethod
    def from_stored(cls, alert: StoredAlert) -> AlertOut:
        known = TECHNIQUES.get(alert.technique)
        return cls(
            id=alert.id,
            rule_id=alert.rule_id,
            severity=alert.severity,
            technique=alert.technique,
            technique_name=known.name if known else None,
            title=alert.title,
            source_ip=alert.source_ip,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            event_count=alert.event_count,
            created_at=alert.created_at,
        )


class AlertDetail(AlertOut):
    evidence: list[str] = Field(description="The original log lines, oldest first")
