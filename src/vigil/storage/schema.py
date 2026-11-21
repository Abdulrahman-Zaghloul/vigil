"""The database tables, described in Python with SQLAlchemy Core.

The database enforces its own rules (CHECK constraints, foreign keys, unique
fingerprints), so even a bug in Vigil cannot store an impossible value.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET

# Predictable constraint names keep migrations readable and reversible.
metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    }
)

events = Table(
    "events",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    # A hash of the original line. Re-scanning a log finds the same fingerprints,
    # so the same event is never stored twice.
    Column("fingerprint", String(64), nullable=False, unique=True),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Column("host", Text, nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("username", Text, nullable=False),
    Column("source_ip", INET, nullable=False),
    Column("source_port", Integer, nullable=False),
    Column("method", String(32), nullable=False),
    Column("user_exists", Boolean, nullable=False),
    Column("raw", Text, nullable=False),
    CheckConstraint("outcome IN ('failure', 'success')", name="outcome_valid"),
    CheckConstraint("source_port BETWEEN 1 AND 65535", name="port_valid"),
    Index(None, "source_ip", "occurred_at"),
    Index(None, "occurred_at"),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", BigInteger, Identity(always=True), primary_key=True),
    Column("fingerprint", String(64), nullable=False, unique=True),
    Column("rule_id", String(64), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("technique", String(16), nullable=False),
    Column("title", Text, nullable=False),
    Column("source_ip", INET, nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("event_count", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="severity_valid"),
    Index(None, "first_seen"),
)

# Many-to-many: one alert cites many events, and one event can back several alerts.
alert_evidence = Table(
    "alert_evidence",
    metadata,
    Column("alert_id", BigInteger, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", BigInteger, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
    Index(None, "event_id"),
)
