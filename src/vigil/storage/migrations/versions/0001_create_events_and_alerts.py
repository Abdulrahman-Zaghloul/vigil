"""Create the events, alerts and alert_evidence tables.

Revision ID: 0001
Revises:
Create Date: 2026-11-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("user_exists", sa.Boolean(), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.CheckConstraint("outcome IN ('failure', 'success')", name="ck_events_outcome_valid"),
        sa.CheckConstraint("source_port BETWEEN 1 AND 65535", name="ck_events_port_valid"),
        sa.PrimaryKeyConstraint("id", name="pk_events"),
        sa.UniqueConstraint("fingerprint", name="uq_events_fingerprint"),
    )
    op.create_index("ix_events_source_ip_occurred_at", "events", ["source_ip", "occurred_at"])
    op.create_index("ix_events_occurred_at", "events", ["occurred_at"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("technique", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_alerts_severity_valid",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_alerts"),
        sa.UniqueConstraint("fingerprint", name="uq_alerts_fingerprint"),
    )
    op.create_index("ix_alerts_first_seen", "alerts", ["first_seen"])

    op.create_table(
        "alert_evidence",
        sa.Column("alert_id", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name="fk_alert_evidence_alert_id_alerts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name="fk_alert_evidence_event_id_events",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id", name="pk_alert_evidence"),
    )
    op.create_index("ix_alert_evidence_event_id", "alert_evidence", ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_alert_evidence_event_id", table_name="alert_evidence")
    op.drop_table("alert_evidence")
    op.drop_index("ix_alerts_first_seen", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_events_occurred_at", table_name="events")
    op.drop_index("ix_events_source_ip_occurred_at", table_name="events")
    op.drop_table("events")
