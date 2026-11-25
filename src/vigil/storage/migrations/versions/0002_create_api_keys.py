"""Create the api_keys table for per-client, scoped API keys.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("key_id", sa.String(length=12), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("secret_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String(length=16)), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "cardinality(scopes) > 0 AND scopes <@ ARRAY['ingest', 'read']::varchar[]",
            name="ck_api_keys_scopes_valid",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("key_id", name="uq_api_keys_key_id"),
    )
    op.create_index(
        "uq_api_keys_active_name",
        "api_keys",
        ["name"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_api_keys_active_name", table_name="api_keys")
    op.drop_table("api_keys")
