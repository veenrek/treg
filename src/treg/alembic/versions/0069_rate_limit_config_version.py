"""ratelimitconfigversion: the audited, versioned request rate-limit policy

Revision ID: 0069
Revises: 0068
Create Date: 2026-10-12

One row per admin write of the rate-limit policy (docs/context/architecture/rate-limit.md); the
highest id is current. A new table, so additive: no running code reads it.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0069"
down_revision: str | Sequence[str] | None = "0068"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ratelimitconfigversion",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("note", sa.String(), nullable=False),
        sa.Column("enforce_approval", sa.String(), nullable=True),
        sa.Column("previous_version", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ratelimitconfigversion")
