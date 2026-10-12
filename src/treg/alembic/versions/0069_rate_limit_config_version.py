"""request admission: rate-limit policy versions, the blocklist and its audit, surge signals

Revision ID: 0069
Revises: 0068
Create Date: 2026-10-12

Four new tables (docs/context/architecture/rate-limit.md): `ratelimitconfigversion` (one audited
row per policy write), `blocklistentry` and `blocklistaudit` (the source of truth `rl:blocklist`
is published from; an audit id is the published version), and `surgesignal` (record-only
per-minute request aggregates). Additive: no running code reads them before this deploy.
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
    op.create_table(
        "blocklistentry",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("revoke_reason", sa.String(), nullable=True),
    )
    op.create_index("ix_blocklistentry_kind", "blocklistentry", ["kind"])
    op.create_index("ix_blocklistentry_value", "blocklistentry", ["value"])
    op.create_index("ix_blocklistentry_expires_at", "blocklistentry", ["expires_at"])
    op.create_table(
        "blocklistaudit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entry_ids", sa.JSON(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("ttl_s", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "surgesignal",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("process_instance", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("ip", sa.String(), nullable=True),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.Column("org_slug", sa.String(), nullable=True),
        sa.Column("org_created_at", sa.DateTime(), nullable=True),
        sa.Column("net_paid_micro", sa.BigInteger(), nullable=True),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("call_requests", sa.Integer(), nullable=False),
        sa.Column("unknown_key_requests", sa.Integer(), nullable=False),
        sa.Column("status_401", sa.Integer(), nullable=False),
        sa.Column("status_403", sa.Integer(), nullable=False),
        sa.Column("status_429", sa.Integer(), nullable=False),
        sa.Column("status_5xx", sa.Integer(), nullable=False),
        sa.Column("blocklist_matches", sa.Integer(), nullable=False),
        sa.Column("distinct_orgs", sa.Integer(), nullable=False),
        sa.Column("distinct_keys", sa.Integer(), nullable=False),
        sa.Column("max_in_flight", sa.Integer(), nullable=False),
    )
    op.create_index("ix_surgesignal_window_start", "surgesignal", ["window_start"])
    op.create_index("ix_surgesignal_ip", "surgesignal", ["ip"])
    op.create_index("ix_surgesignal_org_id", "surgesignal", ["org_id"])


def downgrade() -> None:
    op.drop_table("surgesignal")
    op.drop_table("blocklistaudit")
    op.drop_table("blocklistentry")
    op.drop_table("ratelimitconfigversion")
