"""add scan_exclusions blocklist table

Revision ID: 012_scan_exclusions
Revises: 011_measure_progress_log
Create Date: 2026-08-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "012_scan_exclusions"
down_revision = "011_measure_progress_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sqlalchemy import inspect
    bind = op.get_bind()
    inspector = inspect(bind)
    if "scan_exclusions" in inspector.get_table_names():
        return
    op.create_table(
        "scan_exclusions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("value", sa.String(500), nullable=False),
        sa.Column("note", sa.String(255), nullable=True, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("ix_scan_exclusions_value", "scan_exclusions", ["value"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_scan_exclusions_value")
    op.drop_table("scan_exclusions")
