"""add audit_log table

Revision ID: 007_audit_log
Revises: 006_measure_finding_ids
Create Date: 2026-04-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "007_audit_log"
down_revision = "006_measure_finding_ids"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from sqlalchemy import inspect
    bind = op.get_bind()
    inspector = inspect(bind)
    if "audit_log" in inspector.get_table_names():
        return
    op.create_table(
        "audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("logged_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("user_email", sa.String(255), nullable=False, server_default=""),
        sa.Column("user_name", sa.String(255), nullable=True, server_default=""),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target", sa.String(500), nullable=True, server_default=""),
        sa.Column("details", sa.Text, nullable=True, server_default=""),
        sa.Column("ip_address", sa.String(64), nullable=True, server_default=""),
    )
    op.create_index("ix_audit_log_logged_at", "audit_log", ["logged_at"])
    op.create_index("ix_audit_log_user", "audit_log", ["user_email"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action")
    op.drop_index("ix_audit_log_user")
    op.drop_index("ix_audit_log_logged_at")
    op.drop_table("audit_log")
