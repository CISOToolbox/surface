"""Host liveness (FEAT-68)

Revision ID: 018_host_liveness
Revises: 017_nonconformity_project
Create Date: 2026-11-10

A monitored host keeps the last scan it answered and the first scan it left
unanswered since, so the Hosts view can flag one silent for too long
(possibly decommissioned).
"""
from alembic import op
import sqlalchemy as sa

revision = "018_host_liveness"
down_revision = "017_nonconformity_project"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("monitored_assets", sa.Column("last_alive_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("monitored_assets", sa.Column("unanswered_since", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("monitored_assets", "unanswered_since")
    op.drop_column("monitored_assets", "last_alive_at")
