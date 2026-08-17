"""FEAT-35 (Surface) — findings alert notifications.

Revision ID: 013_findings_notifications
Revises: 012_scan_exclusions
Create Date: 2026-08-17

Surface's model is deliberately simpler than AppSec's: no per-asset
recipient list — a user opts in via their notification preferences
(default OFF), picks a severity floor, and receives every alert of the
platform. Tables:

* ``digest_runs`` — send journal (Watch/Pilot/AppSec pattern), unique
  (recipient, kind, period_key) makes the per-scan alert idempotent.
* ``notification_prefs`` — LOCAL per-user prefs for standalone
  deployments; suite mode proxies Pilot's storage.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "013_findings_notifications"
down_revision = "012_scan_exclusions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "digest_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("recipient", sa.String(320), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),  # alert
        sa.Column("period_key", sa.String(64), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("items_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=False, server_default=""),
        sa.Column("body_html", sa.Text, nullable=False, server_default=""),
    )
    op.create_index("uq_surface_digest_runs", "digest_runs",
                    ["recipient", "kind", "period_key"], unique=True)
    op.create_table(
        "notification_prefs",
        sa.Column("user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("lang", sa.String(5), nullable=False, server_default="fr"),
        sa.Column("module_prefs", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    op.drop_table("notification_prefs")
    op.drop_index("uq_surface_digest_runs", table_name="digest_runs")
    op.drop_table("digest_runs")
