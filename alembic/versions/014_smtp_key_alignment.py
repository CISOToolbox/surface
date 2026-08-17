"""Align Surface's SMTP setting keys on the suite-wide contract.

Revision ID: 014_smtp_key_alignment
Revises: 013_findings_notifications
Create Date: 2026-08-19

Surface stored the pushed SMTP config under names of its own — username /
sender / use_tls — while pilot, asset, watch, compliance and appsec all use
user / from_addr / tls. Same data, two vocabularies: a stale row in one
module is invisible when you read the other, which is exactly how a
leftover ``smtp.username`` went unnoticed while Surface kept attempting
AUTH against a relay that has none.

Renames the three rows in place. ``smtp.recipients`` is Surface's own
(never pushed by Pilot) and is left untouched.

A canonical row already present wins: it is the one the new code writes, so
dropping the legacy duplicate is the safe resolution of the collision on the
unique key.
"""
from alembic import op

revision = "014_smtp_key_alignment"
down_revision = "013_findings_notifications"
branch_labels = None
depends_on = None

_RENAMES = (
    ("smtp.username", "smtp.user"),
    ("smtp.sender", "smtp.from_addr"),
    ("smtp.use_tls", "smtp.tls"),
)


def upgrade() -> None:
    for old, new in _RENAMES:
        op.execute(
            f"DELETE FROM app_settings WHERE key = '{new}' "
            f"AND EXISTS (SELECT 1 FROM app_settings s WHERE s.key = '{old}')"
        )
        op.execute(f"UPDATE app_settings SET key = '{new}' WHERE key = '{old}'")


def downgrade() -> None:
    for old, new in _RENAMES:
        op.execute(
            f"DELETE FROM app_settings WHERE key = '{old}' "
            f"AND EXISTS (SELECT 1 FROM app_settings s WHERE s.key = '{new}')"
        )
        op.execute(f"UPDATE app_settings SET key = '{old}' WHERE key = '{new}'")
