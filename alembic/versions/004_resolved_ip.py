"""v0.2: cache the resolved IP of each monitored asset so the Hosts view
can group aliases that point to the same machine.

Idempotent DO-block so the migration is safe on fresh DBs (where the
table doesn't exist yet) and on re-runs.
"""
from __future__ import annotations

from alembic import op

revision = "004_resolved_ip"
down_revision = "003_v02_tagging_diff"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.monitored_assets') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'monitored_assets' AND column_name = 'resolved_ip'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN resolved_ip VARCHAR(64);
                    CREATE INDEX ix_monitored_assets_resolved_ip
                        ON monitored_assets (resolved_ip)
                        WHERE resolved_ip IS NOT NULL;
                END IF;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.monitored_assets') IS NOT NULL THEN
                DROP INDEX IF EXISTS ix_monitored_assets_resolved_ip;
                ALTER TABLE monitored_assets DROP COLUMN IF EXISTS resolved_ip;
            END IF;
        END
        $$;
    """)
