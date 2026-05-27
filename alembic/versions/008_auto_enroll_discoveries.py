"""v0.4: per-asset toggle to control whether sub-domains discovered
during a scan are auto-enrolled as new MonitoredAsset rows.

Default is FALSE so adding a single host no longer silently grows the
perimeter — discovery findings remain visible in scan results, but
turning a discovered name into a tracked asset is now an opt-in.

Existing rows are migrated with FALSE as well (operators who relied on
the legacy behaviour can flip the flag back on per-asset).

Idempotent DO-block so the migration is safe on fresh DBs (where the
table doesn't exist yet) and on re-runs.
"""
from __future__ import annotations

from alembic import op

revision = "008_auto_enroll_discoveries"
down_revision = "007_audit_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.monitored_assets') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'monitored_assets'
                      AND column_name = 'auto_enroll_discoveries'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN auto_enroll_discoveries BOOLEAN
                        NOT NULL DEFAULT FALSE;
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
                ALTER TABLE monitored_assets
                    DROP COLUMN IF EXISTS auto_enroll_discoveries;
            END IF;
        END
        $$;
    """)
