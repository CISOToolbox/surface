"""v0.2: tagging + criticality on monitored_assets, diff JSON on scan_jobs

Adds:
  - monitored_assets.tags         JSONB DEFAULT '[]'
  - monitored_assets.criticality  VARCHAR(20) DEFAULT 'medium'
  - scan_jobs.diff                JSONB DEFAULT '{}'

The migration is wrapped in a PL/pgSQL DO block (same pattern as 002) so
it is safe on a fresh database where create_all has not run yet, and it
re-applies cleanly on an upgraded database where one or more of the
columns may already exist.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "003_v02_tagging_diff"
down_revision = "002_dedup_key_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.monitored_assets') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'monitored_assets' AND column_name = 'tags'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN tags JSONB NOT NULL DEFAULT '[]'::jsonb;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'monitored_assets' AND column_name = 'criticality'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN criticality VARCHAR(20) NOT NULL DEFAULT 'medium';
                END IF;
            END IF;

            IF to_regclass('public.scan_jobs') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'scan_jobs' AND column_name = 'diff'
                ) THEN
                    ALTER TABLE scan_jobs
                        ADD COLUMN diff JSONB NOT NULL DEFAULT '{}'::jsonb;
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
                ALTER TABLE monitored_assets DROP COLUMN IF EXISTS tags;
                ALTER TABLE monitored_assets DROP COLUMN IF EXISTS criticality;
            END IF;
            IF to_regclass('public.scan_jobs') IS NOT NULL THEN
                ALTER TABLE scan_jobs DROP COLUMN IF EXISTS diff;
            END IF;
        END
        $$;
    """)
