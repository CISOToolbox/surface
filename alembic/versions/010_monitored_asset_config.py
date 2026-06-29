"""v0.6: per-asset free-form scanner config (JSONB).

Generic, non-secret per-asset options consumed by scanners that declare
`wants_config` (e.g. the SMB file-share add-on scanner: custom regex,
extensions, max file size). Secrets (e.g. SMB service-account credentials)
are NOT stored here — they come from the deployment environment.

Default '{}'. Idempotent DO-block, safe on fresh DBs and re-runs.
"""
from __future__ import annotations

from alembic import op

revision = "010_monitored_asset_config"
down_revision = "009_stealth_mode"
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
                      AND column_name = 'config'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN config JSONB NOT NULL DEFAULT '{}'::jsonb;
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
                    DROP COLUMN IF EXISTS config;
            END IF;
        END
        $$;
    """)
