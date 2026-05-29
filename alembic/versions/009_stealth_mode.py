"""v0.5: per-asset opt-in stealth scan mode.

When enabled on a MonitoredAsset, nuclei and nmap drop to a much
slower, browser-impersonating profile so the scan is less likely to
trip WAF / anti-bot protection (Cloudflare, RocketCDN, OVH-managed…)
into blackholing the source IP. Trade-off: scans take 5-10x longer.

Default is FALSE — operators must opt in per asset.

Idempotent DO-block so the migration is safe on fresh DBs (where the
table doesn't exist yet) and on re-runs.
"""
from __future__ import annotations

from alembic import op

revision = "009_stealth_mode"
down_revision = "008_auto_enroll_discoveries"
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
                      AND column_name = 'stealth_mode'
                ) THEN
                    ALTER TABLE monitored_assets
                        ADD COLUMN stealth_mode BOOLEAN
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
                    DROP COLUMN IF EXISTS stealth_mode;
            END IF;
        END
        $$;
    """)
