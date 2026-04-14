"""dedup_key unique constraint — prevents duplicate findings under concurrent scans

Adds a UNIQUE constraint on findings.dedup_key so that two coroutines racing
to insert the same logical finding can't both succeed. The dedup_helper
now handles IntegrityError and retries as a refresh.

Existing duplicates (if any) are collapsed to the oldest row before the
constraint is created.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "002_dedup_key_unique"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent: on a fresh DB (before create_all has run) the findings
    # table does not exist yet — skip. create_all will later create the
    # table with the UNIQUE constraint already declared in models.py.
    # On an existing DB, collapse duplicates then add the constraint.
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.findings') IS NULL THEN
                RETURN;
            END IF;

            WITH ranked AS (
                SELECT id,
                       ROW_NUMBER() OVER (PARTITION BY dedup_key ORDER BY created_at ASC) AS rn
                FROM findings
                WHERE dedup_key IS NOT NULL
            )
            DELETE FROM findings
            WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

            IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'ix_findings_dedup_key') THEN
                DROP INDEX ix_findings_dedup_key;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'uq_findings_dedup_key'
            ) THEN
                ALTER TABLE findings
                    ADD CONSTRAINT uq_findings_dedup_key UNIQUE (dedup_key);
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.findings') IS NULL THEN RETURN; END IF;
            IF EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'uq_findings_dedup_key'
            ) THEN
                ALTER TABLE findings DROP CONSTRAINT uq_findings_dedup_key;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'ix_findings_dedup_key') THEN
                CREATE INDEX ix_findings_dedup_key ON findings (dedup_key);
            END IF;
        END
        $$;
    """)
