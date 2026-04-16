"""v0.3.1: performance indexes on findings table.

Adds composite and single-column indexes on the most-queried columns:
  - (status, severity) — dashboard stats, findings list filter, reports
  - scanner — findings list filter by scanner
  - target — reports GROUP BY, per-host detail
  - created_at — date-range filters, ORDER BY

Idempotent DO-block safe on fresh and existing DBs.
"""
from __future__ import annotations

from alembic import op

revision = "005_findings_indexes"
down_revision = "004_resolved_ip"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.findings') IS NOT NULL THEN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'findings' AND indexname = 'ix_findings_status_severity'
                ) THEN
                    CREATE INDEX ix_findings_status_severity
                        ON findings (status, severity);
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'findings' AND indexname = 'ix_findings_scanner'
                ) THEN
                    CREATE INDEX ix_findings_scanner ON findings (scanner);
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'findings' AND indexname = 'ix_findings_target'
                ) THEN
                    CREATE INDEX ix_findings_target ON findings (target);
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'findings' AND indexname = 'ix_findings_created_at'
                ) THEN
                    CREATE INDEX ix_findings_created_at ON findings (created_at);
                END IF;
            END IF;
        END
        $$;
    """)


def downgrade() -> None:
    op.execute("""
        DROP INDEX IF EXISTS ix_findings_status_severity;
        DROP INDEX IF EXISTS ix_findings_scanner;
        DROP INDEX IF EXISTS ix_findings_target;
        DROP INDEX IF EXISTS ix_findings_created_at;
    """)
