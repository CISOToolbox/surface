"""Allow one Surface Measure to cover multiple Findings.

Symmetric with AppSec migration 002. Bulk triage "À corriger" across N
selected findings used to loop and create N separate measures (UNIQUE
constraint on finding_id blocked grouping). After this migration:

  - measures.finding_ids JSONB[] holds every finding covered by the measure
  - measures.finding_id stays as the "primary" link for backwards compat
    with the 1:1 ORM relationship, and becomes nullable
  - UNIQUE constraint on finding_id is dropped

Idempotent DO-block safe on fresh and existing DBs.
"""
from __future__ import annotations

from alembic import op

revision = "006_measure_finding_ids"
down_revision = "005_findings_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'measures' AND column_name = 'finding_ids'
        ) THEN
            ALTER TABLE measures ADD COLUMN finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
        END IF;
    END $$;
    """)

    op.execute("""
    UPDATE measures
       SET finding_ids = jsonb_build_array(finding_id::text)
     WHERE finding_id IS NOT NULL
       AND finding_ids = '[]'::jsonb;
    """)

    op.execute("""
    DO $$
    DECLARE cname text;
    BEGIN
        SELECT conname INTO cname
          FROM pg_constraint
         WHERE conrelid = 'measures'::regclass
           AND contype = 'u'
           AND pg_get_constraintdef(oid) LIKE '%(finding_id)%';
        IF cname IS NOT NULL THEN
            EXECUTE 'ALTER TABLE measures DROP CONSTRAINT ' || quote_ident(cname);
        END IF;
    END $$;
    """)

    # Also relax the NOT NULL so a future reassignment can unlink.
    op.execute("ALTER TABLE measures ALTER COLUMN finding_id DROP NOT NULL;")


def downgrade() -> None:
    pass
