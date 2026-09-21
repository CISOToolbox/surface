"""Several items per non-conformity (FEAT-45)

Revision ID: 016_nonconformity_subjects
Revises: 015_nonconformities
Create Date: 2026-09-17

A non-conformity may concern several items (requirements overlap across
frameworks). `subjects` lists them; `subject_type`/`subject_id` keep the
first one, the primary, for everything keyed on a single subject.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "016_nonconformity_subjects"
down_revision = "015_nonconformities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("nonconformities",
                  sa.Column("subjects", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.execute("UPDATE nonconformities SET subjects = jsonb_build_array(jsonb_build_object('type', subject_type, 'id', subject_id)) "
               "WHERE subject_id <> ''")


def downgrade() -> None:
    op.drop_column("nonconformities", "subjects")
