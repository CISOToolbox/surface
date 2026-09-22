"""Project scope for the register (FEAT-45)

Revision ID: 017_nonconformity_project
Revises: 016_nonconformity_subjects
Create Date: 2026-09-21

A non-conformity and a derogation belong to the project they were declared
in; a record with no project came from the console and stays module-level.
"""
from alembic import op
import sqlalchemy as sa

revision = "017_nonconformity_project"
down_revision = "016_nonconformity_subjects"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("nonconformities", "derogations"):
        op.add_column(table, sa.Column("project_id", sa.String(64), server_default=""))


def downgrade() -> None:
    for table in ("nonconformities", "derogations"):
        op.drop_column(table, "project_id")
