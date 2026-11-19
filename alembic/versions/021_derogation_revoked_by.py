"""the revocation of a derogation keeps its own who and when (BUG-157)

Revision ID: 021_derogation_revoked_by
Revises: 020_notification_lang_default
Create Date: 2026-11-19

Revoking a derogation wrote the revoker over its approver (`decided_by`).
The revocation now has `revoked_by` and `revoked_at`; `decided_*` stay the
approval's. For a derogation already revoked: the revoker moves to
`revoked_by`, and the approver comes back from the write journal's approval
entry when the journal holds it (otherwise it stays as it was).
"""
from alembic import op
import sqlalchemy as sa

revision = "021_derogation_revoked_by"
down_revision = "020_notification_lang_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("derogations", sa.Column("revoked_by", sa.String(255), nullable=True, server_default=sa.text("''")))
    op.add_column("derogations", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE derogations SET revoked_by = COALESCE(decided_by, ''), revoked_at = updated_at "
               "WHERE status = 'revoked'")
    if sa.inspect(op.get_bind()).has_table("audit_log"):
        op.execute("""
            UPDATE derogations AS d SET decided_by = a.who
            FROM (SELECT DISTINCT ON (target) target,
                         user_email AS who   -- the approval journals its decider as the actor
                  FROM audit_log WHERE action = 'derogation.approved'
                  ORDER BY target, logged_at DESC) AS a
            WHERE d.status = 'revoked' AND a.target = d.reference AND a.who <> ''
        """)


def downgrade() -> None:
    op.drop_column("derogations", "revoked_at")
    op.drop_column("derogations", "revoked_by")
