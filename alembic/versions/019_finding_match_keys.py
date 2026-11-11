"""Finding match keys (FEAT-69)

Revision ID: 019_finding_match_keys
Revises: 018_host_liveness
Create Date: 2026-11-11

Each finding carries the keys it is matched to the monitored assets on, so
the Hosts cards, a host's page and the dashboard are computed by the server
over every finding instead of by the browser over the latest 10 000. Existing
rows are filled here with the same function the write hook uses.
"""
from alembic import op
import sqlalchemy as sa

from src.finding_match import KEY_LEN, match_keys

revision = "019_finding_match_keys"
down_revision = "018_host_liveness"
branch_labels = None
depends_on = None

_TEXT_KEYS = ("match_host", "match_share", "match_evhost", "match_evaddr")
_IP4_KEYS = ("match_host_ip4", "match_evaddr_ip4")
_BATCH = 2000


def upgrade() -> None:
    for name in _TEXT_KEYS:
        op.add_column("findings", sa.Column(name, sa.String(KEY_LEN), nullable=False, server_default=sa.text("''")))
    for name in _IP4_KEYS:
        op.add_column("findings", sa.Column(name, sa.BigInteger(), nullable=True))

    bind = op.get_bind()
    findings = sa.table(
        "findings", sa.column("id"), sa.column("target"), sa.column("evidence", sa.JSON()),
        *(sa.column(n) for n in _TEXT_KEYS + _IP4_KEYS),
    )
    update = (
        findings.update()
        .where(findings.c.id == sa.bindparam("_id"))
        .values({n: sa.bindparam(n) for n in _TEXT_KEYS + _IP4_KEYS})
    )
    last = None
    while True:
        q = sa.select(findings.c.id, findings.c.target, findings.c.evidence).order_by(findings.c.id).limit(_BATCH)
        if last is not None:
            q = q.where(findings.c.id > last)
        rows = bind.execute(q).all()
        if not rows:
            break
        bind.execute(update, [{"_id": r.id, **match_keys(r.target, r.evidence)} for r in rows])
        last = rows[-1].id

    for name in _TEXT_KEYS + _IP4_KEYS:
        op.create_index(f"ix_findings_{name}", "findings", [name])


def downgrade() -> None:
    for name in _TEXT_KEYS + _IP4_KEYS:
        op.drop_index(f"ix_findings_{name}", table_name="findings")
        op.drop_column("findings", name)
