"""FEAT-37 — the ``closed_upstream`` finding status.

A connector cannot tell "fixed" from "excepted as a false positive": both look
like an absence from the upstream feed. This status says only what is known.

Two properties carry the whole design, and both are easy to break silently:

  - it must NOT count in the posture reported to Pilot. Activating a connector
    would otherwise degrade a client's score for findings nobody has to act on.
  - it must NOT be frozen the way ``false_positive`` is. Nobody decided to
    ignore it — the source went quiet. If the source lists it again, it is an
    open finding once more.

Pure stdlib + AST: no database, no running stack.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

MODULE = Path(__file__).resolve().parents[2]


def _source(rel: str) -> str:
    return (MODULE / rel).read_text(encoding="utf-8")


def test_status_is_declared_in_the_enum():
    tree = ast.parse(_source("src/models.py"))
    enum = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "FindingStatus"
    )
    values = {
        n.value.value
        for n in enum.body
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
    }
    assert "closed_upstream" in values, "FindingStatus lost CLOSED_UPSTREAM"


def test_status_fits_the_column():
    """The column is a String(30), not a SQL enum — which is why no migration
    was needed. A longer status would be truncated or rejected at insert."""
    src = _source("src/models.py")
    m = re.search(r'status = Column\(String\((\d+)\).*default="new"', src)
    assert m, "the findings.status column declaration moved"
    assert len("closed_upstream") <= int(m.group(1))


def test_it_is_absent_from_the_posture_filter():
    """open_filter is what Pilot's severity counters are built on."""
    src = _source("src/routes/internal.py")
    m = re.search(r'open_filter = Finding\.status\.in_\(\[([^\]]*)\]', src)
    assert m, "open_filter moved or changed shape"
    assert "closed_upstream" not in m.group(1), (
        "closed_upstream counts as open: enabling a connector would degrade "
        "the posture for findings nobody has to act on"
    )


def test_it_is_a_filterable_status():
    assert "closed_upstream" in _source("src/routes/findings.py"), (
        "the status is not in _VALID_STATUSES — the UI filter would be ignored"
    )


def test_it_reopens_rather_than_staying_frozen():
    """Unlike false_positive, it must reopen when the source lists it again."""
    src = _source("src/findings_dedup.py")
    frozen = re.search(r'if existing\.status == "false_positive":', src)
    reopen = re.search(r'if existing\.status in \(([^)]*)\):', src)
    assert frozen, "the false_positive freeze branch moved"
    assert reopen and "closed_upstream" in reopen.group(1), (
        "closed_upstream is not in the reopen branch: a finding the source "
        "reports again would stay closed"
    )
    # And it must not have been added to the freeze branch by mistake.
    freeze_block = src[frozen.start():frozen.start() + 200]
    assert "closed_upstream" not in freeze_block


def test_the_report_always_shows_the_bucket():
    src = _source("src/routes/reports.py")
    m = re.search(r'by_status = \{([^}]*)\}', src)
    assert m and "closed_upstream" in m.group(1), (
        "the bucket appears only once a finding carries the status, so the "
        "report changes shape between runs"
    )
