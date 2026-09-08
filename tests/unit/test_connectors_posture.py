"""FEAT-37 — criterion 11: enabling the connector must not skew the posture.

The first delivery counted ``defender_recommendation`` findings in the
critical/high/medium/low buckets reported to Pilot: switching the connector
on mechanically degraded the client's score, because every recommendation —
which is a REMEDY covering many machines — was counted as one more
vulnerability. And ``closed_upstream`` must not count as open.

The real ``/internal/stats`` route is exercised against SQLite, not a
re-implementation of its queries: the defect lived in the route.
"""
from __future__ import annotations

import os
import sys

import pytest
import pytest_asyncio

# src.routes.internal drags src.database in, whose module-level engine takes
# PostgreSQL pool arguments that SQLite rejects. The engine never connects in
# these tests (we drive our own session), so any postgres-shaped URL will do —
# and it must OVERRIDE whatever an earlier test file put in the environment.
os.environ["DATABASE_URL"] = "postgresql+asyncpg://t:t@localhost:5432/t"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

from src.models import Base, Finding  # noqa: E402
from src.routes.internal import internal_stats  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://",
                                 connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


def _req() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/internal/stats",
                    "headers": [(b"x-service-token",
                                 os.environ["SERVICE_TOKEN"].encode())],
                    "query_string": b""})


def _finding(i, type_, status="new", severity="high", target="srv01"):
    return Finding(scanner="defender", type=type_, target=target,
                   title=f"f{i}", description="", severity=severity,
                   status=status, dedup_key=f"k{i}", evidence={})


@pytest.mark.asyncio
async def test_recommendations_and_closed_upstream_do_not_count(db):
    db.add(_finding(1, "defender_cve", "new", "high"))
    db.add(_finding(2, "defender_cve", "closed_upstream", "high"))
    db.add(_finding(3, "defender_recommendation", "new", "critical", target="rec-1"))
    db.add(_finding(4, "defender_recommendation", "new", "high", target="rec-2"))
    await db.commit()

    stats = await internal_stats(_req(), db)
    # The severity buckets count exactly ONE open vulnerability (the open CVE):
    # not the closed_upstream one, not the two recommendations.
    high = stats.get("findings_high", None)
    if high is None:
        # v2 envelope: severities live in the breakdown/counters — assert on
        # the posture penalty instead, which derives from the same numbers.
        assert stats["posture"]["score"] == 97, (
            "expected a single 'high' penalty (100 - 3); recommendations or "
            f"closed_upstream leaked into the counters: {stats['posture']}")
    else:
        assert high == 1


@pytest.mark.asyncio
async def test_the_posture_is_identical_with_and_without_recommendations(db):
    db.add(_finding(1, "defender_cve", "new", "high"))
    await db.commit()
    before = (await internal_stats(_req(), db))["posture"]["score"]

    db.add(_finding(2, "defender_recommendation", "new", "critical", target="rec-1"))
    await db.commit()
    after = (await internal_stats(_req(), db))["posture"]["score"]
    assert before == after, (
        "adding a recommendation changed the posture score: enabling the "
        "connector degrades the client's score mechanically (criterion 11)")


@pytest.mark.asyncio
async def test_top_items_name_hosts_not_raw_connector_targets(db):
    """The first delivery's documented symptom: machineId|cveId|productName
    strings reported to Pilot as "hosts". top_items must group on the host
    named in the evidence, and fall back to the target for scanner findings."""
    for i, cve in enumerate(("CVE-1", "CVE-2", "CVE-3")):
        f = _finding(10 + i, "defender_cve", "new", "critical",
                     target=f"m-1|{cve}|edge")
        f.evidence = {"hostname": "srv01.corp.local", "cve": cve}
        db.add(f)
    nmap = _finding(20, "open_port", "new", "high", target="web.example.com:443")
    nmap.scanner = "nmap"
    db.add(nmap)
    await db.commit()

    stats = await internal_stats(_req(), db)
    labels = [item["label"] for item in stats["top_items"]]
    assert "srv01.corp.local" in labels, labels
    assert not any("|" in lb for lb in labels), (
        f"raw connector targets leaked to Pilot as hosts: {labels}")
    top = next(i for i in stats["top_items"] if i["label"] == "srv01.corp.local")
    assert "3 finding(s)" in top["meta"]
