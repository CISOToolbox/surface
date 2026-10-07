"""FEAT-35 / FEAT-55 — the new-findings alert of a scan.

A finding a manual scan inserts is no longer "new" for the next scheduled
run, so if only the scheduler notified, a certificate found by "Scan now"
would never be alerted. Locks:
  - a completed manual scan that inserts findings notifies once with its job
    and the keys of what it inserted; a scan that inserts nothing does not;
  - the alert carries the findings of ITS run only (a scan or a connector
    inserting meanwhile stays out), and a reopened finding is alerted;
  - findings a scanner persists in batches (the sink) are alerted too, and
    Scan all sends one alert naming the assets that brought findings;
  - a run larger than PostgreSQL's bind-parameter cap is queried in chunks.
"""
from __future__ import annotations

import contextlib
import os
import sys
from datetime import datetime, timezone

import pytest
import pytest_asyncio

# Same bootstrap as test_connectors_scheduling.py: src.database builds a
# postgres engine at import (never connected, async_session is replaced).
os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "clef-de-test-suffisamment-longue-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import src.routes.monitored as mon  # noqa: E402
import src.surface_notify as notify  # noqa: E402
from src.findings_dedup import alert_keys, compute_dedup_key, insert_many  # noqa: E402
from src.models import Base, Finding, MonitoredAsset, ScanJob  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest_asyncio.fixture
async def engine():
    e = create_async_engine("sqlite+aiosqlite://",
                            connect_args={"check_same_thread": False},
                            poolclass=StaticPool)
    async with e.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    yield e
    await e.dispose()


@pytest_asyncio.fixture
async def db(engine):
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def wired(monkeypatch, db):
    """Plugs the manual-scan task into the test session and records alerts."""
    alerts: list[tuple] = []

    @contextlib.asynccontextmanager
    async def _session():
        yield db

    async def _notify(_db, job_id, target, keys):
        alerts.append((job_id, target, list(keys)))

    monkeypatch.setattr(mon, "async_session", _session)
    monkeypatch.setattr(mon, "resolve_first_ip", lambda v: None)
    monkeypatch.setattr(notify, "notify_scan_new_findings", _notify)
    return alerts


async def _asset_and_job(db):
    a = MonitoredAsset(kind="domain", value="medsecure.example", enabled=True,
                       enabled_scanners=["ct_logs"], config={})
    db.add(a)
    await db.commit()
    j = ScanJob(target=a.value, profile="manual", scanner="manual-domain",
                status="running", started_at=datetime.now(timezone.utc), triggered_by="manual")
    db.add(j)
    await db.commit()
    return a, j


def _finding(target):
    return {"scanner": "ct_logs", "type": "ct_typosquat_cert", "severity": "high",
            "title": "t", "description": "d", "target": target, "evidence": {}}


@pytest.mark.asyncio
async def test_a_manual_scan_with_new_findings_alerts_once(monkeypatch, db, wired):
    a, j = await _asset_and_job(db)
    monkeypatch.setattr(mon, "run_enabled_scanners",
                        lambda *args, **kw: ([_finding("medsecure.example.net#01")], []))
    await mon._run_manual_scan(a.id, j.id, "domain", a.value, ["ct_logs"])
    key = compute_dedup_key("ct_logs", "ct_typosquat_cert", "medsecure.example.net#01")
    assert wired == [(j.id, a.value, [key])]


@pytest.mark.asyncio
async def test_a_manual_scan_without_new_findings_does_not_alert(monkeypatch, db, wired):
    a, j = await _asset_and_job(db)
    monkeypatch.setattr(mon, "run_enabled_scanners", lambda *args, **kw: ([], []))
    await mon._run_manual_scan(a.id, j.id, "domain", a.value, ["ct_logs"])
    assert wired == []


@pytest.fixture
def mailbox(monkeypatch):
    """One subscriber; records what each alert would send."""
    sent: list[int] = []
    rendered: list[list[str]] = []

    async def _subs(_db):
        return [{"email": "rssi@medsecure.example", "prefs": {"alert_min_severity": "info", "lang": "en"}}]

    async def _send(_db, email, period_key, subject, html, n):
        sent.append(n)
        return "sent"

    def _render(target, findings, lang):
        rendered.append(sorted(f.target for f in findings))
        return ""

    monkeypatch.setattr(notify, "list_subscribers", _subs)
    monkeypatch.setattr(notify, "_journal_and_send", _send)
    monkeypatch.setattr(notify, "render_alert_html", _render)
    return sent, rendered


@pytest.mark.asyncio
async def test_the_alert_carries_its_own_run_only(db, mailbox):
    _, rendered = mailbox
    mine = await insert_many(db, [_finding("medsecure.example.net#01")])
    await insert_many(db, [_finding("other.example.net#02")])   # another run, meanwhile
    await db.commit()
    await notify.notify_scan_new_findings(db, "job-1", "medsecure.example", alert_keys(mine))
    assert rendered == [["medsecure.example.net#01"]]


@pytest.mark.asyncio
async def test_a_reopened_finding_is_alerted(db, mailbox):
    _, rendered = mailbox
    await insert_many(db, [_finding("medsecure.example.net#01")])
    await db.commit()
    f = (await db.execute(Finding.__table__.select())).first()
    await db.execute(Finding.__table__.update().where(Finding.__table__.c.id == f.id).values(status="fixed"))
    await db.commit()
    again = await insert_many(db, [_finding("medsecure.example.net#01")])
    await db.commit()
    assert again["reopened"] == 1
    await notify.notify_scan_new_findings(db, "job-2", "medsecure.example", alert_keys(again))
    assert rendered == [["medsecure.example.net#01"]]


@pytest.mark.asyncio
async def test_findings_persisted_in_batches_are_alerted(monkeypatch, db, wired):
    a, j = await _asset_and_job(db)

    def _scan(kind, value, enabled, stealth, config, sink):
        sink([_finding("a#1"), _finding("b#2")])
        sink([_finding("a#1")])            # second batch: a is refreshed
        return [_finding("c#3")], []

    monkeypatch.setattr(mon, "run_enabled_scanners", _scan)
    await mon._run_manual_scan(a.id, j.id, "domain", a.value, ["ct_logs"])
    keys = sorted(wired[0][2])
    assert keys == sorted(compute_dedup_key("ct_logs", "ct_typosquat_cert", t) for t in ("a#1", "b#2", "c#3"))


@pytest.mark.asyncio
async def test_scan_all_sends_one_alert_naming_the_assets_with_findings(monkeypatch, engine, db):
    alerts: list[tuple] = []
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _notify(_db, job_id, target, keys):
        alerts.append((target, sorted(keys)))

    noisy = ["a.example", "b.example", "c.example", "d.example"]
    monkeypatch.setattr(mon, "async_session", maker)
    monkeypatch.setattr(mon, "check_scan_quota", lambda *a, **k: None)   # in-memory limiter shared across tests
    monkeypatch.setattr(notify, "notify_scan_new_findings", _notify)
    monkeypatch.setattr(mon, "run_enabled_scanners", lambda kind, value, *a, **k: (
        ([_finding(value + ".net#01")] if value in noisy else []), []))
    for v in noisy + ["quiet.example"]:
        db.add(MonitoredAsset(kind="domain", value=v, enabled=True, enabled_scanners=["ct_logs"], config={}))
    await db.commit()

    out = await mon.scan_all(request=None, user=None, db=db)
    assert out["scanned"] == 5
    assert len(alerts) == 1, "one alert for the whole run, not one per asset"
    label, keys = alerts[0]
    assert keys == sorted(compute_dedup_key("ct_logs", "ct_typosquat_cert", v + ".net#01") for v in noisy)
    named = label.split(" (+")[0].split(", ")
    assert len(named) == 3 and set(named) <= set(noisy) and label.endswith(" (+1)")


@pytest.mark.asyncio
async def test_scan_all_does_not_alert_for_a_partial_scan(monkeypatch, engine, db):
    alerts: list[tuple] = []

    async def _notify(_db, job_id, target, keys):
        alerts.append((target, keys))

    state = {"scanner": "smb_scan_rs", "type": "scanner_state", "severity": "info", "title": "s",
             "description": "", "target": "x", "evidence": {"partial": True}}
    monkeypatch.setattr(mon, "async_session", async_sessionmaker(engine, expire_on_commit=False))
    monkeypatch.setattr(mon, "check_scan_quota", lambda *a, **k: None)
    monkeypatch.setattr(notify, "notify_scan_new_findings", _notify)
    monkeypatch.setattr(mon, "run_enabled_scanners", lambda *a, **k: ([_finding("p#01"), state], []))
    db.add(MonitoredAsset(kind="domain", value="partial.example", enabled=True,
                          enabled_scanners=["ct_logs"], config={}))
    await db.commit()

    out = await mon.scan_all(request=None, user=None, db=db)
    assert out["scanned"] == 1 and out["errors"] == []
    assert alerts == [], "a partial scan does not alert, as in the scheduler"


@pytest.mark.asyncio
async def test_a_large_run_is_queried_in_chunks(monkeypatch, db, mailbox):
    _, rendered = mailbox
    monkeypatch.setattr(notify, "_KEYS_PER_QUERY", 2)
    counts = await insert_many(db, [_finding(f"x{i}#0{i}") for i in range(5)])
    await db.commit()
    calls = []
    real = db.execute

    async def _spy(stmt, *a, **k):
        calls.append(stmt)
        return await real(stmt, *a, **k)

    monkeypatch.setattr(db, "execute", _spy)
    await notify.notify_scan_new_findings(db, "job-3", "medsecure.example", alert_keys(counts))
    assert len(rendered[0]) == 5
    assert len(calls) == 3, "5 keys, 2 per query"
