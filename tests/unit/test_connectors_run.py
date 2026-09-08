"""FEAT-37 — the reconciliation guards and the host resolver.

Auto-closing is the only part of a connector that can destroy work. These
tests cover the three guards — each matching a known way of breaking
everything — plus the two defects that sank the first delivery:

  - the ``to_fix``-with-open-measure guard is exercised against a REAL async
    session with a REAL attached measure: the first delivery lazy-loaded
    ``Finding.measure`` and raised ``MissingGreenlet`` on this exact path,
    rolling back every import;
  - host resolution is tested in BOTH discovery orders (external scan first,
    connector first) and across a DNS rename — criteria 2 and 12.

In-memory SQLite: no stack, no Defender tenant.
"""
from __future__ import annotations

import os
import sys

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite://")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.connectors_run import HostResolver, run_connector  # noqa: E402
from src.findings_dedup import compute_dedup_key  # noqa: E402
from src.models import Base, Finding, Measure, MonitoredAsset  # noqa: E402

# SQLite knows neither JSONB nor PostgreSQL server defaults. Same adaptation
# as access/tests/unit/test_stats_review_n1.py — an established pattern in the
# repo rather than one more workaround.
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


def _feed(*cves, machine="m-1", name="srv01.corp.local", ip="10.0.0.5",
          ok=True, excepted=None):
    """A minimal connector result: one machine, one finding per CVE."""
    findings = [{
        "scanner": "defender", "type": "defender_cve",
        "host_ref": machine,
        "target": f"{machine}|{cve}|Product".lower(),
        "title": f"{cve} - Product", "description": "d", "severity": "high",
        "evidence": {"cve": cve, "hostname": name, "address": ip},
    } for cve in cves]
    return {"ok": ok, "error": None if ok else "boom",
            "hosts": [{"id": machine, "dns_name": name, "ip": ip, "label": ""}],
            "findings": findings, "excepted": excepted or []}


def _meta(result):
    async def call(_cfg):
        return result
    return {"label": "t", "callable": call, "config_schema": []}


async def _statuses(db):
    rows = (await db.execute(select(Finding.dedup_key, Finding.status))).all()
    return dict(rows)


def _key(machine, cve):
    return compute_dedup_key("defender", "defender_cve", f"{machine}|{cve}|Product")


# ── Reconciliation ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_vanished_finding_is_closed_and_a_seen_one_is_not(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1", "CVE-2")), {})
    report = await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    assert report["ok"] is True and report["closed"] == 1
    st = await _statuses(db)
    assert st[_key("m-1", "CVE-1")] == "new"
    assert st[_key("m-1", "CVE-2")] == "closed_upstream"


@pytest.mark.asyncio
async def test_reimporting_the_same_feed_closes_nothing(db):
    """Seen keys are DERIVED with the insertion's own function: a divergent
    computation would close, on every import, what was just inserted."""
    await run_connector(db, "defender", _meta(_feed("CVE-1", "CVE-2")), {})
    report = await run_connector(db, "defender", _meta(_feed("CVE-1", "CVE-2")), {})
    assert report["closed"] == 0
    assert set((await _statuses(db)).values()) == {"new"}


@pytest.mark.asyncio
async def test_guard_1_an_incomplete_import_closes_nothing(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1", "CVE-2")), {})
    report = await run_connector(db, "defender", _meta(_feed("CVE-1", ok=False)), {})
    assert report["ok"] is False and report["closed"] == 0
    assert (await _statuses(db))[_key("m-1", "CVE-2")] == "new"


@pytest.mark.asyncio
async def test_guard_2_other_scanners_findings_are_untouched(db):
    db.add(Finding(scanner="nmap", type="open_port", target="srv01.corp.local:443",
                   title="443/tcp", description="", severity="low", status="new",
                   dedup_key=compute_dedup_key("nmap", "open_port", "srv01.corp.local:443"),
                   evidence={}))
    await db.commit()
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    report = await run_connector(db, "defender", _meta(_feed()), {})
    assert report["closed"] == 1        # only the defender finding
    st = await _statuses(db)
    assert st[compute_dedup_key("nmap", "open_port", "srv01.corp.local:443")] == "new"


@pytest.mark.asyncio
async def test_guard_3_false_positive_stays_frozen(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    f = (await db.execute(select(Finding))).scalar_one()
    f.status = "false_positive"
    await db.commit()
    report = await run_connector(db, "defender", _meta(_feed()), {})
    assert report["closed"] == 0
    assert (await _statuses(db))[_key("m-1", "CVE-1")] == "false_positive"


@pytest.mark.asyncio
async def test_guard_3_to_fix_with_open_measure_is_not_closed(db):
    """THE regression test of the revert: the guard reads ``f.measure`` on a
    real async session. Without eager loading this raises MissingGreenlet and
    the whole import rolls back — which is exactly what shipped the first
    time, on the nominal remediation scenario (criterion 6)."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    f = (await db.execute(select(Finding))).scalar_one()
    f.status = "to_fix"
    db.add(Measure(id="SRF-001", title="patch", description="", statut="en_cours",
                   finding_id=f.id, finding_ids=[str(f.id)]))
    await db.commit()
    db.expire_all()                     # force a fresh load in the next select

    report = await run_connector(db, "defender", _meta(_feed()), {})
    assert report["ok"] is True, f"import failed: {report['error']}"
    assert report["closed"] == 0
    assert (await _statuses(db))[_key("m-1", "CVE-1")] == "to_fix"


@pytest.mark.asyncio
async def test_to_fix_with_finished_measure_is_closed(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    f = (await db.execute(select(Finding))).scalar_one()
    f.status = "to_fix"
    db.add(Measure(id="SRF-002", title="patch", description="", statut="termine",
                   finding_id=f.id, finding_ids=[str(f.id)]))
    await db.commit()
    db.expire_all()

    report = await run_connector(db, "defender", _meta(_feed()), {})
    assert report["closed"] == 1
    assert (await _statuses(db))[_key("m-1", "CVE-1")] == "closed_upstream"


@pytest.mark.asyncio
async def test_an_upstream_exception_closes_with_its_motive(db):
    """Criterion 10: a recommendation excepted upstream is closed with the
    reason in the note AND the evidence — the first delivery logged it then
    lost it behind the generic note."""
    reco = {"scanner": "defender", "type": "defender_recommendation",
            "target": "rec-42", "title": "Update Edge", "description": "d",
            "severity": "medium", "evidence": {}}
    first = {"ok": True, "error": None, "hosts": [], "findings": [reco], "excepted": []}
    await run_connector(db, "defender", _meta(first), {})

    second = {"ok": True, "error": None, "hosts": [], "findings": [],
              "excepted": [{"type": "defender_recommendation", "target": "rec-42",
                            "reason": "Full exception"}]}
    report = await run_connector(db, "defender", _meta(second), {})
    assert report["closed"] == 1
    f = (await db.execute(select(Finding))).scalar_one()
    assert f.status == "closed_upstream"
    assert "Full exception" in (f.triage_notes or "")
    assert f.evidence.get("upstream_exception") == "Full exception"


@pytest.mark.asyncio
async def test_a_connector_that_raises_reports_and_closes_nothing(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})

    async def explode(_cfg):
        raise RuntimeError("token endpoint unreachable")
    report = await run_connector(db, "defender",
                                 {"label": "t", "callable": explode}, {})
    assert report["ok"] is False and "RuntimeError" in report["error"]
    assert (await _statuses(db))[_key("m-1", "CVE-1")] == "new"


# ── Host resolution (criteria 2 and 12) ─────────────────────────


@pytest.mark.asyncio
async def test_connector_attaches_to_a_hand_added_host(db):
    """External discovery FIRST: the admin monitors srv01 by hostname, then
    the connector finds the same machine — one card, not two."""
    db.add(MonitoredAsset(kind="host", value="srv01.corp.local", enabled=True,
                          scan_frequency_hours=24, enabled_scanners=[], tags=[],
                          config={}))
    await db.commit()
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    hosts = (await db.execute(select(MonitoredAsset))).scalars().all()
    assert len(hosts) == 1
    assert (hosts[0].config or {}).get("connector_ids", {}).get("defender") == "m-1"
    assert hosts[0].resolved_ip == "10.0.0.5"     # backfilled, not overwritten


@pytest.mark.asyncio
async def test_connector_first_then_scan_matches_by_ip(db):
    """Connector FIRST, then an asset added by IP literal: matched via the
    resolved IP, still one card (criterion 12, other order)."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    resolver = await HostResolver("defender").load(db)
    match = resolver.resolve(db, {"id": "", "dns_name": "", "ip": "10.0.0.5"})
    hosts = (await db.execute(select(MonitoredAsset))).scalars().all()
    assert len(hosts) == 1 and match is hosts[0]


@pytest.mark.asyncio
async def test_a_dns_rename_does_not_duplicate_the_host(db):
    """The upstream id is the stable identity: the machine renamed between
    two imports keeps its single card."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    renamed = _feed("CVE-1", name="srv01-new.corp.local", ip="10.0.0.5")
    await run_connector(db, "defender", _meta(renamed), {})
    hosts = (await db.execute(select(MonitoredAsset))).scalars().all()
    assert len(hosts) == 1


@pytest.mark.asyncio
async def test_two_imports_do_not_duplicate_hosts(db):
    """Criterion 2 in its plainest form — and the reason the manual run and
    the scheduler share a lock."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    hosts = (await db.execute(select(MonitoredAsset))).scalars().all()
    assert len(hosts) == 1


@pytest.mark.asyncio
async def test_discovered_hosts_run_the_connector_and_nothing_else(db):
    """`enabled` means "this host reports findings"; the connector is the
    host's ONLY active scanner at discovery. External scanning stays a
    separate, deliberate choice (criterion 1's corollary: no external scan
    starts on its own)."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    assert h.enabled is True
    assert h.enabled_scanners == ["defender"]
    assert "connector:defender" in (h.tags or [])


@pytest.mark.asyncio
async def test_a_disabled_host_stops_reporting_and_its_findings_close(db):
    """The host-centric model: disabling a host stops its findings entirely — new
    ones are dropped from the feed, existing ones close with an honest
    motive, not the generic "upstream stopped reporting"."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled = False
    await db.commit()

    report = await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    assert report["ok"] is True
    assert report.get("silenced") == 1
    assert report["closed"] == 1
    f = (await db.execute(select(Finding))).scalar_one()
    assert f.status == "closed_upstream"
    assert "hôte désactivé dans Surface" in (f.triage_notes or "")


@pytest.mark.asyncio
async def test_unticking_the_connector_on_a_host_silences_it_too(db):
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled_scanners = ["nmap_quick"]        # connector removed, host stays on
    await db.commit()

    report = await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    assert report.get("silenced") == 1 and report["closed"] == 1


@pytest.mark.asyncio
async def test_org_wide_findings_survive_host_silencing(db):
    """A recommendation has no host_ref: silencing one machine must not
    silence organisation-wide findings."""
    reco = {"scanner": "defender", "type": "defender_recommendation",
            "target": "rec-1", "title": "Update", "description": "d",
            "severity": "medium", "evidence": {}}
    feed = _feed("CVE-1")
    feed["findings"].append(reco)
    await run_connector(db, "defender", _meta(feed), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled = False
    await db.commit()

    report = await run_connector(db, "defender", _meta(feed), {})
    st = await _statuses(db)
    assert st[compute_dedup_key("defender", "defender_recommendation", "rec-1")] == "new"
    assert report.get("silenced") == 1


@pytest.mark.asyncio
async def test_re_enabling_the_host_reopens_its_findings(db):
    feed = _feed("CVE-1")
    await run_connector(db, "defender", _meta(feed), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled = False
    await db.commit()
    await run_connector(db, "defender", _meta(feed), {})   # closes

    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled = True
    await db.commit()
    await run_connector(db, "defender", _meta(feed), {})   # reopens
    f = (await db.execute(select(Finding).where(Finding.type == "defender_cve"))).scalar_one()
    assert f.status == "new"


@pytest.mark.asyncio
async def test_enrolment_heals_the_old_model_and_augments_external_hosts(db):
    """One-shot enrolment: an old-model artefact (disabled, empty) is enabled
    with the connector as its scanner; an externally-scanned host GAINS the
    connector alongside its existing scanners (both views on one card) but a
    host the admin disabled stays disabled — enabled is the admin's call."""
    db.add(MonitoredAsset(kind="host", value="srv01.corp.local", enabled=False,
                          scan_frequency_hours=24, enabled_scanners=[], tags=["connector:defender"],
                          config={"connector_ids": {"defender": "m-1"}}))
    # An externally-scanned host, currently disabled by the admin.
    db.add(MonitoredAsset(kind="host", value="srv09.corp.local", enabled=False,
                          scan_frequency_hours=24, enabled_scanners=["nmap_quick"], tags=[],
                          config={}))
    await db.commit()

    def two(*cves):
        f = _feed(cves[0], machine="m-1", name="srv01.corp.local", ip="10.0.0.1")
        f["hosts"].append({"id": "m-9", "dns_name": "srv09.corp.local", "ip": "10.0.0.9", "label": ""})
        f["findings"].append({"scanner": "defender", "type": "defender_cve",
                              "host_ref": "m-9", "target": "m-9|CVE-9|Product",
                              "title": "t", "description": "d", "severity": "high",
                              "evidence": {"hostname": "srv09.corp.local"}})
        return f

    await run_connector(db, "defender", _meta(two("CVE-1")), {})
    rows = {a.value: a for a in (await db.execute(select(MonitoredAsset))).scalars().all()}
    healed = rows["srv01.corp.local"]
    assert healed.enabled is True and healed.enabled_scanners == ["defender"]
    ext = rows["srv09.corp.local"]
    assert ext.enabled is False                      # admin's call, not re-enabled
    assert ext.enabled_scanners == ["nmap_quick", "defender"]   # connector added


@pytest.mark.asyncio
async def test_an_admin_removing_the_connector_makes_it_stick(db):
    """After enrolment, unticking the connector on a host is honoured on the
    next import: it is not silently re-added."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    h.enabled_scanners = ["nmap_quick"]              # admin removes the connector
    await db.commit()

    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    h = (await db.execute(select(MonitoredAsset))).scalar_one()
    assert h.enabled_scanners == ["nmap_quick"]      # NOT re-added


@pytest.mark.asyncio
async def test_a_machine_with_no_name_and_no_ip_creates_no_ghost_host(db):
    feed = _feed("CVE-1")
    feed["hosts"].append({"id": "m-ghost", "dns_name": "", "ip": "", "label": ""})
    report = await run_connector(db, "defender", _meta(feed), {})
    assert report["ok"] is True
    hosts = (await db.execute(select(MonitoredAsset))).scalars().all()
    assert len(hosts) == 1
    assert all(h.value for h in hosts)


# ── Multi-instance isolation ────────────────────────────────────


@pytest.mark.asyncio
async def test_two_instances_never_close_each_others_findings(db):
    """THE danger of multi-instance: findings are stamped with the INSTANCE
    key as their scanner, and reconciliation is scoped on it. If both
    Defender tenants shared scanner="defender", every import of tenant A
    would close everything tenant B reported."""
    feed_a = _feed("CVE-A", machine="m-a", name="srv-a.corp.local", ip="10.0.0.1")
    feed_b = _feed("CVE-B", machine="m-b", name="srv-b.corp.local", ip="10.0.0.2")
    await run_connector(db, "defender", _meta(feed_a), {})
    await run_connector(db, "defender:acme", _meta(feed_b), {})

    # Tenant A reimports its unchanged feed: tenant B's finding must survive.
    report = await run_connector(db, "defender", _meta(feed_a), {})
    assert report["closed"] == 0
    st = await _statuses(db)
    assert all(v == "new" for v in st.values()), st

    # Findings carry their instance key, whatever the add-on put in them.
    scanners = {s for (s,) in (await db.execute(select(Finding.scanner))).all()}
    assert scanners == {"defender", "defender:acme"}


@pytest.mark.asyncio
async def test_the_engine_stamp_overrides_the_addon_scanner(db):
    """An add-on hardcodes scanner="defender" in its findings; run as the
    instance "defender:acme" they must land — and reconcile — under the
    instance key, not the hardcoded one."""
    feed = _feed("CVE-1")
    assert all(c["scanner"] == "defender" for c in feed["findings"])
    await run_connector(db, "defender:acme", _meta(feed), {})
    f = (await db.execute(select(Finding))).scalar_one()
    assert f.scanner == "defender:acme"
    assert f.dedup_key.startswith("defender:acme|")


@pytest.mark.asyncio
async def test_reconciliation_leaves_a_manually_fixed_finding_alone(db):
    """A finding an analyst marked "fixed" is a human decision: when it
    vanishes from the feed the reconciliation must not overwrite it with the
    vaguer closed_upstream."""
    await run_connector(db, "defender", _meta(_feed("CVE-1")), {})
    f = (await db.execute(select(Finding))).scalar_one()
    f.status = "fixed"
    await db.commit()

    report = await run_connector(db, "defender", _meta(_feed()), {})
    assert report["closed"] == 0
    assert (await _statuses(db))[_key("m-1", "CVE-1")] == "fixed"
