"""FEAT-69 — findings matched to the monitored assets by the server.

The Hosts cards, a host's page and the dashboard used to be computed by the
browser over the latest 10 000 findings only. They are now computed over
every finding, from match keys stored on each row (src/finding_match.py) and
asset rules applied at query time (src/finding_assets.py). These tests pin
the rules the browser applied, kind by kind, and that every write path keeps
the keys current.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
# A URL the app engine accepts; it never connects (the tests bring their own).
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test")

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src import finding_assets  # noqa: E402
from src.finding_match import cidr_bounds, ip4_int, match_keys, share_hostname, target_host_part  # noqa: E402
from src.models import Base, Finding, MonitoredAsset  # noqa: E402

# SQLite knows neither JSONB nor PostgreSQL server defaults (same adaptation
# as test_connectors_run.py).
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
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


def _finding(target, evidence=None, severity="high", status="new", type_="open_port", created=None,
             scanner="nmap", **kw):
    return Finding(id=uuid.uuid4(), scanner=scanner, type=type_, severity=severity, status=status,
                   title="t", target=target, evidence=evidence or {},
                   created_at=created or datetime.now(timezone.utc), **kw)


def _asset(kind, value, resolved_ip=None):
    return MonitoredAsset(id=uuid.uuid4(), kind=kind, value=value, resolved_ip=resolved_ip)


async def _targets(db, *assets):
    rows = (await db.execute(select(Finding.target).where(finding_assets.assets_condition(assets)))).scalars()
    return sorted(rows)


# ── Keys ──

@pytest.mark.parametrize("target,host", [
    ("93.184.216.34:443", "93.184.216.34"),
    ("Host.TLD:8080", "host.tld"),
    ("host.tld", "host.tld"),
    ("  host.tld  ", "host.tld"),
    ("\\\\Srv\\share\\dir", "srv"),
    ("//srv/share", "srv"),
    ("smb://srv/share", "srv"),
    ("https://host.tld/path", "https://host.tld/path"),   # as the browser did
    ("", ""),
])
def test_target_host_part(target, host):
    assert target_host_part(target) == host


def test_share_hostname_of_any_share_spelling():
    for v in ("\\\\srv\\a", "//srv/a", "smb://SRV/a", "srv/a", "srv"):
        assert share_hostname(v) == "srv"


@pytest.mark.parametrize("value,n", [
    ("10.0.0.1", 10 * 2**24 + 1), ("255.255.255.255", 2**32 - 1),
    ("10.0.0.01", None), ("10.0.0", None), ("10.0.0.256", None), (" 10.0.0.1", None), ("host", None),
    ("١٠.0.0.1", None),
])
def test_ip4_int_is_strict(value, n):
    assert ip4_int(value) == n


def test_cidr_bounds():
    assert cidr_bounds("10.1.2.0/24") == (ip4_int("10.1.2.0"), ip4_int("10.1.2.255"))
    assert cidr_bounds("10.1.2.77/24") == (ip4_int("10.1.2.0"), ip4_int("10.1.2.255"))
    assert cidr_bounds("0.0.0.0/0") == (0, 2**32 - 1)
    assert cidr_bounds("10.1.2.3") is None and cidr_bounds("10.1.2.0/33") is None and cidr_bounds("x/8") is None


def test_evidence_keys_take_hostname_then_host():
    k = match_keys("10.0.0.5:22", {"hostname": "", "host": "Web.Example", "address": "10.0.0.5"})
    assert (k["match_evhost"], k["match_evaddr"], k["match_evaddr_ip4"]) == ("web.example", "10.0.0.5", ip4_int("10.0.0.5"))
    assert match_keys(None, None)["match_host"] == ""


# ── Write paths keep the keys current ──

@pytest.mark.asyncio
async def test_keys_are_set_on_insert_and_follow_an_update(db):
    f = _finding("10.0.0.5:22", {"hostname": "a.example"})
    db.add(f)
    await db.commit()
    assert (f.match_host, f.match_evhost, f.match_host_ip4) == ("10.0.0.5", "a.example", ip4_int("10.0.0.5"))
    f.evidence = {"hostname": "b.example"}     # a rescan refreshes the evidence
    await db.commit()
    assert f.match_evhost == "b.example"


@pytest.mark.asyncio
async def test_a_deduplicated_rescan_refreshes_the_keys(db):
    from src.findings_dedup import insert_or_dedupe
    await insert_or_dedupe(db, {"scanner": "tls", "type": "tls_weak", "target": "a.example:443",
                                "title": "t", "severity": "high", "evidence": {}})
    await db.commit()
    await insert_or_dedupe(db, {"scanner": "tls", "type": "tls_weak", "target": "a.example:443",
                                "title": "t", "severity": "high", "evidence": {"address": "10.9.9.9"}})
    await db.commit()
    f = (await db.execute(select(Finding))).scalar_one()
    assert (f.match_host, f.match_evaddr) == ("a.example", "10.9.9.9")


# ── Rules, kind by kind ──

@pytest.mark.asyncio
async def test_a_host_owns_its_name_and_its_resolved_ip(db):
    db.add_all([
        _finding("h.example:443"),                                   # target host part
        _finding("10.20.0.5"),                                       # resolved IP as target
        _finding("10.30.0.1", {"hostname": "H.example"}),            # evidence hostname
        _finding("summary", {"address": "10.20.0.5"}),               # evidence address = resolved IP
        _finding("other.example"),
        _finding("summary2", {"address": "h.example"}),              # an address is not a name
        _finding("x.h.example"),                                     # a host has no subdomains
    ])
    await db.commit()
    host = _asset("host", "H.example", resolved_ip="10.20.0.5")
    assert await _targets(db, host) == ["10.20.0.5", "10.30.0.1", "h.example:443", "summary"]


@pytest.mark.asyncio
async def test_a_host_without_resolved_ip_owns_its_name_only(db):
    db.add_all([_finding("10.20.0.5"), _finding("h.example")])
    await db.commit()
    assert await _targets(db, _asset("host", "h.example")) == ["h.example"]


@pytest.mark.asyncio
async def test_a_domain_owns_itself_and_its_subdomains(db):
    db.add_all([
        _finding("example.com"), _finding("www.example.com:443"),
        _finding("10.0.0.1", {"hostname": "mail.example.com"}),
        _finding("badexample.com"), _finding(".example.com"), _finding("example.com.evil"),
    ])
    await db.commit()
    assert await _targets(db, _asset("domain", "Example.com")) == ["10.0.0.1", "example.com", "www.example.com:443"]


@pytest.mark.asyncio
async def test_a_domain_pattern_character_is_literal(db):
    db.add_all([_finding("a.ex_mple.com"), _finding("a.exampleXcom"), _finding("a.exaample.com")])
    await db.commit()
    assert await _targets(db, _asset("domain", "ex_mple.com")) == ["a.ex_mple.com"]


@pytest.mark.asyncio
async def test_a_range_owns_its_addresses_and_itself(db):
    db.add_all([
        _finding("10.1.2.0/24"), _finding("10.1.2.9:22"), _finding("summary", {"address": "10.1.2.200"}),
        _finding("10.1.3.1"), _finding("x", {"address": "10.1.3.1"}),
    ])
    await db.commit()
    assert await _targets(db, _asset("ip_range", "10.1.2.0/24")) == ["10.1.2.0/24", "10.1.2.9:22", "summary"]


@pytest.mark.asyncio
async def test_a_share_owns_every_share_of_its_server(db):
    db.add_all([_finding("\\\\srv\\a"), _finding("//srv/b"), _finding("smb://srv2/a"), _finding("srv:445")])
    await db.commit()
    assert await _targets(db, _asset("file_share", "\\\\SRV\\x")) == ["//srv/b", "\\\\srv\\a"]


@pytest.mark.asyncio
async def test_an_asset_without_value_owns_nothing(db):
    db.add(_finding("", {}))
    await db.commit()
    assert await _targets(db, _asset("host", "")) == []


# ── Figures ──

@pytest.mark.asyncio
async def test_card_counts(db):
    db.add_all([
        _finding("h.example", severity="critical"),
        _finding("h.example", severity="info"),
        _finding("h.example", status="false_positive"),
        _finding("h.example", status="fixed"),
        _finding("h.example", status="to_fix", severity="medium"),
    ])
    await db.commit()
    c = await finding_assets.counts_for(db, [_asset("host", "h.example")])
    assert c == {"total": 5, "active": 2, "open": 2, "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 1,
                 "false_positive": 1, "fixed": 1, "closed_upstream": 0, "derogated": 0}


@pytest.mark.asyncio
async def test_a_same_ip_group_counts_a_shared_finding_once(db):
    a, b = _asset("host", "a.example", "10.0.0.5"), _asset("host", "b.example", "10.0.0.5")
    db.add_all([a, b, _finding("10.0.0.5"), _finding("a.example"), _finding("b.example")])
    await db.commit()
    out = await finding_assets.asset_counts(db)
    assert out["assets"][str(a.id)]["total"] == 2 and out["assets"][str(b.id)]["total"] == 2
    assert out["ip_groups"] == {"10.0.0.5": await finding_assets.counts_for(db, [a, b])}
    assert out["ip_groups"]["10.0.0.5"]["total"] == 3


@pytest.mark.asyncio
async def test_more_than_ten_thousand_findings_are_all_counted(db):
    old = datetime.now(timezone.utc) - timedelta(days=400)
    db.add_all([_finding("noise.example") for _ in range(10_000)])
    db.add(_finding("old.example", created=old))
    await db.commit()
    assert (await finding_assets.counts_for(db, [_asset("host", "old.example")]))["total"] == 1


@pytest.mark.asyncio
async def test_top_hosts_rank_by_worst_severity_then_count(db):
    db.add_all([
        _finding("a.example", severity="high"), _finding("a.example", severity="high"),
        _finding("b.example:443", severity="critical"),
        _finding("m|cve|p", {"hostname": "c.example"}, severity="low"),     # connector: host in evidence
        _finding("d.example", severity="info"),                             # info only: not exposed
        _finding("e.example", status="fixed", severity="critical"),          # closed
        _finding("m|rec|p", severity="high", type_="defender_recommendation"),
        _finding("m|x|p", severity="high"),                                  # opaque target, no host
    ])
    await db.commit()
    rows = await finding_assets.top_hosts(db, 10)
    assert [(r["host"], r["max_sev"], r["active"]) for r in rows] == [
        ("b.example", 0, 1), ("a.example", 1, 2), ("c.example", 3, 1)]


@pytest.mark.asyncio
async def test_dashboard_stats(db):
    now = datetime.now(timezone.utc)
    db.add_all([
        _finding("a", severity="critical", created=now - timedelta(days=40)),
        _finding("a", severity="high", created=now - timedelta(hours=2)),
        _finding("a", severity="info", created=now - timedelta(hours=1)),
        _finding("a", severity="low", status="fixed", created=now - timedelta(days=3),
                 triaged_at=now - timedelta(days=1)),
    ])
    await db.commit()
    s = await finding_assets.dashboard_stats(db, "Europe/Paris")
    assert s["by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1}
    assert s["by_status"]["new"] == 3 and s["by_status"]["fixed"] == 1
    assert s["recent_24h"] == 1
    assert s["top_types"] == [{"type": "open_port", "count": 2}]
    assert s["top_scanners"] == [{"scanner": "nmap", "count": 4}]
    tl = s["timeline"]
    assert len(tl) == 30 and tl[-1]["key"] == now.astimezone(finding_assets._zone("Europe/Paris")).date().isoformat()
    assert tl[0]["critical"] == 1 and tl[-1]["critical"] == 1           # created before the window
    assert tl[-1]["high"] == 1 and tl[-1]["info"] == 1 and tl[-1]["low"] == 1
    assert tl[-5]["low"] == 0                                           # not yet created
    assert sum(d["triaged"] for d in tl) == 1


@pytest.mark.asyncio
async def test_a_blank_type_or_scanner_ranks_with_its_default(db):
    db.add_all([_finding("a", type_=""), _finding("a", type_="other"),
                _finding("a", scanner=""), _finding("a", scanner="manual")])
    await db.commit()
    s = await finding_assets.dashboard_stats(db, None)
    assert {"type": "other", "count": 2} in s["top_types"]
    assert [t["type"] for t in s["top_types"]].count("other") == 1
    assert {"scanner": "manual", "count": 2} in s["top_scanners"]
    assert [t["scanner"] for t in s["top_scanners"]].count("manual") == 1


@pytest.mark.asyncio
async def test_an_unknown_zone_falls_back_to_utc(db):
    s = await finding_assets.dashboard_stats(db, "Not/AZone")
    assert s["timeline"][-1]["key"] == datetime.now(timezone.utc).date().isoformat()


# ── A host page's list ──

@pytest.mark.asyncio
async def test_a_host_page_lists_its_findings_most_severe_first_by_page(db):
    from src.routes.findings import list_findings
    host = _asset("host", "h.example")
    now = datetime.now(timezone.utc)
    db.add_all([host,
                _finding("h.example", severity="low", created=now),
                _finding("h.example:443", severity="critical", created=now - timedelta(days=2)),
                _finding("h.example:22", severity="critical", created=now - timedelta(days=1)),
                _finding("h.example:80", severity="high", status="false_positive"),
                _finding("other.example", severity="critical")])
    await db.commit()

    async def page(offset, status_not=()):
        rows = await list_findings(status=None, severity=None, scanner=None, status_not=list(status_not),
                                   asset_id=[host.id], limit=2, offset=offset, user=None, db=db)
        return [(r["target"], r["severity"]) for r in rows]

    assert await page(0) == [("h.example:22", "critical"), ("h.example:443", "critical")]
    assert await page(2) == [("h.example:80", "high"), ("h.example", "low")]
    assert await page(2, ["false_positive"]) == [("h.example", "low")]


@pytest.mark.asyncio
async def test_closed_upstream_and_derogated_are_not_to_triage(db):
    # BUG-147 — "open" is new + to_fix everywhere else (Findings filter,
    # dashboard, posture): a finding the source no longer reports, or one
    # under an approved derogation, has nothing to triage.
    db.add_all([
        _finding("h.example", severity="critical", status="closed_upstream"),
        _finding("h.example", severity="critical", status="derogated"),
        _finding("h.example", severity="high"),
    ])
    await db.commit()
    c = await finding_assets.counts_for(db, [_asset("host", "h.example")])
    assert (c["critical"], c["high"], c["open"], c["active"], c["total"]) == (0, 1, 1, 1, 3)
    assert (c["closed_upstream"], c["derogated"]) == (1, 1)
