"""FEAT-70 — the Findings table is filtered, sorted and paged by the server.

The browser used to load the latest 10 000 findings and filter them itself.
It now asks for one page of the filter (src/finding_filters.py), and a bulk
action can target every finding of the filter, refused when the filter no
longer matches the count the user confirmed.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
# A URL the app engine accepts; it never connects (the tests bring their own).
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test")

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

from src.auth import get_current_user  # noqa: E402
from src.database import get_db  # noqa: E402
from src.finding_filters import FindingFilter  # noqa: E402
from src.models import Base, Derogation, Finding  # noqa: E402
from src.routes import findings as routes  # noqa: E402

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


def _req() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/findings/bulk-triage", "headers": [],
                    "query_string": b"", "client": ("127.0.0.1", 1)})


_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _finding(title, severity="high", status="new", scanner="nmap", type_="open_port", target="h.example",
             description="", age_days=0):
    return Finding(id=uuid.uuid4(), scanner=scanner, type=type_, severity=severity, status=status,
                   title=title, description=description, target=target, evidence={},
                   created_at=_T0 - timedelta(days=age_days))


async def _list(db, *, limit=100, offset=0, sort="created_at", direction="desc", with_total=False, **filters):
    f = FindingFilter(**filters)
    return await routes.list_findings(
        status=f.status, status_not=f.status_not, severity=f.severity, severity_not=f.severity_not,
        scanner=f.scanner, scanner_not=f.scanner_not, q=f.q, sort=sort, direction=direction,
        asset_id=[], with_total=with_total, limit=limit, offset=offset, user=None, db=db)


async def _titles(db, **kw):
    return sorted(r["title"] for r in await _list(db, **kw))


@pytest_asyncio.fixture
async def mixed(db):
    db.add_all([
        _finding("a", severity="critical", status="new", scanner="nmap"),
        _finding("b", severity="high", status="to_fix", scanner="tls"),
        _finding("c", severity="info", status="new", scanner="nmap"),
        _finding("d", severity="low", status="false_positive", scanner="nuclei"),
        _finding("e", severity="medium", status="derogated", scanner="tls"),
        _finding("f", severity="high", status="fixed", scanner="nuclei"),
    ])
    await db.commit()
    return db


# ── Filters ──

@pytest.mark.asyncio
async def test_no_filter_lists_everything(mixed):
    assert await _titles(mixed) == ["a", "b", "c", "d", "e", "f"]


@pytest.mark.asyncio
async def test_included_values_of_a_row_combine_with_or(mixed):
    assert await _titles(mixed, severity=["critical", "high"]) == ["a", "b", "f"]


@pytest.mark.asyncio
async def test_excluded_values_are_left_out(mixed):
    assert await _titles(mixed, severity_not=["info"]) == ["a", "b", "d", "e", "f"]
    assert await _titles(mixed, status_not=["false_positive", "derogated"]) == ["a", "b", "c", "f"]


@pytest.mark.asyncio
async def test_rows_combine_with_and(mixed):
    assert await _titles(mixed, severity=["critical", "high"], scanner_not=["tls"]) == ["a", "f"]
    assert await _titles(mixed, status=["new"], scanner=["nmap"], severity_not=["info"]) == ["a"]


@pytest.mark.asyncio
async def test_open_is_new_and_to_fix(mixed):
    assert await _titles(mixed, status=["open"]) == ["a", "b", "c"]
    assert await _titles(mixed, status=["open", "fixed"]) == ["a", "b", "c", "f"]


@pytest.mark.asyncio
async def test_a_single_legacy_value_still_filters(mixed):
    # `?status=new` from an older caller is a one-value list.
    assert await _titles(mixed, status=["new"]) == ["a", "c"]
    assert await _titles(mixed, status=[""]) == ["a", "b", "c", "d", "e", "f"]


@pytest.mark.asyncio
async def test_unknown_included_values_match_nothing(mixed):
    assert await _titles(mixed, severity=["urgent"]) == []
    assert await _titles(mixed, status_not=["bogus"]) == ["a", "b", "c", "d", "e", "f"]


# ── Search ──

@pytest.mark.asyncio
async def test_search_reads_every_stored_text_case_insensitively(db):
    db.add_all([
        _finding("Weak cipher suite", target="x.example"),
        _finding("t2", description="Uses TLS 1.0", target="y.example"),
        _finding("t3", target="mail.medsecure.example"),
        _finding("t4", scanner="nuclei", target="z.example"),
        _finding("t5", type_="takeover", target="w.example"),
    ])
    await db.commit()
    assert await _titles(db, q="CIPHER") == ["Weak cipher suite"]
    assert await _titles(db, q="tls 1.0") == ["t2"]
    assert await _titles(db, q="medsecure") == ["t3"]
    assert await _titles(db, q="nucl") == ["t4"]
    assert await _titles(db, q="takeover") == ["t5"]
    assert await _titles(db, q="  ") == ["Weak cipher suite", "t2", "t3", "t4", "t5"]


@pytest.mark.asyncio
async def test_search_wildcards_are_literal(db):
    db.add_all([_finding("100% exposed"), _finding("1000 exposed"), _finding("a_b"), _finding("axb")])
    await db.commit()
    assert await _titles(db, q="100%") == ["100% exposed"]
    assert await _titles(db, q="a_b") == ["a_b"]


# ── Sort, pages and total ──

@pytest.mark.asyncio
async def test_sort_holds_over_the_whole_filter(db):
    db.add_all([
        _finding("old-critical", severity="critical", age_days=30),
        _finding("new-low", severity="low", age_days=0),
        _finding("mid-critical", severity="critical", age_days=10),
        _finding("mid-info", severity="info", age_days=5),
    ])
    await db.commit()

    async def order(**kw):
        return [r["title"] for r in await _list(db, **kw)]

    assert await order() == ["new-low", "mid-info", "mid-critical", "old-critical"]
    assert await order(direction="asc") == ["old-critical", "mid-critical", "mid-info", "new-low"]
    assert await order(sort="severity") == ["mid-critical", "old-critical", "new-low", "mid-info"]
    assert await order(sort="severity", direction="asc") == ["mid-info", "new-low", "mid-critical", "old-critical"]
    # Page 2 of the severity order continues page 1, it is not page 2 sorted alone.
    assert await order(sort="severity", limit=2, offset=2) == ["new-low", "mid-info"]


@pytest.mark.asyncio
async def test_with_total_gives_the_page_and_the_filter_total(db):
    db.add_all([_finding(f"f{i:03}", severity="info" if i % 3 == 0 else "high", age_days=i) for i in range(250)])
    await db.commit()
    page = await _list(db, with_total=True, severity_not=["info"], limit=100, offset=100)
    assert page["total"] == 166
    assert len(page["items"]) == 66
    assert page["items"][0]["title"] == "f151"
    # Without the flag: the bare list, as older callers read it.
    assert isinstance(await _list(db, limit=1), list)


@pytest.mark.asyncio
async def test_the_scanner_pills_list_every_scanner(mixed):
    assert await routes.list_finding_scanners(user=None, db=mixed) == ["nmap", "nuclei", "tls"]


# ── Bulk actions on the whole filter ──

async def _statuses(db):
    db.expunge_all()
    return {f.title: f.status for f in (await db.execute(select(Finding))).scalars().all()}


@pytest.mark.asyncio
async def test_bulk_triage_on_the_filter_changes_every_finding_of_it(mixed, monkeypatch):
    monkeypatch.setattr(routes, "_CHUNK", 2)        # several IN lists
    flt = FindingFilter(status=["open"], severity_not=["info"])
    r = await routes.bulk_triage(routes.BulkTriageRequest(filter=flt, expected=2, status="fixed"),
                                 _req(), user=None, db=mixed)
    assert r["updated"] == 2 and r["items"] == []      # a filter names no finding
    st = await _statuses(mixed)
    assert st["a"] == "fixed" and st["b"] == "fixed" and st["c"] == "new" and st["e"] == "derogated"


@pytest.mark.asyncio
async def test_bulk_triage_refuses_a_filter_whose_count_changed(mixed):
    flt = FindingFilter(status=["open"])
    with pytest.raises(HTTPException) as e:
        await routes.bulk_triage(routes.BulkTriageRequest(filter=flt, expected=2, status="fixed"),
                                 _req(), user=None, db=mixed)
    assert e.value.status_code == 409
    assert set((await _statuses(mixed)).values()) >= {"new", "to_fix"}


@pytest.mark.asyncio
async def test_a_bulk_target_is_ids_or_a_filter_with_its_count(mixed):
    flt = FindingFilter(status=["open"])
    for body in (routes.BulkTriageRequest(status="fixed"),
                 routes.BulkTriageRequest(filter=flt, status="fixed"),
                 routes.BulkTriageRequest(filter=flt, expected=3, ids=[uuid.uuid4()], status="fixed")):
        with pytest.raises(HTTPException) as e:
            await routes.bulk_triage(body, _req(), user=None, db=mixed)
        assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_a_measure_covers_at_most_its_limit_of_findings(mixed, monkeypatch):
    monkeypatch.setattr(routes, "_MEASURE_MAX_FINDINGS", 2)
    body = routes.BulkTriageRequest(filter=FindingFilter(status=["open"]), expected=3,
                                    status="to_fix", measure_title="Patch")
    with pytest.raises(HTTPException) as e:
        await routes.bulk_triage(body, _req(), user=None, db=mixed)
    assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_bulk_delete_on_the_filter(mixed, monkeypatch):
    monkeypatch.setattr(routes, "_CHUNK", 2)
    body = routes.BulkDeleteRequest(filter=FindingFilter(scanner=["nmap", "tls"]), expected=4)
    r = await routes.bulk_delete(body, _req(), user=None, db=mixed)
    assert r["deleted"] == 4
    assert sorted(await _statuses(mixed)) == ["d", "f"]


@pytest.mark.asyncio
async def test_bulk_triage_revokes_only_the_live_derogations_of_its_findings(mixed):
    e = (await mixed.execute(select(Finding).where(Finding.title == "e"))).scalar_one()
    other = uuid.uuid4()
    mixed.add_all([
        Derogation(id=uuid.uuid4(), reference="DER-1", subject_type="finding", subject_id=str(e.id),
                   title="t", justification="j", risk_owner="o", approver="a", valid_from=date(2026, 1, 1),
                   valid_until=date(2026, 12, 31), status="approved"),
        Derogation(id=uuid.uuid4(), reference="DER-2", subject_type="finding", subject_id=str(other),
                   title="t", justification="j", risk_owner="o", approver="a", valid_from=date(2026, 1, 1),
                   valid_until=date(2026, 12, 31), status="approved"),
    ])
    b = (await mixed.execute(select(Finding).where(Finding.title == "b"))).scalar_one()
    mixed.add(Derogation(id=uuid.uuid4(), reference="DER-3", subject_type="finding", subject_id=str(b.id),
                         title="t", justification="j", risk_owner="o", approver="a", valid_from=date(2026, 1, 1),
                         valid_until=date(2026, 12, 31), status="pending_approval"))
    await mixed.commit()
    body = routes.BulkTriageRequest(filter=FindingFilter(scanner=["tls"]), expected=2, status="fixed")
    await routes.bulk_triage(body, _req(), user=None, db=mixed)
    mixed.expunge_all()
    ders = {d.reference: d.status for d in (await mixed.execute(select(Derogation))).scalars().all()}
    assert ders == {"DER-1": "revoked", "DER-2": "approved", "DER-3": "rejected"}


@pytest.mark.asyncio
async def test_bulk_delete_revokes_the_live_derogations_of_its_findings(mixed):
    e = (await mixed.execute(select(Finding).where(Finding.title == "e"))).scalar_one()
    mixed.add(Derogation(id=uuid.uuid4(), reference="DER-1", subject_type="finding", subject_id=str(e.id),
                         title="t", justification="j", risk_owner="o", approver="a", valid_from=date(2026, 1, 1),
                         valid_until=date(2026, 12, 31), status="approved"))
    await mixed.commit()
    await routes.bulk_delete(routes.BulkDeleteRequest(filter=FindingFilter(status=["derogated"]), expected=1),
                             _req(), user=None, db=mixed)
    mixed.expunge_all()
    assert [d.status for d in (await mixed.execute(select(Derogation))).scalars().all()] == ["revoked"]


def test_a_filter_refuses_a_key_it_does_not_know():
    # "statuses" for "status" would otherwise mean "every finding".
    with pytest.raises(ValidationError):
        FindingFilter(statuses=["open"])


@pytest.mark.asyncio
async def test_a_bulk_action_on_a_filter_needs_the_role_before_anything_else(mixed):
    def account(role):
        return SimpleNamespace(id=uuid.uuid4(), name=role, email=f"{role}@medsecure.example", role="user",
                               _module_role=role)
    flt = FindingFilter(status=["open"])
    for call, role in (
        (lambda u: routes.bulk_triage(routes.BulkTriageRequest(filter=flt, expected=3, status="fixed"), _req(), user=u, db=mixed), "viewer"),
        (lambda u: routes.bulk_delete(routes.BulkDeleteRequest(filter=flt, expected=3), _req(), user=u, db=mixed), "viewer"),
        (lambda u: routes.bulk_delete(routes.BulkDeleteRequest(filter=flt, expected=3), _req(), user=u, db=mixed), "triager"),
    ):
        with pytest.raises(HTTPException) as e:
            await call(account(role))
        assert e.value.status_code == 403
    assert len(await _statuses(mixed)) == 6
    r = await routes.bulk_triage(routes.BulkTriageRequest(filter=flt, expected=3, status="fixed"),
                                 _req(), user=account("triager"), db=mixed)
    assert r["updated"] == 3


# ── Over HTTP: the query string and the body as the page sends them ──

@pytest_asyncio.fixture
async def http(mixed):
    async def _db():
        yield mixed
    app = FastAPI()
    app.include_router(routes.router)
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_current_user] = lambda: None
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://surface") as c:
        yield c


@pytest.mark.asyncio
async def test_the_query_string_repeats_its_keys_and_sorts_with_dir(http):
    r = await http.get("/api/findings?with_total=true&limit=2&offset=0&sort=severity&dir=asc"
                       "&severity=critical&severity=high&severity=info&status_not=fixed&status_not=to_fix")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2 and [f["title"] for f in body["items"]] == ["c", "a"]   # least severe first
    r = await http.get("/api/findings?sort=severity&dir=desc&status=open")
    assert [f["title"] for f in r.json()] == ["a", "b", "c"]
    assert (await http.get("/api/findings?sort=title")).status_code == 422
    assert (await http.get("/api/findings?dir=up")).status_code == 422


@pytest.mark.asyncio
async def test_a_bulk_body_with_a_misspelt_filter_key_is_refused(http, mixed):
    before = await _statuses(mixed)
    r = await http.post("/api/findings/bulk-triage",
                        json={"filter": {"statuses": ["open"]}, "expected": 6, "status": "fixed"})
    assert r.status_code == 422
    r = await http.post("/api/findings/bulk-delete", json={"filter": {"statuses": ["open"]}, "expected": 6})
    assert r.status_code == 422
    assert await _statuses(mixed) == before
