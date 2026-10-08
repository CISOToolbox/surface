"""BUG-90 — the Pilot relay of measures and the pushed custom LLM, per build.

The suite-only ``src/routes/internal.py`` carries the Pilot payload builder
and the LLM config Pilot pushes; a standalone build ships without it. Locks,
through the real handlers against SQLite:
  - suite: creating a measure, updating it and triaging its finding to
    ``to_fix`` each notify Pilot with the measure; the pushed LLM config is
    the one ``_get_custom_llm`` returns;
  - standalone (the file absent): the same three calls succeed without
    notifying, and ``_get_custom_llm`` falls back to the module's settings.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest
import pytest_asyncio

os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

import src.pilot_notify as pilot_notify  # noqa: E402
import src.routes.measures as measures  # noqa: E402
from src.ai_proxy_common import _get_custom_llm  # noqa: E402
from src.models import AppSettings, Base, Finding  # noqa: E402
from src.routes.findings import triage_finding  # noqa: E402
from src.schemas import FindingTriage, MeasureCreate, MeasureUpdate  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

_HAS_INTERNAL = os.path.exists(os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes", "internal.py"))
_suite_tree = pytest.mark.skipif(not _HAS_INTERNAL, reason="suite-only route, absent from a standalone build")


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.fixture
def relayed(monkeypatch):
    """Payloads handed to Pilot, whichever module sends them."""
    sent: list[dict] = []

    def _notify(payload):
        sent.append(payload)

        async def _noop():
            return None
        return _noop()

    monkeypatch.setattr(measures, "notify_pilot_measure", _notify, raising=False)
    monkeypatch.setattr(pilot_notify, "notify_pilot_measure", _notify)
    return sent


@pytest.fixture
def standalone(monkeypatch):
    """The suite-only route is absent, as in a standalone build."""
    monkeypatch.setitem(sys.modules, "src.routes.internal", None)


def _req() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/measures", "headers": [],
                    "query_string": b"", "client": ("127.0.0.1", 1)})


async def _finding(db):
    f = Finding(id=uuid.uuid4(), scanner="nmap", type="open_port", severity="high",
                title="22/tcp open", target="10.0.0.1", status="new", evidence={})
    db.add(f)
    await db.commit()
    db.expunge(f)            # a request starts from a fresh session: let triage load it
    return f


async def _three_calls(db):
    """Create a measure, update it, triage a finding to to_fix."""
    m = await measures.create_measure(MeasureCreate(title="Close SSH"), _req(), user=None, db=db)
    await measures.update_measure(m["id"], MeasureUpdate(statut="en_cours"), _req(), user=None, db=db)
    f = await _finding(db)
    out = await triage_finding(f.id, FindingTriage(status="to_fix", measure_title="Restrict SSH"),
                               _req(), user=None, db=db)
    return m, out


@_suite_tree
@pytest.mark.asyncio
async def test_the_suite_relays_each_measure_change_to_pilot(db, relayed):
    m, out = await _three_calls(db)
    assert len(relayed) == 3, "create, update and to_fix triage each notify Pilot"
    assert [p["source_id"] for p in relayed] == [m["id"], m["id"], out["measure_id"]]
    assert relayed[0]["status"] != relayed[1]["status"], "the update carries the new status"
    assert relayed[2]["entity_id"] == str(out["id"]) and relayed[2]["title"] == "Restrict SSH"


@pytest.mark.asyncio
async def test_a_standalone_build_changes_measures_without_pilot(db, relayed, standalone):
    m, out = await _three_calls(db)
    assert m["statut"] == "a_faire" and out["status"] == "to_fix"
    assert relayed == []


@_suite_tree
@pytest.mark.asyncio
async def test_the_suite_uses_the_llm_pilot_pushed(db, monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setattr(internal, "_custom_llm", {"endpoint": "https://llm.medsecure.example", "model": "m1"})
    assert (await _get_custom_llm(db))["endpoint"] == "https://llm.medsecure.example"


@pytest.mark.asyncio
async def test_a_standalone_build_reads_its_own_llm_settings(db, standalone):
    assert not (await _get_custom_llm(db)).get("endpoint")
    db.add_all([AppSettings(key="ai_custom_endpoint", value="https://llm.medsecure.example"),
                AppSettings(key="ai_custom_model", value="m2")])
    await db.commit()
    cl = await _get_custom_llm(db)
    assert (cl["endpoint"], cl["model"]) == ("https://llm.medsecure.example", "m2")
