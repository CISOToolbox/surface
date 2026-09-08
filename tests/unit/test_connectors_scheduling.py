"""FEAT-37 — the decision to run, or not run, a connector.

The reconciliation engine is tested elsewhere (test_connectors_run.py). This
file only tests the gatekeeper: **who is allowed to run, and when**.

Three ways to break everything, one per test:

  - running an unconfigured connector → a burst of authentication failures
    against the upstream API, up to the service account getting blocked;
  - ignoring the interval → one import every 60 s instead of every 6 h;
  - not timestamping a failure → same effect as above, worse, since failure
    is precisely when the hammering happens.

Plus acceptance criterion 1 of the spec: with no connector configured,
Surface behaves exactly as before — and the per-connector lock, which is
what keeps a manual run and a scheduler pass from importing the same tenant
twice (the first delivery's host duplication).
"""
from __future__ import annotations

import contextlib
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

# src/database.py builds its engine AT IMPORT with pool_size/max_overflow,
# which the SQLite dialect rejects — importing src.scheduler under a sqlite
# URL therefore raises at collection. Force a postgres URL: the engine is
# only built, never connected, since `async_session` is replaced by the test
# session. Other test files are unaffected: they create their sqlite engine
# explicitly, without reading DATABASE_URL.
os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "clef-de-test-suffisamment-longue-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import src.scheduler as sched  # noqa: E402
from src.connectors_config import key_for, save_config  # noqa: E402
from src.models import Base  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

NOM = "faux"
SCHEMA = [{"key": "jeton", "label": "Jeton", "type": "password",
           "secret": True, "required": True}]


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


@pytest.fixture
def registre(monkeypatch, db):
    """Registers a connector that counts its runs, and plugs the scheduler
    into the test session."""
    appels: list[dict] = []

    async def _callable(config):
        appels.append(dict(config))
        return {"ok": True, "hosts": [], "findings": [], "error": None}

    meta = {"label": "Faux", "interval_hours": 6, "callable": _callable,
            "config_schema": SCHEMA}
    monkeypatch.setattr(sched, "CONNECTOR_REGISTRY", {NOM: meta}, raising=False)

    @contextlib.asynccontextmanager
    async def _session():
        yield db

    monkeypatch.setattr(sched, "async_session", _session)
    return appels, meta


@pytest.mark.asyncio
async def test_nothing_runs_without_a_registry(monkeypatch):
    """Criterion 1: no connector installed = unchanged behaviour.

    Not even a session must be opened — without this short-circuit, an
    installation with no connector would pay one query per tick for nothing.
    """
    monkeypatch.setattr(sched, "CONNECTOR_REGISTRY", {}, raising=False)

    def _boom():
        raise AssertionError("a session was opened with no connector registered")

    monkeypatch.setattr(sched, "async_session", _boom)
    await sched._run_due_connectors()


@pytest.mark.asyncio
async def test_a_disabled_connector_does_not_run(registre, db):
    appels, _ = registre
    await save_config(db, NOM, SCHEMA, {"jeton": "x"}, enabled=False)
    await db.commit()
    await sched._run_due_connectors()
    assert appels == []


@pytest.mark.asyncio
async def test_an_enabled_but_unconfigured_connector_does_not_run(registre, db):
    """Otherwise: a burst of authentication failures against the upstream API."""
    appels, _ = registre
    await save_config(db, NOM, SCHEMA, {}, enabled=True)
    await db.commit()
    await sched._run_due_connectors()
    assert appels == [], "a connector without credentials was launched"


@pytest.mark.asyncio
async def test_an_enabled_and_configured_connector_runs_once(registre, db):
    appels, _ = registre
    await save_config(db, NOM, SCHEMA, {"jeton": "x"}, enabled=True)
    await db.commit()

    await sched._run_due_connectors()
    assert len(appels) == 1
    assert appels[0]["jeton"] == "x", "the configuration did not reach the connector"

    # Immediate second pass: the 6 h interval has not elapsed.
    await sched._run_due_connectors()
    assert len(appels) == 1, "the interval is not honoured — import on every tick"


@pytest.mark.asyncio
async def test_it_runs_again_once_the_interval_has_elapsed(registre, db):
    appels, _ = registre
    await save_config(db, NOM, SCHEMA, {"jeton": "x"}, enabled=True)
    await db.commit()
    await sched._run_due_connectors()

    vieux = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
    await save_config(db, NOM, [{"key": "last_run_at"}], {"last_run_at": vieux}, None)
    await db.commit()

    await sched._run_due_connectors()
    assert len(appels) == 2


@pytest.mark.asyncio
async def test_a_failing_connector_is_timestamped_and_not_retried(registre, db,
                                                                  monkeypatch):
    """The worst case: it fails, so it retries — in a loop, every 60 s."""
    appels, meta = registre

    async def _ko(config):
        appels.append(dict(config))
        return {"ok": False, "error": "HTTP 401", "hosts": [], "findings": []}

    meta["callable"] = _ko
    await save_config(db, NOM, SCHEMA, {"jeton": "x"}, enabled=True)
    await db.commit()

    await sched._run_due_connectors()
    await sched._run_due_connectors()
    assert len(appels) == 1, "a failing connector is relaunched on every pass"

    from src.connectors_config import _raw
    assert (await _raw(db, NOM)).get("last_run_at"), "the failure was not timestamped"


@pytest.mark.asyncio
async def test_a_crashing_connector_does_not_stop_the_pass(registre, db, monkeypatch):
    """A raising connector must not stop the next ones from running."""
    appels, meta = registre

    async def _boom(config):
        raise RuntimeError("jeton expiré")

    autre_appels: list[dict] = []

    async def _ok(config):
        autre_appels.append(dict(config))
        return {"ok": True, "hosts": [], "findings": [], "error": None}

    meta["callable"] = _boom
    autre = {"label": "Autre", "interval_hours": 6, "callable": _ok,
             "config_schema": SCHEMA}
    monkeypatch.setattr(sched, "CONNECTOR_REGISTRY", {NOM: meta, "zautre": autre},
                        raising=False)
    for n in (NOM, "zautre"):
        await save_config(db, n, SCHEMA, {"jeton": "x"}, enabled=True)
    await db.commit()

    await sched._run_due_connectors()
    assert autre_appels, "a broken connector interrupted the pass"


@pytest.mark.asyncio
async def test_a_secret_field_is_encrypted_whatever_its_name(registre, db):
    """The field is named `jeton`: its key is `connector_faux_jeton`, which
    settings_crypto's historical pattern does NOT recognise as secret.

    This case is what revealed the defect — encryption followed the key
    name, so an add-on naming its secret `token` or `jeton` wrote it in
    cleartext, with no error and no trace. The schema decides now.
    """
    from sqlalchemy import select as _select

    from src.models import AppSettings
    from src.settings_crypto import is_secret_key

    assert not is_secret_key(key_for(NOM, "jeton")), (
        "the naming pattern now recognises this field: the test no longer "
        "covers the case it targeted, pick another"
    )
    await save_config(db, NOM, SCHEMA, {"jeton": "valeur-tres-identifiable"}, True)
    await db.commit()
    row = (await db.execute(
        _select(AppSettings).where(AppSettings.key == key_for(NOM, "jeton"))
    )).scalar_one()
    assert "valeur-tres-identifiable" not in row.value, "secret stored in cleartext"
    assert row.value.startswith("enc:v1:")


@pytest.mark.asyncio
async def test_a_locked_connector_is_skipped_not_queued(registre, db):
    """The per-connector lock is shared with the manual-run route: a pass
    that finds it held must skip, not wait and import a second time right
    behind the first (criterion 2 — duplicated hosts)."""
    from src.connectors_run import lock_for

    appels, _ = registre
    await save_config(db, NOM, SCHEMA, {"jeton": "x"}, enabled=True)
    await db.commit()

    async with lock_for(NOM):
        await sched._run_due_connectors()
    assert appels == [], "a locked connector was run anyway"

    await sched._run_due_connectors()
    assert len(appels) == 1
