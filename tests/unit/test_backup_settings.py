"""BUG-92 — a backup leaves out the settings Pilot pushes, and a restore too.

Pilot pushes the AI settings (``ai_*``) and the outbound proxy (``proxy.*``),
which the module stores. A backup carries the module's own settings only: a
restore on another deployment must not bring back its AI keys, nor a proxy,
which the start-up exports without validating it again. Locks, through the
export and restore routes against SQLite:
  - the export leaves out ``ai_*`` and ``proxy.*`` and keeps the rest;
  - a restore ignores the ``ai_*`` and ``proxy.*`` rows of a payload and
    keeps the stored ones.
Suite tree only: a standalone build ships without ``src/routes/internal.py``.
"""
from __future__ import annotations

import os
import sys

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON, select  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.database import get_db  # noqa: E402
from src.models import AppSettings, Base  # noqa: E402

_HAS_INTERNAL = os.path.exists(os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes", "internal.py"))
pytestmark = pytest.mark.skipif(not _HAS_INTERNAL, reason="suite-only route (standalone build)")

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()

_TOKEN = "svc-token-for-tests-0123456789abcdef"
_STORED = {"proxy.https_proxy": "http://proxy.medsecure.example:3128", "ai_provider": "custom",
           "digest.weekday": "monday"}


@pytest_asyncio.fixture
async def sessions():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as s:
        s.add_all([AppSettings(key=k, value=v) for k, v in _STORED.items()])
        await s.commit()
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def client(monkeypatch, sessions):
    import src.routes.internal as internal
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN)

    async def _db():
        async with sessions() as s:
            yield s

    app = FastAPI()
    app.include_router(internal.router)
    app.dependency_overrides[get_db] = _db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://surface",
                                 headers={"X-Service-Token": _TOKEN}) as c:
        yield c


async def _settings(sessions) -> dict:
    async with sessions() as s:
        return {r.key: r.value for r in (await s.execute(select(AppSettings))).scalars().all()}


@pytest.mark.asyncio
async def test_the_backup_leaves_out_what_pilot_pushes(client):
    resp = await client.get("/api/internal/export/surface")
    assert resp.status_code == 200
    assert resp.json()["data"]["app_settings"] == [{"key": "digest.weekday", "value": "monday"}]


@pytest.mark.asyncio
async def test_a_restore_keeps_what_pilot_pushed(client, sessions):
    data = (await client.get("/api/internal/export/surface")).json()["data"]
    data["app_settings"] += [{"key": "proxy.https_proxy", "value": "http://10.0.0.8:3128"},
                             {"key": "ai_provider", "value": "openai"}]
    resp = await client.put("/api/internal/restore/surface", json={"data": data})
    assert resp.status_code == 200
    assert await _settings(sessions) == _STORED
