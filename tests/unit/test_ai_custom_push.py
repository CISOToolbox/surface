"""BUG-92 — the custom LLM config Pilot pushes reaches Surface.

Pilot pushes the custom LLM (endpoint, model, key, label) to every module at
``PUT /api/internal/ai-custom``; ``_get_custom_llm`` reads it back. Surface
had no such route: the push got 405, Pilot ignored it, and every custom LLM
call answered "Custom LLM not configured". Locks, through the HTTP route:
  - a push with the service token is the config ``_get_custom_llm`` returns;
  - a new push replaces the previous one, a cleared key included;
  - a push without the right token is refused and changes nothing;
  - the config Pilot also sends with the AI keys, label included, is the one
    used once a restart has emptied the in-memory copy.
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

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.ai_proxy_common import _get_api_key, _get_custom_llm, make_ai_router  # noqa: E402
from src.database import get_db  # noqa: E402
from src.models import AppSettings, AuditLog  # noqa: E402

_HAS_INTERNAL = os.path.exists(os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes", "internal.py"))
pytestmark = pytest.mark.skipif(not _HAS_INTERNAL, reason="suite-only route (standalone build)")

_TOKEN = "svc-token-for-tests-0123456789abcdef"
_MISTRAL = {"endpoint": "https://api.mistral.ai/v1", "model": "mistral-small-latest",
            "key": "medsecure-llm-key", "label": "MedSecure LLM"}


@pytest_asyncio.fixture
async def client(monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN)
    monkeypatch.setattr(internal, "_custom_llm", {})
    app = FastAPI()
    app.include_router(internal.router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://surface") as c:
        yield c


async def _push(client, body, token=_TOKEN):
    return await client.put("/api/internal/ai-custom", json=body, headers={"X-Service-Token": token})


@pytest.mark.asyncio
async def test_a_pushed_custom_llm_is_the_one_surface_uses(client):
    resp = await _push(client, _MISTRAL)
    assert resp.status_code == 200
    assert await _get_custom_llm(None) == _MISTRAL


@pytest.mark.asyncio
async def test_a_new_push_replaces_the_previous_one(client):
    await _push(client, _MISTRAL)
    resp = await _push(client, {"endpoint": "https://llm.medsecure.example/v1", "model": "m2"})
    assert resp.status_code == 200
    assert await _get_custom_llm(None) == {"endpoint": "https://llm.medsecure.example/v1", "model": "m2",
                                           "key": "", "label": "Custom LLM"}


@pytest.mark.asyncio
async def test_a_push_without_the_service_token_changes_nothing(client):
    await _push(client, _MISTRAL)
    resp = await _push(client, {"endpoint": "https://evil.example/v1"}, token="wrong")
    assert resp.status_code == 403
    assert (await _get_custom_llm(None))["endpoint"] == _MISTRAL["endpoint"]


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
        await c.run_sync(AuditLog.__table__.create)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_stored_custom_llm_survives_a_restart(db, monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setenv("SERVICE_TOKEN", _TOKEN)
    app = FastAPI()
    app.include_router(make_ai_router())
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://surface") as c:
        resp = await c.put("/api/ai/keys", headers={"X-Service-Token": _TOKEN}, json={
            "ai_custom_endpoint": _MISTRAL["endpoint"], "ai_custom_key": _MISTRAL["key"],
            "ai_custom_model": _MISTRAL["model"], "ai_custom_label": _MISTRAL["label"]})
    assert resp.status_code == 200
    monkeypatch.setattr(internal, "_custom_llm", {})  # what a restart leaves in memory
    assert await _get_custom_llm(db) == _MISTRAL


@pytest.mark.asyncio
async def test_the_log_names_the_endpoint_host_never_the_key_or_url(client, caplog):
    import logging
    with caplog.at_level(logging.INFO):
        await _push(client, {**_MISTRAL, "endpoint": "https://api.mistral.ai/v1/tenant-medsecure"})
    logged = [r.getMessage() for r in caplog.records if r.name != "httpx"]
    assert [m for m in logged if "api.mistral.ai" in m]
    assert not [m for m in logged if _MISTRAL["key"] in m or "tenant-medsecure" in m]

@pytest.mark.asyncio
async def test_settings_cleared_in_pilot_are_cleared_in_the_module(db, monkeypatch):
    import src.routes.internal as internal
    monkeypatch.setenv("SERVICE_TOKEN", _TOKEN)
    monkeypatch.setattr(internal, "SERVICE_TOKEN", _TOKEN, raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(internal, "_custom_llm", {})
    app = FastAPI()
    app.include_router(make_ai_router())
    app.include_router(internal.router)
    app.dependency_overrides[get_db] = lambda: db
    headers = {"X-Service-Token": _TOKEN}
    full = {"openai": "sk-medsecure", "ai_custom_endpoint": _MISTRAL["endpoint"], "ai_custom_key": _MISTRAL["key"],
            "ai_custom_model": _MISTRAL["model"], "ai_custom_label": _MISTRAL["label"]}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://module") as c:
        assert (await c.put("/api/ai/keys", headers=headers, json=full)).status_code == 200
        assert (await c.put("/api/ai/keys", headers=headers, json={k: "" for k in full})).status_code == 200
        assert (await c.put("/api/internal/ai-custom", headers=headers,
                            json={"endpoint": "", "model": "", "key": "", "label": ""})).status_code == 200
        for _ in range(2):  # as pushed, then after a restart (memory empty)
            custom = await _get_custom_llm(db)
            assert (custom.get("endpoint", ""), custom.get("key", "")) == ("", "")
            assert not await _get_api_key("openai", db)
            monkeypatch.setattr(internal, "_custom_llm", {})

