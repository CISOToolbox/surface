"""BUG-91 — a call to the custom LLM provider, end to end in the module.

``call_llm`` validates the custom endpoint with ``src.ssrf_guard`` before
posting the prompt; Surface did not ship that module, so any configured
custom LLM answered 500 (``ModuleNotFoundError``). Locks, against SQLite with
the network replaced:
  - a configured endpoint is called on the IP validated at resolution time,
    with the original name in ``Host`` and SNI, and its reply is returned;
  - an endpoint resolving to a private address is refused with 400 and
    never contacted.
"""
from __future__ import annotations

import os
import socket
import sys

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ["DATABASE_URL"] = "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test"
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.ai_proxy_common import call_llm  # noqa: E402
from src.models import AppSettings  # noqa: E402

_HOST = "llm.medsecure.example"


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add_all([AppSettings(key="ai_custom_endpoint", value=f"https://{_HOST}/v1"),
                         AppSettings(key="ai_custom_model", value="medsecure-llm")])
        await session.commit()
        yield session
    await engine.dispose()


@pytest.fixture
def network(monkeypatch):
    """DNS answers `resolves_to` for the endpoint; HTTP requests are recorded."""
    state = {"resolves_to": "93.184.216.34", "requests": []}

    def _getaddrinfo(host, *a, **k):
        assert host == _HOST, host
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (state["resolves_to"], 0))]

    def _reply(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "triage: patch the host"}}]})

    real = httpx.AsyncClient
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(_reply)}))
    return state


@pytest.mark.asyncio
async def test_a_configured_custom_llm_is_called_on_the_validated_ip(db, network):
    out = await call_llm(db, "system", "a finding", provider="custom", model="")
    assert out == "triage: patch the host"
    [req] = network["requests"]
    assert str(req.url) == "https://93.184.216.34/v1/chat/completions"
    assert req.headers["Host"] == _HOST
    assert req.extensions.get("sni_hostname") == _HOST


@pytest.mark.asyncio
async def test_a_custom_llm_on_a_private_address_is_refused(db, network):
    network["resolves_to"] = "10.0.0.5"
    with pytest.raises(HTTPException) as exc:
        await call_llm(db, "system", "a finding", provider="custom", model="")
    assert exc.value.status_code == 400
    assert network["requests"] == []
