"""BUG-95 — the AI agent reaches a custom LLM through the outbound proxy.

``call_llm`` resolved the custom endpoint locally and connected to the pinned
IP (DNS-rebinding guard). Behind a proxy that broke twice: on a network
without public DNS the endpoint never resolved, and the proxy was asked to
``CONNECT`` an IP, which a proxy filtering by name refuses. Through a proxy
the request now goes to the name; the guard still refuses an internal name,
an internal or metadata literal, and a name that resolves locally to one.
Directly (no proxy, or the host in the exceptions) it stays pinned. Whether
a proxy applies is ``ssrf_guard.proxy_for``, which follows httpx's own
NO_PROXY rules. Locks, against SQLite with the network replaced:
  - ``proxy_for`` routes as httpx does, entry by entry;
  - through the proxy: the request names the endpoint, even unresolvable;
  - through the proxy: internal name, metadata literal, name resolving to a
    private address are refused (400), nothing sent;
  - a host in NO_PROXY, or no proxy at all: pinned on the validated IP.
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

from sqlalchemy import update  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.ai_proxy_common import call_llm  # noqa: E402
from src.models import AppSettings  # noqa: E402

_HOST = "llm.medsecure.example"
_PROXY = "http://ops:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
         "REQUEST_METHOD")


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(AppSettings.__table__.create)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        session.add_all([AppSettings(key="ai_custom_endpoint", value=f"https://{_HOST}/v1"),
                         AppSettings(key="ai_custom_model", value="medsecure-llm"),
                         AppSettings(key="ai_custom_key", value="sk-medsecure-llm")])
        await session.commit()
        yield session
    await engine.dispose()


@pytest.fixture
def network(monkeypatch):
    """DNS answers ``resolves_to`` (None: no DNS); every transport is recorded
    with its proxy, every request with its URL. A request through a client
    without its own transport would reach the real network: it is recorded
    under ``unrouted`` instead."""
    state = {"resolves_to": "93.184.216.34", "proxies": [], "requests": [], "unrouted": []}

    def getaddrinfo(host, *a, **k):
        if state["resolves_to"] is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (state["resolves_to"], 0))]

    def reply(request):
        state["requests"].append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "triage: patch the host"}}]})

    def transport(*_a, proxy=None, **_k):
        state["proxies"].append(proxy)
        return httpx.MockTransport(reply)

    def unrouted(request):
        state["unrouted"].append(request)
        return httpx.Response(599)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: real_client(
        *a, **{**k, "transport": k.get("transport") or httpx.MockTransport(unrouted)}))
    return state


async def _endpoint(db, url):
    await db.execute(update(AppSettings).where(AppSettings.key == "ai_custom_endpoint").values(value=url))
    await db.commit()


# ── proxy_for follows httpx ──────────────────────────────────────

_ENTRIES = ["api.openai.com", "openai.com", ".openai.com", "api.openai.com:443", "api.openai.com:8443",
            "10.0.0.0/8", "10.1.2.3", "::1", "localhost", "*", "https://api.openai.com", "http://api.openai.com",
            "api.openai.com,localhost", ""]
_URLS = ["https://api.openai.com/v1", "https://api.openai.com:8443/v1", "http://api.openai.com/",
         "https://xapi.openai.com/", "https://sub.api.openai.com/", "https://openai.com/", "https://10.0.0.0/",
         "https://10.1.2.3/", "http://[::1]:8080/", "http://localhost/", "https://llm.medsecure.example/"]


@pytest.mark.parametrize("env", [{"HTTPS_PROXY": _PROXY}, {"HTTP_PROXY": _PROXY},
                                 {"ALL_PROXY": _PROXY}, {"HTTPS_PROXY": "proxy.medsecure.example:3128"}])
@pytest.mark.parametrize("no_proxy", _ENTRIES)
def test_proxy_for_routes_as_httpx_does(monkeypatch, env, no_proxy):
    from src.ssrf_guard import proxy_for
    for var, value in {**env, "NO_PROXY": no_proxy}.items():
        monkeypatch.setenv(var, value)
    with httpx.Client() as c:
        for url in _URLS:
            proxied = c._transport_for_url(httpx.URL(url)) is not c._transport
            assert (proxy_for(url) is not None) == proxied, (url, env, no_proxy)


def test_proxy_for_reads_a_given_mapping_not_the_environment(monkeypatch):
    from src.ssrf_guard import proxy_for
    monkeypatch.setenv("HTTPS_PROXY", "http://old-proxy.medsecure.example:3128")
    assert proxy_for("https://api.openai.com/", {"https": _PROXY, "no": ""}) == _PROXY
    assert proxy_for("https://api.openai.com/", {"https": _PROXY, "no": "openai.com"}) is None
    assert proxy_for("https://api.openai.com/", {"https": "proxy.medsecure.example:3128"}) == \
        "http://proxy.medsecure.example:3128"


# ── the custom LLM through the proxy ─────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("resolves_to", [None, "93.184.216.34"])  # no DNS here, or a public answer
async def test_the_custom_llm_is_reached_by_name_through_the_proxy(db, network, monkeypatch, resolves_to):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    network["resolves_to"] = resolves_to
    assert await call_llm(db, "system", "a finding", provider="custom", model="") == "triage: patch the host"
    [req] = network["requests"]
    assert str(req.url) == f"https://{_HOST}/v1/chat/completions"
    assert req.headers["Authorization"] == "Bearer sk-medsecure-llm"
    assert network["proxies"] == [_PROXY] and network["unrouted"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,resolves_to", [
    ("https://pilot-app/v1", None),                       # a sibling of the suite
    ("https://metadata.google.internal/v1", None),
    ("https://169.254.169.254/v1", None),                 # metadata literal
    ("https://10.0.0.5/v1", None),                        # private literal
    (f"https://{_HOST}/v1", "10.0.0.5"),                  # a name that resolves here to a private address
    (f"http://{_HOST}/v1", None),                         # https is still required
    ("https://pilot-app./v1", None),                      # a final dot does not hide a sibling
    ("https://metadata.google.internal./v1", None),
    ("https://llm-internal/v1", None),                    # a name without a domain is internal
])
async def test_the_guard_still_refuses_internal_targets_through_the_proxy(db, network, monkeypatch,
                                                                          endpoint, resolves_to):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    network["resolves_to"] = resolves_to
    await _endpoint(db, endpoint)
    with pytest.raises(HTTPException) as exc:
        await call_llm(db, "system", "a finding", provider="custom", model="")
    assert exc.value.status_code == 400
    assert network["requests"] == [] and network["unrouted"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("env", [{}, {"HTTPS_PROXY": _PROXY, "NO_PROXY": "medsecure.example"}])
async def test_a_direct_call_stays_pinned_on_the_validated_ip(db, network, monkeypatch, env):
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    await call_llm(db, "system", "a finding", provider="custom", model="")
    [req] = network["requests"]
    assert str(req.url) == "https://93.184.216.34/v1/chat/completions"
    assert req.headers["Host"] == _HOST and req.extensions.get("sni_hostname") == _HOST
    assert network["proxies"] == [None] and network["unrouted"] == []
