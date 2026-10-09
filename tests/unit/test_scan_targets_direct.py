"""BUG-92 — the scanners reach their target directly, never through the proxy.

Surface now receives Pilot's outbound proxy and exports it for the module's
own outbound calls (AI provider, CVE feeds). httpx follows it in every client
that trusts the environment, so the scanners that reach the scanned target
would have sent it to the corporate proxy: an internal target would be
refused, and the scanners read a refusal as "nothing found". Until scanning
through the proxy is supported, they do not follow the proxy Pilot pushed;
a proxy the deployment set itself (a standalone .env) they follow, as they
always did. Locks: every httpx call of an add-on passes
``trust_env=not pushed_proxy()``, unless the add-on is listed as calling
only a third-party service (NVD, Shodan, crt.sh…), which follows the proxy;
the HTTP probe and the screenshot browser follow the same rule.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


def _clients(tree: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "httpx"
            and n.func.attr in ("Client", "AsyncClient", "get", "post", "head", "request", "stream")]


def _ignores_the_proxy(call: ast.Call) -> bool:
    """``trust_env=not pushed_proxy()``: off only for the proxy Pilot pushed."""
    return any(k.arg == "trust_env" and isinstance(k.value, ast.UnaryOp) and isinstance(k.value.op, ast.Not)
               and isinstance(k.value.operand, ast.Call) and getattr(k.value.operand.func, "id", "") == "pushed_proxy"
               for k in call.keywords)


# Add-ons whose HTTP calls go to a third-party service, never to the scanned
# target: those follow the proxy like the module's other outbound calls.
_THIRD_PARTY = {
    "ct_logs": "certificate transparency logs",
    "typosquatting": "crt.sh",
    "tls": "crt.sh",
    "cloud_buckets": "the cloud storage providers",
    "cve_lookup": "NVD",
    "shodan": "the Shodan API",
    "defender": "Microsoft Graph",
}
_ADDONS = sorted((_ROOT / "addons").glob("*/*/*.py"))


def test_every_add_on_reaching_the_scanned_target_ignores_the_proxy():
    following = {}
    for f in _ADDONS:
        calls = [c.lineno for c in _clients(ast.parse(f.read_text(encoding="utf-8"))) if not _ignores_the_proxy(c)]
        if calls and f.stem not in _THIRD_PARTY:
            following[f"{f.parent.parent.name}/{f.stem}"] = calls
    assert following == {}, "these reach the scanned target through the proxy: pass " \
                            "trust_env=not pushed_proxy(), " \
                            "or list the add-on in _THIRD_PARTY if it only calls a third-party service"


@pytest.mark.parametrize("addon", ["security_headers", "sensitive_files", "js_analysis", "takeover"])
def test_a_scanner_reaching_the_target_ignores_the_proxy(addon):
    calls = _clients(ast.parse((_ROOT / "addons" / "core" / addon / f"{addon}.py").read_text(encoding="utf-8")))
    assert calls, addon
    assert [c.lineno for c in calls if not _ignores_the_proxy(c)] == []


def test_the_http_probe_ignores_the_proxy():
    tree = ast.parse((_ROOT / "src" / "scan_common.py").read_text(encoding="utf-8"))
    [probe] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_http_probe"]
    calls = _clients(probe)
    assert calls and [c.lineno for c in calls if not _ignores_the_proxy(c)] == []


@pytest.fixture
def pushed(monkeypatch):
    """Set whether the proxy in the environment came from Pilot."""
    from src import proxy_common

    def _set(value: bool):
        monkeypatch.setattr(proxy_common, "pushed_proxy", lambda: value)
    return _set


@pytest.mark.parametrize("from_pilot", [True, False])
def test_the_http_probe_follows_only_a_proxy_the_deployment_set(monkeypatch, pushed, from_pilot):
    import httpx

    import src.scan_common as scan_common
    pushed(from_pilot)
    seen = {}

    class _Client:
        def __init__(self, **kw):
            seen.update(kw)

        def __enter__(self):
            raise httpx.ConnectError("stop here")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(httpx, "Client", _Client)
    assert scan_common._http_probe("portal.medsecure.example", 443, "https") is None
    assert seen["trust_env"] is (not from_pilot)


@pytest.mark.parametrize("from_pilot", [True, False])
def test_the_screenshot_browser_ignores_only_the_proxy_pilot_pushed(monkeypatch, pushed, from_pilot):
    import sys
    import types

    from conftest import load_core_addon
    pushed(from_pilot)
    launched = []

    class _Chromium:
        def launch(self, **kw):
            launched.append(kw["args"])
            raise RuntimeError("stop here")

    class _Playwright:
        chromium = _Chromium()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    api = types.ModuleType("playwright.sync_api")
    api.sync_playwright = lambda: _Playwright()
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", api)
    mod = load_core_addon("screenshot")
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)
    mod.scan_host_screenshot("portal.medsecure.example")
    assert launched and all(("--no-proxy-server" in args) is from_pilot for args in launched)

