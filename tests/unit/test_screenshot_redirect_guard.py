"""Regression: the screenshot add-on vets every hop of a redirect chain.

Chromium (Playwright 1.51) routes the FIRST request of a redirect chain only:
whether the route continues the request or fulfills it with a 3xx, Chromium
follows the next hops itself, unvetted. A target answering
"302 -> http://169.254.169.254/latest/meta-data/" had the metadata requested
and rendered into the PNG stored on the finding. Locks:
  - the route follows the chain itself and vets each Location before
    requesting it: a refused host is never requested, at any hop;
  - a chain inside the allowed perimeter, host changes included, captures
    the final page; cookies do not follow a host change; hops are capped;
  - the backstop before capture: a page whose URL, redirect chain or loaded
    requests touch a refused host is not captured;
  - service workers are blocked.
The fake below plays Chromium as observed: only the first request is
routed, and a 3xx given back to the browser is followed without the route.
"""
from __future__ import annotations

import sys
import types
from urllib.parse import urljoin

import pytest

from conftest import load_core_addon

TARGET = "portal.medsecure.example"
METADATA = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"


class _Req:
    def __init__(self, url, redirected_from=None, method="GET", headers=None):
        self.url = url
        self.redirected_from = redirected_from
        self.method = method
        self.headers = headers or {"user-agent": "chromium", "cookie": "session=medsecure"}


class _Resp:
    def __init__(self, status, headers=None, request=None):
        self.status = status
        self.headers = headers or {}
        self.request = request


class _Net:
    """The servers: answers per URL, and every request that reached one."""

    def __init__(self, answers):
        self.answers = answers
        self.hits: list[tuple[str, str, dict | None]] = []
        self.via: dict[str, str] = {}  # url -> what made the request

    def get(self, url, method="GET", headers=None, via="browser"):
        self.hits.append((url, method, headers))
        self.via[url] = via
        return self.answers.get(url, (200, {}))

    @property
    def urls(self):
        return [u for u, _, _ in self.hits]


class _Route:
    def __init__(self, request, net):
        self.request = request
        self._net = net
        self.outcome = None
        self.response = None

    def fetch(self, url=None, method=None, headers=None, max_redirects=None):
        assert max_redirects == 0, "the route must not let anything follow redirects for it"
        # route.fetch sends the browser context's cookie jar along.
        status, hdrs = self._net.get(url or self.request.url, method or self.request.method, headers,
                                     via="route.fetch+jar")
        return _Resp(status, hdrs)

    def abort(self):
        self.outcome = "abort"

    def continue_(self):
        self.outcome = "continue"

    def fulfill(self, response=None, **kw):
        self.outcome = "fulfill"
        self.response = response


class _ApiContext:
    """pw.request.new_context(): a request context without the browser's jar."""

    def __init__(self, net, made, **kw):
        self._net = net
        made.append(kw)

    def fetch(self, url, method=None, headers=None, max_redirects=None):
        assert max_redirects == 0, "the route must not let anything follow redirects for it"
        status, hdrs = self._net.get(url, method or "GET", headers, via="cookieless")
        return _Resp(status, hdrs)


def _browser(net, launched, contexts, escaped_extra=(), forged_chain=None, final_url=None,
             first_method="GET", subresources=(), api_contexts=None):
    api_contexts = [] if api_contexts is None else api_contexts

    class _Context:
        def __init__(self, **kw):
            self.kw = kw
            self.handler = None
            self.listeners = {}
            contexts.append(self)

        def route(self, pattern, handler):
            self.handler = handler

        def on(self, event, cb):
            self.listeners.setdefault(event, []).append(cb)

        def finished(self, url):
            for cb in self.listeners.get("requestfinished", []):
                cb(_Req(url))

        def new_page(self):
            return _Page(self)

    class _Page:
        def __init__(self, ctx):
            self.ctx = ctx
            self.url = "about:blank"

        def set_default_timeout(self, ms):
            pass

        def _follow(self, req, status, headers):
            # Chromium itself: no route from here on (and its own hop limit).
            for _ in range(20):
                if not 300 <= status < 400:
                    return req
                self.ctx.finished(req.url)
                req = _Req(urljoin(req.url, headers["location"]), req)
                status, headers = net.get(req.url)
            raise RuntimeError("net::ERR_TOO_MANY_REDIRECTS")

        def goto(self, url, **kw):
            req = _Req(url, method=first_method)
            route = _Route(req, net)
            self.ctx.handler(route)
            if route.outcome in ("abort", None):
                raise RuntimeError(f"net::ERR_FAILED at {url}")
            if route.outcome == "continue":
                status, headers = net.get(url)
                req = self._follow(req, status, headers)
            elif 300 <= route.response.status < 400:
                req = self._follow(req, route.response.status, route.response.headers)
            for sub in subresources:  # each one is a request of its own: routed
                sub_route = _Route(_Req(sub), net)
                self.ctx.handler(sub_route)
                if sub_route.outcome == "continue":
                    net.get(sub)
            self.ctx.finished(req.url)
            for extra in escaped_extra:
                self.ctx.finished(extra)
            self.url = final_url or req.url
            return _Resp(200, request=forged_chain or req)

        def title(self):
            return "Page at " + self.url

        def screenshot(self, **kw):
            return ("PNG of " + self.url).encode()

    class _Browser:
        def new_context(self, **kw):
            return _Context(**kw)

        def close(self):
            pass

    class _Chromium:
        def launch(self, **kw):
            launched.append(kw)
            return _Browser()

    class _Playwright:
        chromium = _Chromium()
        request = types.SimpleNamespace(new_context=lambda **kw: _ApiContext(net, api_contexts, **kw))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return _Playwright


@pytest.fixture
def shoot(monkeypatch):
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)

    def _run(answers, **fake):
        net, launched, contexts = _Net(answers), [], []
        api = types.ModuleType("playwright.sync_api")
        pw = _browser(net, launched, contexts, **fake)
        api.sync_playwright = lambda: pw()
        monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
        monkeypatch.setitem(sys.modules, "playwright.sync_api", api)
        mod = load_core_addon("screenshot")

        def _policy(t, allow_unresolved=False):
            if t.startswith("169.254."):
                raise ValueError("metadata")
            return "203.0.113.10", t
        monkeypatch.setattr(mod, "_safe_target", lambda t: t)
        monkeypatch.setattr(mod, "_resolve_safe_target", _policy)
        monkeypatch.setattr(mod, "resolve_first_ip", lambda t: "203.0.113.10")
        return mod.scan_host_screenshot(TARGET), net, launched, contexts, mod

    return _run


def _both(path_to: dict) -> dict:
    """The same answers on https:443 and http:80."""
    out = {}
    for base in (f"https://{TARGET}:443", f"http://{TARGET}:80"):
        for path, answer in path_to.items():
            out[base + path] = answer
    return out


def test_first_hop_to_metadata_is_never_requested(shoot):
    answers = _both({"/": (302, {"location": METADATA})})
    findings, net, *_ = shoot(answers)
    assert findings == []
    assert METADATA not in net.urls


def test_second_hop_to_metadata_is_never_requested(shoot):
    # The first hop is allowed; Chromium would follow the second by itself.
    answers = _both({"/": (302, {"location": "/hop2"}), "/hop2": (302, {"location": METADATA})})
    findings, net, *_ = shoot(answers)
    assert findings == []
    assert METADATA not in net.urls


def test_subresource_on_a_refused_host_is_never_requested(shoot):
    findings, net, *_ = shoot(_both({"/": (200, {})}), subresources=(METADATA,))
    assert METADATA not in net.urls
    assert [f["type"] for f in findings] == ["screenshot", "screenshot"]


def test_chain_changing_host_is_captured_without_cookies(shoot):
    www = "https://www.medsecure.example/home"
    answers = _both({"/": (301, {"location": f"https://{TARGET}/"})})
    answers[f"https://{TARGET}/"] = (302, {"location": www})
    findings, net, *_ = shoot(answers)
    assert [f["type"] for f in findings] == ["screenshot", "screenshot"]
    # The browser gets the final answer under the first URL.
    assert findings[0]["evidence"]["page_title"] == f"Page at https://{TARGET}:443/"
    hops = {u: h for u, _, h in net.hits}
    assert www in hops and "cookie" not in {k.lower() for k in hops[www]}
    # Same host: the browser's context (its cookies are the target's own).
    # Another host: a request context without the browser's cookie jar.
    assert net.via[f"https://{TARGET}:443/"] == "route.fetch+jar"
    assert net.via[f"https://{TARGET}/"] == "route.fetch+jar"
    assert net.via[www] == "cookieless"


def test_redirect_loop_is_capped(shoot):
    answers = _both({"/": (302, {"location": "/"})})
    findings, net, _, _, mod = shoot(answers)
    assert findings == []
    assert len(net.urls) == 2 * (mod._MAX_HOPS + 1)


def test_307_keeps_the_method_and_303_becomes_get(shoot):
    answers = _both({"/": (307, {"location": "/a"}), "/a": (303, {"location": "/b"})})
    _, net, *_ = shoot(answers, first_method="POST")
    methods = {u.rsplit(":", 1)[-1]: m for u, m, _ in net.hits if u.startswith("https://")}
    assert methods == {"443/": "POST", "443/a": "POST", "443/b": "GET"}


@pytest.mark.parametrize("fake", [
    {"final_url": METADATA},
    {"escaped_extra": (METADATA,)},
    {"forged_chain": _Req(f"https://{TARGET}:443/", redirected_from=_Req(METADATA))},
], ids=["page-url", "escaped-request", "redirect-chain"])
def test_backstop_refuses_capture(shoot, fake):
    # Something reached a refused host outside the route: no PNG of it.
    findings, *_ = shoot(_both({"/": (200, {})}), **fake)
    assert findings == []


def test_service_workers_blocked(shoot):
    _, _, launched, contexts, _ = shoot(_both({"/": (200, {})}))
    assert contexts and all(c.kw.get("service_workers") == "block" for c in contexts)
    assert not any("host-resolver-rules" in a for kw in launched for a in kw["args"])


def test_cookieless_context_keeps_the_proxy_and_tls_policy(shoot, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.medsecure.example:3128")
    made: list = []
    answers = _both({"/": (302, {"location": "https://www.medsecure.example/"})})
    shoot(answers, api_contexts=made)
    assert made and made[0]["ignore_https_errors"] is True
    assert made[0]["proxy"]["server"] == "http://proxy.medsecure.example:3128"

