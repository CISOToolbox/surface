"""FEAT-57 — the page scanners follow the target's redirects as it says.

A target's ``config.follow_redirects`` is ``none``, ``same_domain`` (the
default, the key absent included) or ``all``. js_analysis and
security_headers read the page the root redirects to. Locks, with the
network replaced (every address stubbed, the proxy's transport and the
direct one recorded):
  - ``same_domain`` follows a redirect on the target's registrable domain,
    not off it; ``all`` follows any; ``none`` follows nothing;
  - every hop is validated as a target is (metadata, loopback refused, the
    LAN allowed), resolved once, pinned to its address with its name in
    ``Host`` and as SNI directly, and asked for by name through the proxy;
  - only http(s) is followed, at most five hops, a loop ends;
  - js_analysis resolves the page's relative scripts against the page's
    URL; security_headers grades the page reached and names its URL;
  - a hop that fails, or that is not followed, leaves the previous page as
    the page; a hop to a host of the scan blocklist is not contacted;
  - an IP target only follows redirects on its own address in
    ``same_domain``;
  - an unknown value is not stored, and reads as the default.
"""
from __future__ import annotations

import os
import socket
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import load_core_addon  # noqa: E402

import src.scan_common as scan_common  # noqa: E402

_PROXY = "http://scan:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
_TARGET = "portal.medsecure.example"
_ADDRESSES = {_TARGET: "93.184.216.34", "www.medsecure.example": "93.184.216.41",
              "login.other.example": "93.184.216.50", "lan.other.example": "10.0.0.5",
              "meta.other.example": "169.254.169.254", "internal.medsecure.example": "127.0.0.1"}
_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
_HEADERS = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, host), port or 0))])
    scan_common.take_proxy_failures()


@pytest.fixture
def site(monkeypatch):
    """Every request lands in a recorder, as (route, url, Host, SNI). ``pages``
    maps (Host, path) to a response, or an exception to raise; anything else
    is a 404."""
    seen: list[tuple[str, str, str, str | None]] = []
    pages: dict[tuple[str, str], httpx.Response] = {}

    def answer(route):
        def handle(request):
            host = request.headers.get("Host")
            seen.append((route, str(request.url), host, request.extensions.get("sni_hostname")))
            page = pages.get((host, request.url.raw_path.decode()))
            if isinstance(page, Exception):
                raise page
            if page is not None and not hasattr(page, "_content"):
                # A body to stream (one that fails, say): served as is.
                return httpx.Response(page.status_code, headers=page.headers, stream=page.stream)
            return httpx.Response(page.status_code, headers=page.headers, content=page.content) if page \
                else httpx.Response(404)
        return handle

    # Patched on the class: a ``transport=`` argument would turn the
    # environment's proxies off.
    monkeypatch.setattr(httpx.Client, "_init_proxy_transport",
                        lambda self, proxy, **kw: httpx.MockTransport(answer("proxy")))
    monkeypatch.setattr(httpx.Client, "_init_transport", lambda self, **kw: httpx.MockTransport(answer("direct")))
    return seen, pages


def _redirect(location, status=302):
    return httpx.Response(status, headers={"Location": location})


def _page(html="", headers=None):
    return httpx.Response(200, text=html, headers=headers or {})


def _js(site, config=None):
    mod = load_core_addon("js_analysis")
    return mod.scan_host_js_analysis(_TARGET, config) if config is not None else mod.scan_host_js_analysis(_TARGET)


def _urls(seen):
    return [s[1] for s in seen]


def _not_analysed(findings):
    """(where the redirect led, why it was not followed) of js_analysis's
    one finding saying so."""
    [f] = findings
    assert f["type"] == "js_not_analysed" and f["severity"] == "info"
    return f["evidence"]["location"], f["evidence"]["reason"]


@pytest.mark.parametrize("config", [None, {}, {"follow_redirects": "same_domain"}, {"follow_redirects": "bogus"}])
def test_by_default_a_redirect_on_the_target_is_followed_and_its_scripts_read(site, config):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/fr/login?next=%2F")
    pages[(_TARGET, "/fr/login?next=%2F")] = _page('<script src="app.js"></script>')
    pages[(_TARGET, "/fr/app.js")] = _page(f"var k = '{_KEY}';")
    findings = _js(site, config)
    assert seen == [
        ("direct", "https://93.184.216.34/", _TARGET, _TARGET),
        ("direct", "https://93.184.216.34/fr/login?next=%2F", _TARGET, _TARGET),
        ("direct", "https://93.184.216.34/fr/app.js", _TARGET, _TARGET)]
    assert [f["evidence"]["js_url"] for f in findings] == [f"https://{_TARGET}/fr/app.js"]


def test_same_domain_follows_another_host_of_the_domain_on_its_own_address(site):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example:8443/home", 301)
    pages[("www.medsecure.example:8443", "/home")] = _page('<script src="/w.js"></script>')
    pages[("www.medsecure.example:8443", "/w.js")] = _page(f"var k = '{_KEY}';")
    findings = _js(site)
    assert seen[1:] == [
        ("direct", "https://93.184.216.41:8443/home", "www.medsecure.example:8443", "www.medsecure.example"),
        ("direct", "https://93.184.216.41:8443/w.js", "www.medsecure.example:8443", "www.medsecure.example")]
    assert [f["evidence"]["js_url"] for f in findings] == ["https://www.medsecure.example:8443/w.js"]


def test_same_domain_does_not_follow_another_domain(site):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://login.other.example/")
    pages[("login.other.example", "/")] = _page('<script src="/a.js"></script>')
    assert _not_analysed(_js(site)) == ("https://login.other.example/", "off the target's domain")
    assert _urls(seen) == ["https://93.184.216.34/"]


def test_none_follows_nothing(site):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/login")
    pages[(_TARGET, "/login")] = _page('<script src="/a.js"></script>')
    assert _not_analysed(_js(site, {"follow_redirects": "none"})) == (
        f"https://{_TARGET}/login", "the target's setting is not to follow redirects")
    assert _urls(seen) == ["https://93.184.216.34/"]


@pytest.mark.parametrize("host,address", [("login.other.example", "93.184.216.50"), ("lan.other.example", "10.0.0.5")])
def test_all_follows_another_domain_and_reads_that_pages_scripts(site, host, address):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect(f"https://{host}/sso")
    pages[(host, "/sso")] = _page('<script src="/s.js"></script>')
    pages[(host, "/s.js")] = _page(f"var k = '{_KEY}';")
    findings = _js(site, {"follow_redirects": "all"})
    assert seen[1:] == [("direct", f"https://{address}/sso", host, host),
                        ("direct", f"https://{address}/s.js", host, host)]
    assert [f["evidence"]["js_url"] for f in findings] == [f"https://{host}/s.js"]


@pytest.mark.parametrize("location", ["https://meta.other.example/latest/", "https://internal.medsecure.example/",
                                      "https://169.254.169.254/", "ftp://www.medsecure.example/"])
def test_a_hop_is_validated_as_a_target_is(site, location):
    # Refused, not crashed: the redirect itself is graded.
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect(location)
    [finding] = _headers({"follow_redirects": "all"})
    assert finding["evidence"]["url"] == f"https://{_TARGET}/"
    assert finding["evidence"]["redirect_reason"] in (
        "not a host the scanner may reach (internal or unresolvable)", "not an http(s) URL")
    assert _urls(seen) == ["https://93.184.216.34/"]


@pytest.mark.parametrize("location,reason", [("javascript:alert(1)", "not an http(s) URL"),
                                             ("https://www.medsecure.example:99999/", "Port out of range 0-65535"),
                                             ("https://www.medsecure.example:abc/", "Port could not be cast to integer value as 'abc'"),
                                             ("http://[::1", "Invalid IPv6 URL"),
                                             ("http://www.medsecure.example\x01/", "not a host the scanner may reach (internal or unresolvable)")])
def test_a_location_httpx_cannot_parse_is_said_not_followed(site, location, reason):
    # httpx builds the redirect request even when not following it, and
    # refuses these URLs: the redirect is still the page, and said.
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect(location)
    assert _not_analysed(_js(site, {"follow_redirects": "all"}))[1] == reason
    [finding] = _headers({"follow_redirects": "all"})
    assert finding["evidence"]["variant"] == "redirect_not_followed"
    assert _urls(seen) == ["https://93.184.216.34/"] * 2


def test_a_redirect_chain_stops_after_five_hops(site):
    seen, pages = site
    for i in range(10):
        pages[(_TARGET, "/" if i == 0 else f"/{i}")] = _redirect(f"/{i + 1}")
    assert _not_analysed(_js(site)) == (f"https://{_TARGET}/6", "redirect loop or too many redirects")
    assert len(seen) == 6


def test_a_redirect_loop_ends(site):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/a")
    pages[(_TARGET, "/a")] = _redirect("/")
    assert _not_analysed(_js(site))[1] == "redirect loop or too many redirects"
    assert _urls(seen) == ["https://93.184.216.34/", "https://93.184.216.34/a"]


def test_a_redirect_to_http_on_the_target_is_followed_without_sni(site):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect(f"http://{_TARGET}/legacy")
    pages[(_TARGET, "/legacy")] = _page("<p>legacy</p>")
    _js(site)
    assert seen[1] == ("direct", "http://93.184.216.34/legacy", _TARGET, None)


def test_a_hop_host_is_resolved_once(site, monkeypatch):
    seen, pages = site
    resolved = []
    real = scan_common._resolve_safe_target
    monkeypatch.setattr(scan_common, "_resolve_safe_target", lambda t: resolved.append(t) or real(t))
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/a")
    pages[("www.medsecure.example", "/a")] = _redirect("/b")
    pages[("www.medsecure.example", "/b")] = _page('<script src="/c.js"></script>')
    _js(site)
    assert resolved.count("www.medsecure.example") == 1
    assert _urls(seen)[-1] == "https://93.184.216.41/c.js"


def test_through_the_proxy_each_hop_is_asked_for_by_name(site, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", "www.medsecure.example")
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/a")
    pages[("www.medsecure.example", "/a")] = _redirect(f"https://{_TARGET}/b")
    pages[(_TARGET, "/b")] = _page()
    _js(site)
    # each hop on its own host's routing: the excepted one directly
    assert seen == [("proxy", f"https://{_TARGET}/", _TARGET, None),
                    ("direct", "https://93.184.216.41/a", "www.medsecure.example", "www.medsecure.example"),
                    ("proxy", f"https://{_TARGET}/b", _TARGET, None)]


def test_a_proxy_refusing_a_hop_is_reported_under_its_host(site, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/a")

    def refuse(self, proxy, **kw):
        def handle(request):
            if request.url.host == "www.medsecure.example":
                raise httpx.ProxyError("403 Forbidden", request=request)
            return pages[(_TARGET, "/")]
        return httpx.MockTransport(handle)

    monkeypatch.setattr(httpx.Client, "_init_proxy_transport", refuse)
    assert _not_analysed(_js(site)) == ("https://www.medsecure.example/a",
                                        "the redirect target failed (ProxyError)")
    assert [f[0] for f in scan_common.take_proxy_failures()] == ["www.medsecure.example"]


def _headers(config=None):
    mod = load_core_addon("security_headers")
    return mod.scan_host_security_headers(_TARGET, config) if config is not None \
        else mod.scan_host_security_headers(_TARGET)


def test_security_headers_grades_the_page_reached(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/home")
    pages[(_TARGET, "/home")] = _page(headers=_HEADERS)
    [finding] = _headers()
    assert finding["evidence"]["grade"] == "A"
    assert finding["evidence"]["url"] == f"https://{_TARGET}/home"


def test_security_headers_without_following_grades_the_redirect(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/home")
    pages[(_TARGET, "/home")] = _page(headers=_HEADERS)
    [finding] = _headers({"follow_redirects": "none"})
    assert finding["evidence"]["grade"] == "F"
    assert finding["evidence"]["url"] == f"https://{_TARGET}/"


def test_the_dispatcher_hands_the_targets_config_to_both_scanners(site):
    from src import scanners
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/home")
    scanners.run_enabled_scanners("host", _TARGET, ["js_analysis", "security_headers"],
                                  config={"follow_redirects": "none"})
    assert _urls(seen) == ["https://93.184.216.34/", "https://93.184.216.34/"]


@pytest.mark.parametrize("value,stored", [("none", "none"), ("same_domain", "same_domain"), ("all", "all"),
                                          ("ALL", None), ("bogus", None), (1, None)])
def test_only_a_known_value_is_stored(value, stored):
    from src.routes.monitored import _merge_config_secrets
    assert _merge_config_secrets({"follow_redirects": value}, {}).get("follow_redirects") == stored


@pytest.mark.parametrize("error", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")])
def test_a_hop_that_fails_leaves_the_redirect_as_the_page(site, error):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/home")
    pages[("www.medsecure.example", "/home")] = error
    [finding] = _headers()
    assert finding["evidence"]["grade"] == "F"
    assert finding["evidence"]["url"] == f"https://{_TARGET}/"
    assert _urls(seen) == ["https://93.184.216.34/", "https://93.184.216.41/home"]


def test_a_root_that_fails_gives_nothing(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = httpx.ConnectError("refused")
    assert _headers() == [] and _js(site) == []


def test_a_hop_off_the_domain_not_followed_is_graded_as_the_redirect(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://login.other.example/")
    pages[("login.other.example", "/")] = _page(headers=_HEADERS)
    [finding] = _headers()
    assert finding["evidence"]["grade"] == "F" and finding["evidence"]["url"] == f"https://{_TARGET}/"


@pytest.mark.parametrize("port", [":443", ""])
def test_a_default_port_is_the_same_url(site, port):
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect(f"https://{_TARGET}{port}/")
    assert _not_analysed(_js(site))[1] == "redirect loop or too many redirects"
    assert _urls(seen) == ["https://93.184.216.34/"]


def _ip_target(site, location, mode):
    seen, pages = site
    pages[("10.0.1.5", "/")] = _redirect(location)
    pages[("10.0.1.5", "/login")] = _page(headers=_HEADERS)
    pages[("10.1.1.5", "/login")] = _page(headers=_HEADERS)
    mod = load_core_addon("security_headers")
    [finding] = mod.scan_host_security_headers("10.0.1.5", {"follow_redirects": mode})
    return finding["evidence"]["url"], _urls(seen)


def test_an_ip_target_follows_a_redirect_on_its_own_address(site):
    assert _ip_target(site, "/login", "same_domain") == (
        "https://10.0.1.5/login", ["https://10.0.1.5/", "https://10.0.1.5/login"])


def test_an_ip_target_does_not_follow_another_address_on_the_same_domain(site):
    # Split like a name, 10.0.1.5 and 10.1.1.5 share "1.5".
    assert _ip_target(site, "https://10.1.1.5/login", "same_domain") == ("https://10.0.1.5/", ["https://10.0.1.5/"])
    site[0].clear()
    assert _ip_target(site, "https://10.1.1.5/login", "all")[0] == "https://10.1.1.5/login"


@pytest.mark.parametrize("exclusion", ["www.medsecure.example", "medsecure.example", "93.184.216.0/24"])
def test_a_hop_to_an_excluded_host_is_not_contacted(site, exclusion):
    from src import scanners
    seen, pages = site
    monkey_target = "shop.example.net"
    _ADDRESSES[monkey_target] = "198.51.100.7"
    try:
        pages[(monkey_target, "/")] = _redirect("https://www.medsecure.example/home")
        pages[("www.medsecure.example", "/home")] = _page(headers=_HEADERS)
        findings, _d = scanners.run_enabled_scanners("host", monkey_target, ["security_headers"],
                                                     config={"follow_redirects": "all"}, exclusions=[exclusion])
    finally:
        del _ADDRESSES[monkey_target]
    assert _urls(seen) == ["https://198.51.100.7/"]
    assert [(f["evidence"]["url"], f["evidence"]["redirect_reason"]) for f in findings] == [
        (f"https://{monkey_target}/", "host in the scan blocklist")]


def test_the_blocklist_of_a_run_does_not_outlive_it(site):
    from src import scanners
    seen, pages = site
    scanners.run_enabled_scanners("host", _TARGET, ["security_headers"], exclusions=["www.medsecure.example"])
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/home")
    pages[("www.medsecure.example", "/home")] = _page(headers=_HEADERS)
    seen.clear()
    [finding] = _headers()
    assert finding["evidence"]["url"] == "https://www.medsecure.example/home"


def test_security_headers_says_the_redirect_it_graded_was_not_followed(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://login.other.example/sso?ticket=s3cret#x")
    [finding] = _headers()
    assert finding["title"].endswith("(redirect not followed)")
    assert finding["evidence"]["status_code"] == 302
    assert {k: finding["evidence"][k] for k in ("variant", "redirect_location", "redirect_reason")} == {
        "variant": "redirect_not_followed", "redirect_location": "https://login.other.example/sso",
        "redirect_reason": "off the target's domain"}
    assert "s3cret" not in finding["description"] and "https://login.other.example/sso" in finding["description"]


def test_security_headers_on_the_page_reached_says_nothing_of_redirects(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/home")
    pages[(_TARGET, "/home")] = _page(headers=_HEADERS)
    [finding] = _headers()
    assert "variant" not in finding["evidence"] and "redirect" not in finding["title"]
    assert finding["evidence"]["status_code"] == 200


def test_js_analysis_on_a_page_without_scripts_says_nothing(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _page("<p>no scripts</p>")
    assert _js(site) == []


def test_a_hop_whose_client_cannot_open_leaves_the_redirect_as_the_page(site, monkeypatch):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://www.medsecure.example/home")
    real = scan_common.scan_client

    def scan_client(host, ip=None, **kw):
        if host == "www.medsecure.example":
            raise OSError("no file descriptor left")
        return real(host, ip, **kw)

    mod = load_core_addon("security_headers")
    monkeypatch.setattr(mod, "scan_client", scan_client)
    [finding] = mod.scan_host_security_headers(_TARGET)
    assert finding["evidence"]["redirect_reason"] == "the redirect target failed (OSError)"


def test_the_url_of_the_page_reached_keeps_no_query(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/landing?token=s3cret")
    pages[(_TARGET, "/landing?token=s3cret")] = _page(headers=_HEADERS)
    [finding] = _headers()
    assert finding["evidence"]["url"] == f"https://{_TARGET}/landing"


def test_the_redirect_setting_is_read_back(monkeypatch):
    from src.routes.monitored import _redact_config_out
    assert _redact_config_out({"follow_redirects": "none"})["follow_redirects"] == "none"


@pytest.mark.parametrize("exclusion", ["www.medsecure.example", "93.184.216.41/32"])
def test_a_script_host_of_the_scan_blocklist_is_not_contacted(site, monkeypatch, exclusion):
    # The run's blocklist covers every host a scanner reaches on its own: a
    # redirect hop, and a script's host.
    monkeypatch.setattr(scan_common._EXCLUSIONS_CTX, "values", [exclusion], raising=False)
    seen, pages = site
    pages[(_TARGET, "/")] = _page('<script src="https://www.medsecure.example/w.js"></script>'
                                  '<script src="/app.js"></script>')
    pages[(_TARGET, "/app.js")] = _page(f"var k = '{_KEY}';")
    findings = _js(site)
    assert _urls(seen) == ["https://93.184.216.34/", "https://93.184.216.34/app.js"]
    assert len(findings) == 1


def test_a_long_page_url_keeps_its_path_for_relative_scripts(site):
    seen, pages = site
    deep = "/" + "a" * 320 + "/index"
    pages[(_TARGET, "/")] = _redirect(deep)
    pages[(_TARGET, deep)] = _page('<script src="app.js"></script>')
    _js(site)
    assert _urls(seen)[-1] == "https://93.184.216.34/" + "a" * 320 + "/app.js"


def test_credentials_in_a_location_are_not_kept(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = _redirect("https://bob:hunter2@login.other.example/x?t=1")
    [finding] = _headers()
    assert finding["evidence"]["redirect_location"] == "https://login.other.example/x"
    assert "hunter2" not in finding["description"]
    assert _not_analysed(_js(site))[0] == "https://login.other.example/x"


class _BrokenStream(httpx.SyncByteStream):
    def __init__(self, error=None):
        self.error = error or httpx.ReadTimeout("body too slow")

    def __iter__(self):
        raise self.error


@pytest.mark.parametrize("error", [httpx.ReadTimeout("body too slow"),
                                   httpx.RemoteProtocolError("peer closed connection")])
def test_a_page_whose_body_fails_is_not_taken_as_the_page(site, monkeypatch, error):
    # The headers came, the body did not: the hop failed (the redirect is
    # the page, said), it is not a page with nothing in it.
    seen, pages = site
    pages[(_TARGET, "/")] = _redirect("/login")
    pages[(_TARGET, "/login")] = httpx.Response(200, headers=_HEADERS, stream=_BrokenStream(error))
    assert _not_analysed(_js(site)) == (f"https://{_TARGET}/login",
                                        f"the redirect target failed ({type(error).__name__})")
    [finding] = _headers()
    assert finding["evidence"]["status_code"] == 302 and finding["evidence"]["variant"] == "redirect_not_followed"


def test_a_root_whose_body_fails_gives_nothing(site):
    _seen, pages = site
    pages[(_TARGET, "/")] = httpx.Response(200, headers=_HEADERS, stream=_BrokenStream())
    assert _headers() == [] and _js(site) == []


def test_with_all_the_scripts_are_those_of_the_page_reached_domain(site):
    seen, pages = site
    _ADDRESSES["cdn.other.example"] = "93.184.216.51"
    try:
        pages[(_TARGET, "/")] = _redirect("https://login.other.example/sso")
        pages[("login.other.example", "/sso")] = _page(
            '<script src="https://cdn.other.example/c.js"></script>'
            f'<script src="https://{_TARGET}/t.js"></script>')
        _js(site, {"follow_redirects": "all"})
    finally:
        del _ADDRESSES["cdn.other.example"]
    assert _urls(seen)[2:] == ["https://93.184.216.51/c.js"]
