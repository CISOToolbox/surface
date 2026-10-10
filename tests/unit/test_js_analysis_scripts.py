"""BUG-98 — js_analysis reads the target's scripts, each on its own host.

Locks, with the network replaced (every address stubbed, the proxy's
transport and the direct one recorded):
  - a relative ``src`` is resolved against the target's name, so directly it
    is read (on the locked IP) instead of being dropped as off-domain;
  - directly, a script is fetched on the IP its own host was validated at,
    with that name in ``Host`` (and its port when not the default) and as
    TLS SNI; through the proxy, by name;
  - a script follows the proxy routing of its own host, not the target's;
  - the target's own scripts stay on its locked IP, whatever the case of
    its name; a script host is resolved once; a foreign host is not even
    resolved; an IP target only has its
    own scripts; a bracketed IPv6 target resolves its relative ones;
  - a script keeps its path parameters; an invalid port in one ``src``
    leaves the other scripts read;
  - a proxy failure on a neighbour host's script is reported even when the
    root answered, through the proxy or directly;
  - the HTTP scanners' root request, pinned to the locked IP, sends the
    name as SNI.
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
_ADDRESSES = {"portal.medsecure.example": "93.184.216.34", "cdn.medsecure.example": "93.184.216.40",
              "internal.medsecure.example": "127.0.0.1", "tracker.other.example": "93.184.216.50"}
_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, host), port or 0))])
    scan_common.take_proxy_failures()


def _proxied(monkeypatch, no_proxy=""):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", no_proxy)


@pytest.fixture
def network(monkeypatch):
    """Every request lands in a recorder, as (route, url, Host, SNI): route
    ``proxy`` for the transport httpx built from the environment's proxy,
    ``direct`` otherwise. ``pages`` maps a path to its body (200), anything
    else is a 404; ``refuse`` lists hosts the proxy refuses."""
    seen: list[tuple[str, str, str, str | None]] = []
    pages: dict[str, str] = {}
    refuse: set[str] = set()

    def answer(route):
        def handle(request):
            seen.append((route, str(request.url), request.headers.get("Host"),
                         request.extensions.get("sni_hostname")))
            if route == "proxy" and request.url.host in refuse:
                raise httpx.ProxyError("502 Bad Gateway", request=request)
            body = pages.get(request.url.path)
            return httpx.Response(200, text=body) if body is not None else httpx.Response(404)
        return handle

    # Patched on the class: a ``transport=`` argument would turn the
    # environment's proxies off.
    monkeypatch.setattr(httpx.Client, "_init_proxy_transport",
                        lambda self, proxy, **kw: httpx.MockTransport(answer("proxy")))
    monkeypatch.setattr(httpx.Client, "_init_transport", lambda self, **kw: httpx.MockTransport(answer("direct")))
    return seen, pages, refuse, scan_common.scan_client


def _js(monkeypatch, network, html, target="portal.medsecure.example"):
    seen, pages, _refuse, client = network
    pages["/"] = html
    mod = load_core_addon("js_analysis")
    monkeypatch.setattr(mod, "scan_client", client)
    return mod.scan_host_js_analysis(target), seen[1:]


def test_directly_a_relative_script_is_read_on_the_locked_ip(monkeypatch, network):
    network[1]["/app.js"] = f"var k = '{_KEY}';"
    findings, scripts = _js(monkeypatch, network, '<script src="/app.js?v=3"></script>')
    assert network[0][0] == ("direct", "https://93.184.216.34/", "portal.medsecure.example",
                             "portal.medsecure.example")
    assert scripts == [("direct", "https://93.184.216.34/app.js?v=3", "portal.medsecure.example",
                        "portal.medsecure.example")]
    assert [f["evidence"]["js_url"] for f in findings] == ["https://portal.medsecure.example/app.js?v=3"]


def test_directly_a_script_of_another_host_is_pinned_to_its_own_address(monkeypatch, network):
    _f, scripts = _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/lib.js"></script>'
                                            '<script src="https://cdn.medsecure.example:8443/x.js"></script>')
    assert scripts == [("direct", "https://93.184.216.40/lib.js", "cdn.medsecure.example", "cdn.medsecure.example"),
                       ("direct", "https://93.184.216.40:8443/x.js", "cdn.medsecure.example:8443",
                        "cdn.medsecure.example")]


def test_through_the_proxy_a_script_is_asked_for_by_name(monkeypatch, network):
    _proxied(monkeypatch)
    _f, scripts = _js(monkeypatch, network, '<script src="/app.js"></script>'
                                            '<script src="https://cdn.medsecure.example/lib.js"></script>')
    assert scripts == [("proxy", "https://portal.medsecure.example/app.js", "portal.medsecure.example", None),
                       ("proxy", "https://cdn.medsecure.example/lib.js", "cdn.medsecure.example", None)]


def test_a_script_host_in_the_exceptions_is_reached_directly(monkeypatch, network):
    _proxied(monkeypatch, "cdn.medsecure.example")
    _f, scripts = _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/lib.js"></script>')
    assert network[0][0][0] == "proxy"
    assert scripts == [("direct", "https://93.184.216.40/lib.js", "cdn.medsecure.example", "cdn.medsecure.example")]


def test_a_script_host_outside_the_exceptions_goes_through_the_proxy(monkeypatch, network):
    _proxied(monkeypatch, "portal.medsecure.example")
    _f, scripts = _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/lib.js"></script>')
    assert network[0][0][0] == "direct"
    assert scripts == [("proxy", "https://cdn.medsecure.example/lib.js", "cdn.medsecure.example", None)]


def test_an_invalid_port_leaves_the_other_scripts_read(monkeypatch, network):
    network[1]["/app.js"] = f"var k = '{_KEY}';"
    findings, scripts = _js(monkeypatch, network, '<script src="https://cdn.medsecure.example:99999/x.js"></script>'
                                                  '<script src="/app.js"></script>')
    assert [s[1] for s in scripts] == ["https://93.184.216.34/app.js"]
    assert len(findings) == 1


@pytest.mark.parametrize("target", ["portal.medsecure.example", "Portal.MedSecure.example"])
def test_the_targets_own_scripts_stay_on_its_locked_ip(monkeypatch, network, target):
    # A second lookup of the target answers elsewhere (DNS rebinding): its
    # scripts, whatever the case of its name, stay on the address validated.
    answers = iter(["93.184.216.34"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers, "93.184.216.99"), port or 0))])
    _f, scripts = _js(monkeypatch, network, '<script src="/app.js"></script>'
                                            '<script src="https://portal.medsecure.example/b.js"></script>', target)
    assert [s[1] for s in scripts] == ["https://93.184.216.34/app.js", "https://93.184.216.34/b.js"]


def test_a_script_host_is_resolved_once(monkeypatch, network):
    # Its first answer is in an excepted range, the next one outside: the
    # client goes direct, so every script of that host stays on the first.
    _proxied(monkeypatch, "10.0.0.0/8")
    answers = {"portal.medsecure.example": iter(["93.184.216.34"]),
               "cdn.medsecure.example": iter(["10.1.2.3", "93.184.216.40"])}
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers[host], "169.254.169.254"), port or 0))])
    _f, scripts = _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/a.js"></script>'
                                            '<script src="https://cdn.medsecure.example/b.js"></script>')
    assert scripts == [("direct", f"https://10.1.2.3/{n}.js", "cdn.medsecure.example", "cdn.medsecure.example")
                       for n in "ab"]


def test_a_script_keeps_its_path_parameters_and_its_port(monkeypatch, network):
    _f, scripts = _js(monkeypatch, network, '<script src="/app.js;v=3?x=1"></script>'
                                            '<script src="https://portal.medsecure.example:8443/p.js"></script>')
    assert scripts == [("direct", "https://93.184.216.34/app.js;v=3?x=1", "portal.medsecure.example",
                        "portal.medsecure.example"),
                       ("direct", "https://93.184.216.34:8443/p.js", "portal.medsecure.example:8443",
                        "portal.medsecure.example")]


def test_a_plain_http_script_is_pinned_without_sni(monkeypatch, network):
    _f, scripts = _js(monkeypatch, network, '<script src="http://cdn.medsecure.example/lib.js"></script>')
    assert scripts == [("direct", "http://93.184.216.40/lib.js", "cdn.medsecure.example", None)]


def test_an_ip_target_reads_its_own_scripts_only(monkeypatch, network):
    # Split like a name, two addresses share a "registrable domain" ("1.5"
    # for 10.0.1.5 and 192.168.1.5): an address only has its own scripts.
    _f, scripts = _js(monkeypatch, network, '<script src="http://192.168.1.5:8080/x.js"></script>'
                                            '<script src="/app.js"></script>', "10.0.1.5")
    assert [s[1] for s in scripts] == ["https://10.0.1.5/app.js"]


def test_a_bracketed_ipv6_target_reads_its_relative_scripts(monkeypatch, network):
    network[1]["/app.js"] = f"var k = '{_KEY}';"
    findings, scripts = _js(monkeypatch, network, '<script src="/app.js"></script>', "[2001:db8::1]")
    assert network[0][0][1] == "https://[2001:db8::1]/"
    assert [s[1] for s in scripts] == ["https://[2001:db8::1]/app.js"] and len(findings) == 1


def test_a_foreign_script_host_is_not_resolved(monkeypatch, network):
    looked_up = []

    def lookup(host, port=0, *a, **k):
        looked_up.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, host), port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    _f, scripts = _js(monkeypatch, network, '<script src="https://tracker.other.example/t.js"></script>'
                                            '<script src="/app.js"></script>')
    assert "tracker.other.example" not in looked_up
    assert [s[1] for s in scripts] == ["https://93.184.216.34/app.js"]


def test_blocked_and_foreign_script_hosts_are_not_fetched(monkeypatch, network):
    _f, scripts = _js(monkeypatch, network, '<script src="https://internal.medsecure.example/x.js"></script>'
                                            '<script src="https://tracker.other.example/t.js"></script>'
                                            '<script src="file:///etc/passwd"></script>'
                                            '<script src="/app.js"></script>')
    assert [s[1] for s in scripts] == ["https://93.184.216.34/app.js"]


def test_a_proxy_refusing_a_neighbour_script_is_reported(monkeypatch, network):
    _proxied(monkeypatch, "portal.medsecure.example")
    network[2].add("cdn.medsecure.example")
    _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/lib.js"></script>')
    assert scan_common.take_proxy_failures() == [
        ("cdn.medsecure.example", "proxy.medsecure.example", "ProxyError: 502 Bad Gateway")]


def test_a_proxy_refusing_a_script_is_reported_though_it_answered_the_root(monkeypatch, network):
    _proxied(monkeypatch)
    network[2].add("cdn.medsecure.example")
    _js(monkeypatch, network, '<script src="https://cdn.medsecure.example/lib.js"></script>')
    assert network[0][0][0] == "proxy"
    assert scan_common.take_proxy_failures() == [
        ("cdn.medsecure.example", "proxy.medsecure.example", "ProxyError: 502 Bad Gateway")]


@pytest.mark.parametrize("addon,function", [("security_headers", "scan_host_security_headers"),
                                            ("sensitive_files", "scan_host_sensitive_files")])
def test_directly_the_root_request_sends_the_name_as_sni(monkeypatch, network, addon, function):
    seen, pages, _refuse, client = network
    pages["/"] = "<html></html>"
    mod = load_core_addon(addon)
    monkeypatch.setattr(mod, "scan_client", client)
    getattr(mod, function)("portal.medsecure.example")
    https = [s for s in seen if s[1].startswith("https://")]
    assert https and all(s[1].startswith("https://93.184.216.34") and s[3] == "portal.medsecure.example"
                         for s in https)
