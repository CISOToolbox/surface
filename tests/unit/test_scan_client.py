"""BUG-94 — the scanners reach a public target through the outbound proxy.

Surface receives Pilot's outbound proxy (or its deployment sets one), and its
own calls follow it; the scanners that reach the scanned target ignored the
proxy Pilot pushed, so in a network where the proxy is the only way out every
scan of a public target failed. They now build their httpx client with
``scan_common.scan_client(host, locked_ip)``:
  - direct when the target is a proxy exception: by name (a domain covers its
    subdomains), by exact IP, by the deployment's IPv4 ranges, or ``*`` —
    matched on the name and on the locked IP the scanner connects to, which
    httpx alone would compare to the IP only;
  - through the proxy otherwise, and then a refused, unreachable or silent
    proxy is logged once per client, with the target and the proxy host only,
    since the scanners swallow request errors and would read it as "nothing
    found";
  - an exception with a port exempts its host on every port (a scanner
    reaches several), and a range passed as the target (discovery) is
    matched against the deployment's ranges;
  - a 407 is the proxy's answer, never the target's: it is an error, logged,
    not a page the scanner reads as the target's;
  - every scanner reaching the target passes the locked IP it validated
    (through the proxy it then asks for the name: BUG-97); a target in the
    exceptions never reaches the proxy (a real socket stands in for it);
  - a proxy failure becomes a finding of the scanner, not only a log line:
    the scanners swallow request errors and would show a clean scan; but a
    client that got an answer otherwise (https refused, http answered) did
    scan, and is not reported.
"""
from __future__ import annotations

import logging
import os
import socket
import sys
import threading

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import load_core_addon  # noqa: E402

import src.scan_common as scan_common  # noqa: E402
from src.scan_common import bypasses_proxy, scan_client  # noqa: E402

_PROXY = "http://scan:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")


@pytest.fixture(autouse=True)
def _proxy(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", "lab.medsecure.local,192.0.2.7,10.0.0.0/8")


@pytest.mark.parametrize("host,ip,expected", [
    ("lab.medsecure.local", None, True),
    ("PACS.Lab.MedSecure.Local.", None, True),
    ("notlab.medsecure.local", None, False),
    ("pacs.medsecure.example", "192.0.2.7", True),
    ("192.0.2.7", None, True),
    ("[192.0.2.7]", None, True),
    ("pacs.medsecure.example", "10.4.2.1", True),
    ("10.4.2.1", None, True),
    ("portal.medsecure.example", "93.184.216.34", False),
    ("portal.medsecure.example", None, False),
])
def test_an_exception_is_matched_on_the_name_and_on_the_locked_ip(host, ip, expected):
    assert bypasses_proxy(host, ip) is expected


@pytest.mark.parametrize("host,ip,expected", [
    ("intranet.medsecure.local", None, True),
    ("app.intranet.medsecure.local", None, True),
    ("pacs.medsecure.example", "192.0.2.9", True),
    ("192.0.2.9", None, True),
    ("portal.medsecure.example", "93.184.216.34", False),
])
def test_an_exception_with_a_port_exempts_its_host(monkeypatch, host, ip, expected):
    monkeypatch.setenv("NO_PROXY", "intranet.medsecure.local:8080,192.0.2.9:443")
    assert bypasses_proxy(host, ip) is expected


@pytest.mark.parametrize("target,expected", [
    ("10.1.0.0/16", True),
    ("10.0.0.0/8", True),
    ("203.0.113.0/28", False),
    ("0.0.0.0/0", False),
])
def test_a_range_target_is_matched_against_the_ranges(target, expected):
    assert bypasses_proxy(target) is expected


def test_star_exempts_every_target(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "*")
    assert bypasses_proxy("portal.medsecure.example", "93.184.216.34")


@pytest.mark.parametrize("host,ip,direct", [
    ("pacs.medsecure.example", "10.4.2.1", True),
    ("portal.medsecure.example", "93.184.216.34", False),
])
def test_a_scan_client_is_direct_for_an_exception_and_proxied_otherwise(host, ip, direct):
    with scan_client(host, ip) as c:
        assert c.trust_env is (not direct)


@pytest.mark.parametrize("error", [httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout])
def test_a_failing_proxy_is_logged_once_per_client(caplog, error):
    def fail(request):
        raise error("proxy failure", request=request)

    scan_common.take_proxy_failures()
    # Mounted on https://, it stands in for the proxy transport the environment sets.
    with scan_client("portal.medsecure.example", "93.184.216.34",
                     mounts={"https://": httpx.MockTransport(fail)}) as c:
        for _ in range(2):
            with pytest.raises(error):
                c.get("https://93.184.216.34/")
    cause = "ProxyError: proxy failure" if error is httpx.ProxyError else error.__name__
    assert scan_common.take_proxy_failures() == [("portal.medsecure.example", "proxy.medsecure.example", cause)]


def test_a_407_from_the_proxy_is_an_error_not_the_targets_page(caplog):
    answers = []

    def proxy_auth_required(request):
        answers.append(request.url)
        return httpx.Response(407, text="Proxy Authentication Required")

    scan_common.take_proxy_failures()
    # Mounted on http://, it stands in for the proxy transport: plain HTTP
    # is forwarded, so the proxy's refusal comes back as a response.
    with scan_client("portal.medsecure.example", "93.184.216.34",
                     mounts={"http://": httpx.MockTransport(proxy_auth_required)}) as c:
        for _ in range(2):
            with pytest.raises(httpx.ProxyError):
                c.get("http://93.184.216.34/.env")
    assert len(answers) == 2
    assert scan_common.take_proxy_failures() == [("portal.medsecure.example", "proxy.medsecure.example", "HTTP 407")]


def test_a_407_inside_the_https_tunnel_is_the_targets():
    # Through the proxy, https is a CONNECT tunnel: a refused CONNECT raises
    # in httpx; a 407 read inside the tunnel comes from the target.
    with scan_client("portal.medsecure.example", "93.184.216.34",
                     mounts={"https://": httpx.MockTransport(lambda r: httpx.Response(407))}) as c:
        assert c.get("https://93.184.216.34/").status_code == 407


@pytest.fixture
def fake_proxy(monkeypatch):
    """A local socket standing in for the proxy: records each request line
    and refuses it, so nothing leaves the machine."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    seen: list[str] = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                head = conn.recv(4096).decode(errors="replace")
                seen.append(head.split("\r\n")[0])
                seen.append("auth" if "Proxy-Authorization: Basic" in head else "no-auth")
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://scan:s3cret@127.0.0.1:{srv.getsockname()[1]}"
    monkeypatch.setenv("HTTPS_PROXY", url)
    monkeypatch.setenv("HTTP_PROXY", url)
    yield seen
    srv.close()


def test_the_proxy_gets_the_credentials(fake_proxy):
    with scan_client("portal.medsecure.example", "93.184.216.34", timeout=5) as c:
        with pytest.raises(httpx.ProxyError):
            c.get("https://portal.medsecure.example/")
    assert fake_proxy[:2] == ["CONNECT portal.medsecure.example:443 HTTP/1.1", "auth"]


def test_a_target_in_the_exceptions_never_reaches_the_proxy(fake_proxy):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    with scan_client("lab.medsecure.local", "127.0.0.1", timeout=5) as c:
        with pytest.raises(httpx.ConnectError):
            c.get(f"https://127.0.0.1:{port}/")
    assert fake_proxy == []


def test_a_proxy_failure_is_a_finding_of_the_scanner(monkeypatch, caplog):
    from src import scanners

    def fail(request):
        raise httpx.ProxyError("refused", request=request)

    def headers_like(target):
        try:
            with scan_client(target, "93.184.216.34", mounts={"https://": httpx.MockTransport(fail)}) as c:
                c.get("https://93.184.216.34/")
        except Exception:
            return []  # what the HTTP scanners do

    def clean(target):
        return []

    for name, fn in (("headers_like", headers_like), ("clean", clean)):
        monkeypatch.setitem(scanners.SCANNER_REGISTRY, name,
                            {"callable": fn, "kinds": ["host"], "returns_discovered": False})
    with caplog.at_level(logging.WARNING):
        findings, _ = scanners.run_enabled_scanners("host", "portal.medsecure.example", ["headers_like", "clean"])
    warned = [r.getMessage() for r in caplog.records if "outbound proxy" in r.getMessage()]
    assert len(warned) == 1 and "headers_like" in warned[0] and "proxy.medsecure.example" in warned[0]
    assert "s3cret" not in warned[0]
    assert [(f["scanner"], f["type"], f["target"]) for f in findings] == [
        ("headers_like", "scanner_error", "portal.medsecure.example")]
    assert findings[0]["evidence"]["proxy_host"] == "proxy.medsecure.example"
    assert "s3cret" not in repr(findings)


def test_a_client_answered_on_another_scheme_is_not_a_proxy_failure(monkeypatch):
    from src import scanners

    def https_refused(request):
        raise httpx.ProxyError("CONNECT refused: 443 closed", request=request)

    def http_like(target):
        with scan_client(target, "93.184.216.34", mounts={
                "https://": httpx.MockTransport(https_refused),
                "http://": httpx.MockTransport(lambda r: httpx.Response(404))}) as c:
            for scheme in ("https", "http"):
                try:
                    c.get(f"{scheme}://93.184.216.34/")
                except httpx.HTTPError:
                    continue
        return []

    monkeypatch.setitem(scanners.SCANNER_REGISTRY, "http_like",
                        {"callable": http_like, "kinds": ["host"], "returns_discovered": False})
    findings, _ = scanners.run_enabled_scanners("host", "portal.medsecure.example", ["http_like"])
    assert findings == []


@pytest.mark.parametrize("https_fails", [True, False])
def test_takeover_with_https_refused_and_http_answered_is_no_proxy_failure(monkeypatch, caplog, https_fails):
    from src import scanners
    mod = load_core_addon("takeover")
    real = scan_client

    def refused(request):
        raise httpx.ProxyError("CONNECT refused", request=request)

    http = httpx.MockTransport(refused if not https_fails else lambda r: httpx.Response(404, text="nothing"))
    monkeypatch.setattr(mod, "scan_client", lambda host, ip=None, **kw: real(
        host, ip, mounts={"https://": httpx.MockTransport(refused), "http://": http}, **kw))
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)
    monkeypatch.setattr(mod, "resolve_first_ip", lambda t: None)
    monkeypatch.setattr(mod, "_resolve_cname_chain", lambda t: ["shop-medsecure.github.io"])
    monkeypatch.setitem(scanners.SCANNER_REGISTRY, "takeover",
                        {"callable": mod.scan_host_takeover, "kinds": ["host"], "returns_discovered": False})
    with caplog.at_level(logging.WARNING):
        findings, _ = scanners.run_enabled_scanners("host", "shop.medsecure.example", ["takeover"])
    errors = [f for f in findings if f["type"] == "scanner_error"]
    warned = [r for r in caplog.records if "outbound proxy" in r.getMessage()]
    if https_fails:  # http answered: the check ran
        assert errors == [] and warned == []
    else:  # neither scheme got through
        assert len(errors) == 1 and len(warned) == 1


def test_sensitive_files_passes_the_locked_ip_to_both_its_clients(monkeypatch):
    mod = load_core_addon("sensitive_files")
    seen = []
    real = scan_client

    def record(host, ip=None, **kw):
        seen.append((host, ip))
        return real(host, ip, transport=httpx.MockTransport(lambda r: httpx.Response(404)), timeout=1)

    monkeypatch.setattr(mod, "scan_client", record)
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("203.0.113.9", "portal.medsecure.example"))
    mod.scan_host_sensitive_files("portal.medsecure.example")
    assert len(seen) == 2 and set(seen) == {("portal.medsecure.example", "203.0.113.9")}


def test_a_407_on_a_direct_client_is_the_targets(caplog):
    with scan_client("pacs.medsecure.example", "10.4.2.1",
                     transport=httpx.MockTransport(lambda r: httpx.Response(407))) as c:
        assert c.get("http://10.4.2.1/").status_code == 407


def test_a_direct_failure_is_not_blamed_on_the_proxy():
    def fail(request):
        raise httpx.ConnectError("refused", request=request)

    scan_common.take_proxy_failures()
    with pytest.raises(httpx.ConnectError):
        with scan_client("pacs.medsecure.example", "10.4.2.1", transport=httpx.MockTransport(fail)) as c:
            c.get("https://10.4.2.1/")
    assert scan_common.take_proxy_failures() == []


class _Stop(Exception):
    pass


@pytest.mark.parametrize("addon,function", [
    ("security_headers", "scan_host_security_headers"),
    ("sensitive_files", "scan_host_sensitive_files"),
    ("js_analysis", "scan_host_js_analysis"),
])
def test_a_scanner_passes_the_locked_ip_it_connects_to(monkeypatch, addon, function):
    mod = load_core_addon(addon)
    seen = []

    def record(host, ip=None, **kw):
        seen.append((host, ip))
        raise _Stop

    monkeypatch.setattr(mod, "scan_client", record)
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("203.0.113.9", "portal.medsecure.example"))
    try:
        getattr(mod, function)("portal.medsecure.example")
    except _Stop:
        pass
    assert seen and seen[0] == ("portal.medsecure.example", "203.0.113.9")


def test_the_takeover_check_goes_through_scan_client(monkeypatch):
    seen = []

    def record(host, ip=None, **kw):
        seen.append(host)
        raise _Stop

    mod = load_core_addon("takeover")
    monkeypatch.setattr(mod, "resolve_first_ip", lambda t: None)
    monkeypatch.setattr(mod, "scan_client", record)
    try:
        mod._fetch_takeover_body("shop.medsecure.example")
    except _Stop:
        pass
    assert seen == ["shop.medsecure.example"]
