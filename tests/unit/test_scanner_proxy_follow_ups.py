"""BUG-97 — the scanners through the outbound proxy, follow-ups of BUG-94.

Locks, with the network replaced:
  - ``takeover`` matches the exceptions on the address its target resolves
    to; the raw-socket scanners too, before warning that they go direct;
  - through the proxy, the HTTP scanners ask for the target by name, with no
    forced ``Host`` (the proxy resolves it, the vhost is the scanned name);
    directly, they stay on the locked IP with the name in ``Host``;
  - with the name in the URL, httpx's routing still agrees with
    ``bypasses_proxy`` and the proxied transport keeps ``verify``;
  - a transport error is always logged; once the https tunnel is open
    (the proxy accepted the CONNECT) an error is the target's, a failed TLS
    handshake included; before, a silent or hanging-up proxy is the proxy's;
    a refused CONNECT carries the proxy's status;
  - Chromium gets the proxy of the captured scheme or none, the exceptions in
    its own syntax, decoded credentials; the failure names that proxy;
  - nuclei's "every request failed" holds at equality, not one below.
"""
from __future__ import annotations

import logging
import os
import socket
import ssl
import sys
import threading

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import load_core_addon  # noqa: E402
from test_scanner_proxy import _fake_playwright, _patch_run  # noqa: E402

import src.scan_common as scan_common  # noqa: E402
from src.scan_common import scan_client  # noqa: E402

_PROXY = "http://scan:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
_ADDRESSES = {"portal.medsecure.example": "93.184.216.34", "pacs.medsecure.example": "10.4.2.1",
              "shop.medsecure.example": "10.4.2.9", "xmedsecure.example": "127.0.0.1"}


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


class _Stop(Exception):
    pass


# ── exceptions matched on the resolved address ───────────────────

def test_takeover_matches_the_exceptions_on_the_resolved_address(monkeypatch):
    mod = load_core_addon("takeover")
    seen = []

    def record(host, ip=None, **kw):
        seen.append((host, ip))
        raise _Stop

    monkeypatch.setattr(mod, "scan_client", record)
    with pytest.raises(_Stop):
        mod._fetch_takeover_body("shop.medsecure.example")
    assert seen == [("shop.medsecure.example", "10.4.2.9")]


def test_the_unused_http_probe_is_gone():
    from src import scanners
    assert not hasattr(scan_common, "_http_probe") and not hasattr(scanners, "_http_probe")


@pytest.mark.parametrize("addon,call", [
    ("nmap", lambda m: m.scan_host_ports("pacs.medsecure.example")),
    ("tls", lambda m: m.scan_host_tls("pacs.medsecure.example")),
    ("tls_grade", lambda m: m.scan_host_tls_grade("pacs.medsecure.example")),
])
def test_a_raw_socket_scanner_says_nothing_for_a_name_resolving_in_an_excepted_range(monkeypatch, caplog,
                                                                                      addon, call):
    mod = load_core_addon(addon)
    _patch_run(monkeypatch, mod, stdout=b"<nmaprun></nmaprun>") if hasattr(mod, "subprocess") else None
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)

    def no_connection(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(socket, "create_connection", no_connection)
    _proxied(monkeypatch, "10.0.0.0/8")
    with caplog.at_level(logging.WARNING):
        call(mod)
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]


@pytest.mark.parametrize("addon,call", [
    ("nmap", lambda m: m.scan_host_ports("pacs.medsecure.example")),
    ("tls", lambda m: m.scan_host_tls("pacs.medsecure.example")),
    ("tls_grade", lambda m: m.scan_host_tls_grade("pacs.medsecure.example")),
])
def test_without_a_proxy_the_raw_socket_warning_resolves_nothing(monkeypatch, addon, call):
    mod = load_core_addon(addon)
    _patch_run(monkeypatch, mod, stdout=b"<nmaprun></nmaprun>") if hasattr(mod, "subprocess") else None
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)

    def no_connection(*a, **k):
        raise OSError("no route")

    def no_lookup(target):
        raise AssertionError(f"{target} resolved for a proxy warning without a proxy")

    monkeypatch.setattr(socket, "create_connection", no_connection)
    monkeypatch.setattr(scan_common, "resolve_first_ip", no_lookup)
    call(mod)


# ── the HTTP scanners ask the proxy for the name ─────────────────

_HTTP_SCANNERS = [
    ("security_headers", "scan_host_security_headers"),
    ("sensitive_files", "scan_host_sensitive_files"),
    ("js_analysis", "scan_host_js_analysis"),
]


def _run_scanner(monkeypatch, addon, function, ip, name):
    """Run a scanner whose every request lands in a recorder (standing in for
    the proxy when one applies, for the target otherwise)."""
    mod = load_core_addon(addon)
    requests = []

    def answer(request):
        requests.append(request)
        return httpx.Response(404)

    real = scan_client

    def recorded(host, locked_ip=None, **kw):
        recorder = httpx.MockTransport(answer)
        return real(host, locked_ip, transport=recorder, mounts={"https://": recorder, "http://": recorder}, **kw)

    monkeypatch.setattr(mod, "scan_client", recorded)
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: (ip, name))
    getattr(mod, function)(name)
    return requests


@pytest.mark.parametrize("addon,function", _HTTP_SCANNERS)
def test_through_the_proxy_a_scanner_asks_for_the_name(monkeypatch, addon, function):
    _proxied(monkeypatch)
    requests = _run_scanner(monkeypatch, addon, function, "93.184.216.34", "portal.medsecure.example")
    assert requests
    assert {r.url.host for r in requests} == {"portal.medsecure.example"}
    assert all(r.headers["Host"].split(":")[0] == "portal.medsecure.example" for r in requests)


@pytest.mark.parametrize("addon,function", _HTTP_SCANNERS)
@pytest.mark.parametrize("proxy", [True, False])
def test_directly_a_scanner_stays_on_the_locked_ip(monkeypatch, addon, function, proxy):
    if proxy:
        _proxied(monkeypatch, "medsecure.example")
    requests = _run_scanner(monkeypatch, addon, function, "10.4.2.1", "pacs.medsecure.example")
    assert requests
    assert {r.url.host for r in requests} == {"10.4.2.1"}
    assert {r.headers["Host"] for r in requests} == {"pacs.medsecure.example"}


def test_through_the_proxy_js_analysis_fetches_the_scripts_by_name(monkeypatch):
    _proxied(monkeypatch)
    mod = load_core_addon("js_analysis")
    requests = []

    def answer(request):
        requests.append(request)
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/app.js"></script>')
        return httpx.Response(200, text="var k = 1;")

    real = scan_client
    monkeypatch.setattr(mod, "scan_client", lambda host, ip=None, **kw: real(
        host, ip, mounts={"https://": httpx.MockTransport(answer)}, **kw))
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("93.184.216.34", "portal.medsecure.example"))
    mod.scan_host_js_analysis("portal.medsecure.example")
    assert [str(r.url) for r in requests] == ["https://portal.medsecure.example/",
                                              "https://portal.medsecure.example/app.js"]


@pytest.mark.parametrize("entry", [".medsecure.example", "*.medsecure.example"])
def test_an_exception_written_with_a_leading_dot_stays_on_the_locked_ip(monkeypatch, entry):
    # Pilot normalizes NO_PROXY; a deployment's own may not be. httpx goes
    # direct for ``.x``: bypasses_proxy must agree, or the name is resolved
    # again outside the locked IP (``*.x`` means the same to whoever wrote it).
    _proxied(monkeypatch, entry)
    assert scan_common.bypasses_proxy("portal.medsecure.example", "93.184.216.34")
    assert scan_common.target_request("portal.medsecure.example", "93.184.216.34", "https") == (
        "https://93.184.216.34", {"Host": "portal.medsecure.example"}, {"sni_hostname": "portal.medsecure.example"})


@pytest.mark.parametrize("scheme,expected", [
    ("https", ("https://93.184.216.34:8443", {"Host": "portal.medsecure.example:8443"},
               {"sni_hostname": "portal.medsecure.example"})),
    ("http", ("http://portal.medsecure.example:8443", {}, {})),
])
def test_the_target_request_follows_the_proxy_of_its_scheme(monkeypatch, scheme, expected):
    monkeypatch.setenv("HTTP_PROXY", _PROXY)  # plain HTTP only
    assert scan_common.target_request("portal.medsecure.example", "93.184.216.34", scheme, 8443) == expected


@pytest.mark.parametrize("port,expected", [(443, "https://[2001:db8::1]:443"), (None, "https://[2001:db8::1]")])
def test_the_target_request_brackets_an_ipv6_address(port, expected):
    # Unbracketed, httpx refuses the URL (InvalidURL, not a transport error):
    # the scanner swallowed it and an IPv6 host read as clean.
    assert scan_common.target_request("v6.medsecure.example", "2001:db8::1", "https", port) == (
        expected, {"Host": "v6.medsecure.example"}, {"sni_hostname": "v6.medsecure.example"})


def test_a_bracketed_ip_target_sends_no_sni():
    # An address is never a TLS server name.
    assert scan_common.target_request("[2001:db8::1]", "2001:db8::1", "https") == (
        "https://[2001:db8::1]", {"Host": "[2001:db8::1]"}, {})


def test_an_ipv6_exception_with_a_port_exempts_its_address(monkeypatch):
    _proxied(monkeypatch, "[fd00::1]:443")
    assert scan_common.bypasses_proxy("v6.medsecure.example", "fd00::1")


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
                seen.append(conn.recv(4096).decode(errors="replace").split("\r\n")[0])
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://scan:s3cret@127.0.0.1:{srv.getsockname()[1]}"
    monkeypatch.setenv("HTTPS_PROXY", url)
    monkeypatch.setenv("HTTP_PROXY", url)
    yield seen
    srv.close()


def test_the_proxy_is_asked_for_the_name_of_the_scanned_host(fake_proxy, monkeypatch):
    mod = load_core_addon("security_headers")
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("93.184.216.34", "portal.medsecure.example"))
    assert mod.scan_host_security_headers("portal.medsecure.example") == []
    assert fake_proxy == ["CONNECT portal.medsecure.example:443 HTTP/1.1"]


def test_sensitive_files_asks_the_proxy_for_the_name_on_both_schemes(fake_proxy, monkeypatch):
    mod = load_core_addon("sensitive_files")
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("93.184.216.34", "portal.medsecure.example"))
    mod.scan_host_sensitive_files("portal.medsecure.example")
    assert fake_proxy[:2] == ["CONNECT portal.medsecure.example:443 HTTP/1.1",
                              "GET http://portal.medsecure.example/ HTTP/1.1"]


def test_a_gateway_error_of_the_proxy_does_not_hide_its_refused_connect(fake_proxy, monkeypatch):
    # The proxy refuses the CONNECT, then answers the forwarded plain-HTTP
    # request with its own 502: that is not the target answering.
    mod = load_core_addon("sensitive_files")
    monkeypatch.setattr(mod, "_resolve_safe_target", lambda t: ("93.184.216.34", "portal.medsecure.example"))
    scan_common.take_proxy_failures()
    assert mod.scan_host_sensitive_files("portal.medsecure.example") == []
    assert scan_common.take_proxy_failures() == [
        ("portal.medsecure.example", "127.0.0.1", "ProxyError: 502 Bad Gateway")]


def test_an_unreachable_proxy_is_the_proxys(monkeypatch):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
    scan_common.take_proxy_failures()
    with scan_client("portal.medsecure.example", "93.184.216.34", timeout=2) as c:
        with pytest.raises(httpx.ConnectError):
            c.get("https://portal.medsecure.example/")
    assert scan_common.take_proxy_failures() == [("portal.medsecure.example", "127.0.0.1", "ConnectError")]


def test_a_name_next_to_an_excepted_domain_goes_through_the_proxy(fake_proxy, monkeypatch):
    # The URL now carries the name: httpx's own NO_PROXY match on it must
    # agree with bypasses_proxy (a domain covers its subdomains, no suffix).
    monkeypatch.setenv("NO_PROXY", "medsecure.example")
    with scan_client("xmedsecure.example", "127.0.0.1", timeout=5) as c:
        with pytest.raises(httpx.ProxyError):
            c.get("https://xmedsecure.example/")
    assert fake_proxy == ["CONNECT xmedsecure.example:443 HTTP/1.1"]


def test_the_proxied_transport_keeps_verify(monkeypatch):
    _proxied(monkeypatch)
    with scan_client("portal.medsecure.example", "93.184.216.34", verify=False) as c:
        transport = c._transport_for_url(httpx.URL("https://portal.medsecure.example/"))
        assert transport is not c._transport
        assert transport._pool._ssl_context.verify_mode == ssl.CERT_NONE


# ── which errors are the proxy's ─────────────────────────────────

def _fail_through(scheme, error, message="failure"):
    def fail(request):
        raise error(message, request=request)

    scan_common.take_proxy_failures()
    with scan_client("portal.medsecure.example", "93.184.216.34",
                     mounts={f"{scheme}://": httpx.MockTransport(fail)}) as c:
        with pytest.raises(error):
            c.get(f"{scheme}://portal.medsecure.example/")
    return scan_common.take_proxy_failures()


@pytest.fixture
def scripted_proxy(monkeypatch):
    """A local socket standing in for the proxy, which plays one script:
    ``silent`` never answers the CONNECT, ``close`` hangs up without
    answering; ``tunnel_*`` accept it (200), then the target behind the
    tunnel sends no TLS (``garbage``), hangs up (``close``) or says nothing
    (``silent``)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    script = {"play": "silent"}
    held = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.recv(4096)
            play = script["play"]
            if play.startswith("tunnel_"):
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if play == "tunnel_garbage":
                    conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            if play.endswith("silent"):
                held.append(conn)
            else:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://scan:s3cret@127.0.0.1:{srv.getsockname()[1]}"
    monkeypatch.setenv("HTTPS_PROXY", url)
    monkeypatch.setenv("HTTP_PROXY", url)
    yield script
    srv.close()
    for conn in held:
        conn.close()


def _scan_through(play, script):
    script["play"] = play
    scan_common.take_proxy_failures()
    with scan_client("portal.medsecure.example", "93.184.216.34", verify=False, timeout=1) as c:
        with pytest.raises(httpx.TransportError) as exc:
            c.get("https://portal.medsecure.example/")
    return type(exc.value).__name__, scan_common.take_proxy_failures()


@pytest.mark.parametrize("play,error", [("silent", "ReadTimeout"), ("close", "RemoteProtocolError")])
def test_a_proxy_silent_or_hanging_up_on_the_connect_is_the_proxys(scripted_proxy, play, error):
    assert _scan_through(play, scripted_proxy) == (error, [("portal.medsecure.example", "127.0.0.1", error)])


@pytest.mark.parametrize("play", ["tunnel_garbage", "tunnel_close", "tunnel_silent"])
def test_once_the_tunnel_is_open_an_error_is_the_targets_and_is_logged(scripted_proxy, caplog, play):
    with caplog.at_level(logging.INFO):
        error, failures = _scan_through(play, scripted_proxy)
    assert failures == []
    assert [r for r in caplog.records if "portal.medsecure.example" in r.getMessage() and error in r.getMessage()]


@pytest.mark.parametrize("error", [httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.ReadTimeout])
def test_in_plain_http_an_error_is_the_proxys(monkeypatch, error):
    _proxied(monkeypatch)
    assert _fail_through("http", error) == [("portal.medsecure.example", "proxy.medsecure.example", error.__name__)]


@pytest.mark.parametrize("error", [httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.ReadTimeout])
def test_on_a_tunnel_already_open_an_error_is_the_targets(monkeypatch, error):
    # A MockTransport emits no httpcore trace, as a reused keep-alive
    # connection does: no new connection, so the tunnel was open already.
    _proxied(monkeypatch)
    assert _fail_through("https", error) == []


def test_a_pool_timeout_is_the_proxys(monkeypatch):
    _proxied(monkeypatch)
    assert _fail_through("https", httpx.PoolTimeout) == [
        ("portal.medsecure.example", "proxy.medsecure.example", "PoolTimeout")]


def test_a_refused_connect_carries_the_proxys_status(monkeypatch):
    _proxied(monkeypatch)
    assert _fail_through("https", httpx.ProxyError, "502 Bad Gateway") == [
        ("portal.medsecure.example", "proxy.medsecure.example", "ProxyError: 502 Bad Gateway")]


# ── Chromium ─────────────────────────────────────────────────────

def test_chromium_gets_no_proxy_for_a_scheme_that_has_none(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    mod.scan_host_screenshot("portal.medsecure.example")
    https, http = launched
    assert https["proxy"]["server"] == "http://proxy.medsecure.example:3128"
    assert "proxy" not in http and "--no-proxy-server" in http["args"]


def test_chromium_reaches_a_name_resolving_in_an_excepted_range_directly(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch)
    _proxied(monkeypatch, "10.0.0.0/8")
    mod.scan_host_screenshot("pacs.medsecure.example")
    assert launched and all("proxy" not in kw and "--no-proxy-server" in kw["args"] for kw in launched)


def test_chromium_decodes_the_proxy_credentials(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://scan%40med:s3%3Acret@proxy.medsecure.example:3128")
    mod.scan_host_screenshot("portal.medsecure.example")
    assert launched[0]["proxy"]["username"] == "scan@med" and launched[0]["proxy"]["password"] == "s3:cret"


def test_chromium_gets_the_exceptions_in_its_own_syntax(monkeypatch):
    # An entry's port is dropped, as bypasses_proxy does: an excluded host
    # reaches no port through the proxy.
    mod, launched = _fake_playwright(monkeypatch)
    _proxied(monkeypatch, "lab.medsecure.local,192.0.2.7,10.0.0.0/8,::1,fd00::/8,intranet:8080")
    mod.scan_host_screenshot("portal.medsecure.example")
    assert launched and all(kw["proxy"]["bypass"] == (
        "lab.medsecure.local,.lab.medsecure.local,192.0.2.7,10.0.0.0/8,[::1],fd00::/8,intranet,.intranet")
        for kw in launched)


def test_chromium_reads_dotted_and_bracketed_exceptions_as_the_other_scanners_do(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch)
    _proxied(monkeypatch, ".medsecure.example,*.corp.example,[fd00::1]:443,10.0.0.1:8080")
    mod.scan_host_screenshot("portal.example.org")
    assert launched and all(kw["proxy"]["bypass"] == (
        "medsecure.example,.medsecure.example,corp.example,.corp.example,[fd00::1],10.0.0.1") for kw in launched)


def test_a_direct_screenshot_failure_is_not_blamed_on_a_proxy(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch, "net::ERR_PROXY_CONNECTION_FAILED")
    _proxied(monkeypatch, "medsecure.example")
    assert mod.scan_host_screenshot("portal.medsecure.example") == []


def test_a_screenshot_failure_names_the_proxy_chromium_was_given(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch, "net::ERR_TUNNEL_CONNECTION_FAILED")
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    [finding] = mod.scan_host_screenshot("portal.medsecure.example")
    assert finding["type"] == "scanner_error" and finding["evidence"]["proxy_host"] == "proxy.medsecure.example"


# ── nuclei ───────────────────────────────────────────────────────

@pytest.mark.parametrize("errors,blamed", [(5, True), (4, False)])
def test_nuclei_blames_the_proxy_only_when_every_request_failed(monkeypatch, errors, blamed):
    nuclei = load_core_addon("nuclei")
    stats = f'{{"errors":"{errors}","hosts":"1","requests":"5","total":"5"}}\n'.encode()
    _patch_run(monkeypatch, nuclei, stderr=stats)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    findings = nuclei.scan_nuclei("portal.medsecure.example")
    assert ([f["type"] for f in findings] == ["scanner_error"]) is blamed
