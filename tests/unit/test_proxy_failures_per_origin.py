"""BUG-99 — a proxy failure is tracked per origin of the scanned target.

Locks, with the network replaced:
  - an answer on one origin (scheme, port) of the target does not hide the
    proxy refusing another one: the target's root answered, its script on
    another port or scheme was refused, and that is reported;
  - an answer on the same origin clears an earlier failure, not a later
    one (a probe of the root does not cover the requests made after it);
  - origins a scanner tries as equivalents (``alternative_origins``: https,
    then http as a fallback) are one: one answering is enough, all refused
    is one failure;
  - sensitive_files and takeover try https then http as equivalents;
  - one finding per target, naming the refused origin;
  - js_analysis reports the target's own script refused on another port.
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
from src.scan_common import alternative_origins, scan_client  # noqa: E402

_PROXY = "http://scan:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
_TARGET = "portal.medsecure.example"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port=0, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))])
    scan_common.take_proxy_failures()


def _proxy_refusing(*refused):
    """A transport standing in for the proxy, failing the origins listed as
    ``scheme:port``: it refuses the CONNECT on https; on plain HTTP it cannot
    be reached (a proxy refusing forwarded HTTP answers with a page, which
    reads as the target's)."""
    def answer(request):
        if f"{request.url.scheme}:{request.url.port or {'https': 443, 'http': 80}[request.url.scheme]}" in refused:
            if request.url.scheme == "http":
                raise httpx.ConnectError("connection refused", request=request)
            raise httpx.ProxyError("403 Forbidden", request=request)
        return httpx.Response(200, text="ok")
    transport = httpx.MockTransport(answer)
    return {"https://": transport, "http://": transport}


def _fetch(*urls, refused=()):
    with scan_client(_TARGET, "93.184.216.34", mounts=_proxy_refusing(*refused)) as c:
        for url in urls:
            try:
                c.get(url)
            except httpx.HTTPError:
                pass


def test_a_refusal_on_another_port_is_not_hidden_by_the_root():
    _fetch(f"https://{_TARGET}/", f"https://{_TARGET}:8443/a.js", refused=("https:8443",))
    assert scan_common.take_proxy_failures() == [
        (_TARGET, "proxy.medsecure.example", "ProxyError: 403 Forbidden", f"https://{_TARGET}:8443")]


def test_a_refusal_on_another_scheme_is_not_hidden_by_the_root():
    _fetch(f"https://{_TARGET}/", f"http://{_TARGET}/a.js", refused=("http:80",))
    assert scan_common.take_proxy_failures() == [
        (_TARGET, "proxy.medsecure.example", "ConnectError", f"http://{_TARGET}")]


def test_a_refusal_on_the_locked_address_is_named_after_the_target():
    _fetch("https://93.184.216.34:8443/a.js", refused=("https:8443",))
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}:8443"]
    # and an answer by name clears a failure by address, on the same origin
    calls = []

    def flaky(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ProxyError("502 Bad Gateway", request=request)
        return httpx.Response(200)

    with scan_client(_TARGET, "93.184.216.34", mounts={"https://": httpx.MockTransport(flaky)}) as c:
        for url in ("https://93.184.216.34/", f"https://{_TARGET}/"):
            try:
                c.get(url)
            except httpx.HTTPError:
                pass
    assert scan_common.take_proxy_failures() == []


def test_an_ipv6_target_origin_is_bracketed():
    with scan_client("2001:db8::1", "2001:db8::1", mounts=_proxy_refusing("https:8443")) as c:
        with pytest.raises(httpx.HTTPError):
            c.get("https://[2001:db8::1]:8443/a.js")
    assert [f[3] for f in scan_common.take_proxy_failures()] == ["https://[2001:db8::1]:8443"]


def test_each_refused_origin_of_one_client_is_kept():
    # :8443 then :9443 refused, then :8443 answers: :9443 is still reported.
    calls = []

    def answer(request):
        calls.append(request.url.port)
        if len(calls) <= 2:
            raise httpx.ProxyError("403 Forbidden", request=request)
        return httpx.Response(200)

    with scan_client(_TARGET, "93.184.216.34", mounts={"https://": httpx.MockTransport(answer)}) as c:
        for port in (8443, 9443, 8443):
            try:
                c.get(f"https://{_TARGET}:{port}/a.js")
            except httpx.HTTPError:
                pass
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}:9443"]


def test_an_answer_on_the_same_origin_clears_its_failure():
    calls = []

    def flaky(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ProxyError("502 Bad Gateway", request=request)
        return httpx.Response(200)

    with scan_client(_TARGET, "93.184.216.34", mounts={"https://": httpx.MockTransport(flaky)}) as c:
        for path in ("/a", "/b"):
            try:
                c.get(f"https://{_TARGET}{path}")
            except httpx.HTTPError:
                pass
    assert scan_common.take_proxy_failures() == []


def test_an_answer_before_a_failure_does_not_clear_it():
    # The root answered, then the proxy failed every later request there.
    calls = []

    def answer(request):
        calls.append(request)
        if len(calls) > 1:
            raise httpx.ProxyError("403 Forbidden", request=request)
        return httpx.Response(200)

    with scan_client(_TARGET, "93.184.216.34", mounts={"https://": httpx.MockTransport(answer)}) as c:
        for path in ("/", "/a"):
            try:
                c.get(f"https://{_TARGET}{path}")
            except httpx.HTTPError:
                pass
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}"]


def test_a_later_client_failing_an_origin_another_one_reached_is_reported():
    _fetch(f"https://{_TARGET}/")
    _fetch(f"https://{_TARGET}/a", refused=("https:443",))
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}"]


def test_two_clients_on_two_origins_of_one_target_are_tracked_apart():
    _fetch(f"https://{_TARGET}/")
    _fetch(f"https://{_TARGET}:8443/a.js", refused=("https:8443",))
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}:8443"]


@pytest.mark.parametrize("refused,expected", [
    (("https:443",), []),
    (("https:443", "http:80"), [(_TARGET, "proxy.medsecure.example", "ProxyError: 403 Forbidden",
                                 f"https://{_TARGET}")]),
])
def test_alternative_origins_need_one_answer(refused, expected):
    # https, then http as a fallback, in two clients as takeover does.
    with alternative_origins():
        for scheme in ("https", "http"):
            _fetch(f"{scheme}://{_TARGET}/", refused=refused)
    assert scan_common.take_proxy_failures() == expected


def test_an_answer_among_alternatives_clears_an_earlier_failure_of_its_origin():
    _fetch(f"https://{_TARGET}/", refused=("https:443",))
    with alternative_origins():
        _fetch(f"https://{_TARGET}/")
    assert scan_common.take_proxy_failures() == []


def test_alternatives_do_not_hide_a_refusal_made_after_them():
    with alternative_origins():
        _fetch(f"https://{_TARGET}/", f"http://{_TARGET}/", refused=("https:443",))
    _fetch(f"https://{_TARGET}:8443/a.js", refused=("https:8443",))
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}:8443"]


def test_one_finding_per_target_names_the_refused_origin(monkeypatch):
    from src import scanners

    def two_refused(target):
        _fetch(f"https://{_TARGET}/", f"https://{_TARGET}:8443/a.js", f"https://{_TARGET}:9443/b.js",
               refused=("https:8443", "https:9443"))
        return []

    monkeypatch.setitem(scanners.SCANNER_REGISTRY, "two_refused",
                        {"callable": two_refused, "kinds": ["host"], "returns_discovered": False})
    findings, _ = scanners.run_enabled_scanners("host", _TARGET, ["two_refused"])
    [finding] = findings
    assert finding["evidence"]["origin"] == f"https://{_TARGET}:8443"
    assert f"https://{_TARGET}:8443" in finding["description"]


def test_js_analysis_reports_its_own_script_refused_on_another_port(monkeypatch):
    mod = load_core_addon("js_analysis")
    real = scan_client

    def answer(request):
        if request.url.port == 8443:
            raise httpx.ProxyError("403 Forbidden", request=request)
        return httpx.Response(200, text=f'<script src="https://{_TARGET}:8443/app.js"></script>')

    transport = httpx.MockTransport(answer)
    monkeypatch.setattr(mod, "scan_client", lambda host, ip=None, **kw: real(
        host, ip, mounts={"https://": transport, "http://": transport}, **kw))
    assert mod.scan_host_js_analysis(_TARGET) == []
    assert scan_common.take_proxy_failures() == [
        (_TARGET, "proxy.medsecure.example", "ProxyError: 403 Forbidden", f"https://{_TARGET}:8443")]


def test_sensitive_files_reports_a_proxy_failing_after_its_probe(monkeypatch):
    mod = load_core_addon("sensitive_files")
    real = scan_client

    def answer(request):
        if request.url.path != "/":
            raise httpx.ProxyError("403 Forbidden", request=request)
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(answer)
    monkeypatch.setattr(mod, "scan_client", lambda host, ip=None, **kw: real(
        host, ip, mounts={"https://": transport, "http://": transport}, **kw))
    assert mod.scan_host_sensitive_files(_TARGET) == []
    assert [f[3] for f in scan_common.take_proxy_failures()] == [f"https://{_TARGET}"]


@pytest.mark.parametrize("refused,expected", [(("https:443",), []), (("https:443", "http:80"), [f"https://{_TARGET}"])])
def test_sensitive_files_falls_back_to_http_without_a_failure(monkeypatch, refused, expected):
    mod = load_core_addon("sensitive_files")
    real = scan_client
    monkeypatch.setattr(mod, "scan_client", lambda host, ip=None, **kw: real(
        host, ip, mounts=_proxy_refusing(*refused), **kw))
    mod.scan_host_sensitive_files(_TARGET)
    assert [f[3] for f in scan_common.take_proxy_failures()] == expected
