"""BUG-94 — nuclei, the screenshot browser and the raw-socket scanners with the proxy.

nuclei reads no HTTP(S)_PROXY: it proxies through its ``-proxy`` flag only, so
every nuclei scan went out directly. Chromium follows ``*_proxy`` but drops a
``user:pass@`` in it. nmap, the TLS checks and the SMB scanner open raw
sockets, which an HTTP proxy cannot carry. Locks:
  - nuclei gets the proxy that applies to the target, through a 0600 file
    removed afterwards (the URL may carry credentials), with ``-pi``; none for
    a target in the exceptions, by name or by the address it resolves to;
  - nuclei with a proxy it cannot reach (exit 1, "all proxies are dead") or
    that fails every request (its JSON stats) is logged, and the former is an
    error finding rather than a clean scan;
  - Chromium gets the proxy explicitly, credentials included, or
    ``--no-proxy-server`` for a target in the exceptions;
  - the raw-socket scanners log that they go direct when a proxy applies,
    and only then: not for a target in the exceptions;
  - a nuclei failure unrelated to the proxy is not blamed on it, and its
    output is still read; a partial failure through the proxy is not "every
    request failed";
  - the -proxy file never outlives a failure to write it.
"""
from __future__ import annotations

import logging
import os
import socket
import stat
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import load_core_addon  # noqa: E402

_PROXY = "http://scan:s3cret@proxy.medsecure.example:3128"
_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy")
_ADDRESSES = {"portal.medsecure.example": "93.184.216.34", "pacs.medsecure.example": "10.4.2.1"}
_DEAD = b'[FTL] Program exiting: cause="all proxies are dead got : dial tcp 127.0.0.1:9: connect: connection refused"\n'
_ALL_FAILED = b'{"errors":"2","hosts":"1","matched":"0","requests":"1","total":"1"}\n'


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ADDRESSES.get(host, host), 0))])


def _patch_run(monkeypatch, mod, rc=0, stdout=b"", stderr=b""):
    """Replace the binary call; record argv and the -proxy file as it was
    during the call (the scanner removes it afterwards)."""
    seen: dict = {}

    def run(args, **_kw):
        seen["args"] = list(args)
        if "-proxy" in args:
            path = args[args.index("-proxy") + 1]
            seen.update(path=path, mode=stat.S_IMODE(os.stat(path).st_mode), proxy=open(path).read().strip())
        return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)
    monkeypatch.setattr(mod.subprocess, "run", run)
    return seen


@pytest.fixture
def nuclei(monkeypatch):
    return load_core_addon("nuclei")


def test_nuclei_goes_through_the_proxy(nuclei, monkeypatch):
    seen = _patch_run(monkeypatch, nuclei)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    nuclei.scan_nuclei("portal.medsecure.example")
    assert seen["proxy"] == _PROXY and seen["mode"] == 0o600 and "-pi" in seen["args"]
    assert not any("s3cret" in a for a in seen["args"])
    assert not os.path.exists(seen["path"])


@pytest.mark.parametrize("no_proxy,target", [
    ("medsecure.example", "portal.medsecure.example"),   # by name
    ("10.0.0.0/8", "pacs.medsecure.example"),            # by the address it resolves to
    ("10.4.2.1", "10.4.2.1"),
])
def test_nuclei_reaches_a_target_in_the_exceptions_directly(nuclei, monkeypatch, no_proxy, target):
    seen = _patch_run(monkeypatch, nuclei)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", no_proxy)
    nuclei.scan_nuclei(target)
    assert "-proxy" not in seen["args"]


def test_nuclei_without_a_proxy_goes_direct(nuclei, monkeypatch):
    seen = _patch_run(monkeypatch, nuclei)
    nuclei.scan_nuclei("portal.medsecure.example")
    assert "-proxy" not in seen["args"]


def test_the_proxy_file_is_removed_when_nuclei_times_out(nuclei, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    paths = []

    def timeout(args, **_kw):
        paths.append(args[args.index("-proxy") + 1])
        raise nuclei.subprocess.TimeoutExpired(args, 1)

    _patch_run(monkeypatch, nuclei)
    monkeypatch.setattr(nuclei.subprocess, "run", timeout)
    [finding] = nuclei.scan_nuclei("portal.medsecure.example")
    assert finding["type"] == "scanner_timeout" and paths and not os.path.exists(paths[0])


def test_a_dead_proxy_is_logged_and_is_an_error_not_a_clean_scan(nuclei, monkeypatch, caplog):
    _patch_run(monkeypatch, nuclei, rc=1, stderr=_DEAD)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with caplog.at_level(logging.WARNING):
        findings = nuclei.scan_nuclei("portal.medsecure.example")
    assert [f["type"] for f in findings] == ["scanner_error"]
    warned = [r.getMessage() for r in caplog.records if "proxy" in r.getMessage()]
    assert warned and "proxy.medsecure.example" in warned[0] and "s3cret" not in warned[0]


def test_a_nuclei_failure_unrelated_to_the_proxy_is_not_blamed_on_it(nuclei, monkeypatch, caplog):
    line = (b'{"template-id":"exposed-env","info":{"name":"Exposed .env","severity":"high"},'
            b'"matched-at":"https://portal.medsecure.example/.env","host":"portal.medsecure.example"}\n')
    _patch_run(monkeypatch, nuclei, rc=1, stdout=line, stderr=b"[FTL] Could not run nuclei: no templates provided\n")
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with caplog.at_level(logging.WARNING):
        findings = nuclei.scan_nuclei("portal.medsecure.example")
    assert not [f for f in findings if "proxy" in f["title"]]
    assert any(f.get("severity") == "high" for f in findings)
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]


def test_a_partial_failure_through_the_proxy_is_not_every_request(nuclei, monkeypatch, caplog):
    _patch_run(monkeypatch, nuclei, stderr=b'{"errors":"3","hosts":"1","matched":"0","requests":"10","total":"10"}\n')
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with caplog.at_level(logging.WARNING):
        nuclei.scan_nuclei("portal.medsecure.example")
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]


def test_the_stats_are_the_last_json_line_that_has_them(nuclei):
    stderr = '{"errors":"2","requests":"4"}\n{"level":"info","msg":"done"}\n'
    assert nuclei._nuclei_stats(stderr) == (4, 2)


def test_the_proxy_file_is_removed_when_writing_it_fails(nuclei, monkeypatch, tmp_path):
    _patch_run(monkeypatch, nuclei)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setattr(nuclei.tempfile, "tempdir", str(tmp_path))

    def disk_full(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(nuclei.os, "fdopen", disk_full)
    [finding] = nuclei.scan_nuclei("portal.medsecure.example")
    assert finding["type"] == "scanner_error" and not list(tmp_path.iterdir())


@pytest.mark.parametrize("stats", [_ALL_FAILED, b'{"errors":"30","hosts":"1","requests":"30","total":"30"}\n'])
def test_a_proxy_failing_every_request_is_logged_and_an_error_finding(nuclei, monkeypatch, caplog, stats):
    _patch_run(monkeypatch, nuclei, stderr=stats)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with caplog.at_level(logging.WARNING):
        findings = nuclei.scan_nuclei("portal.medsecure.example")
    assert [r for r in caplog.records if "proxy" in r.getMessage()]
    assert [f["type"] for f in findings] == ["scanner_error"]


def test_failing_requests_without_a_proxy_are_not_blamed_on_one(nuclei, monkeypatch, caplog):
    _patch_run(monkeypatch, nuclei, stderr=_ALL_FAILED)
    with caplog.at_level(logging.WARNING):
        nuclei.scan_nuclei("portal.medsecure.example")
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]


def test_the_waf_detection_reads_the_json_stats(nuclei, monkeypatch):
    stats = b'{"errors":"80","hosts":"1","matched":"0","requests":"100","total":"100"}\n'
    _patch_run(monkeypatch, nuclei, stderr=stats)
    findings = nuclei.scan_nuclei("portal.medsecure.example")
    assert [f["type"] for f in findings] == ["scanner_blocked"]


def _fake_playwright(monkeypatch, error="stop here", answers=()):
    """Chromium that fails with ``error``, except for the schemes in
    ``answers``, which load and are captured."""
    launched = []

    class _Page:
        def set_default_timeout(self, ms):
            pass

        def goto(self, url, **kw):
            if not url.startswith(tuple(f"{s}://" for s in answers)):
                raise RuntimeError(error)

        def title(self):
            return "Portal"

        def screenshot(self, **kw):
            return b"png"

    class _Browser:
        def new_context(self, **kw):
            return types.SimpleNamespace(route=lambda *a: None, new_page=_Page)

        def close(self):
            pass

    class _Chromium:
        def launch(self, **kw):
            launched.append(kw)
            if not answers:
                raise RuntimeError(error)
            return _Browser()

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
    return mod, launched


@pytest.mark.parametrize("error", ["net::ERR_TUNNEL_CONNECTION_FAILED at https://portal",
                                   "net::ERR_PROXY_CONNECTION_FAILED at https://portal"])
def test_a_screenshot_the_proxy_failed_is_an_error_finding(monkeypatch, error):
    mod, launched = _fake_playwright(monkeypatch, error)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    findings = mod.scan_host_screenshot("portal.medsecure.example")
    assert [f["type"] for f in findings] == ["scanner_error"]
    assert findings[0]["evidence"]["proxy_host"] == "proxy.medsecure.example" and "s3cret" not in repr(findings)


def test_a_screenshot_captured_on_the_other_scheme_is_no_proxy_failure(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch, "net::ERR_TUNNEL_CONNECTION_FAILED", answers=("http",))
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    findings = mod.scan_host_screenshot("portal.medsecure.example")
    assert [f["type"] for f in findings] == ["screenshot"]


def test_a_screenshot_failing_without_a_proxy_is_not_blamed_on_one(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch, "net::ERR_CONNECTION_REFUSED")
    assert mod.scan_host_screenshot("portal.medsecure.example") == []


def test_chromium_gets_the_proxy_with_its_credentials(monkeypatch):
    mod, launched = _fake_playwright(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("HTTP_PROXY", _PROXY)
    mod.scan_host_screenshot("portal.medsecure.example")
    assert launched and all(kw.get("proxy") == {"server": "http://proxy.medsecure.example:3128",
                                                "username": "scan", "password": "s3cret"} for kw in launched)
    assert not any("--no-proxy-server" in kw["args"] or "s3cret" in " ".join(kw["args"]) for kw in launched)


@pytest.mark.parametrize("with_proxy", [True, False])
def test_chromium_reaches_a_target_in_the_exceptions_directly(monkeypatch, with_proxy):
    mod, launched = _fake_playwright(monkeypatch)
    if with_proxy:
        monkeypatch.setenv("HTTPS_PROXY", _PROXY)
        monkeypatch.setenv("HTTP_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", "medsecure.example")
    mod.scan_host_screenshot("portal.medsecure.example")
    assert launched and all("proxy" not in kw for kw in launched)
    assert all(("--no-proxy-server" in kw["args"]) is with_proxy for kw in launched)


@pytest.mark.parametrize("addon,call", [
    ("nmap", lambda m: m.scan_host_ports("portal.medsecure.example")),
    ("discovery", lambda m: m.scan_iprange_discovery("203.0.113.0/28")),
    ("tls", lambda m: m.scan_host_tls("portal.medsecure.example")),
    ("tls_grade", lambda m: m.scan_host_tls_grade("portal.medsecure.example")),
])
def test_a_raw_socket_scanner_says_it_goes_direct_when_a_proxy_applies(monkeypatch, caplog, addon, call):
    mod = load_core_addon(addon)
    _patch_run(monkeypatch, mod, stdout=b"<nmaprun></nmaprun>") if hasattr(mod, "subprocess") else None
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)

    def no_connection(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(socket, "create_connection", no_connection)
    with caplog.at_level(logging.WARNING):
        call(mod)
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with caplog.at_level(logging.WARNING):
        call(mod)
    warned = [r.getMessage() for r in caplog.records if "proxy" in r.getMessage()]
    assert warned and not any("s3cret" in m for m in warned)


@pytest.mark.parametrize("addon,call,no_proxy", [
    ("nmap", lambda m: m.scan_host_ports("portal.medsecure.example"), "medsecure.example"),
    ("discovery", lambda m: m.scan_iprange_discovery("203.0.113.0/28"), "203.0.113.0/24"),
    ("tls", lambda m: m.scan_host_tls("portal.medsecure.example"), "portal.medsecure.example"),
    ("tls_grade", lambda m: m.scan_host_tls_grade("portal.medsecure.example"), "medsecure.example:443"),
])
def test_a_raw_socket_scanner_says_nothing_for_a_target_in_the_exceptions(monkeypatch, caplog, addon, call,
                                                                           no_proxy):
    mod = load_core_addon(addon)
    _patch_run(monkeypatch, mod, stdout=b"<nmaprun></nmaprun>") if hasattr(mod, "subprocess") else None
    monkeypatch.setattr(mod, "_safe_target", lambda t: t)

    def no_connection(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(socket, "create_connection", no_connection)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    monkeypatch.setenv("NO_PROXY", no_proxy)
    with caplog.at_level(logging.WARNING):
        call(mod)
    assert not [r for r in caplog.records if "proxy" in r.getMessage()]
