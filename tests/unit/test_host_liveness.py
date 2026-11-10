"""FEAT-68 — host liveness: a host silent for too long is flagged inactive.

Pins:
  1. the rule (src/host_liveness.py): the setting, the two dates, when a
     host is inactive;
  2. what proves an answer: nmap ports open or closed (never its "up" state,
     -Pn makes every host up), an HTTP answer through scan_client;
  3. the dispatcher: a host scan whose liveness scanner ran ends with the
     control record, applied to the asset by apply_scanner_state; a silence
     that is ours (an error of the scanning machine, a raw-socket scanner
     under an outbound proxy) proves nothing;
  4. the asset: a new target, a host re-enabled or left without a scanner
     that can see an answer forgets its dates; the setting is admin-only.
"""
import asyncio
import errno
import os
import socket
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:5999/surface_test")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("ENCRYPTION_KEY", "test-encryption-key-long-enough-1234")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import host_liveness, scan_common, scanners  # noqa: E402
from src.findings_dedup import apply_scanner_state  # noqa: E402
from src.models import MonitoredAsset  # noqa: E402
from src.routes import monitored as mon  # noqa: E402

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
               "http_proxy", "https_proxy", "all_proxy", "no_proxy")


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    for v in _PROXY_VARS:
        monkeypatch.delenv(v, raising=False)

NOW = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)


def _asset(**kw):
    base = dict(kind="host", enabled=True, value="h.example", config={},
                last_alive_at=None, unanswered_since=None)
    base.update(kw)
    return SimpleNamespace(**base)


# ── 1. The rule ─────────────────────────────────────────────────

class TestRule:
    def test_setting_defaults_to_7_and_rejects_out_of_bounds(self):
        assert host_liveness.parse_inactive_after_days(None) == 7
        assert host_liveness.parse_inactive_after_days("x") == 7
        assert host_liveness.parse_inactive_after_days("0") == 7
        assert host_liveness.parse_inactive_after_days("366") == 7
        assert host_liveness.parse_inactive_after_days("14") == 14

    def test_an_answer_clears_the_silence_a_silence_keeps_its_start(self):
        a = _asset()
        host_liveness.apply_liveness(a, False, NOW - timedelta(days=3))
        host_liveness.apply_liveness(a, False, NOW)
        assert a.unanswered_since == NOW - timedelta(days=3)
        host_liveness.apply_liveness(a, True, NOW)
        assert (a.last_alive_at, a.unanswered_since) == (NOW, None)

    def test_inactive_once_silent_for_the_setting(self):
        since = NOW - timedelta(days=7)
        assert host_liveness.inactive_since(_asset(unanswered_since=since), 7, NOW) == since
        assert host_liveness.inactive_since(_asset(unanswered_since=since), 8, NOW) is None
        assert host_liveness.inactive_since(_asset(), 7, NOW) is None

    def test_only_an_enabled_host(self):
        since = NOW - timedelta(days=30)
        assert host_liveness.inactive_since(_asset(unanswered_since=since, enabled=False), 7, NOW) is None
        assert host_liveness.inactive_since(_asset(unanswered_since=since, kind="domain"), 7, NOW) is None


# ── 2. What proves an answer ────────────────────────────────────

def _nmap_xml(ports="", extra=""):
    return (f'<nmaprun><host><status state="up"/><address addr="10.0.0.5"/>'
            f'<ports>{extra}{ports}</ports></host></nmaprun>')


def _noted(fn):
    scan_common._LIVENESS_CTX.hosts = set()
    try:
        fn()
        return scan_common.host_answered("h.example")
    finally:
        scan_common._LIVENESS_CTX.hosts = None


def _inconclusive(fn):
    scan_common._LIVENESS_CTX.inconclusive = set()
    try:
        fn()
        return scan_common.host_inconclusive("h.example")
    finally:
        scan_common._LIVENESS_CTX.inconclusive = None


def _get(handler, url="https://10.0.0.5/", direct=True):
    with patch.object(scan_common, "bypasses_proxy", return_value=direct):
        with scan_common.scan_client("h.example", "10.0.0.5", transport=httpx.MockTransport(handler)) as c:
            try:
                c.get(url)
            except httpx.TransportError:
                pass


def _refused(r):
    raise httpx.ConnectError("refused", request=r)


class TestAnswers:
    def test_nmap_open_or_closed_port_is_an_answer(self):
        open_ = '<port protocol="tcp" portid="22"><state state="open"/></port>'
        closed = '<extraports state="closed" count="99"/>'
        assert _noted(lambda: scan_common._parse_nmap_xml(_nmap_xml(ports=open_), "h.example"))
        assert _noted(lambda: scan_common._parse_nmap_xml(_nmap_xml(extra=closed), "h.example"))

    def test_nmap_all_filtered_is_no_answer_even_up(self):
        filtered = '<extraports state="filtered" count="100"/>'
        assert not _noted(lambda: scan_common._parse_nmap_xml(_nmap_xml(extra=filtered), "h.example"))

    def test_an_http_answer_through_scan_client(self):
        assert _noted(lambda: _get(lambda r: httpx.Response(404)))
        assert not _noted(lambda: _get(_refused))

    def test_a_connection_the_target_accepted_is_an_answer(self):
        # A slow answer: the TCP connection is up, the read times out.
        def slow(r):
            r.extensions["trace"]("connection.connect_tcp.complete", {})
            raise httpx.ReadTimeout("slow", request=r)
        assert _noted(lambda: _get(slow))

    def test_a_gateway_error_of_the_proxy_is_no_answer(self, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.medsecure.example:3128")
        assert not _noted(lambda: _get(lambda r: httpx.Response(502), url="http://h.example/", direct=False))
        assert _noted(lambda: _get(lambda r: httpx.Response(404), url="http://h.example/", direct=False))

    def test_an_error_of_the_scanning_machine_is_inconclusive(self):
        def no_route(r):
            raise httpx.ConnectError("no route", request=r) from OSError(errno.ENETUNREACH, "unreachable")
        assert _inconclusive(lambda: _get(no_route))
        assert not _inconclusive(lambda: _get(_refused))

    def test_tls_connection_reset_and_local_errors(self, monkeypatch):
        scan = scanners.SCANNER_REGISTRY["tls"]["callable"]
        tls = scan.__globals__  # the add-on's module namespace
        monkeypatch.setitem(tls, "_safe_target", lambda t: t)

        def connect(exc):
            def create_connection(*_a, **_k):
                raise exc
            monkeypatch.setattr(socket, "create_connection", create_connection)

        connect(ConnectionRefusedError())
        assert _noted(lambda: scan("h.example"))
        connect(socket.timeout())
        assert not _noted(lambda: scan("h.example"))
        assert not _inconclusive(lambda: scan("h.example"))
        connect(OSError(errno.ENETUNREACH, "unreachable"))
        assert _inconclusive(lambda: scan("h.example"))

        class _Sock:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _Sock())
        monkeypatch.setitem(tls, "_tls_ssl_context", lambda: SimpleNamespace(
            wrap_socket=lambda *a, **k: (_ for _ in ()).throw(OSError("handshake"))))
        assert _noted(lambda: scan("h.example"))

    def test_nmap_without_the_target_is_inconclusive(self):
        assert _inconclusive(lambda: scan_common._parse_nmap_xml("<nmaprun></nmaprun>", "h.example"))
        assert not _inconclusive(lambda: scan_common._parse_nmap_xml(_nmap_xml(), "h.example"))

    def test_outside_a_run_nothing_is_kept(self):
        scan_common.note_alive("h.example")
        assert not scan_common.host_answered("h.example")


# ── 3. The dispatcher ───────────────────────────────────────────

class TestDispatcher:
    def setup_method(self):
        self.answer = True
        self.result = []

        def probe(value):
            if self.answer:
                scan_common.note_alive(value)
            return list(self.result)

        scanners.SCANNER_REGISTRY["__probe"] = {"label": "p", "kinds": {"host", "domain"}, "callable": probe,
                                                "returns_discovered": False, "liveness": True}
        scanners.SCANNER_REGISTRY["__dns"] = {"label": "d", "kinds": {"host"}, "callable": lambda v: [],
                                              "returns_discovered": False}

    def teardown_method(self):
        scanners.SCANNER_REGISTRY.pop("__probe", None)
        scanners.SCANNER_REGISTRY.pop("__dns", None)

    def _liveness(self, kind="host", enabled=("__probe",)):
        findings, _ = scanners.run_enabled_scanners(kind, "h.example", list(enabled))
        return [f["evidence"]["liveness"] for f in findings if f["type"] == "scanner_state"]

    def test_a_host_that_answered(self):
        assert self._liveness() == [{"alive": True}]

    def test_a_host_that_did_not(self):
        self.answer = False
        assert self._liveness() == [{"alive": False}]

    def test_no_record_without_a_liveness_scanner_or_for_another_kind(self):
        assert self._liveness(enabled=("__dns",)) == []
        assert self._liveness(kind="domain") == []

    def test_a_scanner_failing_on_our_side_proves_nothing(self):
        self.answer = False
        self.result = [{"scanner": "__probe", "type": "scanner_error", "severity": "info",
                        "title": "", "description": "", "target": "h.example", "evidence": {}}]
        assert self._liveness() == []

    def test_the_record_is_applied_to_the_asset_and_never_persisted(self):
        self.answer = False
        findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__probe"])
        a = _asset()
        out, state = apply_scanner_state(a, findings)
        assert out == []
        assert a.unanswered_since is not None and a.last_alive_at is None
        assert not (state or {}).get("partial")

    def test_an_inconclusive_scanner_proves_nothing(self):
        self.answer = False
        scanners.SCANNER_REGISTRY["__probe"]["callable"] = lambda v: scan_common.note_inconclusive(v) or []
        assert self._liveness() == []
        # An answer it saw anyway still counts.
        scanners.SCANNER_REGISTRY["__probe"]["callable"] = lambda v: (
            scan_common.note_alive(v), scan_common.note_inconclusive(v)) and []
        assert self._liveness() == [{"alive": True}]
        scanners.SCANNER_REGISTRY["__probe"]["callable"] = lambda v: scan_common.note_inconclusive(v) or []
        # The mark is the scanner's own: another one that ran to its end counts.
        scanners.SCANNER_REGISTRY["__probe2"] = {"label": "p", "kinds": {"host"}, "callable": lambda v: [],
                                                 "returns_discovered": False, "liveness": True}
        try:
            assert self._liveness(enabled=("__probe", "__probe2")) == [{"alive": False}]
        finally:
            scanners.SCANNER_REGISTRY.pop("__probe2", None)

    def test_a_raw_socket_scanner_under_the_proxy_proves_no_silence(self, monkeypatch):
        scanners.SCANNER_REGISTRY["__probe"]["liveness"] = "direct"
        monkeypatch.setattr(scanners, "proxy_applies", lambda v: True)
        self.answer = False
        assert self._liveness() == []
        # What it sees still counts.
        self.answer = True
        assert self._liveness() == [{"alive": True}]
        # Without the proxy, its silence counts.
        self.answer = False
        monkeypatch.setattr(scanners, "proxy_applies", lambda v: False)
        assert self._liveness() == [{"alive": False}]

    def test_the_context_is_dropped_after_the_run(self):
        self._liveness()
        assert scan_common._LIVENESS_CTX.hosts is None
        assert scan_common._LIVENESS_CTX.inconclusive is None

    def test_the_real_scanners_are_flagged(self):
        reg = scanners.SCANNER_REGISTRY
        for name in ("security_headers", "sensitive_files", "js_analysis"):
            assert reg[name].get("liveness") is True, name
        for name in ("nmap_quick", "nmap_standard", "nmap_deep", "tls"):
            assert reg[name].get("liveness") == "direct", name


class TestNameGone:
    def setup_method(self):
        self.reason = "no_name"

        def probe(value):
            raise scan_common.UnresolvedTarget("gone", self.reason, value)

        scanners.SCANNER_REGISTRY["__probe"] = {"label": "p", "kinds": {"host"}, "callable": probe,
                                                "returns_discovered": False, "liveness": True}

    def teardown_method(self):
        scanners.SCANNER_REGISTRY.pop("__probe", None)

    def _liveness(self):
        findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__probe"])
        return [f["evidence"]["liveness"] for f in findings if f["type"] == "scanner_state"]

    def test_a_name_that_no_longer_exists_does_not_answer(self):
        assert self._liveness() == [{"alive": False}]
        self.reason = "no_address"
        assert self._liveness() == [{"alive": False}]

    def test_a_failed_lookup_proves_nothing(self):
        self.reason = "lookup_failed"
        assert self._liveness() == []


# ── 4. The asset ────────────────────────────────────────────────

def _user(role: str):
    return SimpleNamespace(id=uuid.uuid4(), email=f"{role}@medsecure.example", _module_role=role)


class _DB:
    def __init__(self, asset=None):
        self.asset = asset
        self.added = []

    async def get(self, model, _id):
        return self.asset if model is MonitoredAsset else None

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        return None

    async def refresh(self, _obj):
        return None


@pytest.fixture
def _no_log(monkeypatch):
    async def _log(*a, **k):
        return None
    monkeypatch.setattr(mon, "log_action", _log)
    monkeypatch.setattr(mon, "_validate", lambda kind, value: value)  # no DNS


@pytest.mark.usefixtures("_no_log")
class TestAssetDates:
    def _silent_host(self, **kw):
        base = dict(id=uuid.uuid4(), kind="host", value="h.example", enabled=True,
                    enabled_scanners=["nmap_quick"], tags=[], config={},
                    last_alive_at=NOW - timedelta(days=12), unanswered_since=NOW - timedelta(days=10))
        base.update(kw)
        return MonitoredAsset(**base)

    def _patch(self, asset, **fields):
        body = mon.MonitoredAssetUpdate(kind=asset.kind, value=asset.value, **fields)
        asyncio.run(mon.update_asset(asset.id, body, request=None, user=_user("admin"), db=_DB(asset)))
        return asset.unanswered_since, asset.last_alive_at

    def test_another_edit_keeps_them(self):
        a = self._silent_host()
        assert self._patch(a, label="MedSecure VPN") == (NOW - timedelta(days=10), NOW - timedelta(days=12))

    def test_a_new_target_forgets_them(self):
        a = self._silent_host()
        body = mon.MonitoredAssetUpdate(kind="host", value="other.example")
        asyncio.run(mon.update_asset(a.id, body, request=None, user=_user("admin"), db=_DB(a)))
        assert (a.unanswered_since, a.last_alive_at) == (None, None)

    def test_a_host_re_enabled_forgets_them(self):
        assert self._patch(self._silent_host(enabled=False), enabled=True) == (None, None)

    def test_no_scanner_left_that_sees_an_answer_forgets_them(self):
        dns_only = [n for n, m in scanners.SCANNER_REGISTRY.items()
                    if "host" in m["kinds"] and not m.get("liveness")][:1]
        assert dns_only
        assert self._patch(self._silent_host(), enabled_scanners=dns_only) == (None, None)


@pytest.mark.usefixtures("_no_log")
class TestSettingRoute:
    def _put(self, role):
        body = mon.LivenessSettings(inactive_after_days=14)
        db = _DB()
        out = asyncio.run(mon.put_liveness_settings(body, request=None, user=_user(role), db=db))
        return out, db

    def test_an_editor_cannot_change_it(self):
        with pytest.raises(HTTPException) as e:
            self._put("editor")
        assert e.value.status_code == 403

    def test_an_admin_can(self):
        out, db = self._put("admin")
        assert out["inactive_after_days"] == 14
        assert [(r.key, r.value) for r in db.added] == [(host_liveness.SETTING_KEY, "14")]

    def test_out_of_bounds_is_refused(self):
        for days in (0, 366):
            with pytest.raises(ValueError):
                mon.LivenessSettings(inactive_after_days=days)
