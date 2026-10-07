"""Unit tests for the ct_logs core add-on — lookalike certificate watch (FEAT-55).

Offline: crt.sh is replaced by a fake keyed on the query string. Locks:
- a certificate issued within the window on a lookalike flagged by
  typosquatting in the same scan yields one high finding per certificate
  (precertificate + final certificate share a serial → one finding);
- an older certificate, or no typosquatting finding, yields nothing;
- lookalikes never reach `discovered` (no auto-enrolment of attacker domains);
- the dispatcher runs typosquatting before ct_logs whatever the asset order,
  and passes (value, prior_findings, config) to a scanner declaring both.
"""
from datetime import datetime, timedelta, timezone

import httpx

from conftest import load_core_addon

from src import scanners

ct = load_core_addon("ct_logs")

_NOW = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)


def _iso(days_ago: int) -> str:
    return (_NOW - timedelta(days=days_ago)).isoformat()


def _typo(lookalike: str, original: str = "acme.example") -> dict:
    return {"scanner": "typosquatting", "type": "typosquat_domain", "severity": "medium",
            "target": lookalike, "evidence": {"original": original, "lookalike": lookalike}}


def _row(serial: str, names: str, days_ago: int, crt_id: int = 1) -> dict:
    return {"id": crt_id, "serial_number": serial, "name_value": names,
            "common_name": names.split("\n")[0], "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
            "not_before": _iso(days_ago), "not_after": _iso(days_ago - 90)}


def _fake_crt(monkeypatch, responses: dict[str, list]):
    calls: list[str] = []

    def fake(query, timeouts, max_bytes):
        calls.append(query)
        return responses.get(query, []), None

    monkeypatch.setattr(ct, "_fetch_crt_sh", fake)
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)
    monkeypatch.setattr(ct, "_safe_target", lambda d: d)
    return calls


def _certs(findings):
    return [f for f in findings if f["type"] == "ct_typosquat_cert"]


def test_recent_cert_on_lookalike_raises_one_finding_per_serial(monkeypatch):
    _fake_crt(monkeypatch, {
        "acme.example.net": [_row("0a1b", "acme.example.net\nwww.acme.example.net", 3, 10),
                             _row("0a1b", "acme.example.net", 3, 11)],   # precert, same serial
        "%25.acme.example.net": [_row("0c2d", "*.acme.example.net", 1, 12)],
    })
    findings, discovered = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    certs = _certs(findings)
    assert sorted(f["target"] for f in certs) == ["acme.example.net#0a1b", "acme.example.net#0c2d"]
    assert all(f["severity"] == "high" and f["scanner"] == "ct_logs" for f in certs)
    wild = next(f for f in certs if f["evidence"]["serial"] == "0c2d")
    assert wild["evidence"]["names"] == ["*.acme.example.net"]
    assert "acme.example.net" not in discovered


def test_cert_outside_window_is_ignored(monkeypatch):
    _fake_crt(monkeypatch, {"acme.example.net": [_row("0a1b", "acme.example.net", 45)]})
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert _certs(findings) == []
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")],
                                         {"ct_typosquat_window_days": 60})
    assert len(_certs(findings)) == 1


def test_no_typosquatting_finding_means_no_lookalike_query(monkeypatch):
    calls = _fake_crt(monkeypatch, {"%25.acme.example": [_row("01", "www.acme.example", 1)]})
    findings, discovered = ct.scan_domain_ct_logs("acme.example", [], {})
    assert calls == ["%25.acme.example"]
    assert _certs(findings) == []
    assert discovered == ["www.acme.example"]


def test_lookalike_of_another_domain_is_skipped(monkeypatch):
    calls = _fake_crt(monkeypatch, {})
    ct.scan_domain_ct_logs("acme.example", [_typo("other.example.net", original="other.example")], {})
    assert calls == ["%25.acme.example"]


def test_domain_query_failure_does_not_hide_lookalike_certs(monkeypatch):
    def fake(query, timeouts, max_bytes):
        if query == "%25.acme.example":
            return None, RuntimeError("502")
        return ([_row("0a1b", "acme.example.net", 2)] if query == "acme.example.net" else []), None

    monkeypatch.setattr(ct, "_fetch_crt_sh", fake)
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)
    monkeypatch.setattr(ct, "_safe_target", lambda d: d)
    findings, discovered = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert {f["type"] for f in findings} == {"ct_error", "ct_typosquat_cert"}
    assert discovered == []


def test_lookalike_watch_stops_after_repeated_crt_sh_failures(monkeypatch):
    calls: list[str] = []

    def fake(query, timeouts, max_bytes):
        calls.append(query)
        return ([], None) if query == "%25.acme.example" else (None, httpx.ConnectTimeout("timeout"))

    monkeypatch.setattr(ct, "_fetch_crt_sh", fake)
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)
    monkeypatch.setattr(ct, "_safe_target", lambda d: d)
    prior = [_typo(f"acme{i}.example.net") for i in range(10)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    assert _certs(findings) == []
    assert len(calls) == 1 + 2 * ct._MAX_LOOKALIKE_FAILURES


def test_an_oversized_lookalike_does_not_stop_the_watch(monkeypatch):
    def fake(query, timeouts, max_bytes):
        if query.startswith("acme9."):
            return [_row("0f", "acme9.example.net", 1)], None
        if query == "%25.acme.example" or query.startswith("%25."):
            return [], None
        return None, ValueError("crt.sh response exceeded 5242880 bytes")

    monkeypatch.setattr(ct, "_fetch_crt_sh", fake)
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)
    monkeypatch.setattr(ct, "_safe_target", lambda d: d)
    prior = [_typo(f"acme{i}.example.net") for i in range(10)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    assert [f["target"] for f in _certs(findings)] == ["acme9.example.net#0f"]


def test_finding_names_its_host_and_a_default_issuer(monkeypatch):
    row = _row("0a1b", "acme.example.net", 2)
    row["issuer_name"] = ""
    _fake_crt(monkeypatch, {"acme.example.net": [row]})
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    ev = _certs(findings)[0]["evidence"]
    assert ev["hostname"] == "acme.example.net"
    assert ev["issuer"] == "unknown"


def test_an_outage_counts_only_when_neither_query_answered(monkeypatch):
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)

    def refused_then_down(query, timeouts, max_bytes):
        if query.startswith("%25."):
            return None, httpx.ConnectError("down")
        return None, ValueError("too large")

    monkeypatch.setattr(ct, "_fetch_crt_sh", refused_then_down)
    certs, err = ct._lookalike_certs("acme.example.net")
    assert certs == {} and isinstance(err, httpx.HTTPError)

    def down_then_answered(query, timeouts, max_bytes):
        if query.startswith("%25."):
            return [], None
        return None, httpx.ConnectError("down")

    monkeypatch.setattr(ct, "_fetch_crt_sh", down_then_answered)
    certs, err = ct._lookalike_certs("acme.example.net")
    assert certs == {} and err is None


def test_window_days_is_clamped():
    assert ct._window_days({}) == 30
    assert ct._window_days({"ct_typosquat_window_days": 0}) == 1
    assert ct._window_days({"ct_typosquat_window_days": 9999}) == 365
    assert ct._window_days({"ct_typosquat_window_days": "x"}) == 30


def test_dispatcher_runs_typosquatting_before_ct_logs():
    assert scanners._order_by_dependencies(["ct_logs", "tls", "typosquatting"]) == \
        ["typosquatting", "ct_logs", "tls"]
    # already ordered, or producer disabled: untouched
    assert scanners._order_by_dependencies(["typosquatting", "ct_logs"]) == ["typosquatting", "ct_logs"]
    assert scanners._order_by_dependencies(["ct_logs", "tls"]) == ["ct_logs", "tls"]


def test_dispatcher_passes_prior_findings_and_config(monkeypatch):
    seen = {}

    def producer(value, config=None):
        return [_typo("acme.example.net")]

    def consumer(value, prior, config):
        seen["prior"], seen["config"] = prior, config
        return [], []

    monkeypatch.setitem(scanners.SCANNER_REGISTRY, "t_producer", {
        "label": "p", "kinds": {"domain"}, "callable": producer,
        "returns_discovered": False, "wants_config": True})
    monkeypatch.setitem(scanners.SCANNER_REGISTRY, "t_consumer", {
        "label": "c", "kinds": {"domain"}, "callable": consumer, "returns_discovered": True,
        "wants_prior_findings": True, "wants_config": True, "runs_after": ["t_producer"]})
    scanners.run_enabled_scanners("domain", "acme.example", ["t_consumer", "t_producer"],
                                  config={"ct_typosquat_window_days": 7})
    assert [f["target"] for f in seen["prior"]] == ["acme.example.net"]
    assert seen["config"] == {"ct_typosquat_window_days": 7}
