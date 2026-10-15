"""Unit tests for the ct_logs core add-on — lookalike certificate watch (FEAT-55).

Offline: crt.sh is replaced by a fake keyed on the query string. Locks:
- a certificate issued within the window on a lookalike flagged by
  typosquatting in the same scan yields one high finding per certificate
  (precertificate + final certificate share a serial → one finding);
- an older certificate, or no typosquatting finding, yields nothing;
- lookalikes never reach `discovered` (no auto-enrolment of attacker domains);
- the dispatcher runs typosquatting before ct_logs whatever the asset order,
  and passes (value, prior_findings, config) to a scanner declaring both;
- BUG-103: a flagged lookalike whose certificates could not be checked
  (crt.sh failing on both queries or on one, watch stopped after repeated
  failures, time budget spent, over the per-scan cap) is named, with the
  cause, in one info finding ``ct_lookalikes_not_checked`` — never a scan
  that reads clean.
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
    monkeypatch.setattr(ct, "_safe_name", lambda d: d)
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
    monkeypatch.setattr(ct, "_safe_name", lambda d: d)
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
    monkeypatch.setattr(ct, "_safe_name", lambda d: d)
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
    monkeypatch.setattr(ct, "_safe_name", lambda d: d)
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
    certs, err, partial = ct._lookalike_certs("acme.example.net")
    assert certs == {} and isinstance(err, httpx.HTTPError) and partial is None

    def down_then_answered(query, timeouts, max_bytes):
        if query.startswith("%25."):
            return [], None
        return None, httpx.ConnectError("down")

    monkeypatch.setattr(ct, "_fetch_crt_sh", down_then_answered)
    certs, err, partial = ct._lookalike_certs("acme.example.net")
    assert certs == {} and err is None and isinstance(partial, httpx.HTTPError)


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


def _not_checked(findings):
    return [f for f in findings if f["type"] == "ct_lookalikes_not_checked"]


def _crt(monkeypatch, fake):
    monkeypatch.setattr(ct, "_fetch_crt_sh", fake)
    monkeypatch.setattr(ct.time, "sleep", lambda s: None)
    monkeypatch.setattr(ct, "_safe_name", lambda d: d)


def _bad_gateway(query):
    request = httpx.Request("GET", f"https://crt.sh/?q={query}")
    return httpx.HTTPStatusError("502 Bad Gateway", request=request,
                                 response=httpx.Response(502, request=request))


def test_a_crt_sh_outage_names_every_lookalike_not_checked(monkeypatch):
    # The case seen: crt.sh answers 502, the watch stops after three
    # lookalikes; the others were never asked about.
    _crt(monkeypatch, lambda q, t, m: (None, _bad_gateway(q)))
    prior = [_typo(f"acme{i}.example.net") for i in range(6)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    (nc,) = _not_checked(findings)
    assert nc["scanner"] == "ct_logs" and nc["severity"] == "info" and nc["target"] == "acme.example"
    ev = nc["evidence"]
    assert ev["original"] == "acme.example"
    assert ev["lookalikes"] == [f"acme{i}.example.net" for i in range(6)]
    assert ev["causes"] == ["crt.sh answered HTTP 502",
                            f"watch stopped after {ct._MAX_LOOKALIKE_FAILURES} crt.sh outages"]
    lines = nc["description"].split("\n")
    assert "- acme2.example.net: crt.sh answered HTTP 502" in lines
    assert f"- acme3.example.net: watch stopped after {ct._MAX_LOOKALIKE_FAILURES} crt.sh outages" in lines
    # The UI templates get each lookalike with its own cause.
    assert ev["checks"][2] == "acme2.example.net: crt.sh answered HTTP 502"
    assert ev["checks"][3] == f"acme3.example.net: watch stopped after {ct._MAX_LOOKALIKE_FAILURES} crt.sh outages"


def test_an_unreachable_crt_sh_is_named_as_such(monkeypatch):
    _crt(monkeypatch, lambda q, t, m: ([], None) if q == "%25.acme.example"
         else (None, httpx.ConnectTimeout("timeout")))
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert _not_checked(findings)[0]["evidence"]["causes"] == ["crt.sh unreachable (ConnectTimeout)"]


def test_a_lookalike_with_one_query_failed_is_not_checked(monkeypatch):
    # The subdomain query is the one that finds test.<lookalike>: its
    # failure is not covered by the exact one answering.
    def fake(query, timeouts, max_bytes):
        if query == "%25.acme.example.net":
            return None, _bad_gateway(query)
        return [], None

    _crt(monkeypatch, fake)
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == ["acme.example.net"]
    assert ev["causes"] == ["crt.sh answered HTTP 502 on one of its two queries"]


def test_certificates_found_on_a_partly_checked_lookalike_are_kept(monkeypatch):
    def fake(query, timeouts, max_bytes):
        if query == "acme.example.net":
            return [_row("0a1b", "acme.example.net", 2)], None
        if query == "%25.acme.example.net":
            return None, httpx.ConnectError("down")
        return [], None

    _crt(monkeypatch, fake)
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert [f["target"] for f in _certs(findings)] == ["acme.example.net#0a1b"]
    assert _not_checked(findings)[0]["evidence"]["lookalikes"] == ["acme.example.net"]


def test_an_oversized_lookalike_is_named_and_the_others_are_not(monkeypatch):
    def fake(query, timeouts, max_bytes):
        if query.endswith("acme0.example.net"):
            return None, ValueError("crt.sh response exceeded 5242880 bytes")
        return [], None

    _crt(monkeypatch, fake)
    prior = [_typo(f"acme{i}.example.net") for i in range(3)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == ["acme0.example.net"]
    assert ev["causes"] == ["crt.sh answer refused (crt.sh response exceeded 5242880 bytes)"]


def test_a_json_answer_that_is_not_a_list_is_not_a_check(monkeypatch):
    # crt.sh answering an error or a rate limit as a JSON object: nothing
    # was read, on both queries or on one.
    _crt(monkeypatch, lambda q, t, m: ([], None) if q == "%25.acme.example"
         else ({"error": "rate limited"}, None))
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == ["acme.example.net"]
    assert ev["causes"] == ["crt.sh answer refused (not a list)"]

    _crt(monkeypatch, lambda q, t, m: ({"error": "rate limited"}, None) if q == "%25.acme.example.net"
         else ([], None))
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert _not_checked(findings)[0]["evidence"]["causes"] == [
        "crt.sh answer refused (not a list) on one of its two queries"]


def test_a_refused_answer_between_outages_does_not_reset_the_count(monkeypatch):
    # outage, outage, JSON object, outage: three outages, the watch stops.
    def fake(query, timeouts, max_bytes):
        if query == "%25.acme.example":
            return [], None
        if query.endswith("acme2.example.net"):
            return {"error": "rate limited"}, None
        return None, httpx.ConnectError("down")

    _crt(monkeypatch, fake)
    prior = [_typo(f"acme{i}.example.net") for i in range(6)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    ev = _not_checked(findings)[0]["evidence"]
    stopped = f"watch stopped after {ct._MAX_LOOKALIKE_FAILURES} crt.sh outages"
    assert ev["checks"] == ["acme0.example.net: crt.sh unreachable (ConnectError)",
                            "acme1.example.net: crt.sh unreachable (ConnectError)",
                            "acme2.example.net: crt.sh answer refused (not a list)",
                            "acme3.example.net: crt.sh unreachable (ConnectError)",
                            f"acme4.example.net: {stopped}", f"acme5.example.net: {stopped}"]


def test_a_spent_time_budget_names_the_lookalikes_left(monkeypatch):
    _crt(monkeypatch, lambda q, t, m: ([], None))
    monkeypatch.setattr(ct, "_LOOKALIKE_BUDGET_S", -1.0)
    prior = [_typo(f"acme{i}.example.net") for i in range(2)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == ["acme0.example.net", "acme1.example.net"]
    assert ev["causes"] == ["watch time budget spent"]


def test_a_budget_spent_midway_names_only_the_lookalikes_left(monkeypatch):
    _crt(monkeypatch, lambda q, t, m: ([], None))
    clock = iter([0.0, 0.0, 0.0] + [1e9] * 10)   # deadline, then the first two checks in time
    monkeypatch.setattr(ct, "time", type("T", (), {"sleep": staticmethod(lambda s: None),
                                                    "monotonic": staticmethod(lambda: next(clock))}))
    prior = [_typo(f"acme{i}.example.net") for i in range(4)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == ["acme2.example.net", "acme3.example.net"]


def test_lookalikes_over_the_cap_are_named(monkeypatch):
    _crt(monkeypatch, lambda q, t, m: ([], None))
    prior = [_typo(f"acme{i}.example.net") for i in range(ct._MAX_LOOKALIKES + 2)]
    findings, _ = ct.scan_domain_ct_logs("acme.example", prior, {})
    ev = _not_checked(findings)[0]["evidence"]
    assert ev["lookalikes"] == [f"acme{i}.example.net" for i in range(ct._MAX_LOOKALIKES, ct._MAX_LOOKALIKES + 2)]
    assert ev["causes"] == [f"over the {ct._MAX_LOOKALIKES} lookalikes checked per scan"]


def test_every_lookalike_checked_gives_no_not_checked_finding(monkeypatch):
    _fake_crt(monkeypatch, {"acme.example.net": [_row("0a1b", "acme.example.net", 3)]})
    findings, _ = ct.scan_domain_ct_logs("acme.example", [_typo("acme.example.net")], {})
    assert _not_checked(findings) == [] and len(_certs(findings)) == 1
    findings, _ = ct.scan_domain_ct_logs("acme.example", [], {})
    assert _not_checked(findings) == []
