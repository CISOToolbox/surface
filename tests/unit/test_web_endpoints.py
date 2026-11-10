"""A web scanner runs only on an open TCP port where a web server answers.

The dispatcher runs the port scans of the run first, probes the open TCP
ports they found, and hands the confirmed (scheme, port) to the web
scanners. These tests pin:

  1. the probe: any HTTP answer confirms a port, a failure does not, HTTPS
     first (HTTP first on 80), a proxy's refusal or gateway error on plain
     HTTP is no answer, a CONNECT the proxy refuses is no proxy failure once
     an endpoint is found;
  2. the dispatcher: web scanners after the port scans, only the open TCP
     ports probed (443 and 80 too under the outbound proxy), no web scanner
     without an endpoint, a finding when the run has no port scan or its
     port scan failed, the context cleared after the run;
  3. the scanners: each web endpoint is scanned (nuclei once per endpoint,
     its findings naming host:port off the default port).
"""
import os
import subprocess
import sys
from contextlib import contextmanager
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from conftest import load_core_addon  # noqa: E402

from src import scan_common, scanners  # noqa: E402

nuclei = load_core_addon("nuclei")


# ── 1. The probe ────────────────────────────────────────────────

class _Resp:
    def __init__(self, status):
        self.status_code = status


def _probe(answers, ports, proxy=""):
    """probe_web_endpoints with the target at 10.0.0.5 and a client whose
    answer per "scheme:port" is a status, or an exception when missing."""
    asked = []

    class _Client:
        def get(self, url, **kw):
            scheme, rest = url.split("://", 1)
            port = rest.split("/", 1)[0].rsplit(":", 1)[1]
            asked.append(f"{scheme}:{port}")
            if f"{scheme}:{port}" not in answers:
                raise ConnectionError("refused")
            return _Resp(answers[f"{scheme}:{port}"])

    @contextmanager
    def fake_client(*a, **kw):
        yield _Client()

    with patch.object(scan_common, "_resolve_safe_target", return_value=("10.0.0.5", "h.example")), \
            patch.object(scan_common, "scan_client", fake_client), \
            patch.object(scan_common, "_proxy_for", return_value=proxy), \
            patch.object(scan_common, "bypasses_proxy", return_value=not proxy):
        return scan_common.probe_web_endpoints("h.example", ports), asked


class TestProbe:
    def test_any_http_answer_confirms_a_port(self):
        found, _ = _probe({"https:443": 200, "https:8443": 403, "http:8080": 404}, [22, 443, 8080, 8443])
        assert found == [("https", 443), ("http", 8080), ("https", 8443)]

    def test_a_port_that_never_answers_http_is_not_web(self):
        found, asked = _probe({}, [22])
        assert found == []
        assert asked == ["https:22", "http:22"]

    def test_https_first_and_http_first_on_80(self):
        _, asked = _probe({"http:80": 301, "https:443": 200}, [80, 443])
        assert asked == ["http:80", "https:443"]

    def test_a_proxy_gateway_error_on_plain_http_is_no_answer(self):
        found, _ = _probe({"http:8080": 502}, [8080], proxy="http://proxy:3128")
        assert found == []

    def test_a_proxy_refusal_on_plain_http_is_no_answer(self):
        # Squid refuses a port outside Safe_ports (22) with its own 403.
        found, _ = _probe({"http:22": 403}, [22], proxy="http://proxy:3128")
        assert found == []
        # Directly, a 403 is the target's.
        found, _ = _probe({"http:22": 403}, [22])
        assert found == [("http", 22)]

    def test_proxy_refusals_are_no_failure_once_an_endpoint_is_found(self):
        def probe_failing(cause, found_on=None):
            scan_common.take_proxy_failures()

            @contextmanager
            def fake_client(host, *a, **kw):
                class _Client:
                    def get(self, url, **kw):
                        origin = url.split("/", 3)[0] + "//" + url.split("/", 3)[2]
                        if found_on and url.startswith(f"https://10.0.0.5:{found_on}/"):
                            return _Resp(200)
                        scan_common._record_proxy_outcome(host, {origin: ("proxy", cause)}, set())
                        raise ConnectionError("refused")
                yield _Client()

            with patch.object(scan_common, "_resolve_safe_target", return_value=("10.0.0.5", "h.example")), \
                    patch.object(scan_common, "scan_client", fake_client):
                scan_common.probe_web_endpoints("h.example", [22] + ([found_on] if found_on else []))
            return scan_common.take_proxy_failures()

        assert probe_failing("ProxyError: 403 Forbidden", found_on=443) == []
        # No endpoint at all: a proxy refusing everything is said, or the
        # web scans would vanish without a word.
        assert [f[2] for f in probe_failing("ProxyError: 503 Service Unavailable")] == [
            "ProxyError: 503 Service Unavailable"]
        assert [f[2] for f in probe_failing("ConnectError")] == ["ConnectError"]
        assert [f[2] for f in probe_failing("ProxyError: 407 Proxy Authentication Required")] == [
            "ProxyError: 407 Proxy Authentication Required"]

    def test_a_target_refused_by_validation_has_no_endpoint(self):
        with patch.object(scan_common, "_resolve_safe_target", side_effect=ValueError("internal")):
            assert scan_common.probe_web_endpoints("localhost", [443]) == []


# ── 2. The dispatcher ───────────────────────────────────────────

def _open_port(port, proto="tcp"):
    return {"scanner": "nmap", "type": "open_port", "severity": "info", "title": "", "description": "",
            "target": f"10.0.0.5:{port}", "evidence": {"port": port, "protocol": proto}}


class TestDispatcher:
    def setup_method(self):
        self.calls = []
        self.seen = {}

        def port_scan(value):
            self.calls.append("ports")
            return [_open_port(22), _open_port(443), _open_port(8443), _open_port(53, "udp")]

        def web(value):
            self.calls.append("web")
            self.seen["endpoints"] = scan_common.web_endpoints()
            return []

        def other(value):
            self.calls.append("other")
            return []

        scanners.SCANNER_REGISTRY["__ports"] = {"label": "p", "kinds": {"host"}, "callable": port_scan,
                                                "returns_discovered": False, "port_scan": True}
        scanners.SCANNER_REGISTRY["__web"] = {"label": "w", "kinds": {"host"}, "callable": web,
                                              "returns_discovered": False, "web": True}
        scanners.SCANNER_REGISTRY["__other"] = {"label": "o", "kinds": {"host"}, "callable": other,
                                                "returns_discovered": False}

    def teardown_method(self):
        for name in ("__ports", "__web", "__other"):
            scanners.SCANNER_REGISTRY.pop(name, None)
        scan_common._WEB_CTX.endpoints = None

    def test_web_scanners_get_the_confirmed_endpoints_of_the_open_tcp_ports(self):
        with patch.object(scanners, "probe_web_endpoints", return_value=[("https", 443), ("https", 8443)]) as probe:
            findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__web", "__other", "__ports"])
        probe.assert_called_once_with("h.example", [22, 443, 8443])
        assert self.calls == ["ports", "web", "other"]
        assert self.seen["endpoints"] == [("https", 443), ("https", 8443)]
        assert scan_common.web_endpoints() is None, "the context is the run's only"
        assert not any(f["type"] == "web_scans_skipped" for f in findings)

    def test_no_web_endpoint_no_web_scanner(self):
        with patch.object(scanners, "probe_web_endpoints", return_value=[]):
            findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web", "__other"])
        assert self.calls == ["ports", "other"]
        assert not any(f["type"] == "web_scans_skipped" for f in findings)

    def test_no_port_scan_no_web_scanner_and_a_finding_says_so(self):
        with patch.object(scanners, "probe_web_endpoints") as probe:
            findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__web", "__other"])
        probe.assert_not_called()
        assert self.calls == ["other"]
        skipped = [f for f in findings if f["type"] == "web_scans_skipped"]
        assert len(skipped) == 1
        assert skipped[0]["evidence"]["scanners"] == ["__web"]
        assert skipped[0]["severity"] == "info"

    def test_under_the_proxy_443_and_80_are_probed_too(self):
        with patch.object(scanners, "proxy_applies", return_value=True), \
                patch.object(scanners, "probe_web_endpoints", return_value=[("https", 443)]) as probe:
            scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web"])
        probe.assert_called_once_with("h.example", [22, 80, 443, 8443])
        # Nothing open (the port scan cannot go through the proxy): still probed.
        scanners.SCANNER_REGISTRY["__ports"]["callable"] = lambda v: []
        with patch.object(scanners, "proxy_applies", return_value=True), \
                patch.object(scanners, "probe_web_endpoints", return_value=[("https", 443)]) as probe:
            scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web"])
        probe.assert_called_once_with("h.example", [80, 443])
        assert self.seen["endpoints"] == [("https", 443)]

    def test_a_failed_port_scan_without_endpoint_says_so(self):
        scanners.SCANNER_REGISTRY["__ports"]["callable"] = lambda v: [{
            "scanner": "nmap", "type": "scanner_timeout", "severity": "info", "title": "", "description": "",
            "target": v, "evidence": {}}]
        with patch.object(scanners, "probe_web_endpoints") as probe:
            findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web"])
        probe.assert_not_called()
        skipped = [f for f in findings if f["type"] == "web_scans_skipped"]
        assert [f["evidence"] for f in skipped] == [{"scanners": ["__web"], "variant": "port_scan_failed"}]
        # Under the proxy an endpoint was found anyway: the web scans ran, no finding.
        with patch.object(scanners, "proxy_applies", return_value=True), \
                patch.object(scanners, "probe_web_endpoints", return_value=[("https", 443)]):
            findings, _ = scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web"])
        assert not any(f["type"] == "web_scans_skipped" for f in findings)

    def test_a_port_scan_finding_nothing_open_probes_nothing(self):
        self.calls.clear()
        scanners.SCANNER_REGISTRY["__ports"]["callable"] = lambda v: []
        with patch.object(scanners, "probe_web_endpoints") as probe:
            scanners.run_enabled_scanners("host", "h.example", ["__ports", "__web"])
        probe.assert_not_called()
        assert self.calls == []

    def test_the_registry_flags_the_real_scanners(self):
        reg = scanners.SCANNER_REGISTRY
        for name in ("nmap_quick", "nmap_standard", "nmap_deep"):
            assert reg[name].get("port_scan") is True, name
        for name in ("security_headers", "sensitive_files", "js_analysis"):
            assert reg[name].get("web") is True, name
        for name in ("tls", "tls_grade", "takeover"):
            assert not reg[name].get("web"), name


# ── 3. The scanners ─────────────────────────────────────────────

def _fake_proc(stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=stderr)


class TestNucleiPerEndpoint:
    def teardown_method(self):
        scan_common._WEB_CTX.endpoints = None

    def _run(self, endpoints, stderr=b""):
        scan_common._WEB_CTX.endpoints = endpoints
        with patch.object(nuclei, "shutil") as sh, patch.object(nuclei.subprocess, "run") as run:
            sh.which.return_value = "/usr/local/bin/nuclei"
            run.return_value = _fake_proc(stderr)
            findings = nuclei.scan_nuclei("example.com")
        urls = [c.args[0][c.args[0].index("-target") + 1] for c in run.call_args_list]
        return findings, urls

    def test_one_run_per_endpoint(self):
        _, urls = self._run([("https", 443), ("http", 8080)])
        assert urls == ["https://example.com", "http://example.com:8080"]

    def test_outside_a_dispatcher_run_https_on_the_name(self):
        _, urls = self._run(None)
        assert urls == ["https://example.com"]

    def test_findings_name_host_port_off_the_default_port(self):
        stats = b'{"requests":"100","errors":"90"}\n'
        findings, _ = self._run([("https", 443), ("https", 8443)], stats)
        targets = sorted(f["target"] for f in findings if f["type"] == "scanner_blocked")
        assert targets == ["example.com", "example.com:8443"]

    def test_the_error_rate_is_at_most_100(self):
        stats = b'{"requests":"1987","errors":"2203"}\n'
        findings, _ = self._run(None, stats)
        blocked = [f for f in findings if f["type"] == "scanner_blocked"]
        assert blocked[0]["evidence"]["error_rate_pct"] == 100
