"""Unit tests for the `scanner_blocked` finding emitted by scan_nuclei
when a WAF / anti-bot massively rejects probes.

Locks the contract that an operator looking at a host behind RocketCDN
or Cloudflare doesn't conclude "zero findings = host is clean" when the
real story is "nuclei never reached most templates". The diagnostic
finding makes the scan invalidity visible.
"""
import os
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from conftest import load_core_addon  # noqa: E402

nuclei = load_core_addon("nuclei")


def _fake_proc(stdout: bytes = b"", stderr: bytes = b"", rc: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def _stats_line(requests: int, errors: int, matched: int = 0) -> bytes:
    return (
        f"[0:00:30] | Templates: 0 | Hosts: 1 | RPS: 10 | "
        f"Matched: {matched} | Errors: {errors} | Requests: {requests}/{requests} (100%)\n"
    ).encode()


class TestScannerBlocked:
    """`scan_nuclei` is called with a sphynx.studio-shaped target; we
    mock subprocess.run so the test is fast and offline. The mocked
    stderr carries a final stats line we control."""

    def _run(self, requests: int, errors: int, stdout: bytes = b"") -> list:
        with patch.object(nuclei, "shutil") as mock_shutil, \
             patch.object(nuclei.subprocess, "run") as mock_run:
            mock_shutil.which.return_value = "/usr/local/bin/nuclei"
            mock_run.return_value = _fake_proc(stdout=stdout, stderr=_stats_line(requests, errors))
            return nuclei.scan_nuclei("example.com")

    def test_high_error_rate_emits_finding(self):
        findings = self._run(requests=1000, errors=800)
        blocked = [f for f in findings if f.get("type") == "scanner_blocked"]
        assert len(blocked) == 1
        f = blocked[0]
        assert f["severity"] == "info"
        assert f["evidence"]["errors"] == 800
        assert f["evidence"]["requests"] == 1000
        assert f["evidence"]["error_rate_pct"] == 80
        assert "WAF" in f["description"] or "anti-bot" in f["description"]

    def test_low_error_rate_emits_nothing(self):
        findings = self._run(requests=1000, errors=50)
        assert not any(f.get("type") == "scanner_blocked" for f in findings)

    def test_small_scan_skips_threshold(self):
        """A 10-request scan with 8 errors is ambiguous (transient flap,
        not necessarily a WAF). Threshold requires >=50 requests."""
        findings = self._run(requests=10, errors=8)
        assert not any(f.get("type") == "scanner_blocked" for f in findings)

    def test_exactly_50pct_on_threshold_emits(self):
        """Exactly the threshold value should fire (it's a `>=` check)."""
        findings = self._run(requests=100, errors=50)
        blocked = [f for f in findings if f.get("type") == "scanner_blocked"]
        assert len(blocked) == 1
        assert blocked[0]["evidence"]["error_rate_pct"] == 50

    def test_missing_stderr_stats_does_not_crash(self):
        """A nuclei build / run that doesn't produce a stats line must
        not break the scanner — we just lose the diagnostic for that
        run."""
        with patch.object(nuclei, "shutil") as mock_shutil, \
             patch.object(nuclei.subprocess, "run") as mock_run:
            mock_shutil.which.return_value = "/usr/local/bin/nuclei"
            mock_run.return_value = _fake_proc(stdout=b"", stderr=b"some unrelated output\n")
            findings = nuclei.scan_nuclei("example.com")
        assert findings == []

    def test_blocked_coexists_with_real_findings(self):
        """If nuclei DID match some templates AND was blocked on others,
        both the real findings and the diagnostic finding must surface."""
        real = (
            b'{"template-id":"weak-tls-version","info":{"name":"Weak TLS",'
            b'"severity":"medium","description":"x"},"matched-at":"https://example.com"}\n'
        )
        findings = self._run(requests=2000, errors=1500, stdout=real)
        types = {f.get("type") for f in findings}
        assert "scanner_blocked" in types
        assert any(f.get("severity") == "medium" for f in findings)
