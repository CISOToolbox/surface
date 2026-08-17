"""Unit tests for the per-asset stealth scan mode.

Locks two invariants:

1. The thread-local context exposed by `_is_stealth()` is set by
   `run_enabled_scanners(stealth=True)` only for the duration of that
   call, and is reset to False on exit even when a scanner crashes.
2. `scan_nuclei` mutates its tuning AND argv only when the context
   says so — defaults stay defaults when stealth is off.
"""
import os
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from conftest import load_core_addon  # noqa: E402

from src import scanners  # noqa: E402

nuclei = load_core_addon("nuclei")
nmap = load_core_addon("nmap")


def _fake_proc(stdout: bytes = b"", stderr: bytes = b"", rc: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


class TestStealthContext:
    def teardown_method(self):
        # Tests share the module-level threading.local; reset to avoid
        # cross-test bleed if a test forgets to clear.
        scanners._STEALTH_CTX.on = False

    def test_default_is_off(self):
        assert scanners._is_stealth() is False

    def test_run_enabled_scanners_sets_then_clears(self):
        seen = {}

        def fake_callable(value):
            seen["during"] = scanners._is_stealth()
            return []

        scanners.SCANNER_REGISTRY["__test_probe"] = {
            "label": "test", "kinds": {"host"}, "callable": fake_callable,
            "returns_discovered": False,
        }
        try:
            scanners.run_enabled_scanners("host", "example.com", ["__test_probe"], stealth=True)
            assert seen["during"] is True
            assert scanners._is_stealth() is False, "context must be cleared after the call"
        finally:
            del scanners.SCANNER_REGISTRY["__test_probe"]

    def test_context_cleared_even_when_scanner_raises(self):
        def boom(value):
            raise RuntimeError("kaboom")

        scanners.SCANNER_REGISTRY["__test_boom"] = {
            "label": "test", "kinds": {"host"}, "callable": boom,
            "returns_discovered": False,
        }
        try:
            scanners.run_enabled_scanners("host", "example.com", ["__test_boom"], stealth=True)
            assert scanners._is_stealth() is False
        finally:
            del scanners.SCANNER_REGISTRY["__test_boom"]


class TestNucleiStealth:
    """When stealth context is set, scan_nuclei must drop rate/concurrency,
    add a browser UA header, and bump the subprocess timeout."""

    def teardown_method(self):
        scanners._STEALTH_CTX.on = False

    def _capture_nuclei_args(self, stealth: bool):
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["timeout"] = kwargs.get("timeout")
            return _fake_proc()

        with patch.object(nuclei, "shutil") as mock_shutil, \
             patch.object(nuclei.subprocess, "run", side_effect=fake_run):
            mock_shutil.which.return_value = "/usr/local/bin/nuclei"
            scanners._STEALTH_CTX.on = stealth
            try:
                nuclei.scan_nuclei("example.com")
            finally:
                scanners._STEALTH_CTX.on = False
        return captured

    def test_stealth_off_keeps_defaults(self):
        cap = self._capture_nuclei_args(stealth=False)
        args = cap["args"]
        # rate-limit and concurrency keep their env-default values (>=20)
        rate_idx = args.index("-rate-limit")
        conc_idx = args.index("-concurrency")
        assert int(args[rate_idx + 1]) >= 20
        assert int(args[conc_idx + 1]) >= 20
        assert "-H" not in args
        assert "-delay" not in args
        assert cap["timeout"] == 900

    def test_stealth_on_caps_rate_and_concurrency(self):
        cap = self._capture_nuclei_args(stealth=True)
        args = cap["args"]
        rate_idx = args.index("-rate-limit")
        conc_idx = args.index("-concurrency")
        assert int(args[rate_idx + 1]) <= 3
        assert int(args[conc_idx + 1]) <= 2

    def test_stealth_on_adds_browser_ua_and_delay(self):
        cap = self._capture_nuclei_args(stealth=True)
        args = cap["args"]
        assert "-H" in args
        ua_idx = args.index("-H")
        assert "User-Agent: Mozilla/5.0" in args[ua_idx + 1]
        assert "-delay" in args
        delay_idx = args.index("-delay")
        assert args[delay_idx + 1] == "1"

    def test_stealth_on_extends_subprocess_timeout(self):
        cap = self._capture_nuclei_args(stealth=True)
        # 1-hour cap in stealth, 15-min cap in normal mode
        assert cap["timeout"] == 3600


class TestNmapStealth:
    """nmap timing template flips from -T4 (aggressive) to -T2 (polite)
    when stealth is on. Subprocess timeout bumps proportionally so the
    longer scan can finish."""

    def teardown_method(self):
        scanners._STEALTH_CTX.on = False

    def _capture_nmap_args(self, stealth: bool):
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["timeout"] = kwargs.get("timeout")
            return _fake_proc(stdout=b"<nmaprun></nmaprun>")

        with patch.object(nmap, "shutil") as mock_shutil, \
             patch.object(nmap.subprocess, "run", side_effect=fake_run):
            mock_shutil.which.return_value = "/usr/local/bin/nmap"
            scanners._STEALTH_CTX.on = stealth
            try:
                nmap.scan_host_ports("example.com", profile="quick")
            finally:
                scanners._STEALTH_CTX.on = False
        return captured

    def test_stealth_off_uses_t4(self):
        cap = self._capture_nmap_args(stealth=False)
        assert "-T4" in cap["args"]
        assert "-T2" not in cap["args"]
        assert cap["timeout"] == 180

    def test_stealth_on_swaps_to_t2(self):
        cap = self._capture_nmap_args(stealth=True)
        assert "-T2" in cap["args"]
        assert "-T4" not in cap["args"]
        # quick profile default timeout 180 → 720 in stealth (×4)
        assert cap["timeout"] == 720
