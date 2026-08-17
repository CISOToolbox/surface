"""Unit tests for the FEAT-14 `nmap_deep` scanner registry entry.

Locks the invariants from the FEAT-14 spec:

1. `nmap_deep` is registered and exposed by the scanners catalog for
   both `host` and `ip_range` kinds.
2. It is NOT activated by default (opt-in only — a full-port scan is
   heavy).
3. Its callable runs `scan_host_ports` with the existing `deep` profile
   (`-p-`), not a new profile.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from conftest import load_core_addon  # noqa: E402

from src import scanners  # noqa: E402

nmap = load_core_addon("nmap")


class TestNmapDeepRegistry:
    def test_registered(self):
        assert "nmap_deep" in scanners.SCANNER_REGISTRY
        meta = scanners.SCANNER_REGISTRY["nmap_deep"]
        assert meta["kinds"] == {"host", "ip_range"}
        assert meta["returns_discovered"] is False

    def test_exposed_for_host_and_ip_range(self):
        host_names = {s["name"] for s in scanners.available_scanners_for_kind("host")}
        range_names = {s["name"] for s in scanners.available_scanners_for_kind("ip_range")}
        assert "nmap_deep" in host_names
        assert "nmap_deep" in range_names

    def test_opt_in_not_default(self):
        for kind, defaults in scanners.DEFAULT_SCANNERS_BY_KIND.items():
            assert "nmap_deep" not in defaults, f"nmap_deep must be opt-in, found in {kind} defaults"

    def test_callable_uses_deep_profile(self):
        with patch.object(nmap, "scan_host_ports", return_value=[]) as mocked:
            nmap.SURFACE_SCANNERS["nmap_deep"]["callable"]("10.0.0.0/24")
        mocked.assert_called_once_with("10.0.0.0/24", profile="deep")
