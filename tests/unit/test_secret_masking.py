"""Unit tests for _mask_secret — secret truncation before DB storage."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from conftest import load_core_addon

_mask_secret = load_core_addon("js_analysis")._mask_secret


class TestMaskSecret:
    def test_critical_long_key(self):
        key = "AKIAIOSFODNN7EXAMPLE1234567890AB"
        masked = _mask_secret(key, "critical")
        assert "AKIA" in masked
        assert "90AB" in masked
        assert len(masked) < len(key)
        assert "IOSFODNN" not in masked

    def test_high_long_key(self):
        # Deliberately NOT shaped like a real provider token: a fixture
        # matching a known vendor key format trips GitHub push protection
        # on every push of this repo, for no test value.
        key = "notarealkey_abcdefghijklmnopqrstuvwx"
        masked = _mask_secret(key, "high")
        assert masked.startswith("nota")
        assert masked.endswith("uvwx")

    def test_medium_not_masked(self):
        val = "eyJhbGciOiJIUzI1NiJ9.payload.signature"
        result = _mask_secret(val, "medium")
        assert len(result) == min(200, len(val))

    def test_info_not_masked(self):
        val = "192.168.1.42"
        assert _mask_secret(val, "info") == val

    def test_short_critical_fully_masked(self):
        assert _mask_secret("short", "critical") == "***"

    def test_empty(self):
        assert _mask_secret("", "critical") == ""
