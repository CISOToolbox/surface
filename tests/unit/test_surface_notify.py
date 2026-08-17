"""Unit tests for the FEAT-35 Surface notification helpers."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
os.environ.setdefault("JWT_SECRET", "x" * 64)
os.environ.setdefault("AUTH_MODE", "none")

from src.surface_notify import (  # noqa: E402
    SURFACE_PREF_DEFAULTS,
    render_alert_html,
    severity_passes,
    surface_prefs_of,
)


class TestSeverity:
    def test_info_tier_below_low(self):
        assert severity_passes("info", "low") is False  # info < low floor
        assert severity_passes("low", "low")
        assert not severity_passes("medium", "high")
        assert severity_passes("critical", "high")


class TestPrefs:
    def test_opt_in_default_off(self):
        # Surface is opt-in: no prefs = no alerts.
        assert SURFACE_PREF_DEFAULTS["alert_enabled"] is False
        assert surface_prefs_of(None)["alert_enabled"] is False

    def test_block_and_lang(self):
        p = surface_prefs_of({"lang": "en", "module_prefs": {"surface": {
            "alert_enabled": True, "alert_min_severity": "critical"}}})
        assert p["alert_enabled"] is True
        assert p["alert_min_severity"] == "critical"
        assert p["lang"] == "en"


class _F:
    def __init__(self, sev, title, target=""):
        self.severity = sev
        self.title = title
        self.target = target


class TestRendering:
    def test_escaping(self):
        html = render_alert_html("<h>.example.com", [_F("high", "<img onerror=x>")], "fr")
        assert "<img onerror" not in html
        assert "&lt;img onerror" in html
        assert "&lt;h&gt;.example.com" in html
