"""Unit tests for nuclei severity overrides and tech extraction."""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from conftest import load_core_addon

_apply_severity_override = load_core_addon("nuclei")._apply_severity_override
_extract_tech_from_prior = load_core_addon("cve_lookup")._extract_tech_from_prior


class TestSeverityOverride:
    def test_eol_upgraded(self):
        assert _apply_severity_override("msexchange-eol", "info") == "high"

    def test_ntlm_upgraded(self):
        assert _apply_severity_override("ntlm-directories", "info") == "medium"

    def test_iis_shortname_upgraded(self):
        assert _apply_severity_override("iis-shortname-detect", "info") == "medium"

    def test_unknown_template_unchanged(self):
        assert _apply_severity_override("unknown-template", "info") == "info"

    def test_already_higher_unchanged(self):
        assert _apply_severity_override("msexchange-eol", "critical") == "critical"

    def test_phpmyadmin_panel(self):
        assert _apply_severity_override("phpmyadmin-panel", "info") == "high"


class TestExtractTech:
    def test_nuclei_tech_detect(self):
        prior = [
            {"scanner": "nuclei", "type": "tech-detect",
             "evidence": {"template_id": "tech-detect", "matcher_name": "ms-iis", "extracted": None}},
        ]
        v, uv = _extract_tech_from_prior(prior)
        assert any("IIS" in p for p, _ in v) or any("IIS" in p for p in uv)

    def test_versioned_upgrade(self):
        prior = [
            {"scanner": "nuclei", "type": "tech-detect",
             "evidence": {"template_id": "tech-detect", "matcher_name": "ms-iis", "extracted": None}},
            {"scanner": "nuclei", "type": "microsoft-iis-version",
             "evidence": {"template_id": "microsoft-iis-version", "extracted": ["Microsoft-IIS/10.0"]}},
        ]
        v, uv = _extract_tech_from_prior(prior)
        assert ("Microsoft IIS", "10.0") in v
        assert "Microsoft IIS" not in uv

    def test_exchange_version(self):
        prior = [
            {"scanner": "nuclei", "type": "msexchange-eol",
             "evidence": {"template_id": "msexchange-eol", "extracted": ["15.1.2507.39"]}},
        ]
        v, uv = _extract_tech_from_prior(prior)
        assert any("Exchange" in p for p, _ in v)

    def test_legacy_techstack(self):
        prior = [
            {"type": "tech_fingerprint",
             "evidence": {"product": "nginx", "version": "1.24.0"}},
        ]
        v, uv = _extract_tech_from_prior(prior)
        assert ("nginx", "1.24.0") in v

    def test_empty(self):
        v, uv = _extract_tech_from_prior([])
        assert v == []
        assert uv == []
