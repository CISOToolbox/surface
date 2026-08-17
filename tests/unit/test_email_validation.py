"""Unit tests for SMTP email validation (CRLF, header injection)."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from routes.reports import _validate_email, _parse_recipients, _validate_smtp_host


class TestValidateEmail:
    def test_valid(self):
        assert _validate_email("user@example.com") == "user@example.com"

    def test_crlf_rejected(self):
        with pytest.raises(ValueError):
            _validate_email("user@example.com\r\nBcc: evil@evil.com")

    def test_nul_rejected(self):
        with pytest.raises(ValueError):
            _validate_email("user@example.com\x00")

    def test_empty(self):
        with pytest.raises(ValueError):
            _validate_email("")

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            _validate_email("notanemail")


class TestParseRecipients:
    def test_single(self):
        assert _parse_recipients("a@b.com") == ["a@b.com"]

    def test_multiple(self):
        r = _parse_recipients("a@b.com, c@d.org")
        assert len(r) == 2

    def test_empty(self):
        with pytest.raises(ValueError):
            _parse_recipients("")


class TestValidateSmtpHost:
    def test_docker_sibling_blocked(self):
        with pytest.raises(ValueError):
            _validate_smtp_host("surface-db")

    def test_metadata_blocked(self):
        with pytest.raises(ValueError):
            _validate_smtp_host("169.254.169.254")

    def test_valid_host(self):
        result = _validate_smtp_host("smtp.gmail.com")
        assert result == "smtp.gmail.com"
