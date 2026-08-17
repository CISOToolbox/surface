"""Unit tests for _resolve_safe_target — the SSRF allowlist guard.

Every scanner path depends on this function being correct. If it lets
a loopback, metadata, or docker-sibling address through, the entire
scan chain is compromised.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


def _resolve(target: str):
    from scanners import _resolve_safe_target
    return _resolve_safe_target(target)


class TestBlockedTargets:
    def test_loopback_127(self):
        with pytest.raises(ValueError):
            _resolve("127.0.0.1")

    def test_loopback_localhost(self):
        with pytest.raises(ValueError):
            _resolve("localhost")

    def test_metadata_aws(self):
        with pytest.raises(ValueError):
            _resolve("169.254.169.254")

    def test_metadata_alibaba(self):
        with pytest.raises(ValueError):
            _resolve("100.100.100.200")

    def test_docker_sibling_surface_db(self):
        with pytest.raises(ValueError):
            _resolve("surface-db")

    def test_docker_sibling_pilot_app(self):
        with pytest.raises(ValueError):
            _resolve("pilot-app")

    def test_docker_sibling_bare_pilot(self):
        with pytest.raises(ValueError):
            _resolve("pilot")

    def test_empty_target(self):
        with pytest.raises(ValueError):
            _resolve("")

    def test_too_long(self):
        with pytest.raises(ValueError):
            _resolve("a" * 254)

    def test_shell_injection_semicolon(self):
        with pytest.raises(ValueError):
            _resolve("example.com; rm -rf /")

    def test_shell_injection_backtick(self):
        with pytest.raises(ValueError):
            _resolve("example.com`id`")


class TestAllowedTargets:
    def test_public_ip(self):
        locked_ip, canonical = _resolve("8.8.8.8")
        assert canonical == "8.8.8.8"
        assert locked_ip == "8.8.8.8"

    def test_rfc1918_10(self):
        locked_ip, canonical = _resolve("10.0.0.1")
        assert canonical == "10.0.0.1"

    def test_rfc1918_192(self):
        locked_ip, canonical = _resolve("192.168.1.1")
        assert canonical == "192.168.1.1"

    def test_cidr_range(self):
        locked_ip, canonical = _resolve("192.168.1.0/24")
        assert canonical == "192.168.1.0/24"
        assert locked_ip is None

    def test_public_hostname(self):
        locked_ip, canonical = _resolve("example.com")
        assert canonical == "example.com"
        assert locked_ip is not None


class TestEdgeCases:
    def test_url_with_scheme_stripped(self):
        locked_ip, canonical = _resolve("https://example.com")
        assert canonical == "https://example.com"

    def test_ipv6_loopback(self):
        with pytest.raises(ValueError):
            _resolve("::1")
