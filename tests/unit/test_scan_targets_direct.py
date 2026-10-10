"""BUG-94 — every add-on reaching the scanned target goes through scan_client.

``scan_common.scan_client(host, locked_ip)`` decides, target by target,
between the outbound proxy and a direct connection, and logs a failing proxy.
Locks: the add-ons that reach the scanned target open no httpx client of their
own; any other httpx call of an add-on belongs to one listed as calling only a
third-party service (NVD, Shodan, crt.sh…), which follows the proxy like the
module's other outbound calls.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]


def _clients(tree: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "httpx"
            and n.func.attr in ("Client", "AsyncClient", "get", "post", "head", "request", "stream")]


# Add-ons whose HTTP calls go to a third-party service, never to the scanned
# target: those follow the proxy like the module's other outbound calls.
_THIRD_PARTY = {
    "ct_logs": "certificate transparency logs",
    "typosquatting": "crt.sh",
    "tls": "crt.sh",
    "cloud_buckets": "the cloud storage providers",
    "cve_lookup": "NVD",
    "shodan": "the Shodan API",
    "defender": "Microsoft Graph",
}
_ADDONS = sorted((_ROOT / "addons").glob("*/*/*.py"))


_REACHING_THE_TARGET = ("security_headers", "sensitive_files", "js_analysis", "takeover")


def test_every_add_on_calling_httpx_is_a_scanner_through_scan_client_or_third_party():
    unknown = {f"{f.parent.parent.name}/{f.stem}": [c.lineno for c in _clients(ast.parse(f.read_text(encoding="utf-8")))]
               for f in _ADDONS}
    unknown = {k: v for k, v in unknown.items() if v and k.split("/")[1] not in _THIRD_PARTY}
    assert unknown == {}, "these call httpx directly: a scanner reaching its target goes " \
                          "through scan_common.scan_client; list a third-party caller in _THIRD_PARTY"


@pytest.mark.parametrize("addon", _REACHING_THE_TARGET)
def test_a_scanner_reaching_the_target_uses_scan_client(addon):
    src = (_ROOT / "addons" / "core" / addon / f"{addon}.py").read_text(encoding="utf-8")
    assert _clients(ast.parse(src)) == [] and "scan_client(" in src

