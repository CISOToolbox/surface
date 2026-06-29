"""TLS protocol/cipher grade scanner — Surface core add-on."""
from __future__ import annotations

import socket
import ssl
from typing import Any

from src.scan_common import (
    _safe_target, _tls_ssl_context,
)


# ═══════════════════════════════════════════════════════════════
# v0.3 — TLS protocol/cipher grade
# ═══════════════════════════════════════════════════════════════
#
# Beyond cert validity (already covered by scan_host_tls), grade the
# TLS handshake configuration: supported protocols, cipher families,
# Forward Secrecy. Qualys-lite, pure Python stdlib, one connection
# per protocol attempt.

_TLS_PROBE_VERSIONS = [
    ("TLSv1.3", "TLS 1.3"),
    ("TLSv1.2", "TLS 1.2"),
    ("TLSv1.1", "TLS 1.1 (deprecated)"),
    ("TLSv1",   "TLS 1.0 (deprecated)"),
    ("SSLv3",   "SSL 3.0 (POODLE)"),
]


def _try_tls_version(target: str, port: int, version_name: str) -> bool:
    """Return True if the server accepts a handshake for `version_name`."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force a single version via min/max when supported (3.10+)
        v_map = {
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1":   ssl.TLSVersion.TLSv1,
            "SSLv3":   ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None,
        }
        v = v_map.get(version_name)
        if v is None:
            return False
        try:
            ctx.minimum_version = v
            ctx.maximum_version = v
        except (ValueError, OSError):
            return False
        with socket.create_connection((target, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                return ssock.version() is not None
    except Exception:
        return False


def scan_host_tls_grade(target: str) -> list[dict[str, Any]]:
    """Probe each major TLS version and the negotiated cipher at the
    highest supported version. Emit one finding per insecure legacy
    version accepted + one summary with the overall grade."""
    target = _safe_target(target)
    port = 443

    # Quick reachability check — skip hosts that don't even answer 443
    try:
        with socket.create_connection((target, port), timeout=3):
            pass
    except Exception:
        return []

    supported: list[str] = []
    for vkey, _label in _TLS_PROBE_VERSIONS:
        if _try_tls_version(target, port, vkey):
            supported.append(vkey)

    # Inspect the best connection for cipher info
    best_cipher = ""
    best_protocol = ""
    try:
        ctx = _tls_ssl_context()
        with socket.create_connection((target, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                c = ssock.cipher()
                if c:
                    best_cipher = c[0]
                    best_protocol = c[1] or ssock.version() or ""
    except Exception:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    c = ssock.cipher()
                    if c:
                        best_cipher = c[0]
                        best_protocol = c[1] or ""
        except Exception:
            pass

    findings: list[dict[str, Any]] = []
    legacy = [v for v in supported if v in ("TLSv1", "TLSv1.1", "SSLv3")]
    has_modern = "TLSv1.3" in supported or "TLSv1.2" in supported

    # Grade
    if not has_modern:
        grade = "F"
    elif legacy:
        grade = "D" if "SSLv3" in legacy else "C"
    elif best_cipher and any(w in best_cipher for w in ("RC4", "3DES", "NULL", "EXPORT", "MD5")):
        grade = "D"
    elif "TLSv1.3" in supported:
        grade = "A"
    else:
        grade = "B"

    sev = {"A": "info", "B": "info", "C": "medium", "D": "high", "F": "critical"}[grade]
    desc = f"Grade TLS : {grade}\n\nProtocoles supportes : {', '.join(supported) or 'aucun'}\n"
    if best_cipher:
        desc += f"Cipher negocie : {best_cipher} ({best_protocol})\n"
    if legacy:
        desc += f"\n⚠ Versions legacy acceptees : {', '.join(legacy)} — a desactiver."
    findings.append({
        "scanner": "tls_grade",
        "type": "tls_grade",
        "severity": sev,
        "title": f"TLS grade {grade} sur {target}",
        "description": desc,
        "target": f"{target}:443",
        "evidence": {
            "grade": grade,
            "supported_versions": supported,
            "legacy_versions": legacy,
            "best_cipher": best_cipher,
            "best_protocol": best_protocol,
        },
    })
    return findings


SURFACE_SCANNERS = {"tls_grade": {"label": "TLS protocol/cipher grade",
    "kinds": {"host"}, "callable": scan_host_tls_grade, "returns_discovered": False}}
