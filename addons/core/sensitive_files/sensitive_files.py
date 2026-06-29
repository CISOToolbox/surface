"""Exposed sensitive files scanner — Surface core add-on."""
from __future__ import annotations

from typing import Any

from src.scan_common import (
    _resolve_safe_target,
)


# ═══════════════════════════════════════════════════════════════
# v0.3 — Sensitive files / dotfiles exposure
# ═══════════════════════════════════════════════════════════════
#
# Probes a short list of well-known paths (≈25) that should NEVER
# be publicly served: .git/config, .env, web.config, backup.sql,
# server-status, phpinfo.php, swagger.json, etc. A 200 response with
# content matching a known signature is a high-severity finding.
#
# Kept intentionally small to stay fast (< 5s per host). Operators
# who need exhaustive path bruteforce should use dirb/gobuster/
# feroxbuster externally and bulk-import the results.

_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    # (path, expected_content_marker, severity)
    ("/.git/config",                "[core]",                   "critical"),
    ("/.git/HEAD",                  "ref:",                     "critical"),
    ("/.env",                       "=",                        "critical"),
    ("/.env.local",                 "=",                        "critical"),
    ("/.env.production",            "=",                        "critical"),
    ("/.htpasswd",                  ":$",                       "critical"),
    ("/config.php",                 "<?php",                    "high"),
    ("/config.yml",                 ":",                        "high"),
    ("/config.yaml",                ":",                        "high"),
    ("/application.properties",     "=",                        "high"),
    ("/web.config",                 "<?xml",                    "high"),
    ("/backup.sql",                 "INSERT",                   "critical"),
    ("/dump.sql",                   "INSERT",                   "critical"),
    ("/database.sql",               "INSERT",                   "critical"),
    ("/wp-config.php",              "<?php",                    "critical"),
    ("/.DS_Store",                  "Bud1",                     "low"),
    ("/server-status",              "Server Status",            "medium"),
    ("/server-info",                "Server Version",           "medium"),
    ("/phpinfo.php",                "phpinfo()",                "high"),
    ("/info.php",                   "phpinfo()",                "high"),
    ("/.well-known/security.txt",   "",                         "info"),
    ("/swagger.json",               '"swagger"',                "medium"),
    ("/swagger/v1/swagger.json",    '"swagger"',                "medium"),
    ("/openapi.json",               '"openapi"',                "medium"),
    ("/api/docs",                   "",                         "info"),
    ("/.aws/credentials",           "aws_",                     "critical"),
    ("/docker-compose.yml",         "services:",                "high"),
    ("/Dockerfile",                 "FROM ",                    "low"),
]


def scan_host_sensitive_files(target: str) -> list[dict[str, Any]]:
    """Probe a list of well-known sensitive paths on the target host.
    A 200 response whose body contains the expected marker is flagged
    as a security finding. Probes both HTTP (80) and HTTPS (443), and
    stops after 3 connection errors in a row to stay fast on dead hosts."""
    import httpx

    # Full re-validation via _resolve_safe_target (same allowlist path as
    # _safe_target, with explicit lock of the resolved IP at call time).
    _, target = _resolve_safe_target(target)
    findings: list[dict[str, Any]] = []
    schemes = [(443, "https"), (80, "http")]

    # Pick whichever scheme answers /.
    working: tuple[int, str] | None = None
    with httpx.Client(verify=False, follow_redirects=False, timeout=3.0) as client:
        for port, scheme in schemes:
            try:
                r = client.get(f"{scheme}://{target}:{port}/",
                               headers={"User-Agent": "Surface/0.3 (CISO Toolbox)"})
                if r.status_code < 500:
                    working = (port, scheme)
                    break
            except Exception:
                continue
    if not working:
        return []
    port, scheme = working
    base = f"{scheme}://{target}:{port}"

    with httpx.Client(verify=False, follow_redirects=False, timeout=3.0) as client:
        consecutive_errors = 0
        for path, marker, sev in _SENSITIVE_PATHS:
            try:
                r = client.get(base + path,
                               headers={"User-Agent": "Surface/0.3 (CISO Toolbox)"})
            except Exception:
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    break
                continue
            consecutive_errors = 0
            if r.status_code != 200:
                continue
            # Security.txt and api/docs are informational — they're
            # expected to be 200 and have no marker. Other paths
            # must carry the expected content marker to be flagged.
            body = (r.text or "")[:512]
            if marker and marker not in body:
                continue
            findings.append({
                "scanner": "sensitive_files",
                "type": "sensitive_file_exposed",
                "severity": sev,
                "title": f"Fichier sensible expose : {path} sur {target}",
                "description": (
                    f"Le chemin {path} est accessible publiquement sur {base} "
                    f"(HTTP 200). Contenu caracteristique detecte : {marker or '(aucun)'}. "
                    f"Retirer ou proteger ce chemin immediatement — il peut "
                    f"exposer des identifiants, des sources ou la configuration "
                    f"de l'infrastructure."
                ),
                "target": f"{target}:{port}",
                "evidence": {
                    "url": base + path,
                    "http_status": r.status_code,
                    "marker_found": marker,
                    "body_preview": body[:200],
                    "content_length": len(r.content),
                },
            })
    return findings


SURFACE_SCANNERS = {"sensitive_files": {"label": "Sensitive files exposure",
    "kinds": {"host"}, "callable": scan_host_sensitive_files, "returns_discovered": False}}
