"""Nmap port scanner (quick/standard/deep) — Surface core add-on."""
from __future__ import annotations

import shutil
import subprocess
from typing import Any

from src.scan_common import (
    _safe_target, _parse_nmap_xml, _is_stealth,
)


# ═══════════════════════════════════════════════════════════════
# HOST scanners (IP or DNS name)
# ═══════════════════════════════════════════════════════════════

NMAP_PROFILES = {
    "quick":    ["-T4", "-F", "-Pn"],
    "standard": ["-T4", "-sV", "--top-ports", "1000", "-Pn"],
    "deep":     ["-T4", "-sV", "-sC", "-p-", "-Pn"],
}



def scan_host_ports(target: str, profile: str = "quick") -> list[dict[str, Any]]:
    """Run nmap with the given profile and return findings (one per open port + summary)."""
    target = _safe_target(target)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [{
            "scanner": "nmap", "type": "error", "severity": "info",
            "title": "nmap binary not found", "description": "Le binaire nmap est introuvable sur le serveur Surface.",
            "target": target, "evidence": {},
        }]

    profile_args = list(NMAP_PROFILES.get(profile, NMAP_PROFILES["quick"]))
    timeout = {"quick": 180, "standard": 600, "deep": 1800}.get(profile, 300)
    if _is_stealth():
        # Swap the timing template down from T4 (aggressive) to T2
        # (polite — 0.4 s between probes, much smaller parallelism).
        # Bump the subprocess timeout proportionally so the longer
        # scan can actually finish instead of being killed.
        profile_args = ["-T2" if a == "-T4" else a for a in profile_args]
        timeout *= 4
    args = [nmap_path, "-oX", "-"] + profile_args + [target]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Operational signal, not a security issue — keep it as info so
        # it doesn't bump dashboard severity counters or trigger alerts.
        return [{
            "scanner": "nmap", "type": "scanner_timeout", "severity": "info",
            "title": f"Scan nmap timeout pour {target}",
            "description": f"Le scan a depasse {timeout}s.", "target": target, "evidence": {},
        }]
    except Exception as e:
        return [{
            "scanner": "nmap", "type": "scanner_error", "severity": "info",
            "title": f"Scan nmap echoue pour {target}",
            "description": str(e), "target": target, "evidence": {},
        }]

    if proc.returncode not in (0, None):
        return [{
            "scanner": "nmap", "type": "scanner_error", "severity": "info",
            "title": f"nmap exit {proc.returncode} pour {target}",
            "description": (proc.stderr.decode(errors="replace") or "")[:500],
            "target": target, "evidence": {},
        }]

    return _parse_nmap_xml(proc.stdout.decode(errors="replace"), target)


SURFACE_SCANNERS = {
    "nmap_quick": {"label": "Nmap (top 100 ports)", "kinds": {"host"},
        "callable": lambda t: scan_host_ports(t, profile="quick"), "returns_discovered": False},
    "nmap_standard": {"label": "Nmap (top 1000 + service detection)", "kinds": {"host"},
        "callable": lambda t: scan_host_ports(t, profile="standard"), "returns_discovered": False},
    "nmap_deep": {"label": "Nmap (tous les ports + détection services)", "kinds": {"host", "ip_range"},
        "callable": lambda t: scan_host_ports(t, profile="deep"), "returns_discovered": False},
}
