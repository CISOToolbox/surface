"""IP-range host discovery (nmap ping sweep) — Surface core add-on."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from src.scan_common import (
    _safe_target, _is_stealth,
)


# ═══════════════════════════════════════════════════════════════
# IP RANGE: discovery
# ═══════════════════════════════════════════════════════════════

def scan_iprange_discovery(cidr: str) -> tuple[list[dict[str, Any]], list[str]]:
    """nmap ping sweep on a CIDR. Returns (findings, list_of_discovered_ips)."""
    cidr = _safe_target(cidr)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [{
            "scanner": "nmap", "type": "error", "severity": "info",
            "title": "nmap binary not found", "description": "", "target": cidr, "evidence": {},
        }], []

    timing = "-T2" if _is_stealth() else "-T4"
    sweep_timeout = 2400 if _is_stealth() else 600
    # `--` ends option parsing: the CIDR can never be read as a flag.
    args = [nmap_path, "-oX", "-", "-sn", timing, "--", cidr]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=sweep_timeout)
    except Exception as e:
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"Discovery scan failed for {cidr}",
            "description": str(e), "target": cidr, "evidence": {},
        }], []

    if proc.returncode not in (0, None):
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"nmap exit {proc.returncode} for {cidr}",
            "description": (proc.stderr.decode(errors="replace") or "")[:500],
            "target": cidr, "evidence": {},
        }], []

    discovered: list[str] = []
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(proc.stdout.decode(errors="replace"))
    except ET.ParseError:
        return findings, discovered

    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        if not addr:
            continue
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""
        discovered.append(addr)
        findings.append({
            "scanner": "discovery", "type": "host_discovered", "severity": "info",
            "title": f"New host discovered on {cidr}: {addr}" + (f" ({hostname})" if hostname else ""),
            "description": f"A host is reachable at {addr}." + (f" Hostname: {hostname}." if hostname else "") + f"\nIt was automatically added to the monitored hosts.",
            "target": addr,
            "evidence": {"cidr": cidr, "address": addr, "hostname": hostname},
        })

    findings.append({
        "scanner": "discovery", "type": "discovery_summary", "severity": "info",
        "title": f"Discovery on {cidr}: {len(discovered)} active host(s)",
        "description": f"{len(discovered)} hosts respond to the ping sweep on {cidr}.",
        "target": cidr,
        "evidence": {"cidr": cidr, "discovered": discovered},
    })
    return findings, discovered


SURFACE_SCANNERS = {"discovery": {"label": "Host discovery (ping sweep)",
    "kinds": {"ip_range"}, "callable": scan_iprange_discovery, "returns_discovered": True}}
