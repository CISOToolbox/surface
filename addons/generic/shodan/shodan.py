"""Shodan passive scanners (domain + host) — Surface core add-on."""
from __future__ import annotations

import re
import socket
from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _normalize_host, _in_scope,
)
from src.scanners import _get_shodan_api_key


def scan_domain_shodan(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Passive subdomain enumeration via Shodan DNS API.

    Hits https://api.shodan.io/dns/domain/{domain} which does NOT consume
    query credits — it is part of the standard Shodan subscription.
    Returns discovered hostnames for auto-enrollment by the scheduler.
    """
    import httpx

    domain = _safe_target(domain).lower()
    api_key = _get_shodan_api_key()
    findings: list[dict[str, Any]] = []

    if not api_key:
        findings.append({
            "scanner": "shodan", "type": "shodan_no_key", "severity": "info",
            "title": f"Shodan: API key not configured",
            "description": (
                "The Shodan scanner is enabled on this target but no API "
                "key is configured. Open Settings -> Shodan to add your "
                "key, or remove this scanner from the target's list of "
                "active scanners."
            ),
            "target": domain, "evidence": {},
        })
        return findings, []

    url = f"https://api.shodan.io/dns/domain/{domain}"
    try:
        resp = httpx.get(url, params={"key": api_key}, timeout=30.0)
        if resp.status_code == 401:
            findings.append({
                "scanner": "shodan", "type": "shodan_auth_error", "severity": "info",
                "title": "Shodan: invalid API key (401)",
                "description": "The configured Shodan API key is not valid. Check it in Settings.",
                "target": domain, "evidence": {"status": 401},
            })
            return findings, []
        if resp.status_code == 404:
            findings.append({
                "scanner": "shodan", "type": "shodan_no_data", "severity": "info",
                "title": f"Shodan: no data for {domain}",
                "description": "Shodan has no known subdomains for this domain.",
                "target": domain, "evidence": {},
            })
            return findings, []
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        logger.info("shodan_domain: %s failed: %s", domain, e)
        findings.append({
            "scanner": "shodan", "type": "shodan_error", "severity": "info",
            "title": f"Shodan: network error for {domain}",
            "description": str(e)[:500],
            "target": domain, "evidence": {"error": str(e)[:500]},
        })
        return findings, []

    subdomains_raw = data.get("subdomains") or []
    discovered: set[str] = set()
    for sub in subdomains_raw:
        host = f"{sub}.{domain}"
        h = _normalize_host(host)
        if h and _in_scope(h, domain) and h != domain:
            discovered.add(h)
    hosts = sorted(discovered)

    findings.append({
        "scanner": "shodan", "type": "shodan_domain_discovery", "severity": "info",
        "title": f"Shodan: {len(hosts)} subdomain(s) identified for {domain}",
        "description": (
            f"Shodan DNS API returned {len(subdomains_raw)} known "
            f"subdomain(s) for {domain}. Results come from Shodan's "
            f"passive banner grabbing across the Internet."
        ),
        "target": domain,
        "evidence": {
            "source": "shodan",
            "count": len(hosts),
            "subdomains_sample": hosts[:50],
            "tags": data.get("tags") or [],
        },
    })
    return findings, hosts


def scan_host_shodan(target: str) -> list[dict[str, Any]]:
    """Active host lookup via Shodan /shodan/host/{ip}.

    WARNING: Each call consumes 1 query credit on the user's Shodan account.
    Free tier = 100 credits/month. Schedule with care.

    Emits:
      - one finding per known CVE (high severity)
      - one info finding with ports / services / CPE / tags / last update
    """
    import httpx

    target = _safe_target(target)
    api_key = _get_shodan_api_key()
    if not api_key:
        # Silent return — the scanner is opt-in and the user clearly forgot
        # to set a key before enabling it. The domain scanner emits the
        # visible "no_key" finding, no need to spam every host.
        return []

    # Resolve hostname to IP (Shodan host API requires an IP)
    try:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            ip = target
        else:
            ip = socket.gethostbyname(target)
    except (socket.gaierror, OSError) as e:
        logger.info("shodan_host: DNS resolve failed for %s: %s", target, e)
        return []

    url = f"https://api.shodan.io/shodan/host/{ip}"
    try:
        resp = httpx.get(url, params={"key": api_key}, timeout=30.0)
    except httpx.HTTPError as e:
        logger.info("shodan_host: %s failed: %s", target, e)
        return []

    if resp.status_code == 404:
        return [{
            "scanner": "shodan", "type": "shodan_no_data", "severity": "info",
            "title": f"Shodan: no data for {target} ({ip})",
            "description": "Shodan has no banner for this IP (never scanned or results not indexed).",
            "target": target, "evidence": {"ip": ip},
        }]
    if resp.status_code == 401:
        return [{
            "scanner": "shodan", "type": "shodan_auth_error", "severity": "info",
            "title": "Shodan: invalid API key (401)",
            "description": "The configured Shodan API key is not valid.",
            "target": target, "evidence": {"status": 401},
        }]
    try:
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.info("shodan_host: %s HTTP error: %s", target, e)
        return []

    findings: list[dict[str, Any]] = []
    shodan_url = f"https://www.shodan.io/host/{ip}"

    # Known CVEs: emit one high-severity finding per CVE
    vulns = data.get("vulns") or []
    for cve in vulns:
        findings.append({
            "scanner": "shodan",
            "type": f"shodan_vuln",
            "severity": "high",
            "title": f"Shodan: {cve} detected on {target}",
            "description": (
                f"Shodan reports that {target} ({ip}) is potentially "
                f"exposed to {cve}. Verify the exact version of the affected "
                f"service and patch it. Details: {shodan_url}"
            ),
            "target": target,
            "evidence": {
                "cve": cve, "ip": ip, "shodan_url": shodan_url,
            },
        })

    # Port summary
    ports = sorted(data.get("ports") or [])
    services: list[dict[str, Any]] = []
    for banner in (data.get("data") or [])[:20]:
        services.append({
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "product": banner.get("product"),
            "version": banner.get("version"),
            "cpe": banner.get("cpe23") or banner.get("cpe"),
        })

    summary_desc_parts = [
        f"Shodan observed ports {', '.join(str(p) for p in ports[:20])} on {ip}."
    ]
    if data.get("last_update"):
        summary_desc_parts.append(f"Last observation: {data.get('last_update')}.")
    if data.get("tags"):
        summary_desc_parts.append(f"Tags: {', '.join(data.get('tags'))}.")
    summary_desc_parts.append(f"Details: {shodan_url}")

    findings.append({
        "scanner": "shodan",
        "type": "shodan_host_summary",
        "severity": "info",
        "title": f"Shodan: {len(ports)} port(s) observed on {target} ({ip})",
        "description": " ".join(summary_desc_parts),
        "target": target,
        "evidence": {
            "ip": ip,
            "hostnames": (data.get("hostnames") or [])[:20],
            "ports": ports,
            "services": services,
            "tags": data.get("tags") or [],
            "os": data.get("os"),
            "last_update": data.get("last_update"),
            "vulns_count": len(vulns),
            "shodan_url": shodan_url,
        },
    })

    return findings


SURFACE_SCANNERS = {
    "shodan_domain": {"label": "Shodan DNS (subdomains, passive, 0 credit)", "kinds": {"domain"},
        "callable": scan_domain_shodan, "returns_discovered": True},
    "shodan_host": {"label": "Shodan host lookup (ports/CVE, 1 credit/req)", "kinds": {"host"},
        "callable": scan_host_shodan, "returns_discovered": False},
}
