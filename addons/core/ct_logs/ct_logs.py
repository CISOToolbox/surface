"""Certificate Transparency subdomain discovery — Surface core add-on."""
from __future__ import annotations

import json
from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _normalize_host, _in_scope,
)


# ═══════════════════════════════════════════════════════════════
# Discovery helpers (scope / normalization)
# ═══════════════════════════════════════════════════════════════

# Second-level public suffixes we handle explicitly. Not exhaustive — for
# a fully correct registrable-domain computation use the Public Suffix List
# (via `tldextract`). This covers the common cases we see in practice.


# ═══════════════════════════════════════════════════════════════
# Certificate Transparency (crt.sh) — passive subdomain discovery
# ═══════════════════════════════════════════════════════════════

def scan_domain_ct_logs(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Discover sub-domains of `domain` via Certificate Transparency logs.

    Queries https://crt.sh/?q=%25.<domain>&output=json — fully passive,
    no API key. Each entry in crt.sh may contain multiple DNS names
    separated by newlines (the SAN list of the cert). Wildcards and out-
    of-scope entries are filtered out; the remaining hostnames are
    returned as `discovered` so the scheduler auto-enrolls them.
    """
    import httpx

    domain = _safe_target(domain).lower()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "CISO-Surface/1.0 (+https://cisotoolbox.org)"}
    discovered: set[str] = set()
    findings: list[dict[str, Any]] = []

    # crt.sh can return hundreds of MB for popular domains — we cap both
    # the response body AND the number of rows we process to keep memory
    # bounded on adversarial / popular seeds.
    _CT_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap
    _CT_MAX_ROWS = 20_000              # cap on certificates examined

    data = None
    last_error: Exception | None = None
    for attempt, timeout in enumerate((30.0, 60.0, 90.0), start=1):
        try:
            with httpx.stream("GET", url, timeout=timeout, headers=headers, follow_redirects=True) as resp:
                resp.raise_for_status()
                buf = bytearray()
                oversized = False
                for chunk in resp.iter_bytes():
                    if len(buf) + len(chunk) > _CT_MAX_BYTES:
                        oversized = True
                        break
                    buf.extend(chunk)
                if oversized:
                    last_error = ValueError(f"crt.sh response exceeded {_CT_MAX_BYTES} bytes")
                    logger.info("ct_logs: response for %s too large, aborting parse", domain)
                    break
                try:
                    data = json.loads(buf)
                except ValueError as e:
                    last_error = e
                    logger.info("ct_logs: crt.sh JSON parse error for %s: %s", domain, e)
                    break
            break
        except httpx.HTTPError as e:
            last_error = e
            logger.info("ct_logs: crt.sh attempt %d/%d timed out for %s (timeout=%.0fs): %s",
                        attempt, 3, domain, timeout, e)
            continue

    if data is None:
        findings.append({
            "scanner": "ct_logs", "type": "ct_error", "severity": "info",
            "title": f"CT logs : crt.sh injoignable pour {domain}",
            "description": (
                f"La requete crt.sh a echoue apres 3 tentatives : {last_error}. "
                f"crt.sh est connu pour etre lent ou ponctuellement indisponible — "
                f"reessayer plus tard via une nouvelle execution du scanner."
            ),
            "target": domain, "evidence": {"error": str(last_error)},
        })
        return findings, []

    if not isinstance(data, list):
        return findings, []

    for row in data[:_CT_MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        name_value = row.get("name_value") or ""
        for raw in str(name_value).split("\n"):
            h = _normalize_host(raw)
            if h and _in_scope(h, domain):
                discovered.add(h)

    discovered.discard(domain)
    hosts = sorted(discovered)

    findings.append({
        "scanner": "ct_logs", "type": "ct_discovery", "severity": "info",
        "title": f"CT logs : {len(hosts)} sous-domaine(s) decouvert(s) pour {domain}",
        "description": (
            f"Le scan des logs Certificate Transparency (crt.sh) a identifie "
            f"{len(hosts)} hostnames associes au domaine {domain}. "
            f"Ces hostnames sont automatiquement ajoutes a la liste des assets "
            f"surveilles (kind=host) et seront scannes selon la frequence par defaut."
        ),
        "target": domain,
        "evidence": {
            "source": "crt.sh",
            "query": f"%.{domain}",
            "count": len(hosts),
            "hosts_sample": hosts[:50],
        },
    })
    return findings, hosts


SURFACE_SCANNERS = {"ct_logs": {"label": "Subdomain discovery (CT logs)",
    "kinds": {"domain"}, "callable": scan_domain_ct_logs, "returns_discovered": True}}
