"""CVE matching (NVD + EPSS + KEV) — Surface core add-on."""
from __future__ import annotations

import re as _re

from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target,
)


# ═══════════════════════════════════════════════════════════════
# v0.2 — CVE matching + EPSS + CISA KEV enrichment
# ═══════════════════════════════════════════════════════════════
#
# Given the (product, version) tuples produced by the techstack scanner
# (and any nmap service detection that emits banner data), look up known
# CVEs via the public NVD JSON 2.0 API, then enrich each CVE with its
# EPSS probability and a CISA KEV flag. Everything is cached in-process
# for 24h so the same lookup never hits the network twice in a row.
#
# Heavy CVE feeds (full mirrors) are explicitly out of scope — Surface
# is meant to be a small, self-hostable tool, not a vulnerability
# database. The lookup is best-effort: if NVD is unreachable, the
# scanner emits an info finding but never blocks the rest of the scan.

import threading as _threading
import time as _time

_CVE_CACHE_LOCK = _threading.Lock()
_CVE_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CVE_CACHE_TTL = 24 * 3600

_EPSS_CACHE: dict[str, float] = {}
_KEV_CACHE: set[str] = set()
_KEV_LOADED_AT: float = 0.0
_KEV_TTL = 24 * 3600


def _kev_load() -> set[str]:
    """Pull CISA's Known Exploited Vulnerabilities catalog (≈1000 CVE IDs).
    Refreshed once a day. Best-effort — a network failure leaves the
    previous cached set untouched."""
    global _KEV_LOADED_AT, _KEV_CACHE
    now = _time.monotonic()
    with _CVE_CACHE_LOCK:
        if _KEV_CACHE and (now - _KEV_LOADED_AT) < _KEV_TTL:
            return _KEV_CACHE
    try:
        import httpx
        with httpx.Client(timeout=10.0) as c:
            r = c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if r.status_code != 200:
                return _KEV_CACHE
            data = r.json()
        ids = {v.get("cveID", "") for v in (data.get("vulnerabilities") or []) if v.get("cveID")}
        with _CVE_CACHE_LOCK:
            _KEV_CACHE = ids
            _KEV_LOADED_AT = now
    except Exception as e:
        logger.warning("kev: fetch failed: %s", e)
    return _KEV_CACHE


def _epss_lookup(cve_ids: list[str]) -> dict[str, float]:
    """Batch EPSS lookup — POST one request per ~50 CVE IDs to the FIRST
    EPSS API. Returns {cve_id: probability}. Network failure → empty."""
    out: dict[str, float] = {}
    missing = [c for c in cve_ids if c not in _EPSS_CACHE]
    if missing:
        try:
            import httpx
            with httpx.Client(timeout=10.0) as c:
                # FIRST EPSS API supports comma-separated cve= param
                r = c.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(missing[:50])})
                if r.status_code == 200:
                    for item in (r.json().get("data") or []):
                        cid = item.get("cve", "")
                        try:
                            _EPSS_CACHE[cid] = float(item.get("epss", 0))
                        except (TypeError, ValueError):
                            pass
        except Exception as e:
            logger.warning("epss: fetch failed: %s", e)
    for c in cve_ids:
        if c in _EPSS_CACHE:
            out[c] = _EPSS_CACHE[c]
    return out


# NVD keywordSearch needs the right wording — product names from nuclei
# don't always match the terms NVD uses in CVE descriptions. This map
# normalizes to NVD-friendly keywords.
_NVD_KEYWORD_MAP: dict[str, str] = {
    "microsoft iis": "Internet Information Services",
    "microsoft exchange server": "Exchange Server",
    "asp.net": "ASP.NET",
    "apache http server": "Apache HTTP Server",
    "apache tomcat": "Apache Tomcat",
    "ruby on rails": "Rails",
    "node.js": "Node.js",
}


def _nvd_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Query NVD 2.0 for CVEs affecting `product` (optionally version).
    Returns up to 25 entries sorted by CVSS v3 score desc. Cached 24h."""
    if not product:
        return []
    key = f"{product.lower()}|{version or '*'}"
    with _CVE_CACHE_LOCK:
        cached = _CVE_CACHE.get(key)
        if cached and (_time.monotonic() - cached[0]) < _CVE_CACHE_TTL:
            return cached[1]

    # Normalize product name to NVD-friendly keyword
    nvd_product = _NVD_KEYWORD_MAP.get(product.lower(), product)
    # Truncate overly-specific build numbers (e.g. 15.1.2507.39 → 15.1)
    # to improve NVD keyword matching. Minor/patch builds are too specific
    # for description-based search.
    if version and version.count(".") >= 2:
        version = ".".join(version.split(".")[:2])

    cves: list[dict[str, Any]] = []
    try:
        import httpx
        params: dict[str, Any] = {"keywordSearch": nvd_product, "resultsPerPage": 25}
        if version:
            params["keywordSearch"] = f"{nvd_product} {version}"
        with httpx.Client(timeout=15.0) as c:
            r = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
            if r.status_code != 200:
                logger.info("nvd: %s for %s", r.status_code, product)
                with _CVE_CACHE_LOCK:
                    _CVE_CACHE[key] = (_time.monotonic(), [])
                return []
            data = r.json()
        for item in (data.get("vulnerabilities") or [])[:25]:
            cve = item.get("cve") or {}
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descs = cve.get("descriptions") or []
            description = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics") or {}
            score = 0.0
            severity = ""
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(k) or []
                if arr:
                    cd = arr[0].get("cvssData") or {}
                    score = float(cd.get("baseScore", 0))
                    severity = cd.get("baseSeverity", "") or arr[0].get("baseSeverity", "")
                    break
            cves.append({
                "id": cve_id,
                "description": description[:500],
                "score": score,
                "severity": severity.lower(),
                "published": cve.get("published", ""),
            })
        cves.sort(key=lambda c: c["score"], reverse=True)
    except Exception as e:
        logger.warning("nvd: query failed for %s: %s", product, e)
    with _CVE_CACHE_LOCK:
        _CVE_CACHE[key] = (_time.monotonic(), cves)
    return cves


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# Mapping from nuclei matcher-name / template-id to an NVD-compatible
# product keyword. Nuclei's wappalyzer uses short slugs (e.g. "ms-iis")
# while NVD expects "Internet Information Services" or "iis". Only the
# most common products need a mapping — others fall back to the slug.
_NUCLEI_TO_NVD_PRODUCT: dict[str, str] = {
    "ms-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "microsoft-iis-version": "Microsoft IIS",
    "microsoft-exchange": "Microsoft Exchange Server",
    "msexchange-eol": "Microsoft Exchange Server",
    "ms-exchange-server": "Microsoft Exchange Server",
    "ms-exchange-web-service": "Microsoft Exchange Server",
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "openssl": "OpenSSL",
    "php": "PHP",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "tomcat": "Apache Tomcat",
    "spring-boot": "Spring Boot",
    "django": "Django",
    "rails": "Ruby on Rails",
    "node.js": "Node.js",
    "express": "Express",
    "react": "React",
    "angular": "Angular",
    "jquery": "jQuery",
    "aspnet-version-detect": "ASP.NET",
    "openssh": "OpenSSH",
    "grafana-panel": "Grafana",
    "jenkins-panel": "Jenkins",
    "gitlab-panel": "GitLab",
    "kibana-panel": "Kibana",
    "elasticsearch": "Elasticsearch",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "phpmyadmin-panel": "phpMyAdmin",
    "adminer-panel": "Adminer",
    "portainer-panel": "Portainer",
    "traefik-panel": "Traefik",
}


def _extract_tech_from_prior(prior_findings: list[dict[str, Any]]) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract (product, version) tuples from prior scanner output.

    Reads two sources:
      1. techstack's `tech_fingerprint` (legacy, kept for backward compat)
      2. nuclei's tech-detect / version-detect / fingerprint templates

    Returns (versioned, unversioned) buckets."""
    versioned: list[tuple[str, str]] = []
    unversioned: list[str] = []
    seen_products: set[str] = set()

    for f in prior_findings or []:
        ev = f.get("evidence") or {}

        # Source 1: techstack findings (legacy)
        if f.get("type") == "tech_fingerprint":
            p = (ev.get("product") or "").strip()
            v = (ev.get("version") or "").strip()
            if p and p.lower() not in seen_products:
                seen_products.add(p.lower())
                if v:
                    versioned.append((p, v))
                else:
                    unversioned.append(p)
            continue

        # Source 2: nuclei findings with tech/version data
        if f.get("scanner") != "nuclei":
            continue
        template_id = ev.get("template_id") or f.get("type") or ""
        matcher = ev.get("matcher_name") or ""
        extracted = ev.get("extracted") or []

        # Map to NVD product name
        product = (
            _NUCLEI_TO_NVD_PRODUCT.get(template_id)
            or _NUCLEI_TO_NVD_PRODUCT.get(matcher)
            or ""
        )
        if not product:
            # For unknown matchers from tech-detect, use the matcher as-is
            # (cleaned up). Skip generic templates that don't identify a product.
            if template_id in ("tech-detect", "fingerprinthub-web-fingerprints") and matcher:
                product = matcher.replace("-", " ").title()
            else:
                continue

        # Extract version from extracted-results if available.
        # Nuclei templates return versions in various formats:
        #   "15.1.2507.39"       (ms-exchange-server, msexchange-eol)
        #   "Microsoft-IIS/10.0" (microsoft-iis-version)
        #   "4.0.30319"          (aspnet-version-detect)
        version = ""
        if isinstance(extracted, list) and extracted:
            for ex in extracted:
                if not isinstance(ex, str):
                    continue
                slash = _re.search(r"/(\d[\d.]+)", ex)
                if slash:
                    version = slash.group(1)
                    break
                if _re.match(r"^\d+[\d.]+", ex):
                    version = ex.strip()
                    break

        pkey = product.lower()
        if version:
            # Upgrade: if we already saw this product as unversioned,
            # promote it to versioned now that we have a version.
            if pkey in seen_products:
                if product in unversioned:
                    unversioned.remove(product)
                # Check not already in versioned with same product
                if not any(p.lower() == pkey for p, _ in versioned):
                    versioned.append((product, version))
            else:
                versioned.append((product, version))
            seen_products.add(pkey)
        else:
            if pkey not in seen_products:
                unversioned.append(product)
                seen_products.add(pkey)

    return versioned, unversioned


def scan_host_cve_lookup(target: str, prior_findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """For each detected technology (from nuclei or techstack), look up
    matching CVEs and emit one `cve_match` finding per CVE (capped to
    top 5 per product). Each finding carries EPSS + KEV enrichment.

    Since v0.3.1, the primary tech source is nuclei's wappalyzer output
    (tech-detect, fingerprinthub, version-detect templates). The legacy
    techstack findings are still consumed for backward compatibility."""
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []

    versioned, unversioned = _extract_tech_from_prior(prior_findings)

    findings_info: list[dict[str, Any]] = []
    for p in unversioned:
        findings_info.append({
            "scanner": "cve_lookup",
            "type": "cve_no_version",
            "severity": "info",
            "title": f"CVE lookup: {p} detected without version on {target}",
            "description": (
                f"The product {p} was identified on {target} but its version "
                f"is not exposed. An NVD lookup without a version returns the "
                f"product's entire history — too noisy to be useful. "
                f"Check the version manually (/server-status page, "
                f"application banners, IT configuration) then re-run."
            ),
            "target": target,
            "evidence": {"product": p, "reason": "missing_version"},
        })

    if not versioned and not unversioned:
        return [{
            "scanner": "cve_lookup",
            "type": "cve_no_tech",
            "severity": "info",
            "title": f"CVE lookup: no technology detected on {target}",
            "description": (
                f"No versioned product identified for {target}. "
                f"The nuclei scanner (auto mode) must run before cve_lookup."
            ),
            "target": target,
            "evidence": {"target": target},
        }]

    findings.extend(findings_info)

    kev = _kev_load()
    all_cve_ids: list[str] = []
    by_product: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for product, version in versioned:
        cves = _nvd_lookup(product, version)
        if not cves:
            continue
        by_product[(product, version)] = cves[:5]
        all_cve_ids.extend(c["id"] for c in cves[:5])

    epss = _epss_lookup(all_cve_ids) if all_cve_ids else {}

    for (product, version), cves in by_product.items():
        for cve in cves:
            cid = cve["id"]
            sev = _cvss_to_severity(cve["score"])
            in_kev = cid in kev
            epss_score = epss.get(cid)
            label = product + (f" {version}" if version else "")
            title = f"{cid} — {label} on {target}"
            if in_kev:
                title = "[KEV] " + title
                # Bump severity on KEV (actively exploited in the wild)
                if sev in ("medium", "low"):
                    sev = "high"
            description_parts = [
                f"CVSS: {cve['score']} ({sev})",
                cve["description"],
            ]
            if epss_score is not None:
                description_parts.append(f"EPSS: {epss_score * 100:.1f}% probability of public exploitation")
            if in_kev:
                description_parts.append("CISA KEV: exploited in the wild, patch as a priority")
            findings.append({
                "scanner": "cve_lookup",
                "type": "cve_match",
                "severity": sev,
                "title": title,
                "description": "\n\n".join(description_parts),
                "target": target,
                "evidence": {
                    "cve_id": cid,
                    "cvss_score": cve["score"],
                    "cvss_severity": cve["severity"],
                    "epss": epss_score,
                    "kev": in_kev,
                    "product": product,
                    "version": version,
                    "published": cve["published"],
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                },
            })
    return findings


SURFACE_SCANNERS = {"cve_lookup": {"label": "CVE matching (NVD + EPSS + KEV)",
    "kinds": {"host"}, "callable": scan_host_cve_lookup, "returns_discovered": False,
    "wants_prior_findings": True}}
# Optional (generic) add-on, but default-on for host scans when included.
SURFACE_DEFAULT_SCANNERS = {"host": ["cve_lookup"]}
