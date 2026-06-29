"""Subdomain takeover scanner (CNAME fingerprinting) — Surface core add-on."""
from __future__ import annotations

import re
from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target,
)


# ═══════════════════════════════════════════════════════════════
# Subdomain takeover detection (CNAME fingerprinting)
# ═══════════════════════════════════════════════════════════════
#
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz
# Conservative detection: requires BOTH a CNAME pattern match AND a
# fingerprint string in the HTTP body, OR (for selected services) an
# NXDOMAIN on the CNAME target.

from typing import TypedDict


class TakeoverFingerprint(TypedDict, total=False):
    service: str
    cname_patterns: tuple[str, ...]
    fingerprints: tuple[str, ...]
    nxdomain_is_vulnerable: bool
    severity: str


_TAKEOVER_FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    {
        "service": "AWS S3",
        "cname_patterns": (
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$",
            r"\.s3\.[a-z0-9-]+\.amazonaws\.com$",
            r"\.s3-website\.[a-z0-9-]+\.amazonaws\.com$",
        ),
        "fingerprints": ("NoSuchBucket", "The specified bucket does not exist"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": (r"\.github\.io$",),
        "fingerprints": (
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html",
        ),
        "nxdomain_is_vulnerable": False,
        "severity": "critical",
    },
    {
        "service": "Heroku",
        "cname_patterns": (r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.herokussl\.com$"),
        "fingerprints": ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Azure",
        "cname_patterns": (
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
            r"\.azureedge\.net$",
            r"\.blob\.core\.windows\.net$",
        ),
        "fingerprints": ("404 Web Site not found", "The resource you are looking for has been removed"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Vercel",
        "cname_patterns": (r"\.vercel\.app$", r"\.now\.sh$", r"\.vercel-dns\.com$"),
        "fingerprints": ("The deployment could not be found", "DEPLOYMENT_NOT_FOUND"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Netlify",
        "cname_patterns": (r"\.netlify\.com$", r"\.netlify\.app$"),
        "fingerprints": ("Not Found - Request ID",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Shopify",
        "cname_patterns": (r"\.myshopify\.com$",),
        "fingerprints": ("Sorry, this shop is currently unavailable",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cname_patterns": (r"\.fastly\.net$",),
        "fingerprints": ("Fastly error: unknown domain",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Pantheon",
        "cname_patterns": (r"\.pantheonsite\.io$",),
        "fingerprints": ("The gods are wise", "404 error unknown site"),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Tumblr",
        "cname_patterns": (r"domains\.tumblr\.com$", r"\.tumblr\.com$"),
        "fingerprints": ("Whatever you were looking for doesn't currently exist at this address",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Ghost",
        "cname_patterns": (r"\.ghost\.io$",),
        "fingerprints": ("The thing you were looking for is no longer here",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Zendesk",
        "cname_patterns": (r"\.zendesk\.com$",),
        "fingerprints": ("Help Center Closed",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Helpjuice",
        "cname_patterns": (r"\.helpjuice\.com$",),
        "fingerprints": ("We could not find what you're looking for",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Help Scout",
        "cname_patterns": (r"\.helpscoutdocs\.com$",),
        "fingerprints": ("No settings were found for this company",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Webflow",
        "cname_patterns": (r"\.webflow\.io$", r"\.proxy\.webflow\.com$"),
        "fingerprints": ("The page you are looking for doesn't exist or has been moved",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "ReadMe",
        "cname_patterns": (r"\.readme\.io$",),
        "fingerprints": ("Project doesnt exist... yet!",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Strikingly",
        "cname_patterns": (r"\.s\.strikinglydns\.com$",),
        "fingerprints": ("PAGE NOT FOUND",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": (r"\.surge\.sh$",),
        "fingerprints": ("project not found",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "WordPress.com",
        "cname_patterns": (r"\.wordpress\.com$",),
        "fingerprints": ("Do you want to register",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Unbounce",
        "cname_patterns": (r"\.unbouncepages\.com$",),
        "fingerprints": ("The requested URL was not found on this server",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Intercom",
        "cname_patterns": (r"\.custom\.intercom\.help$",),
        "fingerprints": ("This page is reserved for artistic dogs",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": (r"\.bitbucket\.io$",),
        "fingerprints": ("Repository not found",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Cargo Collective",
        "cname_patterns": (r"\.cargocollective\.com$",),
        "fingerprints": ("404 Not Found",),
        "nxdomain_is_vulnerable": False,
        "severity": "low",
    },
    {
        "service": "Launchrock",
        "cname_patterns": (r"\.launchrock\.com$",),
        "fingerprints": ("It looks like you may have taken a wrong turn somewhere",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "SmugMug",
        "cname_patterns": (r"domains\.smugmug\.com$",),
        "fingerprints": (),
        "nxdomain_is_vulnerable": True,
        "severity": "medium",
    },
)


def _resolve_cname_chain(host: str, max_depth: int = 5) -> list[str]:
    """Return the full CNAME chain starting at `host`, empty if none."""
    import dns.resolver
    import dns.exception

    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            resolver.timeout = 5
            ans = resolver.resolve(current, "CNAME")
            if not ans:
                break
            target = str(ans[0].target).rstrip(".").lower()
            if not target or target == current:
                break
            chain.append(target)
            current = target
        except dns.exception.DNSException:
            break
        except Exception:
            break
    return chain


def _cname_target_is_nxdomain(target: str) -> bool:
    """True when the given hostname explicitly NXDOMAINs — a strong
    dangling-CNAME signal for services that release claim on no-A-record."""
    import dns.resolver
    import dns.exception
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 5
        resolver.resolve(target, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.exception.DNSException:
        return False
    except Exception:
        return False


def _match_takeover_service(cname: str) -> dict[str, Any] | None:
    for entry in _TAKEOVER_FINGERPRINTS:
        for pat in entry["cname_patterns"]:
            if re.search(pat, cname, re.IGNORECASE):
                return entry
    return None


_TAKEOVER_MAX_BODY_BYTES = 10_000


def _fetch_takeover_body(target: str) -> tuple[int | None, str]:
    """Fetch http(s)://target and return (status_code, body ≤10KB).
    - Streams the response and stops after 10 KB to avoid memory blowup on
      attacker-controlled CDN targets that could return huge bodies.
    - TLS verification disabled: the target IS typically abandoned /
      mis-configured, so a broken cert is the norm.
    - follow_redirects disabled: a dangling takeover target that redirects
      to a metadata endpoint (169.254.169.254) would bypass our _safe_target
      guard. Takeover fingerprints appear on the first response anyway.
    """
    import httpx
    headers = {"User-Agent": "CISO-Surface/1.0 (takeover-check)"}
    for scheme in ("https", "http"):
        try:
            with httpx.stream(
                "GET",
                f"{scheme}://{target}",
                timeout=10.0,
                headers=headers,
                follow_redirects=False,
                verify=False,
            ) as resp:
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    remaining = _TAKEOVER_MAX_BODY_BYTES - len(buf)
                    if remaining <= 0:
                        break
                    buf.extend(chunk[:remaining])
                body = buf.decode("utf-8", errors="replace")
                return (resp.status_code, body)
        except httpx.HTTPError:
            continue
    return (None, "")


def scan_host_takeover(target: str) -> list[dict[str, Any]]:
    """Detect subdomain takeover opportunities on `target`.

    Steps:
      1. Resolve the CNAME chain.
      2. For each CNAME, match against known-vulnerable service patterns.
      3. Fetch http(s)://target and scan the body for the fingerprint, or
         (for services flagged nxdomain_is_vulnerable) check whether the
         CNAME target has no A record.
      4. Emit one critical/high finding per confirmed hit.
    """
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []

    cname_chain = _resolve_cname_chain(target)
    if not cname_chain:
        return []

    logger.info("takeover: %s -> cname chain: %s", target, cname_chain)

    # Fetch the target body ONCE. Each fingerprint check inspects the same
    # response — avoiding N HTTP round-trips per CNAME in the chain.
    status_code, body = _fetch_takeover_body(target)
    body_lc = body.lower()

    for cname in cname_chain:
        entry = _match_takeover_service(cname)
        if not entry:
            continue

        service = entry["service"]
        severity = entry.get("severity", "critical")
        fps = entry.get("fingerprints", ())
        nxdomain_vuln = entry.get("nxdomain_is_vulnerable", False)

        target_nxdomain = _cname_target_is_nxdomain(cname) if nxdomain_vuln else False

        fingerprint_hit: str | None = None
        for fp in fps:
            if fp and fp.lower() in body_lc:
                fingerprint_hit = fp
                break

        vulnerable = bool(fingerprint_hit) or target_nxdomain
        if not vulnerable:
            continue

        reasons: list[str] = []
        if fingerprint_hit:
            reasons.append(f"empreinte '{fingerprint_hit}' detectee dans la reponse HTTP")
        if target_nxdomain:
            reasons.append(f"le target CNAME ({cname}) est en NXDOMAIN (dangling)")

        findings.append({
            "scanner": "takeover",
            "type": "subdomain_takeover",
            "severity": severity,
            "title": f"Subdomain takeover possible sur {target} (via {service})",
            "description": (
                f"Le sous-domaine {target} pointe via CNAME vers {cname} ({service}), "
                f"mais la ressource cible est abandonnee : {' ET '.join(reasons)}. "
                f"Un attaquant peut potentiellement enregistrer cette ressource {service} "
                f"et servir du contenu sous votre nom de domaine. "
                f"Remediation : supprimer ou corriger l'enregistrement CNAME pour "
                f"{target} dans votre DNS autoritaire."
            ),
            "target": target,
            "evidence": {
                "cname_chain": cname_chain,
                "matched_cname": cname,
                "service": service,
                "fingerprint_hit": fingerprint_hit,
                "target_nxdomain": target_nxdomain,
                "http_status_code": status_code,
                "body_excerpt": body[:500] if body else "",
            },
        })

    return findings


SURFACE_SCANNERS = {"takeover": {"label": "Subdomain takeover (CNAME fingerprint)",
    "kinds": {"host", "domain"}, "callable": scan_host_takeover, "returns_discovered": False}}
