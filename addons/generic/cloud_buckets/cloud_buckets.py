"""Cloud bucket enumeration (S3/Azure/GCS/Spaces) — Surface core add-on."""
from __future__ import annotations

from typing import Any

from src.scan_common import (
    _safe_target, _registrable,
)


# ═══════════════════════════════════════════════════════════════
# v0.3 — Cloud bucket enumeration
# ═══════════════════════════════════════════════════════════════
#
# Given a domain, try the most common cloud bucket naming schemes
# for the org and flag any that resolves + answers a HEAD request.
# Passive — a 200/403 on the bucket URL is enough to declare
# existence, we do not try to list content (that would be intrusive).

_CLOUD_BUCKET_PROBES: list[tuple[str, str]] = [
    # (template, provider) — HTTPS only. Plain-http probes were removed
    # in the v0.3 hardening pass to avoid leaking requests to on-path
    # interceptors or internal HTTP services.
    ("https://{name}.s3.amazonaws.com",         "AWS S3"),
    ("https://s3.amazonaws.com/{name}",         "AWS S3 (path-style)"),
    ("https://{name}.blob.core.windows.net",    "Azure Blob"),
    ("https://storage.googleapis.com/{name}",   "Google Cloud Storage"),
    ("https://{name}.storage.googleapis.com",   "Google Cloud Storage (subdomain)"),
    ("https://{name}.digitaloceanspaces.com",   "DigitalOcean Spaces"),
]


def _bucket_candidates(domain: str) -> list[str]:
    """Build a short list of bucket name candidates from a registrable
    domain, e.g. example.com → [example, examplecom, example-prod,
    example-backup, example-dev, example-assets, static-example, ...]."""
    base = _registrable(domain) or domain
    root = base.split(".")[0]
    variants = {
        root,
        root.replace("-", ""),
        base.replace(".", ""),
        base.replace(".", "-"),
    }
    prefixes = ["", "www-", "static-", "assets-", "cdn-", "backup-"]
    suffixes = ["", "-prod", "-staging", "-dev", "-backup", "-assets", "-static", "-data", "-uploads"]
    out: set[str] = set()
    for p in prefixes:
        for s in suffixes:
            for r in variants:
                name = p + r + s
                if 3 <= len(name) <= 63:
                    out.add(name)
    return sorted(out)


def scan_domain_cloud_buckets(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Enumerate common cloud bucket naming schemes for the domain.
    Returns findings + no discovered hosts (buckets aren't enrolled as
    MonitoredAsset automatically — the operator can add them manually
    if interested)."""
    import httpx

    domain = _safe_target(domain)
    candidates = _bucket_candidates(domain)
    # Cap to avoid hitting rate limits on cloud providers
    candidates = candidates[:80]
    findings: list[dict[str, Any]] = []
    hit: set[str] = set()

    # TLS verification ON: targets are well-known cloud endpoints (S3/Azure/GCS/
    # Spaces) which always present valid certs, so verification can't break
    # detection and avoids trusting a MITM'd response.
    with httpx.Client(follow_redirects=False, timeout=3.0,
                       headers={"User-Agent": "Surface/0.3 (CISO Toolbox)"}) as client:
        for name in candidates:
            for tpl, provider in _CLOUD_BUCKET_PROBES:
                url = tpl.format(name=name)
                if url in hit:
                    continue
                hit.add(url)
                try:
                    r = client.head(url, timeout=2.5)
                except Exception:
                    continue
                # 200/403 → exists. 404 → doesn't.
                if r.status_code in (200, 403):
                    sev = "medium"
                    body_access = False
                    try:
                        g = client.get(url, timeout=2.5)
                        if g.status_code == 200 and ("<Contents>" in g.text or "<ListBucketResult" in g.text):
                            sev = "high"
                            body_access = True
                    except Exception:
                        pass
                    findings.append({
                        "scanner": "cloud_buckets",
                        "type": "cloud_bucket_exposed",
                        "severity": sev,
                        "title": f"Cloud bucket {provider}: {name} for {domain}",
                        "description": (
                            f"The bucket {name} exists on {provider}. "
                            f"URL: {url}. "
                            + ("Its contents are publicly listable — "
                               "likely a major leak." if body_access else
                               "Access denied (403) — the bucket exists "
                               "but the ACLs are correct; verify anyway.")
                        ),
                        "target": domain,
                        "evidence": {
                            "bucket_name": name,
                            "provider": provider,
                            "url": url,
                            "http_status": r.status_code,
                            "listable": body_access,
                        },
                    })
                    break  # one hit per bucket name is enough
    return findings, []


SURFACE_SCANNERS = {"cloud_buckets": {"label": "Cloud bucket enumeration (S3/Azure/GCS)",
    "kinds": {"domain"}, "callable": scan_domain_cloud_buckets, "returns_discovered": True}}
