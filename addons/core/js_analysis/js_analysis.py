"""JavaScript bundle secret/endpoint analysis — Surface core add-on."""
from __future__ import annotations

import re as _re
from contextlib import ExitStack
from typing import Any
from urllib.parse import urljoin, urlparse

from src.scan_common import (
    _resolve_safe_target, scan_client, target_request, _registrable, _is_ip_literal,
)


# ═══════════════════════════════════════════════════════════════
# v0.3 — JavaScript bundle analysis (secrets & endpoints)
# ═══════════════════════════════════════════════════════════════
#
# Fetch the HTML root, pull out every <script src>, download each
# (bounded size), and grep for common secret/endpoint patterns:
# API keys, JWT tokens, internal hostnames, cloud bucket URLs,
# Slack/Stripe/Sentry DSNs, AWS keys.
#
# Pure passive inspection — we only grep bytes we already have.

_JS_MAX_FILES = 20
_JS_MAX_BYTES = 512 * 1024  # 512 KB per file
_JS_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (label, regex, severity)
    ("AWS access key",      r"AKIA[0-9A-Z]{16}",                                "critical"),
    ("AWS secret key",      r"aws_secret_access_key[\s:=\"']+([A-Za-z0-9/+=]{40})", "critical"),
    ("Google API key",      r"AIza[0-9A-Za-z\-_]{35}",                          "high"),
    ("Slack webhook",       r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "high"),
    ("Stripe live key",     r"sk_live_[A-Za-z0-9]{24,}",                        "critical"),
    ("Sentry DSN",          r"https://[a-f0-9]+@[a-z0-9.-]+sentry\.io/[0-9]+",  "medium"),
    ("JWT",                 r"eyJ[A-Za-z0-9_\-]{10,2000}\.[A-Za-z0-9_\-]{10,2000}\.[A-Za-z0-9_\-]{10,2000}", "medium"),
    ("Private IP",          r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\b", "low"),
    ("S3 bucket",           r"[a-z0-9][a-z0-9\-.]{1,61}[a-z0-9]\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com", "low"),
    ("Azure Blob",          r"[a-z0-9][a-z0-9\-]{1,61}\.blob\.core\.windows\.net", "low"),
    ("GCS bucket",          r"storage\.googleapis\.com/[a-zA-Z0-9_\-]{3,}",     "low"),
    ("Firebase",            r"[a-zA-Z0-9\-]+\.firebaseio\.com",                 "low"),
]


def _mask_secret(value: str, severity: str) -> str:
    """Never persist the full match for critical/high-sev secrets.
    Keep enough to identify the hit without leaking exploitable material."""
    if not value:
        return ""
    if severity not in ("critical", "high"):
        return value[:200]
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def scan_host_js_analysis(target: str) -> list[dict[str, Any]]:
    """Fetch / on the target, extract <script src> URLs, download each
    (capped), grep each for secret/endpoint patterns. Emits one finding
    per unique (pattern, match) tuple across all JS files."""

    # Every request reaches its host as target_request says: directly on the
    # IP validated for that host (DNS rebinding), its name in Host and as SNI;
    # through the proxy, by name. One client per host, as each host follows
    # the proxy routing of its own (an exception may cover a script host and
    # not the target, or the reverse).
    locked_ip, target = _resolve_safe_target(target)
    base, _host_hdr, _ext = target_request(target, locked_ip, "https")
    ua = {"User-Agent": "Surface/0.3 (CISO Toolbox)"}
    js_bodies: list[tuple[str, str]] = []
    try:
        with ExitStack() as stack:
            # follow_redirects=False — a 3xx on the HTML root could otherwise
            # redirect us off-domain before script-src extraction.
            client = stack.enter_context(
                scan_client(target, locked_ip, verify=False, follow_redirects=False, timeout=5.0))
            r = client.get(f"{base}/", headers={**ua, **_host_hdr}, extensions=_ext)
            if r.status_code != 200:
                return []
            html = r.text or ""
            # Extract every script src
            src_re = _re.compile(r'<script[^>]+src="([^"]+)"', _re.IGNORECASE)
            raw_urls = src_re.findall(html)[:_JS_MAX_FILES]
            # Relative URLs are the target's: resolved against its name (the
            # root is not redirected), not the address it was fetched at.
            named_base = target_request(target, None, "https")[0] + "/"
            resolved = [urljoin(named_base, u) for u in raw_urls]

            # SSRF guard: reject any script URL that (a) is not http(s),
            # (b) lives on a different registrable domain than the target (an
            # IP target: is another host), or
            # (c) has a hostname that fails _resolve_safe_target (internal
            # IP / loopback / docker sibling / metadata). The attacker
            # controls the HTML so we cannot trust src values.
            # Hosts as urlparse gives them: lower case, no brackets. An
            # address has no domain, only its own scripts.
            name = target.lower().strip("[]")
            target_reg = None if _is_ip_literal(name) else _registrable(name) or name
            clients = {name: (client, locked_ip)}
            for u in resolved:
                try:
                    parsed = urlparse(u)
                    port = parsed.port  # raises on an invalid port
                    host = parsed.hostname or ""
                    if parsed.scheme not in ("http", "https") or not host:
                        continue
                    if host != name and (target_reg is None or (_registrable(host) or host) != target_reg):
                        continue
                    # Resolved once per host: its client's routing and the
                    # URL rest on the same address.
                    if host not in clients:
                        ip = _resolve_safe_target(host)[0]
                        clients[host] = (stack.enter_context(
                            scan_client(host, ip, verify=False, follow_redirects=False, timeout=5.0)), ip)
                    host_client, ip = clients[host]
                    script_base, headers, ext = target_request(host, ip, parsed.scheme, port)
                    path = ((parsed.path or "/") + (f";{parsed.params}" if parsed.params else "")
                            + (f"?{parsed.query}" if parsed.query else ""))
                    # Size-bounded download
                    with host_client.stream("GET", script_base + path, headers={**ua, **headers},
                                              extensions=ext, timeout=4.0) as resp:
                        if resp.status_code != 200:
                            continue
                        chunks: list[bytes] = []
                        total = 0
                        for chunk in resp.iter_bytes(8192):
                            chunks.append(chunk)
                            total += len(chunk)
                            if total >= _JS_MAX_BYTES:
                                break
                        body = b"".join(chunks).decode("utf-8", errors="ignore")
                    js_bodies.append((u, body))
                except Exception:
                    continue
    except Exception:
        return []

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for url, body in js_bodies:
        for label, pattern, sev in _JS_SECRET_PATTERNS:
            for m in _re.finditer(pattern, body):
                raw = (m.group(1) if m.groups() else m.group(0))[:200]
                masked = _mask_secret(raw, sev)
                key = (label, masked)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "scanner": "js_analysis",
                    "type": "js_secret_leak",
                    "severity": sev,
                    "title": f"{label} found in a JS bundle of {target}",
                    "description": (
                        f"A pattern of type '{label}' was found in the "
                        f"JS bundle {url}. Excerpt: {masked}"
                    ),
                    "target": target,
                    "evidence": {
                        "js_url": url,
                        "pattern": label,
                        "match": masked,
                    },
                })
    return findings


SURFACE_SCANNERS = {"js_analysis": {"label": "JavaScript bundle analysis (secrets & endpoints)",
    "kinds": {"host"}, "callable": scan_host_js_analysis, "returns_discovered": False}}
