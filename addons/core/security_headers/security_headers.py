"""HTTP security-headers grade scanner — Surface core add-on."""
from __future__ import annotations

from contextlib import ExitStack
from typing import Any

from src.scan_common import (
    _resolve_safe_target, scan_client, fetch_page, follow_redirects_mode,
)


# ═══════════════════════════════════════════════════════════════
# v0.3 — Security headers grade (Mozilla Observatory-lite)
# ═══════════════════════════════════════════════════════════════
#
# Probes HTTPS root and grades 6 security headers:
#   HSTS, Content-Security-Policy, X-Frame-Options,
#   X-Content-Type-Options, Referrer-Policy, Permissions-Policy
#
# Emits one finding per missing/weak header + one summary finding
# with the overall letter grade (A/B/C/D/F).

def _grade_headers(headers: dict[str, str]) -> tuple[str, list[str], list[str]]:
    """Return (letter_grade, strengths, weaknesses)."""
    lc = {k.lower(): v for k, v in headers.items()}
    score = 0
    strengths: list[str] = []
    weaknesses: list[str] = []

    hsts = lc.get("strict-transport-security", "")
    if hsts:
        if "max-age" in hsts and "includesubdomains" in hsts.lower():
            score += 20
            strengths.append("HSTS with includeSubDomains")
        else:
            score += 10
            weaknesses.append("HSTS present but missing includeSubDomains")
    else:
        weaknesses.append("HSTS missing (Strict-Transport-Security)")

    csp = lc.get("content-security-policy", "")
    if csp:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            score += 10
            weaknesses.append("CSP present but allows 'unsafe-inline' / 'unsafe-eval'")
        else:
            score += 25
            strengths.append("CSP configured (no unsafe-inline)")
    else:
        weaknesses.append("Content-Security-Policy missing")

    xfo = lc.get("x-frame-options", "")
    if xfo.upper() in ("DENY", "SAMEORIGIN"):
        score += 15
        strengths.append(f"X-Frame-Options: {xfo}")
    elif "frame-ancestors" in csp:
        score += 15
        strengths.append("frame-ancestors via CSP")
    else:
        weaknesses.append("X-Frame-Options missing (clickjacking risk)")

    xcto = lc.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        score += 10
        strengths.append("X-Content-Type-Options: nosniff")
    else:
        weaknesses.append("X-Content-Type-Options missing")

    rp = lc.get("referrer-policy", "")
    if rp:
        score += 15
        strengths.append(f"Referrer-Policy: {rp}")
    else:
        weaknesses.append("Referrer-Policy missing")

    pp = lc.get("permissions-policy", "") or lc.get("feature-policy", "")
    if pp:
        score += 15
        strengths.append("Permissions-Policy configured")
    else:
        weaknesses.append("Permissions-Policy missing")

    if score >= 90:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"
    return grade, strengths, weaknesses


def scan_host_security_headers(target: str, asset_config: dict | None = None) -> list[dict[str, Any]]:
    """Fetch the HTTPS root (and its redirects, as the target's
    ``follow_redirects`` says) and grade the security headers of the page
    reached."""

    # Directly, connect to the IP locked at validation time, not the name:
    # handing the hostname to httpx let it re-resolve, so the address that was
    # vetted need not be the one reached (DNS rebinding). The name rides in
    # the Host header so name-based vhosts still answer. Through the proxy,
    # the name (target_request).
    locked_ip, target = _resolve_safe_target(target)

    def open_client(host: str, ip: str | None):
        # follow_redirects=False: a redirect target is not validated by httpx
        # (an SSRF bypass to cloud metadata or loopback); fetch_page
        # validates each hop itself.
        return scan_client(host, ip, verify=False, follow_redirects=False, timeout=5.0)

    try:
        with ExitStack() as stack:
            r, _host, url, stop = fetch_page(stack, {}, open_client, target, locked_ip,
                                       follow_redirects_mode(asset_config),
                                       {"User-Agent": "Surface/0.3 (CISO Toolbox)"})
    except Exception:
        return []

    grade, strengths, weaknesses = _grade_headers(dict(r.headers))
    sev = {"A": "info", "B": "info", "C": "low", "D": "medium", "F": "high"}[grade]
    title = f"Security headers grade {grade} on {target}"
    desc = f"Grade {grade}.\n\n"
    if stop:
        # The grade is the redirect's own headers, not the site's page.
        title += " (redirect not followed)"
        desc = (f"Grade {grade} of the HTTP {r.status_code} redirect to {stop[0]}, not followed: "
                f"{stop[1]}. The page it leads to was not graded.\n\n") + desc
    if strengths:
        desc += "Strengths:\n- " + "\n- ".join(strengths) + "\n\n"
    if weaknesses:
        desc += "To fix:\n- " + "\n- ".join(weaknesses)
    return [{
        "scanner": "security_headers",
        "type": "security_headers_grade",
        "severity": sev,
        "title": title,
        "description": desc,
        "target": f"{target}:443",
        "evidence": {
            "grade": grade,
            "url": url,
            "status_code": r.status_code,
            # Scalars, so the UI words the finding for this case
            # (finding.security_headers_grade.redirect_not_followed.*).
            **({"variant": "redirect_not_followed", "redirect_location": stop[0],
                "redirect_reason": stop[1]} if stop else {}),
            "strengths": strengths,
            "weaknesses": weaknesses,
            "raw_headers": {k: v for k, v in r.headers.items() if k.lower().startswith(("strict-", "content-security", "x-", "referrer", "permissions", "feature-"))},
        },
    }]


SURFACE_SCANNERS = {"security_headers": {"label": "Security headers grade",
    "kinds": {"host"}, "callable": scan_host_security_headers, "returns_discovered": False,
    "wants_config": True}}
