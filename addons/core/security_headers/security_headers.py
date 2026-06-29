"""HTTP security-headers grade scanner — Surface core add-on."""
from __future__ import annotations

from typing import Any

from src.scan_common import (
    _resolve_safe_target,
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


def scan_host_security_headers(target: str) -> list[dict[str, Any]]:
    """Fetch the HTTPS root and grade its security headers."""
    import httpx

    _, target = _resolve_safe_target(target)
    url = f"https://{target}/"
    try:
        # follow_redirects=False: a redirect target is NOT re-validated by
        # _resolve_safe_target, so following it would be an SSRF bypass (to
        # cloud metadata / loopback / RFC1918). The security headers we grade
        # are those of the canonical URL anyway.
        with httpx.Client(verify=False, follow_redirects=False, timeout=5.0) as client:
            r = client.get(url, headers={"User-Agent": "Surface/0.3 (CISO Toolbox)"})
    except Exception:
        return []

    grade, strengths, weaknesses = _grade_headers(dict(r.headers))
    sev = {"A": "info", "B": "info", "C": "low", "D": "medium", "F": "high"}[grade]
    title = f"Security headers grade {grade} sur {target}"
    desc = f"Grade {grade}.\n\n"
    if strengths:
        desc += "Points forts :\n- " + "\n- ".join(strengths) + "\n\n"
    if weaknesses:
        desc += "A corriger :\n- " + "\n- ".join(weaknesses)
    return [{
        "scanner": "security_headers",
        "type": "security_headers_grade",
        "severity": sev,
        "title": title,
        "description": desc,
        "target": f"{target}:443",
        "evidence": {
            "grade": grade,
            "strengths": strengths,
            "weaknesses": weaknesses,
            "raw_headers": {k: v for k, v in r.headers.items() if k.lower().startswith(("strict-", "content-security", "x-", "referrer", "permissions", "feature-"))},
        },
    }]


SURFACE_SCANNERS = {"security_headers": {"label": "Security headers grade",
    "kinds": {"host"}, "callable": scan_host_security_headers, "returns_discovered": False}}
