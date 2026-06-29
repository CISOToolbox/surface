"""Typosquatting / lookalike domain scanner — Surface core add-on."""
from __future__ import annotations

import socket
from typing import Any

from src.scan_common import (
    _safe_target,
)


# ═══════════════════════════════════════════════════════════════
# DOMAIN scanners
# ═══════════════════════════════════════════════════════════════



_QWERTY_NEIGHBORS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "sfcxer", "e": "wrsdf",
    "f": "dgcvrt", "g": "fhbvty", "h": "gjbnyu", "i": "ujkol", "j": "hknmui",
    "k": "jlmio", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
_EXTRA_TLDS = ["com", "net", "org", "fr", "io", "co", "info", "biz", "eu", "app", "dev", "xyz"]


def _generate_typo_variants(domain: str, max_variants: int = 60) -> set[str]:
    """Generate likely typosquats (insertion, omission, replacement, transposition + alt TLDs)."""
    if "." not in domain:
        return set()
    parts = domain.split(".")
    sld = parts[0]
    tld = ".".join(parts[1:])
    variants: set[str] = set()

    # Omission
    for i in range(len(sld)):
        variants.add(sld[:i] + sld[i+1:] + "." + tld)
    # Transposition
    for i in range(len(sld) - 1):
        variants.add(sld[:i] + sld[i+1] + sld[i] + sld[i+2:] + "." + tld)
    # Replacement (qwerty neighbors)
    for i, ch in enumerate(sld):
        for n in _QWERTY_NEIGHBORS.get(ch, ""):
            variants.add(sld[:i] + n + sld[i+1:] + "." + tld)
    # Insertion (qwerty neighbors)
    for i in range(len(sld) + 1):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            if i < len(sld) and sld[i] == ch:
                continue
            variants.add(sld[:i] + ch + sld[i:] + "." + tld)
    # Alt TLDs
    for alt in _EXTRA_TLDS:
        if alt != tld:
            variants.add(sld + "." + alt)

    variants.discard(domain)
    return set(list(variants)[:max_variants])


def scan_domain_typosquatting(domain: str, max_check: int = 50) -> list[dict[str, Any]]:
    """Generate typosquat variants and check which ones are actually registered."""
    domain = _safe_target(domain).lower()
    variants = _generate_typo_variants(domain)
    if not variants:
        return []
    findings: list[dict[str, Any]] = []
    registered = []
    for v in list(variants)[:max_check]:
        try:
            socket.gethostbyname(v)
            registered.append(v)
        except (socket.gaierror, socket.timeout):
            continue

    if registered:
        findings.append({
            "scanner": "typosquatting", "type": "typosquat", "severity": "medium",
            "title": f"{len(registered)} domaine(s) typosquat enregistre(s) similaires a {domain}",
            "description": "Des variantes ressemblant a votre domaine sont enregistrees. A surveiller : phishing, usurpation, redirections malveillantes.\n\nDomaines detectes :\n- " + "\n- ".join(registered[:20]),
            "target": domain,
            "evidence": {"original": domain, "registered_variants": registered, "tested_count": min(len(variants), max_check)},
        })
    else:
        findings.append({
            "scanner": "typosquatting", "type": "typosquat_clean", "severity": "info",
            "title": f"Aucun typosquat detecte pour {domain}",
            "description": f"{min(len(variants), max_check)} variantes testees, aucune n'est enregistree.",
            "target": domain,
            "evidence": {"original": domain, "tested_count": min(len(variants), max_check)},
        })
    return findings


SURFACE_SCANNERS = {"typosquatting": {"label": "Typosquatting",
    "kinds": {"domain"}, "callable": scan_domain_typosquatting, "returns_discovered": False}}
