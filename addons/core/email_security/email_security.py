"""Email security scanner (SPF / DMARC / DKIM / MX) — Surface core add-on.

Extracted from the monolithic scanners.py. Core add-ons are bundled in every
image (the standard Dockerfile copies addons/core into /app/addons), so this is
always available; the modularity lets a slim client image drop scanners it does
not want.
"""
from __future__ import annotations

import re
from typing import Any

from src.scan_common import _dns_query, _safe_target


def scan_domain_email(domain: str) -> list[dict[str, Any]]:
    """Check SPF, DMARC, DKIM and MX records for a domain."""
    domain = _safe_target(domain).lower()
    findings: list[dict[str, Any]] = []

    # MX
    mx = _dns_query(domain, "MX")
    if not mx:
        findings.append({
            "scanner": "email_security", "type": "mx_missing", "severity": "info",
            "title": f"Aucun MX configure pour {domain}",
            "description": "Le domaine n'a pas d'enregistrement MX. Aucun mail ne peut etre recu (peut etre intentionnel).",
            "target": domain, "evidence": {},
        })

    # SPF (TXT starting with v=spf1)
    txt = _dns_query(domain, "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    if not spf:
        findings.append({
            "scanner": "email_security", "type": "spf_missing", "severity": "high",
            "title": f"SPF manquant sur {domain}",
            "description": "Aucun enregistrement SPF (TXT v=spf1...). N'importe qui peut envoyer des mails au nom de ce domaine. Recommande : 'v=spf1 -all' au minimum.",
            "target": domain, "evidence": {"txt_records": txt},
        })
    else:
        # Classify the `all` qualifier. RFC 7208 mechanisms: -all (hard fail, strict),
        # ~all (soft fail, recommended), ?all (neutral, weak), +all (pass anything).
        # Bare `all` with no qualifier == +all per the RFC.
        spf_lc = spf.lower()
        has_hard_fail = "-all" in spf_lc
        has_soft_fail = "~all" in spf_lc
        has_neutral = "?all" in spf_lc
        has_pass_all = ("+all" in spf_lc) or (
            re.search(r"(^|\s)all($|\s)", spf_lc) is not None
            and not (has_hard_fail or has_soft_fail or has_neutral)
        )
        if has_pass_all:
            findings.append({
                "scanner": "email_security", "type": "spf_weak", "severity": "high",
                "title": f"SPF trop permissif sur {domain}",
                "description": f"L'enregistrement SPF accepte tous les emetteurs (+all ou 'all' sans qualifieur). SPF: {spf}",
                "target": domain, "evidence": {"spf": spf},
            })
        elif has_neutral:
            findings.append({
                "scanner": "email_security", "type": "spf_neutral", "severity": "medium",
                "title": f"SPF en mode neutre (?all) sur {domain}",
                "description": f"Le SPF est en mode 'neutre', sans politique de rejet. SPF: {spf}",
                "target": domain, "evidence": {"spf": spf},
            })

    # DMARC (TXT on _dmarc.<domain>)
    dmarc_txt = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_txt if "v=DMARC1" in t), None)
    if not dmarc:
        findings.append({
            "scanner": "email_security", "type": "dmarc_missing", "severity": "high",
            "title": f"DMARC manquant sur {domain}",
            "description": "Aucun enregistrement DMARC. Recommande au minimum 'v=DMARC1; p=none; rua=mailto:...' pour le monitoring, puis durcir vers p=quarantine ou p=reject.",
            "target": domain, "evidence": {},
        })
    else:
        if "p=none" in dmarc:
            findings.append({
                "scanner": "email_security", "type": "dmarc_weak", "severity": "medium",
                "title": f"DMARC en mode monitoring (p=none) sur {domain}",
                "description": f"Le DMARC est en monitoring, pas en application. Apres une periode d'observation, durcir vers quarantine ou reject. DMARC: {dmarc}",
                "target": domain, "evidence": {"dmarc": dmarc},
            })

    # DKIM — try common selectors
    dkim_found = False
    for selector in ("default", "google", "selector1", "selector2", "k1", "mail"):
        dkim_txt = _dns_query(f"{selector}._domainkey.{domain}", "TXT")
        if any("v=DKIM1" in t or "p=" in t for t in dkim_txt):
            dkim_found = True
            break
    if not dkim_found:
        findings.append({
            "scanner": "email_security", "type": "dkim_missing", "severity": "medium",
            "title": f"DKIM non detecte sur {domain}",
            "description": "Aucun selecteur DKIM commun (default, google, selector1...) n'a ete trouve. Verifier la configuration DKIM avec votre provider mail.",
            "target": domain, "evidence": {"selectors_tried": ["default", "google", "selector1", "selector2", "k1", "mail"]},
        })

    return findings


SURFACE_SCANNERS = {
    "email_security": {
        "label": "Email security (SPF/DMARC/DKIM/MX)",
        "kinds": {"domain"},
        "callable": scan_domain_email,
        "returns_discovered": False,
    },
}
