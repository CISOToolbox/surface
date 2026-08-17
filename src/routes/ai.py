"""Surface (ASM) AI endpoints.

The shared /api/ai proxy (provider registry, key/settings management,
/complete, /runtime, /config, /keys, /validate-key, the LLM dispatch) lives in
src/ai_proxy_common.py. Only the ASM finding-triage métier — NVD enrichment,
methodology prompt and the analyze endpoint — is here.
"""
from __future__ import annotations

import datetime
import json
import re

import httpx
from fastapi import Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.ai_proxy_common import (
    _check_ai_access,
    _check_rate_limit,
    _parse_json_lax,
    _provider_complete,
    _runtime_provider_model,
    make_ai_router,
)
from src.auth import get_current_user, require_min_role, require_admin, SURFACE_ROLES
from src.database import get_db
from src.models import User

# Common /api/ai endpoints; the métier endpoint below is appended to it.
router = make_ai_router()


async def _nvd_lookup(cve_id: str) -> str:
    """Fetch verified NVD data for a CVE id and return a prompt-ready block.

    Runs server-side: the strict module CSP (connect-src 'self') blocks the
    browser from reaching services.nvd.nist.gov, so this enrichment only
    works once it is done here rather than in Surface_app.js.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
            )
        if not r.is_success:
            return ""
        vulns = r.json().get("vulnerabilities") or []
        if not vulns:
            return ""
        cve = vulns[0].get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")
        metrics = cve.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss = cvss_list[0] if cvss_list else None
        refs = ", ".join(x.get("url", "") for x in (cve.get("references") or [])[:3])
        block = (
            f"\n\nDonnées NVD vérifiées pour {cve_id} :\n"
            f"Description: {desc}\n"
            f"Publié: {cve.get('published', 'N/A')}\n"
        )
        if cvss:
            cd = cvss.get("cvssData", {})
            block += (
                f"CVSS: {cd.get('baseScore')} ({cd.get('baseSeverity')})\n"
                f"Vecteur: {cd.get('vectorString')}\n"
            )
        return block + f"Références: {refs}"
    except (httpx.HTTPError, ValueError, KeyError, IndexError):
        return ""


def _finding_analysis_system() -> str:
    """System prompt for the ASM finding triage — methodology owned here."""
    today = datetime.date.today().isoformat()
    year = today[:4]
    return (
        "Tu es un analyste cybersécurité senior. L'utilisateur te donne un finding issu d'un scan ASM. "
        f"Date du jour : {today}. Les CVE avec année {year} ou antérieure sont valides et publiées. "
        "Les bases de données du scanner sont à jour — fais confiance aux données CVE fournies. "
        "NE REJETTE PAS un CVE comme faux ou hallucination en te basant uniquement sur l'année. "
        "Si un CVE ID est présent, utilise les données NVD fournies ci-dessous (si disponibles) comme source de vérité. "
        "Tu dois répondre UNIQUEMENT en JSON strict, sans texte autour, avec ces champs : "
        '{"is_probable_false_positive": boolean, "confidence": number between 0 and 1, '
        '"severity_recommendation": "critical"|"high"|"medium"|"low"|"info", '
        '"summary": "2-3 phrases expliquant la finding au CISO", '
        '"remediation": ["étape 1", "étape 2", "étape 3"], '
        '"references": ["URL 1", "URL 2"]}. '
        "Sois concret et actionnable."
    )


class FindingAnalyzeRequest(BaseModel):
    scanner: str = ""
    type: str = ""
    target: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    evidence: dict = {}


class FindingAnalyzeResponse(BaseModel):
    is_probable_false_positive: bool = False
    confidence: float = 0.0
    severity_recommendation: str = ""
    summary: str = ""
    remediation: list[str] = []
    references: list[str] = []


@router.post("/surface/analyze-finding", response_model=FindingAnalyzeResponse)
async def analyze_finding(body: FindingAnalyzeRequest,
                          user: User = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """Triage one ASM finding: false-positive verdict, severity recommendation,
    CISO summary and remediation steps. The methodology prompt and the NVD
    enrichment are built server-side — the frontend only posts the raw finding.
    """
    require_min_role(user, "editor", SURFACE_ROLES)
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    provider, model = await _runtime_provider_model(db)

    cve = re.search(r"CVE-\d{4}-\d+", f"{body.title} {body.description}")
    nvd_block = await _nvd_lookup(cve.group(0)) if cve else ""

    user_prompt = (
        f"Scanner : {body.scanner or 'unknown'}\n"
        f"Type : {body.type or 'unknown'}\n"
        f"Cible : {body.target or 'unknown'}\n"
        f"Sévérité actuelle : {body.severity or 'unknown'}\n"
        f"Titre : {body.title}\n\n"
        f"Description :\n{body.description or '(aucune)'}\n\n"
        f"Évidence :\n{json.dumps(body.evidence or {}, indent=2, ensure_ascii=False)}"
        f"{nvd_block}"
    )
    raw = await _provider_complete(db, _finding_analysis_system(), user_prompt, provider, model)
    parsed = _parse_json_lax(raw)
    refs = [str(x) for x in (parsed.get("references") or [])
            if str(x).startswith(("http://", "https://"))]
    return FindingAnalyzeResponse(
        is_probable_false_positive=bool(parsed.get("is_probable_false_positive")),
        confidence=float(parsed.get("confidence") or 0.0),
        severity_recommendation=str(parsed.get("severity_recommendation") or ""),
        summary=str(parsed.get("summary") or ""),
        remediation=[str(x) for x in (parsed.get("remediation") or [])],
        references=refs,
    )
