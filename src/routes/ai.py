from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import re
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import auth_enabled, get_current_user, require_admin
from src.database import get_db
from src.models import AppSettings, User
from src.schemas import AICompleteRequest, AICompleteResponse, AIConfigResponse, AIRuntimeResponse

router = APIRouter(prefix="/api/ai", tags=["ai"])

AI_PROVIDERS = {
    "anthropic": {
        "label": "Anthropic (Claude)",
        "models": [
            {"id": "claude-opus-4-8", "label": "Claude Opus 4.8"},
            {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
            {"id": "claude-haiku-4-5-20251001", "label": "Claude Haiku 4.5"},
            {"id": "claude-opus-4-6", "label": "Claude Opus 4.6"},
        ],
        "defaultModel": "claude-sonnet-4-6",
        "endpoint": "https://api.anthropic.com/v1/messages",
    },
    "openai": {
        "label": "OpenAI (GPT)",
        "models": [
            {"id": "gpt-5.5", "label": "GPT-5.5"},
            {"id": "gpt-5.5-pro", "label": "GPT-5.5 Pro"},
            {"id": "gpt-5.4-mini", "label": "GPT-5.4 mini"},
            {"id": "gpt-4o", "label": "GPT-4o"},
            {"id": "gpt-4o-mini", "label": "GPT-4o mini"},
        ],
        "defaultModel": "gpt-5.5",
        "endpoint": "https://api.openai.com/v1/chat/completions",
    },
    "bedrock": {
        "label": "AWS Bedrock",
        "models": [
            {"id": "anthropic.claude-sonnet-4-6-20250514-v1:0", "label": "Claude Sonnet 4.6 (Bedrock)"},
            {"id": "anthropic.claude-haiku-4-5-20251001-v1:0", "label": "Claude Haiku 4.5 (Bedrock)"},
        ],
        "defaultModel": "anthropic.claude-sonnet-4-6-20250514-v1:0",
        "endpoint": "https://bedrock-runtime.{region}.amazonaws.com",
    },
}


async def _get_custom_llm(db):
    # Custom LLM provisioning comes from the suite-integration `internal`
    # router when deployed as part of the CISO Toolbox suite. In standalone
    # deployments that file is absent — fall back to the module's own
    # AppSettings (custom LLM configured via PUT /api/ai/keys).
    try:
        from src.routes.internal import _custom_llm
        cl = dict(_custom_llm)
    except ImportError:
        cl = {}
    if not cl.get("endpoint"):
        ep = await _get_setting("ai_custom_endpoint", db)
        if ep:
            cl = {
                "endpoint": ep,
                "key": await _get_setting("ai_custom_key", db),
                "model": await _get_setting("ai_custom_model", db),
                "label": "Custom LLM",
            }
    return cl


async def _get_api_key(provider: str, db: AsyncSession) -> str | None:
    key_name = f"ai_key_{provider}"
    result = await db.execute(select(AppSettings).where(AppSettings.key == key_name))
    setting = result.scalar_one_or_none()
    if setting and setting.value:
        return setting.value
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY")
    return None


async def _get_setting(key: str, db: AsyncSession) -> str:
    r = await db.execute(select(AppSettings).where(AppSettings.key == key))
    s = r.scalar_one_or_none()
    return (s.value if s and s.value else "") or ""


def _sign_v4(method, url, body, access_key, secret_key, region, service):
    """Minimal AWS Signature V4 -- ported from ai_common.js (_signV4)."""
    from urllib.parse import urlparse
    u = urlparse(url)
    date_stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    short_date = date_stamp[:8]
    payload_hash = hashlib.sha256((body or "").encode()).hexdigest()
    headers = {
        "host": u.netloc,
        "x-amz-date": date_stamp,
        "x-amz-content-sha256": payload_hash,
        "content-type": "application/json",
    }
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    canonical_request = "\n".join([
        method, u.path or "/", u.query, canonical_headers, signed_headers, payload_hash,
    ])
    credential_scope = f"{short_date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", date_stamp, credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_signing = _h(_h(_h(_h(("AWS4" + secret_key).encode(), short_date), region), service), "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


_ai_rate: dict[str, list[float]] = {}
AI_RATE_LIMIT = 20


def _check_rate_limit(user_id: str) -> None:
    now = time.time()
    times = _ai_rate.get(user_id, [])
    times = [t for t in times if now - t < 60]
    if len(times) >= AI_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (max 20/min)")
    times.append(now)
    _ai_rate[user_id] = times


def _check_ai_access(user: Optional[User]) -> None:
    if not auth_enabled() or user is None:
        return
    if user.role == "admin":
        return
    if user.ai_enabled != "true":
        raise HTTPException(status_code=403, detail="AI access not granted. Contact your administrator.")


async def _provider_complete(db: AsyncSession, system: str, user_msg: str,
                             provider: str, model: str, max_tokens: int = 4096) -> str:
    """Call the configured AI provider with a system + user prompt and return
    the raw text. Shared by POST /complete and the métier endpoints below.

    A custom provider needs no API key (the key is optional and carried by
    _get_custom_llm); every other provider must have one.
    """
    api_key = await _get_api_key(provider, db)
    if not api_key and provider != "custom":
        raise HTTPException(status_code=503, detail=f"API key not configured for provider: {provider}")
    provider_conf = AI_PROVIDERS.get(provider)
    if provider != "custom" and not provider_conf:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            if provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": model,
                        "max_tokens": max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": user_msg}],
                    },
                )
            elif provider == "custom":
                custom = await _get_custom_llm(db)
                if not custom.get("endpoint"):
                    raise HTTPException(status_code=503, detail="Custom LLM not configured")
                url = custom["endpoint"].rstrip("/")
                # Validate the custom endpoint: must be HTTPS + resolve to a
                # non-private IP. Blocks SSRF to Docker siblings / cloud metadata.
                from urllib.parse import urlparse
                from src.scanners import _resolve_safe_target
                parsed_custom = urlparse(url)
                if parsed_custom.scheme != "https" or not parsed_custom.hostname:
                    raise HTTPException(status_code=400, detail="Custom LLM endpoint must be https://")
                try:
                    _resolve_safe_target(parsed_custom.hostname)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Custom LLM endpoint blocked: {e}")
                if not url.endswith("/chat/completions"):
                    url += "/chat/completions"
                hdrs = {"Content-Type": "application/json"}
                if custom.get("key"):
                    hdrs["Authorization"] = f"Bearer {custom['key']}"
                resp = await client.post(
                    url, headers=hdrs,
                    json={
                        "model": custom.get("model") or model,
                        "max_tokens": max_tokens,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user_msg},
                        ],
                    },
                )
            elif provider == "bedrock":
                region = await _get_setting("ai_region_bedrock", db) or "us-east-1"
                secret = await _get_setting("ai_secret_bedrock", db)
                if not secret:
                    raise HTTPException(status_code=503, detail="Bedrock secret key / region not configured")
                from urllib.parse import quote
                b_url = f"https://bedrock-runtime.{region}.amazonaws.com/model/{quote(model, safe='')}/invoke"
                b_body = json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user_msg}],
                })
                sig_headers = _sign_v4("POST", b_url, b_body, api_key, secret, region, "bedrock")
                resp = await client.post(b_url, headers=sig_headers, content=b_body)
            else:
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "model": model,
                        "max_tokens": max_tokens,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user_msg},
                        ],
                    },
                )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="AI provider timeout")
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"AI provider error: {e}")

    if resp.status_code in (401, 403):
        raise HTTPException(status_code=503, detail="Invalid API key configured on server")
    if not resp.is_success:
        raise HTTPException(status_code=502, detail=f"AI provider returned error {resp.status_code}")

    data = resp.json()
    if provider in ("anthropic", "bedrock"):
        return data.get("content", [{}])[0].get("text", "")
    return data.get("choices", [{}])[0].get("message", {}).get("content", "")


@router.post("/complete", response_model=AICompleteResponse)
async def ai_complete(body: AICompleteRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Generic low-level proxy: relays a pre-built {system, user} prompt to the
    provider. Métier endpoints (below) are preferred — they build the prompt
    server-side from structured data."""
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    text = await _provider_complete(db, body.system, body.user, body.provider, body.model)
    return AICompleteResponse(text=text)


def _ai_managed() -> bool:
    return os.getenv("AI_MANAGED_BY_PILOT", "false").lower() in ("1", "true", "yes")


async def _runtime_provider_model(db: AsyncSession) -> tuple[str, str]:
    async def _get(key: str) -> str:
        r = await db.execute(select(AppSettings).where(AppSettings.key == key))
        s = r.scalar_one_or_none()
        return (s.value if s and s.value else "") or ""
    provider = await _get("ai_provider") or "anthropic"
    model = await _get("ai_model") or AI_PROVIDERS.get(provider, AI_PROVIDERS["anthropic"])["defaultModel"]
    return provider, model


@router.get("/runtime", response_model=AIRuntimeResponse)
async def get_ai_runtime(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    managed = _ai_managed()
    if not auth_enabled() or user is None:
        can_use = True
    else:
        can_use = (user.role == "admin") or (user.ai_enabled == "true")
    provider, model = await _runtime_provider_model(db)
    try:
        custom = await _get_custom_llm(db)
        custom_configured = bool(custom.get("endpoint"))
    except Exception:
        custom_configured = False
    return AIRuntimeResponse(
        managed=managed,
        can_use=can_use,
        provider=provider,
        model=model,
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        custom_configured=custom_configured,
    )


@router.get("/config", response_model=AIConfigResponse)
async def get_ai_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    custom = await _get_custom_llm(db)
    providers = dict(AI_PROVIDERS)
    if custom.get("endpoint"):
        providers["custom"] = {
            "label": custom.get("label", "Custom LLM"),
            "models": [{"id": custom.get("model", "custom"), "label": custom.get("model", "Custom")}],
            "defaultModel": custom.get("model", "custom"),
            "endpoint": custom["endpoint"],
        }
    return AIConfigResponse(
        anthropic_configured=bool(await _get_api_key("anthropic", db)),
        openai_configured=bool(await _get_api_key("openai", db)),
        providers=providers,
    )


@router.put("/keys")
async def set_ai_keys(body: dict, request: Request, db: AsyncSession = Depends(get_db)):
    """Set API keys. Authorized via service token (from Pilot) or admin user."""
    service_token = request.headers.get("X-Service-Token", "")
    if not (service_token and service_token == os.getenv("SERVICE_TOKEN", "")):
        try:
            user = await get_current_user(request, db)
        except HTTPException:
            raise HTTPException(status_code=401, detail="Not authenticated")
        require_admin(user)
    async def _upsert(key: str, value: str) -> None:
        r = await db.execute(select(AppSettings).where(AppSettings.key == key))
        s = r.scalar_one_or_none()
        if s:
            s.value = value
        else:
            db.add(AppSettings(key=key, value=value))
    for provider in ("anthropic", "openai", "bedrock"):
        if provider in body:
            await _upsert(f"ai_key_{provider}", body.get(provider, ""))
    # Bedrock secret/region + custom-LLM config (standalone deployments)
    for extra in ("ai_secret_bedrock", "ai_region_bedrock",
                  "ai_custom_endpoint", "ai_custom_key", "ai_custom_model"):
        if extra in body:
            await _upsert(extra, body.get(extra, ""))
    if "provider" in body:
        await _upsert("ai_provider", body.get("provider", ""))
    if "model" in body:
        await _upsert("ai_model", body.get("model", ""))
    await db.commit()
    return {"ok": True}


@router.get("/keys")
async def get_ai_keys(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    result = {}
    for provider in ("anthropic", "openai"):
        key = await _get_api_key(provider, db)
        result[provider] = "configured" if key else ""
    return result



@router.post("/validate-key")
async def validate_key(provider: str = "anthropic", user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    api_key = await _get_api_key(provider, db)
    if not api_key:
        return {"valid": False, "error": "No API key configured"}

    provider_conf = AI_PROVIDERS.get(provider)
    if not provider_conf:
        return {"valid": False, "error": "Unknown provider"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            if provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": provider_conf["defaultModel"],
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            else:
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                    json={
                        "model": provider_conf["defaultModel"],
                        "max_tokens": 1,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
            valid = resp.status_code not in (401, 403)
            return {"valid": valid}
        except Exception as e:
            return {"valid": False, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# MÉTIER ENDPOINTS — the AI methodology lives here, server-side. The
# frontend posts structured data; the prompt is built below. See
# docs/CHANTIER_IA_BACKEND.md §Phase 2.
# ═══════════════════════════════════════════════════════════════════════


def _parse_json_lax(text: str) -> dict:
    """Strip code fences and pull the outer-most JSON object — models
    occasionally wrap the answer in ```json … ``` despite instructions."""
    m = re.search(r"\{[\s\S]*\}", (text or "").strip())
    if not m:
        raise HTTPException(status_code=502, detail="AI did not return JSON")
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"AI returned invalid JSON: {exc}") from exc


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
