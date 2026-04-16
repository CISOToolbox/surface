from __future__ import annotations

import os
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Request, Depends, HTTPException
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
            {"id": "claude-sonnet-4-6", "label": "Claude Sonnet 4.6"},
            {"id": "claude-opus-4-6", "label": "Claude Opus 4.6"},
        ],
        "defaultModel": "claude-sonnet-4-6",
        "endpoint": "https://api.anthropic.com/v1/messages",
    },
    "openai": {
        "label": "OpenAI (GPT)",
        "models": [
            {"id": "gpt-4o", "label": "GPT-4o"},
            {"id": "gpt-4o-mini", "label": "GPT-4o mini"},
        ],
        "defaultModel": "gpt-4o",
        "endpoint": "https://api.openai.com/v1/chat/completions",
    },
}


async def _get_custom_llm(db):
    # Custom LLM provisioning comes from the suite-integration `internal`
    # router when the module is deployed as part of the CISO Toolbox suite.
    # In standalone deployments that file is absent and there is no custom
    # provider — return an empty dict so the caller falls back cleanly.
    try:
        from src.routes.internal import _custom_llm
    except ImportError:
        return {}
    return dict(_custom_llm)


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


@router.post("/complete", response_model=AICompleteResponse)
async def ai_complete(body: AICompleteRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    _check_ai_access(user)
    _check_rate_limit(str(user.id) if user else "anonymous")
    api_key = await _get_api_key(body.provider, db)
    if not api_key:
        raise HTTPException(status_code=503, detail=f"API key not configured for provider: {body.provider}")

    provider_conf = AI_PROVIDERS.get(body.provider)
    if not provider_conf:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {body.provider}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            if body.provider == "anthropic":
                resp = await client.post(
                    provider_conf["endpoint"],
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": body.model,
                        "max_tokens": 4096,
                        "system": body.system,
                        "messages": [{"role": "user", "content": body.user}],
                    },
                )
            elif body.provider == "custom":
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
                        "model": custom.get("model") or body.model,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": body.system},
                            {"role": "user", "content": body.user},
                        ],
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
                        "model": body.model,
                        "max_tokens": 4096,
                        "messages": [
                            {"role": "system", "content": body.system},
                            {"role": "user", "content": body.user},
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

    if body.provider == "anthropic":
        text = data.get("content", [{}])[0].get("text", "")
    else:
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")

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
    for provider in ("anthropic", "openai"):
        if provider in body:
            await _upsert(f"ai_key_{provider}", body.get(provider, ""))
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
