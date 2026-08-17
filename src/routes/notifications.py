"""FEAT-35 (Surface) — the Notifications bell, served from Surface.

Suite mode: thin proxy to Pilot's single storage; the 'run a test'
delegates the full multi-module orchestration to Pilot so every bell
behaves identically. Standalone: local storage + local test. Identity
required (503 under AUTH_MODE=none, sentinel contract).
"""
from __future__ import annotations

import os
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_identity
from src.database import get_db
from src.models import NotificationPrefs, User

router = APIRouter(prefix="/api/me/notification-prefs", tags=["notifications"])

PILOT_URL = os.getenv("PILOT_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

_VALID_SEVERITIES = ("low", "medium", "high", "critical")


def _suite_mode() -> bool:
    return bool(PILOT_URL and SERVICE_TOKEN)


def _normalize_surface(raw: dict | None) -> dict:
    from src.surface_notify import SURFACE_PREF_DEFAULTS
    out = dict(SURFACE_PREF_DEFAULTS)
    src = raw or {}
    out["alert_enabled"] = bool(src.get("alert_enabled", out["alert_enabled"]))
    v = src.get("alert_min_severity", out["alert_min_severity"])
    if v not in _VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail=f"alert_min_severity must be one of {_VALID_SEVERITIES}")
    out["alert_min_severity"] = v
    pref = str(src.get("subject_prefix", out["subject_prefix"]) or "").strip()[:60]
    out["subject_prefix"] = pref or "[Surface]"
    return out


async def _pilot(method: str, path: str, **kw):
    try:
        async with httpx.AsyncClient(timeout=35.0) as client:
            resp = await client.request(
                method, PILOT_URL.rstrip("/") + path,
                headers={"X-Service-Token": SERVICE_TOKEN}, **kw)
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Pilot unreachable")
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="unknown user in Pilot")
    if not resp.is_success:
        raise HTTPException(status_code=resp.status_code, detail=resp.text[:300])
    return resp.json()


@router.get("")
async def get_prefs(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("GET", "/api/internal/notification-prefs",
                            params={"email": user.email})
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    return {"lang": (p.lang if p else "fr"),
            "module_prefs": {"surface": _normalize_surface(
                ((p.module_prefs if p else {}) or {}).get("surface"))}}


@router.put("")
async def put_prefs(body: dict,
                    user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("PUT", "/api/internal/notification-prefs",
                            json={"email": user.email, "prefs": body})
    lang = body.get("lang", "fr")
    if lang not in ("fr", "en"):
        raise HTTPException(status_code=422, detail="lang must be fr|en")
    block = _normalize_surface((body.get("module_prefs") or {}).get("surface"))
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    if p is None:
        p = NotificationPrefs(user_id=user.id)
        db.add(p)
    p.lang = lang
    p.module_prefs = {"surface": block}
    await db.commit()
    return {"lang": p.lang, "module_prefs": {"surface": block}}


@router.post("/test")
async def send_test(user: Optional[User] = Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    user = require_identity(user)
    if _suite_mode():
        return await _pilot("POST", "/api/internal/notification-test-all",
                            json={"email": user.email})
    from src.surface_notify import SURFACE_PREF_DEFAULTS, surface_prefs_of, send_test_alert
    p = (await db.execute(
        select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)
    )).scalar_one_or_none()
    prefs = surface_prefs_of({"module_prefs": (p.module_prefs if p else {}) or {},
                              "lang": p.lang if p else "fr"})
    if not prefs.get("alert_enabled"):
        return {"results": {"surface": "skipped_disabled"}}
    status = await send_test_alert(db, user.email, prefs)
    if status == "failed":
        raise HTTPException(status_code=502, detail="Envoi SMTP en échec — vérifier la configuration SMTP")
    return {"results": {"surface": status}}
