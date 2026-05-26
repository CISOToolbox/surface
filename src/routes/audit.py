"""Audit log viewing endpoint — admin-only."""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user, require_admin
from src.audit import log_action
from src.database import get_db
from src.models import AppSettings, AuditLog, User

router = APIRouter(prefix="/api/audit-log", tags=["audit"])


@router.get("")
async def list_audit_log(
    action: str | None = Query(None),
    user_email: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    query = select(AuditLog).order_by(AuditLog.logged_at.desc())
    if action:
        query = query.where(AuditLog.action == action)
    if user_email:
        query = query.where(AuditLog.user_email.ilike(f"%{user_email}%"))
    if q:
        like = f"%{q}%"
        from sqlalchemy import or_
        query = query.where(or_(
            AuditLog.action.ilike(like),
            AuditLog.target.ilike(like),
            AuditLog.details.ilike(like),
            AuditLog.user_email.ilike(like),
        ))

    total_q = await db.execute(select(func.count()).select_from(query.subquery()))
    total = total_q.scalar() or 0

    result = await db.execute(query.offset(offset).limit(limit))
    entries = result.scalars().all()

    return {
        "items": [
            {
                "id": str(e.id),
                "logged_at": e.logged_at.isoformat() if e.logged_at else "",
                "user_email": e.user_email,
                "user_name": e.user_name or "",
                "action": e.action,
                "target": e.target or "",
                "details": e.details or "",
                "ip_address": e.ip_address or "",
            }
            for e in entries
        ],
        "total": total,
    }


# ── Audit retention setting ──────────────────────────────────

@router.get("/retention")
async def get_retention(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    result = await db.execute(
        select(AppSettings).where(AppSettings.key == "audit_retention_days")
    )
    row = result.scalar_one_or_none()
    return {"audit_retention_days": int(row.value) if row and row.value.isdigit() else 365}


class RetentionBody(BaseModel):
    days: int


@router.put("/retention")
async def set_retention(
    body: RetentionBody,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if body.days < 30 or body.days > 3650:
        raise HTTPException(status_code=400, detail="Retention must be between 30 and 3650 days")
    result = await db.execute(
        select(AppSettings).where(AppSettings.key == "audit_retention_days")
    )
    row = result.scalar_one_or_none()
    if row:
        row.value = str(body.days)
    else:
        db.add(AppSettings(key="audit_retention_days", value=str(body.days)))
    await log_action(db, user, request, "settings.audit_retention",
                     target=f"{body.days} days")
    await db.commit()
    return {"audit_retention_days": body.days}


# ── Internal endpoint for Pilot aggregation ──────────────────

@router.get("/internal")
async def internal_audit_log(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Return recent audit entries for Pilot aggregation. Auth via service token."""
    import os, secrets as _secrets
    svc_token = os.getenv("SERVICE_TOKEN", "")
    if not svc_token:
        raise HTTPException(status_code=503, detail="Service token not configured")
    req_token = request.headers.get("X-Service-Token", "")
    if not req_token or not _secrets.compare_digest(req_token, svc_token):
        raise HTTPException(status_code=403, detail="Invalid service token")

    result = await db.execute(
        select(AuditLog).order_by(AuditLog.logged_at.desc()).limit(limit)
    )
    module = os.getenv("MODULE_NAME", "unknown")
    return {
        "module": module,
        "items": [
            {
                "logged_at": e.logged_at.isoformat() if e.logged_at else "",
                "user_email": e.user_email,
                "action": e.action,
                "target": e.target or "",
                "details": e.details or "",
                "module": module,
            }
            for e in result.scalars().all()
        ],
    }
