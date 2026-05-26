from __future__ import annotations

import asyncio

from fastapi import Request, APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import Finding, Measure, User
from src.schemas import MeasureUpdate
from src.audit import log_action

router = APIRouter(prefix="/api/measures", tags=["measures"])


def _to_dict(m: Measure) -> dict:
    return {
        "id": m.id,
        "finding_id": str(m.finding_id) if m.finding_id else None,
        "finding_ids": m.finding_ids or [],
        "title": m.title,
        "description": m.description or "",
        "statut": m.statut,
        "responsable": m.responsable or "",
        "echeance": m.echeance or "",
        "created_at": m.created_at,
    }


@router.get("")
async def list_measures(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Measure).order_by(Measure.sort_order))
    return [_to_dict(m) for m in result.scalars().all()]


@router.patch("/{measure_id}")
async def update_measure(
    measure_id: str,
    body: MeasureUpdate,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    m = await db.get(Measure, measure_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    if body.title is not None:
        m.title = body.title
    if body.description is not None:
        m.description = body.description
    if body.statut is not None:
        m.statut = body.statut
    if body.responsable is not None:
        m.responsable = body.responsable
    if body.echeance is not None:
        m.echeance = body.echeance
    await log_action(db, user, request, "measure.update", target=m.title[:60] if m.title else "")
    await db.commit()
    await db.refresh(m)
    from src.routes.internal import _measure_to_pilot_payload
    from src.pilot_notify import notify_pilot_measure
    f = await db.get(Finding, m.finding_id) if m.finding_id else None
    asyncio.ensure_future(notify_pilot_measure(_measure_to_pilot_payload(m, f)))
    return _to_dict(m)


@router.delete("/{measure_id}", status_code=204)
async def delete_measure(
    measure_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    m = await db.get(Measure, measure_id)
    if not m:
        raise HTTPException(status_code=404, detail="Measure not found")
    mid = m.id
    await log_action(db, user, request, "measure.delete", target=m.title[:60] if m.title else "")
    await db.delete(m)
    await db.commit()
    try:
        from src.pilot_notify import notify_pilot_measure_deleted
        asyncio.ensure_future(notify_pilot_measure_deleted(mid))
    except Exception:
        pass
    return None
