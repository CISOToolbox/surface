from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import Measure, User
from src.schemas import MeasureUpdate

router = APIRouter(prefix="/api/measures", tags=["measures"])


def _to_dict(m: Measure) -> dict:
    return {
        "id": m.id, "finding_id": m.finding_id, "title": m.title,
        "description": m.description or "", "statut": m.statut,
        "responsable": m.responsable or "", "echeance": m.echeance or "",
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
    await db.commit()
    await db.refresh(m)
    return _to_dict(m)
