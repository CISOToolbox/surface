from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.orm import selectinload

from src.auth import get_current_user
from src.database import get_db
from src.models import Finding, Measure, User
from src.rate_limit import check_scan_quota
from src.schemas import FindingCreate, FindingResponse, FindingTriage

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _to_dict(f: Finding) -> dict:
    measure_id = f.measure.id if f.measure else None
    return {
        "id": f.id, "scanner": f.scanner, "type": f.type, "severity": f.severity,
        "title": f.title, "description": f.description or "", "target": f.target or "",
        "evidence": f.evidence or {}, "status": f.status,
        "triaged_at": f.triaged_at, "triaged_by": f.triaged_by, "triage_notes": f.triage_notes or "",
        "created_at": f.created_at, "measure_id": measure_id,
    }


@router.get("")
async def list_findings(
    status: str | None = None,
    severity: str | None = None,
    scanner: str | None = None,
    limit: int = 500,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Cap limit to avoid OOM on large datasets
    limit = max(1, min(limit, 2000))
    offset = max(0, offset)
    q = select(Finding).options(selectinload(Finding.measure)).order_by(Finding.created_at.desc())
    if status:
        q = q.where(Finding.status == status)
    if severity:
        q = q.where(Finding.severity == severity)
    if scanner:
        q = q.where(Finding.scanner == scanner)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    findings = result.scalars().all()
    return [_to_dict(f) for f in findings]


@router.post("", status_code=201)
async def create_finding(
    body: FindingCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if body.severity not in ("info", "low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="Invalid severity")
    f = Finding(
        scanner=body.scanner, type=body.type, severity=body.severity,
        title=body.title, description=body.description, target=body.target,
        evidence=body.evidence or {}, status="new",
    )
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return _to_dict(f)


@router.get("/{finding_id}")
async def get_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Finding).options(selectinload(Finding.measure)).where(Finding.id == finding_id)
    )
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_dict(f)


@router.delete("/{finding_id}", status_code=204)
async def delete_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    await db.delete(f)
    await db.commit()


@router.patch("/{finding_id}/triage")
async def triage_finding(
    finding_id: uuid.UUID,
    body: FindingTriage,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Triage a finding: set status to false_positive, to_fix or new.

    When status is to_fix, automatically create a Measure linked to this finding.
    When status changes from to_fix to false_positive/new, the linked measure is removed.
    """
    result = await db.execute(
        select(Finding).options(selectinload(Finding.measure)).where(Finding.id == finding_id)
    )
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    new_status = body.status
    if new_status not in ("new", "false_positive", "to_fix", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid status")

    # Per-status validation: false_positive requires a justification, to_fix requires a measure title.
    if new_status == "false_positive":
        if not (body.notes or "").strip():
            raise HTTPException(status_code=400, detail="Une justification est obligatoire pour declarer un faux positif")
    if new_status == "to_fix":
        if not (body.measure_title or "").strip():
            raise HTTPException(status_code=400, detail="Le nom de la mesure est obligatoire")

    f.status = new_status
    f.triaged_at = datetime.now(timezone.utc)
    f.triaged_by = (user.name if user else None) or (user.email if user else "system")
    if body.notes is not None:
        f.triage_notes = body.notes

    # Auto-create / remove the measure
    if new_status == "to_fix":
        existing = await db.execute(select(Measure).where(Measure.finding_id == finding_id))
        m = existing.scalar_one_or_none()
        if m is None:
            # Use a random hex suffix instead of a race-prone COUNT(*) + 1
            # to avoid unique-constraint collisions when two triages run
            # concurrently. sort_order still uses the count for chronological
            # display ordering in the Measures panel.
            count_result = await db.execute(select(func.count()).select_from(Measure))
            count = count_result.scalar() or 0
            new_id = f"SRF-{uuid.uuid4().hex[:8].upper()}"
            db.add(Measure(
                id=new_id, finding_id=finding_id, sort_order=count,
                title=body.measure_title.strip(),
                description=(body.measure_description or f.description or "").strip(),
                statut="a_faire",
                responsable=(body.responsable or "").strip(),
                echeance=(body.echeance or "").strip(),
            ))
        else:
            # Update existing measure with the new title/details
            m.title = body.measure_title.strip()
            if body.measure_description is not None:
                m.description = body.measure_description.strip()
            if body.responsable is not None:
                m.responsable = body.responsable.strip()
            if body.echeance is not None:
                m.echeance = body.echeance.strip()
    else:
        existing = await db.execute(select(Measure).where(Measure.finding_id == finding_id))
        m = existing.scalar_one_or_none()
        if m:
            await db.delete(m)

    await db.commit()
    await db.refresh(f)
    return _to_dict(f)


# ══════════════════════════════════════════════════════════
# Bulk triage — apply the same status/measure to N findings
# ══════════════════════════════════════════════════════════

from pydantic import BaseModel, Field as _PField


class BulkTriageRequest(BaseModel):
    ids: list[uuid.UUID] = _PField(..., min_length=1, max_length=500)
    status: str
    notes: str | None = None
    measure_title: str | None = None
    measure_description: str | None = None
    responsable: str | None = None
    echeance: str | None = None


@router.post("/bulk-triage")
async def bulk_triage(
    body: BulkTriageRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    check_scan_quota(str(user.id) if user else "anonymous")
    """Apply the same triage to N findings at once.

    For status='to_fix', creates ONE Measure per finding (the model requires
    a 1:1 FK), all sharing the same title/description/responsable/echeance
    so the operator can track a group of identical fixes as a single batch
    in the Measures tab.

    For status='false_positive', the same justification is attached to all
    selected findings.
    """
    if body.status not in ("new", "false_positive", "to_fix", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    if body.status == "false_positive" and not (body.notes or "").strip():
        raise HTTPException(status_code=400, detail="Une justification est obligatoire pour declarer un faux positif")
    if body.status == "to_fix" and not (body.measure_title or "").strip():
        raise HTTPException(status_code=400, detail="Le nom de la mesure est obligatoire")

    result = await db.execute(
        select(Finding).options(selectinload(Finding.measure)).where(Finding.id.in_(body.ids))
    )
    findings = result.scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="Aucun finding trouve pour les ids fournis")

    triaged_by = (user.name if user else None) or (user.email if user else "system")
    now = datetime.now(timezone.utc)

    count_result = await db.execute(select(func.count()).select_from(Measure))
    base_count = count_result.scalar() or 0
    new_measure_idx = 0

    updated: list[dict] = []

    for f in findings:
        f.status = body.status
        f.triaged_at = now
        f.triaged_by = triaged_by
        if body.notes is not None:
            f.triage_notes = body.notes

        # `f.measure` is already eager-loaded via selectinload at line 218.
        # Using it instead of re-querying avoids N+1 on bulk triages of
        # up to 500 findings.
        m = f.measure

        if body.status == "to_fix":
            if m is None:
                new_measure_idx += 1
                db.add(Measure(
                    id=f"SRF-{uuid.uuid4().hex[:8].upper()}",
                    finding_id=f.id,
                    sort_order=base_count + new_measure_idx,
                    title=body.measure_title.strip(),
                    description=(body.measure_description or f.description or "").strip(),
                    statut="a_faire",
                    responsable=(body.responsable or "").strip(),
                    echeance=(body.echeance or "").strip(),
                ))
            else:
                m.title = body.measure_title.strip()
                if body.measure_description is not None:
                    m.description = body.measure_description.strip()
                if body.responsable is not None:
                    m.responsable = body.responsable.strip()
                if body.echeance is not None:
                    m.echeance = body.echeance.strip()
        else:
            if m:
                await db.delete(m)

        updated.append({"id": str(f.id), "status": f.status})

    await db.commit()
    return {
        "updated": len(updated),
        "status": body.status,
        "measures_created": new_measure_idx,
        "items": updated,
    }


class BulkDeleteRequest(BaseModel):
    ids: list[uuid.UUID] = _PField(..., min_length=1, max_length=500)


@router.post("/bulk-delete")
async def bulk_delete(
    body: BulkDeleteRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete N findings at once (and their linked measures via cascade)."""
    check_scan_quota(str(user.id) if user else "anonymous")
    result = await db.execute(select(Finding).where(Finding.id.in_(body.ids)))
    findings = result.scalars().all()
    for f in findings:
        await db.delete(f)
    await db.commit()
    return {"deleted": len(findings)}
