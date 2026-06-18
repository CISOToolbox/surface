from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete as sa_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.orm import selectinload

from src.auth import get_current_user
from src.database import get_db
from src.models import Finding, Measure, User
from src.rate_limit import check_scan_quota
from src.schemas import FindingCreate, FindingResponse, FindingTriage
from src.audit import log_action

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _to_dict(f: Finding, *, include_evidence: bool = True) -> dict:
    measure_id = f.measure.id if f.measure else None
    ev = f.evidence or {}
    if include_evidence:
        evidence = ev
    else:
        # Strip heavy blobs (base64 screenshots) from list responses.
        # The frontend fetches full evidence via GET /findings/{id}.
        evidence = {k: v for k, v in ev.items() if k != "png_b64"} if ev else {}
        if "png_b64" in ev:
            evidence["has_screenshot"] = True
    return {
        "id": f.id, "scanner": f.scanner, "type": f.type, "severity": f.severity,
        "title": f.title, "description": f.description or "", "target": f.target or "",
        "evidence": evidence, "status": f.status,
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
    _VALID_STATUSES = {"new", "to_fix", "false_positive", "fixed"}
    _VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
    limit = max(1, min(limit, 10000))
    offset = max(0, offset)
    q = select(Finding).options(selectinload(Finding.measure)).order_by(Finding.created_at.desc())
    if status and status in _VALID_STATUSES:
        q = q.where(Finding.status == status)
    if severity and severity in _VALID_SEVERITIES:
        q = q.where(Finding.severity == severity)
    if scanner:
        q = q.where(Finding.scanner == scanner)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    findings = result.scalars().all()
    return [_to_dict(f, include_evidence=False) for f in findings]


@router.get("/screenshots")
async def list_screenshots(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return a lightweight {target → png_b64} map of all screenshot
    findings. Used by the host-cards grid to render thumbnails without
    loading every finding's full evidence blob."""
    result = await db.execute(
        select(Finding.target, Finding.evidence, Finding.created_at)
        .where(Finding.scanner == "screenshot")
        .where(Finding.evidence.op("?")("png_b64"))
        .order_by(Finding.created_at.desc())
    )
    by_host: dict[str, str] = {}
    for target, evidence, _ts in result.all():
        host = (target or "").split(":")[0]
        if host and host not in by_host:
            by_host[host] = (evidence or {}).get("png_b64", "")
    return by_host


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
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    await log_action(db, user, request, "finding.delete", target=f"{f.cve_id or f.title[:60]}")
    await db.delete(f)
    await db.commit()


@router.patch("/{finding_id}/triage")
async def triage_finding(
    finding_id: uuid.UUID,
    body: FindingTriage,
    request: Request,
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
            deleted_id = m.id
            await db.delete(m)
            await db.commit()
            from src.pilot_notify import notify_pilot_measure_deleted
            asyncio.ensure_future(notify_pilot_measure_deleted(deleted_id))
            await db.refresh(f)
            return _to_dict(f)

    await db.commit()
    await db.refresh(f)
    if new_status == "to_fix":
        measure = (await db.execute(select(Measure).where(Measure.finding_id == finding_id))).scalar_one_or_none()
        if measure:
            from src.routes.internal import _measure_to_pilot_payload
            from src.pilot_notify import notify_pilot_measure
            asyncio.ensure_future(notify_pilot_measure(_measure_to_pilot_payload(measure, f)))
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
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    check_scan_quota(str(user.id) if user else "anonymous")
    """Apply the same triage to N findings at once.

    For status == "to_fix": update triage metadata on every finding,
    partition into covered (already have a Measure) vs uncovered, update
    existing measures' fields in place, and create ONE new Measure
    covering all uncovered findings via finding_ids JSONB (migration 006).

    For status == "false_positive": attach the same justification to all
    findings and delete any linked measures.
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
    if findings:
        await log_action(db, user, request, "finding.bulk_triage",
                         target=f"{len(findings)} findings", details={"status": body.status})
    if not findings:
        raise HTTPException(status_code=404, detail="Aucun finding trouve pour les ids fournis")

    triaged_by = (user.name if user else None) or (user.email if user else "system")
    now = datetime.now(timezone.utc)

    updated: list[dict] = []
    measures_created = 0

    # Pass 1: update status + triage metadata on every finding.
    for f in findings:
        f.status = body.status
        f.triaged_at = now
        f.triaged_by = triaged_by
        if body.notes is not None:
            f.triage_notes = body.notes
        updated.append({"id": str(f.id), "status": f.status})

    if body.status == "to_fix":
        # Simple semantics: each bulk triage creates ONE new Measure
        # covering exactly the selected findings. No merging with
        # existing measures — finding_ids always equals the user's
        # current selection. See AppSec bulk_triage for the rationale.
        count_result = await db.execute(select(func.count()).select_from(Measure))
        base_count = count_result.scalar() or 0
        primary = findings[0]
        seen: set[str] = set()
        unique_ids: list[str] = []
        for f in findings:
            s = str(f.id)
            if s not in seen:
                seen.add(s)
                unique_ids.append(s)
        description = (
            body.measure_description
            or (primary.description or "")
        ).strip()
        db.add(Measure(
            id=f"SRF-{uuid.uuid4().hex[:8].upper()}",
            finding_id=primary.id,
            finding_ids=unique_ids,
            sort_order=base_count + 1,
            title=body.measure_title.strip()[:500],
            description=description[:2000],
            statut="a_faire",
            responsable=(body.responsable or "").strip(),
            echeance=(body.echeance or "").strip(),
        ))
        measures_created = 1
    else:
        # Non-"to_fix" status: drop the legacy 1:1 linked measure only.
        # Group measures (finding_ids) are left alone — a single finding
        # flipping back to "new" doesn't retroactively undo the group.
        for f in findings:
            if f.measure is not None:
                await db.delete(f.measure)

    await db.commit()
    return {
        "updated": len(updated),
        "status": body.status,
        "measures_created": measures_created,
        "items": updated,
    }


class BulkDeleteRequest(BaseModel):
    ids: list[uuid.UUID] = _PField(..., min_length=1, max_length=500)


@router.post("/bulk-delete")
async def bulk_delete(
    body: BulkDeleteRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete N findings at once (and their linked measures via cascade)."""
    check_scan_quota(str(user.id) if user else "anonymous")
    await log_action(db, user, request, "finding.bulk_delete", target=f"{len(body.ids)} findings")
    # Collect measure IDs before deleting so we can notify Pilot
    measure_rows = (await db.execute(
        select(Measure.id).where(Measure.finding_id.in_(body.ids))
    )).scalars().all()
    await db.execute(sa_delete(Measure).where(Measure.finding_id.in_(body.ids)))
    result = await db.execute(sa_delete(Finding).where(Finding.id.in_(body.ids)))
    await db.commit()
    # Notify Pilot of each deleted measure
    if measure_rows:
        from src.pilot_notify import notify_pilot_measure_deleted
        for mid in measure_rows:
            asyncio.ensure_future(notify_pilot_measure_deleted(mid))
    return {"deleted": result.rowcount}
