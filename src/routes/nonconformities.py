"""FEAT-45 — non-conformities and derogations, Surface flavour.

The mechanics (states, validation, router, expiry) are shared; this file
says what a derogation covers here — a finding — and what "derogated" does
to it: the finding leaves the open queue, is silenced on re-detection, and
comes back to `to_fix` when the derogation ends.
"""
from __future__ import annotations

import uuid

from fastapi import HTTPException
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Measure, Derogation, Finding, Nonconformity
from src.nonconformity_common import make_router


class FindingHook:
    async def exists(self, db: AsyncSession, subject_type: str, subject_id: str) -> Optional[str]:
        if subject_type != "finding":
            return None
        try:
            f = await db.get(Finding, uuid.UUID(subject_id))
        except ValueError:
            return None
        if f is None:
            return None
        if f.status not in ("new", "to_fix"):
            raise HTTPException(status_code=409, detail=f"finding is '{f.status}': only a new or to-fix finding can be derogated")
        return f"{f.target or ''} — {f.title or f.id}"[:500]

    async def apply(self, db: AsyncSession, derogation: Any) -> None:
        f = await db.get(Finding, uuid.UUID(derogation.subject_id))
        if f is None:
            return
        f.status = "derogated"
        f.derogation_id = derogation.id
        f.triaged_at = datetime.now(timezone.utc)
        f.triaged_by = derogation.decided_by or "system"

    async def release(self, db: AsyncSession, derogation: Any, reason: str) -> None:
        f = await db.get(Finding, uuid.UUID(derogation.subject_id))
        if f is None or f.status != "derogated":
            return
        f.status = "to_fix"
        f.derogation_id = None
        f.triaged_at = datetime.now(timezone.utc)
        f.triaged_by = "system"
        f.triage_notes = ((f.triage_notes or "") + f"\n[Derogation {derogation.reference} {reason}]").strip()


    async def missing_measures(self, db: AsyncSession, ids: list) -> list:
        rows = (await db.execute(select(Measure.id).where(Measure.id.in_(ids)))).scalars().all()
        found = set(rows)
        return [i for i in ids if i not in found]


    async def measure_states(self, db: AsyncSession, ids: list) -> dict:
        rows = (await db.execute(select(Measure.id, Measure.statut).where(Measure.id.in_(ids)))).all()
        return {r[0]: r[1] for r in rows}


FINDING_HOOK = FindingHook()
router = make_router(Nonconformity, Derogation, FINDING_HOOK, subject_types=("finding",))
