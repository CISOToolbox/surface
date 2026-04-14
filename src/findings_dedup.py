"""Deduplication helper for findings.

When a scanner produces a finding, we don't want to re-create a row that already
exists. The behavior depends on the existing finding's status:

    new            → refresh title/description/evidence/severity, bump last_seen_at
    false_positive → keep frozen (just bump last_seen_at), do NOT re-emit
    to_fix +
        measure not 'termine' → keep frozen, bump last_seen_at
        measure  'termine'    → reopen as 'new' (the issue came back after fix)
    fixed          → reopen as 'new'

The dedup key is `<scanner>|<type>|<target>`. Same key = same logical issue
across rescans. For findings without a target (rare) we fall back to title hash.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models import Finding

logger = logging.getLogger("surface.dedup")


def compute_dedup_key(scanner: str, type_: str, target: str) -> str:
    return f"{(scanner or '?').lower()}|{(type_ or '?').lower()}|{(target or '').lower()}"


async def insert_or_dedupe(db: AsyncSession, fd: dict[str, Any]) -> str:
    """Insert a finding with deduplication. Returns the action taken:

    'inserted'   — brand new finding
    'refreshed'  — updated existing 'new' finding's content + last_seen_at
    'reopened'   — existing was fixed/triaged-as-to-fix-then-completed; reopened as new
    'silenced'   — existing is false_positive or has an active to_fix measure → no re-emission
    """
    key = compute_dedup_key(fd.get("scanner", ""), fd.get("type", ""), fd.get("target", "") or fd.get("title", ""))
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(Finding).options(selectinload(Finding.measure)).where(Finding.dedup_key == key).limit(1)
    )
    existing = result.scalar_one_or_none()

    if existing is None:
        f = Finding(**fd, status="new", dedup_key=key, last_seen_at=now)
        db.add(f)
        return "inserted"

    if existing.status == "false_positive":
        existing.last_seen_at = now
        return "silenced"

    if existing.status == "to_fix":
        if existing.measure and existing.measure.statut != "termine":
            existing.last_seen_at = now
            return "silenced"
        # Measure is terminée OR no measure attached → reopen
        existing.status = "new"
        existing.title = fd.get("title", existing.title)
        existing.description = (fd.get("description", "") or "") + "\n\n[Reouvert : detecte a nouveau apres remediation]"
        existing.evidence = fd.get("evidence", {}) or {}
        existing.severity = fd.get("severity", existing.severity)
        existing.triaged_at = None
        existing.triaged_by = None
        existing.triage_notes = ""
        existing.last_seen_at = now
        return "reopened"

    if existing.status == "fixed":
        existing.status = "new"
        existing.title = fd.get("title", existing.title)
        existing.description = (fd.get("description", "") or "") + "\n\n[Reouvert : detecte a nouveau]"
        existing.evidence = fd.get("evidence", {}) or {}
        existing.severity = fd.get("severity", existing.severity)
        existing.last_seen_at = now
        return "reopened"

    # status == 'new': refresh content
    existing.title = fd.get("title", existing.title)
    existing.description = fd.get("description", existing.description)
    existing.evidence = fd.get("evidence", existing.evidence) or existing.evidence
    existing.severity = fd.get("severity", existing.severity)
    existing.last_seen_at = now
    return "refreshed"


async def insert_many(db: AsyncSession, finding_dicts: list[dict[str, Any]]) -> dict[str, int]:
    """Apply insert_or_dedupe on a batch and return per-action counts.

    Pre-fetches all existing findings matching the batch's dedup keys in a
    single IN query to avoid N+1 SELECT queries. The per-row logic still
    runs through insert_or_dedupe to preserve the status-machine semantics.

    If two concurrent scans race to insert the same dedup_key, the DB's
    UNIQUE constraint rejects one of them with IntegrityError — we rollback
    and retry the insert path, which now sees the row the winner just
    inserted and takes the refresh branch instead.
    """
    counts = {"inserted": 0, "refreshed": 0, "reopened": 0, "silenced": 0}
    if not finding_dicts:
        return counts

    # Warm the SQLAlchemy identity map with one query for the whole batch.
    keys = {
        compute_dedup_key(
            fd.get("scanner", ""),
            fd.get("type", ""),
            fd.get("target", "") or fd.get("title", ""),
        )
        for fd in finding_dicts
    }
    if keys:
        await db.execute(
            select(Finding)
            .options(selectinload(Finding.measure))
            .where(Finding.dedup_key.in_(keys))
        )

    for fd in finding_dicts:
        try:
            action = await insert_or_dedupe(db, fd)
            await db.flush()
            counts[action] = counts.get(action, 0) + 1
        except IntegrityError:
            await db.rollback()
            try:
                action = await insert_or_dedupe(db, fd)
                await db.flush()
                counts[action] = counts.get(action, 0) + 1
            except Exception:
                logger.exception("dedup retry failed for %s", fd.get("title"))
        except Exception:
            logger.exception("dedup insert failed for %s", fd.get("title"))
    return counts
