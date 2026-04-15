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


async def insert_many(db: AsyncSession, finding_dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply insert_or_dedupe on a batch and return per-action counts plus
    the diff vs the previous state.

    The result dict has the v0.1.x integer keys (`inserted`, `refreshed`,
    `reopened`, `silenced`) and **also** v0.2 lists used by the Scans page:

        added:       new findings inserted
        reopened_l:  findings whose status went back to 'new'
        gone:        dedup keys that exist in the DB for this scope but
                     were NOT seen in the current scan — *informational*
                     only, callers can use this for the "what's new"
                     summary on the per-host timeline. Currently empty
                     because the dedup helper does not know the scope.
    """
    counts: dict[str, Any] = {
        "inserted": 0, "refreshed": 0, "reopened": 0, "silenced": 0,
        "added": [], "reopened_l": [], "gone": [],
    }
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
            if action == "inserted":
                counts["added"].append({
                    "title": fd.get("title", "")[:140],
                    "severity": fd.get("severity", ""),
                    "scanner": fd.get("scanner", ""),
                    "target": fd.get("target", ""),
                })
            elif action == "reopened":
                counts["reopened_l"].append({
                    "title": fd.get("title", "")[:140],
                    "severity": fd.get("severity", ""),
                    "scanner": fd.get("scanner", ""),
                    "target": fd.get("target", ""),
                })
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


def diff_summary(counts: dict[str, Any]) -> dict[str, Any]:
    """Compact ScanJob.diff value: counts only, plus the first 5 added titles
    so the UI badge can show "+3 (XSS, sqli, …)" without re-querying."""
    added = counts.get("added") or []
    reopened = counts.get("reopened_l") or []
    return {
        "added": len(added),
        "reopened": len(reopened),
        "refreshed": counts.get("refreshed", 0),
        "silenced": counts.get("silenced", 0),
        "added_sample": added[:5],
        "reopened_sample": reopened[:5],
    }
