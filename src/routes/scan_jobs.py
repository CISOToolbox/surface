"""Async scan jobs — wraps nmap and parses results into Findings.

Profiles:
  - quick    : -T4 -F (top 100 ports, fast timing)
  - standard : -T4 -sV --top-ports 1000 (top 1000 ports + service detection)
  - deep     : -T4 -sV -sC -p- (all 65535 ports, scripts, slow)

Jobs run in a FastAPI BackgroundTask. The endpoint returns immediately with a
job id; the client polls GET /api/scans/jobs to see the status. When complete,
findings are inserted into the findings table and remain triagable like any
other finding.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import async_session, get_db
from src.findings_dedup import insert_many
from src.models import Finding, ScanJob, User
from src.rate_limit import check_scan_quota
from src.scanners import _parse_nmap_xml, _resolve_safe_target

logger = logging.getLogger("surface.scan_jobs")

router = APIRouter(prefix="/api/scans", tags=["scan_jobs"])


PROFILES = {
    "quick":    ["-T4", "-F", "-Pn"],
    "standard": ["-T4", "-sV", "--top-ports", "1000", "-Pn"],
    "deep":     ["-T4", "-sV", "-sC", "-p-", "-Pn"],
}


async def _run_nmap_job(job_id: uuid.UUID) -> None:
    """Background task: execute nmap, parse output, update job, insert findings."""
    async with async_session() as db:
        job = await db.get(ScanJob, job_id)
        if not job:
            logger.error("ScanJob %s missing", job_id)
            return

        # Mark running
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await db.commit()

        nmap_path = shutil.which("nmap")
        if not nmap_path:
            job.status = "failed"
            job.error = "nmap binary not found in PATH"
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        # Re-resolve the target once more and hand nmap the locked IP, so
        # a DNS rebinding flip between queue time and run time can't redirect
        # us to a private/metadata IP. Falls back to job.target (which is
        # the already-validated canonical form) when no resolution is possible.
        try:
            locked_ip, _ = _resolve_safe_target(job.target)
        except ValueError as e:
            job.status = "failed"
            job.error = f"SSRF re-check failed: {e}"[:1000]
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return
        scan_target = locked_ip or job.target
        args = [nmap_path, "-oX", "-"] + PROFILES.get(job.profile, PROFILES["quick"]) + [scan_target]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                # Generous timeout: 30 min for deep scans
                timeout = {"quick": 180, "standard": 600, "deep": 1800}.get(job.profile, 300)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise RuntimeError(f"Scan timeout apres {timeout}s")

            if proc.returncode not in (0, None):
                err_text = (stderr.decode(errors="replace") if stderr else "")[:1000]
                raise RuntimeError(f"nmap exit {proc.returncode}: {err_text}")

            xml_text = stdout.decode(errors="replace")
            job.raw_output = xml_text[:50000]  # cap stored output

            finding_dicts = _parse_nmap_xml(xml_text, job.target)
            counts = await insert_many(db, finding_dicts)
            job.findings_count = counts.get("inserted", 0) + counts.get("reopened", 0)
            job.status = "completed"
        except Exception as e:
            logger.exception("nmap job %s failed", job_id)
            job.status = "failed"
            job.error = str(e)[:1000]
        finally:
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()


# ── Pydantic schemas ───────────────────────────────────────────

class JobCreate(BaseModel):
    target: str = Field(..., min_length=1)
    profile: str = Field("quick", pattern="^(quick|standard|deep)$")


class JobResponse(BaseModel):
    id: uuid.UUID
    target: str
    profile: str
    scanner: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: int
    error: Optional[str]
    triggered_by: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Routes ─────────────────────────────────────────────────────

def _to_dict(j: ScanJob) -> dict:
    return {
        "id": j.id, "target": j.target, "profile": j.profile, "scanner": j.scanner,
        "status": j.status, "started_at": j.started_at, "completed_at": j.completed_at,
        "findings_count": j.findings_count, "error": j.error or "",
        "triggered_by": j.triggered_by or "", "created_at": j.created_at,
    }


@router.get("/jobs")
async def list_jobs(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(50))
    return [_to_dict(j) for j in result.scalars().all()]


@router.post("/jobs", status_code=201)
async def create_job(
    body: JobCreate,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    check_scan_quota(str(user.id) if user else "anonymous")
    try:
        _, target = _resolve_safe_target(body.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    job = ScanJob(
        target=target, profile=body.profile, scanner="nmap",
        status="pending", triggered_by=(user.email if user else "system"),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    background.add_task(_run_nmap_job, job.id)
    return _to_dict(job)


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    j = await db.get(ScanJob, job_id)
    if not j:
        raise HTTPException(status_code=404, detail="Job not found")
    return _to_dict(j)


@router.delete("/jobs/{job_id}", status_code=204)
async def delete_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    j = await db.get(ScanJob, job_id)
    if not j:
        raise HTTPException(status_code=404, detail="Job not found")
    await db.delete(j)
    await db.commit()
