"""Background scheduler that auto-runs scans on monitored assets.

Loop:
  - every TICK_SECONDS, find enabled assets where last_scan_at is null or older
    than scan_frequency_hours
  - for each, run the matching scanners (in a thread to avoid blocking)
  - insert findings, mark last_scan_at, and for ip_range scans auto-create
    monitored_assets for newly discovered hosts
  - cap to MAX_PER_TICK to spread load

The scheduler runs in the same event loop as FastAPI but the scanners
themselves are blocking (subprocess, sockets), so we use asyncio.to_thread.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from src.database import async_session
from src.findings_dedup import diff_summary, insert_many
from src.models import Finding, MonitoredAsset, ScanJob
from src.scanners import DEFAULT_SCANNERS_BY_KIND, run_enabled_scanners

logger = logging.getLogger("surface.scheduler")

TICK_SECONDS = 60          # how often the scheduler wakes up
MAX_PER_TICK = 3            # cap concurrent scans per tick to spread load
INITIAL_DELAY = 10          # seconds to wait before first tick (let the API boot)
MAX_AUTO_HOSTS_PER_SCAN = 50  # cap hosts auto-enrolled from CT/SAN per single scan


_SCANNER_BY_KIND = {
    "domain": "scheduled-domain",
    "host": "scheduled-host",
    "ip_range": "scheduled-discovery",
}


async def _scan_one(asset_id) -> None:
    """Execute the scanners for a single asset and record the run as a ScanJob."""
    async with async_session() as db:
        asset = await db.get(MonitoredAsset, asset_id)
        if not asset or not asset.enabled:
            return
        kind = asset.kind
        value = asset.value
        enabled_scanners = list(asset.enabled_scanners or []) or DEFAULT_SCANNERS_BY_KIND.get(kind, [])
        scanner_name = _SCANNER_BY_KIND.get(kind, "scheduled")

        # Create the job record (status=running, started_at=now)
        job = ScanJob(
            target=value, profile="scheduled", scanner=scanner_name,
            status="running", started_at=datetime.now(timezone.utc),
            triggered_by="scheduler",
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = job.id

    logger.info("scheduler: running scanners %s for %s/%s (job=%s)", enabled_scanners, kind, value, job_id)
    error_msg = None
    try:
        findings, discovered = await asyncio.to_thread(run_enabled_scanners, kind, value, enabled_scanners)
    except Exception as e:
        logger.exception("scanners crashed for %s/%s", kind, value)
        findings, discovered = [], []
        error_msg = str(e)[:1000]

    async with async_session() as db:
        # Re-fetch (the previous session is closed)
        asset = await db.get(MonitoredAsset, asset_id)
        job = await db.get(ScanJob, job_id)
        if asset is None or job is None:
            return
        dedup_counts = await insert_many(db, findings)
        job.diff = diff_summary(dedup_counts)

        # Auto-add discovered hosts to monitored_assets if not already present.
        # Dedup against BOTH host and domain kinds (a hostname from CT / SAN
        # may already exist as a user-added domain seed — don't duplicate it).
        new_hosts_added = 0
        if discovered:
            existing_q = await db.execute(
                select(MonitoredAsset.value).where(MonitoredAsset.kind.in_(["host", "domain"]))
            )
            existing_values = {v for (v,) in existing_q.all()}
            for value in discovered:
                if new_hosts_added >= MAX_AUTO_HOSTS_PER_SCAN:
                    logger.warning(
                        "scheduler: hit auto-enroll cap (%d) for %s, %d discovered hosts skipped",
                        MAX_AUTO_HOSTS_PER_SCAN, asset.value, len(discovered) - new_hosts_added,
                    )
                    break
                if value in existing_values:
                    continue
                existing_values.add(value)
                db.add(MonitoredAsset(
                    kind="host", value=value,
                    label=f"Decouvert via {asset.value}",
                    notes=f"Auto-decouvert lors du scan de {asset.value} le {datetime.now(timezone.utc).isoformat()[:19]}",
                    enabled=True,
                    scan_frequency_hours=24,
                ))
                new_hosts_added += 1

        asset.last_scan_at = datetime.now(timezone.utc)
        job.completed_at = datetime.now(timezone.utc)
        # Count only inserted+reopened (silenced ones are noise)
        effective = dedup_counts.get("inserted", 0) + dedup_counts.get("reopened", 0)
        job.findings_count = effective
        if error_msg:
            job.status = "failed"
            job.error = error_msg
        else:
            job.status = "completed"
        await db.commit()
    logger.info("scheduler: %s/%s -> job=%s, dedup=%s, %d new hosts", kind, value, job_id, dedup_counts, len(discovered) if discovered else 0)


async def _tick() -> None:
    """One iteration of the scheduler — pick due assets and launch them."""
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        result = await db.execute(
            select(MonitoredAsset).where(MonitoredAsset.enabled == True).where(MonitoredAsset.scan_frequency_hours > 0)
        )
        assets = result.scalars().all()

    due = []
    for a in assets:
        if a.last_scan_at is None:
            due.append(a)
            continue
        next_at = a.last_scan_at + timedelta(hours=a.scan_frequency_hours)
        if next_at <= now:
            due.append(a)

    # Sort: never-scanned first, then oldest last_scan_at
    due.sort(key=lambda a: (a.last_scan_at is not None, a.last_scan_at or datetime.min.replace(tzinfo=timezone.utc)))
    batch = due[:MAX_PER_TICK]
    if batch:
        logger.info("scheduler: %d asset(s) due, processing %d this tick", len(due), len(batch))
        await asyncio.gather(*(_scan_one(a.id) for a in batch), return_exceptions=True)


async def run_scheduler() -> None:
    """Long-running coroutine started on FastAPI startup."""
    logger.info("scheduler: starting in %ds (tick=%ds)", INITIAL_DELAY, TICK_SECONDS)
    await asyncio.sleep(INITIAL_DELAY)
    while True:
        try:
            await _tick()
        except Exception:
            logger.exception("scheduler: tick crashed")
        await asyncio.sleep(TICK_SECONDS)
