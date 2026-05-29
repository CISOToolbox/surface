"""Background scheduler that auto-runs scans on monitored assets.

Loop:
  - every TICK_SECONDS, find enabled assets where last_scan_at is null or older
    than scan_frequency_hours
  - for each, run the matching scanners (in a thread to avoid blocking)
  - insert findings, mark last_scan_at, and for ip_range scans auto-create
    monitored_assets for newly discovered hosts
  - cap to MAX_PER_TICK to spread load
  - daily, refresh the nuclei community templates (`nuclei -ut`)

The scheduler runs in the same event loop as FastAPI but the scanners
themselves are blocking (subprocess, sockets), so we use asyncio.to_thread.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from src.database import async_session
from src.findings_dedup import diff_summary, insert_many
from src.models import Finding, MonitoredAsset, ScanJob
from src.scanners import DEFAULT_SCANNERS_BY_KIND, SCANNER_REGISTRY, resolve_first_ip, run_enabled_scanners

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
        stealth = bool(asset.stealth_mode)

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

    logger.info("scheduler: running scanners %s for %s/%s (job=%s, stealth=%s)", enabled_scanners, kind, value, job_id, stealth)
    error_msg = None
    try:
        findings, discovered = await asyncio.to_thread(run_enabled_scanners, kind, value, enabled_scanners, stealth)
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
        # Gated by the per-asset `auto_enroll_discoveries` flag (default
        # False) so adding a single host or domain never silently grows
        # the perimeter without consent.
        new_hosts_added = 0
        if discovered and bool(asset.auto_enroll_discoveries):
            existing_q = await db.execute(
                select(MonitoredAsset.value).where(MonitoredAsset.kind.in_(["host", "domain"]))
            )
            existing_values = {v for (v,) in existing_q.all()}

            # v0.2 — newly discovered hosts always get the full host
            # default profile (nmap_quick, tls, nuclei, takeover, techstack,
            # cve_lookup...) so operators get immediate value. On top of
            # that we union with any host-compatible scanner the parent had
            # explicitly enabled (e.g. shodan_host if the parent ran it).
            host_defaults = set(DEFAULT_SCANNERS_BY_KIND.get("host", []))
            parent_extras = {
                s for s in (asset.enabled_scanners or [])
                if s in SCANNER_REGISTRY and "host" in SCANNER_REGISTRY[s]["kinds"]
            }
            inherited_scanners = sorted(host_defaults | parent_extras)
            # Inherit business context too — if the parent is "critical"
            # the discovered subdomain is probably critical too.
            inherited_crit = asset.criticality or "medium"
            inherited_tags = list(asset.tags or [])

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
                    scan_frequency_hours=asset.scan_frequency_hours or 24,
                    enabled_scanners=inherited_scanners,
                    criticality=inherited_crit,
                    tags=inherited_tags,
                ))
                new_hosts_added += 1

        asset.last_scan_at = datetime.now(timezone.utc)
        # Cache the resolved IP so the Hosts view can group aliases
        if asset.kind in ("host", "domain"):
            try:
                ip = await asyncio.to_thread(resolve_first_ip, asset.value)
                if ip:
                    asset.resolved_ip = ip
            except Exception:
                pass
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


async def _rebalance_schedule() -> None:
    """Spread scan times evenly so assets with the same frequency don't
    all fire on the same tick.

    Groups assets by `scan_frequency_hours`, then within each group
    assigns a synthetic `last_scan_at` that distributes the next-due
    times uniformly across the period. Only touches assets that have
    never been scanned (`last_scan_at IS NULL`) or that would create a
    burst (more than MAX_PER_TICK assets due in the same 2-minute window).

    Called once at startup and then once per day by the scheduler loop.
    """
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        result = await db.execute(
            select(MonitoredAsset)
            .where(MonitoredAsset.enabled == True)
            .where(MonitoredAsset.scan_frequency_hours > 0)
        )
        assets = result.scalars().all()
        if not assets:
            return

        # Group by frequency
        by_freq: dict[int, list[MonitoredAsset]] = {}
        for a in assets:
            by_freq.setdefault(a.scan_frequency_hours, []).append(a)

        updated = 0
        for freq_h, group in by_freq.items():
            # Only rebalance if there's a burst: count how many are due
            # right now (NULL or past-due).
            due_now = [
                a for a in group
                if a.last_scan_at is None
                or (a.last_scan_at + timedelta(hours=freq_h)) <= now
            ]
            if len(due_now) <= MAX_PER_TICK:
                continue

            # Spread the due assets evenly across the period. Asset i
            # gets last_scan_at = now - (i / N) * period, so each one
            # becomes due at a different future tick.
            period = timedelta(hours=freq_h)
            n = len(due_now)
            # Sort by value for deterministic ordering
            due_now.sort(key=lambda a: a.value)
            for i, a in enumerate(due_now):
                offset = period * (i / n)
                a.last_scan_at = now - offset
                updated += 1

        if updated:
            await db.commit()
            logger.info("scheduler: rebalanced %d asset(s) across %d frequency group(s)",
                        updated, len(by_freq))


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


async def _maybe_send_weekly_digest() -> None:
    """Once a day, check whether we should fire the weekly digest. We
    send at most one per week, tracked via AppSettings `digest.last_sent_at`.
    No-op when SMTP isn't configured."""
    try:
        from src.routes.reports import (
            _aggregate_report, _build_digest_message, _load_smtp,
            _smtp_send_blocking,
        )
    except Exception:
        return
    async with async_session() as db:
        from src.models import AppSettings
        from sqlalchemy import select as _sel
        cfg = await _load_smtp(db)
        if not cfg.get("host") or not cfg.get("sender") or not cfg.get("recipients"):
            return
        last_row = (await db.execute(
            _sel(AppSettings).where(AppSettings.key == "digest.last_sent_at")
        )).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if last_row and last_row.value:
            try:
                last = datetime.fromisoformat(last_row.value)
                if (now - last).total_seconds() < 7 * 24 * 3600:
                    return
            except Exception:
                pass
        data = await _aggregate_report(db)
        try:
            msg, sender, recipients = _build_digest_message(cfg, data)
        except ValueError:
            logger.exception("weekly digest: invalid SMTP config, skipping")
            return
        try:
            port = int(cfg.get("port") or 587)
            host = cfg["host"]
            use_tls = cfg.get("use_tls", "1") != "0"
            await asyncio.to_thread(
                _smtp_send_blocking,
                host, port, use_tls,
                cfg.get("username", ""), cfg.get("password", ""),
                sender, recipients, msg.as_string(),
            )
            if last_row is None:
                db.add(AppSettings(key="digest.last_sent_at", value=now.isoformat()))
            else:
                last_row.value = now.isoformat()
            await db.commit()
            logger.info("weekly digest sent to %s", recipients)
        except Exception:
            logger.exception("weekly digest send failed")


# ── Nuclei templates auto-update ───────────────────────────────────
# Default cadence: 24 h. Override via env NUCLEI_AUTO_UPDATE_HOURS.
# Set NUCLEI_AUTO_UPDATE_HOURS=0 to disable the auto-update entirely.
# Last-run timestamp is persisted in AppSettings so the cadence survives
# restarts.
NUCLEI_AUTO_UPDATE_HOURS = int(os.environ.get("NUCLEI_AUTO_UPDATE_HOURS", "24"))
NUCLEI_UPDATE_KEY = "nuclei.last_template_update_at"
NUCLEI_UPDATE_TIMEOUT = 300  # `nuclei -ut` can take a couple of minutes on a fresh install


async def _maybe_update_nuclei_templates() -> None:
    """Run ``nuclei -ut`` if more than ``NUCLEI_AUTO_UPDATE_HOURS`` have
    elapsed since the last successful refresh. Tracks the last-run via
    ``AppSettings[nuclei.last_template_update_at]``. No-op when the
    nuclei binary is missing or the cadence is disabled (0)."""
    if NUCLEI_AUTO_UPDATE_HOURS <= 0:
        return
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return  # binary not in PATH on this build — silently skip

    from src.models import AppSettings  # local import to mirror digest hook
    now = datetime.now(timezone.utc)
    async with async_session() as db:
        last_row = (await db.execute(
            select(AppSettings).where(AppSettings.key == NUCLEI_UPDATE_KEY)
        )).scalar_one_or_none()
        if last_row and last_row.value:
            try:
                last = datetime.fromisoformat(last_row.value)
                if (now - last).total_seconds() < NUCLEI_AUTO_UPDATE_HOURS * 3600:
                    return
            except ValueError:
                pass  # corrupt value → re-run and overwrite

    logger.info("scheduler: refreshing nuclei templates (last run >%dh ago)",
                NUCLEI_AUTO_UPDATE_HOURS)
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            [nuclei_path, "-ut", "-disable-update-check", "-no-color"],
            capture_output=True, timeout=NUCLEI_UPDATE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.warning("scheduler: nuclei -ut timed out after %ds — will retry next cycle",
                       NUCLEI_UPDATE_TIMEOUT)
        return
    except Exception:
        logger.exception("scheduler: nuclei -ut crashed")
        return

    if proc.returncode != 0:
        # Keep the last-run unchanged so we retry next cycle.
        logger.warning("scheduler: nuclei -ut exited rc=%s: %s",
                       proc.returncode, proc.stderr.decode(errors="replace")[-500:])
        return

    # Bust the cached templates inventory so the next /nuclei/config call
    # sees the new count without waiting 120s.
    try:
        from src.routes.scans import _nuclei_environment_info
        await asyncio.to_thread(_nuclei_environment_info, True)
    except Exception:
        pass

    async with async_session() as db:
        last_row = (await db.execute(
            select(AppSettings).where(AppSettings.key == NUCLEI_UPDATE_KEY)
        )).scalar_one_or_none()
        if last_row is None:
            db.add(AppSettings(key=NUCLEI_UPDATE_KEY, value=now.isoformat()))
        else:
            last_row.value = now.isoformat()
        await db.commit()
    logger.info("scheduler: nuclei templates refreshed (rc=0)")


REBALANCE_INTERVAL_TICKS = 1440  # ~24 h at 60 s/tick
NUCLEI_CHECK_INTERVAL_TICKS = 60  # check the nuclei cadence once an hour


async def run_scheduler() -> None:
    """Long-running coroutine started on FastAPI startup."""
    logger.info("scheduler: starting in %ds (tick=%ds)", INITIAL_DELAY, TICK_SECONDS)
    await asyncio.sleep(INITIAL_DELAY)

    # Initial rebalance: spread any burst of due assets evenly so the
    # first few ticks don't try to scan everything at once.
    try:
        await _rebalance_schedule()
    except Exception:
        logger.exception("scheduler: initial rebalance failed")

    # Initial nuclei template check on startup — covers fresh deployments
    # and ensures templates are current after a long downtime. Re-checks
    # are then driven by NUCLEI_CHECK_INTERVAL_TICKS below.
    try:
        await _maybe_update_nuclei_templates()
    except Exception:
        logger.exception("scheduler: initial nuclei update failed")

    digest_ticks = 0
    rebalance_ticks = 0
    nuclei_ticks = 0
    while True:
        try:
            await _tick()
        except Exception:
            logger.exception("scheduler: tick crashed")
        # Check the digest once every 60 ticks (~1 h).
        digest_ticks += 1
        if digest_ticks >= 60:
            digest_ticks = 0
            try:
                await _maybe_send_weekly_digest()
            except Exception:
                logger.exception("scheduler: digest crashed")
        # Rebalance once a day to smooth out drift from manual scans,
        # newly added assets, or frequency changes.
        rebalance_ticks += 1
        if rebalance_ticks >= REBALANCE_INTERVAL_TICKS:
            rebalance_ticks = 0
            try:
                await _rebalance_schedule()
            except Exception:
                logger.exception("scheduler: rebalance failed")
        # Check nuclei templates freshness once per hour. The helper
        # itself enforces the configured cadence (24 h by default) so
        # this is cheap — just a SELECT on AppSettings most of the time.
        nuclei_ticks += 1
        if nuclei_ticks >= NUCLEI_CHECK_INTERVAL_TICKS:
            nuclei_ticks = 0
            try:
                await _maybe_update_nuclei_templates()
            except Exception:
                logger.exception("scheduler: nuclei update crashed")
        await asyncio.sleep(TICK_SECONDS)
