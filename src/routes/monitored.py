"""Monitored assets — perimeter of domains and IP ranges to scan periodically."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import async_session, get_db
from src.findings_dedup import diff_summary, insert_many
from src.models import Finding, MonitoredAsset, ScanJob, User
from src.rate_limit import check_scan_quota
from src.routes.scans import _quick_scan_sync
from src.scanners import DEFAULT_SCANNERS_BY_KIND, SCANNER_REGISTRY, available_scanners_for_kind, resolve_first_ip, run_enabled_scanners

router = APIRouter(prefix="/api/monitored-assets", tags=["monitored"])


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def _validate(kind: str, value: str) -> str:
    """Return canonical value or raise. Also applies SSRF safeguards."""
    from src.scanners import _safe_target

    v = (value or "").strip()
    if not v:
        raise ValueError("value is required")
    if kind == "domain":
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"Domaine invalide : {v}")
        v = v.lower()
    elif kind == "host":
        try:
            ipaddress.ip_address(v)
        except ValueError:
            if not _DOMAIN_RE.match(v):
                raise ValueError(f"Host invalide (attendu IP ou nom DNS) : {v}")
            v = v.lower()
    elif kind == "ip_range":
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Plage CIDR invalide : {e}")
    else:
        raise ValueError(f"Type inconnu : {kind}")

    # SSRF check (loopback, link-local, cloud metadata, docker siblings)
    _safe_target(v)
    return v


_VALID_CRITICALITY = {"low", "medium", "high", "critical"}


def _clean_tags(tags: list[str] | None) -> list[str]:
    """Tags are short user-supplied labels — strip whitespace, dedupe,
    cap length and total count to keep storage tidy."""
    if not tags:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for t in tags:
        if not isinstance(t, str):
            continue
        v = t.strip()[:30]
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v)
        if len(out) >= 20:
            break
    return out


class MonitoredAssetCreate(BaseModel):
    kind: str = Field(..., pattern="^(domain|host|ip_range)$")
    value: str
    label: Optional[str] = ""
    notes: Optional[str] = ""
    enabled: bool = True
    scan_frequency_hours: int = 24
    enabled_scanners: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    criticality: Optional[str] = "medium"


class MonitoredAssetUpdate(BaseModel):
    kind: Optional[str] = None
    value: Optional[str] = None
    label: Optional[str] = None
    notes: Optional[str] = None
    enabled: Optional[bool] = None
    scan_frequency_hours: Optional[int] = None
    enabled_scanners: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    criticality: Optional[str] = None


def _to_dict(a: MonitoredAsset) -> dict:
    return {
        "id": a.id, "kind": a.kind, "value": a.value, "label": a.label or "",
        "notes": a.notes or "", "enabled": a.enabled,
        "scan_frequency_hours": a.scan_frequency_hours,
        "enabled_scanners": list(a.enabled_scanners or []),
        "tags": list(a.tags or []),
        "criticality": a.criticality or "medium",
        "resolved_ip": a.resolved_ip,
        "last_scan_at": a.last_scan_at, "created_at": a.created_at,
    }


@router.get("/scanners-catalog")
async def scanners_catalog(user: User = Depends(get_current_user)):
    """Return the list of available scanners per asset kind for the UI."""
    return {
        kind: {
            "scanners": available_scanners_for_kind(kind),
            "defaults": DEFAULT_SCANNERS_BY_KIND.get(kind, []),
        }
        for kind in ("domain", "host", "ip_range")
    }


@router.get("")
async def list_assets(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(MonitoredAsset).order_by(MonitoredAsset.created_at.desc()))
    return [_to_dict(a) for a in result.scalars().all()]


@router.post("", status_code=201)
async def create_asset(
    body: MonitoredAssetCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        canonical = _validate(body.kind, body.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Resolve enabled_scanners: validate against registry, fall back to defaults
    requested = body.enabled_scanners
    if requested is None:
        scanners = list(DEFAULT_SCANNERS_BY_KIND.get(body.kind, []))
    else:
        scanners = [s for s in requested if s in SCANNER_REGISTRY and body.kind in SCANNER_REGISTRY[s]["kinds"]]

    crit = (body.criticality or "medium").lower()
    if crit not in _VALID_CRITICALITY:
        crit = "medium"
    resolved_ip = None
    if body.kind in ("host", "domain"):
        try:
            resolved_ip = await asyncio.to_thread(resolve_first_ip, canonical)
        except Exception:
            resolved_ip = None
    a = MonitoredAsset(
        kind=body.kind, value=canonical, label=body.label or "",
        notes=body.notes or "", enabled=bool(body.enabled),
        scan_frequency_hours=int(body.scan_frequency_hours or 24),
        enabled_scanners=scanners,
        tags=_clean_tags(body.tags),
        criticality=crit,
        resolved_ip=resolved_ip,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return _to_dict(a)


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: uuid.UUID,
    body: MonitoredAssetUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    a = await db.get(MonitoredAsset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    new_kind = body.kind or a.kind
    new_value = body.value if body.value is not None else a.value
    if body.kind is not None or body.value is not None:
        try:
            new_value = _validate(new_kind, new_value)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    a.kind = new_kind
    a.value = new_value
    if body.label is not None:
        a.label = body.label
    if body.notes is not None:
        a.notes = body.notes
    if body.enabled is not None:
        a.enabled = body.enabled
    if body.scan_frequency_hours is not None:
        a.scan_frequency_hours = max(0, int(body.scan_frequency_hours))
    if body.enabled_scanners is not None:
        a.enabled_scanners = [
            s for s in body.enabled_scanners
            if s in SCANNER_REGISTRY and a.kind in SCANNER_REGISTRY[s]["kinds"]
        ]
    if body.tags is not None:
        a.tags = _clean_tags(body.tags)
    if body.criticality is not None:
        crit = body.criticality.lower()
        if crit in _VALID_CRITICALITY:
            a.criticality = crit
    await db.commit()
    await db.refresh(a)
    return _to_dict(a)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    a = await db.get(MonitoredAsset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(a)
    await db.commit()


async def _run_manual_scan(
    asset_id: uuid.UUID,
    job_id: uuid.UUID,
    kind: str,
    value: str,
    enabled_scanners: list[str],
) -> None:
    """Background task: run the full scanner chain on a single asset.
    Lives in its own DB session so we never share a connection with the
    request that kicked us off. Mirrors scheduler._scan_one."""
    error_msg: str | None = None
    try:
        findings, discovered = await asyncio.to_thread(run_enabled_scanners, kind, value, enabled_scanners)
    except Exception as e:
        findings, discovered = [], []
        error_msg = str(e)[:1000]

    async with async_session() as db:
        asset = await db.get(MonitoredAsset, asset_id)
        job = await db.get(ScanJob, job_id)
        if asset is None or job is None:
            return

        counts = await insert_many(db, findings)

        # Auto-enrol discovered hosts like the scheduler.
        new_hosts_added = 0
        if discovered:
            existing_q = await db.execute(
                select(MonitoredAsset.value).where(MonitoredAsset.kind.in_(["host", "domain"]))
            )
            existing_values = {v for (v,) in existing_q.all()}
            # Newly discovered hosts get the full host default suite +
            # any host-compatible extras the parent had explicitly enabled.
            host_defaults = set(DEFAULT_SCANNERS_BY_KIND.get("host", []))
            parent_extras = {
                s for s in (asset.enabled_scanners or [])
                if s in SCANNER_REGISTRY and "host" in SCANNER_REGISTRY[s]["kinds"]
            }
            inherited_scanners = sorted(host_defaults | parent_extras)
            for dv in discovered:
                if new_hosts_added >= 50:
                    break
                if dv in existing_values:
                    continue
                existing_values.add(dv)
                db.add(MonitoredAsset(
                    kind="host", value=dv,
                    label=f"Decouvert via {asset.value}",
                    notes=f"Auto-decouvert lors du scan manuel de {asset.value} le {datetime.now(timezone.utc).isoformat()[:19]}",
                    enabled=True,
                    scan_frequency_hours=asset.scan_frequency_hours or 24,
                    enabled_scanners=inherited_scanners,
                    criticality=asset.criticality or "medium",
                    tags=list(asset.tags or []),
                ))
                new_hosts_added += 1

        asset.last_scan_at = datetime.now(timezone.utc)
        if asset.kind in ("host", "domain"):
            try:
                ip = await asyncio.to_thread(resolve_first_ip, asset.value)
                if ip:
                    asset.resolved_ip = ip
            except Exception:
                pass
        job.completed_at = datetime.now(timezone.utc)
        job.diff = diff_summary(counts)
        job.findings_count = counts.get("inserted", 0) + counts.get("reopened", 0)
        if error_msg:
            job.status = "failed"
            job.error = error_msg
        else:
            job.status = "completed"
        await db.commit()


@router.post("/{asset_id}/scan")
async def scan_asset(
    asset_id: uuid.UUID,
    background: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Kick off a full scan on a single monitored asset as a background
    task. Returns immediately with the `job_id` so the frontend can show
    the job in its list and poll for completion."""
    check_scan_quota(str(user.id) if user else "anonymous")
    a = await db.get(MonitoredAsset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")

    kind = a.kind
    value = a.value
    enabled_scanners = list(a.enabled_scanners or []) or DEFAULT_SCANNERS_BY_KIND.get(kind, [])

    # Manual scan → distinct tag so the Scans page shows it as "manual"
    # not "scheduled" (even though it uses the same pipeline)
    scanner_tag = {
        "domain": "manual-domain",
        "host": "manual-host",
        "ip_range": "manual-discovery",
    }.get(kind, "manual")
    job = ScanJob(
        target=value, profile="manual", scanner=scanner_tag,
        status="running", started_at=datetime.now(timezone.utc),
        triggered_by=(user.email if user else "manual"),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    background.add_task(_run_manual_scan, asset_id, job.id, kind, value, enabled_scanners)

    return {
        "target": value,
        "job_id": str(job.id),
        "status": "running",
    }


@router.post("/scan-all")
async def scan_all(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Scan every enabled monitored asset in parallel. Runs the full
    scanner chain (same as the scheduler tick) on each asset so the
    result mirrors what the background scheduler would produce."""
    check_scan_quota(str(user.id) if user else "anonymous")
    result = await db.execute(select(MonitoredAsset).where(MonitoredAsset.enabled == True))
    assets = list(result.scalars().all())
    total_findings = 0
    scanned = 0
    errors = []

    sem = asyncio.Semaphore(3)

    async def _scan_one(asset_id: uuid.UUID, kind: str, value: str, enabled_scanners: list[str]) -> tuple[uuid.UUID, str, dict | None, str | None]:
        """Run the configured scanners on one asset in a dedicated DB
        session (SQLAlchemy async sessions are not coroutine-safe)."""
        async with sem:
            scanners = list(enabled_scanners or []) or DEFAULT_SCANNERS_BY_KIND.get(kind, [])
            try:
                findings, _discovered = await asyncio.to_thread(run_enabled_scanners, kind, value, scanners)
            except Exception as e:
                return asset_id, value, None, str(e)
            try:
                async with async_session() as own_db:
                    counts = await insert_many(own_db, findings)
                    asset = await own_db.get(MonitoredAsset, asset_id)
                    if asset is not None:
                        asset.last_scan_at = datetime.now(timezone.utc)
                    await own_db.commit()
                return asset_id, value, counts, None
            except Exception as e:
                return asset_id, value, None, f"persist: {e}"

    results = await asyncio.gather(*(
        _scan_one(a.id, a.kind, a.value, list(a.enabled_scanners or []))
        for a in assets
    ))
    for _, value, counts, err in results:
        if err is not None:
            errors.append({"value": value, "error": err})
            continue
        total_findings += (counts or {}).get("inserted", 0) + (counts or {}).get("reopened", 0)
        scanned += 1
    return {"scanned": scanned, "findings_created": total_findings, "errors": errors}
