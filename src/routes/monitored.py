"""Monitored assets — perimeter of domains and IP ranges to scan periodically."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import async_session, get_db
from src.findings_dedup import insert_many
from src.models import Finding, MonitoredAsset, User
from src.rate_limit import check_scan_quota
from src.routes.scans import _quick_scan_sync
from src.scanners import DEFAULT_SCANNERS_BY_KIND, SCANNER_REGISTRY, available_scanners_for_kind

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


class MonitoredAssetCreate(BaseModel):
    kind: str = Field(..., pattern="^(domain|host|ip_range)$")
    value: str
    label: Optional[str] = ""
    notes: Optional[str] = ""
    enabled: bool = True
    scan_frequency_hours: int = 24
    enabled_scanners: Optional[list[str]] = None


class MonitoredAssetUpdate(BaseModel):
    kind: Optional[str] = None
    value: Optional[str] = None
    label: Optional[str] = None
    notes: Optional[str] = None
    enabled: Optional[bool] = None
    scan_frequency_hours: Optional[int] = None
    enabled_scanners: Optional[list[str]] = None


def _to_dict(a: MonitoredAsset) -> dict:
    return {
        "id": a.id, "kind": a.kind, "value": a.value, "label": a.label or "",
        "notes": a.notes or "", "enabled": a.enabled,
        "scan_frequency_hours": a.scan_frequency_hours,
        "enabled_scanners": list(a.enabled_scanners or []),
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

    a = MonitoredAsset(
        kind=body.kind, value=canonical, label=body.label or "",
        notes=body.notes or "", enabled=bool(body.enabled),
        scan_frequency_hours=int(body.scan_frequency_hours or 24),
        enabled_scanners=scanners,
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


@router.post("/{asset_id}/scan")
async def scan_asset(
    asset_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run a quick scan on a single monitored asset (domain or IP)."""
    check_scan_quota(str(user.id) if user else "anonymous")
    a = await db.get(MonitoredAsset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    if a.kind == "ip_range":
        raise HTTPException(status_code=400, detail="Quick scan on IP ranges not supported. Use external scanner + bulk-import.")

    try:
        finding_dicts = await asyncio.to_thread(_quick_scan_sync, a.value)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan failed: {e}")

    counts = await insert_many(db, finding_dicts)
    a.last_scan_at = datetime.now(timezone.utc)
    await db.commit()
    return {"target": a.value, "findings_created": counts.get("inserted", 0) + counts.get("reopened", 0), "dedup": counts}


@router.post("/scan-all")
async def scan_all(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Scan every enabled monitored domain/IP in parallel (bounded). Skips ip_range entries."""
    check_scan_quota(str(user.id) if user else "anonymous")
    result = await db.execute(select(MonitoredAsset).where(MonitoredAsset.enabled == True))
    assets = [a for a in result.scalars().all() if a.kind != "ip_range"]
    total_findings = 0
    scanned = 0
    errors = []

    # Concurrency cap: 3 parallel scans at most to avoid overloading the scheduler
    sem = asyncio.Semaphore(3)

    async def _scan_one(asset_id: uuid.UUID, value: str) -> tuple[uuid.UUID, str, dict | None, str | None]:
        """Run the scan + write findings in a dedicated DB session per coroutine,
        so two concurrent scans never share a SQLAlchemy session (which is not
        coroutine-safe)."""
        async with sem:
            try:
                fds = await asyncio.to_thread(_quick_scan_sync, value)
            except Exception as e:
                return asset_id, value, None, str(e)
            try:
                async with async_session() as own_db:
                    counts = await insert_many(own_db, fds)
                    asset = await own_db.get(MonitoredAsset, asset_id)
                    if asset is not None:
                        asset.last_scan_at = datetime.now(timezone.utc)
                    await own_db.commit()
                return asset_id, value, counts, None
            except Exception as e:
                return asset_id, value, None, f"persist: {e}"

    results = await asyncio.gather(*(_scan_one(a.id, a.value) for a in assets))
    for _, value, counts, err in results:
        if err is not None:
            errors.append({"value": value, "error": err})
            continue
        total_findings += (counts or {}).get("inserted", 0) + (counts or {}).get("reopened", 0)
        scanned += 1
    return {"scanned": scanned, "findings_created": total_findings, "errors": errors}
