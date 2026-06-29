"""Monitored assets — perimeter of domains and IP ranges to scan periodically."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request, APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.crypto import encrypt_secret
from src.database import async_session, get_db
from src.findings_dedup import apply_scanner_state, diff_summary, insert_many, make_thread_sink, merge_counts
from src.models import Finding, MonitoredAsset, ScanJob, User
from src.rate_limit import check_scan_quota
from src.routes.scans import _quick_scan_sync
from src.scanners import DEFAULT_SCANNERS_BY_KIND, SCANNER_REGISTRY, addon_help_docs, available_scanners_for_kind, resolve_first_ip, run_enabled_scanners
from src.audit import log_action

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
    elif kind == "file_share":
        # Accept \\host\share, //host/share or smb://host/share. Internal file
        # servers (RFC1918 / internal DNS names) are legitimate, so we do NOT
        # resolve+SSRF-block like the other kinds — only reject loopback /
        # link-local / cloud-metadata literals (SMB to those is never valid).
        raw = v.replace("\\", "/")
        if raw.lower().startswith("smb://"):
            raw = raw[6:]
        raw = raw.lstrip("/")
        parts = [p for p in raw.split("/") if p]
        if len(parts) < 2:
            raise ValueError(f"Partage invalide (attendu \\\\serveur\\partage) : {value}")
        host = parts[0].lower()
        if host in ("localhost",) or host.startswith(("127.", "169.254.", "::1")) or host in ("0.0.0.0",):
            raise ValueError(f"Hôte de partage bloqué : {host}")
        return v
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


_BASE_KINDS = {"domain", "host", "ip_range"}


def _validate_kind(v: str) -> str:
    """Accept the base kinds + any kind contributed by a loaded scanner
    add-on (e.g. file_share from the SMB add-on)."""
    if v in _BASE_KINDS:
        return v
    addon_kinds = {k for meta in SCANNER_REGISTRY.values() for k in meta.get("kinds", ())}
    if v in addon_kinds:
        return v
    raise ValueError(f"Unknown asset kind: {v}")


class MonitoredAssetCreate(BaseModel):
    kind: str
    value: str
    label: Optional[str] = ""
    notes: Optional[str] = ""
    enabled: bool = True
    scan_frequency_hours: int = 24
    enabled_scanners: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    criticality: Optional[str] = "medium"
    auto_enroll_discoveries: bool = False
    stealth_mode: bool = False
    config: Optional[dict] = None

    @field_validator("kind")
    @classmethod
    def _ck(cls, v: str) -> str:
        return _validate_kind(v)


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
    auto_enroll_discoveries: Optional[bool] = None
    stealth_mode: Optional[bool] = None
    config: Optional[dict] = None

    @field_validator("kind")
    @classmethod
    def _ck(cls, v: Optional[str]) -> Optional[str]:
        return _validate_kind(v) if v is not None else v


# Per-target config may carry an SMB password. It is stored encrypted
# (smb_password_enc) and NEVER returned to the client.
def _redact_config_out(config: dict) -> dict:
    out = {k: v for k, v in (config or {}).items() if k != "smb_password_enc"}
    out["smb_password_set"] = bool((config or {}).get("smb_password_enc"))
    return out


def _merge_config_secrets(new_config: dict | None, existing: dict | None) -> dict:
    """Encrypt a freshly-entered smb_password into smb_password_enc; preserve
    the existing one when the client sends none. Strip server-controlled keys
    the client must not set directly."""
    cfg = dict(new_config or {})
    existing = existing or {}
    cfg.pop("smb_password_enc", None)
    cfg.pop("smb_password_set", None)
    pw = cfg.pop("smb_password", None)
    if pw:
        cfg["smb_password_enc"] = encrypt_secret(str(pw))
    elif existing.get("smb_password_enc"):
        cfg["smb_password_enc"] = existing["smb_password_enc"]
    return cfg


def _to_dict(a: MonitoredAsset) -> dict:
    return {
        "id": a.id, "kind": a.kind, "value": a.value, "label": a.label or "",
        "notes": a.notes or "", "enabled": a.enabled,
        "scan_frequency_hours": a.scan_frequency_hours,
        "enabled_scanners": list(a.enabled_scanners or []),
        "tags": list(a.tags or []),
        "criticality": a.criticality or "medium",
        "auto_enroll_discoveries": bool(a.auto_enroll_discoveries),
        "stealth_mode": bool(a.stealth_mode),
        "config": _redact_config_out(a.config or {}),
        "resolved_ip": a.resolved_ip,
        "last_scan_at": a.last_scan_at, "created_at": a.created_at,
    }


@router.get("/scanners-catalog")
async def scanners_catalog(user: User = Depends(get_current_user)):
    """Return the available scanners per asset kind for the UI.

    Kinds are derived from the loaded scanners: the 3 base kinds are always
    present, plus any extra kind contributed by an add-on scanner (e.g.
    `file_share` from the SMB add-on). This way the add-target UI only offers
    a target type when a scanner actually supports it."""
    base = ["domain", "host", "ip_range"]
    extra = sorted({k for meta in SCANNER_REGISTRY.values() for k in meta.get("kinds", ())} - set(base))
    return {
        kind: {
            "scanners": available_scanners_for_kind(kind),
            "defaults": DEFAULT_SCANNERS_BY_KIND.get(kind, []),
        }
        for kind in base + extra
    }


@router.get("/addon-docs")
async def addon_docs(user: User = Depends(get_current_user)):
    """In-app help documentation contributed by loaded add-on scanners.

    Returns [] on a core/public image (no add-on doc is bundled). The frontend
    injects these into the Méthodologie / Utilisation tabs, so the doc for an
    add-on appears strictly when that add-on is installed in this image."""
    return {"addons": addon_help_docs()}


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
    request: Request,
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
        auto_enroll_discoveries=bool(body.auto_enroll_discoveries),
        stealth_mode=bool(body.stealth_mode),
        config=_merge_config_secrets(body.config, {}),
        resolved_ip=resolved_ip,
    )
    db.add(a)
    await log_action(db, user, request, "asset.create", target=canonical)
    await db.commit()
    await db.refresh(a)
    return _to_dict(a)


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: uuid.UUID,
    body: MonitoredAssetUpdate,
    request: Request,
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
    if body.auto_enroll_discoveries is not None:
        a.auto_enroll_discoveries = bool(body.auto_enroll_discoveries)
    if body.stealth_mode is not None:
        a.stealth_mode = bool(body.stealth_mode)
    if body.config is not None:
        a.config = _merge_config_secrets(body.config, a.config or {})
    await db.commit()
    await db.refresh(a)
    return _to_dict(a)


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    a = await db.get(MonitoredAsset, asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    await log_action(db, user, request, "asset.delete", target=a.value)
    await db.delete(a)
    await db.commit()


async def _run_manual_scan(
    asset_id: uuid.UUID,
    job_id: uuid.UUID,
    kind: str,
    value: str,
    enabled_scanners: list[str],
    stealth: bool = False,
    config: dict | None = None,
) -> None:
    """Background task: run the full scanner chain on a single asset.
    Lives in its own DB session so we never share a connection with the
    request that kicked us off. Mirrors scheduler._scan_one."""
    error_msg: str | None = None
    # Incremental sink (see scheduler._scan_one): a sink-aware scanner commits
    # findings batch-by-batch through `sink_db` while it runs, so a killed /
    # timed-out scan keeps everything found so far.
    loop = asyncio.get_running_loop()
    sink_counts: dict | None = None
    async with async_session() as sink_db:
        sink, sink_counts = make_thread_sink(sink_db, loop)
        try:
            findings, discovered = await asyncio.to_thread(
                run_enabled_scanners, kind, value, enabled_scanners, stealth, config or {}, sink)
        except Exception as e:
            findings, discovered = [], []
            error_msg = str(e)[:1000]

    async with async_session() as db:
        asset = await db.get(MonitoredAsset, asset_id)
        job = await db.get(ScanJob, job_id)
        if asset is None or job is None:
            return

        findings, scan_state = apply_scanner_state(asset, findings)
        counts = await insert_many(db, findings)
        if sink_counts:
            merge_counts(counts, sink_counts)

        # Auto-enrol discovered hosts like the scheduler — only when the
        # parent asset opted in. Discovery findings/evidence are kept
        # either way; this flag only controls whether new MonitoredAsset
        # rows are silently created.
        new_hosts_added = 0
        if discovered and bool(asset.auto_enroll_discoveries):
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
        diff = diff_summary(counts)
        if scan_state:
            if scan_state.get("scanned") is not None:
                diff["scanned"] = scan_state.get("scanned")
            if scan_state.get("partial"):
                diff["partial"] = {"scanned": scan_state.get("scanned"), "limit": scan_state.get("limit"),
                                   "inaccessible_dirs": scan_state.get("inaccessible_dirs")}
        job.diff = diff
        job.findings_count = counts.get("inserted", 0) + counts.get("reopened", 0)
        if error_msg:
            job.status = "failed"
            job.error = error_msg
        elif scan_state and scan_state.get("partial"):
            job.status = "partial"
        else:
            job.status = "completed"
        await db.commit()


@router.post("/{asset_id}/scan")
async def scan_asset(
    asset_id: uuid.UUID,
    background: BackgroundTasks,
    request: Request,
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
    stealth = bool(a.stealth_mode)
    cfg = dict(a.config or {})

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

    background.add_task(_run_manual_scan, asset_id, job.id, kind, value, enabled_scanners, stealth, cfg)

    return {
        "target": value,
        "job_id": str(job.id),
        "status": "running",
    }


@router.post("/scan-all")
async def scan_all(
    request: Request,
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

    async def _scan_one(asset_id: uuid.UUID, kind: str, value: str, enabled_scanners: list[str], stealth: bool, config: dict) -> tuple[uuid.UUID, str, dict | None, str | None]:
        """Run the configured scanners on one asset in a dedicated DB
        session (SQLAlchemy async sessions are not coroutine-safe)."""
        async with sem:
            scanners = list(enabled_scanners or []) or DEFAULT_SCANNERS_BY_KIND.get(kind, [])
            loop = asyncio.get_running_loop()
            sink_counts: dict | None = None
            try:
                async with async_session() as sink_db:
                    sink, sink_counts = make_thread_sink(sink_db, loop)
                    findings, _discovered = await asyncio.to_thread(
                        run_enabled_scanners, kind, value, scanners, stealth, config or {}, sink)
            except Exception as e:
                return asset_id, value, None, str(e)
            try:
                async with async_session() as own_db:
                    asset = await own_db.get(MonitoredAsset, asset_id)
                    findings, _state = apply_scanner_state(asset, findings)
                    counts = await insert_many(own_db, findings)
                    if sink_counts:
                        merge_counts(counts, sink_counts)
                    if asset is not None:
                        asset.last_scan_at = datetime.now(timezone.utc)
                    await own_db.commit()
                return asset_id, value, counts, None
            except Exception as e:
                return asset_id, value, None, f"persist: {e}"

    results = await asyncio.gather(*(
        _scan_one(a.id, a.kind, a.value, list(a.enabled_scanners or []), bool(a.stealth_mode), dict(a.config or {}))
        for a in assets
    ))
    for _, value, counts, err in results:
        if err is not None:
            errors.append({"value": value, "error": err})
            continue
        total_findings += (counts or {}).get("inserted", 0) + (counts or {}).get("reopened", 0)
        scanned += 1
    return {"scanned": scanned, "findings_created": total_findings, "errors": errors}
