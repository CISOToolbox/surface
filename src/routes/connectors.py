"""FEAT-37 — connector configuration and triggering.

Administrators only: these routes handle API credentials granting read access
to the whole fleet.

What these routes never do: return a secret field's value. A secret goes in,
it does not come back out — ``read_public`` exposes only a "set" boolean (see
``connectors_config``).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import log_action
from src.auth import get_current_user, require_admin
from src.connectors_config import (add_instance, instance_type, list_instances,
                                   read_config, read_public, record_run,
                                   remove_instance, save_config)
from src.connectors_run import lock_for, run_connector
from src.database import get_db
from src.models import User
from src.scanners import CONNECTOR_REGISTRY

logger = logging.getLogger("surface-backend")

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


class ConnectorUpdate(BaseModel):
    values: dict[str, Any] | None = None
    enabled: bool | None = None


def _meta(key: str) -> dict[str, Any]:
    """Resolves an INSTANCE key ("defender", "defender:acme") to its type
    meta. 404, not 403: the type does not exist in this image, which is a
    normal state — add-ons are loaded dynamically."""
    meta = CONNECTOR_REGISTRY.get(instance_type(key))
    if meta is None:
        raise HTTPException(status_code=404, detail=f"unknown connector '{key}'")
    return meta


async def _known_instance(db, key: str) -> None:
    """An extra instance key must be REGISTERED, not merely well-formed:
    accepting any slug would let a typo silently create a parallel config
    namespace that no scheduler pass ever reads."""
    if ":" in key and key not in (await list_instances(db)):
        raise HTTPException(status_code=404, detail=f"unknown instance '{key}'")


@router.get("/types")
async def list_connector_types(user: Optional[User] = Depends(get_current_user)):
    """The connector TYPES this image can run — what the "add a connector"
    dialog offers. The page is designed as if several types existed even
    while Defender is the only one shipped."""
    require_admin(user)
    return [{"name": name, "label": meta.get("label", name),
             "interval_hours": meta.get("interval_hours", 6)}
            for name, meta in sorted(CONNECTOR_REGISTRY.items())]


@router.get("")
async def list_connectors(user: Optional[User] = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """Every connector INSTANCE present in this image, with its state.

    One entry per default instance (one per installed add-on type) plus one
    per registered extra instance. Empty list = no connector add-on
    installed; the interface then hides the whole section instead of showing
    an empty screen.
    """
    require_admin(user)
    out = []
    extras = await list_instances(db)
    for ctype, meta in sorted(CONNECTOR_REGISTRY.items()):
        entry = await read_public(db, ctype, meta)
        entry.update({"type": ctype, "deletable": False})
        # A PRISTINE default instance (nothing stored, never run) is hidden:
        # the page starts empty and every visible connector is one the admin
        # chose to add. A default that carries config or history stays — it
        # predates the add-a-connector flow and must remain reachable.
        pristine = (not entry["enabled"] and not entry["last_run_at"]
                    and not any(fld["set"] for fld in entry["fields"]))
        if not pristine:
            out.append(entry)
        for key, info in sorted(extras.items()):
            if info.get("type") != ctype:
                continue
            inst = await read_public(db, key, meta)
            inst.update({"type": ctype, "deletable": True,
                         "label": f"{meta.get('label', ctype)} — {info.get('label', key)}",
                         "name": key})
            out.append(inst)
    return out


class InstanceCreate(BaseModel):
    label: str


@router.post("/{ctype}/instances")
async def create_instance(ctype: str, payload: InstanceCreate, request: Request,
                          user: Optional[User] = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """Registers an extra instance of an installed connector type — e.g. a
    second Defender tenant. Its findings carry the instance key as their
    scanner, so each tenant reconciles only its own feed."""
    require_admin(user)
    if ctype not in CONNECTOR_REGISTRY:
        raise HTTPException(status_code=404, detail=f"unknown connector '{ctype}'")
    try:
        key = await add_instance(db, ctype, payload.label)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    await db.commit()
    await log_action(db, user, request, "connector.instance.create", key, {})
    await db.commit()
    return {"name": key}


@router.delete("/{name:path}")
async def delete_instance(name: str, request: Request,
                          user: Optional[User] = Depends(get_current_user),
                          db: AsyncSession = Depends(get_db)):
    """Removes an EXTRA instance and its configuration. The default instance
    (bare type key) is not deletable — disable it instead. The instance's
    findings are kept: deleting a tenant's config must not destroy triage
    history."""
    require_admin(user)
    _meta(name)
    if ":" not in name:
        raise HTTPException(status_code=422,
                            detail="the default instance cannot be deleted")
    await _known_instance(db, name)
    await remove_instance(db, name)
    await db.commit()
    await log_action(db, user, request, "connector.instance.delete", name, {})
    await db.commit()
    return {"ok": True}


@router.put("/{name:path}")
async def update_connector(name: str, payload: ConnectorUpdate, request: Request,
                           user: Optional[User] = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    require_admin(user)
    meta = _meta(name)
    await _known_instance(db, name)
    schema = meta.get("config_schema", []) or []
    await save_config(db, name, schema, payload.values or {}, payload.enabled)
    await db.commit()
    # The audit log records WHICH fields moved, never their value.
    await log_action(db, user, request, "connector.update", name,
                     {"fields": sorted((payload.values or {}).keys()),
                      "enabled": payload.enabled})
    await db.commit()
    return await read_public(db, name, meta)


@router.post("/{name:path}/run")
async def run_now(name: str, request: Request,
                  user: Optional[User] = Depends(get_current_user),
                  db: AsyncSession = Depends(get_db)):
    """Triggers an immediate import, without waiting for the interval.

    Returns the report as-is, failure included (``ok: false``): it is the only
    way an administrator can validate credentials. A 500 would hide the real
    cause behind a generic error.

    The per-connector lock is shared with the scheduler pass: a run already in
    progress answers 409 instead of importing the same tenant twice — the
    first delivery's concurrent imports duplicated hosts (criterion 2).
    """
    require_admin(user)
    meta = _meta(name)
    await _known_instance(db, name)
    schema = meta.get("config_schema", []) or []
    cfg = await read_config(db, name, schema)
    missing = [f["key"] for f in schema
               if f.get("required") and not cfg.get(f["key"], "").strip()]
    if missing:
        raise HTTPException(status_code=422,
                            detail=f"configuration incomplète : {', '.join(missing)}")

    lock = lock_for(name)
    if lock.locked():
        raise HTTPException(status_code=409,
                            detail="un import est déjà en cours pour ce connecteur")
    async with lock:
        report = await run_connector(db, name, meta, cfg)
        await record_run(db, name, report)
        await db.commit()
    await log_action(db, user, request, "connector.run", name,
                     {k: report.get(k) for k in ("ok", "hosts", "findings", "closed")})
    await db.commit()
    return report
