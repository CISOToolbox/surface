"""FEAT-37 — persisted connector configuration.

A connector pulls a tenant-wide inventory: its configuration is global to the
module, not carried by a target. It therefore lives in ``AppSettings``, the
key/value table already used for ``digest.last_sent_at`` and
``nuclei.last_template_update_at``.

**What decides encryption: the schema, not the key name.**
``settings_crypto.is_secret_key()`` recognises the ``connector_<name>_…``
pattern suffixed ``_secret`` / ``_key``, and that was this module's first
version. It is wrong: an add-on declaring ``"secret": True`` on a field named
``token`` or ``jeton`` produces the key ``connector_x_token``, which that
pattern does not recognise — the secret went to the database in cleartext,
with no error and no trace. The defect was found by a test that used a
``jeton`` field, precisely.

So: encrypt **iff the schema declares the field secret**, and decrypt **iff
the stored value carries the** ``enc:v1:`` **marker**. Both decisions are
independent of naming, and reads stay correct for a value written before this
change.

**What never leaves.** ``read_public()`` returns no secret field value, only
a boolean "set". The interface therefore shows whether a secret exists, never
its value — administrator included, page reload included.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.models import AppSettings
from src.settings_crypto import (decrypt_setting, encrypt_setting_or_plain,
                                 is_encrypted, is_secret_key)

logger = logging.getLogger("surface-backend")

ENABLED = "enabled"
LAST_RUN = "last_run_at"
LAST_RESULT = "last_result"

# ── Instances ────────────────────────────────────────────────────
# One connector TYPE (the add-on: "defender") can run as several INSTANCES —
# e.g. two Defender tenants centralised in one Surface. An instance key is
# either the bare type (the default instance, always present) or
# "<type>:<slug>". The key is what everything else is scoped on: the
# AppSettings namespace, the per-instance lock, and — crucially — the
# findings' ``scanner`` field, which is what keeps reconciliation from
# closing another tenant's findings.
INSTANCES_KEY = "connectors_instances"
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def instance_type(key: str) -> str:
    """The connector type of an instance key ("defender:acme" → "defender")."""
    return key.split(":", 1)[0]


def make_slug(label: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", (label or "").strip().lower()).strip("-")[:32]


def valid_slug(slug: str) -> bool:
    return bool(_SLUG_RE.match(slug or ""))


async def list_instances(db) -> dict[str, dict[str, Any]]:
    """Extra instances only: {key: {"type", "label"}}. Default instances (the
    bare type keys) are implicit — one per installed add-on, never listed
    here, never deletable."""
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == INSTANCES_KEY)
    )).scalar_one_or_none()
    if row is None or not row.value:
        return {}
    try:
        data = json.loads(row.value)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


async def _write_instances(db, data: dict[str, dict[str, Any]]) -> None:
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == INSTANCES_KEY)
    )).scalar_one_or_none()
    payload = json.dumps(data)
    if row is None:
        db.add(AppSettings(key=INSTANCES_KEY, value=payload))
    else:
        row.value = payload


async def add_instance(db, ctype: str, label: str) -> str:
    """Registers an extra instance of a connector type; returns its key."""
    slug = make_slug(label)
    if not valid_slug(slug):
        raise ValueError("invalid instance label")
    key = f"{ctype}:{slug}"
    data = await list_instances(db)
    if key in data:
        raise ValueError("instance already exists")
    data[key] = {"type": ctype, "label": label.strip()}
    await _write_instances(db, data)
    return key


async def remove_instance(db, key: str) -> None:
    """Unregisters an extra instance and deletes its configuration keys.

    Its findings are NOT touched: they keep their scanner key and stay
    filterable/triageable — deleting an instance must not silently destroy
    triage history. Reconciliation simply stops for them.
    """
    data = await list_instances(db)
    data.pop(key, None)
    await _write_instances(db, data)
    prefix = f"connector_{key}_"
    # Same autoescape as _raw(): a bare LIKE deleted the sibling instance's
    # keys ("acme" wiping "acme-prod") through the "_" wildcard.
    rows = (await db.execute(
        select(AppSettings).where(AppSettings.key.startswith(prefix, autoescape=True))
    )).scalars().all()
    for r in rows:
        await db.delete(r)


def key_for(connector: str, field: str) -> str:
    """AppSettings key of a connector field.

    The ``connector_`` prefix isolates the namespace; it does **not** decide
    encryption, which follows the add-on's schema (see module docstring).
    """
    return f"connector_{connector}_{field}"


async def _raw(db, connector: str) -> dict[str, str]:
    """Every stored value for a connector, decrypted.

    Decryption follows the **marker** carried by the value, not the key name:
    a cleartext value is returned as-is, a marked value is decrypted. This is
    also what keeps reads correct whatever schema the value was written under.
    """
    prefix = f"connector_{connector}_"
    # startswith + autoescape, NOT like(prefix + "%"): the prefix contains
    # "_", a single-character SQL wildcard — "connector_defender:acme_" also
    # matched every "connector_defender:acme-prod_*" row, polluting reads
    # and, worse, letting remove_instance purge a sibling instance's
    # credentials (review finding, reproduced).
    rows = (await db.execute(
        select(AppSettings).where(AppSettings.key.startswith(prefix, autoescape=True))
    )).scalars().all()
    out: dict[str, str] = {}
    for r in rows:
        field = r.key[len(prefix):]
        raw = r.value or ""
        out[field] = decrypt_setting(raw) if is_encrypted(raw) else raw
    return out


async def _put(db, key: str, value: str, secret: bool = False) -> None:
    """Writes a value. ``secret`` comes from the add-on's schema.

    ``is_secret_key`` is still consulted as a complement — it covers keys that
    already match the historical pattern — but it no longer decides alone.
    """
    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == key)
    )).scalar_one_or_none()
    stored = encrypt_setting_or_plain(value) if (secret or is_secret_key(key)) else value
    if row is None:
        db.add(AppSettings(key=key, value=stored))
    else:
        row.value = stored


async def read_config(db, connector: str, schema: list[dict[str, Any]]) -> dict[str, str]:
    """Cleartext configuration, for execution. Never log the return value."""
    stored = await _raw(db, connector)
    return {f["key"]: stored.get(f["key"], "") for f in schema}


async def is_enabled(db, connector: str) -> bool:
    return (await _raw(db, connector)).get(ENABLED, "") == "1"


async def is_configured(db, connector: str, schema: list[dict[str, Any]]) -> bool:
    """Are all required fields set?"""
    cfg = await read_config(db, connector, schema)
    return all(cfg.get(f["key"], "").strip() for f in schema if f.get("required"))


async def read_public(db, connector: str, meta: dict[str, Any]) -> dict[str, Any]:
    """One connector's state for the interface. **No secret value.**"""
    schema = meta.get("config_schema", []) or []
    stored = await _raw(db, connector)
    fields = []
    for f in schema:
        secret = bool(f.get("secret"))
        value = stored.get(f["key"], "")
        fields.append({
            "key": f["key"],
            "label": f.get("label", f["key"]),
            "type": f.get("type", "text"),
            "required": bool(f.get("required")),
            "secret": secret,
            # A secret never comes back out: only whether it exists.
            "value": "" if secret else value,
            "set": bool(value.strip()),
        })
    last_result: Any = None
    if stored.get(LAST_RESULT):
        try:
            last_result = json.loads(stored[LAST_RESULT])
        except (ValueError, TypeError):
            last_result = None
    return {
        "name": connector,
        "label": meta.get("label", connector),
        "interval_hours": meta.get("interval_hours", 6),
        "enabled": stored.get(ENABLED, "") == "1",
        "configured": all(f["set"] for f in fields if f["required"]),
        "last_run_at": stored.get(LAST_RUN, "") or None,
        "last_result": last_result,
        "fields": fields,
    }


async def save_config(db, connector: str, schema: list[dict[str, Any]],
                      values: dict[str, Any], enabled: bool | None) -> None:
    """Writes the configuration. Fields absent from the schema are ignored.

    A secret field received **empty** is left as-is rather than erased: the
    interface never re-displays a secret, so saving the form sends an empty
    string for an unchanged secret. Overwriting would erase the secret on
    every edit of a neighbouring field. To delete a secret, the interface
    sends an explicit ``null``.
    """
    known = {f["key"]: f for f in schema}
    for k, v in (values or {}).items():
        f = known.get(k)
        if f is None:
            continue
        secret = bool(f.get("secret"))
        if v is None:
            await _put(db, key_for(connector, k), "", secret)
            continue
        v = str(v)
        if secret and not v.strip():
            continue
        await _put(db, key_for(connector, k), v, secret)
    if enabled is not None:
        await _put(db, key_for(connector, ENABLED), "1" if enabled else "0")


async def record_run(db, connector: str, report: dict[str, Any]) -> None:
    """Timestamps the pass and keeps a displayable summary.

    The timestamp is written **whether the import succeeded or not**: without
    it, a failing connector would be relaunched on every 60 s tick, hammering
    the upstream API and possibly getting the service account blocked.
    """
    await _put(db, key_for(connector, LAST_RUN),
               datetime.now(timezone.utc).isoformat())
    summary = {k: report.get(k) for k in
               ("ok", "hosts", "findings", "closed", "error", "duration_s")}
    await _put(db, key_for(connector, LAST_RESULT), json.dumps(summary))
