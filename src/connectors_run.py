"""FEAT-37 — connector execution and upstream-feed reconciliation.

A connector pulls a tenant-wide inventory, creates the hosts it discovers,
and — the heart of the feature — **closes what has left the feed**.

Closing is the dangerous part. Three guards bound it, each matching a known
way of breaking everything:

1. **Only on an end-to-end successful import.** A network error mid-pagination
   must not close half the fleet. The ``ok`` flag returned by the connector is
   the condition — not the absence of an exception, which says nothing about
   completeness.

2. **Scoped to the connector's own scanner.** Never to another scanner's
   findings on the same host: an nmap and a Defender see the same machine
   without knowing about each other.

3. **Human-decided statuses stay decided.** ``false_positive`` is frozen, and
   ``to_fix`` as long as its measure is not done. Auto-closing over them would
   erase remediation work in progress.

What a closure does NOT say: why. An absent CVE may be fixed or excepted —
the Defender API cannot tell them apart. Hence ``closed_upstream`` rather than
``fixed`` or ``false_positive`` (see FEAT-37). The exception: findings whose
upstream exception IS visible (Defender recommendations carry a ``status``)
are closed **with their motive**, passed by the connector in ``excepted``.

Lessons from the reverted first delivery, all baked in here:
  - findings are loaded with ``selectinload(Finding.measure)`` — the lazy
    access raised ``MissingGreenlet`` on the nominal to_fix path and rolled
    back every import;
  - a per-connector ``asyncio.Lock`` serialises the manual run and the
    scheduler pass — two concurrent imports duplicated hosts;
  - hosts are resolved through a prebuilt index (upstream id → DNS name →
    IP), one query per run instead of two per machine.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from src.findings_dedup import compute_dedup_key, insert_many
from src.models import Finding, MonitoredAsset

logger = logging.getLogger("surface-backend")

# Statuses a reconciliation never touches: they carry a human decision or work
# in progress. `fixed` is included — a finding an analyst marked "corrigé" is
# already in a terminal closed state, and overwriting it with closed_upstream
# would replace a precise human decision with the vaguer "the source went
# quiet". If the source keeps reporting it, insert_or_dedupe reopens it to
# `new` anyway (the fix did not hold).
FROZEN_STATUSES = ("false_positive", "fixed")

# One lock per connector, shared by the scheduler pass and the manual-run
# route. Single-process (uvicorn) by construction, like the scheduler itself.
_LOCKS: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


def lock_for(name: str) -> asyncio.Lock:
    return _LOCKS[name]


class HostResolver:
    """Matches an upstream machine to a Surface host, or creates it.

    Matching order: upstream id (stable — the DNS name can change), then DNS
    name, then IP. A host already known to Surface — discovered by an external
    scan — must RECEIVE the connector's findings, not be duplicated, whatever
    the order of the two discoveries (criteria 2 and 12). This is where a
    mistake shows immediately, as two cards for the same machine.

    The index is built once per run: two queries per machine did not scale to
    a 5000-machine fleet, and the in-memory index also makes the batch
    self-consistent (a machine resolved twice in one run hits the same row).
    """

    def __init__(self, connector: str):
        self.connector = connector
        self.by_upstream_id: dict[str, MonitoredAsset] = {}
        self.by_name: dict[str, MonitoredAsset] = {}
        self.by_ip: dict[str, MonitoredAsset] = {}

    async def load(self, db) -> "HostResolver":
        rows = (await db.execute(
            select(MonitoredAsset).where(MonitoredAsset.kind == "host")
        )).scalars().all()
        for a in rows:
            up = ((a.config or {}).get("connector_ids") or {}).get(self.connector, "")
            if up:
                self.by_upstream_id[up] = a
            if a.value:
                self.by_name.setdefault(a.value.strip().lower(), a)
            if a.resolved_ip:
                self.by_ip.setdefault(a.resolved_ip.strip(), a)
        return self

    def resolve(self, db, machine: dict[str, Any]) -> MonitoredAsset:
        up_id = str(machine.get("id", "") or "")
        name = (machine.get("dns_name") or "").strip().lower()
        ip = (machine.get("ip") or "").strip()

        found = (self.by_upstream_id.get(up_id) if up_id else None) \
            or (self.by_name.get(name) if name else None) \
            or (self.by_ip.get(ip) if ip else None)

        if found is not None:
            cfg = dict(found.config or {})
            # One-shot enrolment: the FIRST time this connector meets a host,
            # it adds itself to the host's active scanners (union — a host
            # already scanned externally keeps nmap/TLS AND gains the
            # connector, so both views land on the same card). A host that was
            # in the pure old-model default (disabled, no scanner — an
            # artefact, never an admin's choice) is also enabled. The enrolled
            # flag makes a later admin removal stick: the connector is not
            # re-added on the next import.
            enrolled = dict(cfg.get("connector_enrolled") or {})
            if not enrolled.get(self.connector):
                scanners = list(found.enabled_scanners or [])
                if not found.enabled and not scanners:
                    found.enabled = True        # heal the old-model artefact
                if self.connector not in scanners:
                    scanners.append(self.connector)
                found.enabled_scanners = scanners
                enrolled[self.connector] = True
                cfg["connector_enrolled"] = enrolled
            # Record the upstream id for the next imports: the DNS name may
            # change, the id does not.
            ids = dict(cfg.get("connector_ids") or {})
            if up_id and ids.get(self.connector) != up_id:
                ids[self.connector] = up_id
            cfg["connector_ids"] = ids
            found.config = cfg
            if ip and not found.resolved_ip:
                found.resolved_ip = ip
                self.by_ip.setdefault(ip, found)
            if up_id:
                self.by_upstream_id[up_id] = found
            return found

        asset = MonitoredAsset(
            kind="host",
            value=name or ip,
            label=machine.get("label", "") or "",
            notes="",
            # Enabled, with the CONNECTOR as its only active scanner: `enabled`
            # means "this host reports findings", and the connector is one
            # scanner among others in the host's configuration. Disabling the
            # host (or unticking the connector) stops its findings; adding
            # external scanners is a separate, deliberate choice.
            enabled=True,
            scan_frequency_hours=24,
            enabled_scanners=[self.connector],
            tags=["connector:" + self.connector],
            criticality=machine.get("criticality", "") or "",
            auto_enroll_discoveries=False,
            stealth_mode=False,
            config={"connector_ids": {self.connector: up_id},
                    "connector_enrolled": {self.connector: True},
                    "discovered_by": self.connector},
            resolved_ip=ip or None,
        )
        db.add(asset)
        if up_id:
            self.by_upstream_id[up_id] = asset
        if name:
            self.by_name.setdefault(name, asset)
        if ip:
            self.by_ip.setdefault(ip, asset)
        return asset


async def _reconcile(db, connector: str, seen_keys: set[str],
                     reasons: dict[str, str] | None = None) -> int:
    """Closes as ``closed_upstream`` what the feed no longer reports.

    ONLY called on a complete import — the caller guarantees it. ``reasons``
    maps a dedup_key to an upstream-known motive (recommendation exceptions,
    criterion 10): those closures carry it instead of the generic note.
    """
    reasons = reasons or {}
    # selectinload is load-bearing: the to_fix guard below reads f.measure,
    # and a lazy load in an async session raises MissingGreenlet — the exact
    # failure that rolled back every import of the first delivery.
    rows = (await db.execute(
        select(Finding).options(selectinload(Finding.measure))
        .where(Finding.scanner == connector)
    )).scalars().all()

    closed = 0
    for f in rows:
        if f.dedup_key in seen_keys:
            continue
        if f.status in FROZEN_STATUSES:
            continue
        # to_fix with a still-open measure: remediation in progress.
        if f.status == "to_fix":
            if f.measure is not None and f.measure.statut != "termine":
                continue
        if f.status == "closed_upstream":
            continue                      # already closed, do not rewrite
        f.status = "closed_upstream"
        motif = reasons.get(f.dedup_key)
        if motif == "hôte désactivé dans Surface":
            note = "[Fermé automatiquement : " + motif + "]"
        elif motif:
            note = ("[Fermé automatiquement : exception posée côté source amont — "
                    + motif + "]")
        else:
            note = ("[Fermé automatiquement : la source amont ne le remonte plus "
                    "— corrigé, ou écarté de son côté.]")
        f.triage_notes = ((f.triage_notes or "") + "\n" + note).strip()
        if motif:
            ev = dict(f.evidence or {})
            ev["upstream_exception"] = motif
            f.evidence = ev
        closed += 1
    return closed


async def run_connector(db, name: str, meta: dict[str, Any],
                        config: dict[str, Any]) -> dict[str, Any]:
    """Runs one connector and reconciles. Never raises.

    Returns a report readable in the audit log and the interface. The caller
    holds ``lock_for(name)`` — this function does not re-acquire it so unit
    tests can drive it directly.
    """
    start = datetime.now(timezone.utc)
    report: dict[str, Any] = {"connector": name, "ok": False, "hosts": 0,
                              "findings": 0, "closed": 0, "error": None}
    try:
        result = await meta["callable"](config)
    except Exception as e:  # noqa: BLE001 — a broken connector must not break the tick
        logger.warning("Connector '%s' raised: %s: %s", name, type(e).__name__, e)
        report["error"] = f"{type(e).__name__}: {e}"
        return report

    if not result.get("ok"):
        # Incomplete import: keep what was seen, but CLOSE NOTHING. This is
        # guard #1, and the only thing standing between a network blip and a
        # mass closure.
        report["error"] = result.get("error") or "import incomplet"
        logger.warning("Connector '%s' incomplete, skipping reconciliation: %s",
                       name, report["error"])

    resolver = await HostResolver(name).load(db)
    # Host-level opt-out: `enabled` means "this host reports findings", and
    # the connector is one scanner among others in the host's configuration.
    # Findings of a machine whose host is disabled — or whose scanner list no
    # longer carries this connector — are dropped from the feed, and their
    # existing rows are closed with an honest motive (not the generic
    # "upstream stopped reporting"). Org-wide findings (no host_ref) are
    # never filtered this way.
    silenced_machines: set[str] = set()
    for machine in result.get("hosts", []):
        # A machine with neither DNS name nor IP is unaddressable: creating
        # an asset with value="" would make an uneditable ghost card. Its
        # findings still import (they attach by evidence when possible).
        if not ((machine.get("dns_name") or "").strip()
                or (machine.get("ip") or "").strip()):
            logger.info("connector '%s': machine %s has no name nor IP — skipped",
                        name, machine.get("id", "?"))
            continue
        asset = resolver.resolve(db, machine)
        report["hosts"] += 1
        if not (asset.enabled and name in (asset.enabled_scanners or [])):
            mid = str(machine.get("id", "") or "")
            if mid:
                silenced_machines.add(mid)
    await db.flush()

    # Copies at the engine boundary: the engine stamps and strips keys, and
    # mutating the connector's own dicts would corrupt a result the caller
    # still holds (a reused feed in tests made this visible).
    findings = [dict(c) for c in result.get("findings", [])]
    silence_reasons: dict[str, str] = {}
    if silenced_machines:
        kept = []
        for c in findings:
            if str(c.get("host_ref", "") or "") in silenced_machines:
                key = compute_dedup_key(name, c.get("type", ""),
                                        c.get("target", "") or c.get("title", ""))
                silence_reasons[key] = "hôte désactivé dans Surface"
                continue
            kept.append(c)
        report["silenced"] = len(findings) - len(kept)
        findings = kept
    # The ENGINE stamps the instance key as the scanner, not the add-on: two
    # instances of the same type (two Defender tenants) must never share a
    # scanner value, or each import would close the other tenant's findings
    # during reconciliation. Centralising the stamp here makes a mismatch
    # between insertion and reconciliation impossible.
    for c in findings:
        c["scanner"] = name
        # host_ref is an ENGINE key (host opt-out routing), not a Finding
        # column: it must not reach the model constructor.
        c.pop("host_ref", None)
    if findings:
        counts = await insert_many(db, findings)
        report["findings"] = counts.get("inserted", 0) + counts.get("reopened", 0)

    if result.get("ok"):
        # Seen keys are DERIVED from the feed's findings, with the same
        # function as the insertion. Letting the connector provide its own
        # keys invites divergence: a key computed differently on each side
        # would close, on every import, what was just inserted.
        seen = {compute_dedup_key(name, c.get("type", ""),
                                  c.get("target", "") or c.get("title", ""))
                for c in findings}
        # Upstream-known exceptions (criterion 10): the connector names the
        # finding it wants closed and why, as {type, target, reason} entries.
        # Their keys must NOT be in `seen`.
        reasons = {compute_dedup_key(name, e.get("type", ""), e.get("target", "")):
                   str(e.get("reason", "") or "exception")
                   for e in (result.get("excepted") or [])}
        reasons.update(silence_reasons)
        report["closed"] = await _reconcile(db, name, seen, reasons)
        report["ok"] = True

    await db.commit()
    report["duration_s"] = round((datetime.now(timezone.utc) - start).total_seconds(), 1)
    return report
