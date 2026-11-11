"""Which findings belong to which monitored asset, and the figures built on
it (FEAT-69): the Hosts cards, a host's page, the dashboard and the executive
report, all over every finding in the database.

The finding side is the match keys stored on each row (src/finding_match.py);
the asset side is matched here, at query time, so an asset added, renamed or
resolving to another IP is matched against every existing finding at once.
The rules, per asset kind:

    host        its value or its resolved IP: the target's host part, the
                evidence hostname (value) or the evidence address (IP)
    domain      itself or any subdomain, on the target or the evidence hostname
    ip_range    the range itself as target, or an address inside it, on the
                target or the evidence address (IPv4)
    file_share  the share's server
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import ColumnElement, case, false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.finding_match import cidr_bounds, share_hostname
from src.models import Finding, MonitoredAsset

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("new", "false_positive", "to_fix", "fixed", "closed_upstream", "derogated")
OPEN = ("new", "to_fix")

# Severity rank, most severe first, for an ORDER BY.
SEVERITY_RANK = case({s: i for i, s in enumerate(SEVERITIES)}, value=Finding.severity, else_=len(SEVERITIES))


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _subdomain_of(column, domain: str) -> ColumnElement[bool]:
    # The domain itself, or "<at least one char>.<domain>".
    return or_(column == domain, column.like("_%." + _like_escape(domain), escape="\\"))


def asset_condition(asset: MonitoredAsset) -> ColumnElement[bool]:
    """The findings that belong to `asset`."""
    value = (asset.value or "").lower()
    if not value:
        return false()
    if asset.kind == "file_share":
        server = share_hostname(asset.value)
        return Finding.match_share == server if server else false()
    if asset.kind == "domain":
        return or_(_subdomain_of(Finding.match_host, value), _subdomain_of(Finding.match_evhost, value))
    if asset.kind == "ip_range":
        cond = [Finding.match_host == value]
        bounds = cidr_bounds(asset.value)
        if bounds:
            low, high = bounds
            cond += [Finding.match_host_ip4.between(low, high), Finding.match_evaddr_ip4.between(low, high)]
        return or_(*cond)
    cond = [Finding.match_host == value, Finding.match_evhost == value]
    ip = (asset.resolved_ip or "").lower()
    if ip:
        cond += [Finding.match_host == ip, Finding.match_evaddr == ip]
    return or_(*cond)


def assets_condition(assets: Iterable[MonitoredAsset]) -> ColumnElement[bool]:
    """The findings that belong to any of `assets`, each once."""
    conds = [asset_condition(a) for a in assets]
    return or_(*conds) if conds else false()


# Statuses with nothing to triage, each counted apart on the card.
_COUNTED_APART = ("false_positive", "fixed", "closed_upstream", "derogated")


def _empty_counts() -> dict[str, int]:
    return {"total": 0, "active": 0, "open": 0, **{s: 0 for s in SEVERITIES},
            **{s: 0 for s in _COUNTED_APART}}


async def counts_for(db: AsyncSession, assets: list[MonitoredAsset]) -> dict[str, int]:
    """A card's counts over the findings of `assets`:

        total            every finding
        critical..info   the open ones (new, to_fix), by severity
        active, open     the same, info excluded
        false_positive, fixed, closed_upstream, derogated
                         counted apart: nothing to triage
    """
    out = _empty_counts()
    rows = (await db.execute(
        select(Finding.severity, Finding.status, func.count())
        .where(assets_condition(assets))
        .group_by(Finding.severity, Finding.status)
    )).all()
    for severity, status, n in rows:
        out["total"] += n
        if status not in OPEN:
            if status in _COUNTED_APART:
                out[status] += n
            continue
        if severity in SEVERITIES:
            out[severity] += n
        if severity == "info":
            continue
        out["active"] += n
        out["open"] += n
    return out


async def asset_counts(db: AsyncSession) -> dict[str, Any]:
    """Counts of every asset, and of every group of hosts sharing a resolved
    IP (shown as one card: a finding of the shared IP counts once)."""
    assets = list((await db.execute(select(MonitoredAsset))).scalars().all())
    by_asset = {str(a.id): await counts_for(db, [a]) for a in assets}
    by_ip: dict[str, list[MonitoredAsset]] = {}
    for a in assets:
        if a.kind == "host" and a.resolved_ip:
            by_ip.setdefault(a.resolved_ip, []).append(a)
    by_group = {ip: await counts_for(db, members) for ip, members in by_ip.items() if len(members) > 1}
    return {"assets": by_asset, "ip_groups": by_group}


async def assets_by_ids(db: AsyncSession, ids: list[uuid.UUID]) -> list[MonitoredAsset]:
    if not ids:
        return []
    return list((await db.execute(select(MonitoredAsset).where(MonitoredAsset.id.in_(ids)))).scalars().all())


# ── Hosts most exposed: shared by the dashboard and the executive report ──

def _finding_host(target: str | None, evhost: str, evaddr: str) -> str:
    """The host an open finding is listed under: the host its evidence names,
    else the target up to its first ':'. Connector findings carry an opaque
    target (`machine|cve|product`) and name their host in the evidence."""
    return evhost or evaddr or (target or "").split(":")[0]


async def top_hosts(db: AsyncSession, n: int) -> list[dict[str, Any]]:
    """The hosts with open findings above info, most severe first, then most
    findings. Each row: host, max_sev (rank, 0 = critical), active (above
    info) and counts (by severity, info included, and total)."""
    rows = (await db.execute(
        select(Finding.target, Finding.match_evhost, Finding.match_evaddr, Finding.severity)
        .where(Finding.status.in_(OPEN))
        .where(Finding.type != "defender_recommendation")
    )).all()
    hosts: dict[str, dict[str, Any]] = {}
    for target, evhost, evaddr, severity in rows:
        host = _finding_host(target, evhost, evaddr)
        if not host or "|" in host:
            continue
        h = hosts.setdefault(host, {"host": host, "max_sev": len(SEVERITIES), "active": 0,
                                    "counts": {**{s: 0 for s in SEVERITIES}, "total": 0}})
        if severity in SEVERITIES:
            h["counts"][severity] += 1
        h["counts"]["total"] += 1
        if severity == "info":
            continue
        h["active"] += 1
        if severity in SEVERITIES:
            h["max_sev"] = min(h["max_sev"], SEVERITIES.index(severity))
    ranked = sorted((h for h in hosts.values() if h["active"]), key=lambda h: (h["max_sev"], -h["active"]))
    return ranked[:n]


# ── Dashboard ──

def _zone(tz: str | None):
    try:
        return ZoneInfo(tz) if tz else timezone.utc
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


async def dashboard_stats(db: AsyncSession, tz: str | None, days: int = 30) -> dict[str, Any]:
    """Every figure of the dashboard, over every finding. Days are cut at the
    viewer's midnight (`tz`, an IANA zone; UTC when unknown)."""
    by_severity = {s: 0 for s in SEVERITIES}   # open findings, info included
    by_status = {s: 0 for s in STATUSES}
    for severity, status, n in (await db.execute(
        select(Finding.severity, Finding.status, func.count()).group_by(Finding.severity, Finding.status)
    )).all():
        if status in by_status:
            by_status[status] += n
        if status in OPEN and severity in by_severity:
            by_severity[severity] += n

    now = datetime.now(timezone.utc)
    recent_24h = (await db.execute(
        select(func.count()).select_from(Finding)
        .where(Finding.severity != "info").where(Finding.created_at > now - timedelta(days=1))
    )).scalar_one()

    # A blank type or scanner ranks with its default, not as a second line.
    ftype = func.coalesce(func.nullif(Finding.type, ""), "other")
    scanner = func.coalesce(func.nullif(Finding.scanner, ""), "manual")
    top_types = [{"type": t, "count": c} for t, c in (await db.execute(
        select(ftype, func.count().label("c"))
        .where(Finding.status.in_(OPEN)).where(Finding.severity != "info")
        .group_by(ftype).order_by(func.count().desc(), ftype).limit(5)
    )).all()]
    top_scanners = [{"scanner": s, "count": c} for s, c in (await db.execute(
        select(scanner, func.count().label("c"))
        .group_by(scanner).order_by(func.count().desc(), scanner).limit(5)
    )).all()]

    return {
        "by_severity": by_severity,
        "by_status": by_status,
        "recent_24h": recent_24h,
        "top_hosts": [{"host": h["host"], "max_sev": h["max_sev"], "total": h["active"]}
                      for h in await top_hosts(db, 5)],
        "top_types": top_types,
        "top_scanners": top_scanners,
        "timeline": await _timeline(db, _zone(tz), days, now),
    }


async def _timeline(db: AsyncSession, zone, days: int, now: datetime) -> list[dict[str, Any]]:
    """One entry per day, oldest first, ending today in `zone`: the findings
    of each severity created by the end of that day (cumulative, so the curve
    never drops on a quiet day), and the findings triaged during it."""
    today = now.astimezone(zone).date()
    first = today - timedelta(days=days - 1)
    # Midnights in the zone: a day across a DST change is not 24 h long.
    start = datetime.combine(first, time.min, zone)
    end = datetime.combine(today + timedelta(days=1), time.min, zone)
    out: list[dict[str, Any]] = [
        {"key": (first + timedelta(days=i)).isoformat(), **{s: 0 for s in SEVERITIES}, "triaged": 0}
        for i in range(days)
    ]

    def day_of(ts: datetime) -> int | None:
        d: date = _aware(ts).astimezone(zone).date()
        i = (d - first).days
        return i if 0 <= i < days else None

    # Created before the window: in every day's total.
    for severity, n in (await db.execute(
        select(Finding.severity, func.count()).where(Finding.created_at < start)
        .group_by(Finding.severity)
    )).all():
        if severity in SEVERITIES:
            for entry in out:
                entry[severity] += n
    for severity, created in (await db.execute(
        select(Finding.severity, Finding.created_at)
        .where(Finding.created_at >= start).where(Finding.created_at < end)
    )).all():
        i = day_of(created)
        if i is None or severity not in SEVERITIES:
            continue
        for entry in out[i:]:
            entry[severity] += 1
    for (triaged,) in (await db.execute(
        select(Finding.triaged_at)
        .where(Finding.triaged_at >= start).where(Finding.triaged_at < end)
    )).all():
        i = day_of(triaged)
        if i is not None:
            out[i]["triaged"] += 1
    return out


def _aware(ts: datetime) -> datetime:
    # SQLite hands timestamps back naive; they are stored in UTC.
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)

