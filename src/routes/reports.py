"""v0.3 — Executive report + email digest.

The PDF report is generated client-side (the frontend opens a new
tab with a print-optimised layout and lets the user print-to-PDF via
their browser) so the backend stays dependency-free. This endpoint
returns the aggregated data the frontend needs.

The email digest reuses the same data shape and is sent via stdlib
smtplib + email.mime — no new dependencies.

Hardening (post-v0.3 audit):
  - _aggregate_report uses SQL aggregations (no full-table scans)
  - _render_digest_html escapes every interpolated value
  - SMTP host is validated via _resolve_safe_target (SSRF)
  - sender/recipients are validated with email.utils.parseaddr
  - The blocking smtplib call runs in asyncio.to_thread
"""
from __future__ import annotations

import asyncio
import html as _html
import logging
import re
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import AppSettings, Finding, Measure, MonitoredAsset, ScanJob, User
from src.scanners import _resolve_safe_target

logger = logging.getLogger("surface.reports")
router = APIRouter(prefix="/api/reports", tags=["reports"])


_EMAIL_ADDR_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def _validate_email(addr: str) -> str:
    """Reject CRLF/NUL (header-injection vector), run through parseaddr,
    enforce a strict regex. Raises ValueError on anything suspicious."""
    raw = addr or ""
    if any(c in raw for c in ("\r", "\n", "\x00")):
        raise ValueError("Caractères de contrôle interdits dans l'adresse")
    clean = raw.strip()
    if not clean:
        raise ValueError("Adresse vide")
    _, parsed = parseaddr(clean)
    if not parsed or not _EMAIL_ADDR_RE.match(parsed):
        raise ValueError(f"Adresse invalide : {addr!r}")
    return parsed


def _parse_recipients(raw: str) -> list[str]:
    out: list[str] = []
    for r in (raw or "").split(","):
        r = r.strip()
        if r:
            out.append(_validate_email(r))
    if not out:
        raise ValueError("Aucun destinataire valide")
    return out


def _validate_smtp_host(host: str) -> str:
    """SSRF guard: run the configured SMTP host through the same allowlist
    as scan targets (blocks loopback, metadata, docker siblings, …)."""
    clean = (host or "").strip()
    if not clean:
        raise ValueError("Host SMTP manquant")
    # _resolve_safe_target enforces charset + blocklist + DNS resolution
    _, canonical = _resolve_safe_target(clean)
    return canonical


async def _aggregate_report(db: AsyncSession) -> dict[str, Any]:
    """Collect every piece of data the executive report needs via SQL
    aggregations. Never loads full tables into memory — the top-N lists
    are bounded with LIMIT clauses."""
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)

    # --- findings: severity × status counts via GROUP BY ---
    sev_status_rows = (await db.execute(
        select(Finding.severity, Finding.status, func.count()).group_by(
            Finding.severity, Finding.status
        )
    )).all()
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status = {"new": 0, "to_fix": 0, "false_positive": 0, "fixed": 0}
    for sev, status, count in sev_status_rows:
        by_status[status] = by_status.get(status, 0) + count
        if status in ("new", "to_fix"):
            by_sev[sev] = by_sev.get(sev, 0) + count

    new_last_7d = (await db.execute(
        select(func.count()).select_from(Finding).where(Finding.created_at >= seven_days_ago)
    )).scalar() or 0
    new_last_30d = (await db.execute(
        select(func.count()).select_from(Finding).where(Finding.created_at >= thirty_days_ago)
    )).scalar() or 0

    # --- top 10 active findings (severity rank × recency), LIMIT at DB layer ---
    sev_order = case(
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        value=Finding.severity,
        else_=9,
    )
    top_rows = (await db.execute(
        select(Finding.id, Finding.severity, Finding.scanner, Finding.title,
               Finding.target, Finding.created_at)
        .where(Finding.status.in_(("new", "to_fix")))
        .order_by(sev_order.asc(), Finding.created_at.desc())
        .limit(10)
    )).all()
    top_findings = [
        {
            "id": str(row.id),
            "severity": row.severity,
            "scanner": row.scanner,
            "title": row.title,
            "target": row.target or "",
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in top_rows
    ]

    # --- asset counts via GROUP BY ---
    kind_rows = (await db.execute(
        select(MonitoredAsset.kind, func.count()).group_by(MonitoredAsset.kind)
    )).all()
    kind_counts = {k: c for k, c in kind_rows}
    hosts_count = kind_counts.get("host", 0)
    domains_count = kind_counts.get("domain", 0)
    assets_total = sum(kind_counts.values())

    # --- top 10 hosts by active-finding severity, bounded by LIMIT ---
    # Group by the host portion of target, capped to the first ':' for port.
    host_expr = func.split_part(Finding.target, ":", 1).label("host")
    crit_expr = func.sum(case((Finding.severity == "critical", 1), else_=0)).label("crit")
    high_expr = func.sum(case((Finding.severity == "high", 1), else_=0)).label("high")
    med_expr = func.sum(case((Finding.severity == "medium", 1), else_=0)).label("med")
    low_expr = func.sum(case((Finding.severity == "low", 1), else_=0)).label("low")
    info_expr = func.sum(case((Finding.severity == "info", 1), else_=0)).label("info_")
    total_expr = func.count().label("total")
    host_rows = (await db.execute(
        select(host_expr, crit_expr, high_expr, med_expr, low_expr, info_expr, total_expr)
        .where(Finding.status.in_(("new", "to_fix")))
        .where(Finding.target.isnot(None))
        .where(Finding.target != "")
        .group_by(host_expr)
        .order_by(crit_expr.desc(), high_expr.desc(), total_expr.desc())
        .limit(10)
    )).all()
    top_hosts = [
        {
            "value": row.host or "",
            "counts": {
                "critical": int(row.crit or 0),
                "high": int(row.high or 0),
                "medium": int(row.med or 0),
                "low": int(row.low or 0),
                "info": int(row.info_ or 0),
                "total": int(row.total or 0),
            },
        }
        for row in host_rows if row.host
    ]

    # --- scan health (last 7d) via GROUP BY ---
    job_rows = (await db.execute(
        select(ScanJob.status, func.count())
        .where(ScanJob.created_at >= seven_days_ago)
        .group_by(ScanJob.status)
    )).all()
    job_counts = {s: c for s, c in job_rows}
    jobs_total = sum(job_counts.values())
    jobs_ok = job_counts.get("completed", 0)
    jobs_failed = job_counts.get("failed", 0)

    # --- measures via GROUP BY ---
    measure_rows = (await db.execute(
        select(Measure.statut, func.count()).group_by(Measure.statut)
    )).all()
    measure_counts = {s: c for s, c in measure_rows}
    measures_total = sum(measure_counts.values())
    measures_done = measure_counts.get("termine", 0)
    measures_in_progress = measure_counts.get("en_cours", 0)

    return {
        "generated_at": now.isoformat(),
        "period": {
            "days": 30,
            "from": thirty_days_ago.isoformat(),
            "to": now.isoformat(),
        },
        "totals": {
            "active_findings": sum(by_sev.values()),
            "by_severity": by_sev,
            "by_status": by_status,
            "new_last_7d": int(new_last_7d),
            "new_last_30d": int(new_last_30d),
        },
        "scope": {
            "hosts": int(hosts_count),
            "domains": int(domains_count),
            "assets_total": int(assets_total),
        },
        "top_findings": top_findings,
        "top_hosts": top_hosts,
        "scans": {
            "last_7d": int(jobs_total),
            "completed": int(jobs_ok),
            "failed": int(jobs_failed),
            "success_rate": round(jobs_ok / jobs_total * 100) if jobs_total else 100,
        },
        "measures": {
            "total": int(measures_total),
            "done": int(measures_done),
            "in_progress": int(measures_in_progress),
            "burn_down": round(measures_done / measures_total * 100) if measures_total else 0,
        },
    }


@router.get("/executive")
async def executive_report(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregated data the frontend uses to render the executive PDF."""
    return await _aggregate_report(db)


# ═══════════════════════════════════════════════════════════════
# Email digest — SMTP config + send endpoint + renderer
# ═══════════════════════════════════════════════════════════════

class SmtpConfig(BaseModel):
    host: str = Field("", max_length=200)
    port: int = Field(587, ge=1, le=65535)
    username: str = Field("", max_length=200)
    password: str = Field("", max_length=500)
    sender: str = Field("", max_length=200)
    recipients: str = Field("", max_length=1000)  # comma-separated
    use_tls: bool = True


async def _load_smtp(db: AsyncSession) -> dict[str, str]:
    rows = await db.execute(select(AppSettings).where(AppSettings.key.like("smtp.%")))
    cfg: dict[str, str] = {}
    for r in rows.scalars():
        cfg[r.key[len("smtp."):]] = r.value or ""
    return cfg


def _render_digest_html(data: dict[str, Any]) -> str:
    """Render the weekly-digest HTML. Every interpolated value is passed
    through html.escape — the finding title/target/host come from scanner
    output and must be treated as untrusted."""
    e = _html.escape
    sevs = data["totals"]["by_severity"]
    rows = ""
    for f in data["top_findings"][:10]:
        rows += (
            f'<tr><td style="padding:4px 8px"><strong>{e(str(f["severity"]))}</strong></td>'
            f'<td style="padding:4px 8px">{e(str(f["title"]))}</td>'
            f'<td style="padding:4px 8px;color:#6b7280;font-family:monospace">{e(str(f["target"]))}</td></tr>'
        )
    host_rows = ""
    for h in data["top_hosts"][:10]:
        c = h["counts"]
        host_rows += (
            f'<tr><td style="padding:4px 8px;font-family:monospace">{e(str(h["value"]))}</td>'
            f'<td style="padding:4px 8px"><strong style="color:#b91c1c">{int(c.get("critical",0))}</strong> · '
            f'<strong style="color:#f97316">{int(c.get("high",0))}</strong> · '
            f'{int(c.get("medium",0))} · {int(c.get("low",0))}</td></tr>'
        )
    generated_at = e(str(data["generated_at"])[:10])
    active = int(data["totals"]["active_findings"])
    new7 = int(data["totals"]["new_last_7d"])
    hosts = int(data["scope"]["hosts"])
    crit = int(sevs.get("critical", 0))
    high = int(sevs.get("high", 0))
    med = int(sevs.get("medium", 0))
    scans_7d = int(data["scans"]["last_7d"])
    success = int(data["scans"]["success_rate"])
    m_done = int(data["measures"]["done"])
    m_total = int(data["measures"]["total"])
    return f"""<!doctype html>
<html><body style="font-family:Segoe UI,sans-serif;background:#f9fafb;margin:0;padding:24px">
<div style="max-width:720px;margin:0 auto;background:white;border:1px solid #e5e7eb;border-radius:12px;padding:24px">
    <h1 style="margin:0 0 4px;color:#1e40af">Surface — digest hebdomadaire</h1>
    <p style="color:#6b7280;margin:0 0 24px">Synthèse générée le {generated_at}</p>

    <h2 style="font-size:1.1em;margin:0 0 8px">Résumé</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px">
        <tr style="background:#f9fafb">
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{active}</strong> findings actifs</td>
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{new7}</strong> nouveaux (7 j)</td>
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{hosts}</strong> hosts surveillés</td>
        </tr>
        <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#b91c1c"><strong>{crit}</strong> critical</td>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#f97316"><strong>{high}</strong> high</td>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#eab308"><strong>{med}</strong> medium</td>
        </tr>
    </table>

    <h2 style="font-size:1.1em;margin:16px 0 8px">Top 10 findings à traiter</h2>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb">{rows}</table>

    <h2 style="font-size:1.1em;margin:16px 0 8px">Top 10 hosts exposés</h2>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb">{host_rows}</table>

    <p style="color:#9ca3af;font-size:0.85em;margin-top:24px">Scans 7 j : {scans_7d} lancés, {success}% succès. Mesures : {m_done}/{m_total} terminées.</p>
    <p style="color:#9ca3af;font-size:0.85em">Ce rapport est généré automatiquement par Surface (CISO Toolbox).</p>
</div>
</body></html>"""


def _smtp_send_blocking(host: str, port: int, use_tls: bool,
                        username: str, password: str,
                        sender: str, recipients: list[str],
                        raw_message: str) -> None:
    """Blocking smtplib helper. Must be called via asyncio.to_thread()
    from async code — stdlib smtplib does not support asyncio."""
    if use_tls:
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            s.starttls()
            if username and password:
                s.login(username, password)
            s.sendmail(sender, recipients, raw_message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as s:
            if username and password:
                s.login(username, password)
            s.sendmail(sender, recipients, raw_message)


def _build_digest_message(cfg: dict[str, str], data: dict[str, Any]) -> tuple[MIMEMultipart, str, list[str]]:
    """Validate sender/recipients/host, build the MIME message. Raises
    ValueError / HTTPException-worthy errors that the caller translates."""
    _validate_smtp_host(cfg["host"])  # SSRF guard
    sender = _validate_email(cfg["sender"])
    recipients = _parse_recipients(cfg.get("recipients", ""))
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Surface — digest hebdomadaire"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(_render_digest_html(data), "html", "utf-8"))
    return msg, sender, recipients


@router.get("/smtp/config")
async def smtp_get_config(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    cfg = await _load_smtp(db)
    return {
        "host": cfg.get("host", ""),
        "port": int(cfg.get("port") or 587),
        "username": cfg.get("username", ""),
        "sender": cfg.get("sender", ""),
        "recipients": cfg.get("recipients", ""),
        "use_tls": (cfg.get("use_tls", "1") != "0"),
        "password_set": bool(cfg.get("password")),
    }


@router.put("/smtp/config")
async def smtp_set_config(
    body: SmtpConfig,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Pre-persist validation: reject unsafe host + malformed addresses so
    # the scheduler can trust whatever is in AppSettings.
    if body.host:
        try:
            _validate_smtp_host(body.host)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"SMTP host refusé : {e}")
    if body.sender:
        try:
            _validate_email(body.sender)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Sender invalide : {e}")
    if body.recipients:
        try:
            _parse_recipients(body.recipients)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Recipients invalides : {e}")

    entries = {
        "host": body.host,
        "port": str(body.port),
        "username": body.username,
        "sender": body.sender,
        "recipients": body.recipients,
        "use_tls": "1" if body.use_tls else "0",
    }
    # Only persist password if non-empty (UI shows placeholder for existing)
    if body.password:
        entries["password"] = body.password
    for short, value in entries.items():
        key = f"smtp.{short}"
        existing = (await db.execute(select(AppSettings).where(AppSettings.key == key))).scalar_one_or_none()
        if existing is None:
            db.add(AppSettings(key=key, value=value))
        else:
            existing.value = value
    await db.commit()
    return {"ok": True}


@router.post("/email-digest/send")
async def email_digest_send(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manual trigger: aggregate a fresh report and email it now.
    Also scheduled weekly via the scheduler (if SMTP is configured)."""
    cfg = await _load_smtp(db)
    if not cfg.get("host") or not cfg.get("sender") or not cfg.get("recipients"):
        raise HTTPException(status_code=400, detail="SMTP non configuré (host/sender/recipients manquants)")

    data = await _aggregate_report(db)
    try:
        msg, sender, recipients = _build_digest_message(cfg, data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

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
    except Exception as e:
        logger.exception("email digest send failed")
        raise HTTPException(status_code=502, detail=f"SMTP send failed: {e}")
    return {"sent": True, "recipients": recipients}
