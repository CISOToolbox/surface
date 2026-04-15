"""v0.3 — Executive report + email digest.

The PDF report is generated client-side (the frontend opens a new
tab with a print-optimised layout and lets the user print-to-PDF via
their browser) so the backend stays dependency-free. This endpoint
returns the aggregated data the frontend needs.

The email digest reuses the same data shape and is sent via stdlib
smtplib + email.mime — no new dependencies.
"""
from __future__ import annotations

import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.models import AppSettings, Finding, Measure, MonitoredAsset, ScanJob, User

logger = logging.getLogger("surface.reports")
router = APIRouter(prefix="/api/reports", tags=["reports"])


async def _aggregate_report(db: AsyncSession) -> dict[str, Any]:
    """Collect every piece of data the executive report needs in one
    pass, so the frontend can render the whole page without extra
    round-trips. Kept deliberately small (no raw finding dumps)."""
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)

    # Counts by severity — active findings only (new + to_fix)
    findings = (await db.execute(select(Finding))).scalars().all()
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_status = {"new": 0, "to_fix": 0, "false_positive": 0, "fixed": 0}
    active_findings: list[Finding] = []
    new_last_7d = 0
    new_last_30d = 0
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
        if f.status in ("new", "to_fix"):
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            active_findings.append(f)
        if f.created_at and f.created_at >= seven_days_ago:
            new_last_7d += 1
        if f.created_at and f.created_at >= thirty_days_ago:
            new_last_30d += 1

    # Top 10 active findings by severity × recency
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    active_findings.sort(
        key=lambda f: (sev_rank.get(f.severity, 9), -(f.created_at.timestamp() if f.created_at else 0))
    )
    top_findings = [
        {
            "id": str(f.id),
            "severity": f.severity,
            "scanner": f.scanner,
            "title": f.title,
            "target": f.target or "",
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in active_findings[:10]
    ]

    # Monitored assets — totals + top exposed hosts
    assets = (await db.execute(select(MonitoredAsset))).scalars().all()
    hosts = [a for a in assets if a.kind == "host"]
    domains = [a for a in assets if a.kind == "domain"]

    # Per-host active-finding counts
    host_counts: dict[str, dict[str, int]] = {}
    for f in active_findings:
        tgt = (f.target or "").split(":")[0]
        if not tgt:
            continue
        d = host_counts.setdefault(tgt, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
        d[f.severity] = d.get(f.severity, 0) + 1
        d["total"] += 1
    top_hosts = sorted(host_counts.items(),
                       key=lambda kv: (kv[1].get("critical", 0), kv[1].get("high", 0), kv[1]["total"]),
                       reverse=True)[:10]

    # Scan health over the last 7 days
    recent_jobs = [j for j in (await db.execute(select(ScanJob))).scalars().all()
                   if j.created_at and j.created_at >= seven_days_ago]
    jobs_total = len(recent_jobs)
    jobs_failed = sum(1 for j in recent_jobs if j.status == "failed")
    jobs_ok = sum(1 for j in recent_jobs if j.status == "completed")

    # Measures status
    measures = (await db.execute(select(Measure))).scalars().all()
    measures_total = len(measures)
    measures_done = sum(1 for m in measures if m.statut == "termine")
    measures_in_progress = sum(1 for m in measures if m.statut == "en_cours")

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
            "new_last_7d": new_last_7d,
            "new_last_30d": new_last_30d,
        },
        "scope": {
            "hosts": len(hosts),
            "domains": len(domains),
            "assets_total": len(assets),
        },
        "top_findings": top_findings,
        "top_hosts": [
            {
                "value": host,
                "counts": counts,
            }
            for host, counts in top_hosts
        ],
        "scans": {
            "last_7d": jobs_total,
            "completed": jobs_ok,
            "failed": jobs_failed,
            "success_rate": round(jobs_ok / jobs_total * 100) if jobs_total else 100,
        },
        "measures": {
            "total": measures_total,
            "done": measures_done,
            "in_progress": measures_in_progress,
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
    sevs = data["totals"]["by_severity"]
    rows = ""
    for f in data["top_findings"][:10]:
        rows += (
            f'<tr><td style="padding:4px 8px"><strong>{f["severity"]}</strong></td>'
            f'<td style="padding:4px 8px">{f["title"]}</td>'
            f'<td style="padding:4px 8px;color:#6b7280;font-family:monospace">{f["target"]}</td></tr>'
        )
    host_rows = ""
    for h in data["top_hosts"][:10]:
        c = h["counts"]
        host_rows += (
            f'<tr><td style="padding:4px 8px;font-family:monospace">{h["value"]}</td>'
            f'<td style="padding:4px 8px"><strong style="color:#b91c1c">{c.get("critical",0)}</strong> · '
            f'<strong style="color:#f97316">{c.get("high",0)}</strong> · '
            f'{c.get("medium",0)} · {c.get("low",0)}</td></tr>'
        )
    return f"""<!doctype html>
<html><body style="font-family:Segoe UI,sans-serif;background:#f9fafb;margin:0;padding:24px">
<div style="max-width:720px;margin:0 auto;background:white;border:1px solid #e5e7eb;border-radius:12px;padding:24px">
    <h1 style="margin:0 0 4px;color:#1e40af">Surface — digest hebdomadaire</h1>
    <p style="color:#6b7280;margin:0 0 24px">Synthèse générée le {data["generated_at"][:10]}</p>

    <h2 style="font-size:1.1em;margin:0 0 8px">Résumé</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px">
        <tr style="background:#f9fafb">
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{data["totals"]["active_findings"]}</strong> findings actifs</td>
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{data["totals"]["new_last_7d"]}</strong> nouveaux (7 j)</td>
            <td style="padding:8px;border:1px solid #e5e7eb"><strong>{data["scope"]["hosts"]}</strong> hosts surveillés</td>
        </tr>
        <tr>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#b91c1c"><strong>{sevs.get("critical",0)}</strong> critical</td>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#f97316"><strong>{sevs.get("high",0)}</strong> high</td>
            <td style="padding:8px;border:1px solid #e5e7eb;color:#eab308"><strong>{sevs.get("medium",0)}</strong> medium</td>
        </tr>
    </table>

    <h2 style="font-size:1.1em;margin:16px 0 8px">Top 10 findings à traiter</h2>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb">{rows}</table>

    <h2 style="font-size:1.1em;margin:16px 0 8px">Top 10 hosts exposés</h2>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb">{host_rows}</table>

    <p style="color:#9ca3af;font-size:0.85em;margin-top:24px">Scans 7 j : {data["scans"]["last_7d"]} lancés, {data["scans"]["success_rate"]}% succès. Mesures : {data["measures"]["done"]}/{data["measures"]["total"]} terminées.</p>
    <p style="color:#9ca3af;font-size:0.85em">Ce rapport est généré automatiquement par Surface (CISO Toolbox).</p>
</div>
</body></html>"""


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
    html = _render_digest_html(data)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Surface — digest hebdomadaire"
    msg["From"] = cfg["sender"]
    recipients = [r.strip() for r in cfg["recipients"].split(",") if r.strip()]
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html", "utf-8"))
    try:
        port = int(cfg.get("port") or 587)
        host = cfg["host"]
        if cfg.get("use_tls", "1") != "0":
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                if cfg.get("username") and cfg.get("password"):
                    s.login(cfg["username"], cfg["password"])
                s.sendmail(cfg["sender"], recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                if cfg.get("username") and cfg.get("password"):
                    s.login(cfg["username"], cfg["password"])
                s.sendmail(cfg["sender"], recipients, msg.as_string())
    except Exception as e:
        logger.exception("email digest send failed")
        raise HTTPException(status_code=502, detail=f"SMTP send failed: {e}")
    return {"sent": True, "recipients": recipients}
