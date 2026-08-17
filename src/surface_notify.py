"""FEAT-35 (Surface) — new-findings alert notifications.

Surface's model is platform-wide by design: there is NO per-asset
recipient list. A user subscribes through their notification preferences
(default OFF), picks a severity floor, and receives an email for every
scan that discovers new findings at or above that floor.

Subscribers are enumerated from Pilot in suite mode (single storage) or
from the local ``notification_prefs`` table in standalone. Send
discipline is the shared suite pattern: ``digest_runs`` journal, one
email per (scan job × recipient), archived bodies, never failing the
scan on a notification error.
"""
from __future__ import annotations

import asyncio
import html as _html
import logging
import os
import uuid
from datetime import datetime, timezone
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import DigestRun, Finding, NotificationPrefs, User

logger = logging.getLogger("surface-notify")

PILOT_URL = os.getenv("PILOT_URL", "")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SURFACE_PREF_DEFAULTS = {"alert_enabled": False, "alert_min_severity": "low",
                         "subject_prefix": "[Surface]"}


def severity_passes(severity: str, minimum: str) -> bool:
    s = _SEV_ORDER.get((severity or "").lower(), 3)
    m = _SEV_ORDER.get((minimum or "low").lower(), 3)
    return s <= m


def surface_prefs_of(full_prefs: dict | None) -> dict:
    out = dict(SURFACE_PREF_DEFAULTS)
    block = ((full_prefs or {}).get("module_prefs") or {}).get("surface") or {}
    for k in out:
        if k in block:
            out[k] = block[k]
    out["lang"] = (full_prefs or {}).get("lang") or ""
    return out


async def list_subscribers(db: AsyncSession) -> list[dict]:
    """[{email, prefs(surface block + lang)}] for every opted-in user."""
    if PILOT_URL and SERVICE_TOKEN:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    PILOT_URL.rstrip("/") + "/api/internal/notification-subscribers",
                    headers={"X-Service-Token": SERVICE_TOKEN},
                    json={"module": "surface"})
            if resp.is_success:
                return [{"email": s["email"], "prefs": surface_prefs_of(s["prefs"])}
                        for s in resp.json().get("subscribers", [])]
            logger.warning("pilot subscribers lookup failed: HTTP %s", resp.status_code)
        except httpx.HTTPError as exc:
            logger.warning("pilot subscribers lookup unreachable: %s", exc)
        return []
    rows = (await db.execute(
        select(User, NotificationPrefs)
        .join(NotificationPrefs, NotificationPrefs.user_id == User.id)
    )).all()
    out = []
    for u, p in rows:
        block = surface_prefs_of({"module_prefs": p.module_prefs or {}, "lang": p.lang})
        if block.get("alert_enabled"):
            out.append({"email": u.email.lower(), "prefs": block})
    return out


# ── rendering ────────────────────────────────────────────────────────────

_L = {
    "fr": {
        "subject": "{prefix} {target} — {n} nouveau(x) finding(s)",
        "hello": "Bonjour,",
        "intro": "Le scan de {target} a découvert de nouveaux findings sur votre surface d'attaque :",
        "open_app": "Ouvrir dans Surface",
        "footer": "Vous recevez cet email car vous avez activé les alertes Surface dans vos préférences de notification (cloche). Le seuil de sévérité s'y règle aussi.",
    },
    "en": {
        "subject": "{prefix} {target} — {n} new finding(s)",
        "hello": "Hello,",
        "intro": "The scan of {target} discovered new findings on your attack surface:",
        "open_app": "Open in Surface",
        "footer": "You receive this email because you enabled Surface alerts in your notification preferences (bell). The severity floor is configured there too.",
    },
}

_SEV_COLORS = {"critical": "#c0392b", "high": "#e67e22",
               "medium": "#f1c40f", "low": "#95a5a6", "info": "#bdc3c7"}


def render_alert_html(target: str, findings: list[Finding], lang: str) -> str:
    L = _L.get(lang) or _L["en"]
    e = _html.escape
    body = "<p>" + e(L["hello"]) + "</p>"
    body += "<p>" + e(L["intro"].format(target=target)) + "</p>"
    body += '<table style="border-collapse:collapse;width:100%;background:#fff">'
    ordered = sorted(findings, key=lambda f: _SEV_ORDER.get((f.severity or "").lower(), 3))
    for f in ordered:
        color = _SEV_COLORS.get((f.severity or "").lower(), "#bdc3c7")
        body += ('<tr style="border-bottom:1px solid #e5e7eb">'
                 '<td style="padding:6px 10px;white-space:nowrap;color:' + color
                 + ';font-weight:700;text-transform:uppercase;font-size:12px">' + e(f.severity or "?") + "</td>"
                 '<td style="padding:6px 10px">' + e(f.title or "") + "</td>"
                 '<td style="padding:6px 10px;font-family:monospace;font-size:12px;color:#6b7280">'
                 + e((f.target or "")[:80]) + "</td></tr>")
    body += "</table>"
    base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    if base:
        url = base + "/surface/#findings"
        body += ('<p><a href="' + e(url) + '" style="color:#2563eb">'
                 + e(L["open_app"]) + " ↗</a></p>")
    body += '<p style="margin-top:26px;font-size:12px;color:#7f8c8d">' + e(L["footer"]) + "</p>"
    return ('<!doctype html><html><body style="font-family:Arial,sans-serif;color:#222;'
            'line-height:1.5;background:#f5f5f5;margin:0;padding:0">'
            '<div style="max-width:760px;margin:0 auto;padding:24px">' + body + "</div></body></html>")


# ── delivery (Surface's own SMTP rows, decrypted) ────────────────────────

async def _smtp_cfg(db: AsyncSession) -> dict:
    from src.routes.reports import _load_smtp
    return await _load_smtp(db)


def _send_email(cfg: dict, recipient: str, subject: str, html: str) -> None:
    from src.mailer_common import smtp_deliver
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    from src.routes.reports import _smtp_tls_on, _validate_smtp_host
    sender = cfg.get("from_addr") or cfg.get("user") or ""
    msg["From"] = formataddr(("CISO Toolbox Surface", sender))
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html", "utf-8"))
    smtp_deliver(
        cfg.get("host", ""), int(cfg.get("port") or 587),
        use_tls=_smtp_tls_on(cfg),
        username=cfg.get("user") or "", password=cfg.get("password") or "",
        sender=sender, recipients=[recipient], raw_message=msg.as_string(),
        # Same guard as the report path (reports.py): loopback, link-local,
        # cloud metadata and sibling service names are never a mail relay
        # from inside this container. LAN relays (RFC1918) are allowed.
        # Applying it on one send path and not the other meant the same
        # config could pass or fail depending on which mail was going out.
        host_validator=_validate_smtp_host,
    )


async def _journal_and_send(db: AsyncSession, recipient: str, period_key: str,
                            subject: str, html: str, items: int) -> str:
    cfg = await _smtp_cfg(db)
    status, err = "sent", ""
    if not cfg.get("host"):
        status, err = "failed", "SMTP not configured"
    else:
        try:
            await asyncio.to_thread(_send_email, cfg, recipient, subject, html)
        except Exception as exc:
            status, err = "failed", str(exc)[:2000]
    db.add(DigestRun(id=uuid.uuid4(), recipient=recipient, kind="alert",
                     period_key=period_key, status=status, items_count=items,
                     error_message=err, body_html=html))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return "duplicate"
    logger.info("surface alert %s for %s (%s items)", status, recipient, items)
    return status


# ── the alert (called at scan completion) ────────────────────────────────

async def notify_scan_new_findings(db: AsyncSession, job_id, target: str,
                                   started_at: datetime | None) -> None:
    """Email every subscriber about findings first seen by this run,
    filtered by their severity floor. Never raises."""
    try:
        since = started_at or datetime.now(timezone.utc)
        new_rows = (await db.execute(
            select(Finding).where(
                Finding.status == "new",
                Finding.created_at >= since,
            )
        )).scalars().all()
        if not new_rows:
            return
        for sub in await list_subscribers(db):
            prefs = sub["prefs"]
            visible = [f for f in new_rows
                       if severity_passes(f.severity, prefs.get("alert_min_severity", "low"))]
            if not visible:
                continue
            lang = prefs.get("lang") or "en"
            lang = lang if lang in ("fr", "en") else "en"
            prefix = (prefs.get("subject_prefix") or "[Surface]").strip()
            html = render_alert_html(target, visible, lang)
            subject = (_L.get(lang) or _L["en"])["subject"].format(
                prefix=prefix, target=target, n=len(visible))
            await _journal_and_send(db, sub["email"], str(job_id), subject, html, len(visible))
    except Exception:  # pragma: no cover — never fail the scan on notify
        logger.exception("surface alert notification crashed for job %s", job_id)
        try:
            await db.rollback()
        except Exception:
            pass


async def send_test_alert(db: AsyncSession, email: str, prefs: dict) -> str:
    """'Run a test' — an alert-style email with the most recent open
    findings above the caller's floor (empty test still sends, so the
    SMTP chain is verifiable)."""
    rows = (await db.execute(
        select(Finding).where(Finding.status.in_(("new", "to_fix")))
        .order_by(Finding.created_at.desc()).limit(200)
    )).scalars().all()
    visible = [f for f in rows
               if severity_passes(f.severity, prefs.get("alert_min_severity", "low"))][:15]
    lang = prefs.get("lang") or "en"
    lang = lang if lang in ("fr", "en") else "en"
    prefix = (prefs.get("subject_prefix") or "[Surface]").strip()
    html = render_alert_html("test", visible, lang)
    subject = (_L.get(lang) or _L["en"])["subject"].format(
        prefix=prefix, target="test", n=len(visible))
    return await _journal_and_send(db, email.lower(), "t-" + uuid.uuid4().hex[:8],
                                   subject, html, len(visible))
