"""Shared SMTP helpers for CISO Toolbox backend modules.

Master copy: ``shared/python/mailer_common.py``. Copied verbatim into each
module's ``src/`` (no runtime shared dependency — keep the copies identical
and re-copy from the master whenever you change it).

Three modules send mail, with two genuinely different config models:

  * **Watch / Asset** — config is pushed by Pilot into an in-memory
    ``_smtp_config`` dict (``src.routes.internal``) and falls back to env
    vars in standalone mode. They build an ``EmailMessage`` and call
    :func:`send_html_email`.
  * **Surface** — config lives in the database (``app_settings`` rows
    ``smtp.*``), it builds a ``MIMEMultipart`` message and runs the host
    through an SSRF allowlist before connecting. It calls the low-level
    :func:`smtp_deliver` directly, passing its ``host_validator``.

What is shared is the **transport** (the smtplib connection dance: implicit
TLS on port 465, STARTTLS otherwise, optional login, send) plus the
push/env config resolution used by the two twins. Message construction and
the DB/SSRF concerns stay in each module because they legitimately differ.

stdlib only — no new dependency.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from collections.abc import Callable, Sequence
from email.message import EmailMessage


def smtp_deliver(
    host: str,
    port: int,
    *,
    use_tls: bool,
    username: str,
    password: str,
    sender: str,
    recipients: Sequence[str],
    raw_message: str,
    timeout: int = 30,
    host_validator: Callable[[str], None] | None = None,
) -> None:
    """Low-level SMTP delivery. Raises on failure — the caller wraps it.

    * ``port == 465`` → implicit TLS (``SMTP_SSL``).
    * otherwise plain ``SMTP`` + ``STARTTLS`` when ``use_tls`` is true.
    * ``host_validator`` (optional) is invoked before connecting; it must
      raise to abort an unsafe host (Surface's SSRF allowlist).
    """
    if host_validator is not None:
        host_validator(host)
    rcpts = list(recipients)
    if port == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=timeout) as s:
            s.ehlo()
            if username:
                s.login(username, password)
            s.sendmail(sender, rcpts, raw_message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as s:
            s.ehlo()
            if use_tls:
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if username:
                s.login(username, password)
            s.sendmail(sender, rcpts, raw_message)


def resolve_pushed_config(pushed: dict | None, default_from: str) -> dict:
    """Resolve SMTP config from a Pilot in-memory push dict, then env vars.

    Used by Watch and Asset. ``pushed`` is their module-level ``_smtp_config``
    (may be ``None``/empty). Returns host, port (int), user, password,
    from_addr, tls (bool). Empty host means "not configured" — the caller
    short-circuits.
    """
    pushed = pushed or {}

    def _pick(push_key: str, env_key: str, default: str = "") -> str:
        v = pushed.get(push_key)
        if v not in (None, ""):
            return str(v)
        return os.getenv(env_key, default) or default

    user = _pick("user", "SMTP_USER", "")
    port_raw = _pick("port", "SMTP_PORT", "587")
    try:
        port = int(str(port_raw).strip() or "587")
    except ValueError:
        port = 587
    tls_raw = _pick("tls", "SMTP_TLS", "true")
    return {
        "host": _pick("host", "SMTP_HOST", ""),
        "port": port,
        "user": user,
        "password": _pick("password", "SMTP_PASSWORD", ""),
        "from_addr": _pick("from_addr", "SMTP_FROM", user or default_from),
        "tls": str(tls_raw).strip().lower() in ("1", "true", "yes", "on"),
    }


def send_html_email(cfg: dict, to: str, subject: str, html: str,
                    timeout: int = 30) -> tuple[bool, str]:
    """Build an HTML ``EmailMessage`` from a resolved ``cfg`` and send it.

    Returns ``(ok, error_message)``. ``(False, "smtp_not_configured")`` when
    ``cfg['host']`` is empty. Used by Watch and Asset.
    """
    if not cfg.get("host"):
        return False, "smtp_not_configured"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = to
    msg.set_content("HTML mail required.")
    msg.add_alternative(html, subtype="html")
    try:
        smtp_deliver(
            cfg["host"], cfg["port"],
            use_tls=cfg.get("tls", True),
            username=cfg.get("user", ""), password=cfg.get("password", ""),
            sender=cfg["from_addr"], recipients=[to],
            raw_message=msg.as_string(), timeout=timeout,
        )
        return True, ""
    except Exception as e:
        return False, str(e)[:5000]
