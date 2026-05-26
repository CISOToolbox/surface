"""Audit log — records user actions for traceability.

Usage from any route:
    from src.audit import log_action
    await log_action(db, user, request, "finding.triage",
                     target="App / CVE-xxx", details={"from": "new", "to": "fixed"})

The audit_log table is append-only, never modified or deleted.
Admin-only GET /api/audit-log exposes it to the frontend.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import AuditLog, User

logger = logging.getLogger("audit")


async def log_action(
    db: AsyncSession,
    user: Optional[User],
    request: Optional[Request],
    action: str,
    target: str = "",
    details: str | dict = "",
) -> None:
    """Append an entry to the audit log. Non-blocking — errors are
    logged but never bubble up to the caller.

    Resilience: the insert runs inside a SAVEPOINT so that an audit-log
    failure (e.g. schema drift, missing column) cannot poison the
    caller's outer transaction with a PendingRollbackError.
    User attributes are read into local strings up front so the
    caller's User instance is never re-accessed if the savepoint
    rolls back."""
    # Snapshot user attrs BEFORE any DB I/O — once we enter the
    # savepoint, a failed flush would expire ORM instances and
    # subsequent attribute access would lazy-load on a poisoned txn.
    try:
        email = (getattr(user, "email", "") or "") if user else ""
        name = (getattr(user, "name", "") or "") if user else ""
    except Exception:
        email, name = "", ""
    ip = request.client.host if request and request.client else ""
    detail_str = json.dumps(details, default=str) if isinstance(details, dict) else str(details or "")

    try:
        async with db.begin_nested():
            db.add(AuditLog(
                logged_at=datetime.now(timezone.utc),
                user_email=email[:255],
                user_name=name[:255],
                action=action[:100],
                target=str(target)[:500],
                details=detail_str[:5000],
                ip_address=ip[:64],
            ))
            # flush within the savepoint so any DB error is rolled
            # back at the savepoint level — the outer transaction
            # stays usable.
            await db.flush()
    except Exception as e:
        logger.warning("audit log write failed: %s", e)
