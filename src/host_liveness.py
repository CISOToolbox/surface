"""Host liveness (FEAT-68): is a monitored host still answering?

A scan proves a host alive when one of its scanners sees it answer: a port
open or closed (a reset) to nmap, a TCP connection for TLS, any HTTP answer
from the target to a web scanner. The scanners report it through
``scan_common.note_alive``; the dispatcher turns it into a ``liveness``
control record, applied here to the asset.

The asset keeps the last scan the host answered (``last_alive_at``) and the
first scan it left unanswered since (``unanswered_since``, cleared by an
answer). A host unanswered for ``inactive_after_days`` (a setting, 7 by
default) is flagged inactive — possibly decommissioned. Nothing is disabled
automatically. A scan whose scanners could not see an answer (none of them
can, or each failed on our side) leaves both dates untouched.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

SETTING_KEY = "hosts.inactive_after_days"
DEFAULT_INACTIVE_AFTER_DAYS = 7
MIN_INACTIVE_AFTER_DAYS = 1
MAX_INACTIVE_AFTER_DAYS = 365


def parse_inactive_after_days(raw: str | None) -> int:
    """The stored setting, or the default when missing or out of bounds."""
    try:
        days = int(raw or "")
    except ValueError:
        return DEFAULT_INACTIVE_AFTER_DAYS
    if MIN_INACTIVE_AFTER_DAYS <= days <= MAX_INACTIVE_AFTER_DAYS:
        return days
    return DEFAULT_INACTIVE_AFTER_DAYS


def apply_liveness(asset: Any, alive: bool, now: datetime) -> None:
    """Record one scan that could see the host answer."""
    if alive:
        asset.last_alive_at = now
        asset.unanswered_since = None
    elif asset.unanswered_since is None:
        asset.unanswered_since = now


def forget(asset: Any) -> None:
    """Drop what past scans said: about another target, before the host was
    disabled, or while a scanner could see it answer."""
    asset.last_alive_at = None
    asset.unanswered_since = None


def inactive_since(asset: Any, days: int, now: datetime) -> datetime | None:
    """When an enabled host stopped answering, once that is ``days`` old."""
    since = getattr(asset, "unanswered_since", None)
    if asset.kind != "host" or not asset.enabled or since is None:
        return None
    return since if now - since >= timedelta(days=days) else None
