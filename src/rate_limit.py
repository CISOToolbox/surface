"""In-memory sliding-window rate limiter.

Simple enough for single-worker deployments. For multi-worker or HA, replace
with a Redis-backed counter.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._last_prune: float = 0.0

    def check(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Return True if the action is allowed, False if rate-limited.
        Uses a deque for O(1) popleft; periodically prunes idle keys so the
        dict doesn't grow forever."""
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            allowed = len(bucket) < limit
            if allowed:
                bucket.append(now)
            if now - self._last_prune > 300:
                self._prune(cutoff)
                self._last_prune = now
            return allowed

    def _prune(self, cutoff: float) -> None:
        """Drop buckets whose most recent entry is older than the window."""
        dead = [k for k, b in self._buckets.items() if not b or b[-1] < cutoff]
        for k in dead:
            del self._buckets[k]


# Global instances — one per action, different limits
scan_limiter = RateLimiter()


def check_scan_quota(user_id: str) -> None:
    """Raise HTTPException 429 if the user has launched too many scans lately.

    Soft quota: 20 scans per minute per user (covers accidental burst + CLI loops).
    """
    from fastapi import HTTPException
    if not scan_limiter.check(user_id, limit=20, window_seconds=60):
        raise HTTPException(status_code=429, detail="Trop de scans recents. Reessayer dans 1 minute.")
