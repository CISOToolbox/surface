"""Surface scanner ENGINE.

The scanners themselves now live as add-on modules under `addons/core/<name>/`
(bundled in every image) and `addons/generic|custom/` (opt-in). This module
keeps only:
- the registry + add-on loader (`SCANNER_REGISTRY`, `_load_addon_scanners`),
- the dispatcher (`run_enabled_scanners` / `_run_scanners_inner`),
- cross-cutting app config used by both scanners and HTTP routes
  (nuclei tuning cache, Shodan API-key cache),
- a re-export of the shared primitives from `src.scan_common` so existing
  `from src.scanners import ...` call-sites keep working.

Shared helpers (anti-SSRF, scope, stealth, nmap-XML parsing, TLS context) live
in `src.scan_common`. See `addons/README.md` for the add-on contract.
"""
from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger("surface.scanners")

from src.scan_common import (  # noqa: F401  # re-exported for routes/scheduler + add-ons
    _DOCKER_SIBLING_NAMES, _METADATA_IPS,
    _safe_target, _resolve_safe_target, resolve_first_ip, _is_ip_literal, _check_ip_allowed,
    _int_env, _dns_query, _http_probe,
    _severity_for_port, HIGH_RISK_SERVICES, CRITICAL_SERVICES, _parse_nmap_xml, _tls_ssl_context,
    _STEALTH_CTX, _STEALTH_BROWSER_UA, _is_stealth,
    _MULTI_LABEL_TLDS, _HOST_RE, _registrable, _normalize_host, _in_scope,
)





_NUCLEI_TUNING_KEYS = ("rate_limit", "concurrency", "bulk_size", "timeout", "retries")
_NUCLEI_TUNING_LIMITS: dict[str, tuple[int, int]] = {
    "rate_limit":  (1, 5000),
    "concurrency": (1, 500),
    "bulk_size":   (1, 500),
    "timeout":     (1, 300),
    "retries":     (0, 10),
}
_nuclei_tuning_cache: dict[str, int] | None = None
_nuclei_tuning_lock = threading.Lock()


# ── Stealth context (per-scan opt-in) ────────────────────────────
# Set by `run_enabled_scanners` when the asset has `stealth_mode=True`.
# Scanners that issue lots of HTTP probes (nuclei) or do active port
# scans (nmap) check `_is_stealth()` and switch to a slower, browser-
# impersonating profile so the scan flies under most WAF / anti-bot
# radars. Stored as a thread-local because each
# `asyncio.to_thread(run_enabled_scanners, …)` runs the whole chain on
# a single worker thread — two parallel scans get two independent
# contexts and never interfere.


def _nuclei_env_defaults() -> dict[str, int]:
    return {
        # Defaults bumped in v0.3.1 after live benchmarking: the v0.2
        # values (rate=20, c=25) were so low that a single well-populated
        # host hit the 15-min subprocess timeout with < 2 % template
        # coverage and produced zero findings. Current defaults complete
        # a typical host in 2-3 minutes at ~60 rps.
        "rate_limit":  _int_env("SURFACE_NUCLEI_RATE_LIMIT", 150, 1, 5000),
        "concurrency": _int_env("SURFACE_NUCLEI_CONCURRENCY", 50, 1, 500),
        "bulk_size":   _int_env("SURFACE_NUCLEI_BULK_SIZE", 50, 1, 500),
        "timeout":     _int_env("SURFACE_NUCLEI_TIMEOUT", 15, 1, 300),
        "retries":     _int_env("SURFACE_NUCLEI_RETRIES", 1, 0, 10),
    }


def _nuclei_tuning() -> dict[str, int]:
    """Current tuning: DB-cached if loaded, else env defaults. Sync-safe."""
    with _nuclei_tuning_lock:
        if _nuclei_tuning_cache is not None:
            return dict(_nuclei_tuning_cache)
    return _nuclei_env_defaults()


def set_nuclei_tuning_cache(overrides: dict[str, int]) -> dict[str, int]:
    """Merge + clamp overrides into the in-memory cache. Called by async
    routes after loading from / writing to AppSettings. Returns effective."""
    global _nuclei_tuning_cache
    cleaned: dict[str, int] = {}
    for k, v in (overrides or {}).items():
        if k not in _NUCLEI_TUNING_KEYS:
            continue
        try:
            iv = int(v)
        except (TypeError, ValueError):
            continue
        lo, hi = _NUCLEI_TUNING_LIMITS[k]
        cleaned[k] = max(lo, min(hi, iv))
    with _nuclei_tuning_lock:
        base = dict(_nuclei_tuning_cache) if _nuclei_tuning_cache else _nuclei_env_defaults()
        base.update(cleaned)
        _nuclei_tuning_cache = base
        return dict(base)


# ═══════════════════════════════════════════════════════════════
# Shodan integration (external reconnaissance API)
# ═══════════════════════════════════════════════════════════════
#
# Two scanners:
#   shodan_domain — passive subdomain enumeration via Shodan DNS API
#                   (/dns/domain/{domain}, 0 query credits consumed)
#   shodan_host   — active host lookup via /shodan/host/{ip}, 1 query
#                   credit per call. Returns ports, services, CPE,
#                   known CVEs, tags, last observation date.
#
# The API key is stored in AppSettings (backend-only) and cached here
# in-memory. Scanner threads read the cache via _get_shodan_api_key()
# without touching the async DB. The /api/scans/shodan/config routes
# load/save the key and update this cache atomically.
#
# Neither scanner is enabled by default — the user must explicitly add
# them to an asset's enabled_scanners list, because shodan_host costs
# query credits on their Shodan account.

_SHODAN_API_KEY: str | None = None
_shodan_lock = threading.Lock()


def _get_shodan_api_key() -> str | None:
    """Return the cached Shodan API key, or None if not configured."""
    with _shodan_lock:
        return _SHODAN_API_KEY


def set_shodan_api_key_cache(key: str | None) -> None:
    """Update the in-memory Shodan key cache. Called by routes after
    reading from or writing to AppSettings."""
    global _SHODAN_API_KEY
    with _shodan_lock:
        _SHODAN_API_KEY = (key or "").strip() or None


def shodan_key_masked(key: str | None) -> str:
    """Return a display-safe masked version of the key (last 4 chars)."""
    if not key:
        return ""
    if len(key) < 8:
        return "•" * len(key)
    return "•" * (len(key) - 4) + key[-4:]


SCANNER_REGISTRY: dict[str, dict[str, Any]] = {}


DEFAULT_SCANNERS_BY_KIND = {
    "domain": ["email_security", "typosquatting", "tls", "ct_logs", "dns_brute", "takeover"],
    # nuclei + cve_lookup are now optional (generic) add-ons; when included they
    # re-add themselves to the host defaults via their SURFACE_DEFAULT_SCANNERS.
    "host": [
        "nmap_quick", "tls", "tls_grade", "takeover",
        "sensitive_files", "security_headers", "js_analysis",
    ],
    "ip_range": ["discovery"],
}


# ── Add-on scanners ───────────────────────────────────────────
# Beyond the built-in scanners above, a deployment can drop bespoke scanners
# (e.g. an SMB file-share content scanner) into an add-on directory without
# forking this module — same model as the Access connectors. Each *.py found
# under the dirs in SURFACE_ADDON_PATHS (+ /app/addons), scanned recursively,
# may expose:
#   SURFACE_SCANNERS = { "<name>": {label, kinds, callable, returns_discovered,
#                                   [wants_config], [wants_prior_findings]} }
#   SURFACE_DEFAULT_SCANNERS = { "<kind>": ["<name>", ...] }   # optional
# Entries are merged into SCANNER_REGISTRY / DEFAULT_SCANNERS_BY_KIND. A file
# whose dependency is missing is skipped (logged), never fatal.
def _load_addon_scanners() -> None:
    import importlib.util
    import os

    paths = [p.strip() for p in os.environ.get("SURFACE_ADDON_PATHS", "").split(os.pathsep) if p.strip()]
    if "/app/addons" not in paths:
        paths.append("/app/addons")

    seen: set[str] = set()
    for base in paths:
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            for fname in sorted(files):
                if not fname.endswith(".py") or fname.startswith("_") or fname.startswith("test_") or fname == "conftest.py":
                    continue
                fpath = os.path.join(root, fname)
                if fpath in seen:
                    continue
                seen.add(fpath)
                try:
                    spec = importlib.util.spec_from_file_location(f"surface_addon_{fname[:-3]}", fpath)
                    if spec is None or spec.loader is None:
                        continue
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for name, entry in (getattr(mod, "SURFACE_SCANNERS", {}) or {}).items():
                        SCANNER_REGISTRY[name] = entry
                        logger.info("Loaded add-on scanner '%s' from %s", name, fpath)
                    for kind, names in (getattr(mod, "SURFACE_DEFAULT_SCANNERS", {}) or {}).items():
                        DEFAULT_SCANNERS_BY_KIND.setdefault(kind, [])
                        for n in names:
                            if n not in DEFAULT_SCANNERS_BY_KIND[kind]:
                                DEFAULT_SCANNERS_BY_KIND[kind].append(n)
                except Exception as e:  # noqa: BLE001 — a broken add-on must not crash boot
                    logger.warning("Skipped add-on scanner %s: %s: %s", fpath, type(e).__name__, e)


_load_addon_scanners()


def available_scanners_for_kind(kind: str) -> list[dict[str, str]]:
    """Return [{name, label}] of scanners applicable to the given kind."""
    return [
        {"name": name, "label": meta["label"]}
        for name, meta in SCANNER_REGISTRY.items()
        if kind in meta["kinds"]
    ]


def addon_help_docs() -> list[dict[str, Any]]:
    """Return [{scanner, kinds, doc}] for loaded scanners that ship in-app help.

    Only add-ons actually present in THIS image expose a `doc` (see the add-on's
    SURFACE_SCANNERS entry), so the frontend renders help strictly for what is
    installed — and an image built without an add-on never ships its doc text.
    `doc` is a bilingual map: {lang: {"methodo": html, "usage": html}}."""
    return [
        {"scanner": name, "kinds": sorted(meta.get("kinds", ())), "doc": meta["doc"]}
        for name, meta in SCANNER_REGISTRY.items()
        if meta.get("doc")
    ]


def run_enabled_scanners(kind: str, value: str, enabled: list[str], stealth: bool = False, config: dict | None = None, sink=None) -> tuple[list[dict[str, Any]], list[str]]:
    """Run only the scanners whose names are in `enabled`. Returns (findings, discovered).

    When ``stealth=True``, sets a thread-local flag that scanners
    (nuclei, nmap) check to switch to a slower, less detectable
    profile. The flag is always cleared on exit so a panicking
    scanner can't leak the state into a subsequent unrelated run on
    the same worker thread.
    """
    findings: list[dict[str, Any]] = []
    discovered: list[str] = []
    if not enabled:
        enabled = DEFAULT_SCANNERS_BY_KIND.get(kind, [])

    _STEALTH_CTX.on = bool(stealth)
    try:
        return _run_scanners_inner(kind, value, enabled, findings, discovered, config or {}, sink)
    finally:
        _STEALTH_CTX.on = False


def _run_scanners_inner(kind: str, value: str, enabled: list[str],
                        findings: list[dict[str, Any]],
                        discovered: list[str],
                        config: dict | None = None,
                        sink=None) -> tuple[list[dict[str, Any]], list[str]]:
    """Inner loop split out so `run_enabled_scanners` can wrap it in a
    try/finally that always clears the stealth context.

    `sink`, when provided, is a thread-safe `sink(batch)` that persists a batch
    of findings incrementally (see findings_dedup.make_thread_sink). A scanner
    with `wants_sink=True` receives it and streams findings to it as they are
    discovered (so a killed/long scan keeps what it found); such a scanner
    returns only the findings it did NOT sink (status/summary)."""
    for name in enabled:
        meta = SCANNER_REGISTRY.get(name)
        if not meta:
            logger.warning("Unknown scanner %s requested for %s/%s", name, kind, value)
            continue
        if kind not in meta["kinds"]:
            logger.warning("Scanner %s not applicable to kind=%s, skipping", name, kind)
            continue
        try:
            if meta.get("wants_sink"):
                # Streaming scanner: gets the per-scanner config + the sink and
                # persists incrementally. Returns only non-sunk findings.
                result = meta["callable"](value, config or {}, sink)
            elif meta.get("wants_prior_findings"):
                # Pass a snapshot of everything emitted so far on this scope
                # so the scanner can chain off it (e.g. cve_lookup reads
                # tech_fingerprint evidences).
                result = meta["callable"](value, list(findings))
            elif meta.get("wants_config"):
                # Pass the asset's per-scanner config dict (add-on scanners).
                result = meta["callable"](value, config or {})
            else:
                result = meta["callable"](value)
            if meta["returns_discovered"]:
                f, d = result
                findings.extend(f)
                discovered.extend(d)
            else:
                findings.extend(result or [])
        except Exception as e:
            logger.exception("Scanner %s crashed for %s/%s", name, kind, value)
            findings.append({
                "scanner": name, "type": "exception", "severity": "info",
                "title": f"Erreur scanner {name} pour {value}",
                "description": str(e), "target": value, "evidence": {},
            })

    return findings, discovered