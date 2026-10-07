"""Certificate Transparency monitoring — Surface core add-on.

Two passive uses of crt.sh, no API key:
  • subdomain discovery for the monitored domain (``ct_discovery``);
  • certificates issued on the lookalike domains the typosquatting scanner
    flagged in the same scan (``ct_typosquat_cert``, FEAT-55) — a fresh
    certificate on a lookalike is a strong phishing-preparation signal.

Config (per monitored asset, ``asset.config``):
  ct_typosquat_window_days (int, def 30) — a lookalike certificate raises a
      finding when its ``not_before`` falls within the last N days.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _normalize_host, _in_scope,
)

_CT_HEADERS = {"User-Agent": "CISO-Surface/1.0 (+https://cisotoolbox.org)"}

# crt.sh can return hundreds of MB for popular domains — we cap both the
# response body AND the number of rows we process to keep memory bounded on
# adversarial / popular seeds.
_CT_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap
_CT_MAX_ROWS = 20_000              # cap on certificates examined

# Lookalike certificate watch (FEAT-55).
_DEF_WINDOW_DAYS = 30
_MAX_LOOKALIKES = 30               # lookalikes queried per scan (2 requests each)
_LOOKALIKE_MAX_BYTES = 5 * 1024 * 1024
_LOOKALIKE_TIMEOUTS = (30.0,)
_MAX_LOOKALIKE_FAILURES = 3        # consecutive crt.sh outages before giving up
_LOOKALIKE_BUDGET_S = 300.0        # wall-clock cap on the whole lookalike watch


def _fetch_crt_sh(query: str, timeouts: tuple[float, ...],
                  max_bytes: int) -> tuple[Any, Exception | None]:
    """GET crt.sh for ``query`` (already URL-encoded) → ``(data, error)``.

    ``data`` is the decoded JSON, or None on failure; each timeout in
    ``timeouts`` is one attempt. The error is an ``httpx.HTTPError`` when
    crt.sh could not be reached or answered with an HTTP error, a
    ``ValueError`` when the answer was refused here (too large, not JSON).
    crt.sh is a fixed external host and the query is only a parameter, so
    there is no SSRF surface here."""
    import httpx

    url = f"https://crt.sh/?q={query}&output=json"
    last_error: Exception | None = None
    for attempt, timeout in enumerate(timeouts, start=1):
        try:
            with httpx.stream("GET", url, timeout=timeout, headers=_CT_HEADERS, follow_redirects=True) as resp:
                resp.raise_for_status()
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    if len(buf) + len(chunk) > max_bytes:
                        err = ValueError(f"crt.sh response exceeded {max_bytes} bytes")
                        logger.info("ct_logs: response for %s too large, aborting parse", query)
                        return None, err
                    buf.extend(chunk)
                if not buf.strip():
                    return [], None
                try:
                    return json.loads(buf), None
                except ValueError as e:
                    logger.info("ct_logs: crt.sh JSON parse error for %s: %s", query, e)
                    return None, e
        except httpx.HTTPError as e:
            last_error = e
            logger.info("ct_logs: crt.sh attempt %d/%d failed for %s (timeout=%.0fs): %s",
                        attempt, len(timeouts), query, timeout, e)
    return None, last_error


# ═══════════════════════════════════════════════════════════════
# Certificate Transparency (crt.sh) — passive subdomain discovery
# ═══════════════════════════════════════════════════════════════

def scan_domain_ct_logs(domain: str, prior_findings: list[dict[str, Any]] | None = None,
                        config: dict | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """Discover sub-domains of `domain` via Certificate Transparency logs.

    Queries https://crt.sh/?q=%25.<domain>&output=json — fully passive,
    no API key. Each entry in crt.sh may contain multiple DNS names
    separated by newlines (the SAN list of the cert). Wildcards and out-
    of-scope entries are filtered out; the remaining hostnames are
    returned as `discovered` so the scheduler auto-enrolls them.

    Then watches the certificates of the lookalikes flagged by typosquatting
    earlier in this scan (``prior_findings``) — see ``_lookalike_cert_findings``.
    """
    domain = _safe_target(domain).lower()
    findings: list[dict[str, Any]] = []
    discovered: set[str] = set()

    data, last_error = _fetch_crt_sh(f"%25.{domain}", (30.0, 60.0, 90.0), _CT_MAX_BYTES)

    if data is None:
        findings.append({
            "scanner": "ct_logs", "type": "ct_error", "severity": "info",
            "title": f"CT logs: crt.sh unreachable for {domain}",
            "description": (
                f"The crt.sh request failed after 3 attempts: {last_error}. "
                f"crt.sh is known to be slow or occasionally unavailable — "
                f"retry later via a new run of the scanner."
            ),
            "target": domain, "evidence": {"error": str(last_error)},
        })
    elif not isinstance(data, list):
        data = None

    # Lookalike certificates first, independent of the discovery outcome: a
    # crt.sh failure on the (often huge) domain query must not hide them.
    findings.extend(_lookalike_cert_findings(domain, prior_findings or [], config or {}))
    if data is None:
        return findings, []

    for row in data[:_CT_MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        name_value = row.get("name_value") or ""
        for raw in str(name_value).split("\n"):
            h = _normalize_host(raw)
            if h and _in_scope(h, domain):
                discovered.add(h)

    discovered.discard(domain)
    hosts = sorted(discovered)

    findings.append({
        "scanner": "ct_logs", "type": "ct_discovery", "severity": "info",
        "title": f"CT logs: {len(hosts)} subdomain(s) discovered for {domain}",
        "description": (
            f"The Certificate Transparency logs scan (crt.sh) identified "
            f"{len(hosts)} hostnames associated with the domain {domain}. "
            f"These hostnames are automatically added to the list of monitored "
            f"assets (kind=host) and will be scanned at the default frequency."
        ),
        "target": domain,
        "evidence": {
            "source": "crt.sh",
            "query": f"%.{domain}",
            "count": len(hosts),
            "hosts_sample": hosts[:50],
        },
    })
    return findings, hosts


# ═══════════════════════════════════════════════════════════════
# Certificates issued on typosquatting lookalikes (FEAT-55)
# ═══════════════════════════════════════════════════════════════

def _flagged_lookalikes(domain: str, prior_findings: list[dict[str, Any]]) -> list[str]:
    """Lookalikes the typosquatting scanner flagged for ``domain`` in this scan."""
    out: list[str] = []
    for f in prior_findings:
        if f.get("scanner") != "typosquatting" or f.get("type") != "typosquat_domain":
            continue
        ev = f.get("evidence") or {}
        if (ev.get("original") or domain).lower() != domain:
            continue
        h = _normalize_host(str(ev.get("lookalike") or f.get("target") or ""))
        if h and h != domain and h not in out:
            out.append(h)
    return out


def _parse_ts(raw: Any) -> datetime | None:
    """crt.sh timestamps are naive UTC ISO strings (``2026-10-01T12:00:00``)."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _window_days(config: dict) -> int:
    try:
        n = int(config.get("ct_typosquat_window_days", _DEF_WINDOW_DAYS))
    except (TypeError, ValueError):
        n = _DEF_WINDOW_DAYS
    return max(1, min(n, 365))


def _names_in_scope(name_value: str, lookalike: str) -> list[str]:
    """SAN entries of a crt.sh row naming ``lookalike`` or a subdomain of it.

    Unlike discovery, wildcards are kept (``*.lookalike``): a wildcard
    certificate on a lookalike is just as much a phishing signal."""
    out: set[str] = set()
    for raw in name_value.split("\n"):
        raw = raw.strip().lower()
        wildcard = raw.startswith("*.")
        h = _normalize_host(raw[2:] if wildcard else raw)
        if h and _in_scope(h, lookalike):
            out.add("*." + h if wildcard else h)
    return sorted(out)


def _lookalike_certs(lookalike: str) -> tuple[dict[str, dict[str, Any]], Exception | None]:
    """Certificates naming ``lookalike`` or one of its subdomains, by serial.

    Two queries: crt.sh's exact identity match misses subdomain-only
    certificates, and the exact query keeps apex-only ones covered should
    ``%.x`` not return them. A precertificate and its final certificate share
    a serial number, so keying by serial yields one entry per issued
    certificate.

    The error is returned only when neither query was answered, preferring a
    network/HTTP error (an outage) over a refused answer."""
    import httpx

    certs: dict[str, dict[str, Any]] = {}
    answered = False
    error: Exception | None = None
    for q in (quote(lookalike, safe=""), "%25." + quote(lookalike, safe="")):
        data, err = _fetch_crt_sh(q, _LOOKALIKE_TIMEOUTS, _LOOKALIKE_MAX_BYTES)
        time.sleep(0.3)  # throttle crt.sh
        if data is None:
            if error is None or isinstance(err, httpx.HTTPError):
                error = err
            continue
        answered = True
        if not isinstance(data, list):
            continue
        for row in data[:_CT_MAX_ROWS]:
            if not isinstance(row, dict):
                continue
            names = _names_in_scope(str(row.get("name_value") or ""), lookalike)
            if not names:
                continue
            serial = str(row.get("serial_number") or "").lower() or f"id-{row.get('id')}"
            cur = certs.get(serial)
            if cur is None:
                certs[serial] = dict(row, _names=names)
            else:
                cur["_names"] = sorted(set(cur["_names"]) | set(names))
    return certs, (None if answered else error)


def _lookalike_cert_findings(domain: str, prior_findings: list[dict[str, Any]],
                             config: dict) -> list[dict[str, Any]]:
    """One ``ct_typosquat_cert`` finding per certificate issued on a flagged
    lookalike within the window.

    ``target`` = ``<lookalike>#<serial>``: the dedup key is per certificate, so
    each new certificate is inserted — and alerted — once; the same
    certificate seen again on the next scan only refreshes its finding. The
    lookalikes are never returned as ``discovered``: they are not the
    organisation's surface and must not be auto-enrolled."""
    import httpx

    lookalikes = _flagged_lookalikes(domain, prior_findings)
    if not lookalikes:
        return []
    days = _window_days(config)
    since = datetime.now(timezone.utc) - timedelta(days=days)
    findings: list[dict[str, Any]] = []
    failures = 0
    deadline = time.monotonic() + _LOOKALIKE_BUDGET_S
    for lookalike in lookalikes[:_MAX_LOOKALIKES]:
        if time.monotonic() > deadline:
            logger.info("ct_logs: lookalike watch budget spent for %s, stopped at %s", domain, lookalike)
            break
        certs, error = _lookalike_certs(lookalike)
        if error is not None and not certs:
            logger.info("ct_logs: crt.sh failed for lookalike %s: %s", lookalike, error)
            # Only an outage (network or HTTP error) counts towards giving up:
            # one oversized lookalike (a popular real domain) must not stop
            # the watch of the others.
            if isinstance(error, httpx.HTTPError):
                failures += 1
                if failures >= _MAX_LOOKALIKE_FAILURES:
                    logger.info("ct_logs: crt.sh failing, lookalike watch stopped for %s", domain)
                    break
            continue
        failures = 0
        for serial, row in sorted(certs.items()):
            nb = _parse_ts(row.get("not_before"))
            if nb is None or nb < since:
                continue
            na = _parse_ts(row.get("not_after"))
            issuer = str(row.get("issuer_name") or "") or "unknown"
            findings.append({
                "scanner": "ct_logs", "type": "ct_typosquat_cert", "severity": "high",
                "title": f"Certificate issued on lookalike domain {lookalike}",
                "description": (
                    f"A certificate was issued on {nb.date().isoformat()} for {', '.join(row['_names'])}, "
                    f"a lookalike of {domain} flagged by the typosquatting scanner "
                    f"(issuer: {issuer}).\n"
                    f"Risk: a valid certificate is usually the last step before a "
                    f"phishing site or a brand-impersonation campaign goes live."
                ),
                "target": f"{lookalike}#{serial}",
                "evidence": {
                    # hostname: the host widgets (app, Pilot, report) group on
                    # it — the per-certificate target would make one pseudo
                    # host per certificate.
                    "original": domain, "lookalike": lookalike, "hostname": lookalike,
                    "serial": serial,
                    "crtsh_id": row.get("id"), "issuer": issuer,
                    "common_name": row.get("common_name") or "",
                    "names": row["_names"],
                    "issued_on": nb.date().isoformat(),
                    "not_before": nb.isoformat(), "not_after": na.isoformat() if na else "",
                    "window_days": days, "source": "crt.sh",
                },
            })
    if len(lookalikes) > _MAX_LOOKALIKES:
        logger.info("ct_logs: %d lookalikes for %s, only the first %d checked",
                    len(lookalikes), domain, _MAX_LOOKALIKES)
    return findings


SURFACE_SCANNERS = {"ct_logs": {"label": "Subdomain discovery (CT logs)",
    "kinds": {"domain"}, "callable": scan_domain_ct_logs, "returns_discovered": True,
    "wants_prior_findings": True, "wants_config": True,
    "runs_after": ["typosquatting"]}}
