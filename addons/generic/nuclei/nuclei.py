"""Nuclei DAST scanner + severity overrides — Surface generic add-on.

The nuclei binary + templates are NOT in the lean base image; they are installed
by this add-on's install.sh during the client-image overlay (into
/usr/local/bin/nuclei and /opt/nuclei-templates). Point nuclei at that templates
dir here (the base no longer sets the env), and the scanner degrades gracefully
to a "binary not found" finding when the add-on isn't installed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any

os.environ.setdefault("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _STEALTH_BROWSER_UA, _is_stealth,
)
from src.scanners import _nuclei_tuning


# ═══════════════════════════════════════════════════════════════
# Nuclei (DAST templates)
# ═══════════════════════════════════════════════════════════════

NUCLEI_SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}

# Many nuclei community templates classify security-relevant findings
# as "info" because they are *detections*, not active exploits. But
# from a CISO's perspective, running an EOL Exchange or exposing NTLM
# directories IS a real risk that deserves triage. This map upgrades
# specific template IDs to a minimum severity — the original nuclei
# severity is kept if it is already higher.
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_NUCLEI_SEVERITY_OVERRIDES: dict[str, str] = {
    # End-of-life / unsupported software — real patch-gap risk
    "msexchange-eol":               "high",
    "iis-eol":                      "high",
    "apache-eol":                   "high",
    "nginx-eol":                    "high",
    "php-eol":                      "high",
    "wordpress-eol":                "high",
    "drupal-eol":                   "high",
    "tomcat-eol":                   "high",
    "openssh-eol":                  "high",
    "debian-eol":                   "high",
    "ubuntu-eol":                   "high",
    "centos-eol":                   "high",
    "windows-eol":                  "high",
    # Information leakage exploitable for lateral movement
    "ntlm-directories":             "medium",
    "ms-exchange-local-domain":     "medium",
    "ms-exchange-server":           "low",
    "ms-exchange-web-service":      "low",
    # File / path enumeration
    "iis-shortname-detect":         "medium",
    "directory-listing":            "medium",
    # Admin panels exposed to the Internet
    "microsoft-exchange-panel":     "medium",
    "phpmyadmin-panel":             "high",
    "adminer-panel":                "high",
    "grafana-panel":                "low",
    "kibana-panel":                 "low",
    "jenkins-panel":                "medium",
    "gitlab-panel":                 "low",
    "portainer-panel":              "medium",
    "traefik-panel":                "low",
    "rancher-panel":                "medium",
    # Misconfigured or dangerous features
    "graphql-alias-batching":       "low",
    "graphql-directive-overloading":"low",
    "cors-misconfig":               "medium",
    "open-redirect":                "medium",
    "google-floc-disabled":         "info",  # keep info, not actionable
}


def _apply_severity_override(template_id: str, nuclei_sev: str) -> str:
    """Return the effective severity, upgrading if Surface's override
    map assigns a higher floor than the template's native severity."""
    override = _NUCLEI_SEVERITY_OVERRIDES.get(template_id)
    if not override:
        return nuclei_sev
    if _SEV_RANK.get(override, 0) > _SEV_RANK.get(nuclei_sev, 0):
        return override
    return nuclei_sev




# ── Nuclei tuning: env vars are defaults, DB overrides cached here ─────
# scan_nuclei() runs in a thread via asyncio.to_thread and cannot hit the
# async DB. HTTP routes populate this process-wide cache from AppSettings
# on startup and on every save, so UI edits take effect immediately.

# ═══════════════════════════════════════════════════════════════
# Nuclei (DAST templates)
# ═══════════════════════════════════════════════════════════════


def scan_nuclei(target: str, severity_filter: str = "info,low,medium,high,critical") -> list[dict[str, Any]]:
    """Run nuclei against the target with default templates.

    Tries https:// then http:// if the target has no scheme. Streams JSONL output
    so we can parse incrementally even on big runs.
    """
    target = _safe_target(target)
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return [{
            "scanner": "nuclei", "type": "error", "severity": "info",
            "title": "nuclei binary not found",
            "description": "The nuclei binary could not be found.",
            "target": target, "evidence": {},
        }]

    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    tuning = _nuclei_tuning()
    stealth = _is_stealth()
    if stealth:
        # Stealth profile: a typical WAF / anti-bot fingerprints scanners
        # on rate + UA + bulk timing. Drop hard on rate/concurrency,
        # impersonate a real Chrome, space probes by 1s. Scans go from
        # ~3 min to ~30 min but the SOC-side detection rate plummets.
        tuning = dict(tuning)
        tuning["rate_limit"] = min(tuning.get("rate_limit", 150), 3)
        tuning["concurrency"] = min(tuning.get("concurrency", 50), 2)
        tuning["bulk_size"] = min(tuning.get("bulk_size", 50), 5)
        tuning["timeout"] = max(tuning.get("timeout", 15), 20)

    # v0.3.1 — run in automatic-scan mode (`-as`). Nuclei first runs
    # wappalyzer-style tech detection on the target and then executes
    # only the templates that match the detected stack. On a typical
    # host this drops ~25 500 planned requests to ~1 500, and the
    # remaining templates are actually *relevant* to the technologies
    # behind the URL — so scans complete 10-15x faster AND yield more
    # meaningful findings than the brute-force mode we used in v0.2/v0.3.
    args = [
        nuclei_path, "-target", url, "-jsonl", "-silent",
        "-as",
        "-stats", "-stats-interval", "30",  # emit progress on stderr so we can
                                            # detect WAF-blocked scans afterwards
        "-severity", severity_filter,
        "-rate-limit", str(tuning["rate_limit"]),
        "-concurrency", str(tuning["concurrency"]),
        "-bulk-size", str(tuning["bulk_size"]),
        "-timeout", str(tuning["timeout"]),
        "-retries", str(tuning["retries"]),
        "-disable-update-check",
        "-no-color",
    ]
    if stealth:
        # Browser UA + 1-s delay between probes round out the stealth
        # profile. nuclei `-H "Header: Value"` adds a custom header
        # globally; nuclei `-delay 1` introduces a per-request jitter.
        args += ["-H", f"User-Agent: {_STEALTH_BROWSER_UA}", "-delay", "1"]
    logger.info("nuclei: rate=%d c=%d bulk=%d timeout=%ds retries=%d stealth=%s for %s",
                tuning["rate_limit"], tuning["concurrency"], tuning["bulk_size"],
                tuning["timeout"], tuning["retries"], stealth, url)
    # Stealth scans run 5-10x slower than default, so the 15-min hard
    # cap is unreachable in practice — give them 60 min before pulling
    # the plug. Normal scans keep the 15-min default.
    subprocess_timeout = 3600 if stealth else 900
    try:
        proc = subprocess.run(args, capture_output=True, timeout=subprocess_timeout)
    except subprocess.TimeoutExpired:
        # Operational signal, not a vulnerability — info severity so the
        # dashboard doesn't treat a slow target as a high-severity alert.
        cap_min = subprocess_timeout // 60
        return [{
            "scanner": "nuclei", "type": "scanner_timeout", "severity": "info",
            "title": f"Nuclei timeout on {url}",
            "description": f"The nuclei scan exceeded {cap_min} minutes.",
            "target": target, "evidence": {"stealth": stealth, "cap_seconds": subprocess_timeout},
        }]
    except Exception as e:
        return [{
            "scanner": "nuclei", "type": "scanner_error", "severity": "info",
            "title": f"Nuclei failed on {url}",
            "description": str(e), "target": target, "evidence": {},
        }]

    findings: list[dict[str, Any]] = []
    for line in proc.stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {}) or {}
        template_id = r.get("template-id") or ""
        raw_sev = NUCLEI_SEVERITY_MAP.get((info.get("severity") or "info").lower(), "info")
        sev = _apply_severity_override(template_id, raw_sev)
        name = info.get("name") or template_id or "Nuclei finding"
        matched = r.get("matched-at") or r.get("host") or url
        tags = info.get("tags") or []
        # Normalize target to "host" or "host:port" so it matches the
        # format used by every other scanner. Nuclei stores the full
        # matched URL (https://host/path) which breaks per-host lookup
        # in the frontend and reports. Keep the full URL in evidence.
        norm_target = target
        try:
            from urllib.parse import urlparse as _up
            _pu = _up(matched)
            _h = _pu.hostname or target
            _p = _pu.port
            norm_target = f"{_h}:{_p}" if _p and _p not in (80, 443) else _h
        except Exception:
            pass
        findings.append({
            "scanner": "nuclei",
            "type": (info.get("classification", {}) or {}).get("cve-id") or r.get("template-id") or "nuclei",
            "severity": sev,
            "title": f"{name} on {matched}",
            "description": (info.get("description") or "").strip()[:1000] +
                           (f"\n\nTemplate: {r.get('template-id')}" if r.get("template-id") else ""),
            "target": norm_target,
            "evidence": {
                "template_id": r.get("template-id"),
                "matched_at": matched,
                "tags": tags if isinstance(tags, list) else [],
                "reference": info.get("reference") or [],
                "matcher_name": r.get("matcher-name"),
                "extracted": r.get("extracted-results"),
            },
        })

    # WAF / anti-bot detection: when a target massively rejects nuclei's
    # probes, the scan looks "clean" (zero findings) while in reality we
    # never reached most templates. Operators were puzzled by exactly
    # that on WP sites behind aggressive CDNs (e.g. RocketCDN). Parse
    # nuclei's `-stats` output (last line on stderr) for the cumulative
    # requests/errors counts and emit a `scanner_blocked` info finding
    # when the ratio is high enough to invalidate the "no findings = safe"
    # conclusion. Threshold is conservative (>=50% errors AND >=50 requests
    # — small scans naturally have noisy ratios on transient hiccups).
    try:
        last_stats = ""
        for line in proc.stderr.decode(errors="replace").splitlines():
            if "Errors:" in line and "Requests:" in line:
                last_stats = line
        if last_stats:
            err_match = re.search(r"Errors:\s*(\d+)", last_stats)
            req_match = re.search(r"Requests:\s*(\d+)", last_stats)
            errors = int(err_match.group(1)) if err_match else 0
            requests = int(req_match.group(1)) if req_match else 0
            if requests >= 50 and errors / max(requests, 1) >= 0.5:
                pct = round(100 * errors / requests)
                findings.append({
                    "scanner": "nuclei", "type": "scanner_blocked", "severity": "info",
                    "title": f"Nuclei scan blocked on {url} ({pct}% error rate)",
                    "description": (
                        f"Nuclei issued {requests} requests against {url} and "
                        f"{errors} were rejected ({pct}%). The target likely sits "
                        "behind a WAF / anti-bot that drops automated probes. "
                        "Findings below are partial — the absence of "
                        "vulnerabilities does NOT mean the host is clean. "
                        "Consider a manual review or a stealth scan from a "
                        "different egress IP."
                    ),
                    "target": target,
                    "evidence": {
                        "errors": errors,
                        "requests": requests,
                        "error_rate_pct": pct,
                    },
                })
    except Exception:
        # Never let stats parsing break a successful scan — at worst we
        # miss the diagnostic finding on this run.
        logger.exception("nuclei: stats parsing failed for %s", target)

    # No "scan_clean" info finding — a scan that finds nothing (and that
    # wasn't blocked) is expected behavior, not something to persist and
    # triage. The ScanJob record (findings_count=0) already conveys it.
    return findings


SURFACE_SCANNERS = {"nuclei": {"label": "Nuclei (templates DAST)",
    "kinds": {"host"}, "callable": scan_nuclei, "returns_discovered": False}}
# Optional (generic) add-on, but default-on for host scans when included.
SURFACE_DEFAULT_SCANNERS = {"host": ["nuclei"]}
