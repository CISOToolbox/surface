"""Surface trigger endpoints — quick port + TLS scan, bulk import.

Quick scan runs synchronously and produces findings. For heavier ASM workloads
(Shodan, recursive subdomain enum, Nuclei templates) use external runners and
push results via /api/findings/bulk.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import get_current_user
from src.database import get_db
from src.findings_dedup import insert_many
from src.models import Finding, User
from src.rate_limit import check_scan_quota

router = APIRouter(prefix="/api/scans", tags=["scans"])


# ── Quick scan: TCP ports + TLS ────────────────────────────────

# Common ports to probe. Kept small to stay fast (< 10s) and avoid being mistaken
# for a real port scan. For exhaustive scans, run nmap externally and bulk-import.
COMMON_PORTS = [
    (21, "ftp", "high"),
    (22, "ssh", "info"),
    (23, "telnet", "critical"),
    (25, "smtp", "low"),
    (53, "dns", "info"),
    (80, "http", "info"),
    (110, "pop3", "low"),
    (135, "rpc", "high"),
    (139, "netbios", "high"),
    (143, "imap", "low"),
    (443, "https", "info"),
    (445, "smb", "high"),
    (1433, "mssql", "high"),
    (1521, "oracle", "high"),
    (3306, "mysql", "high"),
    (3389, "rdp", "critical"),
    (5432, "postgresql", "high"),
    (5900, "vnc", "high"),
    (6379, "redis", "high"),
    (8080, "http-alt", "info"),
    (8443, "https-alt", "info"),
    (9200, "elasticsearch", "high"),
    (27017, "mongodb", "high"),
]


class QuickScanRequest(BaseModel):
    target_host: str = Field(..., min_length=1)


def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def _check_tls(host: str, port: int = 443, connect_ip: str | None = None) -> dict[str, Any] | None:
    """Return certificate info or None if connection failed.
    When `connect_ip` is provided, TCP goes to that IP but the TLS SNI and
    hostname verification still use `host` — this pins the target to the
    IP resolved at validation time (anti DNS-rebinding)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((connect_ip or host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None


def _check_tls_no_verify(host: str, port: int = 443, connect_ip: str | None = None) -> dict[str, Any] | None:
    """Same but disable cert verification — used to detect expired/invalid certs."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_ip or host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                # Parse minimal info from binary cert
                import datetime as _dt
                # Use ssl helper — load PEM-decoded OpenSSL cert
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert_obj = x509.load_der_x509_certificate(der, default_backend())
                return {
                    "subject": cert_obj.subject.rfc4514_string(),
                    "issuer": cert_obj.issuer.rfc4514_string(),
                    "not_before": cert_obj.not_valid_before_utc.isoformat() if hasattr(cert_obj, "not_valid_before_utc") else cert_obj.not_valid_before.isoformat(),
                    "not_after": cert_obj.not_valid_after_utc.isoformat() if hasattr(cert_obj, "not_valid_after_utc") else cert_obj.not_valid_after.isoformat(),
                    "serial": format(cert_obj.serial_number, "x"),
                }
    except Exception:
        return None


def _quick_scan_sync(host: str) -> list[dict[str, Any]]:
    """Probe common TCP ports and inspect the TLS certificate if 443 is open."""
    from src.scanners import _resolve_safe_target
    # Strip scheme if present
    if "://" in host:
        from urllib.parse import urlparse
        host = urlparse(host).hostname or host
    if not host:
        raise ValueError("Invalid host")
    # SSRF validation: allow public + private LAN, block loopback/link-local/docker siblings.
    # Use the locked IP for all downstream connections to prevent DNS rebinding.
    locked_ip, host = _resolve_safe_target(host)
    connect_ip = locked_ip or host  # None only for CIDR (not reached here) / unresolvable

    findings: list[dict[str, Any]] = []
    open_ports = []
    for port, service, sev in COMMON_PORTS:
        if _check_port(connect_ip, port):
            open_ports.append((port, service, sev))
            if sev != "info":
                findings.append({
                    "scanner": "port_scan",
                    "type": "open_port",
                    "severity": sev,
                    "title": f"Port {port}/{service} ouvert sur {host}",
                    "description": f"Le service {service} est joignable sur {host}:{port}. " +
                                   ("Ce protocole est obsolete ou tres expose, a fermer immediatement." if sev == "critical" else
                                    "Verifier que ce service est intentionnellement expose et durci." if sev == "high" else
                                    "Service standard expose, verifier la configuration."),
                    "target": f"{host}:{port}",
                    "evidence": {"host": host, "port": port, "service": service},
                })

    # Always emit a summary finding so the user knows the scan ran, with the
    # full list of open ports (even info ones) in evidence.
    summary_sev = "info"
    if not open_ports:
        summary_msg = "Aucun port commun ouvert. L'host est peut-etre derriere un firewall, en down, ou repond uniquement sur des ports non standards."
    else:
        port_list = ", ".join(f"{p}/{s}" for p, s, _ in open_ports)
        summary_msg = f"{len(open_ports)} port(s) ouvert(s) detecte(s) : {port_list}."
    findings.append({
        "scanner": "port_scan",
        "type": "scan_summary",
        "severity": summary_sev,
        "title": f"Resume du scan sur {host}",
        "description": summary_msg,
        "target": host,
        "evidence": {"host": host, "ports_tested": len(COMMON_PORTS), "open_ports": [{"port": p, "service": s, "severity": sev} for p, s, sev in open_ports]},
    })

    # TLS check on 443 if open — connect to locked IP but present the original
    # hostname as SNI so the cert can be validated against it.
    if any(p == 443 for p, _, _ in open_ports):
        cert = _check_tls(host, 443, connect_ip=connect_ip)
        if cert is None:
            # Connection failed with verification — try without
            try:
                cert_raw = _check_tls_no_verify(host, 443, connect_ip=connect_ip)
                if cert_raw:
                    findings.append({
                        "scanner": "tls",
                        "type": "tls_invalid",
                        "severity": "high",
                        "title": f"Certificat TLS invalide sur {host}:443",
                        "description": "Le certificat TLS ne valide pas (expire, nom invalide, autorite inconnue ou auto-signe). Voir l'evidence pour les details du certificat.",
                        "target": f"{host}:443",
                        "evidence": cert_raw,
                    })
                else:
                    findings.append({
                        "scanner": "tls",
                        "type": "tls_unreachable",
                        "severity": "medium",
                        "title": f"Handshake TLS impossible sur {host}:443",
                        "description": "Le port 443 est ouvert mais le handshake TLS echoue. Configuration TLS cassee ?",
                        "target": f"{host}:443",
                        "evidence": {"host": host, "port": 443},
                    })
            except Exception:
                pass
        else:
            # Cert valid — check expiry
            from datetime import datetime as _dt, timezone as _tz
            try:
                expiry = _dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
                days_left = (expiry - _dt.now(tz=_tz.utc)).days
                if days_left < 0:
                    sev = "critical"
                elif days_left < 7:
                    sev = "high"
                elif days_left < 30:
                    sev = "medium"
                else:
                    sev = None
                if sev:
                    findings.append({
                        "scanner": "tls",
                        "type": "tls_expiring",
                        "severity": sev,
                        "title": f"Certificat TLS de {host} expire dans {days_left} jour(s)",
                        "description": f"Le certificat de {host} expire le {cert['notAfter']}. Renouveler avant cette date.",
                        "target": f"{host}:443",
                        "evidence": {"notAfter": cert["notAfter"], "subject": cert.get("subject"), "issuer": cert.get("issuer")},
                    })
            except (KeyError, ValueError):
                pass

    return findings


@router.post("/quick")
async def quick_scan(
    body: QuickScanRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """TCP port scan + TLS cert check on the target host. Synchronous, ~10s."""
    check_scan_quota(str(user.id) if user else "anonymous")
    try:
        finding_dicts = await asyncio.to_thread(_quick_scan_sync, body.target_host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan failed: {e}")

    counts = await insert_many(db, finding_dicts)
    await db.commit()
    return {"target": body.target_host, "findings_created": counts.get("inserted", 0) + counts.get("reopened", 0), "dedup": counts}


# ── Bulk import (for nmap, shodan, etc.) ───────────────────────

class BulkFinding(BaseModel):
    scanner: str = "manual"
    type: str = "other"
    severity: str = "medium"
    title: str
    description: str = ""
    target: str = ""
    evidence: dict[str, Any] = {}


class BulkImportRequest(BaseModel):
    findings: list[BulkFinding] = Field(..., max_length=500)


@router.post("/bulk-import")
async def bulk_import(
    body: BulkImportRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    check_scan_quota(str(user.id) if user else "anonymous")
    valid_severities = {"info", "low", "medium", "high", "critical"}
    finding_dicts = []
    skipped = 0
    for raw in body.findings:
        if raw.severity not in valid_severities or not (raw.title or "").strip():
            skipped += 1
            continue
        finding_dicts.append({
            "scanner": raw.scanner, "type": raw.type, "severity": raw.severity,
            "title": raw.title, "description": raw.description, "target": raw.target,
            "evidence": raw.evidence or {},
        })
    counts = await insert_many(db, finding_dicts)
    await db.commit()
    return {"inserted": counts.get("inserted", 0) + counts.get("reopened", 0), "skipped": skipped, "dedup": counts}


# ═══════════════════════════════════════════════════════════════
# Nuclei — tuning config + manual templates update
# ═══════════════════════════════════════════════════════════════

async def _load_nuclei_tuning_from_db(db: AsyncSession) -> None:
    """Pull nuclei.* keys from AppSettings and push them to the scanner cache."""
    from sqlalchemy import select
    from src.models import AppSettings
    from src.scanners import _NUCLEI_TUNING_KEYS, set_nuclei_tuning_cache

    result = await db.execute(
        select(AppSettings).where(AppSettings.key.like("nuclei.%"))
    )
    overrides: dict[str, int] = {}
    for row in result.scalars():
        short_key = row.key[len("nuclei."):]
        if short_key in _NUCLEI_TUNING_KEYS:
            try:
                overrides[short_key] = int(row.value)
            except (TypeError, ValueError):
                pass
    set_nuclei_tuning_cache(overrides)


import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Cache the nuclei templates inventory — os.walk over 13k .yaml files takes
# hundreds of ms on slow filesystems. Entries are invalidated after 120s or
# explicitly after `nuclei -ut` completes.
_NUCLEI_ENV_CACHE: dict[str, "Any"] = {}
_NUCLEI_ENV_CACHE_AT: float = 0.0
_NUCLEI_ENV_CACHE_TTL = 120.0


def _nuclei_environment_info(force: bool = False) -> dict[str, Any]:
    """Return nuclei version + templates count.
    Cached for 120s to avoid a full os.walk on every GET /nuclei/config call.
    `force=True` bypasses the cache (called after a templates update)."""
    import os
    import re
    import shutil
    import subprocess
    import time

    global _NUCLEI_ENV_CACHE, _NUCLEI_ENV_CACHE_AT
    now = time.monotonic()
    if not force and _NUCLEI_ENV_CACHE and (now - _NUCLEI_ENV_CACHE_AT) < _NUCLEI_ENV_CACHE_TTL:
        return dict(_NUCLEI_ENV_CACHE)

    info: dict[str, Any] = {"installed": False, "templates_count": 0, "version": ""}
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return info

    info["installed"] = True
    try:
        out = subprocess.run([nuclei_path, "-version", "-no-color"], capture_output=True, timeout=5)
        raw = (out.stderr.decode(errors="replace") or out.stdout.decode(errors="replace"))
        # Strip ANSI color codes and extract the version number from the
        # first line that matches "vX.Y.Z" (ignore banner / paths / cache dirs).
        cleaned = _ANSI_RE.sub("", raw)
        m = re.search(r"v\d+\.\d+\.\d+", cleaned)
        info["version"] = m.group(0) if m else cleaned.splitlines()[0].strip()
    except Exception:
        pass

    templates_dir = os.path.expanduser("~/nuclei-templates")
    if os.path.isdir(templates_dir):
        count = 0
        for root, _, files in os.walk(templates_dir):
            count += sum(1 for f in files if f.endswith(".yaml"))
        info["templates_count"] = count
        # Do NOT leak the absolute filesystem path to the client — it
        # reveals the container layout (and confirms process runs as root).
        try:
            mtime = os.path.getmtime(templates_dir)
            info["last_update"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        except OSError:
            pass

    _NUCLEI_ENV_CACHE = info
    _NUCLEI_ENV_CACHE_AT = now
    return info


class NucleiTuningPatch(BaseModel):
    rate_limit:  int | None = Field(default=None, ge=1, le=5000)
    concurrency: int | None = Field(default=None, ge=1, le=500)
    bulk_size:   int | None = Field(default=None, ge=1, le=500)
    timeout:     int | None = Field(default=None, ge=1, le=300)
    retries:     int | None = Field(default=None, ge=0, le=10)


@router.get("/nuclei/config")
async def nuclei_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return current tuning (DB-cached or env defaults) + templates info."""
    from src.scanners import _nuclei_tuning, _NUCLEI_TUNING_LIMITS, _nuclei_env_defaults
    await _load_nuclei_tuning_from_db(db)
    # _nuclei_environment_info does subprocess.run + os.walk over thousands
    # of template files — offload to a thread so we don't block the event loop.
    info = await asyncio.to_thread(_nuclei_environment_info)
    info["tuning"] = _nuclei_tuning()
    info["tuning_defaults"] = _nuclei_env_defaults()
    info["tuning_limits"] = {k: {"min": lo, "max": hi} for k, (lo, hi) in _NUCLEI_TUNING_LIMITS.items()}
    return info


@router.put("/nuclei/config")
async def nuclei_config_update(
    body: NucleiTuningPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Persist nuclei tuning to AppSettings and refresh the in-memory cache."""
    from sqlalchemy import select
    from src.models import AppSettings
    from src.scanners import _NUCLEI_TUNING_KEYS, set_nuclei_tuning_cache

    payload = body.model_dump(exclude_none=True)
    if not payload:
        raise HTTPException(status_code=400, detail="At least one tuning field is required")

    for k, v in payload.items():
        db_key = f"nuclei.{k}"
        existing = (await db.execute(select(AppSettings).where(AppSettings.key == db_key))).scalar_one_or_none()
        if existing is None:
            db.add(AppSettings(key=db_key, value=str(v)))
        else:
            existing.value = str(v)
    await db.commit()

    effective = set_nuclei_tuning_cache(payload)
    return {"tuning": effective, "persisted": payload}


@router.post("/nuclei/update-templates")
async def nuclei_update_templates(user: User = Depends(get_current_user)):
    """Trigger `nuclei -ut` to refresh the community templates.

    Blocks for up to 3 minutes. Returns stdout/stderr and the new template
    count. This is a privileged operation (rate-limited via scan quota) —
    the call is CPU/IO heavy and should not be spammed.
    """
    import shutil
    import subprocess

    check_scan_quota(str(user.id) if user else "anonymous")

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        raise HTTPException(status_code=500, detail="nuclei binary not found in PATH")

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            [nuclei_path, "-ut", "-disable-update-check", "-no-color"],
            capture_output=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="nuclei -ut timeout (>180s)")

    stdout = proc.stdout.decode(errors="replace")[-2000:]
    stderr = proc.stderr.decode(errors="replace")[-2000:]

    # Force-refresh the inventory cache since we just mutated the filesystem.
    info = await asyncio.to_thread(_nuclei_environment_info, True)

    return {
        "rc": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "templates_count": info.get("templates_count", 0),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════
# Shodan API key — stored in AppSettings, never returned to client
# ═══════════════════════════════════════════════════════════════
#
# The full API key is NEVER sent back to the frontend. GET and PUT
# return only a masked version (last 4 chars) and the `configured`
# boolean. The key lives in AppSettings under `shodan.api_key` and
# is mirrored into an in-memory cache in scanners.py so scanner
# threads can read it without the async DB.

class ShodanKeyPatch(BaseModel):
    api_key: str = Field(..., min_length=8, max_length=128)


async def _load_shodan_key_from_db(db: AsyncSession) -> None:
    """Pull shodan.api_key from AppSettings and push it to the scanner cache."""
    from sqlalchemy import select
    from src.models import AppSettings
    from src.scanners import set_shodan_api_key_cache

    row = (await db.execute(
        select(AppSettings).where(AppSettings.key == "shodan.api_key")
    )).scalar_one_or_none()
    set_shodan_api_key_cache(row.value if row else None)


@router.get("/shodan/config")
async def shodan_get_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return whether a Shodan key is configured, plus a masked preview.
    The full key is never exposed on the wire."""
    from src.scanners import _get_shodan_api_key, shodan_key_masked
    await _load_shodan_key_from_db(db)
    key = _get_shodan_api_key()
    return {
        "configured": bool(key),
        "masked": shodan_key_masked(key),
    }


@router.put("/shodan/config")
async def shodan_set_config(
    body: ShodanKeyPatch,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Save a new Shodan API key. The call tests the key against
    /api/account/profile before persisting. Returns only the masked
    version plus the Shodan profile metadata."""
    import httpx
    from sqlalchemy import select
    from src.models import AppSettings
    from src.scanners import set_shodan_api_key_cache, shodan_key_masked

    key = body.api_key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="La cle API est vide")

    # Verify the key against Shodan's account endpoint (0 credit cost)
    try:
        def _probe() -> httpx.Response:
            return httpx.get(
                "https://api.shodan.io/account/profile",
                params={"key": key},
                timeout=15.0,
            )
        resp = await asyncio.to_thread(_probe)
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Shodan injoignable : {e}")

    if resp.status_code == 401:
        raise HTTPException(status_code=400, detail="Cle API Shodan invalide (401 Unauthorized)")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Erreur Shodan ({resp.status_code}) : {resp.text[:200]}")

    try:
        profile = resp.json()
    except Exception:
        profile = {}

    # Persist and update cache
    existing = (await db.execute(
        select(AppSettings).where(AppSettings.key == "shodan.api_key")
    )).scalar_one_or_none()
    if existing is None:
        db.add(AppSettings(key="shodan.api_key", value=key))
    else:
        existing.value = key

    # Also record when the key was last verified
    last_check_row = (await db.execute(
        select(AppSettings).where(AppSettings.key == "shodan.last_check_at")
    )).scalar_one_or_none()
    now_iso = datetime.now(timezone.utc).isoformat()
    if last_check_row is None:
        db.add(AppSettings(key="shodan.last_check_at", value=now_iso))
    else:
        last_check_row.value = now_iso

    await db.commit()
    set_shodan_api_key_cache(key)

    return {
        "configured": True,
        "masked": shodan_key_masked(key),
        "last_check_at": now_iso,
        "profile": {
            "display_name": profile.get("display_name"),
            "member": profile.get("member"),
            "credits": profile.get("credits"),
        },
    }


@router.delete("/shodan/config")
async def shodan_delete_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove the Shodan key from AppSettings and clear the cache."""
    from sqlalchemy import select
    from src.models import AppSettings
    from src.scanners import set_shodan_api_key_cache

    for k in ("shodan.api_key", "shodan.last_check_at"):
        row = (await db.execute(
            select(AppSettings).where(AppSettings.key == k)
        )).scalar_one_or_none()
        if row:
            await db.delete(row)
    await db.commit()
    set_shodan_api_key_cache(None)
    return {"configured": False, "masked": ""}
