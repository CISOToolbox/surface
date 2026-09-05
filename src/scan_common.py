"""Shared primitives for Surface scanners.

Extracted from the original monolithic `scanners.py` so that each scanner can
live in its own add-on module (`addons/core/<name>/`, `addons/generic/<name>/`)
while reusing one copy of the cross-cutting helpers:

- anti-SSRF / anti-shell-injection target validation
- DNS / scope helpers (registrable domain, in-scope test, host normalisation)
- the per-scan stealth thread-local
- small env / HTTP / DNS utilities

Add-on modules import what they need from here:

    from src.scan_common import _resolve_safe_target, _is_stealth, _in_scope

Keep this module dependency-light (stdlib + lazily-imported httpx/dnspython) so
importing it never pulls a heavy or optional dependency at boot.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import threading
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("surface.scanners")


# ═══════════════════════════════════════════════════════════════
# Target validation (anti-SSRF + anti-shell-injection)
# ═══════════════════════════════════════════════════════════════

# Docker Compose service names siblings. Direct scan of these from inside
# the surface container is a lateral-movement vector. We block them even
# though private IPs are allowed in general.
_DOCKER_SIBLING_NAMES: frozenset[str] = frozenset({
    "pilot-app", "pilot-db",
    "risk-app", "risk-db",
    "vendor-app", "vendor-db",
    "compliance-app", "compliance-db",
    "asset-app", "asset-db",
    "access-app", "access-db",
    "appsec-app", "appsec-db",
    # Legacy names kept defensively (pre-rename scan -> appsec)
    "scan-app", "scan-db",
    "surface-app", "surface-db",
    "proxy",
    # Bare service names without suffix (docker uses both)
    "pilot", "risk", "vendor", "compliance", "asset", "access", "appsec", "scan", "surface",
})

# Known cloud metadata IPs (AWS, GCP, Azure, Alibaba, DigitalOcean).
_METADATA_IPS: frozenset[str] = frozenset({
    "169.254.169.254",   # AWS/GCP/Azure classic metadata
    "100.100.100.200",   # Alibaba
    "192.0.0.192",       # Oracle Cloud
    "fd00:ec2::254",     # AWS IPv6
})


def _safe_target(t: str) -> str:
    """Backward-compatible wrapper: validate + return the original target string.
    Use `_resolve_safe_target()` when downstream code needs the locked IP."""
    _, canonical = _resolve_safe_target(t)
    return canonical


def _resolve_safe_target(t: str, allow_unresolved: bool = False) -> tuple[str | None, str]:
    """Validate a scan target against shell injection and SSRF.

    Returns `(locked_ip, canonical_target)` where:
      - `locked_ip` is the resolved IP string to use for outbound connections
        (prevents DNS rebinding TOCTOU). `None` for CIDR ranges and unresolvable
        names.
      - `canonical_target` is the cleaned-up original (still useful for log lines
        and as the SNI/Host header).

    Blocked: loopback, link-local, cloud metadata, docker-compose siblings,
    multicast, reserved ranges. LAN (RFC1918) and public IPs are allowed.

    `allow_unresolved=True` returns `(None, canonical)` instead of raising when
    the name has no usable address. This is for ENROLLING a discovery seed (a
    monitored domain) whose apex legitimately has no A record — the per-connection
    lock still fires when a scanner actually contacts a host, so nothing that
    resolves to a forbidden target is ever reached. A name that DOES resolve to a
    blocked IP is still rejected.
    """
    t = (t or "").strip()
    if not t:
        raise ValueError("Cible requise")
    if len(t) > 253:
        raise ValueError("Cible trop longue")
    if not re.match(r"^[A-Za-z0-9._\-/:\[\]]+$", t):
        raise ValueError(f"Cible invalide (caracteres non autorises) : {t}")
    # A leading '-' would be parsed by nmap as an option, not a target
    # (`-Pn`, `-sU`, `-r`… all satisfy the charset above). No hostname,
    # IP or CIDR ever starts with a dash. Defence in depth: the argv
    # builders also pass `--` before the target.
    if t.startswith("-"):
        raise ValueError(f"Cible invalide (ne peut pas commencer par '-') : {t}")

    raw = t
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    host_only = raw
    if "/" in host_only and not re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", host_only):
        raise ValueError(f"Cible invalide (chemin inattendu) : {t}")

    # Strip brackets for IPv6 literals like [::1] before further checks
    bare = host_only.strip("[]")
    # For IPv4/hostname:port, split on the LAST colon only if it looks
    # like a port (not an IPv6 address which contains multiple colons)
    if ":" in bare and bare.count(":") == 1:
        bare = bare.split(":")[0]
    bare = bare.split("/")[0].lower()
    if bare in _DOCKER_SIBLING_NAMES:
        raise ValueError(f"Cible interne bloquee : {bare} (scan lateral non autorise)")

    if "/" in host_only:
        try:
            net = ipaddress.ip_network(host_only.strip("[]"), strict=False)
        except ValueError as e:
            raise ValueError(f"Plage CIDR invalide : {e}")
        _check_network_allowed(net, original=t)
        return None, t

    try:
        ip = ipaddress.ip_address(bare)
        _check_ip_allowed(ip, original=t)
        return str(ip), t
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(bare, None)
    except (socket.gaierror, UnicodeError) as e:
        # Fail-CLOSED by default, like ssrf_guard.resolve_safe_target. Accepting
        # an unresolvable name here handed it verbatim to nmap/httpx, which
        # resolve independently — the validation would then have proved nothing
        # about what actually gets contacted. Exception: enrolling a domain seed
        # (allow_unresolved), where no connection is made to the apex.
        if allow_unresolved:
            return None, t
        raise ValueError(f"Cible non resolvable : {bare} ({e})")

    resolved = [info[4][0] for info in infos if info[4]]
    locked: str | None = None
    for ip_str in resolved:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        _check_ip_allowed(ip, original=t)
        if locked is None:
            locked = ip_str
    if locked is None:
        if allow_unresolved:
            return None, t
        raise ValueError(f"Cible non resolvable : {bare} (aucune adresse exploitable)")
    return locked, t


def resolve_first_ip(value: str) -> str | None:
    """Return the first A/AAAA record for `value`, or None on failure.
    Used by the scheduler to cache resolved_ip on MonitoredAsset rows so
    the Hosts view can group aliases that point to the same machine.
    Skips CIDR ranges and returns the bare IP for literals."""
    if not value:
        return None
    bare = value.strip().lstrip("[").rstrip("]")
    if "/" in bare:
        return None
    # Pure IP? Return as-is.
    try:
        ipaddress.ip_address(bare)
        return bare
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(bare, None)
    except (socket.gaierror, UnicodeError):
        return None
    for info in infos:
        if info[4]:
            return info[4][0]
    return None


def _is_ip_literal(value: str) -> bool:
    """True when `value` is a bare IPv4/IPv6 literal (no hostname, no port)."""
    bare = (value or "").strip()
    # Strip square brackets around IPv6 literals (e.g. "[::1]")
    if bare.startswith("[") and bare.endswith("]"):
        bare = bare[1:-1]
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        return False


def _check_ip_allowed(ip: ipaddress._BaseAddress, original: str) -> None:
    """Raise ValueError if the IP is on the blocklist. Allows public + private LAN."""
    ip_str = str(ip)
    if ip_str in _METADATA_IPS:
        raise ValueError(f"Cible metadata cloud bloquee : {ip_str}")
    if ip.is_loopback:
        raise ValueError(f"Cible loopback bloquee : {ip_str} (non pertinent depuis un conteneur)")
    if ip.is_link_local:
        raise ValueError(f"Cible link-local bloquee : {ip_str} (risque metadata cloud)")
    if ip.is_unspecified:
        raise ValueError(f"Cible 0.0.0.0/:: bloquee")
    if ip.is_multicast:
        raise ValueError(f"Cible multicast bloquee : {ip_str}")
    if ip.is_reserved:
        raise ValueError(f"Cible dans un bloc reserve : {ip_str}")
    # is_private == RFC1918 (10/8, 172.16/12, 192.168/16) — ALLOWED by user choice
    # is_global == public IP — ALLOWED


# Blocked ranges, expressed as networks, so that a CIDR range can be tested for
# OVERLAP. Checking only the network address and the broadcast address let
# through any range that *contains* a forbidden target without bounding it:
# 100.100.100.0/24 has .0 and .255 as its bounds, so the Alibaba metadata IP
# (100.100.100.200) was swept without either of the two checks flinching.
_BLOCKED_NETWORKS: tuple = tuple(
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "::1/128",                 # loopback
        "169.254.0.0/16", "fe80::/10",            # link-local (metadata cloud)
        "0.0.0.0/32", "::/128",                   # unspecified
        "224.0.0.0/4", "ff00::/8",                # multicast
        "100.100.100.200/32",                     # Alibaba
        "192.0.0.192/32",                         # Oracle Cloud
        "fd00:ec2::254/128",                      # AWS IPv6
    )
)


def _check_network_allowed(net: ipaddress._BaseNetwork, original: str) -> None:
    """Reject a CIDR range that overlaps a blocked range.

    Enumerating every host would be impractical (a /8 holds 16 million of them),
    so overlap is tested network against network. The bounds are still checked
    individually so that the precise error messages of _check_ip_allowed are
    kept for the most common cases.
    """
    for ip in (net.network_address, net.broadcast_address):
        _check_ip_allowed(ip, original=original)
    for blocked in _BLOCKED_NETWORKS:
        if net.version == blocked.version and net.overlaps(blocked):
            raise ValueError(
                f"Plage {net} interdite : elle recouvre le bloc reserve {blocked}"
            )


# ═══════════════════════════════════════════════════════════════
# Small env / DNS / HTTP utilities
# ═══════════════════════════════════════════════════════════════

def _int_env(name: str, default: int, minv: int = 1, maxv: int = 10000) -> int:
    """Read an integer env var, clamped to [minv, maxv]."""
    try:
        v = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minv, min(maxv, v))


def _dns_query(domain: str, rtype: str) -> list[str]:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype)
        return [str(a) for a in answers]
    except Exception:
        return []


def _http_probe(target: str, port: int, scheme: str, timeout: float = 5.0) -> dict[str, Any] | None:
    """Issue one GET / on (target:port) and return {status, headers, body}.
    Returns None on connection failure."""
    import httpx
    url = f"{scheme}://{target}:{port}/"
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as c:
            r = c.get(url, headers={"User-Agent": "Surface/0.2 (CISO Toolbox)"})
            body_snippet = r.text[:8192] if r.text else ""
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": body_snippet,
                "url": url,
            }
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# Stealth context (per-scan opt-in)
# ═══════════════════════════════════════════════════════════════
# Set by `run_enabled_scanners` when the asset has `stealth_mode=True`.
# Scanners that issue lots of HTTP probes (nuclei) or do active port scans
# (nmap) check `_is_stealth()` and switch to a slower, browser-impersonating
# profile. Thread-local because each `asyncio.to_thread(run_enabled_scanners,…)`
# runs the whole chain on a single worker thread — parallel scans get
# independent contexts and never interfere.
_STEALTH_CTX = threading.local()
_STEALTH_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _is_stealth() -> bool:
    return bool(getattr(_STEALTH_CTX, "on", False))


# ═══════════════════════════════════════════════════════════════
# DNS scope helpers (registrable domain, in-scope test)
# ═══════════════════════════════════════════════════════════════

_MULTI_LABEL_TLDS: frozenset[str] = frozenset({
    "co.uk", "co.jp", "co.nz", "co.za", "co.kr", "co.in",
    "com.au", "com.br", "com.cn", "com.mx", "com.tw", "com.sg", "com.hk",
    "org.uk", "net.uk", "ac.uk", "gov.uk",
    "gouv.fr", "ac.jp", "or.jp", "ne.jp",
})

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


def _registrable(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without a PSL dependency."""
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _normalize_host(raw: str) -> str | None:
    """Return a sanitized lowercase hostname, or None if invalid/wildcard."""
    if not raw:
        return None
    h = raw.strip().strip(".").lower()
    if not h or "*" in h or " " in h or ":" in h:
        return None
    if len(h) > 253:
        return None
    if not _HOST_RE.match(h):
        return None
    return h


def _in_scope(host: str, scope: str) -> bool:
    """True if `host` is the scope domain itself or a sub-domain of it."""
    scope = scope.lower().strip(".")
    return host == scope or host.endswith("." + scope)


# ═══════════════════════════════════════════════════════════════
# Port-risk classification + nmap XML parsing (shared: nmap add-on + import route)
# ═══════════════════════════════════════════════════════════════

HIGH_RISK_SERVICES = {
    "telnet", "ftp", "rsh", "rlogin", "tftp", "smb", "netbios-ssn",
    "microsoft-ds", "ms-wbt-server", "rdp", "vnc", "mysql", "postgresql",
    "mssql", "ms-sql-s", "oracle", "redis", "mongodb", "elasticsearch",
    "memcached", "rpcbind", "nfs",
}
CRITICAL_SERVICES = {"telnet", "tftp", "rsh", "rlogin", "vnc", "rdp"}


def _severity_for_port(port: int, service: str) -> str:
    s = (service or "").lower()
    if s in CRITICAL_SERVICES:
        return "critical"
    if s in HIGH_RISK_SERVICES:
        return "high"
    if port in (80, 443, 22, 25, 53, 8080, 8443):
        return "info"
    return "medium"


def _parse_nmap_xml(xml_text: str, fallback_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [{
            "scanner": "nmap", "type": "parse_error", "severity": "info",
            "title": f"nmap parsing error for {fallback_target}",
            "description": str(e), "target": fallback_target, "evidence": {},
        }]

    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else fallback_target
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") == "down":
            findings.append({
                "scanner": "nmap", "type": "host_down", "severity": "info",
                "title": f"Host {addr} unavailable",
                "description": "The host did not respond during the scan.",
                "target": addr, "evidence": {"address": addr, "hostname": hostname},
            })
            continue

        ports_el = host.find("ports")
        open_ports = []
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portnum = int(p.get("portid", "0"))
                proto = p.get("protocol", "tcp")
                service_el = p.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                banner = " ".join(x for x in [product, version] if x)
                open_ports.append((portnum, proto, service_name, banner))
                sev = _severity_for_port(portnum, service_name)
                title = f"Port {portnum}/{proto} ({service_name}) open on {addr}"
                if banner:
                    title += f" — {banner}"
                desc = f"The {service_name} service is listening on {addr}:{portnum}/{proto}."
                if banner:
                    desc += f"\nBanner detected: {banner}"
                if sev == "critical":
                    desc += "\nObsolete or highly exposed service. Close it immediately."
                elif sev == "high":
                    desc += "\nSensitive service. Verify intentional exposure, authentication, and patching."
                findings.append({
                    "scanner": "nmap", "type": "open_port", "severity": sev,
                    "title": title, "description": desc, "target": f"{addr}:{portnum}",
                    "evidence": {
                        "address": addr, "hostname": hostname, "port": portnum,
                        "protocol": proto, "service": service_name,
                        "product": product, "version": version,
                    },
                })
        findings.append({
            "scanner": "nmap", "type": "host_summary", "severity": "info",
            "title": f"nmap summary: {addr}" + (f" ({hostname})" if hostname else ""),
            "description": f"{len(open_ports)} open port(s) on {addr}." + (f" Hostname: {hostname}." if hostname else ""),
            "target": addr,
            "evidence": {
                "address": addr, "hostname": hostname,
                "open_ports": [{"port": p, "proto": pr, "service": s, "banner": b} for p, pr, s, b in open_ports],
            },
        })
    return findings


# ═══════════════════════════════════════════════════════════════
# Up-to-date TLS context (shared: tls / tls_grade / sensitive_files)
# ═══════════════════════════════════════════════════════════════

def _tls_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that uses the most up-to-date CA bundle available.

    Python's system store on `python:3.12-slim` points to `/usr/lib/ssl/`
    which may lag behind modern roots (ISRG Root X1/X2 cross-signing,
    new ECC chains, etc.). `certifi` is a transitive dep of httpx and
    ships a fresh bundle updated with each Python release."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()
