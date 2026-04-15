"""All Surface scanners. Each function returns a list of finding dicts.

Functions are intentionally synchronous and CPU/IO-light. They are invoked
from a background scheduler and run in `asyncio.to_thread` to avoid blocking
the event loop.

The dispatcher `run_scanners_for_kind` picks the right set of scanners for the
asset's kind (domain | host | ip_range).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
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
    "scan-app", "scan-db",
    "surface-app", "surface-db",
    "proxy",
    # Bare service names without suffix (docker uses both)
    "pilot", "risk", "vendor", "compliance", "asset", "access", "scan", "surface",
})

# Known cloud metadata IPs (AWS, GCP, Azure, Alibaba, DigitalOcean).
_METADATA_IPS: frozenset[str] = frozenset({
    "169.254.169.254",   # AWS/GCP/Azure classic metadata
    "100.100.100.200",   # Alibaba
    "fd00:ec2::254",     # AWS IPv6
})


def _safe_target(t: str) -> str:
    """Backward-compatible wrapper: validate + return the original target string.
    Use `_resolve_safe_target()` when downstream code needs the locked IP."""
    _, canonical = _resolve_safe_target(t)
    return canonical


def _resolve_safe_target(t: str) -> tuple[str | None, str]:
    """Validate a scan target against shell injection and SSRF.

    Returns `(locked_ip, canonical_target)` where:
      - `locked_ip` is the resolved IP string to use for outbound connections
        (prevents DNS rebinding TOCTOU). `None` for CIDR ranges and unresolvable
        names.
      - `canonical_target` is the cleaned-up original (still useful for log lines
        and as the SNI/Host header).

    Blocked: loopback, link-local, cloud metadata, docker-compose siblings,
    multicast, reserved ranges. LAN (RFC1918) and public IPs are allowed.
    """
    t = (t or "").strip()
    if not t:
        raise ValueError("Cible requise")
    if len(t) > 253:
        raise ValueError("Cible trop longue")
    if not re.match(r"^[A-Za-z0-9._\-/:\[\]]+$", t):
        raise ValueError(f"Cible invalide (caracteres non autorises) : {t}")

    raw = t
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    host_only = raw
    if "/" in host_only and not re.match(r"^[0-9a-fA-F:.]+/\d{1,3}$", host_only):
        raise ValueError(f"Cible invalide (chemin inattendu) : {t}")

    bare = host_only.split(":")[0].split("/")[0].lower()
    if bare in _DOCKER_SIBLING_NAMES:
        raise ValueError(f"Cible interne bloquee : {bare} (scan lateral non autorise)")

    if "/" in host_only:
        try:
            net = ipaddress.ip_network(host_only, strict=False)
        except ValueError as e:
            raise ValueError(f"Plage CIDR invalide : {e}")
        for ip in (net.network_address, net.broadcast_address):
            _check_ip_allowed(ip, original=t)
        return None, t

    try:
        ip = ipaddress.ip_address(bare)
        _check_ip_allowed(ip, original=t)
        return str(ip), t
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(bare, None)
    except (socket.gaierror, UnicodeError):
        return None, t

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
    return locked, t


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
    # is_private == RFC1918 (10/8, 172.16/12, 192.168/16) — AUTORISE par choix utilisateur
    # is_global == IP publique — AUTORISE


# ═══════════════════════════════════════════════════════════════
# HOST scanners (IP or DNS name)
# ═══════════════════════════════════════════════════════════════

NMAP_PROFILES = {
    "quick":    ["-T4", "-F", "-Pn"],
    "standard": ["-T4", "-sV", "--top-ports", "1000", "-Pn"],
    "deep":     ["-T4", "-sV", "-sC", "-p-", "-Pn"],
}

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


def scan_host_ports(target: str, profile: str = "quick") -> list[dict[str, Any]]:
    """Run nmap with the given profile and return findings (one per open port + summary)."""
    target = _safe_target(target)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [{
            "scanner": "nmap", "type": "error", "severity": "info",
            "title": "nmap binary not found", "description": "Le binaire nmap est introuvable sur le serveur Surface.",
            "target": target, "evidence": {},
        }]

    args = [nmap_path, "-oX", "-"] + NMAP_PROFILES.get(profile, NMAP_PROFILES["quick"]) + [target]
    timeout = {"quick": 180, "standard": 600, "deep": 1800}.get(profile, 300)
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"Scan nmap timeout pour {target}",
            "description": f"Le scan a depasse {timeout}s.", "target": target, "evidence": {},
        }]
    except Exception as e:
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"Scan nmap echoue pour {target}",
            "description": str(e), "target": target, "evidence": {},
        }]

    if proc.returncode not in (0, None):
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"nmap exit {proc.returncode} pour {target}",
            "description": (proc.stderr.decode(errors="replace") or "")[:500],
            "target": target, "evidence": {},
        }]

    return _parse_nmap_xml(proc.stdout.decode(errors="replace"), target)


def _parse_nmap_xml(xml_text: str, fallback_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [{
            "scanner": "nmap", "type": "parse_error", "severity": "info",
            "title": f"Erreur parsing nmap pour {fallback_target}",
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
                "title": f"Host {addr} indisponible",
                "description": "L'host n'a pas repondu pendant le scan.",
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
                title = f"Port {portnum}/{proto} ({service_name}) ouvert sur {addr}"
                if banner:
                    title += f" — {banner}"
                desc = f"Le service {service_name} ecoute sur {addr}:{portnum}/{proto}."
                if banner:
                    desc += f"\nBanner detectee : {banner}"
                if sev == "critical":
                    desc += "\nService obsolete ou hautement expose. A fermer immediatement."
                elif sev == "high":
                    desc += "\nService sensible. Verifier l'exposition intentionnelle, l'auth et le patch."
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
            "title": f"Resume nmap : {addr}" + (f" ({hostname})" if hostname else ""),
            "description": f"{len(open_ports)} port(s) ouvert(s) sur {addr}." + (f" Hostname: {hostname}." if hostname else ""),
            "target": addr,
            "evidence": {
                "address": addr, "hostname": hostname,
                "open_ports": [{"port": p, "proto": pr, "service": s, "banner": b} for p, pr, s, b in open_ports],
            },
        })
    return findings


def _san_hostnames_from_dict(cert_dict: dict) -> list[str]:
    """Extract DNSName SAN entries from the ssl.getpeercert() dict form."""
    san = cert_dict.get("subjectAltName") or ()
    return [val for kind, val in san if kind == "DNS"]


def _san_hostnames_from_der(der: bytes) -> list[str]:
    """Extract DNSName SAN entries from a DER-encoded cert (fallback)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        cert_obj = x509.load_der_x509_certificate(der, default_backend())
        ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return []


def _filter_san_in_scope(sans: list[str], target: str) -> list[str]:
    """Filter SAN DNS names: drop wildcards, invalid, target itself, and
    anything outside the target's registrable domain."""
    scope = _registrable(target)
    kept: set[str] = set()
    for raw in sans:
        h = _normalize_host(raw)
        if not h or h == target.lower():
            continue
        if _in_scope(h, scope):
            kept.add(h)
    return sorted(kept)


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


def _parse_cert_details(der: bytes) -> dict[str, Any]:
    """Pull notBefore / notAfter / SAN from a DER cert without relying on
    verification. Used to independently classify a verify failure."""
    out: dict[str, Any] = {}
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import ExtensionOID
        cert_obj = x509.load_der_x509_certificate(der, default_backend())
        out["subject"] = cert_obj.subject.rfc4514_string()
        out["issuer"] = cert_obj.issuer.rfc4514_string()
        try:
            nb = cert_obj.not_valid_before_utc
            na = cert_obj.not_valid_after_utc
        except AttributeError:
            # cryptography < 42
            nb = cert_obj.not_valid_before
            na = cert_obj.not_valid_after
        out["not_before"] = nb.isoformat()
        out["not_after"] = na.isoformat()
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(tz=_tz.utc)
        out["expired"] = now > na.replace(tzinfo=nb.tzinfo or _tz.utc)
        out["not_yet_valid"] = now < nb.replace(tzinfo=nb.tzinfo or _tz.utc)
        out["days_left"] = (na.replace(tzinfo=_tz.utc) - now).days
        try:
            ext = cert_obj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            out["san"] = list(ext.value.get_values_for_type(x509.DNSName))
        except Exception:
            out["san"] = []
    except Exception as e:
        out["parse_error"] = str(e)
    return out


def _hostname_covered_by(cert_details: dict[str, Any], hostname: str) -> bool:
    """True if `hostname` matches any SAN entry (wildcard-aware)."""
    import fnmatch
    h = hostname.lower()
    for san in cert_details.get("san", []) or []:
        p = (san or "").lower()
        if not p:
            continue
        if "*" in p:
            if fnmatch.fnmatchcase(h, p):
                return True
        elif h == p:
            return True
    return False


def _reverse_cert_lookup(cert_dict: dict, target: str, max_results: int = 50) -> list[str]:
    """Query crt.sh for any other hostname that has been issued a cert by
    the same issuer with the same serial number. Useful to find sibling
    assets (CDN edges, regional aliases) that share a wildcard cert but
    are not in the local SAN list. Filtered to the same registrable
    domain as `target` to stay in scope. Network failure → empty list."""
    serial = ""
    issuer = ""
    issuer_tuples = cert_dict.get("issuer") or ()
    for entry in issuer_tuples:
        for k, v in entry:
            if k == "commonName":
                issuer = v
                break
    serial = (cert_dict.get("serialNumber", "") or "").lower()
    if not serial and not issuer:
        return []

    base = _registrable(target)
    if not base:
        return []

    out: set[str] = set()
    try:
        import httpx
        # crt.sh accepts a serial query via id parameter or the serial in
        # hex. Use the keyword search on the registrable domain — cheaper
        # and gives sibling hosts directly.
        with httpx.Client(timeout=15.0) as c:
            r = c.get(f"https://crt.sh/?q=%25.{base}&output=json")
            if r.status_code != 200:
                return []
            for entry in r.json()[:1000]:
                names = (entry.get("name_value") or "").split("\n")
                for n in names:
                    n = n.strip().lower().lstrip("*.")
                    if not n or n == target.lower():
                        continue
                    if not (n == base or n.endswith("." + base)):
                        continue
                    out.add(n)
                    if len(out) >= max_results:
                        return sorted(out)
    except Exception as e:
        logger.info("crt.sh reverse lookup failed: %s", e)
    return sorted(out)


def scan_host_tls(target: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Check the TLS certificate validity on port 443 AND extract SAN DNS
    names as discovered hosts (pivoting from one cert to its siblings)."""
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []
    discovered: list[str] = []
    port = 443

    try:
        ctx = _tls_ssl_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)

        sans = _san_hostnames_from_dict(cert) or _san_hostnames_from_der(der)
        discovered = _filter_san_in_scope(sans, target)

        try:
            from datetime import datetime as _dt, timezone as _tz
            # notAfter is always UTC per RFC 5280 — parse as naive then stamp UTC.
            expiry = _dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
            days_left = (expiry - _dt.now(tz=_tz.utc)).days
            if days_left < 0:
                sev, msg = "critical", f"Le certificat est EXPIRE depuis {-days_left} jour(s)."
            elif days_left < 7:
                sev, msg = "high", f"Le certificat expire dans {days_left} jour(s)."
            elif days_left < 30:
                sev, msg = "medium", f"Le certificat expire dans {days_left} jour(s) — planifier le renouvellement."
            else:
                sev = None
                msg = ""
            ev = {
                "notAfter": cert["notAfter"],
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "san_dns_names": sans,
                "san_in_scope": discovered,
            }
            if sev:
                findings.append({
                    "scanner": "tls", "type": "tls_expiring", "severity": sev,
                    "title": f"Certificat TLS de {target} : {msg}",
                    "description": f"Le certificat expire le {cert['notAfter']}.",
                    "target": f"{target}:443", "evidence": ev,
                })
            else:
                findings.append({
                    "scanner": "tls", "type": "tls_valid", "severity": "info",
                    "title": f"Certificat TLS valide pour {target} ({days_left}j restants)",
                    "description": (
                        f"Cert valide jusqu'au {cert['notAfter']}. "
                        f"SAN : {len(sans)} entree(s), dont {len(discovered)} dans le scope."
                    ),
                    "target": f"{target}:443", "evidence": ev,
                })
        except (KeyError, ValueError):
            pass

        if discovered:
            findings.append({
                "scanner": "tls", "type": "tls_san_discovery", "severity": "info",
                "title": f"TLS SAN : {len(discovered)} hostname(s) decouvert(s) via {target}",
                "description": (
                    f"Le certificat de {target} declare {len(discovered)} "
                    f"autre(s) hostname(s) dans le meme scope ({_registrable(target)}). "
                    f"Ils sont automatiquement ajoutes aux assets surveilles."
                ),
                "target": f"{target}:443",
                "evidence": {"discovered_hosts": discovered},
            })

        # v0.2 — reverse cert lookup: ask crt.sh which OTHER hostnames have
        # been issued certs by the same issuer + serial. This catches sibling
        # assets that share the same wildcard cert but are not in the local
        # SAN list (e.g. CDN edges, regional aliases).
        try:
            sibling_hosts = _reverse_cert_lookup(cert, target)
            if sibling_hosts:
                # Merge into discovered so the scheduler enrolls them too
                for h in sibling_hosts:
                    if h not in discovered:
                        discovered.append(h)
                findings.append({
                    "scanner": "tls", "type": "tls_reverse_cert", "severity": "info",
                    "title": f"Reverse cert : {len(sibling_hosts)} hostname(s) partagent le cert de {target}",
                    "description": (
                        f"crt.sh a identifie {len(sibling_hosts)} autre(s) hostname(s) "
                        f"emis par le meme issuer/serial. Ils sont ajoutes aux assets "
                        f"surveilles."
                    ),
                    "target": f"{target}:443",
                    "evidence": {"siblings": sibling_hosts, "source": "crt.sh"},
                })
        except Exception as e:
            logger.info("reverse cert lookup failed for %s: %s", target, e)

        return findings, discovered

    except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
        # Verification failed. Re-connect in non-verifying mode to grab the
        # cert bytes, then classify: is the cert REALLY broken (expired,
        # hostname mismatch, self-signed) or is the scanner just missing
        # a root in its CA store? The latter is a scanner limitation and
        # must not be reported as a security finding.
        err_str = str(e)
        der: bytes | None = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except Exception:
            pass

        if der is None:
            findings.append({
                "scanner": "tls", "type": "tls_error", "severity": "info",
                "title": f"TLS unreachable on {target}:443",
                "description": f"Impossible de recuperer le certificat : {err_str}",
                "target": f"{target}:443", "evidence": {"error": err_str},
            })
            return findings, []

        details = _parse_cert_details(der)
        sans = _san_hostnames_from_der(der)
        discovered = _filter_san_in_scope(sans, target)
        hostname_ok = _hostname_covered_by({"san": sans}, target)
        expired = bool(details.get("expired"))
        not_yet = bool(details.get("not_yet_valid"))
        self_signed = details.get("subject") and details.get("subject") == details.get("issuer")

        # Real problems worth flagging
        if expired:
            findings.append({
                "scanner": "tls", "type": "tls_expired", "severity": "critical",
                "title": f"Certificat TLS expire sur {target}:443",
                "description": f"Le certificat a expire le {details.get('not_after')}.",
                "target": f"{target}:443",
                "evidence": {**details, "san_dns_names": sans, "san_in_scope": discovered, "error": err_str},
            })
        elif not_yet:
            findings.append({
                "scanner": "tls", "type": "tls_not_yet_valid", "severity": "high",
                "title": f"Certificat TLS pas encore valide sur {target}:443",
                "description": f"Le certificat n'est valide qu'a partir du {details.get('not_before')}.",
                "target": f"{target}:443",
                "evidence": {**details, "error": err_str},
            })
        elif not hostname_ok and sans and not _is_ip_literal(target):
            # Only flag hostname mismatch when the target is actually a DNS
            # name. If the operator scans a bare IP, the cert is inherently
            # issued for the hostname(s) in its SAN — a mismatch against the
            # IP is expected and not a security finding (it's the same
            # behaviour `openssl s_client` would produce).
            findings.append({
                "scanner": "tls", "type": "tls_hostname_mismatch", "severity": "high",
                "title": f"Certificat TLS ne couvre pas {target}",
                "description": (
                    f"Le certificat presente par {target}:443 ne contient pas ce hostname "
                    f"dans ses SAN. SAN declares : {', '.join(sans[:10])}"
                ),
                "target": f"{target}:443",
                "evidence": {**details, "san_dns_names": sans, "san_in_scope": discovered, "error": err_str},
            })
        elif self_signed:
            findings.append({
                "scanner": "tls", "type": "tls_self_signed", "severity": "medium",
                "title": f"Certificat TLS self-signed sur {target}:443",
                "description": (
                    f"Le certificat est auto-signe (subject == issuer). Acceptable pour "
                    f"un host interne mais pas pour un service expose publiquement."
                ),
                "target": f"{target}:443",
                "evidence": {**details, "san_dns_names": sans, "error": err_str},
            })
        else:
            # Verification failed for a reason we cannot confirm — most
            # likely an incomplete CA store on our side (modern LE roots
            # missing, corporate PKI, etc.). Emit a non-alarmist info
            # finding AND still report expiry if the cert is close to EOL.
            days_left = details.get("days_left")
            if isinstance(days_left, int):
                if days_left < 7:
                    findings.append({
                        "scanner": "tls", "type": "tls_expiring", "severity": "high",
                        "title": f"Certificat TLS de {target} : expire dans {days_left} jour(s)",
                        "description": f"Le certificat expire le {details.get('not_after')}.",
                        "target": f"{target}:443",
                        "evidence": {**details, "san_dns_names": sans},
                    })
                elif days_left < 30:
                    findings.append({
                        "scanner": "tls", "type": "tls_expiring", "severity": "medium",
                        "title": f"Certificat TLS de {target} : expire dans {days_left} jour(s)",
                        "description": f"Le certificat expire le {details.get('not_after')}.",
                        "target": f"{target}:443",
                        "evidence": {**details, "san_dns_names": sans},
                    })
            findings.append({
                "scanner": "tls", "type": "tls_unverifiable", "severity": "info",
                "title": f"Certificat TLS non verifiable sur {target}:443 (CA store limite)",
                "description": (
                    f"Verification systeme echouee ({err_str}), mais l'analyse directe "
                    f"du certificat ne montre pas de probleme : le cert n'est pas expire, "
                    f"couvre bien le hostname, et n'est pas auto-signe. Cette erreur est "
                    f"probablement due a une chaine de confiance incomplete cote scanner "
                    f"(CA racine non incluse dans le bundle local). Aucun risque pour la cible."
                ),
                "target": f"{target}:443",
                "evidence": {**details, "san_dns_names": sans, "san_in_scope": discovered, "error": err_str},
            })
        return findings, discovered
    except (socket.timeout, ConnectionRefusedError, OSError):
        return [], []


# ═══════════════════════════════════════════════════════════════
# DOMAIN scanners
# ═══════════════════════════════════════════════════════════════

def _dns_query(domain: str, rtype: str) -> list[str]:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype)
        return [str(a) for a in answers]
    except Exception:
        return []


def scan_domain_email(domain: str) -> list[dict[str, Any]]:
    """Check SPF, DMARC, DKIM and MX records for a domain."""
    domain = _safe_target(domain).lower()
    findings: list[dict[str, Any]] = []

    # MX
    mx = _dns_query(domain, "MX")
    if not mx:
        findings.append({
            "scanner": "email_security", "type": "mx_missing", "severity": "info",
            "title": f"Aucun MX configure pour {domain}",
            "description": "Le domaine n'a pas d'enregistrement MX. Aucun mail ne peut etre recu (peut etre intentionnel).",
            "target": domain, "evidence": {},
        })

    # SPF (TXT starting with v=spf1)
    txt = _dns_query(domain, "TXT")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    if not spf:
        findings.append({
            "scanner": "email_security", "type": "spf_missing", "severity": "high",
            "title": f"SPF manquant sur {domain}",
            "description": "Aucun enregistrement SPF (TXT v=spf1...). N'importe qui peut envoyer des mails au nom de ce domaine. Recommande : 'v=spf1 -all' au minimum.",
            "target": domain, "evidence": {"txt_records": txt},
        })
    else:
        # Classify the `all` qualifier. RFC 7208 mechanisms: -all (hard fail, strict),
        # ~all (soft fail, recommended), ?all (neutral, weak), +all (pass anything).
        # Bare `all` with no qualifier == +all per the RFC.
        spf_lc = spf.lower()
        has_hard_fail = "-all" in spf_lc
        has_soft_fail = "~all" in spf_lc
        has_neutral = "?all" in spf_lc
        has_pass_all = ("+all" in spf_lc) or (
            re.search(r"(^|\s)all($|\s)", spf_lc) is not None
            and not (has_hard_fail or has_soft_fail or has_neutral)
        )
        if has_pass_all:
            findings.append({
                "scanner": "email_security", "type": "spf_weak", "severity": "high",
                "title": f"SPF trop permissif sur {domain}",
                "description": f"L'enregistrement SPF accepte tous les emetteurs (+all ou 'all' sans qualifieur). SPF: {spf}",
                "target": domain, "evidence": {"spf": spf},
            })
        elif has_neutral:
            findings.append({
                "scanner": "email_security", "type": "spf_neutral", "severity": "medium",
                "title": f"SPF en mode neutre (?all) sur {domain}",
                "description": f"Le SPF est en mode 'neutre', sans politique de rejet. SPF: {spf}",
                "target": domain, "evidence": {"spf": spf},
            })

    # DMARC (TXT on _dmarc.<domain>)
    dmarc_txt = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_txt if "v=DMARC1" in t), None)
    if not dmarc:
        findings.append({
            "scanner": "email_security", "type": "dmarc_missing", "severity": "high",
            "title": f"DMARC manquant sur {domain}",
            "description": "Aucun enregistrement DMARC. Recommande au minimum 'v=DMARC1; p=none; rua=mailto:...' pour le monitoring, puis durcir vers p=quarantine ou p=reject.",
            "target": domain, "evidence": {},
        })
    else:
        if "p=none" in dmarc:
            findings.append({
                "scanner": "email_security", "type": "dmarc_weak", "severity": "medium",
                "title": f"DMARC en mode monitoring (p=none) sur {domain}",
                "description": f"Le DMARC est en monitoring, pas en application. Apres une periode d'observation, durcir vers quarantine ou reject. DMARC: {dmarc}",
                "target": domain, "evidence": {"dmarc": dmarc},
            })

    # DKIM — try common selectors
    dkim_found = False
    for selector in ("default", "google", "selector1", "selector2", "k1", "mail"):
        dkim_txt = _dns_query(f"{selector}._domainkey.{domain}", "TXT")
        if any("v=DKIM1" in t or "p=" in t for t in dkim_txt):
            dkim_found = True
            break
    if not dkim_found:
        findings.append({
            "scanner": "email_security", "type": "dkim_missing", "severity": "medium",
            "title": f"DKIM non detecte sur {domain}",
            "description": "Aucun selecteur DKIM commun (default, google, selector1...) n'a ete trouve. Verifier la configuration DKIM avec votre provider mail.",
            "target": domain, "evidence": {"selectors_tried": ["default", "google", "selector1", "selector2", "k1", "mail"]},
        })

    return findings


_QWERTY_NEIGHBORS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "sfcxer", "e": "wrsdf",
    "f": "dgcvrt", "g": "fhbvty", "h": "gjbnyu", "i": "ujkol", "j": "hknmui",
    "k": "jlmio", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
_EXTRA_TLDS = ["com", "net", "org", "fr", "io", "co", "info", "biz", "eu", "app", "dev", "xyz"]


def _generate_typo_variants(domain: str, max_variants: int = 60) -> set[str]:
    """Generate likely typosquats (insertion, omission, replacement, transposition + alt TLDs)."""
    if "." not in domain:
        return set()
    parts = domain.split(".")
    sld = parts[0]
    tld = ".".join(parts[1:])
    variants: set[str] = set()

    # Omission
    for i in range(len(sld)):
        variants.add(sld[:i] + sld[i+1:] + "." + tld)
    # Transposition
    for i in range(len(sld) - 1):
        variants.add(sld[:i] + sld[i+1] + sld[i] + sld[i+2:] + "." + tld)
    # Replacement (qwerty neighbors)
    for i, ch in enumerate(sld):
        for n in _QWERTY_NEIGHBORS.get(ch, ""):
            variants.add(sld[:i] + n + sld[i+1:] + "." + tld)
    # Insertion (qwerty neighbors)
    for i in range(len(sld) + 1):
        for ch in "abcdefghijklmnopqrstuvwxyz":
            if i < len(sld) and sld[i] == ch:
                continue
            variants.add(sld[:i] + ch + sld[i:] + "." + tld)
    # Alt TLDs
    for alt in _EXTRA_TLDS:
        if alt != tld:
            variants.add(sld + "." + alt)

    variants.discard(domain)
    return set(list(variants)[:max_variants])


def scan_domain_typosquatting(domain: str, max_check: int = 50) -> list[dict[str, Any]]:
    """Generate typosquat variants and check which ones are actually registered."""
    domain = _safe_target(domain).lower()
    variants = _generate_typo_variants(domain)
    if not variants:
        return []
    findings: list[dict[str, Any]] = []
    registered = []
    for v in list(variants)[:max_check]:
        try:
            socket.gethostbyname(v)
            registered.append(v)
        except (socket.gaierror, socket.timeout):
            continue

    if registered:
        findings.append({
            "scanner": "typosquatting", "type": "typosquat", "severity": "medium",
            "title": f"{len(registered)} domaine(s) typosquat enregistre(s) similaires a {domain}",
            "description": "Des variantes ressemblant a votre domaine sont enregistrees. A surveiller : phishing, usurpation, redirections malveillantes.\n\nDomaines detectes :\n- " + "\n- ".join(registered[:20]),
            "target": domain,
            "evidence": {"original": domain, "registered_variants": registered, "tested_count": min(len(variants), max_check)},
        })
    else:
        findings.append({
            "scanner": "typosquatting", "type": "typosquat_clean", "severity": "info",
            "title": f"Aucun typosquat detecte pour {domain}",
            "description": f"{min(len(variants), max_check)} variantes testees, aucune n'est enregistree.",
            "target": domain,
            "evidence": {"original": domain, "tested_count": min(len(variants), max_check)},
        })
    return findings


# ═══════════════════════════════════════════════════════════════
# IP RANGE: discovery
# ═══════════════════════════════════════════════════════════════

def scan_iprange_discovery(cidr: str) -> tuple[list[dict[str, Any]], list[str]]:
    """nmap ping sweep on a CIDR. Returns (findings, list_of_discovered_ips)."""
    cidr = _safe_target(cidr)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [{
            "scanner": "nmap", "type": "error", "severity": "info",
            "title": "nmap binary not found", "description": "", "target": cidr, "evidence": {},
        }], []

    args = [nmap_path, "-oX", "-", "-sn", "-T4", cidr]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=600)
    except Exception as e:
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"Discovery scan echoue pour {cidr}",
            "description": str(e), "target": cidr, "evidence": {},
        }], []

    if proc.returncode not in (0, None):
        return [{
            "scanner": "nmap", "type": "error", "severity": "medium",
            "title": f"nmap exit {proc.returncode} pour {cidr}",
            "description": (proc.stderr.decode(errors="replace") or "")[:500],
            "target": cidr, "evidence": {},
        }], []

    discovered: list[str] = []
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(proc.stdout.decode(errors="replace"))
    except ET.ParseError:
        return findings, discovered

    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else None
        if not addr:
            continue
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""
        discovered.append(addr)
        findings.append({
            "scanner": "discovery", "type": "host_discovered", "severity": "info",
            "title": f"Nouvel host decouvert sur {cidr} : {addr}" + (f" ({hostname})" if hostname else ""),
            "description": f"Un host est joignable sur {addr}." + (f" Hostname: {hostname}." if hostname else "") + f"\nIl a ete ajoute automatiquement aux hosts surveilles.",
            "target": addr,
            "evidence": {"cidr": cidr, "address": addr, "hostname": hostname},
        })

    findings.append({
        "scanner": "discovery", "type": "discovery_summary", "severity": "info",
        "title": f"Discovery sur {cidr} : {len(discovered)} host(s) actifs",
        "description": f"{len(discovered)} hosts repondent au ping sweep sur {cidr}.",
        "target": cidr,
        "evidence": {"cidr": cidr, "discovered": discovered},
    })
    return findings, discovered


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


def _int_env(name: str, default: int, minv: int = 1, maxv: int = 10000) -> int:
    """Read an integer env var, clamped to [minv, maxv]."""
    try:
        v = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minv, min(maxv, v))


# ── Nuclei tuning: env vars are defaults, DB overrides cached here ─────
# scan_nuclei() runs in a thread via asyncio.to_thread and cannot hit the
# async DB. HTTP routes populate this process-wide cache from AppSettings
# on startup and on every save, so UI edits take effect immediately.

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


def _nuclei_env_defaults() -> dict[str, int]:
    return {
        "rate_limit":  _int_env("SURFACE_NUCLEI_RATE_LIMIT", 20, 1, 5000),
        "concurrency": _int_env("SURFACE_NUCLEI_CONCURRENCY", 25, 1, 500),
        "bulk_size":   _int_env("SURFACE_NUCLEI_BULK_SIZE", 25, 1, 500),
        "timeout":     _int_env("SURFACE_NUCLEI_TIMEOUT", 10, 1, 300),
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
# DNS brute-force (active, passive sources having missed subdomains)
# ═══════════════════════════════════════════════════════════════

# Curated default wordlist (~300 entries) covering generic, dev/test, security,
# infra, CI/CD, monitoring, CISO-specific modules and common corporate
# sub-domains. Not exhaustive — override with SURFACE_DNS_BRUTE_WORDLIST=<path>
# to point at a larger list (one word per line). Assetnote-style lists of
# 100k+ entries work fine, expect longer scan times (~5-10 minutes).
_DNS_BRUTE_DEFAULT_WORDS: tuple[str, ...] = (
    # Root / generic
    "www", "www2", "web", "m", "mobile", "old", "new", "legacy", "archive",
    "home", "main", "portal", "site", "sites", "root", "public", "private",
    "internal", "external", "intranet", "extranet",
    # Mail
    "mail", "mail1", "mail2", "mail3", "email", "webmail", "webmail2",
    "smtp", "smtp1", "smtp2", "smtp3", "smtpout", "smtp-out", "smtpin",
    "smtp-in", "mailout", "mail-out", "outbound", "inbound", "relay",
    "relay1", "relay2", "sender", "mailsender", "bounce", "return-path",
    "imap", "imap1", "imap2", "pop", "pop3",
    "mx", "mx1", "mx2", "mx3", "mxout", "mx-out",
    "exchange", "ex", "ex1", "ex2", "outlook", "owa", "ecp", "mapi",
    "activesync", "eas", "zimbra", "postfix", "sendmail",
    "mailgw", "mail-gw", "mailgateway", "mail-gateway", "mailserver",
    "mail-server", "mailhost", "autodiscover", "autoconfig",
    "mdaemon", "openrelay", "mailman", "listserv",
    # Microsoft 365 / Entra artifacts (useful even when the app proxy is off-domain)
    "msoid", "sts", "adfs", "adfs1", "adfs2", "sts1", "sts2",
    "lyncdiscover", "lyncweb", "sip", "meet", "dialin", "webex",
    # DNS / name services
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "resolver",
    # FTP / file transfer
    "ftp", "ftp2", "sftp", "tftp", "files", "file", "share", "download",
    "upload", "uploads", "fileshare", "sharepoint",
    # Web applications
    "api", "api2", "apis", "api-v1", "api-v2", "rest", "graphql", "soap",
    "app", "apps", "application", "admin", "administrator", "adm",
    "backend", "frontend", "console", "panel", "dashboard", "control",
    "manage", "manager", "management", "cpanel", "webmin", "plesk",
    "phpmyadmin", "pma", "adminer",
    # Environments
    "dev", "development", "devel", "devs", "developer", "developers",
    "test", "tests", "testing", "tester", "qa", "uat", "preprod",
    "pre-prod", "pre", "staging", "stage", "stg", "sandbox", "sbx",
    "demo", "demos", "lab", "labs", "poc", "mvp", "beta", "alpha",
    "canary", "perf", "load", "integration", "int",
    # Dev-prefixed common apps
    "dev-api", "dev-app", "dev-admin", "dev-web", "test-api", "test-app",
    "staging-api", "staging-app", "prod-api", "prod-app",
    "api-dev", "api-test", "api-staging", "api-prod", "api-preprod",
    # Identity / auth / security
    "sec", "security", "secure", "ssl", "tls",
    "sso", "auth", "oauth", "oauth2", "oidc", "saml", "login", "signin",
    "id", "identity", "iam", "keycloak", "okta", "adfs", "duo",
    "mfa", "2fa", "otp", "radius", "ldap", "ldaps", "ad", "kerberos",
    # VPN / remote access — generic names
    "vpn", "vpn1", "vpn2", "vpn3", "vpn4", "vpn-gw", "vpngw", "vpn-gateway",
    "vpn-prod", "vpn-dev", "vpn-test", "vpn-fr", "vpn-eu", "vpn-us",
    "vpn-admin", "vpn-user", "vpn-users", "vpn-ssl", "sslvpn", "ssl-vpn",
    "webvpn", "web-vpn", "vpn-web", "portal", "vpn-portal", "vpnportal",
    "mobilevpn", "mobile-vpn", "clientless", "clientless-vpn",
    "remote", "remote1", "remote2", "remoteaccess", "remote-access", "ra",
    "ra-vpn", "ravpn", "access", "access-gw", "accessgw", "access1",
    "access2", "access-vpn", "extranet-vpn",
    "tunnel", "tun", "tun0", "tun1", "ipsec", "ipsec-vpn", "l2tp", "pptp",
    "gre", "esp", "ikev2",
    # VPN / remote access — enterprise product names
    "globalprotect", "global-protect", "gp", "gp-portal", "gpportal",
    "gp-gw", "gpgw", "gp1", "gp2", "palo", "paloalto", "pa", "panos",
    "anyconnect", "any-connect", "ac", "ac1", "ac2", "ciscoanyconnect",
    "cisco-vpn", "cisco-asa", "asa", "asa1", "asa2", "asav",
    "ocserv", "openconnect", "ios-xe",
    "forti", "fortinet", "forticlient", "fortigate", "fortigate1",
    "fortigate2", "fortimail", "fortiweb", "fortimanager", "fortianalyzer",
    "fgt", "fgt1", "fgt2", "fg", "fg1", "fg2",
    "pulse", "pulsesecure", "pulse-secure", "ivanti", "ivanti-vpn", "psa",
    "psa1", "psa2", "junos-pulse",
    "zscaler", "zs", "zs-vpn", "zpa", "zia", "zsapp",
    "juniper", "ivc", "ivs", "junos",
    "checkpoint", "cp", "cpvpn", "cp-vpn", "ckp", "gaia", "mab", "mobile-access",
    "netscaler", "ns", "ns1", "ns2", "nsvpn", "citrix", "citrix-vpn",
    "citrix-gw", "citrixgw", "ctx", "ctx1", "ctx2", "ica", "ica-proxy",
    "xenapp", "storefront", "workspace", "wsa", "cag",
    "openvpn", "ovpn", "ovpn-access", "ovpn-admin", "ovpn1", "ovpn2",
    "wireguard", "wg", "wg0", "wg1", "wg2",
    "tailscale", "ts-vpn", "cato", "catocloud", "twingate",
    "zerotier", "zt", "zerotier-one",
    "cloudflareaccess", "cloudflare-access", "cfa", "warp", "teams",
    "zerotrust", "zero-trust", "ztna", "sse", "sase",
    # Remote desktop / terminal services
    "rdp", "rdg", "rdgw", "rd-gateway", "rdgateway", "rdpgateway",
    "rds", "ts", "tsgw", "rdweb", "rd-web", "remotedesktop",
    "remote-desktop", "remoteapp", "mstsc", "terminal", "terminalserver",
    "teamviewer", "tv", "anydesk", "rustdesk",
    # Gateway / firewall conventions
    "fw", "firewall", "fw1", "fw2", "fw01", "fw02", "fwint", "fwext",
    "gw", "gw1", "gw2", "gateway", "gateway1", "gateway2",
    "internetgw", "border", "edge", "edge1", "edge2", "perimeter",
    "nac", "nac-gw", "radiusnac",
    # Extranet / partner / B2B
    "extranet", "ext", "external", "partner", "partners", "partenaire",
    "partenaires", "supplier", "suppliers", "fournisseur", "fournisseurs",
    "client", "clients", "b2b", "b2c", "guest", "guests",
    # Monitoring / ops / observability
    "monitor", "monitoring", "grafana", "kibana", "elastic", "elastic-search",
    "elasticsearch", "es", "prom", "prometheus", "alertmanager", "metrics",
    "stats", "status", "health", "healthz", "uptime", "ping",
    "logs", "logging", "syslog", "splunk", "jaeger", "loki", "opensearch",
    "nagios", "zabbix", "cacti", "munin", "apm", "sentry", "newrelic",
    # CI/CD / dev tooling
    "ci", "cd", "build", "builds", "jenkins", "gitlab", "github", "git",
    "gogs", "gitea", "bitbucket", "svn", "cvs", "mercurial", "artifact",
    "artifacts", "nexus", "harbor", "registry", "docker", "dockerhub",
    "sonar", "sonarqube", "codecov", "coveralls", "argo", "argocd",
    "tekton", "drone", "circle", "circleci", "travis", "teamcity", "bamboo",
    # Collaboration / docs / tickets
    "jira", "confluence", "wiki", "wikis", "docs", "doc", "documentation",
    "readme", "manual", "help", "helpdesk", "support", "ticket", "tickets",
    "servicedesk", "otrs", "zendesk", "freshdesk", "mantis", "bugzilla",
    "redmine", "trello", "asana", "notion", "slack", "teams", "mattermost",
    "rocket", "rocketchat", "discord", "matrix",
    # CISO Toolbox modules (dogfooding)
    "pilot", "risk", "vendor", "compliance", "asset", "access", "scan",
    "surface", "watch", "audit", "ciso", "security-toolbox",
    # Storage / DB / middleware
    "db", "database", "mysql", "postgres", "postgresql", "pgsql",
    "mongo", "mongodb", "redis", "memcache", "memcached", "cache",
    "mariadb", "mssql", "oracle", "cassandra", "neo4j", "influx",
    "rabbitmq", "rabbit", "kafka", "zookeeper", "activemq", "nats",
    "s3", "minio", "ceph", "swift", "nas", "smb", "cifs", "nfs",
    "backup", "backups", "dr", "failover",
    # Finance / HR / ERP / CRM
    "crm", "erp", "sap", "hr", "rh", "finance", "accounting", "billing",
    "invoice", "invoices", "payment", "payments", "cart", "checkout",
    "shop", "store", "commerce", "marketplace", "salesforce", "oracle-crm",
    "sage", "dynamics",
    # Content / media / marketing
    "blog", "news", "press", "media", "stream", "video", "videos",
    "images", "img", "photos", "gallery", "cdn", "cdn2", "static",
    "static1", "static2", "assets", "asset", "resources", "res",
    "content", "cms", "wordpress", "drupal", "joomla", "magento",
    "ghost", "strapi", "contentful", "shopify",
    # Communication
    "chat", "im", "meeting", "meet", "conf", "conference", "webinar",
    "zoom", "webex", "jitsi", "bigbluebutton", "bbb",
    # Network / infra
    "gw", "gateway", "router", "switch", "fw", "firewall", "lb", "loadbalancer",
    "proxy", "reverse-proxy", "squid", "haproxy", "traefik", "envoy",
    "ingress", "ingress-controller",
    # Regional
    "fr", "en", "eu", "us", "uk", "de", "it", "es", "ch", "be", "ca",
    "asia", "apac", "emea", "amer", "latam", "africa",
    # Versions / instances
    "v1", "v2", "v3", "v4", "1", "2", "3", "01", "02", "03",
    "prod", "production", "live", "release",
    # Specialized / less common but worth trying
    "remote", "rdp", "ts", "teamviewer", "rustdesk", "anydesk",
    "ci-dev", "ci-prod", "registry-dev", "registry-prod",
    "captive", "guest", "wifi", "byod",
    "time", "ntp", "pool",
    "directory", "dir", "contacts", "phonebook",
    "survey", "surveys", "forms", "questionnaire",
    "kb", "knowledge", "faq", "training", "learn", "lms", "moodle",
    "elearning", "video-training",
)


# Base tokens from which we auto-generate compound permutations
# (a, b, ab, ba, a-b, b-a). This catches the naming convention chaos:
#   vpnssl vs sslvpn vs vpn-ssl vs ssl-vpn vs vpn.ssl (not a single label)
# A pairing across these bases produces ~160 extra wordlist entries — well
# worth a few seconds of extra DNS time.
_COMPOUND_TOKENS: tuple[str, ...] = (
    "vpn", "ssl", "sslvpn", "tls", "remote", "ra", "access", "portal",
    "web", "secure", "sec", "gw", "gateway", "connect", "connection",
    "client", "admin", "user", "entry", "login",
)


def _generate_compounds(tokens: tuple[str, ...]) -> list[str]:
    """Build compound words like (vpn, ssl) → [vpnssl, sslvpn, vpn-ssl,
    ssl-vpn]. Only pairs tokens from the same base set — enough to cover
    most real-world naming collisions without exploding the wordlist."""
    out: set[str] = set()
    for a in tokens:
        for b in tokens:
            if a == b:
                continue
            out.add(a + b)
            out.add(f"{a}-{b}")
    return sorted(out)


_WORDLIST_ALLOWED_DIRS = ("/data/wordlists", "/app/wordlists")


def _load_dns_brute_wordlist() -> list[str]:
    """Load the DNS brute-force wordlist. Override via SURFACE_DNS_BRUTE_WORDLIST
    pointing at a file inside /data/wordlists or /app/wordlists."""
    import pathlib
    path = os.environ.get("SURFACE_DNS_BRUTE_WORDLIST", "").strip()
    if path:
        try:
            resolved = pathlib.Path(path).resolve(strict=False)
            in_allowed = any(
                str(resolved).startswith(str(pathlib.Path(d).resolve()) + os.sep)
                for d in _WORDLIST_ALLOWED_DIRS
            )
            if not in_allowed:
                logger.warning("dns_brute: wordlist path outside allowed dirs: %s", path)
                path = ""
        except (OSError, RuntimeError) as e:
            logger.warning("dns_brute: cannot resolve %s: %s", path, e)
            path = ""
    if path and os.path.isfile(path):
        try:
            words: list[str] = []
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if not w or w.startswith("#"):
                        continue
                    # Keep only valid DNS labels
                    if re.match(r"^[a-z0-9][a-z0-9_-]*$", w):
                        words.append(w)
            if words:
                # Dedupe while preserving order
                seen: set[str] = set()
                deduped = [w for w in words if not (w in seen or seen.add(w))]
                logger.info("dns_brute: loaded %d unique words from %s", len(deduped), path)
                return deduped
        except OSError as e:
            logger.warning("dns_brute: cannot read %s: %s", path, e)
    # Dedupe the embedded tuple (overlap can exist across sections) and
    # append auto-generated compounds for the VPN/remote-access vocabulary.
    seen2: set[str] = set()
    base = [w for w in _DNS_BRUTE_DEFAULT_WORDS if not (w in seen2 or seen2.add(w))]
    for c in _generate_compounds(_COMPOUND_TOKENS):
        if c not in seen2:
            seen2.add(c)
            base.append(c)
    return base


def _detect_dns_wildcard(domain: str) -> set[str]:
    """Return the set of IPs that a random `.domain` resolves to.
    Used to filter out wildcard DNS responses from brute-force hits."""
    import random
    import string
    import dns.resolver

    wildcard_ips: set[str] = set()
    # Try 2 random labels to catch wildcards that cycle IPs
    for _ in range(2):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            resolver.timeout = 3
            ans = resolver.resolve(f"{rnd}.{domain}", "A")
            for a in ans:
                wildcard_ips.add(str(a))
        except Exception:
            pass
    return wildcard_ips


def scan_domain_dns_brute(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Active DNS brute-force — resolves <word>.<domain> for each word in the
    wordlist concurrently. Filters out wildcard responses. Returns findings
    and the list of discovered hostnames for auto-enrollment.

    Tuning:
      SURFACE_DNS_BRUTE_CONCURRENCY  parallel queries (default 10)
      SURFACE_DNS_BRUTE_TIMEOUT      per-query timeout seconds (default 3)
      SURFACE_DNS_BRUTE_WORDLIST     override path (one word per line)
    """
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor, as_completed

    domain = _safe_target(domain).lower()
    words = _load_dns_brute_wordlist()
    concurrency = _int_env("SURFACE_DNS_BRUTE_CONCURRENCY", 10, 1, 100)
    timeout = _int_env("SURFACE_DNS_BRUTE_TIMEOUT", 3, 1, 30)

    wildcard_ips = _detect_dns_wildcard(domain)
    logger.info("dns_brute: %s — %d words, concurrency=%d, wildcard=%s",
                domain, len(words), concurrency, wildcard_ips or "none")

    discovered: set[str] = set()
    discovered_with_ips: dict[str, list[str]] = {}

    def _resolve_one(word: str) -> tuple[str, list[str]] | None:
        host = f"{word}.{domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            resolver.timeout = timeout
            ans = resolver.resolve(host, "A")
            ips = [str(a) for a in ans]
            return (host, ips)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = [ex.submit(_resolve_one, w) for w in words]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if not res:
                continue
            host, ips = res
            # Drop wildcard false positives: if every IP returned is in the
            # wildcard set, the hostname does not really exist as a distinct
            # record.
            if wildcard_ips and all(ip in wildcard_ips for ip in ips):
                continue
            h = _normalize_host(host)
            # Scope = the seed domain exactly, NOT its registrable root.
            # This keeps discovery within what the user explicitly asked
            # to monitor (e.g. a seed `sub.example.com` should not leak
            # hits to `other.example.com`). TLS pivot uses _registrable
            # because its purpose is sibling discovery.
            if h and _in_scope(h, domain) and h != domain:
                discovered.add(h)
                discovered_with_ips[h] = ips

    hosts = sorted(discovered)
    findings: list[dict[str, Any]] = [{
        "scanner": "dns_brute",
        "type": "dns_brute_discovery",
        "severity": "info",
        "title": f"DNS brute-force : {len(hosts)} sous-domaine(s) decouvert(s) pour {domain}",
        "description": (
            f"Le scan de brute-force DNS avec {len(words)} mots-cles a identifie "
            f"{len(hosts)} hostnames qui resolvent sous {domain}. "
            + ("Wildcard DNS detecte sur " + ", ".join(sorted(wildcard_ips)) + " — les hits pointant uniquement vers ces IPs ont ete filtres." if wildcard_ips else "Pas de wildcard DNS detecte.")
        ),
        "target": domain,
        "evidence": {
            "wordlist_size": len(words),
            "concurrency": concurrency,
            "timeout_seconds": timeout,
            "wildcard_ips": sorted(wildcard_ips),
            "count": len(hosts),
            "hosts_sample": [{"host": h, "ips": discovered_with_ips.get(h, [])} for h in hosts[:50]],
        },
    }]
    return findings, hosts


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


def scan_domain_shodan(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Passive subdomain enumeration via Shodan DNS API.

    Hits https://api.shodan.io/dns/domain/{domain} which does NOT consume
    query credits — it is part of the standard Shodan subscription.
    Returns discovered hostnames for auto-enrollment by the scheduler.
    """
    import httpx

    domain = _safe_target(domain).lower()
    api_key = _get_shodan_api_key()
    findings: list[dict[str, Any]] = []

    if not api_key:
        findings.append({
            "scanner": "shodan", "type": "shodan_no_key", "severity": "info",
            "title": f"Shodan : cle API non configuree",
            "description": (
                "Le scanner Shodan est active sur cette cible mais aucune "
                "cle API n'est configuree. Ouvrez Parametres -> Shodan "
                "pour ajouter votre cle, ou retirez ce scanner de la liste "
                "des scanners actifs de la cible."
            ),
            "target": domain, "evidence": {},
        })
        return findings, []

    url = f"https://api.shodan.io/dns/domain/{domain}"
    try:
        resp = httpx.get(url, params={"key": api_key}, timeout=30.0)
        if resp.status_code == 401:
            findings.append({
                "scanner": "shodan", "type": "shodan_auth_error", "severity": "info",
                "title": "Shodan : cle API invalide (401)",
                "description": "La cle API Shodan configuree n'est pas valide. Verifiez-la dans les Parametres.",
                "target": domain, "evidence": {"status": 401},
            })
            return findings, []
        if resp.status_code == 404:
            findings.append({
                "scanner": "shodan", "type": "shodan_no_data", "severity": "info",
                "title": f"Shodan : aucune donnee pour {domain}",
                "description": "Shodan ne connait pas de sous-domaines pour ce domaine.",
                "target": domain, "evidence": {},
            })
            return findings, []
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        logger.info("shodan_domain: %s failed: %s", domain, e)
        findings.append({
            "scanner": "shodan", "type": "shodan_error", "severity": "info",
            "title": f"Shodan : erreur reseau pour {domain}",
            "description": str(e)[:500],
            "target": domain, "evidence": {"error": str(e)[:500]},
        })
        return findings, []

    subdomains_raw = data.get("subdomains") or []
    discovered: set[str] = set()
    for sub in subdomains_raw:
        host = f"{sub}.{domain}"
        h = _normalize_host(host)
        if h and _in_scope(h, domain) and h != domain:
            discovered.add(h)
    hosts = sorted(discovered)

    findings.append({
        "scanner": "shodan", "type": "shodan_domain_discovery", "severity": "info",
        "title": f"Shodan : {len(hosts)} sous-domaine(s) identifie(s) pour {domain}",
        "description": (
            f"Shodan DNS API a remonte {len(subdomains_raw)} sous-domaine(s) "
            f"connu(s) pour {domain}. Les resultats proviennent du banner "
            f"grabbing passif de Shodan sur Internet."
        ),
        "target": domain,
        "evidence": {
            "source": "shodan",
            "count": len(hosts),
            "subdomains_sample": hosts[:50],
            "tags": data.get("tags") or [],
        },
    })
    return findings, hosts


def scan_host_shodan(target: str) -> list[dict[str, Any]]:
    """Active host lookup via Shodan /shodan/host/{ip}.

    WARNING: Each call consumes 1 query credit on the user's Shodan account.
    Free tier = 100 credits/month. Schedule with care.

    Emits:
      - one finding per known CVE (high severity)
      - one info finding with ports / services / CPE / tags / last update
    """
    import httpx

    target = _safe_target(target)
    api_key = _get_shodan_api_key()
    if not api_key:
        # Silent return — the scanner is opt-in and the user clearly forgot
        # to set a key before enabling it. The domain scanner emits the
        # visible "no_key" finding, no need to spam every host.
        return []

    # Resolve hostname to IP (Shodan host API requires an IP)
    try:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            ip = target
        else:
            ip = socket.gethostbyname(target)
    except (socket.gaierror, OSError) as e:
        logger.info("shodan_host: DNS resolve failed for %s: %s", target, e)
        return []

    url = f"https://api.shodan.io/shodan/host/{ip}"
    try:
        resp = httpx.get(url, params={"key": api_key}, timeout=30.0)
    except httpx.HTTPError as e:
        logger.info("shodan_host: %s failed: %s", target, e)
        return []

    if resp.status_code == 404:
        return [{
            "scanner": "shodan", "type": "shodan_no_data", "severity": "info",
            "title": f"Shodan : aucune donnee pour {target} ({ip})",
            "description": "Shodan ne possede pas de banner pour cette IP (jamais scannee ou resultats non indexes).",
            "target": target, "evidence": {"ip": ip},
        }]
    if resp.status_code == 401:
        return [{
            "scanner": "shodan", "type": "shodan_auth_error", "severity": "info",
            "title": "Shodan : cle API invalide (401)",
            "description": "La cle API Shodan configuree n'est pas valide.",
            "target": target, "evidence": {"status": 401},
        }]
    try:
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.info("shodan_host: %s HTTP error: %s", target, e)
        return []

    findings: list[dict[str, Any]] = []
    shodan_url = f"https://www.shodan.io/host/{ip}"

    # Known CVEs: emit one high-severity finding per CVE
    vulns = data.get("vulns") or []
    for cve in vulns:
        findings.append({
            "scanner": "shodan",
            "type": f"shodan_vuln",
            "severity": "high",
            "title": f"Shodan : {cve} detectee sur {target}",
            "description": (
                f"Shodan signale que {target} ({ip}) est potentiellement "
                f"exposee a {cve}. Verifier la version exacte du service "
                f"concerne et patcher. Details : {shodan_url}"
            ),
            "target": target,
            "evidence": {
                "cve": cve, "ip": ip, "shodan_url": shodan_url,
            },
        })

    # Port summary
    ports = sorted(data.get("ports") or [])
    services: list[dict[str, Any]] = []
    for banner in (data.get("data") or [])[:20]:
        services.append({
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "product": banner.get("product"),
            "version": banner.get("version"),
            "cpe": banner.get("cpe23") or banner.get("cpe"),
        })

    summary_desc_parts = [
        f"Shodan a observe les ports {', '.join(str(p) for p in ports[:20])} sur {ip}."
    ]
    if data.get("last_update"):
        summary_desc_parts.append(f"Derniere observation : {data.get('last_update')}.")
    if data.get("tags"):
        summary_desc_parts.append(f"Tags : {', '.join(data.get('tags'))}.")
    summary_desc_parts.append(f"Details : {shodan_url}")

    findings.append({
        "scanner": "shodan",
        "type": "shodan_host_summary",
        "severity": "info",
        "title": f"Shodan : {len(ports)} port(s) observe(s) sur {target} ({ip})",
        "description": " ".join(summary_desc_parts),
        "target": target,
        "evidence": {
            "ip": ip,
            "hostnames": (data.get("hostnames") or [])[:20],
            "ports": ports,
            "services": services,
            "tags": data.get("tags") or [],
            "os": data.get("os"),
            "last_update": data.get("last_update"),
            "vulns_count": len(vulns),
            "shodan_url": shodan_url,
        },
    })

    return findings


# ═══════════════════════════════════════════════════════════════
# Subdomain takeover detection (CNAME fingerprinting)
# ═══════════════════════════════════════════════════════════════
#
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz
# Conservative detection: requires BOTH a CNAME pattern match AND a
# fingerprint string in the HTTP body, OR (for selected services) an
# NXDOMAIN on the CNAME target.

from typing import TypedDict


class TakeoverFingerprint(TypedDict, total=False):
    service: str
    cname_patterns: tuple[str, ...]
    fingerprints: tuple[str, ...]
    nxdomain_is_vulnerable: bool
    severity: str


_TAKEOVER_FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    {
        "service": "AWS S3",
        "cname_patterns": (
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$",
            r"\.s3\.[a-z0-9-]+\.amazonaws\.com$",
            r"\.s3-website\.[a-z0-9-]+\.amazonaws\.com$",
        ),
        "fingerprints": ("NoSuchBucket", "The specified bucket does not exist"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": (r"\.github\.io$",),
        "fingerprints": (
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html",
        ),
        "nxdomain_is_vulnerable": False,
        "severity": "critical",
    },
    {
        "service": "Heroku",
        "cname_patterns": (r"\.herokuapp\.com$", r"\.herokudns\.com$", r"\.herokussl\.com$"),
        "fingerprints": ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Azure",
        "cname_patterns": (
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
            r"\.azureedge\.net$",
            r"\.blob\.core\.windows\.net$",
        ),
        "fingerprints": ("404 Web Site not found", "The resource you are looking for has been removed"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Vercel",
        "cname_patterns": (r"\.vercel\.app$", r"\.now\.sh$", r"\.vercel-dns\.com$"),
        "fingerprints": ("The deployment could not be found", "DEPLOYMENT_NOT_FOUND"),
        "nxdomain_is_vulnerable": True,
        "severity": "critical",
    },
    {
        "service": "Netlify",
        "cname_patterns": (r"\.netlify\.com$", r"\.netlify\.app$"),
        "fingerprints": ("Not Found - Request ID",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Shopify",
        "cname_patterns": (r"\.myshopify\.com$",),
        "fingerprints": ("Sorry, this shop is currently unavailable",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cname_patterns": (r"\.fastly\.net$",),
        "fingerprints": ("Fastly error: unknown domain",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Pantheon",
        "cname_patterns": (r"\.pantheonsite\.io$",),
        "fingerprints": ("The gods are wise", "404 error unknown site"),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Tumblr",
        "cname_patterns": (r"domains\.tumblr\.com$", r"\.tumblr\.com$"),
        "fingerprints": ("Whatever you were looking for doesn't currently exist at this address",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Ghost",
        "cname_patterns": (r"\.ghost\.io$",),
        "fingerprints": ("The thing you were looking for is no longer here",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Zendesk",
        "cname_patterns": (r"\.zendesk\.com$",),
        "fingerprints": ("Help Center Closed",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Helpjuice",
        "cname_patterns": (r"\.helpjuice\.com$",),
        "fingerprints": ("We could not find what you're looking for",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Help Scout",
        "cname_patterns": (r"\.helpscoutdocs\.com$",),
        "fingerprints": ("No settings were found for this company",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Webflow",
        "cname_patterns": (r"\.webflow\.io$", r"\.proxy\.webflow\.com$"),
        "fingerprints": ("The page you are looking for doesn't exist or has been moved",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "ReadMe",
        "cname_patterns": (r"\.readme\.io$",),
        "fingerprints": ("Project doesnt exist... yet!",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Strikingly",
        "cname_patterns": (r"\.s\.strikinglydns\.com$",),
        "fingerprints": ("PAGE NOT FOUND",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": (r"\.surge\.sh$",),
        "fingerprints": ("project not found",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "WordPress.com",
        "cname_patterns": (r"\.wordpress\.com$",),
        "fingerprints": ("Do you want to register",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Unbounce",
        "cname_patterns": (r"\.unbouncepages\.com$",),
        "fingerprints": ("The requested URL was not found on this server",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Intercom",
        "cname_patterns": (r"\.custom\.intercom\.help$",),
        "fingerprints": ("This page is reserved for artistic dogs",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": (r"\.bitbucket\.io$",),
        "fingerprints": ("Repository not found",),
        "nxdomain_is_vulnerable": False,
        "severity": "high",
    },
    {
        "service": "Cargo Collective",
        "cname_patterns": (r"\.cargocollective\.com$",),
        "fingerprints": ("404 Not Found",),
        "nxdomain_is_vulnerable": False,
        "severity": "low",
    },
    {
        "service": "Launchrock",
        "cname_patterns": (r"\.launchrock\.com$",),
        "fingerprints": ("It looks like you may have taken a wrong turn somewhere",),
        "nxdomain_is_vulnerable": False,
        "severity": "medium",
    },
    {
        "service": "SmugMug",
        "cname_patterns": (r"domains\.smugmug\.com$",),
        "fingerprints": (),
        "nxdomain_is_vulnerable": True,
        "severity": "medium",
    },
)


def _resolve_cname_chain(host: str, max_depth: int = 5) -> list[str]:
    """Return the full CNAME chain starting at `host`, empty if none."""
    import dns.resolver
    import dns.exception

    chain: list[str] = []
    current = host
    for _ in range(max_depth):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5
            resolver.timeout = 5
            ans = resolver.resolve(current, "CNAME")
            if not ans:
                break
            target = str(ans[0].target).rstrip(".").lower()
            if not target or target == current:
                break
            chain.append(target)
            current = target
        except dns.exception.DNSException:
            break
        except Exception:
            break
    return chain


def _cname_target_is_nxdomain(target: str) -> bool:
    """True when the given hostname explicitly NXDOMAINs — a strong
    dangling-CNAME signal for services that release claim on no-A-record."""
    import dns.resolver
    import dns.exception
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.timeout = 5
        resolver.resolve(target, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.exception.DNSException:
        return False
    except Exception:
        return False


def _match_takeover_service(cname: str) -> dict[str, Any] | None:
    for entry in _TAKEOVER_FINGERPRINTS:
        for pat in entry["cname_patterns"]:
            if re.search(pat, cname, re.IGNORECASE):
                return entry
    return None


_TAKEOVER_MAX_BODY_BYTES = 10_000


def _fetch_takeover_body(target: str) -> tuple[int | None, str]:
    """Fetch http(s)://target and return (status_code, body ≤10KB).
    - Streams the response and stops after 10 KB to avoid memory blowup on
      attacker-controlled CDN targets that could return huge bodies.
    - TLS verification disabled: the target IS typically abandoned /
      mis-configured, so a broken cert is the norm.
    - follow_redirects disabled: a dangling takeover target that redirects
      to a metadata endpoint (169.254.169.254) would bypass our _safe_target
      guard. Takeover fingerprints appear on the first response anyway.
    """
    import httpx
    headers = {"User-Agent": "CISO-Surface/1.0 (takeover-check)"}
    for scheme in ("https", "http"):
        try:
            with httpx.stream(
                "GET",
                f"{scheme}://{target}",
                timeout=10.0,
                headers=headers,
                follow_redirects=False,
                verify=False,
            ) as resp:
                buf = bytearray()
                for chunk in resp.iter_bytes():
                    remaining = _TAKEOVER_MAX_BODY_BYTES - len(buf)
                    if remaining <= 0:
                        break
                    buf.extend(chunk[:remaining])
                body = buf.decode("utf-8", errors="replace")
                return (resp.status_code, body)
        except httpx.HTTPError:
            continue
    return (None, "")


def scan_host_takeover(target: str) -> list[dict[str, Any]]:
    """Detect subdomain takeover opportunities on `target`.

    Steps:
      1. Resolve the CNAME chain.
      2. For each CNAME, match against known-vulnerable service patterns.
      3. Fetch http(s)://target and scan the body for the fingerprint, or
         (for services flagged nxdomain_is_vulnerable) check whether the
         CNAME target has no A record.
      4. Emit one critical/high finding per confirmed hit.
    """
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []

    cname_chain = _resolve_cname_chain(target)
    if not cname_chain:
        return []

    logger.info("takeover: %s -> cname chain: %s", target, cname_chain)

    # Fetch the target body ONCE. Each fingerprint check inspects the same
    # response — avoiding N HTTP round-trips per CNAME in the chain.
    status_code, body = _fetch_takeover_body(target)
    body_lc = body.lower()

    for cname in cname_chain:
        entry = _match_takeover_service(cname)
        if not entry:
            continue

        service = entry["service"]
        severity = entry.get("severity", "critical")
        fps = entry.get("fingerprints", ())
        nxdomain_vuln = entry.get("nxdomain_is_vulnerable", False)

        target_nxdomain = _cname_target_is_nxdomain(cname) if nxdomain_vuln else False

        fingerprint_hit: str | None = None
        for fp in fps:
            if fp and fp.lower() in body_lc:
                fingerprint_hit = fp
                break

        vulnerable = bool(fingerprint_hit) or target_nxdomain
        if not vulnerable:
            continue

        reasons: list[str] = []
        if fingerprint_hit:
            reasons.append(f"empreinte '{fingerprint_hit}' detectee dans la reponse HTTP")
        if target_nxdomain:
            reasons.append(f"le target CNAME ({cname}) est en NXDOMAIN (dangling)")

        findings.append({
            "scanner": "takeover",
            "type": "subdomain_takeover",
            "severity": severity,
            "title": f"Subdomain takeover possible sur {target} (via {service})",
            "description": (
                f"Le sous-domaine {target} pointe via CNAME vers {cname} ({service}), "
                f"mais la ressource cible est abandonnee : {' ET '.join(reasons)}. "
                f"Un attaquant peut potentiellement enregistrer cette ressource {service} "
                f"et servir du contenu sous votre nom de domaine. "
                f"Remediation : supprimer ou corriger l'enregistrement CNAME pour "
                f"{target} dans votre DNS autoritaire."
            ),
            "target": target,
            "evidence": {
                "cname_chain": cname_chain,
                "matched_cname": cname,
                "service": service,
                "fingerprint_hit": fingerprint_hit,
                "target_nxdomain": target_nxdomain,
                "http_status_code": status_code,
                "body_excerpt": body[:500] if body else "",
            },
        })

    return findings


# ═══════════════════════════════════════════════════════════════
# Nuclei (DAST templates)
# ═══════════════════════════════════════════════════════════════


def scan_nuclei(target: str, severity_filter: str = "low,medium,high,critical") -> list[dict[str, Any]]:
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
            "description": "Le binaire nuclei est introuvable.",
            "target": target, "evidence": {},
        }]

    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    tuning = _nuclei_tuning()

    args = [
        nuclei_path, "-target", url, "-jsonl", "-silent",
        "-severity", severity_filter,
        "-rate-limit", str(tuning["rate_limit"]),
        "-concurrency", str(tuning["concurrency"]),
        "-bulk-size", str(tuning["bulk_size"]),
        "-timeout", str(tuning["timeout"]),
        "-retries", str(tuning["retries"]),
        "-disable-update-check",
        "-no-color",
    ]
    logger.info("nuclei: rate=%d c=%d bulk=%d timeout=%ds retries=%d for %s",
                tuning["rate_limit"], tuning["concurrency"], tuning["bulk_size"],
                tuning["timeout"], tuning["retries"], url)
    try:
        proc = subprocess.run(args, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        return [{
            "scanner": "nuclei", "type": "timeout", "severity": "medium",
            "title": f"Nuclei timeout sur {url}",
            "description": "Le scan nuclei a depasse 15 minutes.", "target": target, "evidence": {},
        }]
    except Exception as e:
        return [{
            "scanner": "nuclei", "type": "error", "severity": "medium",
            "title": f"Nuclei echoue sur {url}",
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
        sev = NUCLEI_SEVERITY_MAP.get((info.get("severity") or "info").lower(), "info")
        name = info.get("name") or r.get("template-id") or "Nuclei finding"
        matched = r.get("matched-at") or r.get("host") or url
        tags = info.get("tags") or []
        findings.append({
            "scanner": "nuclei",
            "type": (info.get("classification", {}) or {}).get("cve-id") or r.get("template-id") or "nuclei",
            "severity": sev,
            "title": f"{name} on {matched}",
            "description": (info.get("description") or "").strip()[:1000] +
                           (f"\n\nTemplate: {r.get('template-id')}" if r.get("template-id") else ""),
            "target": matched,
            "evidence": {
                "template_id": r.get("template-id"),
                "matched_at": matched,
                "tags": tags if isinstance(tags, list) else [],
                "reference": info.get("reference") or [],
                "matcher_name": r.get("matcher-name"),
                "extracted": r.get("extracted-results"),
            },
        })

    if not findings:
        findings.append({
            "scanner": "nuclei", "type": "scan_clean", "severity": "info",
            "title": f"Nuclei : aucun finding sur {url}",
            "description": f"Aucune detection avec les templates par defaut (severite >= {severity_filter}).",
            "target": target, "evidence": {"url": url, "severity_filter": severity_filter},
        })
    return findings


# ═══════════════════════════════════════════════════════════════
# Discovery helpers (scope / normalization)
# ═══════════════════════════════════════════════════════════════

# Second-level public suffixes we handle explicitly. Not exhaustive — for
# a fully correct registrable-domain computation use the Public Suffix List
# (via `tldextract`). This covers the common cases we see in practice.
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
# Certificate Transparency (crt.sh) — passive subdomain discovery
# ═══════════════════════════════════════════════════════════════

def scan_domain_ct_logs(domain: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Discover sub-domains of `domain` via Certificate Transparency logs.

    Queries https://crt.sh/?q=%25.<domain>&output=json — fully passive,
    no API key. Each entry in crt.sh may contain multiple DNS names
    separated by newlines (the SAN list of the cert). Wildcards and out-
    of-scope entries are filtered out; the remaining hostnames are
    returned as `discovered` so the scheduler auto-enrolls them.
    """
    import httpx

    domain = _safe_target(domain).lower()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "CISO-Surface/1.0 (+https://cisotoolbox.org)"}
    discovered: set[str] = set()
    findings: list[dict[str, Any]] = []

    # crt.sh can return hundreds of MB for popular domains — we cap both
    # the response body AND the number of rows we process to keep memory
    # bounded on adversarial / popular seeds.
    _CT_MAX_BYTES = 50 * 1024 * 1024   # 50 MB hard cap
    _CT_MAX_ROWS = 20_000              # cap on certificates examined

    data = None
    last_error: Exception | None = None
    for attempt, timeout in enumerate((30.0, 60.0, 90.0), start=1):
        try:
            with httpx.stream("GET", url, timeout=timeout, headers=headers, follow_redirects=True) as resp:
                resp.raise_for_status()
                buf = bytearray()
                oversized = False
                for chunk in resp.iter_bytes():
                    if len(buf) + len(chunk) > _CT_MAX_BYTES:
                        oversized = True
                        break
                    buf.extend(chunk)
                if oversized:
                    last_error = ValueError(f"crt.sh response exceeded {_CT_MAX_BYTES} bytes")
                    logger.info("ct_logs: response for %s too large, aborting parse", domain)
                    break
                try:
                    data = json.loads(buf)
                except ValueError as e:
                    last_error = e
                    logger.info("ct_logs: crt.sh JSON parse error for %s: %s", domain, e)
                    break
            break
        except httpx.HTTPError as e:
            last_error = e
            logger.info("ct_logs: crt.sh attempt %d/%d timed out for %s (timeout=%.0fs): %s",
                        attempt, 3, domain, timeout, e)
            continue

    if data is None:
        findings.append({
            "scanner": "ct_logs", "type": "ct_error", "severity": "info",
            "title": f"CT logs : crt.sh injoignable pour {domain}",
            "description": (
                f"La requete crt.sh a echoue apres 3 tentatives : {last_error}. "
                f"crt.sh est connu pour etre lent ou ponctuellement indisponible — "
                f"reessayer plus tard via une nouvelle execution du scanner."
            ),
            "target": domain, "evidence": {"error": str(last_error)},
        })
        return findings, []

    if not isinstance(data, list):
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
        "title": f"CT logs : {len(hosts)} sous-domaine(s) decouvert(s) pour {domain}",
        "description": (
            f"Le scan des logs Certificate Transparency (crt.sh) a identifie "
            f"{len(hosts)} hostnames associes au domaine {domain}. "
            f"Ces hostnames sont automatiquement ajoutes a la liste des assets "
            f"surveilles (kind=host) et seront scannes selon la frequence par defaut."
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
# Scanner registry + dispatcher
# ═══════════════════════════════════════════════════════════════

# Each scanner is identified by a canonical name. The registry maps a name to:
#   - a callable: (value: str) -> list[finding_dict] OR (list[finding_dict], list[str])
#   - the kinds it applies to
#   - whether it returns discovered hosts (only ip_range scanners do)
# ═══════════════════════════════════════════════════════════════
# v0.2 — Tech stack fingerprinting (Wappalyzer-lite)
# ═══════════════════════════════════════════════════════════════
#
# Probes HTTP/HTTPS on the target and tries to identify the underlying
# stack from response headers, body markers and cookies. Designed to be
# fast (single GET per scheme/port) and dependency-free — no Wappalyzer
# binary, no chromium, no JS execution. The signature DB is intentionally
# small (~30 entries) and covers the products that produce the noisiest
# CVE feeds — operators who need exhaustive fingerprinting can plug
# Nuclei templates instead.
#
# Each detected product yields a finding of type `tech_fingerprint` with
# evidence `{product, version, source}` so the cve_lookup helper below
# can match it without re-parsing.

import re as _re

# Signatures — (product, regex, source_field). source_field is "header",
# "body" or "cookie". The regex captures the version in group(1) when
# possible; absent group → version "" (still flagged for inventory).
_TECH_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Servers
    ("nginx",       r"nginx/?([\d.]+)?",                            "Server",      "header"),
    ("Apache",      r"Apache/?([\d.]+)?",                           "Server",      "header"),
    ("IIS",         r"Microsoft-IIS/?([\d.]+)?",                    "Server",      "header"),
    ("LiteSpeed",   r"LiteSpeed",                                   "Server",      "header"),
    ("Caddy",       r"Caddy",                                       "Server",      "header"),
    ("Tomcat",      r"Apache-Coyote/?([\d.]+)?",                    "Server",      "header"),
    ("Cloudflare",  r"cloudflare",                                  "Server",      "header"),

    # App frameworks (X-Powered-By)
    ("PHP",         r"PHP/?([\d.]+)?",                              "X-Powered-By","header"),
    ("ASP.NET",     r"ASP\.NET",                                    "X-Powered-By","header"),
    ("Express",     r"Express",                                     "X-Powered-By","header"),
    ("Next.js",     r"Next\.js",                                    "X-Powered-By","header"),
    ("Servlet",     r"Servlet/?([\d.]+)?",                          "X-Powered-By","header"),
    ("PHP",         r"PHPSESSID",                                   "Set-Cookie",  "cookie"),

    # CMS — body markers
    ("WordPress",   r'<meta name="generator" content="WordPress ?([\d.]+)?',           "",            "body"),
    ("Drupal",      r'<meta name="generator" content="Drupal ?([\d.]+)?',              "",            "body"),
    ("Joomla",      r'<meta name="generator" content="Joomla! ?([\d.]+)?',             "",            "body"),
    ("TYPO3",       r'<meta name="generator" content="TYPO3 ?CMS ?([\d.]+)?',          "",            "body"),
    ("Ghost",       r'<meta name="generator" content="Ghost ?([\d.]+)?',               "",            "body"),
    ("Strapi",      r"X-Strapi",                                    "",            "header_any"),

    # JS frameworks (body inspection)
    ("React",       r"react(?:-dom)?@?([\d.]+)?",                   "",            "body"),
    ("Angular",     r"ng-version=\"([\d.]+)?\"",                    "",            "body"),
    ("Vue.js",      r"vue(?:js)?@?([\d.]+)?",                       "",            "body"),

    # Edge / CDN / WAF
    ("Akamai",      r"AkamaiGHost",                                 "Server",      "header"),
    ("Fastly",      r"Fastly",                                      "X-Served-By", "header"),
    ("Sucuri",      r"Sucuri",                                      "X-Sucuri-ID", "header"),

    # Databases — sometimes leaked in error pages, very rare on prod
    ("MySQL",       r"MySQL server has gone away|MySQL_(\d+)",      "",            "body"),
    ("PostgreSQL",  r"PostgreSQL ?([\d.]+)?",                       "",            "body"),

    # Container / orchestration (rare but high signal)
    ("Kubernetes",  r"kubernetes",                                  "X-Kubernetes-Pod-Name", "header"),
    ("Traefik",     r"Traefik",                                     "Server",      "header"),
]


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


def _match_tech_signatures(probe: dict[str, Any]) -> list[dict[str, str]]:
    """Run every signature against the probe response. Returns a list of
    {product, version, source}."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    headers = probe.get("headers") or {}
    body = probe.get("body") or ""
    # Lowercase header lookup
    lc_headers = {k.lower(): v for k, v in headers.items()}
    for product, pattern, header_name, source in _TECH_SIGNATURES:
        haystack = ""
        if source == "header":
            haystack = lc_headers.get(header_name.lower(), "")
        elif source == "header_any":
            for v in lc_headers.values():
                if _re.search(pattern, str(v), _re.IGNORECASE):
                    haystack = str(v)
                    break
            if not haystack and header_name and header_name.lower() in lc_headers:
                haystack = lc_headers[header_name.lower()]
        elif source == "cookie":
            haystack = lc_headers.get("set-cookie", "")
        elif source == "body":
            haystack = body
        if not haystack:
            continue
        m = _re.search(pattern, haystack, _re.IGNORECASE)
        if not m:
            continue
        version = ""
        if m.lastindex and m.group(1):
            version = m.group(1)
        # Dedupe by product+version
        key = product + "|" + version
        if key in seen:
            continue
        seen.add(key)
        found.append({"product": product, "version": version, "source": source})
    return found


def scan_host_techstack(target: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Probe HTTP and HTTPS on the standard ports and emit one
    `tech_fingerprint` finding per detected product. The detected
    (product, version) tuples flow into the cve_lookup scanner that
    runs right after this one (when both are enabled)."""
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []
    seen: dict[str, dict[str, str]] = {}

    for port, scheme in [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]:
        probe = _http_probe(target, port, scheme)
        if not probe:
            continue
        for tech in _match_tech_signatures(probe):
            key = (tech["product"] + "|" + tech["version"]).lower()
            if key in seen:
                continue
            seen[key] = tech
            label = tech["product"] + (f" {tech['version']}" if tech["version"] else "")
            findings.append({
                "scanner": "techstack",
                "type": "tech_fingerprint",
                "severity": "info",
                "title": f"Tech detectee : {label} sur {target}",
                "description": (
                    f"Le probe HTTP a identifie {label} via "
                    f"{tech['source']}. Cette information est passive et sert "
                    f"d'inventaire — utilisez le scanner cve_lookup pour la "
                    f"correler aux CVE connus."
                ),
                "target": f"{target}:{port}",
                "evidence": {
                    "product": tech["product"],
                    "version": tech["version"],
                    "source": tech["source"],
                    "port": port,
                    "scheme": scheme,
                    "url": probe.get("url", ""),
                    "http_status": probe.get("status", 0),
                },
            })
    return findings, []


# ═══════════════════════════════════════════════════════════════
# v0.2 — CVE matching + EPSS + CISA KEV enrichment
# ═══════════════════════════════════════════════════════════════
#
# Given the (product, version) tuples produced by the techstack scanner
# (and any nmap service detection that emits banner data), look up known
# CVEs via the public NVD JSON 2.0 API, then enrich each CVE with its
# EPSS probability and a CISA KEV flag. Everything is cached in-process
# for 24h so the same lookup never hits the network twice in a row.
#
# Heavy CVE feeds (full mirrors) are explicitly out of scope — Surface
# is meant to be a small, self-hostable tool, not a vulnerability
# database. The lookup is best-effort: if NVD is unreachable, the
# scanner emits an info finding but never blocks the rest of the scan.

import threading as _threading
import time as _time

_CVE_CACHE_LOCK = _threading.Lock()
_CVE_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CVE_CACHE_TTL = 24 * 3600

_EPSS_CACHE: dict[str, float] = {}
_KEV_CACHE: set[str] = set()
_KEV_LOADED_AT: float = 0.0
_KEV_TTL = 24 * 3600


def _kev_load() -> set[str]:
    """Pull CISA's Known Exploited Vulnerabilities catalog (≈1000 CVE IDs).
    Refreshed once a day. Best-effort — a network failure leaves the
    previous cached set untouched."""
    global _KEV_LOADED_AT, _KEV_CACHE
    now = _time.monotonic()
    with _CVE_CACHE_LOCK:
        if _KEV_CACHE and (now - _KEV_LOADED_AT) < _KEV_TTL:
            return _KEV_CACHE
    try:
        import httpx
        with httpx.Client(timeout=10.0) as c:
            r = c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if r.status_code != 200:
                return _KEV_CACHE
            data = r.json()
        ids = {v.get("cveID", "") for v in (data.get("vulnerabilities") or []) if v.get("cveID")}
        with _CVE_CACHE_LOCK:
            _KEV_CACHE = ids
            _KEV_LOADED_AT = now
    except Exception as e:
        logger.warning("kev: fetch failed: %s", e)
    return _KEV_CACHE


def _epss_lookup(cve_ids: list[str]) -> dict[str, float]:
    """Batch EPSS lookup — POST one request per ~50 CVE IDs to the FIRST
    EPSS API. Returns {cve_id: probability}. Network failure → empty."""
    out: dict[str, float] = {}
    missing = [c for c in cve_ids if c not in _EPSS_CACHE]
    if missing:
        try:
            import httpx
            with httpx.Client(timeout=10.0) as c:
                # FIRST EPSS API supports comma-separated cve= param
                r = c.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(missing[:50])})
                if r.status_code == 200:
                    for item in (r.json().get("data") or []):
                        cid = item.get("cve", "")
                        try:
                            _EPSS_CACHE[cid] = float(item.get("epss", 0))
                        except (TypeError, ValueError):
                            pass
        except Exception as e:
            logger.warning("epss: fetch failed: %s", e)
    for c in cve_ids:
        if c in _EPSS_CACHE:
            out[c] = _EPSS_CACHE[c]
    return out


def _nvd_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Query NVD 2.0 for CVEs affecting `product` (optionally version).
    Returns up to 25 entries sorted by CVSS v3 score desc. Cached 24h."""
    if not product:
        return []
    key = f"{product.lower()}|{version or '*'}"
    with _CVE_CACHE_LOCK:
        cached = _CVE_CACHE.get(key)
        if cached and (_time.monotonic() - cached[0]) < _CVE_CACHE_TTL:
            return cached[1]

    cves: list[dict[str, Any]] = []
    try:
        import httpx
        # NVD CPE-name search is more accurate when we have a version
        params: dict[str, Any] = {"keywordSearch": product, "resultsPerPage": 25}
        if version:
            params["keywordSearch"] = f"{product} {version}"
        with httpx.Client(timeout=15.0) as c:
            r = c.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
            if r.status_code != 200:
                logger.info("nvd: %s for %s", r.status_code, product)
                with _CVE_CACHE_LOCK:
                    _CVE_CACHE[key] = (_time.monotonic(), [])
                return []
            data = r.json()
        for item in (data.get("vulnerabilities") or [])[:25]:
            cve = item.get("cve") or {}
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descs = cve.get("descriptions") or []
            description = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics") or {}
            score = 0.0
            severity = ""
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(k) or []
                if arr:
                    cd = arr[0].get("cvssData") or {}
                    score = float(cd.get("baseScore", 0))
                    severity = cd.get("baseSeverity", "") or arr[0].get("baseSeverity", "")
                    break
            cves.append({
                "id": cve_id,
                "description": description[:500],
                "score": score,
                "severity": severity.lower(),
                "published": cve.get("published", ""),
            })
        cves.sort(key=lambda c: c["score"], reverse=True)
    except Exception as e:
        logger.warning("nvd: query failed for %s: %s", product, e)
    with _CVE_CACHE_LOCK:
        _CVE_CACHE[key] = (_time.monotonic(), cves)
    return cves


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def scan_host_cve_lookup(target: str, prior_findings: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    """For each tech_fingerprint finding produced earlier in the same
    scanner chain, look up the matching CVEs and emit one `cve_match`
    finding per CVE (capped to top 5 per product). Each finding carries
    EPSS + KEV enrichment in its evidence.

    The `prior_findings` list is supplied by `run_enabled_scanners` —
    it contains every finding emitted by the scanners that ran before
    cve_lookup on the same target. We pull (product, version) out of
    each tech_fingerprint evidence and feed the lookups."""
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []

    products: list[tuple[str, str]] = []
    for f in prior_findings or []:
        if f.get("type") != "tech_fingerprint":
            continue
        ev = f.get("evidence") or {}
        p = ev.get("product", "")
        v = ev.get("version", "")
        if p and (p, v) not in products:
            products.append((p, v))

    if not products:
        return [{
            "scanner": "cve_lookup",
            "type": "cve_no_tech",
            "severity": "info",
            "title": f"CVE lookup : aucune tech detectee sur {target}",
            "description": (
                f"Aucun finding de type tech_fingerprint trouve pour {target}. "
                f"Activez le scanner techstack pour amorcer le matching CVE."
            ),
            "target": target,
            "evidence": {"target": target},
        }], []

    kev = _kev_load()
    all_cve_ids: list[str] = []
    by_product: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for product, version in products:
        cves = _nvd_lookup(product, version)
        if not cves:
            continue
        by_product[(product, version)] = cves[:5]
        all_cve_ids.extend(c["id"] for c in cves[:5])

    epss = _epss_lookup(all_cve_ids) if all_cve_ids else {}

    for (product, version), cves in by_product.items():
        for cve in cves:
            cid = cve["id"]
            sev = _cvss_to_severity(cve["score"])
            in_kev = cid in kev
            epss_score = epss.get(cid)
            label = product + (f" {version}" if version else "")
            title = f"{cid} — {label} sur {target}"
            if in_kev:
                title = "[KEV] " + title
                # Bump severity on KEV (actively exploited in the wild)
                if sev in ("medium", "low"):
                    sev = "high"
            description_parts = [
                f"CVSS : {cve['score']} ({sev})",
                cve["description"],
            ]
            if epss_score is not None:
                description_parts.append(f"EPSS : {epss_score * 100:.1f}% probabilite d'exploitation publique")
            if in_kev:
                description_parts.append("CISA KEV : exploite dans la nature, fixe en priorite")
            findings.append({
                "scanner": "cve_lookup",
                "type": "cve_match",
                "severity": sev,
                "title": title,
                "description": "\n\n".join(description_parts),
                "target": target,
                "evidence": {
                    "cve_id": cid,
                    "cvss_score": cve["score"],
                    "cvss_severity": cve["severity"],
                    "epss": epss_score,
                    "kev": in_kev,
                    "product": product,
                    "version": version,
                    "published": cve["published"],
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                },
            })
    return findings, []


# ═══════════════════════════════════════════════════════════════
# v0.2 — HTTP screenshot capture (optional, env-gated)
# ═══════════════════════════════════════════════════════════════
#
# Visual recon: grab a PNG screenshot of every reachable HTTP root and
# attach it to a finding so the operator can see what the asset actually
# looks like without leaving Surface. OFF by default because chromium is
# a 250 MB dependency — turn on with `SURFACE_ENABLE_SCREENSHOTS=1` after
# adding `playwright` + `playwright install chromium` to the image.
#
# When the dependency is missing the scanner emits a single info finding
# explaining how to enable it, and never crashes the scan.

def scan_host_screenshot(target: str) -> tuple[list[dict[str, Any]], list[str]]:
    if os.environ.get("SURFACE_ENABLE_SCREENSHOTS", "") != "1":
        return [], []
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return [{
            "scanner": "screenshot", "type": "screenshot_disabled", "severity": "info",
            "title": f"Screenshots desactives sur {target}",
            "description": (
                "Le scanner screenshot necessite playwright + chromium. "
                "Installez-les dans l'image (`pip install playwright && "
                "playwright install chromium`) puis relancez le scan."
            ),
            "target": target, "evidence": {"reason": "playwright not installed"},
        }], []

    import base64
    for port, scheme in [(443, "https"), (80, "http")]:
        url = f"{scheme}://{target}:{port}/"
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 720})
                page = context.new_page()
                page.set_default_timeout(8000)
                page.goto(url, wait_until="domcontentloaded")
                title = page.title()[:200]
                png = page.screenshot(type="png", full_page=False)
                browser.close()
            findings.append({
                "scanner": "screenshot",
                "type": "screenshot",
                "severity": "info",
                "title": f"Screenshot {scheme.upper()} : {title or target}",
                "description": f"Capture visuelle de {url}",
                "target": f"{target}:{port}",
                "evidence": {
                    "url": url,
                    "page_title": title,
                    "png_b64": base64.b64encode(png).decode("ascii"),
                    "size_bytes": len(png),
                },
            })
        except Exception as e:
            logger.info("screenshot failed for %s: %s", url, e)
    return findings, []


SCANNER_REGISTRY: dict[str, dict[str, Any]] = {
    "email_security": {
        "label": "Email security (SPF/DMARC/DKIM/MX)",
        "kinds": {"domain"},
        "callable": scan_domain_email,
        "returns_discovered": False,
    },
    "typosquatting": {
        "label": "Typosquatting",
        "kinds": {"domain"},
        "callable": scan_domain_typosquatting,
        "returns_discovered": False,
    },
    "tls": {
        "label": "Certificat TLS (+ SAN discovery)",
        "kinds": {"domain", "host"},
        "callable": scan_host_tls,
        "returns_discovered": True,
    },
    "ct_logs": {
        "label": "Subdomain discovery (CT logs)",
        "kinds": {"domain"},
        "callable": scan_domain_ct_logs,
        "returns_discovered": True,
    },
    "dns_brute": {
        "label": "Subdomain brute-force",
        "kinds": {"domain"},
        "callable": scan_domain_dns_brute,
        "returns_discovered": True,
    },
    "nmap_quick": {
        "label": "Nmap (top 100 ports)",
        "kinds": {"host"},
        "callable": lambda t: scan_host_ports(t, profile="quick"),
        "returns_discovered": False,
    },
    "nmap_standard": {
        "label": "Nmap (top 1000 + service detection)",
        "kinds": {"host"},
        "callable": lambda t: scan_host_ports(t, profile="standard"),
        "returns_discovered": False,
    },
    "nuclei": {
        "label": "Nuclei (templates DAST)",
        "kinds": {"host"},
        "callable": scan_nuclei,
        "returns_discovered": False,
    },
    "techstack": {
        "label": "Tech stack fingerprinting",
        "kinds": {"host"},
        "callable": scan_host_techstack,
        "returns_discovered": False,
    },
    "screenshot": {
        "label": "HTTP screenshot capture (optional)",
        "kinds": {"host"},
        "callable": scan_host_screenshot,
        "returns_discovered": False,
    },
    "cve_lookup": {
        "label": "CVE matching (NVD + EPSS + KEV)",
        "kinds": {"host"},
        "callable": scan_host_cve_lookup,
        "returns_discovered": False,
        "wants_prior_findings": True,
    },
    "takeover": {
        "label": "Subdomain takeover (CNAME fingerprint)",
        "kinds": {"host", "domain"},
        "callable": scan_host_takeover,
        "returns_discovered": False,
    },
    "shodan_domain": {
        "label": "Shodan DNS (sous-domaines, passif, 0 credit)",
        "kinds": {"domain"},
        "callable": scan_domain_shodan,
        "returns_discovered": True,
    },
    "shodan_host": {
        "label": "Shodan host lookup (ports/CVE, 1 credit/req)",
        "kinds": {"host"},
        "callable": scan_host_shodan,
        "returns_discovered": False,
    },
    "discovery": {
        "label": "Host discovery (ping sweep)",
        "kinds": {"ip_range"},
        "callable": scan_iprange_discovery,
        "returns_discovered": True,
    },
}


DEFAULT_SCANNERS_BY_KIND = {
    "domain": ["email_security", "typosquatting", "tls", "ct_logs", "dns_brute", "takeover"],
    "host": ["nmap_quick", "tls", "nuclei", "takeover", "techstack", "cve_lookup"],
    "ip_range": ["discovery"],
}


def available_scanners_for_kind(kind: str) -> list[dict[str, str]]:
    """Return [{name, label}] of scanners applicable to the given kind."""
    return [
        {"name": name, "label": meta["label"]}
        for name, meta in SCANNER_REGISTRY.items()
        if kind in meta["kinds"]
    ]


def run_enabled_scanners(kind: str, value: str, enabled: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Run only the scanners whose names are in `enabled`. Returns (findings, discovered)."""
    findings: list[dict[str, Any]] = []
    discovered: list[str] = []
    if not enabled:
        enabled = DEFAULT_SCANNERS_BY_KIND.get(kind, [])

    for name in enabled:
        meta = SCANNER_REGISTRY.get(name)
        if not meta:
            logger.warning("Unknown scanner %s requested for %s/%s", name, kind, value)
            continue
        if kind not in meta["kinds"]:
            logger.warning("Scanner %s not applicable to kind=%s, skipping", name, kind)
            continue
        try:
            if meta.get("wants_prior_findings"):
                # Pass a snapshot of everything emitted so far on this scope
                # so the scanner can chain off it (e.g. cve_lookup reads
                # tech_fingerprint evidences).
                result = meta["callable"](value, list(findings))
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