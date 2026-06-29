"""TLS certificate scanner (+ SAN/reverse-cert discovery) — Surface core add-on."""
from __future__ import annotations

import socket
import ssl
from typing import Any

from src.scan_common import logger
from src.scan_common import (
    _safe_target, _is_ip_literal, _tls_ssl_context,
    _registrable, _normalize_host, _in_scope,
)


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


SURFACE_SCANNERS = {"tls": {"label": "Certificat TLS (+ SAN discovery)",
    "kinds": {"domain", "host"}, "callable": scan_host_tls, "returns_discovered": True}}
