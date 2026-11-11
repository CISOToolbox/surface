"""Keys a finding is matched to the monitored assets on (FEAT-69).

Scanners name what they found differently: nmap and discovery put the
resolved IP in `target` (the hostname only survives in evidence.hostname),
tls/headers/quick-scan put the hostname, connectors an opaque stable target
with the host in the evidence. A finding therefore belongs to an asset
through ANY of:

    match_host        the target's host part, minus a trailing :port
                      (the server, for a share path)
    match_share       the server of the target read as a share path
    match_evhost      evidence.hostname, else evidence.host
    match_evaddr      evidence.address
    match_host_ip4    match_host as an IPv4 integer, for range lookups
    match_evaddr_ip4  match_evaddr as an IPv4 integer

All lower-cased. They depend on the finding alone (target and evidence), so
they are computed when the finding is written and never go stale when an
asset is added, renamed or resolves to another IP: the asset side is matched
at query time (src/finding_assets.py).

Pure functions, no database: the migration that fills existing rows and the
model's write hook both call `match_keys`.
"""
from __future__ import annotations

import re
from typing import Any

# Width of the key columns, the same as Finding.target. A longer key cannot
# equal an asset value (bounded the same way) and is cut to fit the column.
KEY_LEN = 500

_PORT = re.compile(r"^(.*):([0-9]+)\Z")
_SHARE_PREFIX = re.compile(r"^(\\\\|//|smb://)", re.I)
_PARSE_INT = re.compile(r"^\s*([+-]?[0-9]+)")


def share_hostname(value: str) -> str:
    """The server of a share path: `\\\\srv\\share`, `//srv/share`,
    `smb://srv/share` and `srv/share` all give `srv`."""
    v = (value or "").strip()
    v = re.sub(r"^smb://", "", v, flags=re.I)
    v = re.sub(r"^[\\/]+", "", v).replace("\\", "/")
    i = v.find("/")
    return (v[:i] if i >= 0 else v).lower()


def target_host_part(target: str) -> str:
    """Host/IP part of a target, minus a trailing :port, lower-cased:
    `93.184.216.34:443` gives `93.184.216.34`, `host.tld:8080` `host.tld`."""
    t = (target or "").strip()
    if not t:
        return ""
    if _SHARE_PREFIX.match(t):
        return share_hostname(t)
    m = _PORT.match(t)
    return (m.group(1) if m else t).lower()


def ip4_int(value: str) -> int | None:
    """A dotted IPv4 address as an integer; None for anything else (leading
    zeros, spaces and out-of-range octets included)."""
    parts = (value or "").split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not p.isascii() or not p.isdigit() or str(int(p)) != p or int(p) > 255:
            return None
        n = n * 256 + int(p)
    return n


def cidr_bounds(cidr: str) -> tuple[int, int] | None:
    """First and last address of an IPv4 range `a.b.c.d/n`; None when the
    value is not one."""
    if not cidr or "/" not in cidr:
        return None
    parts = cidr.split("/")
    m = _PARSE_INT.match(parts[1])
    if not m:
        return None
    bits = int(m.group(1))
    if bits < 0 or bits > 32:
        return None
    net = ip4_int(parts[0])
    if net is None:
        return None
    mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    low = net & mask
    return low, low | (~mask & 0xFFFFFFFF)


def _ev_text(evidence: dict[str, Any], *names: str) -> str:
    for name in names:
        v = evidence.get(name)
        if isinstance(v, str) and v:
            return v.lower()
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v:
            return str(v).lower()
    return ""


def match_keys(target: str | None, evidence: dict[str, Any] | None) -> dict[str, Any]:
    """The match columns of a finding, keyed by column name."""
    ev = evidence if isinstance(evidence, dict) else {}
    host = target_host_part(target or "")[:KEY_LEN]
    evaddr = _ev_text(ev, "address")[:KEY_LEN]
    return {
        "match_host": host,
        "match_share": share_hostname(target or "")[:KEY_LEN],
        "match_evhost": _ev_text(ev, "hostname", "host")[:KEY_LEN],
        "match_evaddr": evaddr,
        "match_host_ip4": ip4_int(host),
        "match_evaddr_ip4": ip4_int(evaddr),
    }
