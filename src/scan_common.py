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
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from typing import Any
from urllib.parse import urljoin, urlparse

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


# ═══════════════════════════════════════════════════════════════
# Outbound proxy for the scanners
# ═══════════════════════════════════════════════════════════════
# proxy_common exports the proxy (Pilot's, or the deployment's own) and the
# exception list into HTTP(S)_PROXY / NO_PROXY, normalized. A scanner reaching
# the scanned target follows it, except for a target in the exceptions. The
# scanners connect to the IP locked at validation time, so the exceptions are
# matched here, on the name and on that IP: httpx alone would only see the IP.

def proxy_exceptions() -> list[str]:
    """NO_PROXY, one host per entry, as the scanners read it: lower case, the
    ``:port`` dropped (a scanner reaches several ports, an excluded host must
    not reach the proxy on any of them), IPv6 brackets dropped, and ``.x`` or
    ``*.x`` read as ``x`` (a deployment's own NO_PROXY is not normalized)."""
    out = []
    for entry in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(","):
        entry = entry.strip().lower()
        if entry.startswith("[") and "]" in entry:
            entry = entry[1:entry.index("]")]
        elif entry.count(":") == 1 and entry.rpartition(":")[2].isdigit():
            entry = entry.rpartition(":")[0]
        entry = entry[2:] if entry.startswith("*.") else entry[1:] if entry.startswith(".") else entry
        if entry:
            out.append(entry)
    return out


def bypasses_proxy(host: str, ip: str | None = None) -> bool:
    """Whether NO_PROXY exempts this target: ``*``, its exact IP (the name or
    the locked ``ip``), an IPv4 range the deployment set, or a domain that is
    the name or one of its parents (entries read by ``proxy_exceptions``). A
    range given as the target (discovery) is exempt when a range of NO_PROXY
    contains it."""
    name = (host or "").strip().lower().rstrip(".").strip("[]")
    addresses = []
    for candidate in (ip, name):
        try:
            addresses.append(ipaddress.ip_network((candidate or "").strip("[]"), strict=False))
        except ValueError:
            pass
    for entry in proxy_exceptions():
        if entry == "*":
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            if name == entry or name.endswith("." + entry):
                return True
            continue
        if any(a.subnet_of(network) for a in addresses if a.version == network.version):
            return True
    return False


def _proxy_for(scheme: str) -> str:
    """The proxy the environment sets for a scheme, ALL_PROXY as fallback."""
    proxies = urllib.request.getproxies_environment()
    return proxies.get(scheme) or proxies.get("all") or ""


def _warn_unproxied(scanner: str, target: str) -> None:
    """Log that a raw-socket scanner reaches ``target`` directly although a
    proxy applies to it: an HTTP proxy carries HTTP, not port scans or TLS
    handshakes (nmap's --proxies is applied by nsock to NSE and -sV only)."""
    if (_proxy_for("https") or _proxy_for("http")) and not bypasses_proxy(target, resolve_first_ip(target)):
        logger.warning("%s: an outbound proxy is set, but %s cannot use it: "
                       "it reaches %s directly", scanner, scanner, target)


def target_request(target: str, locked_ip: str | None, scheme: str,
                   port: int | None = None) -> tuple[str, dict[str, str], dict[str, str]]:
    """The base URL (no trailing slash), headers and request extensions of a
    scanner reaching ``target``, validated at ``locked_ip``. Directly it
    connects to the locked IP (DNS rebinding), the name in ``Host`` (with a
    port that is not the scheme's default) and, on https, as TLS SNI: a host
    that picks its certificate or vhost by SNI answers as for the name.
    Through the proxy it names the target: the proxy resolves it, a proxy
    filtering by name accepts it, and a forwarded plain-HTTP request keeps
    the scanned vhost (a proxy rewrites ``Host`` from the URL)."""
    proxied = bool(_proxy_for(scheme)) and not bypasses_proxy(target, locked_ip)
    host = target if proxied or not locked_ip else locked_ip
    bare = host.strip("[]")  # a target may come bracketed
    netloc = f"[{bare}]" if ":" in bare else bare
    netloc = f"{netloc}:{port}" if port else netloc
    base = f"{scheme}://{netloc}"
    if host == target:
        return base, {}, {}
    default = {"https": 443, "http": 80}.get(scheme)
    headers = {"Host": target if port in (None, default) else f"{target}:{port}"}
    sni = scheme == "https" and not _is_ip_literal(target)  # an address is no server name
    return base, headers, ({"sni_hostname": target} if sni else {})


# A target's ``config.follow_redirects``: whether the page scanners follow its
# root's redirects, none, those on its registrable domain, or all of them.
FOLLOW_REDIRECT_MODES = ("none", "same_domain", "all")
_MAX_REDIRECTS = 5


def follow_redirects_mode(asset_config: dict | None) -> str:
    """The target's redirect policy; ``same_domain`` when unset or unknown."""
    mode = (asset_config or {}).get("follow_redirects")
    return mode if mode in FOLLOW_REDIRECT_MODES else "same_domain"


def fetch_page(stack, clients: dict, open_client, target: str, locked_ip: str,
               mode: str, headers: dict[str, str]):
    """GET the target's root, then its redirects as ``mode`` allows: the page
    a browser would show. httpx never follows a redirect itself (its target
    is not validated): each hop is validated as a target is
    (``_resolve_safe_target``, once per host), pinned to its address with
    ``target_request``, and reached by a client of its own host
    (``open_client(host, ip)``, entered on ``stack``, kept in ``clients`` as
    {host: (client, ip)}) for that host's proxy routing. Only http(s), at
    most ``_MAX_REDIRECTS`` hops, no URL twice, no host of the run's scan
    blocklist (``scan_exclusions``). A redirect not followed, or followed to
    a hop that fails, is the page; the root failing raises. Returns
    (response, host, URL by name without its query, stop): ``stop`` is None,
    or, when the page
    is a redirect not followed, (where it led, without its query; why)."""
    import httpx

    name = target.lower().strip("[]")
    target_reg = None if _is_ip_literal(name) else _registrable(name) or name
    host, ip, scheme, port, path = name, locked_ip, "https", None, "/"
    visited: set[str] = set()
    previous = None

    def without_query(u: str) -> str:
        # The page's URL, and where a redirect led in a finding: neither its
        # query nor its credentials (user:password@), as either may carry a
        # secret.
        u = u.split("?", 1)[0].split("#", 1)[0]
        scheme, sep, rest = u.partition("://")
        if sep:
            netloc, slash, tail = rest.partition("/")
            u = scheme + sep + netloc.rsplit("@", 1)[-1] + slash + tail
        return u

    while True:
        url = target_request(host, None, scheme, port)[0] + path
        try:
            if host not in clients:
                clients[host] = (stack.enter_context(open_client(target if host == name else host, ip)), ip)
            client, ip = clients[host]
            base, host_hdr, ext = target_request(host, ip, scheme, port)
            # httpx builds the redirect request even when not following it,
            # and refuses a Location it cannot parse (javascript:, a bad
            # port, a control character: InvalidURL or RemoteProtocolError).
            # Once a redirect came in (the hook saw its headers; its body is
            # not needed), that answer is still the page. Any other error,
            # a body that fails to arrive included, is the request failing.
            answers: list = []
            client.event_hooks["response"].append(answers.append)
            try:
                response = client.get(base + path, headers={**headers, **host_hdr}, extensions=ext)
            except (httpx.InvalidURL, httpx.RemoteProtocolError):
                if not (answers and answers[-1].is_redirect):
                    raise
                response = answers[-1]
            finally:
                client.event_hooks["response"].remove(answers.append)
        except Exception as e:
            if previous is None:
                raise
            logger.info("scan of %s: redirect to %s not followed (%s)", target, url, type(e).__name__)
            return (*previous, (without_query(url)[:300], f"the redirect target failed ({type(e).__name__})"))
        page = response, host, without_query(url)
        visited.add(url)
        if not response.is_redirect:
            return (*page, None)
        location = response.headers.get("location", "")
        try:
            location = urljoin(url, location)  # raises on a broken IPv6 host
            if mode == "none":
                raise ValueError("the target's setting is not to follow redirects")
            nxt = urlparse(location)
            nxt_host, nxt_port = (nxt.hostname or ""), nxt.port  # an invalid port raises
            if nxt.scheme not in ("http", "https") or not nxt_host:
                raise ValueError("not an http(s) URL")
            if nxt_port == {"https": 443, "http": 80}[nxt.scheme]:
                nxt_port = None
            nxt_path = ((nxt.path or "/") + (f";{nxt.params}" if nxt.params else "")
                        + (f"?{nxt.query}" if nxt.query else ""))
            nxt_url = target_request(nxt_host, None, nxt.scheme, nxt_port)[0] + nxt_path
            if mode == "same_domain" and nxt_host != name and (
                    target_reg is None or (_registrable(nxt_host) or nxt_host) != target_reg):
                raise ValueError("off the target's domain")
            if nxt_url in visited or len(visited) > _MAX_REDIRECTS:
                raise ValueError("redirect loop or too many redirects")
            if nxt_host in clients:
                nxt_ip = clients[nxt_host][1]
            else:
                try:
                    nxt_ip = _resolve_safe_target(nxt_host)[0]
                except ValueError as e:
                    logger.info("scan of %s: redirect host %s refused (%s)", target, nxt_host, e)
                    raise ValueError("not a host the scanner may reach (internal or unresolvable)")
            if _excluded_host(nxt_host, nxt_ip):
                raise ValueError("host in the scan blocklist")
        except ValueError as e:
            logger.info("scan of %s: redirect from %s not followed (%s)", target, url, e)
            return (*page, (without_query(location)[:300], str(e)))
        previous = page
        host, ip, scheme, port, path = nxt_host, nxt_ip, nxt.scheme, nxt_port, nxt_path


# Per thread: the proxy failures and the answers of the scanned targets, by
# origin of the target (scheme, port): {target: {origin: (proxy host, cause)}}
# and {target: {origins answered}}, plus the open ``alternative_origins``.
_PROXY_STATE = threading.local()


def _proxy_sink() -> tuple[dict, dict]:
    groups = getattr(_PROXY_STATE, "groups", None)
    if groups:
        return groups[-1]
    if not hasattr(_PROXY_STATE, "failures"):
        _PROXY_STATE.failures, _PROXY_STATE.answered = {}, {}
    return _PROXY_STATE.failures, _PROXY_STATE.answered


def _record_proxy_outcome(target: str, failures: dict, answered: set) -> None:
    # The outcome of a client (or a group) comes after what the sink holds:
    # an origin it reached clears an earlier failure there. (Which origins
    # answered only matters among alternatives: one is enough.)
    sink_failures, sink_answered = _proxy_sink()
    for origin in answered:
        sink_failures.get(target, {}).pop(origin, None)
        sink_answered.setdefault(target, set()).add(origin)
    for origin, failure in failures.items():
        sink_failures.setdefault(target, {}).setdefault(origin, failure)


@contextmanager
def alternative_origins():
    """Requests made inside reach the same content by several origins of a
    target (https, then http as a fallback): one origin answering is enough,
    the proxy failures of the others are dropped. All of them failing is
    the target's failure as usual."""
    group: tuple[dict, dict] = ({}, {})
    if not getattr(_PROXY_STATE, "groups", None):
        _PROXY_STATE.groups = []
    _PROXY_STATE.groups.append(group)
    try:
        yield
    finally:
        _PROXY_STATE.groups.pop()
        failures, answered = group
        for target in set(failures) | set(answered):
            _record_proxy_outcome(target, {} if answered.get(target) else failures.get(target, {}),
                                  answered.get(target, set()))


def take_proxy_failures() -> list[tuple[str, str, str, str]]:
    """The targets ``scan_client`` could not reach through the proxy on this
    thread since the last call, as (target, proxy host, cause, origin): an
    origin (scheme, port) of the target that the proxy failed and that no
    request reached afterwards (an answer before it, such as a probe of the
    root, does not show the later requests went through); one per target,
    its first such origin. An answer on another origin does not clear it (a
    script on another port is not the root), except among
    ``alternative_origins``. The dispatcher calls it
    around each scanner and turns them into a finding of that scanner."""
    failures = getattr(_PROXY_STATE, "failures", {})
    _PROXY_STATE.failures, _PROXY_STATE.answered = {}, {}
    out = []
    for target, by_origin in failures.items():
        if by_origin:
            origin, (proxy_host, cause) = next(iter(by_origin.items()))
            out.append((target, proxy_host, cause, origin))
    return out


@contextmanager
def scan_client(host: str, ip: str | None = None, **kwargs: Any):
    """The httpx client of a scanner that reaches the scanned target ``host``
    (validated at ``ip``, the locked address; ``target_request`` builds what to
    ask for): direct when the target is a proxy exception, through the
    outbound proxy otherwise. The scanners swallow request errors, so each
    one is logged here, and a proxy that refuses, cannot be reached or does
    not answer is recorded for the dispatcher (``take_proxy_failures``),
    which reports it: without it the scan reads as a clean one."""
    import httpx

    direct = bypasses_proxy(host, ip)

    def origin(url) -> str:
        # The target's origin the request reached, whether the URL names the
        # target or its locked address.
        default = {"https": 443, "http": 80}.get(url.scheme)
        bare = host.strip("[]")
        netloc = f"[{bare}]" if ":" in bare else bare
        return f"{url.scheme}://{netloc}" + (f":{url.port}" if url.port and url.port != default else "")

    class _Client(httpx.Client):
        def __init__(self, **kw):
            super().__init__(**kw)
            # The origins failed since their last answer (proxy host, cause,
            # the first of the run), and the origins that answered.
            self.failures: dict[str, tuple[str, str]] = {}
            self.answered: set[str] = set()

        def _warn(self, request, cause: str) -> None:
            proxy = "" if direct else _proxy_for(request.url.scheme)
            if proxy:
                self.failures.setdefault(origin(request.url), (urlparse(proxy).hostname or "?", cause))

        def send(self, request, **kw):
            stage = {"connect": False, "tls": False}
            outer = request.extensions.get("trace")

            def trace(event: str, info: dict) -> None:
                # httpcore: a new connection, then (through the proxy) the
                # CONNECT on it, then the tunnel's TLS handshake.
                if event == "connection.connect_tcp.started":
                    stage["connect"] = True
                elif event == "proxy.start_tls.started":
                    stage["tls"] = True
                if outer:
                    outer(event, info)

            request.extensions["trace"] = trace
            try:
                response = super().send(request, **kw)
            except httpx.TransportError as e:
                cause = f"ProxyError: {e}" if isinstance(e, httpx.ProxyError) else type(e).__name__
                proxied = not direct and _proxy_for(request.url.scheme)
                # Once the proxy accepted the CONNECT (the TLS handshake with
                # the target started) or on a tunnel already open, the
                # connection is the target's: a failed handshake, a read, a
                # write, a slow answer are its own. Reaching the proxy, its
                # answer to the CONNECT, and plain HTTP (forwarded) are the
                # proxy's. A connection error only arises on a new connection.
                if isinstance(e, (httpx.ProxyError, httpx.PoolTimeout)) or request.url.scheme != "https":
                    tunnel = False
                elif stage["tls"] or stage["connect"]:
                    tunnel = stage["tls"]
                else:
                    tunnel = not isinstance(e, (httpx.ConnectError, httpx.ConnectTimeout))
                logger.info("scan of %s: %s %s%s failed (%s)", host, request.method, request.url.scheme,
                            " through the outbound proxy" if proxied else "", cause)
                if not tunnel:
                    self._warn(request, cause)
                raise
            # Plain HTTP is forwarded, so a proxy refusing it answers in the
            # target's place: a 407 is the proxy's, never the target's page.
            # (https goes through a CONNECT tunnel: a refused CONNECT raises,
            # and a 407 read inside the tunnel is the target's.)
            if (response.status_code == 407 and request.url.scheme == "http"
                    and not direct and _proxy_for("http")):
                response.close()
                self._warn(request, "HTTP 407")
                raise httpx.ProxyError("the outbound proxy requires authentication", request=request)
            # A gateway error on forwarded plain HTTP is most likely the
            # proxy's own: it does not show that the target was reached, nor
            # hide a refused CONNECT on https.
            if not (response.status_code in (502, 503, 504) and request.url.scheme == "http"
                    and not direct and _proxy_for("http")):
                self.failures.pop(origin(request.url), None)
                self.answered.add(origin(request.url))
            return response

    with _Client(trust_env=not direct, **kwargs) as client:
        try:
            yield client
        finally:
            _record_proxy_outcome(host, client.failures, client.answered)


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


# The scan blocklist (ScanExclusion values) of the run, set by
# `run_enabled_scanners` like the stealth flag: the scanned asset is checked
# before the run, a host the run reaches on its own (a redirect hop) here.
_EXCLUSIONS_CTX = threading.local()


def scan_exclusions() -> list[str]:
    return list(getattr(_EXCLUSIONS_CTX, "values", None) or [])


def _excluded_host(host: str, ip: str | None) -> bool:
    exclusions = scan_exclusions()
    if not exclusions:
        return False
    from src.models import is_excluded  # models pulls SQLAlchemy: not at import
    return is_excluded([host, ip or ""], exclusions)


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
