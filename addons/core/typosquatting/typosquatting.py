"""Typosquatting / lookalike domain monitoring — Surface core add-on (FEAT-23).

Generates lookalike permutations with **dnstwist** (homoglyph, bitsquatting,
hyphenation, TLD-swap, …; falls back to a small built-in generator if dnstwist
is unavailable), then flags a lookalike as active by:
  • DNS registration (an A record resolves), and/or
  • Certificate Transparency — for the highest-risk permutation classes only,
    a cert issued on the lookalike (an early phishing-prep signal, often before
    any A record exists).

Emits **one finding per detected lookalike** (`type=typosquat_domain`,
`target=<lookalike>`) so the dedup engine (`<scanner>|<type>|<target>`) surfaces
NEW lookalikes as `new` on each scheduled scan and closes vanished ones — i.e.
continuous monitoring of a domain declared with surveillance. A `typosquat_summary`
finding carries the per-domain count for the dashboard.

Config (per monitored asset, `asset.config`):
  typosquat_max_variants (int, def 80) — permutations generated per scan
  typosquat_use_ct       (bool, def True) — enable the CT lookups
  typosquat_max_ct       (int, def 40) — cap on crt.sh requests per scan
"""
from __future__ import annotations

import json
import socket
import time
from typing import Any
from urllib.parse import quote

from src.scan_common import _safe_target, logger

# Permutation classes that justify a (rate-limited) CT lookup — the
# highest-confidence impersonation vectors. Kept small to bound crt.sh load.
_CT_HIGH_RISK = {"homoglyph", "replacement", "tld-swap", "bitsquatting", "addition", "hyphenation"}

# Permutation classes emitted in full before the round-robin cap kicks in:
# few in number, highest-confidence impersonation, must never be dropped.
_PRIORITY_CLASSES = ("tld-swap",)

_DEF_MAX_VARIANTS = 80
_DEF_MAX_CT = 40
_DEF_USE_CT = True

_CT_HEADERS = {"User-Agent": "CISO-Surface/1.0 (+https://cisotoolbox.org)"}


# ── Built-in fallback generator (used only if dnstwist is unavailable) ──
_QWERTY_NEIGHBORS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "sfcxer", "e": "wrsdf",
    "f": "dgcvrt", "g": "fhbvty", "h": "gjbnyu", "i": "ujkol", "j": "hknmui",
    "k": "jlmio", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}
_EXTRA_TLDS = ["com", "net", "org", "fr", "io", "co", "info", "biz", "eu", "app", "dev", "xyz"]


def _builtin_permutations(domain: str) -> list[tuple[str, str]]:
    """[(permuted_domain, class), …] — omission/transposition/qwerty/TLD."""
    if "." not in domain:
        return []
    parts = domain.split(".")
    sld, tld = parts[0], ".".join(parts[1:])
    out: dict[str, str] = {}
    for i in range(len(sld)):
        out[sld[:i] + sld[i + 1:] + "." + tld] = "omission"
    for i in range(len(sld) - 1):
        out[sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:] + "." + tld] = "transposition"
    for i, ch in enumerate(sld):
        for n in _QWERTY_NEIGHBORS.get(ch, ""):
            out[sld[:i] + n + sld[i + 1:] + "." + tld] = "replacement"
    for alt in _EXTRA_TLDS:
        if alt != tld:
            out[sld + "." + alt] = "tld-swap"
    out.pop(domain, None)
    return list(out.items())


def _seeds_for(domain: str) -> list[str]:
    """Seeds fed to dnstwist. dnstwist applies ONE transform per seed, so a
    hyphenated domain also gets a de-hyphenated seed — otherwise double
    mutations (drop the hyphen AND swap TLD/typo, e.g. ``acme-corp.example`` →
    ``acmecorp.example``) are never generated."""
    seeds = [domain]
    parts = domain.split(".")
    sld, tld = parts[0], ".".join(parts[1:])
    if "-" in sld and tld:
        dehyphen = sld.replace("-", "") + "." + tld
        if dehyphen != domain:
            seeds.append(dehyphen)
    return seeds


def _dnstwist_permutations(domain: str, max_variants: int) -> list[tuple[str, str]]:
    """[(permuted_domain, fuzzer_class), …] via dnstwist; [] if unavailable.

    A ``tld_dictionary`` is passed so dnstwist actually emits TLD-swaps (same
    name, different extension) — its ``tld`` fuzzer is a no-op without one, so
    a primary typosquat vector (``…​.net`` / ``.fr`` / …) was otherwise missed."""
    try:
        import dnstwist
    except Exception:
        return []
    try:
        seeds = _seeds_for(domain)
        raw: list[dict] = []
        for seed in seeds:
            try:
                fuzz = dnstwist.Fuzzer(seed, tld_dictionary=_EXTRA_TLDS)
            except TypeError:  # older dnstwist without the kwarg
                fuzz = dnstwist.Fuzzer(seed)
            fuzz.generate()
            got = getattr(fuzz, "domains", None)
            if got is None and hasattr(fuzz, "permutations"):
                got = fuzz.permutations()
            raw.extend(got or [])
        # Bucket by permutation class. Only the monitored domain itself is
        # excluded; the de-hyphenated seed (e.g. acmecorp.example) IS a
        # legitimate lookalike we want to keep.
        by_class: dict[str, list[str]] = {}
        for d in raw:
            dom = (d.get("domain") or d.get("domain-name") or "").lower()
            klass = d.get("fuzzer", "")
            if not dom or dom == domain or klass in ("*original", "original"):
                continue
            by_class.setdefault(klass, []).append(dom)
        out: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _emit(dom: str, klass: str) -> bool:
            if dom in seen:
                return len(out) >= max_variants
            seen.add(dom)
            out.append((dom, klass))
            return len(out) >= max_variants

        # The de-hyphenated exact name (extra seed, e.g. acmecorp.example) is a
        # top-value lookalike but sits deep in the omission bucket — guarantee
        # it, else the cap drops the exact brand-without-hyphen.
        for seed in seeds[1:]:
            if seed != domain and _emit(seed, "hyphen-removal"):
                return out
        # TLD-swaps (same name, other extension) are few — bounded by the seed
        # count × len(_EXTRA_TLDS) — and the highest-value brand-impersonation
        # vector, so emit them ALL first: the cap must never drop a lookalike
        # like <brand>.net / <brand>.fr. Then round-robin the remaining classes
        # so a huge class (homoglyph easily yields 1000+) can't crowd them out.
        for klass in _PRIORITY_CLASSES:
            for dom in by_class.pop(klass, []):
                if _emit(dom, klass):
                    return out
        while len(out) < max_variants and any(by_class.values()):
            for klass in list(by_class.keys()):
                bucket = by_class[klass]
                if not bucket:
                    continue
                if _emit(bucket.pop(0), klass):
                    break
        return out
    except Exception as e:  # noqa: BLE001
        logger.info("typosquatting: dnstwist failed for %s: %s", domain, e)
        return []


def _is_registered(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False


def _crt_sh_cert_count(domain: str, timeout: float = 20.0) -> int | None:
    """Number of CT certificates seen for an exact lookalike (None on error,
    0 if none). crt.sh is a fixed external host; the lookalike is only a query
    parameter, so there is no SSRF surface here."""
    import httpx
    url = "https://crt.sh/?q=" + quote(domain, safe="") + "&output=json"
    try:
        r = httpx.get(url, timeout=timeout, headers=_CT_HEADERS, follow_redirects=True)
        if r.status_code != 200:
            return None
        body = r.text.strip()
        if not body:
            return 0
        data = json.loads(body)
        return len(data) if isinstance(data, list) else 0
    except Exception:  # noqa: BLE001
        return None


def scan_domain_typosquatting(domain: str, config: dict | None = None) -> list[dict[str, Any]]:
    """Generate lookalikes (dnstwist) and flag the active ones via DNS + CT."""
    config = config or {}
    domain = _safe_target(domain).lower()
    if "." not in domain:
        return []
    max_variants = max(1, min(int(config.get("typosquat_max_variants", _DEF_MAX_VARIANTS)), 500))
    use_ct = bool(config.get("typosquat_use_ct", _DEF_USE_CT))
    max_ct = max(0, min(int(config.get("typosquat_max_ct", _DEF_MAX_CT)), 200))

    perms = _dnstwist_permutations(domain, max_variants)
    engine = "dnstwist"
    if not perms:
        perms = _builtin_permutations(domain)[:max_variants]
        engine = "builtin"

    findings: list[dict[str, Any]] = []
    active: list[str] = []
    ct_done = 0

    for perm, klass in perms:
        registered = _is_registered(perm)
        ct_hits: int | None = None
        if use_ct and ct_done < max_ct and klass in _CT_HIGH_RISK:
            ct_hits = _crt_sh_cert_count(perm)
            ct_done += 1
            time.sleep(0.3)  # throttle crt.sh
        method = []
        if registered:
            method.append("dns")
        if ct_hits:
            method.append("ct")
        if not method:
            continue
        active.append(perm)
        # One finding per lookalike → unique dedup key, so a NEW lookalike is
        # surfaced as `new` and a vanished one is closed `fixed`.
        findings.append({
            "scanner": "typosquatting", "type": "typosquat_domain",
            "severity": "high" if "ct" in method else "medium",
            "title": f"Active lookalike domain: {perm}",
            "description": (
                f"Variant resembling {domain} (class: {klass}).\n"
                f"Detection: {', '.join(method)}"
                + (f" - {ct_hits} certificate(s) in Certificate Transparency" if ct_hits else "")
                + ".\nRisk: phishing, brand impersonation, malicious redirection."
            ),
            "target": perm,
            "evidence": {
                "original": domain, "lookalike": perm, "class": klass,
                "method": method, "ct_certs": ct_hits, "engine": engine,
            },
        })

    findings.append({
        "scanner": "typosquatting", "type": "typosquat_summary", "severity": "info",
        "title": (f"{len(active)} active lookalike(s) for {domain}"
                  if active else f"No active lookalike for {domain}"),
        "description": (
            f"{len(perms)} permutations generated ({engine}), {ct_done} checked "
            f"in Certificate Transparency; {len(active)} active."
        ),
        "target": domain,
        "evidence": {
            "original": domain, "engine": engine, "permutations": len(perms),
            "ct_checked": ct_done, "active_sample": active[:50],
        },
    })
    return findings


SURFACE_SCANNERS = {"typosquatting": {"label": "Typosquatting",
    "kinds": {"domain"}, "callable": scan_domain_typosquatting,
    "returns_discovered": False, "wants_config": True}}
