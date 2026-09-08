"""FEAT-37 — Microsoft Defender for Endpoint connector.

Imports the vulnerabilities reported machine by machine, creates one host per
machine, and lets the connector engine close what has left the feed.

**What the API allows, and what it does not.** Defender exposes no exception
or false-positive field: the documentation is explicit, *"Exceptions are
currently only supported in the Microsoft Defender portal, and not via public
API"*. But a CVE put under exception **leaves the inventory** — exactly like a
fixed CVE. The feature's two requirements (do not report what was excepted;
close what was fixed) are therefore handled by a single mechanism: reconciling
what disappeared. There is no "false positives" connector to write.

The price: "fixed" cannot be told apart from "excepted". Hence
``closed_upstream``, which says what is known and nothing more.

**Recommendations, however, carry their exception.** ``GET /api/recommendations``
exposes a ``status`` field the portal moves away from ``Active`` when an
exception is set. An excepted recommendation can therefore be closed **with
its motive** — which a CVE does not allow. They are returned in ``excepted``
so the engine writes the motive into the closure note (criterion 10 of the
spec; the first delivery dropped them silently and lost the motive).

> The exact values of that field are undocumented: the portal shows "Full
> exception" and "Partial exception", the API-side form must be read off a
> real tenant. The condition below treats everything that is not ``Active``
> as an exception, which is the safe behaviour: at worst a recommendation is
> closed wrongly and reopens on the next feed.

**Host attachment (the first delivery's blind spot).** The finding ``target``
is the stable identity ``machineId|cveId|productName`` — it survives DNS
renames and product upgrades. Attachment to a host card is carried by
``evidence.hostname`` / ``evidence.address``: the frontend's
``_findingMatchesAsset`` matches those against the asset's value and cached
``resolved_ip``. The first delivery put neither in evidence, so every host
card was empty.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("surface-backend")

_AUTH = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_API = "https://api.securitycenter.microsoft.com/api"
_SCOPE = "https://api.securitycenter.microsoft.com/.default"

# $top caps at 10 000 API-side. We paginate shorter: a huge page that fails
# costs the whole batch, and a several-thousand-machine fleet fits memory
# better in slices.
_PAGE = 2000
_TIMEOUT = 60.0
# Bounded retries on throttling/transient errors. Retry-After is honoured but
# capped: a poisoned header must not park the import for an hour.
_MAX_RETRIES = 5
_MAX_RETRY_WAIT = 120.0
# Machines named on a recommendation finding: display material for the triage
# view, not an inventory — one capped page, never a full pagination.
_RECO_MACHINES_CAP = 200

# Defender severities → Surface scale. Defender has no "info".
_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


class _Session:
    """Token-holding wrapper: refreshes on 401, backs off on 429/5xx.

    A fleet import can outlive the ~1 h token: the first delivery fetched one
    token and died mid-pagination. Here a 401 triggers exactly one refresh per
    request, and throttling honours Retry-After within bounds.
    """

    def __init__(self, client, tenant: str, client_id: str, secret: str):
        self._client = client
        self._tenant = tenant
        self._client_id = client_id
        self._secret = secret
        self._token = ""

    async def _refresh(self) -> None:
        r = await self._client.post(
            _AUTH.format(tenant=self._tenant),
            data={"grant_type": "client_credentials", "client_id": self._client_id,
                  "client_secret": self._secret, "scope": _SCOPE},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        self._token = r.json()["access_token"]

    async def get(self, path: str, params: dict[str, Any]) -> Any:
        if not self._token:
            await self._refresh()
        refreshed = False
        for attempt in range(_MAX_RETRIES + 1):
            r = await self._client.get(
                f"{_API}/{path}", params=params,
                headers={"Authorization": f"Bearer {self._token}"})
            if r.status_code == 401 and not refreshed:
                refreshed = True
                await self._refresh()
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < _MAX_RETRIES:
                wait = 0.0
                try:
                    wait = float(r.headers.get("Retry-After", "") or 0)
                except ValueError:
                    pass
                wait = min(max(wait, 2.0 * (attempt + 1)), _MAX_RETRY_WAIT)
                logger.info("Defender API %s on %s — retry %d/%d in %.0fs",
                            r.status_code, path, attempt + 1, _MAX_RETRIES, wait)
                await asyncio.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()  # exhausted retries: surface the last status

    async def pages(self, path: str) -> list[dict[str, Any]]:
        """Paginates an endpoint to the end. Raises on the first hard error.

        Raising is deliberate: the caller turns the exception into
        ``ok: False``, which forbids the reconciliation. Silently returning a
        partial list would close half the fleet on the next import.
        """
        out: list[dict[str, Any]] = []
        skip = 0
        while True:
            data = await self.get(path, {"$top": _PAGE, "$skip": skip})
            batch = data.get("value", [])
            out.extend(batch)
            if len(batch) < _PAGE:
                return out
            skip += _PAGE


def _cve_finding(v: dict[str, Any], machine_name: str, machine_ip: str,
                 machine_os: str = "") -> dict[str, Any]:
    """One machine × CVE pair.

    The target — hence the dedup key — does NOT carry the product version.
    Including it would make the finding vanish and reappear on every minor
    upgrade, wiping the triage each time — the exact defect fixed on AppSec in
    August 2026, where keys carried file:line and lost false positives on any
    edit. The version lives in the evidence, where it refreshes without
    breaking identity. Hostname and IP live there too — they are what binds
    the finding to its host card.
    """
    product = v.get("productName", "") or ""
    target = f"{v.get('machineId','')}|{v.get('cveId','')}|{product}".lower()
    return {
        "scanner": "defender",
        "type": "defender_cve",
        # host_ref: the engine drops this finding when its host is disabled
        # or no longer carries the connector in its scanner list.
        "host_ref": v.get("machineId", ""),
        "target": target,
        "title": f"{v.get('cveId','CVE ?')} - {product or 'produit inconnu'}"
                 + (f" sur {machine_name}" if machine_name else ""),
        "description": (f"Vulnérabilité remontée par Microsoft Defender sur "
                        f"{machine_name or v.get('machineId','')}."),
        "severity": _SEVERITY.get(str(v.get("severity", "")).lower(), "medium"),
        "evidence": {
            "cve": v.get("cveId", ""),
            "product": product,
            "vendor": v.get("productVendor", ""),
            "version": v.get("productVersion", ""),   # here, not in the key
            "fixing_kb": v.get("fixingKbId", ""),      # the fix is named
            "machine_id": v.get("machineId", ""),
            "hostname": machine_name,                  # host attachment
            "address": machine_ip,                     # host attachment (fallback)
            "os": machine_os,
        },
    }


def _reco_finding(r: dict[str, Any]) -> dict[str, Any]:
    """An organisation-wide recommendation.

    ``type`` distinguishes it from a CVE, not ``severity``. A dedicated
    criticality level was considered and rejected: routes/internal.py counts
    open findings by critical/high/medium/low and reports those numbers to
    Pilot. Adding a "recommendation" value there would mix what a finding IS
    with how SEVERE it is, and skew the posture score.
    """
    score = r.get("severityScore", 0) or 0
    exposed = r.get("exposedMachinesCount", 0) or 0
    if r.get("publicExploit") or score >= 8:
        sev = "critical"
    elif score >= 6 or exposed > 50:
        sev = "high"
    elif score >= 3:
        sev = "medium"
    else:
        sev = "low"
    return {
        "scanner": "defender",
        "type": "defender_recommendation",
        "target": str(r.get("id", "")).lower(),
        "title": r.get("recommendationName", "Recommandation Defender"),
        "description": (f"{exposed} machine(s) exposée(s). "
                        f"Catégorie : {r.get('recommendationCategory', '?')}."),
        "severity": sev,
        "evidence": {
            "product": r.get("productName", ""),
            "vendor": r.get("vendor", ""),
            "recommended_version": r.get("recommendedVersion", ""),
            "remediation_type": r.get("remediationType", ""),
            "exposed_machines": exposed,
            "public_exploit": bool(r.get("publicExploit")),
            "unpatchable_cve": bool(r.get("hasUnpatchableCve")),
            "status": r.get("status", ""),
        },
    }


async def run(config: dict[str, Any]) -> dict[str, Any]:
    """Pulls the tenant inventory. Does not raise: returns ``ok: False`` on failure."""
    import httpx

    tenant = (config.get("tenant_id") or "").strip()
    client_id = (config.get("client_id") or "").strip()
    secret = (config.get("client_secret") or "").strip()
    if not (tenant and client_id and secret):
        return {"ok": False, "error": "tenant_id, client_id et client_secret sont requis",
                "hosts": [], "findings": [], "excepted": []}

    hosts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    excepted: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
            session = _Session(client, tenant, client_id, secret)

            machines = await session.pages("machines")
            names: dict[str, str] = {}
            ips: dict[str, str] = {}
            oses: dict[str, str] = {}
            for m in machines:
                name = (m.get("computerDnsName") or "").strip()
                mid = m.get("id", "")
                names[mid] = name
                ips[mid] = (m.get("lastIpAddress") or "").strip()
                oses[mid] = (m.get("osPlatform") or "").strip()
                hosts.append({
                    "id": mid,
                    "dns_name": name,
                    "ip": ips[mid],
                    "label": oses[mid],
                    "criticality": "",
                })

            for v in await session.pages("vulnerabilities/machinesVulnerabilities"):
                mid = v.get("machineId", "")
                findings.append(_cve_finding(v, names.get(mid, ""), ips.get(mid, ""),
                                             oses.get(mid, "")))

            for r in await session.pages("recommendations"):
                status = str(r.get("status", "Active")).strip()
                if status.lower() != "active":
                    # Excepted upstream: NOT kept in the feed (so the engine
                    # closes it), but named with its motive so the closure
                    # note says WHY — criterion 10.
                    excepted.append({
                        "type": "defender_recommendation",
                        "target": str(r.get("id", "")).lower(),
                        "reason": status,
                    })
                    continue
                reco = _reco_finding(r)
                # Name the exposed machines on the finding (capped): the
                # triage view shows WHO is concerned without a portal round
                # trip. Enrichment only — a failure here must not fail the
                # import (reconciliation is gated on the main feeds alone).
                try:
                    refs = await session.get(
                        f"recommendations/{r.get('id', '')}/machineReferences",
                        {"$top": _RECO_MACHINES_CAP})
                    # dict.fromkeys: dedupe while preserving order — Defender
                    # can hold several machine records for one device.
                    reco["evidence"]["machines"] = list(dict.fromkeys(
                        (x.get("computerDnsName") or "").strip()
                        for x in (refs.get("value") or []) if x.get("computerDnsName")))
                except Exception as e:  # noqa: BLE001 — enrichment is best-effort
                    logger.info("Defender machineReferences failed for '%s': %s",
                                r.get("id", "?"), type(e).__name__)
                findings.append(reco)

    except Exception as e:  # noqa: BLE001 — failure must forbid the reconciliation
        # The secret must appear nowhere: only the exception type and message
        # are logged, never the request.
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "hosts": hosts, "findings": findings, "excepted": []}

    return {"ok": True, "error": None, "hosts": hosts,
            "findings": findings, "excepted": excepted}


SURFACE_CONNECTORS = {
    "defender": {
        "label": "Microsoft Defender for Endpoint (vulnérabilités du parc)",
        "callable": run,
        "interval_hours": 6,
        "config_schema": [
            {"key": "tenant_id", "label": "Tenant Entra (GUID)", "type": "text", "required": True},
            {"key": "client_id", "label": "Application (client) ID", "type": "text", "required": True},
            {"key": "client_secret", "label": "Secret client", "type": "password",
             "secret": True, "required": True},
        ],
    },
}
