"""FEAT-37 — the Defender connector against a faked API.

The first delivery's tests were happy paths only, single page, and never
exercised the failure modes that gate the reconciliation. These do:

  - pagination across several pages, and a failure ON PAGE 2 → ``ok: False``
    with everything gathered so far (criterion 7 depends on that flag);
  - 429 throttling honoured (Retry-After) then success;
  - an expired token mid-import → one refresh, then success (a fleet import
    outlives the ~1 h token);
  - excepted recommendations returned with their motive (criterion 10);
  - evidence carries hostname AND address — what binds a finding to its host
    card, the first delivery's blind spot.

httpx is faked with a MockTransport: no network, no tenant.
"""
from __future__ import annotations

import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from conftest import load_core_addon  # noqa: E402

defender = load_core_addon("defender")

CONFIG = {"tenant_id": "t", "client_id": "c", "client_secret": "s3cret"}
_PAGE = defender._PAGE


def _machine(i):
    return {"id": f"m-{i}", "computerDnsName": f"srv{i}.corp.local",
            "lastIpAddress": f"10.0.0.{i}", "osPlatform": "WindowsServer2022"}


def _vuln(i, cve="CVE-2026-0001"):
    return {"id": f"v-{i}", "cveId": cve, "machineId": f"m-{i}",
            "productName": "Edge", "productVendor": "Microsoft",
            "productVersion": "120.0", "fixingKbId": "KB500", "severity": "High"}


class Api:
    """Scriptable Defender API. ``fail_at`` injects one error response the
    Nth time the given path is requested (1-based)."""

    def __init__(self, machines=1, vulns=1, recos=(), fail_at=None,
                 token_expires_after=None):
        self.machines = [_machine(i) for i in range(machines)]
        self.vulns = [_vuln(i % machines) for i in range(vulns)]
        self.recos = list(recos)
        self.fail_at = fail_at or {}          # {path_suffix: (n, status, headers)}
        self.calls: dict[str, int] = {}
        self.token_calls = 0
        self.token_expires_after = token_expires_after
        self.data_calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "oauth2" in url:
            self.token_calls += 1
            return httpx.Response(200, json={"access_token": f"tok-{self.token_calls}"})

        self.data_calls += 1
        if (self.token_expires_after is not None
                and self.data_calls > self.token_expires_after
                and request.headers.get("Authorization") == "Bearer tok-1"):
            return httpx.Response(401, json={"error": "expired"})

        for suffix, (n, status, headers) in self.fail_at.items():
            if url.split("?")[0].endswith(suffix):
                self.calls[suffix] = self.calls.get(suffix, 0) + 1
                if self.calls[suffix] == n:
                    return httpx.Response(status, headers=headers or {}, json={})

        if "/machineReferences" in url:
            return httpx.Response(200, json={"value": [
                {"id": "m-0", "computerDnsName": "srv0.corp.local"},
                {"id": "m-1", "computerDnsName": "srv1.corp.local"},
            ]})
        if url.split("?")[0].endswith("/machines"):
            data = self.machines
        elif url.split("?")[0].endswith("machinesVulnerabilities"):
            data = self.vulns
        elif url.split("?")[0].endswith("/recommendations"):
            data = self.recos
        else:
            return httpx.Response(404, json={})
        skip = int(request.url.params.get("$skip", 0))
        top = int(request.url.params.get("$top", _PAGE))
        return httpx.Response(200, json={"value": data[skip:skip + top]})


async def _run(api, monkeypatch=None):
    real_client = httpx.AsyncClient

    def fake_client(**kw):
        kw.pop("transport", None)
        return real_client(transport=httpx.MockTransport(api.handler), **kw)

    orig = httpx.AsyncClient
    httpx.AsyncClient = fake_client
    try:
        return await defender.run(CONFIG)
    finally:
        httpx.AsyncClient = orig


def test_missing_config_fails_without_calling_anything():
    result = asyncio.run(defender.run({"tenant_id": "t"}))
    assert result["ok"] is False and "requis" in result["error"]


def test_nominal_import_binds_findings_to_their_host():
    api = Api(machines=2, vulns=2,
              recos=[{"id": "rec-1", "recommendationName": "Update Edge",
                      "status": "Active", "severityScore": 7,
                      "exposedMachinesCount": 10}])
    result = asyncio.run(_run(api))
    assert result["ok"] is True
    assert len(result["hosts"]) == 2
    cves = [f for f in result["findings"] if f["type"] == "defender_cve"]
    # Evidence carries the attachment keys — hostname and address — while the
    # target stays the machineId-stable identity.
    for f in cves:
        assert f["evidence"]["hostname"].endswith(".corp.local")
        assert f["evidence"]["address"].startswith("10.0.0.")
        assert f["target"].startswith("m-")
    # The version is in the evidence, never in the identity.
    assert all("120.0" not in f["target"] for f in cves)
    assert any(f["type"] == "defender_recommendation" for f in result["findings"])


def test_pagination_walks_all_pages():
    api = Api(machines=1, vulns=_PAGE * 2 + 5)
    result = asyncio.run(_run(api))
    assert result["ok"] is True
    assert len([f for f in result["findings"] if f["type"] == "defender_cve"]) \
        == _PAGE * 2 + 5


def test_a_failure_on_page_two_yields_ok_false():
    """Criterion 7 upstream half: the flag must say the import is incomplete —
    the engine then closes nothing. The multi-page path was never exercised by
    the first delivery's tests."""
    api = Api(machines=1, vulns=_PAGE + 10,
              fail_at={"machinesVulnerabilities": (2, 403, None)})
    result = asyncio.run(_run(api))
    assert result["ok"] is False
    assert "403" in result["error"]


def test_429_is_retried_honouring_retry_after(monkeypatch):
    waits = []

    async def fake_sleep(s):
        waits.append(s)
    monkeypatch.setattr(defender.asyncio, "sleep", fake_sleep)

    api = Api(machines=1, vulns=1,
              fail_at={"/machines": (1, 429, {"Retry-After": "7"})})
    result = asyncio.run(_run(api))
    assert result["ok"] is True
    assert waits and waits[0] == 7.0


def test_an_expired_token_is_refreshed_once_and_the_import_continues():
    api = Api(machines=1, vulns=1, token_expires_after=1)
    result = asyncio.run(_run(api))
    assert result["ok"] is True
    assert api.token_calls == 2      # initial + one refresh


def test_excepted_recommendations_carry_their_motive():
    api = Api(machines=1, vulns=0,
              recos=[{"id": "rec-1", "recommendationName": "A", "status": "Active",
                      "severityScore": 2, "exposedMachinesCount": 1},
                     {"id": "rec-2", "recommendationName": "B",
                      "status": "Full exception", "severityScore": 2,
                      "exposedMachinesCount": 1}])
    result = asyncio.run(_run(api))
    assert result["ok"] is True
    kept = [f["target"] for f in result["findings"]
            if f["type"] == "defender_recommendation"]
    assert kept == ["rec-1"]
    assert result["excepted"] == [{"type": "defender_recommendation",
                                   "target": "rec-2", "reason": "Full exception"}]


def test_the_secret_never_appears_in_a_failure_report():
    api = Api(machines=1, vulns=1, fail_at={"/machines": (1, 500, None)})
    # 500 is retried then surfaces; shrink the retries to keep the test fast.
    orig = defender._MAX_RETRIES
    defender._MAX_RETRIES = 0
    try:
        result = asyncio.run(_run(api))
    finally:
        defender._MAX_RETRIES = orig
    assert result["ok"] is False
    assert "s3cret" not in repr(result)


def test_recommendations_name_their_exposed_machines():
    api = Api(machines=1, vulns=0,
              recos=[{"id": "rec-1", "recommendationName": "A", "status": "Active",
                      "severityScore": 2, "exposedMachinesCount": 2}])
    result = asyncio.run(_run(api))
    reco = next(f for f in result["findings"]
                if f["type"] == "defender_recommendation")
    assert reco["evidence"]["machines"] == ["srv0.corp.local", "srv1.corp.local"]


def test_a_failing_machine_references_call_does_not_fail_the_import():
    """Enrichment is best-effort: reconciliation is gated on the main feeds,
    a broken per-recommendation call must not turn a complete import into an
    incomplete one."""
    api = Api(machines=1, vulns=1,
              recos=[{"id": "rec-1", "recommendationName": "A", "status": "Active",
                      "severityScore": 2, "exposedMachinesCount": 2}],
              fail_at={"machineReferences": (1, 500, None)})
    orig = defender._MAX_RETRIES
    defender._MAX_RETRIES = 0
    try:
        result = asyncio.run(_run(api))
    finally:
        defender._MAX_RETRIES = orig
    assert result["ok"] is True
    reco = next(f for f in result["findings"]
                if f["type"] == "defender_recommendation")
    assert "machines" not in reco["evidence"]


def test_cve_evidence_carries_the_machine_os():
    api = Api(machines=1, vulns=1)
    result = asyncio.run(_run(api))
    cve = next(f for f in result["findings"] if f["type"] == "defender_cve")
    assert cve["evidence"]["os"] == "WindowsServer2022"
