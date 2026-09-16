"""FEAT-45 — non-conformities and derogations on findings.

The shared mechanics are exercised through Surface's own models and hook,
against SQLite: request → approve → the finding is derogated; expiry brings
it back to to_fix; a triage lifts the derogation; the transition and
validation guards answer 409 / 422."""
import os
import sys
import uuid
from datetime import date, timedelta

import pytest
import pytest_asyncio
from fastapi import HTTPException

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
os.environ.setdefault("MODULE_NAME", "surface")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-32ch")
os.environ.setdefault("SERVICE_TOKEN", "svc-token-for-tests-0123456789abcdef")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sqlalchemy import JSON  # noqa: E402
from sqlalchemy.dialects.postgresql import JSONB as _JSONB  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from starlette.requests import Request  # noqa: E402

from src.models import Base, Derogation, Finding, Nonconformity  # noqa: E402
from src.nonconformity_common import (check_transition, expire_derogations,  # noqa: E402
                                      next_reference, validate_derogation_request)
from src.routes.nonconformities import FINDING_HOOK, router  # noqa: E402
from src.findings_dedup import insert_or_dedupe  # noqa: E402

for _t in Base.metadata.tables.values():
    for _c in _t.columns:
        if _c.server_default is not None:
            _sd = str(getattr(_c.server_default, "arg", "")).lower()
            if any(k in _sd for k in ("gen_random_uuid", "now(", "::jsonb")):
                _c.server_default = None
        if isinstance(_c.type, _JSONB):
            _c.type = JSON()


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False},
                                 poolclass=StaticPool)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


def _req() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/derogations", "headers": [],
                    "query_string": b"", "client": ("127.0.0.1", 1)})


def _endpoint(name: str):
    for r in router.routes:
        if r.endpoint.__name__ == name:
            return r.endpoint
    raise KeyError(name)


async def _finding(db, status="to_fix"):
    f = Finding(id=uuid.uuid4(), scanner="nmap", type="open_port", severity="high",
                title="22/tcp open", target="10.0.0.1", status=status, evidence={})
    db.add(f)
    await db.commit()
    return f


def _der_body(fid, **over):
    body = {"subject_type": "finding", "subject_id": str(fid), "title": "Accepted until the migration",
            "justification": "The host is decommissioned in Q1; compensating firewall rule in place.",
            "risk_owner": "ops@medsecure.example", "approver": "ciso@medsecure.example",
            "valid_until": (date.today() + timedelta(days=90)).isoformat()}
    body.update(over)
    return body


# ── pure rules ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("kind,cur,new,ok", [
    ("nonconformity", "to_qualify", "open", True),
    ("nonconformity", "to_qualify", "closed", False),
    ("nonconformity", "to_qualify", "derogated", True),
    ("nonconformity", "open", "derogated", True),
    ("nonconformity", "closed", "open", False),
    ("derogation", "pending_approval", "approved", True),
    ("derogation", "approved", "approved", False),
    ("derogation", "approved", "revoked", True),
    ("derogation", "rejected", "approved", False),
])
def test_transitions(kind, cur, new, ok):
    if ok:
        check_transition(kind, cur, new)
    else:
        with pytest.raises(HTTPException) as e:
            check_transition(kind, cur, new)
        assert e.value.status_code == 409


def test_validation_names_the_missing_field():
    with pytest.raises(HTTPException) as e:
        validate_derogation_request({"subject_type": "finding", "subject_id": "x", "title": "t",
                                     "justification": "j", "risk_owner": "", "approver": "a"}, 365)
    assert e.value.status_code == 422 and "risk_owner" in e.value.detail


def test_validation_requires_a_bounded_end_date():
    base = {"subject_type": "finding", "subject_id": "x", "title": "t", "justification": "j",
            "risk_owner": "r", "approver": "a"}
    with pytest.raises(HTTPException) as e:
        validate_derogation_request(dict(base), 365)
    assert e.value.status_code == 422 and "valid_until" in e.value.detail
    with pytest.raises(HTTPException) as e:
        validate_derogation_request(dict(base, valid_until=(date.today() + timedelta(days=400)).isoformat()), 365)
    assert e.value.status_code == 422 and "maximum" in e.value.detail
    out = validate_derogation_request(dict(base, valid_until=(date.today() + timedelta(days=30)).isoformat()), 365)
    assert out["valid_from"] == date.today()


# ── the finding flow ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_request_approve_expire_brings_the_finding_back(db):
    f = await _finding(db)
    request = _endpoint("request_derogation")
    decide = _endpoint("decide_derogation")
    from src.nonconformity_common import DerogationCreate, DecisionBody
    d = await request(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    assert d["status"] == "pending_approval" and d["reference"].startswith("DER-")
    assert (await db.get(Finding, f.id)).status == "to_fix"      # nothing changes before the decision

    d = await decide(d["id"], DecisionBody(approve=True, note="ok"), _req(), user=None, db=db)
    assert d["status"] == "approved"
    f2 = await db.get(Finding, f.id)
    assert f2.status == "derogated" and str(f2.derogation_id) == d["id"]

    # a second request on the same subject is refused while one is live
    with pytest.raises(HTTPException) as e:
        await request(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    assert e.value.status_code == 409

    # past the end date, the scheduler pass expires it and the finding is to_fix again
    n = await expire_derogations(db, Derogation, FINDING_HOOK, Nonconformity,
                                 today=date.today() + timedelta(days=91))
    assert n == 1
    f3 = await db.get(Finding, f.id)
    assert f3.status == "to_fix" and f3.derogation_id is None
    assert (await db.get(Derogation, uuid.UUID(d["id"]))).status == "expired"


@pytest.mark.asyncio
async def test_refusal_needs_a_note_and_leaves_the_finding_alone(db):
    f = await _finding(db)
    from src.nonconformity_common import DerogationCreate, DecisionBody
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    with pytest.raises(HTTPException) as e:
        await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=False, note=""), _req(), user=None, db=db)
    assert e.value.status_code == 422
    d = await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=False, note="not acceptable"), _req(), user=None, db=db)
    assert d["status"] == "rejected"
    assert (await db.get(Finding, f.id)).status == "to_fix"


@pytest.mark.asyncio
async def test_a_derogation_needs_an_open_finding(db):
    """A finding that exists but is not actionable is a 409 (the caller knows
    it exists); an unknown id stays a 404."""
    f = await _finding(db, status="fixed")
    from src.nonconformity_common import DerogationCreate
    with pytest.raises(HTTPException) as e:
        await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:
        await _endpoint("request_derogation")(DerogationCreate(**_der_body(uuid.uuid4())), _req(), user=None, db=db)
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_a_pending_request_dies_with_the_finding_and_cannot_resurrect_it(db):
    """A request still pending when the analyst settles the finding
    is rejected by the triage; and approving a request whose finding was
    fixed meanwhile is refused instead of putting the finding back."""
    from src.nonconformity_common import DerogationCreate, DecisionBody
    from src.routes.findings import FindingTriage, triage_finding
    request = _endpoint("request_derogation")
    decide = _endpoint("decide_derogation")

    f1 = await _finding(db)
    d1 = await request(DerogationCreate(**_der_body(f1.id)), _req(), user=None, db=db)
    db.expunge_all()
    await triage_finding(f1.id, FindingTriage(status="fixed"), _req(), user=None, db=db)
    d1b = await db.get(Derogation, uuid.UUID(d1["id"]))
    assert d1b.status == "rejected" and "fixed" in (d1b.decision_note or "")

    f2 = await _finding(db)
    d2 = await request(DerogationCreate(**_der_body(f2.id)), _req(), user=None, db=db)
    f2.status = "fixed"                       # settled outside the triage route (bulk, import…)
    await db.commit()
    with pytest.raises(HTTPException) as e:
        await decide(d2["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    assert e.value.status_code == 409
    assert (await db.get(Finding, f2.id)).status == "fixed"


@pytest.mark.asyncio
async def test_deleting_a_finding_settles_its_derogations(db):
    """Single and bulk deletion alike: an approved derogation is revoked, a
    pending request is rejected, both with the deletion as the reason."""
    from src.nonconformity_common import DerogationCreate, DecisionBody
    from src.routes.findings import BulkDeleteRequest, bulk_delete, delete_finding
    request = _endpoint("request_derogation")

    f1 = await _finding(db)
    d1 = await request(DerogationCreate(**_der_body(f1.id)), _req(), user=None, db=db)     # pending
    db.expunge_all()
    await delete_finding(f1.id, _req(), user=None, db=db)
    d1b = await db.get(Derogation, uuid.UUID(d1["id"]))
    assert d1b.status == "rejected" and "deleted" in (d1b.decision_note or "")

    f2 = await _finding(db)
    d2 = await request(DerogationCreate(**_der_body(f2.id)), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d2["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    db.expunge_all()
    await bulk_delete(BulkDeleteRequest(ids=[f2.id]), _req(), user=None, db=db)
    d2b = await db.get(Derogation, uuid.UUID(d2["id"]))
    assert d2b.status == "revoked" and "deleted" in (d2b.revoked_reason or "")
    assert (await db.get(Finding, f2.id)) is None


@pytest.mark.asyncio
async def test_patch_keeps_the_server_rules(db):
    """The generic PATCH cannot bypass what the dedicated routes
    enforce — measures must exist, a remediation keeps at least one, the
    subject is not editable, evidence is capped."""
    from src.models import Measure
    from src.nonconformity_common import NonconformityCreate, NonconformityPatch, QualifyBody, RemediationBody
    patch_nc = _endpoint("patch_nonconformity")
    n = await _endpoint("declare_nonconformity")(NonconformityCreate(title="Unpatched jump host"), _req(), user=None, db=db)
    with pytest.raises(HTTPException) as e:
        await patch_nc(n["id"], NonconformityPatch(measure_ids=["MES-NOPE"]), user=None, db=db)
    assert e.value.status_code == 422
    with pytest.raises(HTTPException) as e:
        await patch_nc(n["id"], NonconformityPatch(title="x"), user=None, db=db)
    assert e.value.status_code == 422
    assert "subject_type" not in NonconformityPatch.model_fields
    r = await patch_nc(n["id"], NonconformityPatch(evidence=[f"e{i}" for i in range(80)]), user=None, db=db)
    assert len(r["evidence"]) == 50

    db.add(Measure(id="MES-P1", title="Rotate the shared account", statut="a_faire"))
    await db.commit()
    await _endpoint("qualify_nonconformity")(n["id"], QualifyBody(), user=None, db=db)
    await _endpoint("nonconformity_in_remediation")(n["id"], RemediationBody(measure_ids=["MES-P1"]), user=None, db=db)
    with pytest.raises(HTTPException) as e:
        await patch_nc(n["id"], NonconformityPatch(measure_ids=[]), user=None, db=db)
    assert e.value.status_code == 422


@pytest.mark.asyncio
async def test_triage_of_a_derogated_finding_revokes_the_derogation(db):
    f = await _finding(db)
    from src.nonconformity_common import DerogationCreate, DecisionBody, revoke_for_subject
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    # what routes/findings.py does before it writes the analyst's status
    n = await revoke_for_subject(db, Derogation, "finding", str(f.id), "finding triaged to 'fixed'", actor="ana")
    await db.commit()
    assert n == 1
    assert (await db.get(Derogation, uuid.UUID(d["id"]))).status == "revoked"


@pytest.mark.asyncio
async def test_both_triage_routes_lift_the_derogation(db):
    """The single and the bulk triage routes both leave `derogated` the same
    way: the derogation is revoked and the finding no longer points at it."""
    from src.nonconformity_common import DerogationCreate, DecisionBody
    from src.routes.findings import BulkTriageRequest, FindingTriage, bulk_triage, triage_finding

    async def derogated_finding():
        f = await _finding(db)
        d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
        await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
        assert (await db.get(Finding, f.id)).status == "derogated"
        db.expunge_all()          # the route loads its own objects, as a request would
        return f, uuid.UUID(d["id"])

    f1, d1 = await derogated_finding()
    await triage_finding(f1.id, FindingTriage(status="fixed"), _req(), user=None, db=db)
    assert (await db.get(Derogation, d1)).status == "revoked"
    f1b = await db.get(Finding, f1.id)
    assert f1b.status == "fixed" and f1b.derogation_id is None

    f2, d2 = await derogated_finding()
    await bulk_triage(BulkTriageRequest(ids=[str(f2.id)], status="fixed"), _req(), user=None, db=db)
    assert (await db.get(Derogation, d2)).status == "revoked"
    f2b = await db.get(Finding, f2.id)
    assert f2b.status == "fixed" and f2b.derogation_id is None


@pytest.mark.asyncio
async def test_a_derogated_finding_is_silenced_on_redetection(db):
    f = await _finding(db, status="derogated")
    f.dedup_key = "nmap|open_port|10.0.0.1"
    await db.commit()
    action = await insert_or_dedupe(db, {"scanner": "nmap", "type": "open_port", "severity": "high",
                                         "title": "22/tcp open", "target": "10.0.0.1", "evidence": {}})
    await db.commit()
    assert action == "silenced"
    assert (await db.get(Finding, f.id)).status == "derogated"


# ── declared non-conformities ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_declared_nonconformity_is_qualified_then_derogated(db):
    from src.nonconformity_common import (NonconformityCreate, QualifyBody, DerogationCreate, DecisionBody,
                                          CloseBody)
    nc = await _endpoint("declare_nonconformity")(
        NonconformityCreate(title="Developers push to main without review", source="observation",
                            severity="high", domain="secure development"), _req(), user=None, db=db)
    assert nc["status"] == "to_qualify" and nc["reference"] == f"NC-{date.today().year}-001"
    nc = await _endpoint("qualify_nonconformity")(nc["id"], QualifyBody(severity="medium"), user=None, db=db)
    assert nc["status"] == "open" and nc["severity"] == "medium"
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(nc["id"], subject_type="nonconformity")),
                                              _req(), user=None, db=db)
    d = await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    assert (await db.get(Nonconformity, uuid.UUID(nc["id"]))).status == "derogated"
    nc = await _endpoint("close_nonconformity")(nc["id"], CloseBody(closure_evidence="Branch protection enabled, PR #12"),
                                                user=None, db=db)
    assert nc["status"] == "closed"
    assert (await db.get(Derogation, uuid.UUID(d["id"]))).status == "revoked"
    second = await _endpoint("declare_nonconformity")(NonconformityCreate(title="Another one"), _req(), user=None, db=db)
    assert second["reference"] == f"NC-{date.today().year}-002"
    with pytest.raises(HTTPException) as e:                      # closed: no derogation any more
        await _endpoint("request_derogation")(DerogationCreate(**_der_body(nc["id"], subject_type="nonconformity")),
                                              _req(), user=None, db=db)
    assert e.value.status_code == 409


@pytest.mark.asyncio
async def test_remediation_needs_existing_corrective_measures(db):
    """In remediation = carried by at least one measure of the module; an
    unknown id is refused, a measure created on its own (no finding) is fine."""
    from src.models import Measure
    from src.nonconformity_common import NonconformityCreate, QualifyBody, RemediationBody
    from src.routes.measures import create_measure
    from src.schemas import MeasureCreate

    n = await _endpoint("declare_nonconformity")(
        NonconformityCreate(title="Backups not tested"), _req(), user=None, db=db)
    await _endpoint("qualify_nonconformity")(n["id"], QualifyBody(), user=None, db=db)
    remediation = _endpoint("nonconformity_in_remediation")

    with pytest.raises(HTTPException) as e:
        await remediation(n["id"], RemediationBody(measure_ids=["MES-NOPE"]), user=None, db=db)
    assert e.value.status_code == 422 and "MES-NOPE" in e.value.detail

    m = await create_measure(MeasureCreate(title="Run a restore test quarterly"), _req(), user=None, db=db)
    assert m["id"].startswith("MES-") and m["finding_id"] is None
    assert (await db.get(Measure, m["id"])).statut == "a_faire"

    r = await remediation(n["id"], RemediationBody(measure_ids=[m["id"], m["id"]]), user=None, db=db)
    assert r["status"] == "in_remediation" and r["measure_ids"] == [m["id"]]
    # closing waits for the measures: refused while one is not done, fine once it is
    from src.nonconformity_common import CloseBody
    close = _endpoint("close_nonconformity")
    with pytest.raises(HTTPException) as e:
        await close(n["id"], CloseBody(closure_evidence="restore report"), user=None, db=db)
    assert e.value.status_code == 409 and m["id"] in e.value.detail
    (await db.get(Measure, m["id"])).statut = "termine"
    await db.commit()
    r = await close(n["id"], CloseBody(closure_evidence="restore report"), user=None, db=db)
    assert r["status"] == "closed"
    # the list can be changed while in remediation, never emptied
    with pytest.raises(Exception):
        RemediationBody(measure_ids=[])


@pytest.mark.asyncio
async def test_a_free_derogation_needs_no_subject(db):
    """subject_type "none": no id, no live-derogation rule, and the finding
    hook is never called (its uuid parsing would choke on an empty id)."""
    from src.nonconformity_common import DerogationCreate, DecisionBody, RevokeBody
    body = _der_body("", subject_type="none", subject_id="", title="Legacy TLS 1.1 on the fax gateway")
    d = await _endpoint("request_derogation")(DerogationCreate(**body), _req(), user=None, db=db)
    assert d["status"] == "pending_approval" and d["subject_type"] == "none" and d["subject_id"] == ""
    # two free derogations may coexist: there is no subject to be exclusive on
    d2 = await _endpoint("request_derogation")(DerogationCreate(**body), _req(), user=None, db=db)
    assert d2["reference"] != d["reference"]
    d = await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    assert d["status"] == "approved"
    d = await _endpoint("revoke_derogation")(d["id"], RevokeBody(reason="policy changed"), _req(), user=None, db=db)
    assert d["status"] == "revoked"
    n = await expire_derogations(db, Derogation, FINDING_HOOK, Nonconformity, today=date.today() + timedelta(days=400))
    assert n == 0
    # a subject-bound request still needs its id
    with pytest.raises(HTTPException) as e:
        await _endpoint("request_derogation")(DerogationCreate(**_der_body("", subject_id="")), _req(), user=None, db=db)
    assert e.value.status_code == 422 and "subject_id" in e.value.detail


@pytest.mark.asyncio
async def test_derogation_on_a_fresh_nonconformity_qualifies_it_on_approval(db):
    """Declared from the derogation flow, a non-conformity is still to qualify:
    the request is accepted, and the approval counts as its qualification."""
    from src.nonconformity_common import DerogationCreate, DecisionBody, NonconformityCreate
    n = await _endpoint("declare_nonconformity")(NonconformityCreate(title="Shared admin account"), _req(), user=None, db=db)
    assert n["status"] == "to_qualify"
    d = await _endpoint("request_derogation")(
        DerogationCreate(**_der_body("", subject_type="nonconformity", subject_id=n["id"])), _req(), user=None, db=db)
    assert d["subject_label"].startswith(n["reference"])
    await _endpoint("decide_derogation")(d["id"], DecisionBody(approve=True), _req(), user=None, db=db)
    nc = await db.get(Nonconformity, uuid.UUID(n["id"]))
    assert nc.status == "derogated" and nc.qualified_at is not None and str(nc.derogation_id) == d["id"]


@pytest.mark.asyncio
async def test_next_reference_is_per_year(db):
    assert await next_reference(db, Nonconformity, "NC", date(2030, 1, 1)) == "NC-2030-001"


# ── internal register (what Pilot reads and relays) ──────────────────────

@pytest.mark.asyncio
async def test_internal_router_lists_relays_and_guards(db):
    """The service-token router lists non-conformities with their treatment
    and every derogation, relays a declaration and a decision with the Pilot
    user as actor, and refuses without the token."""
    from src.nonconformity_common import (make_internal_router, DerogationCreate, RemediationBody, QualifyBody,
                                          InternalDeclaration, InternalDecision)
    from src.routes.nonconformities import FINDING_HOOK
    from src.models import Measure

    calls = []
    def check(request):
        calls.append(request.headers.get("x-service-token"))
        if request.headers.get("x-service-token") != "tok":
            raise HTTPException(status_code=403, detail="Invalid service token")
    internal = make_internal_router(Nonconformity, Derogation, FINDING_HOOK, ("finding",), check)
    def ep(name):
        for r in internal.routes:
            if r.endpoint.__name__ == name:
                return r.endpoint
        raise KeyError(name)
    def req(token="tok"):
        return Request({"type": "http", "method": "POST", "path": "/api/internal/x", "query_string": b"",
                        "headers": [(b"x-service-token", token.encode())], "client": ("127.0.0.1", 1)})

    with pytest.raises(HTTPException) as e:
        await ep("internal_nonconformities")(req("wrong"), db=db)
    assert e.value.status_code == 403

    # declaration relayed from Pilot: the actor is the Pilot user, not "system"
    nc = await ep("internal_declare")(InternalDeclaration(title="Declared from the console", severity="high",
                                                          actor="rssi@medsecure.example"), req(), db=db)
    assert nc["declared_by"] == "rssi@medsecure.example" and nc["status"] == "to_qualify"

    # treatment reflects the state: none → measure once in remediation
    await _endpoint("qualify_nonconformity")(nc["id"], QualifyBody(), user=None, db=db)
    db.add(Measure(id="MES-INT", title="Fix it", statut="a_faire")); await db.commit()
    await _endpoint("nonconformity_in_remediation")(nc["id"], RemediationBody(measure_ids=["MES-INT"]), user=None, db=db)
    listing = await ep("internal_nonconformities")(req(), db=db)
    assert listing["total"] == 1 and listing["items"][0]["treatment"] == "measure"

    # decision relayed from Pilot on a finding derogation
    f = await _finding(db)
    d = await _endpoint("request_derogation")(DerogationCreate(**_der_body(f.id)), _req(), user=None, db=db)
    out = await ep("internal_decide")(d["id"], InternalDecision(approve=True, note="ok", actor="ciso@medsecure.example"),
                                      req(), db=db)
    assert out["status"] == "approved" and out["decided_by"] == "ciso@medsecure.example"
    assert (await db.get(Finding, f.id)).status == "derogated"
    ders = await ep("internal_derogations")(req(), db=db)
    assert ders["total"] == 1 and ders["items"][0]["status"] == "approved"
    assert all(c == "tok" for c in calls[1:])
