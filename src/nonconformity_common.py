# -----------------------------------------------------------------------------
# Generated file - do not edit.
# It is overwritten at every release; a change made here is lost.
# See CONTRIBUTING.md.
# -----------------------------------------------------------------------------
"""Non-conformities and derogations — the shared mechanics (FEAT-45).

An identical copy of this file ships in every module's src/ directory.
Do NOT edit the per-module copies: open an issue describing the change.

Two objects, one treatment cycle, whatever the module:

* a **non-conformity** (``nonconformities`` table) is a deviation *declared*
  by a person — observed by chance, reported, found in an informal review or
  an incident — as opposed to the items the module's own controls and
  scanners already produce (findings, KO controls, gaps). It is qualified
  before it enters the register, then remediated by measures, derogated, or
  closed with evidence;
* a **derogation** (``derogations`` table) is a governed, time-boxed
  acceptance of an item the module owns (a finding, a control, a declared
  non-conformity…): justification, risk owner, approver, end date, review
  date, compensating measures. Approved, it is immutable; it expires or is
  revoked, and the item it covers goes back to "to fix".

The module owns the storage (its own ``Base``), the subject vocabulary and
what "derogated" means for each subject kind (``SubjectHook``). This file
owns the states, the transitions, the server-side validation, the router
and the expiration pass, so that every module behaves the same and the
consolidation upstream reads one contract.

Status paths (409 on any other):

    nonconformity: to_qualify -> open | rejected
                   open -> in_remediation | derogated | closed
                   in_remediation -> open | derogated | closed
                   derogated -> open | closed            (on expiry / revocation)
    derogation:    pending_approval -> approved | rejected
                   approved -> expired | revoked
"""
from __future__ import annotations

import logging
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import Column, Date, DateTime, Index, String, Text, func, select, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession

# src.auth and src.database are imported inside make_router(): models.py
# imports this file for define_models(), and src.auth imports models.

logger = logging.getLogger("nonconformity")

NC_SOURCES = ("observation", "report", "informal_review", "incident")
NC_SEVERITIES = ("critical", "high", "medium", "low")
NC_STATUSES = ("to_qualify", "open", "in_remediation", "derogated", "closed", "rejected")
NC_TRANSITIONS: dict[str, set[str]] = {
    "to_qualify": {"open", "rejected", "derogated"},   # derogated: approval qualifies implicitly
    "open": {"in_remediation", "derogated", "closed"},
    "in_remediation": {"open", "derogated", "closed"},
    "derogated": {"open", "closed"},
    "closed": set(),
    "rejected": set(),
}
DER_STATUSES = ("pending_approval", "approved", "rejected", "expired", "revoked")
DER_TRANSITIONS: dict[str, set[str]] = {
    "pending_approval": {"approved", "rejected"},
    "approved": {"expired", "revoked"},
    "rejected": set(),
    "expired": set(),
    "revoked": set(),
}
DEFAULT_MAX_DAYS = 365
MAX_DAYS_SETTING = "nonconformity.max_derogation_days"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── models ───────────────────────────────────────────────────────────────

def define_models(Base: Any) -> tuple[type, type]:
    """Declare the two tables on the module's own declarative Base.

    Called once from the module's ``models.py``::

        Nonconformity, Derogation = define_models(Base)
    """

    class Nonconformity(Base):  # type: ignore[misc,valid-type]
        __tablename__ = "nonconformities"
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                    server_default=text("gen_random_uuid()"))
        reference = Column(String(20), nullable=False, unique=True)
        source = Column(String(30), nullable=False, default="observation")
        observed_at = Column(Date, nullable=False)
        observed_by = Column(String(255), default="")
        declared_by = Column(String(255), default="")
        title = Column(String(500), nullable=False)
        description = Column(Text, default="")
        severity = Column(String(20), nullable=False, default="medium")
        evidence = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
        domain = Column(String(100), default="")
        requirement_ref = Column(String(200), default="")
        subject_type = Column(String(50), default="")
        subject_id = Column(String(200), default="")
        # Every item the record is about ([{"type", "id"}]): requirements
        # overlap across frameworks, one gap may concern several. The pair
        # above keeps the first one, the primary, for what is keyed on one.
        subjects = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
        status = Column(String(30), nullable=False, default="to_qualify", server_default=text("'to_qualify'"))
        qualified_by = Column(String(255), default="")
        qualified_at = Column(DateTime(timezone=True), nullable=True)
        rejection_note = Column(Text, default="")
        closed_at = Column(DateTime(timezone=True), nullable=True)
        closure_evidence = Column(Text, default="")
        measure_ids = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
        derogation_id = Column(UUID(as_uuid=True), nullable=True)
        created_at = Column(DateTime(timezone=True), default=_now, server_default=text("NOW()"))
        updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, server_default=text("NOW()"))
        __table_args__ = (Index("ix_nonconformities_status", "status"),)

    class Derogation(Base):  # type: ignore[misc,valid-type]
        __tablename__ = "derogations"
        id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
                    server_default=text("gen_random_uuid()"))
        reference = Column(String(20), nullable=False, unique=True)
        subject_type = Column(String(50), nullable=False)
        subject_id = Column(String(200), nullable=False)
        subject_label = Column(String(500), default="")
        title = Column(String(500), nullable=False)
        justification = Column(Text, nullable=False)
        risk_owner = Column(String(255), nullable=False)
        approver = Column(String(255), nullable=False)
        compensating_measure_ids = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
        valid_from = Column(Date, nullable=False)
        valid_until = Column(Date, nullable=False)
        review_at = Column(Date, nullable=True)
        status = Column(String(30), nullable=False, default="pending_approval",
                        server_default=text("'pending_approval'"))
        requested_by = Column(String(255), default="")
        requested_at = Column(DateTime(timezone=True), default=_now, server_default=text("NOW()"))
        decided_by = Column(String(255), default="")
        decided_at = Column(DateTime(timezone=True), nullable=True)
        decision_note = Column(Text, default="")
        revoked_reason = Column(Text, default="")
        renews_id = Column(UUID(as_uuid=True), nullable=True)
        created_at = Column(DateTime(timezone=True), default=_now, server_default=text("NOW()"))
        updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now, server_default=text("NOW()"))
        __table_args__ = (Index("ix_derogations_status", "status"),
                          Index("ix_derogations_subject", "subject_type", "subject_id"))

    return Nonconformity, Derogation


# ── pure rules ───────────────────────────────────────────────────────────

def check_transition(kind: str, current: str, new: str) -> None:
    """409 unless ``current -> new`` is a declared path."""
    table = NC_TRANSITIONS if kind == "nonconformity" else DER_TRANSITIONS
    if new not in table.get(current, set()):
        raise HTTPException(status_code=409,
                            detail=f"{kind}: cannot go from '{current}' to '{new}'")


def validate_derogation_request(body: dict, max_days: int, today: Optional[date] = None) -> dict:
    """422 naming the field unless the request is complete and bounded."""
    today = today or date.today()
    required = ["title", "justification", "risk_owner", "approver", "subject_type"]
    if str(body.get("subject_type") or "") != "none":
        required.append("subject_id")          # a free derogation has no subject
    missing = [f for f in required if not str(body.get(f) or "").strip()]
    if missing:
        raise HTTPException(status_code=422, detail=f"derogation: missing {', '.join(missing)}")
    valid_from = _as_date(body.get("valid_from")) or today
    valid_until = _as_date(body.get("valid_until"))
    if valid_until is None:
        raise HTTPException(status_code=422, detail="derogation: valid_until is required")
    if valid_until <= valid_from:
        raise HTTPException(status_code=422, detail="derogation: valid_until must be after valid_from")
    if (valid_until - valid_from).days > max_days:
        raise HTTPException(status_code=422,
                            detail=f"derogation: duration exceeds the maximum of {max_days} days")
    review_at = _as_date(body.get("review_at"))
    if review_at is not None and not (valid_from <= review_at <= valid_until):
        raise HTTPException(status_code=422, detail="derogation: review_at must fall within the validity")
    return {"valid_from": valid_from, "valid_until": valid_until, "review_at": review_at}


def _as_date(v: Any) -> Optional[date]:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        raise HTTPException(status_code=422, detail=f"derogation: invalid date '{v}'")


async def next_reference(db: AsyncSession, Model: Any, prefix: str, today: Optional[date] = None) -> str:
    """``NC-2026-007`` / ``DER-2026-003``: per-year counter. Records are
    never deleted, so the count is the sequence; a concurrent duplicate is
    retried by ``commit_with_reference``."""
    year = (today or date.today()).year
    head = f"{prefix}-{year}-"
    n = await db.scalar(select(func.count()).select_from(Model).where(Model.reference.like(head + "%")))
    return f"{head}{(n or 0) + 1:03d}"


async def commit_with_reference(db: AsyncSession, obj: Any, Model: Any, prefix: str) -> None:
    """Commit a new record whose reference is a per-year counter: two
    concurrent creations can compute the same number, so a unique-violation
    on the reference is retried with a fresh one instead of surfacing as a
    500; any other integrity error is raised as is."""
    from sqlalchemy.exc import IntegrityError
    for attempt in range(4):
        db.add(obj)
        try:
            await db.commit()
            return
        except IntegrityError as e:
            await db.rollback()
            if "reference" not in str(e.orig).lower() and "unique" not in str(e.orig).lower():
                raise
            if attempt == 3:
                raise HTTPException(status_code=503, detail="could not allocate a reference, retry")
            obj.reference = await next_reference(db, Model, prefix)


async def max_derogation_days(db: AsyncSession) -> int:
    try:
        from src.models import AppSettings
        row = await db.get(AppSettings, MAX_DAYS_SETTING)
        if row and str(row.value).strip().isdigit():
            return max(1, int(row.value))
    except Exception:  # the setting is optional; the default rules
        pass
    return DEFAULT_MAX_DAYS


# ── module hook ──────────────────────────────────────────────────────────

class SubjectHook(Protocol):
    """What the module does with the item a derogation covers."""

    async def exists(self, db: AsyncSession, subject_type: str, subject_id: str) -> Optional[str]:
        """The subject's label when it exists, ``None`` otherwise. A module may
        raise an HTTPException (409) for an item that exists but cannot be
        derogated in its current state."""

    async def apply(self, db: AsyncSession, derogation: Any) -> None:
        """The subject enters its 'derogated' state."""

    async def release(self, db: AsyncSession, derogation: Any, reason: str) -> None:
        """The subject leaves 'derogated' (expiry, revocation) → back to 'to fix'."""

    async def missing_measures(self, db: AsyncSession, ids: list) -> list:
        """Ids among `ids` that name no measure of the module (a remediation
        only links measures that exist). Modules without a measure store
        return `ids` unchanged."""
        ...

    async def measure_states(self, db: AsyncSession, ids: list) -> dict:
        """{id: status} of the module's measures among `ids`, the status being
        the module's own value ("termine" means done). Missing ids are absent."""
        ...


def _actor(user: Any) -> str:
    if user is None:
        return "system"
    return getattr(user, "name", None) or getattr(user, "email", None) or "system"


async def _audit(db: AsyncSession, user: Any, request: Optional[Request], action: str,
                 target: str, details: dict, actor: str = "") -> None:
    try:
        try:
            from src.audit_common import log_write
        except ImportError:
            from src.audit import log_write
        await log_write(db, user, request, action, target=target, details=details,
                        actor=actor, commit=False)
    except Exception:
        logger.debug("audit skipped for %s", action, exc_info=True)


# ── serialization ────────────────────────────────────────────────────────

def subjects_of(n: Any) -> list:
    """The record's items, the legacy single pair as a one-item list."""
    subs = [x for x in (n.subjects or []) if isinstance(x, dict) and x.get("id")]
    if not subs and n.subject_id:
        subs = [{"type": n.subject_type or "", "id": n.subject_id}]
    return [{"type": str(x.get("type") or ""), "id": str(x.get("id") or "")} for x in subs]


def normalize_subjects(subjects: Any, subject_type: str, subject_id: str, kinds: tuple) -> list:
    """The items a record is about, deduplicated, each of a kind the module
    attaches records to; the legacy single pair is the one-item form."""
    raw = list(subjects or [])
    if not raw and (subject_type or subject_id):
        raw = [{"type": subject_type, "id": subject_id}]
    if len(raw) > 50:
        raise HTTPException(status_code=422, detail="at most 50 subjects per record")
    out: list = []
    seen: set = set()
    for x in raw:
        st = str(x.get("type") or "").strip() if isinstance(x, dict) else ""
        sid = str(x.get("id") or "").strip()[:200] if isinstance(x, dict) else ""
        if st not in kinds or not sid:
            raise HTTPException(status_code=422, detail=f"each subject needs a type among {', '.join(kinds)} and an id")
        if (st, sid) in seen:
            continue
        seen.add((st, sid))
        out.append({"type": st, "id": sid})
    return out


def nc_to_dict(n: Any) -> dict:
    return {
        "id": str(n.id), "reference": n.reference, "source": n.source,
        "observed_at": n.observed_at.isoformat() if n.observed_at else None,
        "observed_by": n.observed_by or "", "declared_by": n.declared_by or "",
        "title": n.title, "description": n.description or "", "severity": n.severity,
        "evidence": n.evidence or [], "domain": n.domain or "",
        "requirement_ref": n.requirement_ref or "",
        "subject_type": n.subject_type or "", "subject_id": n.subject_id or "",
        "subjects": subjects_of(n),
        "status": n.status, "qualified_by": n.qualified_by or "",
        "qualified_at": n.qualified_at.isoformat() if n.qualified_at else None,
        "rejection_note": n.rejection_note or "",
        "closed_at": n.closed_at.isoformat() if n.closed_at else None,
        "closure_evidence": n.closure_evidence or "",
        "measure_ids": n.measure_ids or [],
        "derogation_id": str(n.derogation_id) if n.derogation_id else None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
    }


def der_to_dict(d: Any) -> dict:
    return {
        "id": str(d.id), "reference": d.reference,
        "subject_type": d.subject_type, "subject_id": d.subject_id,
        "subject_label": d.subject_label or "",
        "title": d.title, "justification": d.justification,
        "risk_owner": d.risk_owner, "approver": d.approver,
        "compensating_measure_ids": d.compensating_measure_ids or [],
        "valid_from": d.valid_from.isoformat() if d.valid_from else None,
        "valid_until": d.valid_until.isoformat() if d.valid_until else None,
        "review_at": d.review_at.isoformat() if d.review_at else None,
        "status": d.status, "requested_by": d.requested_by or "",
        "requested_at": d.requested_at.isoformat() if d.requested_at else None,
        "decided_by": d.decided_by or "",
        "decided_at": d.decided_at.isoformat() if d.decided_at else None,
        "decision_note": d.decision_note or "", "revoked_reason": d.revoked_reason or "",
        "renews_id": str(d.renews_id) if d.renews_id else None,
        "days_left": (d.valid_until - date.today()).days if d.valid_until and d.status == "approved" else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


# ── schemas ──────────────────────────────────────────────────────────────

class NonconformityCreate(BaseModel):
    title: str = Field(min_length=3, max_length=500)
    description: str = ""
    source: str = "observation"
    severity: str = "medium"
    observed_at: Optional[str] = None
    observed_by: str = ""
    domain: str = ""
    requirement_ref: str = ""
    subject_type: str = ""
    subject_id: str = ""
    # [{"type", "id"}]; the pair above is the one-item form.
    subjects: list = Field(default_factory=list)
    evidence: list = Field(default_factory=list)


class NonconformityPatch(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    observed_at: Optional[str] = None
    observed_by: Optional[str] = None
    domain: Optional[str] = None
    requirement_ref: Optional[str] = None
    evidence: Optional[list] = None
    measure_ids: Optional[list] = None
    # The items the record is about: set, changed or removed (empty list)
    # while no derogation covers the record; the module validates each item.
    # `subjects` replaces the list; the pair below is the one-item form.
    subjects: Optional[list] = None
    subject_type: Optional[str] = None
    subject_id: Optional[str] = None


class QualifyBody(BaseModel):
    severity: Optional[str] = None
    domain: Optional[str] = None
    requirement_ref: Optional[str] = None


class NoteBody(BaseModel):
    note: str = ""


class RemediationBody(BaseModel):
    measure_ids: list = Field(min_length=1, max_length=100)


class CloseBody(BaseModel):
    closure_evidence: str = Field(min_length=3)


class DerogationCreate(BaseModel):
    subject_type: str
    subject_id: str
    title: str = ""
    justification: str = ""
    risk_owner: str = ""
    approver: str = ""
    compensating_measure_ids: list = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    review_at: Optional[str] = None
    renews_id: Optional[str] = None


class DecisionBody(BaseModel):
    approve: bool
    note: str = ""


class RevokeBody(BaseModel):
    reason: str = Field(min_length=3)


class InternalDecision(BaseModel):
    """A decision relayed by Pilot: the Pilot user is the actor."""
    approve: bool
    note: str = ""
    actor: str = "pilot"


class InternalDeclaration(NonconformityCreate):
    """A declaration relayed by Pilot: the Pilot user is the declarant."""
    actor: str = "pilot"


class SettingsBody(BaseModel):
    max_derogation_days: int = Field(ge=1, le=3650)
    actor: str = ""            # relayed by the console; ignored by the module's own route


# ── expiration ───────────────────────────────────────────────────────────

async def expire_derogations(db: AsyncSession, Derogation: Any, hook: SubjectHook,
                             Nonconformity: Any = None, today: Optional[date] = None) -> int:
    """approved → expired for every derogation past its end date; the subject
    goes back to 'to fix'. Returns the number expired. Commits."""
    today = today or date.today()
    rows = (await db.execute(select(Derogation).where(Derogation.status == "approved",
                                                       Derogation.valid_until < today))).scalars().all()
    n = 0
    for d in rows:
        d.status = "expired"
        d.updated_at = _now()
        if d.subject_type not in ("nonconformity", "none"):
            await hook.release(db, d, "expired")
        if Nonconformity is not None and d.subject_type == "nonconformity":
            await _release_nonconformity(db, Nonconformity, d)
        await _audit(db, None, None, "derogation.expired", d.reference,
                     {"subject": f"{d.subject_type}:{d.subject_id}", "valid_until": d.valid_until.isoformat()},
                     actor="scheduler")
        n += 1
    if n:
        await db.commit()
    return n


async def _release_nonconformity(db: AsyncSession, Nonconformity: Any, d: Any) -> None:
    try:
        nc = await db.get(Nonconformity, uuid.UUID(str(d.subject_id)))
    except ValueError:
        nc = None
    if nc is not None and nc.status == "derogated":
        nc.status = "open"
        nc.derogation_id = None
        nc.updated_at = _now()


# ── router ───────────────────────────────────────────────────────────────

class NcService:
    """The operations shared by the module's own routes and the internal
    (service-token) routes Pilot calls: lookups, declaration, decision."""

    def __init__(self, Nonconformity: Any, Derogation: Any, hook: SubjectHook, subject_types: tuple) -> None:
        self.Nonconformity = Nonconformity
        self.Derogation = Derogation
        self.hook = hook
        self.kinds = tuple(subject_types) + ("nonconformity", "none")

    async def nc(self, db: AsyncSession, nc_id: str) -> Any:
        try:
            row = await db.get(self.Nonconformity, uuid.UUID(str(nc_id)))
        except ValueError:
            row = None
        if row is None:
            raise HTTPException(status_code=404, detail="Non-conformity not found")
        return row

    async def der(self, db: AsyncSession, der_id: str) -> Any:
        try:
            row = await db.get(self.Derogation, uuid.UUID(str(der_id)))
        except ValueError:
            row = None
        if row is None:
            raise HTTPException(status_code=404, detail="Derogation not found")
        return row

    async def subject_label(self, db: AsyncSession, subject_type: str, subject_id: str) -> str:
        if subject_type == "none":
            return ""
        if subject_type == "nonconformity":
            nc = await self.nc(db, subject_id)
            if nc.status not in ("to_qualify", "open", "in_remediation"):
                raise HTTPException(status_code=409, detail=f"non-conformity is '{nc.status}', not open")
            return f"{nc.reference} — {nc.title}"
        label = await self.hook.exists(db, subject_type, subject_id)
        if label is None:
            raise HTTPException(status_code=404, detail=f"{subject_type} '{subject_id}' not found")
        return label

    async def declare(self, db: AsyncSession, body: "NonconformityCreate", actor: str,
                      user: Any, request: Optional[Request]) -> dict:
        """A new non-conformity, 'to qualify'. `actor` is who declares it (the
        module's user, or the Pilot user relayed by the internal route)."""
        if body.source not in NC_SOURCES:
            raise HTTPException(status_code=422, detail=f"source must be one of {', '.join(NC_SOURCES)}")
        if body.severity not in NC_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"severity must be one of {', '.join(NC_SEVERITIES)}")
        nc_kinds = tuple(k for k in self.kinds if k not in ("nonconformity", "none"))
        subjects = normalize_subjects(body.subjects, body.subject_type, body.subject_id, nc_kinds)
        for sub in subjects:
            await self.subject_label(db, sub["type"], sub["id"])     # 404 / 409 from the module's hook
        observed = _as_date(body.observed_at) or date.today()
        if observed > date.today():
            raise HTTPException(status_code=422, detail="observed_at cannot be in the future")
        nc = self.Nonconformity(
            id=uuid.uuid4(), reference=await next_reference(db, self.Nonconformity, "NC"),
            source=body.source, observed_at=observed,
            observed_by=body.observed_by[:255] or actor, declared_by=actor,
            title=body.title.strip()[:500], description=body.description[:5000],
            severity=body.severity, evidence=body.evidence[:50],
            domain=body.domain[:100], requirement_ref=body.requirement_ref[:200],
            subject_type=subjects[0]["type"] if subjects else "", subject_id=subjects[0]["id"] if subjects else "",
            subjects=subjects, status="to_qualify",
        )
        await commit_with_reference(db, nc, self.Nonconformity, "NC")
        await _audit(db, user, request, "nonconformity.declared", nc.reference,
                     {"severity": nc.severity, "source": nc.source, "subjects": [f"{x['type']}:{x['id']}" for x in subjects]},
                     actor=actor)
        await db.commit()
        await db.refresh(nc)
        return nc_to_dict(nc)

    async def decide(self, db: AsyncSession, d: Any, approve: bool, note: str, actor: str,
                     user: Any, request: Optional[Request]) -> dict:
        """Approval or refusal; the subject is re-checked at approval."""
        new = "approved" if approve else "rejected"
        check_transition("derogation", d.status, new)
        if not approve and not (note or "").strip():
            raise HTTPException(status_code=422, detail="a refusal needs a note")
        d.status = new
        d.decided_by = actor
        d.decided_at = _now()
        d.decision_note = (note or "")[:5000]
        d.updated_at = _now()
        if approve:
            if d.subject_type == "nonconformity":
                nc = await self.nc(db, d.subject_id)
                check_transition("nonconformity", nc.status, "derogated")
                if nc.status == "to_qualify":          # approving the derogation accepts the finding
                    nc.qualified_by = actor
                    nc.qualified_at = _now()
                nc.status = "derogated"
                nc.derogation_id = d.id
                nc.updated_at = _now()
            elif d.subject_type != "none":
                # The subject may have moved on since the request (a finding
                # fixed meanwhile): approving would resurrect it.
                if await self.hook.exists(db, d.subject_type, d.subject_id) is None:
                    raise HTTPException(status_code=409, detail="the subject is no longer open: nothing to derogate")
                await self.hook.apply(db, d)
        await _audit(db, user, request, "derogation." + new, d.reference,
                     {"subject": f"{d.subject_type}:{d.subject_id}", "note": (note or "")[:200]}, actor=actor)
        await db.commit()
        await db.refresh(d)
        return der_to_dict(d)


async def declared_counts(db: AsyncSession, Nonconformity: Any) -> dict:
    """{to_qualify, open, derogated} of the declared non-conformities, for the
    stats envelope (a derogated record joins the module's derogated items)."""
    rows = (await db.execute(select(Nonconformity.status, func.count()).group_by(Nonconformity.status))).all()
    by = {status: int(n) for status, n in rows}
    return {"to_qualify": by.get("to_qualify", 0), "open": by.get("open", 0) + by.get("in_remediation", 0),
            "derogated": by.get("derogated", 0)}


def nc_treatment(nc: Any) -> str:
    """What carries the non-conformity today: a measure, a derogation, nothing."""
    if nc.status == "derogated":
        return "derogation"
    if nc.status == "in_remediation" and (nc.measure_ids or []):
        return "measure"
    return "none"


def make_internal_router(Nonconformity: Any, Derogation: Any, hook: SubjectHook,
                         subject_types: tuple, check_service_token: Any) -> APIRouter:
    """The register as Pilot sees it (service-token): every non-conformity
    with its treatment, every derogation, decisions and declarations relayed
    from Pilot with the Pilot user as actor, and the module's settings."""
    from src.database import get_db

    svc = NcService(Nonconformity, Derogation, hook, subject_types)
    router = APIRouter(prefix="/api/internal", tags=["nonconformities-internal"])

    @router.get("/nonconformities")
    async def internal_nonconformities(request: Request, status: Optional[str] = None,
                                       db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        q = select(Nonconformity).order_by(Nonconformity.created_at.desc())
        if status:
            q = q.where(Nonconformity.status == status)
        rows = (await db.execute(q)).scalars().all()
        items = []
        for r in rows:
            d = nc_to_dict(r)
            d["treatment"] = nc_treatment(r)
            items.append(d)
        return {"items": items, "total": len(items)}

    @router.post("/nonconformities", status_code=201)
    async def internal_declare(body: InternalDeclaration, request: Request,
                               db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        return await svc.declare(db, body, (body.actor or "pilot")[:255], None, request)

    @router.get("/derogations")
    async def internal_derogations(request: Request, status: Optional[str] = None,
                                   db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        q = select(Derogation).order_by(Derogation.created_at.desc())
        if status:
            q = q.where(Derogation.status == status)
        rows = (await db.execute(q)).scalars().all()
        return {"items": [der_to_dict(r) for r in rows], "total": len(rows)}

    @router.post("/derogations/{der_id}/decision")
    async def internal_decide(der_id: str, body: InternalDecision, request: Request,
                              db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        d = await svc.der(db, der_id)
        return await svc.decide(db, d, body.approve, body.note, (body.actor or "pilot")[:255], None, request)

    @router.get("/nonconformities-settings")
    async def internal_get_settings(request: Request, db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        return {"max_derogation_days": await max_derogation_days(db)}

    @router.put("/nonconformities-settings")
    async def internal_put_settings(body: SettingsBody, request: Request, db: AsyncSession = Depends(get_db)):
        check_service_token(request)
        from src.models import AppSettings
        row = await db.get(AppSettings, MAX_DAYS_SETTING)
        if row is None:
            db.add(AppSettings(key=MAX_DAYS_SETTING, value=str(body.max_derogation_days)))
        else:
            row.value = str(body.max_derogation_days)
        await _audit(db, None, request, "nonconformity.settings", MAX_DAYS_SETTING,
                     {"max_derogation_days": body.max_derogation_days}, actor=(body.actor or "pilot")[:255])
        await db.commit()
        return {"max_derogation_days": body.max_derogation_days}

    return router


def make_router(Nonconformity: Any, Derogation: Any, hook: SubjectHook,
                subject_types: tuple[str, ...]) -> APIRouter:
    """The module mounts this once. ``subject_types`` are the kinds a
    derogation may cover in this module ('finding', 'control'…); the
    kind 'nonconformity' is always accepted."""
    from src.auth import get_current_user, require_admin
    from src.database import get_db

    router = APIRouter(prefix="/api", tags=["nonconformities"])
    # "none": a free derogation — an accepted deviation with no item behind
    # it (a practice, a policy clause); the title says what it covers.
    kinds = tuple(subject_types) + ("nonconformity", "none")

    svc = NcService(Nonconformity, Derogation, hook, subject_types)
    _nc = svc.nc
    _der = svc.der
    _subject_label = svc.subject_label

    # -- non-conformities --------------------------------------------------
    @router.get("/nonconformities")
    async def list_nonconformities(status: Optional[str] = None,
                                   user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        q = select(Nonconformity).order_by(Nonconformity.created_at.desc())
        if status:
            q = q.where(Nonconformity.status == status)
        rows = (await db.execute(q)).scalars().all()
        return {"items": [nc_to_dict(r) for r in rows], "total": len(rows)}

    @router.post("/nonconformities", status_code=201)
    async def declare_nonconformity(body: NonconformityCreate, request: Request,
                                    user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        return await svc.declare(db, body, _actor(user), user, request)

    @router.get("/nonconformities/{nc_id}")
    async def get_nonconformity(nc_id: str, user=Depends(get_current_user),
                                db: AsyncSession = Depends(get_db)):
        return nc_to_dict(await _nc(db, nc_id))

    @router.patch("/nonconformities/{nc_id}")
    async def patch_nonconformity(nc_id: str, body: NonconformityPatch,
                                  user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        nc = await _nc(db, nc_id)
        if nc.status in ("closed", "rejected"):
            raise HTTPException(status_code=409, detail=f"non-conformity is '{nc.status}'")
        # Before qualification the declarant may still correct the record;
        # afterwards, and for anyone else, it is an administrator's edit.
        if nc.status != "to_qualify" or (nc.declared_by or "") != _actor(user):
            require_admin(user)
        data = body.model_dump(exclude_unset=True)
        if "title" in data and len(str(data["title"] or "").strip()) < 3:
            raise HTTPException(status_code=422, detail="title needs at least 3 characters")
        if "source" in data and data["source"] not in NC_SOURCES:
            raise HTTPException(status_code=422, detail=f"source must be one of {', '.join(NC_SOURCES)}")
        if "severity" in data and data["severity"] not in NC_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"severity must be one of {', '.join(NC_SEVERITIES)}")
        if "observed_at" in data:
            observed = _as_date(data["observed_at"]) or nc.observed_at
            if observed and observed > date.today():
                raise HTTPException(status_code=422, detail="observed_at cannot be in the future")
            data["observed_at"] = observed
        if "evidence" in data:
            data["evidence"] = [str(e)[:1000] for e in (data["evidence"] or [])][:50]
        if "subjects" in data or "subject_type" in data or "subject_id" in data:
            nc_kinds = tuple(k for k in kinds if k not in ("nonconformity", "none"))
            wanted = normalize_subjects(data.pop("subjects", None), str(data.pop("subject_type", "") or ""),
                                        str(data.pop("subject_id", "") or ""), nc_kinds)
            current = subjects_of(nc)
            if wanted != current:
                # Requested or granted on this record, the derogation was about its subjects.
                covered = nc.derogation_id or await db.scalar(
                    select(func.count()).select_from(Derogation).where(
                        Derogation.subject_type == "nonconformity", Derogation.subject_id == str(nc.id),
                        Derogation.status.in_(["pending_approval", "approved"])))
                if covered:
                    raise HTTPException(status_code=409, detail="a derogation covers the non-conformity: its subjects cannot change")
                for sub in wanted:
                    if sub not in current:
                        await _subject_label(db, sub["type"], sub["id"])      # 404 / 409 from the module's hook
                data["subjects"] = wanted
                data["subject_type"] = wanted[0]["type"] if wanted else ""
                data["subject_id"] = wanted[0]["id"] if wanted else ""
        if "measure_ids" in data:
            ids = []
            for m in data["measure_ids"] or []:
                m = str(m).strip()[:64]
                if m and m not in ids:
                    ids.append(m)
            if nc.status == "in_remediation" and not ids:
                raise HTTPException(status_code=422, detail="remediation: at least one corrective measure is required")
            missing = await hook.missing_measures(db, ids) if ids else []
            if missing:
                raise HTTPException(status_code=422, detail=f"unknown measure(s) {', '.join(missing)}")
            data["measure_ids"] = ids
            if ids and nc.status == "open":          # the first corrective measure starts the remediation
                data["status"] = "in_remediation"
        caps = {"title": 500, "description": 5000, "observed_by": 255, "domain": 100, "requirement_ref": 200}
        for field, value in data.items():
            setattr(nc, field, value[:caps.get(field, 5000)] if isinstance(value, str) else value)
        nc.updated_at = _now()
        await _audit(db, user, None, "nonconformity.updated", nc.reference, {"fields": sorted(data.keys())})
        await db.commit()
        await db.refresh(nc)
        return nc_to_dict(nc)

    @router.post("/nonconformities/{nc_id}/qualify")
    async def qualify_nonconformity(nc_id: str, body: QualifyBody,
                                    user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        require_admin(user)
        nc = await _nc(db, nc_id)
        check_transition("nonconformity", nc.status, "open")
        if body.severity:
            if body.severity not in NC_SEVERITIES:
                raise HTTPException(status_code=422, detail=f"severity must be one of {', '.join(NC_SEVERITIES)}")
            nc.severity = body.severity
        if body.domain is not None:
            nc.domain = body.domain[:100]
        if body.requirement_ref is not None:
            nc.requirement_ref = body.requirement_ref[:200]
        nc.status = "open"
        nc.qualified_by = _actor(user)
        nc.qualified_at = _now()
        nc.updated_at = _now()
        await _audit(db, user, None, "nonconformity.qualified", nc.reference, {"severity": nc.severity})
        await db.commit()
        await db.refresh(nc)
        return nc_to_dict(nc)

    @router.post("/nonconformities/{nc_id}/reject")
    async def reject_nonconformity(nc_id: str, body: NoteBody,
                                   user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        require_admin(user)
        nc = await _nc(db, nc_id)
        check_transition("nonconformity", nc.status, "rejected")
        if not body.note.strip():
            raise HTTPException(status_code=422, detail="a rejection needs a note")
        nc.status = "rejected"
        nc.rejection_note = body.note[:5000]
        nc.qualified_by = _actor(user)
        nc.qualified_at = _now()
        nc.updated_at = _now()
        await revoke_for_subject(db, Derogation, "nonconformity", str(nc.id), "non-conformity rejected", _actor(user))
        await _audit(db, user, None, "nonconformity.rejected", nc.reference, {"note": body.note[:200]})
        await db.commit()
        return nc_to_dict(nc)

    @router.post("/nonconformities/{nc_id}/remediation")
    async def nonconformity_in_remediation(nc_id: str, body: RemediationBody,
                                           user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        """The non-conformity is in remediation: at least one corrective
        measure of the module is linked, and every id must exist. Also the
        way to change the linked measures while in remediation."""
        nc = await _nc(db, nc_id)
        if nc.status != "in_remediation":
            check_transition("nonconformity", nc.status, "in_remediation")
        ids = []
        for m in body.measure_ids:
            m = str(m).strip()[:64]
            if m and m not in ids:
                ids.append(m)
        if not ids:
            raise HTTPException(status_code=422, detail="remediation: at least one corrective measure is required")
        missing = await hook.missing_measures(db, ids)
        if missing:
            raise HTTPException(status_code=422, detail=f"remediation: unknown measure(s) {', '.join(missing)}")
        nc.measure_ids = ids
        nc.status = "in_remediation"
        nc.updated_at = _now()
        await _audit(db, user, None, "nonconformity.remediation", nc.reference, {"measure_ids": ids})
        await db.commit()
        return nc_to_dict(nc)

    @router.post("/nonconformities/{nc_id}/close")
    async def close_nonconformity(nc_id: str, body: CloseBody,
                                  user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        require_admin(user)
        nc = await _nc(db, nc_id)
        check_transition("nonconformity", nc.status, "closed")
        # Closing means the remediation is done: every linked measure is.
        if nc.measure_ids:
            states = await hook.measure_states(db, list(nc.measure_ids))
            pending = [m for m in nc.measure_ids if states.get(m) != "termine"]
            if pending:
                raise HTTPException(status_code=409,
                                    detail=f"measures not done: {', '.join(pending)}")
        await revoke_for_subject(db, Derogation, "nonconformity", str(nc.id), "non-conformity closed", _actor(user))
        nc.status = "closed"
        nc.closure_evidence = body.closure_evidence[:5000]
        nc.closed_at = _now()
        nc.derogation_id = None
        nc.updated_at = _now()
        await _audit(db, user, None, "nonconformity.closed", nc.reference, {"evidence": body.closure_evidence[:200]})
        await db.commit()
        return nc_to_dict(nc)

    # -- derogations ---------------------------------------------------------
    @router.get("/derogations")
    async def list_derogations(status: Optional[str] = None, subject_type: Optional[str] = None,
                               subject_id: Optional[str] = None,
                               user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        q = select(Derogation).order_by(Derogation.created_at.desc())
        if status:
            q = q.where(Derogation.status == status)
        if subject_type:
            q = q.where(Derogation.subject_type == subject_type)
        if subject_id:
            q = q.where(Derogation.subject_id == subject_id)
        rows = (await db.execute(q)).scalars().all()
        return {"items": [der_to_dict(r) for r in rows], "total": len(rows)}

    @router.post("/derogations", status_code=201)
    async def request_derogation(body: DerogationCreate, request: Request,
                                 user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        if body.subject_type not in kinds:
            raise HTTPException(status_code=422, detail=f"subject_type must be one of {', '.join(kinds)}")
        dates = validate_derogation_request(body.model_dump(), await max_derogation_days(db))
        # A live derogation on the subject is the first thing to say: once
        # approved, the subject is no longer "open", and a 404 would hide it.
        pending = 0 if body.subject_type == "none" else await db.scalar(
            select(func.count()).select_from(Derogation).where(
                Derogation.subject_type == body.subject_type, Derogation.subject_id == body.subject_id,
                Derogation.status.in_(["pending_approval", "approved"])))
        if pending:
            raise HTTPException(status_code=409, detail="this subject already has a pending or approved derogation")
        label = await _subject_label(db, body.subject_type, body.subject_id)
        renews = None
        if body.renews_id:
            prev = await _der(db, body.renews_id)
            if prev.subject_type != body.subject_type or prev.subject_id != body.subject_id:
                raise HTTPException(status_code=422, detail="renews_id must point at a derogation of the same subject")
            renews = prev.id
        d = Derogation(
            id=uuid.uuid4(), reference=await next_reference(db, Derogation, "DER"),
            subject_type=body.subject_type, subject_id=("" if body.subject_type == "none" else body.subject_id)[:200],
            subject_label=label[:500],
            title=body.title.strip()[:500], justification=body.justification.strip()[:10000],
            risk_owner=body.risk_owner.strip()[:255], approver=body.approver.strip()[:255],
            compensating_measure_ids=[str(m)[:64] for m in body.compensating_measure_ids][:100],
            valid_from=dates["valid_from"], valid_until=dates["valid_until"], review_at=dates["review_at"],
            status="pending_approval", requested_by=_actor(user), requested_at=_now(), renews_id=renews,
        )
        await commit_with_reference(db, d, Derogation, "DER")
        await _audit(db, user, request, "derogation.requested", d.reference,
                     {"subject": f"{d.subject_type}:{d.subject_id}", "valid_until": str(d.valid_until)})
        await db.commit()
        await db.refresh(d)
        return der_to_dict(d)

    @router.get("/derogations/{der_id}")
    async def get_derogation(der_id: str, user=Depends(get_current_user),
                             db: AsyncSession = Depends(get_db)):
        return der_to_dict(await _der(db, der_id))

    @router.post("/derogations/{der_id}/decision")
    async def decide_derogation(der_id: str, body: DecisionBody, request: Request,
                                user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        require_admin(user)
        d = await _der(db, der_id)
        return await svc.decide(db, d, body.approve, body.note, _actor(user), user, request)

    @router.post("/derogations/{der_id}/revoke")
    async def revoke_derogation(der_id: str, body: RevokeBody, request: Request,
                                user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        require_admin(user)
        d = await _der(db, der_id)
        check_transition("derogation", d.status, "revoked")
        d.status = "revoked"
        d.revoked_reason = body.reason[:5000]
        d.decided_by = _actor(user)
        d.updated_at = _now()
        if d.subject_type == "nonconformity":
            await _release_nonconformity(db, Nonconformity, d)
        elif d.subject_type != "none":
            await hook.release(db, d, "revoked")
        await _audit(db, user, request, "derogation.revoked", d.reference, {"reason": body.reason[:200]})
        await db.commit()
        await db.refresh(d)
        return der_to_dict(d)

    # -- settings ------------------------------------------------------------
    @router.get("/nonconformities-settings")
    async def get_settings(user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
        return {"max_derogation_days": await max_derogation_days(db),
                "sources": list(NC_SOURCES), "severities": list(NC_SEVERITIES),
                "subject_types": list(kinds)}

    @router.put("/nonconformities-settings")
    async def put_settings(body: SettingsBody, user=Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
        require_admin(user)
        from src.models import AppSettings
        row = await db.get(AppSettings, MAX_DAYS_SETTING)
        if row is None:
            db.add(AppSettings(key=MAX_DAYS_SETTING, value=str(body.max_derogation_days)))
        else:
            row.value = str(body.max_derogation_days)
        await _audit(db, user, None, "nonconformity.settings", MAX_DAYS_SETTING,
                     {"max_derogation_days": body.max_derogation_days})
        await db.commit()
        return {"max_derogation_days": body.max_derogation_days}

    return router


async def revoke_for_subject(db: AsyncSession, Derogation: Any, subject_type: str, subject_id: str,
                             reason: str, actor: str = "system") -> int:
    """When the module itself moves a derogated item (a triage, a closure),
    the covering derogation is revoked with that reason. No commit."""
    rows = (await db.execute(select(Derogation).where(
        Derogation.subject_type == subject_type, Derogation.subject_id == str(subject_id),
        Derogation.status.in_(["approved", "pending_approval"])))).scalars().all()
    for d in rows:
        if d.status == "approved":
            d.status = "revoked"
            d.revoked_reason = reason[:5000]
        else:                       # a request on a subject that moved on is moot
            d.status = "rejected"
            d.decision_note = reason[:5000]
            d.decided_at = _now()
        d.decided_by = actor
        d.updated_at = _now()
    return len(rows)


__all__ = [
    "commit_with_reference", "make_internal_router", "NcService", "nc_treatment", "InternalDecision", "InternalDeclaration", "declared_counts",
    "NC_SOURCES", "NC_SEVERITIES", "NC_STATUSES", "NC_TRANSITIONS",
    "DER_STATUSES", "DER_TRANSITIONS", "DEFAULT_MAX_DAYS", "MAX_DAYS_SETTING",
    "define_models", "check_transition", "validate_derogation_request", "next_reference",
    "max_derogation_days", "SubjectHook", "expire_derogations", "make_router",
    "revoke_for_subject", "nc_to_dict", "der_to_dict",
]
