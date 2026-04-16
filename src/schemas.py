from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

import json as _json

# Hard cap on serialized JSONB evidence payload (~ 32 KB)
_MAX_EVIDENCE_BYTES = 32768


# ── User ───────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    role: str = "user"
    ai_enabled: str = "false"
    last_login: Optional[datetime] = None
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    role: Optional[str] = None
    ai_enabled: Optional[str] = None


# ── Findings ───────────────────────────────────────────────────

class FindingCreate(BaseModel):
    scanner: str = Field("manual", max_length=100)
    type: str = Field("other", max_length=100)
    severity: str = Field("medium", max_length=20)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field("", max_length=10000)
    target: str = Field("", max_length=500)
    evidence: dict[str, Any] = {}

    @field_validator("evidence")
    @classmethod
    def _cap_evidence(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(_json.dumps(v or {})) > _MAX_EVIDENCE_BYTES:
            raise ValueError(f"evidence payload too large (>{_MAX_EVIDENCE_BYTES} bytes serialized)")
        return v or {}


class FindingTriage(BaseModel):
    status: str  # false_positive | to_fix | new
    notes: Optional[str] = None  # required when status=false_positive (justification)
    measure_title: Optional[str] = None       # required when status=to_fix
    measure_description: Optional[str] = None
    responsable: Optional[str] = None
    echeance: Optional[str] = None


class FindingResponse(BaseModel):
    id: uuid.UUID
    scanner: str
    type: str
    severity: str
    title: str
    description: str
    target: str
    evidence: dict[str, Any]
    status: str
    triaged_at: Optional[datetime]
    triaged_by: Optional[str]
    triage_notes: Optional[str]
    created_at: datetime
    measure_id: Optional[str] = None
    model_config = {"from_attributes": True}


# ── Measures ───────────────────────────────────────────────────

class MeasureUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    statut: Optional[str] = None
    responsable: Optional[str] = None
    echeance: Optional[str] = None


class MeasureResponse(BaseModel):
    id: str
    finding_id: uuid.UUID
    title: str
    description: str
    statut: str
    responsable: str
    echeance: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ── AI ─────────────────────────────────────────────────────────

class AICompleteRequest(BaseModel):
    system: str
    user: str
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"


class AICompleteResponse(BaseModel):
    text: str


class AIConfigResponse(BaseModel):
    anthropic_configured: bool
    openai_configured: bool
    providers: dict[str, dict[str, Any]]


class AIRuntimeResponse(BaseModel):
    managed: bool
    can_use: bool
    provider: str
    model: str
    anthropic_configured: bool
    openai_configured: bool
    custom_configured: bool = False
