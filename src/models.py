from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ── Status enums — kept as string enums for JSON serialization ─

class FindingStatus(str, Enum):
    NEW = "new"
    FALSE_POSITIVE = "false_positive"
    TO_FIX = "to_fix"
    FIXED = "fixed"


class ScanJobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class MeasureStatus(str, Enum):
    A_FAIRE = "a_faire"
    EN_COURS = "en_cours"
    TERMINE = "termine"


# ── Auth & Settings ────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)
    picture = Column(String(500), nullable=True)
    provider = Column(String(50), nullable=False)
    provider_id = Column(String(255), nullable=False)
    role = Column(String(50), default="user", server_default=text("'user'"))
    ai_enabled = Column(String(5), default="false", server_default=text("'false'"))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    last_login = Column(DateTime(timezone=True), nullable=True)


class AppSettings(Base):
    __tablename__ = "app_settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False, default="")


# ── Findings ───────────────────────────────────────────────────
# A Finding is anything detected by the scanner: vulnerability, misconfig,
# exposed asset, etc. The user triages it as false_positive or to_fix.
# Triaging to_fix automatically creates a Measure.

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    # Source (which scanner produced it)
    scanner = Column(String(100), nullable=False, default="manual")  # nuclei | semgrep | osv | manual | ...
    # Type / category, e.g. "xss", "sqli", "outdated_dep", "open_port"
    type = Column(String(100), nullable=False, default="other")
    severity = Column(String(20), nullable=False, default="medium")  # info | low | medium | high | critical
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True, default="")
    target = Column(String(500), nullable=True, default="")  # URL / host / asset
    evidence = Column(JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb"))
    # Triage status
    status = Column(String(30), nullable=False, default="new", server_default=text("'new'"))
    # new | false_positive | to_fix | fixed
    triaged_at = Column(DateTime(timezone=True), nullable=True)
    triaged_by = Column(String(255), nullable=True)
    triage_notes = Column(Text, nullable=True, default="")
    # Deduplication: same dedup_key across rescans means same finding.
    # Format: "<scanner>|<type>|<target>" (computed at insert time).
    dedup_key = Column(String(500), nullable=True, unique=True, index=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    measure = relationship("Measure", back_populates="finding", uselist=False, cascade="all, delete-orphan")


# ── Measures (auto-created from to_fix findings) ───────────────

class Measure(Base):
    __tablename__ = "measures"

    id = Column(String(30), primary_key=True)  # short readable id like SRF-001
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True)
    sort_order = Column(Integer, nullable=False, default=0)
    title = Column(String(500), nullable=False, default="")
    description = Column(Text, nullable=True, default="")
    statut = Column(String(50), nullable=False, default="a_faire")  # a_faire | en_cours | termine
    responsable = Column(String(255), nullable=True, default="")
    echeance = Column(String(20), nullable=True, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))

    finding = relationship("Finding", back_populates="measure")


# ── Scan jobs (async heavy scans) ─────────────────────────────

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    target = Column(String(500), nullable=False)
    profile = Column(String(50), nullable=False, default="quick")  # quick | standard | deep
    scanner = Column(String(50), nullable=False, default="nmap")
    status = Column(String(20), nullable=False, default="pending")  # pending | running | completed | failed
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    findings_count = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True, default="")
    raw_output = Column(Text, nullable=True, default="")
    triggered_by = Column(String(255), nullable=True, default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))


# ── Monitored assets (perimeter to scan) ──────────────────────

class MonitoredAsset(Base):
    __tablename__ = "monitored_assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()"))
    kind = Column(String(20), nullable=False, default="domain")  # domain | ip | ip_range
    value = Column(String(500), nullable=False)
    label = Column(String(255), nullable=True, default="")
    notes = Column(Text, nullable=True, default="")
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    scan_frequency_hours = Column(Integer, nullable=False, default=24, server_default=text("24"))
    enabled_scanners = Column(JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb"))
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), server_default=text("NOW()"))
