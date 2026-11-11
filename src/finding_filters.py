"""The Findings table's filters, sort and search, applied by the server
(FEAT-70): the table reads one page at a time, and a bulk action can target
every finding of the filter instead of a list of ids.

Each pill row (status, severity, scanner) has included and excluded values:
a finding passes a row if it has one of the included values (or none is
included) and none of the excluded ones; the rows combine with AND. The
search looks for its text, case-insensitive, in the stored title,
description, target, scanner and type.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import ColumnElement, or_

from src.finding_assets import OPEN, SEVERITIES, SEVERITY_RANK, STATUSES
from src.models import Finding

_SEARCH_MAX = 200


class FindingFilter(BaseModel):
    # A misspelt key would widen the filter to every finding: refuse it.
    model_config = ConfigDict(extra="forbid")

    status: list[str] = Field(default_factory=list)
    status_not: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    severity_not: list[str] = Field(default_factory=list)
    scanner: list[str] = Field(default_factory=list)
    scanner_not: list[str] = Field(default_factory=list)
    q: str = ""


def _statuses(values: list[str]) -> list[str]:
    # "open" is the shortcut for the statuses still to be handled.
    out: list[str] = []
    for v in values:
        for s in (OPEN if v == "open" else (v,)):
            if s in STATUSES and s not in out:
                out.append(s)
    return out


def _severities(values: list[str]) -> list[str]:
    return [v for v in values if v in SEVERITIES]


def _scanners(values: list[str]) -> list[str]:
    return [v for v in values if v][:100]


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def conditions(f: FindingFilter) -> list[ColumnElement[bool]]:
    """The WHERE clauses of a filter. Unknown statuses and severities are
    ignored; a row whose included values are all unknown matches nothing."""
    out: list[ColumnElement[bool]] = []
    for column, inc_raw, exc_raw, clean in (
        (Finding.status, f.status, f.status_not, _statuses),
        (Finding.severity, f.severity, f.severity_not, _severities),
        (Finding.scanner, f.scanner, f.scanner_not, _scanners),
    ):
        inc_raw = [v for v in inc_raw if v]
        inc, exc = clean(inc_raw), clean(exc_raw)
        if inc_raw:
            out.append(column.in_(inc))
        if exc:
            out.append(column.notin_(exc))
    q = (f.q or "").strip()[:_SEARCH_MAX]
    if q:
        pattern = "%" + _like_escape(q) + "%"
        out.append(or_(*(col.ilike(pattern, escape="\\") for col in (
            Finding.title, Finding.description, Finding.target, Finding.scanner, Finding.type))))
    return out


SortKey = Literal["created_at", "severity"]
SortDir = Literal["asc", "desc"]


def order_by(sort: SortKey, direction: SortDir) -> list:
    """The table's order, stable across pages: severity "desc" is the most
    severe first; ties newest first, then by id."""
    if sort == "severity":
        rank = SEVERITY_RANK.asc() if direction == "desc" else SEVERITY_RANK.desc()
        return [rank, Finding.created_at.desc(), Finding.id]
    created = Finding.created_at.desc() if direction == "desc" else Finding.created_at.asc()
    return [created, Finding.id]
