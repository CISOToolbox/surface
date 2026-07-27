"""Shared auth module for CISO Toolbox backend modules.

This file is COPIED into each module's src/ directory by the deploy/sync
scripts. Do NOT edit the per-module copies — edit the original at
shared/python/auth_common.py and propagate.

Supports three modes:
  - **pilot** (AUTH_MODE=pilot, default): Suite-integrated. JWT cookie set by
    Pilot, per-module permissions in the JWT `permissions` dict.
  - **standalone** (AUTH_MODE=standalone): Own login flow via AUTH_TOKEN.
  - **none** (AUTH_MODE=none): Authentication DISABLED — every route is served
    as admin. Dev/test only, and the ONLY way to run without a credential:
    `assert_auth_posture()` refuses to boot if the mode's credential is missing
    in any other mode, so an unconfigured production can never silently open up.

Configuration (env vars read at import time):
  JWT_SECRET, AUTH_MODE, AUTH_TOKEN, MODULE_COOKIE, MODULE_NAME
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
import jwt
from jwt.exceptions import InvalidTokenError as JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.models import User

# ── Configuration (read once at import) ──────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
AUTH_MODE = os.getenv("AUTH_MODE", "pilot")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
MODULE_COOKIE = os.getenv("MODULE_COOKIE", "module_token")
MODULE_NAME = os.getenv("MODULE_NAME", "")

COOKIE_NAME = "pilot_token" if AUTH_MODE == "pilot" else MODULE_COOKIE


# ── Auth state ───────────────────────────────────────────────────

def auth_enabled() -> bool:
    if AUTH_MODE == "none":
        return False
    if AUTH_MODE == "standalone":
        return bool(AUTH_TOKEN)
    return bool(JWT_SECRET)


def assert_auth_posture() -> None:
    """Fail closed unless no-auth is explicitly opted into. Call once at
    application startup.

    Running with authentication disabled is a deliberate dev/test convenience
    and MUST be requested explicitly via AUTH_MODE=none. In any other mode an
    empty credential (JWT_SECRET in pilot mode, AUTH_TOKEN in standalone) would
    make `auth_enabled()` False and serve every route as admin — a silent
    production footgun. Refuse to boot in that grey area instead of opening up.
    """
    if AUTH_MODE == "none":
        return
    if not auth_enabled():
        cred = "AUTH_TOKEN" if AUTH_MODE == "standalone" else "JWT_SECRET"
        raise RuntimeError(
            f"{cred} is empty but AUTH_MODE is '{AUTH_MODE}', not 'none'. "
            f"Set {cred} to enable authentication (production), or set "
            "AUTH_MODE=none to run without authentication (test only). "
            "Refusing to start."
        )


# ── JWT ──────────────────────────────────────────────────────────

def create_jwt(user_id: str, email: str, role: str, permissions: dict | None = None) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "permissions": permissions or {},
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ── User sync ────────────────────────────────────────────────────

async def _sync_user_from_jwt(db: AsyncSession, payload: dict) -> User:
    """Find or create a local user record from JWT claims.

    The JWT is the source of truth for the display name AND the global role
    (Pilot puts both in the payload). If either is present and differs from
    the stored value, refresh it — otherwise the row is frozen at the value
    it was first created with, so a role change in Pilot (or a standalone
    re-login) would never take effect and a demotion would never apply.
    """
    email = payload.get("email", "")
    jwt_name = (payload.get("name") or "").strip()
    jwt_role = payload.get("role")
    fallback_name = email.split("@")[0] if email else ""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user:
        dirty = False
        if jwt_name and user.name != jwt_name:
            user.name = jwt_name
            dirty = True
        if jwt_role and user.role != jwt_role:
            user.role = jwt_role
            dirty = True
        if dirty:
            await db.commit()
        return user
    user = User(
        email=email,
        name=jwt_name or fallback_name,
        provider="pilot" if AUTH_MODE == "pilot" else "token",
        provider_id=payload.get("sub", ""),
        role=payload.get("role", "user"),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ── Module-role resolution ───────────────────────────────────────

def _get_module_role(payload: dict) -> str:
    """Extract the role for this module from the JWT permissions dict.

    A per-module role always wins. Otherwise a global role maps through:
    a suite admin is admin everywhere, and a suite "viewer" is read-only
    everywhere (instead of being blocked at get_current_user with no role)."""
    perms = payload.get("permissions") or {}
    if MODULE_NAME and MODULE_NAME in perms:
        return perms[MODULE_NAME]
    role = payload.get("role")
    if role == "admin":
        return "admin"
    if role == "viewer":
        return "viewer"
    return ""


async def _resolve_user_from_cookie(
    request: Request,
    db: AsyncSession,
) -> tuple[Optional[User], str]:
    """Decode the JWT cookie, sync the user row and return (user, module_role).
    Raises 401 if unauthenticated, but does NOT check module permissions
    — callers decide what to enforce."""
    if not auth_enabled():
        return None, "admin"
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_jwt(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    module_role = _get_module_role(payload)
    if not module_role and payload.get("role") == "admin":
        module_role = "admin"
    user = await _sync_user_from_jwt(db, payload)
    user._module_role = module_role or ""  # type: ignore
    return user, module_role or ""


# ── FastAPI dependencies ─────────────────────────────────────────

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Standard dependency for business routes — rejects users without
    a module role with 403."""
    user, module_role = await _resolve_user_from_cookie(request, db)
    if user is not None and not module_role:
        raise HTTPException(status_code=403, detail="No access to this module")
    return user


async def get_current_user_permissive(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Permissive dependency for /auth/me and /auth/role — always returns
    the user regardless of module permissions."""
    user, _ = await _resolve_user_from_cookie(request, db)
    return user


# ── Role helpers ─────────────────────────────────────────────────

def get_module_role(user: Optional[User]) -> str:
    if user is None:
        return "admin"  # no auth = full access
    return getattr(user, "_module_role", "") or "admin"


# Canonical module-role vocabulary for the owner-model modules. Centralised so
# the role strings live in ONE place (a typo can't silently create a role that
# maps to nothing) and the ladder below reads as intent. "control" = internal
# controls team, admin-equivalent at the module level.
ADMIN_MODULE_ROLES = ("admin", "control")
EDITOR_MODULE_ROLES = ("editor", "contributor", "manager")
VIEWER_MODULE_ROLES = ("viewer", "reader", "triager")


# Canonical module-role → permission ladder. Single source of truth for the
# owner-model modules (risk, vendor, compliance) so a given role grants the
# SAME rights everywhere instead of each module rolling its own ladder (or, as
# risk did, having none). An unknown/empty role grants nothing.
def perms_for_module_role(role: str) -> list[str]:
    if role in ADMIN_MODULE_ROLES:
        return ["read", "edit", "delete", "share"]
    if role in EDITOR_MODULE_ROLES:
        return ["read", "edit"]
    if role in VIEWER_MODULE_ROLES:
        return ["read"]
    return []


def require_min_role(user: Optional[User], min_role: str, hierarchy: list[str]) -> None:
    """Check the user has at least min_role in the given hierarchy."""
    role = get_module_role(user)
    if role == "admin":
        return
    if not role:
        raise HTTPException(status_code=403, detail="No access to this module")
    if role not in hierarchy or min_role not in hierarchy:
        raise HTTPException(status_code=403, detail=f"Requires {min_role} role")
    if hierarchy.index(role) < hierarchy.index(min_role):
        raise HTTPException(status_code=403, detail=f"Requires {min_role} role, you have {role}")


def require_admin(user: Optional[User]) -> None:
    if user is None:
        return
    role = get_module_role(user)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
