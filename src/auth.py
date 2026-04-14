"""Auth module — supports standalone (token-based) and suite-integrated modes.
Reads per-module permissions from the JWT `permissions` field.
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

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24
AUTH_MODE = os.getenv("AUTH_MODE", "standalone")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
MODULE_COOKIE = os.getenv("MODULE_COOKIE", "module_token")
MODULE_NAME = os.getenv("MODULE_NAME", "")  # e.g. "risk", "vendor", "access"

COOKIE_NAME = "pilot_token" if AUTH_MODE == "pilot" else MODULE_COOKIE


def auth_enabled() -> bool:
    if AUTH_MODE == "standalone":
        return bool(AUTH_TOKEN) and bool(JWT_SECRET)
    return bool(JWT_SECRET)


def assert_auth_configured() -> None:
    """Called at startup. Refuse to boot if auth is silently disabled,
    unless SURFACE_ALLOW_NO_AUTH=1 is explicitly set (dev only)."""
    if auth_enabled():
        return
    if os.getenv("SURFACE_ALLOW_NO_AUTH", "") == "1":
        return
    raise RuntimeError(
        "Authentication is not configured. Set JWT_SECRET "
        "(and AUTH_TOKEN in standalone mode), or explicitly allow "
        "unauthenticated access with SURFACE_ALLOW_NO_AUTH=1 for dev."
    )


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


async def _sync_user_from_jwt(db: AsyncSession, payload: dict) -> User:
    """Find or create a local user record from JWT claims."""
    email = payload.get("email", "")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user:
        return user
    user = User(
        email=email,
        name=email.split("@")[0],
        provider="pilot" if AUTH_MODE == "pilot" else "token",
        provider_id=payload.get("sub", ""),
        role=payload.get("role", "user"),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _get_module_role(payload: dict) -> str:
    """Extract the role for this module from the JWT permissions."""
    perms = payload.get("permissions") or {}
    if MODULE_NAME and MODULE_NAME in perms:
        return perms[MODULE_NAME]
    # Fallback: suite-wide admin → grant admin on this module
    if payload.get("role") == "admin":
        return "admin"
    return ""


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    if not auth_enabled():
        return None
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_jwt(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check module-level permission
    module_role = _get_module_role(payload)
    if not module_role and payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No access to this module")

    user = await _sync_user_from_jwt(db, payload)
    # Store the module role on the user object for route-level checks
    user._module_role = module_role  # type: ignore
    return user


def get_module_role(user: Optional[User]) -> str:
    """Get the module-specific role for the current user."""
    if user is None:
        return "admin"  # no auth = full access
    return getattr(user, "_module_role", "") or "admin"


def require_admin(user: Optional[User]) -> None:
    if user is None:
        return
    role = get_module_role(user)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
