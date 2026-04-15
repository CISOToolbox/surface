"""Auth routes — dual mode:

- **suite mode** (``AUTH_MODE=pilot``): Surface delegates the login UI to the
  central Pilot login page. The OAuth/OIDC flow happens in Pilot, which then
  issues a suite-wide JWT cookie read by this module.
- **standalone mode** (``AUTH_MODE=standalone``): Surface exposes its own
  provider routes. Configuration is driven by env vars:

    * ``ENTRA_CLIENT_ID`` / ``ENTRA_CLIENT_SECRET`` / ``ENTRA_TENANT_ID``
    * ``GOOGLE_CLIENT_ID`` / ``GOOGLE_CLIENT_SECRET``
    * ``OIDC_CLIENT_ID`` / ``OIDC_CLIENT_SECRET`` / ``OIDC_ISSUER`` /
      ``OIDC_LABEL`` (optional display name)
    * ``AUTH_TOKEN`` — legacy token-based login (still accepted)

  A provider that is not configured is simply reported as unavailable by
  ``/auth/providers`` and its ``/login/<provider>`` endpoint returns 503.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import (
    AUTH_MODE,
    AUTH_TOKEN,
    COOKIE_NAME,
    MODULE_NAME,
    auth_enabled,
    create_jwt,
    get_current_user,
    get_module_role,
)
from src.database import get_db
from src.models import User
from src.schemas import UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])

APP_URL = os.getenv("APP_URL", "")

# ── Provider configuration (standalone mode only) ──────────────────────
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "")
ENTRA_CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "")
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "common")

ENTRA_AUTH_URL = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/authorize"
ENTRA_TOKEN_URL = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/token"

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "")
OIDC_LABEL = os.getenv("OIDC_LABEL", "SSO")

SCOPES = "openid profile email"

_oidc_endpoints: dict | None = None


def _entra_configured() -> bool:
    return AUTH_MODE == "standalone" and bool(ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET)


def _google_configured() -> bool:
    return AUTH_MODE == "standalone" and bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def _oidc_configured() -> bool:
    return AUTH_MODE == "standalone" and bool(OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_ISSUER)


async def _get_oidc_endpoints() -> dict:
    global _oidc_endpoints
    if _oidc_endpoints:
        return _oidc_endpoints
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.get(OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration", timeout=10)
        resp.raise_for_status()
        _oidc_endpoints = resp.json()
    return _oidc_endpoints


@router.get("/providers")
async def get_providers():
    if AUTH_MODE == "standalone":
        return {
            "auth_enabled": auth_enabled(),
            "standalone": True,
            "token": bool(AUTH_TOKEN),
            "entra": _entra_configured(),
            "google": _google_configured(),
            "oidc": _oidc_configured(),
            "oidc_label": OIDC_LABEL if _oidc_configured() else None,
        }
    return {
        "auth_enabled": auth_enabled(),
        "central": True,
        "pilot_login": "/login.html",
    }


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Auth not enabled")
    return user


@router.get("/role")
async def get_role(user: User = Depends(get_current_user)):
    """Return the user's role for this module (used by frontend to show/hide UI)."""
    role = get_module_role(user)
    return {"module": MODULE_NAME, "role": role, "email": user.email if user else ""}


@router.post("/logout")
async def logout():
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(COOKIE_NAME, samesite="lax", path="/")
    return response


# ── Token login (legacy standalone) ────────────────────────────────────
@router.post("/login/token")
async def login_token(body: dict, db: AsyncSession = Depends(get_db)):
    """Standalone mode: login with AUTH_TOKEN secret."""
    if AUTH_MODE != "standalone":
        raise HTTPException(status_code=503, detail="Token login only in standalone mode")
    if not AUTH_TOKEN:
        raise HTTPException(status_code=503, detail="AUTH_TOKEN not configured")

    token = body.get("token", "")
    import secrets as _secrets
    if not _secrets.compare_digest(token, AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid token")

    email = body.get("email", "admin@local")
    user = await _upsert_user(db, email=email, name=email.split("@")[0], picture="", provider="token", provider_id="token")
    jwt_token = _issue_jwt(user)
    response = JSONResponse(content={"ok": True, "email": user.email, "role": user.role})
    response.set_cookie(COOKIE_NAME, jwt_token, httponly=True, samesite="lax", max_age=86400, secure=_cookie_secure(), path="/")
    return response


# ── Microsoft Entra / M365 ─────────────────────────────────────────────
@router.get("/login/entra")
async def login_entra(request: Request):
    if not _entra_configured():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    redirect_uri = APP_URL + "/auth/callback/entra"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=ENTRA_CLIENT_ID, client_secret=ENTRA_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    uri, state = client.create_authorization_url(ENTRA_AUTH_URL)
    response = RedirectResponse(url=uri)
    response.set_cookie("oauth_state", state, httponly=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_redirect", redirect_after, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback/entra")
async def callback_entra(request: Request, db: AsyncSession = Depends(get_db)):
    if not _entra_configured():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    redirect_uri = APP_URL + "/auth/callback/entra"
    client = AsyncOAuth2Client(client_id=ENTRA_CLIENT_ID, client_secret=ENTRA_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(ENTRA_TOKEN_URL, authorization_response=str(request.url))
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    id_token = token.get("id_token", "")
    if not id_token:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    jwks_url = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys"
    issuer = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
    try:
        claims = await _verify_id_token_jwks(id_token, jwks_url, audience=ENTRA_CLIENT_ID, issuer=issuer)
    except Exception:
        return RedirectResponse(url="/login.html?error=token_verify_failed")
    email = claims.get("email") or claims.get("preferred_username", "")
    name = claims.get("name", "")
    provider_id = claims.get("oid") or claims.get("sub", "")
    if not email:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    user = await _upsert_user(db, email=email, name=name, picture="", provider="entra", provider_id=provider_id)
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


# ── Google ─────────────────────────────────────────────────────────────
@router.get("/login/google")
async def login_google(request: Request):
    if not _google_configured():
        raise HTTPException(status_code=503, detail="Google OAuth not configured")
    redirect_uri = APP_URL + "/auth/callback/google"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    uri, state = client.create_authorization_url(GOOGLE_AUTH_URL)
    response = RedirectResponse(url=uri)
    response.set_cookie("oauth_state", state, httponly=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_redirect", redirect_after, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback/google")
async def callback_google(request: Request, db: AsyncSession = Depends(get_db)):
    if not _google_configured():
        raise HTTPException(status_code=503, detail="Google OAuth not configured")
    redirect_uri = APP_URL + "/auth/callback/google"
    client = AsyncOAuth2Client(client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(GOOGLE_TOKEN_URL, authorization_response=str(request.url))
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    client.token = token
    resp = await client.get(GOOGLE_USERINFO_URL)
    if not resp.is_success:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    userinfo = resp.json()
    user = await _upsert_user(
        db,
        email=userinfo.get("email", ""),
        name=userinfo.get("name", ""),
        picture=userinfo.get("picture", ""),
        provider="google",
        provider_id=userinfo.get("sub", ""),
    )
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


# ── Custom OIDC ────────────────────────────────────────────────────────
@router.get("/login/oidc")
async def login_oidc(request: Request):
    if not _oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured")
    endpoints = await _get_oidc_endpoints()
    redirect_uri = APP_URL + "/auth/callback/oidc"
    redirect_after = _sanitize_redirect(request.query_params.get("redirect", "/"))
    client = AsyncOAuth2Client(client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET, redirect_uri=redirect_uri, scope=SCOPES)
    uri, state = client.create_authorization_url(endpoints["authorization_endpoint"])
    response = RedirectResponse(url=uri)
    response.set_cookie("oauth_state", state, httponly=True, samesite="lax", max_age=600)
    response.set_cookie("oauth_redirect", redirect_after, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback/oidc")
async def callback_oidc(request: Request, db: AsyncSession = Depends(get_db)):
    if not _oidc_configured():
        raise HTTPException(status_code=503, detail="OIDC not configured")
    endpoints = await _get_oidc_endpoints()
    redirect_uri = APP_URL + "/auth/callback/oidc"
    client = AsyncOAuth2Client(client_id=OIDC_CLIENT_ID, client_secret=OIDC_CLIENT_SECRET, redirect_uri=redirect_uri)
    try:
        token = await client.fetch_token(endpoints["token_endpoint"], authorization_response=str(request.url))
    except Exception:
        return RedirectResponse(url="/login.html?error=auth_failed")
    client.token = token
    userinfo = None
    userinfo_url = endpoints.get("userinfo_endpoint")
    if userinfo_url:
        resp = await client.get(userinfo_url)
        if resp.is_success:
            userinfo = resp.json()
    if userinfo is None:
        id_token = token.get("id_token", "")
        jwks_url = endpoints.get("jwks_uri")
        if not id_token or not jwks_url:
            return RedirectResponse(url="/login.html?error=userinfo_failed")
        try:
            userinfo = await _verify_id_token_jwks(
                id_token, jwks_url,
                audience=OIDC_CLIENT_ID,
                issuer=endpoints.get("issuer"),
            )
        except Exception:
            return RedirectResponse(url="/login.html?error=token_verify_failed")
    email = userinfo.get("email", "")
    if not email:
        return RedirectResponse(url="/login.html?error=userinfo_failed")
    user = await _upsert_user(
        db,
        email=email,
        name=userinfo.get("name") or userinfo.get("preferred_username", ""),
        picture=userinfo.get("picture", ""),
        provider="oidc",
        provider_id=userinfo.get("sub", ""),
    )
    redirect_after = request.cookies.get("oauth_redirect", "/")
    return _login_response(user, redirect_after)


# ── Helpers ────────────────────────────────────────────────────────────
async def _upsert_user(
    db: AsyncSession,
    email: str,
    name: str,
    picture: str,
    provider: str,
    provider_id: str,
) -> User:
    """Find or create a standalone user. First user gets admin role."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user:
        if name:
            user.name = name
        if picture:
            user.picture = picture
        user.last_login = now
    else:
        count_result = await db.execute(select(func.count()).select_from(User))
        role = "admin" if count_result.scalar() == 0 else "user"
        user = User(
            email=email,
            name=name or email.split("@")[0],
            picture=picture or None,
            provider=provider,
            provider_id=provider_id or "",
            role=role,
            last_login=now,
        )
        db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _issue_jwt(user: User) -> str:
    """Build the per-module JWT for a standalone user.

    Standalone Surface only speaks for itself, so permissions collapse to
    ``{MODULE_NAME: user.role}``. ``get_current_user`` in src/auth.py reads
    that map and enforces access."""
    perms = {MODULE_NAME: user.role} if MODULE_NAME else {}
    return create_jwt(str(user.id), user.email, user.role, perms)


def _login_response(user: User, redirect_to: str = "/") -> RedirectResponse:
    token = _issue_jwt(user)
    response = RedirectResponse(url=_sanitize_redirect(redirect_to), status_code=302)
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True, samesite="lax",
        max_age=86400, secure=_cookie_secure(), path="/",
    )
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_redirect")
    return response


def _sanitize_redirect(raw: str | None) -> str:
    """Ensure the post-login redirect is a safe relative path (anti open-redirect)."""
    if not raw:
        return "/"
    if not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return "/"
    if "://" in raw:
        return "/"
    return raw


def _cookie_secure() -> bool:
    """Derive Secure flag from APP_URL to avoid leaking JWT over HTTP."""
    return APP_URL.startswith("https://")


async def _verify_id_token_jwks(id_token: str, jwks_url: str, audience: str, issuer: str | None = None) -> dict:
    """Fetch JWKS, verify the id_token signature, and return its claims.

    Uses PyJWKClient (synchronous); wrapped via asyncio.to_thread to avoid
    blocking the event loop.
    """
    import asyncio
    import jwt as jose_jwt
    from jwt import PyJWKClient

    def _work() -> dict:
        client = PyJWKClient(jwks_url)
        signing_key = client.get_signing_key_from_jwt(id_token)
        options = {"verify_signature": True, "verify_aud": bool(audience), "verify_iss": bool(issuer)}
        return jose_jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
            options=options,
        )

    return await asyncio.to_thread(_work)
