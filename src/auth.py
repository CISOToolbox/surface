"""Auth module — thin wrapper over auth_common.py with Surface-specific overrides.

Surface defaults to AUTH_MODE=standalone and adds assert_auth_configured().
Edit the shared auth logic in shared/python/auth_common.py, not here.
"""
import os

from src.auth_common import (  # noqa: F401 — re-export
    AUTH_MODE,
    AUTH_TOKEN,
    COOKIE_NAME,
    JWT_SECRET,
    MODULE_COOKIE,
    MODULE_NAME,
    create_jwt,
    decode_jwt,
    get_current_user,
    get_current_user_permissive,
    get_module_role,
    require_admin,
    require_min_role,
)


# Surface override: in standalone mode, require BOTH AUTH_TOKEN and JWT_SECRET.
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
