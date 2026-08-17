"""Auth module — thin wrapper over auth_common.py.

Edit the shared auth logic in shared/python/auth_common.py, not here.
This file only re-exports symbols so existing imports keep working.
"""
from src.auth_common import (  # noqa: F401 — re-export
    ADMIN_MODULE_ROLES,
    AUTH_MODE,
    AUTH_TOKEN,
    COOKIE_NAME,
    JWT_SECRET,
    MODULE_COOKIE,
    MODULE_NAME,
    auth_enabled,
    assert_auth_posture,
    create_jwt,
    decode_jwt,
    get_current_user,
    get_current_user_permissive,
    get_module_role,
    perms_for_module_role,
    require_admin,
    require_identity,
    require_min_role,
    VIEWER_MODULE_ROLES,
)

# Role ladder for require_min_role() on this module's routes. It lists the
# aliases of every tier (see ADMIN/EDITOR/VIEWER_MODULE_ROLES in auth_common),
# because require_min_role raises 403 when the caller's role is absent from the
# ladder — a short ["viewer", "editor", "admin"] would lock out a perfectly
# legitimate "contributor" or "manager". Defined once here rather than per
# route file: seven copies of the same list is exactly how the catalogue and
# the CSS masters drifted.
SURFACE_ROLES = [
    "viewer", "reader", "triager",
    "editor", "contributor", "manager",
    "admin", "control",
]

