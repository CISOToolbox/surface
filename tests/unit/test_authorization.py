"""Unit tests for Surface authorization guards.

Tests require_admin, get_module_role, require_min_role (from access auth),
service token checks on internal endpoints, and source-code verification
that write routes require authentication.
"""
import ast
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

ROUTES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "src", "routes")


# ── get_module_role ───────────────────────────────────────────────

class TestGetModuleRole:
    def test_none_user_returns_admin(self):
        from auth import get_module_role
        assert get_module_role(None) == "admin"

    def test_user_with_module_role(self):
        from auth import get_module_role
        user = SimpleNamespace(_module_role="viewer")
        assert get_module_role(user) == "viewer"

    def test_user_without_module_role_gets_nothing(self):
        """A real user with no role for THIS module has no role — not admin.

        This asserted the opposite, which is what the fallback did: any
        authenticated account with no permission entry for the module was
        reported as its administrator. Business routes never reached that
        branch (get_current_user 403s on an empty module role first), but the
        permissive dependencies did, and GET /auth/role answered "admin".

        `None` still means admin — that is the auth-disabled sentinel, tested
        just above, and a different thing entirely.
        """
        from auth import get_module_role
        user = SimpleNamespace()
        assert get_module_role(user) == ""


# ── require_admin ─────────────────────────────────────────────────

class TestRequireAdmin:
    def test_rejects_viewer(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="viewer")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_rejects_editor(self):
        from auth import require_admin
        from fastapi import HTTPException
        user = SimpleNamespace(_module_role="editor")
        with pytest.raises(HTTPException) as exc:
            require_admin(user)
        assert exc.value.status_code == 403

    def test_accepts_admin(self):
        from auth import require_admin
        user = SimpleNamespace(_module_role="admin")
        require_admin(user)  # no exception

    def test_accepts_none_auth_disabled(self):
        from auth import require_admin
        require_admin(None)  # no exception


# ── _get_module_role (JWT extraction) ─────────────────────────────

class TestGetModuleRoleFromJWT:
    # _get_module_role is private, so it lives in auth_common and is NOT among
    # the names auth.py re-exports — reaching for it through `auth` raised
    # AttributeError and these three had been failing silently for a while.
    # Reload auth_common, not auth: MODULE_NAME is read at import time there.
    @staticmethod
    def _reload(monkeypatch):
        monkeypatch.setenv("MODULE_NAME", "surface")
        import importlib, auth_common
        return importlib.reload(auth_common)

    def test_extracts_from_permissions(self, monkeypatch):
        ac = self._reload(monkeypatch)
        payload = {"permissions": {"surface": "editor"}, "role": "user"}
        assert ac._get_module_role(payload) == "editor"

    def test_fallback_admin_for_pilot_admin(self, monkeypatch):
        ac = self._reload(monkeypatch)
        payload = {"permissions": {}, "role": "admin"}
        assert ac._get_module_role(payload) == "admin"

    def test_empty_for_regular_user_no_permission(self, monkeypatch):
        ac = self._reload(monkeypatch)
        payload = {"permissions": {}, "role": "user"}
        assert ac._get_module_role(payload) == ""


# ── Internal service token ────────────────────────────────────────

class TestInternalServiceToken:
    def test_rejects_missing_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "svc-secret")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        from fastapi import HTTPException
        request = SimpleNamespace(headers={})
        with pytest.raises(HTTPException) as exc:
            internal_mod._check_service_token(request)
        assert exc.value.status_code == 403

    def test_rejects_wrong_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "svc-secret")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        from fastapi import HTTPException
        request = SimpleNamespace(headers={"X-Service-Token": "wrong"})
        with pytest.raises(HTTPException) as exc:
            internal_mod._check_service_token(request)
        assert exc.value.status_code == 403

    def test_accepts_correct_token(self, monkeypatch):
        monkeypatch.setenv("SERVICE_TOKEN", "svc-secret")
        import importlib
        import routes.internal as internal_mod
        importlib.reload(internal_mod)
        request = SimpleNamespace(headers={"X-Service-Token": "svc-secret"})
        internal_mod._check_service_token(request)  # no exception


# ── Source analysis: admin-only routes ────────────────────────────

def _find_admin_routes():
    """Return set of (filename, func_name) that call require_admin."""
    result = set()
    for fname in os.listdir(ROUTES_DIR):
        if not fname.endswith(".py") or fname == "__init__.py":
            continue
        fpath = os.path.join(ROUTES_DIR, fname)
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if "require_admin" in ast.dump(node):
                    result.add((fname, node.name))
    return result


def _find_authenticated_routes():
    """Return set of (filename, func_name) that use get_current_user."""
    result = set()
    for fname in os.listdir(ROUTES_DIR):
        if not fname.endswith(".py") or fname == "__init__.py":
            continue
        fpath = os.path.join(ROUTES_DIR, fname)
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if "get_current_user" in ast.dump(node):
                    result.add((fname, node.name))
    return result


EXPECTED_ADMIN_ROUTES = {
    ("users.py", "list_users"),
    ("users.py", "update_user"),
    ("directory_proxy.py", "set_source"),
}


class TestRouteProtection:
    def test_admin_routes_present(self):
        actual = _find_admin_routes()
        missing = EXPECTED_ADMIN_ROUTES - actual
        assert not missing, f"Routes expected to require admin: {missing}"

    def test_write_routes_require_auth(self):
        """All findings/scans/measures write endpoints must use get_current_user."""
        auth_routes = _find_authenticated_routes()
        write_files = {"findings.py", "scans.py", "measures.py", "scan_jobs.py"}
        for fname, func_name in auth_routes:
            if fname in write_files:
                continue  # already authenticated
        # Check that every route function in write files is authenticated
        for fname in write_files:
            fpath = os.path.join(ROUTES_DIR, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath) as f:
                tree = ast.parse(f.read(), filename=fpath)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for deco in node.decorator_list:
                        deco_src = ast.dump(deco)
                        if "router" in deco_src and ("post" in deco_src or "put" in deco_src or "patch" in deco_src or "delete" in deco_src):
                            assert (fname, node.name) in auth_routes, (
                                f"{fname}:{node.name} is a write route but lacks get_current_user"
                            )

    def test_internal_routes_use_service_token(self):
        """All /internal/ endpoints must call _check_service_token."""
        fpath = os.path.join(ROUTES_DIR, "internal.py")
        with open(fpath) as f:
            tree = ast.parse(f.read(), filename=fpath)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for deco in node.decorator_list:
                    if "router" in ast.dump(deco):
                        body_src = ast.dump(node)
                        assert "_check_service_token" in body_src, (
                            f"internal.py:{node.name} missing _check_service_token"
                        )


def test_triage_routes_gate_on_triager_not_editor():
    """Pilot > Users offers surface roles viewer/triager/admin; the triage
    endpoints must be reachable by a triager. Regression: they required
    'editor', which Pilot never assigns for surface — the role could do
    nothing beyond viewer (403 'Requires editor role, you have triager')."""
    import pathlib
    src = pathlib.Path(__file__).resolve().parents[2] / "src" / "routes" / "findings.py"
    text = src.read_text()
    for fn in ("triage_finding", "bulk_triage"):
        body = text.split(f"async def {fn}", 1)[1][:800]
        assert 'require_min_role(user, "triager"' in body, f"{fn} must gate on triager"
