"""BUG-90 — the standalone build ships without the suite-only routes.

``src/routes/internal.py`` (Pilot provisioning, service-token gate) and
``src/routes/directory_proxy.py`` are removed from the standalone build. An
unguarded import of either one stopped the app from starting
(``nonconformities.py``) or turned a measure update, a ``to_fix`` triage and
a custom-LLM call into a 500. Locks:
  - every import of a suite-only route is a static ``from … import``
    directly inside a ``try`` whose only handler is ``except
    ModuleNotFoundError as e`` opening on ``if e.name != "<that module>":
    raise``: only the missing file is tolerated;
  - every name imported from a suite-only route exists there, so a rename
    fails here instead of silently dropping the Pilot integration;
  - the app starts without them, and serves its health route;
  - with them, the suite mounts its internal routes, the non-conformity
    register included, and a suite-only module that is broken or misses a
    dependency fails the start-up. The handlers' behaviour without the file
    is locked in ``test_pilot_relay.py``.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2]
SUITE_ONLY = {"src.routes.internal": "src/routes/internal.py",
              "src.routes.directory_proxy": "src/routes/directory_proxy.py"}
_SHORT = {m.rsplit(".", 1)[1] for m in SUITE_ONLY}
_suite_tree = pytest.mark.skipif(not (MODULE / "src/routes/internal.py").exists(),
                                 reason="suite-only route, absent from a standalone build")


def _sources():
    for path in sorted((MODULE / "src").rglob("*.py")):
        rel = path.relative_to(MODULE).as_posix()
        if rel not in SUITE_ONLY.values():
            yield rel, ast.parse(path.read_text(encoding="utf-8"), filename=rel)


def _target(node, rel: str) -> str | None:
    """The suite-only module a node imports, if any."""
    if isinstance(node, ast.Import):
        return next((a.name for a in node.names if a.name in SUITE_ONLY), None)
    if isinstance(node, ast.ImportFrom):
        if node.level:                                   # from .internal import x / from . import internal
            if rel.startswith("src/routes/") and node.level == 1:
                names = [node.module] if node.module else [a.name for a in node.names]
                return next((f"src.routes.{n}" for n in names if n in _SHORT), None)
            return None
        if node.module in SUITE_ONLY:
            return node.module
        if node.module == "src.routes":
            return next((f"src.routes.{a.name}" for a in node.names if a.name in _SHORT), None)
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name in ("import_module", "__import__") and node.args[0].value in SUITE_ONLY:
            return node.args[0].value
    return None


def _tolerated(try_node) -> str | None:
    """The module a ``try`` tolerates the absence of, if it is the only one.

    Its sole handler must be ``except ModuleNotFoundError as e:`` opening on
    ``if e.name != "<module>": raise`` — any other shape (a broader or extra
    handler, an inverted or wrong comparison) tolerates more than the file.
    """
    if len(try_node.handlers) != 1:
        return None
    h = try_node.handlers[0]
    if not (isinstance(h.type, ast.Name) and h.type.id == "ModuleNotFoundError" and h.name and h.body):
        return None
    first = h.body[0]
    if not (isinstance(first, ast.If) and not first.orelse and len(first.body) == 1
            and isinstance(first.body[0], ast.Raise) and first.body[0].exc is None):
        return None
    t = first.test
    if (isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], ast.NotEq)
            and isinstance(t.left, ast.Attribute) and t.left.attr == "name"
            and isinstance(t.left.value, ast.Name) and t.left.value.id == h.name
            and isinstance(t.comparators[0], ast.Constant) and t.comparators[0].value in SUITE_ONLY):
        return t.comparators[0].value
    return None


def _direct(stmts):
    """Nodes of these statements, without descending into nested scopes."""
    stack = list(stmts)
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(n))


def _violations() -> list[str]:
    found = []
    for rel, tree in _sources():
        guarded: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and (tolerated := _tolerated(node)):
                guarded.update((id(n), tolerated) for n in _direct(node.body))
        for node in ast.walk(tree):
            target = _target(node, rel)
            if target is None:
                continue
            static = isinstance(node, ast.ImportFrom) and node.module == target and not node.level
            if not static or guarded.get(id(node)) != target:
                found.append(f"{rel}:{node.lineno}")
    return found


def test_every_suite_only_import_is_narrowly_guarded():
    assert _violations() == [], (
        "import a suite-only route as `from src.routes.<name> import x` directly inside "
        "`try:` whose only handler is `except ModuleNotFoundError as e:` opening on "
        "`if e.name != \"src.routes.<name>\": raise`")


def _defined(rel: str) -> set[str]:
    tree = ast.parse((MODULE / rel).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
    return names


@_suite_tree
def test_every_name_imported_from_a_suite_only_route_exists():
    missing = []
    for rel, tree in _sources():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in SUITE_ONLY and not node.level:
                defined = _defined(SUITE_ONLY[node.module])
                missing += [f"{rel}:{node.lineno} {a.name}" for a in node.names if a.name not in defined]
    assert missing == []


_PROBE = """
import importlib.abc, importlib.util, sys, types
mode = {mode!r}


class _MissingDependency(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    # The file is there, but something it imports is not.
    def find_spec(self, name, path=None, target=None):
        return importlib.util.spec_from_loader(name, self) if name in {suite_only!r} else None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        raise ModuleNotFoundError("No module named 'src.gone'", name="src.gone")


for m in {suite_only!r}:
    if mode == "standalone":
        sys.modules[m] = None                       # ModuleNotFoundError, as in a standalone build
    elif mode == "broken":
        sys.modules[m] = types.ModuleType(m)        # present but empty: ImportError on every name
if mode == "transitive":
    sys.meta_path.insert(0, _MissingDependency())
try:
    import src.main
except ImportError as e:
    print("start-failed", type(e).__name__)
    raise SystemExit(0)
paths = {{r.path for r in src.main.app.routes}}
print("health" if "/api/health" in paths else "no-health")
print("stats" if "/api/internal/stats" in paths else "no-stats")
print("register" if "/api/internal/nonconformities" in paths else "no-register")
print("internal" if any(p.startswith("/api/internal") for p in paths) else "no-internal")
"""


def _start(mode: str) -> list[str]:
    env = dict(os.environ,
               DATABASE_URL="postgresql+asyncpg://u:p@127.0.0.1:1/surface_test",
               MODULE_NAME="surface",
               JWT_SECRET="test-secret-that-is-long-enough-32ch",
               ENCRYPTION_KEY="test-encryption-key-long-enough-1234")
    out = subprocess.run([sys.executable, "-c", _PROBE.format(mode=mode, suite_only=list(SUITE_ONLY))],
                         cwd=MODULE, env=env, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.split()


def test_the_app_starts_without_the_suite_only_routes():
    assert _start("standalone") == ["health", "no-stats", "no-register", "no-internal"]


@_suite_tree
def test_the_suite_mounts_its_internal_routes():
    assert _start("suite") == ["health", "stats", "register", "internal"]


def test_a_broken_suite_only_module_fails_the_start_up():
    """Present but missing a name: the guard must not swallow it."""
    assert _start("broken") == ["start-failed", "ImportError"]


def test_a_suite_only_module_missing_a_dependency_fails_the_start_up():
    """Present but importing a missing module: only the file itself is tolerated."""
    assert _start("transitive") == ["start-failed", "ModuleNotFoundError"]
