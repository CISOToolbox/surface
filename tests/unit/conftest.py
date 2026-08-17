"""Unit-test bootstrap.

Built-in scanners now live as add-on modules under addons/core/ and are loaded
at import of src.scanners via the add-on loader. Point the loader at addons/core
BEFORE any test imports src.scanners so SCANNER_REGISTRY is populated, and expose
a helper to import a core add-on module directly for white-box tests.
"""
import importlib.util
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.dirname(__file__))  # so tests can `from conftest import ...`
os.environ.setdefault("SURFACE_ADDON_PATHS", os.path.join(_ROOT, "addons", "core"))


def load_core_addon(name: str):
    """Import addons/{core,generic}/<name>/<name>.py as a standalone module
    (for tests that patch a scanner's subprocess/shutil or call it directly).
    Searches core first, then generic (some scanners are optional generic
    add-ons, e.g. nuclei, cve_lookup)."""
    for tier in ("core", "generic"):
        path = os.path.join(_ROOT, "addons", tier, name, name + ".py")
        if os.path.isfile(path):
            spec = importlib.util.spec_from_file_location("addon_" + name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    raise FileNotFoundError(f"addon not found in core/ or generic/: {name}")
