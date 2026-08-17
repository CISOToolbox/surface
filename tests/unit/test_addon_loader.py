"""Unit tests for the Surface add-on scanner loader (src/scanners).

Locks the contract that lets a deployment drop a bespoke scanner into an
add-on directory without editing core:
- a module exposing SURFACE_SCANNERS is merged into SCANNER_REGISTRY
- SURFACE_DEFAULT_SCANNERS is merged into DEFAULT_SCANNERS_BY_KIND
- wants_config is honored; test_*/_*/conftest are ignored
- a broken add-on is skipped, never crashes import
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src import scanners  # noqa: E402

_GOOD = (
    'def _scan(value, config=None):\n'
    '    return []\n'
    'SURFACE_SCANNERS = {"acme_scan": {"label": "Acme", "kinds": {"file_share"},\n'
    '    "callable": _scan, "returns_discovered": False, "wants_config": True}}\n'
    'SURFACE_DEFAULT_SCANNERS = {"file_share": ["acme_scan"]}\n'
)
_BROKEN = "import a_module_that_does_not_exist_xyz  # noqa\n"


def _write(d, name, content):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(content)
    return p


class TestAddonScannerLoader:
    def teardown_method(self):
        scanners.SCANNER_REGISTRY.pop("acme_scan", None)
        scanners.DEFAULT_SCANNERS_BY_KIND.pop("file_share", None)
        os.environ.pop("SURFACE_ADDON_PATHS", None)

    def test_loads_good_addon(self, tmp_path):
        _write(str(tmp_path), "acme.py", _GOOD)
        os.environ["SURFACE_ADDON_PATHS"] = str(tmp_path)
        scanners._load_addon_scanners()
        assert "acme_scan" in scanners.SCANNER_REGISTRY
        assert scanners.SCANNER_REGISTRY["acme_scan"]["wants_config"] is True
        assert "acme_scan" in scanners.DEFAULT_SCANNERS_BY_KIND.get("file_share", [])
        assert [s["name"] for s in scanners.available_scanners_for_kind("file_share")] == ["acme_scan"]

    def test_ignores_tests_and_private(self, tmp_path):
        _write(str(tmp_path), "test_acme.py", _GOOD)
        _write(str(tmp_path), "_acme.py", _GOOD)
        _write(str(tmp_path), "conftest.py", _GOOD)
        os.environ["SURFACE_ADDON_PATHS"] = str(tmp_path)
        scanners._load_addon_scanners()
        assert "acme_scan" not in scanners.SCANNER_REGISTRY

    def test_broken_addon_skipped(self, tmp_path):
        _write(str(tmp_path), "broken.py", _BROKEN)
        _write(str(tmp_path), "acme.py", _GOOD)
        os.environ["SURFACE_ADDON_PATHS"] = str(tmp_path)
        scanners._load_addon_scanners()  # must not raise
        assert "acme_scan" in scanners.SCANNER_REGISTRY

    def test_recursive_subdirs(self, tmp_path):
        sub = tmp_path / "generic" / "acme"
        sub.mkdir(parents=True)
        _write(str(sub), "acme.py", _GOOD)
        os.environ["SURFACE_ADDON_PATHS"] = str(tmp_path)
        scanners._load_addon_scanners()
        assert "acme_scan" in scanners.SCANNER_REGISTRY
