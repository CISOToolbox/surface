# Generic add-on scanners (Surface)

> **Full contract & runtime/help/build/propagation rules: see
> [`../README.md`](../README.md).** This file is a quick reference.

**Shareable** Surface scanners, reusable across clients. Each connector lives
in its own subdir `generic/<name>/<name>.py` (+ optional `requirements.txt`).

A scanner module exposes:

```python
SURFACE_SCANNERS = {
    "<name>": {
        "label": "...",
        "kinds": {"file_share"},          # which target kinds it applies to
        "callable": scan_fn,              # scan_fn(value) or scan_fn(value, config)
        "returns_discovered": False,
        "wants_config": True,             # optional: callable gets (value, asset_config)
        "doc": {                          # optional: in-app help, served only
            "fr": {"methodo": "<html>", "usage": "<html>"},   # when the add-on
            "en": {"methodo": "<html>", "usage": "<html>"},   # is installed
        },
    },
}
SURFACE_DEFAULT_SCANNERS = {"file_share": ["<name>"]}   # optional
```

The core loader (`src/scanners.py:_load_addon_scanners`) auto-discovers every
module under the dirs in `SURFACE_ADDON_PATHS` (recursively) and merges its
entries into `SCANNER_REGISTRY` / `DEFAULT_SCANNERS_BY_KIND`. It skips
`test_*`, `_*`, `conftest.py`, and any scanner whose dependency is missing.

Client-**specific** scanners go under `../custom/<client>/` instead, and are
baked into a client image only when selected at build time.
