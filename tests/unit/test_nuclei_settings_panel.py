"""BUG-93 — the settings panel tells the admin the templates come with the image.

Where the templates directory is read-only, ``GET /nuclei/config`` answers
``templates_updatable: false`` and the refresh route answers 409. The panel
must then show a note instead of the "Update templates" button. Lock, running
the compiled ``_renderNucleiFormInto`` under node against stubs: the note
replaces the button when the templates cannot be updated in place, and the
button stays otherwise (an older backend without the field included).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_JS = (Path(__file__).resolve().parents[2] / "app" / "js" / "Surface_app.js").read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node not installed")


def _render(cfg: dict) -> str:
    m = re.search(r"^([ \t]*)function _renderNucleiFormInto\(.*?^\1\}", _JS, re.S | re.M)
    assert m
    script = """
function t(k) { return k; } function esc(s) { return String(s); } function _icon() { return ""; }
function _fmtDate(d) { return String(d); }
""" + m.group(0) + f"""
var holder = {{innerHTML: ""}};
_renderNucleiFormInto(holder, {json.dumps(cfg)});
console.log(JSON.stringify(holder.innerHTML));
"""
    return json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)


_BASE = {"installed": True, "version": "v3.11.1", "templates_count": 13742, "tuning": {},
         "tuning_defaults": {}, "tuning_limits": {}}


@pytest.mark.parametrize("updatable,note", [(False, True), (True, False), (None, False)])
def test_the_note_replaces_the_update_button_when_templates_are_read_only(updatable, note):
    cfg = dict(_BASE) if updatable is None else {**_BASE, "templates_updatable": updatable}
    html = _render(cfg)
    assert ("nuclei.templates_from_image" in html) is note
    assert ('id="nuclei-update-btn"' in html) is not note
