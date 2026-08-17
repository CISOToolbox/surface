"""SMB/CIFS file-share content scanner — Rust worker (Surface add-on).

This is the high-throughput variant of `smb_scan`: the actual crawl + document
extraction + regex matching is done by a compiled Rust binary
(`bin/ciso-smb-scan`) run as a **separate process**. Two wins over the pure
Python scanner:

- **No event-loop starvation** — the CPU-heavy work runs out-of-process, so a
  large filer scan never makes the FastAPI app lag (the Python scanner ran its
  extractors in threads inside the app process, contending on the GIL).
- **Faster** — native, GIL-free, fast regex.

Trade-off: the Rust MVP does **not** extract PDF bodies (no mature crate
matching pdfminer); PDF files are still flagged by name, and Office
(docx/xlsx/pptx) + text/config/code bodies are fully scanned. Use the pure
Python `smb_scan` add-on instead if PDF body extraction matters.

Findings schema, secret ruleset, masking and host roll-up (target = UNC path)
are identical to `smb_scan`, so the two are drop-in comparable.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import subprocess

logger = logging.getLogger("surface-smb-rs")

# The image bundles one binary per arch (ciso-smb-scan-<amd64|arm64>); pick the
# one matching the running platform. Falls back to a plain `ciso-smb-scan` (the
# single-arch local dev build).
_ARCH = {"x86_64": "amd64", "amd64": "amd64",
         "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower(), "")
_BINDIR = os.path.join(os.path.dirname(__file__), "bin")


def _resolve_bin() -> str:
    for cand in (f"ciso-smb-scan-{_ARCH}" if _ARCH else "", "ciso-smb-scan"):
        if not cand:
            continue
        p = os.path.join(_BINDIR, cand)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return os.path.join(_BINDIR, f"ciso-smb-scan-{_ARCH or 'unknown'}")


_BIN = _resolve_bin()


def _finding(severity: str, title: str, description: str, target: str,
             evidence: dict, type_: str = "smb_status") -> dict:
    return {"scanner": "smb_scan", "type": type_, "severity": severity,
            "title": title, "description": description, "target": target,
            "evidence": evidence}


_SINK_BATCH = int(os.getenv("SURFACE_SMB_RS_BATCH", "50") or "50")

# Worker record types that are control/status, not content findings: they are
# returned to the caller (never streamed to the incremental sink). scanner_state
# carries the resume-cursor config patch the caller merges into the asset.
_STATUS_TYPES = {"smb_status", "scanner_state"}


def scan_smb_share_rs(value: str, config: dict | None = None, sink=None) -> list[dict]:
    config = config or {}
    if not os.path.isfile(_BIN) or not os.access(_BIN, os.X_OK):
        return [_finding("info", "Rust SMB worker unavailable",
                         f"Binary missing or not executable: {_BIN}. "
                         "Rebuild the image with the smb_scan_rs add-on.", value, {})]

    user = (config.get("smb_username") or os.getenv("SURFACE_SMB_USERNAME", "")).strip()
    domain = (config.get("smb_domain") or os.getenv("SURFACE_SMB_DOMAIN", "")).strip()
    pw = os.getenv("SURFACE_SMB_PASSWORD", "")
    if config.get("smb_password_enc"):
        try:
            from src.crypto import decrypt_secret
            pw = decrypt_secret(config["smb_password_enc"]) or pw
        except Exception as e:
            logger.warning("SMB password decrypt failed: %s", e)
    if not user or not pw:
        return [_finding("info", "Missing SMB credentials",
                         "Set credentials on the target, or define "
                         "SURFACE_SMB_USERNAME / SURFACE_SMB_PASSWORD (+ DOMAIN).", value, {})]

    # Non-secret config forwarded to the worker (secrets go via env, never argv).
    worker_cfg = {
        k: config[k] for k in ("extensions", "max_size_mb", "max_files",
                               "time_budget_s", "custom_regex") if k in config
    }
    # Resume cursor (set by the previous scan via a scanner_state record the
    # caller merged back into the asset config) — the worker skips files already
    # covered so each scan advances through a large share instead of re-scanning
    # the same head every time.
    if config.get("smb_resume_after"):
        worker_cfg["resume_after"] = config["smb_resume_after"]
    env = dict(os.environ)
    env.update({
        "SMB_TARGET": value,
        "SMB_USER": user,
        "SMB_PASS": pw,
        "SMB_DOMAIN": domain,
        "SMB_CONFIG": json.dumps(worker_cfg),
    })
    # The worker honours time_budget_s itself; give the subprocess a backstop.
    timeout = int(config.get("time_budget_s") or 1800) + 300

    # Stream NDJSON (one finding per line) from the worker and persist
    # incrementally via `sink`. If the scan is killed / times out, everything
    # already streamed is already committed — no all-or-nothing loss. Without a
    # sink (e.g. standalone), accumulate and return the whole list (legacy).
    import threading
    try:
        proc = subprocess.Popen([_BIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, bufsize=1, text=True)
    except Exception as e:
        return [_finding("info", "Rust SMB worker: execution failed",
                         f"{type(e).__name__}: {e}", value, {})]

    returned: list[dict] = []   # status findings -> returned to the caller
    batch: list[dict] = []
    streamed = 0
    killer = threading.Timer(timeout, proc.kill)  # hard backstop if it overruns
    killer.daemon = True
    killer.start()
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                f = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(f, dict):
                continue
            if sink is not None and f.get("type") not in _STATUS_TYPES:
                batch.append(f)
                streamed += 1
                if len(batch) >= _SINK_BATCH:
                    try:
                        sink(batch)
                    except Exception as e:
                        logger.warning("incremental sink failed: %s", e)
                    batch = []
            else:
                returned.append(f)
        if sink is not None and batch:
            try:
                sink(batch)
            except Exception as e:
                logger.warning("incremental sink (flush) failed: %s", e)
    finally:
        killer.cancel()
        try:
            proc.wait(timeout=10)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    rc = proc.returncode
    if rc == -9:   # killed by our backstop — partial result already persisted
        returned.append(_finding(
            "info", "Rust SMB worker: scan interrupted (time budget exceeded)",
            f"The worker was stopped past the time budget. {streamed} content finding(s) "
            "already recorded (partial result). Increase time_budget_s or reduce the scope.",
            value, {"streamed": streamed}, type_="smb_status"))
    elif rc not in (0, None):
        err = ""
        try:
            err = (proc.stderr.read() or "")[:300] if proc.stderr else ""
        except Exception:
            pass
        returned.append(_finding("info", "Rust SMB worker: error",
                                 f"exit {rc}. {err}", value, {}))
    return returned


_DOC = {
    "fr": {
        "methodo":
            '<h2>Scan de partages de fichiers (SMB/CIFS) — worker Rust <em>— add-on</em></h2>'
            '<p>Variante haute performance du scan SMB : le parcours, l\'extraction '
            'documentaire et la détection de secrets sont réalisés par un binaire '
            '<strong>Rust exécuté hors du process applicatif</strong>. Avantages : '
            'l\'app ne rame plus pendant un gros scan (plus de contention GIL), et le '
            'débit est nettement supérieur (code natif, regex rapide).</p>'
            '<ul>'
            '<li><strong>Formats couverts</strong> : texte / config / code, et le corps '
            'des documents <strong>Word (.docx), Excel (.xlsx), PowerPoint (.pptx)</strong>.</li>'
            '<li><strong>PDF</strong> : le corps n\'est <em>pas</em> extrait par le worker '
            'Rust (pas de bibliothèque équivalente à pdfminer) — les PDF restent flaggés '
            'par leur nom, sans lecture de leur contenu.</li>'
            '<li><strong>Ruleset, masquage, plafonds</strong> (max_files / budget temps) et '
            'rattachement au host.</li>'
            '</ul>',
        "usage":
            '<h2>Cible « Partage de fichiers » — worker Rust <em>(add-on SMB)</em></h2>'
            '<p>Identique à l\'add-on SMB Python (mêmes champs : chemin, identifiants, '
            'extensions, taille max, regex), mais exécuté par un worker Rust hors-process '
            'pour ne pas ralentir l\'application sur de gros volumes. L\'extraction PDF '
            'n\'est pas couverte par cette variante.</p>',
    },
    "en": {
        "methodo":
            '<h2>File-share scanning (SMB/CIFS) — Rust worker <em>— add-on</em></h2>'
            '<p>High-throughput variant of the SMB scan: the crawl, document '
            'extraction and secret matching run in a <strong>Rust binary executed '
            'out-of-process</strong>. The app no longer lags during a big scan (no GIL '
            'contention) and throughput is markedly higher (native, fast regex).</p>'
            '<ul>'
            '<li><strong>Covered</strong>: text / config / code, and the body of '
            '<strong>Word (.docx), Excel (.xlsx), PowerPoint (.pptx)</strong>.</li>'
            '<li><strong>PDF</strong>: bodies are <em>not</em> extracted by the Rust '
            'worker (no pdfminer-grade crate) — PDFs are still flagged by name, their '
            'content is not read.</li>'
            '<li><strong>Ruleset, masking, caps</strong> (max_files / time budget) and '
            'host roll-up.</li>'
            '</ul>',
        "usage":
            '<h2>"File share" target — Rust worker <em>(SMB add-on)</em></h2>'
            '<p>Same as the Python SMB add-on (same fields: path, credentials, '
            'extensions, max size, regex) but run by an out-of-process Rust worker so it '
            'never slows the app on large volumes. PDF body extraction is not covered by '
            'this variant.</p>',
    },
}

SURFACE_SCANNERS = {
    "smb_scan_rs": {
        "label": "SMB file-share content — Rust worker (secrets & sensitive data)",
        "kinds": {"file_share"},
        "callable": scan_smb_share_rs,
        "returns_discovered": False,
        "wants_config": True,
        "wants_sink": True,
        "doc": _DOC,
    },
}
SURFACE_DEFAULT_SCANNERS = {"file_share": ["smb_scan_rs"]}
