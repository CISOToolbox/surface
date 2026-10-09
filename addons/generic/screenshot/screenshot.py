"""HTTP screenshot capture (Playwright) — Surface generic add-on.

Playwright + the Chromium build are NOT in the lean base image; they are
installed by this add-on (requirements.txt + apt-packages.txt + install.sh)
during the client-image overlay, into /ms-playwright. Point Playwright there
(the base no longer sets the env). When the add-on isn't installed the scanner
degrades gracefully to a "playwright not installed" finding.
"""
from __future__ import annotations

import os
from typing import Any

os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")

from src.scan_common import logger
from src.scan_common import (
    _proxy_for,
    _resolve_safe_target,
    _safe_target,
    bypasses_proxy,
    resolve_first_ip,
)


# ═══════════════════════════════════════════════════════════════
# v0.2 — HTTP screenshot capture (optional)
# ═══════════════════════════════════════════════════════════════
#
# Visual recon: grab a PNG screenshot of every reachable HTTP root and
# attach it to a finding so the operator can see what the asset actually
# looks like without leaving Surface. Opt-in per asset via the scanner
# toggle (not in default scanners) because chromium is a ~250 MB image
# dependency. If playwright + chromium aren't installed, the scanner
# emits a single info finding explaining how to enable it and never
# crashes the scan — so enabling the scanner on an asset without the
# deps installed is safe.

def scan_host_screenshot(target: str) -> list[dict[str, Any]]:
    target = _safe_target(target)
    findings: list[dict[str, Any]] = []
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return [{
            "scanner": "screenshot", "type": "screenshot_disabled", "severity": "info",
            "title": f"Screenshots disabled on {target}",
            "description": (
                "The screenshot scanner requires playwright + chromium. "
                "Install them in the image (`pip install playwright && "
                "playwright install chromium`) then re-run the scan."
            ),
            "target": target, "evidence": {"reason": "playwright not installed"},
        }]

    import base64
    from urllib.parse import unquote, urlparse

    # Every sibling HTTP scanner sets follow_redirects=False and says why.
    # Chromium has no such switch: it follows 3xx, meta-refresh and JS
    # navigations, resolving DNS itself, so a scanned host answering
    # "302 -> http://169.254.169.254/latest/meta-data/" would render cloud
    # metadata straight into the PNG stored on the finding — a readable
    # exfiltration channel. Vet every request the page makes instead, with the
    # same policy as the other scanners (LAN allowed, loopback/link-local/
    # metadata/docker-siblings refused). Results are memoised: a page pulls
    # dozens of sub-resources and each check costs a DNS round-trip.
    _verdicts: dict[str, bool] = {}

    def _host_allowed(host: str) -> bool:
        if host not in _verdicts:
            try:
                _resolve_safe_target(host)
                _verdicts[host] = True
            except Exception:
                _verdicts[host] = False
        return _verdicts[host]

    def _guard(route):
        host = (urlparse(route.request.url).hostname or "").lower()
        if not host or not _host_allowed(host):
            logger.info("screenshot: blocked navigation to %s", route.request.url[:120])
            return route.abort()
        return route.continue_()

    proxy_failed = ""
    for port, scheme in [(443, "https"), (80, "http")]:
        url = f"{scheme}://{target}:{port}/"
        try:
            with sync_playwright() as pw:
                # Chromium reads *_proxy but drops a user:pass@ in it: give it
                # the proxy explicitly, or none for a target in the exceptions.
                launch: dict[str, Any] = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]}
                if bypasses_proxy(target, resolve_first_ip(target)):
                    if _proxy_for("https") or _proxy_for("http"):
                        launch["args"].append("--no-proxy-server")
                elif _proxy_for(scheme):
                    p = urlparse(_proxy_for(scheme))
                    launch["proxy"] = {"server": f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")}
                    if p.username:
                        launch["proxy"].update(username=unquote(p.username), password=unquote(p.password or ""))
                browser = pw.chromium.launch(**launch)
                context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 720})
                context.route("**/*", _guard)
                page = context.new_page()
                page.set_default_timeout(8000)
                page.goto(url, wait_until="domcontentloaded")
                title = page.title()[:200]
                png = page.screenshot(type="png", full_page=False)
                browser.close()
            findings.append({
                "scanner": "screenshot",
                "type": "screenshot",
                "severity": "info",
                "title": f"Screenshot {scheme.upper()}: {title or target}",
                "description": f"Visual capture of {url}",
                "target": f"{target}:{port}",
                "evidence": {
                    "url": url,
                    "page_title": title,
                    "png_b64": base64.b64encode(png).decode("ascii"),
                    "size_bytes": len(png),
                },
            })
        except Exception as e:
            logger.info("screenshot failed for %s: %s", url, e)
            if "ERR_PROXY" in str(e) or "ERR_TUNNEL" in str(e):
                proxy_failed = urlparse(_proxy_for(scheme)).hostname or "?"
    if not findings and proxy_failed:  # neither scheme captured, the proxy said why
        logger.warning("screenshot of %s through the outbound proxy %s failed", target, proxy_failed)
        findings.append({
            "scanner": "screenshot", "type": "scanner_error", "severity": "info",
            "title": f"Screenshot of {target} failed through the outbound proxy",
            "description": "Chromium could not reach the target through the outbound proxy.",
            "target": target, "evidence": {"proxy_host": proxy_failed},
        })
    return findings


SURFACE_SCANNERS = {"screenshot": {"label": "HTTP screenshot capture (optional)",
    "kinds": {"host"}, "callable": scan_host_screenshot, "returns_discovered": False}}
