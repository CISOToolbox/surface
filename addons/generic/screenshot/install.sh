#!/bin/sh
# Download the Playwright Chromium build into /ms-playwright. Run by
# Dockerfile.addons during the client-image overlay (as root), AFTER pip
# installs playwright (requirements.txt). So Chromium (~250 MB) exists only in
# images that include the screenshot add-on.
set -e
export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
playwright install chromium
chown -R surface:surface /ms-playwright 2>/dev/null || true
echo "✓ Playwright Chromium installed in /ms-playwright"
