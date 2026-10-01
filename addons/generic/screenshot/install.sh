#!/bin/sh
# Download the Playwright Chromium build into /ms-playwright. Run at image
# build (as root), once playwright is installed: from the image's
# requirements-lock.txt in the base image, from this add-on's requirements.txt
# when Dockerfile.addons layers it. So Chromium (~250 MB) exists only in images
# that include the screenshot add-on.
set -e
export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
playwright install chromium
chown -R surface:surface /ms-playwright 2>/dev/null || true
echo "✓ Playwright Chromium installed in /ms-playwright"
