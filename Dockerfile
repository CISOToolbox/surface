# ┌──────────────────────────────────────────────────────────────────┐
# │  CISO Toolbox — Surface (ASM) hardened LEAN image                │
# │  Non-root (surface:1000), read-only rootfs friendly.            │
# │  Heavy/optional scanner deps (nuclei binary+templates,          │
# │  Playwright/Chromium) are NOT here — they ship WITH their        │
# │  generic add-on (nuclei, screenshot) via Dockerfile.addons.     │
# └──────────────────────────────────────────────────────────────────┘

# ── Stage 1: pip dependencies ────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: hardened runtime ────────────────────────────────────
FROM python:3.12-slim

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="ciso-surface" \
      org.opencontainers.image.description="CISO Toolbox — Surface (ASM) module" \
      org.opencontainers.image.vendor="CISOToolbox" \
      org.opencontainers.image.source="https://github.com/CISOToolbox/demo-docker" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Runtime system packages only — no compilers, no curl/wget/git. nmap is the
# one always-on scanner binary (the nmap core add-on). Chromium libs, nuclei,
# Playwright are NOT installed here — they come with their add-on.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        nmap ca-certificates dumb-init \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -f /usr/bin/wget /usr/bin/curl 2>/dev/null || true

# Copy pip packages from builder.
COPY --from=builder /install /usr/local

# Non-root user — UID 1000 chosen for compatibility with OpenShift
# arbitrary UID ranges and standard Docker-on-host permission mapping.
RUN useradd -r -m -u 1000 -s /usr/sbin/nologin surface \
    && mkdir -p /app /data/wordlists \
    && chown -R surface:surface /app /data

WORKDIR /app

COPY --chown=surface:surface src/ src/
COPY --chown=surface:surface app/ app/
# Core scanners ship as add-on modules under /app/addons (the loader walks it
# recursively). Their Python deps are already in requirements.txt. Optional
# add-ons (generic/custom) are layered on top by Dockerfile.addons, which also
# installs their heavy deps (nuclei binary, Chromium) so the base stays lean.
COPY --chown=surface:surface addons/core/ addons/core/
COPY --chown=surface:surface alembic/ alembic/
COPY --chown=surface:surface alembic.ini .
COPY --chown=surface:surface docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Hardening: Python optimisations + disable .pyc cache on read-only rootfs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# HEALTHCHECK so orchestrators (Docker, k8s, Compose) can detect hangs.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"]

USER surface

# dumb-init as PID 1 — reaps zombies from subprocess scans (nmap, nuclei)
# and forwards signals cleanly for graceful shutdown.
ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
