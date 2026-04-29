# ┌──────────────────────────────────────────────────────────────────┐
# │  CISO Toolbox — Surface (ASM) standalone hardened image         │
# │  Multi-stage: pip deps → tools → hardened runtime               │
# │  Non-root (surface:1000), read-only rootfs friendly,            │
# │  minimal packages, no compiler/shell utilities in final layer.  │
# └──────────────────────────────────────────────────────────────────┘

# ── Stage 1: pip dependencies ────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: scanning tools (nuclei, nmap, Playwright/Chromium) ──
FROM python:3.12-slim AS tools

ARG NUCLEI_VERSION=3.8.0
ARG NUCLEI_TEMPLATES_TAG=v10.4.2

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
       nmap curl unzip git ca-certificates \
    && ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
         amd64)  NUCLEI_ARCH=amd64 ;; \
         arm64)  NUCLEI_ARCH=arm64 ;; \
         *)      NUCLEI_ARCH=amd64 ;; \
       esac \
    && curl -fsSL -o /tmp/nuclei.zip \
       "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    && unzip -d /tmp/nuclei /tmp/nuclei.zip \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# Pin templates to a specific tag — deterministic + supply-chain safe.
RUN git clone --depth 1 --branch ${NUCLEI_TEMPLATES_TAG} \
        https://github.com/projectdiscovery/nuclei-templates /nuclei-templates \
    && find /nuclei-templates -name '*.yaml' | wc -l \
    && rm -rf /nuclei-templates/.git

# ── Stage 3: hardened runtime ────────────────────────────────────
FROM python:3.12-slim

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="ciso-surface" \
      org.opencontainers.image.description="CISO Toolbox — Surface (ASM) module" \
      org.opencontainers.image.vendor="CISOToolbox" \
      org.opencontainers.image.source="https://github.com/CISOToolbox/surface" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Install only the runtime system packages — no compilers, no curl/wget/git.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        nmap ca-certificates dumb-init \
        # Playwright / Chromium runtime deps
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
        libatspi2.0-0 libx11-6 libxcb1 libxext6 \
        fonts-liberation fonts-unifont \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -f /usr/bin/wget /usr/bin/curl 2>/dev/null || true

# Copy pip packages from builder.
COPY --from=builder /install /usr/local

# Playwright: install only Chromium browser.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install chromium \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy nuclei binary + templates from the tools stage.
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /nuclei-templates /opt/nuclei-templates

# Non-root user — UID 1000 for host/OCP compatibility.
RUN useradd -r -m -u 1000 -s /usr/sbin/nologin surface \
    && mkdir -p /app /data/wordlists \
    && chown -R surface:surface /app /data /opt/nuclei-templates /ms-playwright

WORKDIR /app

COPY --chown=surface:surface src/ src/
COPY --chown=surface:surface app/ app/
COPY --chown=surface:surface alembic/ alembic/
COPY --chown=surface:surface alembic.ini .
COPY --chown=surface:surface docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Hardening env vars.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

EXPOSE 8080

# HEALTHCHECK so orchestrators detect hangs.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"]

USER surface

# dumb-init as PID 1 — reaps zombies from subprocess scans (nmap, nuclei)
# and forwards signals cleanly for graceful shutdown.
ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
