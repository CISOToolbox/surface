FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

# Install nmap for active scanning + nuclei for vuln templates.
ARG NUCLEI_VERSION=3.4.7
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl unzip git ca-certificates \
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
    && rm -rf /tmp/nuclei /tmp/nuclei.zip \
    && nuclei -version 2>&1 | head -3 || true

# Pre-download the nuclei community templates at build time so the first scan
# is instant and reproducible. We clone a SPECIFIC tag from the official repo
# (not HEAD) so the build is deterministic and resistant to upstream supply
# chain compromise. Bump this on each nuclei version upgrade.
# Updates at runtime are done via /api/scans/nuclei/update-templates which
# calls `nuclei -ut` (works fine once a session exists).
ARG NUCLEI_TEMPLATES_TAG=v10.4.1
RUN git clone --depth 1 --branch ${NUCLEI_TEMPLATES_TAG} https://github.com/projectdiscovery/nuclei-templates /root/nuclei-templates \
    && count=$(find /root/nuclei-templates -name '*.yaml' | wc -l) \
    && echo "Bundled nuclei templates: $count" \
    && test "$count" -gt 1000 \
    && rm -rf /root/nuclei-templates/.git \
    && apt-get purge -y curl unzip git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /install /usr/local

# Playwright + Chromium for the `screenshot` scanner.
# We install the chromium runtime libraries manually rather than via
# `playwright install --with-deps` because the latter tries to pull a
# few legacy ttf-* packages that have been dropped from Debian trixie.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
        libatspi2.0-0 libx11-6 libxcb1 libxext6 \
        fonts-liberation fonts-unifont \
    && playwright install chromium \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -m -u 1000 surface \
    && mkdir -p /app /data/wordlists \
    && chown -R surface:surface /app /data /root/nuclei-templates /ms-playwright

COPY --chown=surface:surface src/ src/
COPY --chown=surface:surface app/ app/
COPY --chown=surface:surface alembic/ alembic/
COPY --chown=surface:surface alembic.ini .
COPY --chown=surface:surface docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

USER surface
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
