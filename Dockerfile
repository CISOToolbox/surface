# ┌──────────────────────────────────────────────────────────────────┐
# │  CISO Toolbox — Surface (ASM) hardened image                     │
# │  Non-root (surface:1000), read-only rootfs friendly.            │
# │  Ships addons/core AND addons/generic with their heavy deps      │
# │  (nuclei binary+templates, Playwright/Chromium, libsmbclient),   │
# │  so every published image — standalone, suite and client — has   │
# │  the full scanner set. Only addons/custom/<client>/ is layered   │
# │  on top, by Dockerfile.addons.                                   │
# └──────────────────────────────────────────────────────────────────┘

# ── Stage 1: pip dependencies ────────────────────────────────────
# Base image (DEP-07 / CNT-01): python:3.13-slim pinned by tag **and** by the
# multi-arch index digest below, so every build resolves to the exact same
# bits on amd64 and arm64. 3.13 closes the CPython CVEs that had no fix in
# the 3.12 line. Bump tag and digest together:
#   skopeo inspect docker://docker.io/library/python:<tag> --format '{{.Digest}}'
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: hardened runtime ────────────────────────────────────
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="ciso-surface" \
      org.opencontainers.image.description="CISO Toolbox — Surface (ASM) module" \
      org.opencontainers.image.vendor="CISOToolbox" \
      org.opencontainers.image.source="https://github.com/CISOToolbox/demo-docker" \
      org.opencontainers.image.licenses="MIT"

# Runtime system packages — no compilers, no curl/wget/git. nmap is the one
# always-on scanner binary (the nmap core add-on). The generic add-ons declare
# their own system packages in apt-packages.txt; they are installed further
# down, from the add-on tree itself, so the list stays owned by the add-on.
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
# Scanners ship as add-on modules under /app/addons (the loader walks it
# recursively). Two tiers are bundled here:
#   - core/    always-on, Python deps already in requirements.txt
#   - generic/ shareable optional scanners. Bundled since 2026-09 so that every
#              published image (ciso-surface, ciso-surface-suite, and the client
#              images layered on them) carries the full scanner set. Only
#              addons/custom/<client>/ is layered on top, by Dockerfile.addons.
COPY --chown=surface:surface addons/core/ addons/core/
COPY --chown=surface:surface addons/generic/ addons/generic/

# Each generic add-on declares and carries its own dependencies. Same three
# steps as Dockerfile.addons, in the same order — requirements.txt BEFORE
# install.sh, because the screenshot add-on's install.sh calls the `playwright`
# entry point its requirements.txt installs.
#   1) system packages (Chromium runtime libs, libsmbclient…)
#   2) Python deps
#   3) install.sh — heavy binaries fetched at build (nuclei + its templates,
#      the Playwright Chromium download). Nothing is fetched at runtime.
RUN APT_PKGS="$(cat $(find /app/addons -name apt-packages.txt) 2>/dev/null \
        | grep -vE '^\s*#|^\s*$' | sort -u | tr '\n' ' ')" \
    && if [ -n "$APT_PKGS" ]; then \
         apt-get update && apt-get install -y --no-install-recommends $APT_PKGS \
         && rm -rf /var/lib/apt/lists/*; \
       fi \
    && for r in $(find /app/addons -name requirements.txt | sort); do \
         echo "── add-on deps: $r ──"; \
         pip install --no-cache-dir -r "$r" || exit 1; \
       done \
    && for s in $(find /app/addons -name install.sh | sort); do \
         echo "── add-on install: $s ──"; sh "$s"; \
       done \
    && find /app/addons -type d -name bin -exec sh -c 'chmod +x "$1"/* 2>/dev/null || true' _ {} \; \
    && chown -R surface:surface /app/addons \
    && rm -rf /tmp/* /var/tmp/*

# Fail loudly on a missing compiled worker. smb_scan_rs is the one add-on whose
# artefact is produced OUTSIDE the image (rust/build.sh cross-compiles it; rustc
# segfaults under qemu, so it cannot be a builder stage in a multi-arch build).
# Being gitignored, it is trivially forgotten — and it was: the images published
# before 2026-09 carried the add-on with an empty bin/, so the scanner failed at
# first use with "Binary missing". A build that cannot ship a working scanner
# must not produce an image at all.
RUN for a in amd64 arm64; do \
      b="/app/addons/generic/smb_scan_rs/bin/ciso-smb-scan-$a"; \
      [ -x "$b" ] || { echo "FATAL: $b missing or not executable."; \
        echo "Run: bash addons/generic/smb_scan_rs/rust/build.sh amd64 arm64"; \
        exit 1; }; \
    done
COPY --chown=surface:surface alembic/ alembic/
COPY --chown=surface:surface alembic.ini .
COPY --chown=surface:surface docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Hardening: Python optimisations + disable .pyc cache on read-only rootfs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1


# Version identity (FEAT-29): baked at build, exposed via GET /api/version.
ARG PRODUCT_VERSION=dev
ARG BUILD_DATE=
ARG GIT_SHA=
ENV PRODUCT_VERSION=${PRODUCT_VERSION} \
    BUILD_DATE=${BUILD_DATE} \
    GIT_SHA=${GIT_SHA}

EXPOSE 8080

# HEALTHCHECK so orchestrators (Docker, k8s, Compose) can detect hangs.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"]

USER surface

# dumb-init as PID 1 — reaps zombies from subprocess scans (nmap, nuclei)
# and forwards signals cleanly for graceful shutdown.
ENTRYPOINT ["dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
