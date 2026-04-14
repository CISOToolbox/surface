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
COPY src/ src/
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
