# Surface

**Continuous Attack Surface Management for CISOs.**

Surface discovers, monitors and triages the assets and vulnerabilities
exposed on the Internet (or on a LAN) for a given perimeter. It runs as a
single Docker Compose stack — FastAPI + PostgreSQL + nuclei + nmap — on
your own machine or a self-hosted VM. **No SaaS, no telemetry, no third
party** beyond the public scanners Surface queries on your behalf
(crt.sh, Shodan, NVD, CISA KEV, upstream nuclei templates).

Part of the [CISO Toolbox](https://cisotoolbox.org) open-source suite.

> **Current release:** v0.3.1 — 22 scanners, nuclei automatic-scan mode,
> executive report, weekly email digest, AI triage, screenshots,
> performance indexes, non-root Docker image. See [release notes](#release-notes).

---

## Highlights at a glance

| Pillar              | Capability                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------|
| Discovery           | CT logs, DNS brute-force, SAN pivoting, CIDR ping sweep, reverse DNS, typosquatting          |
| Assessment          | nmap (quick/standard/deep), nuclei automatic-scan, TLS cert, **TLS grade A-F**, **Security headers A-F** |
| Tech & CVE          | Nuclei wappalyzer tech-detect → **NVD + EPSS + CISA KEV** matching (versioned only)          |
| Exposure            | **Sensitive-file probe** (28 paths), **JS secret scan**, **Cloud bucket enum**               |
| Triage              | Bulk triage, dedup with status machine, **AI triage** (Anthropic/OpenAI), corrective measures |
| Reporting           | **Executive report** (print-to-PDF), **Weekly email digest** (SMTP), 30-day dashboard timeline |
| Security by design  | SSRF guard, DNS-rebinding TOCTOU lock, CSP-strict UI, secret masking, non-root container     |

---

## Features

### Discovery (4 scanners)

- **Certificate Transparency** (`ct_logs`) — crt.sh query for every TLS
  certificate ever issued under a root domain.
- **DNS brute-force** (`dns_brute`) — 1460+ compound keywords, parallel
  resolution, wildcard filtering, optional custom wordlist via
  `SURFACE_DNS_BRUTE_WORDLIST`.
- **SAN pivoting** — during the TLS scan of each host, siblings sharing
  the same certificate are auto-enrolled as monitored assets.
- **CIDR ping sweep** (`discovery`) — nmap host discovery on a range,
  with auto-enrolment of live IPs (capped at 50 per scan to prevent
  runaway from large ranges).

### Assessment (12 scanners per host, 7 per domain)

#### Host-level

| Scanner             | Default | Role                                                           |
|---------------------|---------|----------------------------------------------------------------|
| `nmap_quick`        | yes     | Top-100 port scan (quick profile)                              |
| `nmap_standard`     |         | Top-1000 ports + service/version detection                     |
| `tls`               | yes     | Cert validity, expiry, SAN discovery, chain, hostname mismatch |
| `tls_grade`         | yes     | Protocol/cipher grade A-F (probes TLS 1.0→1.3 + SSL 3.0)       |
| `security_headers`  | yes     | HSTS / CSP / X-Frame / XCTO / RP / PP grade A-F                |
| `nuclei`            | yes     | Automatic-scan mode: wappalyzer + matching templates only      |
| `takeover`          | yes     | 25-fingerprint subdomain takeover detection                    |
| `cve_lookup`        | yes     | NVD 2.0 + EPSS + CISA KEV (from nuclei tech-detect output)    |
| `sensitive_files`   | yes     | 28-path probe (.git, .env, backup.sql, wp-config, .aws, …)     |
| `js_analysis`       | yes     | 12 secret patterns grep across 20 × 512 KB JS bundles          |
| `shodan_host`       |         | Shodan `/host/{ip}` enrichment *(1 Shodan credit per lookup)*  |
| `screenshot`        |         | Chromium headless screenshot *(opt-in, Playwright bundled)*    |

`techstack` (30-signature HTTP fingerprinting) is still available in the
registry but no longer in the default set — nuclei's wappalyzer provides
broader tech detection (3 000+ signatures) and feeds `cve_lookup` directly.

#### Domain-level

| Scanner         | Default | Role                                                     |
|-----------------|---------|----------------------------------------------------------|
| `email_security`| yes     | SPF, DMARC, DKIM, MX analysis                            |
| `typosquatting` | yes     | 60 lookalike variants (omission, transposition, alt TLDs) |
| `ct_logs`       | yes     | crt.sh subdomain discovery                                |
| `dns_brute`     | yes     | Wordlist brute-force with wildcard filter                 |
| `tls`           | yes     | Cert check (domain-level apex probe)                      |
| `takeover`      | yes     | NXDOMAIN + SaaS fingerprint cross-check                   |
| `shodan_domain` |         | Shodan `/dns/domain` *(no credit cost)*                   |
| `cloud_buckets` |         | S3 / Azure Blob / GCS / DO Spaces bucket enumeration      |

#### IP range

| Scanner       | Role                                            |
|---------------|-------------------------------------------------|
| `discovery`   | nmap ping sweep with host auto-enrolment        |

### Nuclei automatic-scan mode *(v0.3.1)*

Since v0.3.1 nuclei runs in **automatic-scan** mode (`-as`): it probes
the target with wappalyzer first, identifies the tech stack, then
executes **only the templates that match** the detected technologies.
This drops the request count from ~25 000 (brute-force all templates)
to ~1 500 (relevant ones only), completing a typical host in 3-5 minutes
instead of timing out. Default tuning: rate-limit 150, concurrency 50,
bulk-size 50, timeout 15 s.

**Severity overrides** — nuclei community templates classify many
security-relevant detections as `info`. Surface upgrades 35+ template
IDs to a minimum severity that reflects CISO-grade risk assessment:

- EOL software (`msexchange-eol`, `iis-eol`, `php-eol`, …) → **high**
- Exposed admin panels (`phpmyadmin-panel`, `adminer-panel`, …) → **high**
- NTLM directory leaks, IIS shortname → **medium**
- GraphQL batching / directive overloading → **low**

### Triage & action plan

- **Deduplication** — the same `scanner | type | target` across rescans
  merges into one finding with a status machine:
  `new → to_fix → fixed` or `new → false_positive` (with mandatory
  justification kept for audit).
- **Bulk triage** — classify N findings in one click (false-positive,
  corrective-measure, or hard delete with cascade).
- **AI triage** — one-click call to Anthropic or OpenAI with a
  structured prompt. Button only visible when the AI assistant is
  configured. API key stays in browser localStorage; the call flies
  directly from the browser to the LLM provider — **the Surface
  backend never sees the key.**
- **Corrective measures** — `to_fix` findings auto-create a measure
  with owner, deadline, and status tracked inside Surface.
- **Full audit trail** — `triaged_at`, `triaged_by`, justification
  preserved indefinitely.

### Reporting

- **Executive report** — toolbar button renders a print-ready HTML page
  in a new tab (Cmd/Ctrl+P → Save as PDF). SQL-aggregated via
  `GROUP BY` + `LIMIT` — stays fast on large databases.
- **Weekly email digest** — `smtplib`-based HTML digest sent once a
  week to a configurable recipient list. Includes a **Send now** button.
- **Screenshots** — displayed inline in finding detail view and as
  thumbnails on host cards. Loaded lazily via a dedicated
  `/api/findings/screenshots` endpoint.

### UX

- **Dashboard v2** — alert banner, 30-day timeline, top exposed hosts,
  top finding types, scanner health panel, measures burn-down.
- **Host grouping** — hosts sharing the same resolved IP are grouped
  into a single card (including IP-literal entries).
- **Inline finding detail** — clicking a finding in the host view opens
  its detail (description, evidence, screenshot, triage, AI) without
  navigating away from the host page.
- **Settings accordion** — 6 native `<details>` sections (Language,
  AI assistant, Timezone, Nuclei, Shodan, SMTP), exclusive expand.
- **Timezone picker** — 30 IANA zones, browser default.
- **FR / EN bilingual** — complete interface with in-app methodology
  and usage guides.
- **Vanilla JS** frontend — no framework, no bundler, CSP-strict.

### Security by design

- **Non-root container** — runs as `surface:1000` (Dockerfile `USER`
  directive). nmap/nuclei capabilities work without root.
- **SSRF guard** — `_resolve_safe_target()` rejects loopback, link-local,
  cloud metadata, docker-compose siblings. Locks resolved IP against
  DNS rebinding. Validates SMTP host, every `<script src>` URL in
  `js_analysis`, and all secondary fetch targets.
- **Email header injection** — sender/recipients validated with
  `parseaddr` + strict regex; CRLF/NUL rejected.
- **Secret masking** — critical/high matches truncated to `abcd…wxyz`
  in the database (never leaked to API or AI triage).
- **XSS protection** — all `innerHTML` escaped via `esc()`, AI-generated
  reference links restricted to `https?://`, digest template uses
  `html.escape`.
- **ReDoS hardening** — JWT and all secret patterns bounded `{10,2000}`.
- **Non-blocking SMTP** — `smtplib` wrapped in `asyncio.to_thread`.
- **CSP-strict** — `script-src 'self'`, no inline, no eval.
- **Fail-closed auth** — `SURFACE_ALLOW_NO_AUTH=1` is dev-only.
- **Rate limiting** — per-user sliding window on scan endpoints.
- **Keys stored server-side** — Shodan, SMTP password never returned
  in GET responses.

---

## Quick start

```bash
cp .env.example .env
# Edit .env — set DB_PASSWORD, JWT_SECRET, APP_URL, AUTH_TOKEN
docker compose up -d
# → open the URL from APP_URL
```

The first time you log in, use the value of `AUTH_TOKEN` from your
`.env` and any email address — the first user becomes admin
automatically.

### Dev mode without auth

For **local development only**:

```bash
SURFACE_ALLOW_NO_AUTH=1 docker compose up -d
```

This bypasses the fail-closed auth check. **Never use in production.**

---

## Environment variables

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `DB_PASSWORD` | yes | — | PostgreSQL password |
| `JWT_SECRET` | yes | — | JWT signing key — use a long random string |
| `AUTH_TOKEN` | yes | — | Shared secret for the standalone login endpoint |
| `APP_URL` | yes | — | Public URL. Cookie `Secure` flag is set when this starts with `https://` |
| `AUTH_MODE` | no | `standalone` | Keep `standalone` for a local deploy |
| `SURFACE_NUCLEI_RATE_LIMIT` | no | `150` | Nuclei requests/sec cap |
| `SURFACE_NUCLEI_CONCURRENCY` | no | `50` | Nuclei template concurrency |
| `SURFACE_DNS_BRUTE_WORDLIST` | no | — | Path to a custom wordlist (must live inside `/data/wordlists/` or `/app/wordlists/`) |
| `SURFACE_ALLOW_NO_AUTH` | no | — | Set to `1` to disable auth for local dev |

All settings that need runtime changes (Shodan key, SMTP config, nuclei
tuning, timezone) live in the **Settings accordion** inside the UI and
are persisted in the `app_settings` table — env vars are for deploy-time
bootstrap only.

See `.env.example` for a minimal working set.

---

## Container image

```
ghcr.io/cisotoolbox/ciso-surface:v0.3.1
ghcr.io/cisotoolbox/ciso-surface:latest
```

Multi-arch: `linux/amd64`, `linux/arm64`.

Two tag families are published to the same image name:

- `:vX.Y.Z` / `:latest` — standalone build (public, no suite-only code)
- `:vX.Y.Z-suite` / `:suite` — suite build (adds Pilot integration routes)

This `README.md` describes the standalone build. The suite variant is
consumed by the CISO Toolbox demo-docker deployment.

---

## Tech stack

FastAPI · SQLAlchemy async · PostgreSQL · Alembic · vanilla JS (no
framework) · nuclei · nmap · Playwright + Chromium · dnspython · httpx ·
cryptography · certifi · stdlib `smtplib` · stdlib `ssl`

---

## Project layout

```
surface/
├── Dockerfile              # multi-stage build, non-root, nuclei + playwright
├── docker-compose.yml      # FastAPI + PostgreSQL stack
├── .env.example            # minimal env var template
├── alembic/                # schema migrations (001..005)
├── src/                    # FastAPI backend
│   ├── main.py             # app wiring, startup hooks
│   ├── auth.py             # JWT + standalone token login
│   ├── models.py           # SQLAlchemy models + indexes
│   ├── scanners.py         # all scanners + SSRF guard
│   ├── scheduler.py        # background recurring scans + weekly digest
│   ├── findings_dedup.py   # status-machine dedup logic
│   ├── rate_limit.py       # sliding-window rate limiter
│   └── routes/             # FastAPI routers
│       ├── monitored.py    # CRUD + scan triggering
│       ├── scans.py        # job history, quick scan, nuclei/shodan config
│       ├── findings.py     # triage, bulk, import, screenshots
│       ├── measures.py     # action plan
│       ├── reports.py      # executive report + SMTP digest
│       └── ai.py           # AI triage proxy
└── app/                    # vanilla JS frontend
    ├── index.html
    ├── js/                 # Surface app + i18n + shared libs
    └── css/                # Surface-specific styles + shared cisotoolbox.css
```

---

## Release notes

### v0.3.1 — 2026-04-16

Security hardening, nuclei refactoring, performance, UX polish:

**Security**
- Container runs as non-root (`USER surface`, uid 1000)
- `javascript:` URI blocked in AI-generated reference links (XSS fix)
- Status allowlist on `PATCH /internal/measures`
- Query param allowlist on `GET /findings`
- Playwright upgraded to 1.51 (was 1.47)

**Nuclei refactoring**
- Automatic-scan mode (`-as`) — wappalyzer first, then matching templates
- Default tuning bumped: rate-limit 150, concurrency 50, bulk-size 50
- 35+ severity overrides (EOL→high, panels→medium, NTLM→medium, etc.)
- Target normalized to `host:port` (was full URL — broke host detail)
- `cve_lookup` reads nuclei `tech-detect` output (techstack no longer required)
- NVD keyword mapping + version truncation for better CVE matching
- Timeout/error findings downgraded to info, `scan_clean` removed
- Severity filter includes info for tech-detect visibility

**Removed**
- `github_enum` scanner, GitHub settings section, routes, env vars
  (will be reimplemented as per-asset scan type in v0.4)
- `SURFACE_ENABLE_SCREENSHOTS` env var (screenshot is opt-in per asset)
- `techstack` removed from defaults (still available in registry)

**Performance**
- Migration 005: 4 indexes on findings (status+severity, scanner, target, created_at)
- Connection pool: pool_size=20, max_overflow=10
- `/api/findings` strips `png_b64` from list responses
- `/api/findings/screenshots` endpoint for host card thumbnails
- `/api/internal/stats` uses `GROUP BY` instead of full-table scan
- Bulk delete uses batch `DELETE IN` instead of N individual deletes

**UX**
- Screenshot displayed inline in finding detail + thumbnail on host cards
- Inline finding detail in host page (click a finding → see detail without navigating away)
- AI triage button hidden when assistant not configured
- Host grouping fixed: IP-literal hosts now group with hostname aliases
- Playwright + Chromium bundled in Docker image

### v0.3.0 — 2026-04-15

Six new scanners, executive reporting, email digest, AI triage:

- `sensitive_files`, `security_headers`, `tls_grade`, `js_analysis`,
  `cloud_buckets`, `github_enum` (removed in v0.3.1)
- Executive report (client-side print-to-PDF)
- Weekly email digest via stdlib `smtplib`
- AI-assisted triage (Anthropic / OpenAI)
- Collapsible Settings accordion, timezone picker
- SSRF hardening, secret masking, ReDoS fix, email header injection fix

### v0.2.1

Async manual scans via BackgroundTask, host grouping by resolved IP
(alembic 004), timezone-aware date formatting, scanner tuple-return fix.

### v0.2.0

Asset tagging + criticality + risk score, scan diff bubbles, tech
stack fingerprinting, CVE matching (NVD + EPSS + KEV), reverse cert
lookup, per-host scan timeline, HTTP screenshots. Alembic 003.

### v0.1.0

First public release. Core scanners (`nmap`, `tls`, `nuclei`,
`ct_logs`, `takeover`, `shodan`), SSRF guard, standalone repo
force-reinit.

---

## Contributing

This repository is synchronized from the [CISO Toolbox] monorepo via
`shared/sync-backend-modules.sh`. Contributions that touch code should
be proposed against the monorepo — they will be propagated here on the
next release cut.

---

## License

See `LICENSE` at the repo root once published.

[CISO Toolbox]: https://cisotoolbox.org
