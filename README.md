# Surface

**Continuous Attack Surface Management for CISOs.**

Surface discovers, monitors and triages the assets and vulnerabilities
exposed on the Internet (or on a LAN) for a given perimeter. It runs as a
single Docker Compose stack — FastAPI + PostgreSQL + nuclei + nmap — on
your own machine or a self-hosted VM. No SaaS, no telemetry, no external
dependency beyond the public scanners it queries (crt.sh, Shodan, upstream
nuclei templates).

Part of the [CISO Toolbox](https://cisotoolbox.org) open-source suite.

---

## Features

### Discovery
- **Certificate Transparency logs** (crt.sh) — retrieve every subdomain
  ever certified under a root domain
- **DNS brute-force** — compound wordlist tuned for VPN / remote access /
  admin-panel naming patterns, with wildcard filtering
- **Subjective Alternative Names** — extract host aliases from TLS certs
- **CIDR ping-sweep** — identify live IPs in a network range and enrol
  them as monitored hosts

### Assessment
- **nmap** — port scan (quick / standard / deep profiles) with service and
  version detection, banner grabbing, severity classification
- **nuclei** — community templates pinned at build time, configurable
  rate-limit, concurrency, bulk-size, timeout and retries
- **TLS certificate** — expiry, chain, hostname mismatch, self-signed
- **Subdomain takeover** — fingerprint database covering 25+ SaaS services
  (S3, GitHub Pages, Heroku, Azure, Vercel, Shopify, Fastly, …)
- **Shodan** *(optional, API key)* — domain search and per-host enrichment
- **Email security** — SPF, DMARC, DKIM alignment

### Triage and action plan
- **Deduplication** — same `scanner | type | target` across rescans merges
  into one finding with a proper status machine (new → to_fix → fixed, or
  false_positive)
- **Bulk triage** — classify N findings in one click
- **Corrective measures** — each `to_fix` finding auto-creates a measure
  with owner, deadline and status tracked locally in Surface
- **Full audit trail** — triaged_at, triaged_by, justification preserved

### UX
- **Dashboard v2** — alert banner, 30-day timeline, top exposed hosts,
  top finding types, scanner health, measures burndown
- **Scheduler** — per-asset scan frequency, auto-enrolment of discovered
  hosts (capped at 50/scan to avoid runaway)
- **FR / EN bilingual** — complete interface with in-app help
- **Vanilla JS** frontend — no framework, no build step, CSP-strict

### Security by design
- SSRF guard with cloud-metadata blocklist
- DNS-rebinding TOCTOU protection (resolved IP locked end-to-end)
- Per-user sliding-window rate limit on scan endpoints
- JWT cookie with `HttpOnly` + `Secure` (when `APP_URL` is HTTPS)
- Content-Security-Policy: `script-src 'self'` (no inline, no eval)
- Shodan / AI keys stored server-side, never returned in GET responses
- DNS brute-force wordlist restricted to a trusted directory

---

## Quick start

```bash
cp .env.example .env
# Edit .env — set DB_PASSWORD, JWT_SECRET, APP_URL, AUTH_TOKEN
docker compose up -d
# → open the URL from APP_URL
```

The first time you log in, use the value of `AUTH_TOKEN` from your `.env`
and any email address — the first user becomes admin automatically.

### Dev mode without auth

For local development only:

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
| `SURFACE_NUCLEI_RATE_LIMIT` | no | `20` | Nuclei requests/sec cap |
| `SURFACE_NUCLEI_CONCURRENCY` | no | `25` | Nuclei template concurrency |
| `SURFACE_DNS_BRUTE_WORDLIST` | no | — | Path to a custom wordlist (must live inside `/data/wordlists/` or `/app/wordlists/`) |
| `SURFACE_ALLOW_NO_AUTH` | no | — | Set to `1` to disable auth for local dev |

See `.env.example` for a minimal working set.

---

## Container image

```
ghcr.io/cisotoolbox/ciso-surface:v0.1.0
ghcr.io/cisotoolbox/ciso-surface:latest
```

Multi-arch: `linux/amd64`, `linux/arm64`.

---

## Tech stack

FastAPI · SQLAlchemy async · PostgreSQL · vanilla JS (no framework) ·
nuclei · nmap · dnspython · httpx · cryptography · certifi

---

## Project layout

```
surface/
├── Dockerfile              # multi-stage build with pinned nuclei templates
├── docker-compose.yml      # FastAPI + PostgreSQL stack
├── .env.example            # minimal env var template
├── alembic/                # schema migrations
├── src/                    # FastAPI backend
│   ├── main.py             # app wiring, startup hooks
│   ├── auth.py             # JWT + standalone token login
│   ├── models.py           # SQLAlchemy models
│   ├── scanners.py         # all scanners + SSRF guard
│   ├── scheduler.py        # background recurring scans
│   ├── findings_dedup.py   # status-machine dedup logic
│   ├── rate_limit.py       # sliding-window rate limiter
│   └── routes/             # FastAPI routers
└── app/                    # vanilla JS frontend
    ├── index.html
    ├── js/                 # Surface app + i18n + shared libs
    └── css/                # Surface-specific styles + shared cisotoolbox.css
```

---

## Contributing

This repository is synchronized from the [CISO Toolbox] monorepo via
`shared/sync-backend-modules.sh`. Contributions that touch code should be
proposed against the monorepo — they will be propagated here on the next
release cut.

---

## License

See `LICENSE` at the repo root once published.

[CISO Toolbox]: https://cisotoolbox.org
