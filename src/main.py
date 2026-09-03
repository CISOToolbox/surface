from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response

_scheduler_task = None  # prevent GC of asyncio task
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from src.database import async_session, engine
from src.models import Base
from src.routes.ai import router as ai_router
from src.routes.auth import router as auth_router
from src.routes.findings import router as findings_router
from src.routes.measures import router as measures_router
from src.routes.monitored import router as monitored_router
from src.routes.scan_jobs import router as scan_jobs_router
from src.routes.reports import router as reports_router
from src.routes.scans import router as scans_router
from src.routes.users import router as users_router
from src.routes.audit import router as audit_router
from src.version_common import version_payload

# Suite-integration routers — only present in the full suite build;
# silently absent in standalone deployments.
try:
    from src.routes.internal import router as internal_router
except ImportError:
    internal_router = None

try:
    from src.routes.directory_proxy import router as directory_proxy_router
except ImportError:
    directory_proxy_router = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("surface-backend")

app = FastAPI(title="Surface Backend", version="0.3.1")


@app.exception_handler(Exception)
async def _global_error_handler(request, exc):
    import logging as _log
    _log.getLogger("surface-backend").error("Unhandled error: %s", exc, exc_info=True)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.anthropic.com https://api.openai.com https://services.nvd.nist.gov"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Même politique de cache que le proxy de la suite (nginx $cache_policy) :
        # sans Cache-Control, un déploiement standalone (sans proxy) laisse le
        # navigateur au cache heuristique — vieux JS sur nouveau backend, la
        # classe de panne la plus déroutante qui soit (formats d'API croisés).
        # Ne touche pas aux routes qui posent déjà leur propre politique.
        if "cache-control" not in response.headers:
            ct = response.headers.get("content-type", "")
            if ct.startswith(("image/", "font/")):
                response.headers["Cache-Control"] = "public, max-age=3600"
            else:
                response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


app.add_middleware(SecurityHeadersMiddleware)
# Generic write journal (FEAT-30 P1.6): every mutating /api request is
# journaled; routes already covered by in-handler log_action are excluded.
from src.audit_common import install_write_journal_middleware
install_write_journal_middleware(app, exclude=[
    ("DELETE", r"/api/findings/[^/]+"),
    ("POST", r"/api/findings/bulk-(triage|delete)"),
    ("POST", r"/api/monitored-assets"),
    ("DELETE", r"/api/monitored-assets/[^/]+"),
    ("POST", r"/api/monitored-assets/exclusions"),
    ("DELETE", r"/api/monitored-assets/exclusions/[^/]+"),
    ("PATCH", r"/api/measures/[^/]+"),
    ("DELETE", r"/api/measures/[^/]+"),
    ("POST", r"/api/scans/jobs"),
])

APP_URL = os.environ.get("APP_URL", "http://localhost:8086")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(auth_router)
app.include_router(findings_router)
app.include_router(scans_router)
app.include_router(scan_jobs_router)
app.include_router(monitored_router)
app.include_router(measures_router)
app.include_router(ai_router)
app.include_router(reports_router)
app.include_router(users_router)
app.include_router(audit_router)
from src.routes.notifications import router as notifications_router
app.include_router(notifications_router)
if internal_router is not None:
    app.include_router(internal_router)
if directory_proxy_router is not None:
    app.include_router(directory_proxy_router)


@app.get("/api/health")
async def health():
    return {"status": "ok"}



@app.get("/api/version")
async def version():
    """Version identity (FEAT-29): public, used for backup
    compatibility checks before restore."""
    async with async_session() as db:
        return await version_payload("surface", Base.metadata, db)

@app.on_event("startup")
async def on_startup():
    # Fail closed unless AUTH_MODE=none is explicit (see auth_common.assert_auth_posture).
    from src.auth import assert_auth_posture
    assert_auth_posture()
    import asyncio
    from sqlalchemy import select
    from src.scheduler import run_scheduler
    from src.database import async_session
    from src.models import AppSettings
    from src.scanners import set_shodan_api_key_cache, set_nuclei_tuning_cache, _NUCLEI_TUNING_KEYS

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

    # Reconcile orphaned scan jobs. Scans run in-process (FastAPI
    # BackgroundTasks + the scheduler), so any job still marked running/pending
    # at startup was killed by the restart and can never finish. Mark them
    # failed so they stop showing as "in progress" forever — otherwise every
    # redeploy leaks a stuck job into the Scans view.
    from datetime import datetime, timezone
    from sqlalchemy import update as _sa_update
    from src.models import ScanJob
    async with async_session() as db:
        res = await db.execute(
            _sa_update(ScanJob)
            .where(ScanJob.status.in_(["running", "pending"]))
            .values(
                # Stored as a translation KEY (not prose): the frontend localizes
                # job.error.* keys, so this message follows the UI language.
                status="failed",
                error="job.error.interrupted_by_restart",
                completed_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        if res.rowcount:
            logger.info("Reconciled %d orphaned scan job(s) -> failed", res.rowcount)

    # Hydrate in-memory caches from AppSettings so scanners have the
    # right tuning + API keys before the first scheduler tick fires.
    async with async_session() as db:
        row = (await db.execute(
            select(AppSettings).where(AppSettings.key == "shodan.api_key")
        )).scalar_one_or_none()
        if row:
            set_shodan_api_key_cache(row.value)
            logger.info("Shodan API key loaded from DB")
        result = await db.execute(
            select(AppSettings).where(AppSettings.key.like("nuclei.%"))
        )
        overrides: dict[str, int] = {}
        for r in result.scalars():
            short = r.key[len("nuclei."):]
            if short in _NUCLEI_TUNING_KEYS:
                try:
                    overrides[short] = int(r.value)
                except (TypeError, ValueError):
                    pass
        if overrides:
            set_nuclei_tuning_cache(overrides)
            logger.info("Nuclei tuning loaded from DB: %s", overrides)

    global _scheduler_task
    _scheduler_task = asyncio.create_task(run_scheduler())
    logger.info("Surveillance scheduler started")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
