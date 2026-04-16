from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from src.auth import assert_auth_configured
from src.database import engine
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

# Suite-integration routers — only present in the full suite build;
# silently absent in standalone deployments.
try:
    from src.routes.internal import router as internal_router
except ImportError:
    internal_router = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("surface-backend")

app = FastAPI(title="Surface Backend", version="0.3.1")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)

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
if internal_router is not None:
    app.include_router(internal_router)


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.on_event("startup")
async def on_startup():
    import asyncio
    from sqlalchemy import select
    from src.scheduler import run_scheduler
    from src.database import async_session
    from src.models import AppSettings
    from src.scanners import set_shodan_api_key_cache, set_nuclei_tuning_cache, _NUCLEI_TUNING_KEYS

    assert_auth_configured()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created")

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

    asyncio.create_task(run_scheduler())
    logger.info("Surveillance scheduler started")


app.mount("/", StaticFiles(directory="app", html=True), name="static")
