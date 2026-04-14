#!/bin/sh
# Run pending migrations, then hand off to uvicorn.
# Tolerant on first-boot: if the database is empty, create_all (called at
# FastAPI startup) creates the tables and the alembic baseline is stamped
# automatically via `upgrade head` (the baseline is a no-op migration).
set -e

if [ -n "$DATABASE_URL" ]; then
    echo "[entrypoint] Running alembic upgrade head..."
    alembic upgrade head || {
        echo "[entrypoint] alembic upgrade failed, retrying after 3s (DB maybe not ready yet)"
        sleep 3
        alembic upgrade head
    }
fi

exec python -m uvicorn src.main:app --host 0.0.0.0 --port 8080
