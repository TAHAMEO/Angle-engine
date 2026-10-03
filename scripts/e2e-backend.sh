#!/usr/bin/env bash
# Disposable backend for the Playwright end-to-end tests (frontend/playwright.config.ts starts it).
#
# Recreates the e2e database from scratch, loads the offline demo (fixture connectors, offline demo AI, built-in
# scanner, fixture face detector — development settings only), writes the image fixtures the tests upload, then runs
# the background worker and the API on 127.0.0.1:${E2E_API_PORT:-8000} until it is stopped.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
PY="${ANGEL_PYTHON:-$BACKEND/.venv/bin/python}"
PG_PORT="${ANGEL_PG_PORT:-54329}"
DB="${ANGEL_E2E_DB:-angel_engine_e2e}"
VAR="$BACKEND/var/e2e"
API_PORT="${E2E_API_PORT:-8000}"

"$ROOT/scripts/dev-postgres.sh" init >/dev/null
"$ROOT/scripts/dev-postgres.sh" start >/dev/null
"$ROOT/scripts/dev-postgres.sh" createdb "$DB"
"$ROOT/scripts/dev-redis.sh" start >/dev/null

url() { printf 'postgresql+asyncpg://%s:%s_dev@127.0.0.1:%s/%s' "$1" "$1" "$PG_PORT" "$DB"; }
export ANGEL_ENV=development
export ANGEL_PUBLIC_ORIGIN="${E2E_BASE_URL:-http://localhost:3000}"
# Secure __Host- cookies when the suite runs over HTTPS (through a TLS proxy, like a real deployment).
if [[ "$ANGEL_PUBLIC_ORIGIN" == https://* ]]; then export ANGEL_COOKIE_SECURE=true; else export ANGEL_COOKIE_SECURE=false; fi
export ANGEL_SCANNER=builtin ANGEL_FACE_DETECTOR=fixture ANGEL_CONNECTOR_MODE=fixtures ANGEL_AI_PROVIDER=fake
export ANGEL_DATABASE_URL="$(url ae_app)" ANGEL_DATABASE_URL_WORKER="$(url ae_worker)"
export ANGEL_DATABASE_URL_MAINTENANCE="$(url ae_maintenance)" ANGEL_DATABASE_URL_OWNER="$(url ae_owner)"
export ANGEL_KEYRING_PATH="$VAR/keys/keyring.json" ANGEL_STORAGE_PATH="$VAR/storage"
export ANGEL_REDIS_URL="${ANGEL_E2E_REDIS_URL:-redis://127.0.0.1:${ANGEL_REDIS_PORT:-63799}/1}"
# The suite drives many pages per minute for each demo account; rate limiting is covered by the backend tests.
export ANGEL_RATE_LIMIT_ENABLED=false
export ANGEL_LOG_LEVEL="${ANGEL_LOG_LEVEL:-WARNING}"
unset ANGEL_MIGRATION_URL ANGEL_SECRETS_DIR

rm -rf "$VAR"
mkdir -p "$VAR/fixtures"
cd "$BACKEND"
"$PY" - <<'PY'
import os

import redis

redis.Redis.from_url(os.environ["ANGEL_REDIS_URL"]).flushdb()  # fresh rate-limit counters for every run
PY
"$PY" -m alembic downgrade base >/dev/null
"$PY" -m alembic upgrade head >/dev/null
"$PY" -m angel_engine.cli seed-demo
"$PY" - "$VAR/fixtures" <<'PY'
import sys
from pathlib import Path

from angel_engine.demo.images import flyer, storefront

out = Path(sys.argv[1])
(out / "storefront-with-face-marker.jpg").write_bytes(storefront(size=(1400, 875), quality=85))
(out / "flyer.jpg").write_bytes(flyer())
PY

trap 'trap - INT TERM EXIT; kill $(jobs -p) 2>/dev/null; wait' INT TERM EXIT
"$PY" -m angel_engine.worker --queues analysis,egress,ai,maintenance &
"$PY" -m uvicorn angel_engine.main:create_app --factory --host 127.0.0.1 --port "$API_PORT" --no-access-log &
wait -n
