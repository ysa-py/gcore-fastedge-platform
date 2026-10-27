#!/usr/bin/env bash
# Run the REAL wasm binary locally with fastedge-run + Redis + the local
# Gcore control-plane mock, then execute the E2E smoke suite.
#
# Requirements:
#   - fastedge-run on PATH (or set FASTEDGE_RUN to the binary path)
#     https://github.com/G-Core/FastEdge-lib/releases
#   - python3 with redislite (pip install redislite)
#
# Usage:
#   scripts/run_local.sh              # start server + run smoke suite
#   scripts/run_local.sh --no-smoke   # start server only
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
MOCK_PORT="${MOCK_PORT:-8099}"
REDIS_PORT="${REDIS_PORT:-6399}"
API_KEY="${GCORE_API_KEY:-test-gcore-api-key}"
RUN_BIN="${FASTMEDGE_RUN:-${FASTEDGE_RUN:-fastedge-run}}"

command -v "$RUN_BIN" >/dev/null 2>&1 || {
  echo "fastedge-run not found. Install it from https://github.com/G-Core/FastEdge-lib/releases"
  echo "or set FASTEDGE_RUN=/path/to/fastedge-run"
  exit 1
}

# 1. Control-plane mock (+ Redis).
python3 scripts/dev/local_gcore_mock.py --redis-port "$REDIS_PORT" --http-port "$MOCK_PORT" --api-key "$API_KEY" &
MOCK_PID=$!
sleep 1.5

# 2. Credentials (fresh bootstrap admin for this run).
HASH=$(python3 scripts/generate_admin_credentials.py --password 'bootstrap-secret-1' | grep ADMIN_PASSWORD_HASH | cut -d= -f2-)
SESSION_KEY=$(python3 scripts/generate_admin_credentials.py --session-key | grep SESSION_SIGNING_KEY | cut -d= -f2-)
APP_KEY=$(python3 scripts/generate_admin_credentials.py --session-key | grep APP_TOKEN_SIGNING_KEY | cut -d= -f2-)

# 3. The real wasm runtime.
"$RUN_BIN" http \
  --port "$PORT" \
  -w target/wasm32-wasip1/release/fastedge_admin_platform.wasm \
  --kv-stores default=redis://127.0.0.1:"$REDIS_PORT" \
  --env FE_STORE_ID=42 \
  --env FE_API_BASE=http://127.0.0.1:"$MOCK_PORT" \
  --env FE_STORE_NAME=default \
  --env FE_COOKIE_INSECURE=true \
  --secret SESSION_SIGNING_KEY="$SESSION_KEY" \
  --secret APP_TOKEN_SIGNING_KEY="$APP_KEY" \
  --secret GCORE_API_KEY="$API_KEY" \
  --secret ADMIN_USERNAME=bootstrap-admin \
  --secret ADMIN_PASSWORD_HASH="$HASH" &
RUN_PID=$!

cleanup() {
  kill "$RUN_PID" "$MOCK_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 2
echo ""
echo "Admin panel:  http://127.0.0.1:$PORT/  (bootstrap-admin / bootstrap-secret-1)"
echo "Smoke target: http://127.0.0.1:$PORT"
echo ""

if [ "${1:-}" != "--no-smoke" ]; then
  python3 scripts/dev/smoke_e2e.py "http://127.0.0.1:$PORT"
  EXIT=$?
  echo ""
  echo "Leaving the server running for manual inspection (Ctrl+C to stop)…"
  wait
  exit $EXIT
fi

wait
