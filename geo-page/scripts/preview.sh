#!/usr/bin/env bash
#
# Run geo-page locally on the real FastEdge runtime (the same `fastedge-run`
# binary the test suite uses), reachable from other machines on port 8080.
#
#   ./scripts/preview.sh [--port 8080]
#
# FastEdge's runtime binds loopback only, so this script fronts it with socat
# on 0.0.0.0. Geo headers are demo values supplied with --headers, because a
# machine outside Gcore's edge has no POP to inject geoip-* headers.
#
# Stop with Ctrl-C.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PORT=8080
RUNTIME_PORT=8099

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    --runtime-port) RUNTIME_PORT="${2:?--runtime-port needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v socat >/dev/null || { echo "error: socat is required (apt install socat / brew install socat)" >&2; exit 1; }
[ -f wasm/geo-page.wasm ] || { echo "==> building WASM"; npm run build; }

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  RUNNER="$PROJECT_ROOT/node_modules/@gcoredev/fastedge-test/dist/fastedge-cli/fastedge-run-linux-x64" ;;
  Darwin-arm64)  RUNNER="$PROJECT_ROOT/node_modules/@gcoredev/fastedge-test/dist/fastedge-cli/fastedge-run-darwin-arm64" ;;
  *)             RUNNER="${FASTEDGE_RUN_PATH:-}" ;;
esac
[ -n "$RUNNER" ] && [ -x "$RUNNER" ] || { echo "error: no fastedge-run binary for this platform; set FASTEDGE_RUN_PATH" >&2; exit 1; }

cleanup() {
  [ -n "${RUNTIME_PID:-}" ] && kill "$RUNTIME_PID" 2>/dev/null || true
  [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$RUNNER" http -p "$RUNTIME_PORT" -w wasm/geo-page.wasm --wasi-http true --geo \
  --headers x-real-ip=203.0.113.42 \
  --headers geoip-country-code=PT \
  --headers geoip-country-name=Portugal \
  --headers geoip-city=Lisbon \
  --headers geoip-reg=11 \
  --headers geoip-continent=EU \
  --headers geoip-asn=12345 \
  --headers geoip-lat=38.7167 \
  --headers geoip-long=-9.1333 \
  --headers x-forwarded-proto=https &
RUNTIME_PID=$!

for _ in $(seq 1 30); do
  if curl -sf -m 1 "http://127.0.0.1:$RUNTIME_PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

socat "TCP-LISTEN:$PORT,bind=0.0.0.0,fork,reuseaddr,keepalive" "TCP:127.0.0.1:$RUNTIME_PORT" &
SOCAT_PID=$!

echo ""
echo "geo-page is live on http://localhost:$PORT  (demo geo: Lisbon, Portugal)"
echo "JSON: http://localhost:$PORT/api/me   Health: http://localhost:$PORT/healthz"
echo "Ctrl-C to stop."
echo ""
wait "$SOCAT_PID"
