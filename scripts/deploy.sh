#!/usr/bin/env bash
# Deploy the wasm artifact to FastEdge via the official REST API.
#
# Requires:
#   GCORE_API_KEY  — a Gcore permanent API token (Customer Portal → API tokens)
#   WASM_PATH      — optional; defaults to the release artifact
#
# Actions (explicit, idempotent):
#   1. upload the binary          POST /fastedge/v1/binaries/raw
#   2. create (or update) the app POST /fastedge/v1/apps
#
# The script NEVER configures secrets or Edge Storage automatically — those
# hold privileged values and belong in the portal (see docs/DEPLOYMENT.md).
set -euo pipefail

API_BASE="${GCORE_API_BASE:-https://api.gcore.com}"
APP_NAME="${APP_NAME:-fastedge-admin-platform}"
WASM_PATH="${WASM_PATH:-target/wasm32-wasip1/release/fastedge_admin_platform.wasm}"
API_KEY="${GCORE_API_KEY:-}"

[ -n "$API_KEY" ] || { echo "GCORE_API_KEY is required (export it first)."; exit 1; }
[ -f "$WASM_PATH" ] || { echo "artifact not found: $WASM_PATH (run scripts/build.sh first)"; exit 1; }

echo "==> uploading $WASM_PATH ($(numfmt --to=iec "$(stat -c%s "$WASM_PATH")"))"
BIN_ID=$(curl -sS -X POST "$API_BASE/fastedge/v1/binaries/raw" \
  -H "Authorization: APIKey $API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@$WASM_PATH" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "    binary id: $BIN_ID"

echo "==> creating application '$APP_NAME'"
APP_JSON=$(curl -sS -X POST "$API_BASE/fastedge/v1/apps" \
  -H "Authorization: APIKey $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"$APP_NAME\", \"binary\": $BIN_ID, \"status\": 1}")
echo "$APP_JSON" | python3 -m json.tool
URL=$(echo "$APP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))")
echo ""
echo "==> deployed: $URL"
echo "Next steps (portal): attach secrets, create + link an Edge Storage store,"
echo "then set the app env vars — see docs/DEPLOYMENT.md for the checklist."
