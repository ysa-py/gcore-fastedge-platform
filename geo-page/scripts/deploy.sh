#!/usr/bin/env bash
#
# Deploy geo-page to Gcore FastEdge.
#
# Usage:
#   export GCORE_API_KEY="<your-api-key>"        # never hard-code the key
#   ./scripts/deploy.sh                          # build + upload + create/update + verify
#   ./scripts/deploy.sh --skip-build             # reuse ./wasm/geo-page.wasm
#   ./scripts/deploy.sh --name my-other-name     # deploy under a different app name
#   ./scripts/deploy.sh --dry-run                # print the plan, touch nothing (no key needed)
#
# What it does (mirrors the /gcore-fastedge:deploy skill):
#   1. builds the WASM (npm run build) unless --skip-build
#   2. uploads the binary   POST  /fastedge/v1/binaries/raw
#   3. looks the app up by name, hard-refuses an api_type mismatch,
#      then PATCHes it (update) or POSTs /fastedge/v1/apps (create, status=1)
#   4. waits for the app URL to answer 200 and prints name / id / binary id / URL
#
# Requirements: bash, curl, jq, node + npm (for the build).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

APP_NAME="geo-page"
DESCRIPTION="Shows the visitor's IP address, country and city"
WASM_PATH="$PROJECT_ROOT/wasm/geo-page.wasm"
API_BASE="${GCORE_API_BASE:-https://api.gcore.com}"
SKIP_BUILD=0
DRY_RUN=0
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-60}"
STATE_DIR="$PROJECT_ROOT/.fastedge"
STATE_FILE="$STATE_DIR/deployment.json"

while [ $# -gt 0 ]; do
  case "$1" in
    --name) APP_NAME="${2:?--name needs a value}"; shift 2 ;;
    --description) DESCRIPTION="${2:?--description needs a value}"; shift 2 ;;
    --wasm) WASM_PATH="${2:?--wasm needs a value}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '%s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- pre-flight -------------------------------------------------------------

if ! printf '%s' "$APP_NAME" | grep -qE '^[a-z0-9][a-z0-9-]*[a-z0-9]$'; then
  fail "app name '$APP_NAME' does not match FastEdge's ^[a-z0-9][a-z0-9-]*[a-z0-9]$"
fi

if [ "$DRY_RUN" -eq 0 ]; then
  command -v curl >/dev/null || fail "curl is required"
  command -v jq   >/dev/null || fail "jq is required (https://jqlang.github.io/jq/)"
  [ -n "${GCORE_API_KEY:-}" ] || fail "GCORE_API_KEY is not set. Export it in this shell (do not commit it)."
fi

# --- 1. build ---------------------------------------------------------------

if [ "$SKIP_BUILD" -eq 0 ]; then
  command -v npm >/dev/null || fail "npm is required to build (or pass --skip-build)"
  [ -d node_modules ] || { log "==> installing dependencies (node_modules missing)"; npm install --no-audit --no-fund; }
  log "==> building WASM"
  npm run build
fi

[ -f "$WASM_PATH" ] || fail "WASM not found at $WASM_PATH (build first, or pass --wasm)"
WASM_BYTES=$(wc -c < "$WASM_PATH" | tr -d ' ')
log "==> artifact: $WASM_PATH ($WASM_BYTES bytes)"

if [ "$DRY_RUN" -eq 1 ]; then
  log ""
  log "dry run — nothing was sent to $API_BASE"
  log "  1. POST $API_BASE/fastedge/v1/binaries/raw            (upload $WASM_BYTES-byte WASM)"
  log "  2. GET  $API_BASE/fastedge/v1/apps                    (look for name '$APP_NAME')"
  log "  3. POST $API_BASE/fastedge/v1/apps  or  PATCH .../apps/{id}  (bind the binary, status=1)"
  log "  4. GET  https://<app-url>/                            (expect HTTP 200)"
  exit 0
fi

api() { # api <method> <path> [curl args...]
  local method="$1" path="$2"; shift 2
  curl -sS --fail-with-body -m 120 -X "$method" "$API_BASE$path" \
    -H "Authorization: APIKey $GCORE_API_KEY" "$@"
}

# --- 2. upload the binary ---------------------------------------------------

log "==> uploading binary"
UPLOAD_RESPONSE=$(api POST /fastedge/v1/binaries/raw \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "@$WASM_PATH")

BINARY_ID=$(printf '%s' "$UPLOAD_RESPONSE" | jq -r '.id // empty')
[ -n "$BINARY_ID" ] || fail "upload did not return a binary id: $UPLOAD_RESPONSE"
log "    binary id: $BINARY_ID"

# --- 3. create or update the app -------------------------------------------

APP_ID=""
APP_URL=""

if [ -f "$STATE_FILE" ]; then
  STATE_NAME=$(jq -r '.appName // empty' "$STATE_FILE" 2>/dev/null || true)
  STATE_ID=$(jq -r '.appId // empty' "$STATE_FILE" 2>/dev/null || true)
  if [ "$STATE_NAME" = "$APP_NAME" ] && [ -n "$STATE_ID" ]; then
    APP_ID="$STATE_ID"
    log "==> reusing app id $APP_ID from $STATE_FILE"
  fi
fi

if [ -z "$APP_ID" ]; then
  log "==> looking up an existing app named '$APP_NAME'"
  APPS=$(api GET '/fastedge/v1/apps?limit=1000')
  MATCH=$(printf '%s' "$APPS" | jq -r --arg name "$APP_NAME" \
    '(.apps // .result // .) | if type == "array" then . else [] end
     | map(select(.name == $name)) | .[0] // empty')
  if [ -n "$MATCH" ]; then
    APP_ID=$(printf '%s' "$MATCH" | jq -r '.id')
    EXISTING_TYPE=$(printf '%s' "$MATCH" | jq -r '.api_type // "wasi-http"')
    if [ "$EXISTING_TYPE" != "wasi-http" ]; then
      fail "app '$APP_NAME' already exists with api_type='$EXISTING_TYPE'; refusing to overwrite it. Pick another --name."
    fi
    log "    found app id $APP_ID — will update it"
  fi
fi

if [ -n "$APP_ID" ]; then
  log "==> updating app $APP_ID (binary $BINARY_ID)"
  APP=$(api PATCH "/fastedge/v1/apps/$APP_ID" -H 'Content-Type: application/json' \
    -d "{\"binary\": $BINARY_ID}")
else
  log "==> creating app '$APP_NAME'"
  COMMENT=$(printf '%s' "$DESCRIPTION" | cut -c1-250)
  APP=$(api POST /fastedge/v1/apps -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg name "$APP_NAME" --argjson binary "$BINARY_ID" --arg comment "$COMMENT" \
          '{name: $name, binary: $binary, status: 1, comment: $comment}')")
  APP_ID=$(printf '%s' "$APP" | jq -r '.id // empty')
  [ -n "$APP_ID" ] || fail "create did not return an app id: $APP"
fi

APP_URL=$(printf '%s' "$APP" | jq -r '.url // .app_url // empty')
[ -n "$APP_URL" ] || APP_URL=$(api GET "/fastedge/v1/apps/$APP_ID" | jq -r '.url // .app_url // empty')
[ -n "$APP_URL" ] || fail "the API did not report a URL for app $APP_ID"
case "$APP_URL" in
  http*) : ;;
  *) APP_URL="https://$APP_URL" ;;
esac

mkdir -p "$STATE_DIR"
jq -n --arg appName "$APP_NAME" --argjson appId "$APP_ID" \
      --argjson binaryId "$BINARY_ID" --arg appUrl "$APP_URL" \
      --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{appName: $appName, appId: $appId, binaryId: $binaryId, appUrl: $appUrl, deployedAt: $deployedAt}' \
  > "$STATE_FILE"

# --- 4. verify --------------------------------------------------------------

log "==> verifying $APP_URL (up to ${VERIFY_TIMEOUT}s)"
STATUS=""
DEADLINE=$(( $(date +%s) + VERIFY_TIMEOUT ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "$APP_URL" || true)
  [ "$STATUS" = "200" ] && break
  sleep 3
done

case "$STATUS" in
  200) VERDICT="live" ;;
  530) VERDICT="530 — check env vars / binary validity" ;;
  531) VERDICT="531 — runtime error in the app code" ;;
  532) VERDICT="532 — execution timed out" ;;
  533) VERDICT="533 — memory limit exceeded" ;;
  *)   VERDICT="not 200 yet — the app may need a few more seconds to propagate" ;;
esac

log ""
log "Deployment summary"
log "  App name:  $APP_NAME"
log "  App ID:    $APP_ID"
log "  Binary ID: $BINARY_ID"
log "  URL:       $APP_URL"
log "  HTTP:      ${STATUS:-no response} ($VERDICT)"
log "  State:     $STATE_FILE"
log ""
log "Open ${APP_URL} in a browser to see the page."
log "JSON view:  ${APP_URL}/api/me"
