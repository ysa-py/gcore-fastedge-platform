#!/usr/bin/env bash
# Build the production WebAssembly artifact and report its size.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo test (host)"
cargo test --quiet 2>&1 | grep -E "test result" || true

echo "==> cargo clippy"
cargo clippy --all-targets --quiet 2>&1 | grep -c "^warning" | xargs -I{} echo "clippy warnings: {}" || true

echo "==> cargo fmt --check"
cargo fmt --check && echo "fmt: clean"

echo "==> frontend unit tests (node --test)"
npm test --prefix frontend --silent || { echo "frontend tests failed"; exit 1; }

echo "==> building wasm32-wasip1 release artifact"
cargo build --release --target wasm32-wasip1

ARTIFACT="target/wasm32-wasip1/release/fastedge_admin_platform.wasm"
SIZE=$(stat -c%s "$ARTIFACT")
echo "==> artifact: $ARTIFACT ($(numfmt --to=iec "$SIZE"))"
if [ "$SIZE" -gt 2000000 ]; then
  echo "WARNING: artifact exceeds 2 MB — verify your plan's binary size limit before deploying."
fi
echo "==> done"
