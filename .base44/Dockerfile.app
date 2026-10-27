# Sandbox / development image for the FastEdge admin platform (Base44).
#
# Deliberately does NOT bake application code: the repository is bind-mounted at
# runtime and the WASM artifact is rebuilt from that source when the container
# starts (see docker-compose.base44.yml), so source edits never require an image
# rebuild. This image only provides the toolchain and the runtime.

FROM rust:1.85-bookworm

# socat    — fastedge-run listens on loopback only, so a forwarder exposes it to
#            the published container port.
# python3  — scripts/generate_admin_credentials.py (development credentials).
# nodejs + npm — frontend unit tests (`npm test --prefix frontend`) / scripts/build.sh.
# curl     — container healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl nodejs npm python3 socat \
 && rm -rf /var/lib/apt/lists/*

# The toolchain the project pins (rust-toolchain.toml: channel `stable`,
# target wasm32-wasip1). clippy/rustfmt keep `scripts/build.sh` usable here.
RUN rustup toolchain install stable --profile minimal \
      --component clippy --component rustfmt \
      --target wasm32-wasip1

# The real FastEdge runtime that executes the wasm artifact (sha256-verified).
ARG FASTEDGE_RUN_VERSION=0.22.0
ARG FASTEDGE_RUN_SHA256=5eb8e6e88b580af817d1eca20ba13dfa88ca554f76a7d0e29989e929776371ae
RUN tarball="fastedge-run-v${FASTEDGE_RUN_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
 && dir="fastedge-run-v${FASTEDGE_RUN_VERSION}-x86_64-unknown-linux-gnu" \
 && curl -fsSL -o "/tmp/${tarball}" \
      "https://github.com/G-Core/FastEdge-lib/releases/download/v${FASTEDGE_RUN_VERSION}/${tarball}" \
 && echo "${FASTEDGE_RUN_SHA256}  /tmp/${tarball}" | sha256sum -c - \
 && tar -xzf "/tmp/${tarball}" -C /tmp \
 && install -m 0755 "/tmp/${dir}/fastedge-run" /usr/local/bin/fastedge-run \
 && rm -rf "/tmp/${tarball}" "/tmp/${dir}"

WORKDIR /app
