#!/usr/bin/env python3
"""LOCAL TESTING ONLY — a faithful mock of the Gcore FastEdge control-plane
endpoints used by this application's write path.

Why this exists: Edge Storage is application read-only. Writes go through
the account REST API (PUT /fastedge/v1/kv/{store_id}/data ...). To run the
REAL wasm binary end-to-end on a developer machine (fastedge-run + Redis),
this mock reproduces the documented semantics against the same local Redis
that fastedge-run reads from, so the full cycle works:

    admin panel → wasm app → send_request → this mock → Redis →
    (instant "replication") → fastedge-run KV reads → app responses

This mirrors the verified API shapes from the official documentation and
OpenAPI schemas (modify_store_data_entry). It also serves /fastedge/v1/me
and /fastedge/v1/stats/calls so the panel's platform-status features are
exercised. It is never deployed anywhere.

Usage:
    python3 scripts/dev/local_gcore_mock.py --redis-port 6399 --http-port 8099 --api-key test-gcore-api-key

    # containerised: expose Redis and the HTTP surface to the other containers
    # on the compose network (see docker-compose.base44.yml)
    python3 scripts/dev/local_gcore_mock.py --redis-bind 0.0.0.0 --http-bind 0.0.0.0

Requires: redislite (pip install redislite).
"""
import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import redislite
except ImportError:
    sys.exit("redislite is required: pip install redislite")

REDIS = None
API_KEY = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        expected = f"APIKey {API_KEY}"
        if self.headers.get("Authorization") != expected:
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        if self.path == "/fastedge/v1/me":
            if not self._authed():
                return
            self._json(200, {
                "client": {"id": 1, "name": "local-test"},
                "plan": {"name": "Free", "max_duration": 1000, "mem_limit": 134217728, "max_subrequests": 50},
                "limits": {"apps": 10, "kv_stores": 5, "binaries": 20},
            })
            return
        if self.path.startswith("/fastedge/v1/stats/calls"):
            if not self._authed():
                return
            self._json(200, {"points": [{"ts": 0, "calls": 0}]})
            return
        self._json(404, {"error": "not found"})

    def do_PUT(self):
        if not self.path.startswith("/fastedge/v1/kv/") or not self.path.endswith("/data"):
            self._json(404, {"error": "not found"})
            return
        if not self._authed():
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except ValueError:
            self._json(400, {"error": "invalid json"})
            return
        # Accept both documented envelope forms.
        if isinstance(payload, list):
            entries = payload
        elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
            entries = payload["data"]
        else:
            self._json(422, {"error": "expected entry array or {\"data\": [...]}"})
            return
        applied = 0
        for e in entries:
            op = e.get("op")
            key = e.get("key", "")
            datatype = e.get("datatype")
            if not key or datatype != "kv":
                self._json(422, {"error": "invalid entry", "entry": e})
                return
            if op == "add":
                p = e.get("payload") or {}
                enc = p.get("encoding", "plain")
                value = p.get("value", "")
                if enc == "base64":
                    try:
                        REDIS.set(key, base64.b64decode(value))
                    except Exception:
                        self._json(422, {"error": "invalid base64"})
                        return
                else:
                    REDIS.set(key, value.encode())
                applied += 1
            elif op == "del_key":
                REDIS.delete(key)
                applied += 1
            elif op == "del_entries":
                self._json(422, {"error": "del_entries not supported by mock"})
                return
            else:
                self._json(422, {"error": "unknown op"})
                return
        self._json(200, {"status": "ok", "applied": applied})


def main():
    global REDIS, API_KEY
    ap = argparse.ArgumentParser()
    ap.add_argument("--redis-port", type=int, default=6399)
    ap.add_argument(
        "--redis-bind",
        default="127.0.0.1",
        help="address the embedded Redis listens on (0.0.0.0 shares it with another container)",
    )
    ap.add_argument("--http-port", type=int, default=8099)
    ap.add_argument(
        "--http-bind",
        default="127.0.0.1",
        help="address the mock's HTTP surface listens on (0.0.0.0 makes it reachable from another container)",
    )
    ap.add_argument("--api-key", default="test-gcore-api-key")
    args = ap.parse_args()
    API_KEY = args.api_key
    REDIS = redislite.Redis(
        serverconfig={
            "port": str(args.redis_port),
            "bind": args.redis_bind,
            # Reachable from outside this container only when asked for, and then
            # never left in Redis' loopback-only "protected" mode.
            "protected-mode": "no" if args.redis_bind != "127.0.0.1" else "yes",
        }
    )
    print(f"[mock] redis listening on {args.redis_bind}:{args.redis_port}", flush=True)
    server = ThreadingHTTPServer((args.http_bind, args.http_port), Handler)
    print(
        f"[mock] gcore control-plane mock on http://{args.http_bind}:{args.http_port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
