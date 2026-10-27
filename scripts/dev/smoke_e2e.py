#!/usr/bin/env python3
"""End-to-end smoke suite against a RUNNING FastEdge app instance.

Works against:
  * fastedge-run locally (real wasm runtime + Redis + mock control plane),
  * or a production deployment URL (https://<app>.fastedge.app).

Every step exercises the real HTTP surface of the wasm binary — no mocks
inside the app. Exits non-zero on the first failure with a short report.
"""
import base64
import json
import sys
import time
import urllib.request
import urllib.error

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
RUN_ID = str(int(time.time()))  # unique suffix so the suite is re-runnable
XRW = "fastedge-admin"
COOKIE = None
RESULTS = []


def call(method, path, body=None, use_cookie=True, headers=None, xrw=True):
    req = urllib.request.Request(BASE + path, method=method)
    if xrw:
        req.add_header("X-Requested-With", XRW)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = None
    if body is not None:
        req.add_header("Content-Type", "application/json")
        data = json.dumps(body).encode()
    if use_cookie and COOKIE:
        req.add_header("Cookie", "fes_session=" + COOKIE)
    try:
        with urllib.request.urlopen(req, data=data, timeout=15) as resp:
            raw = resp.read()
            set_cookie = resp.headers.get("Set-Cookie") or ""
            return resp.status, json.loads(raw) if raw else None, dict(resp.headers), set_cookie
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = {"raw": raw.decode(errors="replace")}
        return e.code, parsed, dict(e.headers), e.headers.get("Set-Cookie") or ""


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    mark = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail and not cond else ""))
    if not cond:
        print(f"\n     detail: {detail}")
        print(f"\n{sum(r[1] for r in RESULTS)}/{len(RESULTS)} steps passed before failure.")
        sys.exit(1)


def session_cookie(set_cookie):
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith("fes_session="):
            return part[len("fes_session="):]
    return None


def main():
    print(f"== FastEdge E2E smoke against {BASE} ==")

    # 1. Public liveness.
    s, b, h, _ = call("GET", "/healthz", use_cookie=False)
    check("GET /healthz → 200 ok", s == 200 and b["status"] == "ok", f"got {s} {b}")

    # 2. SPA shell with strict CSP.
    req = urllib.request.Request(BASE + "/", method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        csp = resp.headers.get("Content-Security-Policy") or ""
        ctype = resp.headers.get("Content-Type") or ""
        body = resp.read().decode(errors="replace")
    check("GET / serves SPA with CSP", "default-src 'self'" in csp and "text/html" in ctype, f"cs={'csp' if csp else 'none'} ct={ctype}")
    check("SPA references module assets", "/assets/js/main.js" in body and "/assets/styles.css" in body)

    # 3. Assets served with ETag revalidation (correctness-first caching).
    req = urllib.request.Request(BASE + "/assets/styles.css", method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        check("GET /assets/styles.css → 200 css", resp.status == 200 and "text/css" in resp.headers.get("Content-Type", ""))
        css_etag = resp.headers.get("ETag") or ""
        check("asset ETag present", css_etag.startswith('"'), f"etag={css_etag!r}")
        check("asset revalidation policy", resp.headers.get("Cache-Control") == "no-cache")
    req2 = urllib.request.Request(BASE + "/assets/styles.css", method="GET", headers={"If-None-Match": css_etag})
    try:
        with urllib.request.urlopen(req2, timeout=15) as resp2:
            status = resp2.status
    except urllib.error.HTTPError as e2:
        status = e2.code
    check("asset revalidation → 304", status == 304, f"got {status}")

    # 4. Auth required for admin APIs.
    s, b, _, _ = call("GET", "/api/users", use_cookie=False)
    check("GET /api/users without session → 401", s == 401, f"got {s} {b}")

    # 5. Login (bootstrap admin seeded via secrets).
    global COOKIE
    s, b, h, sc = call("POST", "/api/auth/login", {"username": "bootstrap-admin", "password": "bootstrap-secret-1"}, use_cookie=False)
    check("POST /api/auth/login → 200", s == 200 and b.get("role") == "super_admin", f"got {s} {b}")
    COOKIE = session_cookie(sc)
    check("session cookie set (HttpOnly, SameSite=Strict)", bool(COOKIE) and "HttpOnly" in sc and "SameSite=Strict" in sc, f"set-cookie={sc[:60]}")

    # 6. CSRF guard: WITH a valid session cookie but WITHOUT the custom
    # header → 403 (cross-site requests cannot forge custom headers).
    s, b, _, _ = call("POST", "/api/users", {"email": "x@y.z"}, use_cookie=True, xrw=False)
    check("POST with session but no X-Requested-With → 403", s == 403, f"got {s} {b}")
    s, b, _, _ = call("POST", "/api/auth/logout", {})
    check("POST without step-up first still allowed for logout", s == 200, f"got {s}")
    s, b, h, sc = call("POST", "/api/auth/login", {"username": "bootstrap-admin", "password": "bootstrap-secret-1"}, use_cookie=False)
    COOKIE = session_cookie(sc)

    # 7. Step-up required for destructive ops.
    s, b, _, _ = call("POST", "/api/users", {"email": "smoke@example.io", "display_name": "Smoke User"})
    check("create without step-up → STEP_UP_REQUIRED", s == 403 and b["error"]["code"] == "STEP_UP_REQUIRED", f"got {s} {b}")

    # 8. Step-up grants write access.
    s, b, _, sc = call("POST", "/api/auth/stepup", {"password": "bootstrap-secret-1"})
    check("POST /api/auth/stepup → 200", s == 200, f"got {s} {b}")
    new_cookie = session_cookie(sc)
    if new_cookie:
        COOKIE = new_cookie

    # 9. Create a user.
    s, b, _, _ = call("POST", "/api/users", {
        "email": f"smoke-{RUN_ID}@example.io", "display_name": "Smoke User", "entitlement_id": "ent-basic",
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600)),
    })
    check("POST /api/users → 201", s == 201 and b["uid"].startswith("u"), f"got {s} {b}")
    uid = b["uid"]

    # 10. Listing finds the user.
    s, b, _, _ = call("GET", f"/api/users?q=smoke-{RUN_ID}&limit=10&offset=0")
    check("GET /api/users?q=smoke finds user", s == 200 and b["total"] >= 1, f"got {s}")

    # 11. Credential issuance — token visible exactly once.
    s, b, _, _ = call("POST", f"/api/users/{uid}/credentials", {"label": "smoke"})
    check("POST credentials → 201 with token", s == 201 and b["credential"]["token"].startswith("sk_live_"), f"got {s} {b}")
    token = b["credential"]["token"]
    cred_id = b["credential"]["cred_id"]
    s, b, _, _ = call("GET", f"/api/users/{uid}")
    check("token never echoed again in user record", s == 200 and "sk_live_" not in json.dumps(b), "raw token leaked in user view")

    # 12. Token exchange → short-lived access token.
    s, b, _, _ = call("POST", "/api/v1/token", {"token": token}, use_cookie=False)
    check("POST /api/v1/token → 200 access token", s == 200 and b["token_type"] == "Bearer", f"got {s} {b}")
    access = b["access_token"]

    # 13. /api/v1/me with live entitlement.
    s, b, _, _ = call("GET", "/api/v1/me", use_cookie=False, headers={"Authorization": "Bearer " + access})
    check("GET /api/v1/me → 200 with subscription", s == 200 and b["subscription"]["status"] == "active", f"got {s} {b}")

    # 14. Boundary rule with the REAL clock. The API enforces a 60-second
    # future floor for expiry changes, so set +61s and actually WAIT for
    # the expiration to pass — a genuine, unmocked boundary verification.
    # 75s keeps a safe margin above the 60s API floor even under 1-2s
    # of clock skew between the test process and the runtime.
    exp_epoch = int(time.time()) + 75
    exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_epoch))
    s, b, _, _ = call("PUT", f"/api/users/{uid}/subscription", {"expires_at": exp})
    check("PUT subscription near-term expiry → 200", s == 200, f"got {s} {b}")
    s, b, _, _ = call("GET", "/api/v1/me", use_cookie=False, headers={"Authorization": "Bearer " + access})
    check("access allowed before expiry", s == 200, f"got {s} {b}")
    wait = max(0.5, exp_epoch - time.time() + 1.0)
    print(f"     …waiting {wait:.1f}s for the real expiration to pass")
    time.sleep(wait)
    s, b, _, _ = call("GET", "/api/v1/me", use_cookie=False, headers={"Authorization": "Bearer " + access})
    check("access REJECTED at/after expiry (UTC >= rule)", s == 403 and b["error"]["message"] == "Access expired.", f"got {s} {b}")

    # 15. Renew re-enables.
    s, b, _, _ = call("POST", f"/api/users/{uid}/subscription/renew", {"extend_days": 1})
    check("renew → 200", s == 200, f"got {s} {b}")
    s, b, _, _ = call("GET", "/api/v1/me", use_cookie=False, headers={"Authorization": "Bearer " + access})
    check("access restored after renew", s == 200, f"got {s} {b}")

    # 16. Credential revocation rotates version.
    s, b, _, _ = call("DELETE", f"/api/users/{uid}/credentials/{cred_id}")
    check("DELETE credential → 200", s == 200, f"got {s}")
    s, b, _, _ = call("POST", "/api/v1/token", {"token": token}, use_cookie=False)
    check("exchange with revoked token → denied", s == 401, f"got {s} {b}")

    # 17. Audit trail recorded the actions.
    s, b, _, _ = call("GET", "/api/audit?limit=50&offset=0")
    actions = [e["action"] for e in b.get("events", [])]
    check("audit contains create_user", "create_user" in actions, f"actions={actions[:8]}")
    check("audit contains credential events", "issue_credential" in actions and "revoke_credential" in actions)
    check("audit never contains raw tokens", "sk_live_" not in json.dumps(b))

    # 18. Config get/put round-trip.
    s, cfg, _, _ = call("GET", "/api/config")
    check("GET /api/config → 200", s == 200, f"got {s}")
    cfg2 = {k: cfg[k] for k in ["session_ttl_s", "step_up_ttl_s", "app_token_ttl_s", "login_max_attempts", "login_window_s", "import_batch_max", "audit_retention_days", "pbkdf2_iterations"]}
    s, b, _, _ = call("PUT", "/api/config", cfg2)
    check("PUT /api/config → 200 version bump", s == 200 and b["version"] == cfg["version"] + 1, f"got {s} {b}")

    # 19. Overview aggregates real numbers.
    s, b, _, _ = call("GET", "/api/overview")
    check("GET /api/overview → 200 with users.total ≥ 1", s == 200 and b["users"]["total"] >= 1, f"got {s}")

    # 20. Import dry-run validates without writing.
    payload_users = [{"email": f"import-smoke-{RUN_ID}@example.io", "display_name": "Imported"}]
    s, b, _, _ = call("POST", "/api/import", {"options": {"apply": False}, "payload": {"users": payload_users}})
    check("import dry-run → planned_creates=1, created=0", s == 200 and b["planned_creates"] == 1 and b["created"] == 0, f"got {s} {b}")
    s, b, _, _ = call("POST", "/api/import", {"options": {"apply": True}, "payload": {"users": payload_users}})
    check("import apply → created=1", s == 200 and b["created"] == 1, f"got {s} {b}")

    # 21. Export sanitized (no token hashes by default).
    s, b, _, _ = call("POST", "/api/export", {})
    check("export → sanitized (no token_hash)", s == 200 and "token_hash" not in json.dumps(b), "token_hash leaked")

    # 22. Health diagnostics.
    s, b, _, _ = call("GET", "/api/system/health")
    check("GET /api/system/health → 200 probes", s == 200 and b["storage"]["read_probe"] == "ok", f"got {s} {b}")

    # 23. Limits proxy (mock or real).
    s, b, _, _ = call("GET", "/api/system/limits")
    check("GET /api/system/limits responds", s == 200, f"got {s} {b}")

    # 24. Logout revokes.
    s, b, _, _ = call("POST", "/api/auth/logout", {})
    check("logout → 200", s == 200, f"got {s}")
    s, b, _, _ = call("GET", "/api/auth/session")
    check("session dead after logout", s == 401, f"got {s}")

    total = len(RESULTS)
    print(f"\n== E2E SMOKE: {sum(r[1] for r in RESULTS)}/{total} steps passed ==")


if __name__ == "__main__":
    main()
