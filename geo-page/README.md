# geo-page

A **FastEdge HTTP app (TypeScript)** that shows each visitor their own IP address, country and city — served entirely from Gcore's edge, with no origin server.

```
visitor ──▶ nearest FastEdge POP ──▶ geo-page.wasm ──▶ HTML page
                 │
                 └── injects x-real-ip + geoip-* + pop-* headers
```

## What the page shows

| Field | Source on the edge |
|---|---|
| IP address | `event.client.address` (`x-real-ip`, falling back to `x-forwarded-for`) |
| Country | `event.client.geo.countryName` + `geo.countryCode` (`geoip-country-name`, `geoip-country-code`) |
| City | `event.client.geo.city` (`geoip-city`) |
| Region / continent / ASN / coordinates | `geoip-reg`, `geoip-continent`, `geoip-asn`, `geoip-lat`, `geoip-long` |
| Edge POP that answered | `event.server.pop` (`pop-city`, `pop-country-code`) |

The country code is rendered as a flag, and missing values degrade to `Unknown` with an explanatory note instead of a broken page.

## Routes

| Route | Response |
|---|---|
| `GET|HEAD /` | HTML page |
| `GET|HEAD /?format=json` or `Accept: application/json` | same data as JSON |
| `GET|HEAD /api/me` | JSON: `ip`, `country`, `country_code`, `city`, `region`, `continent`, `asn`, `latitude`, `longitude`, `protocol`, `edge_pop`, `generated_at` |
| `GET|HEAD /healthz` | `{"status":"ok"}` |
| any other method | `405` + `Allow: GET, HEAD` |
| any other path | `404` JSON |

Every response is `Cache-Control: no-store` with `Vary: geoip-country-code, geoip-city`, so a shared cache can never hand one visitor another visitor's location. The HTML response carries a strict CSP (`default-src 'none'; style-src 'unsafe-inline'; …`) — the page runs no JavaScript at all — plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. All interpolated values are HTML-escaped.

## Local development

```bash
npm install
npm run build          # tsc (strict) → wasm/geo-page.wasm
npm test               # 8 tests, run against the built WASM
./scripts/preview.mjs  # real fastedge-run behind a proxy on http://localhost:8080
```

`npm test` uses `@gcoredev/fastedge-test`, which boots the bundled `fastedge-run` binary — the same runtime the edge uses — and issues real HTTP requests at the compiled WASM. The tests feed `x-real-ip` / `geoip-*` headers exactly as a POP would.

`scripts/preview.mjs` serves the built artifact on `0.0.0.0:8080` with **demo** geo values (visitor in Lisbon, Portugal; POP in Paris), because a machine outside Gcore's network has no POP to inject geo headers. It is a faithful preview of the deployed page, not the edge deployment itself.

It runs the bundled `fastedge-run` exactly as the tests do and proxies it, for two reasons: the runtime binds loopback only, and the app's production CSP (`frame-ancestors 'none'`) would correctly refuse to render inside a preview panel's iframe. The proxy therefore drops that one response header in preview only — every other header the edge app emits (`no-store`, `Vary`, `nosniff`, `Referrer-Policy`, content type) is passed through untouched, and `npm test` asserts the real CSP on the artifact itself.

## Deploy

```bash
export GCORE_API_KEY="<your key>"     # keep it out of shell history/commits
./scripts/deploy.sh
```

The script implements the `/gcore-fastedge:deploy` flow in one command:

1. `npm run build` (skip with `--skip-build`)
2. `POST /fastedge/v1/binaries/raw` — uploads the WASM
3. `GET /fastedge/v1/apps` — finds an existing app named `geo-page`
   (an `api_type` mismatch is a hard refusal, never a silent overwrite)
4. `PATCH /fastedge/v1/apps/{id}` on update, `POST /fastedge/v1/apps` with `status: 1` on create
5. polls the returned app URL until it answers `200`, then prints name / app ID / binary ID / URL
6. records `appName`, `appId`, `binaryId`, `appUrl` in `.fastedge/deployment.json` (git-ignored) so a re-deploy updates the same app

Useful flags: `--dry-run` (plan only, no key needed), `--name`, `--description`, `--wasm`, `--skip-build`. `GCORE_API_BASE` overrides the API host. Requirements: `curl`, `jq`, Node ≥ 22. No Docker and no extra tooling — the FastEdge runtime ships with `@gcoredev/fastedge-test`.

The API returns the app URL at build time (`POST`/`PATCH /fastedge/v1/apps` → `url`), typically of the form `https://<app-id>.fastedge.gcore.com`. There is no separate DNS step.

### Deploy from CI instead (optional)

If the shell you are in cannot reach `api.gcore.com`, the same script runs unchanged on a GitHub runner. Add `GCORE_API_KEY` as a repository secret and a manual workflow at `.github/workflows/deploy-geo-page.yml`:

```yaml
name: deploy geo-page
on: { workflow_dispatch: {} }
jobs:
  deploy:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: geo-page } }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: sudo apt-get update && sudo apt-get install -y jq
      - run: npm ci
      - run: npm test
      - run: ./scripts/deploy.sh
        env: { GCORE_API_KEY: "${{ secrets.GCORE_API_KEY }}" }
```

The job prints the app URL; revoke the key afterwards if it is a temporary one.

## Layout

```
geo-page/
├── src/index.ts            # the whole app (routing, rendering, JSON)
├── fastedge-test/app.test.mjs
├── scripts/deploy.sh       # build → upload → create/update → verify
├── scripts/preview.mjs     # local fastedge-run behind an embedding-safe proxy
├── package.json
└── tsconfig.json           # strict, noEmit (fastedge-build does the bundling)
```

## Verification (executed in this repository)

| Check | Result |
|---|---|
| `npm run build` (tsc strict + fastedge-build) | build success, `wasm/geo-page.wasm` = 12,127,012 bytes |
| `npm test` (`@gcoredev/fastedge-test` + real `fastedge-run`) | **8/8 passed** |
| `npm run preview` + `curl` on `:8080` | `200` HTML with IP `203.0.113.42`, Lisbon, Portugal 🇵🇹, POP Paris, FR; `/api/me` JSON; `/healthz` ok; `POST /` → `405` |
| `scripts/deploy.sh` (real deploy to `api.gcore.com`) | **deployed & live** (2026-10-27): app `geo-page` (id 3616), binary 10169 → <https://geo-page-1076003.fastedge.app> — `200` with real POP-injected geo (visitor IP `34.168.24.2`, The Dalles, United States, POP Seattle, US), `/api/me` JSON, `/healthz` ok, `POST /` → `405`, unknown path → `404`. A re-deploy updates the same app (state in `.fastedge/deployment.json`). |

## Limits

- City/region accuracy is only as good as Gcore's GeoIP database; a missing city renders as `Unknown`, never as a wrong guess.
- Basic-plan execution is capped at 50 ms and 128 MB — this app renders a single string and does no I/O, so it stays far inside both.
- `geoip-*` headers are injected by the POP, not by the client; the local runtime has to be told to supply them (that is what `scripts/preview.mjs` does).
