/**
 * geo-page — a FastEdge HTTP app (TypeScript).
 *
 * Renders a page with the visitor's IP address, country and city. The values
 * come from the FastEdge edge POP, which injects them on every request:
 *
 *   x-real-ip / x-forwarded-for  -> event.client.address
 *   geoip-* headers              -> event.client.geo (country, city, region, ASN, ...)
 *   pop-* headers                -> event.server.pop (the POP that served the request)
 *
 * Routes:
 *   GET|HEAD /            -> HTML page (or JSON when ?format=json / Accept: application/json)
 *   GET|HEAD /api/me      -> JSON payload
 *   GET|HEAD /healthz     -> {"status":"ok"}
 */

const UNKNOWN = 'Unknown';

interface Snapshot {
  readonly ip: string;
  readonly countryCode: string;
  readonly countryName: string;
  readonly city: string;
  readonly region: string;
  readonly continent: string;
  readonly asn: string;
  readonly latitude: number | null;
  readonly longitude: number | null;
  readonly protocol: string;
  readonly hasGeo: boolean;
  readonly popCity: string;
  readonly popCountry: string;
  readonly renderedAt: string;
}

/** Reads the platform-provided client/server metadata relevant to this page. */
function readSnapshot(event: FetchEvent): Snapshot {
  const client = event.client;
  const geo = client.geo;
  const pop = event.server.pop;

  const countryCode = (geo.countryCode ?? '').trim().toUpperCase();
  const countryName = (geo.countryName ?? '').trim();
  const city = (geo.city ?? '').trim();

  return {
    ip: (client.address ?? '').trim(),
    countryCode,
    countryName,
    city,
    region: (geo.region ?? '').trim(),
    continent: (geo.continent ?? '').trim().toUpperCase(),
    asn: (geo.asn ?? '').trim(),
    latitude: typeof geo.latitude === 'number' ? geo.latitude : null,
    longitude: typeof geo.longitude === 'number' ? geo.longitude : null,
    protocol: (client.protocol ?? '').trim().toLowerCase(),
    hasGeo: Boolean(countryCode || countryName || city),
    popCity: (pop.city ?? '').trim(),
    popCountry: (pop.countryCode ?? '').trim().toUpperCase(),
    renderedAt: new Date().toISOString(),
  };
}

/** Escapes text before it is interpolated into HTML. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Turns an ISO 3166-1 alpha-2 code into a regional-indicator flag; '' if invalid. */
function flagEmoji(countryCode: string): string {
  if (!/^[A-Z]{2}$/.test(countryCode)) {
    return '';
  }
  const base = 0x1f1e6;
  return String.fromCodePoint(
    base + (countryCode.charCodeAt(0) - 65),
    base + (countryCode.charCodeAt(1) - 65),
  );
}

function orUnknown(value: string): string {
  return value.length > 0 ? value : UNKNOWN;
}

function formatCoordinate(latitude: number | null, longitude: number | null): string {
  if (latitude === null || longitude === null) {
    return UNKNOWN;
  }
  return `${latitude.toFixed(3)}, ${longitude.toFixed(3)}`;
}

function formatPop(popCity: string, popCountry: string): string {
  const parts = [popCity, popCountry].filter((part) => part.length > 0);
  return parts.length > 0 ? parts.join(', ') : UNKNOWN;
}

function renderPage(snapshot: Snapshot): string {
  const flag = flagEmoji(snapshot.countryCode);
  const country = orUnknown(snapshot.countryName || snapshot.countryCode);
  const city = orUnknown(snapshot.city);
  const ip = orUnknown(snapshot.ip);
  const countryDetail = snapshot.countryCode
    ? `${escapeHtml(country)} <span class="code">${escapeHtml(snapshot.countryCode)}</span>`
    : escapeHtml(country);

  const notice = snapshot.hasGeo
    ? ''
    : `<p class="notice">Geo data was not provided for this request, so country and city are unknown. In production the FastEdge POP injects <code>geoip-*</code> headers automatically.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Your connection &middot; geo-page</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #070a12;
    --panel: rgba(20, 27, 45, 0.72);
    --border: rgba(125, 152, 255, 0.18);
    --text: #eef2ff;
    --muted: #8b96b8;
    --accent: #6ea8ff;
    --accent-2: #8f7bff;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    padding: 2.5rem 1.25rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background:
      radial-gradient(900px 500px at 12% -5%, rgba(110, 168, 255, 0.20), transparent 60%),
      radial-gradient(800px 500px at 90% 105%, rgba(143, 123, 255, 0.20), transparent 60%),
      var(--bg);
    color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  main {
    width: min(46rem, 100%);
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: clamp(1.5rem, 4vw, 2.75rem);
    box-shadow: 0 30px 80px rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(14px);
  }
  .eyebrow {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    font-size: 0.72rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 1.6rem;
  }
  .dot {
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    background: #46d39a;
    box-shadow: 0 0 0 4px rgba(70, 211, 154, 0.16);
  }
  h1 {
    font-size: clamp(1.05rem, 2.6vw, 1.25rem);
    font-weight: 600;
    margin: 0 0 0.35rem;
    color: var(--muted);
    letter-spacing: 0.01em;
  }
  .ip {
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    font-size: clamp(1.65rem, 6.5vw, 2.9rem);
    font-weight: 650;
    letter-spacing: -0.02em;
    margin: 0 0 1.8rem;
    word-break: break-all;
    background: linear-gradient(92deg, var(--accent), var(--accent-2) 70%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }
  .where {
    display: flex;
    align-items: center;
    gap: 0.85rem;
    padding: 1.05rem 1.15rem;
    border-radius: 14px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.06);
  }
  .flag { font-size: 2rem; line-height: 1; }
  .flag.empty { display: none; }
  .where-text { min-width: 0; }
  .city {
    font-size: 1.22rem;
    font-weight: 600;
    margin: 0;
  }
  .country {
    margin: 0.1rem 0 0;
    color: var(--muted);
    font-size: 0.92rem;
  }
  .country .code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.72rem;
    letter-spacing: 0.08em;
    padding: 0.05rem 0.34rem;
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--accent);
  }
  dl.facts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
    gap: 0.85rem;
    margin: 1.6rem 0 0;
  }
  dl.facts > div {
    padding: 0.8rem 0.9rem;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.025);
  }
  dt {
    font-size: 0.68rem;
    letter-spacing: 0.13em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 0.3rem;
  }
  dd {
    margin: 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.88rem;
    word-break: break-word;
  }
  .notice {
    margin: 1.5rem 0 0;
    padding: 0.85rem 1rem;
    border-radius: 12px;
    border: 1px solid rgba(255, 196, 92, 0.32);
    background: rgba(255, 196, 92, 0.08);
    color: #ffd79a;
    font-size: 0.85rem;
  }
  .notice code { color: #ffe9c2; }
  footer {
    margin-top: 1.9rem;
    padding-top: 1.15rem;
    border-top: 1px solid rgba(255, 255, 255, 0.07);
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1rem;
    justify-content: space-between;
    color: var(--muted);
    font-size: 0.76rem;
  }
  footer a { color: var(--accent); text-decoration: none; }
  footer a:hover { text-decoration: underline; }
  @media (prefers-reduced-motion: no-preference) {
    main { animation: rise 0.5s ease-out both; }
    @keyframes rise {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: none; }
    }
  }
</style>
</head>
<body>
<main>
  <p class="eyebrow"><span class="dot" aria-hidden="true"></span>Your connection &middot; served from the edge</p>
  <h1>Your IP address</h1>
  <p class="ip">${escapeHtml(ip)}</p>

  <div class="where">
    <span class="flag${flag ? '' : ' empty'}" aria-hidden="true">${flag}</span>
    <div class="where-text">
      <p class="city">${escapeHtml(city)}</p>
      <p class="country">${countryDetail}</p>
    </div>
  </div>
  ${notice}

  <dl class="facts">
    <div><dt>Region</dt><dd>${escapeHtml(orUnknown(snapshot.region))}</dd></div>
    <div><dt>Continent</dt><dd>${escapeHtml(orUnknown(snapshot.continent))}</dd></div>
    <div><dt>Coordinates</dt><dd>${escapeHtml(formatCoordinate(snapshot.latitude, snapshot.longitude))}</dd></div>
    <div><dt>Network (ASN)</dt><dd>${escapeHtml(orUnknown(snapshot.asn))}</dd></div>
    <div><dt>Protocol</dt><dd>${escapeHtml(orUnknown(snapshot.protocol))}</dd></div>
    <div><dt>Edge POP</dt><dd>${escapeHtml(formatPop(snapshot.popCity, snapshot.popCountry))}</dd></div>
  </dl>

  <footer>
    <span>Generated ${escapeHtml(snapshot.renderedAt)}</span>
    <span><a href="/api/me">JSON</a> &middot; <a href="/healthz">Health</a> &middot; powered by FastEdge</span>
  </footer>
</main>
</body>
</html>`;
}

function renderJson(snapshot: Snapshot): string {
  return JSON.stringify(
    {
      ip: snapshot.ip || null,
      country: snapshot.countryName || null,
      country_code: snapshot.countryCode || null,
      city: snapshot.city || null,
      region: snapshot.region || null,
      continent: snapshot.continent || null,
      asn: snapshot.asn || null,
      latitude: snapshot.latitude,
      longitude: snapshot.longitude,
      protocol: snapshot.protocol || null,
      edge_pop: {
        city: snapshot.popCity || null,
        country_code: snapshot.popCountry || null,
      },
      generated_at: snapshot.renderedAt,
    },
    null,
    2,
  );
}

const BASE_HEADERS: Readonly<Record<string, string>> = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store, max-age=0',
  vary: 'geoip-country-code, geoip-city',
};

function jsonResponse(body: string, status: number, extra?: Record<string, string>): Response {
  return new Response(body, {
    status,
    headers: {
      ...BASE_HEADERS,
      'content-type': 'application/json; charset=utf-8',
      ...extra,
    },
  });
}

function wantsJson(request: Request, pathname: string): boolean {
  if (pathname === '/api/me') {
    return true;
  }
  const url = new URL(request.url);
  if (url.searchParams.get('format') === 'json') {
    return true;
  }
  const accept = request.headers.get('accept') ?? '';
  return accept.toLowerCase().includes('application/json');
}

async function eventHandler(event: FetchEvent): Promise<Response> {
  const { request } = event;
  const method = request.method.toUpperCase();
  const { pathname } = new URL(request.url);

  if (method !== 'GET' && method !== 'HEAD') {
    return jsonResponse(JSON.stringify({ error: 'method_not_allowed' }), 405, {
      allow: 'GET, HEAD',
    });
  }

  if (pathname === '/healthz') {
    return jsonResponse(JSON.stringify({ status: 'ok' }), 200);
  }

  if (pathname !== '/' && pathname !== '/api/me') {
    const snapshot = readSnapshot(event);
    return new Response(
      JSON.stringify({ error: 'not_found', path: pathname, ip: snapshot.ip || null }),
      {
        status: 404,
        headers: {
          ...BASE_HEADERS,
          'content-type': 'application/json; charset=utf-8',
        },
      },
    );
  }

  const snapshot = readSnapshot(event);

  if (wantsJson(request, pathname)) {
    return jsonResponse(renderJson(snapshot), 200);
  }

  const headers = {
    ...BASE_HEADERS,
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  };

  if (method === 'HEAD') {
    return new Response(null, { status: 200, headers });
  }

  return new Response(renderPage(snapshot), { status: 200, headers });
}

addEventListener('fetch', (event: FetchEvent) => {
  event.respondWith(eventHandler(event));
});
