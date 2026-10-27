import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  defineTestSuite,
  runAndExit,
  runHttpRequest,
  assertHttpStatus,
  assertHttpHeader,
  assertHttpNoHeader,
  assertHttpBodyContains,
  assertHttpContentType,
  assertHttpJson,
} from '@gcoredev/fastedge-test/test';

const here = dirname(fileURLToPath(import.meta.url));

// Geo-IP values below are what a FastEdge POP would inject for a visitor in
// Lisbon, Portugal. Locally they have to be supplied explicitly.
const lisbon = {
  'x-real-ip': '203.0.113.42',
  'geoip-country-code': 'PT',
  'geoip-country-name': 'Portugal',
  'geoip-city': 'Lisbon',
  'geoip-reg': '11',
  'geoip-continent': 'EU',
  'geoip-asn': '12345',
  'geoip-lat': '38.7167',
  'geoip-long': '-9.1333',
  'x-forwarded-proto': 'https',
  'pop-city': 'Madrid',
  'pop-country-code': 'ES',
};

await runAndExit(
  defineTestSuite({
    wasmPath: resolve(here, '../wasm/geo-page.wasm'),
    tests: [
      {
        name: 'GET / renders HTML with IP, city and country',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/', method: 'GET', headers: lisbon });
          assertHttpStatus(response, 200);
          assertHttpContentType(response, 'text/html');
          assertHttpBodyContains(response, '203.0.113.42');
          assertHttpBodyContains(response, 'Lisbon');
          assertHttpBodyContains(response, 'Portugal');
          assertHttpBodyContains(response, 'PT');
          assertHttpBodyContains(response, '🇵🇹');
          assertHttpBodyContains(response, 'Madrid, ES');
          assertHttpBodyContains(response, '38.717, -9.133');
          assertHttpHeader(response, 'cache-control', 'no-store, max-age=0');
        },
      },
      {
        name: 'GET / sends no-store caching and a locked-down CSP',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/', method: 'GET', headers: lisbon });
          assertHttpHeader(
            response,
            'content-security-policy',
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          );
          assertHttpHeader(response, 'x-content-type-options', 'nosniff');
          assertHttpHeader(response, 'vary', 'geoip-country-code, geoip-city');
        },
      },
      {
        name: 'GET /api/me returns the visitor as JSON',
        async run(runner) {
          const response = await runHttpRequest(runner, {
            path: '/api/me',
            method: 'GET',
            headers: lisbon,
          });
          assertHttpStatus(response, 200);
          assertHttpContentType(response, 'application/json');
          const body = assertHttpJson(response);
          if (body.ip !== '203.0.113.42') throw new Error(`unexpected ip: ${String(body.ip)}`);
          if (body.country_code !== 'PT') throw new Error(`unexpected country_code: ${String(body.country_code)}`);
          if (body.country !== 'Portugal') throw new Error(`unexpected country: ${String(body.country)}`);
          if (body.city !== 'Lisbon') throw new Error(`unexpected city: ${String(body.city)}`);
          if (body.latitude !== 38.7167) throw new Error(`unexpected latitude: ${String(body.latitude)}`);
          if (body.longitude !== -9.1333) throw new Error(`unexpected longitude: ${String(body.longitude)}`);
          if (body.edge_pop.city !== 'Madrid') throw new Error(`unexpected edge_pop.city: ${String(body.edge_pop.city)}`);
        },
      },
      {
        name: 'GET /?format=json and Accept: application/json both return JSON',
        async run(runner) {
          const byQuery = await runHttpRequest(runner, {
            path: '/?format=json',
            method: 'GET',
            headers: lisbon,
          });
          assertHttpContentType(byQuery, 'application/json');

          const byHeader = await runHttpRequest(runner, {
            path: '/',
            method: 'GET',
            headers: { ...lisbon, accept: 'application/json' },
          });
          assertHttpContentType(byHeader, 'application/json');
          assertHttpJson(byHeader);
        },
      },
      {
        name: 'missing geo headers degrade gracefully to Unknown',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/', method: 'GET' });
          assertHttpStatus(response, 200);
          assertHttpBodyContains(response, 'Unknown');
          assertHttpBodyContains(response, 'Geo data was not provided for this request');
          assertHttpNoHeader(response, 'location');
        },
      },
      {
        name: 'GET /healthz returns ok',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/healthz', method: 'GET' });
          assertHttpStatus(response, 200);
          const body = assertHttpJson(response);
          if (body.status !== 'ok') throw new Error(`unexpected status: ${String(body.status)}`);
        },
      },
      {
        name: 'POST / is rejected with 405 and an Allow header',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/', method: 'POST' });
          assertHttpStatus(response, 405);
          assertHttpHeader(response, 'allow', 'GET, HEAD');
        },
      },
      {
        name: 'unknown paths return 404 JSON',
        async run(runner) {
          const response = await runHttpRequest(runner, { path: '/nope', method: 'GET', headers: lisbon });
          assertHttpStatus(response, 404);
          const body = assertHttpJson(response);
          if (body.error !== 'not_found') throw new Error(`unexpected error: ${String(body.error)}`);
        },
      },
    ],
  }),
);
