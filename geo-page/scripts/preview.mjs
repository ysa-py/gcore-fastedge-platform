/**
 * Local preview harness for geo-page.
 *
 * Serves the built WASM on 0.0.0.0 so it can be opened from a browser (or a
 * hosted preview panel) while running the real FastEdge runtime underneath:
 *
 *   browser  ──▶  this proxy (0.0.0.0:8080)  ──▶  fastedge-run (127.0.0.1:8099)
 *                                                      └─ wasm/geo-page.wasm
 *
 * Why a proxy instead of socat alone:
 *   - fastedge-run binds loopback only, so a forwarder is required anyway.
 *   - The preview panel embeds the page in an iframe; the app's production CSP
 *     (`frame-ancestors 'none'`) would legitimately block that. The proxy drops
 *     only that one response header for the preview. Every other header the edge
 *     app emits is passed through untouched, and the tests assert the real ones.
 *
 * Demo geo values are injected through fastedge-run's --headers flag, because a
 * machine outside Gcore's network has no POP to supply geoip-* headers.
 *
 *   node scripts/preview.mjs [--port 8080] [--runtime-port 8099]
 */

import { createServer, request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(here, '..');
const wasmPath = resolve(projectRoot, 'wasm/geo-page.wasm');

const args = process.argv.slice(2);
const argValue = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};

const port = Number(argValue('--port', '8080'));
const runtimePort = Number(argValue('--runtime-port', '8099'));

function runtimeBinary() {
  const cliDir = resolve(projectRoot, 'node_modules/@gcoredev/fastedge-test/dist/fastedge-cli');
  if (process.platform === 'linux' && process.arch === 'x64') {
    return resolve(cliDir, 'fastedge-run-linux-x64');
  }
  if (process.platform === 'darwin' && process.arch === 'arm64') {
    return resolve(cliDir, 'fastedge-run-darwin-arm64');
  }
  return process.env.FASTEDGE_RUN_PATH ?? '';
}

const demoHeaders = [
  'x-real-ip=203.0.113.42',
  'geoip-country-code=PT',
  'geoip-country-name=Portugal',
  'geoip-city=Lisbon',
  'geoip-reg=11',
  'geoip-continent=EU',
  'geoip-asn=12345',
  'geoip-lat=38.7167',
  'geoip-long=-9.1333',
  'x-forwarded-proto=https',
  'pop-city=Paris',
  'pop-country-code=FR',
];

if (!existsSync(wasmPath)) {
  console.error(`error: ${wasmPath} not found — run "npm run build" first.`);
  process.exit(1);
}

const binary = runtimeBinary();
if (!binary || !existsSync(binary)) {
  console.error('error: no bundled fastedge-run for this platform; set FASTEDGE_RUN_PATH.');
  process.exit(1);
}

const child = spawn(
  binary,
  ['http', '-p', String(runtimePort), '-w', wasmPath, '--wasi-http', 'true',
    ...demoHeaders.flatMap((header) => ['--headers', header])],
  { stdio: ['ignore', 'inherit', 'inherit'] },
);

const shutdown = (code = 0) => {
  if (!child.killed) child.kill('SIGTERM');
  server.close();
  process.exit(code);
};
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
child.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`fastedge-run exited with code ${code}`);
    shutdown(1);
  }
});

/**
 * Waits for the runtime's listener, then for one successful /healthz.
 * The first request compiles a ~12 MB module, which can take tens of seconds —
 * so the health check gets a generous timeout instead of a short poll loop
 * (aborting a compile in flight only restarts the work).
 */
function waitForPort(timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolvePort, rejectPort) => {
    const attempt = () => {
      const socket = connect(runtimePort, '127.0.0.1');
      socket.once('connect', () => {
        socket.destroy();
        resolvePort();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) {
          rejectPort(new Error(`fastedge-run never listened on port ${runtimePort}`));
          return;
        }
        setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

async function waitForRuntime() {
  await waitForPort();
  try {
    const response = await fetch(`http://127.0.0.1:${runtimePort}/healthz`, {
      signal: AbortSignal.timeout(120_000),
    });
    if (response.ok) return;
    throw new Error(`/healthz answered ${response.status}`);
  } catch (error) {
    throw new Error(`fastedge-run did not become ready on port ${runtimePort}: ${error.message}`);
  }
}

const server = createServer((clientRequest, clientResponse) => {
  const upstream = httpRequest(
    {
      host: '127.0.0.1',
      port: runtimePort,
      method: clientRequest.method,
      path: clientRequest.url,
      headers: { ...clientRequest.headers, host: `localhost:${runtimePort}` },
    },
    (upstreamResponse) => {
      const headers = { ...upstreamResponse.headers };
      // Preview-only: allow the page to be embedded in the preview panel.
      delete headers['content-security-policy'];
      clientResponse.writeHead(upstreamResponse.statusCode ?? 502, headers);
      upstreamResponse.pipe(clientResponse);
    },
  );

  upstream.on('error', (error) => {
    clientResponse.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    clientResponse.end(`fastedge-run proxy error: ${error.message}\n`);
  });

  clientRequest.pipe(upstream);
});

await waitForRuntime();

server.listen(port, '0.0.0.0', () => {
  console.log('');
  console.log(`geo-page is live on http://localhost:${port}  (demo visitor: Lisbon, Portugal · POP Paris)`);
  console.log(`JSON:   http://localhost:${port}/api/me`);
  console.log(`Health: http://localhost:${port}/healthz`);
  console.log('Ctrl-C to stop.');
  console.log('');
});
