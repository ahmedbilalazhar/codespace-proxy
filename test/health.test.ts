/**
 * Unit tests for src/health.ts. Run with: npm test
 * Uses only built-in node:test + node:assert and local mock TCP servers —
 * no network, no VS Code, no proxy required.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import {
  DEFAULT_CONFIG,
  HealthConfig,
  checkProcessRunning,
  checkTcpPort,
  deriveState,
  fetchTrafficIpFromServices,
  fetchViaHttpProxy,
  isPlausibleIp,
  modelIdPresentInZenBody,
  parseHttpResponse,
  probeZenService,
  runHealthCheck,
  runHealthCheckGuarded,
} from '../src/health';

function cfg(): HealthConfig {
  return { ...DEFAULT_CONFIG, checkTimeoutMs: 2000 };
}

/** Start a throwaway TCP server; resolves with its port. */
function listenOnce(onConn?: (s: net.Socket) => void): Promise<{ server: net.Server; port: number }> {
  return new Promise((resolve) => {
    const server = net.createServer((s) => onConn?.(s));
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as net.AddressInfo).port });
    });
  });
}

describe('checkTcpPort', () => {
  it('port available -> true', async () => {
    const { server, port } = await listenOnce();
    try {
      assert.equal(await checkTcpPort('127.0.0.1', port, 2000), true);
    } finally {
      server.close();
    }
  });

  it('port unavailable (1080-style closed port) -> false', async () => {
    const { server, port } = await listenOnce();
    await new Promise<void>((r) => server.close(() => r()));
    assert.equal(await checkTcpPort('127.0.0.1', port, 1000), false);
  });

  it('port 8080-style closed port -> false without hanging', async () => {
    const t0 = Date.now();
    assert.equal(await checkTcpPort('127.0.0.1', 1, 800), false); // port 1 virtually always closed
    assert.ok(Date.now() - t0 < 5000, 'check must respect timeout');
  });
});

describe('checkProcessRunning (mocked exec)', () => {
  const present = (_f: string, _a: string[], _o: { timeout: number }, cb: (e: Error | null, s: string) => void) =>
    cb(null, '"ssh.exe","28184","Console","1","18,212 K"\r\n');
  const absent = (_f: string, _a: string[], _o: { timeout: number }, cb: (e: Error | null, s: string) => void) =>
    cb(null, 'INFO: No tasks are running which match the specified criteria.\r\n');
  const failing = (_f: string, _a: string[], _o: { timeout: number }, cb: (e: Error | null, s: string) => void) =>
    cb(new Error('boom'), '');

  it('SSH process present -> true', async () => {
    assert.equal(await checkProcessRunning('ssh.exe', present), true);
  });

  it('SSH process absent -> false', async () => {
    assert.equal(await checkProcessRunning('ssh.exe', absent), false);
  });

  it('exec failure -> false (never throws)', async () => {
    assert.equal(await checkProcessRunning('ssh.exe', failing), false);
  });
});

describe('parseHttpResponse / modelIdPresentInZenBody', () => {
  it('parses status + body', () => {
    const p = parseHttpResponse('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"a":1}');
    assert.equal(p.statusCode, 200);
    assert.equal(p.body, '{"a":1}');
  });

  it('rejects garbage', () => {
    assert.throws(() => parseHttpResponse('not http at all'));
  });

  it('finds model id in Zen body (both spacing styles)', () => {
    assert.equal(modelIdPresentInZenBody('{"data":[{"id":"muse-spark-1.3-contributor-free"}]}', 'muse-spark-1.3-contributor-free'), true);
    assert.equal(modelIdPresentInZenBody('{"data": [{"id": "muse-spark-1.3-contributor-free"}]}', 'muse-spark-1.3-contributor-free'), true);
    assert.equal(modelIdPresentInZenBody('{"data":[{"id":"other-model"}]}', 'muse-spark-1.3-contributor-free'), false);
  });
});

describe('fetchViaHttpProxy against a mock HTTP bridge', () => {
  let server: net.Server;
  let port: number;

  before(async () => {
    const h = await listenOnce((s) => {
      let data = '';
      s.on('data', (c) => {
        data += c.toString('utf8');
        if (data.includes('\r\n\r\n')) {
          const body = '16.192.228.28';
          s.end(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
        }
      });
    });
    server = h.server;
    port = h.port;
  });

  after(() => {
    server.close();
  });

  it('returns body through the mock bridge', async () => {
    const body = await fetchViaHttpProxy('127.0.0.1', port, 'http://api.ipify.org/', 2000);
    assert.equal(body, '16.192.228.28');
  });

  it('rejects when the bridge is down', async () => {
    await assert.rejects(() => fetchViaHttpProxy('127.0.0.1', 1, 'http://api.ipify.org/', 800));
  });
});

describe('runHealthCheck + deriveState, layered L1/L2 (injected mocks)', () => {
  const up = async () => true;
  const transportOk = async () => ({
    ok: true,
    statusCode: 204 as number | null,
    target: 'https://www.gstatic.com/generate_204',
    elapsedMs: 5,
    detail: 'transport probe ok',
  });

  it('L1 + L2 healthy -> HEALTHY with no echo and no Zen in the cycle', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: up,
      checkProcess: async () => true,
      probeTransport: transportOk,
    });
    assert.equal(deriveState(r), 'HEALTHY');
    assert.equal(r.proxyTrafficOk, true);
    assert.equal(r.externalIp, null, 'normal path must not use echo services');
    assert.equal(r.zenChecked, false, 'Zen runs on a separate cadence, not in the transport cycle');
  });

  it('1080 down + ssh missing -> SSH_DOWN', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: async (h, p) => p !== 1080,
      checkProcess: async () => false,
    });
    assert.equal(r.socksUp, false);
    assert.equal(deriveState(r), 'SSH_DOWN');
  });

  it('1080 down + ssh running -> SOCKS_DOWN', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: async (h, p) => p !== 1080,
      checkProcess: async (img) => img === 'ssh.exe',
    });
    assert.equal(deriveState(r), 'SOCKS_DOWN');
  });

  it('1080 ok but 8080 down -> HTTP_BRIDGE_DOWN', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: async (h, p) => p !== 8080,
      checkProcess: async () => true,
    });
    assert.equal(deriveState(r), 'HTTP_BRIDGE_DOWN');
  });

  it('ports ok but L2 probe fails -> PROXY_FAILED single sample (policy confirms later)', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: up,
      checkProcess: async () => true,
      probeTransport: async () => ({
        ok: false,
        statusCode: null,
        target: 'https://www.gstatic.com/generate_204',
        elapsedMs: 50,
        detail: 'transport probe failed: socket hang up',
      }),
    });
    assert.equal(deriveState(r), 'PROXY_FAILED');
    assert.equal(r.proxyTrafficOk, false);
    assert.match(r.reason ?? '', /single sample, unconfirmed/);
  });

  it('throwing L2 probe counts as down, never rejects', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: up,
      checkProcess: async () => true,
      probeTransport: async () => {
        throw new Error('boom');
      },
    });
    assert.equal(deriveState(r), 'PROXY_FAILED');
  });

  it('L2 non-2xx/3xx -> PROXY_FAILED sample, never healthy', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: up,
      checkProcess: async () => true,
      probeTransport: async () => ({
        ok: false,
        statusCode: 502,
        target: 'https://www.gstatic.com/generate_204',
        elapsedMs: 50,
        detail: 'transport probe answered HTTP 502',
      }),
    });
    assert.equal(r.proxyTrafficOk, false);
    assert.equal(deriveState(r), 'PROXY_FAILED');
  });

  it('never throws, even when every seam fails', async () => {
    const r = await runHealthCheck(cfg(), {
      checkPort: async () => {
        throw new Error('x');
      },
      checkProcess: async () => {
        throw new Error('y');
      },
      probeTransport: async () => {
        throw new Error('z');
      },
    });
    assert.ok(r.reason);
    assert.equal(deriveState(r), 'SSH_DOWN');
  });
});

describe('probeZenService (LEVEL 3, service-side only)', () => {
  it('200 + model -> reachable, no proxy verdict attached', async () => {
    const z = await probeZenService(cfg(), async () => ({
      statusCode: 200,
      body: '{"data":[{"id":"muse-spark-1.3-contributor-free"}]}',
    }));
    assert.equal(z.reachable, true);
    assert.equal(z.modelAvailable, true);
    assert.equal(z.reason, null);
  });

  it('throwing fetch -> unreachable with service-side reason, never throws', async () => {
    const z = await probeZenService(cfg(), async () => {
      throw new Error('proxy CONNECT refused with HTTP 502');
    });
    assert.equal(z.reachable, false);
    assert.match(z.reason ?? '', /service-side, not proxy health/);
  });

  it('non-200 -> unreachable (service-side)', async () => {
    const z = await probeZenService(cfg(), async () => ({ statusCode: 503, body: 'upstream error' }));
    assert.equal(z.reachable, false);
    assert.equal(z.statusCode, 503);
  });

  it('200 without the model -> reachable but model missing', async () => {
    const z = await probeZenService(cfg(), async () => ({ statusCode: 200, body: '{"data":[{"id":"other"}]}' }));
    assert.equal(z.reachable, true);
    assert.equal(z.modelAvailable, false);
  });
});

describe('isPlausibleIp', () => {
  it('accepts v4 and v6, rejects junk', async () => {
    assert.equal(isPlausibleIp('16.192.228.28'), true);
    assert.equal(isPlausibleIp('  1.2.3.4\n'), true);
    assert.equal(isPlausibleIp('2001:db8::1'), true);
    assert.equal(isPlausibleIp(''), false);
    assert.equal(isPlausibleIp('<html>login</html>'), false);
    assert.equal(isPlausibleIp('connection refused'), false);
    assert.equal(isPlausibleIp('abc'), false);
  });
});

describe('fetchTrafficIpFromServices', () => {
  it('falls over to the second service with attribution', async () => {
    let calls = 0;
    const reading = await fetchTrafficIpFromServices(
      async (_h, _p, url) => {
        calls++;
        if (url.includes('ipify')) {
          throw new Error('ipify down');
        }
        return '9.9.9.9\n';
      },
      '127.0.0.1',
      8080,
      ['http://api.ipify.org/', 'http://checkip.amazonaws.com/'],
      1000,
    );
    assert.deepEqual(reading, { ip: '9.9.9.9', service: 'http://checkip.amazonaws.com/' });
    assert.equal(calls, 2);
  });

  it('skips non-IP bodies, rejects when everything fails', async () => {
    await assert.rejects(() =>
      fetchTrafficIpFromServices(async () => 'nope', '127.0.0.1', 8080, ['http://a/', 'http://b/'], 1000),
    );
  });
});

describe('runHealthCheckGuarded', () => {
  it('fast check passes through, not timed out', async () => {
    const { result, timedOut } = await runHealthCheckGuarded(
      cfg(),
      {
        checkPort: async () => true,
        checkProcess: async () => true,
        probeTransport: async () => ({
          ok: true,
          statusCode: 204,
          target: 'https://www.gstatic.com/generate_204',
          elapsedMs: 5,
          detail: 'ok',
        }),
      },
      5000,
    );
    assert.equal(timedOut, false);
    assert.equal(deriveState(result), 'HEALTHY');
  });

  it('hung stage trips the guard instead of hanging', async () => {
    const t0 = Date.now();
    const { result, timedOut } = await runHealthCheckGuarded(
      cfg(),
      { checkPort: () => new Promise<boolean>(() => {}) }, // never settles, no handles
      300,
    );
    assert.equal(timedOut, true);
    assert.match(result.reason ?? '', /overall guard/);
    assert.ok(Date.now() - t0 < 5000);
  });
});
