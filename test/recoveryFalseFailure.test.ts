/**
 * Regression tests for the recovery false-failure fixes in
 * src/recoveryMachine.ts:
 *   - an IP-echo outage must NOT sink recovery when the transport itself
 *     works (echo services are diagnostic-only, never infrastructure proof),
 *   - a genuinely dead transport still fails recovery,
 *   - a dead tunnel is still distinguished from a dead echo service.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import { DEFAULT_RECOVERY_CONFIG, recoverProxy } from '../src/recoveryMachine';
import { probeSocksTunnel } from '../src/socks';
import type { TransportProbeResult } from '../src/health';

const transportOk = async (): Promise<TransportProbeResult> => ({
  ok: true,
  statusCode: 204,
  target: 'https://www.gstatic.com/generate_204',
  elapsedMs: 5,
  detail: 'transport probe ok',
});

function baseCfg() {
  return {
    ...DEFAULT_RECOVERY_CONFIG,
    securityGroupId: '',
    maxAttempts: 2,
    baseDelayMs: 1,
    maxDelayMs: 2,
    socksWaitMs: 50,
    httpWaitMs: 50,
    checkTimeoutMs: 200,
  };
}

const noopExec = async () => '';
const ELASTIC = DEFAULT_RECOVERY_CONFIG.expectedExternalIp;

describe('recovery — echo-service outage must not fail a working chain', () => {
  it('HTTP echo down but transport probe OK -> READY with egress unverified', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => ({ ip: ELASTIC, service: 's', elapsedMs: 1 }),
      // Stage 1 (transport probe via :8080) succeeds...
      probeTransport: transportOk,
      // ...stage 2 (echo) is down.
      httpEgress: async () => {
        throw new Error('all IP echo services failed (api.ipify.org: timeout)');
      },
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, true, `expected READY, got ${outcome.state}: ${outcome.path.join('->')}`);
    assert.equal(outcome.state, 'READY');
    assert.equal(outcome.egressVerified, false);
    assert.ok(outcome.logs.some((l) => l.message.includes('egress IP unverified')));
  });

  it('transport probe through :8080 fails -> still an honest RECOVERY_FAILED', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => ({ ip: ELASTIC, service: 's', elapsedMs: 1 }),
      probeTransport: async (): Promise<TransportProbeResult> => ({
        ok: false,
        statusCode: null,
        target: 'https://www.gstatic.com/generate_204',
        elapsedMs: 5,
        detail: 'transport probe failed: connection reset',
      }),
      httpEgress: async () => ELASTIC,
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.state, 'RECOVERY_FAILED');
  });

  it('echo answers a WRONG ip -> still RECOVERY_FAILED (real misroute)', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => ({ ip: ELASTIC, service: 's', elapsedMs: 1 }),
      probeTransport: transportOk,
      httpEgress: async () => '1.2.3.4',
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.match(outcome.path.join(','), /RECOVERY_FAILED/);
  });
});

describe('recovery — dead tunnel vs dead echo (step D classification)', () => {
  it('SOCKS CONNECT opens but echo body is garbage -> no ssh kill, recovery continues', async () => {
    let spawned = 0;
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => {
        throw new Error('echo service answered HTTP 503 through SOCKS5');
      },
      // CONNECT channel opens (tunnel alive), only the echo is broken.
      socksProbe: async () => ({
        connected: true,
        ip: null,
        service: 'http://checkip.amazonaws.com/',
        detail: 'SOCKS CONNECT channel opened; echo unusable',
      }),
      spawnSshFn: () => {
        spawned += 1;
        return { ok: true, pid: 1, detail: 'spawned' };
      },
      probeTransport: transportOk,
      httpEgress: async () => ELASTIC,
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, true, outcome.path.join('->'));
    assert.equal(spawned, 0, 'a live tunnel must never be killed over an echo outage');
    assert.equal(outcome.state, 'READY');
  });

  it('tunnel refused for all targets -> honest RECOVERY_FAILED', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => {
        throw new Error('SOCKS5 handshake refused');
      },
      socksProbe: async () => ({
        connected: false,
        ip: null,
        service: null,
        detail: 'SOCKS5 tunnel refused/broken for all targets',
      }),
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.state, 'RECOVERY_FAILED');
  });
});

describe('probeSocksTunnel classification (error-shape based)', () => {
  it('timeout after CONNECT counts as connected (tunnel forwards, echo is bad)', async () => {
    // A sink server: accepts the SOCKS greeting, never replies.
    const sink = net.createServer((s) => {
      s.once('data', () => {
        /* swallow greeting; never reply */
      });
    });
    await new Promise<void>((r) => sink.listen(0, '127.0.0.1', () => r()));
    const sinkPort = (sink.address() as net.AddressInfo).port;
    try {
      const r = await probeSocksTunnel('127.0.0.1', sinkPort, 100, {
        connect: async () => {
          const sock = new net.Socket();
          return new Promise<net.Socket>((resolve) => {
            sock.connect(sinkPort, '127.0.0.1', () => resolve(sock));
          });
        },
      });
      assert.equal(r.connected, true, r.detail);
    } finally {
      await new Promise<void>((r) => sink.close(() => r()));
    }
  });

  it('handshake refusal counts as not connected', async () => {
    const r = await probeSocksTunnel('127.0.0.1', 1, 50, {
      connect: async () => {
        const sock = new net.Socket();
        return new Promise<net.Socket>((resolve, reject) => {
          const fail = (e: Error) => {
            try {
              sock.destroy();
            } catch {
              /* ignore */
            }
            reject(e);
          };
          sock.once('error', () => fail(new Error('connect ECONNREFUSED')));
          sock.connect(1, '127.0.0.1', () => {
            fail(new Error('SOCKS5 connection closed before handshake completed'));
          });
        });
      },
    });
    assert.equal(r.connected, false);
  });
});
