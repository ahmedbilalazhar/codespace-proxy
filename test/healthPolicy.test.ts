/**
 * Tests for the false-positive fix (src/healthPolicy.ts + layered health).
 * Each maps to a required scenario: diagnostic failures must never read as
 * proxy failure, confirmation needs consecutive strikes, notifications only
 * for confirmed user-relevant events.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { deriveState, runHealthCheck } from '../src/health';
import {
  DEFAULT_POLICY_CONFIG,
  PolicyState,
  createProbeGate,
  emptyPolicy,
  emptyZen,
  hasRecentTrafficOk,
  nextPolicy,
  nextZen,
  shouldNotifyRecovery,
} from '../src/healthPolicy';

const CFG = { failureThreshold: 3, minOutageNotifySec: 20, recentTrafficWindowMs: 120_000 };
const IDLE = { transportOnlyFailure: false, recentTrafficOk: false, reconnecting: false, recovering: false };

function down(over: Partial<typeof IDLE> = {}) {
  return { ...IDLE, ...over };
}

const upPorts = async () => true;
const transportOk = async () => ({
  ok: true,
  statusCode: 204 as number | null,
  target: 'https://www.gstatic.com/generate_204',
  elapsedMs: 5,
  detail: 'ok',
});
const transportFail = async () => ({
  ok: false,
  statusCode: null as number | null,
  target: 'https://www.gstatic.com/generate_204',
  elapsedMs: 50,
  detail: 'transport probe failed: socket hang up',
});

describe('Test 1 — OpenCode works, transport probe fails: DEGRADED, no strike, no recovery', () => {
  it('policy holds strikes at 0 when recent tracked traffic succeeded', () => {
    let s: PolicyState = emptyPolicy();
    const out = nextPolicy(s, 'infra-down', 1_000_000, CFG, down({ transportOnlyFailure: true, recentTrafficOk: true }));
    s = out.state;
    assert.equal(s.verdict, 'DEGRADED');
    assert.equal(s.strikes, 0);
    assert.deepEqual(out.events, []);
    const out2 = nextPolicy(s, 'infra-down', 1_001_000, CFG, down({ transportOnlyFailure: true, recentTrafficOk: true }));
    assert.equal(out2.state.strikes, 0, 'repeated diagnostic failures must not accrue strikes while traffic flows');
    assert.deepEqual(out2.events, []);
  });

  it('layered check performs no echo lookup in the normal path', async () => {
    const { DEFAULT_CONFIG } = await import('../src/health.js');
    const r = await runHealthCheck(
      { ...DEFAULT_CONFIG, checkTimeoutMs: 2000 },
      { checkPort: upPorts, checkProcess: async () => true, probeTransport: transportFail },
    );
    assert.equal(deriveState(r), 'PROXY_FAILED', 'single sample only — confirmation happens in policy');
    assert.equal(r.externalIp, null, 'no echo service may be consulted in the normal path');
    assert.equal(r.zenChecked, false, 'no Zen in the transport cycle');
  });
});

describe('Test 2 — OpenCode works, Zen times out: ZEN_*, proxy stays healthy', () => {
  it('zen degrades then goes unreachable across consecutive failures, proxy verdict untouched', () => {
    let z = emptyZen();
    z = nextZen(z, false);
    assert.equal(z.verdict, 'ZEN_DEGRADED');
    z = nextZen(z, false);
    assert.equal(z.verdict, 'ZEN_DEGRADED');
    z = nextZen(z, false);
    assert.equal(z.verdict, 'ZEN_UNREACHABLE');
    z = nextZen(z, true);
    assert.deepEqual(z, { consecutiveFailures: 0, verdict: 'ZEN_OK' });
  });

  it('healthy transport + bad zen still derives HEALTHY at the transport layer', async () => {
    const { DEFAULT_CONFIG } = await import('../src/health.js');
    const r = await runHealthCheck(
      { ...DEFAULT_CONFIG, checkTimeoutMs: 2000 },
      { checkPort: upPorts, checkProcess: async () => true, probeTransport: transportOk },
    );
    assert.equal(deriveState(r), 'HEALTHY', 'Zen outage must not sink the transport verdict');
  });
});

describe('Tests 3/4/5 — strikes gate recovery: 1,2 degraded; 3rd confirms', () => {
  it('failure #1 and #2 -> DEGRADED, no event, no recovery', () => {
    let s = emptyPolicy();
    let o = nextPolicy(s, 'infra-down', 1000, CFG, down());
    assert.equal(o.state.verdict, 'DEGRADED');
    assert.equal(o.state.strikes, 1);
    assert.deepEqual(o.events, []);
    o = nextPolicy(o.state, 'infra-down', 2000, CFG, down());
    assert.equal(o.state.verdict, 'DEGRADED');
    assert.equal(o.state.strikes, 2);
    assert.deepEqual(o.events, []);
  });

  it('failure #3 -> PROXY_DOWN with exactly one notify event', () => {
    let s = emptyPolicy();
    let o = nextPolicy(s, 'infra-down', 1000, CFG, down());
    o = nextPolicy(o.state, 'infra-down', 2000, CFG, down());
    o = nextPolicy(o.state, 'infra-down', 3000, CFG, down());
    assert.equal(o.state.verdict, 'PROXY_DOWN');
    assert.equal(o.state.strikes, 3);
    assert.deepEqual(o.events, ['notify-proxy-down']);
    assert.equal(o.state.confirmedDownSinceMs, 3000);
    const o2 = nextPolicy(o.state, 'infra-down', 4000, CFG, down());
    assert.deepEqual(o2.events, [], 'no repeat notification while the episode continues');
  });

  it('success resets strikes (flapping never confirms)', () => {
    let s = emptyPolicy();
    for (const t of [1000, 2000]) {
      const o = nextPolicy(s, 'infra-down', t, CFG, down());
      s = nextPolicy(o.state, 'ok', t + 500, CFG, down()).state;
    }
    assert.equal(s.strikes, 0);
    assert.equal(s.verdict, 'READY');
    assert.equal(s.confirmedDownSinceMs, null);
  });
});

describe('Test 6 — single-flight gate: no overlapping probes', () => {
  it('second tryEnter fails while held; works again after exit', () => {
    const g = createProbeGate();
    assert.equal(g.tryEnter(), true);
    assert.equal(g.active, true);
    assert.equal(g.tryEnter(), false, 'a 15s-style pile-up must be impossible');
    g.exit();
    assert.equal(g.active, false);
    assert.equal(g.tryEnter(), true);
    g.exit();
  });
});

describe('Test 7 — network change: RECONNECTING owns the outcome, no premature verdict', () => {
  it('strikes accrue silently while reconnecting; notify only after the sequence releases', () => {
    let s = emptyPolicy();
    const rc = { ...down(), reconnecting: true };
    let o = nextPolicy(s, 'infra-down', 1000, CFG, rc);
    o = nextPolicy(o.state, 'infra-down', 2000, CFG, rc);
    o = nextPolicy(o.state, 'infra-down', 3000, CFG, rc);
    assert.equal(o.state.verdict, 'PROXY_DOWN', 'genuinely dead proxy still confirms underneath');
    assert.deepEqual(o.events, [], 'no PROXY_FAILED-style notification before the G-sequence settles');
    const o2 = nextPolicy(o.state, 'infra-down', 4000, CFG, down());
    assert.deepEqual(o2.events, ['notify-proxy-down'], 'notification fires once released and still down');
  });
});

describe('Tests 8/9 — real port loss still confirms and allows recovery', () => {
  it(':1080 actually disappears x3 -> confirmable PROXY_DOWN input', async () => {
    const { DEFAULT_CONFIG } = await import('../src/health.js');
    let s = emptyPolicy();
    for (const t of [1000, 2000, 3000]) {
      const r = await runHealthCheck(
        { ...DEFAULT_CONFIG, checkTimeoutMs: 2000 },
        { checkPort: async (_h, p) => p !== 1080, checkProcess: async () => false },
      );
      assert.equal(deriveState(r), 'SSH_DOWN');
      const o = nextPolicy(s, 'infra-down', t, CFG, down());
      s = o.state;
    }
    assert.equal(s.verdict, 'PROXY_DOWN');
  });

  it(':8080 actually disappears x3 -> confirmable PROXY_DOWN input', async () => {
    const { DEFAULT_CONFIG } = await import('../src/health.js');
    let s = emptyPolicy();
    for (const t of [1000, 2000, 3000]) {
      const r = await runHealthCheck(
        { ...DEFAULT_CONFIG, checkTimeoutMs: 2000 },
        { checkPort: async (_h, p) => p !== 8080, checkProcess: async () => true, probeTransport: transportOk },
      );
      assert.equal(deriveState(r), 'HTTP_BRIDGE_DOWN');
      s = nextPolicy(s, 'infra-down', t, CFG, down()).state;
    }
    assert.equal(s.verdict, 'PROXY_DOWN');
  });
});

describe('Test 10 — recovery notification only for outages that matter', () => {
  it('20s confirmed outage -> notify once', () => {
    const { notify, downForMs } = shouldNotifyRecovery(1_000_000, 1_020_000, 20);
    assert.equal(notify, true);
    assert.equal(downForMs, 20_000);
  });

  it('5s blip -> silent (no false "down for Xs")', () => {
    assert.equal(shouldNotifyRecovery(1_000_000, 1_005_000, 20).notify, false);
  });

  it('never confirmed -> silent', () => {
    assert.equal(shouldNotifyRecovery(null, 1_005_000, 20).notify, false);
  });
});

describe('Test 11 — repeated transients: no notification storm', () => {
  it('ten alternating blips produce zero notify events', () => {
    let s = emptyPolicy();
    let notifies = 0;
    let t = 1000;
    for (let i = 0; i < 10; i++) {
      const o1 = nextPolicy(s, 'infra-down', t, CFG, down());
      notifies += o1.events.length;
      s = nextPolicy(o1.state, 'ok', t + 500, CFG, down()).state;
      t += 1000;
    }
    assert.equal(notifies, 0);
    assert.equal(s.verdict, 'READY');
  });

  it('two-strike episodes back-to-back produce zero notifies', () => {
    let s = emptyPolicy();
    let notifies = 0;
    for (let ep = 0; ep < 5; ep++) {
      for (let i = 0; i < 2; i++) {
        const o = nextPolicy(s, 'infra-down', ep * 10000 + i * 1000, CFG, down());
        notifies += o.events.length;
        s = o.state;
      }
      s = nextPolicy(s, 'ok', ep * 10000 + 3000, CFG, down()).state;
    }
    assert.equal(notifies, 0);
  });
});

describe('hasRecentTrafficOk — strongest-signal rule', () => {
  it('recent success with no newer failure vetoes', () => {
    assert.equal(hasRecentTrafficOk({ lastSuccessAtMs: 900, lastFailureAtMs: null }, 1000, 120_000), true);
  });

  it('stale success does not veto', () => {
    assert.equal(hasRecentTrafficOk({ lastSuccessAtMs: 1000, lastFailureAtMs: null }, 1_000_000, 120_000), false);
  });

  it('newer failure beats older success', () => {
    assert.equal(hasRecentTrafficOk({ lastSuccessAtMs: 1000, lastFailureAtMs: 1500 }, 2000, 120_000), false);
  });

  it('custom threshold from config, not hardcoded', () => {
    assert.equal(DEFAULT_POLICY_CONFIG.failureThreshold, 3);
  });
});
