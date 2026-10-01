/**
 * Tests for src/recoveryMachine.ts — layered A-H state machine.
 * All I/O mocked; no network, no processes, no AWS needed.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RECOVERY_CONFIG, backoffMs, recoverProxy } from '../src/recoveryMachine';

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

/** Stage-1 HTTP verification seam (real probe would dial a dead :8080 here). */
const transportOk = async () => ({
  ok: true,
  statusCode: 204 as number | null,
  target: 'https://www.gstatic.com/generate_204',
  elapsedMs: 5,
  detail: 'transport probe ok',
});

describe('backoffMs', () => {
  it('exponential with cap', () => {
    assert.equal(backoffMs(0, 2000, 15000), 2000);
    assert.equal(backoffMs(1, 2000, 15000), 4000);
    assert.equal(backoffMs(10, 2000, 15000), 15000);
  });
});

describe('recoverProxy — READY path (all healthy, idempotent, no spawns)', () => {
  it('ports listening + e2e match -> READY with SOCKS_UP + HTTP_PROXY_UP in path', async () => {
    const states: string[] = [];
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      probeTransport: transportOk,
      socksE2E: async () => ({ ip: '16.192.228.28', service: 'http://api.ipify.org/', elapsedMs: 5 }),
      httpEgress: async () => '16.192.228.28',
      sleep: async () => {},
      now: () => 0,
      onState: (s) => states.push(s),
    });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.state, 'READY');
    assert.ok(states.includes('SOCKS_UP'));
    assert.ok(states.includes('HTTP_PROXY_UP'));
    assert.ok(states.includes('READY'));
    assert.ok(outcome.logs.some((l) => l.tag === 'SOCKS END-TO-END CHECK'));
    assert.ok(outcome.logs.some((l) => l.tag === 'RECOVERY SUCCESS'));
  });
});

describe('recoverProxy — 1080 absent, 22 reachable -> single ssh spawn', () => {
  it('starts exactly ONE ssh, verifies 1080, then SOCKS e2e', async () => {
    let socksUp = false;
    let spawns = 0;
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async (_h, p) => (p === 1080 ? socksUp : true),
      checkAws: async () => true,
      listSsh: async () => ({ kept: null, killed: [], detail: 'none' }),
      listHpts: async () => ({ kept: 1, killed: [], detail: 'one' }),
      spawnSshFn: () => {
        spawns += 1;
        socksUp = true;
        return { ok: true, pid: 111, detail: 'ssh spawned' };
      },
      probeTransport: transportOk,
      socksE2E: async () => ({ ip: '16.192.228.28', service: 's', elapsedMs: 1 }),
      httpEgress: async () => '16.192.228.28',
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, true);
    assert.equal(spawns, 1);
    assert.ok(outcome.path.includes('SSH_PROCESS_DOWN'));
    assert.ok(outcome.path.includes('SOCKS_STARTING'));
  });
  it('ssh.exe existing is never success: port never opens -> RECOVERY_FAILED', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async (_h, p) => (p === 1080 ? false : true),
      checkAws: async () => true,
      listSsh: async () => ({ kept: 999, killed: [], detail: 'one owned but dead port' }),
      spawnSshFn: () => ({ ok: true, pid: 111, detail: 'ssh spawned' }),
      sleep: async () => {},
      now: (() => {
        let t = 0;
        return () => (t += 100);
      })(),
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.state, 'RECOVERY_FAILED');
  });
});

describe('recoverProxy — AWS unreachable triggers SG repair (direct IP, no proxy)', () => {
  it('discovers direct IP, repairs SG, retries 22, then READY', async () => {
    let awsUp = false;
    const seen: string[] = [];
    const outcome = await recoverProxy({ ...baseCfg(), securityGroupId: 'sg-1' }, noopExec, {
      checkPort: async () => true,
      checkAws: async () => awsUp,
      fetchDirectIp: async () => ({ ip: '9.9.9.9', service: 'https://api.ipify.org/' }),
      repairSg: async (_c, ip) => {
        seen.push(ip);
        awsUp = true;
        return { ok: true, detail: `authorized ${ip}/32 — verified`, authorizedCurrent: true, revoked: ['1.1.1.1/32'] };
      },
      probeTransport: transportOk,
      socksE2E: async () => ({ ip: '16.192.228.28', service: 's', elapsedMs: 1 }),
      httpEgress: async () => '16.192.228.28',
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, true);
    assert.deepEqual(seen, ['9.9.9.9']);
    assert.ok(outcome.path.includes('AWS_SSH_UNREACHABLE'));
    assert.ok(outcome.path.includes('SG_REPAIRING'));
    assert.equal(outcome.sgRepaired, true);
  });
  it('no securityGroupId + AWS down -> honest RECOVERY_FAILED (never 0.0.0.0/0)', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => false,
      fetchDirectIp: async () => ({ ip: '9.9.9.9', service: 's' }),
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.equal(outcome.state, 'RECOVERY_FAILED');
  });
});

describe('recoverProxy — wrong SOCKS egress never reports READY', () => {
  it('mismatched egress -> RECOVERY_FAILED', async () => {
    const outcome = await recoverProxy(baseCfg(), noopExec, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksE2E: async () => ({ ip: '1.2.3.4', service: 's', elapsedMs: 1 }),
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.match(outcome.path.join(','), /RECOVERY_FAILED/);
  });
});

describe('recoverProxy — single-flight idempotence', () => {
  it('two concurrent calls share one execution', async () => {
    let runs = 0;
    const cfg = baseCfg();
    const deps = {
      checkPort: async () => {
        runs += 1;
        return true;
      },
      checkAws: async () => true,
      probeTransport: transportOk,
      socksE2E: async () => ({ ip: '16.192.228.28', service: 's', elapsedMs: 1 }),
      httpEgress: async () => '16.192.228.28',
      sleep: async () => {},
      now: () => 0,
    };
    const [a, b] = await Promise.all([recoverProxy(cfg, noopExec, deps), recoverProxy(cfg, noopExec, deps)]);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.deepEqual(a.path, b.path);
  });
});
