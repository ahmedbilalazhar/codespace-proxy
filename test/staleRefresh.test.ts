/**
 * Tests for the stale-listener refresh in src/recoveryMachine.ts step D:
 * :1080 answers TCP but speaks no SOCKS (dead tunnel squatting the port).
 * Bounded to one refresh of OWNED ssh; foreign listeners are never killed.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RECOVERY_CONFIG, recoverProxy } from '../src/recoveryMachine';

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

const SSH_CMDLINE = 'ssh.exe -D 127.0.0.1:1080 -N ubuntu@16.192.228.28';

function execWithStaleSsh() {
  return async (file: string) => {
    if (file === 'powershell.exe') {
      return JSON.stringify([{ ProcessId: 4000, Name: 'ssh.exe', CommandLine: SSH_CMDLINE }]);
    }
    if (file === 'netstat') {
      return '  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING       4000\r\n';
    }
    if (file === 'taskkill') {
      return 'SUCCESS: The process has been terminated.\r\n';
    }
    throw new Error(`unexpected exec: ${file}`);
  };
}

describe('stale-listener refresh', () => {
  it('kills owned stale ssh once, respawns, re-verifies -> READY', async () => {
    let spawned = 0;
    let e2eCalls = 0;
    const outcome = await recoverProxy(baseCfg(), execWithStaleSsh(), {
      checkPort: async () => true,
      checkAws: async () => true,
      socksProbe: async () => ({ connected: false, ip: null, service: null, detail: 'dead handshake' }),
      spawnSshFn: () => {
        spawned += 1;
        return { ok: true, pid: 4001, detail: 'ssh spawned (pid 4001)' };
      },
      probeTransport: async () => ({
        ok: true,
        statusCode: 204 as number | null,
        target: 'https://www.gstatic.com/generate_204',
        elapsedMs: 5,
        detail: 'transport probe ok',
      }),
      socksE2E: async () => {
        e2eCalls += 1;
        if (spawned === 0) {
          throw new Error('SOCKS5 end-to-end check failed (stale tunnel, no handshake reply)');
        }
        return { ip: '16.192.228.28', service: 's', elapsedMs: 1 };
      },
      httpEgress: async () => '16.192.228.28',
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.state, 'READY');
    assert.equal(spawned, 1, 'exactly one fresh tunnel');
    assert.ok(outcome.path.includes('SOCKS_DOWN'), 'refresh leg recorded');
    assert.ok(e2eCalls > 2, 'e2e retried after refresh');
  });

  it('foreign listener on :1080 is reported, never killed -> RECOVERY_FAILED', async () => {
    const execForeign = async (file: string) => {
      if (file === 'powershell.exe') {
        return '[]';
      }
      if (file === 'netstat') {
        return '  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING       9999\r\n';
      }
      throw new Error(`must not kill foreign pid (saw exec: ${file})`);
    };
    const outcome = await recoverProxy(baseCfg(), execForeign, {
      checkPort: async () => true,
      checkAws: async () => true,
      socksProbe: async () => ({ connected: false, ip: null, service: null, detail: 'dead handshake' }),
      socksE2E: async () => {
        throw new Error('SOCKS5 handshake got no reply');
      },
      sleep: async () => {},
      now: () => 0,
    });
    assert.equal(outcome.ok, false);
    assert.ok(outcome.logs.some((l) => l.tag === 'SSH STOP' && l.message.includes('non-owned pid 9999')));
  });
});
