import { it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { DEFAULT_PROC_CONFIG, observeChild, spawnSsh, spawnHpts, startupFailure, buildSshArgs, ChildStatus } from '../src/procOwn';
import { waitForPort } from '../src/runbook';
import { DEFAULT_RECOVERY_CONFIG, recoverProxy } from '../src/recoveryMachine';

const failed: ChildStatus = { exited: true, exitCode: 255, signal: null, stderr: 'Host key verification failed.\r\n' };

it('captures real child stderr and exit code, then explains host trust failure', async () => {
  const child = spawn(process.execPath, ['-e', 'process.stderr.write("Host key verification failed.\\n"); process.exitCode = 255;'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const status = observeChild(child);
  await new Promise<void>((resolve, reject) => { child.once('close', () => resolve()); child.once('error', reject); });
  assert.equal(status().exitCode, 255);
  assert.equal(status().stderr.trim(), 'Host key verification failed.');
  const detail = startupFailure('SSH', { pid: child.pid ?? null, status });
  assert.match(detail!, /SSH exited with code 255: Host key verification failed/);
  assert.match(detail!, /fingerprint.*AWS.*interactive SSH/);
});

it('stderr storage is bounded for a noisy child', async () => {
  const child = spawn(process.execPath, ['-e', 'process.stderr.write("x".repeat(20000) + "tail");'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const status = observeChild(child);
  await new Promise<void>((resolve, reject) => { child.once('close', () => resolve()); child.once('error', reject); });
  assert.equal(status().stderr.length, 4096);
  assert.ok(status().stderr.endsWith('tail'));
});

it('SSH and bridge diagnostics redact quoted key paths with spaces', () => {
  const key = 'C:\\Users\\Example User\\.ssh\\private-key.pem';
  const cfg = { ...DEFAULT_PROC_CONFIG, sshKeyPath: key, hptsCmd: 'C:\\Program Files\\hpts.cmd' };
  for (const start of [spawnSsh, spawnHpts]) {
    const launched = start(cfg, () => ({ pid: 1, status: () => ({ ...failed, stderr: `Load key "${key}": invalid format` }) }));
    const detail = startupFailure('SSH', launched)!;
    assert.ok(!detail.includes(key));
    assert.ok(!detail.includes('Example User'));
    assert.match(detail, /redacted-key-path/);
    assert.match(detail, /valid OpenSSH private key/);
  }
  const launched = spawnSsh(cfg, () => { throw new Error(`cannot open "${key}"`); });
  assert.ok(!launched.detail.includes(key));
});

it('missing private key fails before launching any executable', () => {
  const result = spawnSsh({ ...DEFAULT_PROC_CONFIG, sshKeyPath: join(tmpdir(), 'missing-proxy-key-9f734.pem') });
  assert.equal(result.ok, false);
  assert.equal(result.pid, null);
  assert.match(result.detail, /SSH key is missing or unreadable/);
  assert.ok(!result.detail.includes(tmpdir()));
});

it('port wait stops on known process failure before probing or sleeping', async () => {
  const result = await waitForPort(async () => assert.fail('probe after exit'), '127.0.0.1', 1080, 30000, 750, 5000,
    async () => assert.fail('sleep after exit'), () => 0, () => 'SSH exited with code 255');
  assert.deepEqual(result, { up: false, waitedMs: 0, probes: 0, failure: 'SSH exited with code 255' });
});

it('process exit during a port probe overrides a listening port', async () => {
  let exited = false;
  const result = await waitForPort(async () => { exited = true; return true; }, '127.0.0.1', 1080, 30000, 750, 5000,
    async () => assert.fail('sleep after exit'), () => 0, () => exited ? 'SSH exited' : null);
  assert.equal(result.up, false);
  assert.equal(result.failure, 'SSH exited');
});

it('recovery reports host verification failure without waiting 30s or starting the bridge', async () => {
  const cfg = { ...DEFAULT_RECOVERY_CONFIG, socksWaitMs: 30000 };
  const result = await recoverProxy(cfg, async () => assert.fail('unexpected process action'), {
    checkPort: async () => false, checkAws: async () => true,
    listSsh: async () => ({ kept: null, killed: [], detail: 'none' }),
    spawnSshFn: () => ({ ok: true, pid: 1, detail: 'spawned', status: () => failed }),
    spawnHptsFn: () => assert.fail('bridge started despite SSH failure'),
    sleep: async () => assert.fail('slept despite exited SSH'), now: () => 0,
  });
  assert.equal(result.ok, false);
  assert.equal(result.elapsedMs, 0);
  assert.ok(result.logs.some((l) => l.tag === 'RECOVERY FAILURE' && /Host key verification failed/.test(l.message)));
});

it('background SSH uses the configured identity and keeps host verification enabled', () => {
  const args = buildSshArgs(DEFAULT_PROC_CONFIG);
  assert.ok(args.includes('IdentitiesOnly=yes'));
  assert.ok(args.includes('BatchMode=yes'));
  assert.ok(!args.some((v) => /StrictHostKeyChecking=(no|off)|UserKnownHostsFile=/i.test(v)));
});
