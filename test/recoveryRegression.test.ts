import { it } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_RECOVERY_CONFIG, recoverProxy } from '../src/recoveryMachine';
import { spawnSsh, isOurSshCmdline, isOurHptsCmdline, DEFAULT_PROC_CONFIG } from '../src/procOwn';

const cfg = { ...DEFAULT_RECOVERY_CONFIG, maxAttempts: 1, checkTimeoutMs: 50 };
const okTransport = { ok: true, statusCode: 204, target: 'https://example.test', elapsedMs: 1, detail: 'ok' };
const goodDeps = {
  checkPort: async () => true, checkAws: async () => true,
  socksE2E: async () => ({ ip: cfg.expectedExternalIp, service: 's', elapsedMs: 1 }),
  httpEgress: async () => cfg.expectedExternalIp,
  probeTransport: async () => okTransport,
};

it('off during AWS probe prevents subsequent process creation', async () => {
  let enabled = true;
  const result = await recoverProxy(cfg, async () => '', {
    ...goodDeps, canContinue: () => enabled, checkPort: async () => false,
    checkAws: async () => { enabled = false; return true; },
    listSsh: async () => ({ kept: null, killed: [], detail: 'none' }),
    spawnSshFn: () => { assert.fail('spawn after off'); },
  });
  assert.equal(result.ok, false);
  assert.ok(result.logs.some((l) => l.message.includes('turned off')));
});

it('an echo outage does not kill a live owned tunnel', async () => {
  const result = await recoverProxy(cfg, async (file) => { assert.fail(`unexpected process action ${file}`); }, {
    ...goodDeps, socksE2E: async () => { throw new Error('echo down'); },
    socksProbe: async () => ({ connected: true, ip: null, service: 's', detail: 'echo down, CONNECT ok' }),
  });
  assert.equal(result.ok, true);
});

it('wrong SOCKS IP cannot be overridden by connectivity-only evidence', async () => {
  const result = await recoverProxy(cfg, async () => '', {
    ...goodDeps, socksE2E: async () => ({ ip: '1.2.3.4', service: 's', elapsedMs: 1 }),
    socksProbe: async () => ({ connected: true, ip: null, service: 's', detail: 'CONNECT ok' }),
  });
  assert.equal(result.ok, false);
});

it('a broken owned HTTP listener is refreshed once and transport rechecked', async () => {
  let killed = false;
  let spawned = 0;
  let probes = 0;
  const result = await recoverProxy(cfg, async (file) => {
    if (file === 'powershell.exe') return JSON.stringify([{ Name: 'node.exe', ProcessId: 9, CommandLine: 'node.exe http-proxy-to-socks -p 8080 -s 127.0.0.1:1080' }]);
    if (file === 'taskkill') { killed = true; return 'SUCCESS'; }
    throw new Error(file);
  }, { ...goodDeps, portOwner: async () => 9,
    probeTransport: async () => { probes++; return { ...okTransport, ok: spawned > 0 }; },
    spawnHptsFn: () => { assert.equal(killed, true); spawned++; return { ok: true, pid: 10, detail: 'spawned' }; },
  });
  assert.equal(result.ok, true);
  assert.equal(spawned, 1);
  assert.equal(probes, 2);
});

it('custom SSH port reaches the actual tunnel argv', () => {
  spawnSsh({ ...DEFAULT_PROC_CONFIG, sshPort: 2222 }, (_file, args) => {
    assert.equal(args[args.indexOf('-p') + 1], '2222');
    return { pid: 1 };
  });
});

it('ownership requires exact arguments, not prefixes or incidental command text', () => {
  assert.equal(isOurSshCmdline('ssh.exe -D 10800 -N ubuntu@16.192.228.28', cfg), false);
  assert.equal(isOurSshCmdline('ssh.exe -D 1080 -N ubuntu@16.192.228.28.evil', cfg), false);
  assert.equal(isOurSshCmdline('ssh.exe -d 1080 -n ubuntu@16.192.228.28', cfg), false);
  assert.equal(isOurHptsCmdline('node http-proxy-to-socks -p 80800 -s 127.0.0.1:1080', cfg), false);
  assert.equal(isOurHptsCmdline('node http-proxy-to-socks -p 8080 -s 10.0.0.1:1080', cfg), false);
});
