import { strict as assert } from 'assert';
import { describe, it } from 'node:test';
import {
  buildSshArgs,
  spawnSsh,
  spawnHpts,
  isLegacyProxySshCmdline,
  dedupOurSsh,
  DEFAULT_PROC_CONFIG,
  type ProxyProcConfig,
} from '../src/procOwn';

interface Captured {
  exe: string;
  args: string[];
}

describe('proc stability', () => {
  const cfg: ProxyProcConfig = {
    ...DEFAULT_PROC_CONFIG,
    sshExe: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
    hptsCmd: 'C:\\Users\\Proxy User\\npm-global\\hpts.cmd',
    ec2Host: '16.192.228.28',
    socksPort: 1080,
    httpPort: 8080,
  };

  it('ssh args include keepalive + connect timeout + batch mode', () => {
    const args = buildSshArgs(cfg);
    expectFlagValue(args, '-o', 'ServerAliveInterval=30');
    expectFlagValue(args, '-o', 'ServerAliveCountMax=3');
    expectFlagValue(args, '-o', 'ConnectTimeout=8');
    expectFlagValue(args, '-o', 'BatchMode=yes');
    expectFlagValue(args, '-o', 'ExitOnForwardFailure=yes');
  });

  it('ssh spawn receives the resolved ssh.exe directly (no cmd.exe wrapper)', () => {
    const captured: Captured[] = [];
    const r = spawnSsh(cfg, (exe, args) => {
      captured.push({ exe, args });
      return { pid: 4242 };
    });
    assert.equal(r.ok, true);
    assert.equal(captured.length, 1);
    const call = captured[0];
    assert.match(call.exe.toLowerCase(), /ssh\.exe$/);
    assert.ok(!call.exe.toLowerCase().includes('cmd.exe'));
    assert.ok(call.args.includes(`${cfg.sshUser}@${cfg.ec2Host}`));
  });

  it('hpts .cmd shim is wrapped via cmd.exe /d /s /c (Node >=18 EINVAL fix)', () => {
    const captured: Captured[] = [];
    const r = spawnHpts(cfg, (exe, args) => {
      captured.push({ exe, args });
      return { pid: 4243 };
    });
    assert.equal(r.ok, true);
    assert.equal(captured.length, 1);
    const call = captured[0];
    assert.equal(call.exe.toLowerCase(), 'cmd.exe');
    assert.deepEqual(call.args.slice(0, 3), ['/d', '/s', '/c']);
    assert.match(call.args[3], /^"".*hpts\.cmd" "-p" "8080" "-s" "127\.0\.0\.1:1080""$/i);
  });

  it('non-batch hpts command is spawned directly without wrapper', () => {
    const captured: Captured[] = [];
    const r = spawnHpts({ ...cfg, hptsCmd: 'C:\\tools\\hpts.exe' }, (exe, args) => {
      captured.push({ exe, args });
      return { pid: 4244 };
    });
    assert.equal(r.ok, true);
    assert.equal(captured.length, 1);
    const call = captured[0];
    assert.match(call.exe.toLowerCase(), /hpts\.exe$/);
    assert.ok(!call.exe.toLowerCase().includes('cmd.exe'));
  });
});

describe('legacy zombie tunnel migration (old-build ssh on 13.48.149.186)', () => {
  const legacyCmdline = 'ssh.exe -i C:\\Users\\hp\\.ssh\\opencode-proxy-key.pem -D 127.0.0.1:1080 -N ubuntu@13.48.149.186';

  it('legacy-host tunnel matches the migration matcher', () => {
    assert.equal(isLegacyProxySshCmdline(legacyCmdline, DEFAULT_PROC_CONFIG), true);
  });
  it('migration matcher still rejects unrelated ssh', () => {
    assert.equal(isLegacyProxySshCmdline('ssh git@github.com', DEFAULT_PROC_CONFIG), false);
    assert.equal(isLegacyProxySshCmdline('ssh.exe -D 127.0.0.1:2222 -N ubuntu@13.48.149.186', DEFAULT_PROC_CONFIG), false);
    assert.equal(isLegacyProxySshCmdline('ssh.exe -D 127.0.0.1:1080 ubuntu@13.48.149.186', DEFAULT_PROC_CONFIG), false);
  });
  it('dedup treats the legacy zombie as OURS (killable, keepable)', async () => {
    const exec = async (file: string) => {
      if (file === 'powershell.exe') {
        return JSON.stringify([{ ProcessId: 33, Name: 'ssh.exe', CommandLine: legacyCmdline }]);
      }
      throw new Error('unexpected ' + file);
    };
    const r = await dedupOurSsh(exec, DEFAULT_PROC_CONFIG, 33);
    assert.equal(r.kept, 33);
    assert.deepEqual(r.killed, []);
    assert.match(r.detail, /pid 33/);
  });
  it('dedup replaces the legacy zombie with a modern one (kills legacy, keeps current host)', async () => {
    const modern = 'ssh.exe -i KEY -D 127.0.0.1:1080 -N ubuntu@16.192.228.28';
    const exec = async (file: string, args: string[]) => {
      if (file === 'powershell.exe') {
        return JSON.stringify([
          { ProcessId: 33, Name: 'ssh.exe', CommandLine: legacyCmdline },
          { ProcessId: 44, Name: 'ssh.exe', CommandLine: modern },
        ]);
      }
      if (file === 'taskkill') {
        return 'SUCCESS';
      }
      void args;
      throw new Error('unexpected ' + file);
    };
    const r = await dedupOurSsh(exec, DEFAULT_PROC_CONFIG, 44);
    assert.equal(r.kept, 44);
    assert.deepEqual(r.killed, [33]);
  });
});

function expectFlagValue(args: string[], flag: string, value: string): void {
  const pairs: Array<[string, string | undefined]> = args.map((a, i) => [a, args[i + 1]]);
  const found = pairs.some(([f, v]) => f === flag && v === value);
  assert.ok(
    found,
    `expected a "${flag} ${value}" pair in ${JSON.stringify(args)}`,
  );
}
