/**
 * Tests for src/procOwn.ts — single-owner process matching (no live procs).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_PROC_CONFIG,
  buildHptsArgs,
  buildSshArgs,
  dedupOurHpts,
  dedupOurSsh,
  expandEnv,
  isOurHptsCmdline,
  isOurSshCmdline,
  spawnHpts,
  spawnSsh,
} from '../src/procOwn';

describe('expandEnv', () => {
  it('expands %VAR% segments', () => {
    assert.equal(expandEnv('%FOO%\\bar', { FOO: 'C:\\x' } as NodeJS.ProcessEnv), 'C:\\x\\bar');
  });
});

describe('buildSshArgs / buildHptsArgs', () => {
  it('ssh args pin -D host:port, -N, keepalive, ExitOnForwardFailure, user@host', () => {
    const args = buildSshArgs(DEFAULT_PROC_CONFIG);
    assert.ok(args.includes('-N'));
    assert.ok(args.includes('ubuntu@16.192.228.28'));
    const di = args.indexOf('-D');
    assert.equal(args[di + 1], '127.0.0.1:1080');
    assert.ok(args.includes('ExitOnForwardFailure=yes'));
  });
  it('hpts args pin -p and -s', () => {
    assert.deepEqual(buildHptsArgs(DEFAULT_PROC_CONFIG), ['-p', '8080', '-s', '127.0.0.1:1080']);
  });
});

describe('isOurSshCmdline', () => {
  it('matches the exact owned tunnel', () => {
    assert.equal(
      isOurSshCmdline(
        '"C:\\Windows\\System32\\OpenSSH\\ssh.exe" -i "C:\\k\\a.pem" -D 127.0.0.1:1080 -N -o ServerAliveInterval=30 ubuntu@16.192.228.28',
        DEFAULT_PROC_CONFIG,
      ),
      true,
    );
  });
  it('a random ssh.exe never matches', () => {
    assert.equal(isOurSshCmdline('ssh.exe', DEFAULT_PROC_CONFIG), false);
    assert.equal(isOurSshCmdline('ssh git@github.com', DEFAULT_PROC_CONFIG), false);
    assert.equal(isOurSshCmdline('ssh.exe -D 9999 -N ubuntu@16.192.228.28', DEFAULT_PROC_CONFIG), false);
    assert.equal(isOurSshCmdline('ssh.exe -D 127.0.0.1:1080 -N other@1.2.3.4', DEFAULT_PROC_CONFIG), false);
  });
});

describe('isOurHptsCmdline', () => {
  it('matches owned bridge, rejects strangers', () => {
    assert.equal(
      isOurHptsCmdline('node http-proxy-to-socks -p 8080 -s 127.0.0.1:1080', DEFAULT_PROC_CONFIG),
      true,
    );
    assert.equal(isOurHptsCmdline('node server.js', DEFAULT_PROC_CONFIG), false);
    assert.equal(isOurHptsCmdline('node http-proxy-to-socks -p 9999 -s 127.0.0.1:1080', DEFAULT_PROC_CONFIG), false);
  });
});

describe('dedupOurSsh (mocked CIM + taskkill)', () => {
  const CIM = (rows: unknown) => async (file: string) => {
    if (file === 'powershell.exe') {
      return JSON.stringify(rows);
    }
    if (file === 'taskkill') {
      return 'SUCCESS';
    }
    throw new Error(`unexpected ${file}`);
  };
  it('no owned ssh + foreign listener -> never kills', async () => {
    const r = await dedupOurSsh(CIM([]), DEFAULT_PROC_CONFIG, 9999);
    assert.equal(r.kept, null);
    assert.deepEqual(r.killed, []);
    assert.match(r.detail, /foreign pid/);
  });
  it('single owned ssh -> left alone', async () => {
    const r = await dedupOurSsh(
      CIM([{ ProcessId: 11, Name: 'ssh.exe', CommandLine: 'ssh.exe -D 127.0.0.1:1080 -N ubuntu@16.192.228.28' }]),
      DEFAULT_PROC_CONFIG,
      11,
    );
    assert.equal(r.kept, 11);
    assert.deepEqual(r.killed, []);
  });
  it('multiple owned -> keep port owner, kill rest', async () => {
    const killed: number[] = [];
    const exec = async (file: string, args: string[]) => {
      if (file === 'powershell.exe') {
        return JSON.stringify([
          { ProcessId: 11, Name: 'ssh.exe', CommandLine: 'ssh.exe -D 127.0.0.1:1080 -N ubuntu@16.192.228.28' },
          { ProcessId: 22, Name: 'ssh.exe', CommandLine: 'ssh.exe -D 127.0.0.1:1080 -N ubuntu@16.192.228.28' },
        ]);
      }
      if (file === 'taskkill') {
        killed.push(parseInt(args[args.indexOf('/PID') + 1], 10));
        return 'SUCCESS';
      }
      throw new Error('x');
    };
    const r = await dedupOurSsh(exec, DEFAULT_PROC_CONFIG, 22);
    assert.equal(r.kept, 22);
    assert.deepEqual(r.killed, [11]);
  });
  it('random ssh.exe is invisible to dedup (never killed)', async () => {
    const r = await dedupOurSsh(
      CIM([{ ProcessId: 77, Name: 'ssh.exe', CommandLine: 'ssh git@github.com' }]),
      DEFAULT_PROC_CONFIG,
      77,
    );
    assert.equal(r.kept, null);
    assert.deepEqual(r.killed, []);
  });
});

describe('dedupOurHpts', () => {
  it('foreign listener on :8080 is reported, not killed', async () => {
    const r = await dedupOurHpts(async () => '[]', DEFAULT_PROC_CONFIG, 555);
    assert.equal(r.kept, null);
    assert.match(r.detail, /foreign pid/);
  });
});

describe('spawnSsh / spawnHpts (mocked spawn)', () => {
  it('returns pid on success, never logs key material', () => {
    const r = spawnSsh(DEFAULT_PROC_CONFIG, () => ({ pid: 1234 }));
    assert.equal(r.ok, true);
    assert.ok(!r.detail.includes('.pem'));
    const h = spawnHpts({ ...DEFAULT_PROC_CONFIG, hptsCmd: 'C:\\tools\\hpts.cmd' }, () => ({ pid: 5678 }));
    assert.equal(h.ok, true);
  });
  it('no pid -> failure', () => {
    assert.equal(spawnSsh(DEFAULT_PROC_CONFIG, () => ({ pid: null, error: 'ENOENT' })).ok, false);
  });
});
