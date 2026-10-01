import { it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launchResolved } from '../src/procOwn';

it('Windows batch launch preserves paths containing spaces and argument values', { skip: process.platform !== 'win32' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'proxy spawn test '));
  const script = join(dir, 'fake bridge.cmd');
  writeFileSync(script, '@echo off\r\necho %~1 %~2 %~3 %~4\r\n');
  try {
    const finished = new Promise<void>((resolve, reject) => {
      const result = launchResolved(script, ['-p', '8080', '-s', '127.0.0.1:1080'], (exe, args, opts) => {
        const child = spawn(exe, args, { ...opts, stdio: ['ignore', 'pipe', 'pipe'] });
        let output = '';
        child.stdout.on('data', (data) => output += data);
        child.once('error', reject);
        child.once('close', (code) => {
          try { assert.equal(code, 0); assert.equal(output.trim(), '-p 8080 -s 127.0.0.1:1080'); resolve(); }
          catch (e) { reject(e); }
        });
        return { pid: child.pid ?? null };
      });
      assert.ok(result.pid);
    });
    await finished;
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('missing executable reports failure without an unhandled child error', () => {
  const code = `const {spawnSsh, DEFAULT_PROC_CONFIG} = require('./out/src/procOwn');
    const r = spawnSsh({...DEFAULT_PROC_CONFIG, sshExe: 'missing-proxy-ssh-executable-9f734'});
    if (r.ok) process.exitCode=1;`;
  assert.doesNotThrow(() => execFileSync(process.execPath, ['-e', code], { cwd: process.cwd(), timeout: 5000 }));
});
