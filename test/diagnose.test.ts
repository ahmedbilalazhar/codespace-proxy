/**
 * Tests for src/diagnose.ts — parsers, redaction, and the orchestrated probe.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deepDiagnose,
  formatDeep,
  parseNetstatListeners,
  parseSchtasksRow,
  parseTasklistPids,
  redactCommandLine,
} from '../src/diagnose';

describe('redactCommandLine', () => {
  it('redacts the ssh -i key path but keeps flags/ports', () => {
    const out = redactCommandLine(
      '"C:\\Windows\\System32\\OpenSSH\\ssh.exe" -i "C:\\Users\\hp\\.ssh\\opencode-proxy-key.pem" -D 1080 -N ubuntu@16.192.228.28',
    );
    assert.ok(!out.includes('.pem'), out);
    assert.ok(!out.includes('opencode-proxy-key'), out);
    assert.ok(out.includes('-D 1080'), out);
    assert.ok(out.includes('-i <redacted>'), out);
  });

  it('redacts bare -i value and stray .pem tokens', () => {
    assert.ok(redactCommandLine('ssh -i C:\\k\\a.pem -N').includes('-i <redacted>'));
    assert.ok(redactCommandLine('tool C:\\x\\b.pem run').includes('<redacted-key-path>'));
  });

  it('leaves innocent lines alone and truncates huge ones', () => {
    assert.equal(redactCommandLine('node proxy.js -p 8080'), 'node proxy.js -p 8080');
    assert.ok(redactCommandLine('x'.repeat(500)).endsWith('…'));
  });
});

describe('parsers', () => {
  it('parseTasklistPids extracts pid column only', () => {
    const out = parseTasklistPids(
      '"opencode.exe","18936","Console","1","10,000 K"\r\n"ssh.exe","28184","Console","1","18,212 K"\r\nINFO: No tasks\r\n',
    );
    assert.deepEqual(out, [18936, 28184]);
  });

  it('parseSchtasksRow parses name + status', () => {
    const row = parseSchtasksRow('"\\OpenCode SSH SOCKS5","N/A","Running"\r\n');
    assert.deepEqual(row, { name: 'OpenCode SSH SOCKS5', status: 'Running' });
    assert.equal(parseSchtasksRow('ERROR: The system cannot find the file specified.\r\n'), null);
  });

  it('parseNetstatListeners finds listeners incl. IPv6 form', () => {
    const out = parseNetstatListeners(
      '  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING       28184\r\n' +
        '  TCP    [::]:8080               [::]:0                 LISTENING       1234\r\n' +
        '  TCP    127.0.0.1:3457         0.0.0.0:0              LISTENING       9999\r\n' +
        '  TCP    127.0.0.1:1080         1.2.3.4:443            ESTABLISHED     555\r\n',
      [1080, 8080],
    );
    assert.deepEqual(out, [
      { port: 1080, pid: 28184 },
      { port: 8080, pid: 1234 },
    ]);
  });
});

describe('deepDiagnose (mocked exec)', () => {
  const exec = async (file: string, args: string[]): Promise<string> => {
    if (file === 'powershell.exe') {
      return JSON.stringify([
        { ProcessId: 28184, Name: 'ssh.exe', CommandLine: 'ssh.exe -i C:\\k\\a.pem -D 1080 -N ubuntu@16.192.228.28' },
        { ProcessId: 1234, Name: 'node.exe', CommandLine: 'node http-proxy-to-socks -p 8080 -s 127.0.0.1:1080' },
      ]);
    }
    if (file === 'schtasks') {
      const tn = args[args.indexOf('/TN') + 1];
      return `"\\${tn}","N/A","Running"\r\n`;
    }
    if (file === 'netstat') {
      return '  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING       28184\r\n';
    }
    throw new Error(`unexpected: ${file}`);
  };

  it('assembles redacted info from all probes', async () => {
    const info = await deepDiagnose({ socksPort: 1080, httpPort: 8080 }, exec);
    assert.equal(info.sshCmdlines.length, 1);
    assert.ok(!info.sshCmdlines[0].includes('.pem'));
    assert.ok(info.sshCmdlines[0].includes('-D 1080'));
    assert.equal(info.bridgeCmdlines.length, 1);
    assert.deepEqual(info.tasks.map((t) => t.status), ['Running', 'Running']);
    assert.deepEqual(info.listeners, [{ port: 1080, pid: 28184 }]);
    assert.ok(info.notes.some((n) => n.includes(':8080')));
  });

  it('never throws; failures become notes', async () => {
    const failing = async () => {
      throw new Error('nope');
    };
    const info = await deepDiagnose({ socksPort: 1080, httpPort: 8080 }, failing);
    // powershell + netstat failures -> notes; schtasks failures -> task statuses.
    assert.ok(info.notes.length >= 2);
    assert.deepEqual(info.sshCmdlines, []);
    assert.ok(info.tasks.every((t) => t.status.includes('query failed')));
  });

  it('formatDeep renders every section', () => {
    const lines = formatDeep({
      sshCmdlines: ['ssh.exe -D 1080'],
      bridgeCmdlines: [],
      tasks: [{ name: 'T', status: 'Ready' }],
      listeners: [{ port: 1080, pid: 1 }],
      notes: ['n'],
    });
    assert.ok(lines.some((l) => l.includes('ssh.exe -D 1080')));
    assert.ok(lines.some((l) => l.includes('"T": Ready')));
  });
});
