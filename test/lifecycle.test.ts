import { it } from 'node:test';
import assert from 'node:assert/strict';
import { ProxyLifecycle } from '../src/lifecycle';
import { shutdownProxy } from '../src/shutdown';
import { DEFAULT_PROC_CONFIG } from '../src/procOwn';

it('off immediately rejects new work and waits for in-flight work', async () => {
  const gate = new ProxyLifecycle();
  let release!: () => void;
  let entered!: () => void;
  const started = new Promise<void>((r) => entered = r);
  const job = gate.run(async () => { entered(); await new Promise<void>((r) => release = r); });
  await started;
  let drained = false;
  const stop = gate.drain().then(() => drained = true);
  await gate.run(async () => assert.fail('must not start after off'));
  assert.equal(drained, false);
  release();
  await Promise.all([job, stop]);
  assert.equal(drained, true);
});

it('shutdown persists task restoration, disables retry tasks, kills bridge before ssh, and leaves foreigners', async () => {
  const calls: string[] = [];
  let processes = [
    { ProcessId: 1, Name: 'ssh.exe', CommandLine: 'ssh.exe -D 127.0.0.1:1080 -N ubuntu@16.192.228.28' },
    { ProcessId: 2, Name: 'node.exe', CommandLine: 'node.exe C:\\npm\\node_modules\\http-proxy-to-socks\\bin\\hpts.js -p 8080 -s 127.0.0.1:1080' },
    { ProcessId: 3, Name: 'ssh.exe', CommandLine: 'ssh.exe -D 127.0.0.1:10800 -N ubuntu@16.192.228.28' },
  ];
  const exec = async (file: string, args: string[]) => {
    if (file === 'powershell.exe') {
      if (args.at(-1)?.includes('Get-ScheduledTask')) {
        const name = args.at(-1)?.includes("$n='bridge'") ? 'bridge' : 'ssh';
        return JSON.stringify({
          TaskName: name, TaskPath: '\\',
          State: calls.includes(`schtasks /end /TN ${name}`) ? 'Disabled' : 'Running',
          Enabled: !calls.includes(`schtasks /change /TN ${name} /DISABLE`),
        });
      }
      return JSON.stringify(processes);
    }
    if (file === 'netstat') return '';
    calls.push([file, ...args].join(' '));
    if (file === 'taskkill') processes = processes.filter((p) => p.ProcessId !== Number(args[1]));
    return 'SUCCESS';
  };
  const result = await shutdownProxy(exec, { ...DEFAULT_PROC_CONFIG, sshTaskName: 'ssh', bridgeTaskName: 'bridge' }, async (n) => { calls.push(`remember ${n}`); });
  assert.equal(result.ok, true, result.details.join('\n'));
  assert.deepEqual(calls, [
    'remember bridge', 'schtasks /change /TN bridge /DISABLE', 'schtasks /end /TN bridge',
    'remember ssh', 'schtasks /change /TN ssh /DISABLE', 'schtasks /end /TN ssh',
    'taskkill /PID 2 /F /T', 'taskkill /PID 1 /F /T',
  ]);
  assert.deepEqual(processes.map((p) => p.ProcessId), [3]);
});

it('shutdown cannot claim success when discovery or termination fails', async () => {
  const result = await shutdownProxy(async () => { throw new Error('access denied'); },
    { ...DEFAULT_PROC_CONFIG, sshTaskName: 'ssh', bridgeTaskName: 'bridge' }, async () => {});
  assert.equal(result.ok, false);
  assert.ok(result.details.some((d) => d.includes('Cannot verify')));
});

it('a failed persistence step does not disable that task', async () => {
  const result = await shutdownProxy(async (file, args) => {
    assert.notEqual(file, 'schtasks');
    return args.at(-1)?.includes('Get-ScheduledTask') ? JSON.stringify({ TaskName: 'proxy', State: 'Ready', Enabled: true }) : '[]';
  }, { ...DEFAULT_PROC_CONFIG, sshTaskName: 'ssh', bridgeTaskName: 'bridge' }, async () => { throw new Error('storage failed'); });
  assert.equal(result.ok, false);
});

it('off releases a pending launch prompt so shutdown can finish', async () => {
  const gate = new ProxyLifecycle();
  const result = gate.waitWhileEnabled(new Promise<string>(() => {}));
  gate.enabled = false;
  assert.equal(await result, undefined);
});

it('foreign listeners prevent a false shutdown success and are never killed', async () => {
  const result = await shutdownProxy(async (file) => {
    assert.notEqual(file, 'taskkill');
    return file === 'netstat' ? '  TCP    127.0.0.1:8080    0.0.0.0:0    LISTENING    99\r\n' : '';
  }, { ...DEFAULT_PROC_CONFIG, sshTaskName: 'ssh', bridgeTaskName: 'bridge' }, async () => {});
  assert.equal(result.ok, false);
  assert.ok(result.details.some((d) => d.includes('pid 99')));
});

it('off interrupts a recovery backoff rather than waiting for its whole delay', async () => {
  const gate = new ProxyLifecycle();
  const sleep = gate.sleep(60_000);
  gate.enabled = false;
  await assert.rejects(sleep, /turned off/);
});
