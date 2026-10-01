import { it } from 'node:test';
import assert from 'node:assert/strict';
const Module = require('node:module');

// Exercise the integration logic without opening a VS Code window.
const loader = Module as unknown as { _load: (...args: any[]) => any };
const originalLoad = loader._load;
const settings: Record<string, unknown> = { trackRequests: false, logToFile: false, autoRecover: true, failureThreshold: 2 };
const noop = () => {};
const mockVscode = {
  StatusBarAlignment: { Left: 1 },
  window: {
    createStatusBarItem: () => ({ show: noop, dispose: noop }),
    showWarningMessage: async () => undefined, showErrorMessage: async () => undefined,
    showInformationMessage: async () => undefined,
    onDidChangeWindowState: () => ({ dispose: noop }),
  },
  workspace: { getConfiguration: () => ({ get: (key: string, fallback: unknown) => settings[key] ?? fallback }) },
  MarkdownString: class { appendMarkdown() { return this; } },
};
loader._load = function (name, ...args) { return name === 'vscode' ? mockVscode : originalLoad.call(this, name, ...args); };
const { Monitor } = require('../src/extension');
loader._load = originalLoad;
const health = require('../src/health');
const machine = require('../src/recoveryMachine');
const tasks = require('../src/recover');
const awsNet = require('../src/awsNet');

function createMonitor(saved = new Map<string, unknown>()) {
  const context = {
    extension: { packageJSON: { version: '0.11.1' } },
    subscriptions: [], globalState: {
      get: (key: string, fallback: unknown) => saved.has(key) ? saved.get(key) : fallback,
      update: async (key: string, value: unknown) => { saved.set(key, value); },
    },
  };
  const monitor = new Monitor(context, { appendLine: noop, show: noop });
  monitor.lastZenProbeAt = Date.now();
  monitor.refreshDeep = async () => {};
  monitor.checkSchedulerConflict = async () => {};
  return { monitor, saved };
}
const readyOutcome = { ok: true, state: 'READY', logs: [], elapsedMs: 1, path: ['READY'], publicIpDirect: null };
function healthResult(ok: boolean) {
  return { timedOut: false, result: {
    socksUp: ok, httpUp: ok, proxyTrafficOk: ok, sshRunning: ok, opencodeRunning: false,
    reason: ok ? null : 'ports closed', elapsedMs: 1, socksMs: 1, httpMs: 1, trafficMs: 1,
    zenMs: null, transportStatus: ok ? 204 : null,
  } };
}

it('diagnostics identify the installed version and expand actual task names and ports', () => {
  const { monitor } = createMonitor();
  monitor.cfg.sshTaskName = 'Custom SSH';
  monitor.cfg.bridgeTaskName = 'Custom Bridge';
  monitor.cfg.socksPort = 11080;
  monitor.cfg.httpPort = 18080;
  try {
    const report = monitor.buildFullReport();
    assert.match(report, /Extension version\s+0\.11\.1/);
    assert.match(report, /127\.0\.0\.1:11080/);
    assert.match(report, /hpts -p 18080/);
    assert.match(report, /"Custom SSH" \/ "Custom Bridge"/);
    assert.ok(!report.includes('${cfg.'));
  } finally { monitor.dispose(); }
});

it('manual recovery preserves the actual startup error in diagnostics and its notification', async () => {
  const { monitor } = createMonitor();
  const detail = 'SSH exited with code 255: Host key verification failed.';
  let notification = '';
  monitor.notifyFail = (message: string) => { notification = message; };
  machine.recoverProxy = async () => ({ ...readyOutcome, ok: false, state: 'RECOVERY_FAILED', logs: [{ tag: 'RECOVERY FAILURE', message: detail, at: 'now' }] });
  try {
    await monitor.runDirectRecovery('manual-command');
    assert.match(monitor.buildFullReport(), /Recovery failure\s+SSH exited with code 255: Host key verification failed/);
    assert.ok(notification.includes(detail));
  } finally { monitor.dispose(); }
});

it('an automatic Wi-Fi IP change owns exactly one recovery despite a failed health check', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.lastPublicIp = '1.1.1.1';
  monitor.baseState = 'SSH_DOWN';
  let recoveries = 0;
  awsNet.fetchDirectPublicIp = async () => ({ ip: '9.9.9.9', service: 'test' });
  monitor.runDirectRecovery = async (reason: string) => { assert.equal(reason, 'network-change'); recoveries++; };
  monitor.check = async () => { monitor.display = 'PROXY_DOWN'; await monitor.maybeRecover(); };
  try {
    await monitor.pollPublicIpOnce();
    assert.equal(recoveries, 1);
    assert.equal(monitor.lastPublicIp, '9.9.9.9');
    assert.equal(monitor.publicIpPollRunning, false);
  } finally { monitor.dispose(); }
});

it('the first automatic IP discovery checks and repairs an unhealthy proxy', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.baseState = 'SSH_DOWN';
  let recoveries = 0;
  awsNet.fetchDirectPublicIp = async () => ({ ip: '9.9.9.9', service: 'test' });
  monitor.check = async () => {};
  monitor.runDirectRecovery = async () => { recoveries++; };
  try { await monitor.pollPublicIpOnce(); assert.equal(recoveries, 1); }
  finally { monitor.dispose(); }
});

it('overlapping network polls discover and repair only once', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.baseState = 'SSH_DOWN';
  let release!: () => void;
  let fetched = 0;
  let repaired = 0;
  awsNet.fetchDirectPublicIp = () => { fetched++; return new Promise((r) => { release = () => r({ ip: '9.9.9.9', service: 'test' }); }); };
  monitor.check = async () => {};
  monitor.runDirectRecovery = async () => { repaired++; };
  try {
    const first = monitor.pollPublicIpOnce();
    await new Promise((r) => setImmediate(r));
    await monitor.pollPublicIpOnce();
    release();
    await first;
    assert.equal(fetched, 1);
    assert.equal(repaired, 1);
  } finally { monitor.dispose(); }
});

it('automatic network polling respects autoRecover=false and off during discovery', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.cfg.autoRecover = false;
  awsNet.fetchDirectPublicIp = async () => assert.fail('lookup despite opt-out');
  monitor.runDirectRecovery = async () => assert.fail('repair despite opt-out');
  try {
    await monitor.pollPublicIpOnce();
    monitor.cfg.autoRecover = true;
    awsNet.fetchDirectPublicIp = async () => { monitor.lifecycle.enabled = false; return { ip: '9.9.9.9', service: 'test' }; };
    await monitor.pollPublicIpOnce();
    assert.equal(monitor.lastPublicIp, null);
    assert.equal(monitor.publicIpPollRunning, false);
  } finally { monitor.dispose(); }
});

it('a dry-run network recovery releases RECONNECTING without launching processes', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.cfg.autoRecoverDryRun = true;
  monitor.baseState = 'SSH_DOWN';
  monitor.check = async () => {};
  awsNet.fetchDirectPublicIp = async () => ({ ip: '9.9.9.9', service: 'test' });
  machine.recoverProxy = async () => assert.fail('dry run launched recovery');
  try {
    await monitor.pollPublicIpOnce();
    assert.equal(monitor.reconnecting, false);
    assert.equal(monitor.publicIpPollRunning, false);
    assert.equal(monitor.display, 'DEGRADED');
  } finally { monitor.dispose(); }
});

it('a thrown network health check releases attribution and permits later polling', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.publicIpPollSec = 30;
  monitor.baseState = 'SSH_DOWN';
  let checks = 0;
  monitor.check = async () => { checks++; throw new Error('probe failed'); };
  awsNet.fetchDirectPublicIp = async () => ({ ip: '9.9.9.9', service: 'test' });
  try {
    await monitor.pollPublicIpOnce(true);
    assert.equal(monitor.reconnecting, false);
    assert.equal(monitor.display, 'DEGRADED');
    await monitor.pollPublicIpOnce(true);
    assert.equal(checks, 2);
    assert.equal(monitor.publicIpPollRunning, false);
  } finally { monitor.dispose(); }
});

it('successful auto-recovery completes its parent health check instead of awaiting itself', { timeout: 1500 }, async () => {
  const { monitor } = createMonitor();
  let repaired = false;
  let probes = 0;
  health.runHealthCheckGuarded = async () => { probes++; return healthResult(repaired); };
  machine.recoverProxy = async () => { repaired = true; return readyOutcome; };
  try {
    await monitor.refresh(false); // strike 1
    await monitor.refresh(false); // strike 2 -> recover -> queued fresh check
    await new Promise((r) => setImmediate(r));
    assert.equal(monitor.running, false);
    assert.equal(monitor.baseState, 'HEALTHY');
    assert.ok(probes >= 3);
  } finally { monitor.dispose(); }
});

it('failed recovery records cooldown and does not run again on every poll', async () => {
  const { monitor } = createMonitor();
  let recoveries = 0;
  health.runHealthCheckGuarded = async () => healthResult(false);
  machine.recoverProxy = async () => { recoveries++; return { ...readyOutcome, ok: false, state: 'RECOVERY_FAILED' }; };
  try {
    for (let i = 0; i < 6; i++) await monitor.refresh(false);
    assert.equal(recoveries, 1);
    assert.ok(monitor.cadence.lastAttemptMs > 0);
  } finally { monitor.dispose(); }
});

it('autoRecover=false suppresses direct automatic recovery', async () => {
  const { monitor } = createMonitor();
  monitor.cfg.autoRecover = false;
  health.runHealthCheckGuarded = async () => healthResult(false);
  machine.recoverProxy = async () => assert.fail('automatic recovery despite opt-out');
  try { for (let i = 0; i < 4; i++) await monitor.refresh(false); }
  finally { monitor.dispose(); }
});

it('persisted off mode starts neither timers, probes nor bootstrap recovery', async () => {
  const { monitor } = createMonitor(new Map([['proxy.enabled.v1', false]]));
  health.runHealthCheckGuarded = async () => assert.fail('probe while off');
  machine.recoverProxy = async () => assert.fail('recovery while off');
  try {
    monitor.start();
    await monitor.refresh(true);
    await monitor.maybeBootstrap();
    await monitor.runDirectRecovery('manual-command');
    assert.equal(monitor.timer, null);
    assert.equal(monitor.publicIpTimer, null);
    assert.equal(monitor.display, 'OFF');
  } finally { monitor.dispose(); }
});

it('turn off during a health check drains it and suppresses late recovery', async () => {
  const { monitor, saved } = createMonitor();
  let release!: (value: unknown) => void;
  health.runHealthCheckGuarded = () => new Promise((r) => release = r);
  tasks.defaultExecAsync = async () => ''; // no scheduled tasks or owned processes
  machine.recoverProxy = async () => assert.fail('late recovery after off');
  const check = monitor.refresh(false);
  const off = monitor.turnOff();
  release(healthResult(false));
  await Promise.all([check, off]);
  assert.equal(saved.get('proxy.enabled.v1'), false);
  assert.equal(monitor.display, 'OFF');
  monitor.dispose();
});

it('off cancels an on request waiting for persistence and remains off', async () => {
  const { monitor, saved } = createMonitor(new Map([['proxy.enabled.v1', false]]));
  let release!: () => void;
  let started!: () => void;
  const entered = new Promise<void>((r) => started = r);
  monitor.context.globalState.update = async (key: string, value: unknown) => {
    if (key === 'proxy.enabled.v1' && value === true) {
      started();
      await new Promise<void>((r) => release = r);
    }
    saved.set(key, value);
  };
  tasks.defaultExecAsync = async () => '';
  machine.recoverProxy = async () => assert.fail('must not recover after off');
  health.runHealthCheckGuarded = async () => assert.fail('must not start monitor after off');
  const on = monitor.turnOn();
  await entered;
  const off = monitor.turnOff();
  release();
  await Promise.all([on, off]);
  assert.equal(saved.get('proxy.enabled.v1'), false);
  assert.equal(monitor.lifecycle.enabled, false);
  monitor.dispose();
});
