/**
 * Tests for src/runbook.ts — gating, idempotence, port waits, egress compare.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_RUNBOOK_CONFIG,
  RunbookConfig,
  RunbookDeps,
  buildProxyEnv,
  formatProxyEnv,
  formatRunbook,
  planRunbook,
  runRunbook,
  waitForPort,
} from '../src/runbook';

function cfg(over: Partial<RunbookConfig> = {}): RunbookConfig {
  return {
    ...DEFAULT_RUNBOOK_CONFIG,
    portWaitMs: 400,
    portPollMs: 10,
    execTimeoutMs: 50,
    ...over,
  };
}

interface HarnessOpts {
  /** Ports that answer, as a function of time (ms since start). */
  socksUp?: (t: number) => boolean;
  httpUp?: (t: number) => boolean;
  egress?: () => Promise<string>;
  tasks?: Record<string, { ok: boolean; detail: string }>;
  opencodeExpectedIp?: string;
}

interface Harness {
  deps: RunbookDeps;
  started: string[];
  clock: number;
}

function harness(opts: HarnessOpts = {}): Harness {
  const socksUp = opts.socksUp ?? (() => true);
  const httpUp = opts.httpUp ?? (() => true);
  const egress = opts.egress ?? (async () => opts.opencodeExpectedIp ?? '16.192.228.28');
  const tasks = opts.tasks ?? {};
  const h: Harness = {
    deps: null as unknown as RunbookDeps,
    started: [],
    clock: 0,
  };
  h.deps = {
    runTask: async (task) => {
      h.started.push(task);
      return tasks[task] ?? { ok: true, detail: 'SUCCESS: Attempted to run the scheduled task' };
    },
    probePort: async (_host, port) => {
      h.clock += 5; // each probe costs 5ms of virtual time
      return port === cfg().socksPort ? socksUp(h.clock) : httpUp(h.clock);
    },
    egressIp: egress,
    sleep: async (ms) => {
      h.clock += ms;
    },
    now: () => h.clock,
  };
  return h;
}

const byId = (r: Awaited<ReturnType<typeof runRunbook>>, id: string) => r.steps.find((s) => s.id === id)!;

describe('buildProxyEnv', () => {
  it('sets both cases plus NO_PROXY', () => {
    const env = buildProxyEnv('127.0.0.1', 8080);
    assert.equal(env.HTTP_PROXY, 'http://127.0.0.1:8080');
    assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:8080');
    assert.equal(env.http_proxy, 'http://127.0.0.1:8080');
    assert.equal(env.https_proxy, 'http://127.0.0.1:8080');
    assert.equal(env.NO_PROXY, 'localhost,127.0.0.1,::1');
    assert.equal(env.no_proxy, 'localhost,127.0.0.1,::1');
  });

  it('honours a custom NO_PROXY list', () => {
    assert.equal(buildProxyEnv('127.0.0.1', 8080, 'example.com').NO_PROXY, 'example.com');
  });

  it('summary line contains no secret material', () => {
    const s = formatProxyEnv(buildProxyEnv('127.0.0.1', 8080));
    assert.match(s, /http:\/\/127\.0\.0\.1:8080/);
    assert.match(s, /NO_PROXY=/);
  });
});

describe('planRunbook', () => {
  it('healthy chain needs no starts', () => {
    assert.deepEqual(planRunbook(cfg(), true, true), []);
  });
  it('lists only the ports that are actually down', () => {
    assert.deepEqual(planRunbook(cfg(), false, true), ['ssh-tunnel']);
    assert.deepEqual(planRunbook(cfg(), true, false), ['http-bridge']);
    assert.deepEqual(planRunbook(cfg(), false, false), ['ssh-tunnel', 'http-bridge']);
  });
});

describe('waitForPort', () => {
  it('resolves true on the first probe', async () => {
    let clock = 0;
    const r = await waitForPort(
      async () => true,
      '127.0.0.1',
      1080,
      1000,
      10,
      50,
      async () => {
        clock += 10;
      },
      () => clock,
    );
    assert.equal(r.up, true);
    assert.equal(r.probes, 1);
  });

  it('gives up after the budget', async () => {
    let clock = 0;
    const r = await waitForPort(
      async () => false,
      '127.0.0.1',
      1080,
      100,
      10,
      50,
      async () => {
        clock += 10;
      },
      () => clock,
    );
    assert.equal(r.up, false);
    assert.ok(r.probes > 1, 'should probe more than once before giving up');
    assert.ok(r.waitedMs >= 100);
  });

  it('a throwing probe counts as down, never rejects', async () => {
    let clock = 0;
    const r = await waitForPort(
      async () => {
        throw new Error('boom');
      },
      '127.0.0.1',
      1080,
      50,
      10,
      50,
      async () => {
        clock += 10;
      },
      () => clock,
    );
    assert.equal(r.up, false);
  });
});

describe('runRunbook — everything already up', () => {
  it('skips both starts, still verifies egress', async () => {
    const h = harness();
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.ok, true);
    assert.deepEqual(h.started, [], 'must not start tasks whose ports already answer');
    assert.equal(byId(r, 'ssh-tunnel').status, 'skipped');
    assert.equal(byId(r, 'http-bridge').status, 'skipped');
    assert.equal(byId(r, 'proxy-egress').status, 'ok');
    assert.equal(r.egressIp, '16.192.228.28');
  });
});

describe('runRunbook — cold start', () => {
  it('starts both tasks, in order, and waits for the ports', async () => {
    const h = harness({
      socksUp: (t) => t > 40,
      httpUp: (t) => t > 80,
    });
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.ok, true, JSON.stringify(r.steps, null, 2));
    assert.deepEqual(h.started, ['OpenCode SSH SOCKS5', 'OpenCode HTTP Proxy Bridge']);
    assert.equal(byId(r, 'ssh-tunnel').status, 'ok');
    assert.equal(byId(r, 'socks-port').status, 'ok');
    assert.equal(byId(r, 'http-bridge').status, 'ok');
    assert.equal(byId(r, 'http-port').status, 'ok');
    assert.equal(byId(r, 'proxy-env').status, 'ok');
  });

  it('numbers the steps like the hand runbook', async () => {
    const h = harness();
    const r = await runRunbook(cfg(), h.deps);
    assert.deepEqual(
      r.steps.map((s) => s.n),
      [1, 2, 3, 4, 5, 6],
    );
  });
});

describe('runRunbook — gating', () => {
  it('refuses to start an ambiguous shared task for either failed port', async () => {
    const shared = cfg({ bridgeTask: cfg().sshTask });
    for (const down of ['socks', 'http']) {
      const h = harness({ socksUp: () => down !== 'socks', httpUp: () => down !== 'http' });
      const r = await runRunbook(shared, h.deps);
      assert.equal(r.ok, false);
      assert.deepEqual(h.started, []);
      assert.match(byId(r, down === 'socks' ? 'ssh-tunnel' : 'http-bridge').detail, /must differ/);
    }
  });

  it('a refused task start fails step 1 and blocks 2-6', async () => {
    const h = harness({
      socksUp: () => false,
      httpUp: () => false,
      tasks: { 'OpenCode SSH SOCKS5': { ok: false, detail: 'task is Disabled' } },
    });
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 'ssh-tunnel');
    assert.equal(byId(r, 'ssh-tunnel').status, 'failed');
    assert.match(byId(r, 'ssh-tunnel').detail, /Disabled/);
    for (const id of ['socks-port', 'http-bridge', 'http-port', 'proxy-env', 'proxy-egress']) {
      assert.equal(byId(r, id).status, 'blocked', id);
      assert.match(byId(r, id).detail, /blocked by step 1/);
    }
    // The bridge task must NOT be started once step 1 failed.
    assert.deepEqual(h.started, ['OpenCode SSH SOCKS5']);
  });

  it('a task that starts but never binds fails the port step, not the task step', async () => {
    const h = harness({ socksUp: () => false, httpUp: () => true });
    const r = await runRunbook(cfg({ portWaitMs: 100, portPollMs: 10 }), h.deps);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 'socks-port');
    assert.equal(byId(r, 'ssh-tunnel').status, 'ok');
    assert.match(byId(r, 'socks-port').detail, /never opened/);
    assert.deepEqual(h.started, ['OpenCode SSH SOCKS5']);
  });

  it('a wrong egress IP fails step 6 and reports the mismatch', async () => {
    const h = harness({ egress: async () => '1.2.3.4' });
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 'proxy-egress');
    assert.match(byId(r, 'proxy-egress').detail, /1\.2\.3\.4/);
    assert.match(byId(r, 'proxy-egress').detail, /expected 16.192.228.28/);
    assert.equal(r.egressIp, null, 'a wrong IP must not be reported as the egress');
  });

  it('an egress probe that throws is a failed step, not a dead runbook', async () => {
    const h = harness({
      egress: async () => {
        throw new Error('all IP echo services failed');
      },
    });
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.ok, false);
    assert.equal(r.failedAt, 'proxy-egress');
    assert.match(byId(r, 'proxy-egress').detail, /all IP echo services failed/);
  });

  it('an empty expected IP skips the comparison but keeps the run honest', async () => {
    const h = harness({ egress: async () => '1.2.3.4' });
    const r = await runRunbook(cfg({ expectedExternalIp: '' }), h.deps);
    assert.equal(r.ok, true);
    assert.equal(r.egressIp, '1.2.3.4');
    assert.match(byId(r, 'proxy-egress').detail, /comparison skipped/);
  });

  it('an empty task name fails cleanly instead of starting something', async () => {
    const h = harness({ socksUp: () => false, httpUp: () => true });
    const r = await runRunbook(cfg({ sshTask: '   ' }), h.deps);
    assert.equal(r.failedAt, 'ssh-tunnel');
    assert.match(byId(r, 'ssh-tunnel').detail, /no SSH tunnel task name configured/);
    assert.deepEqual(h.started, []);
  });

  it('env is still returned on success so the caller can launch opencode', async () => {
    const h = harness();
    const r = await runRunbook(cfg(), h.deps);
    assert.equal(r.env.HTTP_PROXY, 'http://127.0.0.1:8080');
    assert.equal(r.env.HTTPS_PROXY, 'http://127.0.0.1:8080');
  });
});

describe('onStep / formatRunbook', () => {
  it('publishes a running then a terminal state for every step', async () => {
    const seen: string[] = [];
    const h = harness();
    h.deps.onStep = (s) => seen.push(`${s.id}:${s.status}`);
    await runRunbook(cfg(), h.deps);
    for (const id of ['ssh-tunnel', 'socks-port', 'http-bridge', 'http-port', 'proxy-env', 'proxy-egress']) {
      assert.ok(seen.includes(`${id}:running`), `${id} running`);
      assert.ok(
        seen.some((x) => x.startsWith(`${id}:`) && !x.endsWith(':running')),
        `${id} terminal`,
      );
    }
  });

  it('report renders all six numbered lines', async () => {
    const h = harness();
    const r = await runRunbook(cfg(), h.deps);
    const lines = formatRunbook(r);
    assert.equal(lines.length, 7);
    assert.match(lines[0], /proxy egress verified/);
    for (const n of [1, 2, 3, 4, 5, 6]) {
      assert.ok(lines.some((l) => l.includes(`${n}. `)), `step ${n} present`);
    }
  });

  it('report names the stopping step on failure', async () => {
    const h = harness({ socksUp: () => false, httpUp: () => true });
    const r = await runRunbook(cfg({ portWaitMs: 50, portPollMs: 10 }), h.deps);
    assert.match(formatRunbook(r)[0], /stopped at step socks-port/);
  });
});
