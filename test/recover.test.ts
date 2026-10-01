/**
 * Tests for src/recover.ts — budgets, cooldowns, safe-state mapping, runner.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  RecoverAttempt,
  RecoverConfig,
  planRecovery,
  planStuckTask,
  queryScheduledTask,
  reviveScheduledTask,
  runScheduledTask,
  stopScheduledTask,
  taskForState,
  waitForTaskStopped,
} from '../src/recover';

function cfg(): RecoverConfig {
  return {
    enabled: true,
    maxAttempts: 3,
    cooldownMs: 60_000,
    sshTask: 'OpenCode SSH SOCKS5',
    bridgeTask: 'OpenCode HTTP Proxy Bridge',
  };
}

function att(task: string, agoMs: number, ok = true): RecoverAttempt {
  return { atMs: 1_000_000 - agoMs, task, ok, detail: 'x' };
}

describe('taskForState', () => {
  it('maps local port failures to their owning tasks', () => {
    const c = cfg();
    assert.equal(taskForState('SSH_DOWN', c), 'OpenCode SSH SOCKS5');
    assert.equal(taskForState('SOCKS_DOWN', c), 'OpenCode SSH SOCKS5');
    assert.equal(taskForState('HTTP_BRIDGE_DOWN', c), 'OpenCode HTTP Proxy Bridge');
    for (const s of ['PROXY_FAILED', 'ZEN_UNREACHABLE', 'MODEL_UNAVAILABLE', 'HEALTHY', 'STARTING', 'UNKNOWN'] as const) {
      assert.equal(taskForState(s, c), null, s);
    }
  });

  it('empty task name -> null (no phantom task)', () => {
    assert.equal(taskForState('SSH_DOWN', { ...cfg(), sshTask: '  ' }), null);
  });
});

describe('planRecovery', () => {
  it('disabled -> none, never acts', () => {
    const p = planRecovery('SSH_DOWN', { ...cfg(), enabled: false }, [], 1_000_000);
    assert.equal(p.kind, 'none');
  });

  it('fresh outage -> run the owning task', () => {
    assert.deepEqual(planRecovery('SSH_DOWN', cfg(), [], 1_000_000), {
      kind: 'run-task',
      task: 'OpenCode SSH SOCKS5',
    });
    assert.deepEqual(planRecovery('HTTP_BRIDGE_DOWN', cfg(), [], 1_000_000), {
      kind: 'run-task',
      task: 'OpenCode HTTP Proxy Bridge',
    });
  });

  it('cooldown gates repeats, expiry re-arms', () => {
    const c = cfg();
    const cooling = planRecovery('SSH_DOWN', c, [att(c.sshTask, 10_000)], 1_000_000);
    assert.equal(cooling.kind, 'none');
    assert.match((cooling as { reason: string }).reason, /cooling down/);
    const rearmed = planRecovery('SSH_DOWN', c, [att(c.sshTask, 61_000)], 1_000_000);
    assert.equal(rearmed.kind, 'run-task');
  });

  it('budget exhausted -> give up loudly', () => {
    const c = cfg();
    const p = planRecovery(
      'SSH_DOWN',
      c,
      [att(c.sshTask, 500_000), att(c.sshTask, 400_000), att(c.sshTask, 300_000)],
      1_000_000,
    );
    assert.equal(p.kind, 'none');
    assert.match((p as { reason: string }).reason, /gave up after 3\/3/);
  });

  it('budgets are per task', () => {
    const c = cfg();
    const spent = [att(c.sshTask, 500_000), att(c.sshTask, 400_000), att(c.sshTask, 300_000)];
    assert.equal(planRecovery('HTTP_BRIDGE_DOWN', c, spent, 1_000_000).kind, 'run-task');
  });

  it('unfixable states -> explanatory none', () => {
    const p = planRecovery('ZEN_UNREACHABLE', cfg(), [], 1_000_000);
    assert.equal(p.kind, 'none');
    assert.match((p as { reason: string }).reason, /no safe automatic fix/);
  });

  it('refuses an ambiguous configuration that names the same task twice', () => {
    const c = { ...cfg(), bridgeTask: cfg().sshTask };
    assert.match((planRecovery('SSH_DOWN', c, [], 1_000_000) as { reason: string }).reason, /must differ/);
  });
});

describe('runScheduledTask (mocked exec)', () => {
  it('queries then runs on Ready task', async () => {
    const calls: string[][] = [];
    const r = await runScheduledTask(
      async (file, args) => {
        calls.push([file, ...args]);
        if (args[0] === '/query') {
          return '"\\OpenCode SSH SOCKS5","N/A","Ready"\r\n';
        }
        return 'SUCCESS: Attempted to run the scheduled task\r\n';
      },
      'OpenCode SSH SOCKS5',
    );
    assert.equal(r.ok, true);
    assert.deepEqual(calls.map((c) => c[1]), ['/query', '/run']);
  });

  it('missing task -> no /run call', async () => {
    const calls: string[][] = [];
    const r = await runScheduledTask(
      async (file, args) => {
        calls.push([file, ...args]);
        if (args[0] === '/query') {
          throw new Error('ERROR: The system cannot find the file specified.');
        }
        return '';
      },
      'Nope',
    );
    assert.equal(r.ok, false);
    assert.equal(r.outcome, 'failed');
    assert.match(r.detail, /not found/);
    assert.equal(calls.length, 1, 'must not attempt /run on a task that does not exist');
  });

  it('Disabled task -> no /run call', async () => {
    const calls: string[][] = [];
    const r = await runScheduledTask(
      async () => '"\\T","N/A","Disabled"\r\n',
      'T',
    );
    assert.equal(r.ok, false);
    assert.match(r.detail, /Disabled/);
    assert.equal(calls.length, 0);
  });

  it('failed /run -> ok false with message', async () => {
    const r = await runScheduledTask(
      async (file, args) => {
        if (args[0] === '/query') {
          return '"\\T","N/A","Ready"\r\n';
        }
        throw new Error('ERROR: Access is denied.');
      },
      'T',
    );
    assert.equal(r.ok, false);
    assert.match(r.detail, /Access is denied/);
  });

  it('empty name -> immediate refusal', async () => {
    let called = false;
    const r = await runScheduledTask(
      async () => {
        called = true;
        return '';
      },
      '  ',
    );
    assert.equal(r.ok, false);
    assert.equal(called, false);
  });
});

// The IgnoreNew wedge: schtasks exits 0 and prints SUCCESS for a start request
// it then discards, because the task is already marked Running. Reporting that
// as success is how auto-recovery spends its whole budget doing nothing.
describe('runScheduledTask — IgnoreNew wedge', () => {
  it('detects the discarded request and reports it as NOT ok', async () => {
    const calls: string[] = [];
    const r = await runScheduledTask(
      async (_file, args) => {
        calls.push(args[0]);
        if (args[0] === '/query') {
          return '"\\T","N/A","Running"\r\n';
        }
        return 'INFO: scheduled task "T" is currently running. SUCCESS: Attempted to run the scheduled task "T".\r\n';
      },
      'T',
    );
    assert.equal(r.outcome, 'ignored-running');
    assert.equal(r.ok, false, 'a discarded request must never count as success');
    assert.match(r.detail, /already marked Running/);
    assert.match(r.detail, /stuck, not healthy/);
    assert.deepEqual(calls, ['/query'], 'do not issue a known ignored /run request');
  });

  it('a real start is still ok', async () => {
    const r = await runScheduledTask(
      async (_file, args) => (args[0] === '/query' ? '"\\T","N/A","Ready"\r\n' : 'SUCCESS: Attempted to run the scheduled task "T".\r\n'),
      'T',
    );
    assert.equal(r.outcome, 'started');
    assert.equal(r.ok, true);
  });

  it('failed start -> outcome failed', async () => {
    const r = await runScheduledTask(
      async (file, args) => {
        if (args[0] === '/query') {
          return '"\\T","N/A","Ready"\r\n';
        }
        throw new Error('ERROR: Access is denied.');
      },
      'T',
    );
    assert.equal(r.outcome, 'failed');
    assert.equal(r.ok, false);
  });
});

describe('queryScheduledTask', () => {
  it('parses Running / Ready / Disabled', async () => {
    const mk = (status: string) => async () => `"\\T","N/A","${status}"\r\n`;
    assert.deepEqual(await queryScheduledTask(mk('Running'), 'T'), {
      exists: true,
      disabled: false,
      running: true,
      status: 'Running',
    });
    assert.deepEqual(await queryScheduledTask(mk('Ready'), 'T'), {
      exists: true,
      disabled: false,
      running: false,
      status: 'Ready',
    });
    const d = await queryScheduledTask(mk('Disabled'), 'T');
    assert.equal(d.disabled, true);
  });

  it('missing task -> exists false', async () => {
    const s = await queryScheduledTask(async () => {
      throw new Error('ERROR: The system cannot find the file specified.');
    }, 'Nope');
    assert.equal(s.exists, false);
    assert.equal(s.running, false);
  });

  it('distinguishes a failed query from a missing task', async () => {
    const s = await queryScheduledTask(async () => { throw new Error('Access is denied.'); }, 'T');
    assert.equal(s.exists, false);
    assert.match(s.status, /query failed: Access is denied/);
  });
});

describe('planStuckTask', () => {
  it('a port that answers ALWAYS wins — a working task is never stopped', () => {
    for (const running of [true, false]) {
      for (const allow of [true, false]) {
        const p = planStuckTask({ taskRunning: running, portUp: true, allowReset: allow }, ':8080');
        assert.equal(p.kind, 'none', `running=${running} allowReset=${allow}`);
        assert.match((p as { reason: string }).reason, /healthy/);
      }
    }
  });

  it('not running + port closed -> plain run', () => {
    assert.equal(planStuckTask({ taskRunning: false, portUp: false, allowReset: true }, ':8080').kind, 'run-task');
    assert.equal(planStuckTask({ taskRunning: false, portUp: false, allowReset: false }, ':8080').kind, 'run-task');
  });

  it('running + port closed + no opt-in -> refuses and says why', () => {
    const p = planStuckTask({ taskRunning: true, portUp: false, allowReset: false }, ':8080');
    assert.equal(p.kind, 'none');
    assert.match((p as { reason: string }).reason, /stuck instance/);
    assert.match((p as { reason: string }).reason, /autoRecoverResetStuckTask/);
  });

  it('running + port closed + opt-in -> stop then run', () => {
    const p = planStuckTask({ taskRunning: true, portUp: false, allowReset: true }, ':8080');
    assert.equal(p.kind, 'stop-then-run');
    assert.match((p as { reason: string }).reason, /:8080 is closed/);
  });
});

describe('stopScheduledTask / waitForTaskStopped', () => {
  it('stop uses /end and reports the result', async () => {
    const calls: string[][] = [];
    const r = await stopScheduledTask(async (file, args) => {
      calls.push([file, ...args]);
      return 'SUCCESS: Attempted to stop the scheduled task "T".\r\n';
    }, 'T');
    assert.equal(r.ok, true);
    assert.deepEqual(calls, [['schtasks', '/end', '/TN', 'T']]);
  });

  it('stop failure is reported, never thrown', async () => {
    const r = await stopScheduledTask(async () => {
      throw new Error('ERROR: Access is denied.');
    }, 'T');
    assert.equal(r.ok, false);
    assert.match(r.detail, /Access is denied/);
  });

  it('wait returns as soon as the task leaves Running', async () => {
    let calls = 0;
    let clock = 0;
    const r = await waitForTaskStopped(
      async () => {
        calls += 1;
        return calls < 3 ? '"\\T","N/A","Running"\r\n' : '"\\T","N/A","Ready"\r\n';
      },
      'T',
      5000,
      100,
      async () => {
        clock += 100;
      },
      () => clock,
    );
    assert.equal(r.stopped, true);
    assert.equal(calls, 3);
  });

  it('wait gives up rather than hanging on a task that never stops', async () => {
    let clock = 0;
    const r = await waitForTaskStopped(
      async () => '"\\T","N/A","Running"\r\n',
      'T',
      300,
      100,
      async () => {
        clock += 100;
      },
      () => clock,
    );
    assert.equal(r.stopped, false);
    assert.ok(r.waitedMs >= 300);
  });

  it('does not mistake a failed status query for a stopped task', async () => {
    let clock = 0;
    const r = await waitForTaskStopped(
      async () => { throw new Error('Access is denied.'); },
      'T', 300, 100,
      async () => { clock += 100; },
      () => clock,
    );
    assert.equal(r.stopped, false);
    assert.match(r.lastStatus, /query failed/);
  });
});

describe('reviveScheduledTask (mocked Scheduler and port)', () => {
  const watch = { host: '127.0.0.1', port: 1080 };
  function fixture(initial: 'Ready' | 'Running', initialPort = false) {
    let status = initial;
    let portUp = initialPort;
    let clock = 0;
    const calls: string[] = [];
    return {
      calls,
      deps: {
        exec: async (_file: string, args: string[]) => {
          calls.push(args[0]);
          if (args[0] === '/query') return `"\\T","N/A","${status}"\r\n`;
          if (args[0] === '/end') { status = 'Ready'; return 'SUCCESS'; }
          if (args[0] === '/run') { status = 'Running'; portUp = true; return 'SUCCESS'; }
          throw new Error('unexpected call');
        },
        probe: async () => portUp,
        sleep: async (ms: number) => { clock += ms; },
        now: () => clock,
      },
      setPort: (up: boolean) => { portUp = up; },
    };
  }

  it('never touches a task whose port answers', async () => {
    const f = fixture('Running', true);
    const r = await reviveScheduledTask('T', watch, true, 0, f.deps);
    assert.equal(r.ok, true);
    assert.deepEqual(f.calls, []);
  });

  it('starts a Ready task and verifies its port', async () => {
    const f = fixture('Ready');
    const r = await reviveScheduledTask('T', watch, true, 0, f.deps);
    assert.equal(r.ok, true);
    assert.deepEqual(f.calls, ['/query', '/query', '/run']);
  });

  it('resets a stuck Running task, then verifies the port', async () => {
    const f = fixture('Running');
    const r = await reviveScheduledTask('T', watch, true, 0, f.deps);
    assert.equal(r.ok, true);
    assert.deepEqual(f.calls, ['/query', '/end', '/query', '/query', '/run']);
  });

  it('refuses a stuck task when reset is disabled', async () => {
    const f = fixture('Running');
    const r = await reviveScheduledTask('T', watch, false, 0, f.deps);
    assert.equal(r.ok, false);
    assert.deepEqual(f.calls, ['/query']);
  });

  it('avoids stopping if the port opens during the task query', async () => {
    const f = fixture('Running');
    let probes = 0;
    const r = await reviveScheduledTask('T', watch, true, 0, {
      ...f.deps,
      probe: async () => ++probes >= 2,
    });
    assert.equal(r.ok, true);
    assert.deepEqual(f.calls, ['/query']);
  });

  it('reports a task that starts but never opens its port', async () => {
    const f = fixture('Ready');
    const r = await reviveScheduledTask('T', watch, true, 0, {
      ...f.deps,
      probe: async () => false,
    });
    assert.equal(r.ok, false);
    assert.match(r.detail, /never opened/);
  });

  it('restores a task it stopped even if auto-recovery is disabled mid-attempt', async () => {
    const f = fixture('Running');
    let enabled = true;
    const r = await reviveScheduledTask('T', watch, true, 0, {
      ...f.deps,
      exec: async (file, args) => {
        const out = await f.deps.exec(file, args);
        if (args[0] === '/end') enabled = false;
        return out;
      },
      canReset: () => enabled,
      canStart: () => enabled,
    });
    assert.equal(r.ok, true);
    assert.ok(f.calls.includes('/run'));
  });
});
