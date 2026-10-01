/**
 * recover.ts — opt-in self-healing (no vscode dependency).
 *
 * Ground rules:
 * - Only the user's existing scheduled tasks are started or, with a confirmed
 *   closed port and reset enabled, stopped and restarted. No ssh/node command
 *   lines, model, auth, or configuration files are changed.
 * - Only local port failures are fixable (SSH_DOWN, SOCKS_DOWN,
 *   HTTP_BRIDGE_DOWN). Task state and the port are checked before action.
 *   Remote failures get diagnosis without automatic task action.
 * - Budgets: bounded attempts per outage with cooldowns; give up loudly.
 */

import { execFile } from 'child_process';
import type { HealthState } from './health';
import { parseSchtasksRow, type ExecAsync } from './diagnose';
import { waitForPort } from './runbook';

export interface RecoverConfig {
  enabled: boolean;
  /** Max start attempts per outage, per task. */
  maxAttempts: number;
  /** Minimum gap between attempts (ms). */
  cooldownMs: number;
  sshTask: string;
  bridgeTask: string;
}

export interface RecoverAttempt {
  atMs: number;
  task: string;
  /** Did schtasks accept the start request (health verification happens separately). */
  ok: boolean;
  detail: string;
}

export type RecoverPlan = { kind: 'run-task'; task: string } | { kind: 'none'; reason: string };

/**
 * What `schtasks /run` actually did.
 *
 * `ignored-running` is the dangerous one. Both tasks are configured with
 * `MultipleInstances = IgnoreNew`, so a run request against a task that
 * Scheduler still believes is Running is **discarded silently** — yet schtasks
 * exits 0 and prints "SUCCESS: Attempted to run the scheduled task". Treating
 * that as success is how auto-recovery burns its whole budget doing nothing.
 */
export type TaskRunOutcome = 'started' | 'ignored-running' | 'failed';

export interface TaskRunResult {
  ok: boolean;
  detail: string;
  outcome: TaskRunOutcome;
}

export interface TaskStateInfo {
  exists: boolean;
  disabled: boolean;
  running: boolean;
  status: string;
}

/** Query a scheduled task's existence, Disabled flag and Running state. */
export async function queryScheduledTask(
  exec: ExecAsync = defaultExecAsync,
  taskName: string,
  timeoutMs = 10000,
): Promise<TaskStateInfo> {
  if (!taskName || taskName.trim().length === 0) {
    return { exists: false, disabled: false, running: false, status: 'no task name configured' };
  }
  try {
    const out = await exec('schtasks', ['/query', '/TN', taskName, '/FO', 'CSV', '/NH'], Math.min(timeoutMs, 10000));
    const row = parseSchtasksRow(out);
    if (!row) {
      return { exists: false, disabled: false, running: false, status: 'unparseable task query' };
    }
    const disabled = /disabled/i.test(row.status);
    return { exists: true, disabled, running: /running/i.test(row.status), status: row.status };
  } catch (e) {
    const message = firstLine((e as Error).message);
    const missing = /cannot find|not found|does not exist/i.test(message);
    return { exists: false, disabled: false, running: false, status: missing ? 'not found' : `query failed: ${message}` };
  }
}

/**
 * Start a scheduled task by name. Pre-checks it exists and isn't Disabled, so
 * we never burn attempts on a task that cannot run. Never throws.
 *
 * `ok` means "the chain may now be working" — it is deliberately false for an
 * ignored request against a task Scheduler already calls Running, so callers
 * budget correctly instead of counting a no-op as a success.
 */
export async function runScheduledTask(
  exec: ExecAsync = defaultExecAsync,
  taskName: string,
  timeoutMs = 15000,
): Promise<TaskRunResult> {
  if (!taskName || taskName.trim().length === 0) {
    return { ok: false, detail: 'no task name configured', outcome: 'failed' };
  }
  const state = await queryScheduledTask(exec, taskName, timeoutMs);
  if (!state.exists) {
    return { ok: false, detail: `task "${taskName}": ${state.status}`, outcome: 'failed' };
  }
  if (state.disabled) {
    return { ok: false, detail: `task "${taskName}" is Disabled`, outcome: 'failed' };
  }
  if (state.running) {
    return {
      ok: false,
      detail: `task "${taskName}" is already marked Running, so the start request would be ignored (MultipleInstances=IgnoreNew) — the task is stuck, not healthy`,
      outcome: 'ignored-running',
    };
  }
  try {
    const out = await exec('schtasks', ['/run', '/TN', taskName], timeoutMs);
    const t = out.trim();
    // schtasks reports success for a request it then discards. Detect it.
    if (/is currently running/i.test(t)) {
      return {
        ok: false,
        detail: `task "${taskName}" is already marked Running, so the start request was ignored (MultipleInstances=IgnoreNew) — the task is stuck, not healthy`,
        outcome: 'ignored-running',
      };
    }
    return { ok: true, detail: t.length > 0 ? firstLine(t) : `start request accepted for "${taskName}"`, outcome: 'started' };
  } catch (e) {
    return { ok: false, detail: `cannot start task "${taskName}": ${firstLine((e as Error).message)}`, outcome: 'failed' };
  }
}

/**
 * Stop a scheduled task. This is the one action that goes beyond "only start
 * things", so callers must gate it on the port being confirmed CLOSED and on
 * the user opting in. Never throws.
 */
export async function stopScheduledTask(
  exec: ExecAsync = defaultExecAsync,
  taskName: string,
  timeoutMs = 15000,
): Promise<{ ok: boolean; detail: string }> {
  if (!taskName || taskName.trim().length === 0) {
    return { ok: false, detail: 'no task name configured' };
  }
  try {
    const out = await exec('schtasks', ['/end', '/TN', taskName], timeoutMs);
    const t = out.trim();
    return { ok: true, detail: t.length > 0 ? firstLine(t) : `stop request accepted for "${taskName}"` };
  } catch (e) {
    return { ok: false, detail: `cannot stop task "${taskName}": ${firstLine((e as Error).message)}` };
  }
}

/** Poll until the task is no longer Running, or the budget runs out. */
export async function waitForTaskStopped(
  exec: ExecAsync,
  taskName: string,
  waitMs: number,
  pollMs: number,
  sleep: (ms: number) => Promise<void>,
  now: () => number,
): Promise<{ stopped: boolean; waitedMs: number; lastStatus: string }> {
  const started = now();
  for (;;) {
    const s = await queryScheduledTask(exec, taskName, 8000);
    if (s.exists && !s.running) {
      return { stopped: true, waitedMs: now() - started, lastStatus: s.status };
    }
    if (now() - started >= waitMs) {
      return { stopped: false, waitedMs: now() - started, lastStatus: s.status };
    }
    await sleep(Math.max(50, pollMs));
  }
}

export interface ReviveTaskDeps {
  /** Explicit proxy-off veto also applies after we stopped a stuck task. */
  canContinue?: () => boolean;
  exec: ExecAsync;
  probe: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  onProgress?: (detail: string) => void;
  /** Recheck live settings before a task is stopped or started. */
  canStart?: () => boolean;
  canReset?: () => boolean;
}

/** Recover one local task, verifying the port before and after any action. */
export async function reviveScheduledTask(
  task: string,
  watch: { host: string; port: number } | null,
  allowReset: boolean,
  portWaitMs: number,
  deps: ReviveTaskDeps,
): Promise<{ ok: boolean; detail: string }> {
  const label = watch ? `${watch.host}:${watch.port}` : 'its port';
  const portUp = async (): Promise<boolean> => {
    if (!watch) return false;
    try {
      return await deps.probe(watch.host, watch.port, 5000);
    } catch {
      return false;
    }
  };

  if (await portUp()) {
    return { ok: true, detail: `${label} already answers — ${task} left alone` };
  }
  const state = await queryScheduledTask(deps.exec, task, 10000);
  if (!state.exists) {
    return { ok: false, detail: `task "${task}": ${state.status}` };
  }
  if (state.disabled) {
    return { ok: false, detail: `task "${task}" is Disabled` };
  }
  if (await portUp()) {
    return { ok: true, detail: `${label} opened while checking "${task}" — task left alone` };
  }

  const plan = planStuckTask({ taskRunning: state.running, portUp: false, allowReset }, label);
  if (plan.kind === 'none') {
    return { ok: false, detail: plan.reason };
  }
  let stoppedByUs = false;
  if (plan.kind === 'stop-then-run') {
    if (deps.canReset && !deps.canReset()) {
      return { ok: false, detail: 'stuck-task reset was disabled while checking the task' };
    }
    deps.onProgress?.(`"${task}" is stuck: ${plan.reason}`);
    const stop = await stopScheduledTask(deps.exec, task, 15000);
    if (!stop.ok) {
      return { ok: false, detail: `cannot stop stuck task "${task}": ${stop.detail}` };
    }
    stoppedByUs = true;
    const stopped = await waitForTaskStopped(deps.exec, task, 10000, 500, deps.sleep, deps.now);
    if (!stopped.stopped) {
      return { ok: false, detail: `task "${task}" could not be verified stopped within 10s (last query: ${stopped.lastStatus})` };
    }
    deps.onProgress?.(`"${task}" stopped after ${stopped.waitedMs}ms`);
    if (await portUp()) {
      return { ok: true, detail: `${label} opened while stopping "${task}" — no start needed` };
    }
  } else {
    deps.onProgress?.(plan.reason);
  }

  if (deps.canContinue && !deps.canContinue()) return { ok: false, detail: 'proxy was turned off during recovery' };
  if (!stoppedByUs && deps.canStart && !deps.canStart()) {
    return { ok: false, detail: 'auto-recovery was disabled while checking the task' };
  }
  const res = await runScheduledTask(deps.exec, task, 15000);
  if (!res.ok) {
    return { ok: false, detail: res.detail };
  }
  if (!watch) {
    return { ok: true, detail: res.detail };
  }
  const r = await waitForPort(deps.probe, watch.host, watch.port, portWaitMs, 750, 5000, deps.sleep, deps.now);
  return r.up
    ? { ok: true, detail: `${label} opened ${r.waitedMs}ms after starting "${task}"` }
    : { ok: false, detail: `"${task}" was started but ${label} never opened within ${Math.round(portWaitMs / 1000)}s (${r.probes} probes)` };
}

// ---------------------------------------------------------------------------
// Stuck-task planning (pure)
// ---------------------------------------------------------------------------

export type StuckTaskPlan =
  | { kind: 'run-task'; reason: string }
  | { kind: 'stop-then-run'; reason: string }
  | { kind: 'none'; reason: string };

export interface StuckTaskInput {
  /** Task Scheduler's own view: is the task marked Running? */
  taskRunning: boolean;
  /** Ground truth: does the port the task is supposed to own answer? */
  portUp: boolean;
  /** User opt-in for stopping a task. */
  allowReset: boolean;
}

/**
 * Decide how to revive a task whose port is down.
 *
 * The single most important rule: **a port that answers wins, always.** If the
 * port is up the task is doing its job, whatever Scheduler thinks, and we must
 * not stop a working bridge because of a stale state flag.
 */
export function planStuckTask(input: StuckTaskInput, portLabel = 'the port'): StuckTaskPlan {
  if (input.portUp) {
    return { kind: 'none', reason: `${portLabel} answers — the task is healthy, leaving it alone` };
  }
  if (!input.taskRunning) {
    return { kind: 'run-task', reason: 'task is not running and its port is closed' };
  }
  if (!input.allowReset) {
    return {
      kind: 'none',
      reason: `task is marked Running but ${portLabel} is closed (stuck instance); enable opencodeProxyHealth.autoRecoverResetStuckTask to stop and restart it`,
    };
  }
  return {
    kind: 'stop-then-run',
    reason: `task is marked Running but ${portLabel} is closed (stuck instance) — stopping it so it can be restarted`,
  };
}

/** Which scheduled task (if any) owns recovery for a chain state. */
export function taskForState(state: HealthState, cfg: RecoverConfig): string | null {
  if (state === 'SSH_DOWN' || state === 'SOCKS_DOWN') {
    return cfg.sshTask.trim().length > 0 ? cfg.sshTask : null;
  }
  if (state === 'HTTP_BRIDGE_DOWN') {
    return cfg.bridgeTask.trim().length > 0 ? cfg.bridgeTask : null;
  }
  return null;
}

/** Decide the next step. Pure — attempt history stays with the caller. */
export function planRecovery(
  state: HealthState,
  cfg: RecoverConfig,
  attempts: RecoverAttempt[],
  nowMs: number,
): RecoverPlan {
  if (!cfg.enabled) {
    return { kind: 'none', reason: 'auto-recovery disabled (monitoring only)' };
  }
  if (cfg.sshTask.trim() === cfg.bridgeTask.trim()) {
    return { kind: 'none', reason: 'SSH and bridge task names must differ for safe recovery' };
  }
  const task = taskForState(state, cfg);
  if (!task) {
    return { kind: 'none', reason: `no safe automatic fix for ${state}` };
  }
  const relevant = attempts.filter((a) => a.task === task);
  if (relevant.length >= cfg.maxAttempts) {
    return { kind: 'none', reason: `gave up after ${relevant.length}/${cfg.maxAttempts} attempts for "${task}"` };
  }
  const last = relevant[relevant.length - 1];
  if (last) {
    const waitMs = cfg.cooldownMs - (nowMs - last.atMs);
    if (waitMs > 0) {
      return { kind: 'none', reason: `cooling down: next attempt for "${task}" in ${Math.ceil(waitMs / 1000)}s` };
    }
  }
  return { kind: 'run-task', task };
}

function firstLine(s: string): string {
  return String(s).split('\n')[0].slice(0, 200);
}

export function defaultExecAsync(file: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(String(stdout ?? ''));
      }
    });
  });
}
