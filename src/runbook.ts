/**
 * runbook.ts — the manual recovery runbook, executed as one ordered, gated
 * sequence. No `vscode` dependency, so it stays unit-testable with plain Node.
 *
 * This mirrors the runbook you run by hand, step for step:
 *   1. START SSH TUNNEL   → schtasks /run "OpenCode SSH SOCKS5" (your own task)
 *   2. CHECK SSH PORT     → wait for TCP 127.0.0.1:<socksPort>
 *   3. START HTTP BRIDGE  → schtasks /run "OpenCode HTTP Proxy Bridge"
 *   4. (bridge port)      → wait for TCP 127.0.0.1:<httpPort>
 *   5. SET PROXY          → build the env map applied to launched children
 *   6. TEST PROXY         → egress IP through the proxy must match expected
 *   7. START OPENCODE     → owned by the caller (needs a UI prompt)
 *
 * Ground rules carried over from recover.ts:
 * - Task recovery is supplied by the caller. The extension only operates on
 *   the user's existing scheduled tasks and never synthesises ssh commands.
 * - Strictly sequential and gated: a failed step marks every later step
 *   `blocked`. A half-built chain is worse than an honest failure.
 * - Idempotent: a step whose port already answers is reported `skipped`,
 *   not "fixed". Never start a second ssh that would collide on :1080.
 * - Never throws. Failures are data.
 */

import type { ExecAsync } from './diagnose';
import { EXPECTED_PROXY_EGRESS_IP } from './netModel';

export type StepStatus = 'running' | 'ok' | 'failed' | 'skipped' | 'blocked';

export type StepId =
  | 'ssh-tunnel'
  | 'socks-port'
  | 'http-bridge'
  | 'http-port'
  | 'proxy-env'
  | 'proxy-egress';

export interface StepState {
  id: StepId;
  /** Numbered to match the hand-run runbook, so logs are recognisable. */
  n: number;
  title: string;
  status: StepStatus;
  detail: string;
  startedAtMs: number;
  endedAtMs: number | null;
}

export interface RunbookConfig {
  socksHost: string;
  socksPort: number;
  httpHost: string;
  httpPort: number;
  /** Empty disables the comparison (egress is still observed and reported). */
  expectedExternalIp: string;
  sshTask: string;
  bridgeTask: string;
  /** How long a step waits for its port to come up before failing. */
  portWaitMs: number;
  /** Gap between port probes while waiting. */
  portPollMs: number;
  execTimeoutMs: number;
}

export const DEFAULT_RUNBOOK_CONFIG: RunbookConfig = {
  socksHost: '127.0.0.1',
  socksPort: 1080,
  httpHost: '127.0.0.1',
  httpPort: 8080,
  expectedExternalIp: EXPECTED_PROXY_EGRESS_IP,
  sshTask: 'OpenCode SSH SOCKS5',
  bridgeTask: 'OpenCode HTTP Proxy Bridge',
  portWaitMs: 30_000,
  portPollMs: 750,
  execTimeoutMs: 15_000,
};

export interface RunbookDeps {
  /** Start a scheduled task. Must pre-check existence/Disabled state. */
  runTask: (task: string) => Promise<{ ok: boolean; detail: string }>;
  /** One TCP probe. Resolves true/false; must never throw. */
  probePort: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
  /** Public IP observed through the HTTP bridge. Must never throw. */
  egressIp: () => Promise<string>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  /** Called on every status change so the UI can render progress. */
  onStep?: (step: StepState) => void;
}

export interface RunbookResult {
  steps: StepState[];
  /** True only when every step reached `ok` or `skipped`. */
  ok: boolean;
  /** First failed/blocked step id, for a one-line summary. */
  failedAt: StepId | null;
  /** Proxy env for child processes. Only meaningful when `ok`. */
  env: Record<string, string>;
  /** Egress IP seen through the proxy, or null if step 6 never completed. */
  egressIp: string | null;
  elapsedMs: number;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

const NO_PROXY_LIST = 'localhost,127.0.0.1,::1';

/**
 * The proxy env applied to processes the extension launches. Both cases are set
 * because tooling disagrees on which it reads; NO_PROXY keeps loopback traffic
 * (the bridge, the LSP, the dashboard) off the tunnel.
 */
export function buildProxyEnv(httpHost: string, httpPort: number, noProxy = NO_PROXY_LIST): Record<string, string> {
  const url = `http://${httpHost}:${httpPort}`;
  return {
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    http_proxy: url,
    https_proxy: url,
    NO_PROXY: noProxy,
    no_proxy: noProxy,
  };
}

/** One-line human summary of the env map, safe to log (no secrets present). */
export function formatProxyEnv(env: Record<string, string>): string {
  return `${env.HTTP_PROXY} (NO_PROXY=${env.NO_PROXY})`;
}

const STEP_TITLES: Record<StepId, { n: number; title: string }> = {
  'ssh-tunnel': { n: 1, title: 'START SSH TUNNEL' },
  'socks-port': { n: 2, title: 'CHECK SSH PORT' },
  'http-bridge': { n: 3, title: 'START HTTP PROXY BRIDGE' },
  'http-port': { n: 4, title: 'CHECK HTTP BRIDGE PORT' },
  'proxy-env': { n: 5, title: 'SET PROXY' },
  'proxy-egress': { n: 6, title: 'TEST PROXY' },
};

const STEP_ORDER: StepId[] = ['ssh-tunnel', 'socks-port', 'http-bridge', 'http-port', 'proxy-env', 'proxy-egress'];

function firstLine(s: string, max = 200): string {
  return String(s).split(/\r?\n/)[0].slice(0, max);
}

function makeStep(id: StepId, now: number): StepState {
  return {
    id,
    n: STEP_TITLES[id].n,
    title: STEP_TITLES[id].title,
    status: 'running',
    detail: '',
    startedAtMs: now,
    endedAtMs: null,
  };
}

/**
 * Poll `probePort` until it answers or the budget runs out. Always performs at
 * least one probe, and always resolves — a probe that throws counts as "down".
 */
export async function waitForPort(
  probe: (host: string, port: number, timeoutMs: number) => Promise<boolean>,
  host: string,
  port: number,
  waitMs: number,
  pollMs: number,
  probeTimeoutMs: number,
  sleep: (ms: number) => Promise<void>,
  now: () => number,
): Promise<{ up: boolean; waitedMs: number; probes: number }> {
  const started = now();
  let probes = 0;
  for (;;) {
    probes += 1;
    let up = false;
    try {
      up = await probe(host, port, probeTimeoutMs);
    } catch {
      up = false;
    }
    if (up) {
      return { up: true, waitedMs: now() - started, probes };
    }
    const waited = now() - started;
    if (waited >= waitMs) {
      return { up: false, waitedMs: waited, probes };
    }
    await sleep(Math.max(50, Math.min(pollMs, waitMs - waited)));
  }
}

/**
 * Which of the runbook's start steps can be skipped because their port already
 * answers. Pure, so the caller can render an accurate plan up front.
 */
export function planRunbook(cfg: RunbookConfig, socksUp: boolean, httpUp: boolean): StepId[] {
  const toRun: StepId[] = [];
  if (!socksUp) {
    toRun.push('ssh-tunnel');
  }
  if (!httpUp) {
    toRun.push('http-bridge');
  }
  return toRun;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Run the runbook in order. Never throws; every outcome lands in `steps`.
 * `onStep` fires for each status transition, so a progress bar can follow.
 */
export async function runRunbook(cfg: RunbookConfig, deps: RunbookDeps): Promise<RunbookResult> {
  const startedAt = deps.now();
  const steps = new Map<StepId, StepState>();
  let blockedBy: StepId | null = null;
  let egressIp: string | null = null;

  const env = buildProxyEnv(cfg.httpHost, cfg.httpPort);

  const publish = (s: StepState): void => {
    steps.set(s.id, s);
    deps.onStep?.(s);
  };

  /** Run one step body, or mark it blocked and return the given fallback. */
  const runStep = async <T>(id: StepId, body: () => Promise<{ status: StepStatus; detail: string; value: T }>): Promise<T | null> => {
    if (blockedBy) {
      const s = makeStep(id, deps.now());
      s.status = 'blocked';
      s.detail = `blocked by step ${STEP_TITLES[blockedBy].n} (${STEP_TITLES[blockedBy].title})`;
      s.endedAtMs = deps.now();
      publish(s);
      return null;
    }
    const s = makeStep(id, deps.now());
    publish(s);
    let out: { status: StepStatus; detail: string; value: T };
    try {
      out = await body();
    } catch (e) {
      // A step body that throws is a failed step, not a dead runbook.
      out = { status: 'failed', detail: firstLine((e as Error).message), value: null as T };
    }
    s.status = out.status;
    s.detail = out.detail;
    s.endedAtMs = deps.now();
    publish(s);
    if (out.status === 'failed') {
      blockedBy = id;
    }
    return out.value;
  };

  // 1 + 2 — SSH tunnel, then prove the SOCKS port answers.
  const socksUp = await runStep('ssh-tunnel', async () => {
    let already = false;
    try {
      already = await deps.probePort(cfg.socksHost, cfg.socksPort, cfg.execTimeoutMs);
    } catch {
      already = false;
    }
    if (already) {
      return {
        status: 'skipped' as const,
        detail: `${cfg.socksHost}:${cfg.socksPort} already listening — not starting a second tunnel`,
        value: true,
      };
    }
    if (cfg.sshTask.trim().length === 0) {
      return { status: 'failed' as const, detail: 'no SSH tunnel task name configured', value: false };
    }
    if (cfg.sshTask.trim() === cfg.bridgeTask.trim()) {
      return { status: 'failed' as const, detail: 'SSH and bridge task names must differ for safe recovery', value: false };
    }
    const res = await deps.runTask(cfg.sshTask);
    return res.ok
      ? { status: 'ok' as const, detail: `start requested: "${cfg.sshTask}" (${firstLine(res.detail)})`, value: false }
      : { status: 'failed' as const, detail: res.detail, value: false };
  });

  await runStep('socks-port', async () => {
    if (socksUp === true) {
      return { status: 'ok' as const, detail: `${cfg.socksHost}:${cfg.socksPort} open`, value: true };
    }
    const r = await waitForPort(
      deps.probePort,
      cfg.socksHost,
      cfg.socksPort,
      cfg.portWaitMs,
      cfg.portPollMs,
      cfg.execTimeoutMs,
      deps.sleep,
      deps.now,
    );
    return r.up
      ? { status: 'ok' as const, detail: `${cfg.socksHost}:${cfg.socksPort} open after ${r.waitedMs}ms (${r.probes} probe(s))`, value: true }
      : {
          status: 'failed' as const,
          detail: `${cfg.socksHost}:${cfg.socksPort} never opened in ${Math.round(r.waitedMs / 1000)}s (${r.probes} probe(s)) — SSH task accepted the start but the tunnel did not come up`,
          value: false,
        };
  });

  // 3 + 4 — HTTP bridge, then prove its port answers.
  const httpUp = await runStep('http-bridge', async () => {
    let already = false;
    try {
      already = await deps.probePort(cfg.httpHost, cfg.httpPort, cfg.execTimeoutMs);
    } catch {
      already = false;
    }
    if (already) {
      return {
        status: 'skipped' as const,
        detail: `${cfg.httpHost}:${cfg.httpPort} already listening — bridge left alone`,
        value: true,
      };
    }
    if (cfg.bridgeTask.trim().length === 0) {
      return { status: 'failed' as const, detail: 'no HTTP bridge task name configured', value: false };
    }
    if (cfg.sshTask.trim() === cfg.bridgeTask.trim()) {
      return { status: 'failed' as const, detail: 'SSH and bridge task names must differ for safe recovery', value: false };
    }
    const res = await deps.runTask(cfg.bridgeTask);
    return res.ok
      ? { status: 'ok' as const, detail: `start requested: "${cfg.bridgeTask}" (${firstLine(res.detail)})`, value: false }
      : { status: 'failed' as const, detail: res.detail, value: false };
  });

  await runStep('http-port', async () => {
    if (httpUp === true) {
      return { status: 'ok' as const, detail: `${cfg.httpHost}:${cfg.httpPort} open`, value: true };
    }
    const r = await waitForPort(
      deps.probePort,
      cfg.httpHost,
      cfg.httpPort,
      cfg.portWaitMs,
      cfg.portPollMs,
      cfg.execTimeoutMs,
      deps.sleep,
      deps.now,
    );
    return r.up
      ? { status: 'ok' as const, detail: `${cfg.httpHost}:${cfg.httpPort} open after ${r.waitedMs}ms (${r.probes} probe(s))`, value: true }
      : {
          status: 'failed' as const,
          detail: `${cfg.httpHost}:${cfg.httpPort} never opened in ${Math.round(r.waitedMs / 1000)}s (${r.probes} probe(s)) — bridge task accepted the start but nothing is listening`,
          value: false,
        };
  });

  // 5 — proxy env. Pure: the map is handed to the caller, which applies it to
  // the processes it launches. Nothing on this machine is mutated here.
  await runStep('proxy-env', async () => ({
    status: 'ok' as const,
    detail: `child env only: ${formatProxyEnv(env)}`,
    value: env,
  }));

  // 6 — prove traffic actually leaves through the EC2 tunnel.
  const ip = await runStep('proxy-egress', async () => {
    let seen: string;
    try {
      seen = (await deps.egressIp()).trim();
    } catch (e) {
      return { status: 'failed' as const, detail: `no IP through the proxy: ${firstLine((e as Error).message)}`, value: null as string | null };
    }
    if (!cfg.expectedExternalIp) {
      return { status: 'ok' as const, detail: `proxy answered with ${seen} (no expected IP configured, comparison skipped)`, value: seen };
    }
    if (seen === cfg.expectedExternalIp) {
      return { status: 'ok' as const, detail: `proxy answered with ${seen} — matches expected`, value: seen };
    }
    return {
      status: 'failed' as const,
      detail: `proxy answered with ${seen}, expected ${cfg.expectedExternalIp} — traffic is NOT leaving through your EC2 tunnel`,
      value: null as string | null,
    };
  });
  egressIp = ip;

  const ordered = STEP_ORDER.map((id) => steps.get(id)).filter((s): s is StepState => s !== undefined);
  const ok = ordered.every((s) => s.status === 'ok' || s.status === 'skipped');
  return {
    steps: ordered,
    ok,
    failedAt: blockedBy,
    env,
    egressIp,
    elapsedMs: deps.now() - startedAt,
  };
}

/** Render runbook steps as report lines for the output channel. */
export function formatRunbook(result: RunbookResult): string[] {
  const glyph: Record<StepStatus, string> = {
    running: '…',
    ok: 'OK',
    failed: 'FAIL',
    skipped: 'SKIP',
    blocked: 'BLOCK',
  };
  const lines = [`Recovery runbook — ${result.ok ? 'proxy egress verified' : `stopped at step ${result.failedAt}`} (${result.elapsedMs}ms)`];
  for (const s of result.steps) {
    lines.push(`  ${glyph[s.status].padEnd(5)} ${s.n}. ${s.title} — ${s.detail}`);
  }
  return lines;
}
