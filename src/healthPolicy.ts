/**
 * healthPolicy.ts — pure confirmation policy for health samples.
 *
 * The false-positive fix lives here: ONE failed probe is NEVER a verdict.
 * Infrastructure recovery and user notifications require consecutive
 * confirmed failures; transient blips surface as DEGRADED (status bar only).
 *
 * - Transport ticks: ok | infra-down. Strikes 1..threshold-1 -> DEGRADED
 *   (no notify, no recovery). Strike >= threshold -> PROXY_DOWN (notify once
 *   per episode, recovery allowed). Success resets strikes.
 * - OpenCode-traffic override (K): an L2-only failure while loopback ports
 *   are up AND a tracked OpenCode request recently succeeded is treated as a
 *   diagnostic failure, not proxy failure: no strike, DEGRADED, no recovery.
 * - Zen is tracked separately (1st fail ZEN_DEGRADED, >=3 ZEN_UNREACHABLE),
 *   display-only, never notify, never recover.
 * - Recovery-success notification only when the outage was confirmed AND
 *   lasted at least minOutageNotifySec ("recovered — down for Xs" is otherwise
 *   false and forbidden).
 * - ProbeGate: exactly one active health-check cycle; a poll arriving while
 *   one runs must skip/reuse, never overlap.
 */

export interface PolicyConfig {
  /** Consecutive failures before PROXY_DOWN + recovery (>= 2, default 3). */
  failureThreshold: number;
  /** Confirmed outage length that "matters" for a recovery notification (s). */
  minOutageNotifySec: number;
  /** How recent a tracked OpenCode success must be to veto a strike (ms). */
  recentTrafficWindowMs: number;
}

export const DEFAULT_POLICY_CONFIG: PolicyConfig = {
  failureThreshold: 3,
  minOutageNotifySec: 20,
  recentTrafficWindowMs: 120_000,
};

export type TransportTick = 'ok' | 'infra-down';

export type PolicyVerdict = 'READY' | 'DEGRADED' | 'PROXY_DOWN';

export interface PolicyState {
  strikes: number;
  confirmedDownSinceMs: number | null;
  notifiedDown: boolean;
  verdict: PolicyVerdict;
}

export function emptyPolicy(): PolicyState {
  return { strikes: 0, confirmedDownSinceMs: null, notifiedDown: false, verdict: 'READY' };
}

export type PolicyEvent = 'notify-proxy-down';

export interface PolicySampleOpts {
  /** True when ONLY the L2 probe failed while :1080 and :8080 both answer. */
  transportOnlyFailure: boolean;
  /** True when a tracked OpenCode request succeeded within the window. */
  recentTrafficOk: boolean;
  /** True while the network-change (G) sequence owns the outcome. */
  reconnecting: boolean;
  /** True while the state-machine recovery is actively running. */
  recovering: boolean;
}

/**
 * Fold one transport tick into the policy. Pure. Never throws.
 * While reconnecting/recovering, strikes still accrue (a genuinely dead proxy
 * must still confirm) but the down-notification is suppressed — the sequence
 * owns user messaging until it settles.
 */
export function nextPolicy(
  prev: PolicyState,
  tick: TransportTick,
  nowMs: number,
  cfg: PolicyConfig,
  opts: PolicySampleOpts,
): { state: PolicyState; events: PolicyEvent[] } {
  const threshold = Math.max(2, Math.floor(cfg.failureThreshold));
  if (tick === 'ok') {
    return { state: { strikes: 0, confirmedDownSinceMs: null, notifiedDown: false, verdict: 'READY' }, events: [] };
  }
  // OpenCode itself just succeeded through this proxy: the probe, not the
  // proxy, is wrong. No strike, no recovery, DEGRADED display only.
  if (opts.transportOnlyFailure && opts.recentTrafficOk) {
    return { state: { ...prev, verdict: 'DEGRADED' }, events: [] };
  }
  const strikes = prev.strikes + 1;
  if (strikes < threshold) {
    return { state: { ...prev, strikes, verdict: 'DEGRADED' }, events: [] };
  }
  const confirmedDownSinceMs = prev.confirmedDownSinceMs ?? nowMs;
  const notifiedDown = prev.notifiedDown || opts.reconnecting || opts.recovering ? prev.notifiedDown : true;
  const events: PolicyEvent[] = !prev.notifiedDown && !opts.reconnecting && !opts.recovering ? ['notify-proxy-down'] : [];
  return { state: { strikes, confirmedDownSinceMs, notifiedDown, verdict: 'PROXY_DOWN' }, events };
}

/** Notify "recovered" only for a confirmed outage that lasted long enough. */
export function shouldNotifyRecovery(
  confirmedDownSinceMs: number | null,
  nowMs: number,
  minOutageNotifySec: number,
): { notify: boolean; downForMs: number } {
  if (confirmedDownSinceMs === null) {
    return { notify: false, downForMs: 0 };
  }
  const downForMs = Math.max(0, nowMs - confirmedDownSinceMs);
  return { notify: downForMs >= minOutageNotifySec * 1000, downForMs };
}

export type ZenVerdict = 'ZEN_OK' | 'ZEN_DEGRADED' | 'ZEN_UNREACHABLE';

export interface ZenState {
  consecutiveFailures: number;
  verdict: ZenVerdict;
}

export function emptyZen(): ZenState {
  return { consecutiveFailures: 0, verdict: 'ZEN_OK' };
}

/** Zen tracking: 1st–2nd fail DEGRADED, >=3 UNREACHABLE, success resets. Pure. */
export function nextZen(prev: ZenState, ok: boolean, unreachableThreshold = 3): ZenState {
  if (ok) {
    return { consecutiveFailures: 0, verdict: 'ZEN_OK' };
  }
  const consecutiveFailures = prev.consecutiveFailures + 1;
  return {
    consecutiveFailures,
    verdict: consecutiveFailures >= Math.max(2, unreachableThreshold) ? 'ZEN_UNREACHABLE' : 'ZEN_DEGRADED',
  };
}

/** Minimal tracked-traffic evidence (mapped from RequestSummary by caller). */
export interface TrafficEvidence {
  lastSuccessAtMs: number | null;
  lastFailureAtMs: number | null;
}

/** True when OpenCode demonstrably succeeded recently with no newer failure. */
export function hasRecentTrafficOk(ev: TrafficEvidence, nowMs: number, windowMs: number): boolean {
  if (ev.lastSuccessAtMs === null || nowMs - ev.lastSuccessAtMs > windowMs) {
    return false;
  }
  return ev.lastFailureAtMs === null || ev.lastSuccessAtMs > ev.lastFailureAtMs;
}

// ---------------------------------------------------------------------------
// Auto-recovery cadence (pure)
// ---------------------------------------------------------------------------

/**
 * Decide whether the automatic direct recovery may run now (bug fix: the old
 * caller used a hard attempt ceiling, so after N failed recoveries the proxy
 * stayed down FOREVER on a later transient outage until manual intervention —
 * e.g. three failures during a captive-portal session, then the network heals
 * and nothing ever recovers it).
 *
 * Replacement policy — bounded rapid attempts, then a slow cadence, forever:
 *   - The first `maxRapidAttempts` attempts run at most one per cooldown.
 *   - After that, attempts are still allowed but at least `steadyCadenceMs`
 *     apart (default 5 min): a long outage keeps trying periodically instead
 *     of wedging, while a flapping failure can never loop hot.
 *   - Any confirmed recovery (caller resets state) starts a fresh budget.
 */
export interface RecoveryCadenceConfig {
  maxRapidAttempts: number;
  cooldownMs: number;
  steadyCadenceMs: number;
}

export const DEFAULT_RECOVERY_CADENCE: RecoveryCadenceConfig = {
  maxRapidAttempts: 3,
  cooldownMs: 60_000,
  steadyCadenceMs: 300_000,
};

export interface RecoveryCadenceState {
  /** Failed recovery runs since the last success/confirmation reset. */
  failedAttempts: number;
  /** Epoch ms of the last recovery start (0 = never). */
  lastAttemptMs: number;
}

export function emptyRecoveryCadence(): RecoveryCadenceState {
  return { failedAttempts: 0, lastAttemptMs: 0 };
}

export type RecoveryCadenceDecision =
  | { allowed: true }
  | { allowed: false; reason: string };

export function nextRecoveryCadence(
  st: RecoveryCadenceState,
  nowMs: number,
  cfg: RecoveryCadenceConfig,
): RecoveryCadenceDecision {
  const rapid = Math.max(1, Math.floor(cfg.maxRapidAttempts));
  const cooldown = Math.max(0, cfg.cooldownMs);
  const steady = Math.max(cooldown, cfg.steadyCadenceMs);
  const gapNeeded = st.failedAttempts < rapid ? cooldown : steady;
  if (st.lastAttemptMs > 0 && nowMs - st.lastAttemptMs < gapNeeded) {
    const waitS = Math.ceil((gapNeeded - (nowMs - st.lastAttemptMs)) / 1000);
    return {
      allowed: false,
      reason:
        st.failedAttempts < rapid
          ? `cooling down: next recovery attempt in ${waitS}s`
          : `recovery budget spent; steady-state retry every ${Math.round(steady / 1000)}s (next in ${waitS}s)`,
    };
  }
  return { allowed: true };
}

/**
 * Single-flight gate for health-check cycles: exactly one active probe.
 * tryEnter() returns false while held — the caller must skip (auto poll) or
 * await the in-flight promise (manual refresh), never start a second probe.
 */
export function createProbeGate(): { tryEnter(): boolean; exit(): void; readonly active: boolean } {
  let held = false;
  return {
    tryEnter(): boolean {
      if (held) {
        return false;
      }
      held = true;
      return true;
    },
    exit(): void {
      held = false;
    },
    get active(): boolean {
      return held;
    },
  };
}
