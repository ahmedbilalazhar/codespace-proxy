/**
 * status.ts — pure status-bar presentation logic (no vscode dependency).
 *
 * The status bar shows an ICON ONLY, and the icon system is SHAPE-FIRST:
 * state must be legible with zero color perception (no red/green reliance,
 * no color-emoji anywhere). Severity backgrounds are not used. Each glyph was
 * chosen for its shape meaning:
 *
 *   $(sync~spin)       starting / reconnecting  (motion = working on it)
 *   $(check)           healthy                  (tick = good)
 *   $(watch)           healthy but slow         (clock = waiting on network)
 *   $(play)            tracked request running  (triangle = running)
 *   $(error)           request failed / model missing (cross = failed)
 *   $(debug-disconnect) SSH tunnel process gone (pulled plug)
 *   $(plug)            SOCKS port refused (connector with nowhere to go)
 *   $(arrow-swap)      HTTP bridge handoff broken
 *   $(cloud)           traffic to the cloud fails
 *   $(globe)           remote Zen host unreachable
 *   $(question)        unknown                  (? = unknown, never guessed)
 *
 * Full text lives in the tooltip, the accessibility label, notifications, and
 * the dashboard. Set `opencodeProxyHealth.statusStyle` to "text" for a text
 * item instead (also color-emoji free).
 *
 * The chain health (HealthState) is overlaid with honestly-tracked request
 * information. REQUEST_RUNNING / REQUEST_FAILED are *display* states that only
 * ever appear when the opt-in request tracker (see requests.ts) has first-hand
 * evidence: a lockfile written by scripts/Invoke-TrackedOpencode.ps1.
 * Without the tracker, the overlay is inert and the base state shows.
 */

import type { HealthState } from './health';

export type StatusLevel = 'normal' | 'warning' | 'error';

/**
 * Display states: the chain states plus recovery-machine states plus two
 * request overlays.
 *
 * Recovery states (AWS_SSH_UNREACHABLE, SG_REPAIRING, SOCKS_STARTING,
 * HTTP_STARTING, RECOVERY_FAILED) come from src/recoveryMachine.ts and let the
 * user tell "SSH process missing" apart from "AWS SSH unreachable" apart from
 * "SG being repaired" apart from "SSH reconnecting / SOCKS starting" apart
 * from "HTTP proxy starting" apart from "Proxy ready" — never claiming
 * "ssh.exe is running, therefore SOCKS is healthy".
 */
export type RecoveryDisplayState =
  | 'AWS_SSH_UNREACHABLE'
  | 'SG_REPAIRING'
  | 'SOCKS_STARTING'
  | 'HTTP_STARTING'
  | 'RECOVERY_FAILED';

/**
 * Confirmed-health display states (see src/healthPolicy.ts).
 * DEGRADED = 1..N-1 consecutive failures (transient, status bar only, never
 * notify, never recover). PROXY_DOWN = confirmed after the threshold (notify
 * once, recovery allowed). RECONNECTING = attributed network change owning
 * the outcome. RECOVERING = state machine running. ZEN_DEGRADED = service
 * signal only, never proxy health.
 */
export type ConfirmedDisplayState =
  | 'DEGRADED'
  | 'RECONNECTING'
  | 'PROXY_DOWN'
  | 'RECOVERING'
  | 'ZEN_DEGRADED';

/** Display states: chain + recovery + confirmed-health states + request overlays. */
export type DisplayState =
  | 'OFF'
  | HealthState
  | RecoveryDisplayState
  | ConfirmedDisplayState
  | 'REQUEST_RUNNING'
  | 'REQUEST_FAILED';

/** Status-bar style: icon-only glyph, or the full text item. */
export type StatusStyle = 'icon' | 'text';

export interface RequestSummary {
  trackingInUse: boolean;
  activeCount: number;
  oldestActiveModel: string | null;
  /** Epoch ms when the oldest active request started (null when none active). */
  oldestActiveSinceMs: number | null;
  /** Epoch ms of the most recent request failure (crash/stale or exit != 0). */
  lastFailureAtMs: number | null;
  lastFailureReason: string | null;
  /** Epoch ms of the most recent successfully completed tracked request. */
  lastSuccessAtMs: number | null;
}

export const NO_TRACKING: RequestSummary = {
  trackingInUse: false,
  activeCount: 0,
  oldestActiveModel: null,
  oldestActiveSinceMs: null,
  lastFailureAtMs: null,
  lastFailureReason: null,
  lastSuccessAtMs: null,
};

/**
 * Overlay request evidence onto the chain state.
 * Chain failures always take precedence over request info — a dead proxy is
 * the more important fact. clearedFailureBeforeMs suppresses a known failure
 * (via the "Clear Request Failure" command) until a *newer* failure appears.
 */
export function overlayRequest(
  base: DisplayState,
  req: RequestSummary,
  clearedFailureBeforeMs: number,
): DisplayState {
  if (base !== 'HEALTHY') {
    return base;
  }
  if (req.trackingInUse && req.activeCount > 0) {
    return 'REQUEST_RUNNING';
  }
  if (
    req.trackingInUse &&
    req.lastFailureAtMs !== null &&
    req.lastFailureAtMs > clearedFailureBeforeMs &&
    (req.lastSuccessAtMs === null || req.lastFailureAtMs > req.lastSuccessAtMs)
  ) {
    return 'REQUEST_FAILED';
  }
  return base;
}

export interface StatusView {
  /** Full text, color-emoji free (tooltip, dashboard, notifications, text bar). */
  text: string;
  /** Icon-only glyph for the status bar, e.g. "$(check)". */
  icon: string;
  level: StatusLevel;
  /** Human-readable label; state is never communicated by color alone. */
  accessLabel: string;
}

/** Resolve what the status-bar item shows for a view + style. */
export function barText(view: StatusView, style: StatusStyle): string {
  return style === 'icon' ? view.icon : view.text;
}

export function presentDisplay(
  state: DisplayState,
  opts: { slow?: boolean; activeCount?: number } = {},
): StatusView {
  switch (state) {
    case 'OFF':
      return { text: 'Proxy: OFF', icon: '$(debug-stop)', accessLabel: 'Proxy off', level: 'normal' };
    case 'HEALTHY':
      return opts.slow
        ? {
            text: 'Proxy: SLOW | Muse: Ready',
            icon: '$(watch)',
            level: 'warning',
            accessLabel: 'OpenCode proxy healthy but responding slowly; the network may be sluggish',
          }
        : {
            text: 'Proxy: OK | Muse: Ready',
            icon: '$(check)',
            level: 'normal',
            accessLabel: 'OpenCode proxy healthy, Muse Spark ready',
          };
    case 'REQUEST_RUNNING': {
      const n = Math.max(1, opts.activeCount ?? 1);
      return {
        text: `Proxy: OK | Muse: Running (${n})`,
        icon: '$(play)',
        level: 'normal',
        accessLabel: `OpenCode proxy healthy, ${n} tracked OpenCode request${n === 1 ? '' : 's'} in flight`,
      };
    }
    case 'REQUEST_FAILED':
      return {
        text: 'Muse: ERROR',
        icon: '$(error)',
        level: 'error',
        accessLabel: 'OpenCode proxy healthy, but the last tracked OpenCode request failed',
      };
    case 'SSH_DOWN':
      return {
        text: 'Proxy: SSH DOWN',
        icon: '$(debug-disconnect)',
        level: 'error',
        accessLabel: 'OpenCode proxy down: SSH tunnel process missing',
      };
    case 'SOCKS_DOWN':
      return {
        text: 'Proxy: SOCKS DOWN',
        icon: '$(plug)',
        level: 'error',
        accessLabel: 'OpenCode proxy down: SOCKS5 port refused',
      };
    case 'HTTP_BRIDGE_DOWN':
      return {
        text: 'Proxy: HTTP BRIDGE DOWN',
        icon: '$(arrow-swap)',
        level: 'error',
        accessLabel: 'OpenCode proxy down: HTTP bridge port refused',
      };
    case 'PROXY_FAILED':
      return {
        text: 'Proxy: CONN FAILED',
        icon: '$(cloud)',
        level: 'error',
        accessLabel: 'OpenCode proxy down: traffic cannot pass through the bridge',
      };
    case 'ZEN_UNREACHABLE':
      return {
        text: 'Proxy: ZEN UNREACHABLE',
        icon: '$(globe)',
        level: 'error',
        accessLabel: 'OpenCode proxy up but Zen API unreachable',
      };
    case 'MODEL_UNAVAILABLE':
      return {
        text: 'Muse: UNAVAILABLE',
        icon: '$(error)',
        level: 'error',
        accessLabel: 'Zen reachable but Muse Spark model not listed',
      };
    case 'STARTING':
      return {
        text: '$(sync~spin) Proxy: Starting...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy monitor starting',
      };
    case 'AWS_SSH_UNREACHABLE':
      return {
        text: 'Proxy: AWS SSH UNREACHABLE',
        icon: '$(globe)',
        level: 'error',
        accessLabel: 'OpenCode proxy down: AWS SSH port 22 unreachable, likely public IP changed and security group blocks SSH',
      };
    case 'SG_REPAIRING':
      return {
        text: '$(sync~spin) Proxy: FIXING SG...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy: AWS security group being repaired for the current public IP',
      };
    case 'SOCKS_STARTING':
      return {
        text: '$(sync~spin) Proxy: SOCKS STARTING...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy: SSH reconnecting, SOCKS starting, verifying port 1080',
      };
    case 'HTTP_STARTING':
      return {
        text: '$(sync~spin) Proxy: HTTP STARTING...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy: HTTP proxy starting, verifying port 8080',
      };
    case 'RECOVERY_FAILED':
      return {
        text: 'Proxy: RECOVERY FAILED',
        icon: '$(error)',
        level: 'error',
        accessLabel: 'OpenCode proxy recovery failed after bounded retries, manual action needed',
      };
    case 'DEGRADED':
      return {
        text: 'Proxy: DEGRADED',
        icon: '$(alert)',
        level: 'warning',
        accessLabel: 'OpenCode proxy degraded: isolated probe failures, confirming before any action',
      };
    case 'RECONNECTING':
      return {
        text: '$(sync~spin) Proxy: RECONNECTING...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy reconnecting after a network change, verifying before any verdict',
      };
    case 'PROXY_DOWN':
      return {
        text: 'Proxy: DOWN',
        icon: '$(cloud)',
        level: 'error',
        accessLabel: 'OpenCode proxy confirmed down after consecutive failures, recovery allowed',
      };
    case 'RECOVERING':
      return {
        text: '$(sync~spin) Proxy: RECOVERING...',
        icon: '$(sync~spin)',
        level: 'normal',
        accessLabel: 'OpenCode proxy recovery running, verifying each layer',
      };
    case 'ZEN_DEGRADED':
      return {
        text: 'Muse: DEGRADED',
        icon: '$(globe)',
        level: 'warning',
        accessLabel: 'Proxy transport healthy, OpenCode Zen service degraded (service-side, not proxy health)',
      };
    case 'UNKNOWN':
    default:
      return {
        text: 'OpenCode: Unknown',
        icon: '$(question)',
        level: 'warning',
        accessLabel: 'OpenCode proxy state unknown',
      };
  }
}
