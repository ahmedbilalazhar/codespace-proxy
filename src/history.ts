/**
 * history.ts — persistent uptime/outage history. Pure functions; the extension
 * persists the JSON blob in globalState. Survives reloads for "persistent
 * visibility" into tunnels that die overnight.
 */

export interface Outage {
  sinceMs: number;
  /** null while the outage is ongoing. */
  untilMs: number | null;
}

export interface HealthHistory {
  outages: Outage[];
}

export const HISTORY_WINDOW_MS = 24 * 3600 * 1000;
const MAX_OUTAGES = 200;

export function emptyHistory(): HealthHistory {
  return { outages: [] };
}

export function sanitizeHistory(x: unknown): HealthHistory {
  if (typeof x !== 'object' || x === null || !Array.isArray((x as { outages?: unknown }).outages)) {
    return emptyHistory();
  }
  const outages: Outage[] = [];
  for (const o of (x as { outages: unknown[] }).outages) {
    if (typeof o !== 'object' || o === null) {
      continue;
    }
    const rec = o as Record<string, unknown>;
    if (typeof rec.sinceMs !== 'number' || !Number.isFinite(rec.sinceMs)) {
      continue;
    }
    const untilMs = rec.untilMs === null || rec.untilMs === undefined ? null : rec.untilMs;
    if (untilMs !== null && (typeof untilMs !== 'number' || !Number.isFinite(untilMs))) {
      continue;
    }
    outages.push({ sinceMs: rec.sinceMs, untilMs });
  }
  return { outages: outages.slice(-MAX_OUTAGES) };
}

/** Fold one sample into the history. Opens an outage on failure, closes on health. */
export function updateHistory(h: HealthHistory, healthy: boolean, nowMs: number): HealthHistory {
  const open = h.outages.find((o) => o.untilMs === null);
  if (healthy) {
    if (open) {
      open.untilMs = nowMs;
    }
  } else if (!open) {
    h.outages.push({ sinceMs: nowMs, untilMs: null });
  }
  // Prune outages fully outside the window; cap length.
  const cutoff = nowMs - HISTORY_WINDOW_MS;
  h.outages = h.outages.filter((o) => o.untilMs === null || o.untilMs >= cutoff).slice(-MAX_OUTAGES);
  return h;
}

export interface OutageView {
  sinceMs: number;
  untilMs: number | null;
  durationMs: number;
}

export interface UptimeSummary {
  windowMs: number;
  downMs: number;
  uptimePct: number;
  outageCount: number;
  currentDownSinceMs: number | null;
  recent: OutageView[];
}

/** Clip outages to the window and compute uptime. Pure. */
export function uptimeSummary(h: HealthHistory, nowMs: number, windowMs = HISTORY_WINDOW_MS): UptimeSummary {
  const start = nowMs - windowMs;
  let downMs = 0;
  const recent: OutageView[] = [];
  let currentDownSinceMs: number | null = null;
  for (const o of h.outages) {
    const end = o.untilMs ?? nowMs;
    if (end < start) {
      continue;
    }
    if (o.untilMs === null) {
      currentDownSinceMs = o.sinceMs;
    }
    const clippedSince = Math.max(o.sinceMs, start);
    downMs += Math.max(0, end - clippedSince);
    recent.push({ sinceMs: o.sinceMs, untilMs: o.untilMs, durationMs: end - o.sinceMs });
  }
  recent.sort((a, b) => b.sinceMs - a.sinceMs);
  const uptimePct = Math.round(((windowMs - Math.min(downMs, windowMs)) / windowMs) * 1000) / 10;
  return {
    windowMs,
    downMs,
    uptimePct,
    outageCount: recent.length,
    currentDownSinceMs,
    recent: recent.slice(0, 5),
  };
}

export function formatDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) {
    return `${s}s`;
  }
  const m = Math.floor(s / 60);
  if (m < 60) {
    return `${m}m ${s % 60}s`;
  }
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

const SPARK_LEVELS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/**
 * Text sparkline of recent check durations (monochrome block elements,
 * relative scale). Empty history renders as '—', never throws.
 */
export function sparkline(samples: number[], width = 20): string {
  const data = samples.filter((v) => typeof v === 'number' && Number.isFinite(v)).slice(-Math.max(1, width));
  if (data.length === 0) {
    return '—';
  }
  const max = Math.max(...data);
  if (max <= 0) {
    return data.map(() => SPARK_LEVELS[0]).join('');
  }
  return data
    .map((v) => SPARK_LEVELS[Math.min(SPARK_LEVELS.length - 1, Math.floor((Math.max(0, v) / max) * (SPARK_LEVELS.length - 1)))])
    .join('');
}
