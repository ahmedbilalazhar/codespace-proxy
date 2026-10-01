/**
 * Tests for src/history.ts — outage bookkeeping and uptime math.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  HISTORY_WINDOW_MS,
  emptyHistory,
  formatDuration,
  sanitizeHistory,
  sparkline,
  updateHistory,
  uptimeSummary,
} from '../src/history';

const H = 3600_000;

describe('updateHistory', () => {
  it('opens one outage on failure, no duplicates while down', () => {
    const h = emptyHistory();
    updateHistory(h, false, 1000);
    updateHistory(h, false, 2000);
    assert.equal(h.outages.length, 1);
    assert.equal(h.outages[0].untilMs, null);
  });

  it('closes the outage on recovery', () => {
    const h = emptyHistory();
    updateHistory(h, false, 1000);
    updateHistory(h, true, 5000);
    assert.equal(h.outages[0].untilMs, 5000);
  });

  it('healthy samples with no outage change nothing', () => {
    const h = emptyHistory();
    updateHistory(h, true, 1000);
    assert.equal(h.outages.length, 0);
  });

  it('prunes ancient closed outages', () => {
    const h = emptyHistory();
    updateHistory(h, false, 1000);
    updateHistory(h, true, 2000);
    updateHistory(h, true, 1000 + HISTORY_WINDOW_MS + H);
    assert.equal(h.outages.length, 0);
  });
});

describe('uptimeSummary', () => {
  it('no outages -> 100%', () => {
    const s = uptimeSummary(emptyHistory(), 10_000);
    assert.equal(s.uptimePct, 100);
    assert.equal(s.outageCount, 0);
    assert.equal(s.currentDownSinceMs, null);
  });

  it('one 1h outage in 24h -> 95.8%', () => {
    const h = emptyHistory();
    const now = 100 * H;
    updateHistory(h, false, now - H);
    updateHistory(h, true, now);
    const s = uptimeSummary(h, now);
    assert.equal(s.uptimePct, 95.8);
    assert.equal(s.outageCount, 1);
    assert.equal(s.recent[0].durationMs, H);
  });

  it('ongoing outage counts up to now', () => {
    const h = emptyHistory();
    const now = 100 * H;
    updateHistory(h, false, now - 30 * 60_000);
    const s = uptimeSummary(h, now);
    assert.equal(s.currentDownSinceMs, now - 30 * 60_000);
    assert.ok(s.uptimePct < 100 && s.uptimePct > 97);
  });

  it('outage starting before the window is clipped', () => {
    const h = emptyHistory();
    const now = 100 * H;
    h.outages.push({ sinceMs: now - 48 * H, untilMs: now - 23 * H }); // 1h inside window
    const s = uptimeSummary(h, now);
    assert.equal(s.downMs, H);
  });
});

describe('sanitizeHistory / formatDuration', () => {
  it('rejects garbage, keeps valid entries', () => {
    const h = sanitizeHistory({ outages: [{ sinceMs: 1, untilMs: null }, 42, { sinceMs: 'x' }] });
    assert.equal(h.outages.length, 1);
    assert.deepEqual(sanitizeHistory(null), { outages: [] });
    assert.deepEqual(sanitizeHistory({}), { outages: [] });
  });

  it('formats durations', () => {
    assert.equal(formatDuration(5_000), '5s');
    assert.equal(formatDuration(90_000), '1m 30s');
    assert.equal(formatDuration(2 * H + 5 * 60_000), '2h 5m');
  });
});

describe('sparkline', () => {
  it('empty or invalid -> placeholder, never throws', () => {
    assert.equal(sparkline([]), '—');
    assert.equal(sparkline([NaN, Infinity] as number[]), '—');
  });

  it('scales ascending values across all levels', () => {
    assert.equal(sparkline([1, 2, 3, 4, 5, 6, 7, 8]), '▁▂▃▄▅▆▇█');
  });

  it('flat and zero series stay at the bottom', () => {
    assert.equal(sparkline([5, 5, 5]), '███');
    assert.equal(sparkline([0, 0]), '▁▁');
  });

  it('caps width to the newest samples', () => {
    const many = Array.from({ length: 30 }, (_, i) => i + 1);
    const out = sparkline(many, 20);
    assert.equal(out.length, 20);
    assert.ok(out.endsWith('█'));
  });
});
