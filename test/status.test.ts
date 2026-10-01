/**
 * Tests for src/status.ts — the full presentation matrix is pure and pinned.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DisplayState,
  NO_TRACKING,
  RequestSummary,
  barText,
  overlayRequest,
  presentDisplay,
} from '../src/status';

const FAILED: RequestSummary = {
  trackingInUse: true,
  activeCount: 0,
  oldestActiveModel: null,
  oldestActiveSinceMs: null,
  lastFailureAtMs: 1_000,
  lastFailureReason: 'exit code 1',
  lastSuccessAtMs: null,
};

describe('overlayRequest', () => {
  it('chain failure takes precedence over request info', () => {
    const running: RequestSummary = { ...NO_TRACKING, trackingInUse: true, activeCount: 2 };
    assert.equal(overlayRequest('SSH_DOWN', running, 0), 'SSH_DOWN');
    assert.equal(overlayRequest('ZEN_UNREACHABLE', FAILED, 0), 'ZEN_UNREACHABLE');
  });

  it('active tracked request -> REQUEST_RUNNING', () => {
    const running: RequestSummary = {
      ...NO_TRACKING,
      trackingInUse: true,
      activeCount: 1,
      oldestActiveModel: 'muse-spark-1.3-contributor-free',
    };
    assert.equal(overlayRequest('HEALTHY', running, 0), 'REQUEST_RUNNING');
  });

  it('failed tracked request -> REQUEST_FAILED', () => {
    assert.equal(overlayRequest('HEALTHY', FAILED, 0), 'REQUEST_FAILED');
  });

  it('a newer success clears the failure', () => {
    const s: RequestSummary = { ...FAILED, lastSuccessAtMs: 2_000 };
    assert.equal(overlayRequest('HEALTHY', s, 0), 'HEALTHY');
  });

  it('manual clear suppresses only failures up to the clear time', () => {
    assert.equal(overlayRequest('HEALTHY', FAILED, 1_000), 'HEALTHY');
    const newer: RequestSummary = { ...FAILED, lastFailureAtMs: 3_000 };
    assert.equal(overlayRequest('HEALTHY', newer, 1_000), 'REQUEST_FAILED');
  });

  it('no tracker -> overlay inert, never fabricates request state', () => {
    assert.equal(overlayRequest('HEALTHY', NO_TRACKING, 0), 'HEALTHY');
    assert.equal(overlayRequest('STARTING', NO_TRACKING, 0), 'STARTING');
  });
});

describe('presentDisplay', () => {
  it('every state has a distinct, non-empty text and label', () => {
    const states = [
      'STARTING',
      'HEALTHY',
      'REQUEST_RUNNING',
      'REQUEST_FAILED',
      'SSH_DOWN',
      'SOCKS_DOWN',
      'HTTP_BRIDGE_DOWN',
      'PROXY_FAILED',
      'ZEN_UNREACHABLE',
      'MODEL_UNAVAILABLE',
      'UNKNOWN',
      'DEGRADED',
      'RECONNECTING',
      'PROXY_DOWN',
      'RECOVERING',
      'ZEN_DEGRADED',
    ] as const;
    const texts = new Set<string>();
    for (const s of states) {
      const v = presentDisplay(s, { activeCount: 2 });
      assert.ok(v.text.length > 0, s);
      assert.ok(/^\$\([a-z~-]+\)$/.test(v.icon), `${s} needs a codicon, got ${v.icon}`);
      assert.ok(v.accessLabel.length > 10, `${s} needs a real accessibility label`);
      assert.ok(['normal', 'warning', 'error'].includes(v.level), s);
      assert.ok(!texts.has(v.text), `${s} text must be distinct`);
      texts.add(v.text);
    }
  });

  it('icon variants map to the shape-first set', () => {
    const expected: Record<DisplayState, string> = {
      OFF: '$(debug-stop)',
      STARTING: '$(sync~spin)',
      HEALTHY: '$(check)',
      REQUEST_RUNNING: '$(play)',
      REQUEST_FAILED: '$(error)',
      SSH_DOWN: '$(debug-disconnect)',
      SOCKS_DOWN: '$(plug)',
      HTTP_BRIDGE_DOWN: '$(arrow-swap)',
      PROXY_FAILED: '$(cloud)',
      ZEN_UNREACHABLE: '$(globe)',
      MODEL_UNAVAILABLE: '$(error)',
      UNKNOWN: '$(question)',
      AWS_SSH_UNREACHABLE: '$(globe)',
      SG_REPAIRING: '$(sync~spin)',
      SOCKS_STARTING: '$(sync~spin)',
      HTTP_STARTING: '$(sync~spin)',
      RECOVERY_FAILED: '$(error)',
      DEGRADED: '$(alert)',
      RECONNECTING: '$(sync~spin)',
      PROXY_DOWN: '$(cloud)',
      RECOVERING: '$(sync~spin)',
      ZEN_DEGRADED: '$(globe)',
    };
    for (const [s, icon] of Object.entries(expected) as [DisplayState, string][]) {
      assert.equal(presentDisplay(s, { activeCount: 2 }).icon, icon, s);
    }
    assert.equal(presentDisplay('HEALTHY', { slow: true }).icon, '$(watch)');
  });

  it('barText resolves icon vs text style', () => {
    const v = presentDisplay('HEALTHY');
    assert.equal(barText(v, 'icon'), '$(check)');
    assert.equal(barText(v, 'text'), v.text);
    assert.match(barText(v, 'text'), /Muse: Ready/);
  });

  it('no color emoji anywhere in presentation output', () => {
    // Pictographs, symbols, dingbats, geometric shapes, arrows supplement, VS16.
    const emoji = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{25A0}-\u{25FF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;
    const states = [
      'STARTING', 'HEALTHY', 'REQUEST_RUNNING', 'REQUEST_FAILED', 'SSH_DOWN',
      'SOCKS_DOWN', 'HTTP_BRIDGE_DOWN', 'PROXY_FAILED', 'ZEN_UNREACHABLE',
      'MODEL_UNAVAILABLE', 'UNKNOWN', 'DEGRADED', 'RECONNECTING', 'PROXY_DOWN',
      'RECOVERING', 'ZEN_DEGRADED',
    ] as const;
    for (const s of states) {
      for (const view of [presentDisplay(s, { activeCount: 2 }), presentDisplay(s, { slow: true })]) {
        assert.ok(!emoji.test(view.text), `${s} text must be emoji-free: ${view.text}`);
        assert.ok(!emoji.test(view.accessLabel), `${s} label must be emoji-free`);
      }
    }
  });

  it('slow overlay only affects HEALTHY', () => {
    assert.equal(presentDisplay('HEALTHY', { slow: true }).level, 'warning');
    assert.match(presentDisplay('HEALTHY', { slow: true }).text, /SLOW/);
    assert.match(presentDisplay('HEALTHY').text, /Muse: Ready/);
  });

  it('running count is shown and honest (min 1)', () => {
    assert.match(presentDisplay('REQUEST_RUNNING', { activeCount: 3 }).text, /\(3\)/);
    assert.match(presentDisplay('REQUEST_RUNNING', { activeCount: 3 }).accessLabel, /3 tracked/);
  });

  it('errors use error level, unknown uses warning (never color-only)', () => {
    for (const s of ['SSH_DOWN', 'SOCKS_DOWN', 'HTTP_BRIDGE_DOWN', 'PROXY_FAILED', 'ZEN_UNREACHABLE', 'MODEL_UNAVAILABLE', 'REQUEST_FAILED', 'PROXY_DOWN'] as const) {
      assert.equal(presentDisplay(s).level, 'error', s);
    }
    assert.equal(presentDisplay('UNKNOWN').level, 'warning');
  });

  it('transients are warning/normal, never error (no alarm fatigue)', () => {
    assert.equal(presentDisplay('DEGRADED').level, 'warning');
    assert.equal(presentDisplay('ZEN_DEGRADED').level, 'warning');
    assert.equal(presentDisplay('RECONNECTING').level, 'normal');
    assert.equal(presentDisplay('RECOVERING').level, 'normal');
  });
});
