/**
 * Tests for the auto-recovery cadence (src/healthPolicy.ts) — the replacement
 * for the old hard attempt ceiling that permanently wedged recovery after N
 * failures. Required behaviours:
 *   - rapid attempts remain bounded (cooldown between them),
 *   - after the budget is spent, attempts CONTINUE on a slow steady cadence,
 *   - a success resets the budget (fresh outage = fresh rapid attempts).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_RECOVERY_CADENCE,
  RecoveryCadenceState,
  emptyRecoveryCadence,
  nextRecoveryCadence,
} from '../src/healthPolicy';

const CFG = { maxRapidAttempts: 3, cooldownMs: 60_000, steadyCadenceMs: 300_000 };

describe('nextRecoveryCadence', () => {
  it('first attempt is always allowed', () => {
    assert.deepEqual(nextRecoveryCadence(emptyRecoveryCadence(), 1000, CFG), { allowed: true });
  });

  it('rapid attempts are bounded by the cooldown window', () => {
    let st: RecoveryCadenceState = { failedAttempts: 0, lastAttemptMs: 1000 };
    const blocked = nextRecoveryCadence(st, 1000 + 30_000, CFG);
    assert.equal(blocked.allowed, false);
    const allowed = nextRecoveryCadence(st, 1000 + 61_000, CFG);
    assert.equal(allowed.allowed, true);
  });

  it('after the rapid budget, the steady cadence gates instead of a permanent stop', () => {
    const st: RecoveryCadenceState = { failedAttempts: 3, lastAttemptMs: 1000 };
    const soon = nextRecoveryCadence(st, 1000 + 120_000, CFG);
    assert.equal(soon.allowed, false, 'must not retry hot right after the budget');
    assert.match(soon.allowed ? '' : soon.reason, /steady|budget/i);
    const later = nextRecoveryCadence(st, 1000 + 301_000, CFG);
    assert.equal(later.allowed, true, 'steady-state retry must eventually run');
  });

  it('far-future timestamps still allow (no overflow wedge)', () => {
    const st: RecoveryCadenceState = { failedAttempts: 9, lastAttemptMs: 1 };
    assert.equal(nextRecoveryCadence(st, 400_000, CFG).allowed, true);
  });

  it('defaults are sane (rapid=3, steady=5min)', () => {
    assert.equal(DEFAULT_RECOVERY_CADENCE.maxRapidAttempts, 3);
    assert.equal(DEFAULT_RECOVERY_CADENCE.steadyCadenceMs, 300_000);
  });
});
