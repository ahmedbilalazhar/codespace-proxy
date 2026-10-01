/**
 * Tests for src/requests.ts — lockfile protocol assessment is fully pinned.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assessRequests,
  checkPidAlive,
  summarizeRequests,
} from '../src/requests';

const NOW = 1_700_000_000_000;

function running(id: string, pid: number, startedAgoMs: number, model: string | null = 'muse-spark-1.3-contributor-free') {
  return {
    name: `${id}.running.json`,
    content: JSON.stringify({ v: 1, id, pid, startedAtMs: NOW - startedAgoMs, model }),
  };
}

function done(id: string, exitCode: number, endedAgoMs: number) {
  return {
    name: `${id}.done.json`,
    content: JSON.stringify({
      v: 1, id, pid: 111, startedAtMs: NOW - endedAgoMs - 60_000,
      endedAtMs: NOW - endedAgoMs, exitCode, model: 'muse-spark-1.3-contributor-free',
    }),
  };
}

describe('assessRequests', () => {
  it('live pid -> active', () => {
    const a = assessRequests([running('a', 100, 5_000)], () => true, NOW);
    assert.equal(a.active.length, 1);
    assert.equal(a.stale.length, 0);
    assert.equal(a.active[0].model, 'muse-spark-1.3-contributor-free');
  });

  it('dead pid -> stale, never reported as running', () => {
    const a = assessRequests([running('a', 100, 5_000)], () => false, NOW);
    assert.equal(a.active.length, 0);
    assert.equal(a.stale.length, 1);
    assert.match(a.stale[0].reason, /gone without reporting/);
  });

  it('implausibly old running file with live pid -> stale', () => {
    const a = assessRequests([running('a', 100, 7 * 3600 * 1000)], () => true, NOW);
    assert.equal(a.active.length, 0);
    assert.equal(a.stale.length, 1);
    assert.match(a.stale[0].reason, /6h/);
  });

  it('newest done file wins', () => {
    const a = assessRequests([done('old', 0, 9_000), done('new', 1, 1_000)], () => true, NOW);
    assert.equal(a.lastDone?.id, 'new');
  });

  it('malformed files -> parseErrors, never throws', () => {
    const a = assessRequests(
      [
        { name: 'x.running.json', content: 'not json' },
        { name: 'y.running.json', content: '{"pid":"abc"}' },
        { name: 'z.done.json', content: '{"id":"z"}' },
        { name: 'ignore.txt', content: 'whatever' },
      ],
      () => true,
      NOW,
    );
    assert.equal(a.parseErrors.length, 3);
    assert.equal(a.active.length, 0);
  });

  it('tolerates a UTF-8 BOM (PowerShell Set-Content writes one)', () => {
    const a = assessRequests(
      [{ name: 'b.done.json', content: '\uFEFF' + JSON.stringify({ v: 1, id: 'b', pid: 1, startedAtMs: 1, endedAtMs: 2, exitCode: 0, model: null }) }],
      () => true,
      NOW,
    );
    assert.equal(a.parseErrors.length, 0);
    assert.equal(a.lastDone?.id, 'b');
  });

  it('active sorted oldest-first', () => {
    const a = assessRequests([running('b', 2, 1_000), running('a', 1, 9_000)], () => true, NOW);
    assert.deepEqual(a.active.map((r) => r.id), ['a', 'b']);
  });
});

describe('summarizeRequests', () => {
  it('tracking off -> inert summary', () => {
    const s = summarizeRequests(assessRequests([running('a', 1, 1_000)], () => true, NOW), false);
    assert.equal(s.trackingInUse, false);
    assert.equal(s.activeCount, 1); // raw data present…
    assert.equal(s.oldestActiveSinceMs, NOW - 1_000);
  });

  it('success recorded', () => {
    const s = summarizeRequests(assessRequests([done('d', 0, 1_000)], () => true, NOW), true);
    assert.equal(s.lastSuccessAtMs, NOW - 1_000);
    assert.equal(s.lastFailureAtMs, null);
  });

  it('non-zero exit -> failure with reason', () => {
    const s = summarizeRequests(assessRequests([done('d', 1, 1_000)], () => true, NOW), true);
    assert.equal(s.lastFailureAtMs, NOW - 1_000);
    assert.match(s.lastFailureReason ?? '', /code 1/);
  });

  it('newer success beats older failure and vice versa', () => {
    const failThenOk = summarizeRequests(
      assessRequests([done('f', 2, 9_000), done('s', 0, 1_000)], () => true, NOW), true);
    assert.ok((failThenOk.lastSuccessAtMs ?? 0) > (failThenOk.lastFailureAtMs ?? 0));
    const okThenFail = summarizeRequests(
      assessRequests([done('s', 0, 9_000), done('f', 2, 1_000)], () => true, NOW), true);
    assert.ok((okThenFail.lastFailureAtMs ?? 0) > (okThenFail.lastSuccessAtMs ?? 0));
  });

  it('stale counts as failure', () => {
    const s = summarizeRequests(assessRequests([running('a', 9, 60_000)], () => false, NOW), true);
    assert.equal(s.activeCount, 0);
    assert.equal(s.lastFailureAtMs, NOW - 60_000);
  });
});

describe('checkPidAlive (mocked exec)', () => {
  const mk = (out: string, err: Error | null = null) =>
    (_f: string, _a: string[], _o: { timeout: number }, cb: (e: Error | null, s: string) => void) =>
      cb(err, out);
  const list = '"opencode.exe","18936","Console","1","10,000 K"\r\n"ssh.exe","28184","Console","1","18,212 K"\r\n';

  it('finds pid, rejects partial matches', async () => {
    assert.equal(await checkPidAlive(18936, mk(list)), true);
    assert.equal(await checkPidAlive(1893, mk(list)), false); // must not substring-match
    assert.equal(await checkPidAlive(99999, mk(list)), false);
  });

  it('bad pid / exec failure -> false', async () => {
    assert.equal(await checkPidAlive(-1, mk(list)), false);
    assert.equal(await checkPidAlive(18936, mk('', new Error('x'))), false);
  });
});
