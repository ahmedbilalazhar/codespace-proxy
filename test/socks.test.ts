/**
 * Tests for src/socks.ts — SOCKS5 end-to-end verification (no network needed).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SOCKS_E2E_TARGETS, verifySocksEgressIp } from '../src/socks';

describe('SOCKS_E2E_TARGETS', () => {
  it('uses plain-HTTP echo services (no TLS through SOCKS needed)', () => {
    assert.ok(SOCKS_E2E_TARGETS.length >= 2);
    for (const t of SOCKS_E2E_TARGETS) {
      assert.ok(t.url.startsWith('http://'), t.url);
      assert.equal(t.port, 80);
    }
  });
});

describe('verifySocksEgressIp', () => {
  it('match -> ok', () => {
    const r = verifySocksEgressIp('16.192.228.28', '16.192.228.28');
    assert.equal(r.ok, true);
    assert.match(r.detail, /matches expected/);
  });
  it('mismatch -> not ok, never reported as healthy', () => {
    const r = verifySocksEgressIp('1.2.3.4', '16.192.228.28');
    assert.equal(r.ok, false);
    assert.match(r.detail, /1\.2\.3\.4/);
  });
  it('non-IP body -> not ok (captive portal can never pass)', () => {
    const r = verifySocksEgressIp('<html>captive</html>', '16.192.228.28');
    assert.equal(r.ok, false);
    assert.match(r.detail, /non-IP/);
  });
  it('empty expectation skips comparison but still requires plausible IP', () => {
    assert.equal(verifySocksEgressIp('9.9.9.9', '').ok, true);
    assert.equal(verifySocksEgressIp('not-an-ip!!', '').ok, false);
  });
});
