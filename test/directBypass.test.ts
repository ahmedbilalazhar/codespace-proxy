/**
 * Verifies the refcounted proxy-bypass in src/awsNet.ts (bug fix): two
 * overlapping direct fetches must not restore proxy env vars over each other.
 * Regression for: request B's per-call restore resurrecting HTTP_PROXY while
 * request A (the "direct, proxy-bypassed" lookup) was still in flight.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import { fetchDirectUrl } from '../src/awsNet';

describe('fetchDirectUrl concurrent bypass (refcount)', () => {
  it('a second overlapping direct fetch never sees proxy env restored mid-flight', async () => {
    const prevHttp = process.env.HTTP_PROXY;
    process.env.HTTP_PROXY = 'http://127.0.0.1:8080';

    // Request A: a server that answers only after we release it, so A is
    // provably in flight while B starts and settles.
    let released = false;
    const server = net.createServer((s) => {
      s.on('error', () => {
        /* ignore */
      });
      const wait = setInterval(() => {
        if (released) {
          clearInterval(wait);
          const body = '9.9.9.9';
          s.end(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
        }
      }, 10);
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const portA = (server.address() as net.AddressInfo).port;

    try {
      const pA = fetchDirectUrl(`http://127.0.0.1:${portA}/`, 5000);
      await new Promise((r) => setTimeout(r, 30));
      assert.equal(process.env.HTTP_PROXY, undefined, 'A must hold the bypass');

      // Request B fails fast (connection refused) while A is still in flight.
      const pB = fetchDirectUrl('http://127.0.0.1:1/', 500).catch(() => 'failed');
      await new Promise((r) => setTimeout(r, 30));
      const bResult = await pB;
      assert.equal(bResult, 'failed');
      assert.equal(
        process.env.HTTP_PROXY,
        undefined,
        'B settling must NOT resurrect proxy env while A is in flight (the old per-request snapshot race)',
      );

      released = true;
      const aResult = await pA;
      assert.equal(aResult, '9.9.9.9');

      // After BOTH requests settle, the original env is restored exactly once.
      assert.equal(process.env.HTTP_PROXY, 'http://127.0.0.1:8080');
    } finally {
      server.close();
      if (prevHttp === undefined) {
        delete process.env.HTTP_PROXY;
        delete process.env.http_proxy;
      } else {
        process.env.HTTP_PROXY = prevHttp;
      }
    }
  });
});
