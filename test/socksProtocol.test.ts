import { it } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'net';
import { fetchViaSocks5, probeSocksTunnel } from '../src/socks';

async function serverTest(handler: (s: net.Socket) => void, work: (port: number) => Promise<void>) {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); handler(s); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try { await work((server.address() as net.AddressInfo).port); }
  finally { for (const s of sockets) s.destroy(); await new Promise<void>((r) => server.close(() => r())); }
}

it('SOCKS handles combined CONNECT header/address bytes without discarding them', async () => {
  await serverTest((s) => {
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', () => {
        s.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]));
        s.once('data', () => s.end('HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n16.192.228.28'));
      });
    });
  }, async (p) => assert.equal(await fetchViaSocks5('127.0.0.1', p, 'echo.test', 80, '/', 1000), '16.192.228.28'));
});

it('timeout waiting for a CONNECT reply is never proof of connectivity', async () => {
  await serverTest((s) => s.once('data', () => s.write(Buffer.from([5, 0]))), async (p) => {
    const result = await probeSocksTunnel('127.0.0.1', p, 40);
    assert.equal(result.connected, false);
  });
});

it('a confirmed CONNECT followed by an echo error preserves connectivity evidence', async () => {
  await serverTest((s) => {
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', () => {
        s.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]));
        s.once('data', () => s.end('HTTP/1.1 503 Unavailable\r\nConnection: close\r\n\r\ndown'));
      });
    });
  }, async (p) => {
    const result = await probeSocksTunnel('127.0.0.1', p, 500);
    assert.equal(result.connected, true);
    assert.equal(result.ip, null);
  });
});

it('SOCKS HTTP echoes decode chunked response bodies', async () => {
  await serverTest((s) => {
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', () => {
        s.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]));
        s.once('data', () => s.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n6\r\n16.192\r\n7\r\n.228.28\r\n0\r\n\r\n'));
      });
    });
  }, async (p) => assert.equal(await fetchViaSocks5('127.0.0.1', p, 'echo.test', 80, '/', 1000), '16.192.228.28'));
});

it('SOCKS content-length echoes complete without waiting for TCP close', async () => {
  await serverTest((s) => {
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', () => {
        s.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]));
        s.once('data', () => s.write('HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n16.192.228.28'));
      });
    });
  }, async (p) => assert.equal(await fetchViaSocks5('127.0.0.1', p, 'echo.test', 80, '/', 1000), '16.192.228.28'));
});
