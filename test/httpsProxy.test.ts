import { it } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { fetchHttpsViaProxy } from '../src/health';

// Use a real CONNECT bridge and an injected TLS stream to test HTTP framing
// without adding a certificate library or changing production TLS verification.
async function throughBridge(method: string, reply: Buffer, failTls = false,
  connectReply: string[] = ['HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n']) {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.once('data', (bytes) => {
      assert.match(bytes.toString(), /^CONNECT example\.test:443 HTTP\/1\.1/);
      socket.write(connectReply[0]);
      for (const part of connectReply.slice(1)) setImmediate(() => { if (!socket.destroyed) socket.write(part); });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const tls = require('node:tls');
  const original = tls.connect;
  tls.connect = (options: any, connected: () => void) => {
    assert.equal(options.servername, 'example.test');
    assert.notEqual(options.rejectUnauthorized, false);
    const stream = Object.assign(new EventEmitter(), {
      setTimeout: () => {}, destroy: () => {},
      write: (request: string) => {
        assert.ok(request.startsWith(`${method} /models HTTP/1.1`));
        assert.ok(request.includes('Accept-Encoding: identity'));
        setImmediate(() => {
          for (let i = 0; i < reply.length; i++) stream.emit('data', reply.subarray(i, i + 1));
          stream.emit('close');
        });
      },
    });
    setImmediate(() => {
      if (failTls) stream.emit('error', new Error('certificate verification failed'));
      else connected();
    });
    return stream;
  };
  try {
    return await fetchHttpsViaProxy('127.0.0.1', (server.address() as net.AddressInfo).port,
      'https://example.test/models', method, 1000, 'application/json');
  } finally {
    tls.connect = original;
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
}

it('HTTPS probes decode chunked UTF-8 model lists after CONNECT', async () => {
  const body = Buffer.from('{"data":[{"id":"model-test","name":"€"}]}');
  const reply = Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${body.length.toString(16)}\r\n`),
    body, Buffer.from('\r\n0\r\n\r\n'),
  ]);
  const response = await throughBridge('GET', reply);
  assert.deepEqual(JSON.parse(response.body), { data: [{ id: 'model-test', name: '€' }] });
});

it('HTTPS HEAD probes succeed without the advertised GET body', async () => {
  const response = await throughBridge('HEAD', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n'));
  assert.deepEqual(response, { statusCode: 200, body: '' });
});

it('TLS errors remain failures rather than bypassing certificate checks', async () => {
  await assert.rejects(() => throughBridge('GET', Buffer.alloc(0), true), /certificate verification failed/);
});

it('CONNECT rejection preserves its HTTP status before the error body arrives', async () => {
  await assert.rejects(() => throughBridge('GET', Buffer.alloc(0), false,
    ['HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 500\r\n\r\n']), /CONNECT refused with HTTP 407/);
});

it('CONNECT accepts successful 2xx statuses after a separate informational head', async () => {
  const response = await throughBridge('HEAD', Buffer.from('HTTP/1.1 204 No Content\r\n\r\n'), false,
    ['HTTP/1.1 103 Early Hints\r\n\r\n', 'HTTP/1.1 201 Tunnel established\r\n\r\n']);
  assert.deepEqual(response, { statusCode: 204, body: '' });
});
