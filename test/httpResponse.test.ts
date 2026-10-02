import { it } from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'node:net';
import { parseHttpResponse, tryParseFramedHttpResponse } from '../src/httpResponse';
import { fetchViaHttpProxy, modelIdPresentInZenBody } from '../src/health';

it('chunked model lists decode extensions and trailers before JSON parsing', () => {
  const body = '{"data":[{"id":"model-test"}]}';
  const response = `HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${Buffer.byteLength(body).toString(16)};name=value\r\n${body}\r\n0\r\nX-Checksum: example\r\n\r\n`;
  const parsed = parseHttpResponse(response);
  assert.equal(parsed.body, body);
  assert.equal(modelIdPresentInZenBody(parsed.body, 'model-test'), true);
});

it('UTF-8 split between HTTP chunks is decoded only after reconstructing bytes', () => {
  const body = Buffer.from('A€B');
  const response = Buffer.concat([
    Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n'),
    body.subarray(0, 2), Buffer.from('\r\n3\r\n'), body.subarray(2), Buffer.from('\r\n0\r\n\r\n'),
  ]);
  assert.equal(parseHttpResponse(response).body, 'A€B');
});

it('HEAD, 204, 304 and successful CONNECT do not require an advertised body', () => {
  const response = 'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n';
  assert.equal(parseHttpResponse(response, { method: 'HEAD' }).body, '');
  assert.equal(parseHttpResponse(response, { method: 'CONNECT' }).body, '');
  for (const code of [204, 304]) assert.equal(parseHttpResponse(`HTTP/1.1 ${code} Response\r\nContent-Length: 100\r\n\r\n`).body, '');
});

it('an informational response is skipped in favor of the final response', () => {
  const parsed = parseHttpResponse('HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
  assert.deepEqual(parsed, { statusCode: 200, body: 'ok' });
});

it('truncated or contradictory framing cannot appear as a successful response', () => {
  const bad = [
    'Content-Length: 20\r\n\r\nok',
    'Content-Length: 2\r\nContent-Length: 3\r\n\r\nok',
    'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    'Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n',
    'Transfer-Encoding: chunked\r\n\r\n0\r\n',
    'Transfer-Encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n',
    'Transfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n',
  ];
  for (const raw of bad) assert.throws(() => parseHttpResponse(`HTTP/1.1 200 OK\r\n${raw}`));
});

it('HTTP bridge probes decode chunked echoes across real TCP packets', async () => {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n16.192\r\n');
      // Keep the connection open: completion follows framing, not EOF.
      setImmediate(() => socket.write('7\r\n.228.28\r\n0\r\n\r\n'));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    const ip = await fetchViaHttpProxy('127.0.0.1', (server.address() as net.AddressInfo).port, 'http://echo.test/', 1000);
    assert.equal(ip, '16.192.228.28');
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

it('streaming framing waits for the exact body and rejects malformed data', () => {
  const head = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n';
  assert.equal(tryParseFramedHttpResponse(Buffer.from(head + 'o')), null);
  assert.deepEqual(tryParseFramedHttpResponse(Buffer.from(head + 'ok')), { statusCode: 200, body: 'ok' });
  assert.throws(() => tryParseFramedHttpResponse(Buffer.from(head + 'oops')), /excessive/);
  assert.equal(tryParseFramedHttpResponse(Buffer.from('HTTP/1.1 200 OK\r\n\r\nclose-delimited')), null);
  assert.equal(tryParseFramedHttpResponse(Buffer.from('HTTP/1.1 103 Early Hints\r\n\r\n')), null);
  assert.throws(() => tryParseFramedHttpResponse(Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nokXX')), /invalid HTTP chunk terminator/);
});

it('HTTP content-length echoes finish while the TCP bridge remains open', async () => {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((s) => {
    sockets.add(s); s.once('close', () => sockets.delete(s));
    s.once('data', () => s.write('HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n16.192.228.28'));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    assert.equal(await fetchViaHttpProxy('127.0.0.1', (server.address() as net.AddressInfo).port, 'http://echo.test/', 1000), '16.192.228.28');
  } finally { for (const s of sockets) s.destroy(); await new Promise<void>((r) => server.close(() => r())); }
});
