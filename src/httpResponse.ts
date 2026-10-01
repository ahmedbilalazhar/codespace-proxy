/** Complete HTTP/1.x responses used by the bounded health probes. */
export interface ParsedHttpResponse { statusCode: number; body: string; }
const MAX_BODY_BYTES = 4 * 1024 * 1024;

function decodeChunked(body: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  let total = 0;
  for (;;) {
    const lineEnd = body.indexOf('\r\n', offset);
    if (lineEnd < 0) throw new Error('incomplete HTTP chunk size');
    const line = body.subarray(offset, lineEnd).toString('ascii');
    if (!/^[0-9a-f]+(?:;[^\r\n]*)?$/i.test(line)) throw new Error('invalid HTTP chunk size');
    const size = Number.parseInt(line.split(';')[0], 16);
    if (!Number.isSafeInteger(size) || size > MAX_BODY_BYTES - total) throw new Error('HTTP response exceeded size limit');
    offset = lineEnd + 2;
    if (size === 0) {
      // Even an empty trailer section must end with CRLF.
      if (body.subarray(offset, offset + 2).toString('ascii') === '\r\n') return Buffer.concat(chunks, total);
      const trailerEnd = body.indexOf('\r\n\r\n', offset);
      if (trailerEnd < 0) throw new Error('incomplete HTTP chunk trailers');
      const trailers = body.subarray(offset, trailerEnd).toString('latin1').split('\r\n');
      if (trailers.some((line) => !/^[!#$%&'*+.^_`|~0-9a-z-]+:/i.test(line))) throw new Error('invalid HTTP chunk trailer');
      return Buffer.concat(chunks, total);
    }
    if (offset + size + 2 > body.length || body.subarray(offset + size, offset + size + 2).toString('ascii') !== '\r\n') {
      throw new Error('incomplete HTTP chunk data');
    }
    chunks.push(body.subarray(offset, offset + size));
    total += size;
    offset += size + 2;
  }
}

/** Decode framing before UTF-8 so TCP splits cannot corrupt text/chunk sizes. */
export function parseHttpResponse(raw: string | Buffer, options: { method?: string; headersOnly?: boolean } = {}): ParsedHttpResponse {
  const bytes = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : raw;
  let offset = 0;
  for (;;) {
    const sep = bytes.indexOf('\r\n\r\n', offset);
    if (sep < 0) throw new Error('incomplete HTTP response (no header terminator)');
    if (sep - offset > 64 * 1024) throw new Error('HTTP response headers exceeded size limit');
    const lines = bytes.subarray(offset, sep).toString('latin1').split('\r\n');
    const status = lines.shift() ?? '';
    const match = /^HTTP\/1\.[01]\s+(\d{3})(?:\s|$)/.exec(status);
    const statusCode = match ? Number(match[1]) : 0;
    if (statusCode < 100 || statusCode > 599) throw new Error(`unparseable HTTP status line: ${status.slice(0, 80)}`);
    if (statusCode === 101) throw new Error('unexpected HTTP protocol upgrade');
    if (statusCode < 200) { offset = sep + 4; continue; }

    const headers = new Map<string, string[]>();
    for (const line of lines) {
      const colon = line.indexOf(':');
      if (colon <= 0 || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(line.slice(0, colon))) throw new Error('invalid HTTP response header');
      const name = line.slice(0, colon).toLowerCase();
      headers.set(name, [...(headers.get(name) ?? []), line.slice(colon + 1).trim()]);
    }
    const method = options.method?.toUpperCase();
    // CONNECT negotiation inspects status before the error body arrives.
    if (options.headersOnly || method === 'HEAD' || statusCode === 204 || statusCode === 304 || (method === 'CONNECT' && statusCode >= 200 && statusCode < 300)) {
      return { statusCode, body: '' };
    }
    let body = bytes.subarray(sep + 4);
    if (body.length > MAX_BODY_BYTES) throw new Error('HTTP response exceeded size limit');
    const transfer = headers.get('transfer-encoding');
    const lengths = headers.get('content-length');
    if (transfer && lengths) throw new Error('ambiguous HTTP response framing');
    if (transfer) {
      const codings = transfer.join(',').split(',').map((s) => s.trim().toLowerCase());
      if (codings.length !== 1 || codings[0] !== 'chunked') throw new Error('unsupported HTTP transfer encoding');
      body = decodeChunked(body);
    } else if (lengths) {
      const values = lengths.flatMap((s) => s.split(',').map((v) => v.trim()));
      if (values.some((v) => !/^\d+$/.test(v)) || !values.every((v) => Number(v) === Number(values[0]))) throw new Error('invalid HTTP content length');
      const length = Number(values[0]);
      if (!Number.isSafeInteger(length) || length > MAX_BODY_BYTES) throw new Error('HTTP response exceeded size limit');
      if (body.length !== length) throw new Error('incomplete or excessive HTTP response body');
    }
    return { statusCode, body: body.toString('utf8') };
  }
}
