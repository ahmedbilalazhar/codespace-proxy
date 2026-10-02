/**
 * socks.ts — SOCKS5 end-to-end verification through 127.0.0.1:1080.
 *
 * Why this file exists:
 *   The old recovery logic treated "an ssh.exe process exists" as "the tunnel
 *   is healthy". That is false: when the AWS Security Group blocks SSH (public
 *   IP changed) the ssh.exe process lingers while 127.0.0.1:1080 is dead, and
 *   even when 1080 listens the tunnel may not forward. Health must be proven
 *   by an actual SOCKS5 request through the tunnel, independent of hpts/:8080.
 *
 * What it does (zero dependencies, Windows-compatible, pure Node):
 *   SOCKS5 handshake (no-auth) -> CONNECT <targetHost>:<targetPort> ->
 *   send a plain-HTTP GET for an IP-echo URL -> parse the body -> return the IP.
 *
 * The caller compares the observed egress IP with the expected EC2 IP
 * (the Elastic IP from src/netModel.ts). Only a match proves the tunnel
 * forwards through AWS.
 *
 * Never logs or returns secrets. Timeouts are bounded; functions never hang.
 */

import * as net from 'net';
import { isPlausibleIp } from './health';
import { parseHttpResponse, tryParseFramedHttpResponse } from './httpResponse';

export interface SocksE2EResult {
  /** Egress IP observed through the SOCKS tunnel. */
  ip: string;
  /** Target that answered (for attribution when falling back). */
  service: string;
  /** ms spent inside the SOCKS exchange. */
  elapsedMs: number;
}

export interface SocksE2EDeps {
  /** Injectable socket factory for tests (defaults to net.Socket). */
  connect?: (host: string, port: number, timeoutMs: number) => Promise<net.Socket>;
}

/** IP-echo targets tried in order over the SOCKS tunnel (plain HTTP only). */
export const SOCKS_E2E_TARGETS = [
  { host: 'api.ipify.org', port: 80, path: '/', url: 'http://api.ipify.org/' },
  { host: 'checkip.amazonaws.com', port: 80, path: '/', url: 'http://checkip.amazonaws.com/' },
];

function readExactly(socket: net.Socket, n: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out after ${timeoutMs}ms waiting for ${n} bytes from SOCKS5 proxy`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= n) {
        socket.pause();
        cleanup();
        if (buf.length > n) socket.unshift(buf.subarray(n));
        resolve(buf.subarray(0, n));
      }
    };
    const onError = (e: Error) => {
      cleanup();
      reject(e);
    };
    const onClose = () => {
      cleanup();
      reject(new Error('SOCKS5 connection closed before handshake completed'));
    };
    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.resume();
  });
}

function writeAll(socket: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Open a TCP socket to the SOCKS server with a bounded timeout.
 * Exported for reuse; never throws without an Error message.
 */
export function connectSocksServer(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
        reject(new Error(`timed out after ${timeoutMs}ms connecting to SOCKS5 ${host}:${port}`));
      }
    }, timeoutMs);
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(socket);
      }
    });
    socket.once('timeout', () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        try {
          socket.destroy();
        } catch {
          /* ignore */
        }
        reject(new Error(`timed out after ${timeoutMs}ms connecting to SOCKS5 ${host}:${port}`));
      }
    });
    socket.once('error', (e) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(e as Error);
      }
    });
    try {
      socket.connect(port, host);
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(e as Error);
      }
    }
  });
}

function encodeDomainRequest(host: string, port: number): Buffer {
  const hostBuf = Buffer.from(host, 'utf8');
  if (hostBuf.length > 255) {
    throw new Error('target hostname too long for SOCKS5');
  }
  const out = Buffer.alloc(4 + 1 + hostBuf.length + 2);
  out[0] = 0x05; // VER
  out[1] = 0x01; // CMD = CONNECT
  out[2] = 0x00; // RSV
  out[3] = 0x03; // ATYP = DOMAINNAME
  out[4] = hostBuf.length;
  hostBuf.copy(out, 5);
  out.writeUInt16BE(port, 5 + hostBuf.length);
  return out;
}

/**
 * Fetch one plain-HTTP URL through a SOCKS5 proxy.
 * Resolves with the trimmed response body; rejects with a one-line Error.
 */
class SocksExchangeError extends Error {
  constructor(message: string, public connected: boolean) { super(message); }
}

export async function fetchViaSocks5(
  socksHost: string,
  socksPort: number,
  targetHost: string,
  targetPort: number,
  httpPath: string,
  timeoutMs: number,
  deps: SocksE2EDeps = {},
): Promise<string> {
  const started = Date.now();
  const remaining = () => Math.max(1, timeoutMs - (Date.now() - started));
  const socket = deps.connect
    ? await deps.connect(socksHost, socksPort, timeoutMs)
    : await connectSocksServer(socksHost, socksPort, timeoutMs);
  let connected = false;
  socket.pause();
  try {
    // 1. Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
    await writeAll(socket, Buffer.from([0x05, 0x01, 0x00]));
    const methodReply = await readExactly(socket, 2, remaining());
    if (methodReply[0] !== 0x05 || methodReply[1] !== 0x00) {
      throw new Error(
        `SOCKS5 handshake refused (ver=${methodReply[0]} method=${methodReply[1]}; expected ver=5 method=0)`,
      );
    }
    // 2. CONNECT request (domain form so no local DNS is needed).
    await writeAll(socket, encodeDomainRequest(targetHost, targetPort));
    const connReplyHead = await readExactly(socket, 4, remaining());
    if (connReplyHead[0] !== 0x05) {
      throw new Error(`bad SOCKS5 CONNECT reply version ${connReplyHead[0]}`);
    }
    if (connReplyHead[1] !== 0x00) {
      throw new Error(`SOCKS5 CONNECT failed with reply code 0x${connReplyHead[1].toString(16)}`);
    }
    // Consume BND.ADDR/BND.PORT per ATYP (we do not need the values).
    const atyp = connReplyHead[3];
    if (atyp === 0x01) {
      await readExactly(socket, 4 + 2, remaining());
    } else if (atyp === 0x03) {
      const lenBuf = await readExactly(socket, 1, remaining());
      await readExactly(socket, lenBuf[0] + 2, remaining());
    } else if (atyp === 0x04) {
      await readExactly(socket, 16 + 2, remaining());
    } else {
      throw new Error(`bad SOCKS5 CONNECT address type 0x${atyp.toString(16)}`);
    }
    connected = true;
    // 3. Plain HTTP GET through the established tunnel.
    const req =
      `GET ${httpPath} HTTP/1.1\r\nHost: ${targetHost}\r\nConnection: close\r\n` +
      `User-Agent: opencode-proxy-health\r\nAccept-Encoding: identity\r\n\r\n`;
    await writeAll(socket, Buffer.from(req, 'utf8'));

    // 4. Complete framed responses immediately; otherwise wait for EOF.
    const raw: Buffer = await new Promise((resolve, reject) => {
      let acc: Buffer = Buffer.alloc(0);
      let settled = false;
      const done = (error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else if (acc.length === 0) reject(new Error('empty response through SOCKS5 tunnel'));
        else resolve(acc);
      };
      const timer = setTimeout(() => done(new Error(`timed out waiting for HTTP response through SOCKS5`)), remaining());
      socket.on('data', (c: Buffer) => {
        if (settled) return;
        acc = Buffer.concat([acc, c]);
        if (acc.length > 4 * 1024 * 1024) {
          done(new Error('response through SOCKS5 exceeded size limit'));
          return;
        }
        try { if (tryParseFramedHttpResponse(acc)) done(); }
        catch (e) { done(e as Error); }
      });
      socket.once('error', (e) => done(e as Error));
      socket.once('close', () => done());
      socket.once('end', () => done());
      socket.resume();
    });
    const parsed = parseHttpResponse(raw);
    if (parsed.statusCode !== 200) throw new Error(`echo service answered HTTP ${parsed.statusCode} through SOCKS5`);
    return parsed.body.trim();
  } catch (e) {
    throw new SocksExchangeError((e as Error).message, connected);
  } finally {
    try {
      socket.destroy();
    } catch {
      /* ignore */
    }
  }
}

/**
 * End-to-end SOCKS check: fetch the egress IP through the SOCKS tunnel and
 * verify it is plausible. Tries each echo target in order; the first plausible
 * IP wins. Rejects when nothing usable answers.
 */
export async function checkSocksEndToEnd(
  socksHost: string,
  socksPort: number,
  timeoutMs: number,
  deps: SocksE2EDeps = {},
): Promise<SocksE2EResult> {
  const started = Date.now();
  const errors: string[] = [];
  const fetchOne =
    deps.connect !== undefined
      ? async (t: { host: string; port: number; path: string; url: string }) =>
          fetchViaSocks5(socksHost, socksPort, t.host, t.port, t.path, timeoutMs, deps)
      : async (t: { host: string; port: number; path: string; url: string }) =>
          fetchViaSocks5(socksHost, socksPort, t.host, t.port, t.path, timeoutMs, deps);
  for (const t of SOCKS_E2E_TARGETS) {
    try {
      const body = (await fetchOne(t)).trim();
      if (isPlausibleIp(body)) {
        return { ip: body, service: t.url, elapsedMs: Date.now() - started };
      }
      errors.push(`${t.url} answered a non-IP body`);
    } catch (e) {
      errors.push(`${t.url}: ${(e as Error).message.split('\n')[0].slice(0, 160)}`);
    }
  }
  throw new Error(`SOCKS5 end-to-end check failed (${errors.join('; ')})`);
}

/**
 * Result of a tunnel-connectivity probe: did a SOCKS5 CONNECT through the
 * tunnel reach a real internet host, regardless of whether the echo body
 * turned out to be a plausible IP?
 */
export interface SocksProbeResult {
  /** SOCKS5 handshake + CONNECT + HTTP exchange reached a live target. */
  connected: boolean;
  /** Plausible egress IP when the echo body was usable, else null. */
  ip: string | null;
  service: string | null;
  detail: string;
}

/**
 * Classify a failed SOCKS e2e check (bug fix: recovery used to treat ANY e2e
 * failure — including an echo-service outage — as a dead tunnel, killing a
 * working ssh process and eventually reporting RECOVERY_FAILED).
 *
 * A SOCKS5 CONNECT to a stable internet host succeeding IS end-to-end proof
 * that ssh forwards through EC2 (the channel is established server-side);
 * only the *egress identity* needs the echo body. So:
 * - handshake refused / CONNECT refused / protocol garbage -> connected=false
 *   (tunnel genuinely broken),
 * - timeout after CONNECT / non-IP body / HTTP error status -> connected=true
 *   with ip=null (transport proven, egress unverified).
 */
export async function probeSocksTunnel(
  socksHost: string,
  socksPort: number,
  timeoutMs: number,
  deps: SocksE2EDeps = {},
): Promise<SocksProbeResult> {
  for (const t of SOCKS_E2E_TARGETS) {
    try {
      const body = (await fetchViaSocks5(socksHost, socksPort, t.host, t.port, t.path, timeoutMs, deps)).trim();
      if (isPlausibleIp(body)) {
        return { connected: true, ip: body, service: t.url, detail: `SOCKS CONNECT + echo ${t.url} answered ${body}` };
      }
      // Tunnel forwarded and something answered, just not a usable IP body.
      return { connected: true, ip: null, service: t.url, detail: `SOCKS CONNECT ok via ${t.url}; echo body unusable (${body.slice(0, 40)})` };
    } catch (e) {
      const msg = (e as Error).message;
      if (e instanceof SocksExchangeError && e.connected) {
        return { connected: true, ip: null, service: t.url, detail: `SOCKS CONNECT channel opened via ${t.url}; echo unusable (${msg.split('\n')[0].slice(0, 120)})` };
      }
      // Real tunnel failure for this target; try the next echo target.
    }
  }
  return { connected: false, ip: null, service: null, detail: 'SOCKS5 tunnel refused/broken for all targets' };
}

/**
 * Verify the SOCKS egress IP equals the expected EC2 IP.
 * Empty expectedIp skips the comparison (still requires a plausible IP).
 * Returns { ok, ip } — never throws for a mismatch (only for no IP at all).
 */
export function verifySocksEgressIp(
  observedIp: string,
  expectedIp: string,
): { ok: boolean; detail: string } {
  const ip = observedIp.trim();
  if (!isPlausibleIp(ip)) {
    return { ok: false, detail: `SOCKS tunnel returned a non-IP body (${ip.slice(0, 60)})` };
  }
  if (!expectedIp) {
    return { ok: true, detail: `SOCKS tunnel answered with ${ip} (no expected IP configured, comparison skipped)` };
  }
  if (ip === expectedIp) {
    return { ok: true, detail: `SOCKS tunnel egress ${ip} matches expected EC2 IP` };
  }
  return { ok: false, detail: `SOCKS egress ${ip} does not match expected EC2 IP ${expectedIp}` };
}
