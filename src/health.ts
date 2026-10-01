/**
 * health.ts — pure, testable health-check logic for the OpenCode proxy chain.
 *
 * No dependency on the `vscode` module so this file can be unit-tested with
 * plain Node. All Windows interaction uses built-in Node APIs plus the native
 * `tasklist.exe` command (no WSL, no PowerShell, no third-party packages).
 *
 * Layered model (diagnostic endpoints can NEVER sink the proxy verdict):
 *   LEVEL 1 — local transport (fast, <=1s each):
 *     TCP 127.0.0.1:<socksPort> -> SOCKS up?
 *     Is ssh.exe running?          -> distinguishes SSH_DOWN from SOCKS_DOWN
 *     TCP 127.0.0.1:<httpPort>     -> HTTP bridge up?
 *   LEVEL 2 — proxy transport (light, <=4s):
 *     HEAD <transportProbeUrl> via CONNECT + TLS through :8080.
 *     Any 2xx/3xx proves 8080 -> SOCKS -> EC2 -> internet works.
 *     Deliberately NOT a public-IP echo service and NOT Zen: an outage of
 *     api.ipify.org / checkip.amazonaws.com / ifconfig.me / opencode.ai must
 *     never read as "proxy down". Echo services live ONLY in the bounded
 *     AWS-SG-repair path (src/awsNet.ts + src/recoveryMachine.ts step G).
 *   LEVEL 3 — OpenCode/Zen service (separate cadence, <=5s, never gates the
 *     proxy verdict): GET <zenEndpoint> models. Tracked as ZEN_OK /
 *     ZEN_DEGRADED / ZEN_UNREACHABLE for display only; never triggers
 *     SSH/SOCKS/hpts recovery.
 */

import * as net from 'net';
import * as tls from 'tls';
import { execFile } from 'child_process';
import type { DisplayState } from './status';
import { EXPECTED_PROXY_EGRESS_IP } from './netModel';

export interface HealthConfig {
  socksHost: string;
  socksPort: number;
  httpHost: string;
  httpPort: number;
  zenEndpoint: string;
  model: string;
  expectedExternalIp: string;
  ipifyUrl: string;
  checkTimeoutMs: number;
  /** LEVEL 1 budget per local port probe (ms). Fast loopback: <=1000. */
  portProbeTimeoutMs: number;
  /** LEVEL 2 budget for the transport probe through :8080 (ms). <=4000. */
  transportProbeTimeoutMs: number;
  /** LEVEL 2 target: lightweight, stable, NOT an echo service and NOT Zen. */
  transportProbeUrl: string;
  /** LEVEL 3 budget for the Zen service probe (ms, separate slow cadence). */
  zenProbeTimeoutMs: number;
}

export const DEFAULT_TRANSPORT_PROBE_URL = 'https://www.gstatic.com/generate_204';

export const DEFAULT_CONFIG: HealthConfig = {
  socksHost: '127.0.0.1',
  socksPort: 1080,
  httpHost: '127.0.0.1',
  httpPort: 8080,
  zenEndpoint: 'https://opencode.ai/zen/v1/models',
  model: 'muse-spark-1.3-contributor-free',
  expectedExternalIp: EXPECTED_PROXY_EGRESS_IP,
  ipifyUrl: 'http://api.ipify.org/',
  checkTimeoutMs: 8000,
  portProbeTimeoutMs: 1000,
  transportProbeTimeoutMs: 4000,
  transportProbeUrl: DEFAULT_TRANSPORT_PROBE_URL,
  zenProbeTimeoutMs: 5000,
};

export type HealthState =
  | 'STARTING'
  | 'HEALTHY'
  | 'SSH_DOWN'
  | 'SOCKS_DOWN'
  | 'HTTP_BRIDGE_DOWN'
  | 'PROXY_FAILED'
  | 'ZEN_UNREACHABLE'
  | 'MODEL_UNAVAILABLE'
  | 'UNKNOWN';

export interface HealthResult {
  socksUp: boolean;
  httpUp: boolean;
  sshRunning: boolean;
  /** Informational only: an opencode.exe process exists. This does NOT mean a
   *  model request is currently running. Never used to claim REQUEST_RUNNING. */
  opencodeRunning: boolean;
  /** LEVEL 2 verdict: lightweight transport probe through :8080 succeeded. */
  proxyTrafficOk: boolean;
  /** Normal health path never uses echo services: always null here. Echo is
   *  reserved for the bounded SG-repair/recovery path. Kept for shape compat. */
  externalIp: string | null;
  /** Always null in the layered path (no echo service involved). */
  trafficService: string | null;
  /** Always null in the layered path (no egress-IP comparison here). */
  ipMatchesExpected: boolean | null;
  /** True only when a LEVEL 3 probe actually ran in this cycle. */
  zenChecked: boolean;
  zenReachable: boolean;
  zenStatusCode: number | null;
  /** null when the Zen model list was never retrieved. */
  modelAvailable: boolean | null;
  reason: string | null;
  elapsedMs: number;
  /** Per-stage timings (ms); null when the stage was skipped by early exit. */
  socksMs: number | null;
  httpMs: number | null;
  /** LEVEL 2 transport-probe timing (replaces echo timing). */
  trafficMs: number | null;
  zenMs: number | null;
  /** LEVEL 2 probe target + observed status (null when skipped/failed). */
  transportTarget: string | null;
  transportStatus: number | null;
}

/** Injectable seams for unit tests. */
export interface HealthDeps {
  checkPort?: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
  checkProcess?: (imageName: string) => Promise<boolean>;
  /** LEVEL 2 probe. Must never throw (throwing counts as transport-down). */
  probeTransport?: (cfg: HealthConfig) => Promise<TransportProbeResult>;
}

export interface TransportProbeResult {
  ok: boolean;
  statusCode: number | null;
  target: string;
  elapsedMs: number;
  detail: string;
}

export const SSH_IMAGE = 'ssh.exe';
export const OPENCODE_IMAGE = 'opencode.exe';

// ---------------------------------------------------------------------------
// Low-level checks
// ---------------------------------------------------------------------------

/** True if a TCP connection to host:port succeeds within timeoutMs. */
export function checkTcpPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(ok);
    };
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    try {
      socket.connect(port, host);
    } catch {
      done(false);
    }
    // Absolute backstop in case no socket event fires.
    setTimeout(() => done(false), timeoutMs + 1000).unref?.();
  });
}

export type ExecFn = (
  file: string,
  args: string[],
  opts: { timeout: number },
  cb: (err: Error | null, stdout: string) => void,
) => void;

/**
 * True if a process with the given image name (e.g. "ssh.exe") is running.
 * Uses Windows-native `tasklist.exe`. Never inspects command lines, keys or
 * any sensitive data — only the image-name column.
 */
export function checkProcessRunning(imageName: string, execFn?: ExecFn): Promise<boolean> {
  const run: ExecFn =
    execFn ??
    ((file, args, opts, cb) =>
      execFile(file, args, { timeout: opts.timeout }, (err, stdout) =>
        cb(err as Error | null, String(stdout ?? '')),
      ));
  return new Promise((resolve) => {
    run('tasklist', ['/FI', `IMAGENAME eq ${imageName}`, '/FO', 'CSV', '/NH'], { timeout: 5000 }, (err, stdout) => {
      if (err) {
        resolve(false);
        return;
      }
      const wanted = `"${imageName.toLowerCase()}"`;
      const found = String(stdout)
        .split(/\r?\n/)
        .some((line) => line.trim().toLowerCase().startsWith(wanted));
      resolve(found);
    });
  });
}

// ---------------------------------------------------------------------------
// HTTP-via-proxy helpers (plain-Node, zero dependencies)
// ---------------------------------------------------------------------------

interface ParsedHttpResponse {
  statusCode: number;
  body: string;
}

const MAX_BODY_BYTES = 4 * 1024 * 1024;

export function parseHttpResponse(raw: string): ParsedHttpResponse {
  const sep = raw.indexOf('\r\n\r\n');
  if (sep === -1) {
    throw new Error('incomplete HTTP response (no header terminator)');
  }
  const headerBlock = raw.slice(0, sep);
  const body = raw.slice(sep + 4);
  const statusLine = headerBlock.split('\r\n', 1)[0] ?? '';
  const m = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/);
  if (!m) {
    throw new Error(`unparseable HTTP status line: ${statusLine.slice(0, 80)}`);
  }
  return { statusCode: parseInt(m[1], 10), body };
}

/**
 * GET an http:// URL through a plain HTTP proxy (absolute-URI request form,
 * which is what http-proxy-to-socks and most bridges accept). Resolves with
 * the response body; rejects on timeout, proxy error status, or bad response.
 */
export function fetchViaHttpProxy(
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  timeoutMs: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(targetUrl);
    } catch {
      reject(new Error(`bad target URL: ${targetUrl}`));
      return;
    }
    if (u.protocol !== 'http:') {
      reject(new Error('fetchViaHttpProxy supports http:// targets only'));
      return;
    }
    let settled = false;
    const socket = new net.Socket();
    let raw = '';
    const finish = (err: Error | null, body?: string) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      if (err) {
        reject(err);
      } else {
        resolve(body ?? '');
      }
    };
    const timer = setTimeout(
      () => finish(new Error(`timed out after ${timeoutMs}ms fetching ${targetUrl} via proxy`)),
      timeoutMs,
    );
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.write(
        `GET ${targetUrl} HTTP/1.1\r\nHost: ${u.host}\r\nConnection: close\r\n` +
          `User-Agent: opencode-proxy-health\r\n\r\n`,
      );
    });
    socket.on('data', (chunk: Buffer) => {
      raw += chunk.toString('utf8');
      if (raw.length > MAX_BODY_BYTES) {
        finish(new Error('proxy response exceeded size limit'));
      }
    });
    socket.once('timeout', () => finish(new Error(`timed out after ${timeoutMs}ms fetching ${targetUrl} via proxy`)));
    socket.once('error', (e) => finish(e as Error));
    // 'close' fires after the server half-closes; 'end' may not fire with destroy().
    socket.once('close', () => {
      if (settled || raw.length === 0) {
        finish(new Error(`empty response fetching ${targetUrl} via proxy`));
        return;
      }
      let parsed: ParsedHttpResponse;
      try {
        parsed = parseHttpResponse(raw);
      } catch (e) {
        finish(e as Error);
        return;
      }
      if (parsed.statusCode !== 200) {
        finish(new Error(`proxy returned HTTP ${parsed.statusCode} for ${targetUrl}`));
        return;
      }
      finish(null, parsed.body.trim());
    });
    try {
      socket.connect(proxyPort, proxyHost);
    } catch (e) {
      finish(e as Error);
    }
  });
}

/**
 * Any https:// request through a plain HTTP proxy using CONNECT + TLS.
 * Resolves with { statusCode, body }; rejects when the tunnel cannot be
 * established or the request times out. No credentials or tokens are sent.
 * Shared by the LEVEL 2 transport probe and the LEVEL 3 Zen probe.
 */
export function fetchHttpsViaProxy(
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  method: string,
  timeoutMs: number,
  acceptHeader: string,
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(targetUrl);
    } catch {
      reject(new Error(`bad target URL: ${targetUrl}`));
      return;
    }
    if (u.protocol !== 'https:') {
      reject(new Error('target must be https://'));
      return;
    }
    const targetHost = u.hostname;
    const targetPort = u.port ? parseInt(u.port, 10) : 443;
    const path = u.pathname + (u.search || '');
    let settled = false;
    const finish = (err: Error | null, res?: { statusCode: number; body: string }) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      try {
        tlsSocket?.destroy();
      } catch {
        /* ignore */
      }
      try {
        proxySocket.destroy();
      } catch {
        /* ignore */
      }
      if (err) {
        reject(err);
      } else {
        resolve(res as { statusCode: number; body: string });
      }
    };
    const timer = setTimeout(
      () => finish(new Error(`timed out after ${timeoutMs}ms reaching ${targetHost} via proxy`)),
      timeoutMs,
    );
    let tlsSocket: tls.TLSSocket | null = null;
    const proxySocket = new net.Socket();
    let connectHead = '';
    let tlsData = '';

    const fail = (msg: string) => finish(new Error(msg));

    proxySocket.setTimeout(timeoutMs);
    proxySocket.once('connect', () => {
      proxySocket.write(
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n` +
          `User-Agent: opencode-proxy-health\r\n\r\n`,
      );
    });
    proxySocket.on('data', (chunk: Buffer) => {
      if (tlsSocket) {
        return; // handed off to TLS; should not happen, but stay safe
      }
      connectHead += chunk.toString('utf8');
      const sep = connectHead.indexOf('\r\n\r\n');
      if (sep === -1) {
        if (connectHead.length > 8192) {
          fail('proxy CONNECT response headers too large');
        }
        return;
      }
      let parsed: ParsedHttpResponse;
      try {
        parsed = parseHttpResponse(connectHead);
      } catch (e) {
        finish(e as Error);
        return;
      }
      if (parsed.statusCode !== 200) {
        fail(`proxy CONNECT refused with HTTP ${parsed.statusCode}`);
        return;
      }
      // Tunnel established — upgrade the same socket to TLS.
      try {
        tlsSocket = tls.connect(
          { socket: proxySocket, servername: targetHost, timeout: timeoutMs },
          () => {
            tlsSocket?.write(
              `${method} ${path} HTTP/1.1\r\nHost: ${targetHost}\r\nConnection: close\r\n` +
                `Accept: ${acceptHeader}\r\nUser-Agent: opencode-proxy-health\r\n\r\n`,
            );
          },
        );
      } catch (e) {
        finish(e as Error);
        return;
      }
      tlsSocket.setTimeout(timeoutMs);
      tlsSocket.on('data', (d: Buffer) => {
        tlsData += d.toString('utf8');
        if (tlsData.length > MAX_BODY_BYTES) {
          fail('Zen response exceeded size limit');
        }
      });
      tlsSocket.once('timeout', () => fail(`timed out after ${timeoutMs}ms waiting for Zen response`));
      tlsSocket.once('error', (e) => finish(e as Error));
      tlsSocket.once('close', () => {
        if (settled || tlsData.length === 0) {
          fail('empty response from Zen endpoint');
          return;
        }
        try {
          finish(null, parseHttpResponse(tlsData));
        } catch (e) {
          finish(e as Error);
        }
      });
    });
    proxySocket.once('timeout', () => fail(`timed out after ${timeoutMs}ms on proxy CONNECT`));
    proxySocket.once('error', (e) => finish(e as Error));
    proxySocket.once('close', () => {
      if (!settled && !tlsSocket) {
        fail('proxy connection closed before CONNECT completed');
      }
    });
    try {
      proxySocket.connect(proxyPort, proxyHost);
    } catch (e) {
      finish(e as Error);
    }
  });
}

/**
 * GET an https:// URL through a plain HTTP proxy using CONNECT + TLS.
 * Kept for compatibility; delegates to fetchHttpsViaProxy.
 */
export function fetchZenModelsViaProxy(
  proxyHost: string,
  proxyPort: number,
  zenEndpoint: string,
  timeoutMs: number,
): Promise<{ statusCode: number; body: string }> {
  return fetchHttpsViaProxy(proxyHost, proxyPort, zenEndpoint, 'GET', timeoutMs, 'application/json');
}

/** 2xx/3xx prove transport works (204 = the generate_204 contract). */
function transportStatusOk(statusCode: number): boolean {
  return statusCode === 204 || (statusCode >= 200 && statusCode < 400);
}

/**
 * LEVEL 2 — lightweight end-to-end transport probe through :8080.
 * HEAD <transportProbeUrl> via CONNECT + TLS. Any 2xx/3xx (typically 204)
 * proves bridge -> SOCKS -> EC2 -> internet. Never throws: failures are data.
 * Never touches echo services or Zen semantics.
 */
export async function probeProxyTransport(
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  timeoutMs: number,
): Promise<TransportProbeResult> {
  const started = Date.now();
  try {
    const res = await fetchHttpsViaProxy(proxyHost, proxyPort, targetUrl, 'HEAD', timeoutMs, '*/*');
    const ok = transportStatusOk(res.statusCode);
    return {
      ok,
      statusCode: res.statusCode,
      target: targetUrl,
      elapsedMs: Date.now() - started,
      detail: ok
        ? `transport probe ${targetUrl} answered HTTP ${res.statusCode} through :${proxyPort}`
        : `transport probe ${targetUrl} answered HTTP ${res.statusCode} (not transport-OK)`,
    };
  } catch (e) {
    return {
      ok: false,
      statusCode: null,
      target: targetUrl,
      elapsedMs: Date.now() - started,
      detail: `transport probe failed: ${(e as Error).message.split('\n')[0].slice(0, 160)}`,
    };
  }
}

async function defaultProbeTransport(cfg: HealthConfig): Promise<TransportProbeResult> {
  return probeProxyTransport(cfg.httpHost, cfg.httpPort, cfg.transportProbeUrl, cfg.transportProbeTimeoutMs);
}

export interface ZenProbeResult {
  reachable: boolean;
  statusCode: number | null;
  modelAvailable: boolean | null;
  elapsedMs: number;
  reason: string | null;
}

/**
 * LEVEL 3 — OpenCode/Zen service probe (separate slow cadence, display only).
 * Never throws. A failure here is a SERVICE signal (ZEN_DEGRADED /
 * ZEN_UNREACHABLE), never a proxy-infrastructure failure, and never triggers
 * SSH/SOCKS/hpts recovery by itself.
 */
export async function probeZenService(
  cfg: HealthConfig,
  fetchFn: (
    proxyHost: string,
    proxyPort: number,
    targetUrl: string,
    method: string,
    timeoutMs: number,
    accept: string,
  ) => Promise<{ statusCode: number; body: string }> = fetchHttpsViaProxy,
): Promise<ZenProbeResult> {
  const started = Date.now();
  try {
    const zen = await fetchFn(
      cfg.httpHost,
      cfg.httpPort,
      cfg.zenEndpoint,
      'GET',
      cfg.zenProbeTimeoutMs,
      'application/json',
    );
    if (zen.statusCode !== 200) {
      return {
        reachable: false,
        statusCode: zen.statusCode,
        modelAvailable: null,
        elapsedMs: Date.now() - started,
        reason: `Zen host answered HTTP ${zen.statusCode} through the proxy (service-side, not proxy health)`,
      };
    }
    const present = modelIdPresentInZenBody(zen.body, cfg.model);
    return {
      reachable: true,
      statusCode: 200,
      modelAvailable: present,
      elapsedMs: Date.now() - started,
      reason: present ? null : `Zen model list does not contain "${cfg.model}"`,
    };
  } catch (e) {
    return {
      reachable: false,
      statusCode: null,
      modelAvailable: null,
      elapsedMs: Date.now() - started,
      reason: `Zen unreachable (service-side, not proxy health): ${(e as Error).message.split('\n')[0].slice(0, 160)}`,
    };
  }
}

/** True when the Zen model-list body advertises the given model id. */
export function modelIdPresentInZenBody(body: string, modelId: string): boolean {
  return body.includes(`"id":"${modelId}"`) || body.includes(`"id": "${modelId}"`);
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export interface TrafficReading {
  ip: string;
  service: string;
}

/**
 * Public IP echo services tried in order (plain http so no TLS-through-proxy
 * is needed). A fallback matters: if api.ipify.org alone were used, *its*
 * outage would misreport as *our* tunnel being down.
 */
export const IP_CHECK_URLS = ['http://api.ipify.org/', 'http://checkip.amazonaws.com/'];

/** Loose sanity check: dotted-quad or hex-colon host. Rejects captive-portal
 *  HTML pages or error text that a broken bridge might return with HTTP 200. */
export function isPlausibleIp(s: string): boolean {
  const t = s.trim();
  if (t.length < 3 || t.length > 64 || /\s/.test(t)) {
    return false;
  }
  return /^[0-9a-fA-F.:]+$/.test(t) && /[0-9]/.test(t) && (t.includes('.') || t.includes(':'));
}

export type FetchOne = (
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  timeoutMs: number,
) => Promise<string>;

/** Try each echo service in order; resolve with the first plausible IP. */
export async function fetchTrafficIpFromServices(
  fetchOne: FetchOne,
  proxyHost: string,
  proxyPort: number,
  urls: string[],
  timeoutMs: number,
): Promise<TrafficReading> {
  const errors: string[] = [];
  for (const url of urls) {
    try {
      const ip = (await fetchOne(proxyHost, proxyPort, url, timeoutMs)).trim();
      if (isPlausibleIp(ip)) {
        return { ip, service: url };
      }
      errors.push(`${url} answered a non-IP body`);
    } catch (e) {
      errors.push(`${url}: ${(e as Error).message.split('\n')[0]}`);
    }
  }
  throw new Error(`all IP echo services failed (${errors.join('; ')})`);
}

function blankResult(): HealthResult {
  return {
    socksUp: false,
    httpUp: false,
    sshRunning: false,
    opencodeRunning: false,
    proxyTrafficOk: false,
    externalIp: null,
    trafficService: null,
    ipMatchesExpected: null,
    zenChecked: false,
    zenReachable: false,
    zenStatusCode: null,
    modelAvailable: null,
    reason: null,
    elapsedMs: 0,
    socksMs: null,
    httpMs: null,
    trafficMs: null,
    zenMs: null,
    transportTarget: null,
    transportStatus: null,
  };
}

/**
 * Run the layered transport check (LEVEL 1 + LEVEL 2 only).
 * Never throws — failures are data. Never calls echo services or Zen:
 * a single failed probe here is ONE sample, not a verdict — the caller
 * (src/healthPolicy.ts) requires consecutive failures before confirming.
 */
export async function runHealthCheck(cfg: HealthConfig, deps: HealthDeps = {}): Promise<HealthResult> {
  const started = Date.now();
  const r = blankResult();
  const checkPort = deps.checkPort ?? checkTcpPort;
  const checkProc = deps.checkProcess ?? ((img: string) => checkProcessRunning(img));
  const portTimeout = Math.min(cfg.portProbeTimeoutMs, 5000);

  // LEVEL 1 probes are independent — run them in parallel with per-probe
  // safety so one bad seam cannot reject the batch. Each probe is timed
  // individually (no joint-batch attribution).
  const safe = async <T>(p: Promise<T>, fallback: T): Promise<T> => {
    try {
      return await p;
    } catch {
      return fallback;
    }
  };
  const timed = async <T>(p: Promise<T>): Promise<{ v: T; ms: number }> => {
    const t = Date.now();
    const v = await p;
    return { v, ms: Date.now() - t };
  };
  const [socks, http, sshRunning, opencodeRunning] = await Promise.all([
    safe(timed(checkPort(cfg.socksHost, cfg.socksPort, portTimeout)), null),
    safe(timed(checkPort(cfg.httpHost, cfg.httpPort, portTimeout)), null),
    safe(checkProc(SSH_IMAGE), false),
    // Informational only — a live opencode.exe says nothing about request state.
    safe(checkProc(OPENCODE_IMAGE), false),
  ]);
  r.socksUp = socks?.v ?? false;
  r.socksMs = socks?.ms ?? null;
  r.httpUp = http?.v ?? false;
  r.httpMs = http?.ms ?? null;
  r.sshRunning = sshRunning;
  r.opencodeRunning = opencodeRunning;

  if (!r.socksUp) {
    // Honest wording: an ssh.exe process existing NEVER means the tunnel is
    // healthy (stale process after an SG block is the classic counterexample).
    // Only a listening :1080 plus verified transport proves health.
    r.reason = r.sshRunning
      ? `SOCKS_DOWN — TCP ${cfg.socksHost}:${cfg.socksPort} refused but ssh.exe is running (process presence does NOT mean the tunnel is healthy)`
      : 'SSH_DOWN — ssh.exe process not found and SOCKS5 port refused';
    r.elapsedMs = Date.now() - started;
    return r;
  }
  if (!r.httpUp) {
    r.reason = `SOCKS5 :${cfg.socksPort} OK but HTTP bridge :${cfg.httpPort} refused`;
    r.elapsedMs = Date.now() - started;
    return r;
  }

  // LEVEL 2 — lightweight transport probe. No echo IP, no expected-IP
  // comparison, no Zen: any one failure is a single unconfirmed sample.
  const probe = deps.probeTransport ?? defaultProbeTransport;
  let reading: TransportProbeResult;
  try {
    reading = await probe(cfg);
  } catch (e) {
    reading = {
      ok: false,
      statusCode: null,
      target: cfg.transportProbeUrl,
      elapsedMs: Date.now() - started,
      detail: `transport probe threw: ${(e as Error).message.split('\n')[0].slice(0, 160)}`,
    };
  }
  r.trafficMs = reading.elapsedMs;
  r.transportTarget = reading.target;
  r.transportStatus = reading.statusCode;
  if (!reading.ok) {
    r.reason = `proxy transport probe failed (single sample, unconfirmed): ${reading.detail}`;
    r.elapsedMs = Date.now() - started;
    return r;
  }
  r.proxyTrafficOk = true;
  r.elapsedMs = Date.now() - started;
  return r;
}

/**
 * Map a transport-check result onto the per-tick leg state. Pure function.
 * NOTE: PROXY_FAILED here is ONE unconfirmed sample, never a user verdict —
 * src/healthPolicy.ts gates DEGRADED (strikes 1..N-1) vs PROXY_DOWN display
 * and recovery on consecutive samples. Zen is evaluated only when a LEVEL 3
 * probe actually ran in the cycle (zenChecked); otherwise transport health
 * alone decides, so a Zen outage can never sink the proxy verdict.
 */
export function deriveState(r: HealthResult): HealthState {
  if (!r.socksUp) {
    return r.sshRunning ? 'SOCKS_DOWN' : 'SSH_DOWN';
  }
  if (!r.httpUp) {
    return 'HTTP_BRIDGE_DOWN';
  }
  if (!r.proxyTrafficOk) {
    return 'PROXY_FAILED';
  }
  if (r.zenChecked) {
    if (!r.zenReachable) {
      return 'ZEN_UNREACHABLE';
    }
    if (r.modelAvailable === false) {
      return 'MODEL_UNAVAILABLE';
    }
    if (r.modelAvailable === true) {
      return 'HEALTHY';
    }
    return 'UNKNOWN';
  }
  return 'HEALTHY';
}

export interface ReportMeta {
  lastCheck: Date | null;
  lastSuccess: Date | null;
  downSince: Date | null;
}

export function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/** Render the multi-line diagnostic block shown in the Output channel. */
export function formatReport(state: DisplayState, r: HealthResult, cfg: HealthConfig, meta: ReportMeta): string {
  const tick = (v: boolean) => (v ? 'OK' : 'FAIL');
  const lines = [
    'OpenCode Proxy Health',
    '────────────────────────',
    `SSH SOCKS5 :${cfg.socksPort}     ${r.socksUp ? 'UP' : 'DOWN'} (${tick(r.socksUp)})`,
    `HTTP Proxy :${cfg.httpPort}     ${r.httpUp ? 'UP' : 'DOWN'} (${tick(r.httpUp)})`,
    `SSH Process          ${r.sshRunning ? 'RUNNING' : 'NOT FOUND'}`,
    `Transport (L2)       ${r.proxyTrafficOk ? `OK${r.transportStatus !== null ? ` (HTTP ${r.transportStatus})` : ''}` : r.socksUp && r.httpUp ? 'UNVERIFIED' : 'UNKNOWN'} via ${r.transportTarget ?? cfg.transportProbeUrl}`,
    `Echo services        not polled (reserved for bounded SG-repair/recovery only)`,
    `Zen API (L3)         ${!r.zenChecked ? 'UNCHECKED this cycle (separate slow cadence)' : r.zenReachable ? 'REACHABLE' : 'UNREACHABLE'}${
      r.zenChecked && r.zenStatusCode !== null ? ` (HTTP ${r.zenStatusCode})` : ''
    }`,
    `Muse Spark           ${
      !r.zenChecked ? 'UNKNOWN (unchecked this cycle)' : r.modelAvailable === true ? 'AVAILABLE' : r.modelAvailable === false ? 'UNAVAILABLE' : 'UNKNOWN'
    } (${cfg.model})`,
    `OpenCode process     ${r.opencodeRunning ? 'ACTIVE (informational only)' : 'not observed'}`,
    `Overall state        ${state}`,
  ];
  if (r.reason) {
    lines.push(`Reason               ${r.reason}`);
  }
  if (meta.lastCheck) {
    lines.push(`Last health check    ${meta.lastCheck.toLocaleTimeString()}`);
  }
  if (meta.lastSuccess) {
    lines.push(`Last successful API  ${meta.lastSuccess.toLocaleTimeString()}`);
  }
  if (meta.downSince && state !== 'HEALTHY') {
    lines.push(`Down since           ${meta.downSince.toLocaleTimeString()}`);
  }
  lines.push(`Check took           ${r.elapsedMs}ms`);
  const ms = (v: number | null) => (v === null ? '—' : `${v}ms`);
  lines.push(`Stage timings        L1 ${ms(r.socksMs)} / L2 transport ${ms(r.trafficMs)}${r.zenChecked ? ` / L3 zen ${ms(r.zenMs)}` : ''}`);
  return lines.join('\n');
}

/** Synthetic result for a hung check killed by the overall guard. */
export function unknownResult(reason: string, elapsedMs: number): HealthResult {
  return { ...blankResult(), reason, elapsedMs };
}

/**
 * runHealthCheck with an overall watchdog. Per-layer timeouts (L1 <=1s,
 * L2 <=4s) should suffice, but a pathological hang (e.g. a socket that never
 * settles) must never stall the scheduler or overlap the next poll — after
 * guardMs we report UNKNOWN instead of hanging VS Code. Default 8s sits below
 * the 10s poll interval so a hung cycle can never overlap its successor.
 * Never throws.
 */
export async function runHealthCheckGuarded(
  cfg: HealthConfig,
  deps: HealthDeps = {},
  guardMs = 8000,
): Promise<{ result: HealthResult; timedOut: boolean }> {
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const guard = new Promise<{ result: HealthResult; timedOut: boolean }>((resolve) => {
    timer = setTimeout(() => {
      resolve({
        result: unknownResult(
          `health check exceeded overall guard of ${guardMs}ms (a stage hung despite per-check timeouts)`,
          Date.now() - started,
        ),
        timedOut: true,
      });
    }, guardMs);
  });
  const run = runHealthCheck(cfg, deps).then((result) => ({ result, timedOut: false }));
  const out = await Promise.race([run, guard]);
  if (timer) {
    clearTimeout(timer);
  }
  return out;
}
