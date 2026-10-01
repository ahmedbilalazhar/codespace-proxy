/**
 * recoveryMachine.ts — the robust proxy-recovery state machine.
 *
 * Replaces the old assumption ("ssh.exe exists => tunnel healthy" and
 * "schtasks /run => fixed") with layered, verified, idempotent recovery that
 * works BEFORE OpenCode is usable and WITHOUT OpenCode or a healthy proxy.
 *
 * Layered checks (each gates the next):
 *   A. TCP 127.0.0.1:1080 listening?
 *   B. TCP <ec2Host>:22 reachable (direct, proxy bypassed)?
 *   C. If 22 reachable but 1080 not: kill stale/redundant OWNED ssh.exe,
 *      start exactly ONE ssh tunnel, bounded retry/backoff, verify 1080.
 *      Never assume ssh.exe existing means success.
 *   D. SOCKS5 end-to-end through 1080; egress IP must equal expected EC2 IP.
 *   E. Only after SOCKS healthy: start/recover hpts on :8080 (single owner).
 *   F. Verify 127.0.0.1:8080.
 *   G. Verify HTTP proxy path end-to-end (egress through :8080).
 *   H. READY.
 *
 * Changing public IPs:
 *   When :22 is unreachable, discover the current public IP DIRECTLY
 *   (proxy bypassed), describe the SG, replace stale proxy /32s with the
 *   current /32, verify, then retry :22. All via the existing AWS CLI profile.
 *   Never hardcodes credentials; never opens 0.0.0.0/0.
 *
 * Idempotent + bounded: single-flight guard (second run while one is active
 * returns the in-flight promise), exponential backoff, no busy-loop, handles
 * Wi-Fi change / wake / DNS blip / AWS route blip / timeout / crash /
 * transient port absence.
 */

import { checkTcpPort } from './health';
import { checkSocksEndToEnd, probeSocksTunnel, verifySocksEgressIp, type SocksProbeResult } from './socks';
import type { TransportProbeResult } from './health';
import {
  checkAwsSshReachable,
  fetchDirectPublicIp,
  fetchDirectUrl,
  DIRECT_IP_URLS,
  describeSshRules,
  ensureSshAccess,
  type AwsNetConfig,
} from './awsNet';
import {
  dedupOurSsh,
  dedupOurHpts,
  killPid,
  listenerPidForPort,
  listOurSsh,
  spawnSsh,
  spawnHpts,
  type ProxyProcConfig,
  type SpawnFn,
} from './procOwn';
import { waitForPort } from './runbook';
import type { ExecAsync } from './diagnose';
import { AWS_ELASTIC_IP, AWS_REGION, EXPECTED_PROXY_EGRESS_IP } from './netModel';

export type RecoveryState =
  | 'SSH_PROCESS_DOWN'
  | 'AWS_SSH_UNREACHABLE'
  | 'SG_REPAIRING'
  | 'SOCKS_DOWN'
  | 'SOCKS_STARTING'
  | 'SOCKS_UP'
  | 'HTTP_PROXY_DOWN'
  | 'HTTP_PROXY_STARTING'
  | 'HTTP_PROXY_UP'
  | 'READY'
  | 'RECOVERY_FAILED';

export interface RecoveryMachineConfig extends AwsNetConfig, ProxyProcConfig {
  expectedExternalIp: string;
  /** Stage-1 HTTP verify target (gstatic 204; never an echo service, never Zen). */
  transportProbeUrl?: string;
  /** Stage-1 HTTP verify budget (ms). */
  transportProbeTimeoutMs?: number;
  /** Bounded attempts for port-wait / SG-retry loops. */
  maxAttempts: number;
  /** Base backoff ms (exponential: base * 2^attempt, capped). */
  baseDelayMs: number;
  /** Cap for any single backoff sleep. */
  maxDelayMs: number;
  /** How long to wait for :1080 after ssh spawn. */
  socksWaitMs: number;
  /** How long to wait for :8080 after hpts spawn. */
  httpWaitMs: number;
  checkTimeoutMs: number;
}

export const DEFAULT_RECOVERY_REGION = AWS_REGION;

export const DEFAULT_RECOVERY_CONFIG: RecoveryMachineConfig = {
  ec2Host: AWS_ELASTIC_IP,
  sshPort: 22,
  securityGroupId: '',
  awsProfile: '',
  awsRegion: DEFAULT_RECOVERY_REGION,
  sshExe: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
  sshKeyPath: '%USERPROFILE%\\.ssh\\opencode-proxy-key.pem',
  sshUser: 'ubuntu',
  socksHost: '127.0.0.1',
  socksPort: 1080,
  hptsCmd: '%USERPROFILE%\\npm-global\\hpts.cmd',
  httpPort: 8080,
  expectedExternalIp: EXPECTED_PROXY_EGRESS_IP,
  maxAttempts: 3,
  baseDelayMs: 2000,
  maxDelayMs: 15000,
  socksWaitMs: 30000,
  httpWaitMs: 20000,
  checkTimeoutMs: 8000,
};

export interface RecoveryLog {
  tag:
    | 'PROXY CHECK'
    | 'AWS SSH CHECK'
    | 'PUBLIC IP'
    | 'SECURITY GROUP UPDATE'
    | 'SSH START'
    | 'SSH STOP'
    | 'SOCKS CHECK'
    | 'SOCKS END-TO-END CHECK'
    | 'HTTP BRIDGE START'
    | 'HTTP PROXY CHECK'
    | 'RECOVERY SUCCESS'
    | 'RECOVERY FAILURE';
  message: string;
  at: string;
}

export interface RecoveryOutcome {
  ok: boolean;
  state: RecoveryState;
  /** Ordered states visited (the exact state machine path). */
  path: RecoveryState[];
  logs: RecoveryLog[];
  egressViaSocks: string | null;
  egressViaHttp: string | null;
  /**
   * False when the transport probe passed but the IP-echo egress evidence
   * could not be collected (echo-service outage). The chain is usable; the
   * next regular health cycle re-verifies. Never blocks READY by itself.
   */
  egressVerified: boolean;
  publicIpDirect: string | null;
  sgRepaired: boolean;
  elapsedMs: number;
}

export interface RecoveryDeps {
  checkPort?: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
  checkAws?: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
  fetchDirectIp?: (urls: string[], timeoutMs: number) => Promise<{ ip: string; service: string }>;
  describeSg?: (cfg: RecoveryMachineConfig) => Promise<{ ok: boolean; rules: { cidr: string; description: string; groupId: string }[]; detail: string }>;
  repairSg?: (cfg: RecoveryMachineConfig, ip: string) => Promise<{ ok: boolean; detail: string; authorizedCurrent: boolean; revoked: string[] }>;
  listSsh?: (cfg: RecoveryMachineConfig) => Promise<{ kept: number | null; killed: number[]; detail: string }>;
  listHpts?: (cfg: RecoveryMachineConfig) => Promise<{ kept: number | null; killed: number[]; detail: string }>;
  portOwner?: (port: number) => Promise<number | null>;
  spawnSshFn?: (cfg: RecoveryMachineConfig) => { ok: boolean; pid: number | null; detail: string };
  spawnHptsFn?: (cfg: RecoveryMachineConfig) => { ok: boolean; pid: number | null; detail: string };
  socksE2E?: (host: string, port: number, timeoutMs: number) => Promise<{ ip: string; service: string; elapsedMs: number }>;
  /** Distinguishes "tunnel dead" from "echo service dead" for the final verdict. */
  socksProbe?: (host: string, port: number, timeoutMs: number) => Promise<SocksProbeResult>;
  /** Stage-1 HTTP bridge verification (defaults to health.probeProxyTransport). */
  probeTransport?: (url: string, timeoutMs: number) => Promise<TransportProbeResult>;
  httpEgress?: () => Promise<string>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  onState?: (s: RecoveryState, detail: string) => void;
}

export function backoffMs(attempt: number, baseMs: number, maxMs: number): number {
  const v = baseMs * Math.pow(2, Math.max(0, attempt));
  return Math.min(maxMs, Math.max(baseMs, Math.round(v)));
}

function stamp(): string {
  return new Date().toLocaleTimeString();
}

// Single-flight guard: concurrent recoverProxy() calls share one promise.
let inFlight: Promise<RecoveryOutcome> | null = null;

export function isRecoveryRunning(): boolean {
  return inFlight !== null;
}

/**
 * Run the full layered recovery. Never throws — all failures land in the
 * outcome. Idempotent: a second call while one runs returns the same promise.
 */
export function recoverProxy(
  cfg: RecoveryMachineConfig,
  exec: ExecAsync,
  deps: RecoveryDeps = {},
  spawnFn?: SpawnFn,
): Promise<RecoveryOutcome> {
  if (inFlight) {
    return inFlight;
  }
  const p = runRecoveryInner(cfg, exec, deps, spawnFn).finally(() => {
    inFlight = null;
  });
  inFlight = p;
  return p;
}

async function runRecoveryInner(
  cfg: RecoveryMachineConfig,
  exec: ExecAsync,
  deps: RecoveryDeps,
  spawnFn?: SpawnFn,
): Promise<RecoveryOutcome> {
  const started = (deps.now ?? Date.now)();
  const path: RecoveryState[] = [];
  const logs: RecoveryLog[] = [];
  let egressViaSocks: string | null = null;
  let egressViaHttp: string | null = null;
  let egressVerified = true;
  let publicIpDirect: string | null = null;
  let sgRepaired = false;

  const checkPort = deps.checkPort ?? checkTcpPort;
  const checkAws = deps.checkAws ?? checkAwsSshReachable;
  const sleep = deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const now = deps.now ?? Date.now;

  const emit = (tag: RecoveryLog['tag'], message: string) => {
    logs.push({ tag, message, at: stamp() });
  };
  const enter = (s: RecoveryState, detail: string) => {
    path.push(s);
    deps.onState?.(s, detail);
  };

  const safeCheck = async (host: string, port: number, t: number): Promise<boolean> => {
    try {
      return await checkPort(host, port, t);
    } catch {
      return false;
    }
  };

  // -- A. Is :1080 listening? ---------------------------------------------
  emit('PROXY CHECK', `probing TCP ${cfg.socksHost}:${cfg.socksPort}`);
  const socksListening = await safeCheck(cfg.socksHost, cfg.socksPort, cfg.checkTimeoutMs);
  emit('SOCKS CHECK', `TCP ${cfg.socksHost}:${cfg.socksPort} ${socksListening ? 'listening' : 'refused'}`);

  // -- B. Is AWS :22 reachable (direct)? -----------------------------------
  emit('AWS SSH CHECK', `probing TCP ${cfg.ec2Host}:${cfg.sshPort} (direct, proxy bypassed)`);
  let awsUp = false;
  try {
    awsUp = await checkAws(cfg.ec2Host, cfg.sshPort, cfg.checkTimeoutMs);
  } catch {
    awsUp = false;
  }
  emit('AWS SSH CHECK', `TCP ${cfg.ec2Host}:${cfg.sshPort} ${awsUp ? 'reachable' : 'unreachable'}`);

  if (!awsUp) {
    enter('AWS_SSH_UNREACHABLE', `TCP ${cfg.ec2Host}:${cfg.sshPort} unreachable`);
    // -- bootstrap: direct public IP (NEVER via the broken proxy) ---------
    emit('PUBLIC IP', `discovering current public IP directly (${DIRECT_IP_URLS.length} services, proxy bypassed)`);
    const fetchIp =
      deps.fetchDirectIp ??
      ((urls: string[], t: number) => fetchDirectPublicIp((u, tt) => fetchDirectUrl(u, tt), urls, t));
    try {
      const found = await fetchIp(DIRECT_IP_URLS, cfg.checkTimeoutMs);
      publicIpDirect = found.ip;
      emit('PUBLIC IP', `direct public IP ${found.ip} (via ${found.service}, proxy bypassed)`);
    } catch (e) {
      const detail = (e as Error).message.slice(0, 200);
      emit('RECOVERY FAILURE', `direct public-IP discovery failed: ${detail}`);
      enter('RECOVERY_FAILED', detail);
      return fail();
    }
    // -- SG repair (only when configured; never 0.0.0.0/0) ----------------
    if (cfg.securityGroupId.trim()) {
      enter('SG_REPAIRING', `repairing SG ${cfg.securityGroupId.trim()} for ${publicIpDirect}/32`);
      emit('SECURITY GROUP UPDATE', `describing TCP-22 rules on ${cfg.securityGroupId.trim()} (existing AWS CLI profile)`);
      const repair =
        deps.repairSg ??
        ((c: RecoveryMachineConfig, ip: string) => ensureSshAccess(exec, c, ip));
      let repaired = false;
      for (let attempt = 0; attempt < Math.max(1, cfg.maxAttempts); attempt++) {
        try {
          const r = await repair(cfg, publicIpDirect as string);
          emit('SECURITY GROUP UPDATE', r.detail);
          if (r.ok && r.authorizedCurrent) {
            sgRepaired = r.revoked.length > 0 || /already authorized|verified/.test(r.detail);
            repaired = true;
            break;
          }
          if (attempt < cfg.maxAttempts - 1) {
            const wait = backoffMs(attempt, cfg.baseDelayMs, cfg.maxDelayMs);
            emit('SECURITY GROUP UPDATE', `retry ${attempt + 1}/${cfg.maxAttempts} in ${wait}ms`);
            await sleep(wait);
          } else {
            emit('RECOVERY FAILURE', `SG repair failed: ${r.detail}`);
            enter('RECOVERY_FAILED', r.detail);
            return fail();
          }
        } catch (e) {
          const detail = (e as Error).message.slice(0, 200);
          emit('RECOVERY FAILURE', `SG repair threw: ${detail}`);
          enter('RECOVERY_FAILED', detail);
          return fail();
        }
      }
      if (!repaired) {
        enter('RECOVERY_FAILED', 'SG repair exhausted retries');
        return fail();
      }
      // -- retry TCP 22 after repair --------------------------------------
      emit('AWS SSH CHECK', `re-probing TCP ${cfg.ec2Host}:${cfg.sshPort} after SG repair`);
      let upAfter = false;
      for (let attempt = 0; attempt < Math.max(1, cfg.maxAttempts); attempt++) {
        try {
          upAfter = await checkAws(cfg.ec2Host, cfg.sshPort, cfg.checkTimeoutMs);
        } catch {
          upAfter = false;
        }
        if (upAfter) {
          break;
        }
        if (attempt < cfg.maxAttempts - 1) {
          await sleep(backoffMs(attempt, cfg.baseDelayMs, cfg.maxDelayMs));
        }
      }
      emit('AWS SSH CHECK', `TCP ${cfg.ec2Host}:${cfg.sshPort} after SG repair: ${upAfter ? 'reachable' : 'still unreachable'}`);
      if (!upAfter) {
        // Distinguish "SG fixed but route/SSH still down" from SG failure.
        const d = await (deps.describeSg ?? ((c: RecoveryMachineConfig) => describeSshRules(exec, c)))(cfg);
        emit('SECURITY GROUP UPDATE', `post-repair describe: ${d.detail}`);
        enter('RECOVERY_FAILED', `AWS SSH still unreachable after SG repair (${publicIpDirect}/32 authorized)`);
        return fail();
      }
      awsUp = true;
    } else {
      emit('SECURITY GROUP UPDATE', 'no securityGroupId configured — SG auto-repair disabled; cannot fix IP restriction automatically');
      enter('RECOVERY_FAILED', `AWS SSH unreachable and no securityGroupId configured (direct IP ${publicIpDirect})`);
      return fail();
    }
  }

  // -- C. :22 reachable but :1080 not -> single-owner ssh recovery ---------
  if (!socksListening) {
    const ours = await (async () => {
      try {
        if (deps.listSsh) {
          return await deps.listSsh(cfg);
        }
        const owner = await listenerPidForPort(exec, cfg.socksPort);
        return await dedupOurSsh(exec, cfg, owner);
      } catch (e) {
        return { kept: null, killed: [], detail: `ssh dedup probe failed: ${(e as Error).message.slice(0, 160)}` };
      }
    })();
    if (!ours.kept) {
      enter('SSH_PROCESS_DOWN', ours.detail);
    } else {
      enter('SOCKS_DOWN', `owned ssh.exe (pid ${ours.kept}) but :${cfg.socksPort} refused — stale tunnel`);
    }
    if (ours.killed.length > 0) {
      emit('SSH STOP', `terminated stale/redundant owned ssh.exe pid(s) [${ours.killed.join(', ')}]`);
    } else {
      emit('SSH STOP', `ssh dedup: ${ours.detail}`);
    }

    enter('SOCKS_STARTING', `starting exactly ONE ssh tunnel -D ${cfg.socksHost}:${cfg.socksPort}`);
    const spawnIt =
      deps.spawnSshFn ??
      ((c: RecoveryMachineConfig) => spawnSsh(c, spawnFn as SpawnFn));
    const spawned = spawnIt(cfg);
    emit('SSH START', spawned.detail);
    if (!spawned.ok) {
      enter('RECOVERY_FAILED', spawned.detail);
      emit('RECOVERY FAILURE', spawned.detail);
      return fail();
    }
    const probe = deps.checkPort ?? checkTcpPort;
    const waited = await waitForPort(
      async (h, p, t) => {
        try {
          return await probe(h, p, t);
        } catch {
          return false;
        }
      },
      cfg.socksHost,
      cfg.socksPort,
      cfg.socksWaitMs,
      750,
      5000,
      sleep,
      now,
    );
    emit('SOCKS CHECK', waited.up ? `TCP ${cfg.socksHost}:${cfg.socksPort} opened after ${waited.waitedMs}ms (${waited.probes} probes)` : `TCP ${cfg.socksHost}:${cfg.socksPort} never opened in ${Math.round(waited.waitedMs / 1000)}s`);
    if (!waited.up) {
      enter('RECOVERY_FAILED', `ssh started (pid ${spawned.pid}) but :${cfg.socksPort} never opened`);
      emit('RECOVERY FAILURE', `ssh started but SOCKS port never opened — never assuming ssh.exe means healthy`);
      return fail();
    }
    enter('SOCKS_UP', `TCP ${cfg.socksHost}:${cfg.socksPort} listening`);
  } else {
    enter('SOCKS_UP', `TCP ${cfg.socksHost}:${cfg.socksPort} already listening — no ssh spawn`);
  }

  // -- D. SOCKS5 end-to-end through :1080 -----------------------------------
  emit('SOCKS END-TO-END CHECK', `SOCKS5 CONNECT through ${cfg.socksHost}:${cfg.socksPort}, expecting egress ${cfg.expectedExternalIp}`);
  const socksE2E = deps.socksE2E ?? ((h: string, p: number, t: number) => checkSocksEndToEnd(h, p, t));
  let socksOk = false;
  let lastSocksErr = '';
  const runSocksE2E = async (): Promise<boolean> => {
    for (let attempt = 0; attempt < Math.max(1, cfg.maxAttempts); attempt++) {
      try {
        const r = await socksE2E(cfg.socksHost, cfg.socksPort, cfg.checkTimeoutMs);
        egressViaSocks = r.ip;
        const v = verifySocksEgressIp(r.ip, cfg.expectedExternalIp);
        emit('SOCKS END-TO-END CHECK', `${v.detail} (via ${r.service}, ${r.elapsedMs}ms)`);
        if (v.ok) {
          return true;
        }
        lastSocksErr = v.detail;
        // Wrong egress = tunnel forwards elsewhere; retrying the same ssh won't
        // help — but a transient captive-portal HTML body might. One bounded
        // retry, then fail honestly.
        if (attempt < cfg.maxAttempts - 1) {
          await sleep(backoffMs(attempt, cfg.baseDelayMs, cfg.maxDelayMs));
        }
      } catch (e) {
        lastSocksErr = (e as Error).message.slice(0, 200);
        emit('SOCKS END-TO-END CHECK', `attempt ${attempt + 1} failed: ${lastSocksErr}`);
        if (attempt < cfg.maxAttempts - 1) {
          await sleep(backoffMs(attempt, cfg.baseDelayMs, cfg.maxDelayMs));
        }
      }
    }
    return false;
  };
  socksOk = await runSocksE2E();
  if (!socksOk && socksListening) {
    // Stale-listener refresh (bounded, once): :1080 answered TCP but speaks
    // no SOCKS — a dead tunnel squats the port (classic post-SG-block
    // leftover). Refresh OWNED ssh only; a foreign listener is reported,
    // never killed.
    let ownerPid: number | null = null;
    try {
      ownerPid = deps.portOwner ? await deps.portOwner(cfg.socksPort) : await listenerPidForPort(exec, cfg.socksPort);
    } catch {
      ownerPid = null;
    }
    let owned: number[] = [];
    try {
      owned = (await listOurSsh(exec, cfg)).map((o) => o.pid);
    } catch {
      owned = [];
    }
    if (ownerPid !== null && !owned.includes(ownerPid)) {
      emit('SSH STOP', `:${cfg.socksPort} held by non-owned pid ${ownerPid} with dead SOCKS — refusing to kill a foreign process (manual: schtasks /end or taskkill /PID ${ownerPid} /F)`);
    } else if (owned.length === 0) {
      emit('SSH STOP', `:${cfg.socksPort} listened but no owned ssh.exe found — cannot refresh safely`);
    } else {
      enter('SOCKS_DOWN', `stale owned tunnel squatting :${cfg.socksPort} — refreshing once`);
      for (const pid of owned) {
        const k = await killPid(exec, pid);
        emit('SSH STOP', k.detail);
      }
      enter('SOCKS_STARTING', `starting exactly ONE fresh ssh tunnel -D ${cfg.socksHost}:${cfg.socksPort}`);
      const spawnIt2 =
        deps.spawnSshFn ??
        ((c: RecoveryMachineConfig) => spawnSsh(c, spawnFn as SpawnFn));
      const spawned2 = spawnIt2(cfg);
      emit('SSH START', spawned2.detail);
      if (spawned2.ok) {
        const probe = deps.checkPort ?? checkTcpPort;
        const waited2 = await waitForPort(
          async (h, p, t) => {
            try {
              return await probe(h, p, t);
            } catch {
              return false;
            }
          },
          cfg.socksHost,
          cfg.socksPort,
          cfg.socksWaitMs,
          750,
          5000,
          sleep,
          now,
        );
        if (waited2.up) {
          enter('SOCKS_UP', `fresh tunnel listening, re-verifying end-to-end`);
          socksOk = await runSocksE2E();
        } else {
          lastSocksErr = `fresh ssh started (pid ${spawned2.pid}) but :${cfg.socksPort} never reopened`;
        }
      } else {
        lastSocksErr = spawned2.detail;
      }
    }
  }
  if (!socksOk) {
    // Final verdict requires classification (bug fix): the e2e loop can fail
    // because the ECHO SERVICES are down while the tunnel itself forwards
    // fine. Killing a working ssh over a diagnostic outage is forbidden.
    const classify = deps.socksProbe ?? ((h: string, p: number, t: number) => probeSocksTunnel(h, p, t));
    let classification: SocksProbeResult;
    try {
      classification = await classify(cfg.socksHost, cfg.socksPort, cfg.checkTimeoutMs);
    } catch (e) {
      classification = { connected: false, ip: null, service: null, detail: (e as Error).message.slice(0, 200) };
    }
    if (classification.connected) {
      // Connectivity proven; identity is still enforced in step G via the HTTP
      // path (echo down there is tolerated, a WRONG ip there still fails).
      enter('SOCKS_UP', `tunnel connectivity proven (SOCKS5 CONNECT ok); egress IP unverified (echo unavailable)`);
      egressViaSocks = classification.ip;
      emit('SOCKS END-TO-END CHECK', `connectivity-only pass: ${classification.detail}`);
    } else {
      const detail = `SOCKS end-to-end failed: ${lastSocksErr || classification.detail}`;
      enter('RECOVERY_FAILED', detail);
      emit('RECOVERY FAILURE', detail);
      return fail();
    }
  }

  // -- E/F. Single-owner hpts on :8080 (only after SOCKS healthy) ----------
  const httpListening = await safeCheck(cfg.socksHost === '127.0.0.1' ? '127.0.0.1' : cfg.socksHost, cfg.httpPort, cfg.checkTimeoutMs);
  emit('HTTP PROXY CHECK', `TCP 127.0.0.1:${cfg.httpPort} ${httpListening ? 'listening' : 'refused'}`);
  if (!httpListening) {
    enter('HTTP_PROXY_DOWN', `TCP 127.0.0.1:${cfg.httpPort} refused (SOCKS healthy — bridge only)`);
    const hpts = await (async () => {
      try {
        if (deps.listHpts) {
          return await deps.listHpts(cfg);
        }
        const owner = await listenerPidForPort(exec, cfg.httpPort);
        return await dedupOurHpts(exec, cfg, owner);
      } catch (e) {
        return { kept: null, killed: [], detail: `hpts dedup probe failed: ${(e as Error).message.slice(0, 160)}` };
      }
    })();
    emit('HTTP BRIDGE START', `hpts dedup: ${hpts.detail}`);
    enter('HTTP_PROXY_STARTING', `starting exactly ONE hpts -p ${cfg.httpPort}`);
    const spawnH = deps.spawnHptsFn ?? ((c: RecoveryMachineConfig) => spawnHpts(c, spawnFn as SpawnFn));
    const spawnedH = spawnH(cfg);
    emit('HTTP BRIDGE START', spawnedH.detail);
    if (!spawnedH.ok) {
      enter('RECOVERY_FAILED', spawnedH.detail);
      emit('RECOVERY FAILURE', spawnedH.detail);
      return fail();
    }
    const probe = deps.checkPort ?? checkTcpPort;
    const waited = await waitForPort(
      async (h, p, t) => {
        try {
          return await probe(h, p, t);
        } catch {
          return false;
        }
      },
      '127.0.0.1',
      cfg.httpPort,
      cfg.httpWaitMs,
      750,
      5000,
      sleep,
      now,
    );
    emit('HTTP PROXY CHECK', waited.up ? `TCP 127.0.0.1:${cfg.httpPort} opened after ${waited.waitedMs}ms` : `TCP 127.0.0.1:${cfg.httpPort} never opened`);
    if (!waited.up) {
      enter('RECOVERY_FAILED', `hpts started (pid ${spawnedH.pid}) but :${cfg.httpPort} never opened`);
      emit('RECOVERY FAILURE', `hpts started but HTTP port never opened`);
      return fail();
    }
    enter('HTTP_PROXY_UP', `TCP 127.0.0.1:${cfg.httpPort} listening`);
  } else {
    enter('HTTP_PROXY_UP', `TCP 127.0.0.1:${cfg.httpPort} already listening — bridge left alone`);
  }

  // -- G. HTTP proxy path end-to-end ----------------------------------------
  // Two-stage verification (bug fix: the old code compared the IP echoed by
  // api.ipify.org/checkip and declared RECOVERY_FAILED on any echo-service
  // outage — a diagnostic-service failure masquerading as an infrastructure
  // failure, the exact false-positive class this design forbids elsewhere).
  //
  //   Stage 1 (must pass): a lightweight transport probe through :8080
  //     (gstatic generate_204 — stable, never an echo service, never Zen).
  //     Failure here IS an infrastructure failure -> RECOVERY_FAILED.
  //   Stage 2 (evidence, not a verdict): observe egress via IP-echo through
  //     the bridge. A mismatch with the expected Elastic IP is still fatal
  //     (traffic demonstrably leaves elsewhere), but when every echo service
  //     is unreachable we report READY with "egress unverified" — matching the
  //     layered health-check philosophy that echo services must never sink
  //     an otherwise proven transport.
  emit('HTTP PROXY CHECK', `verifying HTTP proxy path via 127.0.0.1:${cfg.httpPort} (transport probe, then egress evidence)`);
  const { probeProxyTransport, DEFAULT_TRANSPORT_PROBE_URL } = await import('./health');
  const transportUrl = cfg.transportProbeUrl?.trim() || DEFAULT_TRANSPORT_PROBE_URL;
  const transportTimeout = Math.min(cfg.transportProbeTimeoutMs ?? cfg.checkTimeoutMs, cfg.checkTimeoutMs + 4000);
  const transport = deps.probeTransport
    ? await deps.probeTransport(transportUrl, transportTimeout)
    : await probeProxyTransport('127.0.0.1', cfg.httpPort, transportUrl, transportTimeout);
  emit('HTTP PROXY CHECK', transport.detail);
  if (!transport.ok) {
    const detail = `HTTP bridge transport probe failed: ${transport.detail}`;
    enter('RECOVERY_FAILED', detail);
    emit('RECOVERY FAILURE', detail);
    return fail();
  }

  const httpEgress = deps.httpEgress ?? (async () => {
    const { fetchTrafficIpFromServices, fetchViaHttpProxy, IP_CHECK_URLS } = await import('./health');
    const reading = await fetchTrafficIpFromServices(
      fetchViaHttpProxy,
      '127.0.0.1',
      cfg.httpPort,
      ['http://api.ipify.org/', ...IP_CHECK_URLS.filter((u) => u !== 'http://api.ipify.org/')],
      cfg.checkTimeoutMs,
    );
    return reading.ip;
  });
  try {
    const ip = (await httpEgress()).trim();
    egressViaHttp = ip;
    emit('HTTP PROXY CHECK', `HTTP proxy egress ${ip}`);
    if (cfg.expectedExternalIp && ip !== cfg.expectedExternalIp) {
      enter('RECOVERY_FAILED', `HTTP egress ${ip} != expected ${cfg.expectedExternalIp} — NOT leaving via EC2`);
      emit('RECOVERY FAILURE', `HTTP egress mismatch`);
      return fail();
    }
  } catch (e) {
    // Echo services down (or all answered non-IP bodies). The transport was
    // just proven end-to-end in stage 1; do NOT fail recovery on a diagnostic
    // service outage. The next regular health cycle re-verifies.
    const detail = (e as Error).message.slice(0, 200);
    egressViaHttp = null;
    egressVerified = false;
    emit('HTTP PROXY CHECK', `egress IP unverified (echo services unavailable): ${detail}`);
  }

  // -- H. READY ---------------------------------------------------------------
  const egressNote = egressVerified ? `egress via SOCKS ${egressViaSocks ?? '?'} / via HTTP ${egressViaHttp ?? '?'}` : `egress via SOCKS ${egressViaSocks ?? '?'} / HTTP egress unverified (echo services down; transport proven)`;
  enter('READY', egressNote);
  emit(
    'RECOVERY SUCCESS',
    egressVerified
      ? `proxy READY — SOCKS :${cfg.socksPort} + HTTP :${cfg.httpPort} verified end-to-end`
      : `proxy READY — transport verified end-to-end; egress IP unverified (echo services unavailable)`,
  );
  return {
    ok: true,
    state: 'READY',
    path,
    logs,
    egressViaSocks,
    egressViaHttp,
    egressVerified,
    publicIpDirect,
    sgRepaired,
    elapsedMs: now() - started,
  };

  function fail(): RecoveryOutcome {
    return {
      ok: false,
      state: 'RECOVERY_FAILED',
      path,
      logs,
      egressViaSocks,
      egressViaHttp,
      egressVerified,
      publicIpDirect,
      sgRepaired,
      elapsedMs: now() - started,
    };
  }
}

/** Map a recovery state onto the legacy health DisplayState space for UI reuse. */
export function recoveryToDisplay(s: RecoveryState): string {
  switch (s) {
    case 'READY':
      return 'HEALTHY';
    case 'RECOVERY_FAILED':
      return 'UNKNOWN';
    case 'AWS_SSH_UNREACHABLE':
    case 'SG_REPAIRING':
      return 'AWS_SSH_UNREACHABLE';
    case 'SOCKS_STARTING':
      return 'SOCKS_STARTING';
    case 'HTTP_PROXY_STARTING':
      return 'HTTP_STARTING';
    case 'SSH_PROCESS_DOWN':
      return 'SSH_DOWN';
    case 'SOCKS_DOWN':
      return 'SOCKS_DOWN';
    case 'SOCKS_UP':
    case 'HTTP_PROXY_UP':
    case 'HTTP_PROXY_DOWN':
      return s === 'HTTP_PROXY_DOWN' ? 'HTTP_BRIDGE_DOWN' : s;
    default:
      return 'UNKNOWN';
  }
}
