/**
 * procOwn.ts — single-owner process supervision for ssh.exe and hpts.
 *
 * Problem: the old code asked only "is ANY ssh.exe running?" (image name via
 * tasklist) and treated that as tunnel health. Any random ssh.exe — a git
 * fetch, another tunnel, a stale lingering process after an SG block — counted
 * as success, while two competing ssh.exe processes could fight over :1080
 * with only one owning the port.
 *
 * Rules enforced here:
 * - Exactly ONE owner. The extension tracks the child it spawned (pid) AND
 *   identifies the exact expected command line via CIM. A random ssh.exe that
 *   does not match the expected pattern is NEVER assumed to be ours and is
 *   NEVER killed.
 * - Only processes whose command line matches the expected proxy pattern are
 *   considered "belonging to this proxy" and are eligible for stale/redundant
 *   termination. A foreign listener on :1080 is reported, not killed.
 * - Same discipline for hpts (node http-proxy-to-socks -p 8080 -s 127.0.0.1:1080).
 * - Idempotent: if the port already answers from an owned process, do nothing.
 * - Windows-native: CIM (Win32_Process CommandLine), taskkill, spawn with
 *   windowsHide. No WSL, no new dependencies.
 *
 * No secrets are logged: key paths are redacted via diagnose.redactCommandLine.
 */

import { spawn, ChildProcess } from 'child_process';
import { execFile } from 'child_process';
import { redactCommandLine, type ExecAsync } from './diagnose';
import { parseNetstatListeners } from './diagnose';
import { AWS_ELASTIC_IP } from './netModel';
import { win32 } from 'path';

export interface ProxyProcConfig {
  sshExe: string;
  sshKeyPath: string;
  sshUser: string;
  ec2Host: string;
  socksHost: string;
  socksPort: number;
  sshPort?: number;
  hptsCmd: string;
  httpPort: number;
}

export const DEFAULT_PROC_CONFIG: ProxyProcConfig = {
  sshExe: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
  sshKeyPath: '%USERPROFILE%\\.ssh\\opencode-proxy-key.pem',
  sshUser: 'ubuntu',
  ec2Host: AWS_ELASTIC_IP,
  socksHost: '127.0.0.1',
  socksPort: 1080,
  hptsCmd: '%USERPROFILE%\\npm-global\\hpts.cmd',
  httpPort: 8080,
};

/**
 * Hosts used by OLDER versions of this extension (pre netModel). Tunnels still
 * targeting them are OURS — spawned by the old build — and must remain
 * killable for the migration to the correct Elastic IP; otherwise a zombie
 * `ssh -D … ubuntu@13.48.149.186` would squat :1080 as a "foreign" process
 * the new code refuses to touch, and recovery could never replace it.
 * (Never 0.0.0.0/0 — this only widens OWNERSHIP matching, not authorization.)
 */
export const LEGACY_PROXY_HOSTS = ['13.48.149.186'] as const;

export interface OwnedProcess {
  pid: number;
  cmdline: string;
}

/** Expand %VAR% segments (Windows style) using process.env. Pure. */
export function expandEnv(p: string, env: NodeJS.ProcessEnv = process.env): string {
  return String(p).replace(/%([^%]+)%/g, (_, name: string) => env[name] ?? `%${name}%`);
}

/** Exact ssh.exe argv the extension owns. Key path expanded, never logged raw. */
export function buildSshArgs(cfg: ProxyProcConfig): string[] {
  const key = expandEnv(cfg.sshKeyPath);
  return [
    '-i',
    key,
    '-D',
    `${cfg.socksHost}:${cfg.socksPort}`,
    '-N',
    '-p',
    String(cfg.sshPort ?? 22),
    '-o',
    'ServerAliveInterval=30',
    '-o',
    'ServerAliveCountMax=3',
    '-o',
    // Stability fix: without a connect timeout a firewalled/half-open TCP
    // attempt (roaming laptop, SG blocked) can hang in SYN_SENT for the OS
    // default (~21s on Windows) while recovery waits the full socksWaitMs.
    'ConnectTimeout=8',
    '-o',
    // Refuse silent password prompts: a spawned tunnel must never sit at an
    // invisible prompt; if the key is rejected it must die and be reported.
    'BatchMode=yes',
    '-o',
    'ExitOnForwardFailure=yes',
    `${cfg.sshUser}@${cfg.ec2Host}`,
  ];
}

/** Exact hpts argv the extension owns. */
export function buildHptsArgs(cfg: ProxyProcConfig): string[] {
  return ['-p', String(cfg.httpPort), '-s', `${cfg.socksHost}:${cfg.socksPort}`];
}

/**
 * Does this command line belong to OUR ssh tunnel? Strict: must contain
 * ssh.exe, -D <host>:<port> (or -D <port> legacy), -N, and user@ec2Host.
 * A bare `ssh.exe` with no flags never matches. Pure.
 */
function tokens(cmdline: string): string[] {
  return (cmdline.match(/"[^"]*"|[^\s"]+/g) ?? []).map((v) => v.replace(/^"|"$/g, ''));
}

function option(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i >= 0) return args[i + 1];
  return args.find((v) => v.startsWith(flag) && v.length > flag.length)?.slice(flag.length);
}

function sshShape(args: string[], cfg: ProxyProcConfig): boolean {
  if (!/^ssh(?:\.exe)?$/i.test(win32.basename(args[0] ?? ''))) return false;
  const bind = option(args, '-D');
  return args.includes('-N') && (bind === String(cfg.socksPort) || bind === `${cfg.socksHost}:${cfg.socksPort}`);
}

export function isOurSshCmdline(cmdline: string, cfg: ProxyProcConfig): boolean {
  const args = tokens(cmdline);
  return sshShape(args, cfg) && args.includes(`${cfg.sshUser}@${cfg.ec2Host}`);
}

export function isLegacyProxySshCmdline(cmdline: string, cfg: ProxyProcConfig): boolean {
  const args = tokens(cmdline);
  return sshShape(args, cfg) && LEGACY_PROXY_HOSTS.some((h) => args.includes(`${cfg.sshUser}@${h}`));
}

export function isOurHptsCmdline(cmdline: string, cfg: ProxyProcConfig): boolean {
  const args = tokens(cmdline);
  const isBridge = args.some((v) => /(?:^|[\\/])(?:http-proxy-to-socks|hpts)(?:[\\/.]|$)/i.test(v));
  return isBridge && option(args, '-p') === String(cfg.httpPort) &&
    option(args, '-s') === `${cfg.socksHost}:${cfg.socksPort}`;
}

interface CimRow {
  ProcessId?: number;
  Name?: string;
  CommandLine?: string | null;
}

export function asRows(json: string): CimRow[] {
  const t = json.trim();
  if (!t) {
    return [];
  }
  const parsed: unknown = JSON.parse(t);
  const arr = Array.isArray(parsed) ? parsed : [parsed];
  return arr.filter((r): r is CimRow => typeof r === 'object' && r !== null);
}

function defaultExec(file: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(String(stdout ?? ''));
      }
    });
  });
}

export const CIM_PS =
  `$ErrorActionPreference='Stop'; Get-CimInstance Win32_Process -Filter "Name='ssh.exe' or Name='node.exe'" | ` +
  `Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress -Depth 2`;

/** List OUR ssh.exe processes (exact cmdline match). Never throws. */
export async function listOurSsh(
  exec: ExecAsync = defaultExec,
  cfg: ProxyProcConfig = DEFAULT_PROC_CONFIG,
): Promise<OwnedProcess[]> {
  try {
    const out = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', CIM_PS], 12000);
    const outList: OwnedProcess[] = [];
    for (const row of asRows(out)) {
      if (row.Name !== 'ssh.exe' || typeof row.CommandLine !== 'string' || typeof row.ProcessId !== 'number') {
        continue;
      }
      // Ownership includes legacy-version tunnels so the upgrade migration can
      // kill/replace them (see LEGACY_PROXY_HOSTS).
      if (isOurSshCmdline(row.CommandLine, cfg) || isLegacyProxySshCmdline(row.CommandLine, cfg)) {
        outList.push({ pid: row.ProcessId, cmdline: row.CommandLine });
      }
    }
    return outList;
  } catch {
    return [];
  }
}

/** List OUR hpts bridge processes (node.exe running http-proxy-to-socks/hpts). Never throws. */
export async function listOurHpts(
  exec: ExecAsync = defaultExec,
  cfg: ProxyProcConfig = DEFAULT_PROC_CONFIG,
): Promise<OwnedProcess[]> {
  try {
    const out = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', CIM_PS], 12000);
    const outList: OwnedProcess[] = [];
    for (const row of asRows(out)) {
      if (row.Name !== 'node.exe' || typeof row.CommandLine !== 'string' || typeof row.ProcessId !== 'number') {
        continue;
      }
      if (isOurHptsCmdline(row.CommandLine, cfg)) {
        outList.push({ pid: row.ProcessId, cmdline: row.CommandLine });
      }
    }
    return outList;
  } catch {
    return [];
  }
}

/** Which PID (if any) listens on the given port. Returns null when nobody listens. */
export async function listenerPidForPort(
  exec: ExecAsync,
  port: number,
): Promise<number | null> {
  try {
    const out = await exec('netstat', ['-ano', '-p', 'TCP'], 8000);
    const listeners = parseNetstatListeners(out, [port]);
    if (listeners.length === 0) {
      return null;
    }
    return listeners[0].pid;
  } catch {
    return null;
  }
}

/** Kill one PID via taskkill. Never throws. Redacts nothing (pids are safe). */
export async function killPid(
  exec: ExecAsync,
  pid: number,
): Promise<{ ok: boolean; detail: string }> {
  if (!Number.isInteger(pid) || pid <= 0) {
    return { ok: false, detail: `refusing to kill invalid pid ${pid}` };
  }
  try {
    const out = await exec('taskkill', ['/PID', String(pid), '/F', '/T'], 10000);
    return { ok: true, detail: `taskkill pid ${pid}: ${String(out).split('\n')[0].slice(0, 120)}` };
  } catch (e) {
    return { ok: false, detail: `taskkill pid ${pid} failed: ${(e as Error).message.split('\n')[0].slice(0, 160)}` };
  }
}

export interface DedupResult {
  kept: number | null;
  killed: number[];
  detail: string;
}

/**
 * Enforce exactly-one-owner for ssh:
 * - Discover OUR ssh processes (exact cmdline).
 * - If the port listener is a foreign PID (not ours), do NOT kill — report.
 * - If multiple ours exist, keep the one owning the port (or the lowest pid
 *   when nobody listens yet) and kill the rest.
 * - If exactly one ours exists, leave it alone.
 * - If none exist, report empty (caller spawns).
 */
export async function dedupOurSsh(
  exec: ExecAsync,
  cfg: ProxyProcConfig,
  portListenerPid: number | null,
): Promise<DedupResult> {
  const ours = await listOurSsh(exec, cfg);
  if (ours.length === 0) {
    if (portListenerPid !== null) {
      return { kept: null, killed: [], detail: `no owned ssh.exe but :${cfg.socksPort} held by foreign pid ${portListenerPid} — not killing (manual action needed)` };
    }
    return { kept: null, killed: [], detail: 'no owned ssh.exe process found' };
  }
  if (ours.length === 1) {
    return { kept: ours[0].pid, killed: [], detail: `one owned ssh.exe (pid ${ours[0].pid}) — ${redactCommandLine(ours[0].cmdline).slice(0, 120)}` };
  }
  let keep: OwnedProcess = ours[0];
  if (portListenerPid !== null) {
    const owner = ours.find((o) => o.pid === portListenerPid);
    if (owner) {
      keep = owner;
    }
  } else {
    keep = ours.slice().sort((a, b) => a.pid - b.pid)[0];
  }
  const killed: number[] = [];
  for (const o of ours) {
    if (o.pid === keep.pid) {
      continue;
    }
    const r = await killPid(exec, o.pid);
    if (r.ok) {
      killed.push(o.pid);
    }
  }
  return {
    kept: keep.pid,
    killed,
    detail: `dedup ssh: kept pid ${keep.pid}, killed [${killed.join(', ') || 'none'}] of ${ours.length} owned`,
  };
}

/** Same single-owner enforcement for the hpts bridge. */
export async function dedupOurHpts(
  exec: ExecAsync,
  cfg: ProxyProcConfig,
  portListenerPid: number | null,
): Promise<DedupResult> {
  const ours = await listOurHpts(exec, cfg);
  if (ours.length === 0) {
    if (portListenerPid !== null) {
      return { kept: null, killed: [], detail: `no owned hpts but :${cfg.httpPort} held by foreign pid ${portListenerPid} — not killing` };
    }
    return { kept: null, killed: [], detail: 'no owned hpts process found' };
  }
  if (ours.length === 1) {
    return { kept: ours[0].pid, killed: [], detail: `one owned hpts (pid ${ours[0].pid})` };
  }
  let keep: OwnedProcess = ours[0];
  if (portListenerPid !== null) {
    const owner = ours.find((o) => o.pid === portListenerPid);
    if (owner) {
      keep = owner;
    }
  } else {
    keep = ours.slice().sort((a, b) => a.pid - b.pid)[0];
  }
  const killed: number[] = [];
  for (const o of ours) {
    if (o.pid === keep.pid) {
      continue;
    }
    const r = await killPid(exec, o.pid);
    if (r.ok) {
      killed.push(o.pid);
    }
  }
  return { kept: keep.pid, killed, detail: `dedup hpts: kept pid ${keep.pid}, killed [${killed.join(', ') || 'none'}]` };
}

export type SpawnFn = (
  exe: string,
  args: string[],
  opts: { detached: boolean; windowsHide: boolean; windowsVerbatimArguments?: boolean },
) => { pid: number | null; error?: string };

/**
 * Launch exe with args. Stability fix for .cmd/.bat targets: since Node 18
 * (CVE-2024-27980 hardening) spawn() with shell:false REJECTS .cmd/.bat files
 * with EINVAL — which silently broke hpts bridge start on every machine with
 * a modern Node/VS Code (the default hptsCmd is a .cmd shim). Batch targets
 * are ALWAYS routed through `cmd.exe /d /s /c` HERE — independent of any
 * injected spawnFn — so every caller (default or test-injected) gets the
 * wrapper and no path can silently regress to a failing direct spawn.
 */
export function launchResolved(
  exe: string,
  args: string[],
  spawnFn: SpawnFn = rawSpawn,
): { pid: number | null; error?: string } {
  const lower = exe.trim().toLowerCase();
  const isBatch = lower.endsWith('.cmd') || lower.endsWith('.bat');
  const finalExe = isBatch ? 'cmd.exe' : exe;
  // cmd.exe needs one quoted command string, including outer /s quotes.
  // Reject expansion characters even inside quotes rather than reinterpreting paths.
  if (isBatch && [exe, ...args].some((v) => /["%!\r\n]/.test(v))) {
    return { pid: null, error: 'batch path/arguments contain unsupported expansion characters' };
  }
  const command = '"' + [exe, ...args].map((v) => `"${v}"`).join(' ') + '"';
  const finalArgs = isBatch ? ['/d', '/s', '/c', command] : args;
  return spawnFn(finalExe, finalArgs, { detached: true, windowsHide: true, windowsVerbatimArguments: isBatch });
}

function rawSpawn(
  exe: string,
  args: string[],
  opts: { detached: boolean; windowsHide: boolean; windowsVerbatimArguments?: boolean },
): { pid: number | null; error?: string } {
  try {
    const child: ChildProcess = spawn(exe, args, {
      ...opts,
      stdio: 'ignore',
      shell: false,
    });
    // ENOENT/EACCES are emitted asynchronously; an unhandled error kills the host.
    child.once('error', () => {});
    child.unref?.();
    return { pid: typeof child.pid === 'number' ? child.pid : null };
  } catch (e) {
    return { pid: null, error: (e as Error).message };
  }
}

/** Spawn exactly one ssh tunnel (caller must have deduped first). Never logs the key path. */
export function spawnSsh(
  cfg: ProxyProcConfig,
  spawnFn: SpawnFn = rawSpawn,
): { ok: boolean; pid: number | null; detail: string } {
  const exe = expandEnv(cfg.sshExe);
  const args = buildSshArgs(cfg);
  try {
    const r = launchResolved(exe, args, spawnFn);
    if (r.pid && r.pid > 0) {
      return { ok: true, pid: r.pid, detail: `ssh spawned (pid ${r.pid}) -D ${cfg.socksHost}:${cfg.socksPort} -> ${cfg.sshUser}@${cfg.ec2Host}` };
    }
    return { ok: false, pid: null, detail: `ssh spawn failed: ${r.error ?? 'no pid'}` };
  } catch (e) {
    return { ok: false, pid: null, detail: `ssh spawn threw: ${(e as Error).message.slice(0, 160)}` };
  }
}

/** Spawn exactly one hpts bridge (caller must have deduped + verified SOCKS first). */
export function spawnHpts(
  cfg: ProxyProcConfig,
  spawnFn: SpawnFn = rawSpawn,
): { ok: boolean; pid: number | null; detail: string } {
  const exe = expandEnv(cfg.hptsCmd);
  const args = buildHptsArgs(cfg);
  try {
    const r = launchResolved(exe, args, spawnFn);
    if (r.pid && r.pid > 0) {
      return { ok: true, pid: r.pid, detail: `hpts spawned (pid ${r.pid}) -p ${cfg.httpPort} -s ${cfg.socksHost}:${cfg.socksPort}` };
    }
    return { ok: false, pid: null, detail: `hpts spawn failed: ${r.error ?? 'no pid'}` };
  } catch (e) {
    return { ok: false, pid: null, detail: `hpts spawn threw: ${(e as Error).message.slice(0, 160)}` };
  }
}
