/**
 * awsNet.ts — bootstrap networking that MUST NOT depend on the proxy.
 *
 * Problem: the laptop roams (university / home / cafe / hotspot), so its
 * public IP changes. The AWS Security Group restricts TCP 22 to the old
 * public IP /32, so SSH dies while a stale ssh.exe lingers and :1080 is dead.
 *
 * Ground rules (bootstrap constraint):
 * - NOTHING in this file uses the HTTP proxy (:8080) or the SOCKS tunnel
 *   (:1080) or OpenCode. All checks are DIRECT (NO_PROXY equivalent).
 * - NEVER hardcode AWS credentials. All SG mutations go through the
 *   machine's existing AWS CLI configuration (profile/region/env), which the
 *   user already trusts. No access keys in source, logs, or settings.
 * - Least privilege: only configured SSH-port /32 rules marked for this proxy are
 *   touched. Never opens 0.0.0.0/0 automatically. Duplicates are avoided by
 *   describing first, then authorizing and verifying current access before
 *   revoking stale managed rules.
 *
 * Zero runtime dependencies; Windows-compatible; every function bounded by
 * timeouts and injectable for unit tests.
 */

import * as https from 'https';
import * as http from 'http';
import { checkTcpPort, isPlausibleIp } from './health';
import type { ExecAsync } from './diagnose';
import { AWS_ELASTIC_IP, AWS_REGION } from './netModel';

export const DEFAULT_EC2_HOST = AWS_ELASTIC_IP;
export const DEFAULT_SSH_PORT = 22;
export const PROXY_TAG = 'opencode-proxy';

/** Direct (proxy-bypass) public-IP services, tried in order. HTTPS only. */
export const DIRECT_IP_URLS = [
  'https://api.ipify.org/',
  'https://checkip.amazonaws.com/',
  'https://ifconfig.me/ip',
];

export interface AwsNetConfig {
  ec2Host: string;
  sshPort: number;
  /** EC2 security group id that guards TCP 22 (e.g. sg-0abc...). Empty = SG repair disabled. */
  securityGroupId: string;
  /** AWS CLI profile to use (empty = default profile chain). Never a secret. */
  awsProfile: string;
  /** AWS region (empty = CLI default / env). e.g. eu-north-1 for the Elastic IP. */
  awsRegion: string;
  checkTimeoutMs: number;
}

export const DEFAULT_AWS_REGION = AWS_REGION;

export const DEFAULT_AWSNET_CONFIG: AwsNetConfig = {
  ec2Host: DEFAULT_EC2_HOST,
  sshPort: DEFAULT_SSH_PORT,
  securityGroupId: '',
  awsProfile: '',
  awsRegion: DEFAULT_AWS_REGION,
  checkTimeoutMs: 8000,
};

export type FetchDirect = (url: string, timeoutMs: number) => Promise<string>;

/**
 * DIRECT fetch of one URL, ALWAYS bypassing HTTP_PROXY/HTTPS_PROXY.
 * Node http/https do not auto-use proxy env, but we enforce the bypass
 * explicitly: snapshot + delete proxy vars for the duration of the request
 * (restored afterwards) and use a dedicated no-proxy agent. This function
 * never touches 127.0.0.1:8080 or 127.0.0.1:1080.
 */
const PROXY_ENV_VARS = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'];

/**
 * Refcounted process-wide proxy-bypass.
 *
 * BUG FIX (race): the previous implementation snapshotted and mutated
 * process.env per request. Two overlapping direct fetches (public-IP poll vs
 * a recovery-triggered fetch) each restored their OWN snapshot, so the second
 * restore could resurrect HTTP_PROXY/HTTPS_PROXY while the first request was
 * still in flight — silently routing a "direct" lookup through the broken
 * proxy. Now the bypass is acquired once for N concurrent callers and the
 * environment is restored only when the LAST caller releases.
 */
interface ProxyEnvSnapshot {
  values: Map<string, string | undefined>;
}
let bypassDepth = 0;
let bypassSnapshot: ProxyEnvSnapshot | null = null;

function acquireProxyBypass(): void {
  if (bypassDepth === 0) {
    const values = new Map<string, string | undefined>();
    for (const k of PROXY_ENV_VARS) {
      values.set(k, process.env[k]);
      delete process.env[k];
    }
    bypassSnapshot = { values };
  }
  bypassDepth += 1;
}

function releaseProxyBypass(): void {
  if (bypassDepth === 0 || !bypassSnapshot) {
    return;
  }
  bypassDepth -= 1;
  if (bypassDepth > 0) {
    return; // Another direct fetch still needs the bypass held.
  }
  const saved = bypassSnapshot.values;
  bypassSnapshot = null;
  // Windows env keys are case-INSENSITIVE: HTTP_PROXY and http_proxy share one
  // slot. Set all defined values first; delete only names with no defined
  // case-variant, so restoring never clobbers a live bypass held elsewhere.
  const defined = new Set<string>();
  for (const [k, v] of saved) {
    if (v !== undefined) {
      defined.add(k.toLowerCase());
    }
  }
  for (const [k, v] of saved) {
    if (v === undefined) {
      if (!defined.has(k.toLowerCase())) {
        delete process.env[k];
      }
    } else {
      process.env[k] = v;
    }
  }
}

export function fetchDirectUrl(url: string, timeoutMs: number): Promise<string> {
  // Enforce proxy bypass even if a future http client starts honouring env.
  acquireProxyBypass();
  const restore = releaseProxyBypass;
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(url);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('unsupported protocol');
    } catch {
      restore();
      reject(new Error(`bad direct IP URL: ${url}`));
      return;
    }
    const lib = u.protocol === 'https:' ? https : http;
    const agent = u.protocol === 'https:' ? new https.Agent({ keepAlive: false }) : new http.Agent({ keepAlive: false });
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const done = (fn: () => void) => {
      // end/error/timeout can arrive for the same request. Release its bypass
      // exactly once, and cancel its deadline so it cannot release a later poll.
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      agent.destroy();
      restore();
      fn();
    };
    let req: http.ClientRequest;
    try { req = lib.get(
      url,
      { timeout: timeoutMs, family: 4, headers: { 'User-Agent': 'opencode-proxy-health' }, agent },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          done(() => reject(new Error(`direct IP service ${url} answered HTTP ${res.statusCode}`)));
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => {
          body += c;
          if (body.length > 1024) {
            req.destroy();
            done(() => reject(new Error(`direct IP service ${url} answered an oversize body`)));
          }
        });
        res.on('end', () => done(() => resolve(body.trim())));
        res.on('error', (e) => done(() => reject(e)));
        res.on('aborted', () => done(() => reject(new Error('direct IP response aborted'))));
      },
    ); } catch (e) { done(() => reject(e)); return; }
    req.on('timeout', () => {
      req.destroy();
      done(() => reject(new Error(`timed out after ${timeoutMs}ms fetching ${url} directly (proxy bypassed)`)));
    });
    req.on('error', (e) => done(() => reject(e as Error)));
    timer = setTimeout(() => {
      try {
        req.destroy();
      } catch {
        /* ignore */
      }
      done(() => reject(new Error(`timed out after ${timeoutMs}ms fetching ${url} directly (proxy bypassed)`)));
    }, timeoutMs + 1000);
    timer.unref?.();
  });
}

/**
 * Discover the laptop's CURRENT public IP without touching the proxy.
 * Tries each DIRECT_IP_URLS entry; first plausible IP wins.
 */
export async function fetchDirectPublicIp(
  fetchOne: FetchDirect,
  urls: string[],
  timeoutMs: number,
): Promise<{ ip: string; service: string }> {
  const errors: string[] = [];
  for (const url of urls) {
    try {
      const ip = (await fetchOne(url, timeoutMs)).trim();
      if (isPlausibleIp(ip) && !ip.includes(':')) {
        return { ip, service: url };
      }
      errors.push(`${url} did not answer with a public IPv4 address`);
    } catch (e) {
      errors.push(`${url}: ${(e as Error).message.split('\n')[0].slice(0, 160)}`);
    }
  }
  throw new Error(`direct public-IP discovery failed (proxy bypassed; ${errors.join('; ')})`);
}

/** True when TCP ec2Host:sshPort answers within timeoutMs (direct, no proxy). */
export function checkAwsSshReachable(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return checkTcpPort(host, port, timeoutMs);
}

// ---------------------------------------------------------------------------
// Security-group handling via the existing AWS CLI configuration.
// ---------------------------------------------------------------------------

export interface SshRule {
  cidr: string;
  description: string;
  groupId: string;
}

function awsBaseArgs(cfg: AwsNetConfig): string[] {
  const args: string[] = [];
  if (cfg.awsProfile.trim()) {
    args.push('--profile', cfg.awsProfile.trim());
  }
  if (cfg.awsRegion.trim()) {
    args.push('--region', cfg.awsRegion.trim());
  }
  return args;
}

function firstLine(s: string): string {
  return String(s).split('\n')[0].slice(0, 200);
}

/**
 * Invoke the AWS CLI portably. On Windows the per-user pip install provides
 * only `aws.cmd` (no aws.exe), which Node's execFile cannot spawn directly
 * (ENOENT) — route through cmd.exe. Real .exe installs also work via cmd.
 * All args are ours (group ids, CIDRs, flags); no shell metacharacters.
 */
function runAws(exec: ExecAsync, args: string[], timeoutMs: number): Promise<string> {
  if (process.platform === 'win32') {
    return exec('cmd.exe', ['/d', '/c', 'aws', ...args], timeoutMs);
  }
  return exec('aws', args, timeoutMs);
}

/** Describe TCP-22 ingress rules on the SG. Never throws — failures are data. */
export async function describeSshRules(
  exec: ExecAsync,
  cfg: AwsNetConfig,
): Promise<{ ok: boolean; rules: SshRule[]; detail: string }> {
  if (!cfg.securityGroupId.trim()) {
    return { ok: false, rules: [], detail: 'no securityGroupId configured — SG repair disabled' };
  }
  // NOTE: the query intentionally avoids JMESPath filters (`&&`, backticks,
  // spaces): this command also runs under cmd.exe /c on Windows, where `&&`
  // chains commands. Port/protocol filtering happens in parseSshPermissions.
  const args = [
    'ec2',
    'describe-security-groups',
    '--group-ids',
    cfg.securityGroupId.trim(),
    '--query',
    'SecurityGroups[0].IpPermissions',
    '--output',
    'json',
    ...awsBaseArgs(cfg),
  ];
  try {
    const out = await runAws(exec, args, Math.min(cfg.checkTimeoutMs + 7000, 15000));
    if (!Array.isArray(JSON.parse(out))) throw new Error('invalid security-group permissions response');
    const rules = parseSshPermissions(out, cfg.securityGroupId.trim(), cfg.sshPort);
    return { ok: true, rules, detail: `${rules.length} TCP-${cfg.sshPort} rule(s) on ${cfg.securityGroupId.trim()}` };
  } catch (e) {
    return { ok: false, rules: [], detail: `describe-security-groups failed: ${firstLine((e as Error).message)}` };
  }
}

/**
 * Parse describe-security-groups IpPermissions JSON into flat SSH-rule list.
 * Keeps only permissions covering TCP 22 (explicit tcp/22 or all-traffic
 * -1/-1). Pure. Non-SSH permissions (HTTP, etc.) are ignored so repair never
 * touches unrelated rules.
 */
export function parseSshPermissions(json: string, groupId: string, port = 22): SshRule[] {
  const out: SshRule[] = [];
  try {
    const parsed: unknown = JSON.parse(json.trim() === '' ? '[]' : json);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    for (const perm of arr) {
      if (typeof perm !== 'object' || perm === null) {
        continue;
      }
      const rec = perm as Record<string, unknown>;
      if (!coversTcpPort(rec.IpProtocol, rec.FromPort, rec.ToPort, port)) {
        continue;
      }
      const ranges = rec.IpRanges;
      if (!Array.isArray(ranges)) {
        continue;
      }
      for (const r of ranges) {
        if (typeof r !== 'object' || r === null) {
          continue;
        }
        const cidr = (r as Record<string, unknown>).CidrIp;
        const desc = (r as Record<string, unknown>).Description;
        if (typeof cidr === 'string' && cidr.trim()) {
          out.push({
            cidr: cidr.trim(),
            description: typeof desc === 'string' ? desc : '',
            groupId,
          });
        }
      }
    }
  } catch {
    // Unparseable CLI output -> no rules (caller reports the detail).
  }
  return out;
}

/** True when an IpPermission covers inbound TCP 22. Pure. */
function coversTcpPort(proto: unknown, from: unknown, to: unknown, port: number): boolean {
  if (proto === '-1') {
    return true; // all traffic includes TCP 22
  }
  if (proto !== 'tcp') {
    return false;
  }
  if (typeof from !== 'number' || typeof to !== 'number') {
    return false;
  }
  return from <= port && port <= to;
}

/** Is this a /32 rule created by this proxy (safe to replace)? Pure. */
export function isProxyManagedRule(rule: SshRule): boolean {
  if (!rule.cidr.endsWith('/32')) {
    return false;
  }
  const d = rule.description.toLowerCase();
  return d.includes(PROXY_TAG) || d.includes('opencode');
}

/**
 * Does any rule already allow SSH from currentIp? Exact /32 match, or a
 * pre-existing wide-open rule an admin left in place (detected, never
 * created by us). Pure.
 */
export function authorizesIp(rules: SshRule[], currentIp: string): boolean {
  return rules.some((r) => r.cidr === `${currentIp}/32` || r.cidr === '0.0.0.0/0');
}

/** Stale /32 rules that may be revoked (proxy-managed, not the current IP). Pure. */
export function staleProxyRules(rules: SshRule[], currentIp: string): SshRule[] {
  return rules.filter((r) => r.cidr.endsWith('/32') && r.cidr !== `${currentIp}/32` && isProxyManagedRule(r));
}

export interface SgUpdateResult {
  ok: boolean;
  detail: string;
  authorizedCurrent: boolean;
  revoked: string[];
}

/**
 * Safely replace stale SSH /32 rules with the current IP /32:
 *   1. describe first (no blind adds, no duplicates),
 *   2. if current IP already authorized -> verify-only, no mutation,
 *   3. authorize current IP /32 with Description "opencode-proxy",
 *   4. describe again to verify before removing any old access,
 *   5. revoke stale proxy-managed /32s (never 0.0.0.0/0, never foreign rules).
 *
 * Never opens 0.0.0.0/0. Never touches non-/32 or non-proxy rules.
 */
export async function ensureSshAccess(
  exec: ExecAsync,
  cfg: AwsNetConfig,
  currentIp: string,
): Promise<SgUpdateResult> {
  const gid = cfg.securityGroupId.trim();
  if (!gid) {
    return { ok: false, detail: 'no securityGroupId configured — SG repair disabled', authorizedCurrent: false, revoked: [] };
  }
  if (!isPlausibleIp(currentIp) || currentIp.includes(':')) {
    return { ok: false, detail: `refusing SG update for non-IPv4 address ${currentIp.slice(0, 40)}`, authorizedCurrent: false, revoked: [] };
  }
  const before = await describeSshRules(exec, cfg);
  if (!before.ok) {
    return { ok: false, detail: before.detail, authorizedCurrent: false, revoked: [] };
  }
  if (authorizesIp(before.rules, currentIp)) {
    return { ok: true, detail: `${currentIp}/32 already authorized on ${gid} — no change`, authorizedCurrent: true, revoked: [] };
  }
  const revoked: string[] = [];
  try {
    await runAws(
      exec,
      [
        'ec2',
        'authorize-security-group-ingress',
        '--group-id',
        gid,
        '--ip-permissions',
        // No whitespace/quotes: also passed through cmd.exe on Windows.
        // The description is returned by describe-security-groups, unlike tags.
        `IpProtocol=tcp,FromPort=${cfg.sshPort},ToPort=${cfg.sshPort},IpRanges=[{CidrIp=${currentIp}/32,Description=${PROXY_TAG}}]`,
        ...awsBaseArgs(cfg),
      ],
      15000,
    );
  } catch (e) {
    const msg = firstLine((e as Error).message);
    if (/already exists|duplicate/i.test(msg)) {
      // Race: someone else added it — verify below.
    } else {
      return { ok: false, detail: `authorize ${currentIp}/32 failed: ${msg}`, authorizedCurrent: false, revoked };
    }
  }
  const after = await describeSshRules(exec, cfg);
  if (!after.ok) {
    return { ok: false, detail: `authorized ${currentIp}/32 but verification describe failed: ${after.detail}`, authorizedCurrent: false, revoked };
  }
  if (authorizesIp(after.rules, currentIp)) {
    const warnings: string[] = [];
    // Only remove rules seen both before and after authorizing our replacement.
    const staleBefore = new Set(staleProxyRules(before.rules, currentIp).map((r) => r.cidr));
    for (const stale of staleProxyRules(after.rules, currentIp).filter((r) => staleBefore.has(r.cidr))) {
      try {
        await runAws(exec,
          ['ec2', 'revoke-security-group-ingress', '--group-id', gid, '--protocol', 'tcp', '--port', String(cfg.sshPort), '--cidr', stale.cidr, ...awsBaseArgs(cfg)],
          15000);
        revoked.push(stale.cidr);
      } catch (e) {
        warnings.push(`stale ${stale.cidr} retained: ${firstLine((e as Error).message)}`);
      }
    }
    const extra = revoked.length > 0 ? ` (revoked stale ${revoked.join(', ')})` : '';
    return { ok: true, detail: `authorized ${currentIp}/32 on ${gid}${extra} — verified${warnings.length ? `; cleanup warning: ${warnings.join('; ')}` : ''}`, authorizedCurrent: true, revoked };
  }
  return { ok: false, detail: `authorize appeared to succeed but ${currentIp}/32 not present on re-check`, authorizedCurrent: false, revoked };
}

/** Minimal IAM permissions required for SG self-repair (for README/docs). */
export const REQUIRED_IAM_ACTIONS = [
  'ec2:DescribeSecurityGroups',
  'ec2:AuthorizeSecurityGroupIngress',
  'ec2:RevokeSecurityGroupIngress',
];
