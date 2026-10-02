/**
 * diagnose.ts — on-demand deep diagnosis for failure states (no vscode dep).
 *
 * Steady-state ticks stay cheap (TCP + tasklist image names). Only when a
 * check transitions to failure (or the user manually refreshes while
 * unhealthy) do we spend a few extra process spawns to answer *why*:
 *   - exact ssh.exe / bridge command lines (key paths redacted),
 *   - Windows Scheduled Task states for the two proxy tasks,
 *   - which PID (if any) is listening on the SOCKS/HTTP ports.
 *
 * Everything is best-effort with timeouts; any failure becomes a note, never
 * an exception. No key material, tokens, or prompts are ever captured.
 */

import { execFile } from 'child_process';

export interface ExecOptions { env?: NodeJS.ProcessEnv; }
export type ExecAsync = (file: string, args: string[], timeoutMs: number, options?: ExecOptions) => Promise<string>;

export const SSH_TASK_NAME = 'OpenCode SSH SOCKS5';
export const BRIDGE_TASK_NAME = 'OpenCode HTTP Proxy Bridge';

export interface PortListener {
  port: number;
  pid: number;
}

export interface TaskState {
  name: string;
  status: string;
}

export interface DeepInfo {
  sshCmdlines: string[];
  bridgeCmdlines: string[];
  tasks: TaskState[];
  listeners: PortListener[];
  notes: string[];
}

export function emptyDeep(): DeepInfo {
  return { sshCmdlines: [], bridgeCmdlines: [], tasks: [], listeners: [], notes: [] };
}

/**
 * Redact secret-adjacent material from a command line: the argument to ssh -i
 * (a private-key *path*) and any stray *.pem token. Ports/hosts/flags stay.
 */
export function redactCommandLine(cmd: string): string {
  let out = cmd.replace(/(-i\s+)([^\s"']+|"[^"]*"|'[^']*')/, '$1<redacted>');
  out = out.replace(/(\s|^)([^\s"']*\.pem)(?=[\s"']|$)/gi, '$1<redacted-key-path>');
  if (out.length > 300) {
    out = `${out.slice(0, 300)}…`;
  }
  return out;
}

/** Split one `tasklist /FO CSV /NH` line into columns. */
function splitCsv(line: string): string[] {
  const cols: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      cols.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  cols.push(cur);
  return cols;
}

/** All PIDs from tasklist CSV output. Pure (also used for PID-liveness). */
export function parseTasklistPids(stdout: string): number[] {
  const pids: number[] = [];
  for (const line of String(stdout).split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith('"')) {
      continue;
    }
    const cols = splitCsv(t);
    if (cols.length >= 2) {
      const pid = parseInt(cols[1], 10);
      if (Number.isInteger(pid) && pid > 0) {
        pids.push(pid);
      }
    }
  }
  return pids;
}

/** Parse one `schtasks /query /TN <name> /FO CSV /NH` row. Pure. */
export function parseSchtasksRow(stdout: string): TaskState | null {
  for (const line of String(stdout).split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith('"')) {
      continue;
    }
    const cols = splitCsv(t);
    if (cols.length >= 3) {
      const full = cols[0].replace(/^\\+/, '');
      return { name: full, status: cols[2] };
    }
  }
  return null;
}

/** Parse `netstat -ano -p TCP` LISTENING rows for the given ports. Pure. */
export function parseNetstatListeners(stdout: string, ports: number[]): PortListener[] {
  const out: PortListener[] = [];
  for (const line of String(stdout).split(/\r?\n/)) {
    const m = line.match(/^\s*TCP\s+(\S+)\s+\S+\s+LISTENING\s+(\d+)\s*$/i);
    if (!m) {
      continue;
    }
    const local = m[1];
    const portStr = local.startsWith('[') ? local.slice(local.lastIndexOf(']:') + 2) : local.slice(local.lastIndexOf(':') + 1);
    const port = parseInt(portStr, 10);
    const pid = parseInt(m[2], 10);
    if (ports.includes(port) && Number.isInteger(pid)) {
      out.push({ port, pid });
    }
  }
  return out;
}

function defaultExec(file: string, args: string[], timeoutMs: number, options?: ExecOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(file, args, { ...options, timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(String(stdout ?? ''));
      }
    });
  });
}

interface CimRow {
  ProcessId?: number;
  Name?: string;
  CommandLine?: string | null;
}

function asRows(json: string): CimRow[] {
  const t = json.trim();
  if (!t) {
    return [];
  }
  const parsed: unknown = JSON.parse(t);
  const arr = Array.isArray(parsed) ? parsed : [parsed];
  return arr.filter((r): r is CimRow => typeof r === 'object' && r !== null);
}

/** Run the deep probes. Never throws; failures become notes. */
export async function deepDiagnose(
  ports: { socksPort: number; httpPort: number },
  exec: ExecAsync = defaultExec,
): Promise<DeepInfo> {
  const info = emptyDeep();

  // 1. Process command lines via a single CIM query.
  try {
    const ps =
      `Get-CimInstance Win32_Process -Filter "Name='ssh.exe' or Name='node.exe'" | ` +
      `Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress -Depth 2`;
    const out = await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], 12000);
    for (const row of asRows(out)) {
      const cmd = typeof row.CommandLine === 'string' ? row.CommandLine : '';
      if (row.Name === 'ssh.exe' && cmd) {
        info.sshCmdlines.push(redactCommandLine(cmd));
      } else if (row.Name === 'node.exe' && cmd.includes('http-proxy-to-socks')) {
        info.bridgeCmdlines.push(redactCommandLine(cmd));
      }
    }
    if (info.sshCmdlines.length === 0) {
      info.notes.push('no ssh.exe command line observed via CIM (process likely absent)');
    }
    if (info.bridgeCmdlines.length === 0) {
      info.notes.push('no http-proxy-to-socks node command line observed via CIM');
    }
  } catch (e) {
    info.notes.push(`process query failed: ${(e as Error).message.split('\n')[0]}`);
  }

  // 2. Scheduled task states.
  for (const task of [SSH_TASK_NAME, BRIDGE_TASK_NAME]) {
    try {
      const out = await exec('schtasks', ['/query', '/TN', task, '/FO', 'CSV', '/NH'], 8000);
      const row = parseSchtasksRow(out);
      info.tasks.push(row ?? { name: task, status: 'not found' });
    } catch (e) {
      info.tasks.push({ name: task, status: `query failed (${(e as Error).message.split('\n')[0]})` });
    }
  }

  // 3. Who (if anyone) listens on our ports.
  try {
    const out = await exec('netstat', ['-ano', '-p', 'TCP'], 8000);
    info.listeners = parseNetstatListeners(out, [ports.socksPort, ports.httpPort]);
    for (const p of [ports.socksPort, ports.httpPort]) {
      if (!info.listeners.some((l) => l.port === p)) {
        info.notes.push(`nothing listening on :${p}`);
      }
    }
  } catch (e) {
    info.notes.push(`netstat failed: ${(e as Error).message.split('\n')[0]}`);
  }

  return info;
}

/** Render DeepInfo as report lines. */
export function formatDeep(info: DeepInfo): string[] {
  const lines = ['Deep diagnosis (on-demand, best-effort):'];
  for (const c of info.sshCmdlines) {
    lines.push(`  ssh.exe: ${c}`);
  }
  for (const c of info.bridgeCmdlines) {
    lines.push(`  bridge:  ${c}`);
  }
  for (const t of info.tasks) {
    lines.push(`  task "${t.name}": ${t.status}`);
  }
  for (const l of info.listeners) {
    lines.push(`  :${l.port} listener pid: ${l.pid}`);
  }
  for (const n of info.notes) {
    lines.push(`  note: ${n}`);
  }
  return lines;
}
