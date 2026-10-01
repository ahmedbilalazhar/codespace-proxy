import { parseNetstatListeners, type ExecAsync } from './diagnose';
import { asRows, CIM_PS, isOurSshCmdline, isLegacyProxySshCmdline, isOurHptsCmdline, killPid, ProxyProcConfig } from './procOwn';

export interface ShutdownConfig extends ProxyProcConfig {
  sshTaskName: string;
  bridgeTaskName: string;
}

/** Strict discovery: a failed process query cannot prove the proxy is off. */
async function owned(exec: ExecAsync, cfg: ShutdownConfig) {
  const rows = asRows(await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', CIM_PS], 12000));
  return rows.filter((r) => typeof r.ProcessId === 'number' && typeof r.CommandLine === 'string' &&
    (r.Name === 'node.exe' ? isOurHptsCmdline(r.CommandLine, cfg) :
      r.Name === 'ssh.exe' && (isOurSshCmdline(r.CommandLine, cfg) || isLegacyProxySshCmdline(r.CommandLine, cfg))))
    .sort((a, b) => Number(a.Name === 'ssh.exe') - Number(b.Name === 'ssh.exe'));
}

/** Disable launchers before stopping children so retry loops cannot respawn them.
 * rememberTask persists restoration intent BEFORE the first task mutation.
 */
export async function shutdownProxy(exec: ExecAsync, cfg: ShutdownConfig,
  rememberTask: (name: string) => Promise<void>,
): Promise<{ ok: boolean; details: string[] }> {
  const details: string[] = [];
  let ok = true;
  for (const name of [...new Set([cfg.bridgeTaskName, cfg.sshTaskName])]) {
    try {
      // Native object fields avoid locale-dependent schtasks text parsing.
      const literal = "'" + name.replace(/'/g, "''") + "'";
      const query = `$ErrorActionPreference='Stop'; $n=${literal}; Get-ScheduledTask | Where-Object { ($_.TaskPath + $_.TaskName).TrimStart([char]92) -eq $n.TrimStart([char]92) } | Select-Object TaskName,TaskPath,@{Name='State';Expression={[string]$_.State}},@{Name='Enabled';Expression={[bool]$_.Settings.Enabled}} | ConvertTo-Json -Compress`;
      const raw = (await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', query], 10000)).trim();
      if (!raw) continue;
      const task = JSON.parse(raw);
      if (Array.isArray(task) || !task.TaskName || !task.State || typeof task.Enabled !== 'boolean') throw new Error('task query was ambiguous');
      if (task.Enabled) {
        await rememberTask(name);
        await exec('schtasks', ['/change', '/TN', name, '/DISABLE'], 10000);
      }
      if (['Running', 'Queued', '4', '2'].includes(String(task.State))) await exec('schtasks', ['/end', '/TN', name], 10000);
      const verified = JSON.parse(await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', query], 10000));
      if (verified.Enabled !== false || !['Disabled', '1'].includes(String(verified.State))) {
        throw new Error('task did not reach a verified disabled/stopped state');
      }
      details.push(`Task "${name}" disabled/stopped.`);
    } catch (e) {
      ok = false;
      details.push(`Cannot stop task "${name}": ${(e as Error).message}`);
    }
  }
  try {
    for (const row of await owned(exec, cfg)) {
      const result = await killPid(exec, row.ProcessId!);
      details.push(result.detail);
      if (!result.ok) ok = false;
    }
    const remaining = await owned(exec, cfg);
    if (remaining.length) {
      ok = false;
      details.push(`Owned proxy processes remain: ${remaining.map((r) => r.ProcessId).join(', ')}.`);
    }
  } catch (e) {
    ok = false;
    details.push(`Cannot verify proxy processes stopped: ${(e as Error).message}`);
  }
  try {
    const listeners = parseNetstatListeners(await exec('netstat', ['-ano', '-p', 'TCP'], 8000), [cfg.socksPort, cfg.httpPort]);
    if (listeners.length) {
      ok = false;
      details.push(`Proxy ports still have listeners: ${listeners.map((l) => `:${l.port} pid ${l.pid}`).join(', ')}. Unrelated listeners are left untouched.`);
    }
  } catch (e) {
    ok = false;
    details.push(`Cannot verify proxy ports closed: ${(e as Error).message}`);
  }
  return { ok, details };
}
