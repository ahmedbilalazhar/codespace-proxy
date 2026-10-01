/**
 * extension.ts — VS Code integration for the OpenCode proxy health monitor.
 *
 * Two supervisors (explicit, never both at once):
 * - direct (default, recommended): the extension is the SOLE owner. It spawns
 *   exactly one ssh.exe + one hpts, verifies ports + SOCKS end-to-end, and
 *   repairs the AWS SSH security group when the public IP roams. See
 *   src/recoveryMachine.ts. Disable the legacy Task Scheduler tasks in this
 *   mode ("OpenCode SSH SOCKS5", "OpenCode HTTP Proxy Bridge") so two
 *   supervisors never fight.
 * - task (legacy): monitor + opt-in schtasks-based restarts of your existing
 *   scheduled tasks (src/recover.ts + src/runbook.ts). Kept for compatibility.
 *
 * Bootstrap constraint: recovery NEVER requires OpenCode or a healthy proxy.
 */

import * as vscode from 'vscode';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import {
  DEFAULT_CONFIG,
  HealthConfig,
  HealthResult,
  HealthState,
  IP_CHECK_URLS,
  checkTcpPort,
  deriveState,
  fetchTrafficIpFromServices,
  fetchViaHttpProxy,
  formatReport,
  probeZenService,
  runHealthCheckGuarded,
} from './health';
import {
  DEFAULT_POLICY_CONFIG,
  DEFAULT_RECOVERY_CADENCE,
  PolicyState,
  RecoveryCadenceState,
  ZenState,
  createProbeGate,
  emptyPolicy,
  emptyRecoveryCadence,
  emptyZen,
  hasRecentTrafficOk,
  nextPolicy,
  nextRecoveryCadence,
  nextZen,
  shouldNotifyRecovery,
} from './healthPolicy';
import {
  DisplayState,
  NO_TRACKING,
  RequestSummary,
  StatusStyle,
  barText,
  overlayRequest,
  presentDisplay,
} from './status';
import {
  AssessResult,
  DONE_SUFFIX,
  RUNNING_SUFFIX,
  assessRequests,
  checkPidAlive,
  summarizeRequests,
} from './requests';
import {
  HealthHistory,
  emptyHistory,
  formatDuration,
  sanitizeHistory,
  sparkline,
  updateHistory,
  uptimeSummary,
} from './history';
import { DeepInfo, deepDiagnose, emptyDeep, formatDeep } from './diagnose';
import {
  RecoverAttempt,
  RecoverConfig,
  defaultExecAsync,
  planRecovery,
  reviveScheduledTask,
  taskForState,
} from './recover';
import {
  RunbookConfig,
  RunbookResult,
  formatProxyEnv,
  formatRunbook,
  runRunbook,
} from './runbook';
import {
  DEFAULT_RECOVERY_CONFIG,
  RecoveryMachineConfig,
  RecoveryState,
  isRecoveryRunning,
  recoverProxy,
} from './recoveryMachine';
import { ProxyLifecycle } from './lifecycle';
import { shutdownProxy } from './shutdown';
import { DEFAULT_PROC_CONFIG } from './procOwn';
import { DEFAULT_AWSNET_CONFIG, DIRECT_IP_URLS, checkAwsSshReachable, ensureSshAccess, fetchDirectPublicIp, fetchDirectUrl } from './awsNet';
import { queryScheduledTask } from './recover';
import { AWS_ELASTIC_IP, AWS_REGION } from './netModel';

const CHANNEL_NAME = 'OpenCode Proxy Health';
const HISTORY_KEY = 'history.v1';
const ENABLED_KEY = 'proxy.enabled.v1';
const STOP_ERROR_KEY = 'proxy.shutdownIncomplete.v1';
const TASKS_KEY = 'proxy.disabledTasks.v1';
const MAX_TRACK_FILES = 200;
/** Wrapper-PID liveness cache: a long request must not cost a tasklist spawn per tick. */
const PID_CACHE_TTL_MS = 30_000;

type NotifyMode = 'all' | 'errors' | 'none';

type SupervisorMode = 'direct' | 'task';

interface ExtConfig extends HealthConfig {
  intervalSec: number;
  notifications: NotifyMode;
  slowThresholdMs: number;
  logToFile: boolean;
  logFileMaxLines: number;
  trackRequests: boolean;
  requestDir: string;
  autoRecover: boolean;
  autoRecoverDryRun: boolean;
  compactTooltip: boolean;
  autoRecoverMaxAttempts: number;
  autoRecoverCooldownSec: number;
  sshTaskName: string;
  bridgeTaskName: string;
  statusStyle: StatusStyle;
  runbookPortWaitSec: number;
  runbookLaunchOpencode: boolean;
  opencodeCommand: string;
  autoRecoverResetStuckTask: boolean;
  supervisorMode: SupervisorMode;
  ec2Host: string;
  sshPort: number;
  sshExe: string;
  sshKeyPath: string;
  sshUser: string;
  hptsCmd: string;
  securityGroupId: string;
  awsProfile: string;
  awsRegion: string;
  enableAwsRepair: boolean;
  bootstrapRecoverOnStartup: boolean;
  publicIpPollSec: number;
  recoveryMaxAttempts: number;
  recoveryBaseDelayMs: number;
  socksWaitSec: number;
  httpWaitSec: number;
  transportProbeUrl: string;
  portProbeTimeoutMs: number;
  transportProbeTimeoutMs: number;
  zenProbeTimeoutMs: number;
  zenProbeIntervalSec: number;
  failureThreshold: number;
  minOutageNotifySec: number;
  recentTrafficWindowSec: number;
}

function defaultRequestDir(): string {
  return path.join(os.tmpdir(), 'opencode-proxy-health', 'requests');
}

function readExtConfig(): { cfg: ExtConfig; warnings: string[] } {
  const c = vscode.workspace.getConfiguration('opencodeProxyHealth');
  const warnings: string[] = [];
  const num = (key: string, fallback: number, min: number, max = Number.MAX_SAFE_INTEGER): number => {
    const v = c.get<number>(key, fallback);
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max) {
      warnings.push(`setting ${key}=${String(v)} invalid, using ${fallback}`);
      return fallback;
    }
    return v;
  };
  const str = (key: string, fallback: string): string => {
    const v = c.get<string>(key, fallback);
    if (typeof v !== 'string') {
      warnings.push(`setting ${key} invalid, using default`);
      return fallback;
    }
    return v;
  };
  const port = (key: string, fallback: number): number => {
    const raw = c.get<number>(key, fallback);
    if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 1 || raw > 65535) {
      warnings.push(`setting ${key}=${String(raw)} invalid, using ${fallback}`);
      return fallback;
    }
    return raw;
  };

  const socksPort = port('socksPort', DEFAULT_CONFIG.socksPort);
  const httpPort = port('httpPort', DEFAULT_CONFIG.httpPort);
  if (socksPort === httpPort) {
    warnings.push(`socksPort and httpPort are both ${socksPort}; they should differ`);
  }
  const intervalRaw = c.get<number>('healthCheckInterval', 10);
  const intervalSec =
    typeof intervalRaw === 'number' && Number.isFinite(intervalRaw) ? Math.max(3, Math.round(intervalRaw)) : 10;
  if (typeof intervalRaw === 'number' && intervalRaw < 3) {
    warnings.push(`healthCheckInterval=${intervalRaw} clamped to minimum 3s`);
  }
  let zenEndpoint = str('zenEndpoint', DEFAULT_CONFIG.zenEndpoint);
  try {
    const u = new URL(zenEndpoint);
    if (u.protocol !== 'https:') {
      throw new Error('not https');
    }
  } catch {
    warnings.push(`zenEndpoint invalid, using ${DEFAULT_CONFIG.zenEndpoint}`);
    zenEndpoint = DEFAULT_CONFIG.zenEndpoint;
  }
  let model = str('model', DEFAULT_CONFIG.model);
  if (model.trim().length === 0) {
    warnings.push('model is empty, using default');
    model = DEFAULT_CONFIG.model;
  }
  let notifications = str('notifications', 'all') as NotifyMode;
  if (!['all', 'errors', 'none'].includes(notifications)) {
    warnings.push(`notifications=${notifications} invalid, using all`);
    notifications = 'all';
  }
  let statusStyle = str('statusStyle', 'icon') as StatusStyle;
  if (statusStyle !== 'icon' && statusStyle !== 'text') {
    warnings.push(`statusStyle=${statusStyle} invalid, using icon`);
    statusStyle = 'icon';
  }
  const reqDirRaw = str('requestDir', '');
  let sshTaskName = str('sshTaskName', 'OpenCode SSH SOCKS5');
  if (sshTaskName.trim().length === 0) {
    warnings.push('sshTaskName is empty, using default');
    sshTaskName = 'OpenCode SSH SOCKS5';
  }
  let bridgeTaskName = str('bridgeTaskName', 'OpenCode HTTP Proxy Bridge');
  if (bridgeTaskName.trim().length === 0) {
    warnings.push('bridgeTaskName is empty, using default');
    bridgeTaskName = 'OpenCode HTTP Proxy Bridge';
  }
  let supervisorMode = str('supervisorMode', 'direct') as SupervisorMode;
  if (supervisorMode !== 'direct' && supervisorMode !== 'task') {
    warnings.push(`supervisorMode=${supervisorMode} invalid, using direct`);
    supervisorMode = 'direct';
  }
  const ec2Host = str('ec2Host', DEFAULT_AWSNET_CONFIG.ec2Host).trim() || DEFAULT_AWSNET_CONFIG.ec2Host;
  const sshPort = port('sshPort', DEFAULT_AWSNET_CONFIG.sshPort);
  const sshExe = str('sshExe', DEFAULT_PROC_CONFIG.sshExe).trim() || DEFAULT_PROC_CONFIG.sshExe;
  const sshKeyPath = str('sshKeyPath', DEFAULT_PROC_CONFIG.sshKeyPath).trim() || DEFAULT_PROC_CONFIG.sshKeyPath;
  const sshUser = str('sshUser', DEFAULT_PROC_CONFIG.sshUser).trim() || DEFAULT_PROC_CONFIG.sshUser;
  const hptsCmd = str('hptsCmd', DEFAULT_PROC_CONFIG.hptsCmd).trim() || DEFAULT_PROC_CONFIG.hptsCmd;
  const securityGroupId = str('securityGroupId', '').trim();
  const awsProfile = str('awsProfile', '').trim();
  let awsRegion = str('awsRegion', AWS_REGION).trim();
  if (!awsRegion) {
    awsRegion = AWS_REGION;
    warnings.push(`awsRegion is empty, using ${AWS_REGION} (home of the Elastic IP)`);
  }
  let transportProbeUrl = str('transportProbeUrl', DEFAULT_CONFIG.transportProbeUrl).trim();
  try {
    const tu = new URL(transportProbeUrl);
    if (tu.protocol !== 'https:') {
      throw new Error('not https');
    }
  } catch {
    warnings.push(`transportProbeUrl invalid, using ${DEFAULT_CONFIG.transportProbeUrl}`);
    transportProbeUrl = DEFAULT_CONFIG.transportProbeUrl;
  }
  return {
    cfg: {
      socksHost: '127.0.0.1',
      socksPort,
      httpHost: '127.0.0.1',
      httpPort,
      zenEndpoint,
      model,
      expectedExternalIp: str('expectedExternalIp', DEFAULT_CONFIG.expectedExternalIp),
      ipifyUrl: 'http://api.ipify.org/',
      checkTimeoutMs: num('checkTimeoutMs', DEFAULT_CONFIG.checkTimeoutMs, 1000),
      intervalSec,
      notifications,
      slowThresholdMs: num('slowThresholdMs', 6000, 0),
      statusStyle,
      logToFile: c.get<boolean>('logToFile', true) !== false,
      logFileMaxLines: num('logFileMaxLines', 2000, 100),
      trackRequests: c.get<boolean>('trackRequests', true) !== false,
      requestDir: reqDirRaw.trim().length > 0 ? reqDirRaw : defaultRequestDir(),
      // Strict opt-in: only an explicit true enables self-healing.
      autoRecover: c.get<boolean>('autoRecover', false) === true,
      // Dry-run is a modifier of autoRecover: plan and log, never start.
      autoRecoverDryRun: c.get<boolean>('autoRecoverDryRun', false) === true,
      compactTooltip: c.get<boolean>('compactTooltip', false) === true,
      autoRecoverMaxAttempts: num('autoRecoverMaxAttempts', 3, 1, 10),
      autoRecoverCooldownSec: num('autoRecoverCooldownSec', 60, 15, 3600),
      sshTaskName,
      bridgeTaskName,
      runbookPortWaitSec: num('runbookPortWaitSec', 30, 5, 300),
      runbookLaunchOpencode: c.get<boolean>('runbookLaunchOpencode', false) === true,
      opencodeCommand: str('opencodeCommand', 'opencode').trim() || 'opencode',
      // Auto-recovery itself is opt-in; users can separately disable stuck-task resets.
      autoRecoverResetStuckTask: c.get<boolean>('autoRecoverResetStuckTask', true) === true,
      supervisorMode,
      ec2Host,
      sshPort,
      sshExe,
      sshKeyPath,
      sshUser,
      hptsCmd,
      securityGroupId,
      awsProfile,
      awsRegion,
      enableAwsRepair: c.get<boolean>('enableAwsRepair', true) !== false,
      bootstrapRecoverOnStartup: c.get<boolean>('bootstrapRecoverOnStartup', true) !== false,
      // 0 (default) = MANUAL network-change mode: no periodic public-IP poll.
      // A stable network is never disturbed; the user triggers the check after
      // switching Wi-Fi (command + dashboard button).
      publicIpPollSec: num('publicIpPollSec', 0, 0, 3600),
      recoveryMaxAttempts: num('recoveryMaxAttempts', 3, 1, 10),
      recoveryBaseDelayMs: num('recoveryBaseDelayMs', 2000, 500, 15000),
      socksWaitSec: num('socksWaitSec', 30, 5, 120),
      httpWaitSec: num('httpWaitSec', 20, 5, 120),
      transportProbeUrl,
      portProbeTimeoutMs: num('portProbeTimeoutMs', 1000, 250, 5000),
      transportProbeTimeoutMs: num('transportProbeTimeoutMs', 4000, 1000, 10000),
      zenProbeTimeoutMs: num('zenProbeTimeoutMs', 5000, 1000, 15000),
      zenProbeIntervalSec: num('zenProbeIntervalSec', 60, 20, 600),
      failureThreshold: num('failureThreshold', DEFAULT_POLICY_CONFIG.failureThreshold, 2, 5),
      minOutageNotifySec: num('minOutageNotifySec', DEFAULT_POLICY_CONFIG.minOutageNotifySec, 10, 300),
      recentTrafficWindowSec: num('recentTrafficWindowSec', 120, 30, 600),
    },
    warnings,
  };
}

function stamp(): string {
  return new Date().toLocaleTimeString();
}

export class Monitor {
  private lifecycle: ProxyLifecycle;
  private powerWork: Promise<void> = Promise.resolve();
  private powerGeneration = 0;
  private shutdownIncomplete = false;
  private proxiedTerminals = new Set<vscode.Terminal>();
  private item: vscode.StatusBarItem;
  private channel: vscode.OutputChannel;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private currentCheck: Promise<void> | null = null;
  private deepRunning = false;
  private baseState: HealthState = 'STARTING';
  private display: DisplayState = 'STARTING';
  private lastResult: HealthResult | null = null;
  private lastCheck: Date | null = null;
  private lastSuccess: Date | null = null;
  private downSince: Date | null = null;
  private clearedFailureBeforeMs = 0;
  private req: RequestSummary = NO_TRACKING;
  private reqParseErrors: string[] = [];
  private history: HealthHistory = emptyHistory();
  private deep: DeepInfo = emptyDeep();
  private deepFor: DisplayState | null = null;
  private wasSlow = false;
  private logWrites: Promise<void> = Promise.resolve();
  private lastWarnSig = '';
  private pidCache = new Map<number, { alive: boolean; at: number }>();
  private recoverAttempts: RecoverAttempt[] = [];
  private gaveUpLogged = new Set<string>();
  private dryRunLogged = new Set<string>();
  /** Strike-gated confirmation policy (replaces single-sample verdicts). */
  private policy: PolicyState = emptyPolicy();
  private zen: ZenState = emptyZen();
  private lastZenProbeAt = 0;
  private lastZenDetail: string | null = null;
  /** True while the attributed network-change (G) sequence owns the outcome. */
  private reconnecting = false;
  /** True when a recovery run started while down (counts as confirmation). */
  private recoveryEpisodeOutage = false;
  /** Explicit single-flight gate: exactly one health-check cycle at a time. */
  private probeGate = createProbeGate();
  private autoRecoveryRunning = false;
  private manualRecoveryRunning = false;
  private latencies: number[] = [];
  private runbookRunning = false;
  private directRecoveryRunning = false;
  private recoveryState: RecoveryState | null = null;
  private lastDirectRecoveryAt = 0;
  /** Replaces the old hard `directFailures` ceiling: bounded rapid attempts,
   *  then a slow steady cadence — recovery never wedges permanently. */
  private cadence: RecoveryCadenceState = emptyRecoveryCadence();
  /** One recovery-failure toast per outage episode (bug fix: every cadence
   *  retry used to re-toast, so an unrepairable outage spammed a warning
   *  every 5 minutes). Background retries stay in the output log only. */
  private recoveryFailNotified = false;
  private bootstrapDone = false;
  private publicIpTimer: NodeJS.Timeout | null = null;
  private publicIpPollRunning = false;
  private lastPublicIp: string | null = null;
  private lastPublicIpAt = 0;
  private schedulerConflictWarned = false;
  private wakeHook: vscode.Disposable | null = null;
  private cfg: ExtConfig = readExtConfig().cfg;
  private lastRecoveryFailure: string | null = null;

  private get extensionVersion(): string {
    return this.context.extension?.packageJSON?.version ?? 'unknown';
  }

  constructor(
    private context: vscode.ExtensionContext,
    output: vscode.OutputChannel,
  ) {
    this.lifecycle = new ProxyLifecycle(context.globalState.get<boolean>(ENABLED_KEY, true));
    this.shutdownIncomplete = context.globalState.get<boolean>(STOP_ERROR_KEY, false);
    this.channel = output;
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.name = 'OpenCode Proxy Health';
    this.item.command = 'opencode-proxy-health.showDiagnostics';
    this.applyView(presentDisplay('STARTING'), 'STARTING');
    this.item.show();
    context.subscriptions.push(this.item);
    try {
      this.history = sanitizeHistory(this.context.globalState.get(HISTORY_KEY));
    } catch {
      this.history = emptyHistory();
    }
  }

  start(): void {
    this.stop();
    const { cfg, warnings } = readExtConfig();
    this.cfg = cfg;
    if (!this.lifecycle.enabled) {
      this.applyView(presentDisplay('OFF'), 'OFF');
      return;
    }
    const sig = warnings.join('|');
    if (sig !== this.lastWarnSig) {
      this.lastWarnSig = sig;
      for (const w of warnings) {
        this.emit(`[${stamp()}] [WARN] Config: ${w}.`);
      }
    }
    this.emit(
      `[${stamp()}] Monitor started (version ${this.extensionVersion}, interval ${cfg.intervalSec}s, supervisor=${cfg.supervisorMode}). Auto-recovery ${cfg.autoRecover ? (cfg.autoRecoverDryRun ? 'dry run' : 'enabled') : 'off'}. Direct bootstrap ${cfg.bootstrapRecoverOnStartup ? 'on' : 'off'}.`,
    );
    if (cfg.supervisorMode === 'direct') {
      this.emit(
        `[${stamp()}] Supervisor: extension is the SOLE owner (direct). Disable Task Scheduler tasks "${cfg.sshTaskName}" / "${cfg.bridgeTaskName}" so two supervisors never fight. Exactly one ssh.exe + one hpts is owned via exact command-line match; foreign ssh.exe processes are never killed.`,
      );
      if (!cfg.expectedExternalIp) {
        this.emit(`[${stamp()}] [WARN] Direct supervisor: expectedExternalIp is empty, so SOCKS/HTTP egress comparison is skipped (plausible-IP only). Set it to ${AWS_ELASTIC_IP} to enforce EC2 egress.`);
      }
      if (!cfg.securityGroupId) {
        this.emit(`[${stamp()}] [WARN] Direct supervisor: securityGroupId is empty, so AWS SG auto-repair is disabled. Roaming public IPs will report RECOVERY_FAILED with the direct IP until you set opencodeProxyHealth.securityGroupId.`);
      }
      if (cfg.publicIpPollSec > 0) {
        this.emit(`[${stamp()}] Direct supervisor: automatic network-change polling is ON (every ${cfg.publicIpPollSec}s). Set opencodeProxyHealth.publicIpPollSec to 0 for manual-only checks (recommended on a stable network).`);
      } else {
        this.emit(`[${stamp()}] Direct supervisor: automatic network-change polling is OFF (manual mode — recommended on a stable network). After switching Wi-Fi, run "OpenCode Proxy: Check Network / Repair SG Now" or click the dashboard button.`);
      }
      this.emit(`[${stamp()}] Direct supervisor: AWS region ${cfg.awsRegion} (home of the Elastic IP ${AWS_ELASTIC_IP}). SG repair uses the existing AWS CLI profile${cfg.awsProfile ? ` "${cfg.awsProfile}"` : ' (default chain)'}; no credentials in source/settings/logs.`);
    } else {
      this.emit(
        `[${stamp()}] Supervisor: legacy Task Scheduler mode. The extension only starts existing tasks; it never synthesises ssh command lines.`,
      );
    }
    void this.check(false).then(() => this.maybeBootstrap());
    this.timer = setInterval(() => {
      void this.check(false);
    }, cfg.intervalSec * 1000);
    if (this.publicIpTimer) {
      clearInterval(this.publicIpTimer);
      this.publicIpTimer = null;
    }
    // Automatic network-change polling is OPT-IN (publicIpPollSec > 0).
    // Default (0) = manual mode: periodic direct IP polls never run, so a
    // stable network is never probed in the background and the proxy is never
    // disturbed by a false change detection. Recovery still fires whenever the
    // health cycle itself observes the chain down (strikes), which covers
    // Wi-Fi changes too — polling is an accelerant, not a requirement.
    if (cfg.publicIpPollSec > 0) {
      this.publicIpTimer = setInterval(() => {
        void this.pollPublicIpOnce();
      }, Math.max(30, cfg.publicIpPollSec) * 1000);
    }
    // Sleep/wake + Wi-Fi switch detection (bug fix: previously nothing)
    // re-armed the cadence immediately after the OS resumed, so the first
    // post-wake check could be silently swallowed by the cooldown. Hook the
    // main VS Code window's focus event: it fires on resume/unlock and after
    // network reconnections wake the UI. Debounced via the existing
    // single-flight gate — a re-check that arrives mid-cycle is skipped.
    if (!this.wakeHook) {
      try {
        this.wakeHook = vscode.window.onDidChangeWindowState((s) => {
          if (s.focused) {
            // One cheap local refresh; expensive recovery stays gated by the
            // strike policy and the recovery cadence.
            void this.check(false);
          }
        });
        this.context.subscriptions.push(this.wakeHook);
      } catch {
        /* API unavailable (tests/older hosts) — the public-IP poll covers it. */
      }
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.publicIpTimer) {
      clearInterval(this.publicIpTimer);
      this.publicIpTimer = null;
    }
  }

  dispose(): void {
    this.lifecycle.enabled = false;
    this.stop();
    if (this.wakeHook) {
      this.wakeHook.dispose();
      this.wakeHook = null;
    }
  }

  private proxyExec = (file: string, args: string[], timeout: number): Promise<string> => {
    if (!this.lifecycle.enabled) return Promise.reject(new Error('Proxy is turned off'));
    return defaultExecAsync(file, args, timeout);
  };

  turnOff(): Promise<void> {
    ++this.powerGeneration;
    this.lifecycle.enabled = false;
    this.shutdownIncomplete = true;
    this.stop();
    this.applyView(presentDisplay('OFF'), 'OFF');
    this.powerWork = this.powerWork.then(() => this.turnOffInner(), () => this.turnOffInner());
    return this.powerWork;
  }

  private async turnOffInner(): Promise<void> {
    this.lifecycle.enabled = false;
    this.shutdownIncomplete = true;
    this.stop();
    this.applyView(presentDisplay('OFF'), 'OFF');
    try {
      await this.context.globalState.update(ENABLED_KEY, false);
      await this.context.globalState.update(STOP_ERROR_KEY, true);
      await this.lifecycle.drain();
      if (this.currentCheck) await this.currentCheck;
      for (const terminal of this.proxiedTerminals) terminal.dispose();
      this.proxiedTerminals.clear();
      const tasks = this.context.globalState.get<string[]>(TASKS_KEY, []);
      const result = await shutdownProxy(defaultExecAsync, {
        ...this.recoveryMachineConfig(), sshTaskName: this.cfg.sshTaskName, bridgeTaskName: this.cfg.bridgeTaskName,
      }, async (name) => {
        if (!tasks.includes(name)) tasks.push(name);
        await this.context.globalState.update(TASKS_KEY, tasks);
      });
      this.shutdownIncomplete = !result.ok;
      await this.context.globalState.update(STOP_ERROR_KEY, this.shutdownIncomplete);
      this.policy = emptyPolicy();
      this.downSince = null;
      this.recoveryEpisodeOutage = false;
      updateHistory(this.history, true, Date.now());
      await this.context.globalState.update(HISTORY_KEY, this.history);
      this.lastResult = null;
      for (const detail of result.details) this.emit(`[${stamp()}] [STOP] ${detail}`);
      if (result.ok) void vscode.window.showInformationMessage('Proxy is off and will stay off until you turn it on. Clear proxy settings in any other apps or existing terminals before using them directly.');
      else void vscode.window.showErrorMessage('Recovery is paused, but proxy shutdown could not be fully verified. See the output log; retry Turn Proxy Off after resolving the errors.');
    } catch (e) {
      this.shutdownIncomplete = true;
      this.emit(`[${stamp()}] [STOP] Shutdown failed: ${(e as Error).message}`);
      void vscode.window.showErrorMessage(`Proxy shutdown incomplete: ${(e as Error).message}`);
    } finally {
      this.applyView(presentDisplay('OFF'), 'OFF');
    }
  }

  turnOn(): Promise<void> {
    const generation = ++this.powerGeneration;
    const start = () => this.turnOnInner(generation);
    this.powerWork = this.powerWork.then(start, start);
    return this.powerWork;
  }

  private async turnOnInner(generation: number): Promise<void> {
    if (generation !== this.powerGeneration || this.lifecycle.enabled) return;
    try {
      // Restore only tasks this extension disabled, and only in task mode.
      if (this.cfg.supervisorMode === 'task') {
        const pending = this.context.globalState.get<string[]>(TASKS_KEY, []);
        while (pending.length) {
          await defaultExecAsync('schtasks', ['/change', '/TN', pending[0], '/ENABLE'], 10000);
          pending.shift();
          await this.context.globalState.update(TASKS_KEY, pending);
        }
      }
      if (generation !== this.powerGeneration) return;
      await this.context.globalState.update(ENABLED_KEY, true);
      if (generation !== this.powerGeneration) return;
      this.lifecycle.enabled = true;
      this.shutdownIncomplete = false;
      this.bootstrapDone = false;
      this.baseState = 'STARTING';
      this.policy = emptyPolicy();
      this.cadence = emptyRecoveryCadence();
      this.recoveryFailNotified = false;
      this.zen = emptyZen();
      this.lastZenProbeAt = 0;
      this.start();
      if (this.cfg.supervisorMode === 'task') await this.recoverChain();
      else await this.runDirectRecovery('manual-command');
    } catch (e) {
      void vscode.window.showErrorMessage(`Could not turn proxy on: ${(e as Error).message}`);
    }
  }

  // -- commands ------------------------------------------------------------

  async refresh(manual: boolean): Promise<void> {
    await this.check(manual);
  }

  async showDashboard(): Promise<void> {
    type Item = vscode.QuickPickItem & { action?: string; task?: string };
    const restartButton = (task: string): vscode.QuickInputButton => ({
      iconPath: new vscode.ThemeIcon('refresh'),
      tooltip: `Start "${task}" now`,
    });
    const items: Item[] = [{
      label: this.lifecycle.enabled ? '$(debug-stop) Turn proxy off safely' : '$(play) Turn proxy on',
      detail: this.lifecycle.enabled ? 'Stops proxy processes and retry tasks; stays off across VS Code restarts. Closes terminals launched by this extension.' : 'Resume monitoring and recovery. Other terminals may need their proxy environment cleared.',
      action: this.lifecycle.enabled ? 'off' : 'on',
    }];
    const r = this.lastResult;
    const ago = this.lastCheck ? `${Math.max(0, Math.round((Date.now() - this.lastCheck.getTime()) / 1000))}s ago` : 'never';
    const ms = (v: number | null) => (v === null ? '—' : `${v}ms`);
    const updown = (ok: boolean) => (ok ? 'UP' : 'DOWN');
    if (r) {
      items.push({
        label: `$(symbol-event) Overall: ${presentDisplay(this.display).text}`,
        detail: `state ${this.display} · checked ${ago} · took ${r.elapsedMs}ms · confirmation ${this.policy.strikes}/${this.cfg.failureThreshold} strikes`,
      });
      const recoverItem: Item = {
        label:
          this.cfg.supervisorMode === 'direct'
            ? '$(rocket) Direct recovery — run the verified state machine (A-H)'
            : '$(rocket) One-click recovery — run the full runbook',
        detail:
          this.cfg.supervisorMode === 'direct'
            ? `single-owner ssh.exe + hpts, SOCKS end-to-end, AWS :22 + SG repair, then HTTP path (no Task Scheduler, no OpenCode needed)${this.recoveryState ? ` · last: ${this.recoveryState}` : ''}`
            : `starts "${this.cfg.sshTaskName}" / "${this.cfg.bridgeTaskName}" if their ports are down, verifies egress, then offers to launch opencode`,
        action: 'recover-direct',
        buttons: [
          {
            iconPath: new vscode.ThemeIcon('rocket'),
            tooltip:
              this.cfg.supervisorMode === 'direct'
                ? 'Run the direct state-machine recovery now'
                : 'Run the full recovery runbook now',
          },
        ],
      };
      items.push(recoverItem);
      items.push({
        label: `$(shield) Supervisor: ${this.cfg.supervisorMode} — ${this.cfg.supervisorMode === 'direct' ? 'extension is the SOLE owner' : 'legacy Task Scheduler mode'}`,
        detail:
          this.cfg.supervisorMode === 'direct'
            ? `ssh ${this.cfg.sshUser}@${this.cfg.ec2Host}:${this.cfg.sshPort} -D ${this.cfg.socksHost}:${this.cfg.socksPort} · hpts -p ${this.cfg.httpPort} · SG ${this.cfg.securityGroupId || '(not configured)'} · disable tasks "${this.cfg.sshTaskName}" / "${this.cfg.bridgeTaskName}"`
            : `tasks "${this.cfg.sshTaskName}" / "${this.cfg.bridgeTaskName}" · set supervisorMode=direct for single-owner verified recovery`,
      });
      if (this.lastPublicIp) {
        items.push({
          label: `$(globe) Public IP (direct, proxy bypassed): ${this.lastPublicIp}`,
          detail: `last direct poll ${Math.round((Date.now() - this.lastPublicIpAt) / 1000)}s ago · EC2 ${this.cfg.ec2Host}:${this.cfg.sshPort} · automatic polling ${this.cfg.publicIpPollSec > 0 ? `every ${this.cfg.publicIpPollSec}s` : 'OFF (manual mode)'}`,
        });
      }
      if (this.cfg.supervisorMode === 'direct') {
        items.push({
          label: '$(network) Check network / repair SG now (manual)',
          detail: this.cfg.publicIpPollSec > 0
            ? `runs the same check the ${this.cfg.publicIpPollSec}s automatic poll performs`
            : 'run this after a Wi-Fi change: verifies the public IP, re-authorizes the SG /32 if EC2 :22 is blocked (never 0.0.0.0/0)',
          action: 'check-network',
        });
      }
      const socksRow: Item = {
        label: `SOCKS5 :${this.cfg.socksPort} — ${updown(r.socksUp)}`,
        detail: `probes ${ms(r.socksMs)} · ssh.exe ${r.sshRunning ? 'running (presence does NOT mean healthy — only a listening port + SOCKS end-to-end proves health)' : 'not found'}`,
      };
      // Legacy task restart buttons exist ONLY in task mode. In direct mode the
      // extension owns the processes and scheduled tasks must stay disabled,
      // otherwise two supervisors fight over ssh.exe/hpts.
      if (this.baseState === 'SSH_DOWN' && this.cfg.supervisorMode === 'task') {
        socksRow.buttons = [restartButton(this.cfg.sshTaskName)];
        socksRow.task = this.cfg.sshTaskName;
      }
      items.push(socksRow);
      const httpRow: Item = {
        label: `HTTP bridge :${this.cfg.httpPort} — ${updown(r.httpUp)}`,
        detail: r.reason && this.display === 'HTTP_BRIDGE_DOWN' ? r.reason : `traffic check ${ms(r.trafficMs)}`,
      };
      if (this.baseState === 'HTTP_BRIDGE_DOWN' && this.cfg.supervisorMode === 'task') {
        httpRow.buttons = [restartButton(this.cfg.bridgeTaskName)];
        httpRow.task = this.cfg.bridgeTaskName;
      }
      items.push(httpRow);
      items.push({
        label: `Transport (L2) — ${r.proxyTrafficOk ? `OK${r.transportStatus !== null ? ` (HTTP ${r.transportStatus})` : ''}` : 'probing'}`,
        detail: `${r.transportTarget ?? this.cfg.transportProbeUrl} via :${this.cfg.httpPort} in ${ms(r.trafficMs)} · lightweight probe, never an echo service`,
      });
      items.push({
        label: `Zen service (L3) — ${this.zen.verdict === 'ZEN_OK' ? 'OK' : this.zen.verdict}${this.lastZenDetail ? ` (${this.lastZenDetail.slice(0, 80)})` : ''}`,
        detail: `separate slow cadence (every ${this.cfg.zenProbeIntervalSec}s) · service-side only: never triggers proxy recovery · ${this.cfg.model}`,
      });
      items.push({ label: '', kind: vscode.QuickPickItemKind.Separator });
      items.push({ label: `$(pulse) Requests: ${this.requestLine()}`, detail: this.requestDetail() });
      items.push({ label: `$(tools) Auto-recovery: ${this.recoverLine()}`, detail: this.recoverDetail() });
      const up = uptimeSummary(this.history, Date.now());
      items.push({
        label: `$(history) 24h uptime: ${up.uptimePct}% (${up.outageCount} outage${up.outageCount === 1 ? '' : 's'})`,
        detail:
          up.recent.length > 0
            ? up.recent.map((o) => `${new Date(o.sinceMs).toLocaleTimeString()} for ${formatDuration(o.durationMs)}`).join(' · ')
            : 'no outages recorded in the last 24h',
      });
      if (this.latencies.length > 0) {
        const avg = Math.round(this.latencies.reduce((a, b) => a + b, 0) / this.latencies.length);
        items.push({
          label: `$(graph) Latency trend (last ${this.latencies.length}): ${sparkline(this.latencies)}`,
          detail: `avg ${avg}ms · max ${Math.max(...this.latencies)}ms · last ${this.latencies[this.latencies.length - 1]}ms`,
        });
      }
      if (this.deepFor === this.display && (this.deep.tasks.length > 0 || this.deep.listeners.length > 0)) {
        items.push({
          label: '$(search) Deep diagnosis',
          detail: [
            ...this.deep.tasks.map((t) => `${t.name}: ${t.status}`),
            ...this.deep.listeners.map((l) => `:${l.port} pid ${l.pid}`),
          ].join(' · '),
        });
      }
      if (r.reason) {
        items.push({ label: '$(info) Reason', detail: r.reason });
      }
    } else {
      items.push({ label: this.lifecycle.enabled ? '$(sync~spin) No check has completed yet' : '$(debug-stop) Proxy is OFF', detail: this.lifecycle.enabled ? 'wait a few seconds and reopen' : 'Monitoring, startup recovery and network repair are paused.' });
      items.push({ label: '$(rocket) One-click recovery — run the full runbook', action: 'recover' });
    }
    items.push({ label: '', kind: vscode.QuickPickItemKind.Separator });
    items.push({ label: '$(refresh) Refresh now', action: 'refresh' });
    items.push({ label: '$(output) Open output log', action: 'output' });
    if (this.cfg.logToFile) {
      items.push({ label: '$(file) Reveal persisted log file', action: 'logfile' });
    }
    items.push({ label: '$(clippy) Copy diagnostics to clipboard', action: 'copy' });
    items.push({ label: '$(gear) Open extension settings', action: 'settings' });
    if (this.display === 'REQUEST_FAILED') {
      items.push({ label: '$(clear-all) Clear request failure', action: 'clear' });
    }
    const qp = vscode.window.createQuickPick<Item>();
    qp.title = 'OpenCode Proxy Health';
    qp.placeholder = `${presentDisplay(this.display).text} — select a row for detail, or run an action`;
    qp.matchOnDetail = true;
    qp.items = items;
    const pick = await new Promise<Item | undefined>((resolve) => {
      let settled = false;
      const done = (v: Item | undefined) => {
        if (!settled) {
          settled = true;
          resolve(v);
        }
      };
      const subs: vscode.Disposable[] = [];
      subs.push(
        qp.onDidAccept(() => {
          const sel = qp.selectedItems[0] as Item | undefined;
          qp.hide();
          done(sel);
        }),
      );
      subs.push(
        qp.onDidTriggerItemButton(async (e) => {
          const it = e.item as Item;
          if (it.action === 'recover' || it.action === 'recover-direct') {
            qp.hide();
            if (this.cfg.supervisorMode === 'direct') {
              await this.runDirectRecovery('dashboard');
            } else {
              await this.recoverChain();
            }
            await this.showDashboard();
            return;
          }
          if (it.task) {
            qp.hide();
            await this.restartTask(it.task);
            await this.check(true);
            await this.showDashboard();
          }
        }),
      );
      subs.push(
        qp.onDidHide(() => {
          subs.forEach((s) => s.dispose());
          qp.dispose();
          done(undefined);
        }),
      );
      qp.show();
    });
    if (!pick?.action) {
      return;
    }
    if (pick.action === 'off') {
      await this.turnOff();
    } else if (pick.action === 'on') {
      await this.turnOn();
    } else if (pick.action === 'recover' || pick.action === 'recover-direct') {
      if (this.cfg.supervisorMode === 'direct') {
        await this.runDirectRecovery('dashboard');
      } else {
        await this.recoverChain();
      }
    } else if (pick.action === 'check-network') {
      await this.manualNetworkCheck();
      await this.showDashboard();
    } else if (pick.action === 'refresh') {
      await this.check(true);
      await this.showDashboard();
    } else if (pick.action === 'output') {
      this.showOutput();
    } else if (pick.action === 'logfile') {
      await vscode.commands.executeCommand('revealFileInOS', this.logFileUri());
    } else if (pick.action === 'copy') {
      await vscode.env.clipboard.writeText(this.buildFullReport());
      void vscode.window.showInformationMessage('OpenCode proxy diagnostics copied to clipboard.');
    } else if (pick.action === 'settings') {
      await vscode.commands.executeCommand('workbench.action.openSettings', 'opencodeProxyHealth');
    } else if (pick.action === 'clear') {
      this.clearedFailureBeforeMs = Date.now();
      this.emit(`[${stamp()}] Request failure dismissed by user; a newer failure will show again.`);
      this.recomputeView();
      await this.showDashboard();
    }
  }

  showOutput(): void {
    if (this.lastResult) {
      this.emit(`\n[${stamp()}] ── Diagnostics (requested) ──\n${this.buildFullReport()}`);
    } else {
      this.emit(`[${stamp()}] Diagnostics requested — no check has completed yet.`);
    }
    this.channel.show(true);
  }

  async copyDiagnostics(): Promise<void> {
    await vscode.env.clipboard.writeText(this.buildFullReport());
    void vscode.window.showInformationMessage('OpenCode proxy diagnostics copied to clipboard.');
  }

  clearRequestFailure(): void {
    this.clearedFailureBeforeMs = Date.now();
    this.emit(`[${stamp()}] Request failure dismissed by user; a newer failure will show again.`);
    this.recomputeView();
  }

  // -- internals -----------------------------------------------------------

  private requestLine(): string {
    if (!this.cfg.trackRequests) {
      return 'disabled in settings';
    }
    if (!this.req.trackingInUse) {
      return 'not in use';
    }
    if (this.req.activeCount > 0) {
      return `${this.req.activeCount} running`;
    }
    if (this.display === 'REQUEST_FAILED') {
      return 'last failed';
    }
    return 'idle';
  }

  private requestDetail(): string {
    if (!this.cfg.trackRequests) {
      return 'enable opencodeProxyHealth.trackRequests, then run requests via scripts/Invoke-TrackedOpencode.ps1';
    }
    if (!this.req.trackingInUse) {
      return 'no lockfiles yet — run a request via scripts/Invoke-TrackedOpencode.ps1 to enable live Running/Error status';
    }
    const parts: string[] = [];
    if (this.req.activeCount > 0) {
      const bits: string[] = [];
      if (this.req.oldestActiveModel) {
        bits.push(this.req.oldestActiveModel);
      }
      if (this.req.oldestActiveSinceMs !== null) {
        bits.push(`oldest running ${formatDuration(Date.now() - this.req.oldestActiveSinceMs)}`);
      }
      parts.push(`${this.req.activeCount} in flight${bits.length > 0 ? ` (${bits.join(', ')})` : ''}`);
    }
    if (this.req.lastFailureAtMs !== null) {
      parts.push(`last failure ${new Date(this.req.lastFailureAtMs).toLocaleTimeString()}: ${this.req.lastFailureReason ?? ''}`);
    } else if (this.req.lastSuccessAtMs !== null) {
      parts.push(`last success ${new Date(this.req.lastSuccessAtMs).toLocaleTimeString()}`);
    } else if (this.req.activeCount === 0) {
      parts.push('no tracked requests observed yet');
    }
    if (this.reqParseErrors.length > 0) {
      parts.push(`${this.reqParseErrors.length} lockfile parse error(s)`);
    }
    return parts.join(' · ');
  }

  private buildFullReport(): string {
    const cfg = this.cfg;
    const base = [
      this.lastResult
        ? formatReport(this.display, this.lastResult, cfg, {
            lastCheck: this.lastCheck,
            lastSuccess: this.lastSuccess,
            downSince: this.downSince,
          })
        : 'OpenCode Proxy Health\n────────────────────────\n(no check has completed yet)',
      `Extension version    ${this.extensionVersion}`,
      `Supervisor           ${cfg.supervisorMode}${cfg.supervisorMode === 'direct' ? ` (SOLE owner: 1x ssh.exe -D ${cfg.socksHost}:${cfg.socksPort} + 1x hpts -p ${cfg.httpPort}; Task Scheduler tasks "${cfg.sshTaskName}" / "${cfg.bridgeTaskName}" must be DISABLED)` : ` (legacy tasks "${cfg.sshTaskName}" / "${cfg.bridgeTaskName}")`}`,
      `Recovery state       ${this.recoveryState ?? '(none)'}${this.directRecoveryRunning ? ' (running)' : ''}`,
      ...(this.lastRecoveryFailure ? [`Recovery failure     ${this.lastRecoveryFailure}`] : []),
      `AWS                  EC2 ${cfg.ec2Host}:${cfg.sshPort} · SG ${cfg.securityGroupId || '(not configured)'}${cfg.awsProfile ? ` · profile ${cfg.awsProfile}` : ''}${cfg.awsRegion ? ` · region ${cfg.awsRegion}` : ''}`,
      `Direct public IP     ${this.lastPublicIp ?? '(unknown — direct poll, proxy bypassed)'}${this.lastPublicIp ? ` (${Math.round((Date.now() - this.lastPublicIpAt) / 1000)}s ago)` : ''}`,
      `Requests             ${this.requestLine()} — ${this.requestDetail()}`,
    ];
    const up = uptimeSummary(this.history, Date.now());
    base.push(`Uptime 24h           ${up.uptimePct}% (${up.outageCount} outage${up.outageCount === 1 ? '' : 's'})`);
    for (const o of up.recent) {
      base.push(
        `  outage ${new Date(o.sinceMs).toLocaleString()} for ${formatDuration(o.durationMs)}${
          o.untilMs === null ? ' (ongoing)' : ''
        }`,
      );
    }
    if (this.deepFor === this.display && this.lastResult) {
      base.push(...formatDeep(this.deep));
    } else if (this.lastResult && this.baseState !== 'HEALTHY') {
      base.push('Deep diagnosis     (pending — runs automatically on failure)');
    }
    for (const e of this.reqParseErrors.slice(0, 5)) {
      base.push(`Track file error     ${e}`);
    }
    return base.join('\n');
  }

  private emit(line: string): void {
    this.channel.appendLine(line);
    this.logWrites = this.logWrites.then(() => this.appendFileLog(line));
  }

  private logFileUri(): vscode.Uri {
    return vscode.Uri.joinPath(this.context.globalStorageUri, 'proxy-health.log');
  }

  private async appendFileLog(line: string): Promise<void> {
    if (!this.cfg.logToFile) {
      return;
    }
    try {
      await vscode.workspace.fs.createDirectory(this.context.globalStorageUri);
      const p = this.logFileUri();
      let lines: string[] = [];
      try {
        const buf = await vscode.workspace.fs.readFile(p);
        lines = Buffer.from(buf).toString('utf8').split('\n');
      } catch {
        lines = [];
      }
      lines.push(line);
      if (lines.length > this.cfg.logFileMaxLines) {
        lines = lines.slice(-this.cfg.logFileMaxLines);
      }
      await vscode.workspace.fs.writeFile(p, Buffer.from(lines.join('\n'), 'utf8'));
    } catch {
      // Logging must never break monitoring.
    }
  }

  private applyView(
    view: ReturnType<typeof presentDisplay>,
    state: DisplayState,
  ): void {
    if (!this.lifecycle.enabled) {
      view = presentDisplay('OFF');
      if (this.shutdownIncomplete) view = { ...view, icon: '$(alert)', text: 'Proxy: OFF (shutdown incomplete)', level: 'warning', accessLabel: 'Proxy recovery paused; shutdown incomplete. Retry Turn Proxy Off.' };
      state = 'OFF';
      this.display = 'OFF';
    }
    this.item.text = barText(view, this.cfg.statusStyle);
    // Deliberately no severity background tint: state is carried by the glyph
    // shape, the tooltip, and the accessibility label — never by color.
    this.item.backgroundColor = undefined;
    this.item.accessibilityInformation = { label: `OpenCode Proxy Health: ${view.accessLabel}` };
    this.item.tooltip = this.buildTooltip(state, view);
  }

  private recomputeView(): void {
    const slow =
      this.display === 'HEALTHY' && this.cfg.slowThresholdMs > 0 && (this.lastResult?.elapsedMs ?? 0) > this.cfg.slowThresholdMs;
    this.display = overlayRequest(this.baseState, this.req, this.clearedFailureBeforeMs);
    this.applyView(presentDisplay(this.display, { slow, activeCount: this.req.activeCount }), this.display);
  }

  private buildTooltip(state: DisplayState, view: ReturnType<typeof presentDisplay>): vscode.MarkdownString {
    const r = this.lastResult;
    const ago = this.lastCheck ? `${Math.max(0, Math.round((Date.now() - this.lastCheck.getTime()) / 1000))}s ago` : 'never';
    const md = new vscode.MarkdownString(undefined, true);
    md.isTrusted = false;
    md.supportHtml = false;
    md.supportThemeIcons = true;
    md.appendMarkdown('**OpenCode Proxy Health**\n\n');
    if (!this.lifecycle.enabled) {
      md.appendMarkdown(this.shutdownIncomplete ? '**Recovery paused; shutdown incomplete.** See the output log and retry Turn Proxy Off.\n\n' : '**Proxy is off.** Startup recovery and network repair are paused. Use Turn Proxy On to resume.\n\n');
      return md;
    }
    md.appendMarkdown(`State: ${view.icon} \`${state}\` — ${view.accessLabel}\n\n`);
    if (r && !this.cfg.compactTooltip) {
      const ms = (v: number | null) => (v === null ? '—' : `${v}ms`);
      md.appendMarkdown(
        `SSH SOCKS5: ${r.socksUp ? 'UP' : 'DOWN'} (${ms(r.socksMs)}) | ` +
          `HTTP Proxy: ${r.httpUp ? 'UP' : 'DOWN'} | ` +
          `Transport: ${r.proxyTrafficOk ? `OK ${ms(r.trafficMs)}` : 'probing'} | ` +
          `Zen: ${this.zen.verdict === 'ZEN_OK' ? 'OK' : this.zen.verdict}${this.lastZenDetail ? ` (${this.lastZenDetail.slice(0, 80)})` : ''}\n\n`,
      );
      if (this.req.trackingInUse) {
        md.appendMarkdown(`Requests: ${this.requestLine()} — ${this.requestDetail()}\n\n`);
      }
      md.appendMarkdown(
        `Supervisor: \`${this.cfg.supervisorMode}\`${this.recoveryState ? ` · recovery \`${this.recoveryState}\`` : ''}${this.lastPublicIp ? ` · public IP \`${this.lastPublicIp}\` (direct)` : ''}\n\n`,
      );
      md.appendMarkdown(
        `Confirmation: ${this.policy.strikes}/${this.cfg.failureThreshold} strikes` +
          `${this.policy.confirmedDownSinceMs !== null ? ` · confirmed down since ${new Date(this.policy.confirmedDownSinceMs).toLocaleTimeString()}` : ''}\n\n`,
      );
      if (this.baseState !== 'HEALTHY') {
        if (this.cfg.supervisorMode === 'direct') {
          md.appendMarkdown(`Direct recovery: ${this.directRecoveryRunning ? 'running…' : this.recoveryState ?? 'idle'} — verified ports + SOCKS end-to-end + AWS SG repair\n\n`);
        }
        md.appendMarkdown(
          this.cfg.autoRecover
            ? `Auto-fix: ${this.recoverLine()} — ${this.recoverDetail()}\n\n`
            : 'Auto-fix: off (monitoring only) — set opencodeProxyHealth.autoRecover for self-healing\n\n',
        );
      }
      const up = uptimeSummary(this.history, Date.now());
      md.appendMarkdown(`24h uptime: ${up.uptimePct}%\n\n`);
      if (r.reason) {
        md.appendMarkdown(`_${r.reason}_\n\n`);
      }
    }
    md.appendMarkdown(`Last check: ${ago}\n\nClick for dashboard.`);
    return md;
  }

  private async readRequests(): Promise<void> {
    if (!this.cfg.trackRequests) {
      this.req = NO_TRACKING;
      this.reqParseErrors = [];
      return;
    }
    try {
      const names = await fs.readdir(this.cfg.requestDir);
      const wanted = names
        .filter((n) => n.endsWith(RUNNING_SUFFIX) || n.endsWith(DONE_SUFFIX))
        .slice(0, MAX_TRACK_FILES);
      const files: { name: string; content: string }[] = [];
      for (const n of wanted) {
        try {
          files.push({ name: n, content: await fs.readFile(path.join(this.cfg.requestDir, n), 'utf8') });
        } catch {
          // A file vanishing mid-read just means the wrapper finished; ignore.
        }
      }
      // Resolve wrapper PIDs first (async), then assess synchronously.
      const pids = new Set<number>();
      for (const f of files) {
        if (f.name.endsWith(RUNNING_SUFFIX)) {
          const m = f.content.match(/"pid"\s*:\s*(\d+)/);
          if (m) {
            pids.add(parseInt(m[1], 10));
          }
        }
      }
      const alive = new Map<number, boolean>();
      await Promise.all(
        [...pids].map(async (p) => {
          const hit = this.pidCache.get(p);
          if (hit && Date.now() - hit.at < PID_CACHE_TTL_MS) {
            alive.set(p, hit.alive);
            return;
          }
          const v = await checkPidAlive(p);
          this.pidCache.set(p, { alive: v, at: Date.now() });
          alive.set(p, v);
        }),
      );
      if (this.pidCache.size > 64) {
        const cutoff = Date.now() - PID_CACHE_TTL_MS;
        for (const [p, e] of this.pidCache) {
          if (e.at < cutoff) {
            this.pidCache.delete(p);
          }
        }
      }
      const assessed: AssessResult = assessRequests(files, (p) => alive.get(p) ?? false, Date.now());
      this.req = summarizeRequests(assessed, true);
      this.reqParseErrors = assessed.parseErrors;
    } catch {
      // Directory absent/unreadable → tracking not in use. Honest and quiet.
      this.req = NO_TRACKING;
      this.reqParseErrors = [];
    }
  }

  private notifyFail(msg: string): void {
    if (this.cfg.notifications !== 'none') {
      void vscode.window.showWarningMessage(msg);
    }
  }

  private notifyRecover(msg: string): void {
    if (this.cfg.notifications === 'all') {
      void vscode.window.showInformationMessage(msg);
    }
  }

  private async refreshDeep(display: DisplayState): Promise<void> {
    if (this.deepRunning || this.deepFor === display) {
      return;
    }
    this.deepRunning = true;
    try {
      const info = await deepDiagnose({ socksPort: this.cfg.socksPort, httpPort: this.cfg.httpPort });
      this.deep = info;
      this.deepFor = display;
      this.emit(`[${stamp()}] ── Deep diagnosis (${display}) ──`);
      for (const line of formatDeep(info)) {
        this.emit(`[${stamp()}] ${line}`);
      }
    } finally {
      this.deepRunning = false;
    }
  }

  private recoverConfig(): RecoverConfig {
    return {
      enabled: this.cfg.autoRecover,
      maxAttempts: this.cfg.autoRecoverMaxAttempts,
      cooldownMs: this.cfg.autoRecoverCooldownSec * 1000,
      sshTask: this.cfg.sshTaskName,
      bridgeTask: this.cfg.bridgeTaskName,
    };
  }

  private recoverLine(): string {
    if (!this.cfg.autoRecover) {
      return 'OFF (monitoring only)';
    }
    if (this.baseState === 'HEALTHY') {
      return 'ON — idle';
    }
    return `ON — ${this.recoverAttempts.length} attempt(s) used this outage`;
  }

  private recoverDetail(): string {
    if (!this.cfg.autoRecover) {
      return 'enable opencodeProxyHealth.autoRecover to let the extension start your existing scheduled tasks on local failures';
    }
    if (this.baseState === 'HEALTHY') {
      return `fixes SSH_DOWN/SOCKS_DOWN via "${this.cfg.sshTaskName}", HTTP_BRIDGE_DOWN via "${this.cfg.bridgeTaskName}" — budgets reset each outage`;
    }
    const plan = planRecovery(this.baseState, this.recoverConfig(), this.recoverAttempts, Date.now());
    return plan.kind === 'run-task' ? `next step: start "${plan.task}"` : plan.reason;
  }

  /** Which port a task is responsible for opening. */
  private portForTask(task: string, rc: RecoverConfig): { host: string; port: number } | null {
    if (task === rc.sshTask) {
      return { host: this.cfg.socksHost, port: this.cfg.socksPort };
    }
    if (task === rc.bridgeTask) {
      return { host: this.cfg.httpHost, port: this.cfg.httpPort };
    }
    return null;
  }

  /**
   * Bring one task's port back, handling the stuck-task wedge.
   *
   * The wedge: both tasks use `MultipleInstances=IgnoreNew`. If the task's
   * process dies while its parent stays alive, Scheduler still reports Running,
   * and `schtasks /run` is then discarded — silently, while still exiting 0 and
   * printing SUCCESS. Restarting such a task is impossible without stopping it
   * first, so that is the only case where we go beyond "start things".
   *
   * Guard: the port must be observed CLOSED before anything is stopped. A
   * working task is never touched, whatever Scheduler's state says.
   *
   * Never throws.
   */
  private async reviveTask(task: string, rc: RecoverConfig, verb: string): Promise<{ ok: boolean; detail: string }> {
    const watch = this.portForTask(task, rc);
    return reviveScheduledTask(task, watch, verb !== 'Auto-recovery' || this.cfg.autoRecoverResetStuckTask, this.cfg.runbookPortWaitSec * 1000, {
      exec: this.proxyExec,
      probe: checkTcpPort,
      sleep: (ms) => this.lifecycle.sleep(ms),
      now: () => Date.now(),
      onProgress: (detail) => this.emit(`[${stamp()}] [FIX] ${verb}: ${detail}.`),
      canContinue: () => this.lifecycle.enabled,
      canStart: () => this.lifecycle.enabled && (verb !== 'Auto-recovery' || (this.cfg.autoRecover && !this.cfg.autoRecoverDryRun)),
      canReset: () => this.lifecycle.enabled && (verb !== 'Auto-recovery' || (this.cfg.autoRecover && this.cfg.autoRecoverResetStuckTask && !this.cfg.autoRecoverDryRun)),
    });
  }

  /**
   * Attempt one bounded self-healing step against a confirmed local port
   * failure. Remote failures get no automatic task action.
   */
  private async maybeRecover(): Promise<void> {
    if (!this.lifecycle.enabled || !this.cfg.autoRecover) return;
    if (this.runbookRunning || this.autoRecoveryRunning || this.manualRecoveryRunning || this.directRecoveryRunning || this.publicIpPollRunning) {
      return;
    }
    // Direct supervisor owns recovery via the verified state machine; the
    // legacy schtasks path is only for supervisorMode=task. Both require
    // CONFIRMED failure (strikes >= threshold): strikes 1..N-1 stay DEGRADED
    // with no recovery and no notification.      // hpts may only be started by the DIRECT supervisor path in the legacy
      // monitor: the machine (recoveryMachine.ts) starts hpts only after SOCKS
      // is verified end-to-end (layer E gated on D). The legacy auto-recover
      // path (task mode) restores the bridge only via the user's own task.
      if (this.cfg.supervisorMode === 'direct') {
        if (this.display !== 'PROXY_DOWN') {
          return;
        }
      // Bounded but never wedged (bug fix): rapid attempts within budget,
      // then a slow steady cadence — a recovery that failed 3x during a
      // captive-portal session still retries after the network heals.
      const decision = nextRecoveryCadence(
        this.cadence,
        Date.now(),
        {
          maxRapidAttempts: Math.max(1, this.cfg.recoveryMaxAttempts),
          cooldownMs: Math.max(15, this.cfg.autoRecoverCooldownSec) * 1000,
          steadyCadenceMs: 300_000,
        },
      );
      if (!decision.allowed) {
        return;
      }
      await this.runDirectRecovery(`auto-${this.baseState}`);
      return;
    }
    const rc = this.recoverConfig();
    const plan = planRecovery(this.baseState, rc, this.recoverAttempts, Date.now());
    if (plan.kind === 'run-task' && this.policy.strikes < this.cfg.failureThreshold) {
      return;
    }
    if (this.cfg.autoRecoverDryRun && this.cfg.autoRecover) {
      // Safe end-to-end testing of self-healing: plan and log, never start.
      if (plan.kind === 'run-task' && !this.dryRunLogged.has(plan.task)) {
        this.dryRunLogged.add(plan.task);
        this.emit(
          `[${stamp()}] [DRY-RUN] autoRecoverDryRun is on: would start "${plan.task}" now (budgets and cooldowns would apply; nothing was started).`,
        );
      }
      return;
    }
    if (plan.kind === 'none') {
      const task = taskForState(this.baseState, rc);
      if (this.cfg.autoRecover && plan.reason.startsWith('gave up') && task && !this.gaveUpLogged.has(task)) {
        this.gaveUpLogged.add(task);
        this.emit(`[${stamp()}] [FAIL] Auto-recovery ${plan.reason} for ${this.baseState} — manual action needed (see dashboard).`);
        this.notifyFail(`OpenCode proxy auto-recovery gave up (${this.baseState}). Manual action needed.`);
      }
      // Disabled, cooling-down, and unfixable states stay quiet here;
      // the dashboard and tooltip carry the current reasoning.
      return;
    }
    const n = this.recoverAttempts.filter((a) => a.task === plan.task).length + 1;
    this.emit(
      `[${stamp()}] [FIX] Auto-recovery: recovering via "${plan.task}" (attempt ${n}/${rc.maxAttempts} for ${this.baseState}).`,
    );
    this.autoRecoveryRunning = true;
    let res: { ok: boolean; detail: string };
    try {
      res = await this.reviveTask(plan.task, rc, 'Auto-recovery');
    } catch (e) {
      res = { ok: false, detail: `unexpected recovery error: ${(e as Error).message}` };
    } finally {
      this.autoRecoveryRunning = false;
    }
    this.recoverAttempts.push({ atMs: Date.now(), task: plan.task, ok: res.ok, detail: res.detail });
    if (res.ok) {
      this.emit(`[${stamp()}] [FIX] Auto-recovery: ${res.detail}.`);
    } else {
      this.emit(`[${stamp()}] [FAIL] Auto-recovery attempt failed: ${res.detail}.`);
    }
  }

  // -- direct supervisor (state machine, single owner, no Task Scheduler) ----

  private recoveryMachineConfig(): RecoveryMachineConfig {
    const c = this.cfg;
    return {
      ...DEFAULT_RECOVERY_CONFIG,
      ec2Host: c.ec2Host,
      sshPort: c.sshPort,
      securityGroupId: c.enableAwsRepair ? c.securityGroupId : '',
      awsProfile: c.awsProfile,
      awsRegion: c.awsRegion,
      sshExe: c.sshExe,
      sshKeyPath: c.sshKeyPath,
      sshUser: c.sshUser,
      socksHost: c.socksHost,
      socksPort: c.socksPort,
      hptsCmd: c.hptsCmd,
      httpPort: c.httpPort,
      expectedExternalIp: c.expectedExternalIp,
      transportProbeUrl: c.transportProbeUrl,
      transportProbeTimeoutMs: c.transportProbeTimeoutMs,
      maxAttempts: c.recoveryMaxAttempts,
      baseDelayMs: c.recoveryBaseDelayMs,
      maxDelayMs: 15000,
      socksWaitMs: c.socksWaitSec * 1000,
      httpWaitMs: c.httpWaitSec * 1000,
      checkTimeoutMs: c.checkTimeoutMs,
    };
  }

  private recoveryDisplayFor(s: RecoveryState): DisplayState {
    switch (s) {
      case 'AWS_SSH_UNREACHABLE':
        return 'AWS_SSH_UNREACHABLE';
      case 'SG_REPAIRING':
        return 'SG_REPAIRING';
      case 'SOCKS_STARTING':
      case 'SOCKS_DOWN':
      case 'SSH_PROCESS_DOWN':
        return s === 'SSH_PROCESS_DOWN' ? 'SSH_DOWN' : s === 'SOCKS_DOWN' ? 'SOCKS_DOWN' : 'SOCKS_STARTING';
      case 'HTTP_PROXY_STARTING':
        return 'HTTP_STARTING';
      case 'HTTP_PROXY_DOWN':
        return 'HTTP_BRIDGE_DOWN';
      case 'RECOVERY_FAILED':
        return 'RECOVERY_FAILED';
      case 'READY':
      case 'SOCKS_UP':
      case 'HTTP_PROXY_UP':
        // Success states carry no live display of their own: the post-recovery
        // health check derives the honest verdict. (Bug fix: was an unchecked
        // cast of an arbitrary HealthState into DisplayState.)
        return this.display;
      default:
        return 'UNKNOWN';
    }
  }

  /**
   * Run the layered direct recovery state machine (A-H). Bounded, idempotent,
   * single-flight, never requires OpenCode or a healthy proxy. Never throws.
   */
  async runDirectRecovery(reason: string): Promise<void> {
    await this.lifecycle.run(() => this.runDirectRecoveryInner(reason));
  }

  private async runDirectRecoveryInner(reason: string): Promise<void> {
    if (this.cfg.supervisorMode !== 'direct') {
      await this.recoverChain();
      return;
    }
    if (this.directRecoveryRunning || isRecoveryRunning() || this.runbookRunning) {
      this.emit(`[${stamp()}] Direct recovery (${reason}) skipped — another recovery is already running (idempotent).`);
      return;
    }
    if (this.cfg.autoRecoverDryRun) {
      this.emit(`[${stamp()}] [DRY-RUN] Direct recovery (${reason}) would run the state machine now (nothing started).`);
      return;
    }
    this.directRecoveryRunning = true;
    this.cadence = { ...this.cadence, lastAttemptMs: Date.now() };
    this.emit(`[${stamp()}] ── Direct recovery started (${reason}, supervisor=direct) ──`);
    // A recovery run counts as confirmation for outage math: seed the outage
    // clock so a genuinely long repair notifies exactly once on success.
    if (this.baseState !== 'HEALTHY' || this.policy.verdict !== 'READY') {
      this.recoveryEpisodeOutage = true;
      if (this.downSince === null) {
        this.downSince = new Date();
      }
      if (this.policy.confirmedDownSinceMs === null) {
        this.policy = { ...this.policy, confirmedDownSinceMs: Date.now() };
      }
    }
    this.display = 'RECOVERING';
    this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
    const rcfg = this.recoveryMachineConfig();
    try {
      const outcome = await recoverProxy(
        rcfg,
        this.proxyExec,
        {
          canContinue: () => this.lifecycle.enabled,
          sleep: (ms) => this.lifecycle.sleep(ms),
          onState: (s, detail) => {
            this.recoveryState = s;
            const disp = this.recoveryDisplayFor(s);
            this.display = this.baseState === 'HEALTHY' && s === 'READY' ? this.display : disp;
            this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
            this.emit(`[${stamp()}] [${s}] ${detail}`);
          },
        },
      );
      if (!this.lifecycle.enabled) return;
      for (const l of outcome.logs) {
        this.emit(`[${l.at}] [${l.tag}] ${l.message}`);
      }
      this.lastDirectRecoveryAt = Date.now();
      this.recoveryState = outcome.state;
      if (outcome.ok) {
        this.lastRecoveryFailure = null;
        this.cadence = emptyRecoveryCadence();
        this.recoveryFailNotified = false;
        this.emit(`[${stamp()}] [RECOVERY SUCCESS] Direct recovery READY in ${outcome.elapsedMs}ms — SOCKS :${rcfg.socksPort} + HTTP :${rcfg.httpPort} verified end-to-end.`);
        // Success notification is owned by the post-recovery health check:
        // only a confirmed outage lasting >= minOutageNotifySec notifies.
        // Called from checkInner -> maybeRecover: awaiting the current check
        // here would await ourselves forever. Queue the refresh without joining it.
        if (this.running) void this.check(true);
        else await this.check(true);
        if (outcome.publicIpDirect) {
          this.lastPublicIp = outcome.publicIpDirect;
          this.lastPublicIpAt = Date.now();
        }
        void this.checkSchedulerConflict();
      } else {
        this.lastRecoveryFailure = [...outcome.logs].reverse().find((l) => l.tag === 'RECOVERY FAILURE')?.message ?? outcome.state;
        this.cadence = { ...this.cadence, failedAttempts: this.cadence.failedAttempts + 1, lastAttemptMs: Date.now() };
        this.emit(`[${stamp()}] [RECOVERY FAILURE] Direct recovery FAILED (${outcome.state}): path ${outcome.path.join(' -> ')}.`);
        this.display = 'RECOVERY_FAILED';
        this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
        // Notify ONCE per outage episode; the steady 5-minute cadence keeps
        // retrying silently (output log only) instead of re-toasting forever.
        const manual = reason === 'manual-command' || reason === 'dashboard' || reason === 'manual-runbook-redirect';
        if (manual || !this.recoveryFailNotified) {
          this.recoveryFailNotified = true;
          this.notifyFail(`Proxy recovery failed: ${this.lastRecoveryFailure.slice(0, 350)} See output log for details.`);
        }
      }
    } catch (e) {
      if (!this.lifecycle.enabled) return;
      this.lastRecoveryFailure = (e as Error).message;
      this.cadence = { ...this.cadence, failedAttempts: this.cadence.failedAttempts + 1, lastAttemptMs: Date.now() };
      this.emit(`[${stamp()}] [RECOVERY FAILURE] Direct recovery threw: ${(e as Error).message}`);
      this.display = 'RECOVERY_FAILED';
      this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
      const manual = reason === 'manual-command' || reason === 'dashboard' || reason === 'manual-runbook-redirect';
      if (manual || !this.recoveryFailNotified) {
        this.recoveryFailNotified = true;
        this.notifyFail(`Proxy recovery failed (${(e as Error).message.slice(0, 120)}). Will keep retrying in the background — see output log.`);
      }
    } finally {
      this.directRecoveryRunning = false;
      this.reconnecting = false;
    }
  }

  /** Startup bootstrap: health-check first; if unhealthy, enter recovery once. */
  private async maybeBootstrap(): Promise<void> {
    if (!this.lifecycle.enabled || this.bootstrapDone) {
      return;
    }
    this.bootstrapDone = true;
    if (!this.cfg.bootstrapRecoverOnStartup) {
      return;
    }
    if (this.baseState === 'HEALTHY') {
      return;
    }
    if (this.cfg.supervisorMode !== 'direct') {
      return;
    }
    this.emit(`[${stamp()}] Startup bootstrap: chain is ${this.baseState}, entering direct recovery (works before OpenCode is usable).`);
    await this.runDirectRecovery('startup');
  }

  /**
   * One direct public-IP poll (proxy bypassed). Runs only when automatic
   * polling is enabled (publicIpPollSec > 0) or when invoked manually.
   * On a detected change: mark RECONNECTING (not failed), verify, recover.
   */
  private async pollPublicIpOnce(force = false): Promise<void> {
    if (this.publicIpPollRunning || !this.lifecycle.enabled) return;
    if (!force && (!this.cfg.autoRecover || this.cfg.supervisorMode !== 'direct' || this.cfg.publicIpPollSec <= 0)) return;
    this.publicIpPollRunning = true;
    try { await this.lifecycle.run(() => this.pollPublicIpOnceInner(force)); }
    catch (e) {
      if (this.lifecycle.enabled) this.emit(`[${stamp()}] [NETWORK CHECK] Verification failed: ${(e as Error).message}`);
    }
    finally { this.publicIpPollRunning = false; }
  }

  private async pollPublicIpOnceInner(force = false): Promise<void> {
    if (!force && this.cfg.publicIpPollSec <= 0) {
      return;
    }
    if (this.directRecoveryRunning || this.runbookRunning) {
      return;
    }
    let found: { ip: string; service: string };
    try {
      found = await fetchDirectPublicIp((u, t) => fetchDirectUrl(u, t), DIRECT_IP_URLS, Math.min(this.cfg.checkTimeoutMs, 8000));
    } catch {
      return;
    }
    if (!this.lifecycle.enabled || (!force && !this.cfg.autoRecover)) return;
    if (this.directRecoveryRunning || this.runbookRunning || isRecoveryRunning()) return;
    const prev = this.lastPublicIp;
    this.lastPublicIp = found.ip;
    this.lastPublicIpAt = Date.now();
    if (force || (prev !== null && found.ip !== prev) || (!prev && this.baseState !== 'HEALTHY')) {
      this.emit(`[${stamp()}] [PUBLIC IP] ${force ? 'Manual network verification' : 'Network change detected'}: ${prev ?? 'unknown'} -> ${found.ip} (via ${found.service}, direct, proxy bypassed). Marking RECONNECTING (not failed) and verifying.`);
      // Attributed change: RECONNECTING owns the outcome — never PROXY_FAILED
      // before the G-sequence (check :22, SG repair, rebuild, verify) settles.
      this.reconnecting = true;
      this.display = 'RECONNECTING';
      this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
      try {
        await this.check(false);
        if (this.lifecycle.enabled && (force || this.cfg.autoRecover) && this.baseState !== 'HEALTHY' && this.cfg.supervisorMode === 'direct') {
          await this.runDirectRecovery('network-change');
        }
      } finally {
        // A dry run, skipped recovery, or thrown check must release the
        // attribution flag or future failures remain RECONNECTING forever.
        if (!this.directRecoveryRunning) {
          this.reconnecting = false;
          if (this.lifecycle.enabled && this.display === 'RECONNECTING') {
            this.display = this.policy.verdict === 'PROXY_DOWN' ? 'PROXY_DOWN' : 'DEGRADED';
            this.applyView(presentDisplay(this.display, { activeCount: this.req.activeCount }), this.display);
          }
        }
      }
    }
  }

  /**
   * Manual network check (command palette / dashboard button): discover the
   * current public IP directly (proxy bypassed). If it changed from the last
   * known value, run the same attributed change sequence as automatic polling
   * (RECONNECTING -> verify -> recover). Never runs on a timer.
   */
  async manualNetworkCheck(): Promise<void> {
    if (this.cfg.supervisorMode !== 'direct') {
      void vscode.window.showWarningMessage('Manual network check applies to supervisor=direct only.');
      return;
    }
    if (this.publicIpPollRunning || this.directRecoveryRunning || this.runbookRunning || isRecoveryRunning()) {
      void vscode.window.showInformationMessage('A recovery is already running — let it finish first.');
      return;
    }
    this.emit(`[${stamp()}] Manual network check started (direct, proxy bypassed).`);
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'OpenCode proxy: checking network / SG', cancellable: false },
      async () => {
        await this.pollPublicIpOnce(true);
      },
    );
    if (this.lastPublicIp) {
      void vscode.window.showInformationMessage(`Network check done — public IP ${this.lastPublicIp}.`);
    } else {
      void vscode.window.showWarningMessage('Network check could not discover the public IP (offline, or all echo services unreachable).');
    }
  }

  /**
   * Manual SG repair: discover the current public IP directly, verify TCP 22
   * reachability, and (only if unreachable) re-authorize the current /32 on
   * the configured security group. Never opens 0.0.0.0/0; never touches
   * non-proxy rules.
   */
  async manualSgRepair(): Promise<void> {
    await this.lifecycle.run(() => this.manualSgRepairInner());
  }

  private async manualSgRepairInner(): Promise<void> {
    const gid = this.cfg.securityGroupId.trim();
    if (!this.cfg.enableAwsRepair || gid.length === 0) {
      void vscode.window.showWarningMessage('SG repair needs opencodeProxyHealth.securityGroupId set (and enableAwsRepair on).');
      return;
    }
    if (this.directRecoveryRunning || this.runbookRunning || isRecoveryRunning()) {
      void vscode.window.showInformationMessage('A recovery is already running — let it finish first.');
      return;
    }
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'OpenCode proxy: manual SG repair', cancellable: false },
      async (p) => {
        p.report({ message: 'discovering public IP (direct, proxy bypassed)…' });
        let ip: string;
        try {
          const found = await fetchDirectPublicIp((u, t) => fetchDirectUrl(u, t), DIRECT_IP_URLS, Math.min(this.cfg.checkTimeoutMs, 8000));
          ip = found.ip;
          this.lastPublicIp = found.ip;
          this.lastPublicIpAt = Date.now();
        } catch (e) {
          this.emit(`[${stamp()}] [FAIL] Manual SG repair: public IP discovery failed: ${(e as Error).message}`);
          void vscode.window.showErrorMessage('Manual SG repair: could not discover the public IP (proxy bypassed).');
          return;
        }
        p.report({ message: `public IP ${ip} — checking EC2 :22…` });
        this.emit(`[${stamp()}] Manual SG repair: public IP ${ip}; probing ${this.cfg.ec2Host}:${this.cfg.sshPort}.`);
        let awsUp = false;
        try {
          awsUp = await checkAwsSshReachable(this.cfg.ec2Host, this.cfg.sshPort, this.cfg.checkTimeoutMs);
        } catch {
          awsUp = false;
        }
        if (awsUp) {
          this.emit(`[${stamp()}] Manual SG repair: EC2 :22 already reachable — SG is fine for ${ip}, nothing to do.`);
          void vscode.window.showInformationMessage(`EC2 SSH already reachable — SG fine for ${ip}. No change made.`);
          return;
        }
        p.report({ message: `:22 blocked — re-authorizing ${ip}/32…` });
        this.emit(`[${stamp()}] Manual SG repair: :22 unreachable — running describe/revoke/authorize/describe for ${ip}/32 (never 0.0.0.0/0).`);
        try {
          const r = await ensureSshAccess(this.proxyExec, this.recoveryMachineConfig(), ip);
          this.emit(`[${stamp()}] Manual SG repair: ${r.detail}`);
          if (r.ok && r.authorizedCurrent) {
            void vscode.window.showInformationMessage(`SG repaired for ${ip}/32. Run "Recover Proxy" if the tunnel is still down.`);
          } else {
            void vscode.window.showErrorMessage(`Manual SG repair failed: ${r.detail}`);
          }
        } catch (e) {
          this.emit(`[${stamp()}] [FAIL] Manual SG repair threw: ${(e as Error).message}`);
          void vscode.window.showErrorMessage(`Manual SG repair failed: ${(e as Error).message.slice(0, 120)}`);
        }
      },
    );
  }

  /** Warn once, then offer a one-click disable of the legacy scheduled tasks. */
  private async checkSchedulerConflict(): Promise<void> {
    if (this.cfg.supervisorMode !== 'direct' || this.schedulerConflictWarned) {
      return;
    }
    try {
      const ssh = await queryScheduledTask(defaultExecAsync, this.cfg.sshTaskName, 8000);
      const bridge = await queryScheduledTask(defaultExecAsync, this.cfg.bridgeTaskName, 8000);
      if ((ssh.exists && ssh.running) || (bridge.exists && bridge.running)) {
        this.schedulerConflictWarned = true;
        const msg = `Conflict risk: Task Scheduler tasks "${this.cfg.sshTaskName}" (${ssh.status}) / "${this.cfg.bridgeTaskName}" (${bridge.status}) still exist while supervisor=direct. Disable them so two supervisors never fight over ssh.exe/hpts.`;
        this.emit(`[${stamp()}] [WARN] ${msg}`);
        const choice = await vscode.window.showWarningMessage(msg, 'Disable legacy tasks now', 'Keep them');
        if (choice === 'Disable legacy tasks now') {
          await this.disableLegacyTasks();
        } else {
          this.emit(`[${stamp()}] Legacy tasks left enabled by user choice; use the command "OpenCode Proxy: Disable Legacy Task Scheduler Tasks" any time.`);
        }
      }
    } catch {
      /* best-effort only */
    }
  }

  /**
   * Disable (never delete) the legacy Task Scheduler tasks so only the direct
   * supervisor owns ssh.exe/hpts. Disabling is reversible (schtasks /change
   * /ENABLE) and stops the tasks from firing while direct mode is active.
   */
  async disableLegacyTasks(): Promise<void> {
    if (this.cfg.supervisorMode !== 'direct') {
      void vscode.window.showWarningMessage('Legacy tasks are the supervisor in task mode — disabling them would break recovery. Switch supervisorMode=direct first.');
      return;
    }
    const names = [this.cfg.sshTaskName, this.cfg.bridgeTaskName];
    const results: string[] = [];
    for (const name of names) {
      try {
        const st = await queryScheduledTask(defaultExecAsync, name, 8000);
        if (!st.exists) {
          results.push(`"${name}": not found (nothing to do)`);
          continue;
        }
        if (st.running) {
          try {
            await defaultExecAsync('schtasks', ['/End', '/TN', name], 10000);
            results.push(`"${name}": stopped`);
          } catch {
            results.push(`"${name}": stop skipped (not running anymore)`);
          }
        }
        await defaultExecAsync('schtasks', ['/Change', '/TN', name, '/DISABLE'], 10000);
        const after = await queryScheduledTask(defaultExecAsync, name, 8000);
        results.push(after.disabled ? `"${name}": disabled` : `"${name}": disable UNVERIFIED (${after.status})`);
      } catch (e) {
        results.push(`"${name}": FAILED (${(e as Error).message.split('\n')[0].slice(0, 120)})`);
      }
    }
    for (const r of results) {
      this.emit(`[${stamp()}] [FIX] Legacy task: ${r}.`);
    }
    const failedAny = results.some((r) => r.includes('FAILED') || r.includes('UNVERIFIED'));
    if (failedAny) {
      void vscode.window.showWarningMessage(`Legacy task disable finished with warnings: ${results.join(' · ')}`);
    } else {
      void vscode.window.showInformationMessage(`Supervisor conflict resolved: ${results.join(' · ')}. The direct supervisor is now the sole owner.`);
    }
  }

  /** Manual, user-invoked recovery of one task and its port. */
  async restartTask(taskName: string): Promise<void> {
    await this.lifecycle.run(() => this.restartTaskInner(taskName));
  }

  private async restartTaskInner(taskName: string): Promise<void> {
    if (this.cfg.supervisorMode === 'direct') {
      const msg = `supervisor=direct owns ssh.exe/hpts itself — scheduled task "${taskName}" is disabled by design. Use "Recover Proxy (direct supervisor)" instead.`;
      this.emit(`[${stamp()}] [WARN] ${msg}`);
      void vscode.window.showWarningMessage(msg);
      return;
    }
    if (this.runbookRunning || this.autoRecoveryRunning || this.manualRecoveryRunning || this.directRecoveryRunning) {
      void vscode.window.showWarningMessage('A proxy recovery action is already in progress.');
      return;
    }
    const rc = this.recoverConfig();
    if (rc.sshTask.trim() === rc.bridgeTask.trim()) {
      void vscode.window.showWarningMessage('SSH and bridge task names must differ for safe recovery.');
      return;
    }
    this.manualRecoveryRunning = true;
    this.emit(`[${stamp()}] [FIX] Manual task recovery requested: "${taskName}".`);
    try {
      const res = await this.reviveTask(taskName, rc, 'Manual recovery');
      this.emit(`[${stamp()}] ${res.ok ? '[FIX]' : '[FAIL]'} Manual task recovery: ${res.detail}.`);
      await this.check(true);
      if (res.ok) {
        void vscode.window.showInformationMessage(`Task recovery: ${res.detail}.`);
      } else {
        void vscode.window.showWarningMessage(`Could not recover "${taskName}": ${res.detail}`);
      }
    } catch (e) {
      const detail = (e as Error).message;
      this.emit(`[${stamp()}] [FAIL] Manual task recovery: ${detail}.`);
      void vscode.window.showWarningMessage(`Could not recover "${taskName}": ${detail}`);
    } finally {
      this.manualRecoveryRunning = false;
    }
  }

  async restartSshTask(): Promise<void> {
    await this.restartTask(this.cfg.sshTaskName);
  }

  async restartBridgeTask(): Promise<void> {
    await this.restartTask(this.cfg.bridgeTaskName);
  }

  // -- one-click runbook ----------------------------------------------------

  private runbookConfig(): RunbookConfig {
    return {
      socksHost: this.cfg.socksHost,
      socksPort: this.cfg.socksPort,
      httpHost: this.cfg.httpHost,
      httpPort: this.cfg.httpPort,
      expectedExternalIp: this.cfg.expectedExternalIp,
      sshTask: this.cfg.sshTaskName,
      bridgeTask: this.cfg.bridgeTaskName,
      portWaitMs: this.cfg.runbookPortWaitSec * 1000,
      portPollMs: 750,
      execTimeoutMs: 5000,
    };
  }

  /**
   * Run the hand-runbook (steps 1-6) as one gated sequence, then offer to start
   * opencode (step 7) in a terminal carrying the proxy env.
   *
   * Uses the user's existing scheduled tasks, including resetting a stuck
   * task whose port remains closed. Never synthesises an ssh command line or
   * mutates machine-wide environment variables.
   */
  async recoverChain(): Promise<void> {
    await this.lifecycle.run(() => this.recoverChainInner());
  }

  private async recoverChainInner(): Promise<void> {
    if (this.cfg.supervisorMode === 'direct') {
      const msg = 'supervisor=direct owns ssh.exe/hpts itself — the Task Scheduler runbook is disabled by design. Running direct state-machine recovery instead.';
      this.emit(`[${stamp()}] [WARN] ${msg}`);
      void vscode.window.showWarningMessage(msg);
      await this.runDirectRecovery('manual-runbook-redirect');
      return;
    }
    if (this.runbookRunning) {
      void vscode.window.showWarningMessage('A recovery runbook is already running.');
      return;
    }
    if (this.autoRecoveryRunning || this.manualRecoveryRunning || this.directRecoveryRunning) {
      void vscode.window.showWarningMessage('A task recovery action is in progress. Try the runbook after it finishes.');
      return;
    }
    this.runbookRunning = true;
    this.emit(`[${stamp()}] ── Recovery runbook started (one click) ──`);
    let result: RunbookResult;
    try {
      result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'OpenCode proxy: recovering chain',
          cancellable: false,
        },
        (p) => this.executeRunbook(p),
      );
    } catch (e) {
      this.runbookRunning = false;
      this.emit(`[${stamp()}] [FAIL] Recovery runbook threw: ${(e as Error).message}`);
      void vscode.window.showErrorMessage(`Recovery runbook failed: ${(e as Error).message}`);
      return;
    }
    for (const line of formatRunbook(result)) {
      this.emit(`[${stamp()}] ${line}`);
    }
    // Fresh evidence: re-run the normal check so the status bar reflects reality.
    await this.check(true);
    this.runbookRunning = false;

    if (!result.ok) {
      const failed = result.steps.find((s) => s.id === result.failedAt);
      this.emit(
        `[${stamp()}] [FAIL] Runbook stopped at step ${failed?.n ?? '?'} (${failed?.title ?? 'unknown'}): ${failed?.detail ?? 'no detail'}`,
      );
      this.notifyFail(`OpenCode proxy recovery stopped at step ${failed?.n ?? '?'} — ${failed?.detail ?? 'no detail'}`);
      void vscode.window.showErrorMessage(
        `Proxy recovery stopped at step ${failed?.n ?? '?'} (${failed?.title ?? 'unknown'}). See the output log.`,
      );
      return;
    }
    if (this.baseState !== 'HEALTHY') {
      this.emit(`[${stamp()}] [FAIL] Runbook restored the local proxy, but the full health check is ${this.baseState}: ${this.lastResult?.reason ?? 'unknown reason'}.`);
      this.notifyFail(`Proxy recovery incomplete: ${this.baseState}. See the output log.`);
      return;
    }

    const skipped = result.steps.filter((s) => s.status === 'skipped').length;
    this.emit(
      `[${stamp()}] [OK] Runbook complete in ${result.elapsedMs}ms — chain healthy via ${result.egressIp ?? 'unknown egress'}` +
        `${skipped > 0 ? ` (${skipped} step(s) already satisfied)` : ''}.`,
    );
    void vscode.window.showInformationMessage(
      `Proxy chain healthy (egress ${result.egressIp ?? 'unknown'}).`,
    );
    await this.maybeLaunchOpencode(result.env);
  }

  private async executeRunbook(
    p: vscode.Progress<{ message?: string; increment?: number }>,
  ): Promise<RunbookResult> {
    const total = 6;
    const done = new Map<string, string>();
    const mark = (label: string, message: string) => {
      done.set(label, message);
      p.report({ message: `${done.size}/${total} · ${label} — ${message}` });
    };
    return runRunbook(this.runbookConfig(), {
      runTask: (task) => this.reviveTask(task, this.recoverConfig(), 'One-click recovery'),
      probePort: (host, port, timeoutMs) => checkTcpPort(host, port, timeoutMs),
      egressIp: async () => {
        const reading = await fetchTrafficIpFromServices(
          fetchViaHttpProxy,
          this.cfg.httpHost,
          this.cfg.httpPort,
          [this.cfg.ipifyUrl, ...IP_CHECK_URLS.filter((url) => url !== this.cfg.ipifyUrl)],
          this.cfg.checkTimeoutMs,
        );
        return reading.ip;
      },
      sleep: (ms) => this.lifecycle.sleep(ms),
      now: () => Date.now(),
      onStep: (s) => {
        const label = `${s.n}. ${s.title}`;
        if (s.status === 'running') {
          mark(label, 'running…');
        } else {
          this.emit(`[${stamp()}] Runbook ${label} — ${s.status}: ${s.detail}`);
          mark(label, s.status === 'failed' ? s.detail : s.status);
        }
      },
    });
  }

  /**
   * Step 7. Applies the proxy env to a NEW integrated terminal only — the
   * extension host, VS Code, and your existing terminals are left untouched.
   */
  private async maybeLaunchOpencode(env: Record<string, string>): Promise<void> {
    if (!this.lifecycle.enabled) return;
    if (!this.cfg.runbookLaunchOpencode) {
      const pick = await this.lifecycle.waitWhileEnabled(vscode.window.showInformationMessage(
        `Proxy chain is healthy. Start opencode now with the proxy env applied?`,
        'Start opencode',
        'No thanks',
      ));
      if (pick !== 'Start opencode') {
        this.emit(
          `[${stamp()}] opencode not launched. To get the proxy env, start it yourself in a terminal after running:`,
        );
        for (const [k, v] of Object.entries(env)) {
          this.emit(`[${stamp()}]   $env:${k}="${v}"`);
        }
        return;
      }
    }
    if (!this.lifecycle.enabled) return;
    const term = vscode.window.createTerminal({
      name: 'opencode (proxied)',
      env: { ...process.env, ...env } as Record<string, string | null>,
    });
    this.proxiedTerminals.add(term);
    term.show();
    term.sendText(this.cfg.opencodeCommand);
    this.emit(
      `[${stamp()}] [OK] Launched "${this.cfg.opencodeCommand}" in a new terminal with ${formatProxyEnv(env)} applied (that terminal only).`,
    );
  }

  /**
   * Single-flight health-check entry: exactly one cycle at a time (E).
   * An auto poll arriving mid-cycle is SKIPPED; a manual refresh chains onto
   * the in-flight promise and re-runs once. Combined with an 8s overall guard
   * below the 10s poll interval, overlapping 15s-style pile-ups are impossible.
   */
  private async check(manual: boolean): Promise<void> {
    if (!this.lifecycle.enabled) return;
    if (!this.probeGate.tryEnter()) {
      if (manual) {
        if (this.currentCheck) {
          await this.currentCheck;
          return this.check(true);
        }
      }
      return;
    }
    this.running = true;
    const work = this.checkInner(manual)
      .catch((e) => {
        this.baseState = 'UNKNOWN';
        this.display = 'UNKNOWN';
        this.lastResult = null;
        this.applyView(presentDisplay('UNKNOWN'), 'UNKNOWN');
        this.emit(`[${stamp()}] [FAIL] Health check error: ${(e as Error).message}`);
      })
      .finally(() => {
        this.running = false;
        this.currentCheck = null;
        this.probeGate.exit();
      });
    this.currentCheck = work;
    await work;
  }

  private async checkInner(manual: boolean): Promise<void> {
    const cfg = this.cfg;
    const prevBase = this.baseState;
    const prevDisplay = this.display;
    const prevActive = this.req.activeCount;
    const wasFailure = prevBase !== 'HEALTHY' && prevBase !== 'STARTING';
    if (wasFailure && !manual) {
      this.item.text = this.cfg.statusStyle === 'icon' ? '$(sync~spin)' : '$(sync~spin) Proxy: Reconnecting...';
      this.item.backgroundColor = undefined;
    }
    if (manual) {
      this.emit(`[${stamp()}] Manual refresh started.`);
    }

    // LEVEL 1 + LEVEL 2 only (fast budgets, 8s guard < poll interval).
    // Echo services and Zen NEVER run here: one failed probe is one sample.
    const { result, timedOut } = await runHealthCheckGuarded(cfg);
    await this.readRequests();
    if (!this.lifecycle.enabled) return;

    const leg: HealthState = timedOut ? 'UNKNOWN' : deriveState(result);
    if (timedOut) {
      result.reason = result.reason ?? 'health check timed out (single sample, unconfirmed)';
    }
    this.baseState = leg;
    const infraOk = leg === 'HEALTHY';
    const transportOnlyFailure = leg === 'PROXY_FAILED' && result.socksUp && result.httpUp;
    const nowMs = Date.now();
    const recentTrafficOk = hasRecentTrafficOk(
      { lastSuccessAtMs: this.req.lastSuccessAtMs, lastFailureAtMs: this.req.lastFailureAtMs },
      nowMs,
      this.cfg.recentTrafficWindowSec * 1000,
    );
    const folded = nextPolicy(
      this.policy,
      infraOk ? 'ok' : 'infra-down',
      nowMs,
      { failureThreshold: this.cfg.failureThreshold, minOutageNotifySec: this.cfg.minOutageNotifySec, recentTrafficWindowMs: this.cfg.recentTrafficWindowSec * 1000 },
      {
        transportOnlyFailure,
        recentTrafficOk,
        reconnecting: this.reconnecting,
        recovering: this.directRecoveryRunning,
      },
    );
    const wasConfirmed = this.policy.verdict === 'PROXY_DOWN';
    this.policy = folded.state;
    if (transportOnlyFailure && recentTrafficOk && !infraOk) {
      this.emit(`[${stamp()}] [TRACK] Transport probe failed but a tracked OpenCode request succeeded recently — treating as diagnostic failure (no strike, no recovery).`);
    }
    this.lastResult = result;
    this.lastCheck = new Date();
    this.latencies.push(result.elapsedMs);
    if (this.latencies.length > 30) {
      this.latencies = this.latencies.slice(-30);
    }

    // Outages open ONLY on confirmed proxy unavailability — DEGRADED, Zen
    // blips and transient single samples never pollute uptime or "down for".
    updateHistory(this.history, this.policy.confirmedDownSinceMs === null, nowMs);
    // Fire-and-forget: storage latency must never slow the tick.
    void this.context.globalState.update(HISTORY_KEY, this.history).then(undefined, () => {
      // Persistence is best-effort.
    });

    // LEVEL 3 — Zen on a separate slow cadence, display-only. Skipped while
    // transport is down (it needs the proxy) and never gates the verdict.
    if (infraOk && nowMs - this.lastZenProbeAt >= this.cfg.zenProbeIntervalSec * 1000) {
      this.lastZenProbeAt = nowMs;
      try {
        const zen = await probeZenService(cfg);
        const prevZen = this.zen.verdict;
        this.zen = nextZen(this.zen, zen.reachable);
        this.lastZenDetail = zen.reason;
        if (this.zen.verdict !== prevZen) {
          this.emit(`[${stamp()}] [ZEN] ${prevZen} -> ${this.zen.verdict}${zen.reason ? `: ${zen.reason}` : ''} (service-side only; no proxy action).`);
        }
      } catch (e) {
        const prevZen = this.zen.verdict;
        this.zen = nextZen(this.zen, false);
        if (this.zen.verdict !== prevZen) {
          this.emit(`[${stamp()}] [ZEN] ${prevZen} -> ${this.zen.verdict}: ${(e as Error).message.slice(0, 120)} (service-side only).`);
        }
      }
    }

    if (!this.lifecycle.enabled) return;
    const slow =
      infraOk && cfg.slowThresholdMs > 0 && result.elapsedMs > cfg.slowThresholdMs;
    // While the direct state machine is actively driving the UI (SOCKS_STARTING,
    // SG_REPAIRING, ...), do not clobber its transitional display with the raw
    // health state — the machine owns the status until it settles.
    const holdingRecoveryDisplay =
      this.directRecoveryRunning &&
      this.recoveryState !== null &&
      this.recoveryState !== 'READY' &&
      this.recoveryState !== 'RECOVERY_FAILED' &&
      !infraOk;
    if (!holdingRecoveryDisplay) {
      if (infraOk) {
        // Strongest signal first: a live tracked request beats any service
        // probe. Then Zen (display-only), then plain HEALTHY.
        const ocDisplay = overlayRequest('HEALTHY', this.req, this.clearedFailureBeforeMs);
        if (ocDisplay === 'REQUEST_RUNNING' || ocDisplay === 'REQUEST_FAILED') {
          this.display = ocDisplay;
        } else if (this.zen.verdict !== 'ZEN_OK') {
          this.display = this.zen.verdict === 'ZEN_DEGRADED' ? 'ZEN_DEGRADED' : 'ZEN_UNREACHABLE';
        } else {
          this.display = 'HEALTHY';
        }
        this.reconnecting = false;
      } else if (this.reconnecting) {
        this.display = 'RECONNECTING';
      } else if (this.policy.verdict === 'PROXY_DOWN') {
        this.display = 'PROXY_DOWN';
      } else {
        this.display = 'DEGRADED';
      }
    }


    if (infraOk) {
      this.lastSuccess = new Date();
      this.recoveryState = null;
      this.cadence = emptyRecoveryCadence();
      // "Recovered" is only true (and only notified) after a CONFIRMED outage
      // that lasted long enough to matter. A Zen-only blip or a couple of
      // failed probes while traffic flowed must never print "down for Xs".
      // A recovery run counts as confirmation (attributed cause, G-sequence).
      if (wasConfirmed || this.recoveryEpisodeOutage) {
        const sinceMs = this.downSince ? this.downSince.getTime() : nowMs;
        const { notify, downForMs } = shouldNotifyRecovery(sinceMs, nowMs, this.cfg.minOutageNotifySec);
        const downFor = ` (down for ${formatDuration(downForMs)})`;
        const fixed =
          this.recoverAttempts.length > 0 ? ` Auto-recovery made ${this.recoverAttempts.length} attempt(s) this outage.` : '';
        this.emit(`[${stamp()}] [OK] RECOVERED to HEALTHY${downFor}.${fixed}`);
        this.emit(`[${stamp()}] [PROXY CHECK] HEALTHY — SOCKS :${cfg.socksPort} + HTTP :${cfg.httpPort} + transport verified.`);
        if (notify) {
          this.notifyRecover(`OpenCode proxy recovered${downFor}.`);
        }
        this.downSince = null;
        this.deepFor = null;
        this.recoverAttempts = [];
        this.gaveUpLogged.clear();
        this.dryRunLogged.clear();
        this.recoveryEpisodeOutage = false;
        this.recoveryFailNotified = false;
      } else if (manual || prevBase === 'STARTING') {
        this.emit(
          `[${stamp()}] HEALTHY — SOCKS :${cfg.socksPort} OK, HTTP :${cfg.httpPort} OK, transport ${result.transportTarget ?? cfg.transportProbeUrl} HTTP ${result.transportStatus ?? '?'} (${result.elapsedMs}ms).`,
        );
      }
      // Steady-state healthy (and Zen-only states): stay silent, no flooding.
    } else {
      // Mirror the confirmed outage start for duration math + reports.
      if (this.policy.confirmedDownSinceMs !== null && this.downSince === null) {
        this.downSince = new Date(this.policy.confirmedDownSinceMs);
      }
      if (this.policy.confirmedDownSinceMs === null && this.downSince !== null && !wasConfirmed) {
        this.downSince = null;
      }
      // Log transitions only (status bar already shows transients). The ONLY
      // user notification here is the policy's confirmed-down event.
      if (this.display !== prevDisplay || manual) {
        this.emit(
          `[${stamp()}] ${this.display === 'PROXY_DOWN' ? '[FAIL]' : '[WARN]'} ${this.display}: ${result.reason ?? 'no detail'} ` +
            `(strikes ${this.policy.strikes}/${this.cfg.failureThreshold} / SOCKS ${result.socksUp ? 'up' : 'down'} / HTTP ${result.httpUp ? 'up' : 'down'} / ` +
            `SSH ${result.sshRunning ? 'running' : 'missing'} / transport ${result.proxyTrafficOk ? 'ok' : 'failing'})`,
        );
      }
      for (const ev of folded.events) {
        if (ev === 'notify-proxy-down') {
          this.notifyFail(this.cfg.autoRecover ? 'OpenCode proxy connection lost. Recovering...' : 'OpenCode proxy connection lost. Use Recover Proxy from the dashboard.');
        }
      }
      // Self-healing runs only on confirmation (PROXY_DOWN) inside
      // maybeRecover, so the log reads failure → fix attempt → diagnosis.
      await this.maybeRecover();
      // Enrich confirmed failures with on-demand diagnosis (never blocks).
      if (this.display === 'PROXY_DOWN') {
        void this.refreshDeep(this.display);
      }
    }

    // Honest request transitions (only meaningful while transport is healthy).
    if (infraOk) {
      if (this.req.activeCount > 0 && prevActive === 0) {
        this.emit(
          `[${stamp()}] [TRACK] request started (${this.req.activeCount} active${
            this.req.oldestActiveModel ? `, model ${this.req.oldestActiveModel}` : ''
          }).`,
        );
      } else if (this.req.activeCount === 0 && prevActive > 0) {
        if (this.req.lastFailureAtMs !== null && (this.req.lastSuccessAtMs === null || this.req.lastFailureAtMs > this.req.lastSuccessAtMs)) {
          this.emit(`[${stamp()}] [TRACK] request finished: FAILED — ${this.req.lastFailureReason ?? 'unknown reason'}.`);
          this.notifyFail(`Tracked OpenCode request failed — ${this.req.lastFailureReason ?? 'unknown reason'}`);
        } else {
          this.emit(`[${stamp()}] [TRACK] request finished successfully.`);
        }
      } else if (this.display === 'REQUEST_FAILED' && prevDisplay !== 'REQUEST_FAILED') {
        this.emit(`[${stamp()}] [FAIL] Tracked request failure: ${this.req.lastFailureReason ?? 'unknown reason'}.`);
        this.notifyFail(`Tracked OpenCode request failed — ${this.req.lastFailureReason ?? 'unknown reason'}`);
      }
      if (slow && !this.wasSlow) {
        this.emit(
          `[${stamp()}] [WARN] Slow check: ${result.elapsedMs}ms exceeded threshold ${cfg.slowThresholdMs}ms ` +
            `(L1 ${result.socksMs ?? '—'}ms / L2 ${result.trafficMs ?? '—'}ms) — network may be sluggish.`,
        );
      }
    }
    this.wasSlow = slow && infraOk;

    // Manual refresh while confirmed-down also gets fresh deep info.
    if (manual && this.display === 'PROXY_DOWN') {
      await this.refreshDeep(this.display);
    }

    this.applyView(presentDisplay(this.display, { slow, activeCount: this.req.activeCount }), this.display);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const channel = vscode.window.createOutputChannel(CHANNEL_NAME);
  context.subscriptions.push(channel);
  const monitor = new Monitor(context, channel);
  context.subscriptions.push(monitor);

  context.subscriptions.push(
    vscode.commands.registerCommand('opencode-proxy-health.turnOff', () => monitor.turnOff()),
    vscode.commands.registerCommand('opencode-proxy-health.turnOn', () => monitor.turnOn()),
    vscode.commands.registerCommand('opencode-proxy-health.refresh', () => monitor.refresh(true)),
    vscode.commands.registerCommand('opencode-proxy-health.showDiagnostics', () => monitor.showDashboard()),
    vscode.commands.registerCommand('opencode-proxy-health.showOutput', () => monitor.showOutput()),
    vscode.commands.registerCommand('opencode-proxy-health.copyDiagnostics', () => monitor.copyDiagnostics()),
    vscode.commands.registerCommand('opencode-proxy-health.clearRequestFailure', () => monitor.clearRequestFailure()),
    vscode.commands.registerCommand('opencode-proxy-health.restartSshTask', () => monitor.restartSshTask()),
    vscode.commands.registerCommand('opencode-proxy-health.restartBridgeTask', () => monitor.restartBridgeTask()),
    vscode.commands.registerCommand('opencode-proxy-health.recoverChain', () => monitor.recoverChain()),
    vscode.commands.registerCommand('opencode-proxy-health.recoverProxyDirect', () => monitor.runDirectRecovery('manual-command')),
    vscode.commands.registerCommand('opencode-proxy-health.disableLegacyTasks', () => monitor.disableLegacyTasks()),
    vscode.commands.registerCommand('opencode-proxy-health.checkNetworkChange', () => monitor.manualNetworkCheck()),
    // Registered ONCE here (not per start()) — re-arm the timer on changes.
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('opencodeProxyHealth')) {
        monitor.start();
      }
    }),
  );

  monitor.start();
}

export function deactivate(): void {
  // Timer disposal is handled via context.subscriptions.
}
