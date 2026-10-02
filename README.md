# OpenCode Proxy Health (v0.11.2)

## Install v0.11.2

Download [opencode-proxy-health-0.11.2.vsix](releases/opencode-proxy-health-0.11.2.vsix)
using GitHub's **Download raw file** button. In VS Code, run
**Extensions: Install from VSIX**, select that file, and then run
**Developer: Reload Window**. Confirm the OpenCode Proxy output log reports
`version 0.11.2`. This updates the extension without merging unrelated Git
histories or requiring a local build.

This version includes SSH startup diagnostics, safe roaming security-group
repair, and persistent Proxy Off controls. HTTP, HTTPS, and SOCKS probes now
finish complete framed responses without waiting for the server to close its
connection, preventing false timeouts on persistent connections. Partial or
malformed responses remain failures. Windows AWS CLI arguments reject command
expansion characters instead of letting settings be interpreted by cmd.exe.

To build from source: `npm ci`, `npm test`, then `npm run package`. The output
filename follows the version in `package.json`.

## Automatic recovery after changing Wi-Fi

In **Preferences: Open User Settings (JSON)**, merge these settings into your
existing object. Replace the security-group placeholder with the group attached
to your EC2 instance. Configure a valid AWS CLI profile on the same Windows
machine; CloudShell's credentials do not configure the local extension.

```json
{
  "opencodeProxyHealth.supervisorMode": "direct",
  "opencodeProxyHealth.securityGroupId": "YOUR_ATTACHED_SECURITY_GROUP_ID",
  "opencodeProxyHealth.awsRegion": "eu-north-1",
  "opencodeProxyHealth.enableAwsRepair": true,
  "opencodeProxyHealth.autoRecover": true,
  "opencodeProxyHealth.autoRecoverDryRun": false,
  "opencodeProxyHealth.bootstrapRecoverOnStartup": true,
  "opencodeProxyHealth.publicIpPollSec": 30
}
```

The extension checks the current IPv4 address directly, even while the proxy is
down. On an IP change it verifies the chain, authorizes the new `/32` if AWS SSH
is blocked, then recovers and verifies the proxy. New rules carry the
`opencode-proxy` description so subsequent repairs can identify them. New
access is verified before stale managed rules are removed. Unmarked manual
rules and old tag-only rules are retained; identify them manually before any
cleanup. Do not label another user's rule as managed by this proxy.

Network checks run one at a time, respect `autoRecover: false`, and stop doing
work when the proxy is turned off. Failed requests cannot release another
request's proxy bypass. Default polling remains off until roaming is enabled.

Automatic IP repair requires access to the AWS API and outbound SSH on the
configured port. A captive portal must be completed first. A network that
blocks SSH will still require an allowed transport; opening the EC2 firewall
does not bypass that network's restrictions. Host trust and SSH authentication
must also be established before background recovery can succeed.

## SSH reaches EC2 but the SOCKS port never opens

Health probes also decode HTTP chunk framing before parsing IP echoes or model
lists, preserve UTF-8 across network packet boundaries, and accept bodyless
HEAD/204 responses. Malformed or truncated responses remain failures. A skipped
or dry-run network recovery cannot leave the monitor stuck in RECONNECTING.

v0.11.1 captures bounded SSH/bridge stderr and exit codes, redacts the configured
private-key path, and stops waiting for a port as soon as its child exits.
Diagnostics and recovery notifications show the startup error. Missing or
unreadable key files fail before SSH is launched. SSH uses the configured
identity with `IdentitiesOnly=yes`; host verification remains enabled.
The startup log and diagnostic report show the installed extension version.

If SSH reports **Host key verification failed**, first verify the instance's
SSH host fingerprint in the AWS EC2 console: select the instance, then
**Actions → Monitor and troubleshoot → Get system log**. Find the
`BEGIN SSH HOST KEY FINGERPRINTS` section and compare the corresponding
algorithm/fingerprint with the SSH prompt. This is the instance host key,
not the key-pair fingerprint shown on the EC2 Key pairs page. See
[AWS connection prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connection-prereqs-general.html).

After verifying the fingerprint, connect interactively once using your actual
configured key, user, host and port. For the default configuration:

```powershell
$key = "$env:USERPROFILE\.ssh\opencode-proxy-key.pem"
& "$env:WINDIR\System32\OpenSSH\ssh.exe" -i $key -p 22 -o BatchMode=no -o StrictHostKeyChecking=ask -o IdentitiesOnly=yes ubuntu@16.192.228.28 exit
```

Accept the trust prompt only if the fingerprint matches the verified instance.
Then run **OpenCode Proxy: Recover Proxy**. Background SSH uses `BatchMode=yes`,
so it cannot ask you to accept a previously unknown host. If SSH reports a
changed host key instead, investigate the change and verify the replacement
before editing that host's known-hosts entry. Do not disable host verification
or delete the whole known-hosts file.

If port 22 is already reachable, adding a security-group ID will not resolve
host trust or authentication errors. A passphrase-protected private key must
be available through `ssh-agent` for background SSH to use it. A successful
interactive login must be followed by recovery and an end-to-end proxy check;
it does not prove SOCKS forwarding or the HTTP bridge is working yet.

Pulling the repository does not update the installed VSIX. After updating,
build/package/install as described below and reload VS Code. Confirm the
startup log says `version 0.11.2`.

## VS Code shows "Error acquiring .NET" / WebRequestError

This extension has no .NET runtime dependency. That message comes from the
.NET Install Tool used by another extension. Open **View → Output**, select
the .NET installation/runtime channel, and copy the full failure including
the download URL and underlying error. `WebRequestError` alone does not
identify a firewall, proxy, TLS, or download failure.

Verify the proxy is READY before configuring .NET to use it. When the local
HTTP bridge is healthy and you want .NET downloads through it, the supported
setting is `"dotnetAcquisitionExtension.proxyUrl": "http://127.0.0.1:8080"`
(use your configured HTTP port). Remove that explicit setting when downloading
directly with the proxy off. Proxy shutdown does not rewrite other extensions'
settings or your existing terminal environment. Microsoft also documents using
an existing compatible .NET installation through `existingDotnetPath` in its
[C# Dev Kit troubleshooting guide](https://code.visualstudio.com/docs/csharp/cs-dev-kit-faq#_net-sdk).

## Turn the proxy off and back on

Open the VS Code Command Palette (`Ctrl+Shift+P`) and run
**OpenCode Proxy: Turn Proxy Off Safely**, or click the proxy status icon and
choose **Turn proxy off safely**. This pauses monitoring, startup recovery,
network repair, and manual recovery; drains pending work; disables and ends
the configured retry tasks; stops only matching HTTP bridge/SSH processes;
and verifies the proxy ports are closed. The off state persists across
VS Code restarts and configuration changes. Terminals started by this
extension are closed, ending any requests running in them.

If shutdown cannot be verified, the status says **OFF (shutdown incomplete)**
and the output log explains why. Recovery stays paused; fix the reported
permissions/process problem and run the off command again. Foreign processes
are never killed to free a port.

To resume, run **OpenCode Proxy: Turn Proxy On** or use the dashboard. In
legacy task mode, only tasks this extension disabled are re-enabled. In
direct mode, legacy tasks stay disabled to avoid competing supervisors.

The extension does not change machine-wide proxy settings. Other applications
and existing terminals with proxy settings need those settings cleared before
they can connect directly. In a PowerShell terminal, clear this session's
proxy environment with:

```powershell
'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy' |
  ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
```

## Reliability fixes in v0.11.0

- Successful automatic recovery no longer waits on its own health check and
  freezes monitoring. Failed attempts record their cooldown and retry budget.
- `autoRecover: false` now suppresses direct background recovery as well as
  legacy task recovery. `bootstrapRecoverOnStartup` remains a separate startup
  option. Manual network checks verify/repair even on the first check or when
  the public IP has not changed.
- SOCKS replies retain combined TCP packets; handshake/CONNECT timeouts no
  longer count as connectivity. Chunked HTTP echo responses are decoded.
- Echo-service failures are classified before any tunnel restart. A working
  owned tunnel is retained; a known wrong egress IP cannot pass as healthy.
- Closed-port stale processes are stopped before replacement; a listening
  owned bridge that cannot forward is refreshed once and re-verified.
- Process matching uses exact flag values, ports, and SSH targets so shutdown
  cannot mistake a similarly named or numbered process for this proxy.
- Custom SSH ports are passed to the tunnel. Windows batch paths with spaces
  are quoted, missing executables cannot crash the extension host, and the
  legacy bridge launcher uses `call` so its retry loop can resume.

Build and run regression checks with `npm ci` then `npm test`. Package the
extension with `npx @vscode/vsce package --no-dependencies`, install the
resulting VSIX using **Extensions: Install from VSIX**, and reload VS Code.
The extension manages Windows processes; the test suite also runs on Linux.
GitHub Actions covers both platforms, including a real Windows batch-launch
check. Live AWS/key configuration still needs to be verified on your Windows
machine using **Recover Proxy** and the output log.

---

# OpenCode Proxy Health (v0.10.2 — zombie-tunnel migration from old builds)

## v0.10.2 — the old build's tunnel is now replaceable

If you ran a pre-migration build (targeting the old IP `13.48.149.186`), its
zombie `ssh -D … ubuntu@13.48.149.186` keeps squatting `:1080` after you
upgrade. The new build's ownership matcher used to consider that process
"foreign" and refuse to kill it — so recovery could never replace it and the
proxy stayed broken no matter what. Fixed:

- `LEGACY_PROXY_HOSTS` in `src/procOwn.ts`: tunnels with the exact legacy
  shape (`-D <our port> -N …@<old host>`) are recognized as OURS, killable,
  and replaceable. The allowlist is enforced by a source-scan test — it can
  never grow silently. Foreign ssh processes are still never touched.
- Verified: dedup keeps a healthy modern tunnel, kills the legacy zombie,
  and recovery spawns the correct `16.192.228.28` tunnel in its place.

Also in this version: manual-only network checking (`publicIpPollSec: 0`
default), one-click legacy-task disable, per-episode failure toasts.

## v0.10.1 — the bridge could never start; ssh could hang forever

## v0.10.1 — the bridge could never start; ssh could hang forever

Deep stability audit found and fixed two real bugs in `src/procOwn.ts`:

- **hpts bridge spawn was silently impossible on modern Node.** Node ≥18
  (CVE-2024-27980 hardening) rejects `spawn('….cmd')` with `shell:false` and
  `EINVAL` — and the default `hptsCmd` is a `.cmd` shim. Every direct-recovery
  attempt to start the HTTP bridge after a crash would have failed with
  "hpts spawn failed: no pid" while ssh came up fine. Fixed: batch targets are
  now **always** routed through `cmd.exe /d /s /c` inside the shared launcher
  (independent of any injected spawn function, so no code path can regress).
- **ssh could hang ~21s per attempt (or sit invisible at a password prompt).**
  The spawned tunnel had keepalives but no `ConnectTimeout` and no
  `BatchMode`. A firewalled/SG-blocked connect hung in SYN_SENT for the OS
  default while recovery burned its whole wait budget; a rejected key would
  show an invisible prompt instead of dying and being reported. Fixed:
  `ConnectTimeout=8` and `BatchMode=yes` added to the owned argv.

Regression tests: `test/procStability.test.ts` (argv flags; ssh spawned
exactly as resolved; `.cmd` wrapped via `cmd.exe /d /s /c`; non-batch spawned
directly).

## v0.10.0 — one IP model, roaming-proof, never wedges

## v0.10.0 — single IP model + recovery that can't false-fail or wedge

**Correct AWS target everywhere: Elastic IP `16.192.228.28`, region `eu-north-1`.**
All defaults now derive from one authoritative module (`src/netModel.ts`):
`AWS_ELASTIC_IP`, `AWS_REGION`, `EXPECTED_PROXY_EGRESS_IP`, `AWS_SSH_HOST`.
The old hardcoded `13.48.149.186` is gone from source, defaults, scripts,
tests, and docs (a source scan test enforces this). If you ever set
`opencodeProxyHealth.expectedExternalIp` / `ec2Host` manually, clear those
overrides — the defaults are now correct.

Bug fixes shipped in this version:

- **Roaming Wi-Fi works end-to-end.** After a network change: run
  **"OpenCode Proxy: Check Network / Repair SG Now"** (command palette or the
  dashboard button) — it discovers the new laptop IP directly (proxy
  bypassed), and if EC2 `:22` is blocked re-authorizes the SG `/32` (never
  `0.0.0.0/0`), then the tunnel is refreshed (owned ssh only) and verified
  end-to-end. **Automatic network polling is now OFF by default**
  (`publicIpPollSec: 0` = manual mode): a stable network is never probed in
  the background and the proxy is never disturbed by a false change
  detection. Set `publicIpPollSec > 0` only if you roam constantly. Even in
  manual mode, if the chain actually goes down the strike-gated health cycle
  still recovers it automatically — polling was only ever an accelerant.
- **One-click supervisor-conflict fix.** The legacy Task Scheduler tasks
  ("OpenCode SSH SOCKS5" / "OpenCode HTTP Proxy Bridge") now get a
  **Disable legacy tasks now** button on the conflict warning, plus the
  command **"OpenCode Proxy: Disable Legacy Task Scheduler Tasks"**. It
  stops (`schtasks /End`) then disables (`/Change /DISABLE`) both tasks —
  reversible, never deletes — so the direct supervisor is the sole owner of
  ssh.exe/hpts.
- **Recovery no longer false-fails when echo services are down.** Step G is
  two-stage: a transport probe (gstatic 204) MUST pass (real failure ⇒
  `RECOVERY_FAILED`), while the IP-echo is evidence only (echo down ⇒
  `READY` with `egressVerified=false`; wrong IP ⇒ still fails).
- **SOCKS verdict uses a tunnel classifier.** A refused handshake/CONNECT ⇒
  tunnel broken; a timeout after CONNECT ⇒ transport proven, egress
  unverified — a working ssh is never killed over a diagnostic outage.
- **Recovery never wedges.** The old hard attempt ceiling is replaced by a
  cadence: 3 rapid attempts (with cooldown), then a steady retry every 5
  minutes forever — a captive-portal session can no longer permanently
  disable self-healing. Cadence resets on success/HEALTHY.
- **Direct IP checks are race-free.** Per-request `process.env` mutation in
  `fetchDirectUrl` is replaced by a refcounted proxy bypass; concurrent
  direct fetches can no longer restore proxy env mid-flight.
- **Notification hygiene.** Recovery failures toast **once per outage episode**;
  the steady 5-minute background retries are log-only (previously every failed
  attempt raised a warning — combined with the old wrong-IP default that made
  every recovery fail, this caused non-stop `SSH_DOWN`/recovery toast spam in
  installed 0.9.x builds). Installing 0.10.0 fixes both the root cause and the
  spam.
- **Fresh package:** `opencode-proxy-health-0.10.0.vsix` (previous `.vsix`
  builds moved to `archive/vsix/`).

## v0.9.1 — health model stops confusing diagnostics with proxy failure

Symptom fixed: `PROXY_FAILED — all IP echo services failed` + `ZEN_UNREACHABLE`
popups every few seconds while OpenCode coded through the proxy uninterrupted,
followed by a false `recovered — down for 24s`.

Root cause: every poll ran 8s+ IP-echo (ipify) and full Zen model-list fetches
_through the proxy_ and treated any one failure as proxy death, notifying on
every transition.

New layered model (`src/health.ts` + `src/healthPolicy.ts`, pure + tested):

- LEVEL 1 local transport: TCP `:1080` + `:8080`, <=1s each (`portProbeTimeoutMs`).
- LEVEL 2 proxy transport: `HEAD https://www.gstatic.com/generate_204`
  (`transportProbeUrl`) via CONNECT+TLS through `:8080`, <=4s
  (`transportProbeTimeoutMs`). Any 2xx/3xx proves bridge→SOCKS→EC2→internet.
  Never an echo service, never Zen. Echo (`api.ipify.org` etc.) now lives ONLY
  in the bounded SG-repair/recovery path.
- LEVEL 3 Zen service: `GET <zenEndpoint>` models, <=5s, every
  `zenProbeIntervalSec` (60s), display-only (`ZEN_OK`/`ZEN_DEGRADED`/
  `ZEN_UNREACHABLE`). Never triggers SSH/SOCKS/hpts recovery.
- Confirmation: strikes 1–2 → `DEGRADED` (status bar only, no notify, no
  recovery); strike 3 (`failureThreshold`) → `PROXY_DOWN` (one `OpenCode proxy
connection lost. Recovering...` notification, recovery allowed). Success
  resets. Recent tracked OpenCode success vetoes transport-only strikes (K).
- Single-flight: explicit `ProbeGate` + `running`/`currentCheck`; 8s overall
  guard below the 10s interval — overlapping probes impossible.
- Notifications only for: confirmed `PROXY_DOWN`, `RECOVERY_FAILED`/gave-up,
  recovery success after a confirmed outage ≥ `minOutageNotifySec` (20s), and
  the user's own tracked-request failure. Never for single probes, Zen blips,
  DNS hiccups, or transients. `down for Xs` prints only for confirmed outages.
- Network change: public-IP poll marks `RECONNECTING` (never `PROXY_FAILED`),
  then the G-sequence (check `:22`, direct IP, SG repair, rebuild, verify).
- Uptime/outage history opens only on confirmed unavailability.
- Untouched: AWS roaming-IP repair, SG verification, exact process ownership,
  SOCKS verification, hpts ownership, single-flight recovery, dedup,
  bootstrap, network-change detection.

# OpenCode Proxy Health (v0.9.0 — direct supervisor + verified state machine)

VS Code status-bar monitor and opt-in recovery for this proxy chain:

```
OpenCode → HTTP proxy 127.0.0.1:8080 → HTTP→SOCKS bridge
  → SOCKS5 127.0.0.1:1080 → SSH tunnel → AWS EC2 16.192.228.28
  → Zen API (opencode.ai) → muse-spark-1.3-contributor-free
```

## v0.9.0 — direct supervisor (recommended): the extension owns the tunnel

Old flaw: `ssh.exe exists => tunnel healthy` + `schtasks /run => fixed`. When
your public IP roams, AWS blocks SSH (:22), `ssh.exe` lingers, `:1080` is dead,
and Task Scheduler (MultipleInstances=IgnoreNew) silently discards restarts.
The old code never probed `16.192.228.28:22`, never did a SOCKS end-to-end
check, never repaired the Security Group, and could leave 2x `ssh.exe`
fighting over `:1080`.

New default (`supervisorMode: "direct"`): the extension is the SOLE owner.

- Exactly ONE `ssh.exe` + ONE `hpts`, matched by exact command line
  (`-D 127.0.0.1:1080 -N ubuntu@16.192.228.28`, `hpts -p 8080 -s
127.0.0.1:1080`). Random `ssh.exe` (git, other tunnels) is never assumed
  ours and never killed. Stale/redundant OWNED processes are deduped; a
  foreign listener on `:1080`/`:8080` is reported, not killed.
- Layered state machine `src/recoveryMachine.ts` (A-H, bounded retries +
  exponential backoff, single-flight/idempotent, no busy-loop, no OpenCode
  needed):
  `SSH_PROCESS_DOWN -> AWS_SSH_UNREACHABLE -> SG_REPAIRING -> SOCKS_DOWN ->
SOCKS_STARTING -> SOCKS_UP -> HTTP_PROXY_DOWN -> HTTP_PROXY_STARTING ->
HTTP_PROXY_UP -> READY`, else `RECOVERY_FAILED`.
  A: TCP 127.0.0.1:1080. B: TCP 16.192.228.28:22 (direct). C: kill stale owned
  ssh, spawn exactly ONE ssh, wait+verify 1080 (never assume process=healthy).
  D: SOCKS5 CONNECT through 1080, egress must equal 16.192.228.28. E: only
  then spawn hpts. F: verify :8080. G: HTTP egress through :8080. H: READY.
- Roaming-IP repair: when :22 is unreachable, the current public IP is
  discovered DIRECTLY (https://api.ipify.org → checkip.amazonaws.com →
  ifconfig.me/ip, proxy bypassed — never via :8080), the SG is described
  first, current `/32` authorized and re-described to verify, then stale
  managed `/32`s removed and :22 retried. Uses your existing AWS CLI profile
  (`awsProfile`/`awsRegion`); no credentials in source/settings/logs. Never
  opens `0.0.0.0/0`, never touches foreign rules, never adds duplicates.
- Startup: health-check first; if unhealthy and `bootstrapRecoverOnStartup`
  (default on), run the machine once — works before OpenCode is usable.
- Network change: lightweight direct public-IP poll every `publicIpPollSec`
  (default off; when enabled, min 30s); on change, re-check and
  recover. Handles Wi-Fi change, wake-from-sleep, DNS/AWS blips, timeouts,
  crashes, transient port absence.
- Logs: `[PROXY CHECK] [AWS SSH CHECK] [PUBLIC IP] [SECURITY GROUP UPDATE]
[SSH START] [SSH STOP] [SOCKS CHECK] [SOCKS END-TO-END CHECK]
[HTTP BRIDGE START] [HTTP PROXY CHECK] [RECOVERY SUCCESS/FAILURE]` with
  timestamps; key paths/credentials never logged.
- Status: `SSH DOWN` (process missing) vs `AWS SSH UNREACHABLE` vs `FIXING
SG...` vs `SOCKS STARTING...` vs `HTTP STARTING...` vs `Proxy ready` vs
  `RECOVERY FAILED`. No false "ssh.exe running therefore healthy".

### Disable Task Scheduler to avoid two supervisors fighting

When `supervisorMode` is `direct` (default), DISABLE these legacy tasks:

```powershell
schtasks /change /TN "OpenCode SSH SOCKS5" /DISABLE
schtasks /change /TN "OpenCode HTTP Proxy Bridge" /DISABLE
```

The extension warns once if they still exist+Running. Set
`supervisorMode: "task"` only if you explicitly want the legacy
schtasks-only path (`autoRecover` + one-click runbook, `src/recover.ts`).

### AWS IAM (least privilege) for SG self-repair

Attach to the CLI identity (no keys in the extension):

```json
{
  "Effect": "Allow",
  "Action": [
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupIngress"
  ],
  "Resource": "*"
}
```

Scope `Resource` to the proxy SG when possible. Configure once via
`aws configure` / `aws configure --profile <name>`; set
`securityGroupId` (e.g. `sg-...`), `awsProfile` (empty=default),
`awsRegion` (empty=CLI default; `16.192.228.28` is `eu-north-1`).
Empty `securityGroupId` disables SG repair (honest `RECOVERY_FAILED`
telling you the direct IP).

### Manual test checklist (no OpenCode needed)

1. Healthy: `F1 → Recover Proxy (direct)` on a healthy chain → SKIP-style
   `SOCKS_UP`/`HTTP_PROXY_UP`, `READY`, no new processes.
2. `:1080` absent: `taskkill /F /IM ssh.exe` → status `SSH DOWN` → auto/direct
   recovery spawns exactly ONE `ssh.exe`, `:1080` verified, SOCKS e2e match,
   `READY`. Run twice → still ONE process (idempotent).
3. SSH unreachable (roam): change network / revoke your `/32` manually →
   `AWS SSH UNREACHABLE` → direct public IP logged (proxy bypassed) → `SG
REPAIRING` → stale `/32` revoked + current `/32` added + verified →
   `:22` reachable → tunnel rebuilt → `READY`. Confirm in AWS console: no
   duplicates, no `0.0.0.0/0`.
4. `hpts` crash: `taskkill /F /IM node.exe` (bridge only) → `HTTP BRIDGE
DOWN` → exactly ONE `hpts` respawned after SOCKS verified → `READY`.
5. Startup: reload VS Code while tunnel down → bootstrap recovery runs once
   before any OpenCode use.
6. Network switch: university → hotspot → `[PUBLIC IP] x → y` in Output +
   auto re-check/recovery; no tight polling (≥30s interval).

Legacy task mode is unchanged: `autoRecover` (default off) starts existing
scheduled tasks on confirmed local port failures; `autoRecoverResetStuckTask`
(false = starts only). It never changes OpenCode, model, auth, key, or proxy
configuration.

## One-click recovery (the runbook, as a single gated sequence)

The manual runbook — start tunnel, check port, start bridge, set proxy, test
egress, launch opencode — is now one command. **OpenCode Proxy: One-Click
Recovery**, or the `🚀 One-click recovery` row at the top of the dashboard
(hover it for a button). It runs:

| #   | Step                    | What it actually does                                                        |
| --- | ----------------------- | ---------------------------------------------------------------------------- |
| 1   | START SSH TUNNEL        | `schtasks /run "OpenCode SSH SOCKS5"` — **only** if `:1080` is closed        |
| 2   | CHECK SSH PORT          | waits for TCP `127.0.0.1:1080`                                               |
| 3   | START HTTP PROXY BRIDGE | `schtasks /run "OpenCode HTTP Proxy Bridge"` — **only** if `:8080` is closed |
| 4   | CHECK HTTP BRIDGE PORT  | waits for TCP `127.0.0.1:8080`                                               |
| 5   | SET PROXY               | builds the `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` map for step 7              |
| 6   | TEST PROXY              | egress IP through the proxy must equal `expectedExternalIp`                  |
| 7   | START OPENCODE          | asks first, then opens a new terminal carrying the env                       |

Two properties worth knowing:

- **It is idempotent.** A step whose port already answers reports `SKIP`, never
  "fixed" — so a healthy chain is left completely alone, and you never get a
  second `ssh` colliding on `:1080`.
- **It is gated.** A failed step marks every later step `BLOCK`. A half-built
  chain is worse than an honest failure, and step 6 will not report an egress IP
  it did not actually observe.

Step 5 only ever affects processes the extension itself launches. It cannot set
env vars in a terminal you already have open — that is a shell boundary no
extension can cross, so the honest option is a new terminal with the env baked
in. If you decline step 7, the exact `$env:` lines to paste are printed to the
output log.

## What improved in v0.8.0 — the stuck-task wedge, and real self-healing

Enabling `autoRecover` was **not enough to self-heal**, because of a silent
failure mode in Windows Task Scheduler. Both proxy tasks are configured
`MultipleInstances = IgnoreNew`, which means:

> If a task's process dies while its parent stays alive, Task Scheduler still
> reports the task as `Running` — and every subsequent `schtasks /run` is
> **silently discarded**, while still exiting `0` and printing
> `SUCCESS: Attempted to run the scheduled task`.

Auto-recovery would have reported success, spent its whole attempt budget, and
recovered nothing. Verified on this machine:

```
task state : {"exists":true,"running":true,"status":"Running"}
run result : { "ok": false, "outcome": "ignored-running",
  "detail": "task ... is already marked Running, so the start request was
             ignored (MultipleInstances=IgnoreNew) — the task is stuck, not healthy" }
```

v0.8.0 fixes it:

- `runScheduledTask` now detects the discarded request and returns
  `ok: false, outcome: 'ignored-running'`. A no-op can no longer be counted as
  a success, so budgets mean something.
- New `planStuckTask` decides between _start_ and _stop-then-start_. The one
  rule that matters: **a port that answers always wins.** If the port is up the
  task is healthy, whatever Scheduler's state says, and it is never stopped.
- After a start, the extension now **waits for the port** rather than assuming
  success — so a task that starts but never binds is logged as the failure it is.
- `autoRecoverResetStuckTask` (on by default when auto-recovery is enabled)
  permits stopping a task **whose port is confirmed closed** so it can be
  restarted. The port is checked again after querying Task Scheduler. Turn the
  setting off for starts only. The manual one-click runbook can reset a stuck
  task because that command is explicitly invoked by the user.

Verified: with the setting on and the chain healthy, the bridge process was
left untouched (same PID before and after a full runbook).

### Why your bridge kept dying (fixed outside the extension)

The extension can recover local tasks while VS Code Insiders is open. The task
launchers in `scripts/opencode-ssh.cmd` and `scripts/http-proxy-bridge.cmd` also
retry on their own, so a connection or bridge process failure can recover even
when the editor is closed. On this machine the scheduled tasks run copies at
`%USERPROFILE%\opencode-ssh.cmd` and `%USERPROFILE%\http-proxy-bridge.cmd`.

Earlier bridge failures had three causes:

1. **`npx http-proxy-to-socks`** — the package was not installed anywhere, only
   present in an `npx` cache folder. When that entry is missing, `npx` blocks on
   `Ok to proceed? (y)`; a scheduled task has no stdin, so it hangs.
   **Fixed**: installed globally; the launcher now calls the `hpts` binary
   directly.
2. **`ExecutionTimeLimit: PT72H`** — Task Scheduler force-killed the bridge every
   72 hours with nothing to restart it.
3. **`RestartCount: 0`** and the **battery flags on** — a crash never restarted,
   and on battery the tasks were refused at start and stopped on switch.

2 and 3 need an elevated terminal, because both tasks run `RunLevel: Highest`:

```powershell
# right-click C:\Users\hp\harden-opencode-proxy-tasks.ps1 > Run with PowerShell (admin)
```

That sets unlimited execution time, `RestartCount=3` / `RestartInterval=1min`,
and the battery flags off, on both tasks. The launchers now retry indefinitely
after transient failures, logging to `%USERPROFILE%\opencode-ssh.log` and
`%USERPROFILE%\http-proxy-bridge.log`. Missing executables or the SSH key
remain fatal configuration errors. The bridge waits on a `netstat` probe
instead of `Test-NetConnection` (**37s → 0.6s**; the latter does DNS and ICMP
work this does not need).

## What improved in v0.7.0 — at-a-glance failures, trends, safe testing

- **Per-failure glyphs**: SSH-down (pulled plug), SOCKS refused (plug),
  bridge broken (swap), traffic failed (cloud), Zen unreachable (globe) —
  the dead leg is now visible without opening anything.
- **Latency trend row** in the dashboard: text sparkline of the last 30
  checks with avg/max/last, so gradual degradation is visible.
- **One-click remediation**: failing chain rows carry a refresh button that
  starts the owning scheduled task, re-checks, and reopens the dashboard.
- **`autoRecoverDryRun`**: with auto-recovery on, logs what would start
  without starting anything — safe end-to-end testing of self-healing.
- **`compactTooltip`**: short hover (state + last check) instead of the
  full breakdown.

## What improved in v0.6.0 — shape-first visuals, zero color-dependence

- Status bar is a single glyph chosen for **shape meaning**: check = good,
  play triangle = request running, clock = slow/waiting, pulled-plug =
  transport down, cross = request/model failed, question mark = unknown,
  spinner = starting/reconnecting. No severity background tints, no
  red/green reliance — fully legible without color perception.
- **All color emoji removed everywhere** (status texts, tooltip, dashboard,
  output report, logs): green/red bubbles replaced by plain words (`UP`,
  `DOWN`, `CONNECTED`, `UNAVAILABLE`) and greppable ASCII tags (`[OK]`,
  `[FAIL]`, `[WARN]`, `[FIX]`, `[TRACK]`).
- Tooltip echoes the bar glyph (theme icons on) and now carries the full
  text; dashboard rows grouped with separators instead of colored dots.
- Port probes individually timed (previously reported as one joint batch).
- A unit test pins the icon mapping and another forbids color emoji in any
  presentation string, so the visuals can't regress silently.

## What improved in v0.5.0 — icon-only status bar

- The status bar now shows **one tool icon, no text**: `$(tools)` healthy,
  spinning `$(gear~spin)` while a tracked request runs, spinning
  `$(sync~spin)` while starting/reconnecting, `$(wrench)` on proxy failures,
  with error/warning backgrounds by severity. Full text lives in the tooltip,
  accessibility label, notifications, and dashboard.
- Set `opencodeProxyHealth.statusStyle` to `"text"` to restore the old text
  item. `npm run demo` now prints the bar glyph per state.

## What improved in v0.4.0 — opt-in self-healing (off by default)

- **Auto-recovery** (`opencodeProxyHealth.autoRecover`, default `false`):
  after two consecutive local failure checks, it recovers the SSH task on
  `SSH_DOWN` or `SOCKS_DOWN`, and the bridge task on `HTTP_BRIDGE_DOWN`.
  Each attempt verifies the relevant port. Budgets: 3 attempts per task per
  outage, 60 s cooldown; gives up loudly and resets on recovery.
- **What it will NOT do**: synthesise ssh/node command lines (no keys
  involved), touch config/auth, or act on remote failures (`PROXY_FAILED`,
  `ZEN_UNREACHABLE`, `MODEL_UNAVAILABLE`). A live port is left alone.
- **Manual commands** (work even with auto-recovery off): _Restart SSH Tunnel
  Task_, _Restart HTTP Bridge Task_. They leave an answering port alone and
  verify that a recovered port opens.
- Dashboard + tooltip show the auto-recovery state; recovery messages note
  how many attempts were made.

## What improved in v0.3.0

- **Fallback IP echo service** (`checkip.amazonaws.com` after `api.ipify.org`,
  attributed in diagnostics) — one echo service's outage no longer misreports
  as our tunnel being down.
- **IP plausibility gate** — a 200 response with an HTML/error body (captive
  portal, broken bridge) counts as `PROXY_FAILED`, never as "traffic flows".
- **Monitor-wedge fix** — the check body runs under try/finally, so an
  unexpected throw can no longer stick `running` and silently stop all ticks.
- **Fail-closed wrapper** — default exit 1, null-`$LASTEXITCODE` guard, clear
  error when `opencode` isn't on PATH; also accepts `--model=<id>` form.
- **Dashboard can reveal the persisted log file** in the OS explorer.
- **Cheaper long requests** — wrapper-PID liveness cached 30 s (no tasklist
  spawn per tick); history persistence is fire-and-forget.
- **Clearer request wording** — "disabled in settings" vs "not in use", plus
  oldest-in-flight age in the dashboard.
- **Packaging**: `extensionKind: ["ui"]` (checks always run where the proxy
  lives, even with remote folders open), untrusted-workspace support, LICENSE.

## What improved in v0.2.0

- **Honest request status** — opt-in wrapper `scripts/Invoke-TrackedOpencode.ps1`
  writes lockfiles; the extension then truthfully shows `Muse: Running (n)` /
  `Muse: ERROR`. Without it, no request state is ever fabricated.
- **QuickPick dashboard** on click (per-row details + Refresh / Output / Copy /
  Settings / Clear-failure actions) instead of just dumping the output channel.
- **On-demand deep diagnosis** on failure: exact (redacted) `ssh.exe`/bridge
  command lines, scheduled-task states, port listeners.
- **Stage timings + SLOW warning** — see _where_ time goes (probes/traffic/zen)
  so "waiting on network" is distinguishable from "dead".
- **Persistent history**: 24 h uptime % + outage list (survives reloads) and an
  optional rolling log file for overnight post-mortems.
- **Overall watchdog**: a hung check reports `UNKNOWN` instead of stalling.
- **Fixed**: settings listener leaked one subscription per change (now once).
- Presentation matrix extracted to pure `src/status.ts` — unit-tested and
  printable via `npm run demo`.

## Correct VS Code extension structure (per official docs)

```
opencode-proxy-health/
├── package.json          # manifest: 7 commands, 21 settings, ui-kind, onStartupFinished
├── tsconfig.json
├── src/
│   ├── extension.ts      # status bar, dashboard, scheduler, log (vscode APIs)
│   ├── health.ts         # chain probes + state machine (pure Node)
│   ├── status.ts         # presentation + request overlay (pure, tested)
│   ├── requests.ts       # lockfile tracker (pure, tested)
│   ├── history.ts        # uptime/outage bookkeeping (pure, tested)
│   └── diagnose.ts       # deep diagnosis (pure, tested)
├── test/                 # node:test suites, mocks only — no network needed
├── scripts/
│   ├── Invoke-TrackedOpencode.ps1   # opt-in request-tracking wrapper
│   └── demo-status.cjs              # prints every status state (npm run demo)
├── .vscode/launch.json   # F5 → Extension Development Host
├── LICENSE               # MIT
└── README.md
```

APIs used (https://code.visualstudio.com/api): `createStatusBarItem(Left)`,
`registerCommand`, `getConfiguration` + `contributes.configuration`,
`createOutputChannel`, `showQuickPick` with separators, `env.clipboard`,
`globalState` / `globalStorageUri` + `workspace.fs`, `onStartupFinished`,
error/warning-free styling (no severity background tints),
`accessibilityInformation` (never color-only).

## Install / run

```powershell
cd C:\Users\hp\Desktop\Garbage\Proxy\opencode-proxy-health
npm install
npm test          # compile + 135 unit tests
npm run demo      # print all 13 status states + sample report
node scripts/soak-check.cjs 120 60  # read-only health samples for about 2 hours
```

**F5** in VS Code (folder open) → Extension Development Host with the live
indicator. Permanent install: `npx @vscode/vsce package` → Install from VSIX,
or copy the folder to `%USERPROFILE%\.vscode\extensions\opencode-proxy-health-0.8.3\`.

## Enabling live request status (opt-in, honest)

```powershell
.\scripts\Invoke-TrackedOpencode.ps1 run --model "opencode/muse-spark-1.3-contributor-free" "your prompt"
```

The wrapper runs `opencode` unchanged (exit code passes through; fail-closed
to 1 if opencode can't even start) and records `*.running.json` / `*.done.json`
in `%TEMP%\opencode-proxy-health\requests\` (model name only — prompts never
stored; `--model=<id>` form also recognised). The extension then shows:

| Status bar             | Display state     | Meaning                                                                                                       |
| ---------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------- |
| play glyph `$(play)`   | `REQUEST_RUNNING` | n wrapper-tracked requests in flight (first-hand evidence)                                                    |
| cross glyph `$(error)` | `REQUEST_FAILED`  | last tracked request failed (exit ≠ 0 or wrapper died); clears on next success or via _Clear Request Failure_ |

Without the wrapper the overlay is inert — you'll see `Ready`, never a
fabricated `Running`. Chain failures always take precedence over request info.
Caveat: PID liveness is the signal; OS PID reuse in the same instant is a
residual (documented) edge — running files older than 6 h are flagged stale.

## All status states (bar shows the glyph; hover/click for the text)

| Bar glyph                         | State               | Meaning                                                                                                         |
| --------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `$(sync~spin)` spinning arrows    | `STARTING`          | first check not finished yet                                                                                    |
| `$(check)` tick                   | `HEALTHY`           | full chain verified end-to-end                                                                                  |
| `$(watch)` clock                  | `HEALTHY`-slow      | healthy but check > `slowThresholdMs` (default 6 s) — "waiting on network" signal, per-stage timings in tooltip |
| `$(play)` triangle                | `REQUEST_RUNNING`   | n wrapper-tracked requests in flight (first-hand evidence)                                                      |
| `$(error)` cross                  | `REQUEST_FAILED`    | last tracked request failed; clears on next success or via _Clear Request Failure_                              |
| `$(debug-disconnect)` pulled plug | `SSH_DOWN`          | :1080 refused **and** no `ssh.exe` process                                                                      |
| `$(plug)` connector               | `SOCKS_DOWN`        | :1080 refused but `ssh.exe` still runs (re-establishing?)                                                       |
| `$(arrow-swap)` swap              | `HTTP_BRIDGE_DOWN`  | :1080 OK, :8080 refused                                                                                         |
| `$(cloud)` cloud                  | `PROXY_FAILED`      | ports open but no traffic flows, or egress IP ≠ expected EC2 IP                                                 |
| `$(globe)` globe                  | `ZEN_UNREACHABLE`   | proxy works, Zen not reachable (or non-200; 4xx = path OK, refused)                                             |
| `$(error)` cross                  | `MODEL_UNAVAILABLE` | Zen OK but model id missing from model list                                                                     |
| `$(question)` question mark       | `UNKNOWN`           | guard trip / unexpected shape — shown instead of guessing                                                       |

Hover = tooltip with timings, request, 24 h uptime. Click = dashboard
(status rows, latency trend, uptime, deep diagnosis — failing chain rows
carry a one-click restart button for the owning task).

## How health checks work

1. **Parallel probes**: TCP :1080, TCP :8080, `tasklist` for `ssh.exe` /
   `opencode.exe` (informational only) — each with `checkTimeoutMs` (8 s).
2. **IP echo via the bridge** (`api.ipify.org`, fallback
   `checkip.amazonaws.com`, attributed) — body must be a plausible IP equal to
   `expectedExternalIp`; HTML/error bodies or anything else ⇒ `PROXY_FAILED`.
3. **`CONNECT opencode.ai:443` via the bridge → TLS → `GET /zen/v1/models`** —
   body must contain `"id":"<model>"`.
4. Overall watchdog (`max(30 s, timeout×4)`) ⇒ `UNKNOWN`, never a hang.

Interval 10 s (min 3 s); overlapping ticks skipped. Output + optional
`proxy-health.log` record **transitions, recoveries (with duration), slow
entries, request events, deep-diagnosis, manual refreshes** — steady-state
stays silent. On failure transitions the extension additionally runs the CIM /
`schtasks` / `netstat` deep probes (key paths redacted) and logs them.

## Troubleshoot failures

- **SSH DOWN** → task `OpenCode SSH SOCKS5`, key `.pem`, EC2 reachability.
- **SOCKS DOWN** → tunnel re-establishing; watch for `[OK] RECOVERED`.
- **HTTP BRIDGE DOWN** → task `OpenCode HTTP Proxy Bridge` /
  `http-proxy-bridge.cmd`.
- **CONN FAILED** → `curl.exe -x http://127.0.0.1:8080 https://api.ipify.org`
  should print `16.192.228.28`.
- **ZEN UNREACHABLE** → same via `/zen/v1/models`; 4xx = path OK, refused.
- **Muse UNAVAILABLE** → model renamed? Update `opencodeProxyHealth.model`.
- **SLOW** → stage timings in tooltip say which leg (probes/traffic/zen).
- **Muse ERROR** → dashboard shows the failing tracked request + reason.

## Settings (`opencodeProxyHealth.*`)

` socksPort` (1080) · `httpPort` (8080) · `healthCheckInterval` (10 s) ·
`zenEndpoint` · `model` · `expectedExternalIp` ('' skips) · `checkTimeoutMs`
(8000) · `notifications` (`all`|`errors`|`none`) · `slowThresholdMs` (6000,
0 disables) · `logToFile` (true) · `logFileMaxLines` (2000) · `trackRequests`
(true) · `requestDir` ('' = `%TEMP%\opencode-proxy-health\requests`) ·
`autoRecover` (false — the self-healing master switch) ·
`autoRecoverMaxAttempts` (3, 1–10) · `autoRecoverCooldownSec` (60, ≥15) ·
`autoRecoverResetStuckTask` (true — allow stopping a task whose port is
confirmed **closed** so it can be restarted; required to escape the
`IgnoreNew` wedge, see v0.8.0) ·
`runbookPortWaitSec` (30, 5–300) · `runbookLaunchOpencode` (false — skip the
"launch opencode?" prompt) · `opencodeCommand` (`opencode`) ·
`sshTaskName` · `bridgeTaskName` · `statusStyle` (`icon` = tool glyph only,
`text` = full text item) · `autoRecoverDryRun` (false) · `compactTooltip`
(false). Invalid
values fall back with a logged warning; changes re-arm live.

## Test each state (safe — nothing is restarted)

- Unit: `npm test` (90 tests: ports up/down, Zen ok/down/model-missing,
  SSH present/absent, overlay matrix, icon-variant mapping, lockfile protocol
  incl. BOM/stale/age, uptime math + sparklines, redaction/parsers, runbook gating/idempotence, IgnoreNew-wedge detection,
  guard timeout, IP plausibility + fallback,
  recovery budgets/cooldowns/task-runner).
- States: `npm run demo`.
- Live failure: stop task `OpenCode SSH SOCKS5` → pulled-plug glyph +
  deep diagnosis in output; restart → spinner → tick glyph +
  `[OK] RECOVERED (down for …)`.
- Live request: `Invoke-TrackedOpencode.ps1 --version` writes a success
  record; use a failing command to see `Muse: ERROR`, then _Clear Request
  Failure_.
- Live slow: set `slowThresholdMs: 1` → next healthy tick shows SLOW.
- Live self-healing: set `autoRecover: true`, then observe a local port failure
  for two checks → expect a logged task start/reset attempt, a verified port,
  and then `[OK] RECOVERED` after the full health check passes. The automated
  tests exercise stuck tasks and retry behavior without stopping a live proxy.

## Security / performance

No keys, tokens, passwords, prompts, or full command lines are captured —
key paths redacted, only model names stored. Zero runtime dependencies; one
status-bar item; every socket/process call timed; heavy probes (CIM,
schtasks, netstat, PID checks) run only on failure/manual or when lockfiles
exist; extension host never blocked.
