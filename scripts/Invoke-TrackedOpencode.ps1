<#
.SYNOPSIS
  Run `opencode` with honest request tracking for the OpenCode Proxy Health VS Code extension.

.DESCRIPTION
  OpenCode 1.18 exposes no API for "a request is in flight", so the extension
  refuses to guess. This wrapper writes first-hand evidence instead:
    <tmp>/opencode-proxy-health/requests/<pid>-<timestamp>.running.json   while opencode runs
    <tmp>/opencode-proxy-health/requests/<pid>-<timestamp>.done.json      after it exits (with exit code)

  The extension watches that directory and can then truthfully show
  "Muse: Running (n)" and "Muse: ERROR".

  MONITORING ONLY: this script never touches your proxy, SSH tunnel, tasks,
  keys, or model configuration. It just runs `opencode @args` and records
  the outcome. The exit code of opencode is passed through unchanged.

  Only the --model value is recorded. Prompts and full argument lists are
  NEVER written to disk.

.EXAMPLE
  .\Invoke-TrackedOpencode.ps1 run --model "opencode/muse-spark-1.3-contributor-free" "do the thing"
#>
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ForwardArgs
)

$ErrorActionPreference = 'Stop'

if (-not $ForwardArgs -or $ForwardArgs.Count -eq 0) {
  Write-Error 'Usage: .\Invoke-TrackedOpencode.ps1 run --model "<model>" "<prompt>"'
  exit 2
}

$dir = Join-Path ([System.IO.Path]::GetTempPath()) 'opencode-proxy-health\requests'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Prune lockfiles older than 24h so TEMP never fills up.
Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-24) } |
  Remove-Item -Force -ErrorAction SilentlyContinue

$id = '{0}-{1:yyyyMMddHHmmssfff}' -f $PID, (Get-Date)

$model = $null
for ($i = 0; $i -lt $ForwardArgs.Count; $i++) {
  if ($ForwardArgs[$i] -eq '--model' -and ($i + 1) -lt $ForwardArgs.Count) {
    $model = $ForwardArgs[$i + 1]
    break
  }
  if ($ForwardArgs[$i] -like '--model=*') {
    $model = $ForwardArgs[$i].Substring(8)
    break
  }
}

$startedAtMs = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$runningFile = Join-Path $dir "$id.running.json"
$doneFile = Join-Path $dir "$id.done.json"

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText(
  $runningFile,
  (@{ v = 1; id = $id; pid = $PID; startedAtMs = $startedAtMs; model = $model } | ConvertTo-Json -Compress),
  $utf8NoBom
)

# Fail-closed default: any throw before opencode reports (e.g. opencode not
# on PATH) stays a recorded failure instead of silently becoming exit 0.
$code = 1
try {
  & opencode @ForwardArgs
  if ($null -eq $LASTEXITCODE) { $code = 1 } else { $code = $LASTEXITCODE }
}
catch {
  Write-Error "Invoke-TrackedOpencode: failed to run 'opencode': $($_.Exception.Message)"
  $code = 1
}
finally {
  $endedAtMs = [System.DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  [System.IO.File]::WriteAllText(
    $doneFile,
    (@{ v = 1; id = $id; pid = $PID; startedAtMs = $startedAtMs; endedAtMs = $endedAtMs; exitCode = $code; model = $model } | ConvertTo-Json -Compress),
    $utf8NoBom
  )
  Remove-Item -Path $runningFile -Force -ErrorAction SilentlyContinue
}

exit $code
