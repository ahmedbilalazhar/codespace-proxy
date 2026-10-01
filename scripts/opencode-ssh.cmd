@echo off
rem Keep the SOCKS tunnel alive across network drops. Task Scheduler only
rem retries a failed task three times; this loop continues until the task is
rem explicitly stopped.
rem
rem IMPORTANT (supervisor conflict): only use this task with
rem opencodeProxyHealth.supervisorMode=task. In the default direct mode the
rem extension spawns and owns exactly one ssh.exe itself; leave this task
rem DISABLED so two supervisors never fight over :1080.
rem
rem The EC2 endpoint comes from the environment (default matches
rem src/netModel.ts — the static Elastic IP). It is NEVER the laptop's public
rem IP, which changes on every network switch.
setlocal
set "SSH=C:\Windows\System32\OpenSSH\ssh.exe"
set "KEY=%USERPROFILE%\.ssh\opencode-proxy-key.pem"
set "LOG=%USERPROFILE%\opencode-ssh.log"
if "%EC2_HOST%"=="" set "EC2_HOST=16.192.228.28"
if "%SSH_USER%"=="" set "SSH_USER=ubuntu"
if "%SOCKS_PORT%"=="" set "SOCKS_PORT=1080"

if not exist "%SSH%" exit /b 1
if not exist "%KEY%" exit /b 1

:retry
echo [%DATE% %TIME%] starting SSH tunnel >> "%LOG%"
"%SSH%" -i "%KEY%" -D 127.0.0.1:%SOCKS_PORT% -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 %SSH_USER%@%EC2_HOST% >> "%LOG%" 2>&1
set "rc=%errorlevel%"
echo [%DATE% %TIME%] SSH exited with code %rc%; retrying in 15s >> "%LOG%"
timeout /t 15 /nobreak >nul
goto retry
