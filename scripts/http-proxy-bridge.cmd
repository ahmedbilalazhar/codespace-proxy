@echo off
rem Keep the HTTP bridge alive across SOCKS and bridge process failures.
setlocal enabledelayedexpansion

set "LOG=%USERPROFILE%\http-proxy-bridge.log"
set "HPT=%USERPROFILE%\npm-global\hpts.cmd"
set "SOCKS=127.0.0.1:1080"
set "SOCKS_PORT=1080"
set "PORT=8080"

echo [%DATE% %TIME%] bridge launcher starting >> "%LOG%"
if not exist "%HPT%" (
  echo [%DATE% %TIME%] FATAL: %HPT% not found >> "%LOG%"
  exit /b 1
)

set /a tries=0
:wait
netstat -ano -p TCP | findstr "LISTENING" | findstr ":%SOCKS_PORT% " >nul 2>&1
if not errorlevel 1 goto ready
set /a tries+=1
if !tries! geq 300 (
  echo [%DATE% %TIME%] SOCKS5 %SOCKS% still unavailable after 300 tries; continuing to wait >> "%LOG%"
  set /a tries=0
)
timeout /t 2 /nobreak >nul
goto wait

:ready
echo [%DATE% %TIME%] SOCKS5 %SOCKS% ready - starting hpts on :%PORT% >> "%LOG%"
"%HPT%" -p %PORT% -s %SOCKS% >> "%LOG%" 2>&1
set "rc=%errorlevel%"
echo [%DATE% %TIME%] hpts exited with code %rc%; retrying in 15s >> "%LOG%"
timeout /t 15 /nobreak >nul
set /a tries=0
goto wait
