@echo off
rem OpenRMM agent setup. Double-click to install (Windows asks for administrator
rem approval), or run "install.cmd /quiet" as administrator or SYSTEM from
rem Intune, Group Policy or a remote shell. Running it again is safe.
rem "/proxy http://host:port" (or http://user:password@host:port, or direct)
rem sets the proxy the agent uses to reach the server, also on a machine where
rem the agent is already installed; "/proxy none" removes it.
setlocal
set "QUIET="
set "PROXY="
:options
if "%~1"=="" goto run
if /i "%~1"=="/quiet" (set "QUIET=-Quiet" & shift & goto options)
if /i "%~1"=="/proxy" (
  if "%~2"=="" (
    echo OpenRMM setup failed: /proxy needs a value.
    exit /b 1
  )
  set "PROXY=%~2"
  shift
  shift
  goto options
)
echo OpenRMM setup failed: unknown option %1; use /quiet and /proxy VALUE.
exit /b 1
:run
fltmc >nul 2>&1
if errorlevel 1 (
  if defined QUIET (
    echo OpenRMM setup failed: run install.cmd /quiet as administrator or SYSTEM.
    exit /b 5
  )
  set "OPENRMM_SETUP=%~f0"
  set "OPENRMM_PROXY=%PROXY%"
  powershell.exe -NoProfile -Command "$p=@{FilePath=$env:OPENRMM_SETUP;Verb='RunAs'}; if ($env:OPENRMM_PROXY) { $p.ArgumentList='/proxy '+$env:OPENRMM_PROXY }; Start-Process @p"
  if errorlevel 1 (
    echo OpenRMM setup needs administrator approval.
    pause
    exit /b 5
  )
  exit /b 0
)
rem A PowerShell 7 parent passes its module path, which hides Windows
rem PowerShell's own cmdlets; let powershell.exe use its default.
set "PSModulePath="
if defined PROXY (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Proxy "%PROXY%"
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
)
set "RESULT=%ERRORLEVEL%"
if not defined QUIET pause
exit /b %RESULT%
