@echo off
rem OpenRMM agent setup. Double-click to install (Windows asks for administrator
rem approval), or run "install.cmd /quiet" as administrator or SYSTEM from
rem Intune, Group Policy or a remote shell. Running it again is safe.
setlocal
set "QUIET="
if /i "%~1"=="/quiet" set "QUIET=-Quiet"
fltmc >nul 2>&1
if errorlevel 1 (
  if defined QUIET (
    echo OpenRMM setup failed: run install.cmd /quiet as administrator or SYSTEM.
    exit /b 5
  )
  set "OPENRMM_SETUP=%~f0"
  powershell.exe -NoProfile -Command "Start-Process -FilePath $env:OPENRMM_SETUP -Verb RunAs"
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "RESULT=%ERRORLEVEL%"
if not defined QUIET pause
exit /b %RESULT%
