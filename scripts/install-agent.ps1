#Requires -Version 7.0
[CmdletBinding()]
param(
    # The agent MSI and its signed release; defaults to the release bundled into this build.
    [string]$Msi = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist/windows-amd64/openrmm-agent.msi'),
    [string]$Release = (Join-Path (Split-Path -Parent $PSScriptRoot) 'internal/agentbundle/files/release.json')
)

# Installs (or reinstalls) the agent MSI on this machine. An
# installation made by scripts/service.ps1 is converted in place: its service
# registration and program folder are replaced; device identity, state and logs
# under ProgramData are kept. The MSI and its signed release are stored as the
# rollback package the agent's self-update needs. New machines are installed
# and enrolled with an installer downloaded from Add device.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an administrator PowerShell.' }
foreach ($path in @($Msi, $Release)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path; build a release with scripts/release.ps1 first." } }
$signed = Get-Content -LiteralPath $Release -Raw | ConvertFrom-Json
$hash = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLowerInvariant()
if ($signed.manifest.format -ne 2 -or $signed.manifest.package -ne 'msi' -or $signed.manifest.sha256 -ne $hash) { throw 'The release does not describe this MSI.' }

$programRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenRMM Agent'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'OpenRMM Agent'
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
$products = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'OpenRMM Agent' })
$installed = $products.Count -gt 0
# Releases always differ in version; installing the same version twice would
# leave two registrations, so only the rollback package is refreshed then.
if (@($products | Where-Object { $_.PSObject.Properties['DisplayVersion'] -and $_.DisplayVersion -eq "1.0.$($signed.manifest.sequence)" }).Count -gt 0) {
    Write-Output 'This release is already installed; refreshing the rollback package only.'
    $packages = Join-Path $dataRoot 'packages'
    New-Item -ItemType Directory -Path $packages -Force | Out-Null
    Copy-Item -LiteralPath $Msi -Destination (Join-Path $packages 'current.msi') -Force
    Copy-Item -LiteralPath $Release -Destination (Join-Path $packages 'current.json') -Force
    return
}
if (-not $installed -and (Get-Service -Name OpenRMMAgent -ErrorAction SilentlyContinue)) {
    Write-Output 'Converting the script-based installation (identity and state are kept)...'
    foreach ($name in @('OpenRMMAgent', 'OpenRMMAgentUpdater', 'OpenRMMScriptRunner', 'OpenRMMUpdateBroker')) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            & $sc delete $name | Out-Null
        }
    }
    if (Test-Path -LiteralPath $programRoot) {
        if ((Get-Item -LiteralPath $programRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected link at the program folder; inspect it manually.' }
        Remove-Item -LiteralPath $programRoot -Recurse -Force
    }
}
$log = Join-Path ([IO.Path]::GetTempPath()) ('openrmm-agent-install-' + [Guid]::NewGuid().ToString('N') + '.log')
$process = Start-Process -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -ArgumentList @('/i', ('"' + $Msi + '"'), '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*v', ('"' + $log + '"')) -Wait -PassThru
if ($process.ExitCode -notin @(0, 3010)) { throw "Windows Installer failed (exit $($process.ExitCode)); see $log." }
# The first rollback package for self-updates. The data folder is SYSTEM and
# Administrators only (the agent enforces it at start-up).
$packages = Join-Path $dataRoot 'packages'
New-Item -ItemType Directory -Path $packages -Force | Out-Null
Copy-Item -LiteralPath $Msi -Destination (Join-Path $packages 'current.msi') -Force
Copy-Item -LiteralPath $Release -Destination (Join-Path $packages 'current.json') -Force
$service = Get-Service -Name OpenRMMAgent
$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(60))
Write-Output "Installed OpenRMM Agent $($signed.manifest.version) (sequence $($signed.manifest.sequence)); the service is running."
