[CmdletBinding()]
param(
    # Windows Installer version, 1.0.<release sequence>; each release must differ.
    [Parameter(Mandatory)][ValidatePattern('^1\.0\.\d{1,5}$')][string]$ProductVersion,
    # Human version shown in Programs and Features, e.g. 0.1.0-dev+local.
    [ValidatePattern('^[A-Za-z0-9._+-]{1,64}$')][string]$AgentVersion = 'dev'
)

# Builds dist/windows-amd64/openrmm-agent.msi from the already built
# openrmm-agent.exe and openrmm-desktop.exe with wixl in a pinned build image
# (installer/Dockerfile), run through Docker in the Ubuntu WSL distribution.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $projectRoot 'dist/windows-amd64'
foreach ($program in @('openrmm-agent.exe', 'openrmm-desktop.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $dist $program) -PathType Leaf)) { throw "Build $program with scripts/build.ps1 first." }
}
$stage = Join-Path $projectRoot '.local/msi-stage'
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
foreach ($file in @('openrmm-agent.exe', 'openrmm-desktop.exe')) { Copy-Item -LiteralPath (Join-Path $dist $file) -Destination $stage }
foreach ($file in @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md')) { Copy-Item -LiteralPath (Join-Path $projectRoot $file) -Destination $stage }
Copy-Item -LiteralPath (Join-Path $projectRoot 'installer/openrmm-agent.wxs') -Destination $stage

$linuxInstaller = (& wsl.exe -d Ubuntu --exec wslpath -a -u (Join-Path $projectRoot 'installer') | Out-String).Trim()
$linuxStage = (& wsl.exe -d Ubuntu --exec wslpath -a -u $stage | Out-String).Trim()
& wsl.exe -d Ubuntu --user root --exec docker build --quiet -t openrmm-wixl:0.106 $linuxInstaller | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot build the pinned wixl image.' }
& wsl.exe -d Ubuntu --user root --exec docker run --rm --network none --mount "type=bind,src=$linuxStage,dst=/work" openrmm-wixl:0.106 `
    -a x64 -D "ProductVersion=$ProductVersion" -D "AgentVersion=$AgentVersion" -D 'SourceDir=.' -o openrmm-agent.msi openrmm-agent.wxs
if ($LASTEXITCODE -ne 0) { throw 'wixl failed to build the agent MSI.' }
$msi = Join-Path $stage 'openrmm-agent.msi'
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw 'wixl produced no MSI.' }
Copy-Item -LiteralPath $msi -Destination (Join-Path $dist 'openrmm-agent.msi') -Force
Write-Output "Built dist/windows-amd64/openrmm-agent.msi (version $ProductVersion, agent $AgentVersion)."
