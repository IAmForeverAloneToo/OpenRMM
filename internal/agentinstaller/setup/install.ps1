# OpenRMM agent setup, started by install.cmd (Windows PowerShell 5.1 or
# later). Installs the signed agent MSI and hands enrollment.json to the agent
# service, which enrolls this machine on first start and then deletes the file.
# A machine whose installed agent already has an identity is left as it is: it
# updates itself. Exit codes: 0 done, 1 error, 2 incomplete or changed download,
# 3 Windows Installer failed, 4 installed but not enrolled yet, 5 not elevated.
# -Proxy sets the proxy the agent uses to reach the server (none removes it).
param([string]$Proxy = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Stop-Setup([string]$Message, [int]$Code) {
    Write-Output "OpenRMM setup failed: $Message"
    exit $Code
}

try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-Setup 'run install.cmd as administrator.' 5 }
    if (-not [Environment]::Is64BitOperatingSystem) { Stop-Setup 'the OpenRMM agent needs 64-bit Windows.' 1 }
    # The agent checks the value again and logs why it rejects one.
    if ($Proxy -ne '' -and ($Proxy.Length -gt 512 -or $Proxy -notmatch '^(none|direct|(https?://)?([^\s/?#@]+@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?/?)$')) { Stop-Setup 'the proxy must be none, direct or http://[user:password@]host:port (percent-encode special characters in the password).' 1 }
    $msi = Join-Path $PSScriptRoot 'openrmm-agent.msi'
    $release = Join-Path $PSScriptRoot 'release.json'
    $enrollment = Join-Path $PSScriptRoot 'enrollment.json'
    foreach ($path in @($msi, $release, $enrollment)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Stop-Setup "$(Split-Path -Leaf $path) is missing; extract the whole ZIP first." 2 }
    }
    $signed = Get-Content -LiteralPath $release -Raw | ConvertFrom-Json
    $stream = [IO.File]::OpenRead($msi)
    try { $hash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) } finally { $stream.Dispose() }
    if ($signed.manifest.format -ne 2 -or $signed.manifest.package -ne 'msi' -or $signed.manifest.sha256 -ne $hash) { Stop-Setup 'the MSI does not match release.json; download the installer again.' 2 }

    $system32 = [Environment]::SystemDirectory
    $dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'OpenRMM Agent'
    # The identity under state\ is SYSTEM-only; the enrolled agent records its
    # device ID in device.json, which administrators can read.
    $record = Join-Path $dataRoot 'device.json'
    $state = Join-Path $dataRoot 'state'
    $service = Get-Service -Name OpenRMMAgent -ErrorAction SilentlyContinue
    if ($null -ne $service -and (Test-Path -LiteralPath $record)) {
        if ($Proxy -ne '') {
            # The service takes the setting into its protected state when it starts.
            [IO.File]::WriteAllText((Join-Path $dataRoot 'proxy.txt'), $Proxy)
            Restart-Service -Name OpenRMMAgent
            Write-Output 'OpenRMM Agent is already installed and enrolled; its proxy setting was updated and the agent restarted.'
            exit 0
        }
        Write-Output 'OpenRMM Agent is already installed and enrolled on this machine; nothing to do. It keeps itself up to date.'
        exit 0
    }
    if ($null -eq $service -and (Test-Path -LiteralPath $state)) {
        # Uninstalling keeps the old identity, which may have been revoked since.
        # Keep the whole data folder aside (administrators cannot move the
        # SYSTEM-only state folder itself) and enroll as a new device; revoke
        # the old entry in OpenRMM.
        $previous = $dataRoot + '.previous-' + (Get-Date -Format 'yyyyMMddHHmmss')
        [IO.Directory]::Move($dataRoot, $previous)
        Write-Output "The previous OpenRMM data folder was kept as $previous; this machine enrolls as a new device."
    }
    # The token stays in the data folder until the service has enrolled, so the
    # folder is SYSTEM and Administrators only before anything is copied.
    if (-not (Test-Path -LiteralPath $dataRoot)) { New-Item -ItemType Directory -Path $dataRoot | Out-Null }
    if ((Get-Item -LiteralPath $dataRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Setup "unexpected link at $dataRoot; inspect it manually." 1 }
    & (Join-Path $system32 'icacls.exe') $dataRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Setup 'cannot protect the agent data folder.' 1 }
    Copy-Item -LiteralPath $enrollment -Destination (Join-Path $dataRoot 'enrollment.json') -Force
    if ($Proxy -ne '') { [IO.File]::WriteAllText((Join-Path $dataRoot 'proxy.txt'), $Proxy) }
    # The first rollback package for the agent's self-updates.
    $packages = Join-Path $dataRoot 'packages'
    New-Item -ItemType Directory -Path $packages -Force | Out-Null
    Copy-Item -LiteralPath $msi -Destination (Join-Path $packages 'current.msi') -Force
    Copy-Item -LiteralPath $release -Destination (Join-Path $packages 'current.json') -Force

    $version = "1.0.$($signed.manifest.sequence)"
    $same = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'OpenRMM Agent' -and $_.PSObject.Properties['DisplayVersion'] -and $_.DisplayVersion -eq $version })
    if ($same.Count -gt 0) {
        # An earlier attempt installed this release; enroll again with the new file.
        Write-Output 'OpenRMM Agent is installed; restarting it to enroll.'
        Restart-Service -Name OpenRMMAgent
    } else {
        Write-Output "Installing OpenRMM Agent $($signed.manifest.version)..."
        $log = Join-Path ([IO.Path]::GetTempPath()) ('openrmm-agent-install-' + [Guid]::NewGuid().ToString('N') + '.log')
        $process = Start-Process -FilePath (Join-Path $system32 'msiexec.exe') -ArgumentList @('/i', ('"' + $msi + '"'), '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*v', ('"' + $log + '"')) -Wait -PassThru
        if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { Stop-Setup "Windows Installer returned $($process.ExitCode); see $log." 3 }
    }

    Write-Output 'Waiting for the agent to enroll with the server...'
    $deadline = (Get-Date).AddMinutes(2)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -LiteralPath $record) -and -not (Test-Path -LiteralPath (Join-Path $dataRoot 'enrollment.json'))) {
            Write-Output "OpenRMM Agent is installed and enrolled ($((Get-Content -LiteralPath $record -Raw | ConvertFrom-Json).device_id)). The device appears in Devices within a minute."
            exit 0
        }
        Start-Sleep -Seconds 2
    }
    Write-Output "OpenRMM Agent is installed but has not enrolled yet. It keeps retrying; see agent.log in $(Join-Path $dataRoot 'logs')."
    exit 4
} catch {
    Stop-Setup $_.Exception.Message 1
}
