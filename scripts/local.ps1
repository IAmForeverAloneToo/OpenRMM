[CmdletBinding()]
param(
    [ValidateSet('build', 'init', 'up', 'down', 'logs', 'status', 'check', 'storage-info', 'ca')]
    [string]$Action = 'status',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$Distribution = 'Ubuntu',
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,62}$')][string]$Project = 'openrmm-local',
    [string]$ComposeFile = 'compose.yaml'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$sessionFile = Join-Path $projectRoot ".local/wsl-$Distribution-session.json"
if ($Project -ne 'openrmm-local') { $sessionFile = Join-Path $projectRoot ".local/wsl-$Distribution-$Project-session.json" }

function Get-LocalSessionProcess {
    if (-not (Test-Path -LiteralPath $sessionFile)) { return $null }
    try {
        $record = Get-Content -LiteralPath $sessionFile -Raw | ConvertFrom-Json
        $sessionProcess = Get-Process -Id $record.ProcessId -ErrorAction Stop
        # PowerShell 7.5 may deserialize ISO timestamps as DateTime objects.
        # Compare UTC ticks so both old string records and parsed dates work.
        if ($sessionProcess.ProcessName -eq 'wsl' -and $sessionProcess.StartTime.ToUniversalTime().Ticks -eq ([DateTime]$record.StartedUtc).ToUniversalTime().Ticks) {
            return $sessionProcess
        }
        $sessionProcess.Dispose()
    }
    catch { return $null }
    return $null
}

function Start-LocalSession {
    $existingProcess = Get-LocalSessionProcess
    if ($null -ne $existingProcess) {
        $existingProcess.Dispose()
        return $false
    }
    New-Item -ItemType Directory -Path (Join-Path $projectRoot '.local') -Force | Out-Null
    $sessionProcess = Start-Process -FilePath 'wsl.exe' -ArgumentList @('-d', $Distribution, '--exec', 'sleep', 'infinity') -WindowStyle Hidden -PassThru
    if ($sessionProcess.WaitForExit(500)) {
        $sessionProcess.Dispose()
        throw 'Cannot keep the local WSL development session running.'
    }
    try {
        [pscustomobject]@{ProcessId = $sessionProcess.Id; StartedUtc = $sessionProcess.StartTime.ToUniversalTime().ToString('O')} |
            ConvertTo-Json | Set-Content -LiteralPath $sessionFile -Encoding UTF8
    }
    catch {
        $sessionProcess.Kill($true)
        throw
    }
    finally { $sessionProcess.Dispose() }
    return $true
}

function Stop-LocalSession {
    $sessionProcess = Get-LocalSessionProcess
    if ($null -ne $sessionProcess) {
        try {
            $sessionProcess.Kill($true)
            [void]$sessionProcess.WaitForExit(5000)
        }
        finally { $sessionProcess.Dispose() }
    }
    if (Test-Path -LiteralPath $sessionFile) { Remove-Item -LiteralPath $sessionFile }
}

function Invoke-LocalCompose {
    param([string[]]$ComposeArguments)
    # Docker remains inside WSL. No password is put in argv or an environment
    # variable, and no user is added to the root-equivalent Docker group.
    & wsl.exe -d $Distribution --user root --cd $projectRoot --exec docker compose --env-file deploy/local.env -f $ComposeFile -p $Project @ComposeArguments
    if ($LASTEXITCODE -ne 0) { throw 'Local Docker Compose command failed.' }
}

function Preserve-LocalServerImage {
    $container = (Invoke-LocalCompose -ComposeArguments @('ps','-a','-q','server') | Out-String).Trim()
    if (-not $container) { return }
    if ($container -notmatch '^[0-9a-f]{12,64}$') { throw 'Cannot identify a single existing local server before build.' }
    $image = (& wsl.exe -d $Distribution --user root --exec docker inspect --format '{{.Image}}' $container | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $image -notmatch '^sha256:[0-9a-f]{64}$') { throw 'Cannot identify the existing immutable server image.' }
    # Replacing an OCI development tag can drop the only image record, even
    # while its container is running. Keep a stable reference for exact backups.
    $retainedTag = '{0}-retained:{1}' -f $Project,$image.Substring(7)
    & wsl.exe -d $Distribution --user root --exec docker image tag $image $retainedTag
    if ($LASTEXITCODE -ne 0) { throw 'Cannot retain the existing runtime image; verify its backup before rebuilding.' }
    Write-Output 'Retained the existing immutable server image before replacing its development tag.'
}

switch ($Action) {
    'build' {
        # The image embeds the web build from internal/server/webui/dist.
        & (Join-Path $PSScriptRoot 'build-web.ps1')
        Preserve-LocalServerImage
        Invoke-LocalCompose -ComposeArguments @('build', 'server')
    }
    'init' { Invoke-LocalCompose -ComposeArguments @('run', '--rm', '--no-deps', 'certificates') }
    'up' {
        $startedSession = Start-LocalSession
        try { Invoke-LocalCompose -ComposeArguments @('up', '-d', '--wait', '--wait-timeout', '60', 'server') }
        catch {
            if ($startedSession) { Stop-LocalSession }
            throw
        }
    }
    'down' {
        Invoke-LocalCompose -ComposeArguments @('down')
        Stop-LocalSession
    }
    'logs' { Invoke-LocalCompose -ComposeArguments @('logs', '--tail', '100', 'server') }
    'status' { Invoke-LocalCompose -ComposeArguments @('ps', 'server') }
    'check' { Invoke-LocalCompose -ComposeArguments @('exec', '-T', 'server', '/openrmm-agent', '-server', 'https://127.0.0.1:8443', '-ca', '/tls/local/ca.pem', '-ready') }
    'storage-info' { Invoke-LocalCompose -ComposeArguments @('exec', '-T', 'server', '/openrmm-server', '-storage-info') }
    'ca' {
        $containerID = (Invoke-LocalCompose -ComposeArguments @('ps', '-q', 'server') | Out-String).Trim()
        if ($containerID -notmatch '^[0-9a-f]{12,64}$') { throw 'Start the local server before exporting its public CA.' }
        $localDirectory = Join-Path $projectRoot '.local'
        New-Item -ItemType Directory -Path $localDirectory -Force | Out-Null
        $destination = (Join-Path $localDirectory 'container-ca.pem')
        $linuxDestination = (& wsl.exe -d $Distribution --exec wslpath -a -u $destination | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve public CA destination.' }
        & wsl.exe -d $Distribution --user root --exec docker cp "${containerID}:/tls/local/ca.pem" $linuxDestination
        if ($LASTEXITCODE -ne 0) { throw 'Cannot export local public CA.' }
        Write-Output 'Public CA exported to .local/container-ca.pem; no private key or system trust changes.'
    }
}
