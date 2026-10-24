[CmdletBinding()]
param(
    [ValidateSet('all', 'windows', 'linux')][string]$Target = 'all',
    # Embedded in the agent (and reported in heartbeats); scripts/release.ps1 sets it.
    [ValidatePattern('^[A-Za-z0-9._+-]{1,64}$')][string]$AgentVersion,
    # Release sequence built into the agent as its replay floor; scripts/release.ps1 sets it.
    [ValidateRange(0, 65535)][int]$ReleaseSequence = 0,
    # Public signing key(s) the agent trusts for self-updates (comma-separated hex).
    # Defaults to the release key's public.txt when it exists.
    [string]$PinnedKeys
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$savedEnvironment = @{}
foreach ($variableName in @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOWORK')) {
    $savedEnvironment[$variableName] = [Environment]::GetEnvironmentVariable($variableName, 'Process')
}
Push-Location $projectRoot
try {
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $projectRoot '.local/go-build'
    $env:GOMODCACHE = Join-Path $projectRoot '.local/go-mod'
    $env:GOTOOLCHAIN = 'go1.27.2'
    $env:GOWORK = 'off'
    & (Join-Path $PSScriptRoot 'check-dependencies.ps1')
    # The server embeds the web build, so it must exist before Go compiles.
    & (Join-Path $PSScriptRoot 'build-web.ps1')
    if ($Target -in @('all', 'windows')) {
        $env:GOOS = 'windows'
        if (-not $PinnedKeys) {
            $publicFile = Join-Path $projectRoot '.local/agent-updates-publisher/public.txt'
            if (Test-Path -LiteralPath $publicFile -PathType Leaf) { $PinnedKeys = (Get-Content -LiteralPath $publicFile -Raw).Trim() }
        }
        if ($PinnedKeys -and $PinnedKeys -notmatch '^[0-9a-f]{64}(,[0-9a-f]{64}){0,7}$') { throw 'Pinned keys must be up to eight 64-digit lowercase hex Ed25519 public keys.' }
        foreach ($program in @('server', 'agent', 'devcert', 'desktop', 'release', 'custody')) {
            if ($program -eq 'agent') {
                $flags = @()
                if ($AgentVersion) { $flags += "-X github.com/IAmForeverAloneToo/OpenRMM/internal/agent.Version=$AgentVersion" }
                if ($PinnedKeys) { $flags += "-X github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate.PinnedKeys=$PinnedKeys" }
                if ($ReleaseSequence -gt 0) { $flags += "-X github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate.ReleaseSequence=$ReleaseSequence" }
                & go build -mod=readonly -trimpath -buildvcs=false -ldflags ($flags -join ' ') -o "dist/windows-amd64/openrmm-$program.exe" "./cmd/openrmm-$program"
            }
            elseif ($program -eq 'desktop') {
                & go build -mod=readonly -trimpath -buildvcs=false -ldflags '-H=windowsgui' -o "dist/windows-amd64/openrmm-$program.exe" "./cmd/openrmm-$program"
            }
            else {
                & go build -mod=readonly -trimpath -buildvcs=false -o "dist/windows-amd64/openrmm-$program.exe" "./cmd/openrmm-$program"
            }
            if ($LASTEXITCODE -ne 0) { throw "Windows $program build failed." }
        }
        Write-Output 'Built Windows x64 server, agent, certificate helper, desktop companion, offline release signer, and custody verifier.'
    }
    if ($Target -in @('all', 'linux')) {
        $env:GOOS = 'linux'
        & go build -mod=readonly -trimpath -buildvcs=false -o dist/linux-amd64/openrmm-server ./cmd/openrmm-server
        if ($LASTEXITCODE -ne 0) { throw 'Linux server build failed.' }
        Write-Output 'Built Linux x64 server (cross-compilation only).'
    }
}
finally {
    Pop-Location
    foreach ($variableName in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($variableName, $savedEnvironment[$variableName], 'Process')
    }
}
