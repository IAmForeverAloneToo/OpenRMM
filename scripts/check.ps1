[CmdletBinding()]
# -Short skips timing-sensitive native Windows tests (used on CI runners).
param([switch]$Short)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$savedEnvironment = @{}
foreach ($variableName in @('GOOS', 'GOARCH', 'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOWORK')) {
    $savedEnvironment[$variableName] = [Environment]::GetEnvironmentVariable($variableName, 'Process')
}
Push-Location $projectRoot
try {
    # Execute tests for this machine even if a previous command targeted Linux.
    [Environment]::SetEnvironmentVariable('GOOS', $null, 'Process')
    [Environment]::SetEnvironmentVariable('GOARCH', $null, 'Process')
    $env:GOCACHE = Join-Path $projectRoot '.local/go-build'
    $env:GOMODCACHE = Join-Path $projectRoot '.local/go-mod'
    $env:GOTOOLCHAIN = 'go1.27.2'
    $env:GOWORK = 'off'
    & (Join-Path $PSScriptRoot 'check-dependencies.ps1')
    & (Join-Path $PSScriptRoot 'build-web.ps1') -CheckOnly
    $sourceFiles = @(Get-ChildItem -Path cmd,internal -Recurse -Filter '*.go' | ForEach-Object FullName)
    # The pinned toolchain's own gofmt, not whichever one is on PATH.
    $gofmt = Join-Path (& go env GOROOT) 'bin/gofmt'
    $unformatted = @(& $gofmt -l @sourceFiles)
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
    if ($unformatted.Count -ne 0) {
        $unformatted | Write-Output
        throw 'Run gofmt on the listed files.'
    }
    & go vet -mod=readonly ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed.' }
    $testArgs = @('-mod=readonly')
    if ($Short) { $testArgs += '-short' }
    & go test @testArgs ./...
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    Write-Output 'Formatting, vet, and tests passed.'
}
finally {
    Pop-Location
    foreach ($variableName in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($variableName, $savedEnvironment[$variableName], 'Process')
    }
}
