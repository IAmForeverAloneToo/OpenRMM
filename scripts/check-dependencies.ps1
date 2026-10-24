[CmdletBinding()]
param([string]$BaselinePath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($BaselinePath)) {
    $BaselinePath = Join-Path $projectRoot 'dependencies.lock'
}
else {
    $BaselinePath = [IO.Path]::GetFullPath($BaselinePath)
}
$savedEnvironment = @{}
foreach ($variableName in @('GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOWORK')) {
    $savedEnvironment[$variableName] = [Environment]::GetEnvironmentVariable($variableName, 'Process')
}
Push-Location $projectRoot
try {
    $env:GOCACHE = Join-Path $projectRoot '.local/go-build'
    $env:GOMODCACHE = Join-Path $projectRoot '.local/go-mod'
    $env:GOTOOLCHAIN = 'go1.27.2'
    $env:GOWORK = 'off'
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
        throw 'Dependency baseline is missing. Record the reviewed graph before building.'
    }
    $expected = @(Get-Content -LiteralPath $BaselinePath | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    $actual = @(& go list -mod=readonly -m all)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the pinned module graph.' }
    $differences = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual -CaseSensitive)
    if ($differences.Count -ne 0) {
        $differences | Format-Table InputObject,SideIndicator -AutoSize | Out-Host
        throw 'Dependency graph differs from dependencies.lock. Review the change and its transitive dependencies; this check never refreshes the baseline.'
    }
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Module cache integrity verification failed.' }
    Write-Output "Dependency baseline matches ($($actual.Count - 1) external module versions in the full graph)."
}
finally {
    Pop-Location
    foreach ($variableName in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($variableName, $savedEnvironment[$variableName], 'Process')
    }
}
