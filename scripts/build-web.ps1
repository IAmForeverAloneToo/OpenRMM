[CmdletBinding()]
param([switch]$CheckOnly)

# Builds the browser application in web/ into internal/server/webui/dist, which
# the Go server embeds. Packages install exactly from package-lock.json with
# lifecycle scripts disabled (web/.npmrc); the lockfile is never rewritten.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$web = Join-Path $projectRoot 'web'
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'Node.js with npm is required to build the web interface.' }
Push-Location $web
try {
    $lockBefore = (Get-FileHash -LiteralPath package-lock.json -Algorithm SHA256).Hash
    & npm ci --ignore-scripts --no-fund --loglevel=error
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed; package-lock.json must match package.json.' }
    if ((Get-FileHash -LiteralPath package-lock.json -Algorithm SHA256).Hash -ne $lockBefore) { throw 'package-lock.json changed during install.' }
    & npm audit --omit=dev --audit-level=high --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'npm audit reported a high-severity advisory in a runtime package.' }
    & npm run --silent typecheck
    if ($LASTEXITCODE -ne 0) { throw 'Web typecheck failed.' }
    # Unit tests for the pure helpers in src/lib, using Node's built-in runner.
    & npm run --silent test
    if ($LASTEXITCODE -ne 0) { throw 'Web unit tests failed.' }
    if (-not $CheckOnly) {
        & npx --no-install vite build --logLevel warn
        if ($LASTEXITCODE -ne 0) { throw 'Web build failed.' }
        Write-Output 'Built the web interface into internal/server/webui/dist.'
    }
    else { Write-Output 'Web packages verified; typecheck and unit tests passed.' }
}
finally { Pop-Location }
