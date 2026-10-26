[CmdletBinding()]
param(
    # Agent version shown in heartbeats and the Agent updates page, e.g. 0.2.0.
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._+-]{1,64}$')][string]$Version,
    # Folder holding the encrypted signing key (signing-key.json, public.txt, sequence.json).
    [string]$KeyDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) '.local/agent-updates-publisher'),
    [ValidateRange(1, 366)][int]$Days = 365,
    # Also back up and replace the local server (scripts/local.ps1) after building.
    [switch]$Deploy
)

# One release command: build the agent and its MSI, sign the MSI with the next
# sequence from the key's own counter, bundle it into the server build,
# rebuild, and optionally deploy. The passphrase is read without echo and only ever passed to the local
# signer on standard input. The signing key never enters the server or its image.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$signer = Join-Path $projectRoot 'dist/windows-amd64/openrmm-release.exe'
$agent = Join-Path $projectRoot 'dist/windows-amd64/openrmm-agent.exe'
$package = Join-Path $projectRoot 'dist/windows-amd64/openrmm-agent.msi'
$bundle = Join-Path $projectRoot 'internal/agentbundle/files'
$sealed = Join-Path $KeyDirectory 'signing-key.json'
$plain = Join-Path $KeyDirectory 'private.pem'

function Read-Passphrase([string]$Prompt) {
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

if (-not (Test-Path -LiteralPath $sealed)) {
    if (-not (Test-Path -LiteralPath $plain)) { throw "No signing key in $KeyDirectory. Create one with: openrmm-release.exe -create-key <folder> -passphrase-stdin" }
    # One-time protection of an existing plaintext key (S11). Its public key is
    # unchanged, so devices keep trusting it.
    Write-Output 'The signing key is stored unencrypted. Choose a passphrase (15+ characters) to encrypt it now.'
    $last = Read-Host -Prompt 'Highest sequence number already used with this key (see the Agent updates page)'
    if ($last -notmatch '^\d{1,9}$') { throw 'Enter the last sequence as a number.' }
    while ($true) {
        $first = Read-Passphrase 'New passphrase (at least 15 characters)'
        if ($first.Length -lt 15) { Write-Output "That was $($first.Length) characters; use at least 15."; continue }
        $second = Read-Passphrase 'Repeat passphrase'
        if ($first -cne $second) { Write-Output 'The passphrases do not match; try again.'; continue }
        break
    }
    & (Join-Path $PSScriptRoot 'build.ps1') -Target windows
    $output = $first | & $signer -encrypt-key -key $plain -last-sequence $last -passphrase-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Encrypting the signing key failed; the plaintext key is unchanged.' }
    $output
    $first = $null; $second = $null
}

# The sequence is fixed before building: the agent embeds it as its replay
# floor and the MSI uses it as its version (1.0.<sequence>). The signer then
# consumes exactly this sequence; a failed run leaves the counter unchanged.
$counter = Get-Content -LiteralPath (Join-Path $KeyDirectory 'sequence.json') -Raw | ConvertFrom-Json
if ($counter.format -ne 1 -or $counter.last_sequence -lt 0) { throw 'Unreadable sequence counter next to the signing key.' }
$next = [int64]$counter.last_sequence + 1
if ($next -gt 65535) { throw 'The release sequence no longer fits an MSI version.' }
$publicKey = (Get-Content -LiteralPath (Join-Path $KeyDirectory 'public.txt') -Raw).Trim()

# Build everything: the versioned agent with its pinned key, then its MSI.
& (Join-Path $PSScriptRoot 'check.ps1')
& (Join-Path $PSScriptRoot 'build.ps1') -AgentVersion $Version -ReleaseSequence $next -PinnedKeys $publicKey
& (Join-Path $PSScriptRoot 'build-msi.ps1') -ProductVersion "1.0.$next" -AgentVersion $Version

$staging = Join-Path $projectRoot ".local/releases/$Version"
$manifest = Join-Path $staging 'release.json'
if (Test-Path -LiteralPath $manifest) { throw "Release $Version was already signed ($staging). Choose a new version." }
# A folder without a manifest is left by a run that stopped before signing.
if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging | Out-Null
Copy-Item -LiteralPath $agent -Destination (Join-Path $staging 'openrmm-agent.exe')
Copy-Item -LiteralPath $package -Destination (Join-Path $staging 'openrmm-agent.msi')
# The key is opened before a sequence is consumed, so a mistyped passphrase
# costs nothing; allow a few attempts instead of rebuilding everything.
# OPENRMM_SIGNING_PASSPHRASE, when set by the caller, is used without a prompt.
for ($attempt = 1; ; $attempt++) {
    $passphrase = if ($env:OPENRMM_SIGNING_PASSPHRASE) { $env:OPENRMM_SIGNING_PASSPHRASE } else { Read-Passphrase 'Signing key passphrase' }
    try {
        $output = $passphrase | & $signer -key $sealed -passphrase-stdin -binary (Join-Path $staging 'openrmm-agent.msi') -agent (Join-Path $staging 'openrmm-agent.exe') -version $Version -sequence $next -days $Days -out $manifest
        $failed = $LASTEXITCODE -ne 0
    }
    finally { $passphrase = $null }
    if (-not $failed) { $output; break }
    if ($env:OPENRMM_SIGNING_PASSPHRASE -or $attempt -ge 3) { throw 'Signing failed. No sequence was used; check the passphrase and run the same command again.' }
    Write-Output 'Signing failed, most likely a mistyped passphrase. No sequence was used; try again.'
}

# Replace the bundled release and rebuild so the server embeds it.
Get-ChildItem -LiteralPath $bundle -File | Where-Object Name -ne 'README.md' | Remove-Item
Copy-Item -LiteralPath $manifest -Destination (Join-Path $bundle 'release.json')
Copy-Item -LiteralPath (Join-Path $KeyDirectory 'public.txt') -Destination (Join-Path $bundle 'public.txt')
Copy-Item -LiteralPath (Join-Path $staging 'openrmm-agent.msi') -Destination (Join-Path $bundle 'openrmm-agent.msi')
& (Join-Path $PSScriptRoot 'build.ps1') -AgentVersion $Version -ReleaseSequence $next -PinnedKeys $publicKey
# Keep dist identical to what was signed.
Copy-Item -LiteralPath (Join-Path $staging 'openrmm-agent.exe') -Destination $agent -Force
Copy-Item -LiteralPath (Join-Path $staging 'openrmm-agent.msi') -Destination $package -Force
Write-Output "Release $Version (sequence $next) is signed and bundled into the server build ($staging)."

if ($Deploy) {
    $name = 'before-release-' + ($Version -replace '[^A-Za-z0-9-]', '-') + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    & wsl.exe -d Ubuntu --user root --cd $projectRoot --exec python3 scripts/recovery.py backup --project openrmm-local --name $name
    if ($LASTEXITCODE -ne 0) { throw 'Backup failed; the server was not replaced.' }
    & wsl.exe -d Ubuntu --user root --cd $projectRoot --exec python3 scripts/recovery.py verify --name $name
    if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed; the server was not replaced.' }
    & (Join-Path $PSScriptRoot 'local.ps1') -Action build
    & (Join-Path $PSScriptRoot 'local.ps1') -Action up
    & (Join-Path $PSScriptRoot 'local.ps1') -Action check
    # The server imports the bundled release at start-up; a refused import is
    # only a log line, so check for it rather than report success.
    $log = (& (Join-Path $PSScriptRoot 'local.ps1') -Action logs | Out-String)
    if ($log -match 'bundled agent release not imported|bundled agent release is invalid') {
        throw "Deployed, but the server did not import release $Version (see local.ps1 -Action logs). Agents will not be offered it."
    }
    Write-Output "Deployed. The server imported release $Version; roll it out from Agent updates."
}
else {
    Write-Output 'Next: back up and deploy the server (scripts/release.ps1 -Deploy does both), then roll out from Agent updates.'
}
