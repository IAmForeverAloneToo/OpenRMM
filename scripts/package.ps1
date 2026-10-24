[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & (Join-Path $PSScriptRoot 'check.ps1')
    & (Join-Path $PSScriptRoot 'build.ps1')
    & (Join-Path $PSScriptRoot 'local.ps1') -Action build
    # Container isolation/persistence smoke (its own disposable Compose project)
    # and the pinned vulnerability scan of source and built binaries.
    & wsl.exe -d Ubuntu --user root --cd $projectRoot --exec sh scripts/container-smoke.sh
    if ($LASTEXITCODE -ne 0) { throw 'Container smoke test failed.' }
    & wsl.exe -d Ubuntu --user root --cd $projectRoot --exec sh scripts/security-check.sh
    if ($LASTEXITCODE -ne 0) { throw 'Security check failed.' }
    $packageName = 'openrmm-local-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,6)
    $stage = Join-Path $projectRoot ".local/packages/$packageName"
    $output = Join-Path $projectRoot "dist/$packageName.zip"
    New-Item -ItemType Directory -Path $stage | Out-Null
    $selected = @('README.md','SECURITY.md','CONTRIBUTING.md','ROADMAP.md','LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','go.mod','go.sum','dependencies.lock','Dockerfile','compose.yaml','.dockerignore','.gitignore','deploy/local.env')
    $suffixes = @('.go','.sql','.html','.css','.js','.md','.ps1','.py','.sh','.ts','.tsx','.json','.svg','.txt')
    $selected += @('web/.npmrc')
    # installer/ holds the MSI definition and its pinned build image.
    $selected += @('installer/openrmm-agent.wxs','installer/Dockerfile')
    if (Test-Path -LiteralPath (Join-Path $projectRoot 'dist/windows-amd64/openrmm-agent.msi')) { $selected += 'dist/windows-amd64/openrmm-agent.msi' }
    # Only files tracked by git are packaged, so local working files never are.
    $tracked = [Collections.Generic.HashSet[string]]::new([string[]]@(& git -C $projectRoot ls-files))
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'Packaging needs a git checkout.' }
    foreach ($folder in @('cmd','internal','docs','scripts','web')) {
        $selected += @(Get-ChildItem -LiteralPath (Join-Path $projectRoot $folder) -File -Recurse | Where-Object {
            $_.Extension -in $suffixes -and $_.Name -notlike '.env*' -and $_.FullName -notmatch '[\\/]node_modules[\\/]' -and -not ($_.FullName -match '[\\/]internal[\\/]agentbundle[\\/]files[\\/]' -and $_.Name -ne 'README.md') -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $tracked.Contains([IO.Path]::GetRelativePath($projectRoot,$_.FullName).Replace('\','/'))
        } | ForEach-Object { [IO.Path]::GetRelativePath($projectRoot,$_.FullName) })
    }
    $selected += @('dist/windows-amd64/openrmm-release.exe','dist/windows-amd64/openrmm-custody.exe','dist/windows-amd64/openrmm-desktop.exe','dist/windows-amd64/openrmm-agent.exe','dist/windows-amd64/openrmm-server.exe','dist/windows-amd64/openrmm-devcert.exe','dist/linux-amd64/openrmm-server')
    foreach ($relative in $selected) {
        $source = Join-Path $projectRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Package input missing: $relative" }
        if ((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package inputs must not be links.' }
        $destination = Join-Path $stage $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $imageID = (& wsl.exe -d Ubuntu --user root --exec docker image inspect --format '{{.Id}}' openrmm-local:dev | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $imageID -notmatch '^sha256:[0-9a-f]{64}$') { throw 'Cannot inspect the checked local runtime image.' }
    $imagePath = Join-Path $stage 'server-image.tar'
    $linuxImagePath = (& wsl.exe -d Ubuntu --exec wslpath -a -u $imagePath | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve runtime image package path.' }
    & wsl.exe -d Ubuntu --user root --exec docker image save -o $linuxImagePath $imageID
    if ($LASTEXITCODE -ne 0) { throw 'Cannot export the runtime image.' }
    [ordered]@{format=1;kind='local-development';image_id=$imageID;toolchain='go1.27.2';license='AGPL-3.0-only';created_utc=[DateTime]::UtcNow.ToString('O')} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'package.json') -Encoding UTF8
    $hashes = [ordered]@{}
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse | Sort-Object FullName) {
        $relative = [IO.Path]::GetRelativePath($stage,$file.FullName).Replace('\','/')
        $hashes[$relative]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $hashes | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $stage 'checksums.json') -Encoding UTF8
    [IO.Compression.ZipFile]::CreateFromDirectory($stage,$output,[IO.Compression.CompressionLevel]::Optimal,$false)
    $archiveHash=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(($output+'.sha256'),$archiveHash+'  '+[IO.Path]::GetFileName($output)+"`n")
    Write-Output "Created local development package: $output"
    Write-Output 'Includes source, binaries, exact runtime image, instructions, notices, and checksums. No application state or credentials are included.'
}
finally { Pop-Location }
