$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$result=[ordered]@{format='msi_v1';operation=$Operation;outcome='failed';reason='precondition';observed=$false;products=@();mutated=$false;installer_exit=$null;restart_required=$false}
function Finish-Deployment([string]$Outcome,[string]$Reason) {
    $result.outcome=$Outcome;$result.reason=$Reason
    $result | ConvertTo-Json -Compress -Depth 5 | Write-Output
    exit 0
}
function Read-Products {
    $found=@{}
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        try {
            foreach($code in $codes) {
                $key=$root.OpenSubKey(('Software\Microsoft\Windows\CurrentVersion\Uninstall\'+$code),$false)
                if ($null -eq $key) { continue }
                try {
                    if ([int]$key.GetValue('WindowsInstaller',0) -ne 1) { throw 'Not an MSI registration' }
                    $version=[string]$key.GetValue('DisplayVersion','')
                    if ($version -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$') { throw 'Unknown version' }
                    $v=[Version]$version
                    if ($v.Major -gt 255 -or $v.Minor -gt 255 -or $v.Build -gt 65535) { throw 'Invalid MSI version' }
                    if ($found.ContainsKey($code) -and $found[$code] -ne $version) { throw 'Conflicting views' }
                    $found[$code]=$version
                } finally { $key.Dispose() }
            }
        } finally { $root.Dispose() }
    }
    $items=@();foreach($code in @($found.Keys | Sort-Object)) {$items+=@{code=$code;version=$found[$code]}}
    $result.products=@($items);$result.observed=$true
}
function Assert-PackageIdentity([string]$download) {
    $msi=New-Object -ComObject WindowsInstaller.Installer
    $db=$null
    try {
        $db=$msi.OpenDatabase($download,0)
        foreach($property in @('ProductCode','ProductVersion')) {
            $view=$db.OpenView(('SELECT `Value` FROM `Property` WHERE `Property` = '''+$property+''''))
            $record=$null
            try {
                $view.Execute();$record=$view.Fetch();if ($null -eq $record) { throw 'Missing installer property' }
                $value=[string]$record.StringData(1)
                if (($property -eq 'ProductCode' -and $value.ToUpperInvariant() -cne $package.product_code) -or ($property -eq 'ProductVersion' -and $value -cne $package.version)) { throw 'Installer identity mismatch' }
            } finally { if ($null -ne $record) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)};$view.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
        }
    } finally {if ($null -ne $db) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)};[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($msi)}
}
# Begin lifecycle
try {
    if ($Operation -notin @('verify','install','update','uninstall')) { Finish-Deployment 'failed' 'precondition' }
    $parsedCodes=$KnownProducts | ConvertFrom-Json
    $codes=@();foreach($value in $parsedCodes) { $codes+=$value }
    if ($codes.Count -lt 1 -or $codes.Count -gt 20 -or $codes -cnotcontains $package.product_code) { Finish-Deployment 'failed' 'precondition' }
    $seen=@{};foreach($code in $codes) {
        if ($code -isnot [string] -or $code -cnotmatch '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$' -or $seen.ContainsKey($code)) { Finish-Deployment 'failed' 'precondition' }
        $seen[$code]=$true
    }
    $result.reason='observation';Read-Products
    if ($Operation -eq 'verify') { Finish-Deployment 'verified' 'verified' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { Finish-Deployment 'failed' 'denied' }
    $present=@($result.products)
    $target=@($present | Where-Object {$_.code -ceq $package.product_code -and $_.version -ceq $package.version})
    if ($Operation -eq 'install' -and $present.Count -eq 1 -and $target.Count -eq 1) { Finish-Deployment 'no_change' 'verified' }
    if ($Operation -eq 'uninstall' -and $present.Count -eq 0) { Finish-Deployment 'no_change' 'verified' }
    if ($Operation -eq 'install' -and $present.Count -ne 0) { Finish-Deployment 'failed' 'precondition' }
    if ($Operation -eq 'uninstall' -and ($present.Count -ne 1 -or $target.Count -ne 1)) { Finish-Deployment 'failed' 'precondition' }
    if ($Operation -eq 'update') {
        if ($present.Count -ne 1 -or $present[0].code -cne $PreviousCode -or $present[0].version -cne $PreviousVersion -or $PreviousCode -ceq $package.product_code -or $codes -cnotcontains $PreviousCode) { Finish-Deployment 'failed' 'precondition' }
        if ([Version]$package.version -le [Version]$PreviousVersion) { Finish-Deployment 'failed' 'precondition' }
    }
    $installer=Join-Path $env:WINDIR 'System32\msiexec.exe'
    if (-not [IO.File]::Exists($installer)) { Finish-Deployment 'failed' 'unsupported' }
    $download=Join-Path $PSScriptRoot 'package.msi'
    if ($Operation -ne 'uninstall') {
        $result.reason='download'
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        [Net.ServicePointManager]::CheckCertificateRevocationList=$true
        $request=[Net.HttpWebRequest]::Create([Uri]$package.url)
        $request.AllowAutoRedirect=$false;$request.Credentials=$null;$request.UseDefaultCredentials=$false;$request.Proxy=$null
        $request.Timeout=30000;$request.ReadWriteTimeout=15000
        $response=$request.GetResponse()
        try {
            if ([int]$response.StatusCode -ne 200 -or $response.ContentLength -gt 268435456) { throw 'Unexpected source response' }
            $inputStream=$response.GetResponseStream();$output=[IO.File]::Open($download,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {
                $buffer=New-Object byte[] 65536;$total=0L
                while (($read=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $total+=$read;if ($total -gt 268435456) { throw 'Installer too large' };$output.Write($buffer,0,$read)
                }
            } finally { $output.Dispose();$inputStream.Dispose() }
        } finally { $response.Dispose() }
        $result.reason='checksum'
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -cne $package.sha256) { Finish-Deployment 'failed' 'checksum' }
        $result.reason='package_identity'
        Assert-PackageIdentity $download
    }
    # The staged file is inside the runner's private owned workspace. No custom
    # installer switches, transforms, shell commands or reboot commands are used.
    $arguments='/x '+$package.product_code+' /qn /norestart REBOOT=ReallySuppress'
    if ($Operation -ne 'uninstall') { $arguments='/i "'+$download+'" /qn /norestart REBOOT=ReallySuppress ALLUSERS=1 MSIINSTALLPERUSER=""' }
    $result.reason='installer';$result.mutated=$true;$result.observed=$false;$result.products=@()
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$installer;$start.Arguments=$arguments;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $process=New-Object Diagnostics.Process;$process.StartInfo=$start
    if (-not $process.Start()) { Finish-Deployment 'unknown' 'installer' }
    $process.WaitForExit()
    if ($null -eq $process.ExitCode) { Finish-Deployment 'unknown' 'installer' }
    $result.installer_exit=[int]$process.ExitCode
    $result.restart_required=($process.ExitCode -eq 3010)
    if ($process.ExitCode -notin @(0,3010)) { Finish-Deployment 'unknown' 'installer' }
    $result.reason='verification';$result.observed=$false;$result.products=@();Read-Products
    $present=@($result.products)
    if ($Operation -eq 'uninstall') {
        if ($present.Count -ne 0) { Finish-Deployment 'unknown' 'verification' }
    } elseif ($present.Count -ne 1 -or $present[0].code -cne $package.product_code -or $present[0].version -cne $package.version) { Finish-Deployment 'unknown' 'verification' }
    Finish-Deployment 'verified' 'verified'
} catch {
    if ($result.reason -eq 'observation' -or $result.reason -eq 'verification') { $result.observed=$false;$result.products=@() }
    if ($result.mutated) { Finish-Deployment 'unknown' $result.reason }
    Finish-Deployment 'failed' $result.reason
}
