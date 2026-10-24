#Requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('setup', 'confirm', 'reset')][string]$Action = 'setup',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string]$Distribution = 'Ubuntu'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot

function Invoke-AdministratorCommand {
    param([string]$Mode, [hashtable]$RequestData)
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'wsl.exe'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-d', $Distribution, '--user', 'root', '--cd', $projectRoot, '--exec', 'docker', 'compose', '--env-file', 'deploy/local.env', '-f', 'compose.yaml', 'exec', '-T', 'server', '/openrmm-server', "-admin-$Mode")) {
        $startInfo.ArgumentList.Add($argument)
    }
    $commandProcess = [Diagnostics.Process]::new()
    $commandProcess.StartInfo = $startInfo
    try {
        [void]$commandProcess.Start()
        $outputTask = $commandProcess.StandardOutput.ReadToEndAsync()
        $errorTask = $commandProcess.StandardError.ReadToEndAsync()
        # Passwords and confirmation codes are supplied on the process pipe,
        # never in command arguments, environment variables, or a saved file.
        $commandProcess.StandardInput.WriteLine(($RequestData | ConvertTo-Json -Compress))
        $commandProcess.StandardInput.Close()
        if (-not $commandProcess.WaitForExit(20000)) {
            $commandProcess.Kill($true)
            throw 'Local administrator command timed out.'
        }
        $resultText = $outputTask.GetAwaiter().GetResult()
        $errorText = $errorTask.GetAwaiter().GetResult()
        if ($commandProcess.ExitCode -ne 0) {
            $reason = 'Local administrator command failed. Check that the local server is running.'
            try {
                $lastLine = ($errorText.Trim() -split "`n")[-1]
                $errorRecord = $lastLine | ConvertFrom-Json
                if ($errorRecord.reason -is [string] -and $errorRecord.reason.Length -lt 300) { $reason = $errorRecord.reason }
            }
            catch { }
            throw $reason
        }
        try { return ($resultText | ConvertFrom-Json) }
        catch { throw 'Cannot read local administrator result.' }
    }
    finally { $commandProcess.Dispose() }
}

function Read-PrivatePassword {
    $first = Read-Host 'New password (at least 15 characters)' -AsSecureString
    $second = Read-Host 'Confirm password' -AsSecureString
    $firstPointer = [IntPtr]::Zero
    $secondPointer = [IntPtr]::Zero
    try {
        $firstPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
        $secondPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
        $firstText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($firstPointer)
        $secondText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secondPointer)
        if ($firstText -cne $secondText) { throw 'Passwords do not match.' }
        return $firstText
    }
    finally {
        if ($firstPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPointer) }
        if ($secondPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPointer) }
        $first.Dispose()
        $second.Dispose()
    }
}

if ($Action -ne 'confirm') {
    $administratorName = Read-Host 'Administrator username (default admin)'
    if ([string]::IsNullOrWhiteSpace($administratorName)) { $administratorName = 'admin' }
    $passwordText = Read-PrivatePassword
    try { $provisioning = Invoke-AdministratorCommand -Mode $Action -RequestData @{username=$administratorName; password=$passwordText} }
    finally { $passwordText = $null }
    Write-Host ''
    Write-Host 'Add an OpenRMM account to your authenticator app using this secret:'
    Write-Host $provisioning.secret
    Write-Host ''
    Write-Host 'Save these recovery codes privately. Each works once with your password:'
    foreach ($recoveryCode in $provisioning.recovery_codes) { Write-Host $recoveryCode }
    Write-Host ''
    Write-Host 'The account stays inactive until you confirm an authenticator code.'
}
$confirmationCode = Read-Host 'Current six-digit authenticator code'
$confirmation = Invoke-AdministratorCommand -Mode 'confirm' -RequestData @{code=$confirmationCode}
if ($confirmation.status -ne 'confirmed') { throw 'Administrator MFA was not confirmed.' }
Write-Host 'Administrator ready. Wait for the next authenticator code, then sign in at https://127.0.0.1:8443/login.'
