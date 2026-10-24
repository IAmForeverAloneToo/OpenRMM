#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Server = 'https://127.0.0.1:8443',
    [string]$DeviceServer = 'https://127.0.0.1:8444',
    [string]$CA = '.local/container-ca.pem',
    [string]$State = '.local/agent',
    # enrollment.json from an installer downloaded in the UI; its
    # addresses, CA and token replace -Server, -DeviceServer, -CA and the prompt.
    [string]$EnrollmentFile = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $projectRoot 'dist/windows-amd64/openrmm-agent.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw 'Build the Windows agent first with scripts/build.ps1 -Target windows.' }
$privateToken = $null
$caFile = $null
$tokenPointer = [IntPtr]::Zero
$agentProcess = [Diagnostics.Process]::new()
try {
    if ($EnrollmentFile) {
        $file = Get-Content -LiteralPath $EnrollmentFile -Raw | ConvertFrom-Json
        if ($file.version -ne 1 -or -not $file.server_ca) { throw 'Use enrollment.json from an installer of a server with its own CA (console agents need an explicit CA).' }
        $Server, $DeviceServer, $tokenText = $file.server_url, $file.device_url, $file.token
        $caFile = Join-Path ([IO.Path]::GetTempPath()) ('openrmm-ca-' + [Guid]::NewGuid().ToString('N') + '.pem')
        Set-Content -LiteralPath $caFile -Value $file.server_ca -NoNewline
        $CA = $caFile
    } else {
        $privateToken = Read-Host 'Paste the one-time enrollment token' -AsSecureString
        $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($privateToken)
        $tokenText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $binary
    $startInfo.WorkingDirectory = $projectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-enroll','-server',$Server,'-device-server',$DeviceServer,'-ca',$CA,'-state',$State)) { $startInfo.ArgumentList.Add($argument) }
    $agentProcess.StartInfo = $startInfo
    [void]$agentProcess.Start()
    $outputTask = $agentProcess.StandardOutput.ReadToEndAsync()
    $errorTask = $agentProcess.StandardError.ReadToEndAsync()
    $agentProcess.StandardInput.WriteLine((@{token=$tokenText} | ConvertTo-Json -Compress))
    $agentProcess.StandardInput.Close()
    $tokenText = $null
    if (-not $agentProcess.WaitForExit(20000)) { $agentProcess.Kill($true); throw 'Enrollment timed out. Retain the state directory and check the device list before recovery.' }
    $outputTask.GetAwaiter().GetResult() | Out-Null
    $resultText = $errorTask.GetAwaiter().GetResult()
    if ($agentProcess.ExitCode -ne 0) {
        $reason = 'Enrollment failed. Retain the state directory and check the device list before recovery.'
        try { $record = (($resultText.Trim() -split "`n")[-1] | ConvertFrom-Json); if ($record.reason -is [string] -and $record.reason.Length -lt 400) { $reason=$record.reason } } catch { }
        throw $reason
    }
    Write-Host 'Device enrolled. Refresh Devices in OpenRMM to see its identity.'
    Write-Host 'Use openrmm-agent.exe -connect with the same -state path to verify its saved credentials.'
}
finally {
    $tokenText = $null
    if ($tokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
    if ($null -ne $privateToken) { $privateToken.Dispose() }
    if ($caFile) { Remove-Item -LiteralPath $caFile -ErrorAction SilentlyContinue }
    $agentProcess.Dispose()
}
