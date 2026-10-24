[CmdletBinding()]
param(
    [ValidateSet('start', 'stop', 'status', 'configure')]
    [string]$Action = 'status',
    [ValidateSet('true', 'false')][string]$InventoryMode,
    [ValidateSet('true', 'false')][string]$DiskSpaceMode,
    [ValidateSet('true', 'false')][string]$MemoryMode,
    [ValidateSet('true', 'false')][string]$CPUMode,
    [ValidateSet('true', 'false')][string]$UptimeMode,
    [ValidateSet('true', 'false')][string]$ServicesMode,
    [ValidateSet('true','false')][string]$EventLogsMode,
    [ValidateSet('true','false')][string]$WindowsUpdatesMode,
    [ValidateSet('true','false')][string]$SoftwareMode,
    [ValidateSet('true','false')][string]$SessionsMode,
    [ValidateSet('true','false')][string]$LocalAccountsMode,
    [ValidateSet('true','false')][string]$ResponseMode,
    [ValidateSet('true','false')][string]$ProcessesMode,
    [ValidateSet('true','false')][string]$ScriptsMode,
    [ValidateSet('true','false')][string]$DesktopMode,
    [ValidateSet('true','false')][string]$TerminalMode,
    [ValidateSet('true','false')][string]$FilesMode
)

# The agent is installed, updated and removed by its MSI (scripts/install-agent.ps1,
# self-update, or Programs and Features). Features are switched on and off per
# monitoring policy in the server UI. This script starts, stops and
# reports the OpenRMMAgent service and sets local locks: '-<Feature>Mode false'
# locks a feature off on this device whatever its policy says; 'true' removes
# the lock. Locks are machine policy values under
# HKLM\SOFTWARE\Policies\OpenRMM\Agent (also settable by Group Policy), so they
# survive MSI upgrades. The agent applies them when the service restarts.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows service management requires Windows.' }
$serviceName = 'OpenRMMAgent'
$policyKey = 'HKLM:\SOFTWARE\Policies\OpenRMM\Agent'
$features = [ordered]@{InventoryMode='inventory';DiskSpaceMode='disk_space';MemoryMode='memory';CPUMode='cpu';UptimeMode='uptime';ServicesMode='services';EventLogsMode='event_logs';WindowsUpdatesMode='windows_updates';SoftwareMode='software';SessionsMode='sessions';LocalAccountsMode='local_accounts';ResponseMode='response';ProcessesMode='processes';ScriptsMode='scripts';DesktopMode='desktop';TerminalMode='terminal';FilesMode='files'}
$requested = @($features.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) })
if ($requested.Count -gt 0 -and $Action -ne 'configure') { throw 'Feature settings are only valid with configure.' }

function Get-Locks {
    if (-not (Test-Path -LiteralPath $policyKey)) { return @() }
    $values = Get-ItemProperty -LiteralPath $policyKey
    return @($features.Values | Where-Object { $null -ne $values.PSObject.Properties[$_] -and [int]$values.$_ -eq 0 })
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($Action -eq 'status') {
    if ($null -eq $service) { Write-Output 'OpenRMM agent service is not installed.' } else { $service | Select-Object Name, Status, StartType }
    $locks = @(Get-Locks)
    Write-Output ('Local feature locks: ' + $(if ($locks.Count) { $locks -join ', ' } else { 'none' }))
    return
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open an administrator PowerShell to manage the agent. No changes were made.' }
if ($null -eq $service) { throw 'OpenRMMAgent is not installed; run scripts/install-agent.ps1.' }

switch ($Action) {
    'start' {
        Start-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
        Write-Output 'OpenRMM agent service started.'
    }
    'stop' {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -ErrorAction Stop
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        Write-Output 'OpenRMM agent service stopped; credentials were retained.'
    }
    'configure' {
        if ($requested.Count -eq 0) { throw 'Name at least one feature, for example -TerminalMode false.' }
        if (-not (Test-Path -LiteralPath $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
        foreach ($name in $requested) {
            $feature = $features[$name]
            if ($PSBoundParameters[$name] -eq 'false') {
                New-ItemProperty -LiteralPath $policyKey -Name $feature -PropertyType DWord -Value 0 -Force | Out-Null
            } elseif ($null -ne (Get-ItemProperty -LiteralPath $policyKey).PSObject.Properties[$feature]) {
                Remove-ItemProperty -LiteralPath $policyKey -Name $feature
            }
        }
        if ((Get-Service -Name $serviceName).Status -eq 'Running') {
            Restart-Service -Name $serviceName
            (Get-Service -Name $serviceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
        }
        $locks = @(Get-Locks)
        Write-Output ('Local feature locks: ' + $(if ($locks.Count) { $locks -join ', ' } else { 'none' }) + '. A running service was restarted to apply them.')
    }
}
