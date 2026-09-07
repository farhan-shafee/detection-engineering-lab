#requires -Version 5.1
<#
.SYNOPSIS
Read-only local channel and Wazuh service health summary; writes no evidence file.
.DESCRIPTION
Outputs only known channel names, availability, latest matching event ID/time,
and service status. No event messages, users, machine names, addresses, or command
lines are printed. This does not verify Wazuh ingestion or prove a detection.
#>
[CmdletBinding()]
param([ValidateRange(1, 1440)][int]$LookbackMinutes = 15)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Telemetry verification requires Windows.' }
$since = (Get-Date).AddMinutes(-$LookbackMinutes)
$channels = @(
    @{ Name = 'Security'; Ids = @(4624, 4625, 4732, 4698) },
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103, 4104) },
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1) },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1117, 5007) }
)
foreach ($channel in $channels) {
    $row = [ordered]@{
        Channel = $channel.Name
        Status = 'UnavailableOrAccessDenied'
        LatestEventId = $null
        LatestEventUtc = $null
    }
    try {
        $log = Get-WinEvent -ListLog $channel.Name -ErrorAction Stop
        if (-not $log.IsEnabled) {
            $row.Status = 'Disabled'
        } else {
            $row.Status = 'EnabledNoRecentMatchingEvent'
            try {
                $recent = Get-WinEvent -FilterHashtable @{
                    LogName = $channel.Name; Id = $channel.Ids; StartTime = $since
                } -MaxEvents 1 -ErrorAction Stop
                $row.Status = 'RecentMatchingEventPresent'
                $row.LatestEventId = $recent.Id
                $row.LatestEventUtc = $recent.TimeCreated.ToUniversalTime().ToString('o')
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                    $row.Status = 'EnabledQueryFailed'
                }
            }
        }
    } catch { }
    [pscustomobject]$row
}
$service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
$serviceStatus = if ($null -eq $service) { 'NotInstalled' } else { $service.Status.ToString() }
Write-Output "WazuhSvc: $serviceStatus"
Write-Output 'This is local source health only. Check enrollment, agent logs and dashboard searches separately.'
