#requires -Version 5.1
<#
.SYNOPSIS
Preview a single harmless encoded PowerShell process; use -Execute to run it.
.DESCRIPTION
The payload only prints DETECTION-LAB-SAFE. This script creates no accounts,
tasks, files, network connections, or security-policy changes. Windows and
configured telemetry may persist ordinary process/script logs.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param([switch]$Execute)

$ErrorActionPreference = 'Stop'
$payload = "Write-Output 'DETECTION-LAB-SAFE'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
Write-Output 'Plan: launch one Windows PowerShell child process with a fixed benign payload.'
Write-Output "Decoded payload: $payload"
Write-Output "Encoded UTF-16LE payload: $encoded"
Write-Output 'Requires configured Sysmon Event 1 collection for DET-001; a printed marker is not proof of an alert.'
Write-Output 'No temporary resources to clean up. Generated audit records are deliberately retained.'

if (-not $Execute) {
    Write-Output 'Preview only. Run with -Execute to generate the process event.'
    return
}
if ($env:OS -ne 'Windows_NT') { throw 'Execution requires Windows.' }
$powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
    throw 'The expected Windows PowerShell executable was not found.'
}
if ($PSCmdlet.ShouldProcess('This Windows endpoint', 'Run the displayed benign encoded PowerShell payload')) {
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    & $powershellPath -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) { throw "Benign process returned exit code $LASTEXITCODE." }
    Write-Output "Activity started UTC: $startedUtc"
    Write-Output 'Execution finished. Verify endpoint channel and Wazuh ingestion separately.'
}
