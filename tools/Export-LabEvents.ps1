<#
.SYNOPSIS
  Export Sysmon (and optionally Security) events from this machine as JSON lines that
  pipeline.py can replay.

.EXAMPLE
  # Everything since 10:00 today into a benign dataset
  .\Export-LabEvents.ps1 -Since (Get-Date '10:00') -OutFile ..\datasets\benign\day1.jsonl

.NOTES
  Run in the lab VM as Administrator (the Security log needs admin rights).
  Each line is one event: Channel, EventID, TimeCreated, Computer, plus every EventData field.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$Since,
    [Parameter(Mandatory)][string]$OutFile,
    [switch]$IncludeSecurity
)

$logs = @('Microsoft-Windows-Sysmon/Operational')
if ($IncludeSecurity) { $logs += 'Security' }

$folder = Split-Path -Parent $OutFile
if ($folder) { New-Item -ItemType Directory -Force -Path $folder | Out-Null }

$lines = foreach ($log in $logs) {
    Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $Since } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $record = [ordered]@{
                Channel     = $_.LogName
                EventID     = $_.Id
                TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                Computer    = $_.MachineName
            }
            foreach ($field in $xml.Event.EventData.Data) {
                if ($field.Name) { $record[$field.Name] = [string]$field.'#text' }
            }
            $record | ConvertTo-Json -Compress -Depth 3
        }
}

$lines | Set-Content -Path $OutFile -Encoding UTF8
Write-Host ("Wrote {0} events to {1}" -f @($lines).Count, $OutFile)
