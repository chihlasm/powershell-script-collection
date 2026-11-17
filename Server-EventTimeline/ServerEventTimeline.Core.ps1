#Requires -Version 5.1
<#
.SYNOPSIS
    Pure logic for Server Event Timeline: inputs, time windows, the log list, the flag
    catalog, timeline rows, filters, exports and failure wording.

.DESCRIPTION
    Dot-sourced by ServerEventTimeline.Engine.ps1, Start-ServerEventTimeline.ps1 and the tests.
    Nothing here touches the network, the UI or a real event log, so every function can be
    tested on its own.

.NOTES
    REFERENCES (log channel names)
    - Task Scheduler operational log (off by default; must be enabled):
      https://learn.microsoft.com/troubleshoot/mem/intune/device-protection/troubleshoot-bitlocker-policies#collecting-event-log-data
    - Remote Desktop LocalSessionManager / RemoteConnectionManager operational logs:
      https://learn.microsoft.com/troubleshoot/azure/virtual-machines/windows/troubleshoot-rds-instability-september-2026-windows-updates#how-to-identify-the-issue
    - SMB server operational log:
      https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-event-id-1020-warnings-file-server
    - SMB client operational log:
      https://learn.microsoft.com/azure/azure-local/manage/disconnected-operations-security#reference-message-schema-and-event-log
    - Group Policy operational log:
      https://learn.microsoft.com/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance#troubleshooting-checklist
    - Windows Time operational log:
      https://learn.microsoft.com/troubleshoot/windows-server/active-directory/sts-recommendations-for-windows-server
    - Failover Clustering operational log:
      https://learn.microsoft.com/windows-server/failover-clustering/bitlocker-on-csv-in-ws-2022#new-events
#>

function ConvertTo-ServerList {
    <# Turns whatever a tech pasted into a clean list of server names. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $list = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in ($Text -split '[,;\s]+')) {
        $name = $part.Trim()
        if ($name -and $seen.Add($name)) { $list.Add($name) }
    }
    return $list.ToArray()
}

function New-TimelineWindow {
    <#
        The time window the tech asked for. Around/Range times are server-local wall-clock
        (DateTimeKind.Unspecified): "03:00" means 03:00 on each server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Around', 'Range', 'Relative')][string]$Mode,
        [Nullable[datetime]]$At,
        [int]$PlusMinusMinutes = 15,
        [Nullable[datetime]]$From,
        [Nullable[datetime]]$To,
        [int]$LastMinutes = 60
    )

    $unspecified = { param($d) [datetime]::SpecifyKind($d, [DateTimeKind]::Unspecified) }

    switch ($Mode) {
        'Around' {
            if ($null -eq $At) { throw [ArgumentException]'Enter the time to look around.' }
            if ($PlusMinusMinutes -le 0) { throw [ArgumentException]'The plus/minus minutes must be more than 0.' }
            $center = & $unspecified $At
            return [PSCustomObject]@{
                Mode = 'Around'; StartLocal = $center.AddMinutes(-$PlusMinusMinutes)
                EndLocal = $center.AddMinutes($PlusMinusMinutes); LastMinutes = 0
            }
        }
        'Range' {
            if ($null -eq $From -or $null -eq $To) { throw [ArgumentException]'Enter both the From and To times.' }
            if ($From -ge $To) { throw [ArgumentException]'From must be before To.' }
            return [PSCustomObject]@{
                Mode = 'Range'; StartLocal = (& $unspecified $From)
                EndLocal = (& $unspecified $To); LastMinutes = 0
            }
        }
        'Relative' {
            if ($LastMinutes -le 0) { throw [ArgumentException]'The number of minutes must be more than 0.' }
            return [PSCustomObject]@{ Mode = 'Relative'; StartLocal = $null; EndLocal = $null; LastMinutes = $LastMinutes }
        }
    }
}

function ConvertTo-UtcWindow {
    <#
        One server's window in UTC. Around/Range: wall-clock minus that server's UTC offset
        (taken at the window start). Relative: counted back from now.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Window,
        [int]$UtcOffsetMinutes = 0,
        [Nullable[datetime]]$NowUtc
    )

    $utc = { param($d) [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }

    if ($Window.Mode -eq 'Relative') {
        $now = if ($null -ne $NowUtc) { $NowUtc } else { [datetime]::UtcNow }
        $now = & $utc $now
        return [PSCustomObject]@{ StartUtc = $now.AddMinutes(-$Window.LastMinutes); EndUtc = $now }
    }
    return [PSCustomObject]@{
        StartUtc = & $utc ($Window.StartLocal.AddMinutes(-$UtcOffsetMinutes))
        EndUtc   = & $utc ($Window.EndLocal.AddMinutes(-$UtcOffsetMinutes))
    }
}

function Get-TimelineLogCatalog {
    <#
        The logs offered as checkboxes. Every channel name is cited in .NOTES REFERENCES.
        Windows Update client operational and Hyper-V VMMS were in the design's starting list
        but could not be confirmed on Microsoft Learn, so they are left out (Windows Update
        installs still show up in the System log).
    #>
    [CmdletBinding()]
    param()

    $entry = { param($Name, $Label, $Default, $Group) [PSCustomObject]@{ Name = $Name; Label = $Label; Default = $Default; Group = $Group } }

    @(
        & $entry 'System'      'System'      $true 'Core'
        & $entry 'Application' 'Application' $true 'Core'
        & $entry 'Microsoft-Windows-TaskScheduler/Operational'                               'Task Scheduler'                 $true 'Operational'
        & $entry 'Microsoft-Windows-GroupPolicy/Operational'                                 'Group Policy'                   $true 'Operational'
        & $entry 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'        'Remote Desktop sessions'        $true 'Operational'
        & $entry 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'    'Remote Desktop connections'     $true 'Operational'
        & $entry 'Microsoft-Windows-SMBClient/Operational'                                   'File share client (SMB)'        $true 'Operational'
        & $entry 'Microsoft-Windows-SMBServer/Operational'                                   'File share server (SMB)'        $true 'Operational'
        & $entry 'Microsoft-Windows-Time-Service/Operational'                                'Windows Time'                   $true 'Operational'
        & $entry 'Microsoft-Windows-FailoverClustering/Operational'                          'Failover Clustering'            $true 'Operational'
        & $entry 'Security' 'Security (slow on DCs and file servers)' $false 'Security'
    )
}
