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

    REFERENCES (flagged events; community Q&A pages were not counted as verification)
    - Reboot causes (1074, 41, 6008, 6005, Kernel-General 12/13, WER bugcheck 1001,
      WindowsUpdateClient 19):
      https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    - Kernel-Power 41 and 6006: https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart
    - SCM 7031: https://learn.microsoft.com/troubleshoot/exchange/administration/frontend-transport-service-terminate-run-set-servercomponentstate
    - SCM 7034: https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/error-1053-1067-7034-after-update-openssh-doesnt-start
    - SCM 7024: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/netlogon-service-not-start-event-2112-7024
    - SCM 7000/7011: https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error
    - Disk 51: https://learn.microsoft.com/troubleshoot/windows-server/backup-and-storage/event-id-51-information
    - Controller error 11 (logged under the controller driver's name):
      https://learn.microsoft.com/troubleshoot/windows-server/performance/support-for-booting-from-storage-area-network
    - Disk 153, storport reset 129, NTFS 55/98:
      https://learn.microsoft.com/troubleshoot/windows-server/backup-and-storage/troubleshoot-data-corruption-and-disk-errors
    - Application Error 1000, WER 1001: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-application-service-crashing-behavior
    - Application Hang 1002: https://learn.microsoft.com/azure/azure-local/manage/disconnected-operations-security
    - Kernel-General 1 (time changed): https://learn.microsoft.com/troubleshoot/windows-server/active-directory/w32time-event-142-time-service-stopped-advertising
    - Time-Service 129/134: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/error-message-run-w32tm-resync-no-time-data-available
    - Resource-Exhaustion-Detector 2004: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-application-service-memory-leaks
    - Not flagged because no Microsoft page confirmed them: SCM 7023/7009, Disk 7, Ntfs 137,
      volmgr 161, WindowsUpdateClient 20/43, Time-Service 36.
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

# Known-important events: labelled so the eye finds them, never used to hide anything.
# Keyed on log + provider + ID (the same ID means different things from different providers).
# Providers are -like patterns. Every entry is cited in .NOTES REFERENCES above.
$script:FlagCatalog = @(
    @{ Log = 'System'; Providers = @('User32'); Id = 1074; Category = 'Restart'; Label = 'Restart or shutdown requested' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Kernel-Power'); Id = 41; Category = 'Restart'; Label = 'Restarted without a clean shutdown (crash or power loss)' }
    @{ Log = 'System'; Providers = @('EventLog'); Id = 6008; Category = 'Restart'; Label = 'Previous shutdown was unexpected' }
    @{ Log = 'System'; Providers = @('EventLog'); Id = 6005; Category = 'Restart'; Label = 'Windows started (event log service started)' }
    @{ Log = 'System'; Providers = @('EventLog'); Id = 6006; Category = 'Restart'; Label = 'Windows shut down cleanly' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Kernel-General'); Id = 12; Category = 'Restart'; Label = 'Windows started' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Kernel-General'); Id = 13; Category = 'Restart'; Label = 'Windows shut down' }
    @{ Log = 'System'; Providers = @('Service Control Manager'); Id = 7031; Category = 'ServiceCrash'; Label = 'Service crashed (recovery action scheduled)' }
    @{ Log = 'System'; Providers = @('Service Control Manager'); Id = 7034; Category = 'ServiceCrash'; Label = 'Service stopped unexpectedly' }
    @{ Log = 'System'; Providers = @('Service Control Manager'); Id = 7024; Category = 'ServiceCrash'; Label = 'Service stopped with an error' }
    @{ Log = 'System'; Providers = @('Service Control Manager'); Id = 7000; Category = 'ServiceCrash'; Label = 'Service failed to start' }
    @{ Log = 'System'; Providers = @('Service Control Manager'); Id = 7011; Category = 'ServiceCrash'; Label = 'Service timed out responding' }
    @{ Log = 'System'; Providers = @('Disk'); Id = 51; Category = 'Disk'; Label = 'Disk error during a paging operation' }
    @{ Log = 'System'; Providers = @('Disk'); Id = 153; Category = 'Disk'; Label = 'Disk I/O had to be retried' }
    # 11 and 129 are logged under the storage controller driver's own name (stornvme,
    # storahci, storvsc, iaStorA...), not under "disk".
    @{ Log = 'System'; Providers = @('stor*', 'iaStor*'); Id = 11; Category = 'Disk'; Label = 'Disk controller error' }
    @{ Log = 'System'; Providers = @('stor*', 'iaStor*'); Id = 129; Category = 'Disk'; Label = 'Storage reset after a request timed out' }
    @{ Log = 'System'; Providers = @('Ntfs', 'Microsoft-Windows-Ntfs'); Id = 55; Category = 'Disk'; Label = 'File system corruption found (run chkdsk)' }
    @{ Log = 'System'; Providers = @('Ntfs', 'Microsoft-Windows-Ntfs'); Id = 98; Category = 'Disk'; Label = 'Volume needs an offline chkdsk' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-WindowsUpdateClient'); Id = 19; Category = 'Update'; Label = 'Windows Update installed an update' }
    @{ Log = 'Application'; Providers = @('Application Error'); Id = 1000; Category = 'AppCrash'; Label = 'Application crashed' }
    @{ Log = 'Application'; Providers = @('Windows Error Reporting'); Id = 1001; Category = 'AppCrash'; Label = 'Crash report recorded' }
    @{ Log = 'Application'; Providers = @('Application Hang'); Id = 1002; Category = 'AppCrash'; Label = 'Application stopped responding' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-WER-SystemErrorReporting'); Id = 1001; Category = 'Bugcheck'; Label = 'Restarted after a blue screen (bugcheck)' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Kernel-General'); Id = 1; Category = 'TimeJump'; Label = 'System time was changed' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Time-Service'); Id = 129; Category = 'TimeJump'; Label = 'No domain time source could be found' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Time-Service'); Id = 134; Category = 'TimeJump'; Label = 'Time server name lookup failed' }
    @{ Log = 'System'; Providers = @('Microsoft-Windows-Resource-Exhaustion-Detector'); Id = 2004; Category = 'LowMemory'; Label = 'Windows ran low on memory' }
)

$script:LevelNames = @{ 0 = 'Information'; 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning'; 4 = 'Information'; 5 = 'Verbose' }

function Get-EventFlag {
    <# The flag for one event, or $null. #>
    [CmdletBinding()]
    param([string]$Log, [string]$Provider, [int]$Id)

    foreach ($entry in $script:FlagCatalog) {
        if ($entry.Id -ne $Id -or $entry.Log -ne $Log) { continue }
        foreach ($pattern in $entry.Providers) {
            if ($Provider -like $pattern) { return [PSCustomObject]@{ Category = $entry.Category; Label = $entry.Label } }
        }
    }
    return $null
}

function ConvertTo-TimelineRow {
    <#
        One timeline row from one projected remote event (TimeCreatedUtc, Id, ProviderName,
        Level, LogName, Message, RecordId, UserSid, MachineName). Level is numeric because
        LevelDisplayName is localized on non-English servers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)]$Event,
        [int]$UtcOffsetMinutes = 0
    )

    $timeUtc = [datetime]::SpecifyKind([datetime]$Event.TimeCreatedUtc, [DateTimeKind]::Utc)
    $level = [int]$Event.Level
    $levelName = if ($script:LevelNames.ContainsKey($level)) { $script:LevelNames[$level] } else { "Level $level" }

    $message = [string]$Event.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        # The remote event log (RPC) path renders text with this workstation's provider files,
        # so events from software not installed here arrive without text.
        $message = "(No message text: the event's provider isn't installed on this workstation. Event $($Event.Id) from $($Event.ProviderName).)"
    }
    $firstLine = @($message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)[0].Trim()

    $flag = Get-EventFlag -Log $Event.LogName -Provider $Event.ProviderName -Id $Event.Id

    [PSCustomObject]@{
        Server           = $Server
        Log              = $Event.LogName
        TimeUtc          = $timeUtc
        TimeServerLocal  = [datetime]::SpecifyKind($timeUtc.AddMinutes($UtcOffsetMinutes), [DateTimeKind]::Unspecified)
        Level            = $level
        LevelName        = $levelName
        FlagCategory     = if ($flag) { $flag.Category } else { '' }
        Flag             = if ($flag) { $flag.Label } else { '' }
        Provider         = $Event.ProviderName
        EventId          = [int]$Event.Id
        Message          = $message
        MessageFirstLine = $firstLine
        RecordId         = $Event.RecordId
        User             = $Event.UserSid
        Machine          = $Event.MachineName
    }
}

function Merge-TimelineRows {
    <# All servers' rows in one order: UTC time, then server, then record ID. #>
    [CmdletBinding()]
    param([object[]]$Rows)
    @($Rows | Sort-Object -Property TimeUtc, Server, RecordId)
}
