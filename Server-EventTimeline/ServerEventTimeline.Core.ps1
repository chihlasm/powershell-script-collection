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
    - One unexpected restart writes both Kernel-Power 41 and EventLog 6008, and one start
      writes both EventLog 6005 and Kernel-General 12 (same reboot-causes page above), so
      the summary counts each pair once.
    - The story (ServerEventTimeline.Story.ps1) says when a server was back up, not when it
      went down: 41 and 6008 are written at the next start, and a blue screen's WER 1001 and a
      requested restart's 1074 belong to the same restart (same reboot-causes page above).

    The ticket note is built with CaseKit.ps1 (a copy of TicketNote\CaseKit.ps1; see the
    TicketNote README), which defines functions only.
#>

. (Join-Path $PSScriptRoot 'CaseKit.ps1')
# The server list (AD entries, suggestions, notes, file import, background lookups).
. (Join-Path $PSScriptRoot 'ServerEventTimeline.ServerList.ps1')
# "What happened": the story of the flagged events and the timeline picture's layout.
. (Join-Path $PSScriptRoot 'ServerEventTimeline.Story.ps1')
# The Excel workbook export (.xlsx writer, no Excel needed).
. (Join-Path $PSScriptRoot 'ServerEventTimeline.Workbook.ps1')

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

# The summary line above the grid and the ticket note count flagged events in plain words.
# Labels map to a summary kind; Max = several event IDs written for ONE happening (41 + 6008
# for one unexpected restart, 6005 + Kernel-General 12 for one start), so the kind's count is
# the largest per-ID count, not the sum. Kind = how the ticket note files it. Flags with no
# entry here (clean shutdowns, the WER report that follows every app crash) are not counted.
$script:SummaryKinds = @(
    @{ Key = 'UnexpectedRestart'; One = 'unexpected restart'; Many = 'unexpected restarts'; Max = $true; Kind = 'Problem'
        Labels = @('Restarted without a clean shutdown (crash or power loss)', 'Previous shutdown was unexpected')
        Next = 'Check power, the hypervisor host or the hardware logs for {0} around the unexpected restart.' }
    @{ Key = 'Bugcheck'; One = 'blue screen'; Many = 'blue screens'; Max = $false; Kind = 'Problem'
        Labels = @('Restarted after a blue screen (bugcheck)')
        Next = 'Collect the memory dump (C:\Windows\MEMORY.DMP or C:\Windows\Minidump) from {0} and analyse the blue screen.' }
    @{ Key = 'Disk'; One = 'disk error'; Many = 'disk errors'; Max = $false; Kind = 'Problem'
        Labels = @('Disk error during a paging operation', 'Disk I/O had to be retried', 'Disk controller error', 'Storage reset after a request timed out', 'File system corruption found (run chkdsk)', 'Volume needs an offline chkdsk')
        Next = 'Check the disk and storage health of {0} (hardware, SAN or hypervisor storage).' }
    @{ Key = 'ServiceFailure'; One = 'service failure'; Many = 'service failures'; Max = $false; Kind = 'Warning'
        Labels = @('Service crashed (recovery action scheduled)', 'Service stopped unexpectedly', 'Service stopped with an error', 'Service failed to start', 'Service timed out responding')
        Next = 'Check the failing services on {0}: each event names the service.' }
    @{ Key = 'AppCrash'; One = 'app crash or hang'; Many = 'app crashes or hangs'; Max = $false; Kind = 'Warning'
        Labels = @('Application crashed', 'Application stopped responding'); Next = '' }
    @{ Key = 'LowMemory'; One = 'low-memory warning'; Many = 'low-memory warnings'; Max = $false; Kind = 'Warning'
        Labels = @('Windows ran low on memory'); Next = 'Check memory use on {0}: the event names the processes using the most.' }
    @{ Key = 'TimeChange'; One = 'system time change'; Many = 'system time changes'; Max = $false; Kind = 'Warning'
        Labels = @('System time was changed'); Next = '' }
    @{ Key = 'TimeSync'; One = 'time sync problem'; Many = 'time sync problems'; Max = $false; Kind = 'Warning'
        Labels = @('No domain time source could be found', 'Time server name lookup failed'); Next = '' }
    @{ Key = 'Update'; One = 'update installed'; Many = 'updates installed'; Max = $false; Kind = 'Info'
        Labels = @('Windows Update installed an update'); Next = '' }
    @{ Key = 'RestartRequested'; One = 'restart or shutdown requested'; Many = 'restarts or shutdowns requested'; Max = $false; Kind = 'Info'
        Labels = @('Restart or shutdown requested'); Next = '' }
    @{ Key = 'Started'; One = 'Windows start'; Many = 'Windows starts'; Max = $true; Kind = 'Info'
        Labels = @('Windows started (event log service started)', 'Windows started'); Next = '' }
)
$script:SummaryKindByLabel = @{}
foreach ($k in $script:SummaryKinds) { foreach ($l in $k.Labels) { $script:SummaryKindByLabel[$l] = $k } }

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
        [Parameter(Mandatory)]$EventRecord,
        [int]$UtcOffsetMinutes = 0
    )

    $timeUtc = [datetime]::SpecifyKind([datetime]$EventRecord.TimeCreatedUtc, [DateTimeKind]::Utc)
    $level = [int]$EventRecord.Level
    $levelName = if ($script:LevelNames.ContainsKey($level)) { $script:LevelNames[$level] } else { "Level $level" }

    $message = [string]$EventRecord.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        # Over WinRM the text is rendered on the server; over the remote event log (RPC) it is
        # rendered with this workstation's provider files. Either side can lack them.
        $message = "(No message text: Windows couldn't render the message for event $($EventRecord.Id) from $($EventRecord.ProviderName). Over the remote event log route this is normal when that software isn't installed on this workstation.)"
    }
    $firstLine = @($message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)[0].Trim()

    $flag = Get-EventFlag -Log $EventRecord.LogName -Provider $EventRecord.ProviderName -Id $EventRecord.Id

    [PSCustomObject]@{
        Server           = $Server
        Log              = $EventRecord.LogName
        TimeUtc          = $timeUtc
        TimeServerLocal  = [datetime]::SpecifyKind($timeUtc.AddMinutes($UtcOffsetMinutes), [DateTimeKind]::Unspecified)
        Level            = $level
        LevelName        = $levelName
        FlagCategory     = if ($flag) { $flag.Category } else { '' }
        Flag             = if ($flag) { $flag.Label } else { '' }
        Provider         = $EventRecord.ProviderName
        EventId          = [int]$EventRecord.Id
        Message          = $message
        MessageFirstLine = $firstLine
        RecordId         = $EventRecord.RecordId
        User             = $EventRecord.UserSid
        Machine          = $EventRecord.MachineName
    }
}

function Merge-TimelineRows {
    <# All servers' rows in one order: UTC time, then server, then record ID. #>
    [CmdletBinding()]
    param([object[]]$Rows)
    @($Rows | Sort-Object -Property TimeUtc, Server, RecordId)
}

$script:MinLevelSets = @{
    All      = $null
    Warning  = @(1, 2, 3)
    Error    = @(1, 2)
    Critical = @(1)
}

function Test-RowMatchesFilter {
    <#
        True when the row passes the grid's filters. Filter keys: MinLevel (All | Warning |
        Error | Critical), Server ('*' or a name), Log ('*' or a name), FlaggedOnly, Text
        (literal, case-insensitive, matched against message, provider and event ID),
        HiddenSources (provider names to hide), EventKey ('Provider|Id': only that event) and
        FromUtc / ToUtc (UTC datetimes, either may be $null: FromUtc <= TimeUtc < ToUtc).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][hashtable]$Filter)

    $levels = $script:MinLevelSets[[string]$Filter.MinLevel]
    if ($null -ne $levels -and $levels -notcontains [int]$Row.Level) { return $false }
    if ($Filter.Server -and $Filter.Server -ne '*' -and $Row.Server -ne $Filter.Server) { return $false }
    if ($Filter.Log -and $Filter.Log -ne '*' -and $Row.Log -ne $Filter.Log) { return $false }
    if ($Filter.FlaggedOnly -and -not $Row.Flag) { return $false }
    if (@($Filter.HiddenSources) -contains [string]$Row.Provider) { return $false }
    if ($Filter.EventKey -and (Get-TimelineEventKey -Row $Row) -ne $Filter.EventKey) { return $false }
    if ($null -ne $Filter.FromUtc -and [datetime]$Row.TimeUtc -lt [datetime]$Filter.FromUtc) { return $false }
    if ($null -ne $Filter.ToUtc -and [datetime]$Row.TimeUtc -ge [datetime]$Filter.ToUtc) { return $false }

    $text = [string]$Filter.Text
    if ($text) {
        $hay = '{0}|{1}|{2}' -f $Row.EventId, $Row.Provider, $Row.Message
        if ($hay.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }
    return $true
}

function ConvertTo-TimelineText {
    <# Plain text lines for pasting into a ticket note. #>
    [CmdletBinding()]
    param([object[]]$Rows)

    $lines = foreach ($r in $Rows) {
        '{0} (server local) | {1} | {2} | {3} | {4} | {5}' -f $r.TimeServerLocal.ToString('yyyy-MM-dd HH:mm:ss'),
            $r.Server, $r.LevelName, $r.Provider, $r.EventId, $r.MessageFirstLine
    }
    return ($lines -join [Environment]::NewLine)
}

function Export-TimelineCsv {
    <# The visible rows as CSV, with both the server-local and UTC times. #>
    [CmdletBinding()]
    param([object[]]$Rows, [Parameter(Mandatory)][string]$Path)

    $Rows | ForEach-Object {
        [PSCustomObject]@{
            TimeServerLocal = $_.TimeServerLocal.ToString('yyyy-MM-dd HH:mm:ss')
            TimeUtc         = $_.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            Server          = $_.Server
            Log             = $_.Log
            Level           = $_.LevelName
            Flag            = $_.Flag
            Provider        = $_.Provider
            EventId         = $_.EventId
            Message         = $_.Message
            RecordId        = $_.RecordId
            User            = $_.User
            Machine         = $_.Machine
        }
    } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function ConvertTo-TimelineHtml {
    <#
        A self-contained HTML report: what was asked, how each server went (failures, caps,
        timeouts, skipped logs), then the rows. Every piece of text is HTML-encoded.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Context,
        # Every row of the search when -Rows is a filtered list: quiet gaps before a restart are
        # measured from these, so a filter can't make the report claim a longer silence.
        [object[]]$ContextRows
    )

    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.Append(@'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Server Event Timeline</title>
<style>
:root{--bg:#14171c;--panel:#1c2027;--text:#e6e8eb;--muted:#9aa3ad;--line:#2c323b;--accent:#5dade2;--err:#e5534b;--warn:#d4a72c}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--panel:#fff;--text:#1d232b;--muted:#5c6773;--line:#dde1e6;--accent:#1f78b4;--err:#c8312b;--warn:#9a6b00}}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px;color:var(--accent)}
.meta{color:var(--muted)}table{border-collapse:collapse;width:100%;background:var(--panel)}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}.l1,.l2{color:var(--err)}.l3{color:var(--warn)}
.flag{color:var(--accent);font-weight:600}td.msg{white-space:pre-wrap;word-break:break-word}
svg.strip{display:block;background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:6px 0;max-width:1100px}ul.story{list-style:none;padding:0;margin:0}ul.story li{padding:4px 0;border-bottom:1px solid var(--line)}ul.story li.gap{color:var(--muted);font-size:12px;padding-left:24px;border:none}.when{color:var(--muted)}
</style></head><body>
<h1>Server Event Timeline</h1>
'@)
    [void]$sb.AppendFormat('<p class="meta">{0}<br>Servers: {1}<br>Logs: {2}<br>Filters: {3}<br>Made {4}</p>',
        (& $e $Context.WindowText), (& $e (@($Context.Servers) -join ', ')), (& $e (@($Context.Logs) -join ', ')),
        (& $e $Context.FiltersText), (& $e ([datetime]$Context.GeneratedAt).ToString('yyyy-MM-dd HH:mm:ss')))

    if (@($Context.Summary).Count -gt 0) {
        # The verdict first: what was found on each server, in plain words.
        [void]$sb.Append('<h2>What was found</h2><ul>')
        foreach ($line in @($Context.Summary)) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $line)) }
        [void]$sb.Append('</ul>')
    }
    # The picture: each server's flagged events and errors over the search window (or, when
    # the caller gives no window, the time the rows cover).
    $start = $Context.StartUtc; $end = $Context.EndUtc
    $all = @($Rows)
    if (($null -eq $start -or $null -eq $end) -and $all.Count -gt 0) {
        $times = @($all | ForEach-Object { [datetime]$_.TimeUtc } | Sort-Object)
        $start = $times[0]; $end = $times[-1]
        if ($end -le $start) { $start = $start.AddMinutes(-5); $end = $end.AddMinutes(5) }
    }
    if ($null -ne $start -and $null -ne $end -and @($Context.Servers).Count -gt 0) {
        $model = Get-TimelineStripModel -Rows $all -Servers @($Context.Servers) -StartUtc $start -EndUtc $end -Width 900 `
            -ContextRows $ContextRows -UtcOffsets (Get-TimelineServerOffsets -Status @($Context.ServerOutcomes))
        [void]$sb.Append('<h2>Timeline</h2>')
        [void]$sb.Append((ConvertTo-TimelineStripSvg -Model $model -Width 900))
    }
    # What happened, in order, from the same rows the report lists.
    [void]$sb.Append((ConvertTo-TimelineStoryHtml -Story (Get-TimelineStory -Rows $Rows -ContextRows $ContextRows)))

    [void]$sb.Append('<h2>How each server went</h2><table><tr><th>Server</th><th>Result</th><th>Details</th></tr>')
    foreach ($o in @($Context.ServerOutcomes)) {
        $details = New-Object System.Collections.Generic.List[string]
        if ($o.Reason) { $details.Add([string]$o.Reason) }
        if ($o.Transport) { $details.Add("Read via $($o.Transport)") }
        foreach ($l in @($o.Logs | Where-Object { $_.Outcome -ne 'Read' })) {
            $details.Add(('{0}: {1} {2}' -f $l.Log, $l.Outcome, $l.Reason).Trim())
        }
        [void]$sb.AppendFormat('<tr><td>{0}</td><td>{1} ({2} events)</td><td>{3}</td></tr>',
            (& $e $o.Server), (& $e $o.State), (& $e $o.EventCount), ((@($details) | ForEach-Object { & $e $_ }) -join '<br>'))
    }
    [void]$sb.Append('</table>')

    [void]$sb.AppendFormat('<h2>Events ({0})</h2><table><tr><th>Time (server local)</th><th>UTC</th><th>Server</th><th>Log</th><th>Level</th><th>Flag</th><th>Source</th><th>ID</th><th>Message</th></tr>', @($Rows).Count)
    foreach ($r in $Rows) {
        [void]$sb.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="l{4}">{5}</td><td class="flag">{6}</td><td>{7}</td><td>{8}</td><td class="msg">{9}</td></tr>',
            $r.TimeServerLocal.ToString('yyyy-MM-dd HH:mm:ss'), $r.TimeUtc.ToString('yyyy-MM-dd HH:mm:ss'), (& $e $r.Server), (& $e $r.Log),
            [int]$r.Level, (& $e $r.LevelName), (& $e $r.Flag), (& $e $r.Provider), (& $e $r.EventId), (& $e $r.Message))
    }
    [void]$sb.Append('</table></body></html>')
    return $sb.ToString()
}

function Get-RemoteFailureKind {
    <#
        AccessDenied, Connection or Other. Connection failures are the only ones worth retrying
        over the remote event log (RPC); access denied would be denied there too.
        Codes: ERROR_ACCESS_DENIED = 5, RPC_S_SERVER_UNAVAILABLE = 1722 (0x6BA),
        RPC_S_CALL_FAILED_DNE = 1727 (0x6BF).
        https://learn.microsoft.com/troubleshoot/entra/entra-id/user-prov-sync/rpc-errors-affecting-aadconnect
        https://learn.microsoft.com/troubleshoot/windows-server/active-directory/status-code-0x6ba-rpc-server-unavailable
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $ex = $ErrorRecord.Exception
    $chain = @()
    while ($ex) { $chain += $ex; $ex = $ex.InnerException }

    $accessHResult = [int]0x80070005
    $rpcHResults = @([int]0x800706BA, [int]0x800706BF)

    foreach ($x in $chain) {
        if ($x -is [UnauthorizedAccessException] -or $x.HResult -eq $accessHResult) { return 'AccessDenied' }
        if ($x -is [System.Management.Automation.Remoting.PSRemotingTransportException] -and $x.ErrorCode -eq 5) { return 'AccessDenied' }
    }
    if ($ErrorRecord.FullyQualifiedErrorId -like '*AccessDenied*') { return 'AccessDenied' }

    foreach ($x in $chain) {
        if ($x -is [System.Management.Automation.Remoting.PSRemotingTransportException]) { return 'Connection' }
        if ($rpcHResults -contains $x.HResult) { return 'Connection' }
        if ($x -is [System.Net.Sockets.SocketException]) { return 'Connection' }
    }
    return 'Other'
}

function Get-FailureText {
    <# Plain-English failure wording with the next step. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('AccessDenied', 'Connection', 'Other', 'Unreachable', 'TimedOut')][string]$Kind,
        [Parameter(Mandatory)][string]$Server,
        [string]$Detail
    )

    switch ($Kind) {
        'AccessDenied' { "Access denied on ${Server}: check you're an admin there, or use Run as." }
        'Connection'   { "Couldn't connect to ${Server}" + $(if ($Detail) { ": $Detail" } else { '.' }) }
        'Unreachable'  { 'WinRM and remote event log are both unreachable from here.' }
        'TimedOut'     { "${Server} didn't answer in time." }
        default        { "Something went wrong reading ${Server}" + $(if ($Detail) { ": $Detail" } else { '.' }) }
    }
}

$script:SortKeysItems = [Array].GetMethod('Sort', [type[]]@([Array], [Array]))

function New-TimelineRowStore {
    <#
        The window's rows, kept in UTC order, with a parallel key list and the log names seen.
        Notable (with NotableKeys) holds just the flagged and Error/Critical rows, in the same
        order: the timeline picture is drawn from those, so it never walks every row.
    #>
    [PSCustomObject]@{
        # ::new(), not New-Object: a List[object] made with New-Object breaks @() on PS 5.1 and 7.
        Rows = [System.Collections.Generic.List[object]]::new()
        Keys = [System.Collections.Generic.List[long]]::new()
        Logs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        Notable = [System.Collections.Generic.List[object]]::new()
        NotableKeys = [System.Collections.Generic.List[long]]::new()
    }
}

function Add-TimelineRows {
    <#
        Adds a batch to the store and keeps it in UTC order. Only the new rows are touched in
        PowerShell; the re-sort is a native Array.Sort on tick keys, so a 5,000-row batch into
        100,000 rows takes milliseconds instead of a full Sort-Object on the window thread.
        Rows with the exact same tick keep no particular order between them.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Store, [object[]]$NewRows)
    if (-not $NewRows -or $NewRows.Count -eq 0) { return }
    $notable = 0
    foreach ($r in $NewRows) {
        $ticks = ([datetime]$r.TimeUtc).Ticks
        $Store.Rows.Add($r)
        $Store.Keys.Add($ticks)
        [void]$Store.Logs.Add([string]$r.Log)
        if ($r.Flag -or $r.Level -eq 1 -or $r.Level -eq 2) { $Store.Notable.Add($r); $Store.NotableKeys.Add($ticks); $notable++ }
    }
    if ($notable -gt 0) {
        $nKeys = $Store.NotableKeys.ToArray()
        $nItems = $Store.Notable.ToArray()
        $script:SortKeysItems.Invoke($null, @($nKeys, $nItems)) | Out-Null
        $Store.NotableKeys.Clear(); $Store.NotableKeys.AddRange($nKeys)
        $Store.Notable.Clear(); $Store.Notable.AddRange($nItems)
    }
    $keys = $Store.Keys.ToArray()
    $items = $Store.Rows.ToArray()
    # Called through reflection: PowerShell binds [Array]::Sort($keys, $items) to the wrong
    # overload and leaves the rows unsorted.
    $script:SortKeysItems.Invoke($null, @($keys, $items)) | Out-Null
    $Store.Keys.Clear(); $Store.Keys.AddRange($keys)
    $Store.Rows.Clear(); $Store.Rows.AddRange($items)
}

function Select-TimelineRows {
    <#
        The rows that pass the filter: same rules as Test-RowMatchesFilter, in one inline loop
        (a function call per row is too slow for 50,000 rows in the window).
    #>
    [CmdletBinding()]
    param([object[]]$Rows, [Parameter(Mandatory)][hashtable]$Filter)

    $levels = $script:MinLevelSets[[string]$Filter.MinLevel]
    $server = if ($Filter.Server -and $Filter.Server -ne '*') { [string]$Filter.Server } else { $null }
    $log = if ($Filter.Log -and $Filter.Log -ne '*') { [string]$Filter.Log } else { $null }
    $flagged = [bool]$Filter.FlaggedOnly
    $text = [string]$Filter.Text
    $cmp = [StringComparison]::OrdinalIgnoreCase
    $hidden = $null
    if (@($Filter.HiddenSources | Where-Object { $_ }).Count -gt 0) {
        $hidden = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($h in @($Filter.HiddenSources)) { [void]$hidden.Add([string]$h) }
    }
    $eventKey = [string]$Filter.EventKey
    # The time range as ticks, so the loop compares numbers.
    $fromTicks = if ($null -ne $Filter.FromUtc) { ([datetime]$Filter.FromUtc).Ticks } else { [long]::MinValue }
    $toTicks = if ($null -ne $Filter.ToUtc) { ([datetime]$Filter.ToUtc).Ticks } else { [long]::MaxValue }
    $ranged = $null -ne $Filter.FromUtc -or $null -ne $Filter.ToUtc

    if ($null -eq $levels -and -not $server -and -not $log -and -not $flagged -and -not $text -and -not $hidden -and -not $eventKey -and -not $ranged) { return @($Rows) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($ranged) {
            $ticks = ([datetime]$r.TimeUtc).Ticks
            if ($ticks -lt $fromTicks -or $ticks -ge $toTicks) { continue }
        }
        if ($null -ne $levels -and $levels -notcontains [int]$r.Level) { continue }
        if ($server -and $r.Server -ne $server) { continue }
        if ($log -and $r.Log -ne $log) { continue }
        if ($flagged -and -not $r.Flag) { continue }
        if ($hidden -and $hidden.Contains([string]$r.Provider)) { continue }
        if ($eventKey -and ('{0}|{1}' -f $r.Provider, $r.EventId) -ne $eventKey) { continue }
        if ($text -and ('{0}|{1}|{2}' -f $r.EventId, $r.Provider, $r.Message).IndexOf($text, $cmp) -lt 0) { continue }
        $out.Add($r)
    }
    return $out.ToArray()
}

function Get-LocalComputerIdentity {
    <# This computer's name and DNS domain (read locally, no network lookup). #>
    [PSCustomObject]@{
        Name       = $env:COMPUTERNAME
        DomainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
    }
}

function Get-LocalComputerNames {
    <# Every name that means this computer. The first one is the name shown in the list. #>
    [CmdletBinding()]
    param()
    $id = Get-LocalComputerIdentity
    $names = New-Object System.Collections.Generic.List[string]
    $names.Add([string]$id.Name)
    if ($id.DomainName) { $names.Add(('{0}.{1}' -f $id.Name, $id.DomainName).ToLowerInvariant()) }
    foreach ($n in 'localhost', '.', '127.0.0.1', '::1') { $names.Add($n) }
    return $names.ToArray()
}

function Test-IsLocalComputer {
    <# True when the name means this computer, so its logs can be read directly. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [string[]]$LocalNames)
    if (-not $LocalNames) { $LocalNames = @(Get-LocalComputerNames) }
    foreach ($n in $LocalNames) { if ([string]::Equals($Name.Trim(), $n, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

function ConvertFrom-TimelineInputs {
    <#
        Reads what the tech typed into a search request, or a plain message saying what to fix.
        Dates are read as yyyy-MM-dd HH:mm (seconds optional), then in the workstation's format.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$ServersText,
        [ValidateSet('Around', 'Range', 'Relative')][string]$Mode = 'Around',
        [string]$AtText, [int]$PlusMinusMinutes = 15,
        [string]$FromText, [string]$ToText,
        [int]$LastMinutes = 60,
        [string]$CapText = '5000', [string]$TimeoutText = '60', [string]$TotalCapText = '50000'
    )

    $fail = { param($m) [PSCustomObject]@{ Ok = $false; Message = $m; Servers = @(); Window = $null; Cap = 0; TimeoutSec = 0; TotalCap = 0 } }
    $readDate = {
        param($text)
        $d = [datetime]::MinValue
        $formats = [string[]]@('yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm', 'yyyy-MM-ddTHH:mm:ss')
        if ([datetime]::TryParseExact(([string]$text).Trim(), $formats, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
        if ([datetime]::TryParse(([string]$text).Trim(), [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
        return $null
    }

    $servers = @(ConvertTo-ServerList -Text $ServersText)
    if ($servers.Count -eq 0) { return (& $fail 'Enter at least one server name.') }
    # localhost, ., 127.0.0.1 and this computer's FQDN all become its own name, once.
    $localNames = @(Get-LocalComputerNames)
    $servers = @(ConvertTo-ServerList -Text ((@($servers | ForEach-Object {
                        if (Test-IsLocalComputer -Name $_ -LocalNames $localNames) { $localNames[0] } else { $_ }
                    })) -join ','))

    $cap = 0; $timeout = 0
    if (-not [int]::TryParse($CapText, [ref]$cap) -or $cap -le 0) { return (& $fail 'The number of events per log must be a whole number above 0.') }
    if (-not [int]::TryParse($TimeoutText, [ref]$timeout) -or $timeout -le 0) { return (& $fail 'The timeout must be a whole number of seconds above 0.') }
    $totalCap = 0
    if (-not [int]::TryParse($TotalCapText, [ref]$totalCap) -or $totalCap -le 0) { return (& $fail 'The total events per server must be a whole number above 0.') }

    try {
        switch ($Mode) {
            'Around' {
                $at = & $readDate $AtText
                if ($null -eq $at) { return (& $fail "Couldn't read the time. Type it as yyyy-MM-dd HH:mm, for example 2026-11-17 03:00.") }
                $window = New-TimelineWindow -Mode Around -At $at -PlusMinusMinutes $PlusMinusMinutes
            }
            'Range' {
                $from = & $readDate $FromText; $to = & $readDate $ToText
                if ($null -eq $from -or $null -eq $to) { return (& $fail "Couldn't read the From or To time. Type them as yyyy-MM-dd HH:mm.") }
                $window = New-TimelineWindow -Mode Range -From $from -To $to
            }
            'Relative' { $window = New-TimelineWindow -Mode Relative -LastMinutes $LastMinutes }
        }
    }
    catch { return (& $fail $_.Exception.Message) }

    [PSCustomObject]@{ Ok = $true; Message = ''; Servers = $servers; Window = $window; Cap = $cap; TimeoutSec = $timeout; TotalCap = $totalCap }
}

function Get-TimelineStatusLines {
    <# One plain line per server for the status list. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)

    foreach ($s in $Status.Values) {
        $via = switch ($s.Transport) { 'WinRM' { ' (via WinRM)' } 'RPC' { ' (via remote event log)' } 'Local' { ' (this computer, read directly)' } default { '' } }
        switch ($s.State) {
            'Waiting'      { "$($s.Server): waiting" }
            'Querying'     { "$($s.Server): reading...$via" }
            'Done'         { '{0}: done - {1:N0} events{2}{3}' -f $s.Server, $s.EventCount, $via, $(if ($s.Reason) { " - $($s.Reason)" }) }
            'DoneWithGaps' { '{0}: done with gaps - {1:N0} events{2}{3}' -f $s.Server, $s.EventCount, $via, $(if ($s.Reason) { " - $($s.Reason)" }) }
            'Unreachable'  { "$($s.Server): couldn't reach - $($s.Reason)" }
            'Cancelled'    { '{0}: cancelled - {1:N0} events kept' -f $s.Server, $s.EventCount }
            default        { "$($s.Server): $($s.State)" }
        }
    }
}

function Get-TimelineBannerText {
    <#
        The yellow banner: every log whose events are incomplete (capped, timed out, failed,
        not read), so a short log is never mistaken for a quiet one. Skipped logs (missing or
        turned off) are listed in the report, not the banner.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)

    $lines = foreach ($s in $Status.Values) {
        foreach ($l in @($s.Logs)) {
            switch ($l.Outcome) {
                'Capped'   { '{0} {1}: {2} - narrow the window or raise the cap' -f $s.Server, $l.Log, $l.Reason }
                'TimedOut' { '{0} {1}: {2} - try a shorter window or a longer timeout' -f $s.Server, $l.Log, $l.Reason }
                'Failed'   { '{0} {1}: could not be read - {2}' -f $s.Server, $l.Log, $l.Reason }
                'NotRead'  { '{0} {1}: not read - {2}' -f $s.Server, $l.Log, $l.Reason }
            }
        }
    }
    return (@($lines) -join [Environment]::NewLine)
}

function Get-TimelineTimeZoneNote {
    <# A note when the reached servers are in different time zones, else $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)

    $offsets = @($Status.Values | Where-Object { $_.Transport } | ForEach-Object { [int]$_.UtcOffsetMinutes } | Select-Object -Unique)
    if ($offsets.Count -gt 1) {
        return 'These servers are in different time zones, so their local times are not directly comparable: compare the UTC column across them.'
    }
    return $null
}

function Get-LogSelectionSummary {
    <# The text on the closed logs dropdown, e.g. "System, Application + 8 more". #>
    [CmdletBinding()]
    param([string[]]$Labels, [switch]$AllLogs)
    $picked = @($Labels | Where-Object { $_ })
    if ($picked.Count -eq 0) { if ($AllLogs) { return 'All logs with events' }; return 'No logs selected' }
    $text = if ($picked.Count -le 2) { $picked -join ', ' } else { '{0}, {1} + {2} more' -f $picked[0], $picked[1], ($picked.Count - 2) }
    if ($AllLogs) { $text += ' + all logs with events' }
    return $text
}

function Get-TimelineSettingsPath {
    <# Per-user settings (the remembered save folder). Nothing is stored beside the script. #>
    $root = if ($env:APPDATA) { $env:APPDATA } else { $env:LOCALAPPDATA }
    Join-Path $root 'ServerEventTimeline\settings.json'
}

function Read-TimelineSettings {
    <# The remembered settings; empty when the file is missing or damaged. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $empty = [PSCustomObject]@{ SaveFolder = $null; RecentServerLists = @(); AdTarget = ''; ShowPicture = $true }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $empty }
    try {
        $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        return [PSCustomObject]@{
            SaveFolder        = [string]$data.SaveFolder
            RecentServerLists = @($data.RecentServerLists | Where-Object { $_ } | ForEach-Object { [string]$_ })
            AdTarget          = [string]$data.AdTarget
            # The timeline picture is shown unless the tech folded it away.
            ShowPicture       = if ($null -eq $data.ShowPicture) { $true } else { [bool]$data.ShowPicture }
        }
    }
    catch { return $empty }
}

function Save-TimelineSettings {
    <#
        Remembers the save folder, the recent server lists and/or the domain (or DC) to read
        servers from (AdTarget, '' = this computer's domain) and whether the timeline picture
        is shown (ShowPicture); whatever isn't given is kept.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$SaveFolder, [string[]]$RecentServerLists, [AllowEmptyString()][string]$AdTarget, [bool]$ShowPicture)
    $current = Read-TimelineSettings -Path $Path
    $data = [ordered]@{ SaveFolder = $current.SaveFolder; RecentServerLists = @($current.RecentServerLists); AdTarget = $current.AdTarget; ShowPicture = $current.ShowPicture }
    if ($PSBoundParameters.ContainsKey('ShowPicture')) { $data.ShowPicture = $ShowPicture }
    if ($PSBoundParameters.ContainsKey('AdTarget')) { $data.AdTarget = $AdTarget }
    if ($PSBoundParameters.ContainsKey('SaveFolder')) { $data.SaveFolder = $SaveFolder }
    if ($PSBoundParameters.ContainsKey('RecentServerLists')) { $data.RecentServerLists = @($RecentServerLists) }
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $data | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Add-RecentServerList {
    <#
        The recent server lists with this one first. A list already there (same names in any
        order or case) moves to the top instead of appearing twice.
    #>
    [CmdletBinding()]
    param([string[]]$Recent, [Parameter(Mandatory)][string[]]$Servers, [int]$Max = 8)
    $norm = { param($t) (@(ConvertTo-ServerList -Text $t | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ',') }
    $text = (@($Servers) -join ', ')
    $key = & $norm $text
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add($text)
    foreach ($r in @($Recent | Where-Object { $_ })) {
        if ($out.Count -ge $Max) { break }
        if ((& $norm $r) -ne $key) { $out.Add([string]$r) }
    }
    return $out.ToArray()
}

function Resolve-TimelineOutputFolder {
    <# Where exports go: -OutputPath if given, else the remembered folder if it still exists, else the default. #>
    [CmdletBinding()]
    param([string]$OutputPath, [string]$Remembered, [Parameter(Mandatory)][string]$Default)
    if ($OutputPath) { return $OutputPath }
    if ($Remembered -and (Test-Path -LiteralPath $Remembered -PathType Container)) { return $Remembered }
    return $Default
}

function Get-TimelineEventKey {
    <# 'Provider|Id': what "Show only this event" filters on. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row)
    '{0}|{1}' -f $Row.Provider, $Row.EventId
}

function Get-AroundEventText {
    <# The row's time as the Around box reads it (server-local, to the second). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row)
    ([datetime]$Row.TimeServerLocal).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-TimelineFlagCounts {
    <#
        Per server: the summary kinds that occurred and how often, in $script:SummaryKinds
        order (Counts = @{ <server> = [ordered]@{ <kind key> = <count> } }), and how many
        rows carry any flag (Flagged = @{ <server> = <count> }).
    #>
    [CmdletBinding()]
    param([object[]]$Rows)
    $perLabel = @{}
    $flagged = @{}
    foreach ($r in $Rows) {
        if (-not $r.Flag) { continue }
        $s = [string]$r.Server
        if (-not $perLabel.ContainsKey($s)) { $perLabel[$s] = @{}; $flagged[$s] = 0 }
        $flagged[$s]++
        $l = [string]$r.Flag
        if ($perLabel[$s].ContainsKey($l)) { $perLabel[$s][$l]++ } else { $perLabel[$s][$l] = 1 }
    }
    $counts = @{}
    foreach ($s in $perLabel.Keys) {
        $c = [ordered]@{}
        foreach ($k in $script:SummaryKinds) {
            $values = @($k.Labels | ForEach-Object { if ($perLabel[$s].ContainsKey($_)) { [int]$perLabel[$s][$_] } else { 0 } })
            $n = if ($k.Max) { ($values | Measure-Object -Maximum).Maximum } else { ($values | Measure-Object -Sum).Sum }
            if ($n -gt 0) { $c[$k.Key] = [int]$n }
        }
        $counts[$s] = $c
    }
    [PSCustomObject]@{ Counts = $counts; Flagged = $flagged }
}

function Get-TimelineUnrecognisedErrors {
    <#
        Per server: Critical and Error events that are NOT on the known list (no flag), e.g. SQL,
        IIS, Group Policy or backup errors. The summary and the ticket note only describe the
        known events, so without this a server with 40 SQL errors read as "nothing flagged" and
        was "ruled out". Returns @{ <server> = @{ Count; Sources = 'MSSQLSERVER 30, NETLOGON 10' } }
        with the three commonest sources.
    #>
    [CmdletBinding()]
    param([object[]]$Rows, [int]$TopSources = 3)
    $perServer = @{}
    foreach ($r in $Rows) {
        if ($r.Flag -or [int]$r.Level -notin @(1, 2)) { continue }
        $s = [string]$r.Server
        if (-not $perServer.ContainsKey($s)) { $perServer[$s] = @{} }
        $p = [string]$r.Provider
        if ($perServer[$s].ContainsKey($p)) { $perServer[$s][$p]++ } else { $perServer[$s][$p] = 1 }
    }
    $out = @{}
    foreach ($s in $perServer.Keys) {
        $bySource = @($perServer[$s].GetEnumerator() | Sort-Object @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' })
        $total = ($bySource | Measure-Object -Property Value -Sum).Sum
        $top = @($bySource | Select-Object -First $TopSources | ForEach-Object { '{0} {1}' -f $_.Key, $_.Value }) -join ', '
        $out[$s] = @{ Count = [int]$total; Sources = $top }
    }
    return $out
}

function Format-TimelineEventCount {
    # "1 event" / "1,240 events"
    param([int]$Count)
    if ($Count -eq 1) { '1 event' } else { '{0:N0} events' -f $Count }
}

function Format-TimelineUnrecognisedText {
    # "41 errors this tool doesn't recognise" / "1 error this tool doesn't recognise"
    param([int]$Count)
    if ($Count -eq 1) { "1 error this tool doesn't recognise" } else { "$Count errors this tool doesn't recognise" }
}

function Format-TimelineCountParts {
    # "1 unexpected restart", "3 service failures" ... for one kind (Problem/Warning/Info) or all.
    param($Counts, [string]$Kind)
    foreach ($k in $script:SummaryKinds) {
        if ($Kind -and $k.Kind -ne $Kind) { continue }
        if ($Counts -and $Counts.Contains($k.Key)) {
            $n = [int]$Counts[$k.Key]
            '{0} {1}' -f $n, $(if ($n -eq 1) { $k.One } else { $k.Many })
        }
    }
}

function Get-TimelineSummaryLines {
    <#
        The plain-English strip above the grid: one line per server, e.g.
        "APP01: 1 unexpected restart, 3 service failures, 1 update installed".
        Counts every row read (not just the filtered ones). Errors that aren't on the known
        list are named too ("but 40 errors this tool doesn't recognise"), so "nothing flagged"
        is never read as "nothing wrong". ErrorHint is appended to that (the window says how to
        see them). With -Logs, a closing line says when the Security log wasn't read (sign-ins
        and lockouts are only there); SecurityHint is that line's text.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        $Status,
        [string[]]$Logs,
        [string]$ErrorHint = '',
        [string]$SecurityHint = "Security log not read: sign-in and lockout problems won't show up here."
    )
    $fc = Get-TimelineFlagCounts -Rows $Rows
    $unrec = Get-TimelineUnrecognisedErrors -Rows $Rows
    $servers = if ($Status) { @($Status.Keys) } else { @($Rows | ForEach-Object { [string]$_.Server } | Select-Object -Unique) }
    foreach ($s in $servers) {
        $st = if ($Status) { $Status[$s] } else { $null }
        $found = @(Format-TimelineCountParts -Counts $fc.Counts[$s]) -join ', '
        $state = if ($st) { [string]$st.State } else { 'Done' }
        $events = if ($st) { [int]$st.EventCount } else { @($Rows | Where-Object Server -eq $s).Count }
        if ($state -eq 'Unreachable') { "${s}: couldn't be read"; continue }
        if ($state -in @('Waiting', 'Querying')) {
            if ($found) { "${s}: still reading... so far $found" } else { "${s}: still reading..." }
            continue
        }
        $line = if ($found) { "${s}: $found" }
        elseif ($fc.Flagged[$s]) { '{0}: {1} flagged events' -f $s, $fc.Flagged[$s] }
        elseif ($events -eq 0) { "${s}: no events in this window" }
        else { '{0}: nothing flagged in {1}' -f $s, (Format-TimelineEventCount -Count $events) }
        if ($unrec.ContainsKey($s)) {
            $joiner = if ($found -or $fc.Flagged[$s]) { ', plus ' } else { ', but ' }
            $line += $joiner + (Format-TimelineUnrecognisedText -Count $unrec[$s].Count) + $ErrorHint
        }
        if ($state -eq 'DoneWithGaps') { $line += ' (some logs incomplete)' }
        if ($state -eq 'Cancelled') { $line += ' (cancelled)' }
        $line
    }
    # @($null).Count is 1, so filter out empties before asking whether a log list was given.
    $chosen = @($Logs | Where-Object { $_ })
    if ($chosen.Count -gt 0 -and $chosen -notcontains 'Security' -and $SecurityHint) { $SecurityHint }
}

function Get-TimelineServerCards {
    <#
        The sidebar's EACH SERVER block: one card per server. Heading = how reading it went
        (from the engine status), Findings = what was found (the server's summary line without
        its "server: " prefix, or why it couldn't be reached). Warn marks gaps and failures.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status, [string[]]$SummaryLines)
    $via = @{ WinRM = 'WinRM'; RPC = 'remote event log'; Local = 'this computer' }
    foreach ($s in $Status.Values) {
        $name = [string]$s.Server
        $prefix = "${name}: "
        $line = @($SummaryLines | Where-Object { $_ -and $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })[0]
        $findings = if ($line) { $line.Substring($prefix.Length) } else { '' }
        $how = if ($s.Transport -and $via.ContainsKey([string]$s.Transport)) { $via[[string]$s.Transport] } else { '' }
        $count = '{0:N0} events' -f [int]$s.EventCount
        $warn = $false
        $heading = switch ([string]$s.State) {
            'Waiting'      { "… $name · waiting" }
            'Querying'     { if ($how) { "… $name · reading ($how)" } else { "… $name · reading" } }
            'Done'         { (@("✓ $name", $count, $how) | Where-Object { $_ }) -join ' · ' }
            'DoneWithGaps' { $warn = $true; (@("✓ $name", $count, 'with gaps', $how) | Where-Object { $_ }) -join ' · ' }
            'Unreachable'  { $warn = $true; $findings = [string]$s.Reason; "✗ $name · couldn't reach" }
            'Cancelled'    { "■ $name · cancelled · $count kept" }
            default        { "$name · $($s.State)" }
        }
        [PSCustomObject]@{ Server = $name; Heading = $heading; Findings = $findings; Warn = $warn }
    }
}

function Get-TimelineServerNotes {
    <# The summary lines that aren't about one server (for example "Security log not read"). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status, [string[]]$SummaryLines)
    $prefixes = @($Status.Keys | ForEach-Object { "$($_): " })
    foreach ($l in @($SummaryLines | Where-Object { $_ })) {
        $mine = $false
        foreach ($p in $prefixes) { if ($l.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { $mine = $true; break } }
        if (-not $mine) { $l }
    }
}
function Group-TimelineRepeats {
    <#
        Collapses the same unflagged event (server, log, source, ID, level) into one row at its
        first time, e.g. "[240x, last at 03:14:22] Task triggered...". Flagged events are never
        collapsed, so each crash keeps its own time. The originals are kept in Members and are
        not changed.
    #>
    [CmdletBinding()]
    param([object[]]$Rows)
    $groups = @{}
    $order = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($r.Flag) { $order.Add($r); continue }
        $key = '{0}|{1}|{2}|{3}|{4}' -f $r.Server, $r.Log, $r.Provider, $r.EventId, $r.Level
        if ($groups.ContainsKey($key)) { $groups[$key].Add($r); continue }
        $list = New-Object System.Collections.Generic.List[object]
        $list.Add($r)
        $groups[$key] = $list
        $order.Add($list)
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($item in $order) {
        if ($item -isnot [System.Collections.Generic.List[object]]) { $out.Add($item); continue }
        if ($item.Count -eq 1) { $out.Add($item[0]); continue }
        $first = $item[0]
        $lastLocal = [datetime]$item[$item.Count - 1].TimeServerLocal
        $format = if ($lastLocal.Date -eq ([datetime]$first.TimeServerLocal).Date) { 'HH:mm:ss' } else { 'yyyy-MM-dd HH:mm:ss' }
        $copy = $first.PSObject.Copy()
        $copy.MessageFirstLine = '[{0}x, last at {1}] {2}' -f $item.Count, $lastLocal.ToString($format), $first.MessageFirstLine
        $copy | Add-Member -NotePropertyName RepeatCount -NotePropertyValue $item.Count
        $copy | Add-Member -NotePropertyName LastTimeServerLocal -NotePropertyValue $lastLocal
        $copy | Add-Member -NotePropertyName Members -NotePropertyValue $item.ToArray()
        $out.Add($copy)
    }
    return $out.ToArray()
}

function Expand-TimelineRepeats {
    <# Every original row behind collapsed rows (for exports and copying). #>
    [CmdletBinding()]
    param([object[]]$Rows)
    foreach ($r in $Rows) {
        if ($r.PSObject.Properties['Members']) { $r.Members } else { $r }
    }
}

function Resolve-TimelineLogNames {
    <#
        Log names for the console mode: checkbox labels (System, Task Scheduler...) or log
        names, any case; anything else is passed through as a log name. None = the defaults.
    #>
    [CmdletBinding()]
    param([string[]]$Names)
    $catalog = @(Get-TimelineLogCatalog)
    $wanted = @($Names | Where-Object { $_ -and $_.Trim() })
    if ($wanted.Count -eq 0) { return @($catalog | Where-Object Default | ForEach-Object Name) }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $wanted) {
        $t = $n.Trim()
        $hit = $catalog | Where-Object { $_.Name -eq $t -or $_.Label -eq $t } | Select-Object -First 1
        $name = if ($hit) { $hit.Name } else { $t }
        if ($seen.Add($name)) { $name }
    }
}

function Test-TimelineServerComplete {
    <#
        True only when a server was read in full: Done, at least one log actually read, no log
        skipped (missing, turned off, or a mistyped name), and no warning such as a guessed
        time zone. Only then may the ticket note rule it out, or the console exit 0.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)
    if ($Status.State -ne 'Done' -or $Status.Reason) { return $false }
    $logs = @($Status.Logs)
    if (@($logs | Where-Object Outcome -eq 'Read').Count -eq 0) { return $false }
    return (@($logs | Where-Object Outcome -ne 'Read').Count -eq 0)
}

function New-TimelineTicketNote {
    <#
        The four-part ticket note (CaseKit) for a search: what was found per server, which
        servers came back clean, what could not be checked, and next steps. A server is only
        "ruled out" when every log was read, nothing was flagged and it had no errors the tool
        doesn't recognise (those are a warning with their sources: "ruled out" must not hide 40
        SQL errors). When -Logs is given without Security, that's listed as not checked.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Status,
        [object[]]$Rows,
        [string]$WindowText,
        [string[]]$Logs,
        [datetime]$Now = (Get-Date),
        [int]$MaxEventLines = 15,
        [string[]]$EvidencePaths = @()
    )
    $fc = Get-TimelineFlagCounts -Rows $Rows
    $unrec = Get-TimelineUnrecognisedErrors -Rows $Rows
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $servers = @($Status.Keys)
    $incomplete = $false

    foreach ($s in $servers) {
        $st = $Status[$s]
        if ($st.State -eq 'Unreachable') {
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text "${s}: couldn't be read - $($st.Reason)"))
            $next.Add("Check that $s can be reached over WinRM (TCP 5985) or the remote event log, and that your account can read its logs.")
            continue
        }
        foreach ($kind in 'Problem', 'Warning', 'Info') {
            $parts = @(Format-TimelineCountParts -Counts $fc.Counts[$s] -Kind $kind)
            if ($parts.Count -gt 0) { $items.Add((New-TicketNoteItem -Kind $kind -Text ('{0}: {1}' -f $s, ($parts -join ', ')))) }
        }
        foreach ($k in $script:SummaryKinds) {
            if ($k.Next -and $fc.Counts[$s] -and $fc.Counts[$s].Contains($k.Key)) { $next.Add(($k.Next -f $s)) }
        }
        $hasUnrec = $unrec.ContainsKey($s)
        if ($hasUnrec) {
            $u = $unrec[$s]
            $items.Add((New-TicketNoteItem -Kind Warning -Text ('{0}: {1} ({2}) - review them' -f $s, (Format-TimelineUnrecognisedText -Count $u.Count), $u.Sources)))
            $next.Add(('Review the {0} on {1}: filter the timeline to Errors and worse, or see the report.' -f $(if ($u.Count -eq 1) { 'error' } else { "$($u.Count) errors" }), $s))
        }
        $gaps = @($st.Logs | Where-Object { $_.Outcome -in @('Capped', 'TimedOut', 'Failed', 'NotRead', 'Cancelled', 'Pending') })
        foreach ($g in $gaps) {
            $why = if ($g.Reason) { $g.Reason } else { ([string]$g.Outcome).ToLowerInvariant() }
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text ('{0} {1}: {2}' -f $s, $g.Log, $why)))
        }
        foreach ($skip in @($st.Logs | Where-Object Outcome -eq 'Skipped')) {
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text $skip.Reason))
        }
        if ($st.Reason -and $st.State -ne 'Cancelled') {
            # For example a time zone that had to be guessed: the window may be shifted.
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text ('{0}: {1}' -f $s, $st.Reason)))
        }
        $complete = Test-TimelineServerComplete -Status $st
        if ($gaps.Count -gt 0 -or $st.State -ne 'Done') { $incomplete = $true }
        if ($st.State -eq 'Cancelled' -and $gaps.Count -eq 0) {
            $items.Add((New-TicketNoteItem -Kind NotChecked -Text "${s}: the search was cancelled before it finished"))
        }
        if (-not $fc.Flagged[$s] -and -not $hasUnrec) {
            if ($complete) {
                $items.Add((New-TicketNoteItem -Kind Clear -CouldLook $true -Text ('{0}: no flagged events in {1}' -f $s, (Format-TimelineEventCount -Count ([int]$st.EventCount)))))
            }
            else { $items.Add((New-TicketNoteItem -Kind Info -Text "${s}: nothing flagged in the logs that were read")) }
        }
    }
    $chosen = @($Logs | Where-Object { $_ })
    if ($chosen.Count -gt 0 -and $chosen -notcontains 'Security') {
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text 'Security log (sign-ins, lockouts, permission changes): not part of this search'))
    }
    if ($incomplete) { $next.Add('Read the incomplete logs again with a narrower window (or raise the limits under More options).') }

    $flaggedRows = @($Rows | Where-Object { $_.Flag })
    # What happened, in order: repeats and restarts folded into one line each (Story.ps1).
    foreach ($line in @(Format-TimelineStoryText -Story (Get-TimelineStory -Rows $Rows -MaxLines $MaxEventLines))) {
        $items.Add((New-TicketNoteItem -Kind Info -Text $line))
    }

    $flagText = if ($flaggedRows.Count -eq 1) { '1 flagged event' } else { '{0} flagged events' -f $flaggedRows.Count }
    $headline = '{0} - {1} across {2} server(s)' -f $WindowText, $flagText, $servers.Count
    $unrecTotal = 0
    foreach ($v in $unrec.Values) { $unrecTotal += $v.Count }
    if ($unrecTotal -gt 0) { $headline += ', plus ' + (Format-TimelineUnrecognisedText -Count $unrecTotal) }
    $scopeLine = 'Servers: {0}' -f ($servers -join ', ')
    if (@($Logs).Count -gt 0) { $scopeLine += ' | Logs: {0}' -f (@($Logs) -join ', ') }
    $stamp = New-TicketNoteStamp -ScopeLabel Computer -Scope ($servers -join ', ') -Now $Now
    New-TicketNote -Tool 'Server-EventTimeline' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() -NextSteps $next.ToArray() -Stamp $stamp -EvidencePaths $EvidencePaths
}
