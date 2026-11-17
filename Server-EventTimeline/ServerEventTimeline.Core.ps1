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
        [Parameter(Mandatory)]$EventRecord,
        [int]$UtcOffsetMinutes = 0
    )

    $timeUtc = [datetime]::SpecifyKind([datetime]$EventRecord.TimeCreatedUtc, [DateTimeKind]::Utc)
    $level = [int]$EventRecord.Level
    $levelName = if ($script:LevelNames.ContainsKey($level)) { $script:LevelNames[$level] } else { "Level $level" }

    $message = [string]$EventRecord.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        # The remote event log (RPC) path renders text with this workstation's provider files,
        # so events from software not installed here arrive without text.
        $message = "(No message text: the event's provider isn't installed on this workstation. Event $($EventRecord.Id) from $($EventRecord.ProviderName).)"
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
        (literal, case-insensitive, matched against message, provider and event ID).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][hashtable]$Filter)

    $levels = $script:MinLevelSets[[string]$Filter.MinLevel]
    if ($null -ne $levels -and $levels -notcontains [int]$Row.Level) { return $false }
    if ($Filter.Server -and $Filter.Server -ne '*' -and $Row.Server -ne $Filter.Server) { return $false }
    if ($Filter.Log -and $Filter.Log -ne '*' -and $Row.Log -ne $Filter.Log) { return $false }
    if ($Filter.FlaggedOnly -and -not $Row.Flag) { return $false }

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
    param([object[]]$Rows, [Parameter(Mandatory)][hashtable]$Context)

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
</style></head><body>
<h1>Server Event Timeline</h1>
'@)
    [void]$sb.AppendFormat('<p class="meta">{0}<br>Servers: {1}<br>Logs: {2}<br>Filters: {3}<br>Made {4}</p>',
        (& $e $Context.WindowText), (& $e (@($Context.Servers) -join ', ')), (& $e (@($Context.Logs) -join ', ')),
        (& $e $Context.FiltersText), (& $e ([datetime]$Context.GeneratedAt).ToString('yyyy-MM-dd HH:mm:ss')))

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

    if ($null -eq $levels -and -not $server -and -not $log -and -not $flagged -and -not $text) { return @($Rows) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -ne $levels -and $levels -notcontains [int]$r.Level) { continue }
        if ($server -and $r.Server -ne $server) { continue }
        if ($log -and $r.Log -ne $log) { continue }
        if ($flagged -and -not $r.Flag) { continue }
        if ($text -and ('{0}|{1}|{2}' -f $r.EventId, $r.Provider, $r.Message).IndexOf($text, $cmp) -lt 0) { continue }
        $out.Add($r)
    }
    return $out.ToArray()
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
        [string]$CapText = '5000', [string]$TimeoutText = '60'
    )

    $fail = { param($m) [PSCustomObject]@{ Ok = $false; Message = $m; Servers = @(); Window = $null; Cap = 0; TimeoutSec = 0 } }
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

    $cap = 0; $timeout = 0
    if (-not [int]::TryParse($CapText, [ref]$cap) -or $cap -le 0) { return (& $fail 'The number of events per log must be a whole number above 0.') }
    if (-not [int]::TryParse($TimeoutText, [ref]$timeout) -or $timeout -le 0) { return (& $fail 'The timeout must be a whole number of seconds above 0.') }

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

    [PSCustomObject]@{ Ok = $true; Message = ''; Servers = $servers; Window = $window; Cap = $cap; TimeoutSec = $timeout }
}

function Get-TimelineStatusLines {
    <# One plain line per server for the status list. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Status)

    foreach ($s in $Status.Values) {
        $via = switch ($s.Transport) { 'WinRM' { ' (via WinRM)' } 'RPC' { ' (via remote event log)' } default { '' } }
        switch ($s.State) {
            'Waiting'      { "$($s.Server): waiting" }
            'Querying'     { "$($s.Server): reading...$via" }
            'Done'         { '{0}: done - {1:N0} events{2}' -f $s.Server, $s.EventCount, $via }
            'DoneWithGaps' { '{0}: done with gaps - {1:N0} events{2}' -f $s.Server, $s.EventCount, $via }
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
