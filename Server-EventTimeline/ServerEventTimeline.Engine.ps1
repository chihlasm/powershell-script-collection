#Requires -Version 5.1

<#
.SYNOPSIS
    Server Event Timeline: talking to servers (probe + per-log queries) and the background
    engine that runs them without freezing the window.

.DESCRIPTION
    Dot-sources ServerEventTimeline.Core.ps1. Read-only: nothing here changes a server.
    Transport: WinRM (Invoke-Command, filtering on the server) first; the remote event log
    over RPC (Get-WinEvent -ComputerName) only when WinRM can't connect. Access denied is
    reported, never retried over RPC.

.NOTES
    REFERENCES
    - Get-WinEvent (FilterHashtable LogName/StartTime/EndTime, -MaxEvents, -ListLog,
      -ComputerName, -Credential; returns events newest to oldest by default, -Oldest reverses):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
    - FilterHashtable keys Level (Critical 1, Error 2, Warning 3, Informational 4, Verbose 5,
      LogAlways 0), Id and Keywords (AuditFailure = 4503599627370496 = 0x10000000000000); each
      call is one query, so important events are read with several calls and merged:
      https://learn.microsoft.com/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
    - Security audit events are written at Level 0 with the outcome in Keywords (event 4625:
      Level 0, Keywords 0x8010000000000000); 4740 is a Level 0 audit success:
      https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
      https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740
    - "No events were found" is raised as error id NoMatchingEventsFound (not documented on
      Learn; same handling as DC-Diagnostics\Get-DCDiagnostics.ps1 Get-EventsSafe).
    - RPC needs TCP 135 plus dynamic ports; 0x6BA = RPC server unavailable:
      https://learn.microsoft.com/troubleshoot/windows-server/active-directory/status-code-0x6ba-rpc-server-unavailable
    - Win32_OperatingSystem.CurrentTimeZone (minutes offset from UTC):
      https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem
#>

. (Join-Path $PSScriptRoot 'ServerEventTimeline.Core.ps1')

# Runs ON the server (WinRM) or here (RPC, with -ComputerName). Kept PowerShell 3.0-safe:
# target servers can be old. Returns plain objects only.
$script:LogQueryScript = {
    param([string]$LogName, [long]$StartTicks, [long]$EndTicks, [int]$MaxEvents, [string]$ComputerName, $Credential,
        [string]$Part, [int[]]$ImportantIds, [bool]$AuditFailure)

    $start = New-Object DateTime ($StartTicks, [DateTimeKind]::Utc)
    $end = New-Object DateTime ($EndTicks, [DateTimeKind]::Utc)
    $auditFailureKeyword = 4503599627370496   # 0x10000000000000, Get-WinEvent FilterHashtable Keywords
    $ImportantIds = @($ImportantIds)

    # One Get-WinEvent call. Events come newest first (Get-WinEvent's default order). "No
    # events were found" is an empty answer, anything else is thrown.
    $read = {
        param($extra, [bool]$limit)
        # StartTime/EndTime are local time on the machine running Get-WinEvent: it does
        # value.ToString(), re-parses the text as local time and then ToUniversalTime(), so a UTC
        # value would shift the window by the UTC offset (GetEventCommand.cs,
        # HandleStartTimeHashValue / StringToDateTime).
        $filter = @{ LogName = $LogName; StartTime = $start.ToLocalTime(); EndTime = $end.ToLocalTime() }
        foreach ($k in $extra.Keys) { $filter[$k] = $extra[$k] }
        $params = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
        if ($limit) { $params.MaxEvents = $MaxEvents }
        if ($ComputerName) { $params.ComputerName = $ComputerName }
        if ($Credential) { $params.Credential = $Credential }
        try { Get-WinEvent @params }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        }
    }

    $project = {
        process {
            New-Object PSObject -Property @{
                TimeCreatedUtc = $_.TimeCreated.ToUniversalTime()
                Id             = $_.Id
                ProviderName   = $_.ProviderName
                Level          = [int]$_.Level
                LogName        = $_.LogName
                Message        = $_.Message
                RecordId       = $_.RecordId
                UserSid        = if ($_.UserId) { $_.UserId.Value } else { '' }
                MachineName    = $_.MachineName
            }
        }
    }

    if ($Part -eq 'Routine') {
        # Everything that is not Critical/Error/Warning. Security audit events are Level 0 and
        # the outcome is in Keywords, so Security has no Level filter and drops its important
        # events (audit failures, listed IDs, levels 1-3) below.
        $extra = @{}
        if ($LogName -ne 'Security') { $extra.Level = @(0, 4, 5) }
        $isSecurity = $LogName -eq 'Security'
        # Filter first, then Select-Object -First (stops the read early since PowerShell 3.0);
        # .Message is formatted only in the projection, after both.
        $events = @(& $read $extra $false |
                Where-Object {
                    if ($isSecurity) {
                        -not ((($_.Keywords -band $auditFailureKeyword) -ne 0) -or ($ImportantIds -contains $_.Id) -or ($_.Level -ge 1 -and $_.Level -le 3))
                    }
                    else { -not ($ImportantIds -contains $_.Id) }
                } |
                Select-Object -First $MaxEvents |
                & $project)
        return New-Object PSObject -Property @{ Events = $events }
    }

    # Important: levels 1-3, the recognised IDs (chunks of 20 keep each query small), and for
    # Security the audit failures. Merge, drop duplicates, newest first, keep the first N.
    $raw = @()
    $raw += @(& $read @{ Level = @(1, 2, 3) } $true)
    for ($i = 0; $i -lt $ImportantIds.Count; $i += 20) {
        $last = [Math]::Min($i + 19, $ImportantIds.Count - 1)
        $raw += @(& $read @{ Id = [int[]]@($ImportantIds[$i..$last]) } $true)
    }
    if ($AuditFailure) { $raw += @(& $read @{ Keywords = $auditFailureKeyword } $true) }

    $seen = @{}
    # Emitted through the pipeline, not grown with +=: the input can be ~20,000 events.
    $unique = @(foreach ($e in $raw) {
            if (-not $seen.ContainsKey([string]$e.RecordId)) { $seen[[string]$e.RecordId] = $true; $e }
        })
    $events = @($unique | Sort-Object -Property RecordId -Descending | Select-Object -First $MaxEvents | & $project)
    New-Object PSObject -Property @{ Events = $events }
}

# Runs ON the server over WinRM: its UTC offset at the window start and its log channels.
$script:ProbeScript = {
    param($WindowStartLocal)
    $tz = [TimeZoneInfo]::Local
    $at = if ($WindowStartLocal) { [datetime]$WindowStartLocal } else { Get-Date }
    $channels = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        New-Object PSObject -Property @{ Name = $_.LogName; IsEnabled = $_.IsEnabled; RecordCount = $_.RecordCount }
    })
    New-Object PSObject -Property @{
        UtcOffsetMinutes = [int]$tz.GetUtcOffset($at).TotalMinutes
        TimeZoneId       = $tz.Id
        Channels         = $channels
    }
}

function Test-TcpPortQuick {
    <# True when the port accepts a TCP connection within the timeout. Never hangs. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 2000)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Get-RpcUtcOffsetMinutes {
    <#
        The server's current UTC offset over DCOM (same RPC route as the remote event log).
        Win32_OperatingSystem.CurrentTimeZone is the offset now, not at the window start;
        across a DST change the window can be an hour out (noted in the README).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName, [pscredential]$Credential)

    $opt = New-CimSessionOption -Protocol Dcom
    $params = @{ ComputerName = $ComputerName; SessionOption = $opt; ErrorAction = 'Stop' }
    if ($Credential) { $params.Credential = $Credential }
    $session = New-CimSession @params
    try { [int](Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop).CurrentTimeZone }
    finally { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
}

function Invoke-ServerProbe {
    <#
        Can we reach this server, how, what is its UTC offset, and which logs does it have?
        Order: WinRM (5985) -> on port closed or a connection-level failure, RPC (135).
        Access denied stops here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        $WindowStartLocal
    )

    $result = [PSCustomObject]@{
        Server = $ComputerName; Reachable = $false; Transport = ''; UtcOffsetMinutes = 0; TimeZoneId = ''
        Channels = @(); FailureKind = ''; Reason = ''; Note = ''
    }

    # This computer: read its logs straight from disk. No WinRM, no firewall, no network.
    if (Test-IsLocalComputer -Name $ComputerName) {
        $at = if ($WindowStartLocal) { [datetime]$WindowStartLocal } else { Get-Date }
        $channels = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                ForEach-Object { [PSCustomObject]@{ Name = $_.LogName; IsEnabled = [bool]$_.IsEnabled; RecordCount = $_.RecordCount } })
        # Without administrator rights the Security log is missing from the list; keep it so a
        # ticked Security box says "start as administrator" instead of "doesn't exist".
        if (-not ($channels | Where-Object Name -eq 'Security')) {
            $channels += [PSCustomObject]@{ Name = 'Security'; IsEnabled = $true; RecordCount = $null }
        }
        $result.Reachable = $true
        $result.Transport = 'Local'
        $result.UtcOffsetMinutes = [int][TimeZoneInfo]::Local.GetUtcOffset($at).TotalMinutes
        $result.TimeZoneId = [TimeZoneInfo]::Local.Id
        $result.Channels = $channels
        return $result
    }

    $winrmOpen = Test-TcpPortQuick -ComputerName $ComputerName -Port 5985
    if ($winrmOpen) {
        try {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $script:ProbeScript; ArgumentList = @(, $WindowStartLocal); ErrorAction = 'Stop' }
            if ($Credential) { $params.Credential = $Credential }
            $remote = Invoke-Command @params
            $result.Reachable = $true
            $result.Transport = 'WinRM'
            $result.UtcOffsetMinutes = [int]$remote.UtcOffsetMinutes
            $result.TimeZoneId = [string]$remote.TimeZoneId
            $result.Channels = @($remote.Channels | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; IsEnabled = [bool]$_.IsEnabled; RecordCount = $_.RecordCount } })
            return $result
        }
        catch {
            $kind = Get-RemoteFailureKind -ErrorRecord $_
            if ($kind -ne 'Connection') {
                $result.FailureKind = $kind
                $result.Reason = Get-FailureText -Kind $kind -Server $ComputerName -Detail $_.Exception.Message
                return $result
            }
        }
    }

    if (-not (Test-TcpPortQuick -ComputerName $ComputerName -Port 135)) {
        $result.FailureKind = 'Connection'
        $result.Reason = Get-FailureText -Kind Unreachable -Server $ComputerName
        return $result
    }

    try {
        $listErrors = $null
        $params = @{ ListLog = '*'; ComputerName = $ComputerName; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'listErrors' }
        if ($Credential) { $params.Credential = $Credential }
        $result.Channels = @(Get-WinEvent @params | ForEach-Object { [PSCustomObject]@{ Name = $_.LogName; IsEnabled = [bool]$_.IsEnabled; RecordCount = $_.RecordCount } })
        if ($result.Channels.Count -eq 0 -and @($listErrors).Count -gt 0) { throw @($listErrors)[0] }
        $result.Reachable = $true
        $result.Transport = 'RPC'
    }
    catch {
        $kind = Get-RemoteFailureKind -ErrorRecord $_
        $result.Reachable = $false
        $result.FailureKind = $kind
        $result.Reason = Get-FailureText -Kind $kind -Server $ComputerName -Detail $_.Exception.Message
        return $result
    }

    # The time zone comes over WMI/DCOM, a separate firewall rule from the remote event log. If
    # it is blocked the logs are still readable: assume this workstation's offset and say so.
    try { $result.UtcOffsetMinutes = Get-RpcUtcOffsetMinutes -ComputerName $ComputerName -Credential $Credential }
    catch {
        $at = if ($WindowStartLocal) { [datetime]$WindowStartLocal } else { Get-Date }
        $result.UtcOffsetMinutes = [int][TimeZoneInfo]::Local.GetUtcOffset($at).TotalMinutes
        $result.Note = "Couldn't read this server's time zone (WMI is blocked); assumed the same time zone as this workstation."
    }
    return $result
}

function Invoke-LogQuery {
    <# One log on one server for the UTC window. Outcome Read, Capped or Failed. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateSet('WinRM', 'RPC', 'Local')][string]$Transport,
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc,
        [int]$Cap = 5000,
        [pscredential]$Credential,
        [ValidateSet('Important', 'Routine')][string]$Part = 'Important'
    )

    # -Cap is the budget for this part. One more than the cap is read to tell "exactly the cap"
    # from "more than the cap".
    $result = [PSCustomObject]@{ Server = $ComputerName; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' }
    $rule = Get-TimelineImportantRule -LogName $LogName
    $queryArgs = @($LogName, $StartUtc.Ticks, $EndUtc.Ticks, ($Cap + 1))

    try {
        if ($Transport -eq 'WinRM') {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $script:LogQueryScript; ArgumentList = ($queryArgs + @('', $null) + @($Part, [int[]]$rule.Ids, [bool]$rule.AuditFailure)); ErrorAction = 'Stop' }
            if ($Credential) { $params.Credential = $Credential }
            $answer = Invoke-Command @params
        }
        elseif ($Transport -eq 'Local') {
            $answer = & $script:LogQueryScript @queryArgs '' $null $Part ([int[]]$rule.Ids) ([bool]$rule.AuditFailure)
        }
        else {
            $answer = & $script:LogQueryScript @queryArgs $ComputerName $Credential $Part ([int[]]$rule.Ids) ([bool]$rule.AuditFailure)
        }
    }
    catch {
        $kind = Get-RemoteFailureKind -ErrorRecord $_
        $result.Outcome = 'Failed'
        $result.Reason = if ($Transport -eq 'Local' -and $kind -eq 'AccessDenied') {
            "Can't read the $LogName log here: start the tool as administrator."
        }
        else { Get-FailureText -Kind $kind -Server $ComputerName -Detail $_.Exception.Message }
        return $result
    }

    $events = @($answer.Events | Where-Object { $_ })
    if ($events.Count -gt $Cap) {
        $events = @($events[0..($Cap - 1)])
        $result.Outcome = 'Capped'
        $result.Reason = if ($Part -eq 'Important') { 'more than {0:N0} errors and warnings - kept the newest {0:N0}' -f $Cap }
        else { 'kept the newest {0:N0} routine events; older ones in the window weren''t read' -f $Cap }
    }
    foreach ($e in $events) {
        $e.TimeCreatedUtc = [datetime]::SpecifyKind(([datetime]$e.TimeCreatedUtc).ToUniversalTime(), [DateTimeKind]::Utc)
    }
    $result.Events = $events
    $result.Count = $events.Count
    return $result
}

function Get-LogPlan {
    <#
        Which logs to query on one server, and which to skip with a plain reason. If the
        channel list couldn't be read, the selected logs are queried as-is.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Probe,
        [Parameter(Mandatory)][object[]]$Catalog,
        [string[]]$SelectedNames,
        [bool]$AllLogs = $false
    )

    $query = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[object]
    $channels = @{}
    foreach ($c in @($Probe.Channels)) { $channels[$c.Name] = $c }
    $haveList = $channels.Count -gt 0

    foreach ($name in @($SelectedNames)) {
        $label = ($Catalog | Where-Object Name -eq $name | Select-Object -First 1).Label
        if (-not $label) { $label = $name }
        if (-not $haveList) { $query.Add($name); continue }
        # Security is on every Windows machine, but listing it fails for an account that can't
        # read it ("If you're not running PowerShell as an Administrator, you might see error
        # messages that you can't retrieve information about a log", Get-WinEvent on Learn), and
        # the probe lists with SilentlyContinue. Query it anyway: the read then reports access
        # denied instead of a misleading "doesn't exist".
        if ($name -eq 'Security' -and -not $channels.ContainsKey($name)) { $query.Add($name); continue }
        if (-not $channels.ContainsKey($name)) {
            $skipped.Add([PSCustomObject]@{ Log = $name; Reason = "$label log doesn't exist on $($Probe.Server)" })
        }
        elseif (-not $channels[$name].IsEnabled) {
            $reason = "$label log is turned off on $($Probe.Server)"
            if ($name -eq 'Microsoft-Windows-TaskScheduler/Operational') {
                $reason += " (it's off by default; turn on 'Enable All Tasks History' in Task Scheduler to record it from now on)"
            }
            $skipped.Add([PSCustomObject]@{ Log = $name; Reason = $reason })
        }
        else { $query.Add($name) }
    }

    if ($AllLogs) {
        foreach ($c in @($Probe.Channels)) {
            if ($c.RecordCount -gt 0 -and $c.IsEnabled -and -not $query.Contains($c.Name)) { $query.Add($c.Name) }
        }
    }

    [PSCustomObject]@{ Query = $query.ToArray(); Skipped = $skipped.ToArray() }
}

#region Background engine
# The window's timer calls Update-TimelineEngine; all remote work runs in a runspace pool, so
# the window's thread only collects finished work and draws. One probe task per server, then
# one task per (server, log), so a slow log times out alone and a dead server fails alone.

$script:EngineFilePath = $PSCommandPath

# Default background tasks. Each runspace dot-sources this file so it has every function
# and the remote scriptblocks. Tests pass fakes with the same parameters.
$script:DefaultProbeTask = {
    param($EnginePath, $Server, $Credential, $WindowStartLocal)
    . $EnginePath
    Invoke-ServerProbe -ComputerName $Server -Credential $Credential -WindowStartLocal $WindowStartLocal
}
# Runs in the log task's runspace, after the log script: turns the events into timeline rows
# there. Converting on the window's heartbeat took 0.6-0.8 ms per event on the UI thread - a
# 5,000-event log froze the window for 3-4 s and Windows marked it "Not Responding".
$script:RowConverterTask = {
    param($EnginePath, $Server, $UtcOffsetMinutes)
    begin { . $EnginePath }
    process {
        $r = $_
        if ($null -ne $r -and $r.PSObject.Properties['Events'] -and -not $r.PSObject.Properties['Rows']) {
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($e in @($r.Events)) {
                if ($null -ne $e) { $rows.Add((ConvertTo-TimelineRow -Server $Server -EventRecord $e -UtcOffsetMinutes $UtcOffsetMinutes)) }
            }
            $r | Add-Member -NotePropertyName Rows -NotePropertyValue $rows.ToArray()
        }
        $r
    }
}

$script:DefaultLogTask = {
    param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
    . $EnginePath
    Invoke-LogQuery -ComputerName $Server -Transport $Transport -LogName $LogName -StartUtc $StartUtc -EndUtc $EndUtc -Cap $Cap -Credential $Credential
}

function Start-TimelineEngine {
    <# Starts the probes and returns the engine. Never blocks on a server. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Servers,
        [Parameter(Mandatory)]$Window,
        [string[]]$SelectedLogs = @('System', 'Application'),
        [switch]$AllLogs,
        [int]$Cap = 5000,
        [int]$ServerTotalCap = 50000,
        [int]$TimeoutSec = 60,
        [ValidateRange(1, 64)][int]$MaxConcurrency = 8,
        [pscredential]$Credential,
        [scriptblock]$ProbeScript = $script:DefaultProbeTask,
        [scriptblock]$LogScript = $script:DefaultLogTask
    )

    # The pool is twice the dispatch limit: a stopped task whose RPC call can't be interrupted
    # keeps its runspace until the call returns, and must not starve the tasks behind it (a
    # queued task waiting for a runspace would otherwise "time out" without ever running).
    $poolSize = $MaxConcurrency * 2
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $poolSize)
    $pool.Open()

    $status = [ordered]@{}
    foreach ($s in $Servers) {
        $status[$s] = [PSCustomObject]@{
            Server = $s; State = 'Waiting'; Transport = ''; Reason = ''; EventCount = 0; UtcOffsetMinutes = 0
            Logs = New-Object System.Collections.ArrayList
        }
    }

    $engine = [PSCustomObject]@{
        Pool = $pool; Running = New-Object System.Collections.ArrayList; Pending = New-Object System.Collections.ArrayList
        Draining = New-Object System.Collections.ArrayList; Status = $status; Window = $Window
        SelectedLogs = @($SelectedLogs); AllLogs = [bool]$AllLogs; Cap = $Cap; ServerTotalCap = $ServerTotalCap
        TimeoutSec = $TimeoutSec; MaxConcurrency = $MaxConcurrency; PoolSize = $poolSize; Credential = $Credential
        ProbeScript = $ProbeScript; LogScript = $LogScript; Catalog = @(Get-TimelineLogCatalog); Cancelled = $false
        StatusChanged = $true
    }

    foreach ($s in $Servers) {
        [void]$engine.Pending.Add([PSCustomObject]@{
                Kind = 'Probe'; Server = $s; Log = ''
                Parameters = [ordered]@{ EnginePath = $script:EngineFilePath; Server = $s; Credential = $Credential; WindowStartLocal = $Window.StartLocal }
            })
    }
    Start-PendingTimelineTasks -Engine $engine
    return $engine
}

function Start-PendingTimelineTasks {
    # Starts queued tasks up to MaxConcurrency. The timeout clock starts here, not at queueing.
    param([Parameter(Mandatory)]$Engine)
    while ($Engine.Pending.Count -gt 0 -and $Engine.Running.Count -lt $Engine.MaxConcurrency -and
        ($Engine.Running.Count + $Engine.Draining.Count) -lt $Engine.PoolSize) {
        $task = $Engine.Pending[0]
        $Engine.Pending.RemoveAt(0)
        $script = if ($task.Kind -eq 'Probe') { $Engine.ProbeScript } else { $Engine.LogScript }
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $Engine.Pool
        [void]$ps.AddScript($script.ToString())
        foreach ($k in $task.Parameters.Keys) { [void]$ps.AddParameter($k, $task.Parameters[$k]) }
        if ($task.PSObject.Properties['Convert']) {
            # Piped after the log script, in the same runspace: rows are built off the UI thread.
            [void]$ps.AddScript($script:RowConverterTask.ToString())
            foreach ($k in $task.Convert.Keys) { [void]$ps.AddParameter($k, $task.Convert[$k]) }
        }
        $task | Add-Member -NotePropertyName PowerShell -NotePropertyValue $ps -Force
        $task | Add-Member -NotePropertyName Handle -NotePropertyValue $ps.BeginInvoke() -Force
        $task | Add-Member -NotePropertyName Started -NotePropertyValue ([Diagnostics.Stopwatch]::StartNew()) -Force
        [void]$Engine.Running.Add($task)
        if ($task.Kind -eq 'Probe') { $Engine.Status[$task.Server].State = 'Querying' }
        $Engine.StatusChanged = $true
    }
}

function Set-TimelineLogOutcome {
    param($Status, [string]$Log, [string]$Outcome, [int]$Count = 0, [string]$Reason = '')
    $entry = $Status.Logs | Where-Object Log -eq $Log | Select-Object -First 1
    if (-not $entry) {
        $entry = [PSCustomObject]@{ Log = $Log; Outcome = $Outcome; Count = $Count; Reason = $Reason }
        [void]$Status.Logs.Add($entry)
    }
    else { $entry.Outcome = $Outcome; $entry.Count = $Count; $entry.Reason = $Reason }
}

function Stop-TimelineTask {
    # Asks a task to stop and parks it until it actually ends (an RPC call may run on briefly).
    param($Engine, $Task)
    try { [void]$Task.PowerShell.BeginStop($null, $null) } catch { }
    [void]$Engine.Running.Remove($Task)
    [void]$Engine.Draining.Add($Task)
}

function Complete-TimelineProbe {
    param($Engine, $Task, $Probe)
    $st = $Engine.Status[$Task.Server]
    if (-not $Probe -or -not $Probe.Reachable) {
        $st.State = 'Unreachable'
        $st.Reason = if ($Probe) { $Probe.Reason } else { 'No answer from the server.' }
        return
    }
    $st.Transport = $Probe.Transport
    $st.UtcOffsetMinutes = [int]$Probe.UtcOffsetMinutes
    if ($Probe.PSObject.Properties['Note'] -and $Probe.Note) { $st.Reason = [string]$Probe.Note }
    $plan = Get-LogPlan -Probe $Probe -Catalog $Engine.Catalog -SelectedNames $Engine.SelectedLogs -AllLogs $Engine.AllLogs
    foreach ($skip in @($plan.Skipped)) { Set-TimelineLogOutcome -Status $st -Log $skip.Log -Outcome 'Skipped' -Reason $skip.Reason }
    $utc = ConvertTo-UtcWindow -Window $Engine.Window -UtcOffsetMinutes $st.UtcOffsetMinutes
    foreach ($log in @($plan.Query)) {
        Set-TimelineLogOutcome -Status $st -Log $log -Outcome 'Pending'
        [void]$Engine.Pending.Add([PSCustomObject]@{
                Kind = 'Log'; Server = $Task.Server; Log = $log
                Convert = [ordered]@{ EnginePath = $script:EngineFilePath; Server = $Task.Server; UtcOffsetMinutes = $st.UtcOffsetMinutes }
                Parameters = [ordered]@{ EnginePath = $script:EngineFilePath; Server = $Task.Server; Transport = $Probe.Transport; LogName = $log
                    StartUtc = $utc.StartUtc; EndUtc = $utc.EndUtc; Cap = $Engine.Cap; Credential = $Engine.Credential }
            })
    }
}

function Complete-TimelineLog {
    param($Engine, $Task, $Result, $Rows)
    $st = $Engine.Status[$Task.Server]
    if (-not $Result) { Set-TimelineLogOutcome -Status $st -Log $Task.Log -Outcome 'Failed' -Reason 'No answer from the server.'; return }
    # Rows were built in the task's runspace (RowConverterTask); events are converted here only
    # when a result arrives without them.
    $prebuilt = [bool]$Result.PSObject.Properties['Rows']
    # @() around the whole if: assigning an if unrolls a one-row array (no .Count on 5.1).
    $events = @(if ($prebuilt) { $Result.Rows } else { $Result.Events | Where-Object { $_ } })
    $room = [Math]::Max($Engine.ServerTotalCap - $st.EventCount, 0)
    $reason = 'stopped at the {0:N0} event total for this server' -f $Engine.ServerTotalCap
    $outcome = $Result.Outcome
    $why = $Result.Reason
    if ($events.Count -gt $room) {
        # Cut short by the per-server total: never report this log as fully read.
        $events = @($events | Select-Object -First $room)
        $outcome = if ($room -gt 0) { 'Capped' } else { 'NotRead' }
        $why = $reason
    }
    $hitTotal = ($st.EventCount + $events.Count) -ge $Engine.ServerTotalCap

    if ($prebuilt) { $Rows.AddRange([object[]]$events) }
    else { foreach ($e in $events) { $Rows.Add((ConvertTo-TimelineRow -Server $Task.Server -EventRecord $e -UtcOffsetMinutes $st.UtcOffsetMinutes)) } }
    $st.EventCount += $events.Count
    Set-TimelineLogOutcome -Status $st -Log $Task.Log -Outcome $outcome -Count $events.Count -Reason $why

    if ($hitTotal) {
        foreach ($p in @($Engine.Pending | Where-Object { $_.Server -eq $Task.Server -and $_.Kind -eq 'Log' })) {
            [void]$Engine.Pending.Remove($p)
            Set-TimelineLogOutcome -Status $st -Log $p.Log -Outcome 'NotRead' -Reason $reason
        }
        foreach ($r in @($Engine.Running | Where-Object { $_.Server -eq $Task.Server -and $_.Kind -eq 'Log' })) {
            Stop-TimelineTask -Engine $Engine -Task $r
            Set-TimelineLogOutcome -Status $st -Log $r.Log -Outcome 'NotRead' -Reason $reason
        }
    }
}

function Update-TimelineEngine {
    <#
        Called by the window's timer. Collects finished tasks, times out slow ones, starts
        queued ones. Returns NewRows, StatusChanged and Finished. Never blocks.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Engine)

    $rows = New-Object System.Collections.Generic.List[object]
    $changed = [bool]$Engine.StatusChanged
    $Engine.StatusChanged = $false

    foreach ($task in @($Engine.Running)) {
        if (-not $Engine.Running.Contains($task)) { continue }
        $st = $Engine.Status[$task.Server]
        if ($task.Handle.IsCompleted) {
            [void]$Engine.Running.Remove($task)
            $output = $null; $failure = $null
            try { $output = @($task.PowerShell.EndInvoke($task.Handle)) | Select-Object -Last 1 }
            catch { $failure = $_.Exception.Message }
            if (-not $failure -and $task.PowerShell.Streams.Error.Count -gt 0 -and -not $output) {
                $failure = $task.PowerShell.Streams.Error[0].Exception.Message
            }
            $task.PowerShell.Dispose()
            if ($task.Kind -eq 'Probe') {
                if ($failure) { $st.State = 'Unreachable'; $st.Reason = Get-FailureText -Kind Other -Server $task.Server -Detail $failure }
                else { Complete-TimelineProbe -Engine $Engine -Task $task -Probe $output }
            }
            else {
                if ($failure) { Set-TimelineLogOutcome -Status $st -Log $task.Log -Outcome 'Failed' -Reason $failure }
                else { Complete-TimelineLog -Engine $Engine -Task $task -Result $output -Rows $rows }
            }
            $changed = $true
        }
        elseif ($task.Started.Elapsed.TotalSeconds -ge $Engine.TimeoutSec) {
            Stop-TimelineTask -Engine $Engine -Task $task
            if ($task.Kind -eq 'Probe') { $st.State = 'Unreachable'; $st.Reason = Get-FailureText -Kind TimedOut -Server $task.Server }
            else { Set-TimelineLogOutcome -Status $st -Log $task.Log -Outcome 'TimedOut' -Reason ("didn't answer within {0} s" -f $Engine.TimeoutSec) }
            $changed = $true
        }
    }

    foreach ($task in @($Engine.Draining)) {
        if ($task.Handle.IsCompleted) {
            try { $task.PowerShell.Dispose() } catch { }
            [void]$Engine.Draining.Remove($task)
        }
    }

    if (-not $Engine.Cancelled) { Start-PendingTimelineTasks -Engine $Engine }

    foreach ($st in $Engine.Status.Values) {
        if ($st.State -ne 'Querying') { continue }
        $busy = @($Engine.Running + $Engine.Pending | Where-Object { $_.Server -eq $st.Server }).Count
        if ($busy -eq 0) {
            # Skipped = the server doesn't have the log or has it turned off: not missing events.
            $gaps = @($st.Logs | Where-Object { $_.Outcome -notin @('Read', 'Skipped') }).Count
            $st.State = if ($gaps -gt 0) { 'DoneWithGaps' } else { 'Done' }
            $changed = $true
        }
    }

    [PSCustomObject]@{
        NewRows       = $rows.ToArray()
        StatusChanged = $changed
        Finished      = ($Engine.Running.Count -eq 0 -and $Engine.Pending.Count -eq 0)
    }
}

function Stop-TimelineEngine {
    <# Cancel: marks everything unfinished Cancelled at once and asks tasks to stop. Never blocks. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Engine)

    $Engine.Cancelled = $true
    foreach ($p in @($Engine.Pending)) {
        if ($p.Kind -eq 'Log') { Set-TimelineLogOutcome -Status $Engine.Status[$p.Server] -Log $p.Log -Outcome 'Cancelled' }
    }
    $Engine.Pending.Clear()
    foreach ($t in @($Engine.Running)) {
        Stop-TimelineTask -Engine $Engine -Task $t
        if ($t.Kind -eq 'Log') { Set-TimelineLogOutcome -Status $Engine.Status[$t.Server] -Log $t.Log -Outcome 'Cancelled' }
    }
    foreach ($st in $Engine.Status.Values) {
        if ($st.State -in @('Waiting', 'Querying')) { $st.State = 'Cancelled'; $st.Reason = 'Cancelled.' }
    }
    $Engine.StatusChanged = $true
}

function Close-TimelineEngine {
    <# For a new search or closing the window: stop everything and release the pool without waiting. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Engine)

    if (-not $Engine.Cancelled) { Stop-TimelineEngine -Engine $Engine }
    foreach ($t in @($Engine.Draining)) {
        if ($t.Handle.IsCompleted) { try { $t.PowerShell.Dispose() } catch { } }
    }
    try { [void]$Engine.Pool.BeginClose($null, $null) } catch { }
}
#endregion
