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
    - Get-WinEvent (FilterHashtable LogName/StartTime/EndTime, -MaxEvents, -Oldest, -ListLog,
      -ComputerName, -Credential):
      https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
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
    param([string]$LogName, [long]$StartTicks, [long]$EndTicks, [int]$MaxEvents, [string]$ComputerName, $Credential)

    $start = New-Object DateTime ($StartTicks, [DateTimeKind]::Utc)
    $end = New-Object DateTime ($EndTicks, [DateTimeKind]::Utc)
    $params = @{
        FilterHashtable = @{ LogName = $LogName; StartTime = $start; EndTime = $end }
        MaxEvents       = $MaxEvents
        Oldest          = $true
        ErrorAction     = 'Stop'
    }
    if ($ComputerName) { $params.ComputerName = $ComputerName }
    if ($Credential) { $params.Credential = $Credential }

    $raw = @()
    try { $raw = @(Get-WinEvent @params) }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }

    $events = foreach ($e in $raw) {
        New-Object PSObject -Property @{
            TimeCreatedUtc = $e.TimeCreated.ToUniversalTime()
            Id             = $e.Id
            ProviderName   = $e.ProviderName
            Level          = [int]$e.Level
            LogName        = $e.LogName
            Message        = $e.Message
            RecordId       = $e.RecordId
            UserSid        = if ($e.UserId) { $e.UserId.Value } else { '' }
            MachineName    = $e.MachineName
        }
    }
    New-Object PSObject -Property @{ Events = @($events) }
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
        Channels = @(); FailureKind = ''; Reason = ''
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
        $params = @{ ListLog = '*'; ComputerName = $ComputerName; ErrorAction = 'SilentlyContinue' }
        if ($Credential) { $params.Credential = $Credential }
        $result.Channels = @(Get-WinEvent @params | ForEach-Object { [PSCustomObject]@{ Name = $_.LogName; IsEnabled = [bool]$_.IsEnabled; RecordCount = $_.RecordCount } })
        $result.UtcOffsetMinutes = Get-RpcUtcOffsetMinutes -ComputerName $ComputerName -Credential $Credential
        $result.Reachable = $true
        $result.Transport = 'RPC'
    }
    catch {
        $kind = Get-RemoteFailureKind -ErrorRecord $_
        $result.Reachable = $false
        $result.FailureKind = $kind
        $result.Reason = Get-FailureText -Kind $kind -Server $ComputerName -Detail $_.Exception.Message
    }
    return $result
}

function Invoke-LogQuery {
    <# One log on one server for the UTC window. Outcome Read, Capped or Failed. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][ValidateSet('WinRM', 'RPC')][string]$Transport,
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc,
        [int]$Cap = 5000,
        [pscredential]$Credential
    )

    $result = [PSCustomObject]@{ Server = $ComputerName; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' }
    $queryArgs = @($LogName, $StartUtc.Ticks, $EndUtc.Ticks, ($Cap + 1))

    try {
        if ($Transport -eq 'WinRM') {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $script:LogQueryScript; ArgumentList = ($queryArgs + @('', $null)); ErrorAction = 'Stop' }
            if ($Credential) { $params.Credential = $Credential }
            $answer = Invoke-Command @params
        }
        else {
            $answer = & $script:LogQueryScript @queryArgs $ComputerName $Credential
        }
    }
    catch {
        $result.Outcome = 'Failed'
        $result.Reason = Get-FailureText -Kind (Get-RemoteFailureKind -ErrorRecord $_) -Server $ComputerName -Detail $_.Exception.Message
        return $result
    }

    $events = @($answer.Events | Where-Object { $_ })
    if ($events.Count -gt $Cap) {
        $events = @($events[0..($Cap - 1)])
        $result.Outcome = 'Capped'
        $result.Reason = 'stopped at {0:N0} events' -f $Cap
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

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrency)
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
        TimeoutSec = $TimeoutSec; MaxConcurrency = $MaxConcurrency; Credential = $Credential
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
    while ($Engine.Pending.Count -gt 0 -and $Engine.Running.Count -lt $Engine.MaxConcurrency) {
        $task = $Engine.Pending[0]
        $Engine.Pending.RemoveAt(0)
        $script = if ($task.Kind -eq 'Probe') { $Engine.ProbeScript } else { $Engine.LogScript }
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $Engine.Pool
        [void]$ps.AddScript($script.ToString())
        foreach ($k in $task.Parameters.Keys) { [void]$ps.AddParameter($k, $task.Parameters[$k]) }
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
    $plan = Get-LogPlan -Probe $Probe -Catalog $Engine.Catalog -SelectedNames $Engine.SelectedLogs -AllLogs $Engine.AllLogs
    foreach ($skip in @($plan.Skipped)) { Set-TimelineLogOutcome -Status $st -Log $skip.Log -Outcome 'Skipped' -Reason $skip.Reason }
    $utc = ConvertTo-UtcWindow -Window $Engine.Window -UtcOffsetMinutes $st.UtcOffsetMinutes
    foreach ($log in @($plan.Query)) {
        Set-TimelineLogOutcome -Status $st -Log $log -Outcome 'Pending'
        [void]$Engine.Pending.Add([PSCustomObject]@{
                Kind = 'Log'; Server = $Task.Server; Log = $log
                Parameters = [ordered]@{ EnginePath = $script:EngineFilePath; Server = $Task.Server; Transport = $Probe.Transport; LogName = $log
                    StartUtc = $utc.StartUtc; EndUtc = $utc.EndUtc; Cap = $Engine.Cap; Credential = $Engine.Credential }
            })
    }
}

function Complete-TimelineLog {
    param($Engine, $Task, $Result, $Rows)
    $st = $Engine.Status[$Task.Server]
    if (-not $Result) { Set-TimelineLogOutcome -Status $st -Log $Task.Log -Outcome 'Failed' -Reason 'No answer from the server.'; return }
    $events = @($Result.Events | Where-Object { $_ })
    $room = $Engine.ServerTotalCap - $st.EventCount
    $hitTotal = $events.Count -ge $room
    if ($events.Count -gt $room) { $events = @($events | Select-Object -First ([Math]::Max($room, 0))) }

    foreach ($e in $events) { $Rows.Add((ConvertTo-TimelineRow -Server $Task.Server -Event $e -UtcOffsetMinutes $st.UtcOffsetMinutes)) }
    $st.EventCount += $events.Count
    Set-TimelineLogOutcome -Status $st -Log $Task.Log -Outcome $Result.Outcome -Count $events.Count -Reason $Result.Reason

    if ($hitTotal) {
        $reason = 'stopped at the {0:N0} event total for this server' -f $Engine.ServerTotalCap
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
            $gaps = @($st.Logs | Where-Object { $_.Outcome -ne 'Read' }).Count
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
