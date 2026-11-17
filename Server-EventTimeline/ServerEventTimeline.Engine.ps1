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
