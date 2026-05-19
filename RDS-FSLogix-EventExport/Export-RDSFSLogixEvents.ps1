#Requires -Version 5.1

<#
.SYNOPSIS
    Exports RDS- and FSLogix-related Windows event log entries for a specified time window to CSV and HTML.

.DESCRIPTION
    Runs locally on an RDS / Citrix session host. Collects events from:
      - Microsoft-Windows-TerminalServices-*/Operational logs (dynamically enumerated)
      - Microsoft-FSLogix-Apps/Operational, /Admin, and Microsoft-FSLogix-CloudCache/Operational
      - System and Application logs, filtered to RDS/FSLogix providers
      - Optionally Security log entries 4624/4625/4634/4647 filtered to RDP logon types (7, 10)

    Writes a flat CSV plus a self-contained dark-themed HTML report. Per-log errors are
    caught so a single unreachable or missing log does not halt the run.

.PARAMETER StartTime
    Explicit start of the time window. Mutually exclusive with -LastHours / -LastDays.

.PARAMETER EndTime
    End of the time window. Defaults to (Get-Date) when -StartTime is supplied.

.PARAMETER LastHours
    Shortcut: collect events from the last N hours. Mutually exclusive with -StartTime.

.PARAMETER LastDays
    Shortcut: collect events from the last N days. Mutually exclusive with -StartTime.

.PARAMETER OutputPath
    Directory to write CSV and HTML files. Defaults to the current directory.

.PARAMETER IncludeSecurity
    Include Security log RDP logon events (4624/4625/4634/4647, logon types 7/10). Requires admin.

.PARAMETER Level
    Event severity levels to include. Defaults to 1,2,3 (Critical, Error, Warning).
    Pass 1..4 to include Information, or 1..5 for everything.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -LastHours 4
    Exports the last 4 hours of RDS + FSLogix errors and warnings to the current directory.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -StartTime '2026-05-18 08:00' -EndTime '2026-05-18 17:00' -IncludeSecurity -OutputPath C:\Logs
    Exports a specific 9-hour window including RDP logon events to C:\Logs.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -LastDays 1 -Level 1,2,3,4
    Exports the last 24 hours including Information-level events.

.NOTES
    Author: VC3 IT
    Runtime scales with event volume. For routine triage prefer narrow windows
    (a few hours). Whole-week pulls on busy brokers can take several minutes.
    Time stamps in output are local time, matching Event Viewer.
#>
[CmdletBinding(DefaultParameterSetName = 'Last')]
param(
    [Parameter(ParameterSetName = 'Explicit', Mandatory)]
    [datetime]$StartTime,

    [Parameter(ParameterSetName = 'Explicit')]
    [datetime]$EndTime,

    [Parameter(ParameterSetName = 'Last')]
    [ValidateRange(1, 720)]
    [int]$LastHours,

    [Parameter(ParameterSetName = 'Last')]
    [ValidateRange(1, 90)]
    [int]$LastDays,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$IncludeSecurity,

    [ValidateRange(1, 5)]
    [int[]]$Level = @(1, 2, 3)
)

# ---- Functions defined below; orchestration block at the bottom ----

# Color-coded console output matching project convention.
function Write-StatusLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('INFO','PASS','WARN','FAIL')][string]$Status,
        [Parameter(Mandatory)][string]$Message
    )
    $color = switch ($Status) {
        'INFO' { 'Cyan' }
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host ("{0} [{1}] {2}" -f $stamp, $Status, $Message) -ForegroundColor $color
}

# Returns a hashtable @{ Start = [datetime]; End = [datetime] } from the script's parameters.
# Defaults to the last 24 hours when neither -StartTime nor -LastHours/-LastDays were given.
# Caller passes only the parameters they want considered (PowerShell's parameter sets
# already enforce that StartTime and LastHours/LastDays are mutually exclusive).
function Resolve-TimeWindow {
    [CmdletBinding()]
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$LastHours,
        [int]$LastDays
    )

    $now = Get-Date
    $bound = $PSBoundParameters

    if ($bound.ContainsKey('StartTime')) {
        $start = $StartTime
        $end   = if ($bound.ContainsKey('EndTime')) { $EndTime } else { $now }
    }
    elseif ($bound.ContainsKey('LastHours')) {
        $end   = $now
        $start = $now.AddHours(-1 * $LastHours)
    }
    elseif ($bound.ContainsKey('LastDays')) {
        $end   = $now
        $start = $now.AddDays(-1 * $LastDays)
    }
    else {
        # Default: last 24 hours
        $end   = $now
        $start = $now.AddHours(-24)
    }

    if ($start -ge $end) {
        throw "StartTime ($start) must be earlier than EndTime ($end)."
    }

    return @{ Start = $start; End = $end }
}

# Validates that $Path is an existing writable directory. Returns its absolute path.
# Throws with a clear message on failure (caller is responsible for fail-fast).
function Resolve-OutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Output path does not exist or is not a directory: $Path"
    }

    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath

    # Probe write access by creating and deleting a hidden temp file.
    $probe = Join-Path $resolved (".write-probe-{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
    try {
        New-Item -ItemType File -Path $probe -Force -ErrorAction Stop | Out-Null
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
    }
    catch {
        throw "Output path is not writable: $resolved ($($_.Exception.Message))"
    }

    return $resolved
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Query a single Windows event log with a time + level filter.
# Returns an array of [pscustomobject] tagged with the supplied Category and original LogName.
# Catches the "no events were found" exception and treats it as success-with-zero.
# Catches access denied (Security log without admin) and emits a WARN.
function Get-EventsFromLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level,
        [int[]]$Id          # optional: restrict to specific event IDs
    )

    $filter = @{
        LogName   = $LogName
        StartTime = $Start
        EndTime   = $End
        Level     = $Level
    }
    if ($PSBoundParameters.ContainsKey('Id')) { $filter['Id'] = $Id }

    try {
        $raw = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
    }
    catch {
        $msg = $_.Exception.Message
        # Get-WinEvent throws when no matching events exist; detect via message.
        if ($msg -match 'No events were found') {
            Write-StatusLine -Status 'INFO' -Message ("0 events from {0}" -f $LogName)
            return @()
        }
        # Log not present on this host
        if ($msg -match 'There is not a log named' -or
            $msg -match 'The specified channel could not be found' -or
            $msg -match 'There is not an event log on the .* computer that matches') {
            Write-StatusLine -Status 'INFO' -Message ("Log not present, skipping: {0}" -f $LogName)
            return @()
        }
        # Permission denied (Security log without admin)
        if ($msg -match 'Attempted to perform an unauthorized operation' -or
            $_.CategoryInfo.Category -eq 'PermissionDenied') {
            Write-StatusLine -Status 'WARN' -Message ("Access denied reading {0} (try elevation)" -f $LogName)
            return @()
        }
        Write-StatusLine -Status 'FAIL' -Message ("Error reading {0}: {1}" -f $LogName, $msg)
        return @()
    }

    Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1}" -f $raw.Count, $LogName)

    # Normalize to a flat pscustomobject.
    return @($raw | ForEach-Object {
        [pscustomobject]@{
            TimeCreated      = $_.TimeCreated
            Category         = $Category
            LogName          = $_.LogName
            Id               = $_.Id
            Level            = $_.Level
            LevelDisplayName = $_.LevelDisplayName
            ProviderName     = $_.ProviderName
            MachineName      = $_.MachineName
            UserId           = if ($_.UserId) { $_.UserId.Value } else { '' }
            Message          = ($_.Message -replace "`r?`n", ' ' -replace '\s+', ' ').Trim()
        }
    })
}

# Normalize a raw EventLogRecord (from a direct Get-WinEvent call) into the same
# flat shape Get-EventsFromLog produces. Used by Get-SystemAppCategoryEvents which
# does its own two-pass Get-WinEvent calls.
function ConvertTo-NormalizedEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Event,
        [Parameter(Mandatory)][string]$Category
    )
    process {
        [pscustomobject]@{
            TimeCreated      = $Event.TimeCreated
            Category         = $Category
            LogName          = $Event.LogName
            Id               = $Event.Id
            Level            = $Event.Level
            LevelDisplayName = $Event.LevelDisplayName
            ProviderName     = $Event.ProviderName
            MachineName      = $Event.MachineName
            UserId           = if ($Event.UserId) { $Event.UserId.Value } else { '' }
            Message          = ($Event.Message -replace "`r?`n", ' ' -replace '\s+', ' ').Trim()
        }
    }
}

# Enumerate Microsoft-Windows-TerminalServices-* logs that exist on this host.
# Returns an array of [string] log names.
function Get-RDSOperationalLogs {
    try {
        $logs = Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-*' -ErrorAction Stop |
                Where-Object { $_.LogName -like '*/Operational' }
        return ,@($logs | Select-Object -ExpandProperty LogName)
    }
    catch {
        Write-StatusLine -Status 'WARN' -Message ("Could not enumerate TerminalServices logs: {0}" -f $_.Exception.Message)
        return @()
    }
}

function Get-RDSCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($logName in (Get-RDSOperationalLogs)) {
        $events = Get-EventsFromLog -LogName $logName -Category 'RDS' -Start $Start -End $End -Level $Level
        foreach ($e in $events) { $results.Add($e) }
    }
    return ,$results.ToArray()
}

function Get-FSLogixCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )
    $logs = @(
        'Microsoft-FSLogix-Apps/Operational'
        'Microsoft-FSLogix-Apps/Admin'
        'Microsoft-FSLogix-CloudCache/Operational'
    )
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($logName in $logs) {
        $events = Get-EventsFromLog -LogName $logName -Category 'FSLogix' -Start $Start -End $End -Level $Level
        foreach ($e in $events) { $results.Add($e) }
    }
    return ,$results.ToArray()
}

function Get-SystemAppCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )
    # ProviderName supports a literal list in FilterHashtable, but no wildcard.
    # Pass 1: query with literal providers (filtered to those actually present on this
    # host — Get-WinEvent errors out if even one named provider is missing).
    # Pass 2: query the whole log (level + time filtered) and post-filter providers
    # matching Microsoft-Windows-TerminalServices-*.
    $literalProvidersAll = @(
        'TermService','TermDD','RemoteDesktopServices',
        'frxsvc','frxccd','frxdrv','frxdrvvt'
    )

    # Check each candidate individually so one bad provider on the host doesn't poison the enumeration.
    $literalProviders = @($literalProvidersAll | ForEach-Object {
        $name = $_
        try {
            $null = Get-WinEvent -ListProvider $name -ErrorAction Stop
            $name
        } catch {
            # Provider not present — silently skip.
        }
    })
    if ($literalProviders.Count -eq 0) {
        Write-StatusLine -Status 'INFO' -Message 'No RDS/FSLogix literal providers present on this host - skipping literal pass'
    } else {
        Write-StatusLine -Status 'INFO' -Message ("Literal providers found: {0}" -f ($literalProviders -join ', '))
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($logName in @('System','Application')) {
        # --- Literal-provider pass ---
        $literalEvents = @()
        if ($literalProviders.Count -gt 0) {
            try {
                $literalEvents = @(Get-WinEvent -FilterHashtable @{
                    LogName      = $logName
                    StartTime    = $Start
                    EndTime      = $End
                    Level        = $Level
                    ProviderName = $literalProviders
                } -ErrorAction Stop)
                Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1} (literal providers)" -f $literalEvents.Count, $logName)
            }
            catch {
                if ($_.Exception.Message -match 'No events were found') {
                    Write-StatusLine -Status 'INFO' -Message ("0 events from {0} (literal providers)" -f $logName)
                } else {
                    Write-StatusLine -Status 'FAIL' -Message ("Error on {0} literal pass: {1}" -f $logName, $_.Exception.Message)
                }
            }
        }

        # --- Wildcard-provider pass ---
        $wildcardEvents = @()
        try {
            $wildcardEvents = @(
                Get-WinEvent -FilterHashtable @{
                    LogName   = $logName
                    StartTime = $Start
                    EndTime   = $End
                    Level     = $Level
                } -ErrorAction Stop |
                    Where-Object { $_.ProviderName -like 'Microsoft-Windows-TerminalServices-*' }
            )
            Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1} (RDS provider wildcard)" -f $wildcardEvents.Count, $logName)
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                Write-StatusLine -Status 'INFO' -Message ("0 events from {0} (RDS provider wildcard)" -f $logName)
            } else {
                Write-StatusLine -Status 'FAIL' -Message ("Error on {0} wildcard pass: {1}" -f $logName, $_.Exception.Message)
            }
        }

        foreach ($e in @($literalEvents) + @($wildcardEvents)) {
            $results.Add((ConvertTo-NormalizedEvent -Event $e -Category 'System/App'))
        }
    }

    if ($results.Count -eq 0) { return ,@() }

    # De-duplicate: an event could in principle match both passes; sort -Unique
    # on TimeCreated+Id+LogName+ProviderName is a safe key.
    return ,@($results | Sort-Object TimeCreated, Id, LogName, ProviderName -Unique)
}

function Get-SecurityCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )

    if (-not (Test-IsElevated)) {
        Write-StatusLine -Status 'WARN' -Message 'Security log requires elevation - skipping'
        return @()
    }

    # Pull the four logon-related IDs, then post-filter on LogonType.
    $events = Get-EventsFromLog -LogName 'Security' -Category 'Security' -Start $Start -End $End -Level $Level -Id 4624,4625,4634,4647

    # 4634 (logoff) and 4647 (initiated logoff) are session-end events and we keep them all;
    # 4624/4625 we filter to LogonType 7 (unlock) or 10 (RemoteInteractive) by parsing
    # the collapsed Message string ("Logon Type:        10").
    $filtered = New-Object System.Collections.Generic.List[object]
    foreach ($evt in $events) {
        if ($evt.Id -in 4634,4647) {
            $filtered.Add($evt)
            continue
        }
        if ($evt.Message -match 'Logon Type:\s*(\d+)') {
            $lt = [int]$Matches[1]
            if ($lt -in 7,10) { $filtered.Add($evt) }
        }
    }
    Write-StatusLine -Status 'INFO' -Message ("Filtered Security to {0} RDP-relevant events (LogonType 7/10)" -f $filtered.Count)
    return ,$filtered.ToArray()
}
