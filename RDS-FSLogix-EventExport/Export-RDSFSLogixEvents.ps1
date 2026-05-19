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

# Writes the events to a CSV file. Always writes a header row, even when $Events is empty,
# so downstream consumers can rely on a consistent shape.
function Export-EventsToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory)][string]$Path
    )

    $columns = 'TimeCreated','Category','LogName','Id','Level','LevelDisplayName','ProviderName','MachineName','UserId','Message'

    if ($Events.Count -eq 0) {
        # Write header-only CSV.
        ($columns -join ',') | Out-File -LiteralPath $Path -Encoding UTF8
    } else {
        $Events |
            Select-Object $columns |
            Sort-Object TimeCreated |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }

    Write-StatusLine -Status 'PASS' -Message ("Wrote CSV: {0}" -f $Path)
}

# HTML-encode an arbitrary string. Loads System.Web on first call.
function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    if (-not ('System.Web.HttpUtility' -as [type])) {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}

function Export-EventsToHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level,
        [bool]$IncludedSecurity
    )

    $css = @'
<style>
  :root {
    --bg: #14181d; --panel: #1c2128; --panel2: #232a32; --border: #2d3540;
    --text: #e6edf3; --muted: #8b96a3; --accent: #5dade2;
    --err: #f85149; --warn: #d29922; --info: #58a6ff; --ok: #3fb950;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font: 14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px; font-size: 22px; font-weight: 600; letter-spacing: -0.01em; }
  h2 { margin: 32px 0 12px; font-size: 16px; font-weight: 600; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  .header { display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
  .header .meta { color: var(--muted); font-size: 13px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 8px; }
  .chip { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; }
  .chip .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  .chip .value { font-size: 20px; font-weight: 600; margin-top: 4px; }
  details { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
  details > summary { cursor: pointer; padding: 12px 16px; font-weight: 600; user-select: none; list-style: none; display: flex; justify-content: space-between; align-items: center; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary::after { content: '\25BC'; color: var(--muted); font-size: 10px; transition: transform 0.15s; }
  details[open] > summary::after { transform: rotate(180deg); }
  details > summary .count { color: var(--muted); font-weight: 400; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th { background: var(--panel2); text-align: left; padding: 8px 12px; font-weight: 600; cursor: pointer; user-select: none; border-bottom: 1px solid var(--border); white-space: nowrap; }
  thead th:hover { color: var(--accent); }
  tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:hover { background: rgba(255,255,255,0.02); }
  .lvl-err  { color: var(--err); font-weight: 600; }
  .lvl-warn { color: var(--warn); font-weight: 600; }
  .lvl-info { color: var(--info); }
  .lvl-muted{ color: var(--muted); }
  .msg { color: var(--text); max-width: 520px; }
  .msg.truncated { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; cursor: pointer; }
  .msg.truncated:hover { color: var(--accent); }
  .empty { text-align: center; padding: 64px 16px; color: var(--muted); }
  .empty strong { color: var(--text); display: block; font-size: 18px; margin-bottom: 8px; }
  code { background: var(--panel2); padding: 1px 6px; border-radius: 3px; font-size: 12px; color: var(--accent); }
</style>
'@

    $scriptBlock = @'
<script>
  document.addEventListener('click', function (e) {
    if (e.target.classList && e.target.classList.contains('truncated')) {
      e.target.classList.remove('truncated');
    }
  });
  document.querySelectorAll('table').forEach(function (table) {
    var headers = table.querySelectorAll('thead th');
    headers.forEach(function (th, idx) {
      var asc = true;
      th.addEventListener('click', function () {
        var tbody = table.querySelector('tbody');
        var rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort(function (a, b) {
          var av = a.children[idx].dataset.sort || a.children[idx].textContent;
          var bv = b.children[idx].dataset.sort || b.children[idx].textContent;
          var an = parseFloat(av), bn = parseFloat(bv);
          var cmp = (!isNaN(an) && !isNaN(bn)) ? (an - bn) : av.localeCompare(bv);
          return asc ? cmp : -cmp;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
        asc = !asc;
      });
    });
  });
</script>
'@

    # ----- Summary aggregates -----
    $total = $Events.Count
    $byCat = @{ 'RDS' = 0; 'FSLogix' = 0; 'System/App' = 0; 'Security' = 0 }
    foreach ($e in $Events) {
        if ($byCat.ContainsKey($e.Category)) { $byCat[$e.Category]++ }
    }

    $bySev = @{ Critical = 0; Error = 0; Warning = 0; Information = 0; Verbose = 0; Other = 0 }
    foreach ($e in $Events) {
        switch ($e.LevelDisplayName) {
            'Critical'    { $bySev.Critical++ }
            'Error'       { $bySev.Error++ }
            'Warning'     { $bySev.Warning++ }
            'Information' { $bySev.Information++ }
            'Verbose'     { $bySev.Verbose++ }
            default       { $bySev.Other++ }
        }
    }

    # ----- Build per-category sections -----
    $sectionsBuilder = New-Object System.Text.StringBuilder
    foreach ($cat in @('RDS','FSLogix','System/App','Security')) {
        if ($cat -eq 'Security' -and -not $IncludedSecurity) { continue }
        $catEvents = @($Events | Where-Object { $_.Category -eq $cat } | Sort-Object TimeCreated -Descending)
        $catCount = $catEvents.Count
        $openAttr = if ($catCount -gt 0) { ' open' } else { '' }

        [void]$sectionsBuilder.Append("<details$openAttr>")
        [void]$sectionsBuilder.Append("<summary>$(ConvertTo-HtmlEncoded $cat) <span class=`"count`">$catCount events</span></summary>")
        if ($catCount -eq 0) {
            [void]$sectionsBuilder.Append('<div class="empty"><strong>No events</strong>None in this window.</div>')
        } else {
            [void]$sectionsBuilder.Append('<table><thead><tr>')
            foreach ($h in 'Time','Level','Id','Provider','LogName','Message') {
                [void]$sectionsBuilder.Append("<th>$h</th>")
            }
            [void]$sectionsBuilder.Append('</tr></thead><tbody>')
            foreach ($e in $catEvents) {
                $lvlClass = switch ($e.LevelDisplayName) {
                    'Critical'    { 'lvl-err' }
                    'Error'       { 'lvl-err' }
                    'Warning'     { 'lvl-warn' }
                    'Information' { 'lvl-info' }
                    default       { 'lvl-muted' }
                }
                $timeIso = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                [void]$sectionsBuilder.Append('<tr>')
                [void]$sectionsBuilder.Append("<td data-sort=`"$($e.TimeCreated.Ticks)`">$timeIso</td>")
                [void]$sectionsBuilder.Append("<td class=`"$lvlClass`">$(ConvertTo-HtmlEncoded $e.LevelDisplayName)</td>")
                [void]$sectionsBuilder.Append("<td>$($e.Id)</td>")
                [void]$sectionsBuilder.Append("<td>$(ConvertTo-HtmlEncoded $e.ProviderName)</td>")
                [void]$sectionsBuilder.Append("<td>$(ConvertTo-HtmlEncoded $e.LogName)</td>")
                $msg = ConvertTo-HtmlEncoded $e.Message
                [void]$sectionsBuilder.Append("<td class=`"msg truncated`" title=`"Click to expand`">$msg</td>")
                [void]$sectionsBuilder.Append('</tr>')
            }
            [void]$sectionsBuilder.Append('</tbody></table>')
        }
        [void]$sectionsBuilder.Append('</details>')
    }
    $sectionsHtml = $sectionsBuilder.ToString()

    # ----- Empty-state header replaces the sections if there are zero events -----
    if ($total -eq 0) {
        $sectionsHtml = '<div class="empty"><strong>No events in the specified window</strong>Try widening the time range or including Information-level events with <code>-Level 1,2,3,4</code>.</div>'
    }

    $levelText = ($Level | Sort-Object) -join ', '
    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $compEnc = ConvertTo-HtmlEncoded $ComputerName
    $startFmt = $Start.ToString('yyyy-MM-dd HH:mm')
    $endFmt = $End.ToString('yyyy-MM-dd HH:mm')

    $securityChip = ''
    if ($IncludedSecurity) {
        $securityChip = "    <div class=`"chip`"><div class=`"label`">Security</div><div class=`"value`">$($byCat['Security'])</div></div>"
    }
    $errTotal = $bySev.Critical + $bySev.Error

    $html = @"
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>RDS / FSLogix Events &mdash; $compEnc</title>
$css
</head><body>
  <div class="header">
    <div>
      <h1>RDS / FSLogix Events</h1>
      <div class="meta">Host <code>$compEnc</code> &middot; Window <code>$startFmt</code> &rarr; <code>$endFmt</code> &middot; Levels <code>$levelText</code></div>
    </div>
    <div class="meta">Generated $generatedAt</div>
  </div>

  <div class="summary">
    <div class="chip"><div class="label">Total</div><div class="value">$total</div></div>
    <div class="chip"><div class="label">RDS</div><div class="value">$($byCat['RDS'])</div></div>
    <div class="chip"><div class="label">FSLogix</div><div class="value">$($byCat['FSLogix'])</div></div>
    <div class="chip"><div class="label">System / App</div><div class="value">$($byCat['System/App'])</div></div>
$securityChip
    <div class="chip"><div class="label">Errors</div><div class="value lvl-err">$errTotal</div></div>
    <div class="chip"><div class="label">Warnings</div><div class="value lvl-warn">$($bySev.Warning)</div></div>
  </div>

  <h2>Events by Category</h2>
  $sectionsHtml

$scriptBlock
</body></html>
"@

    $html | Out-File -LiteralPath $Path -Encoding UTF8
    Write-StatusLine -Status 'PASS' -Message ("Wrote HTML: {0}" -f $Path)
}

# ============================================================================
# Orchestration
# ============================================================================

try {
    if (-not ('System.Web.HttpUtility' -as [type])) {
        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    }

    # Forward only the time-window parameters the caller actually supplied.
    $windowArgs = @{}
    foreach ($p in 'StartTime','EndTime','LastHours','LastDays') {
        if ($PSBoundParameters.ContainsKey($p)) { $windowArgs[$p] = $PSBoundParameters[$p] }
    }
    $window = Resolve-TimeWindow @windowArgs

    $resolvedOut = Resolve-OutputPath -Path $OutputPath
    $stamp = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
    $csvPath  = Join-Path $resolvedOut ("RDS-FSLogix-Events_{0}_{1}.csv"  -f $env:COMPUTERNAME, $stamp)
    $htmlPath = Join-Path $resolvedOut ("RDS-FSLogix-Events_{0}_{1}.html" -f $env:COMPUTERNAME, $stamp)

    Write-StatusLine -Status 'INFO' -Message ("Host:    {0}" -f $env:COMPUTERNAME)
    Write-StatusLine -Status 'INFO' -Message ("Window:  {0}  ->  {1}" -f $window.Start, $window.End)
    Write-StatusLine -Status 'INFO' -Message ("Levels:  {0}" -f (($Level | Sort-Object) -join ', '))
    Write-StatusLine -Status 'INFO' -Message ("Output:  {0}" -f $resolvedOut)
    if ($IncludeSecurity) { Write-StatusLine -Status 'INFO' -Message 'Security log: requested (admin required)' }

    $all = New-Object System.Collections.Generic.List[object]

    Write-StatusLine -Status 'INFO' -Message '--- Collecting RDS Operational logs ---'
    foreach ($e in (Get-RDSCategoryEvents -Start $window.Start -End $window.End -Level $Level)) {
        $all.Add($e)
    }

    Write-StatusLine -Status 'INFO' -Message '--- Collecting FSLogix logs ---'
    foreach ($e in (Get-FSLogixCategoryEvents -Start $window.Start -End $window.End -Level $Level)) {
        $all.Add($e)
    }

    Write-StatusLine -Status 'INFO' -Message '--- Collecting System / Application (filtered) ---'
    foreach ($e in (Get-SystemAppCategoryEvents -Start $window.Start -End $window.End -Level $Level)) {
        $all.Add($e)
    }

    if ($IncludeSecurity) {
        Write-StatusLine -Status 'INFO' -Message '--- Collecting Security (RDP logon events) ---'
        foreach ($e in (Get-SecurityCategoryEvents -Start $window.Start -End $window.End -Level $Level)) {
            $all.Add($e)
        }
    }

    Write-StatusLine -Status 'INFO' -Message ("--- Total events collected: {0} ---" -f $all.Count)

    Export-EventsToCsv  -Events $all.ToArray() -Path $csvPath
    Export-EventsToHtml -Events $all.ToArray() -Path $htmlPath `
        -ComputerName $env:COMPUTERNAME -Start $window.Start -End $window.End `
        -Level $Level -IncludedSecurity ([bool]$IncludeSecurity)

    Write-StatusLine -Status 'PASS' -Message 'Done.'
}
catch {
    Write-StatusLine -Status 'FAIL' -Message ("Fatal: {0}" -f $_.Exception.Message)
    exit 1
}
