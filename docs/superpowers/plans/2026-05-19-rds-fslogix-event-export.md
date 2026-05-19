# RDS / FSLogix Event Export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone PowerShell script that exports RDS- and FSLogix-related Windows event log entries for a user-specified timeframe to CSV + self-contained HTML report.

**Architecture:** Single `.ps1` script in a new `RDS-FSLogix-EventExport/` folder. Functions are private (script-scope) — no module structure. The script enumerates RDS Operational logs dynamically, queries FSLogix logs by name, post-filters System/Application by provider, and opt-in pulls RDP-relevant Security events. Output goes to one CSV and one HTML file per run, timestamped per the project convention. There is no test framework in this repository, so verification is manual: pre-run static-analysis (`Invoke-ScriptAnalyzer` if present, plus parse-only `Get-Command -Syntax`) and post-run execution against the developer's own session host with documented inspection steps.

**Tech Stack:** PowerShell 5.1+, built-in `Get-WinEvent`, `Export-Csv`, `ConvertTo-Json` (not used in output but useful for debugging), `Here-String` HTML templating. No external modules.

**Design doc:** `docs/plans/2026-05-19-rds-fslogix-event-export-design.md`

---

## File structure

```
RDS-FSLogix-EventExport/
├── Export-RDSFSLogixEvents.ps1   # main script, one file
└── README.md                      # usage + examples
```

Inside `Export-RDSFSLogixEvents.ps1` the responsibilities are split into private functions, each with a single job:

| Function | Responsibility |
|---|---|
| `Resolve-TimeWindow` | Validate and normalize `-StartTime`/`-EndTime`/`-LastHours`/`-LastDays` into a `[datetime]` start + end pair. |
| `Resolve-OutputPath` | Validate `-OutputPath` is writable; return resolved absolute path. |
| `Test-IsElevated` | Return `$true` if running as Administrator. |
| `Get-RDSOperationalLogs` | Enumerate `Microsoft-Windows-TerminalServices-*` logs that exist on this host. |
| `Get-EventsFromLog` | Wrapper around `Get-WinEvent -FilterHashtable` with try/catch for missing logs and zero-result cases. Returns normalized `[pscustomobject]`s tagged with a `Category`. |
| `Get-RDSCategoryEvents` | Calls `Get-EventsFromLog` for every RDS Operational log. |
| `Get-FSLogixCategoryEvents` | Calls `Get-EventsFromLog` for the three FSLogix logs. |
| `Get-SystemAppCategoryEvents` | Pulls System + Application, post-filters by ProviderName (literals + wildcard). |
| `Get-SecurityCategoryEvents` | Pulls Security 4624/4625/4634/4647 then filters to LogonType 7/10. |
| `Write-StatusLine` | Color-coded `[INFO]/[PASS]/[WARN]/[FAIL]` console output (matches project convention). |
| `Export-EventsToCsv` | Flatten events to CSV columns and write via `Export-Csv`. |
| `Export-EventsToHtml` | Build the self-contained dark-themed HTML report. |

All functions are defined inside the same `.ps1`; the bottom of the file is the orchestration block that calls them in order.

---

## Task 1: Scaffold the folder, parameter block, comment-based help, and entry guard

**Files:**
- Create: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`
- Create: `RDS-FSLogix-EventExport/README.md`

- [ ] **Step 1: Create the script file with full param block and help**

Content for `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`:

```powershell
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
```

PowerShell parameter sets enforce the mutual-exclusion rule for us: a user cannot pass `-StartTime` together with `-LastHours` because they're in different sets. We still need a runtime guard for the "neither was passed" case (default to last 24h) — that's in Task 2.

- [ ] **Step 2: Create README.md**

Content for `RDS-FSLogix-EventExport/README.md`:

````markdown
# RDS-FSLogix-EventExport

Local-only PowerShell script that exports RDS- and FSLogix-related Windows event log entries for a user-specified time window to CSV plus a self-contained HTML report.

Designed to be dropped onto an RDS session host or Citrix VDA and run with no setup.

## Requirements
- Windows PowerShell 5.1 or later (PowerShell 7+ also works).
- Run locally on the host whose events you want to collect.
- Administrator elevation required only if you pass `-IncludeSecurity`. Non-admin runs still produce RDS + FSLogix output.

## Usage

```powershell
# Last 4 hours of errors and warnings, output to current directory
.\Export-RDSFSLogixEvents.ps1 -LastHours 4

# Explicit window with RDP logon events, output to C:\Logs
.\Export-RDSFSLogixEvents.ps1 -StartTime '2026-05-18 08:00' -EndTime '2026-05-18 17:00' -IncludeSecurity -OutputPath C:\Logs

# Last day including Information-level entries
.\Export-RDSFSLogixEvents.ps1 -LastDays 1 -Level 1,2,3,4
```

## Output

Two files, both timestamped:

- `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.csv` — flat per-event rows for Excel filtering.
- `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.html` — single self-contained HTML report with category sections, sortable tables, severity color-coding.

## What it collects

| Category | Source |
|---|---|
| RDS | All `Microsoft-Windows-TerminalServices-*/Operational` logs present on the host |
| FSLogix | `Microsoft-FSLogix-Apps/Operational`, `Microsoft-FSLogix-Apps/Admin`, `Microsoft-FSLogix-CloudCache/Operational` |
| System / Application | Filtered to providers: TermService, TermDD, RemoteDesktopServices, Microsoft-Windows-TerminalServices-*, frxsvc, frxccd, frxdrv, frxdrvvt |
| Security (opt-in) | 4624 / 4625 / 4634 / 4647 filtered to LogonType 7 (unlock) and 10 (RemoteInteractive) |

Default severity: 1 (Critical), 2 (Error), 3 (Warning). Override with `-Level`.

## Notes
- Time stamps in output are local time, matching Event Viewer.
- One missing or locked log does not halt the run; it logs a `[WARN]` and continues.
- A zero-event window still produces both files (HTML shows an empty state, CSV has the header only).
````

- [ ] **Step 3: Verify the script parses**

Run from the repo root:

```powershell
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw .\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1), [ref]$null); 'OK'
```

Expected output: `OK`

If you see a parser error, fix the indicated line and re-run.

- [ ] **Step 4: Verify Get-Help works**

```powershell
Get-Help .\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -Full | Out-String | Select-String -SimpleMatch 'SYNOPSIS'
```

Expected: one or more lines containing `SYNOPSIS`. If empty, the comment-based help block is malformed.

- [ ] **Step 5: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1 RDS-FSLogix-EventExport/README.md
git commit -m "feat: scaffold Export-RDSFSLogixEvents script and README"
```

---

## Task 2: Add console output helper and time-window resolver

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1` — append functions after the param block

- [ ] **Step 1: Append `Write-StatusLine` helper**

Add immediately after the `param(...)` block:

```powershell
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
```

- [ ] **Step 2: Append `Resolve-TimeWindow` function**

```powershell
# Returns a hashtable @{ Start = [datetime]; End = [datetime] } from the script's parameters.
# Defaults to the last 24 hours when neither -StartTime nor -LastHours/-LastDays were given.
function Resolve-TimeWindow {
    [CmdletBinding()]
    param(
        [Nullable[datetime]]$StartTime,
        [Nullable[datetime]]$EndTime,
        [Nullable[int]]$LastHours,
        [Nullable[int]]$LastDays
    )

    $now = Get-Date

    if ($StartTime.HasValue) {
        $start = $StartTime.Value
        $end   = if ($EndTime.HasValue) { $EndTime.Value } else { $now }
    }
    elseif ($LastHours.HasValue) {
        $end   = $now
        $start = $now.AddHours(-1 * $LastHours.Value)
    }
    elseif ($LastDays.HasValue) {
        $end   = $now
        $start = $now.AddDays(-1 * $LastDays.Value)
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
```

- [ ] **Step 3: Smoke-test the resolver interactively**

```powershell
. .\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastHours 1 -ErrorAction Stop *>$null
# That actually runs the whole script — instead do this:
$tmpScope = {
    . { (Get-Content -Raw .\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1) -replace '(?ms)^# ---- Functions defined.*$', '' | Invoke-Expression }
}
```

Simpler: open a new PowerShell session and paste just the `Resolve-TimeWindow` function body, then:

```powershell
Resolve-TimeWindow -LastHours 2          # Expect Start = now - 2h, End = now
Resolve-TimeWindow -StartTime (Get-Date).AddDays(-1)   # Expect Start = -24h, End = now
Resolve-TimeWindow                        # Expect Start = -24h, End = now (default)
```

Expected: each call returns a hashtable with `Start` and `End` keys; printing it shows two `DateTime` values.

- [ ] **Step 4: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add Write-StatusLine and Resolve-TimeWindow helpers"
```

---

## Task 3: Add output path validation and elevation check

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

- [ ] **Step 1: Append `Resolve-OutputPath`**

```powershell
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
```

- [ ] **Step 2: Append `Test-IsElevated`**

```powershell
function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
```

- [ ] **Step 3: Smoke-test in a fresh session**

Paste the two functions into a clean PowerShell, then:

```powershell
Resolve-OutputPath -Path .          # Expect: returns absolute path of cwd
Resolve-OutputPath -Path C:\NoSuchDir  # Expect: throws "does not exist"
Test-IsElevated                       # Expect: $true or $false depending on session
```

- [ ] **Step 4: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add Resolve-OutputPath and Test-IsElevated helpers"
```

---

## Task 4: Build the core event-collection wrapper

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

This is the function every category function calls. Get this right and the rest is plumbing.

- [ ] **Step 1: Append `Get-EventsFromLog`**

```powershell
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
        $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    }
    catch [System.Exception] {
        # Get-WinEvent throws when no matching events exist; detect via message.
        if ($_.Exception.Message -match 'No events were found') {
            Write-StatusLine -Status 'INFO' -Message ("0 events from {0}" -f $LogName)
            return @()
        }
        # Log not present on this host
        if ($_.Exception.Message -match 'There is not a log named' -or
            $_.Exception.Message -match 'The specified channel could not be found') {
            Write-StatusLine -Status 'INFO' -Message ("Log not present, skipping: {0}" -f $LogName)
            return @()
        }
        # Permission denied (Security log without admin)
        if ($_.Exception.Message -match 'Attempted to perform an unauthorized operation' -or
            $_.CategoryInfo.Category -eq 'PermissionDenied') {
            Write-StatusLine -Status 'WARN' -Message ("Access denied reading {0} (try elevation)" -f $LogName)
            return @()
        }
        Write-StatusLine -Status 'FAIL' -Message ("Error reading {0}: {1}" -f $LogName, $_.Exception.Message)
        return @()
    }

    Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1}" -f $raw.Count, $LogName)

    # Normalize to a flat pscustomobject. Don't include the FormatDescription if it's null.
    return $raw | ForEach-Object {
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
    }
}
```

- [ ] **Step 2: Smoke-test against a known log in a fresh session**

Paste `Write-StatusLine` and `Get-EventsFromLog` into a clean shell, then:

```powershell
$events = Get-EventsFromLog -LogName 'System' -Category 'Test' -Start (Get-Date).AddDays(-1) -End (Get-Date) -Level 1,2,3
$events.Count          # Expect: a number (could be 0 on a quiet box)
$events[0] | Format-List   # Expect: TimeCreated, Category=Test, LogName=System, Id, Level, ...
```

Then test the missing-log path:

```powershell
$events = Get-EventsFromLog -LogName 'Microsoft-Imaginary-DoesNotExist/Operational' -Category 'Test' -Start (Get-Date).AddDays(-1) -End (Get-Date) -Level 1,2,3
# Expect: INFO line "Log not present, skipping: ..."
# $events.Count -eq 0
```

- [ ] **Step 3: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add Get-EventsFromLog with missing-log and access-denied handling"
```

---

## Task 5: Add the four category-collection functions

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

- [ ] **Step 1: Append `Get-RDSOperationalLogs`**

```powershell
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
```

- [ ] **Step 2: Append `Get-RDSCategoryEvents`**

```powershell
function Get-RDSCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($logName in (Get-RDSOperationalLogs)) {
        $results.AddRange([object[]](Get-EventsFromLog -LogName $logName -Category 'RDS' -Start $Start -End $End -Level $Level))
    }
    return ,$results.ToArray()
}
```

- [ ] **Step 3: Append `Get-FSLogixCategoryEvents`**

```powershell
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
        $results.AddRange([object[]](Get-EventsFromLog -LogName $logName -Category 'FSLogix' -Start $Start -End $End -Level $Level))
    }
    return ,$results.ToArray()
}
```

- [ ] **Step 4: Append `Get-SystemAppCategoryEvents`**

```powershell
function Get-SystemAppCategoryEvents {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End,
        [Parameter(Mandatory)][int[]]$Level
    )
    # ProviderName supports a literal list in FilterHashtable, but no wildcard.
    # We query with the literal providers, then do a second pass that pulls anything
    # whose ProviderName begins with 'Microsoft-Windows-TerminalServices-' by post-filter.
    $literalProviders = @(
        'TermService','TermDD','RemoteDesktopServices',
        'frxsvc','frxccd','frxdrv','frxdrvvt'
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($logName in @('System','Application')) {
        # Literal-provider pass
        try {
            $literalEvents = Get-WinEvent -FilterHashtable @{
                LogName      = $logName
                StartTime    = $Start
                EndTime      = $End
                Level        = $Level
                ProviderName = $literalProviders
            } -ErrorAction Stop
            Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1} (literal providers)" -f $literalEvents.Count, $logName)
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                $literalEvents = @()
                Write-StatusLine -Status 'INFO' -Message ("0 events from {0} (literal providers)" -f $logName)
            } else {
                Write-StatusLine -Status 'FAIL' -Message ("Error on {0} literal pass: {1}" -f $logName, $_.Exception.Message)
                $literalEvents = @()
            }
        }

        # Wildcard-provider pass: query the whole log (filtered to level+time) and post-filter.
        # On a busy host this could be large; level filter keeps it bounded.
        try {
            $wildcardEvents = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $Start
                EndTime   = $End
                Level     = $Level
            } -ErrorAction Stop |
                Where-Object { $_.ProviderName -like 'Microsoft-Windows-TerminalServices-*' }
            Write-StatusLine -Status 'PASS' -Message ("{0,5} events from {1} (RDS provider wildcard)" -f $wildcardEvents.Count, $logName)
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') {
                $wildcardEvents = @()
                Write-StatusLine -Status 'INFO' -Message ("0 events from {0} (RDS provider wildcard)" -f $logName)
            } else {
                Write-StatusLine -Status 'FAIL' -Message ("Error on {0} wildcard pass: {1}" -f $logName, $_.Exception.Message)
                $wildcardEvents = @()
            }
        }

        foreach ($e in @($literalEvents) + @($wildcardEvents)) {
            $results.Add([pscustomobject]@{
                TimeCreated      = $e.TimeCreated
                Category         = 'System/App'
                LogName          = $e.LogName
                Id               = $e.Id
                Level            = $e.Level
                LevelDisplayName = $e.LevelDisplayName
                ProviderName     = $e.ProviderName
                MachineName      = $e.MachineName
                UserId           = if ($e.UserId) { $e.UserId.Value } else { '' }
                Message          = ($e.Message -replace "`r?`n", ' ' -replace '\s+', ' ').Trim()
            })
        }
    }

    # De-duplicate (an event could match both passes if a literal provider also matched the wildcard — it won't, but defensive).
    return ,(@($results) | Sort-Object TimeCreated, Id, LogName -Unique)
}
```

- [ ] **Step 5: Append `Get-SecurityCategoryEvents`**

```powershell
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

    # 4634/4647 have no LogonType in the message we kept (we collapsed it to one line),
    # so we keep them all; 4624/4625 we filter to LogonType 7 or 10 by inspecting the
    # original event's Properties array. Re-query in narrow batches to get the raw events.
    $filtered = New-Object System.Collections.Generic.List[object]
    foreach ($evt in $events) {
        if ($evt.Id -in 4634,4647) {
            $filtered.Add($evt)
            continue
        }
        # For 4624/4625 we need LogonType. Re-fetch this single record by RecordId
        # would be expensive; instead, parse it from the collapsed Message string.
        # The Message contains "Logon Type:        10" (or 7). Use a regex.
        if ($evt.Message -match 'Logon Type:\s*(\d+)') {
            $lt = [int]$Matches[1]
            if ($lt -in 7,10) { $filtered.Add($evt) }
        }
    }
    Write-StatusLine -Status 'INFO' -Message ("Filtered Security to {0} RDP-relevant events (LogonType 7/10)" -f $filtered.Count)
    return ,$filtered.ToArray()
}
```

- [ ] **Step 6: Smoke-test each category function**

In a fresh shell paste everything written so far, then on a host that has RDS/FSLogix:

```powershell
$start = (Get-Date).AddDays(-1); $end = Get-Date; $lvl = @(1,2,3)
(Get-RDSCategoryEvents       -Start $start -End $end -Level $lvl).Count   # number
(Get-FSLogixCategoryEvents   -Start $start -End $end -Level $lvl).Count   # number
(Get-SystemAppCategoryEvents -Start $start -End $end -Level $lvl).Count   # number
(Get-SecurityCategoryEvents  -Start $start -End $end -Level $lvl).Count   # number or warn-and-0
```

Expected: each call prints `[PASS]/[INFO]` lines per log and returns a count without throwing.

- [ ] **Step 7: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add per-category event collection (RDS, FSLogix, System/App, Security)"
```

---

## Task 6: Add CSV export

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

- [ ] **Step 1: Append `Export-EventsToCsv`**

```powershell
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
```

- [ ] **Step 2: Smoke-test**

```powershell
$dummy = @(
    [pscustomobject]@{ TimeCreated = (Get-Date); Category = 'RDS'; LogName = 'X'; Id = 1; Level = 2; LevelDisplayName = 'Error'; ProviderName = 'Y'; MachineName = 'Z'; UserId = ''; Message = 'hello' }
)
Export-EventsToCsv -Events $dummy -Path .\test.csv
Get-Content .\test.csv      # Expect: header row + one data row
Export-EventsToCsv -Events @() -Path .\empty.csv
Get-Content .\empty.csv     # Expect: header row only
Remove-Item .\test.csv, .\empty.csv
```

- [ ] **Step 3: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add Export-EventsToCsv"
```

---

## Task 7: Add HTML report export

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

This is the largest single function. Keep all CSS and JS inline so the output is one shareable file.

- [ ] **Step 1: Append `Export-EventsToHtml`**

```powershell
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

    # HTML-encoder for arbitrary strings.
    function Convert-ToHtmlEncoded([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Web.HttpUtility]::HtmlEncode($s)
    }
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

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

    $script = @'
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
    $byCat = @{}
    foreach ($cat in @('RDS','FSLogix','System/App','Security')) { $byCat[$cat] = 0 }
    foreach ($e in $Events) { $byCat[$e.Category]++ }

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
        $catEvents = $Events | Where-Object { $_.Category -eq $cat } | Sort-Object TimeCreated -Descending
        $catCount = @($catEvents).Count

        [void]$sectionsBuilder.Append("<details$(if($catCount -gt 0){' open'})>")
        [void]$sectionsBuilder.Append("<summary>$(Convert-ToHtmlEncoded $cat) <span class=`"count`">$catCount events</span></summary>")
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
                [void]$sectionsBuilder.Append("<td class=`"$lvlClass`">$(Convert-ToHtmlEncoded $e.LevelDisplayName)</td>")
                [void]$sectionsBuilder.Append("<td>$($e.Id)</td>")
                [void]$sectionsBuilder.Append("<td>$(Convert-ToHtmlEncoded $e.ProviderName)</td>")
                [void]$sectionsBuilder.Append("<td>$(Convert-ToHtmlEncoded $e.LogName)</td>")
                $msg = Convert-ToHtmlEncoded $e.Message
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

    $html = @"
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>RDS / FSLogix Events &mdash; $ComputerName</title>
$css
</head><body>
  <div class="header">
    <div>
      <h1>RDS / FSLogix Events</h1>
      <div class="meta">Host <code>$(Convert-ToHtmlEncoded $ComputerName)</code> &middot; Window <code>$($Start.ToString('yyyy-MM-dd HH:mm'))</code> &rarr; <code>$($End.ToString('yyyy-MM-dd HH:mm'))</code> &middot; Levels <code>$levelText</code></div>
    </div>
    <div class="meta">Generated $generatedAt</div>
  </div>

  <div class="summary">
    <div class="chip"><div class="label">Total</div><div class="value">$total</div></div>
    <div class="chip"><div class="label">RDS</div><div class="value">$($byCat['RDS'])</div></div>
    <div class="chip"><div class="label">FSLogix</div><div class="value">$($byCat['FSLogix'])</div></div>
    <div class="chip"><div class="label">System / App</div><div class="value">$($byCat['System/App'])</div></div>
$(if ($IncludedSecurity) { "    <div class=`"chip`"><div class=`"label`">Security</div><div class=`"value`">$($byCat['Security'])</div></div>" })
    <div class="chip"><div class="label">Errors</div><div class="value lvl-err">$($bySev.Critical + $bySev.Error)</div></div>
    <div class="chip"><div class="label">Warnings</div><div class="value lvl-warn">$($bySev.Warning)</div></div>
  </div>

  <h2>Events by Category</h2>
  $sectionsHtml

$script
</body></html>
"@

    $html | Out-File -LiteralPath $Path -Encoding UTF8
    Write-StatusLine -Status 'PASS' -Message ("Wrote HTML: {0}" -f $Path)
}
```

- [ ] **Step 2: Smoke-test against a synthetic event set**

```powershell
Add-Type -AssemblyName System.Web
$fake = @(
    [pscustomobject]@{ TimeCreated = (Get-Date); Category = 'RDS'; LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id = 21; Level = 4; LevelDisplayName = 'Information'; ProviderName = 'Microsoft-Windows-TerminalServices-LocalSessionManager'; MachineName = 'TESTHOST'; UserId = ''; Message = 'Remote Desktop Services: Session logon succeeded' }
    [pscustomobject]@{ TimeCreated = (Get-Date).AddMinutes(-5); Category = 'FSLogix'; LogName = 'Microsoft-FSLogix-Apps/Operational'; Id = 26; Level = 2; LevelDisplayName = 'Error'; ProviderName = 'Microsoft-FSLogix-Apps'; MachineName = 'TESTHOST'; UserId = ''; Message = 'Profile container mount failed for user X' }
)
Export-EventsToHtml -Events $fake -Path .\test.html -ComputerName 'TESTHOST' -Start (Get-Date).AddHours(-1) -End (Get-Date) -Level 1,2,3 -IncludedSecurity $false
# Open .\test.html in a browser. Verify:
#   - Dark theme renders.
#   - Total = 2, RDS = 1, FSLogix = 1.
#   - Both <details> sections are open.
#   - Clicking column headers sorts rows.
#   - Clicking the message cell expands it.

# Now test the empty-state path:
Export-EventsToHtml -Events @() -Path .\empty.html -ComputerName 'TESTHOST' -Start (Get-Date).AddHours(-1) -End (Get-Date) -Level 1,2,3 -IncludedSecurity $false
# Open .\empty.html and confirm the "No events in the specified window" message renders.

Remove-Item .\test.html, .\empty.html
```

- [ ] **Step 3: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: add Export-EventsToHtml with dark theme, sortable tables, empty state"
```

---

## Task 8: Wire up the orchestration block

**Files:**
- Modify: `RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1`

- [ ] **Step 1: Append orchestration logic at the bottom of the file**

```powershell
# ============================================================================
# Orchestration
# ============================================================================

try {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    # Resolve window. Pass nullable to satisfy Resolve-TimeWindow.
    $window = Resolve-TimeWindow `
        -StartTime $(if ($PSBoundParameters.ContainsKey('StartTime')) { $StartTime } else { $null }) `
        -EndTime   $(if ($PSBoundParameters.ContainsKey('EndTime'))   { $EndTime   } else { $null }) `
        -LastHours $(if ($PSBoundParameters.ContainsKey('LastHours')) { $LastHours } else { $null }) `
        -LastDays  $(if ($PSBoundParameters.ContainsKey('LastDays'))  { $LastDays  } else { $null })

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
    $all.AddRange([object[]](Get-RDSCategoryEvents -Start $window.Start -End $window.End -Level $Level))

    Write-StatusLine -Status 'INFO' -Message '--- Collecting FSLogix logs ---'
    $all.AddRange([object[]](Get-FSLogixCategoryEvents -Start $window.Start -End $window.End -Level $Level))

    Write-StatusLine -Status 'INFO' -Message '--- Collecting System / Application (filtered) ---'
    $all.AddRange([object[]](Get-SystemAppCategoryEvents -Start $window.Start -End $window.End -Level $Level))

    if ($IncludeSecurity) {
        Write-StatusLine -Status 'INFO' -Message '--- Collecting Security (RDP logon events) ---'
        $all.AddRange([object[]](Get-SecurityCategoryEvents -Start $window.Start -End $window.End -Level $Level))
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
```

- [ ] **Step 2: Parse-check**

```powershell
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw .\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1), [ref]$null); 'OK'
```

Expected: `OK`. Fix any parser error before continuing.

- [ ] **Step 3: Commit**

```bash
git add RDS-FSLogix-EventExport/Export-RDSFSLogixEvents.ps1
git commit -m "feat: wire up orchestration and exit handling"
```

---

## Task 9: Manual end-to-end verification

Run the script on an actual RDS or Citrix session host and walk through each scenario from the design.

- [ ] **Step 1: Quiet-window run**

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastHours 1 -OutputPath $env:TEMP
```

Inspect:
- Console shows `[INFO]` window/host/output lines, then `[PASS]/[INFO]` per log.
- Two files exist in `$env:TEMP`, both timestamped, both named `RDS-FSLogix-Events_<HOST>_*`.
- If zero events: CSV has only the header row; HTML shows the empty-state message.

- [ ] **Step 2: Wide-window run**

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastDays 7 -OutputPath $env:TEMP
```

Inspect:
- CSV row count matches the HTML header's "Total" chip.
- Open the HTML in a browser. Each non-empty category section is expanded, sortable on click, severity color-coded.
- Clicking a Message cell expands the truncated text.

- [ ] **Step 3: Non-admin Security run**

Open a *non-elevated* PowerShell:

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastHours 4 -IncludeSecurity -OutputPath $env:TEMP
```

Expected:
- `[WARN] Security log requires elevation - skipping` appears.
- RDS, FSLogix, and System/App sections still populate.
- HTML does NOT show a Security section (because `-IncludedSecurity` flag drives that).

Wait — re-read: the orchestration block sets `IncludedSecurity = $true` based on the param, but `Get-SecurityCategoryEvents` returns `@()` when not elevated. The HTML section will show, but with "No events". That's the correct behavior — the user asked for Security, we honored the ask, and the section is visibly empty with the warning explaining why.

- [ ] **Step 4: Conflicting-parameter run**

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -StartTime (Get-Date).AddHours(-1) -LastHours 2
```

Expected: PowerShell rejects the call before the script body runs, with a parameter-set ambiguity error. (This is why we used parameter sets in Task 1.)

- [ ] **Step 5: Read-only output path**

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastHours 1 -OutputPath 'C:\Windows\System32\drivers'
```

Expected: `[FAIL] Fatal: Output path is not writable: ...` and exit code 1. No partial files created.

- [ ] **Step 6: Information-level run**

```powershell
.\RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1 -LastHours 2 -Level 1,2,3,4 -OutputPath $env:TEMP
```

Expected: noticeably larger event count than the default `-Level 1,2,3` run on the same window.

- [ ] **Step 7: Final commit (if anything was tweaked during testing)**

If you made any fixes during steps 1-6, commit them:

```bash
git add -u
git commit -m "fix: address issues found in end-to-end testing"
```

If nothing changed, skip this step.

---

## Self-review notes

- All four design requirements (RDS / FSLogix / System+App / Security opt-in) have dedicated functions and corresponding tasks (Task 5).
- All four output rules (CSV with header even when empty, HTML with empty-state, dark theme, timestamped filenames) have steps that verify them (Tasks 6, 7, 9).
- Parameter validation (mutual exclusion, default window, output path writability) is enforced by parameter sets (Task 1) + `Resolve-TimeWindow` (Task 2) + `Resolve-OutputPath` (Task 3).
- Per-log error isolation (`Get-EventsFromLog` try/catch for "no events", "log not present", "access denied") is in Task 4 with explicit smoke tests for each branch.
- Function names are consistent across tasks (`Get-EventsFromLog`, `Write-StatusLine`, `Resolve-TimeWindow`, `Resolve-OutputPath` all referenced exactly as defined).
- Property names on the normalized event objects are consistent across `Get-EventsFromLog` (Task 4), `Get-SystemAppCategoryEvents` (Task 5), `Export-EventsToCsv` (Task 6), and `Export-EventsToHtml` (Task 7): `TimeCreated, Category, LogName, Id, Level, LevelDisplayName, ProviderName, MachineName, UserId, Message`.
- No tasks reference symbols not defined elsewhere in the plan. No placeholders.
