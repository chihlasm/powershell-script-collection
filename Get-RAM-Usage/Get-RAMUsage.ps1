<#
.SYNOPSIS
    Breaks down RAM usage by user and process on a Citrix VDA (or any multi-session) server.

.DESCRIPTION
    Collects all running processes with their owning user, measures each process's Private
    Working Set (the "Working Set - Private" counter, which Task Manager shows as private
    working set), and produces:
      - Console summary of per-user RAM usage
      - Interactive HTML report with click-to-expand user drill-down, search, and sorting
      - Optional CSV with one row per process

    Read-only. Nothing on the target server is changed.

.PARAMETER ComputerName
    Target server(s) to query. Defaults to the local machine. The names '.', 'localhost',
    this computer's name, and its FQDN are all treated as the local machine and queried
    without PowerShell remoting.

.PARAMETER Credential
    Optional PSCredential for remote server authentication.

.PARAMETER Top
    Number of top processes to show per user in console output. Default: 15. Use 0 for all.

.PARAMETER OutputPath
    Folder the HTML report (and CSV, when -ExportCSV is a bare file name) is written to.
    Defaults to the current directory. Created if it does not exist.

.PARAMETER ExportCSV
    Also export one row per process to CSV. A bare file name (e.g. ram.csv) is written into
    -OutputPath; a full path is used as-is.

.PARAMETER ExportHTML
    Full path for the HTML report, overriding the default
    <OutputPath>\RAMUsage_<yyyy-MM-dd_HHmmss>.html.

.PARAMETER SkipBrowserOpen
    Don't auto-open the HTML report after generation.

.PARAMETER IncludeSystemProcesses
    Also break down SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and other service / system
    accounts per account in the console (by default they are summarised in one line), and
    open the HTML report with system accounts already shown.

.PARAMETER LoadFunctionsOnly
    Define the script's functions and return without collecting anything. Used by the
    Pester tests.

.EXAMPLE
    .\Get-RAMUsage.ps1
    Shows RAM breakdown for all users on the local server and opens the HTML report.

.EXAMPLE
    .\Get-RAMUsage.ps1 -ComputerName CTXVDA01, CTXVDA02 -OutputPath C:\Reports
    Compares two VDAs in one report saved to C:\Reports.

.EXAMPLE
    .\Get-RAMUsage.ps1 -ExportCSV ram.csv -SkipBrowserOpen
    Writes the HTML report and ram.csv to the current directory without opening a browser.

.EXAMPLE
    .\Get-RAMUsage.ps1 -IncludeSystemProcesses
    Also itemises service and system accounts - useful when the RAM is not going to users.

.NOTES
    Requires: Windows PowerShell 4.0+ (for Get-Process -IncludeUserName; Server 2012 R2
              works as shipped), run as Administrator. For remote servers,
              PowerShell remoting (WinRM) for the process list and CIM for the counters.
    Version : 1.2.0

    REFERENCES
    - Get-Process (5.1): -IncludeUserName requires Run as administrator; the local computer
      can be named by computer name, '.', or 'localhost'.
      https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-process?view=powershell-5.1
    - Memory Performance Information: the "Working Set - Private" counter maps to Task
      Manager's Private Working Set; Private Bytes (PrivateMemorySize64) maps to Commit Size.
      https://learn.microsoft.com/windows/win32/memory/memory-performance-information
#>

# 4.0 (not 3.0) because Get-Process -IncludeUserName needs 4.0; runs on Server 2012 R2 as shipped. Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 4.0

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [PSCredential]$Credential,

    [ValidateRange(0, 100000)]
    [int]$Top = 15,

    [string]$OutputPath = '',

    [string]$ExportCSV,

    [string]$ExportHTML,

    [switch]$SkipBrowserOpen,

    [switch]$IncludeSystemProcesses,

    [switch]$LoadFunctionsOnly
)

$ScriptVersion = '1.2.0'
$ErrorActionPreference = 'Continue'

# This file is deliberately pure ASCII. Windows PowerShell 5.1 reads a BOM-less file as
# ANSI, and a UTF-8 em-dash decodes to a sequence ending in U+201D - which PowerShell
# treats as a closing double quote, silently ending the string and breaking the whole
# script (65 parse errors in v1.1.0). Non-ASCII glyphs are built from char codes or
# CSS/JS escapes instead. The Tests folder enforces this.

#region Helper Functions
function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Test-IsLocalComputer {
    # Get-Process documents '.', 'localhost', and the computer name as the local machine.
    # The FQDN is included too, so none of them fall through to Invoke-Command, which
    # would need WinRM just to query the machine the script is already running on.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $n = $Name.Trim()
    if ($n -eq '.' -or $n -eq 'localhost' -or $n -eq '127.0.0.1' -or $n -eq '::1') { return $true }
    if ($n -eq $env:COMPUTERNAME) { return $true }
    if ($n -like "$($env:COMPUTERNAME).*") { return $true }
    return $false
}

function Resolve-OutputFolder {
    # Blank means "current directory", resolved at run time rather than as a param default
    # so the value is correct however the script is launched.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return (Get-Location).ProviderPath }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Resolve-ExportFilePath {
    # A bare file name lands in the output folder; anything with a folder part is used as-is.
    param([string]$Path, [string]$Folder)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ([string]::IsNullOrEmpty((Split-Path $Path -Parent))) { return (Join-Path $Folder $Path) }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertTo-JsString {
    # Quoted JavaScript string literal. '<' is escaped so a process or user name can never
    # close the report's <script> block.
    param([string]$Text)
    if ($null -eq $Text) { $Text = '' }
    $escaped = $Text.Replace('\', '\\').Replace('"', '\"').Replace('<', '\u003c').Replace("`r", '\r').Replace("`n", '\n')
    return '"' + $escaped + '"'
}

function ConvertTo-JsNumber {
    # Invariant-culture number; missing values become 0 so one unreadable process cannot
    # produce "pws:," and break the whole report's JavaScript.
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '0' }
    return ([double]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-ServerMemoryInfo {
    param([string]$Server, [PSCredential]$Cred)

    $cimParams = @{ ClassName = 'Win32_OperatingSystem'; ErrorAction = 'Stop' }
    if (-not (Test-IsLocalComputer $Server)) {
        $cimParams['ComputerName'] = $Server
    }

    try {
        if ($cimParams.ContainsKey('ComputerName') -and $Cred) {
            $session = New-CimSession -ComputerName $Server -Credential $Cred -ErrorAction Stop
            try { $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop }
            finally { Remove-CimSession $session -ErrorAction SilentlyContinue }
        }
        else {
            $os = Get-CimInstance @cimParams
        }
        return [PSCustomObject]@{
            TotalPhysicalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
            FreePhysicalMB  = [math]::Round($os.FreePhysicalMemory / 1024, 0)
            UsedPhysicalMB  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1024, 0)
            PercentUsed     = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
        }
    }
    catch {
        Write-Host "  [WARN] Could not retrieve memory totals from $Server : $_" -ForegroundColor Yellow
        return $null
    }
}

function Get-ProcessesByUser {
    param([string]$Server, [PSCredential]$Cred)

    $results = (New-Object 'System.Collections.Generic.List[object]')
    $isLocal = Test-IsLocalComputer $Server

    # Step 1: processes with their owning user. -IncludeUserName requires elevation.
    try {
        if ($isLocal) {
            $procs = Get-Process -IncludeUserName -ErrorAction Stop
        }
        else {
            $icParams = @{ ComputerName = $Server; ErrorAction = 'Stop' }
            if ($Cred) { $icParams['Credential'] = $Cred }
            $procs = Invoke-Command @icParams -ScriptBlock {
                Get-Process -IncludeUserName -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Host "  [FAIL] Could not retrieve processes from $Server : $_" -ForegroundColor Red
        if ($isLocal) {
            Write-Host "  [INFO] Run PowerShell as Administrator - the process owner list requires it." -ForegroundColor Cyan
        }
        else {
            Write-Host "  [INFO] Check that PowerShell remoting (WinRM) is enabled on $Server and you are an admin there." -ForegroundColor Cyan
        }
        return $results
    }

    # Step 2: Private Working Set per PID from the performance counter class.
    $privateWSMap = @{}
    try {
        if (-not $isLocal -and $Cred) {
            $session = New-CimSession -ComputerName $Server -Credential $Cred -ErrorAction Stop
            try { $perfData = Get-CimInstance -CimSession $session -ClassName Win32_PerfRawData_PerfProc_Process -ErrorAction Stop }
            finally { Remove-CimSession $session -ErrorAction SilentlyContinue }
        }
        elseif (-not $isLocal) {
            $perfData = Get-CimInstance -ComputerName $Server -ClassName Win32_PerfRawData_PerfProc_Process -ErrorAction Stop
        }
        else {
            $perfData = Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -ErrorAction Stop
        }

        foreach ($perf in ($perfData | Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' })) {
            # Keyed by PID, so duplicate process names (chrome#1, chrome#2) do not collide.
            $privateWSMap[[int]$perf.IDProcess] = [long]$perf.WorkingSetPrivate
        }
    }
    catch {
        Write-Host "  [WARN] Could not read private working set counters from $Server - using commit size (PrivateMemorySize64) instead, which reads higher." -ForegroundColor Yellow
    }

    foreach ($proc in $procs) {
        $userName = if ($proc.UserName) { $proc.UserName } else { 'UNKNOWN' }

        $privateWS = if ($privateWSMap.ContainsKey([int]$proc.Id)) {
            $privateWSMap[[int]$proc.Id]
        }
        else {
            # PrivateMemorySize64 is Private Bytes, which Task Manager calls Commit Size.
            [long]$proc.PrivateMemorySize64
        }

        $results.Add([PSCustomObject]@{
            Server            = $Server
            UserName          = $userName
            ProcessName       = $proc.ProcessName
            PID               = $proc.Id
            SessionId         = $proc.SessionId
            PrivateWorkingSet = $privateWS
            PrivateWSMB       = [math]::Round($privateWS / 1MB, 2)
            WorkingSetBytes   = $proc.WorkingSet64
            WorkingSetMB      = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            CPU_Seconds       = if ($proc.CPU) { [math]::Round($proc.CPU, 1) } else { 0 }
            HandleCount       = $proc.HandleCount
            ThreadCount       = $proc.Threads.Count
            StartTime         = $proc.StartTime
        })
    }

    return $results
}

function Test-IsSystemAccount {
    param([string]$UserName)
    # Kept inside the function so the check never depends on a script-scope variable
    # being visible from wherever it is called.
    $systemAccounts = @(
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\LOCAL SERVICE',
        'NT AUTHORITY\NETWORK SERVICE',
        'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'UNKNOWN'
    )
    if ([string]::IsNullOrWhiteSpace($UserName)) { return $true }
    foreach ($sa in $systemAccounts) {
        if ($UserName -eq $sa -or $UserName.StartsWith($sa)) { return $true }
    }
    if ($UserName -match 'DWM-\d+$' -or $UserName -match 'UMFD-\d+$' -or $UserName -match 'Window Manager') { return $true }
    return $false
}

function Get-AccountGroups {
    # Groups one server's processes by account, largest private working set first.
    param([object[]]$Processes, [switch]$SystemAccounts)
    $selected = @($Processes | Where-Object { [bool](Test-IsSystemAccount $_.UserName) -eq [bool]$SystemAccounts })
    if ($selected.Count -eq 0) { return @() }
    return @($selected | Group-Object UserName |
        Sort-Object { ($_.Group | Measure-Object -Property PrivateWorkingSet -Sum).Sum } -Descending)
}

function Write-AccountBreakdown {
    param([object[]]$Groups, [string]$Heading, [int]$TopCount)

    Write-Host ""
    Write-Host "  $Heading ($($Groups.Count) accounts) - Private Working Set" -ForegroundColor White

    $rank = 0
    foreach ($group in $Groups) {
        $rank++
        $procs = $group.Group
        $totalBytes = ($procs | Measure-Object -Property PrivateWorkingSet -Sum).Sum
        $sessIds = ($procs | Select-Object -ExpandProperty SessionId -Unique | Sort-Object) -join ','
        $usageColor = if ($totalBytes -ge 4GB) { 'Red' } elseif ($totalBytes -ge 2GB) { 'Yellow' } else { 'Green' }

        Write-Host ""
        Write-Host "  $rank. " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($group.Name)" -NoNewline -ForegroundColor White
        Write-Host " (Session $sessIds)" -ForegroundColor DarkGray
        Write-Host "     Total: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$(Format-Bytes $totalBytes)" -NoNewline -ForegroundColor $usageColor
        Write-Host "  ($(@($procs).Count) processes)" -ForegroundColor DarkGray

        $topProcs = $procs | Sort-Object PrivateWorkingSet -Descending
        if ($TopCount -gt 0) { $topProcs = $topProcs | Select-Object -First $TopCount }
        foreach ($tp in $topProcs) {
            Write-Host "       $($tp.ProcessName.PadRight(30)) $((Format-Bytes $tp.PrivateWorkingSet).PadLeft(12))   PID: $($tp.PID)" -ForegroundColor Gray
        }
        if ($TopCount -gt 0 -and @($procs).Count -gt $TopCount) {
            Write-Host "       ... +$(@($procs).Count - $TopCount) more" -ForegroundColor DarkGray
        }
    }
}
#endregion

#region HTML Report
function Export-InteractiveHTMLReport {
    param(
        [System.Collections.Generic.List[object]]$AllData,
        [hashtable]$ServerMemory,
        [string]$OutputFile,
        [string[]]$Servers,
        [switch]$ShowSystemByDefault
    )

    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $serverList = [System.Security.SecurityElement]::Escape(($Servers -join ', '))
    $initialShowSystem = if ($ShowSystemByDefault) { 'true' } else { 'false' }
    $initialSysLabel = if ($ShowSystemByDefault) { 'Hide System Accounts' } else { 'Show System Accounts' }
    $initialSysClass = if ($ShowSystemByDefault) { 'toggle-btn active' } else { 'toggle-btn' }

    # Build the data array for JavaScript
    $jsonRecords = (New-Object 'System.Collections.Generic.List[string]')
    foreach ($proc in $AllData) {
        $isSystem = if (Test-IsSystemAccount $proc.UserName) { 'true' } else { 'false' }
        $startStr = if ($proc.StartTime) { ([datetime]$proc.StartTime).ToString('yyyy-MM-dd HH:mm:ss') } else { '' }

        $jsonRecords.Add(('{{s:{0},u:{1},p:{2},pid:{3},sid:{4},pws:{5},ws:{6},cpu:{7},h:{8},t:{9},st:{10},sys:{11}}}' -f
            (ConvertTo-JsString $proc.Server), (ConvertTo-JsString $proc.UserName), (ConvertTo-JsString $proc.ProcessName),
            (ConvertTo-JsNumber $proc.PID), (ConvertTo-JsNumber $proc.SessionId), (ConvertTo-JsNumber $proc.PrivateWorkingSet),
            (ConvertTo-JsNumber $proc.WorkingSetBytes), (ConvertTo-JsNumber $proc.CPU_Seconds), (ConvertTo-JsNumber $proc.HandleCount),
            (ConvertTo-JsNumber $proc.ThreadCount), (ConvertTo-JsString $startStr), $isSystem))
    }
    $jsonData = "[`n" + ($jsonRecords -join ",`n") + "`n]"

    # Build server memory data
    $memEntries = (New-Object 'System.Collections.Generic.List[string]')
    foreach ($server in $ServerMemory.Keys) {
        $m = $ServerMemory[$server]
        $memEntries.Add(('{0}:{{total:{1},used:{2},free:{3},pct:{4}}}' -f (ConvertTo-JsString $server),
            (ConvertTo-JsNumber $m.TotalPhysicalMB), (ConvertTo-JsNumber $m.UsedPhysicalMB),
            (ConvertTo-JsNumber $m.FreePhysicalMB), (ConvertTo-JsNumber $m.PercentUsed)))
    }
    $memJson = "{" + ($memEntries -join ",") + "}"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RAM Usage Report &mdash; $serverList</title>
<style>
:root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e2e4e9; --muted: #7a7f8d;
        --blue: #3b82f6; --green: #22c55e; --yellow: #eab308; --red: #ef4444; --orange: #f97316; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
.container { max-width: 1400px; margin: 0 auto; }
h1 { font-size: 28px; font-weight: 700; margin-bottom: 4px; }
.subtitle { color: var(--muted); margin-bottom: 24px; font-size: 14px; }

/* Server memory cards */
.mem-cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
.mem-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; flex: 1; min-width: 280px; }
.mem-card h3 { font-size: 14px; color: var(--muted); margin-bottom: 12px; font-weight: 500; }
.mem-card .pct { font-size: 36px; font-weight: 700; }
.mem-card .detail { color: var(--muted); font-size: 13px; margin-top: 8px; }
.mem-bar { height: 8px; background: var(--border); border-radius: 4px; margin-top: 12px; overflow: hidden; }
.mem-bar-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }
.pct-ok { color: var(--green); } .fill-ok { background: var(--green); }
.pct-warn { color: var(--yellow); } .fill-warn { background: var(--yellow); }
.pct-crit { color: var(--red); } .fill-crit { background: var(--red); }

/* Stats row */
.stats { display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }
.stat-box { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; flex: 1; min-width: 150px; }
.stat-val { font-size: 24px; font-weight: 700; color: var(--blue); }
.stat-lbl { font-size: 12px; color: var(--muted); margin-top: 4px; }

/* Controls */
.controls { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }
.search-box { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; color: var(--text);
              font-size: 14px; width: 300px; outline: none; transition: border 0.2s; }
.search-box:focus { border-color: var(--blue); }
.search-box::placeholder { color: var(--muted); }
.toggle-btn { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; color: var(--text);
              cursor: pointer; font-size: 13px; transition: all 0.2s; }
.toggle-btn:hover { border-color: var(--blue); }
.toggle-btn.active { background: var(--blue); border-color: var(--blue); }

/* User table */
.user-table { width: 100%; border-collapse: separate; border-spacing: 0; }
.user-table th { background: var(--card); color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;
                 padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); cursor: pointer; user-select: none;
                 font-weight: 600; position: sticky; top: 0; z-index: 10; }
.user-table th:hover { color: var(--text); }
.user-table th .sort-arrow { margin-left: 4px; font-size: 10px; }
.user-table th.sorted-asc .sort-arrow::after { content: ' \25B2'; }
.user-table th.sorted-desc .sort-arrow::after { content: ' \25BC'; }
.user-row { cursor: pointer; transition: background 0.15s; }
.user-row td { padding: 14px 16px; border-bottom: 1px solid var(--border); }
.user-row:hover { background: rgba(59,130,246,0.08); }
.user-row.expanded { background: rgba(59,130,246,0.12); }
.user-name { font-weight: 600; }
.ram-val { font-variant-numeric: tabular-nums; font-weight: 600; }
.ram-bar-cell { width: 120px; }
.ram-bar-outer { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
.ram-bar-inner { height: 100%; background: var(--blue); border-radius: 3px; transition: width 0.3s; }

/* Process detail panel */
.detail-row { display: none; }
.detail-row.show { display: table-row; }
.detail-row td { padding: 0; border-bottom: 1px solid var(--border); }
.detail-panel { background: rgba(26,29,39,0.7); padding: 16px 24px; }
.detail-search { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; color: var(--text);
                 font-size: 13px; width: 250px; margin-bottom: 12px; outline: none; }
.detail-search:focus { border-color: var(--blue); }
.proc-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.proc-table th { background: transparent; color: var(--muted); font-size: 11px; padding: 8px 12px; border-bottom: 1px solid var(--border);
                 cursor: pointer; user-select: none; text-transform: uppercase; letter-spacing: 0.5px; }
.proc-table th:hover { color: var(--text); }
.proc-table td { padding: 8px 12px; border-bottom: 1px solid rgba(42,45,58,0.5); }
.proc-table tr:hover { background: rgba(59,130,246,0.05); }
.proc-table .num { text-align: right; font-variant-numeric: tabular-nums; }

/* Responsive */
@media (max-width: 768px) {
    .mem-cards, .stats { flex-direction: column; }
    .search-box { width: 100%; }
}
.footer { text-align: center; color: var(--muted); margin-top: 32px; font-size: 13px; padding: 20px; }
.expand-icon { display: inline-block; width: 20px; color: var(--muted); transition: transform 0.2s; }
.user-row.expanded .expand-icon { transform: rotate(90deg); color: var(--blue); }
.sys-account td { color: var(--muted); font-style: italic; }
</style>
</head>
<body>
<div class="container">
    <h1>RAM Usage Report</h1>
    <p class="subtitle">Generated $reportDate | Servers: $serverList</p>

    <div id="mem-cards" class="mem-cards"></div>
    <div id="stats" class="stats"></div>

    <div class="controls">
        <input type="text" class="search-box" id="userSearch" placeholder="Search users..." oninput="filterUsers()">
        <button class="$initialSysClass" id="sysToggle" onclick="toggleSystem()">$initialSysLabel</button>
        <button class="toggle-btn" id="expandAll" onclick="expandAllUsers()">Expand All</button>
        <button class="toggle-btn" id="collapseAll" onclick="collapseAllUsers()">Collapse All</button>
    </div>

    <table class="user-table" id="userTable">
        <thead>
            <tr>
                <th style="width:30px"></th>
                <th data-sort="user" style="width:25%">User <span class="sort-arrow"></span></th>
                <th data-sort="session" style="width:8%">Session <span class="sort-arrow"></span></th>
                <th data-sort="ram" style="width:12%" class="sorted-desc">RAM (Private WS) <span class="sort-arrow"></span></th>
                <th style="width:120px"></th>
                <th data-sort="procs" style="width:8%">Processes <span class="sort-arrow"></span></th>
                <th data-sort="cpu" style="width:10%">CPU (sec) <span class="sort-arrow"></span></th>
                <th data-sort="server" style="width:12%">Server <span class="sort-arrow"></span></th>
            </tr>
        </thead>
        <tbody id="userTableBody"></tbody>
    </table>

    <div class="footer">Generated by Get-RAMUsage v$ScriptVersion</div>
</div>

<script>
const rawData = $jsonData;
const serverMem = $memJson;

let showSystem = $initialShowSystem;
let sortCol = 'ram';
let sortDir = 'desc';

// Group by user+server
function groupData() {
    const groups = {};
    rawData.forEach(r => {
        const key = r.s + '|' + r.u;
        if (!groups[key]) groups[key] = { server: r.s, user: r.u, isSystem: r.sys, procs: [], totalPWS: 0, totalCPU: 0, sessions: new Set() };
        groups[key].procs.push(r);
        groups[key].totalPWS += r.pws;
        groups[key].totalCPU += r.cpu;
        groups[key].sessions.add(r.sid);
    });
    return Object.values(groups);
}

function formatBytes(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
    return b + ' B';
}

function pctClass(p) { return p >= 90 ? 'crit' : p >= 70 ? 'warn' : 'ok'; }

function renderMemCards() {
    const el = document.getElementById('mem-cards');
    let html = '';
    for (const [srv, m] of Object.entries(serverMem)) {
        const cls = pctClass(m.pct);
        html += '<div class="mem-card"><h3>' + escHtml(srv) + '</h3>' +
            '<div class="pct pct-' + cls + '">' + m.pct + '%</div>' +
            '<div class="detail">' + formatBytes(m.used * 1048576) + ' used of ' + formatBytes(m.total * 1048576) + ' (' + formatBytes(m.free * 1048576) + ' free)</div>' +
            '<div class="mem-bar"><div class="mem-bar-fill fill-' + cls + '" style="width:' + m.pct + '%"></div></div></div>';
    }
    el.innerHTML = html;
}

function renderStats() {
    const groups = groupData();
    const userGroups = groups.filter(g => !g.isSystem);
    const totalUserRAM = userGroups.reduce((s, g) => s + g.totalPWS, 0);
    const sysGroups = groups.filter(g => g.isSystem);
    const totalSysRAM = sysGroups.reduce((s, g) => s + g.totalPWS, 0);
    const totalProcs = rawData.length;

    document.getElementById('stats').innerHTML =
        '<div class="stat-box"><div class="stat-val">' + userGroups.length + '</div><div class="stat-lbl">User Sessions</div></div>' +
        '<div class="stat-box"><div class="stat-val">' + formatBytes(totalUserRAM) + '</div><div class="stat-lbl">User RAM (Private WS)</div></div>' +
        '<div class="stat-box"><div class="stat-val">' + formatBytes(totalSysRAM) + '</div><div class="stat-lbl">System RAM</div></div>' +
        '<div class="stat-box"><div class="stat-val">' + totalProcs + '</div><div class="stat-lbl">Total Processes</div></div>';
}

function renderUserTable() {
    let groups = groupData();
    const searchTerm = document.getElementById('userSearch').value.toLowerCase();

    if (!showSystem) groups = groups.filter(g => !g.isSystem);
    if (searchTerm) groups = groups.filter(g => g.user.toLowerCase().includes(searchTerm));

    // Find max RAM for bar scaling
    const maxRAM = Math.max(...groups.map(g => g.totalPWS), 1);

    // Sort
    groups.sort((a, b) => {
        let va, vb;
        switch (sortCol) {
            case 'user': va = a.user.toLowerCase(); vb = b.user.toLowerCase(); return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
            case 'session': va = [...a.sessions].sort()[0] || 0; vb = [...b.sessions].sort()[0] || 0; break;
            case 'ram': va = a.totalPWS; vb = b.totalPWS; break;
            case 'procs': va = a.procs.length; vb = b.procs.length; break;
            case 'cpu': va = a.totalCPU; vb = b.totalCPU; break;
            case 'server': va = a.server.toLowerCase(); vb = b.server.toLowerCase(); return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
            default: va = a.totalPWS; vb = b.totalPWS;
        }
        return sortDir === 'asc' ? va - vb : vb - va;
    });

    const tbody = document.getElementById('userTableBody');
    let html = '';

    groups.forEach((g, idx) => {
        const barPct = (g.totalPWS / maxRAM * 100).toFixed(1);
        const sessStr = [...g.sessions].sort().join(', ');
        const sysClass = g.isSystem ? ' sys-account' : '';

        html += '<tr class="user-row' + sysClass + '" onclick="toggleDetail(' + idx + ')" id="ur' + idx + '">' +
            '<td><span class="expand-icon">\u25B6</span></td>' +
            '<td class="user-name">' + escHtml(g.user) + '</td>' +
            '<td>' + sessStr + '</td>' +
            '<td class="ram-val">' + formatBytes(g.totalPWS) + '</td>' +
            '<td class="ram-bar-cell"><div class="ram-bar-outer"><div class="ram-bar-inner" style="width:' + barPct + '%"></div></div></td>' +
            '<td>' + g.procs.length + '</td>' +
            '<td>' + g.totalCPU.toFixed(1) + '</td>' +
            '<td>' + escHtml(g.server) + '</td></tr>';

        // Detail row (hidden by default)
        html += '<tr class="detail-row" id="dr' + idx + '"><td colspan="8"><div class="detail-panel">' +
            '<input type="text" class="detail-search" placeholder="Search processes..." oninput="filterProcs(' + idx + ', this.value)" onclick="event.stopPropagation()">' +
            '<table class="proc-table"><thead><tr>' +
            '<th onclick="sortProcs(' + idx + ',\'name\',this)">Process <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'pws\',this)" class="num">Private WS <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'pid\',this)" class="num">PID <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'cpu\',this)" class="num">CPU (sec) <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'handles\',this)" class="num">Handles <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'threads\',this)" class="num">Threads <span class="sort-arrow"></span></th>' +
            '<th onclick="sortProcs(' + idx + ',\'start\',this)">Start Time <span class="sort-arrow"></span></th>' +
            '</tr></thead><tbody id="pb' + idx + '"></tbody></table></div></td></tr>';
    });

    tbody.innerHTML = html;

    // Store groups for drill-down
    window._groups = groups;
}

function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function toggleDetail(idx) {
    const ur = document.getElementById('ur' + idx);
    const dr = document.getElementById('dr' + idx);
    const isOpen = dr.classList.contains('show');
    if (isOpen) {
        dr.classList.remove('show');
        ur.classList.remove('expanded');
    } else {
        dr.classList.add('show');
        ur.classList.add('expanded');
        renderProcs(idx, '', 'pws', 'desc');
    }
}

function renderProcs(idx, filter, sortKey, dir) {
    const g = window._groups[idx];
    let procs = g.procs.slice();
    if (filter) procs = procs.filter(p => p.p.toLowerCase().includes(filter.toLowerCase()));

    procs.sort((a, b) => {
        let va, vb;
        switch (sortKey) {
            case 'name': va = a.p.toLowerCase(); vb = b.p.toLowerCase(); return dir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
            case 'pws': va = a.pws; vb = b.pws; break;
            case 'pid': va = a.pid; vb = b.pid; break;
            case 'cpu': va = a.cpu; vb = b.cpu; break;
            case 'handles': va = a.h; vb = b.h; break;
            case 'threads': va = a.t; vb = b.t; break;
            case 'start': va = a.st; vb = b.st; return dir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
            default: va = a.pws; vb = b.pws;
        }
        return dir === 'asc' ? va - vb : vb - va;
    });

    let html = '';
    procs.forEach(p => {
        html += '<tr><td>' + escHtml(p.p) + '</td>' +
            '<td class="num">' + formatBytes(p.pws) + '</td>' +
            '<td class="num">' + p.pid + '</td>' +
            '<td class="num">' + p.cpu.toFixed(1) + '</td>' +
            '<td class="num">' + p.h + '</td>' +
            '<td class="num">' + p.t + '</td>' +
            '<td>' + escHtml(p.st) + '</td></tr>';
    });

    document.getElementById('pb' + idx).innerHTML = html;
}

// Per-detail-panel sort state
const procSortState = {};
function sortProcs(idx, key, thEl) {
    if (!procSortState[idx]) procSortState[idx] = { key: 'pws', dir: 'desc' };
    const st = procSortState[idx];
    if (st.key === key) { st.dir = st.dir === 'asc' ? 'desc' : 'asc'; }
    else { st.key = key; st.dir = 'desc'; }

    // Update header styles
    const ths = thEl.closest('thead').querySelectorAll('th');
    ths.forEach(t => t.classList.remove('sorted-asc', 'sorted-desc'));
    thEl.classList.add('sorted-' + st.dir);

    const searchInput = document.querySelector('#dr' + idx + ' .detail-search');
    const filter = searchInput ? searchInput.value : '';
    renderProcs(idx, filter, st.key, st.dir);
    event.stopPropagation();
}

function filterProcs(idx, val) {
    const st = procSortState[idx] || { key: 'pws', dir: 'desc' };
    renderProcs(idx, val, st.key, st.dir);
}

function filterUsers() { renderUserTable(); }

function toggleSystem() {
    showSystem = !showSystem;
    document.getElementById('sysToggle').classList.toggle('active', showSystem);
    document.getElementById('sysToggle').textContent = showSystem ? 'Hide System Accounts' : 'Show System Accounts';
    renderUserTable();
}

function expandAllUsers() {
    document.querySelectorAll('.detail-row').forEach((dr, i) => {
        if (!dr.classList.contains('show')) { dr.classList.add('show'); document.getElementById('ur' + i)?.classList.add('expanded'); renderProcs(i, '', 'pws', 'desc'); }
    });
}
function collapseAllUsers() {
    document.querySelectorAll('.detail-row').forEach((dr, i) => { dr.classList.remove('show'); document.getElementById('ur' + i)?.classList.remove('expanded'); });
}

// Column sort for user table
document.querySelectorAll('.user-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (sortCol === col) { sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }
        else { sortCol = col; sortDir = 'desc'; }
        document.querySelectorAll('.user-table th').forEach(t => t.classList.remove('sorted-asc', 'sorted-desc'));
        th.classList.add('sorted-' + sortDir);
        renderUserTable();
    });
});

// Initial render
renderMemCards();
renderStats();
renderUserTable();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}
#endregion

#region Main
function Start-RAMReport {
    $divider = ([string][char]0x2501) * 44

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  RAM Usage Report v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    $outputFolder = Resolve-OutputFolder $OutputPath
    $allProcessData = (New-Object 'System.Collections.Generic.List[object]')
    $serverMemory = @{}

    foreach ($server in $ComputerName) {
        Write-Host "[INFO] Querying $server..." -ForegroundColor Cyan
        $memInfo = Get-ServerMemoryInfo -Server $server -Cred $Credential
        if ($memInfo) { $serverMemory[$server] = $memInfo }

        $procs = Get-ProcessesByUser -Server $server -Cred $Credential
        if ($procs.Count -gt 0) {
            foreach ($p in $procs) { $allProcessData.Add($p) }
            Write-Host "[PASS] Found $($procs.Count) processes on $server" -ForegroundColor Green
        }
        else {
            Write-Host "[FAIL] No process data returned from $server" -ForegroundColor Red
        }
    }

    if ($allProcessData.Count -eq 0) {
        Write-Host "`n[FAIL] No data collected from any server. See the messages above." -ForegroundColor Red
        return
    }

    # Console display
    foreach ($server in $ComputerName) {
        $serverProcs = @($allProcessData | Where-Object { $_.Server -eq $server })
        if ($serverProcs.Count -eq 0) { continue }

        Write-Host ""
        Write-Host $divider -ForegroundColor Cyan
        Write-Host "  Server: $server" -ForegroundColor Cyan
        Write-Host $divider -ForegroundColor Cyan

        if ($serverMemory.ContainsKey($server)) {
            $mem = $serverMemory[$server]
            $barWidth = 40
            $usedBars = [math]::Round(($mem.PercentUsed / 100) * $barWidth)
            $freeBars = $barWidth - $usedBars
            $bar = ([char]0x2588).ToString() * $usedBars + ([char]0x2591).ToString() * $freeBars
            $barColor = if ($mem.PercentUsed -ge 90) { 'Red' } elseif ($mem.PercentUsed -ge 70) { 'Yellow' } else { 'Green' }
            Write-Host ""
            Write-Host "  Memory: " -NoNewline
            Write-Host "[$bar] " -NoNewline -ForegroundColor $barColor
            Write-Host "$($mem.PercentUsed)% " -NoNewline -ForegroundColor $barColor
            Write-Host "($(Format-Bytes ($mem.UsedPhysicalMB * 1MB)) / $(Format-Bytes ($mem.TotalPhysicalMB * 1MB)))"
        }

        $userGroups = Get-AccountGroups -Processes $serverProcs
        $sysGroups = Get-AccountGroups -Processes $serverProcs -SystemAccounts

        if ($userGroups.Count -gt 0) {
            Write-AccountBreakdown -Groups $userGroups -Heading 'User Sessions' -TopCount $Top

            $totalUserBytes = ($userGroups | ForEach-Object { $_.Group } | Measure-Object -Property PrivateWorkingSet -Sum).Sum
            Write-Host ""
            Write-Host "  Total User RAM: " -NoNewline -ForegroundColor White
            Write-Host "$(Format-Bytes $totalUserBytes)" -ForegroundColor Cyan
        }

        if ($IncludeSystemProcesses -and $sysGroups.Count -gt 0) {
            Write-AccountBreakdown -Groups $sysGroups -Heading 'System / Service Accounts' -TopCount $Top
        }

        $sysProcs = @($sysGroups | ForEach-Object { $_.Group })
        $totalSysBytes = ($sysProcs | Measure-Object -Property PrivateWorkingSet -Sum).Sum
        Write-Host ""
        Write-Host "  System/Service: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$(Format-Bytes $totalSysBytes) ($($sysProcs.Count) processes)" -NoNewline -ForegroundColor DarkGray
        if (-not $IncludeSystemProcesses) { Write-Host "  - add -IncludeSystemProcesses to itemise" -ForegroundColor DarkGray } else { Write-Host "" }
    }

    if (-not (Test-Path -LiteralPath $outputFolder)) {
        New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'

    # CSV export
    $csvPath = Resolve-ExportFilePath -Path $ExportCSV -Folder $outputFolder
    if ($csvPath) {
        $csvDir = Split-Path $csvPath -Parent
        if ($csvDir -and -not (Test-Path -LiteralPath $csvDir)) { New-Item -Path $csvDir -ItemType Directory -Force | Out-Null }
        $allProcessData | Select-Object Server, UserName, ProcessName, PID, SessionId,
            PrivateWSMB, WorkingSetMB, CPU_Seconds, HandleCount, ThreadCount, StartTime |
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[PASS] CSV exported to: $csvPath" -ForegroundColor Green
    }

    # HTML report
    $htmlPath = Resolve-ExportFilePath -Path $ExportHTML -Folder $outputFolder
    if (-not $htmlPath) { $htmlPath = Join-Path $outputFolder "RAMUsage_$timestamp.html" }
    $htmlDir = Split-Path $htmlPath -Parent
    if ($htmlDir -and -not (Test-Path -LiteralPath $htmlDir)) { New-Item -Path $htmlDir -ItemType Directory -Force | Out-Null }

    Export-InteractiveHTMLReport -AllData $allProcessData -ServerMemory $serverMemory -OutputFile $htmlPath `
        -Servers $ComputerName -ShowSystemByDefault:$IncludeSystemProcesses
    Write-Host "[PASS] HTML report: $htmlPath" -ForegroundColor Green

    if (-not $SkipBrowserOpen -and (Test-Path -LiteralPath $htmlPath)) {
        Start-Process $htmlPath
    }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  Complete!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    return $allProcessData
}

if (-not $LoadFunctionsOnly) {
    $results = Start-RAMReport
}
#endregion
