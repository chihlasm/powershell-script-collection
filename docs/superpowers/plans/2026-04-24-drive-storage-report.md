# Drive Storage Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a single standalone PowerShell script that inventories local fixed drives and folder sizes (to depth 3) and produces a self-contained dark-themed HTML report.

**Architecture:** One folder `Drive-Storage-Report/` with `Get-DriveStorageReport.ps1` and `README.md`. The script uses CIM to enumerate drives, a recursive bottom-up tree walk to tally folder sizes while catching access-denied errors, a post-walk Misc-bucket rollup for folders below the threshold, and an HTML builder that produces one file per run with inline CSS.

**Tech Stack:** Windows PowerShell 5.1+, built-in CIM/WMI (`Win32_LogicalDisk`), `System.IO` via `Get-ChildItem`, no external modules.

**Spec:** [docs/superpowers/specs/2026-04-24-drive-storage-report-design.md](../specs/2026-04-24-drive-storage-report-design.md)

**Testing note:** This repository's convention (per `CLAUDE.md`) is no test framework — each tool is a standalone script. Verification in this plan is manual: each task ends with a run-and-inspect step against a small known folder so behavior can be confirmed before moving on. Commits are frequent so rollback is easy.

---

## Task 1: Create folder and script skeleton

**Files:**
- Create: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Create the folder and script file with full help + param block**

```powershell
<#
.SYNOPSIS
    Generates an HTML report of local drive and folder storage usage.

.DESCRIPTION
    Inventories every fixed drive on the local machine and produces a single
    self-contained HTML file showing drive totals, free space, and per-folder
    sizes to a configurable depth. Folders below a size threshold and folders
    that cannot be read are aggregated into a Misc bucket so totals always
    balance.

    Intended to be copied to and run on target servers locally.

.PARAMETER Drive
    Optional list of drive letters to scan (e.g. C, D). If omitted, all
    local fixed drives are scanned. Accepts 'C', 'C:', or 'C:\'.

.PARAMETER Depth
    Folder depth to break out individually in the report. Default 3.
    Subfolders beyond this depth are rolled into their depth-N ancestor.

.PARAMETER MinSizeMB
    Folders below this size are aggregated into a Misc row at their depth
    level. Default 100 MB.

.PARAMETER OutputPath
    Where the HTML file is written. Defaults to the current directory.
    Created if it does not exist.

.PARAMETER NoOpen
    Skip auto-launching the HTML file after generation.

.EXAMPLE
    .\Get-DriveStorageReport.ps1

    Scan all fixed drives with defaults (depth 3, 100 MB threshold) and open
    the HTML report in the default browser.

.EXAMPLE
    .\Get-DriveStorageReport.ps1 -Drive C -Depth 2 -MinSizeMB 500

    Scan only C:, show two levels of folders, hide anything under 500 MB.

.EXAMPLE
    .\Get-DriveStorageReport.ps1 -OutputPath '\\fileserver\reports\storage' -NoOpen

    Write the report to a network share and don't open it.

.NOTES
    Author:   Michael Chihlas
    Version:  1.0.0
    Requires: PowerShell 5.1+

    Run elevated for best coverage. Without admin, more system folders will
    land in the "Unreadable folders" section and contribute 0 bytes to
    totals.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Drive,

    [ValidateRange(1, 10)]
    [int]$Depth = 3,

    [ValidateRange(0, 100000)]
    [int]$MinSizeMB = 100,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

# --- Logging helpers -------------------------------------------------------

function Write-Status {
    param(
        [ValidateSet('INFO', 'PASS', 'WARN', 'FAIL')]
        [string]$Level,
        [string]$Message
    )
    $color = switch ($Level) {
        'INFO' { 'Cyan' }
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$Level]  $ts  $Message" -ForegroundColor $color
}

Write-Status INFO "Drive Storage Report starting on $env:COMPUTERNAME"
Write-Status INFO "Depth=$Depth, MinSizeMB=$MinSizeMB, OutputPath=$OutputPath"
```

- [ ] **Step 2: Run the script to verify the skeleton executes**

Run from the repo root:

```powershell
cd '.\Drive-Storage-Report'
.\Get-DriveStorageReport.ps1
```

Expected console output (two cyan `[INFO]` lines):
```
[INFO]  2026-04-24 ...  Drive Storage Report starting on <HOSTNAME>
[INFO]  2026-04-24 ...  Depth=3, MinSizeMB=100, OutputPath=<cwd>
```

Also run `.\Get-DriveStorageReport.ps1 -?` and confirm the help page renders with the three `.EXAMPLE` blocks.

- [ ] **Step 3: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: scaffold Get-DriveStorageReport with help and params"
```

---

## Task 2: Drive enumeration

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add the drive enumeration function**

Insert immediately after the `Write-Status` function:

```powershell
# --- Drive enumeration -----------------------------------------------------

function Get-TargetDrive {
    param([string[]]$Filter)

    $all = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' `
        -ErrorAction Stop

    if ($Filter) {
        # Normalize filter input: "C", "C:", "C:\" all -> "C:"
        $normalized = $Filter | ForEach-Object {
            ($_ -replace '[:\\]', '').ToUpperInvariant() + ':'
        }
        $all = $all | Where-Object { $normalized -contains $_.DeviceID }
    }

    $all | ForEach-Object {
        [PSCustomObject]@{
            DeviceID    = $_.DeviceID
            VolumeName  = if ($_.VolumeName) { $_.VolumeName } else { '(no label)' }
            SizeBytes   = [long]$_.Size
            FreeBytes   = [long]$_.FreeSpace
            UsedBytes   = [long]($_.Size - $_.FreeSpace)
            UsedPercent = if ($_.Size) { ($_.Size - $_.FreeSpace) / $_.Size } else { 0 }
        }
    }
}
```

Then replace the tail of the script (after the startup `Write-Status` lines) with:

```powershell
# --- Main flow -------------------------------------------------------------

$drives = @(Get-TargetDrive -Filter $Drive)

if (-not $drives) {
    if ($Drive) {
        Write-Warning "No fixed drives matched filter: $($Drive -join ', ')"
        return
    }
    Write-Error "No fixed drives found on $env:COMPUTERNAME"
    return
}

Write-Status INFO "Scanning $($drives.Count) fixed drive(s)"

foreach ($d in $drives) {
    $pct = '{0:P0}' -f $d.UsedPercent
    Write-Status INFO ("  {0}  {1}  {2} used / {3} total ({4})" -f `
        $d.DeviceID, $d.VolumeName, $d.UsedBytes, $d.SizeBytes, $pct)
}
```

- [ ] **Step 2: Run and verify drive enumeration**

Run `.\Get-DriveStorageReport.ps1`. Expected output includes one line per fixed drive, e.g.:

```
[INFO]  ...  Scanning 2 fixed drive(s)
[INFO]  ...    C:  Windows  489234567890 used / 999111222333 total (49%)
[INFO]  ...    D:  Data  123456789000 used / 2000000000000 total (6%)
```

Also run `.\Get-DriveStorageReport.ps1 -Drive X` (assuming no X: drive). Expected: yellow `WARNING` line "No fixed drives matched filter: X" and the script returns without error.

- [ ] **Step 3: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: enumerate fixed drives with optional filter"
```

---

## Task 3: Byte formatting helper

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add Format-Bytes function after Write-Status**

Insert before the `Get-TargetDrive` function:

```powershell
function Format-Bytes {
    param([long]$Bytes)

    if ($Bytes -lt 1KB)      { return "$Bytes B" }
    if ($Bytes -lt 1MB)      { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB)      { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -lt 1TB)      { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    return ('{0:N2} TB' -f ($Bytes / 1TB))
}
```

Then update the drive summary loop in the Main flow to use it:

```powershell
foreach ($d in $drives) {
    $pct = '{0:P0}' -f $d.UsedPercent
    Write-Status INFO ("  {0}  {1}  {2} used / {3} total ({4})" -f `
        $d.DeviceID, $d.VolumeName, (Format-Bytes $d.UsedBytes), (Format-Bytes $d.SizeBytes), $pct)
}
```

- [ ] **Step 2: Run and verify readable sizes**

Run `.\Get-DriveStorageReport.ps1`. Drive summary lines should now show human-readable units like `456.7 GB used / 931.2 GB total (49%)`.

Also quick spot-check in a PowerShell console:

```powershell
. .\Get-DriveStorageReport.ps1  # (this will fail main flow but dot-source defines functions; skip this)
```

If dot-sourcing triggers main-flow errors, instead open the script in VS Code, copy the `Format-Bytes` function into a scratch console, and verify:
- `Format-Bytes 500` → `500 B`
- `Format-Bytes 2048` → `2 KB`
- `Format-Bytes 1500000` → `1 MB`
- `Format-Bytes 1500000000` → `1.4 GB`
- `Format-Bytes 1500000000000` → `1.36 TB`

- [ ] **Step 3: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: add human-readable byte formatter"
```

---

## Task 4: Recursive folder walker

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add shared walk state + Walk-Folder function after Get-TargetDrive**

```powershell
# --- Folder walker ---------------------------------------------------------

function New-WalkState {
    [PSCustomObject]@{
        Records     = [System.Collections.Generic.List[object]]::new()
        Unreadable  = [System.Collections.Generic.List[string]]::new()
        FolderCount = 0
    }
}

function Invoke-FolderWalk {
    param(
        [string]$Path,
        [int]$CurrentDepth,
        [int]$MaxDepth,
        [object]$State
    )

    $State.FolderCount++

    # Sum files directly in this folder (non-recursive).
    $directBytes = 0L
    try {
        $files = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop
        foreach ($f in $files) {
            if ($f.Length) { $directBytes += [long]$f.Length }
        }
    }
    catch [System.UnauthorizedAccessException], [System.IO.IOException] {
        $State.Unreadable.Add($Path) | Out-Null
        # We can't read files here; walk continues with 0 direct bytes.
    }
    catch {
        $State.Unreadable.Add($Path) | Out-Null
    }

    $totalBytes = $directBytes

    # Recurse into subfolders.
    $subDirs = @()
    try {
        $subDirs = Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction Stop |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
    }
    catch {
        $State.Unreadable.Add($Path) | Out-Null
    }

    foreach ($sub in $subDirs) {
        try {
            $childBytes = Invoke-FolderWalk -Path $sub.FullName `
                -CurrentDepth ($CurrentDepth + 1) `
                -MaxDepth $MaxDepth `
                -State $State
            $totalBytes += $childBytes
        }
        catch {
            $State.Unreadable.Add($sub.FullName) | Out-Null
        }
    }

    # Emit a record for this folder if it's within the report depth.
    # Root (depth 0) is not emitted as a folder row — the drive card shows it.
    if ($CurrentDepth -ge 1 -and $CurrentDepth -le $MaxDepth) {
        $State.Records.Add([PSCustomObject]@{
            Path       = $Path
            Depth      = $CurrentDepth
            SizeBytes  = $totalBytes
            ParentPath = (Split-Path -LiteralPath $Path -Parent)
            IsMisc     = $false
        }) | Out-Null
    }

    return $totalBytes
}
```

- [ ] **Step 2: Wire the walker into Main flow (replace the per-drive summary loop)**

Replace the current `foreach ($d in $drives)` loop at the bottom with:

```powershell
$allResults = @()

foreach ($d in $drives) {
    Write-Status INFO ("Scanning {0}\ ..." -f $d.DeviceID)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $state = New-WalkState
    try {
        $rootBytes = Invoke-FolderWalk -Path ("{0}\" -f $d.DeviceID) `
            -CurrentDepth 0 -MaxDepth $Depth -State $state
    }
    catch {
        Write-Status WARN ("{0}\ failed to scan: {1}" -f $d.DeviceID, $_.Exception.Message)
        continue
    }

    $sw.Stop()
    Write-Status PASS ("{0}\ complete — {1} across {2} folders ({3:N0}s)" -f `
        $d.DeviceID, (Format-Bytes $rootBytes), $state.FolderCount, $sw.Elapsed.TotalSeconds)

    $allResults += [PSCustomObject]@{
        Drive      = $d
        Records    = $state.Records
        Unreadable = $state.Unreadable
        RootBytes  = $rootBytes
    }
}
```

- [ ] **Step 3: Verify the walker on a small folder**

Create a test folder structure you can verify by hand:

```powershell
$t = Join-Path $env:TEMP 'DSR-Test'
Remove-Item $t -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$t\A\B\C\D" | Out-Null
New-Item -ItemType Directory -Path "$t\A\B\E" | Out-Null
New-Item -ItemType Directory -Path "$t\F" | Out-Null
fsutil file createnew "$t\A\big.bin"   10485760  | Out-Null   # 10 MB
fsutil file createnew "$t\A\B\mid.bin" 5242880   | Out-Null   # 5 MB
fsutil file createnew "$t\A\B\C\sm.bin" 1048576  | Out-Null   # 1 MB
fsutil file createnew "$t\F\tiny.bin"  102400    | Out-Null   # 100 KB
```

Temporarily edit the script's Main flow to point at the test folder instead of a drive, OR add a throwaway debug line after the scan loop:

```powershell
# DEBUG: remove after verification
$allResults | ForEach-Object {
    Write-Host "`n=== $($_.Drive.DeviceID) RootBytes=$($_.RootBytes) ==="
    $_.Records | Sort-Object Depth, Path | Format-Table Depth, Path, SizeBytes -AutoSize
}
```

Run `.\Get-DriveStorageReport.ps1 -Drive C -Depth 3` and confirm the debug table prints records at depths 1-3 with sizes that roll up correctly. Sum of depth-1 child totals (plus any files directly in `C:\`) should equal `RootBytes`.

Remove the debug block before committing.

- [ ] **Step 4: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: recursive folder walker with access-denied handling"
```

---

## Task 5: Misc-bucket rollup

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add Merge-SmallFolders after Invoke-FolderWalk**

```powershell
# --- Misc rollup -----------------------------------------------------------

function Merge-SmallFolders {
    param(
        [System.Collections.Generic.List[object]]$Records,
        [long]$ThresholdBytes,
        [string]$DriveRootPath
    )

    $kept = [System.Collections.Generic.List[object]]::new()

    # Group by parent path so we can roll up siblings together.
    $byParent = $Records | Group-Object -Property ParentPath

    foreach ($g in $byParent) {
        $parent = $g.Name
        $children = $g.Group

        $big   = $children | Where-Object { $_.SizeBytes -ge $ThresholdBytes }
        $small = $children | Where-Object { $_.SizeBytes -lt $ThresholdBytes }

        foreach ($b in $big) { $kept.Add($b) | Out-Null }

        if ($small.Count -gt 0) {
            $miscBytes = ($small | Measure-Object -Property SizeBytes -Sum).Sum
            $miscDepth = $small[0].Depth
            $suffix    = if ($small.Count -eq 1) { '' } else { 's' }
            $miscLabel = "(Misc. — {0} folder{1})" -f $small.Count, $suffix

            $kept.Add([PSCustomObject]@{
                Path       = Join-Path $parent $miscLabel
                Depth      = $miscDepth
                SizeBytes  = [long]$miscBytes
                ParentPath = $parent
                IsMisc     = $true
            }) | Out-Null
        }
    }

    return $kept
}
```

- [ ] **Step 2: Call Merge-SmallFolders in Main flow after each scan**

Update the per-drive block:

```powershell
    $thresholdBytes = [long]($MinSizeMB * 1MB)
    $merged = Merge-SmallFolders -Records $state.Records `
        -ThresholdBytes $thresholdBytes `
        -DriveRootPath ("{0}\" -f $d.DeviceID)

    $allResults += [PSCustomObject]@{
        Drive      = $d
        Records    = $merged
        Unreadable = $state.Unreadable
        RootBytes  = $rootBytes
    }
```

Remove the earlier `Records = $state.Records` line — replaced by `$merged`.

- [ ] **Step 3: Verify Misc bucket**

Re-run the debug table from Task 4 step 3 (temporarily re-add and remove) on the test folder. With `-MinSizeMB 1`:
- `F\tiny.bin` (100 KB) should cause `F` (depth 1, 100 KB) to roll into a Misc row at depth 1.
- With `-MinSizeMB 100` default, `F` and other small folders should roll into Misc at depth 1, and the sum of depth-1 sizes (kept + Misc) should still equal the depth-1 child total of the drive.

- [ ] **Step 4: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: roll folders under MinSizeMB into a Misc bucket"
```

---

## Task 6: HTML helpers — head, footer, drive cards

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add HTML-escape and size-bar-color helpers**

Insert after `Merge-SmallFolders`:

```powershell
# --- HTML helpers ----------------------------------------------------------

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text `
        -replace '&', '&amp;' `
        -replace '<', '&lt;' `
        -replace '>', '&gt;' `
        -replace '"', '&quot;' `
        -replace "'", '&#39;')
}

function Get-UsageBarColor {
    param([double]$Fraction)
    if ($Fraction -ge 0.90) { return '#e74c3c' }   # red
    if ($Fraction -ge 0.75) { return '#f39c12' }   # amber
    return '#27ae60'                                # green
}
```

- [ ] **Step 2: Add New-HtmlHead with inline styles**

Still inside the HTML helpers section:

```powershell
function New-HtmlHead {
    @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Drive Storage Report</title>
<style>
  :root {
    --bg: #1a1a1a;
    --surface: #242424;
    --surface-hover: #2d2d2d;
    --border: #333;
    --text: #e8e8e8;
    --text-muted: #8a8a8a;
    --accent: #5dade2;
    --mono: "Cascadia Code", "Consolas", "Courier New", monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 32px;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  h1 { font-size: 22px; margin: 0 0 4px 0; letter-spacing: -0.01em; }
  h2 { font-size: 16px; margin: 32px 0 12px 0; color: var(--accent); font-family: var(--mono); }
  .meta { color: var(--text-muted); font-size: 12px; margin-bottom: 24px; }
  .meta span + span::before { content: " · "; padding: 0 4px; }

  .drives { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .drive-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 18px;
  }
  .drive-card .letter { font-family: var(--mono); font-size: 22px; font-weight: 600; color: var(--accent); }
  .drive-card .label { color: var(--text-muted); margin-left: 8px; font-size: 13px; }
  .drive-card .line  { margin-top: 10px; font-family: var(--mono); }
  .bar { height: 8px; background: #111; border-radius: 4px; overflow: hidden; margin-top: 8px; }
  .bar > span { display: block; height: 100%; border-radius: 4px; }
  .drive-card .free { margin-top: 6px; color: var(--text-muted); font-family: var(--mono); font-size: 12px; }

  table.folders { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
  table.folders th, table.folders td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  table.folders th { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 500; }
  table.folders td.size { text-align: right; font-family: var(--mono); white-space: nowrap; }
  table.folders td.bar-cell { width: 20%; }
  table.folders td.bar-cell .bar { margin-top: 0; }
  table.folders tr:hover td { background: var(--surface-hover); }
  table.folders .path { font-family: var(--mono); color: var(--text); }
  table.folders .misc .path { color: var(--text-muted); font-style: italic; }
  table.folders .misc td.size { color: var(--text-muted); }

  details.unreadable { margin-top: 24px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px 16px; }
  details.unreadable summary { cursor: pointer; color: #f39c12; }
  details.unreadable ul { margin: 8px 0 0 0; padding-left: 20px; font-family: var(--mono); font-size: 12px; color: var(--text-muted); }

  footer { margin-top: 40px; color: var(--text-muted); font-size: 11px; border-top: 1px solid var(--border); padding-top: 16px; }
</style>
</head>
<body>
'@
}

function New-HtmlFooter {
    param([string]$HostName, [datetime]$Generated, [int]$UnreadableCount)
    $note = if ($UnreadableCount -gt 0) {
        "Unreadable folders contribute 0 bytes to totals. Run elevated for deeper coverage."
    } else { "" }
    $ts = $Generated.ToString('yyyy-MM-dd HH:mm:ss')
    @"
<footer>
  Generated by Get-DriveStorageReport.ps1 · $(ConvertTo-HtmlText $HostName) · $ts
  <br>$note
</footer>
</body>
</html>
"@
}
```

- [ ] **Step 3: Add New-HtmlDriveCards**

```powershell
function New-HtmlDriveCards {
    param([object[]]$Drives)

    $cards = foreach ($d in $Drives) {
        $pct   = [math]::Round($d.UsedPercent * 100, 0)
        $color = Get-UsageBarColor -Fraction $d.UsedPercent
        $width = [math]::Round($d.UsedPercent * 100, 1)
        $label = ConvertTo-HtmlText $d.VolumeName
@"
<div class="drive-card">
  <div><span class="letter">$($d.DeviceID)</span><span class="label">$label</span></div>
  <div class="line">$(Format-Bytes $d.UsedBytes) used of $(Format-Bytes $d.SizeBytes) ($pct%)</div>
  <div class="bar"><span style="width:$width%; background:$color"></span></div>
  <div class="free">$(Format-Bytes $d.FreeBytes) free</div>
</div>
"@
    }

    "<div class='drives'>`n$($cards -join "`n")`n</div>"
}
```

- [ ] **Step 4: Smoke-test drive cards by writing a temporary HTML**

Temporarily append to the end of the script:

```powershell
# DEBUG
$html = (New-HtmlHead) + (New-HtmlDriveCards -Drives $allResults.Drive) + (New-HtmlFooter -HostName $env:COMPUTERNAME -Generated (Get-Date) -UnreadableCount 0)
$tmp = Join-Path $env:TEMP 'dsr-debug.html'
Set-Content -Path $tmp -Value $html -Encoding UTF8
Start-Process $tmp
```

Run the script. A browser tab should open showing dark-theme drive cards with colored progress bars, readable byte sizes, and free-space labels. Verify the layout looks correct on one drive and with two+ drives.

Remove the DEBUG block before committing.

- [ ] **Step 5: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: HTML head, footer, and drive summary cards"
```

---

## Task 7: HTML folder table per drive

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add the folder-ordering helper**

Insert in the HTML helpers section:

```powershell
function Get-FolderDisplayName {
    param([string]$Path, [int]$Depth)
    # Depth 1: show the folder name with its drive letter for context.
    # Deeper: show only the leaf name — indentation conveys hierarchy.
    if ($Depth -le 1) { return $Path }
    return (Split-Path -LiteralPath $Path -Leaf)
}

function Sort-FolderRecords {
    param([object[]]$Records)

    # Produce a depth-first, largest-first ordering so children appear
    # under their parent.
    $byParent = @{}
    foreach ($r in $Records) {
        if (-not $byParent.ContainsKey($r.ParentPath)) {
            $byParent[$r.ParentPath] = [System.Collections.Generic.List[object]]::new()
        }
        $byParent[$r.ParentPath].Add($r) | Out-Null
    }

    $ordered = [System.Collections.Generic.List[object]]::new()

    function Emit($parent) {
        if (-not $byParent.ContainsKey($parent)) { return }
        # Misc rows last; everything else sorted by size desc.
        $children = $byParent[$parent] |
            Sort-Object @{Expression = { $_.IsMisc }}, @{Expression = { -$_.SizeBytes }}
        foreach ($c in $children) {
            $ordered.Add($c) | Out-Null
            if (-not $c.IsMisc) { Emit -parent $c.Path }
        }
    }

    # Depth-1 parents are drive roots ("C:\").
    $rootParents = $Records | Where-Object { $_.Depth -eq 1 } |
        Select-Object -ExpandProperty ParentPath -Unique
    foreach ($root in $rootParents) { Emit -parent $root }

    return $ordered
}
```

- [ ] **Step 2: Add New-HtmlFolderSection**

```powershell
function New-HtmlFolderSection {
    param(
        [object]$Drive,
        [object[]]$Records
    )

    if (-not $Records -or $Records.Count -eq 0) {
        return "<h2>$(ConvertTo-HtmlText $Drive.DeviceID)\</h2><p style='color:var(--text-muted)'>No folders above the size threshold.</p>"
    }

    $ordered = Sort-FolderRecords -Records $Records
    $maxBytes = ($Records | Measure-Object -Property SizeBytes -Maximum).Maximum
    if (-not $maxBytes) { $maxBytes = 1 }

    $rows = foreach ($r in $ordered) {
        $indent = ($r.Depth - 1) * 16
        $display = ConvertTo-HtmlText (Get-FolderDisplayName -Path $r.Path -Depth $r.Depth)
        $cls = if ($r.IsMisc) { ' class="misc"' } else { '' }
        $barW = [math]::Round(($r.SizeBytes / $maxBytes) * 100, 1)
@"
<tr$cls>
  <td class="path" style="padding-left:$(10 + $indent)px">$display</td>
  <td class="size">$(Format-Bytes $r.SizeBytes)</td>
  <td class="bar-cell"><div class="bar"><span style="width:$barW%; background:var(--accent)"></span></div></td>
</tr>
"@
    }

    $heading = ConvertTo-HtmlText ("{0}\ — {1} used" -f $Drive.DeviceID, (Format-Bytes $Drive.UsedBytes))

    @"
<h2>$heading</h2>
<table class="folders">
  <thead><tr><th>Folder</th><th style="text-align:right">Size</th><th>Share of drive</th></tr></thead>
  <tbody>
$($rows -join "`n")
  </tbody>
</table>
"@
}
```

- [ ] **Step 3: Smoke-test folder sections**

Temporarily append:

```powershell
# DEBUG
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append((New-HtmlHead))
[void]$sb.Append((New-HtmlDriveCards -Drives $allResults.Drive))
foreach ($r in $allResults) {
    [void]$sb.Append((New-HtmlFolderSection -Drive $r.Drive -Records $r.Records))
}
[void]$sb.Append((New-HtmlFooter -HostName $env:COMPUTERNAME -Generated (Get-Date) -UnreadableCount 0))
$tmp = Join-Path $env:TEMP 'dsr-debug.html'
Set-Content -Path $tmp -Value $sb.ToString() -Encoding UTF8
Start-Process $tmp
```

Run on `-Drive C`. Verify:
- Folders appear indented by depth (0, 16px, 32px).
- Within each parent, folders are sorted largest first.
- Misc rows appear in muted italic at the bottom of their parent's children.
- Size bars are proportional.

Remove DEBUG block.

- [ ] **Step 4: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: HTML folder section with indented, sorted rows"
```

---

## Task 8: Unreadable section + final assembly

**Files:**
- Modify: `Drive-Storage-Report/Get-DriveStorageReport.ps1`

- [ ] **Step 1: Add New-HtmlUnreadableSection**

```powershell
function New-HtmlUnreadableSection {
    param([string[]]$Paths)

    if (-not $Paths -or $Paths.Count -eq 0) { return '' }

    $unique = $Paths | Sort-Object -Unique
    $items = foreach ($p in $unique) { "<li>$(ConvertTo-HtmlText $p)</li>" }

    @"
<details class="unreadable">
  <summary>&#9888; $($unique.Count) folder$(if ($unique.Count -eq 1) { '' } else { 's' }) could not be read (access denied)</summary>
  <ul>
$($items -join "`n")
  </ul>
</details>
"@
}
```

- [ ] **Step 2: Add the top-level header block**

```powershell
function New-HtmlHeaderBlock {
    param(
        [string]$HostName,
        [datetime]$Started,
        [timespan]$Elapsed,
        [int]$DriveCount,
        [long]$TotalBytes
    )
    $tsStart = $Started.ToString('yyyy-MM-dd HH:mm:ss')
    $elapsedStr = '{0:N0}s' -f $Elapsed.TotalSeconds
    @"
<h1>Drive Storage Report</h1>
<div class="meta">
  <span>$(ConvertTo-HtmlText $HostName)</span>
  <span>$tsStart</span>
  <span>$DriveCount drive$(if ($DriveCount -eq 1) { '' } else { 's' })</span>
  <span>$(Format-Bytes $TotalBytes) total</span>
  <span>scan $elapsedStr</span>
</div>
"@
}
```

- [ ] **Step 3: Assemble and write the report in Main flow**

Append at the end of the script, replacing any remaining DEBUG blocks:

```powershell
# --- Build final report ----------------------------------------------------

$reportStart = Get-Date
# $reportStart is the generation timestamp; per-drive elapsed was already
# printed to console. Compute total elapsed by keeping a running stopwatch.
# Instead, capture start at the top of main flow:
```

That note means: refactor to start a stopwatch before the scan loop. Above the `foreach ($d in $drives)` loop, add:

```powershell
$overall = [System.Diagnostics.Stopwatch]::StartNew()
$scanStart = Get-Date
```

And after the loop:

```powershell
$overall.Stop()

if (-not $allResults) {
    Write-Warning "No drives were successfully scanned. Nothing to report."
    return
}

$totalBytes = ($allResults | Measure-Object -Property RootBytes -Sum).Sum
$allUnreadable = @()
foreach ($r in $allResults) { $allUnreadable += $r.Unreadable }

# Ensure OutputPath exists
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    catch {
        Write-Error "Could not create OutputPath '$OutputPath': $($_.Exception.Message)"
        return
    }
}

$fileName = "DriveStorageReport_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HHmmss')
$reportPath = Join-Path $OutputPath $fileName

$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append((New-HtmlHead))
[void]$sb.Append((New-HtmlHeaderBlock -HostName $env:COMPUTERNAME `
    -Started $scanStart -Elapsed $overall.Elapsed `
    -DriveCount $allResults.Count -TotalBytes $totalBytes))
[void]$sb.Append((New-HtmlDriveCards -Drives ($allResults | ForEach-Object { $_.Drive })))
foreach ($r in $allResults) {
    [void]$sb.Append((New-HtmlFolderSection -Drive $r.Drive -Records $r.Records))
}
[void]$sb.Append((New-HtmlUnreadableSection -Paths $allUnreadable))
[void]$sb.Append((New-HtmlFooter -HostName $env:COMPUTERNAME `
    -Generated (Get-Date) -UnreadableCount $allUnreadable.Count))

try {
    Set-Content -LiteralPath $reportPath -Value $sb.ToString() -Encoding UTF8
}
catch {
    Write-Error "Failed to write report to '$reportPath': $($_.Exception.Message)"
    return
}

Write-Status PASS ("Report generated: {0} ({1:N0}s total)" -f $reportPath, $overall.Elapsed.TotalSeconds)

if (-not $NoOpen) {
    try { Start-Process $reportPath } catch { Write-Status WARN "Could not auto-open report: $($_.Exception.Message)" }
}
```

- [ ] **Step 4: Full end-to-end run**

Run `.\Get-DriveStorageReport.ps1 -Drive C -Depth 3 -MinSizeMB 100`. Confirm:
- Console prints INFO/PASS lines per drive and a final PASS with the report path.
- Browser opens the HTML.
- HTML shows: title strip, drive card for C:, folder section with expected largest folders, Misc rows where applicable, Unreadable collapsible section if any access-denied folders were hit, footer.
- File exists in the working directory with filename pattern `DriveStorageReport_<HOSTNAME>_<timestamp>.html`.

Also test `-NoOpen` and confirm the browser does not launch.

Also test `-OutputPath` into a non-existent nested directory like `.\test-out\nested`. Confirm the folder is created and the file is written there.

- [ ] **Step 5: Commit**

```bash
git add "Drive-Storage-Report/Get-DriveStorageReport.ps1"
git commit -m "feat: assemble full HTML report with unreadable section and auto-open"
```

---

## Task 9: README

**Files:**
- Create: `Drive-Storage-Report/README.md`

- [ ] **Step 1: Write the README**

```markdown
# Drive Storage Report

Generates a dark-themed HTML report showing local drive totals, free space, and per-folder sizes up to a configurable depth. Designed to be copied to a target server and run locally.

## Requirements

- Windows Server / Windows 10+
- PowerShell 5.1 or later
- No external modules

## Usage

```powershell
.\Get-DriveStorageReport.ps1
```

Opens the report in your default browser when finished.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Drive` | all fixed drives | Limit scan to specific drive letters, e.g. `-Drive C,D`. Accepts `C`, `C:`, or `C:\`. |
| `-Depth` | `3` | How many folder levels to break out individually. Subfolders beyond this roll up into their depth-N ancestor. |
| `-MinSizeMB` | `100` | Folders below this size are aggregated into a Misc row at their depth level. |
| `-OutputPath` | current dir | Where the HTML file is written. Created if missing. |
| `-NoOpen` | off | Skip auto-launching the HTML file. |

## Examples

Scan every fixed drive with defaults:

```powershell
.\Get-DriveStorageReport.ps1
```

Scan only C:, two levels deep, hide anything under 500 MB:

```powershell
.\Get-DriveStorageReport.ps1 -Drive C -Depth 2 -MinSizeMB 500
```

Write the report to a network share without opening it:

```powershell
.\Get-DriveStorageReport.ps1 -OutputPath '\\fileserver\reports\storage' -NoOpen
```

## Output

A single self-contained HTML file named `DriveStorageReport_<HOSTNAME>_<yyyy-MM-dd_HHmmss>.html`. Contains:

- One drive summary card per fixed drive — total size, used, free, utilization bar.
- Per-drive folder breakdown up to the configured depth, sorted largest first.
- "Misc." rows aggregating folders below the threshold so totals always balance.
- Collapsible "Unreadable folders" section listing anything that threw access denied.

## Notes

- **Run elevated** for deepest coverage. Without admin, more system folders will land in the Unreadable section and contribute 0 bytes to totals.
- Reparse points, junctions, and symlinks are skipped to avoid loops and double-counting.
- Large drives with millions of small files can take several minutes to scan. Watch the progress line.
```

- [ ] **Step 2: Commit**

```bash
git add "Drive-Storage-Report/README.md"
git commit -m "docs: add README for Drive-Storage-Report"
```

---

## Task 10: End-to-end verification

- [ ] **Step 1: Clean run on the primary drive**

Delete any prior test HTMLs in the working dir. Run:

```powershell
.\Get-DriveStorageReport.ps1 -Drive C
```

Verify:
- No red `[FAIL]` output.
- Browser opens the report.
- Drive card color matches usage (green < 75%, amber < 90%, red ≥ 90%).
- Folder list is sorted largest first inside each parent, indented cleanly to 3 levels.
- Misc rows appear where expected, with italic muted styling.
- If there are unreadable folders, the `<details>` block expands to show them.

- [ ] **Step 2: Clean run across all drives with elevated shell**

Open an elevated PowerShell and run:

```powershell
.\Get-DriveStorageReport.ps1
```

Confirm all fixed drives appear in both the summary grid and in per-drive sections. Confirm the Unreadable list is much shorter than in the non-elevated run.

- [ ] **Step 3: Parameter sweeps**

```powershell
.\Get-DriveStorageReport.ps1 -MinSizeMB 10    # more rows, fewer Misc buckets
.\Get-DriveStorageReport.ps1 -MinSizeMB 5000  # few rows, large Misc buckets
.\Get-DriveStorageReport.ps1 -Depth 1         # flat: only top-level folders
.\Get-DriveStorageReport.ps1 -Depth 5         # deeper drill-down
```

Spot-check one report from each and confirm totals still balance (drive-card Used ≈ sum of depth-1 rows for that drive, accounting for Misc).

- [ ] **Step 4: Final commit if anything was tweaked**

```bash
git status
# commit any final fixes
```

---

## Self-Review

**Spec coverage check:**

| Spec item | Task |
|-----------|------|
| Folder layout `Drive-Storage-Report/{ps1,md}` | Task 1, 9 |
| Parameters (`-Drive`, `-Depth`, `-MinSizeMB`, `-OutputPath`, `-NoOpen`) | Task 1 |
| `#Requires -Version 5.1` + comment-based help | Task 1 |
| Drive enumeration via `Win32_LogicalDisk DriveType=3` | Task 2 |
| Normalize `-Drive` input (`C`, `C:`, `C:\`) | Task 2 |
| Reparse point skip | Task 4 |
| Bottom-up single-pass walk emitting at depths 1..MaxDepth | Task 4 |
| Unreadable bucket for access denied | Task 4 |
| Misc bucket rollup per parent, with label showing count | Task 5 |
| Totals always balance (Misc + kept = parent children) | Tasks 5, 10 |
| Dark HTML with drive cards + per-drive tables + Unreadable | Tasks 6, 7, 8 |
| Usage bar color thresholds (75%, 90%) | Task 6 |
| Human-readable byte units | Task 3 |
| Filename `DriveStorageReport_<HOSTNAME>_<timestamp>.html` | Task 8 |
| Console logging with `[INFO]`/`[PASS]`/`[WARN]`/`[FAIL]` prefixes | Task 1, 2, 4, 8 |
| Auto-open unless `-NoOpen` | Task 8 |
| Footer with note about elevated run / unreadable folders | Task 6, 8 |
| README with requirements, params, 3 examples, notes | Task 9 |

All spec items covered.

**Placeholder scan:** No TBD/TODO, no "add appropriate error handling", no undefined references.

**Type / signature consistency:** `$State.Records` used consistently as `List[object]` with `Add(...)`. Record objects have identical property set across `Invoke-FolderWalk`, `Merge-SmallFolders`, and `Sort-FolderRecords` (`Path`, `Depth`, `SizeBytes`, `ParentPath`, `IsMisc`). `Invoke-FolderWalk` is the name used in every call site.

One caught issue inline: initial Misc-label construction used an inline `if` inside `-f`, which PS 5.1 parses as an argument expression — corrected to a two-line `$suffix = if (...) { '' } else { 's' }` pattern. Same pattern used consistently in `New-HtmlUnreadableSection` and `New-HtmlHeaderBlock`.
