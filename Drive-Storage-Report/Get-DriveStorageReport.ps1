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

function Format-Bytes {
    param([long]$Bytes)

    if ($Bytes -lt 1KB)      { return "$Bytes B" }
    if ($Bytes -lt 1MB)      { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB)      { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -lt 1TB)      { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    return ('{0:N2} TB' -f ($Bytes / 1TB))
}

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
    }
    catch {
        $State.Unreadable.Add($Path) | Out-Null
    }

    $totalBytes = $directBytes

    # Recurse into subfolders; skip reparse points to avoid loops.
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

    if ($CurrentDepth -ge 1 -and $CurrentDepth -le $MaxDepth) {
        $State.Records.Add([PSCustomObject]@{
            Path       = $Path
            Depth      = $CurrentDepth
            SizeBytes  = $totalBytes
            ParentPath = [System.IO.Path]::GetDirectoryName($Path)
            IsMisc     = $false
        }) | Out-Null
    }

    return $totalBytes
}

# --- Misc rollup -----------------------------------------------------------

function Merge-SmallFolders {
    param(
        [System.Collections.Generic.List[object]]$Records,
        [long]$ThresholdBytes,
        [string]$DriveRootPath
    )

    $kept = [System.Collections.Generic.List[object]]::new()

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
    if ($Fraction -ge 0.90) { return '#e74c3c' }
    if ($Fraction -ge 0.75) { return '#f39c12' }
    return '#27ae60'
}

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

function Get-FolderDisplayName {
    param([string]$Path, [int]$Depth)
    if ($Depth -le 1) { return $Path }
    return [System.IO.Path]::GetFileName($Path)
}

function Sort-FolderRecords {
    param([object[]]$Records)

    $byParent = @{}
    foreach ($r in $Records) {
        if (-not $byParent.ContainsKey($r.ParentPath)) {
            $byParent[$r.ParentPath] = [System.Collections.Generic.List[object]]::new()
        }
        $byParent[$r.ParentPath].Add($r) | Out-Null
    }

    $ordered = [System.Collections.Generic.List[object]]::new()

    $emit = {
        param($parent)
        if (-not $byParent.ContainsKey($parent)) { return }
        $children = $byParent[$parent] |
            Sort-Object @{Expression = { $_.IsMisc }}, @{Expression = { -$_.SizeBytes }}
        foreach ($c in $children) {
            $ordered.Add($c) | Out-Null
            if (-not $c.IsMisc) {
                & $emit $c.Path
            }
        }
    }

    $rootParents = $Records | Where-Object { $_.Depth -eq 1 } |
        Select-Object -ExpandProperty ParentPath -Unique
    foreach ($root in $rootParents) { & $emit $root }

    return $ordered
}

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
        $leftPad = 10 + $indent
@"
<tr$cls>
  <td class="path" style="padding-left:${leftPad}px">$display</td>
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

# --- Main flow -------------------------------------------------------------

Write-Status INFO "Drive Storage Report starting on $env:COMPUTERNAME"
Write-Status INFO "Depth=$Depth, MinSizeMB=$MinSizeMB, OutputPath=$OutputPath"

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
        $d.DeviceID, $d.VolumeName, (Format-Bytes $d.UsedBytes), (Format-Bytes $d.SizeBytes), $pct)
}

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
}
