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
