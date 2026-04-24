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
        $d.DeviceID, $d.VolumeName, $d.UsedBytes, $d.SizeBytes, $pct)
}
