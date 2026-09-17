<#
.SYNOPSIS
    Scans and repairs FSLogix Profile Container VHDX files for filesystem errors.

.DESCRIPTION
    Detects active user sessions across specified RDS session hosts, skips VHDXs
    belonging to logged-in users, then mounts each offline VHDX to scan for
    filesystem corruption. Unhealthy volumes are repaired in place and verified.
    A CSV report is exported with before/after health status for every disk.

.PARAMETER ProfileShare
    UNC path to the FSLogix Profile Containers folder.

.PARAMETER SessionHosts
    Array of RDS session host names to query for active sessions. Users with
    active sessions will have their VHDXs skipped to avoid data corruption.

.PARAMETER OutputPath
    Directory where the CSV report will be saved. Defaults to the current directory.

.PARAMETER MountTimeoutSeconds
    Maximum seconds to wait for a VHDX volume to become available after mounting.
    Defaults to 15.

.PARAMETER Force
    Bypasses the confirmation prompt before starting repairs.

.EXAMPLE
    .\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1','TS2'

    Scans all VHDX files on the share, skipping any belonging to users logged into TS1 or TS2.

.EXAMPLE
    .\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1' -OutputPath 'C:\Reports' -Force

    Runs the scan and repair without confirmation, saving the report to C:\Reports.

.NOTES
    Version : 2.0
    Requires: Run as Administrator, Hyper-V PowerShell module (for disk image cmdlets)
    All target VHDXs must not be actively mounted by another process.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ProfileShare,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$SessionHosts,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(5, 120)]
    [int]$MountTimeoutSeconds = 15,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# Validate prerequisites
# ============================================================
if (-not (Test-Path $ProfileShare)) {
    Write-Host "[FAIL] Profile share not accessible: $ProfileShare" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $OutputPath)) {
    Write-Host "[FAIL] Output path does not exist: $OutputPath" -ForegroundColor Red
    exit 1
}

$timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile  = Join-Path $OutputPath "VHDX_ScanRepair_$timestamp.csv"

$results       = [System.Collections.ArrayList]::new()
$totalRepaired = 0
$totalHealthy  = 0
$totalFailed   = 0
$totalSkipped  = 0

# ============================================================
# STEP 1 - Collect Active Sessions
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " FSLogix VHDX Health Scan + Repair" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/4] Collecting active sessions across all session hosts..." -ForegroundColor Yellow

$activeUsers = [System.Collections.ArrayList]::new()

foreach ($sessionHost in $SessionHosts) {
    try {
        $sessions = query session /server:$sessionHost 2>$null
        if (-not $sessions) {
            Write-Host "    [WARN] No session data returned from $sessionHost" -ForegroundColor Yellow
            continue
        }

        # Parse the header line to find column positions dynamically
        $headerLine = $sessions[0]
        $userCol    = $headerLine.IndexOf('USERNAME')
        $stateCol   = $headerLine.IndexOf('STATE')

        if ($userCol -lt 0 -or $stateCol -lt 0) {
            Write-Host "    [WARN] Unexpected session output format from $sessionHost" -ForegroundColor Yellow
            continue
        }

        foreach ($line in $sessions | Select-Object -Skip 1) {
            if ($line.Length -lt $stateCol) { continue }

            # Extract state field and check for Active or Disc
            $stateField = $line.Substring($stateCol).Trim() -split '\s+' | Select-Object -First 1
            if ($stateField -eq 'Active' -or $stateField -eq 'Disc') {
                $userField = $line.Substring($userCol, ($stateCol - $userCol)).Trim()
                if ($userField -and $userField -ne '') {
                    $activeUsers.Add($userField.ToLower()) | Out-Null
                }
            }
        }
        Write-Host "    [PASS] Queried: $sessionHost" -ForegroundColor Green
    }
    catch {
        Write-Host "    [WARN] Could not query sessions on ${sessionHost}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$activeUsers = $activeUsers | Select-Object -Unique

if ($activeUsers -and $activeUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "    [WARN] Active users detected -- their VHDXs will be skipped:" -ForegroundColor Yellow
    $activeUsers | ForEach-Object { Write-Host "       - $_" -ForegroundColor Gray }
}
else {
    Write-Host ""
    Write-Host "    [PASS] No active sessions detected -- all VHDXs eligible for scan" -ForegroundColor Green
}

# ============================================================
# STEP 2 - Collect All VHDXs
# ============================================================
Write-Host ""
Write-Host "[2/4] Locating VHDX files on profile share..." -ForegroundColor Yellow

$vhdxFiles = Get-ChildItem -Path $ProfileShare -Filter '*.vhdx' -Recurse -ErrorAction Stop

if (-not $vhdxFiles -or $vhdxFiles.Count -eq 0) {
    Write-Host "    [FAIL] No VHDX files found at: $ProfileShare" -ForegroundColor Red
    exit 1
}

$vhdxCount = @($vhdxFiles).Count
Write-Host "    [PASS] Found $vhdxCount VHDX file(s)" -ForegroundColor Green
Write-Host ""

# ============================================================
# Confirmation gate (unless -Force)
# ============================================================
if (-not $Force) {
    if (-not $PSCmdlet.ShouldProcess("$vhdxCount VHDX files in $ProfileShare", 'Scan and Repair')) {
        Write-Host "[INFO] Operation cancelled by user." -ForegroundColor Cyan
        exit 0
    }
}

# ============================================================
# STEP 3 - Scan + Repair Each VHDX
# ============================================================
Write-Host "[3/4] Scanning and repairing VHDXs..." -ForegroundColor Yellow
Write-Host ""

foreach ($vhdx in $vhdxFiles) {

    $ownerFolder    = $vhdx.Directory.Name
    $username       = ($ownerFolder -split '_')[0].ToLower()
    $healthBefore   = ''
    $healthAfter    = ''
    $repairResult   = ''
    $status         = ''
    $errorMessage   = ''

    # --- Skip active users
    if ($activeUsers -contains $username) {
        Write-Host "    [SKIP] $($vhdx.Name) (user active: $username)" -ForegroundColor Gray
        $totalSkipped++
        $results.Add([PSCustomObject]@{
            VHDX         = $vhdx.Name
            Owner        = $username
            SizeMB       = [math]::Round($vhdx.Length / 1MB, 2)
            HealthBefore = 'N/A'
            RepairResult = 'N/A'
            HealthAfter  = 'N/A'
            Status       = 'SKIPPED - User Active'
            Error        = ''
        }) | Out-Null
        continue
    }

    try {
        # --- Mount VHDX read-write
        $diskImage = Mount-DiskImage -ImagePath $vhdx.FullName -PassThru -ErrorAction Stop

        # --- Wait for volume to become available
        $volume    = $null
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while ($stopwatch.Elapsed.TotalSeconds -lt $MountTimeoutSeconds) {
            $diskInfo = Get-DiskImage -ImagePath $vhdx.FullName -ErrorAction SilentlyContinue
            if ($diskInfo -and $diskInfo.Number -gt 0) {
                $partition = Get-Partition -DiskNumber $diskInfo.Number -ErrorAction SilentlyContinue |
                             Where-Object { $_.DriveLetter }
                if ($partition) {
                    $volume = Get-Volume -DriveLetter $partition.DriveLetter -ErrorAction SilentlyContinue
                    if ($volume) { break }
                }
            }
            Start-Sleep -Milliseconds 500
        }
        $stopwatch.Stop()

        if (-not $volume) {
            throw "Volume not available after $MountTimeoutSeconds seconds"
        }

        $healthBefore = $volume.HealthStatus
        $driveLetter  = $volume.DriveLetter

        # --- Already healthy
        if ($healthBefore -eq 'Healthy') {
            $totalHealthy++
            $repairResult = 'NoActionNeeded'
            $healthAfter  = 'Healthy'
            $status       = 'HEALTHY'
            Write-Host "    [PASS] HEALTHY  : $($vhdx.Name)" -ForegroundColor Green
        }
        else {
            # --- Needs repair
            Write-Host "    [INFO] REPAIRING: $($vhdx.Name) (Before: $healthBefore)" -ForegroundColor Yellow

            if ($PSCmdlet.ShouldProcess($vhdx.Name, "Repair-Volume -OfflineScanAndFix")) {
                $repair       = Repair-Volume -DriveLetter $driveLetter -OfflineScanAndFix -ErrorAction Stop
                $repairResult = "$repair"
            }
            else {
                $repairResult = 'Skipped by user'
            }

            # --- Re-check health after repair
            $volumeAfter = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            $healthAfter = if ($volumeAfter) { $volumeAfter.HealthStatus } else { 'Unknown' }

            if ($healthAfter -eq 'Healthy') {
                $totalRepaired++
                $status = 'REPAIRED'
                Write-Host "    [PASS] REPAIRED : $($vhdx.Name) (After: $healthAfter)" -ForegroundColor Green
            }
            else {
                $totalFailed++
                $status = 'REPAIR FAILED'
                Write-Host "    [FAIL] FAILED   : $($vhdx.Name) (After: $healthAfter)" -ForegroundColor Red
            }
        }

        # --- Dismount cleanly
        Dismount-DiskImage -ImagePath $vhdx.FullName -ErrorAction Stop
    }
    catch {
        $errorMessage = $_.Exception.Message
        $totalFailed++
        $status      = 'ERROR'
        $healthAfter = 'Unknown'
        Write-Host "    [FAIL] ERROR    : $($vhdx.Name) -- $errorMessage" -ForegroundColor Red

        # Best-effort dismount on failure
        try { Dismount-DiskImage -ImagePath $vhdx.FullName -ErrorAction SilentlyContinue } catch { }
    }

    $results.Add([PSCustomObject]@{
        VHDX         = $vhdx.Name
        Owner        = $username
        SizeMB       = [math]::Round($vhdx.Length / 1MB, 2)
        HealthBefore = $healthBefore
        RepairResult = $repairResult
        HealthAfter  = $healthAfter
        Status       = $status
        Error        = $errorMessage
    }) | Out-Null
}

# ============================================================
# STEP 4 - Summary Report
# ============================================================
Write-Host ""
Write-Host "[4/4] Generating report..." -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Total VHDXs Found  : $vhdxCount" -ForegroundColor White
Write-Host "  Already Healthy    : $totalHealthy" -ForegroundColor Green
Write-Host "  Repaired           : $totalRepaired" -ForegroundColor Green
Write-Host "  Repair Failed      : $totalFailed" -ForegroundColor Red
Write-Host "  Skipped (Active)   : $totalSkipped" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Flag any that still need attention
$stillBroken = $results | Where-Object { $_.Status -eq 'REPAIR FAILED' -or $_.Status -eq 'ERROR' }
if ($stillBroken -and $stillBroken.Count -gt 0) {
    Write-Host "[WARN] The following VHDXs require manual attention:" -ForegroundColor Red
    $stillBroken | ForEach-Object {
        Write-Host "    - $($_.VHDX) -- $($_.Error)" -ForegroundColor Red
    }
    Write-Host ""
}

# --- Export CSV report
$results | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
Write-Host "[INFO] Full report saved to: $reportFile" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
