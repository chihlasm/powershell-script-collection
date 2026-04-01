<#
.SYNOPSIS
    Scans and repairs FSLogix Profile Container VHDX files for filesystem errors.

.DESCRIPTION
    Detects active user sessions across specified RDS session hosts, skips VHDXs
    belonging to logged-in users, then mounts each offline VHDX to scan for
    filesystem corruption. Unhealthy volumes are repaired in place and verified.

    Reports include CSV and optional HTML output with color-coded status rows and
    summary statistics. An optional email notification sends the HTML report on
    completion. All runs produce a full transcript log for audit purposes.

    Scanning and repair run in parallel using PowerShell runspaces (PS 5.1
    compatible) with configurable concurrency. Failed repairs are automatically
    retried up to -MaxRetries times before being marked as failed.

    Pre-flight checks verify the Hyper-V PowerShell module is available, each
    session host is reachable, and the profile share is writable before any
    destructive work begins.

.PARAMETER ProfileShare
    UNC path to the FSLogix Profile Containers folder.

.PARAMETER SessionHosts
    Array of RDS session host names to query for active sessions. Users with
    active sessions will have their VHDXs skipped to avoid data corruption.

.PARAMETER OutputPath
    Directory where the CSV report, HTML report, and transcript will be saved.
    Defaults to the current directory.

.PARAMETER MountTimeoutSeconds
    Maximum seconds to wait for a VHDX volume to become available after mounting.
    Defaults to 15.

.PARAMETER ThrottleLimit
    Maximum number of VHDX files to process concurrently via runspaces.
    Defaults to 4.

.PARAMETER MaxRetries
    Number of times to retry a failed repair before marking the disk as failed.
    Defaults to 2.

.PARAMETER HtmlReport
    When specified, generates a styled HTML report alongside the CSV.

.PARAMETER SmtpServer
    SMTP server hostname to use when sending the HTML report by email.
    Requires -EmailTo and -EmailFrom.

.PARAMETER EmailTo
    One or more recipient addresses for the completion email.

.PARAMETER EmailFrom
    Sender address for the completion email.

.PARAMETER Force
    Bypasses the confirmation prompt before starting repairs.

.EXAMPLE
    .\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1','TS2'

    Scans all VHDX files on the share, skipping any belonging to users logged into TS1 or TS2.
    Writes a CSV report and transcript to the current directory.

.EXAMPLE
    .\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1' `
        -OutputPath 'C:\Reports' -Force -HtmlReport -ThrottleLimit 6 -MaxRetries 3

    Runs without confirmation, uses up to 6 parallel workers with 3 retry attempts,
    and generates both CSV and HTML reports in C:\Reports.

.EXAMPLE
    .\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1','TS2' `
        -HtmlReport -SmtpServer 'mail.contoso.com' -EmailTo 'admin@contoso.com' -EmailFrom 'noreply@contoso.com'

    Scans and emails the HTML report to admin@contoso.com on completion.

.NOTES
    Version : 3.0
    Requires: Run as Administrator, Storage module (ships with Windows Server 2012+
              and Windows 8+). No Hyper-V role or tools required -- works inside VMs.
    All target VHDXs must not be actively mounted by another process.
    Parallel processing uses PowerShell runspaces for PS 5.1 compatibility.
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

    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 4,

    [ValidateRange(0, 10)]
    [int]$MaxRetries = 2,

    [switch]$HtmlReport,

    [ValidateNotNullOrEmpty()]
    [string]$SmtpServer,

    [ValidateNotNullOrEmpty()]
    [string[]]$EmailTo,

    [ValidateNotNullOrEmpty()]
    [string]$EmailFrom,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# Timestamp helpers
# ============================================================
$runTimestamp  = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$reportCsv     = Join-Path $OutputPath "VHDX_ScanRepair_$runTimestamp.csv"
$reportHtml    = Join-Path $OutputPath "VHDX_ScanRepair_$runTimestamp.html"
$transcriptLog = Join-Path $OutputPath "VHDX_ScanRepair_$runTimestamp.transcript.log"

function Get-LogTimestamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

# ============================================================
# Start transcript immediately so all output is captured
# ============================================================
Start-Transcript -Path $transcriptLog -Force | Out-Null

# ============================================================
# Banner
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " FSLogix VHDX Health Scan + Repair  v3.0" -ForegroundColor Cyan
Write-Host " $(Get-LogTimestamp)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# PRE-FLIGHT CHECKS
# ============================================================
Write-Host "[PRE-FLIGHT] Running environment checks..." -ForegroundColor Yellow
Write-Host ""

$preFlightPassed = $true

# -- Check 1: Storage module (Mount-DiskImage, Get-Volume, Repair-Volume, etc.)
Write-Host "    [INFO] Checking for Storage module cmdlets..." -ForegroundColor Cyan
try {
    Import-Module Storage -ErrorAction Stop
    Write-Host "    [PASS] Storage module loaded." -ForegroundColor Green
}
catch {
    # Module import failed; check for the critical cmdlets directly
    $requiredCmds = @('Mount-DiskImage', 'Dismount-DiskImage', 'Get-Volume', 'Repair-Volume')
    $missing = $requiredCmds | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
    if ($missing -and $missing.Count -gt 0) {
        Write-Host "    [FAIL] Missing cmdlets: $($missing -join ', '). The Storage module is required." -ForegroundColor Red
        $preFlightPassed = $false
    }
    else {
        Write-Host "    [PASS] All required Storage cmdlets available." -ForegroundColor Green
    }
}

# -- Check 2: Output path exists and is writable
Write-Host "    [INFO] Checking output path: $OutputPath" -ForegroundColor Cyan
if (-not (Test-Path $OutputPath)) {
    Write-Host "    [FAIL] Output path does not exist: $OutputPath" -ForegroundColor Red
    $preFlightPassed = $false
}
else {
    $probeFile = Join-Path $OutputPath ".write_probe_$runTimestamp"
    try {
        [System.IO.File]::WriteAllText($probeFile, 'probe') | Out-Null
        Remove-Item $probeFile -Force -ErrorAction SilentlyContinue
        Write-Host "    [PASS] Output path is writable." -ForegroundColor Green
    }
    catch {
        Write-Host "    [FAIL] Output path is not writable: $($_.Exception.Message)" -ForegroundColor Red
        $preFlightPassed = $false
    }
}

# -- Check 3: Profile share accessibility and writability
Write-Host "    [INFO] Checking profile share: $ProfileShare" -ForegroundColor Cyan
if (-not (Test-Path $ProfileShare)) {
    Write-Host "    [FAIL] Profile share not accessible: $ProfileShare" -ForegroundColor Red
    $preFlightPassed = $false
}
else {
    $shareProbe = Join-Path $ProfileShare ".write_probe_$runTimestamp"
    try {
        [System.IO.File]::WriteAllText($shareProbe, 'probe') | Out-Null
        Remove-Item $shareProbe -Force -ErrorAction SilentlyContinue
        Write-Host "    [PASS] Profile share is accessible and writable." -ForegroundColor Green
    }
    catch {
        Write-Host "    [WARN] Profile share is accessible but may be read-only: $($_.Exception.Message)" -ForegroundColor Yellow
        # Warn only -- a read-only share still allows scanning
    }
}

# -- Check 4: Session host connectivity
Write-Host "    [INFO] Testing connectivity to session hosts..." -ForegroundColor Cyan
foreach ($sessionHost in $SessionHosts) {
    if (Test-Connection -ComputerName $sessionHost -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Host "    [PASS] Reachable: $sessionHost" -ForegroundColor Green
    }
    else {
        Write-Host "    [WARN] Unreachable: $sessionHost -- sessions on this host will not be checked." -ForegroundColor Yellow
    }
}

# -- Check 5: Email parameter consistency
if ($SmtpServer -or $EmailTo -or $EmailFrom) {
    if (-not ($SmtpServer -and $EmailTo -and $EmailFrom)) {
        Write-Host "    [WARN] Incomplete email parameters -- email notification will be skipped. Provide -SmtpServer, -EmailTo, and -EmailFrom together." -ForegroundColor Yellow
        $SmtpServer = $null
        $EmailTo    = $null
        $EmailFrom  = $null
    }
    elseif (-not $HtmlReport) {
        Write-Host "    [INFO] -HtmlReport enabled automatically because email parameters were provided." -ForegroundColor Cyan
        $HtmlReport = $true
    }
}

Write-Host ""

if (-not $preFlightPassed) {
    Write-Host "[FAIL] One or more pre-flight checks failed. Resolve the issues above and re-run." -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

Write-Host "    [PASS] All required pre-flight checks passed." -ForegroundColor Green
Write-Host ""

# ============================================================
# STEP 1 - Collect Active Sessions
# ============================================================
Write-Host "[1/4] Collecting active sessions across all session hosts..." -ForegroundColor Yellow

$activeUsers = [System.Collections.Generic.List[string]]::new()

foreach ($sessionHost in $SessionHosts) {
    try {
        $sessions = query session /server:$sessionHost 2>$null
        if (-not $sessions) {
            Write-Host "    [WARN] No session data returned from $sessionHost" -ForegroundColor Yellow
            continue
        }

        $headerLine = $sessions[0]
        $userCol    = $headerLine.IndexOf('USERNAME')
        $stateCol   = $headerLine.IndexOf('STATE')

        if ($userCol -lt 0 -or $stateCol -lt 0) {
            Write-Host "    [WARN] Unexpected session output format from $sessionHost" -ForegroundColor Yellow
            continue
        }

        foreach ($line in $sessions | Select-Object -Skip 1) {
            if ($line.Length -lt $stateCol) { continue }
            $stateField = $line.Substring($stateCol).Trim() -split '\s+' | Select-Object -First 1
            if ($stateField -eq 'Active' -or $stateField -eq 'Disc') {
                $userField = $line.Substring($userCol, ($stateCol - $userCol)).Trim()
                if ($userField -and $userField -ne '') {
                    $activeUsers.Add($userField.ToLower())
                }
            }
        }
        Write-Host "    [PASS] Queried: $sessionHost" -ForegroundColor Green
    }
    catch {
        Write-Host "    [WARN] Could not query sessions on ${sessionHost}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$activeUsers = @($activeUsers | Select-Object -Unique)

if ($activeUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "    [WARN] Active users detected -- their VHDXs will be skipped:" -ForegroundColor Yellow
    $activeUsers | ForEach-Object { Write-Host "       - $_" -ForegroundColor Gray }
}
else {
    Write-Host ""
    Write-Host "    [PASS] No active sessions detected -- all VHDXs eligible for scan." -ForegroundColor Green
}

# ============================================================
# STEP 2 - Collect All VHDXs
# ============================================================
Write-Host ""
Write-Host "[2/4] Locating VHDX files on profile share..." -ForegroundColor Yellow

$vhdxFiles = Get-ChildItem -Path $ProfileShare -Filter '*.vhdx' -Recurse -ErrorAction Stop

if (-not $vhdxFiles -or @($vhdxFiles).Count -eq 0) {
    Write-Host "    [FAIL] No VHDX files found at: $ProfileShare" -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

$vhdxFiles = @($vhdxFiles)
$vhdxCount = $vhdxFiles.Count
Write-Host "    [PASS] Found $vhdxCount VHDX file(s)" -ForegroundColor Green
Write-Host ""

# ============================================================
# Confirmation gate (unless -Force)
# ============================================================
if (-not $Force) {
    if (-not $PSCmdlet.ShouldProcess("$vhdxCount VHDX files in $ProfileShare", 'Scan and Repair')) {
        Write-Host "[INFO] Operation cancelled by user." -ForegroundColor Cyan
        Stop-Transcript | Out-Null
        exit 0
    }
}

# ============================================================
# STEP 3 - Parallel Scan + Repair via Runspaces
# ============================================================
Write-Host "[3/4] Scanning and repairing VHDXs (ThrottleLimit=$ThrottleLimit, MaxRetries=$MaxRetries)..." -ForegroundColor Yellow
Write-Host ""

# The scriptblock that runs inside each runspace. It must be self-contained --
# no access to parent scope variables, only what is passed through $InputObject.
$workerScript = {
    param(
        [string]  $VhdxFullName,
        [string]  $VhdxName,
        [string]  $OwnerFolder,
        [long]    $FileLength,
        [bool]    $IsActiveUser,
        [string]  $Username,
        [int]     $MountTimeoutSeconds,
        [int]     $MaxRetries
    )

    function Get-LogTimestamp { Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }

    $result = [PSCustomObject]@{
        VHDX              = $VhdxName
        Owner             = $Username
        SizeMB            = [math]::Round($FileLength / 1MB, 2)
        MaxSizeMB         = $null
        FragmentationPct  = $null
        HealthBefore      = ''
        RepairResult      = ''
        HealthAfter       = ''
        RetryCount        = 0
        Status            = ''
        Error             = ''
        LogLines          = [System.Collections.Generic.List[string]]::new()
    }

    if ($IsActiveUser) {
        $result.HealthBefore = 'N/A'
        $result.RepairResult = 'N/A'
        $result.HealthAfter  = 'N/A'
        $result.Status       = 'SKIPPED - User Active'
        $result.LogLines.Add("    [SKIP] $VhdxName (user active: $Username)")
        return $result
    }

    $attempt     = 0
    $repaired    = $false
    $lastError   = ''

    do {
        $attempt++
        try {
            # --- Capture size-on-disk and max VHDX size before mounting
            try {
                $diskImageInfo = Get-DiskImage -ImagePath $VhdxFullName -ErrorAction Stop
                if ($null -ne $diskImageInfo.Size -and $diskImageInfo.Size -gt 0) {
                    $result.MaxSizeMB = [math]::Round($diskImageInfo.Size / 1MB, 2)
                }
            }
            catch { <# non-fatal -- leave null #> }

            # --- Mount VHDX read-write
            $diskImage = Mount-DiskImage -ImagePath $VhdxFullName -PassThru -ErrorAction Stop

            # --- Wait for volume
            $volume    = $null
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            while ($stopwatch.Elapsed.TotalSeconds -lt $MountTimeoutSeconds) {
                $diskInfo = Get-DiskImage -ImagePath $VhdxFullName -ErrorAction SilentlyContinue
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

            $result.HealthBefore = $volume.HealthStatus
            $driveLetter         = $volume.DriveLetter

            # --- Disk space analysis: capture fragmentation via Optimize-Volume -Analyze
            try {
                $analysis = Optimize-Volume -DriveLetter $driveLetter -Analyze -NoDriveLetter:$false -ErrorAction SilentlyContinue -PassThru
                if ($analysis -and $null -ne $analysis.FragmentationPercentage) {
                    $result.FragmentationPct = $analysis.FragmentationPercentage
                }
            }
            catch { <# non-fatal #> }

            if ($result.HealthBefore -eq 'Healthy') {
                $result.RepairResult = 'NoActionNeeded'
                $result.HealthAfter  = 'Healthy'
                $result.Status       = 'HEALTHY'
                $result.LogLines.Add("    [PASS] HEALTHY  : $VhdxName")
                $repaired = $true
            }
            else {
                if ($attempt -gt 1) {
                    $result.LogLines.Add("    [INFO] RETRY $($attempt - 1): $VhdxName (HealthBefore: $($result.HealthBefore))")
                }
                else {
                    $result.LogLines.Add("    [INFO] REPAIRING: $VhdxName (Before: $($result.HealthBefore))")
                }

                $repair              = Repair-Volume -DriveLetter $driveLetter -OfflineScanAndFix -ErrorAction Stop
                $result.RepairResult = "$repair"
                $result.RetryCount   = $attempt - 1

                $volumeAfter        = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
                $result.HealthAfter = if ($volumeAfter) { $volumeAfter.HealthStatus } else { 'Unknown' }

                if ($result.HealthAfter -eq 'Healthy') {
                    $result.Status = 'REPAIRED'
                    $result.LogLines.Add("    [PASS] REPAIRED : $VhdxName (After: $($result.HealthAfter), Attempts: $attempt)")
                    $repaired = $true
                }
                else {
                    $result.Status = 'REPAIR FAILED'
                    $result.LogLines.Add("    [FAIL] FAILED   : $VhdxName (After: $($result.HealthAfter), Attempt: $attempt of $MaxRetries)")
                }
            }

            # --- Dismount cleanly
            Dismount-DiskImage -ImagePath $VhdxFullName -ErrorAction Stop
        }
        catch {
            $lastError = $_.Exception.Message
            $result.LogLines.Add("    [FAIL] ERROR (attempt $attempt): $VhdxName -- $lastError")
            # Best-effort dismount before retry
            try { Dismount-DiskImage -ImagePath $VhdxFullName -ErrorAction SilentlyContinue } catch { }
        }

    } while (-not $repaired -and $attempt -le $MaxRetries)

    # Final status for disks that never succeeded
    if (-not $repaired -and $result.Status -ne 'HEALTHY') {
        if ($result.Status -notin @('REPAIRED', 'REPAIR FAILED')) {
            $result.Status = 'ERROR'
        }
        if ($lastError -ne '') {
            $result.Error = $lastError
        }
        $result.RetryCount = $attempt - 1
    }

    return $result
}

# --- Build runspace pool
$runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
$runspacePool.Open()

$jobs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($vhdx in $vhdxFiles) {
    $ownerFolder = $vhdx.Directory.Name
    $username    = ($ownerFolder -split '_')[0].ToLower()
    $isActive    = $activeUsers -contains $username

    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $runspacePool

    [void]$ps.AddScript($workerScript)
    [void]$ps.AddParameter('VhdxFullName',        $vhdx.FullName)
    [void]$ps.AddParameter('VhdxName',             $vhdx.Name)
    [void]$ps.AddParameter('OwnerFolder',          $ownerFolder)
    [void]$ps.AddParameter('FileLength',           $vhdx.Length)
    [void]$ps.AddParameter('IsActiveUser',         $isActive)
    [void]$ps.AddParameter('Username',             $username)
    [void]$ps.AddParameter('MountTimeoutSeconds',  $MountTimeoutSeconds)
    [void]$ps.AddParameter('MaxRetries',           $MaxRetries)

    $jobs.Add(@{
        PowerShell = $ps
        Handle     = $ps.BeginInvoke()
        VhdxName   = $vhdx.Name
    })
}

# --- Collect results as they complete
$results       = [System.Collections.Generic.List[object]]::new()
$totalRepaired = 0
$totalHealthy  = 0
$totalFailed   = 0
$totalSkipped  = 0

$remaining = [System.Collections.Generic.List[hashtable]]::new($jobs)

while ($remaining.Count -gt 0) {
    $completed = @($remaining | Where-Object { $_.Handle.IsCompleted })
    foreach ($job in $completed) {
        $output = $job.PowerShell.EndInvoke($job.Handle)
        $job.PowerShell.Dispose()

        if ($output) {
            $r = $output[0]
            # Print log lines captured inside the runspace
            foreach ($line in $r.LogLines) {
                $color = switch -Wildcard ($line) {
                    '*\[PASS\]*'  { 'Green'  }
                    '*\[FAIL\]*'  { 'Red'    }
                    '*\[WARN\]*'  { 'Yellow' }
                    '*\[SKIP\]*'  { 'Gray'   }
                    default       { 'Cyan'   }
                }
                Write-Host $line -ForegroundColor $color
            }

            switch ($r.Status) {
                'HEALTHY'         { $totalHealthy++  }
                'REPAIRED'        { $totalRepaired++ }
                { $_ -in @('REPAIR FAILED', 'ERROR') } { $totalFailed++ }
                { $_ -like 'SKIPPED*' }                { $totalSkipped++ }
            }

            $results.Add($r)
        }

        $remaining.Remove($job) | Out-Null
    }

    if ($remaining.Count -gt 0) {
        Start-Sleep -Milliseconds 250
    }
}

$runspacePool.Close()
$runspacePool.Dispose()

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

$stillBroken = @($results | Where-Object { $_.Status -eq 'REPAIR FAILED' -or $_.Status -eq 'ERROR' })
if ($stillBroken.Count -gt 0) {
    Write-Host "[WARN] The following VHDXs require manual attention:" -ForegroundColor Red
    $stillBroken | ForEach-Object {
        Write-Host "    - $($_.VHDX) -- $($_.Error)" -ForegroundColor Red
    }
    Write-Host ""
}

# --- Export CSV report (drop internal LogLines column)
$csvData = $results | Select-Object VHDX, Owner, SizeMB, MaxSizeMB, FragmentationPct,
    HealthBefore, RepairResult, HealthAfter, RetryCount, Status, Error

$csvData | Export-Csv -Path $reportCsv -NoTypeInformation -Encoding UTF8
Write-Host "[INFO] CSV report saved to: $reportCsv" -ForegroundColor Cyan

# ============================================================
# HTML REPORT (optional)
# ============================================================
if ($HtmlReport) {

    function ConvertTo-StatusCssClass {
        param([string]$Status)
        switch -Wildcard ($Status) {
            'HEALTHY'        { return 'status-healthy'  }
            'REPAIRED'       { return 'status-repaired' }
            'REPAIR FAILED'  { return 'status-failed'   }
            'ERROR'          { return 'status-failed'   }
            'SKIPPED*'       { return 'status-skipped'  }
            default          { return ''                 }
        }
    }

    $runDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $htmlRows = foreach ($r in $results) {
        $cssClass = ConvertTo-StatusCssClass -Status $r.Status
        $fragDisplay = if ($null -ne $r.FragmentationPct) { "$($r.FragmentationPct)%" } else { 'N/A' }
        $maxSzDisplay = if ($null -ne $r.MaxSizeMB) { $r.MaxSizeMB } else { 'N/A' }
        "<tr class='$cssClass'>
            <td>$([System.Web.HttpUtility]::HtmlEncode($r.VHDX))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($r.Owner))</td>
            <td>$($r.SizeMB)</td>
            <td>$maxSzDisplay</td>
            <td>$fragDisplay</td>
            <td>$($r.HealthBefore)</td>
            <td>$($r.RepairResult)</td>
            <td>$($r.HealthAfter)</td>
            <td>$($r.RetryCount)</td>
            <td><strong>$([System.Web.HttpUtility]::HtmlEncode($r.Status))</strong></td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($r.Error))</td>
        </tr>"
    }

    $htmlBody = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FSLogix VHDX Repair Report - $runDate</title>
<style>
  body        { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; background: #f4f6f8; margin: 24px; color: #222; }
  h1          { color: #1a3a5c; margin-bottom: 4px; }
  .subtitle   { color: #555; margin-bottom: 20px; font-size: 12px; }
  .summary    { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat-card  { background: #fff; border-radius: 6px; padding: 12px 20px; box-shadow: 0 1px 4px rgba(0,0,0,.12); min-width: 130px; }
  .stat-card .label  { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: .5px; }
  .stat-card .value  { font-size: 26px; font-weight: bold; margin-top: 4px; }
  .val-healthy  { color: #2e7d32; }
  .val-repaired { color: #1565c0; }
  .val-failed   { color: #c62828; }
  .val-skipped  { color: #6d6d6d; }
  .val-total    { color: #1a3a5c; }
  table       { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,.10); border-radius: 6px; overflow: hidden; }
  th          { background: #1a3a5c; color: #fff; padding: 9px 10px; text-align: left; font-size: 12px; white-space: nowrap; }
  td          { padding: 7px 10px; border-bottom: 1px solid #e8e8e8; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .status-healthy  { background: #f1f8f2; }
  .status-repaired { background: #e8f0fe; }
  .status-failed   { background: #fdecea; }
  .status-skipped  { background: #f9f9f9; color: #777; }
  .footer     { margin-top: 16px; font-size: 11px; color: #999; }
</style>
</head>
<body>
<h1>FSLogix VHDX Health Scan + Repair</h1>
<div class="subtitle">Generated: $runDate &nbsp;|&nbsp; Profile Share: $([System.Web.HttpUtility]::HtmlEncode($ProfileShare))</div>

<div class="summary">
  <div class="stat-card"><div class="label">Total VHDXs</div><div class="value val-total">$vhdxCount</div></div>
  <div class="stat-card"><div class="label">Healthy</div><div class="value val-healthy">$totalHealthy</div></div>
  <div class="stat-card"><div class="label">Repaired</div><div class="value val-repaired">$totalRepaired</div></div>
  <div class="stat-card"><div class="label">Failed</div><div class="value val-failed">$totalFailed</div></div>
  <div class="stat-card"><div class="label">Skipped</div><div class="value val-skipped">$totalSkipped</div></div>
</div>

<table>
<thead>
  <tr>
    <th>VHDX</th>
    <th>Owner</th>
    <th>Size (MB)</th>
    <th>Max Size (MB)</th>
    <th>Fragmentation</th>
    <th>Health Before</th>
    <th>Repair Result</th>
    <th>Health After</th>
    <th>Retries</th>
    <th>Status</th>
    <th>Error</th>
  </tr>
</thead>
<tbody>
$($htmlRows -join "`n")
</tbody>
</table>

<div class="footer">FSLogix-Repair.ps1 v3.0 &nbsp;|&nbsp; ThrottleLimit=$ThrottleLimit &nbsp;|&nbsp; MaxRetries=$MaxRetries</div>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($reportHtml, $htmlBody, [System.Text.Encoding]::UTF8)
    Write-Host "[INFO] HTML report saved to: $reportHtml" -ForegroundColor Cyan
}

# ============================================================
# EMAIL NOTIFICATION (optional)
# ============================================================
if ($SmtpServer -and $EmailTo -and $EmailFrom) {
    Write-Host "[INFO] Sending email notification via $SmtpServer..." -ForegroundColor Cyan

    $subjectVerb = if ($totalFailed -gt 0) { 'ACTION REQUIRED' } else { 'Completed' }
    $subject     = "FSLogix VHDX Repair $subjectVerb - $totalFailed failed, $totalRepaired repaired ($runTimestamp)"

    $emailParams = @{
        SmtpServer  = $SmtpServer
        To          = $EmailTo
        From        = $EmailFrom
        Subject     = $subject
        Body        = if ($HtmlReport) { [System.IO.File]::ReadAllText($reportHtml) } else { "FSLogix VHDX scan complete. Total: $vhdxCount  Healthy: $totalHealthy  Repaired: $totalRepaired  Failed: $totalFailed  Skipped: $totalSkipped" }
        BodyAsHtml  = $HtmlReport
        ErrorAction = 'Stop'
    }

    # Attach CSV regardless
    $emailParams['Attachments'] = $reportCsv

    try {
        Send-MailMessage @emailParams
        Write-Host "[PASS] Email sent to: $($EmailTo -join ', ')" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Email notification failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ============================================================
# Transcript close
# ============================================================
Write-Host "[INFO] Transcript log saved to: $transcriptLog" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Stop-Transcript | Out-Null
