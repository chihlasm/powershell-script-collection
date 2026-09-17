<#
.SYNOPSIS
    Collects read-only diagnostics for suspected filesystem/storage corruption:
    disk/NTFS error events, chkdsk dirty bit status, last chkdsk run, VSS health,
    physical disk reliability counters, and recent Windows Update failure history.

.DESCRIPTION
    Generalized for any Windows Server (2012 R2 - 2022) exhibiting symptoms like:
    - Recurring/unexplained file loss
    - Recycle Bin reporting corrupt
    - Windows Update failing on unrelated components
    - General "something's wrong with this server" reports

    Makes NO changes to the system. Does not run chkdsk /f, does not restart
    services, does not touch WU components. Pure collection for triage/escalation.

.PARAMETER OutputPath
    Folder to write the report to. Defaults to C:\ProgramData\VC3\Diagnostics.

.PARAMETER DaysBack
    How many days of System/Application event log history to review. Default 30.

.PARAMETER UpdateHistoryCount
    How many recent Windows Update history entries to review. Default 25.

.EXAMPLE
    .\Get-StorageCorruptionDiagnostics.ps1
    .\Get-StorageCorruptionDiagnostics.ps1 -DaysBack 90 -OutputPath D:\Diag
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\ProgramData\VC3\Diagnostics",
    [int]$DaysBack = 30,
    [int]$UpdateHistoryCount = 25
)

$ErrorActionPreference = 'Continue'
$hostName   = $env:COMPUTERNAME
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime  = (Get-Date).AddDays(-$DaysBack)
$flags      = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}
$reportFile = Join-Path $OutputPath "$($hostName)_StorageDiagnostics_$timestamp.log"

function Write-Section {
    param([string]$Title)
    "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) | Out-File -FilePath $reportFile -Append
}

function Write-Line {
    param([string]$Text = "")
    $Text | Out-File -FilePath $reportFile -Append
}

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------
Write-Line "Storage/Filesystem Corruption Diagnostics"
Write-Line "Host: $hostName"
Write-Line "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line "Event log lookback: $DaysBack days (since $($startTime.ToString('yyyy-MM-dd')))"

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Line "OS: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Line "Manufacturer/Model: $($cs.Manufacturer) / $($cs.Model)"
    Write-Line "Likely VM: $(if ($cs.Model -match 'Virtual|VMware|KVM|Xen') {'Yes'} else {'Unclear - verify manually'})"
    Write-Line "Last Boot: $($os.LastBootUpTime)  |  Uptime: $([math]::Round($uptime.TotalDays,1)) days"
} catch {
    Write-Line "Could not retrieve OS/CS info: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# DISK / NTFS ERROR EVENTS
# ---------------------------------------------------------------------------
Write-Section "DISK / NTFS ERROR EVENTS (System log, last $DaysBack days)"
try {
    $diskEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        StartTime = $startTime
        Level     = 1,2,3   # Critical, Error, Warning
    } -ErrorAction Stop | Where-Object {
        $_.ProviderName -in @('disk','Disk','Ntfs','volmgr','volsnap','storahci','stornvme','iaStorA','iaStorAC','partmgr') -or
        $_.Id -in @(7,15,51,55,129,140,153,154,157)
    }

    if ($diskEvents) {
        $diskEvents | Sort-Object TimeCreated -Descending |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
                @{N='Message';E={($_.Message -split "`n")[0]}} |
            Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append

        $flags.Add("$($diskEvents.Count) disk/NTFS-related error/warning events found in last $DaysBack days (IDs: $((($diskEvents.Id | Sort-Object -Unique) -join ', ')))")
    } else {
        Write-Line "No matching disk/NTFS error events found in the lookback window."
    }
} catch {
    Write-Line "Error querying System log: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# CHKDSK - DIRTY BIT PER VOLUME
# ---------------------------------------------------------------------------
Write-Section "CHKDSK DIRTY BIT STATUS"
try {
    $volumes = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
    foreach ($vol in $volumes) {
        $dirty = fsutil dirty query "$($vol.DriveLetter):" 2>&1
        Write-Line "Volume $($vol.DriveLetter): - $dirty"
        if ($dirty -match 'is Dirty') {
            $flags.Add("Volume $($vol.DriveLetter): dirty bit is SET - chkdsk will run (or is needed) on next reboot")
        }
    }
} catch {
    Write-Line "Error checking dirty bit: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# LAST CHKDSK EXECUTION (autochk results, Application log)
# ---------------------------------------------------------------------------
Write-Section "LAST CHKDSK / AUTOCHK RESULTS (Application log)"
try {
    $chkdskEvents = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Microsoft-Windows-Wininit'
        Id           = 1001
    } -MaxEvents 5 -ErrorAction Stop

    if ($chkdskEvents) {
        foreach ($evt in $chkdskEvents) {
            Write-Line "--- $($evt.TimeCreated) ---"
            Write-Line $evt.Message
            Write-Line ""
        }
    } else {
        Write-Line "No autochk/chkdsk execution records found."
    }
} catch {
    Write-Line "No chkdsk execution history found (or none logged): $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# VSS / SHADOW COPY HEALTH
# ---------------------------------------------------------------------------
Write-Section "VOLUME SHADOW COPY (VSS) STATUS"
try {
    Write-Line "--- vssadmin list writers ---"
    $writerOutput = vssadmin list writers 2>&1
    $writerOutput | Out-File -FilePath $reportFile -Append

    if ($writerOutput -match 'State: \[\d+\] (?!Stable)') {
        $flags.Add("One or more VSS writers are NOT in a Stable state - review writer output above")
    }

    Write-Line "`r`n--- vssadmin list shadowstorage ---"
    vssadmin list shadowstorage 2>&1 | Out-File -FilePath $reportFile -Append
} catch {
    Write-Line "Error querying VSS: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# PHYSICAL DISK HEALTH / RELIABILITY COUNTERS
# ---------------------------------------------------------------------------
Write-Section "PHYSICAL DISK HEALTH"
try {
    $physDisks = Get-PhysicalDisk -ErrorAction Stop
    $physDisks | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Usage |
        Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append

    foreach ($pd in $physDisks) {
        if ($pd.HealthStatus -ne 'Healthy') {
            $flags.Add("Physical disk '$($pd.FriendlyName)' reports HealthStatus: $($pd.HealthStatus)")
        }
        try {
            $rel = Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction Stop
            Write-Line "`r`n$($pd.FriendlyName) reliability counters:"
            Write-Line "  ReadErrorsTotal: $($rel.ReadErrorsTotal)  WriteErrorsTotal: $($rel.WriteErrorsTotal)  Temperature: $($rel.Temperature)"
            if ($rel.ReadErrorsTotal -gt 0 -or $rel.WriteErrorsTotal -gt 0) {
                $flags.Add("Physical disk '$($pd.FriendlyName)' has nonzero read/write error counters (Read: $($rel.ReadErrorsTotal), Write: $($rel.WriteErrorsTotal))")
            }
        } catch {
            Write-Line "  (Reliability counters not supported on this disk/controller - check vendor RAID tool manually, e.g. PERC/RACADM, HPE SSA, StorCLI)"
        }
    }
} catch {
    Write-Line "Get-PhysicalDisk not available or failed: $($_.Exception.Message)"
    Write-Line "If this host uses hardware RAID, check the controller's own management tool directly."
}

# ---------------------------------------------------------------------------
# WINDOWS UPDATE - SERVICE STATUS + RECENT FAILURE HISTORY
# ---------------------------------------------------------------------------
Write-Section "WINDOWS UPDATE SERVICES"
foreach ($svcName in 'wuauserv','bits','cryptsvc','msiserver') {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
        Write-Line "$($svc.DisplayName) ($svcName): Status=$($svc.Status)  StartType=$($svc.StartType)"
    } catch {
        Write-Line "$svcName - not found"
    }
}

Write-Section "RECENT WINDOWS UPDATE HISTORY (last $UpdateHistoryCount entries)"
try {
    $session   = New-Object -ComObject Microsoft.Update.Session
    $searcher  = $session.CreateUpdateSearcher()
    $historyCt = $searcher.GetTotalHistoryCount()
    $count     = [Math]::Min($UpdateHistoryCount, $historyCt)

    if ($count -gt 0) {
        $history = $searcher.QueryHistory(0, $count)
        $failCount = 0
        foreach ($entry in $history) {
            $resultText = switch ($entry.ResultCode) {
                2 { 'Succeeded' }
                3 { 'SucceededWithErrors' }
                4 { 'Failed'; $failCount++ }
                5 { 'Aborted' }
                default { "Unknown ($($entry.ResultCode))" }
            }
            if ($entry.ResultCode -eq 4) { $failCount++ }
            Write-Line "$($entry.Date)  [$resultText]  $($entry.Title)"
        }
        if ($failCount -gt 0) {
            $flags.Add("$failCount failed update(s) in last $count update history entries")
        }
    } else {
        Write-Line "No update history found."
    }
} catch {
    Write-Line "Could not query Windows Update history: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# SUMMARY - prepend flags to top of report
# ---------------------------------------------------------------------------
$summaryLines = @()
$summaryLines += ("=" * 80)
$summaryLines += "FINDINGS SUMMARY - $hostName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$summaryLines += ("=" * 80)
if ($flags.Count -gt 0) {
    $summaryLines += "$($flags.Count) item(s) flagged for review:"
    $i = 1
    foreach ($f in $flags) {
        $summaryLines += "  [$i] $f"
        $i++
    }
} else {
    $summaryLines += "No automated flags raised. Review full report below for details - absence of a flag does not rule out hardware-level issues not visible to Windows (e.g. RAID controller pre-failure states)."
}
$summaryLines += ""

$fullContent = Get-Content $reportFile -Raw
$summaryLines -join "`r`n" | Out-File -FilePath $reportFile -Encoding utf8
$fullContent | Out-File -FilePath $reportFile -Append -Encoding utf8

Write-Host "Diagnostics complete. Report saved to: $reportFile"
if ($flags.Count -gt 0) {
    Write-Host "$($flags.Count) item(s) flagged - see top of report." -ForegroundColor Yellow
}
