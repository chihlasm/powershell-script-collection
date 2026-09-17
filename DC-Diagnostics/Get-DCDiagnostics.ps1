<#
.SYNOPSIS
    Read-only domain controller diagnostics - correlates DC availability/health
    with a Hyper-V host crash or other outage window. Covers dcdiag, NTDS/DNS/
    DFSR event logs, time sync, replication status, and reboot/shutdown history.

.DESCRIPTION
    Run this ON the domain controller. Generalized for any DC being checked
    after a host-level or network incident - not specific to one environment.
    Makes no changes: no ntdsutil, no service restarts, no AD object changes.

.PARAMETER DaysBack
    Event log lookback window. Default 30. Widen to reach older incidents.

.PARAMETER IncidentDates
    Optional array of dates (yyyy-MM-dd) to specifically correlate against -
    pulls a +/- 24 hour window across System/NTDS/DNS/DFSR logs for each date.
    Use this to line up against a Hyper-V host's crash timestamp.

.EXAMPLE
    .\Get-DCDiagnostics.ps1 -DaysBack 210 -IncidentDates '2025-12-05','2026-06-20'
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 30,
    [string[]]$IncidentDates,
    [string]$OutputPath = "C:\ProgramData\VC3\Diagnostics"
)

$ErrorActionPreference = 'Continue'
$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime = (Get-Date).AddDays(-$DaysBack)
$flags     = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$reportFile = Join-Path $OutputPath "$($hostName)_DCDiagnostics_$timestamp.log"

function Write-Section { param([string]$Title) "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) | Out-File -FilePath $reportFile -Append }
function Write-Line    { param([string]$Text = "") $Text | Out-File -FilePath $reportFile -Append }

Write-Line "Domain Controller Diagnostics"
Write-Line "Host: $hostName"
Write-Line "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line "Lookback: $DaysBack days (since $($startTime.ToString('yyyy-MM-dd')))"

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Line "OS: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Line "Last Boot: $($os.LastBootUpTime)  |  Uptime: $([math]::Round($uptime.TotalDays,1)) days"
} catch { Write-Line "Could not retrieve OS info: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# FSMO ROLES / DC INVENTORY
# ---------------------------------------------------------------------------
Write-Section "FSMO ROLES / DC INVENTORY"
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    Write-Line "Domain: $($domain.DNSRoot)"
    Write-Line "PDC Emulator: $($domain.PDCEmulator)"
    Write-Line "RID Master: $($domain.RIDMaster)"
    Write-Line "Infrastructure Master: $($domain.InfrastructureMaster)"
    Write-Line "Schema Master: $($forest.SchemaMaster)"
    Write-Line "Domain Naming Master: $($forest.DomainNamingMaster)"

    $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
    Write-Line "`r`nDomain controllers in this domain: $($allDCs.Count)"
    $allDCs | Select-Object Name, IPv4Address, OperatingSystem, IsGlobalCatalog | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    if ($allDCs.Count -eq 1) {
        $flags.Add("Only ONE domain controller exists in this domain ($hostName) - single point of failure for authentication, DNS, and Group Policy")
    }
} catch {
    Write-Line "ActiveDirectory module/query failed, falling back to netdom: $($_.Exception.Message)"
    try { netdom query fsmo 2>&1 | Out-File -FilePath $reportFile -Append } catch { Write-Line "netdom also failed: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# DCDIAG
# ---------------------------------------------------------------------------
Write-Section "DCDIAG /V"
try {
    $dcdiagOutput = dcdiag /v 2>&1
    $dcdiagOutput | Out-File -FilePath $reportFile -Append
    $failedTests = $dcdiagOutput | Select-String -Pattern 'failed test' -SimpleMatch
    if ($failedTests) {
        foreach ($f in $failedTests) { $flags.Add("dcdiag: $($f.Line.Trim())") }
    } else {
        Write-Line "`r`n(No 'failed test' lines detected in dcdiag output.)"
    }
} catch { Write-Line "dcdiag failed to run: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# REPLICATION STATUS
# ---------------------------------------------------------------------------
Write-Section "REPLICATION STATUS (repadmin)"
try {
    Write-Line "--- repadmin /showrepl ---"
    repadmin /showrepl 2>&1 | Out-File -FilePath $reportFile -Append
    Write-Line "`r`n--- repadmin /replsummary ---"
    $replSummary = repadmin /replsummary 2>&1
    $replSummary | Out-File -FilePath $reportFile -Append
    if ($replSummary -match 'largest delta.*\d+d' -or $replSummary -match 'FAIL') {
        $flags.Add("repadmin /replsummary shows failures or large deltas - review above (expected to be minimal/none-applicable on a single-DC domain)")
    }
} catch { Write-Line "repadmin failed to run: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# TIME SYNC
# ---------------------------------------------------------------------------
Write-Section "TIME SYNCHRONIZATION"
try {
    Write-Line "--- w32tm /query /status ---"
    w32tm /query /status 2>&1 | Out-File -FilePath $reportFile -Append
    Write-Line "`r`n--- w32tm /query /source ---"
    $timeSource = w32tm /query /source 2>&1
    Write-Line $timeSource
    if ($timeSource -match 'Free-running System Clock|Local CMOS Clock') {
        $flags.Add("Time source is the local CMOS/free-running clock, not an external NTP source - PDC emulator should sync to an external time source")
    }
} catch { Write-Line "w32tm query failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# SECURE CHANNEL
# ---------------------------------------------------------------------------
Write-Section "SECURE CHANNEL HEALTH"
try {
    $scResult = Test-ComputerSecureChannel -Verbose 2>&1
    Write-Line "Test-ComputerSecureChannel: $scResult"
    if ($scResult -eq $false) { $flags.Add("Test-ComputerSecureChannel returned FALSE - secure channel to itself/domain is broken") }
} catch { Write-Line "Test-ComputerSecureChannel failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# HOST REBOOT / UNEXPECTED SHUTDOWN HISTORY (for correlation with host crash)
# ---------------------------------------------------------------------------
Write-Section "REBOOT / SHUTDOWN HISTORY (last $DaysBack days)"
try {
    $rebootEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startTime; Id = 1074,6005,6006,6008,41 } -ErrorAction Stop
    if ($rebootEvents) {
        $rebootEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $unexpected = $rebootEvents | Where-Object { $_.Id -in @(6008,41) }
        if ($unexpected) { $flags.Add("$($unexpected.Count) UNEXPECTED shutdown event(s) on this DC (6008/41) - compare timestamps against the Hyper-V host's crash time") }
    } else {
        Write-Line "No reboot/shutdown events found in window."
    }
} catch { Write-Line "Error querying reboot history: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DIRECTORY SERVICE (NTDS) EVENT LOG
# ---------------------------------------------------------------------------
Write-Section "DIRECTORY SERVICE EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $ntdsEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop
    if ($ntdsEvents) {
        $ntdsEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($ntdsEvents.Count) error/warning event(s) in Directory Service log (IDs: $((($ntdsEvents.Id | Sort-Object -Unique) -join ', ')))")
    } else {
        Write-Line "No Directory Service errors/warnings found in window."
    }
} catch { Write-Line "Error querying Directory Service log: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DNS SERVER EVENT LOG (if role installed)
# ---------------------------------------------------------------------------
Write-Section "DNS SERVER EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $dnsEvents = Get-WinEvent -FilterHashtable @{ LogName = 'DNS Server'; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop
    if ($dnsEvents) {
        $dnsEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($dnsEvents.Count) error/warning event(s) in DNS Server log")
    } else {
        Write-Line "No DNS Server errors/warnings found (or DNS role not installed on this DC)."
    }
} catch { Write-Line "DNS Server log not present or query failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DFS REPLICATION (SYSVOL) EVENT LOG
# ---------------------------------------------------------------------------
Write-Section "DFS REPLICATION EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $dfsrEvents = Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop
    if ($dfsrEvents) {
        $dfsrEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($dfsrEvents.Count) error/warning event(s) in DFS Replication log - check for USN rollback (2213) or journal wrap (4614/4004) signatures")
    } else {
        Write-Line "No DFS Replication errors/warnings found in window."
    }
} catch { Write-Line "DFS Replication log not present or query failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# NTDS DATABASE VOLUME HEALTH
# ---------------------------------------------------------------------------
Write-Section "NTDS DATABASE VOLUME HEALTH"
try {
    $ntdsParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
    $dbPath  = $ntdsParams.'DSA Database file'
    $logPath = $ntdsParams.'Database log files path'
    Write-Line "NTDS Database: $dbPath"
    Write-Line "NTDS Log Path: $logPath"

    $volsChecked = @()
    foreach ($p in @($dbPath, $logPath)) {
        if ($p) {
            $drive = ($p -split ':')[0]
            if ($drive -and ($volsChecked -notcontains $drive)) {
                $volsChecked += $drive
                try {
                    $vol = Get-Volume -DriveLetter $drive -ErrorAction Stop
                    $pctFree = [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1)
                    $dirty = fsutil dirty query "$($drive):" 2>&1
                    Write-Line "Volume $($drive): $pctFree% free  |  $dirty"
                    if ($pctFree -lt 10) { $flags.Add("Volume $($drive): (hosts NTDS database/logs) only $pctFree% free") }
                    if ($dirty -match 'is Dirty') { $flags.Add("Volume $($drive): (hosts NTDS database/logs) dirty bit is SET") }
                } catch { }
            }
        }
    }
} catch { Write-Line "Could not read NTDS registry parameters: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# INCIDENT DATE CORRELATION
# ---------------------------------------------------------------------------
if ($IncidentDates) {
    Write-Section "EVENTS NEAR SPECIFIED INCIDENT DATES (+/- 24 hours, all levels)"
    $logsToCheck = @('System','Directory Service','DNS Server','DFS Replication')
    foreach ($d in $IncidentDates) {
        try {
            $day = [datetime]$d
            $rangeStart = $day.AddHours(-24)
            $rangeEnd   = $day.AddHours(24)
            Write-Line "`r`n--- Around $d ($rangeStart) to ($rangeEnd) ---"
            foreach ($logName in $logsToCheck) {
                try {
                    $evts = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $rangeStart; EndTime = $rangeEnd } -ErrorAction Stop
                    if ($evts) {
                        Write-Line "[$logName]"
                        $evts | Sort-Object TimeCreated | Select-Object TimeCreated, Id, LevelDisplayName,
                            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
                    }
                } catch { }
            }
        } catch { Write-Line "Could not parse incident date '$d': $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
$summaryLines = @(("=" * 80), "FINDINGS SUMMARY - $hostName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", ("=" * 80))
if ($flags.Count -gt 0) {
    $summaryLines += "$($flags.Count) item(s) flagged for review:"
    $i = 1
    foreach ($f in $flags) { $summaryLines += "  [$i] $f"; $i++ }
} else {
    $summaryLines += "No automated flags raised. Review full report below."
}
$summaryLines += ""

$fullContent = Get-Content $reportFile -Raw
$summaryLines -join "`r`n" | Out-File -FilePath $reportFile -Encoding utf8
$fullContent | Out-File -FilePath $reportFile -Append -Encoding utf8

Write-Host "Diagnostics complete. Report saved to: $reportFile"
if ($flags.Count -gt 0) { Write-Host "$($flags.Count) item(s) flagged - see top of report." -ForegroundColor Yellow }
