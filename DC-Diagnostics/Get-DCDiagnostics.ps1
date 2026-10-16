#Requires -Version 3.0
<#
.SYNOPSIS
    Read-only domain controller diagnostics - correlates DC availability/health
    with a Hyper-V host crash or other outage window. Covers dcdiag, NTDS/DNS/
    DFSR event logs, time sync, replication status, and reboot/shutdown history.

.DESCRIPTION
    Run this ON the domain controller (local-only by design). It shells out to dcdiag,
    repadmin, w32tm and fsutil and reads the local event logs and NTDS registry
    parameters, so it deliberately has no -ComputerName parameter. To check several DCs,
    run it on each one (for example through Invoke-Command -FilePath).

    Makes no changes: no ntdsutil, no service restarts, no AD object changes.
    Run from an elevated prompt - dcdiag and the Directory Service log need admin rights.

    Output is a single text report, <COMPUTERNAME>_DCDiagnostics_<yyyy-MM-dd_HHmmss>.log,
    with a findings summary at the top.

.PARAMETER DaysBack
    Event log lookback window. Default 30. Widen to reach older incidents.

.PARAMETER IncidentDates
    Optional array of dates (yyyy-MM-dd) to specifically correlate against -
    pulls a +/- 24 hour window across System/NTDS/DNS/DFSR logs for each date.
    Use this to line up against a Hyper-V host's crash timestamp.

.PARAMETER OutputPath
    Directory for the report. Defaults to the current directory. Created if missing.

.EXAMPLE
    .\Get-DCDiagnostics.ps1 -DaysBack 210 -IncidentDates '2025-12-05','2026-06-20'

.EXAMPLE
    .\Get-DCDiagnostics.ps1 -OutputPath D:\Reports
    Runs with the default 30 day window and writes the report to D:\Reports.

.NOTES
    Requires: Windows PowerShell 3.0 or later (runs as shipped on Server 2012).
    The ActiveDirectory module is optional; without it the FSMO section falls back to
    'netdom query fsmo'. Must run on the domain controller being checked.

    Event IDs used (System log unless noted):
      1074  User32 - a process or user initiated a shutdown/restart (planned)
      6005  EventLog service started   (marks a boot)        [not verified on Learn]
      6006  EventLog service stopped  (marks a clean shutdown) [not verified on Learn]
      6008  EventLog - "The previous system shutdown was unexpected"
      41    Kernel-Power - the system rebooted without cleanly shutting down first
            (ID 41 is only counted when the provider is Microsoft-Windows-Kernel-Power)
    DFS Replication log:
      2213  Replication paused after a dirty shutdown of the DFSR database (needs recovery)
      4614  SYSVOL waiting to perform initial replication; 4604 = SYSVOL initialized.
            4614 without 4604 means initial sync has not completed.
    Win32_ComputerSystem.DomainRole: 4 = backup DC, 5 = primary DC (used to warn when the
    script is run on a non-DC).
    Get-WinEvent -FilterHashtable Level values: 1 Critical, 2 Error, 3 Warning.

    REFERENCES
    - Event 41 (Kernel-Power):
      https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart
    - Event 1074 (User32 shutdown initiator):
      https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/identify-cause-of-wmi-shutdown
    - Event 6008 ("The previous system shutdown was unexpected"):
      https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
    - DFSR events 2213 / 4614 / 4604 / 4602 (SYSVOL):
      https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
    - repadmin /replsummary row format (fails/total, %%, error):
      https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8418
    - Win32_ComputerSystem.DomainRole:
      https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysBack = 30,

    [string[]]$IncidentDates,

    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = 'Continue'
# Windows PowerShell's Out-File defaults to UTF-16; keep the whole report UTF-8.
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$startTime = (Get-Date).AddDays(-$DaysBack)
$flags     = New-Object System.Collections.Generic.List[string]

function Write-Console {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message) -ForegroundColor $color
}

function Test-ReplSummaryProblem {
    # 'repadmin /replsummary' prints a header 'Source DSA largest delta fails/total %% error'
    # followed by rows such as '<DC>  04h:02m:16s   4 / 5   80  (8418)'. Only a row with a
    # non-zero 'fails' count (or a delta measured in days) is a problem. Matching the word
    # 'FAIL' flags every run, because the header itself contains 'fails/total'.
    # https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8418
    param([string[]]$Lines)
    foreach ($line in $Lines) {
        if ($line -match '\s(\d+)\s*/\s*(\d+)\s+\d+') {
            if ([int]$Matches[1] -gt 0) { return $true }
        }
        # Delta in days, e.g. '02d.04h:11m:22s' (day format not verified on Learn).
        if ($line -match '\b\d+d\.\d+h') { return $true }
    }
    return $false
}

function Get-EventsSafe {
    # Get-WinEvent throws 'NoMatchingEventsFound' when the filter simply matches nothing;
    # that is a normal result here, not an error.
    param([Parameter(Mandatory)][hashtable]$Filter)
    try {
        return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$reportFile = Join-Path $OutputPath "$($hostName)_DCDiagnostics_$timestamp.log"

function Write-Section { param([string]$Title) "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) | Out-File -FilePath $reportFile -Append }
function Write-Line    { param([string]$Text = "") $Text | Out-File -FilePath $reportFile -Append }

Write-Console INFO "Collecting DC diagnostics on $hostName (lookback $DaysBack days)"

# Local-only tool: warn (but continue) if this is not an elevated session on a domain controller.
$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Console WARN 'Not running elevated - dcdiag and the Directory Service log will likely fail.'
    $flags.Add('Script was not run elevated - results may be incomplete')
}
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.DomainRole -lt 4) {
        Write-Console WARN "This computer is not a domain controller (DomainRole $($cs.DomainRole)). Run this script on the DC."
        $flags.Add("Computer is not a domain controller (Win32_ComputerSystem.DomainRole = $($cs.DomainRole))")
    }
} catch { Write-Line "Could not read Win32_ComputerSystem: $($_.Exception.Message)" }

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

    $allDCs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
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
    $failedTests = @($dcdiagOutput | Select-String -Pattern 'failed test' -SimpleMatch)
    if ($failedTests.Count -gt 0) {
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
    $replSummary = @(repadmin /replsummary 2>&1 | ForEach-Object { "$_" })
    $replSummary | Out-File -FilePath $reportFile -Append
    if (Test-ReplSummaryProblem -Lines $replSummary) {
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
    $scResult = Test-ComputerSecureChannel -ErrorAction Stop
    Write-Line "Test-ComputerSecureChannel: $scResult"
    if ($scResult -eq $false) { $flags.Add("Test-ComputerSecureChannel returned FALSE - secure channel to itself/domain is broken") }
} catch { Write-Line "Test-ComputerSecureChannel failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# HOST REBOOT / UNEXPECTED SHUTDOWN HISTORY (for correlation with host crash)
# ---------------------------------------------------------------------------
Write-Section "REBOOT / SHUTDOWN HISTORY (last $DaysBack days)"
try {
    # Event ID 41 is only meaningful from Kernel-Power; other providers can reuse the number.
    $rebootEvents = @(Get-EventsSafe -Filter @{ LogName = 'System'; StartTime = $startTime; Id = 1074,6005,6006,6008,41 } |
        Where-Object { $_.Id -ne 41 -or $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' })
    if ($rebootEvents.Count -gt 0) {
        $rebootEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $unexpected = @($rebootEvents | Where-Object { $_.Id -in @(6008,41) })
        if ($unexpected.Count -gt 0) { $flags.Add("$($unexpected.Count) UNEXPECTED shutdown event(s) on this DC (6008/41) - compare timestamps against the Hyper-V host's crash time") }
    } else {
        Write-Line "No reboot/shutdown events found in window."
    }
} catch { Write-Line "Error querying reboot history: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DIRECTORY SERVICE (NTDS) EVENT LOG
# ---------------------------------------------------------------------------
Write-Section "DIRECTORY SERVICE EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $ntdsEvents = @(Get-EventsSafe -Filter @{ LogName = 'Directory Service'; StartTime = $startTime; Level = 1,2,3 })
    if ($ntdsEvents.Count -gt 0) {
        $ntdsEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($ntdsEvents.Count) error/warning event(s) in Directory Service log (IDs: $((($ntdsEvents | ForEach-Object { $_.Id } | Sort-Object -Unique) -join ', ')))")
    } else {
        Write-Line "No Directory Service errors/warnings found in window."
    }
} catch { Write-Line "Error querying Directory Service log: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DNS SERVER EVENT LOG (if role installed)
# ---------------------------------------------------------------------------
Write-Section "DNS SERVER EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $dnsEvents = @(Get-EventsSafe -Filter @{ LogName = 'DNS Server'; StartTime = $startTime; Level = 1,2,3 })
    if ($dnsEvents.Count -gt 0) {
        $dnsEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($dnsEvents.Count) error/warning event(s) in DNS Server log")
    } else {
        Write-Line "No DNS Server errors/warnings found in window."
    }
} catch { Write-Line "DNS Server log not present (role not installed?) or query failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# DFS REPLICATION (SYSVOL) EVENT LOG
# ---------------------------------------------------------------------------
Write-Section "DFS REPLICATION EVENT LOG (Error/Warning, last $DaysBack days)"
try {
    $dfsrEvents = @(Get-EventsSafe -Filter @{ LogName = 'DFS Replication'; StartTime = $startTime; Level = 1,2,3 })
    if ($dfsrEvents.Count -gt 0) {
        $dfsrEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        # 2213 = DFSR paused after a dirty database shutdown; 4614 without 4604 = SYSVOL initial sync not finished.
        # https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
        $flags.Add("$($dfsrEvents.Count) error/warning event(s) in DFS Replication log - look for 2213 (dirty shutdown, replication paused) and 4614 without 4604 (SYSVOL initial sync incomplete)")
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
                } catch { Write-Line "Could not check volume $($drive): $($_.Exception.Message)" }
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
                    $evts = @(Get-EventsSafe -Filter @{ LogName = $logName; StartTime = $rangeStart; EndTime = $rangeEnd })
                    if ($evts.Count -gt 0) {
                        Write-Line "[$logName]"
                        $evts | Sort-Object TimeCreated | Select-Object TimeCreated, Id, LevelDisplayName,
                            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
                    }
                } catch { Write-Line "[$logName] not readable: $($_.Exception.Message)" }
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

$fullContent = Get-Content -LiteralPath $reportFile -Raw
$summaryLines -join "`r`n" | Out-File -FilePath $reportFile
$fullContent | Out-File -FilePath $reportFile -Append

Write-Console PASS "Diagnostics complete. Report saved to: $reportFile"
if ($flags.Count -gt 0) { Write-Console WARN "$($flags.Count) item(s) flagged - see top of report." }
else { Write-Console PASS 'No automated flags raised.' }
