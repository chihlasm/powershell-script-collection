#Requires -Version 5.1

<#
.SYNOPSIS
    Second-stage diagnostic: determines whether EventData queries that MATCH are fast.
.DESCRIPTION
    The first diagnostic showed that EventData predicates which match NOTHING force a
    full scan of the Security log (742k records -> 11s for one IP, 52s for twenty terms).
    That is expected: proving absence requires reading every record.

    The decisive question is different: when a query DOES match, can the log stop early
    once -MaxEvents is satisfied?

      If YES -> correlation is salvageable. Real IPs that appear in the log resolve fast;
                only the unresolvable ones cost a full scan, and those can be capped.
      If NO  -> EventData filtering is unusable at this log size and correlation must be
                rebuilt around a single bounded 4624 sweep instead.

    This script answers that by pulling REAL IP addresses out of the DC's own log and
    querying for those, so the queries are guaranteed to match.
.PARAMETER ComputerName
    Domain controller to query. Defaults to the local machine.
.PARAMETER DaysBack
    Search window. Default 7.
.PARAMETER TimeoutSeconds
    Abandon any single test after this long. Default 90.
.EXAMPLE
    .\Debug-CorrelationQuery2.ps1 -ComputerName DC02
.NOTES
    Read-only. Runs queries only; changes nothing.
#>
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,
    [ValidateRange(10, 600)]
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddDays(-$DaysBack)

function Write-Status {
    param([string]$Message, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level='INFO')
    $c = @{PASS='Green';WARN='Yellow';FAIL='Red';INFO='Cyan'}[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $c
}

function Measure-Query {
    param([string]$Label, [scriptblock]$Query, [object[]]$ArgumentList)
    Write-Host ''
    Write-Host "--- $Label" -ForegroundColor White
    $job = Start-Job -ScriptBlock $Query -ArgumentList $ArgumentList
    $sw  = [Diagnostics.Stopwatch]::StartNew()
    if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
        $sw.Stop()
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue 2>$null
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        Write-Status ("{0:N1}s - {1}" -f $sw.Elapsed.TotalSeconds, ($result | Select-Object -Last 1)) 'PASS'
        return $sw.Elapsed.TotalSeconds
    }
    $sw.Stop()
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    Write-Status ("TIMEOUT after {0}s" -f $TimeoutSeconds) 'FAIL'
    return $null
}

Write-Host ''
Write-Status "EventData match-vs-scan diagnostic" 'INFO'
Write-Status "Target: $ComputerName / $DaysBack days" 'INFO'

# --- Step 1: harvest REAL IPs from this DC's own 4624 events -----------------
Write-Host ''
Write-Host '--- Harvesting real IP addresses from recent 4624 events' -ForegroundColor White
$realIps = @()
try {
    $sample = @(Get-WinEvent -ComputerName $ComputerName `
                             -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start} `
                             -MaxEvents 400 -ErrorAction Stop)
    foreach ($e in $sample) {
        $x = [xml]$e.ToXml()
        $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $wks = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
        if ($ip -and $ip -notin @('-','::1','127.0.0.1') -and $wks) {
            $realIps += ($ip -replace '^::ffff:', '')
        }
    }
    $realIps = @($realIps | Select-Object -Unique)
    Write-Status "Found $($realIps.Count) distinct real client IP(s) in the 4624 sample" 'PASS'
    if ($realIps.Count) {
        Write-Host ("       e.g. " + (($realIps | Select-Object -First 5) -join ', ')) -ForegroundColor Gray
    }
} catch {
    Write-Status "Could not sample 4624 events: $($_.Exception.Message)" 'FAIL'
}

if ($realIps.Count -eq 0) {
    Write-Status "No real client IPs found in 4624 events. Correlation cannot work on this DC regardless of query shape - there are no named successful logons to correlate against." 'FAIL'
    Write-Host ''
    Write-Host 'CONCLUSION: leave correlation off (the default). Resolve via DHCP/DNS/AD instead.' -ForegroundColor Yellow
    Write-Host ''
    return
}

$oneIp  = $realIps[0]
$tenIps = @($realIps | Select-Object -First 10)

# --- Test A: EventData query for ONE IP THAT EXISTS -------------------------
$timeA = Measure-Query -Label "A. EventData filter, ONE REAL IP ($oneIp) - should match" -ArgumentList @($ComputerName,$oneIp) -Query {
    param($cn,$ip)
    $xp = "*[System[(EventID=4624)] and EventData[Data[@Name='IpAddress']='$ip' or Data[@Name='IpAddress']='::ffff:$ip']]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 10 -ErrorAction Stop)
        "matched $($e.Count) events"
    } catch { "no match: $($_.Exception.Message)" }
}

# --- Test B: same, but for an IP that does NOT exist ------------------------
$timeB = Measure-Query -Label "B. EventData filter, ONE BOGUS IP - must scan whole log" -ArgumentList @($ComputerName) -Query {
    param($cn)
    $xp = "*[System[(EventID=4624)] and EventData[Data[@Name='IpAddress']='203.0.113.253']]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 10 -ErrorAction Stop)
        "matched $($e.Count) events"
    } catch { "no match (full scan): $($_.Exception.Message)" }
}

# --- Test C: 10 real IPs, the batch shape the export uses -------------------
$timeC = Measure-Query -Label "C. EventData filter, 10 REAL IPs (export batch shape)" -ArgumentList @($ComputerName,$tenIps) -Query {
    param($cn,$ips)
    $terms = ($ips | ForEach-Object { "Data[@Name='IpAddress']='$_' or Data[@Name='IpAddress']='::ffff:$_'" }) -join ' or '
    $xp = "*[System[(EventID=4624 or EventID=4768)] and EventData[$terms]]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 50 -ErrorAction Stop)
        "matched $($e.Count) events"
    } catch { "no match: $($_.Exception.Message)" }
}

# --- Test D: THE ALTERNATIVE - one bounded 4624 sweep, filter in memory -----
# Instead of N queries each risking a full scan, do ONE capped pass over recent 4624s
# and build an IP->name map from whatever it contains. Cost is fixed and predictable.
$timeD = Measure-Query -Label "D. ALTERNATIVE: single capped 4624 sweep (5000 events), map built in memory" -ArgumentList @($ComputerName,$start) -Query {
    param($cn,$st)
    try {
        $e = @(Get-WinEvent -ComputerName $cn -FilterHashtable @{LogName='Security';Id=@(4624,4768);StartTime=$st} -MaxEvents 5000 -ErrorAction Stop)
        $map = @{}
        foreach ($evt in $e) {
            $x = [xml]$evt.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $ip = $d['IpAddress']; $w = $d['WorkstationName']
            if ($ip -and $w) {
                $ip = $ip -replace '^::ffff:', ''
                if (-not $map.ContainsKey($ip)) { $map[$ip] = $w }
            }
        }
        "scanned $($e.Count) events -> $($map.Count) distinct IP->name mappings"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- Verdict ----------------------------------------------------------------
Write-Host ''
Write-Host ('=' * 70) -ForegroundColor DarkGray
Write-Status "VERDICT" 'INFO'

if ($null -ne $timeA -and $timeA -lt 5) {
    Write-Status "Matching EventData queries ARE fast ($([math]::Round($timeA,1))s). Early-exit works." 'PASS'
    Write-Status "The cost is entirely in UNMATCHABLE IPs, each forcing a full log scan." 'INFO'
    Write-Host ''
    Write-Host 'RECOMMENDED FIX: keep targeted queries, but cap total correlation time and' -ForegroundColor Yellow
    Write-Host 'run the single-sweep fallback (test D) when many IPs are unresolvable.' -ForegroundColor Yellow
} else {
    Write-Status "Even MATCHING EventData queries are slow. Targeted correlation is not viable here." 'FAIL'
    Write-Host ''
    Write-Host 'RECOMMENDED FIX: replace per-IP queries with the single capped sweep (test D).' -ForegroundColor Yellow
}

if ($null -ne $timeD) {
    Write-Host ''
    Write-Status ("Single-sweep alternative cost: {0:N1}s for the whole correlation pass, regardless of IP count." -f $timeD) 'INFO'
}
Write-Host ''
