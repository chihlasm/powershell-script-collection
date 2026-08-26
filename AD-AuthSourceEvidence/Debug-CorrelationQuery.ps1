#Requires -Version 5.1

<#
.SYNOPSIS
    Diagnoses which event log query shape is slow on a specific domain controller.
.DESCRIPTION
    Run this ON or AGAINST the domain controller where Export-ADAuthSourceEvidence.ps1
    stalls. It times several query shapes against the real Security log so the slow one
    is identified by measurement rather than guesswork.

    Every query is capped by -MaxEvents and a per-test timeout, so this script cannot
    itself hang the way the export did.
.PARAMETER ComputerName
    Domain controller to query. Defaults to the local machine.
.PARAMETER DaysBack
    Search window. Default 7, to match the export's default.
.PARAMETER TimeoutSeconds
    Abandon any single test after this long and report it as TIMEOUT. Default 60.
.EXAMPLE
    .\Debug-CorrelationQuery.ps1
.EXAMPLE
    .\Debug-CorrelationQuery.ps1 -ComputerName DC02.corp.example.com -DaysBack 7
.NOTES
    Read-only. Runs queries only; changes nothing.
#>
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,
    [ValidateRange(10, 600)]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddDays(-$DaysBack)
$ageMs = [long]((Get-Date) - $start).TotalMilliseconds

function Write-Status {
    param([string]$Message, [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level='INFO')
    $c = @{PASS='Green';WARN='Yellow';FAIL='Red';INFO='Cyan'}[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $c
}

function Measure-Query {
    <#
        Runs one query shape in a background job so a slow query can be abandoned
        instead of hanging this diagnostic too.
    #>
    param(
        [string]$Label,
        [scriptblock]$Query,
        [object[]]$ArgumentList
    )

    Write-Host ''
    Write-Host "--- $Label" -ForegroundColor White

    $job = Start-Job -ScriptBlock $Query -ArgumentList $ArgumentList
    $sw  = [Diagnostics.Stopwatch]::StartNew()

    if (Wait-Job -Job $job -Timeout $TimeoutSeconds) {
        $sw.Stop()
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue 2>$null
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        if ($null -eq $result) {
            Write-Status ("completed in {0:N1}s - no events matched (or access denied)" -f $sw.Elapsed.TotalSeconds) 'WARN'
        } else {
            Write-Status ("completed in {0:N1}s - {1}" -f $sw.Elapsed.TotalSeconds, $result) 'PASS'
        }
        return $sw.Elapsed.TotalSeconds
    }

    $sw.Stop()
    Stop-Job  -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    Write-Status ("TIMEOUT - still running after {0}s. This is the slow shape." -f $TimeoutSeconds) 'FAIL'
    return $null
}

Write-Host ''
Write-Status "Correlation query diagnostic" 'INFO'
Write-Status "Target : $ComputerName" 'INFO'
Write-Status "Window : $DaysBack days (ageMs=$ageMs)" 'INFO'
Write-Status "Timeout: ${TimeoutSeconds}s per test" 'INFO'

# --- 0. How big is the log, and how much of it is 4624? ----------------------
Write-Host ''
Write-Host '--- 0. Log profile' -ForegroundColor White
try {
    $log = Get-WinEvent -ListLog Security -ComputerName $ComputerName -ErrorAction Stop
    Write-Status ("Security log: {0:N0} records, {1:N0} MB max, mode {2}" -f $log.RecordCount, ($log.MaximumSizeInBytes/1MB), $log.LogMode) 'INFO'
} catch {
    Write-Status "Could not read log config: $($_.Exception.Message)" 'WARN'
}

# --- 1. FilterHashtable with StartTime: the indexed, structured form ---------
$null = Measure-Query -Label "1. FilterHashtable Id=4624 + StartTime (indexed time seek)" -ArgumentList @($ComputerName,$start) -Query {
    param($cn,$st)
    try {
        $e = @(Get-WinEvent -ComputerName $cn -FilterHashtable @{LogName='Security';Id=4624;StartTime=$st} -MaxEvents 50 -ErrorAction Stop)
        "returned $($e.Count) events (capped at 50)"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- 2. XPath with timediff: function evaluated PER EVENT --------------------
# Suspected culprit. timediff() is a function call the log may not be able to satisfy
# from its time index, forcing a scan of every record in the log.
$null = Measure-Query -Label "2. XPath with timediff() time bound (suspected slow)" -ArgumentList @($ComputerName,$ageMs) -Query {
    param($cn,$ms)
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 50 -ErrorAction Stop)
        "returned $($e.Count) events (capped at 50)"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- 3. XPath with an EventData predicate, no time bound --------------------
$null = Measure-Query -Label "3. XPath EventData IpAddress filter, NO time bound" -ArgumentList @($ComputerName) -Query {
    param($cn)
    $xp = "*[System[(EventID=4624)] and EventData[Data[@Name='IpAddress']='10.0.0.1']]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 50 -ErrorAction Stop)
        "returned $($e.Count) events (capped at 50)"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- 4. The shape the export currently uses ---------------------------------
$null = Measure-Query -Label "4. CURRENT EXPORT SHAPE: timediff + 10 IPs (20 terms)" -ArgumentList @($ComputerName,$ageMs) -Query {
    param($cn,$ms)
    $terms = (1..10 | ForEach-Object { "Data[@Name='IpAddress']='10.0.0.$_' or Data[@Name='IpAddress']='::ffff:10.0.0.$_'" }) -join ' or '
    $xp = "*[System[(EventID=4624 or EventID=4768) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[$terms]]"
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -FilterXPath $xp -MaxEvents 50 -ErrorAction Stop)
        "returned $($e.Count) events (capped at 50)"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- 5. PROPOSED FIX: FilterXml, time bound in Select Path + EventData ------
# A structured XML query lets the time bound stay in the indexed System predicate while
# the EventData filter rides along, and is the documented form for compound queries.
$null = Measure-Query -Label "5. PROPOSED: FilterXml, SystemTime range + EventData" -ArgumentList @($ComputerName,$start) -Query {
    param($cn,$st)
    $iso = $st.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff') + 'Z'
    $terms = (1..10 | ForEach-Object { "Data[@Name='IpAddress']='10.0.0.$_' or Data[@Name='IpAddress']='::ffff:10.0.0.$_'" }) -join ' or '
    $xml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4768) and TimeCreated[@SystemTime&gt;='$iso']] and EventData[$terms]]</Select>
  </Query>
</QueryList>
"@
    try {
        $e = @(Get-WinEvent -ComputerName $cn -FilterXml $xml -MaxEvents 50 -ErrorAction Stop)
        "returned $($e.Count) events (capped at 50)"
    } catch { "ERROR: $($_.Exception.Message)" }
}

# --- 6. Is it remoting overhead rather than the query at all? ---------------
$null = Measure-Query -Label "6. Trivial query (isolates RPC/remoting overhead)" -ArgumentList @($ComputerName) -Query {
    param($cn)
    try {
        $e = @(Get-WinEvent -ComputerName $cn -LogName Security -MaxEvents 5 -ErrorAction Stop)
        "returned $($e.Count) events"
    } catch { "ERROR: $($_.Exception.Message)" }
}

Write-Host ''
Write-Status "Diagnostic complete." 'INFO'
Write-Host ''
Write-Host 'HOW TO READ THIS:' -ForegroundColor White
Write-Host '  Test 6 slow          -> the problem is remoting/RPC, not the query. Run the export ON the DC.' -ForegroundColor Gray
Write-Host '  Test 2 and 4 slow,'                                                                            -ForegroundColor Gray
Write-Host '    but 1 and 5 fast   -> timediff() is the culprit. Switch to the FilterXml shape (test 5).'    -ForegroundColor Gray
Write-Host '  Test 3 slow          -> EventData predicates scan the whole log on this DC; correlation'       -ForegroundColor Gray
Write-Host '                          must be abandoned in favour of a capped 4624 sample.'                  -ForegroundColor Gray
Write-Host '  Everything fast      -> the stall is elsewhere; capture -Verbose output from the export.'      -ForegroundColor Gray
Write-Host ''
