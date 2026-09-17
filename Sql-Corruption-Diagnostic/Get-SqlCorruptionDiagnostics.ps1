<#
.SYNOPSIS
    Read-only SQL Server diagnostics for suspected data loss/corruption:
    database state, last known-good CHECKDB, suspect pages, backup history,
    error log corruption signatures, and file space/autogrow activity.

.DESCRIPTION
    Generalized for any SQL Server instance being investigated for unexplained
    data loss. Uses Windows Authentication by default via .NET SqlClient - no
    SqlServer PowerShell module required. Makes no changes to the database by
    default. DBCC CHECKDB is opt-in only via -RunCheckDB (see warning below).

.PARAMETER SqlInstance
    Instance to connect to. Use "." or "localhost" for default instance,
    "SERVERNAME\INSTANCENAME" for named instances. Default: "localhost".

.PARAMETER DatabaseName
    Specific database to focus on (e.g. the RMS database). If omitted, all
    non-system databases are covered for state/backup/suspect-page checks.

.PARAMETER DaysBack
    Lookback window for error log and backup history review. Default 30.
    Widen this if you need to cover an incident from several months back
    (e.g. -DaysBack 210 to reach back to a December incident).

.PARAMETER IncidentDates
    Optional array of dates (yyyy-MM-dd) to specifically call out in the
    error log scan, e.g. -IncidentDates '2025-12-05','2026-06-28'

.PARAMETER RunCheckDB
    WARNING: Runs DBCC CHECKDB against each database. This reads every page
    and can be resource-intensive and take a long time on a large production
    database. Defaults to PHYSICAL_ONLY (fast, storage-integrity focused)
    unless -FullCheckDB is also specified. Coordinate timing with the client
    before using this against a live RMS server.

.PARAMETER FullCheckDB
    Use with -RunCheckDB to run the full logical CHECKDB instead of
    PHYSICAL_ONLY. Significantly heavier - after-hours only.

.PARAMETER SqlLogin / SqlPassword
    Optional SQL authentication if Windows Auth isn't viable. Avoid where
    possible; Windows Auth is the default and recommended path.

.EXAMPLE
    .\Get-SqlCorruptionDiagnostics.ps1 -SqlInstance "COSGA-SQL01" -DatabaseName "RMS" -DaysBack 210 -IncidentDates '2025-12-05','2026-06-28'
#>

[CmdletBinding()]
param(
    [string]$SqlInstance = "localhost",
    [string]$DatabaseName,
    [int]$DaysBack = 30,
    [string[]]$IncidentDates,
    [switch]$RunCheckDB,
    [switch]$FullCheckDB,
    [string]$OutputPath = "C:\ProgramData\VC3\Diagnostics",
    [string]$SqlLogin,
    [string]$SqlPassword
)

$ErrorActionPreference = 'Continue'
$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime = (Get-Date).AddDays(-$DaysBack)
$flags     = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$reportFile = Join-Path $OutputPath "$($hostName)_SqlDiagnostics_$timestamp.log"

function Write-Section { param([string]$Title) "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) | Out-File -FilePath $reportFile -Append }
function Write-Line    { param([string]$Text = "") $Text | Out-File -FilePath $reportFile -Append }

# ---------------------------------------------------------------------------
# CONNECTION
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Data -ErrorAction SilentlyContinue

function New-SqlConnectionString {
    param([string]$Database = "master")
    if ($SqlLogin -and $SqlPassword) {
        return "Server=$SqlInstance;Database=$Database;User Id=$SqlLogin;Password=$SqlPassword;TrustServerCertificate=True;Connect Timeout=15;"
    }
    return "Server=$SqlInstance;Database=$Database;Integrated Security=True;TrustServerCertificate=True;Connect Timeout=15;"
}

function Invoke-SqlQuery {
    param([string]$Query, [string]$Database = "master", [int]$TimeoutSec = 60)
    $connStr = New-SqlConnectionString -Database $Database
    $conn = New-Object System.Data.SqlClient.SqlConnection $connStr
    try {
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = $TimeoutSec
        $da = New-Object System.Data.SqlClient.SqlDataAdapter $cmd
        $dt = New-Object System.Data.DataTable
        $da.Fill($dt) | Out-Null
        return $dt
    } finally {
        $conn.Close()
    }
}

Write-Line "SQL Server Diagnostics"
Write-Line "Host: $hostName  |  Instance: $SqlInstance"
Write-Line "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line "Lookback: $DaysBack days (since $($startTime.ToString('yyyy-MM-dd')))"

try {
    $verInfo = Invoke-SqlQuery -Query "SELECT @@VERSION AS Version, SERVERPROPERTY('Edition') AS Edition, SERVERPROPERTY('ProductLevel') AS ProductLevel, SERVERPROPERTY('ProductUpdateLevel') AS CU"
    Write-Line "Version: $($verInfo.Version[0])"
    Write-Line "Edition: $($verInfo.Edition) | Level: $($verInfo.ProductLevel) | CU: $($verInfo.CU)"
} catch {
    Write-Line "COULD NOT CONNECT to instance '$SqlInstance': $($_.Exception.Message)"
    Write-Line "Verify instance name, that SQL Browser/TCP is enabled if named instance, and that this account has access."
    $flags.Add("Could not connect to SQL instance '$SqlInstance' - see connection error above")
    $summaryLines = @(("=" * 80), "FINDINGS SUMMARY - $hostName - CONNECTION FAILED", ("=" * 80)) + $flags
    $summaryLines -join "`r`n" | Set-Content -Path $reportFile -Encoding utf8
    (Get-Content $reportFile -Raw) | Out-File -FilePath $reportFile -Append -Encoding utf8
    Write-Host "Could not connect - see $reportFile"
    return
}

# ---------------------------------------------------------------------------
# DATABASE STATE
# ---------------------------------------------------------------------------
Write-Section "DATABASE STATE"
try {
    $dbFilter = if ($DatabaseName) { "AND name = '$DatabaseName'" } else { "AND database_id > 4" }
    $dbs = Invoke-SqlQuery -Query "SELECT name, state_desc, recovery_model_desc, page_verify_option_desc, is_read_only, create_date FROM sys.databases WHERE 1=1 $dbFilter ORDER BY name"
    $dbs | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    foreach ($row in $dbs) {
        if ($row.state_desc -ne 'ONLINE') { $flags.Add("Database '$($row.name)' state is $($row.state_desc), not ONLINE") }
        if ($row.page_verify_option_desc -ne 'CHECKSUM') { $flags.Add("Database '$($row.name)' PAGE_VERIFY is $($row.page_verify_option_desc), not CHECKSUM - weaker corruption detection") }
    }
} catch { Write-Line "Error querying sys.databases: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# LAST KNOWN GOOD CHECKDB (per database, via DBCC DBINFO - lightweight/safe)
# ---------------------------------------------------------------------------
Write-Section "LAST KNOWN GOOD CHECKDB (per database)"
try {
    $dbNames = if ($DatabaseName) { @($DatabaseName) } else {
        (Invoke-SqlQuery -Query "SELECT name FROM sys.databases WHERE database_id > 4 AND state_desc = 'ONLINE'").name
    }
    foreach ($db in $dbNames) {
        try {
            $dbinfo = Invoke-SqlQuery -Database $db -Query "DBCC DBINFO('$db') WITH TABLERESULTS"
            $lastGood = ($dbinfo | Where-Object { $_.Field -eq 'dbi_dbccLastKnownGood' }).Value
            Write-Line "$db - Last known good CHECKDB: $lastGood"
            if (-not $lastGood -or $lastGood -like '1900-01-01*') {
                $flags.Add("Database '$db' has NO recorded successful CHECKDB (dbi_dbccLastKnownGood is empty/epoch) - integrity unverified")
            } elseif ([datetime]$lastGood -lt (Get-Date).AddDays(-90)) {
                $flags.Add("Database '$db' last known-good CHECKDB was $lastGood - over 90 days ago")
            }
        } catch { Write-Line "$db - could not read DBCC DBINFO: $($_.Exception.Message)" }
    }
} catch { Write-Line "Error enumerating databases for CHECKDB history: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# SUSPECT PAGES
# ---------------------------------------------------------------------------
Write-Section "SUSPECT PAGES (msdb.dbo.suspect_pages)"
try {
    $suspect = Invoke-SqlQuery -Database "msdb" -Query "SELECT DB_NAME(database_id) AS DBName, file_id, page_id, event_type, error_count, last_update_date FROM msdb.dbo.suspect_pages ORDER BY last_update_date DESC"
    if ($suspect.Rows.Count -gt 0) {
        $suspect | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($suspect.Rows.Count) entries in suspect_pages - prior corruption was detected and logged by SQL Server")
    } else {
        Write-Line "No entries in suspect_pages."
    }
} catch { Write-Line "Error querying suspect_pages: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# BACKUP HISTORY
# ---------------------------------------------------------------------------
Write-Section "BACKUP HISTORY (since $($startTime.ToString('yyyy-MM-dd')))"
try {
    $dbFilterBk = if ($DatabaseName) { "AND database_name = '$DatabaseName'" } else { "" }
    $backups = Invoke-SqlQuery -Database "msdb" -Query @"
SELECT database_name,
       CASE type WHEN 'D' THEN 'Full' WHEN 'I' THEN 'Diff' WHEN 'L' THEN 'Log' ELSE type END AS BackupType,
       backup_start_date, backup_finish_date, is_copy_only,
       CAST(backup_size/1024.0/1024.0 AS DECIMAL(10,1)) AS SizeMB
FROM msdb.dbo.backupset
WHERE backup_start_date >= '$($startTime.ToString('yyyy-MM-dd'))' $dbFilterBk
ORDER BY database_name, backup_start_date DESC
"@
    if ($backups.Rows.Count -gt 0) {
        $backups | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $lastLog = $backups | Where-Object { $_.BackupType -eq 'Log' } | Sort-Object backup_start_date -Descending | Select-Object -First 1
        if (-not $lastLog -and ($dbs | Where-Object { $_.recovery_model_desc -eq 'FULL' })) {
            $flags.Add("No log backups found in window for a FULL recovery model database - check log backup job/maintenance plan")
        }
    } else {
        Write-Line "No backups recorded in msdb in this window."
        $flags.Add("No backup history found in msdb for the lookback window - verify backup job is actually running (native or Datto agent)")
    }
} catch { Write-Line "Error querying backup history: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# ERROR LOG - CORRUPTION SIGNATURES
# ---------------------------------------------------------------------------
Write-Section "SQL ERROR LOG - CORRUPTION/IO SIGNATURES"
$searchTerms = @('823','824','825','torn page','consistency-based I/O error','Stack Dump','I/O error','database is corrupt')
try {
    $hits = @()
    for ($archive = 0; $archive -le 6; $archive++) {
        foreach ($term in $searchTerms) {
            try {
                $q = "EXEC master.dbo.xp_readerrorlog $archive, 1, N'$term', NULL, '$($startTime.ToString('yyyy-MM-dd'))', NULL, N'DESC'"
                $rows = Invoke-SqlQuery -Query $q
                if ($rows -and $rows.Rows.Count -gt 0) { $hits += $rows }
            } catch { }  # archive number may not exist - expected, continue
        }
    }
    if ($hits.Count -gt 0) {
        $hits | Sort-Object LogDate -Unique | Select-Object LogDate, Text | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($hits.Count) SQL error log entries matched corruption/IO signatures - review above")
    } else {
        Write-Line "No corruption/IO signature matches found in scanned error log archives."
    }
} catch { Write-Line "Error scanning SQL error log: $($_.Exception.Message)" }

if ($IncidentDates) {
    Write-Section "ERROR LOG NEAR SPECIFIED INCIDENT DATES"
    foreach ($d in $IncidentDates) {
        try {
            $day = [datetime]$d
            $rangeStart = $day.AddDays(-1).ToString('yyyy-MM-dd')
            $rangeEnd   = $day.AddDays(1).ToString('yyyy-MM-dd')
            Write-Line "--- Around $d ($rangeStart to $rangeEnd), all archives, no filter ---"
            for ($archive = 0; $archive -le 6; $archive++) {
                try {
                    $q = "EXEC master.dbo.xp_readerrorlog $archive, 1, NULL, NULL, '$rangeStart', '$rangeEnd', N'ASC'"
                    $rows = Invoke-SqlQuery -Query $q
                    if ($rows -and $rows.Rows.Count -gt 0) {
                        $rows | Select-Object LogDate, Text | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
                    }
                } catch { }
            }
        } catch { Write-Line "Could not parse incident date '$d': $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# FILE SPACE / AUTOGROW
# ---------------------------------------------------------------------------
Write-Section "DATA/LOG FILE SPACE"
try {
    $dbFilterF = if ($DatabaseName) { "WHERE DB_NAME(database_id) = '$DatabaseName'" } else { "" }
    $files = Invoke-SqlQuery -Query @"
SELECT DB_NAME(database_id) AS DBName, name AS LogicalName, physical_name,
       CAST(size/128.0 AS DECIMAL(10,1)) AS SizeMB,
       CASE is_percent_growth WHEN 1 THEN CAST(growth AS VARCHAR) + '%' ELSE CAST(growth/128 AS VARCHAR) + ' MB' END AS Growth,
       max_size
FROM sys.master_files $dbFilterF
ORDER BY DBName, type
"@
    $files | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append

    $volsChecked = @()
    foreach ($f in $files) {
        $drive = ($f.physical_name -split ':')[0]
        if ($drive -and ($volsChecked -notcontains $drive)) {
            $volsChecked += $drive
            try {
                $vol = Get-Volume -DriveLetter $drive -ErrorAction Stop
                $pctFree = [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1)
                Write-Line "Volume $($drive): $pctFree% free ($([math]::Round($vol.SizeRemaining/1GB,1)) GB of $([math]::Round($vol.Size/1GB,1)) GB)"
                if ($pctFree -lt 10) { $flags.Add("Volume $($drive): only $pctFree% free - risk of failed autogrow / DB write failures") }
            } catch { }
        }
    }
} catch { Write-Line "Error querying file space: $($_.Exception.Message)" }

try {
    Write-Line "`r`n--- Autogrow/shrink events (default trace, if enabled) ---"
    $trace = Invoke-SqlQuery -Query @"
DECLARE @path NVARCHAR(260);
SELECT @path = REVERSE(SUBSTRING(REVERSE(path), CHARINDEX('\', REVERSE(path)), 260)) + N'log.trc'
FROM sys.traces WHERE is_default = 1;
SELECT te.name AS EventName, t.DatabaseName, t.FileName, t.StartTime, t.Duration
FROM ::fn_trace_gettable((SELECT @path), DEFAULT) t
JOIN sys.trace_events te ON t.EventClass = te.trace_event_id
WHERE te.name LIKE '%Auto Grow%' OR te.name LIKE '%Auto Shrink%'
ORDER BY t.StartTime DESC
"@
    if ($trace.Rows.Count -gt 0) {
        $trace | Select-Object -First 50 | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    } else {
        Write-Line "No autogrow/shrink events found (or default trace not enabled)."
    }
} catch { Write-Line "Default trace not available/enabled - autogrow history not read: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# WINDOWS APPLICATION LOG - SQL-RELATED ERRORS
# ---------------------------------------------------------------------------
Write-Section "WINDOWS APPLICATION LOG - SQL-RELATED ERRORS ($DaysBack days)"
try {
    $sqlEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop |
        Where-Object { $_.ProviderName -like 'MSSQL*' -and $_.Id -in @(823,824,825,833,3313,5123,9002,17053) }
    if ($sqlEvents) {
        $sqlEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, @{N='Message';E={($_.Message -split "`n")[0]}} |
            Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($sqlEvents.Count) SQL-related error events in Application log (IDs: $((($sqlEvents.Id | Sort-Object -Unique) -join ', ')))")
    } else {
        Write-Line "No matching SQL error events (823/824/825/833/3313/5123/9002/17053) in window."
    }
} catch { Write-Line "Error querying Application log: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# OPTIONAL: DBCC CHECKDB
# ---------------------------------------------------------------------------
if ($RunCheckDB) {
    Write-Section "DBCC CHECKDB RESULTS (RunCheckDB requested)"
    $mode = if ($FullCheckDB) { "" } else { " WITH PHYSICAL_ONLY, NO_INFOMSGS" }
    if ($FullCheckDB) { $modeNote = "FULL logical CHECKDB" } else { $modeNote = "PHYSICAL_ONLY (fast, storage-integrity focused)" }
    Write-Line "Mode: $modeNote"
    $dbNames = if ($DatabaseName) { @($DatabaseName) } else { (Invoke-SqlQuery -Query "SELECT name FROM sys.databases WHERE database_id > 4 AND state_desc = 'ONLINE'").name }
    foreach ($db in $dbNames) {
        Write-Line "`r`n--- CHECKDB: $db (started $(Get-Date -Format 'HH:mm:ss')) ---"
        try {
            $result = Invoke-SqlQuery -Database $db -Query "DBCC CHECKDB('$db')$mode" -TimeoutSec 3600
            if ($result.Rows.Count -gt 0) {
                $result | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
                $flags.Add("CHECKDB on '$db' returned messages - review output, this may indicate corruption")
            } else {
                Write-Line "CHECKDB completed with no errors reported."
            }
        } catch { Write-Line "CHECKDB failed or timed out on '$db': $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
$summaryLines = @(("=" * 80), "FINDINGS SUMMARY - $hostName\$SqlInstance - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", ("=" * 80))
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
