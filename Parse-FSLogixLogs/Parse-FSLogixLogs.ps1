#Requires -Version 5.1
<#
.SYNOPSIS
    Parses FSLogix Profile and ODFC container logs into structured objects for triage.

.DESCRIPTION
    FSLogix writes verbose, UTF-16LE encoded logs that are painful to read by hand and
    impossible to grep reliably with default tooling. This script turns them into objects.

    It surfaces the findings that actually matter during an incident:

      * Logon / logoff events with per-user profile load and unload durations
      * Volume re-attach LOOPS - repeated re-attach of the same container, which indicates
        FSLogix is losing its handle to the SMB share and self-healing. A regular cadence
        (low variance between intervals) points at a timer-driven cause such as SMB session
        loss rather than user activity.
      * Container fill percentage per user, so you can spot profiles approaching SizeInMBs
      * Disk compaction outcomes, including how much space was reclaimable but skipped
        because it fell under FSLogix's internal threshold
      * All ERROR / WARN lines, including FSLogix's [ERROR:xxxxxxxx] coded format
      * Non-monotonic timestamps and other log anomalies

    Designed for MSP use: point it at a single file, a host's log folder, or a UNC path
    holding logs collected from an entire host pool.

.PARAMETER Path
    One or more paths. Accepts a specific .log file, a directory (searched for
    Profile-*.log / ODFC-*.log), or a wildcard. UNC paths are supported.

.PARAMETER Recurse
    Search directories recursively. Useful when logs from multiple hosts have been
    collected into per-host subfolders.

.PARAMETER LogType
    Restrict to Profile logs, ODFC logs, or both. Default: All.

.PARAMETER StartTime
    Only return findings at or after this time. Compared against parsed entry timestamps.

.PARAMETER EndTime
    Only return findings at or before this time.

.PARAMETER ReattachLoopThreshold
    Number of re-attach events for the same user in one log before it is reported as a
    loop. Default 5. A healthy log has zero or one per user (one is normal at logoff).

.PARAMETER ContainerFullWarnPercent
    Flag containers whose used space is at or above this percentage of the volume.
    Default 80.

.PARAMETER ExportPath
    Directory to write CSVs into. One CSV per finding type, plus Findings.csv summary.
    Created if it does not exist.

.PARAMETER Report
    Print a human-readable summary to the console in addition to emitting objects.

.EXAMPLE
    .\Parse-FSLogixLogs.ps1 -Path 'C:\ProgramData\FSLogix\Logs\Profile' -Report

    Parse today's and any older Profile logs on the local host and print a summary.

.EXAMPLE
    .\Parse-FSLogixLogs.ps1 -Path '\\fileserver\FSLogixLogs' -Recurse -Report -ExportPath C:\Temp\FSLogixTriage

    Parse logs collected from a whole host pool and export CSVs for a ticket attachment.

.EXAMPLE
    $r = .\Parse-FSLogixLogs.ps1 -Path .\Profile-20260806.log
    $r.ReattachLoops | Format-List

    Inspect just the re-attach loop findings.

.EXAMPLE
    $r = .\Parse-FSLogixLogs.ps1 -Path .\Profile-20260806.log
    $times = ($r.Reattaches | Where-Object User -eq 'p.sidhu').Timestamp
    .\Get-FSLogixStorageEvents.ps1 -StartTime $times[0].AddMinutes(-5) `
        -EndTime $times[-1].AddMinutes(5) -CorrelateWith $times -Report

    Feed re-attach timestamps into the event log collector to find the trigger.

.NOTES
    Read-only. Never modifies or deletes log files.
    Targets Windows PowerShell 5.1 so it runs on session hosts without extra install.

    FSLogix log reference:
      https://learn.microsoft.com/en-us/fslogix/concepts-fslogix-logging
      https://learn.microsoft.com/en-us/fslogix/troubleshooting-vhd-disk-compaction
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [string[]]$Path,

    [switch]$Recurse,

    [ValidateSet('Profile', 'ODFC', 'All')]
    [string]$LogType = 'All',

    [datetime]$StartTime,

    [datetime]$EndTime,

    [ValidateRange(2, 1000)]
    [int]$ReattachLoopThreshold = 5,

    [ValidateRange(1, 100)]
    [int]$ContainerFullWarnPercent = 80,

    [string]$ExportPath,

    [switch]$Report
)

begin {
    # StrictMode 1.0 catches variable typos without breaking on absent properties,
    # which matters for a diagnostic script that must survive unexpected log content.
    Set-StrictMode -Version 1.0
    $ErrorActionPreference = 'Stop'

    #region Regex patterns
    # Entry format: [HH:mm:ss.fff][tid:xxxxxxxx.xxxxxxxx][LEVEL]   Message
    # Level may carry a code, e.g. [ERROR:00000422]
    $reEntry = [regex]'^\[(?<Time>\d{2}:\d{2}:\d{2}\.\d{3})\]\[tid:(?<Tid>[0-9A-Fa-f.]+)\]\[(?<Level>[A-Z]+)(?::(?<Code>[0-9A-Fa-f]+))?\]\s*(?<Message>.*)$'

    $reSession       = [regex]'^=+\s*(?<Phase>Begin|End)\s+Session:\s*(?<Name>.+?)\s*$'
    $reLoadProfile   = [regex]'^LoadProfile:\s*(?<User>.+?)\s*$'
    $reUnloadProfile = [regex]'^Unload profile:\s*(?<User>.+?)\s*$'
    $reLoadTime      = [regex]'^(?<Kind>load|unload)Profile time:\s*(?<Ms>\d+)\s*milliseconds'
    $reReattachLock  = [regex]'^Acquired reattach virtual disk lock for user\s+(?<User>\S+)\s+\(SID=(?<Sid>S-1-[0-9-]+)\)'
    $reVhdPath       = [regex]'^VHDPath:\s*(?<VhdPath>.+?)\s*$'
    $reReattachOk    = [regex]'^Volume successfully re-attached for\s+(?<VhdPath>.+?)\s*$'
    $reContainer     = [regex]'^vhd\(x\)\s+(?<VhdPath>.+?)\s+has\s+(?<FreeMB>[\d.]+)\s+MB\s+left\s+\((?<FreePct>[\d.]+)\s*%\s*free\)'
    $reCompactResult = [regex]'^Disk size results:\s*WasCompacted:\s*(?<Compacted>\w+),\s*MaxSupportedSize:\s*(?<MaxMB>[\d.]+)\s*MB,\s*MinSupportedSize:\s*(?<MinMB>[\d.]+)\s*MB,\s*Size\s*\(Before:\s*(?<BeforeMB>[\d.]+)\s*MB\s*-\s*After:\s*(?<AfterMB>[\d.]+)\s*MB\),\s*Space Saved:\s*(?<SavedMB>[\d.]+)\s*MB,\s*Compaction took:\s*(?<Ms>\d+)\s*MS'
    $reCompactSkip   = [regex]'^Disk was not compacted,\s*Reason:\s*(?<Reason>.+?),\s*ErrorMessage:\s*(?<ErrorMessage>.*?)\s*$'
    $reAppxTimeout   = [regex]'^AppxPackage installation timeout'
    $reAppxInstall   = [regex]'^Installed\s+(?<Count>\d+)\s+AppXPackages in\s+(?<Ms>\d+)ms'
    $reSessionUser   = [regex]'^User:\s*(?<Sid>S-1-[0-9-]+)\s*\((?<User>[^)]+)\)'
    $reStatusSet     = [regex]'^Status set to\s+(?<Code>\d+):\s*(?<Text>.+?)\s*$'
    $reReasonSet     = [regex]'^Reason set to\s+(?<Code>\d+):\s*(?<Text>.+?)\s*$'
    $reOdfcDisabled  = [regex]'FSLogix Office365 containers feature is not enabled'

    # Header block
    $reHdrCreated  = [regex]'^Log file created\s+(?<Date>\d{4}-\d{2}-\d{2})\s+at\s+(?<Time>\d{2}:\d{2}:\d{2})'
    $reHdrUtc      = [regex]'^UTC(?<Offset>[+-]\d{2}:\d{2})\s*$'
    $reHdrOrigin   = [regex]'^Origin:\s*(?<Origin>.+?)\s*\(Version\s+(?<Version>[\d.]+)\)'
    $reHdrOs       = [regex]'^Windows\s+(?<OsBuild>[\d.]+)\s+\((?<OsName>.+?)\)\s*$'
    $reHdrComputer = [regex]'^Computer Name:\s*(?<Computer>\S+)\s+User Name:\s*(?<RunAs>\S+)'
    $reHdrRam      = [regex]'^Installed system RAM:\s*(?<RamMB>\d+)\s*MB'

    # Container folder naming: <SID>_<user> (default) or <user>_<SID> (FlipFlop)
    $reFolderSidFirst  = [regex]'\\(?<Sid>S-1-[0-9-]+)_(?<User>[^\\]+)\\'
    $reFolderUserFirst = [regex]'\\(?<User>[^\\]+)_(?<Sid>S-1-[0-9-]+)\\'
    #endregion

    function Get-LogLine {
        <#
            Streams lines from a log file with BOM-based encoding detection.
            FSLogix writes UTF-16LE with a BOM; passing detectEncodingFromByteOrderMarks
            lets StreamReader handle UTF-16LE/BE and UTF-8 BOM automatically, and falls
            back to the supplied default (UTF8) when no BOM is present.
            Streaming rather than ReadAllLines keeps memory flat on debug-level logs,
            which can reach hundreds of MB.
        #>
        param([string]$FilePath)

        $reader = $null
        try {
            $reader = New-Object System.IO.StreamReader(
                $FilePath, [System.Text.Encoding]::UTF8, $true)
            while (-not $reader.EndOfStream) {
                $reader.ReadLine()
            }
        }
        finally {
            if ($null -ne $reader) { $reader.Dispose() }
        }
    }

    function Get-MedianValue {
        param([double[]]$Value)
        $s = @($Value | Sort-Object)
        if ($s.Count -eq 0) { return 0 }
        if ($s.Count % 2 -eq 1) { return $s[[int](($s.Count - 1) / 2)] }
        return ($s[($s.Count / 2) - 1] + $s[$s.Count / 2]) / 2
    }

    function Get-UserFromVhdPath {
        param([string]$VhdPath)
        $m = $reFolderSidFirst.Match($VhdPath)
        if ($m.Success) {
            return [PSCustomObject]@{ User = $m.Groups['User'].Value; Sid = $m.Groups['Sid'].Value }
        }
        $m = $reFolderUserFirst.Match($VhdPath)
        if ($m.Success) {
            return [PSCustomObject]@{ User = $m.Groups['User'].Value; Sid = $m.Groups['Sid'].Value }
        }
        return [PSCustomObject]@{ User = $null; Sid = $null }
    }

    function Resolve-LogFile {
        param([string[]]$InputPath, [switch]$DoRecurse, [string]$Type)

        $pattern = switch ($Type) {
            'Profile' { @('Profile-*.log') }
            'ODFC'    { @('ODFC-*.log') }
            default   { @('Profile-*.log', 'ODFC-*.log') }
        }

        $found = New-Object System.Collections.Generic.List[string]
        foreach ($p in $InputPath) {
            if (Test-Path -LiteralPath $p -PathType Container) {
                foreach ($pat in $pattern) {
                    Get-ChildItem -LiteralPath $p -Filter $pat -File -Recurse:$DoRecurse -ErrorAction SilentlyContinue |
                        ForEach-Object { $found.Add($_.FullName) }
                }
            }
            elseif (Test-Path -LiteralPath $p -PathType Leaf) {
                $found.Add((Resolve-Path -LiteralPath $p).ProviderPath)
            }
            else {
                # Treat as wildcard
                $resolved = Get-ChildItem -Path $p -File -Recurse:$DoRecurse -ErrorAction SilentlyContinue
                if ($resolved) { $resolved | ForEach-Object { $found.Add($_.FullName) } }
                else { Write-Warning "Path not found or matched nothing: $p" }
            }
        }
        return ($found | Sort-Object -Unique)
    }

    $allResults = New-Object System.Collections.Generic.List[object]
}

process {
    $files = Resolve-LogFile -InputPath $Path -DoRecurse:$Recurse -Type $LogType
    if (-not $files -or $files.Count -eq 0) {
        Write-Warning 'No FSLogix log files resolved from the supplied path(s).'
        return
    }

    foreach ($file in $files) {

        Write-Verbose "Parsing $file"

        # ---- Per-file state ----
        $meta = [ordered]@{
            FilePath      = $file
            FileName      = [IO.Path]::GetFileName($file)
            LogKind       = if ([IO.Path]::GetFileName($file) -like 'ODFC-*') { 'ODFC' } else { 'Profile' }
            Computer      = $null
            FSLogixVersion= $null
            OsBuild       = $null
            OsName        = $null
            RamMB         = $null
            HeaderCreated = $null
            HeaderUtcOffset = $null
            LogDate       = $null
            LineCount     = 0
            ParsedCount   = 0
        }

        # Derive the log date from the filename (Profile-YYYYMMDD.log). Entry timestamps
        # carry time only, so we need a base date to build real DateTime values.
        $baseDate = $null
        if ([IO.Path]::GetFileNameWithoutExtension($file) -match '(?<Ymd>\d{8})$') {
            try { $baseDate = [datetime]::ParseExact($Matches['Ymd'], 'yyyyMMdd', $null) } catch { $baseDate = $null }
        }
        if ($null -eq $baseDate) {
            $baseDate = (Get-Item -LiteralPath $file).LastWriteTime.Date
            Write-Verbose "  No date in filename; using LastWriteTime date $($baseDate.ToString('yyyy-MM-dd'))"
        }
        $meta.LogDate = $baseDate

        $sessions    = New-Object System.Collections.Generic.List[object]
        $logons      = New-Object System.Collections.Generic.List[object]
        $reattaches  = New-Object System.Collections.Generic.List[object]
        $containers  = New-Object System.Collections.Generic.List[object]
        $compactions = New-Object System.Collections.Generic.List[object]
        $problems    = New-Object System.Collections.Generic.List[object]
        $anomalies   = New-Object System.Collections.Generic.List[object]

        $sessionStack = New-Object System.Collections.Generic.List[object]
        $prevTime     = $null
        $dayOffset    = 0
        $lineNo       = 0
        $inHeader     = $true

        # Rolling context: the re-attach and compaction blocks span several lines, so we
        # remember the most recent user / VHD path / compaction record to attach detail to.
        $ctxUser = $null; $ctxSid = $null; $ctxVhd = $null
        $pendingCompaction = $null
        $lastStatus = $null; $lastReason = $null
        $odfcDisabledSeen = $false

        foreach ($line in (Get-LogLine -FilePath $file)) {
            $lineNo++

            # Strip a leading BOM character if StreamReader left one on line 1
            if ($lineNo -eq 1) { $line = $line -replace '^\uFEFF', '' }

            $m = $reEntry.Match($line)
            if (-not $m.Success) {
                # Header / separator lines
                if ($inHeader -or $lineNo -lt 40) {
                    if     ($reHdrComputer.IsMatch($line)) { $h = $reHdrComputer.Match($line); $meta.Computer = $h.Groups['Computer'].Value }
                    elseif ($reHdrOrigin.IsMatch($line))   { $h = $reHdrOrigin.Match($line);   $meta.FSLogixVersion = $h.Groups['Version'].Value }
                    elseif ($reHdrOs.IsMatch($line))       { $h = $reHdrOs.Match($line);       $meta.OsBuild = $h.Groups['OsBuild'].Value; $meta.OsName = $h.Groups['OsName'].Value }
                    elseif ($reHdrRam.IsMatch($line))      { $h = $reHdrRam.Match($line);      $meta.RamMB = [int]$h.Groups['RamMB'].Value }
                    elseif ($reHdrUtc.IsMatch($line))      { $h = $reHdrUtc.Match($line);      $meta.HeaderUtcOffset = $h.Groups['Offset'].Value }
                    elseif ($reHdrCreated.IsMatch($line))  {
                        $h = $reHdrCreated.Match($line)
                        $meta.HeaderCreated = "$($h.Groups['Date'].Value) $($h.Groups['Time'].Value)"
                    }
                }
                continue
            }

            $inHeader = $false
            $meta.ParsedCount++

            $tod   = [timespan]::Parse($m.Groups['Time'].Value)
            $level = $m.Groups['Level'].Value
            $code  = $m.Groups['Code'].Value
            $msg   = $m.Groups['Message'].Value.Trim()

            # Day rollover: only treat a backward jump of more than 12h as midnight
            # crossing. Smaller backward jumps are log artifacts (FSLogix sometimes
            # leaves stale lines above the header after rotation) and get flagged.
            if ($null -ne $prevTime) {
                $delta = $tod - $prevTime
                if ($delta.TotalHours -lt -12) {
                    $dayOffset++
                }
                elseif ($delta.TotalSeconds -lt 0) {
                    $anomalies.Add([PSCustomObject]@{
                        FilePath = $file
                        Line     = $lineNo
                        Type     = 'NonMonotonicTimestamp'
                        Detail   = "Timestamp moved backward from $prevTime to $tod (log rotation artifact or clock/timezone change)"
                    })
                }
            }
            $prevTime = $tod
            $ts = $baseDate.AddDays($dayOffset).Add($tod)

            # ---- Errors and warnings ----
            if ($level -in @('ERROR', 'WARN', 'WARNING', 'CRITICAL', 'FATAL')) {
                $problems.Add([PSCustomObject]@{
                    Timestamp = $ts
                    Computer  = $meta.Computer
                    LogKind   = $meta.LogKind
                    Level     = $level
                    Code      = if ($code) { $code } else { $null }
                    Message   = $msg
                    Line      = $lineNo
                    FilePath  = $file
                })
            }

            # ---- Session begin / end ----
            $s = $reSession.Match($msg)
            if ($s.Success) {
                $name = $s.Groups['Name'].Value.Trim()
                if ($s.Groups['Phase'].Value -eq 'Begin') {
                    $sessionStack.Add([PSCustomObject]@{ Name = $name; Start = $ts; Line = $lineNo })

                    $lp = $reLoadProfile.Match($name)
                    if ($lp.Success) { $ctxUser = $lp.Groups['User'].Value.Trim() }
                    $up = $reUnloadProfile.Match($name)
                    if ($up.Success) { $ctxUser = $up.Groups['User'].Value.Trim() }
                }
                else {
                    # Pop the newest matching Begin
                    $idx = -1
                    for ($i = $sessionStack.Count - 1; $i -ge 0; $i--) {
                        if ($sessionStack[$i].Name -eq $name) { $idx = $i; break }
                    }
                    if ($idx -ge 0) {
                        $open = $sessionStack[$idx]
                        $sessionStack.RemoveAt($idx)
                        $sessions.Add([PSCustomObject]@{
                            Computer   = $meta.Computer
                            LogKind    = $meta.LogKind
                            Session    = $name
                            Start      = $open.Start
                            End        = $ts
                            DurationMs = [int](($ts - $open.Start).TotalMilliseconds)
                            Depth      = $sessionStack.Count
                            FilePath   = $file
                        })
                    }
                }
                continue
            }

            # ---- Rolling context ----
            $su = $reSessionUser.Match($msg)
            if ($su.Success) { $ctxSid = $su.Groups['Sid'].Value; $ctxUser = $su.Groups['User'].Value.Trim() }

            $vp = $reVhdPath.Match($msg)
            if ($vp.Success) { $ctxVhd = $vp.Groups['VhdPath'].Value.Trim() }

            $st = $reStatusSet.Match($msg); if ($st.Success) { $lastStatus = "$($st.Groups['Code'].Value): $($st.Groups['Text'].Value)" }
            $rs = $reReasonSet.Match($msg); if ($rs.Success) { $lastReason = "$($rs.Groups['Code'].Value): $($rs.Groups['Text'].Value)" }
            if ($reOdfcDisabled.IsMatch($msg)) { $odfcDisabledSeen = $true }

            # ---- Profile load / unload duration ----
            $lt = $reLoadTime.Match($msg)
            if ($lt.Success) {
                $logons.Add([PSCustomObject]@{
                    Timestamp  = $ts
                    Computer   = $meta.Computer
                    LogKind    = $meta.LogKind
                    Action     = if ($lt.Groups['Kind'].Value -eq 'load') { 'LoadProfile' } else { 'UnloadProfile' }
                    User       = $ctxUser
                    Sid        = $ctxSid
                    DurationMs = [int]$lt.Groups['Ms'].Value
                    VhdPath    = $ctxVhd
                    FilePath   = $file
                })
                continue
            }

            # ---- Volume re-attach ----
            $rl = $reReattachLock.Match($msg)
            if ($rl.Success) {
                $reattaches.Add([PSCustomObject]@{
                    Timestamp = $ts
                    Computer  = $meta.Computer
                    LogKind   = $meta.LogKind
                    User      = $rl.Groups['User'].Value
                    Sid       = $rl.Groups['Sid'].Value
                    VhdPath   = $null
                    Succeeded = $false
                    Line      = $lineNo
                    FilePath  = $file
                })
                continue
            }
            $ro = $reReattachOk.Match($msg)
            if ($ro.Success -and $reattaches.Count -gt 0) {
                $last = $reattaches[$reattaches.Count - 1]
                $last.Succeeded = $true
                $last.VhdPath   = $ro.Groups['VhdPath'].Value.Trim()
                continue
            }

            # ---- Container fill ----
            $c = $reContainer.Match($msg)
            if ($c.Success) {
                $vhd     = $c.Groups['VhdPath'].Value.Trim()
                $freeMb  = [double]$c.Groups['FreeMB'].Value
                $freePct = [double]$c.Groups['FreePct'].Value
                # Derive the volume size from free MB and free %, then used space.
                # NOTE: this is space INSIDE the mounted volume, which is not the same as
                # the VHDX file size on the share. Compaction records report file size.
                $totalMb = if ($freePct -gt 0) { [math]::Round($freeMb / ($freePct / 100), 2) } else { $null }
                $usedMb  = if ($null -ne $totalMb) { [math]::Round($totalMb - $freeMb, 2) } else { $null }
                $ident   = Get-UserFromVhdPath -VhdPath $vhd

                $containers.Add([PSCustomObject]@{
                    Timestamp       = $ts
                    Computer        = $meta.Computer
                    LogKind         = $meta.LogKind
                    User            = if ($ident.User) { $ident.User } else { $ctxUser }
                    Sid             = if ($ident.Sid)  { $ident.Sid }  else { $ctxSid }
                    VhdPath         = $vhd
                    FreeMB          = $freeMb
                    FreePercent     = $freePct
                    UsedPercent     = [math]::Round(100 - $freePct, 2)
                    ApproxVolumeMB  = $totalMb
                    ApproxUsedMB    = $usedMb
                    NearCapacity    = ((100 - $freePct) -ge $ContainerFullWarnPercent)
                    FilePath        = $file
                })
                continue
            }

            # ---- Compaction ----
            $cr = $reCompactResult.Match($msg)
            if ($cr.Success) {
                $beforeMb = [double]$cr.Groups['BeforeMB'].Value
                $minMb    = [double]$cr.Groups['MinMB'].Value
                $reclaimable = [math]::Round($beforeMb - $minMb, 2)
                $reclaimPct  = if ($beforeMb -gt 0) { [math]::Round(($reclaimable / $beforeMb) * 100, 2) } else { 0 }

                $pendingCompaction = [PSCustomObject]@{
                    Timestamp        = $ts
                    Computer         = $meta.Computer
                    LogKind          = $meta.LogKind
                    User             = $ctxUser
                    Sid              = $ctxSid
                    VhdPath          = $ctxVhd
                    WasCompacted     = [bool]::Parse($cr.Groups['Compacted'].Value)
                    SizeBeforeMB     = $beforeMb
                    SizeAfterMB      = [double]$cr.Groups['AfterMB'].Value
                    MinSupportedMB   = $minMb
                    MaxSupportedMB   = [double]$cr.Groups['MaxMB'].Value
                    SpaceSavedMB     = [double]$cr.Groups['SavedMB'].Value
                    # Reclaimable = current file size minus the smallest size the volume
                    # could shrink to. FSLogix skips compaction when this ratio falls under
                    # its internal threshold, so a non-zero value here with WasCompacted
                    # false means real space is being left on the table.
                    ReclaimableMB    = $reclaimable
                    ReclaimablePct   = $reclaimPct
                    DurationMs       = [int]$cr.Groups['Ms'].Value
                    SkipReason       = $null
                    SkipErrorMessage = $null
                    FilePath         = $file
                }
                $compactions.Add($pendingCompaction)
                continue
            }
            $cs = $reCompactSkip.Match($msg)
            if ($cs.Success -and $null -ne $pendingCompaction) {
                $pendingCompaction.SkipReason       = $cs.Groups['Reason'].Value.Trim()
                $pendingCompaction.SkipErrorMessage = $cs.Groups['ErrorMessage'].Value.Trim()
                $pendingCompaction = $null
                continue
            }

            # ---- Appx ----
            if ($reAppxTimeout.IsMatch($msg)) {
                $problems.Add([PSCustomObject]@{
                    Timestamp = $ts
                    Computer  = $meta.Computer
                    LogKind   = $meta.LogKind
                    Level     = 'NOTICE'
                    Code      = $null
                    Message   = "AppxPackage installation timeout (adds logon delay; user context: $ctxUser)"
                    Line      = $lineNo
                    FilePath  = $file
                })
            }
        }

        $meta.LineCount = $lineNo

        # ---- Unclosed sessions ----
        foreach ($open in $sessionStack) {
            $anomalies.Add([PSCustomObject]@{
                FilePath = $file
                Line     = $open.Line
                Type     = 'UnclosedSession'
                Detail   = "Session '$($open.Name)' began at $($open.Start.ToString('HH:mm:ss')) and never ended (log may be truncated, or the operation is still running)"
            })
        }

        # ---- Time window filter ----
        # Resolve the window to concrete bounds once. Do not reach for
        # $PSBoundParameters from inside a scriptblock invoked with & - in that scope it
        # refers to the scriptblock's own parameters, not the script's.
        $winStart = if ($PSBoundParameters.ContainsKey('StartTime')) { $StartTime } else { [datetime]::MinValue }
        $winEnd   = if ($PSBoundParameters.ContainsKey('EndTime'))   { $EndTime }   else { [datetime]::MaxValue }

        $logonsF      = @($logons      | Where-Object { $_.Timestamp -ge $winStart -and $_.Timestamp -le $winEnd })
        $reattachesF  = @($reattaches  | Where-Object { $_.Timestamp -ge $winStart -and $_.Timestamp -le $winEnd })
        $containersF  = @($containers  | Where-Object { $_.Timestamp -ge $winStart -and $_.Timestamp -le $winEnd })
        $compactionsF = @($compactions | Where-Object { $_.Timestamp -ge $winStart -and $_.Timestamp -le $winEnd })
        $problemsF    = @($problems    | Where-Object { $_.Timestamp -ge $winStart -and $_.Timestamp -le $winEnd })

        # ---- Re-attach loop detection ----
        $loops = New-Object System.Collections.Generic.List[object]
        foreach ($grp in ($reattachesF | Group-Object -Property User)) {
            if ($grp.Count -lt $ReattachLoopThreshold) { continue }

            $times = @($grp.Group | Sort-Object Timestamp | Select-Object -ExpandProperty Timestamp)
            $intervals = @()
            for ($i = 1; $i -lt $times.Count; $i++) {
                $intervals += ($times[$i] - $times[$i - 1]).TotalSeconds
            }

            $median = Get-MedianValue -Value $intervals
            $mean   = if ($intervals.Count) { ($intervals | Measure-Object -Average).Average } else { 0 }
            $sd     = 0.0
            if ($intervals.Count -gt 1) {
                $sumSq = 0.0
                foreach ($v in $intervals) { $sumSq += [math]::Pow($v - $mean, 2) }
                $sd = [math]::Sqrt($sumSq / ($intervals.Count - 1))
            }

            # Cadence regularity is judged with median absolute deviation rather than the
            # standard deviation. Re-attach storms typically open with a few irregular
            # events (the initial failure, a retry, a reconnect) before settling into a
            # fixed interval. Those leading outliers inflate stddev enough to mask an
            # obvious timer, whereas MAD ignores them.
            $absDev = foreach ($v in $intervals) { [math]::Abs($v - $median) }
            $mad    = Get-MedianValue -Value @($absDev)
            $robustCv = if ($median -gt 0) { [math]::Round($mad / $median, 4) } else { 0 }

            # How many intervals sit within 10% of the median - the size of the periodic run.
            $atCadence = 0
            foreach ($v in $intervals) {
                if ($median -gt 0 -and [math]::Abs($v - $median) -le ($median * 0.10)) { $atCadence++ }
            }

            $isRegular = ($intervals.Count -ge 3 -and $robustCv -lt 0.15)

            $loops.Add([PSCustomObject]@{
                Computer          = $meta.Computer
                LogKind           = $meta.LogKind
                User              = $grp.Name
                Count             = $grp.Count
                FirstSeen         = $times[0]
                LastSeen          = $times[-1]
                SpanMinutes       = [math]::Round(($times[-1] - $times[0]).TotalMinutes, 1)
                MedianIntervalSec = [math]::Round($median, 1)
                MeanIntervalSec   = [math]::Round($mean, 1)
                StdDevSec         = [math]::Round($sd, 1)
                MadSec            = [math]::Round($mad, 1)
                RobustCoefVar     = $robustCv
                IntervalsAtCadence= "$atCadence/$($intervals.Count)"
                RegularCadence    = $isRegular
                AllSucceeded      = (-not ($grp.Group | Where-Object { -not $_.Succeeded }))
                VhdPath           = ($grp.Group | Where-Object { $_.VhdPath } | Select-Object -First 1 -ExpandProperty VhdPath)
                Interpretation    = if ($isRegular) {
                        "Regular ~$([math]::Round($median,0))s cadence ($atCadence of $($intervals.Count) intervals within 10% of median). A fixed period points at SMB session loss, a keepalive/idle timeout, or AV interference - not user activity. Correlate against SMBClient connectivity events."
                    } else {
                        "Irregular intervals (median $([math]::Round($median,0))s, MAD $([math]::Round($mad,0))s). More consistent with user-driven reconnects or sporadic network events."
                    }
                FilePath          = $file
            })
        }

        # ---- Findings summary ----
        $findings = New-Object System.Collections.Generic.List[object]
        function Add-Finding {
            param($Severity, $Type, $Detail)
            $findings.Add([PSCustomObject]@{
                Computer = $meta.Computer; LogKind = $meta.LogKind
                Severity = $Severity; Type = $Type; Detail = $Detail; FilePath = $file
            })
        }

        foreach ($l in $loops) {
            Add-Finding 'High' 'ReattachLoop' ("$($l.User): $($l.Count) volume re-attaches over $($l.SpanMinutes) min, median interval $($l.MedianIntervalSec)s. $($l.Interpretation)")
        }
        foreach ($c in ($containersF | Where-Object NearCapacity | Sort-Object UsedPercent -Descending)) {
            Add-Finding 'Medium' 'ContainerNearCapacity' ("$($c.User): container $($c.UsedPercent)% used ($($c.ApproxUsedMB) MB of ~$($c.ApproxVolumeMB) MB)")
        }
        foreach ($k in ($compactionsF | Where-Object { -not $_.WasCompacted -and $_.ReclaimableMB -gt 0 })) {
            Add-Finding 'Low' 'CompactionSkipped' ("$($k.User): $($k.ReclaimableMB) MB ($($k.ReclaimablePct)%) reclaimable but skipped. Reason: $($k.SkipReason)")
        }
        $errCount = @($problemsF | Where-Object { $_.Level -like 'ERROR*' }).Count
        if ($errCount -gt 0) { Add-Finding 'High' 'LoggedErrors' "$errCount ERROR entries present - inspect the Problems collection" }
        if ($odfcDisabledSeen) {
            Add-Finding 'Info' 'OdfcDisabled' 'ODFC (Office container) is disabled - Outlook OST/cache data is stored inside the profile container, which inflates profile size'
        }
        foreach ($a in ($anomalies | Group-Object Type)) {
            Add-Finding 'Info' $a.Name "$($a.Count) occurrence(s) - see Anomalies collection"
        }

        $result = [PSCustomObject]([ordered]@{
            FilePath        = $meta.FilePath
            FileName        = $meta.FileName
            LogKind         = $meta.LogKind
            Computer        = $meta.Computer
            FSLogixVersion  = $meta.FSLogixVersion
            OsBuild         = $meta.OsBuild
            OsName          = $meta.OsName
            RamMB           = $meta.RamMB
            LogDate         = $meta.LogDate
            HeaderCreated   = $meta.HeaderCreated
            HeaderUtcOffset = $meta.HeaderUtcOffset
            LineCount       = $meta.LineCount
            EntriesParsed   = $meta.ParsedCount
            Findings        = $findings
            ReattachLoops   = $loops
            Logons          = $logonsF
            Reattaches      = $reattachesF
            Containers      = $containersF
            Compactions     = $compactionsF
            Problems        = $problemsF
            Sessions        = $sessions
            Anomalies       = $anomalies
        })

        $allResults.Add($result)
        $result
    }
}

end {
    if ($allResults.Count -eq 0) { return }

    #region Export
    if ($ExportPath) {
        if (-not (Test-Path -LiteralPath $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        $collections = @('Findings', 'ReattachLoops', 'Logons', 'Reattaches',
                         'Containers', 'Compactions', 'Problems', 'Sessions', 'Anomalies')
        foreach ($key in $collections) {
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($r in $allResults) {
                foreach ($row in $r.$key) {
                    if ($null -ne $row) { $rows.Add($row) }
                }
            }
            if ($rows.Count -gt 0) {
                $csv = Join-Path $ExportPath "$key.csv"
                $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
                Write-Verbose "Wrote $($rows.Count) row(s) to $csv"
            }
        }
        Write-Host "CSV export complete: $ExportPath" -ForegroundColor Green
    }
    #endregion

    #region Report
    if ($Report) {
        Write-Host ''
        Write-Host ('=' * 78)
        Write-Host ' FSLogix Log Triage Summary' -ForegroundColor Cyan
        Write-Host ('=' * 78)

        foreach ($r in $allResults) {
            Write-Host ''
            Write-Host ("{0}  [{1}]" -f $r.FileName, $r.LogKind) -ForegroundColor White
            Write-Host ("  Host: {0}   FSLogix: {1}   OS: {2} ({3})" -f `
                $r.Computer, $r.FSLogixVersion, $r.OsBuild, $r.OsName)
            Write-Host ("  Entries parsed: {0} of {1} lines   Log date: {2}   Header TZ: {3}" -f `
                $r.EntriesParsed, $r.LineCount, $r.LogDate.ToString('yyyy-MM-dd'), $r.HeaderUtcOffset)

            if ($r.Logons.Count -gt 0) {
                $loadStats = $r.Logons | Where-Object Action -eq 'LoadProfile' | Measure-Object DurationMs -Average -Maximum
                Write-Host ("  Profile loads: {0}   avg {1} ms   max {2} ms" -f `
                    $loadStats.Count, [int]$loadStats.Average, [int]$loadStats.Maximum)
            }

            if ($r.Findings.Count -eq 0) {
                Write-Host '  No findings.' -ForegroundColor Green
            }
            else {
                foreach ($sev in @('High', 'Medium', 'Low', 'Info')) {
                    foreach ($f in ($r.Findings | Where-Object Severity -eq $sev)) {
                        $colour = switch ($sev) {
                            'High'   { 'Red' }
                            'Medium' { 'Yellow' }
                            'Low'    { 'DarkYellow' }
                            default  { 'Gray' }
                        }
                        Write-Host ("  [{0,-6}] {1}: {2}" -f $sev, $f.Type, $f.Detail) -ForegroundColor $colour
                    }
                }
            }
        }

        Write-Host ''
        Write-Host ('-' * 78)
        Write-Host ' Container fill (highest first)' -ForegroundColor Cyan
        $allC = foreach ($r in $allResults) { $r.Containers }
        $allC = @($allC | Where-Object { $null -ne $_ })
        if ($allC.Count -gt 0) {
            $allC | Sort-Object UsedPercent -Descending |
                Select-Object -First 20 User, UsedPercent, ApproxUsedMB, ApproxVolumeMB, Computer |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        }
        else { Write-Host ' (none recorded)' }

        $allL = foreach ($r in $allResults) { $r.ReattachLoops }
        $allL = @($allL | Where-Object { $null -ne $_ })
        if ($allL.Count -gt 0) {
            Write-Host ('-' * 78)
            Write-Host ' Re-attach loops' -ForegroundColor Cyan
            $allL | Sort-Object Count -Descending |
                Select-Object User, Count, SpanMinutes, MedianIntervalSec, MadSec, IntervalsAtCadence, RegularCadence, Computer |
                Format-Table -AutoSize | Out-String -Width 220 | Write-Host
            Write-Host ' Next step: feed the timestamps into Get-FSLogixStorageEvents.ps1 -CorrelateWith' -ForegroundColor Gray
        }
        Write-Host ('=' * 78)
        Write-Host ''
    }
    #endregion
}
