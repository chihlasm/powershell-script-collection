#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DiskSpd Diagnostic Tool — on-demand storage triage using Microsoft diskspd.exe.

.DESCRIPTION
    Wraps diskspd.exe with a WPF GUI for fast, authoritative storage benchmarks.
    Supports three targeting modes:
      1. Local disk on this machine
      2. UNC path from this machine
      3. Run diskspd ON a remote VDA, targeting a path from that VDA
    Preset workload profiles model FSLogix-like, sequential read, mixed user load,
    and quick-sanity workloads, with override fields for power users.
    Produces a styled HTML report with health assessments.

.PARAMETER Target
    Path or UNC for the storage to test. Required when -NoUI is set.

.PARAMETER ComputerName
    Optional. If set, diskspd runs on this remote VDA targeting -Target from there.

.PARAMETER Workload
    Workload profile: FSLogixLike, SequentialRead, MixedUserLoad, QuickSanity, Custom.

.PARAMETER BlockSize
    Block size override (e.g., 4K, 64K). Required with -Workload Custom.

.PARAMETER Threads
    Thread count override. Required with -Workload Custom.

.PARAMETER QueueDepth
    Outstanding I/Os per thread. Required with -Workload Custom.

.PARAMETER WriteRatioPercent
    Percentage of writes (0-100). Required with -Workload Custom.

.PARAMETER DurationSeconds
    Test duration in seconds. Required with -Workload Custom.

.PARAMETER TestFileSizeMB
    Test file size in MB. Required with -Workload Custom.

.PARAMETER NoUI
    Run in headless mode. Requires -Target.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to the script folder so reports land
    predictably even under -RunAsAdministrator with a different admin account.

.PARAMETER Force
    Bypass business-hours confirmation.

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' -Workload FSLogixLike

.NOTES
    Requires diskspd.exe (bundled) next to this script.
    Must run as Administrator. WPF requires the in-box PresentationFramework assembly.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Target,

    [Parameter()]
    [string]$ComputerName,

    [Parameter()]
    [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
    [string]$Workload = 'FSLogixLike',

    [Parameter()]
    [ValidatePattern('^\d+[KMG]?$')]
    [string]$BlockSize,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$Threads,

    [Parameter()]
    [ValidateRange(1, 256)]
    [int]$QueueDepth,

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$WriteRatioPercent,

    [Parameter()]
    [ValidateRange(5, 3600)]
    [int]$DurationSeconds,

    [Parameter()]
    [ValidateRange(64, 102400)]
    [int]$TestFileSizeMB,

    [Parameter()]
    [switch]$NoUI,

    [Parameter()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = $PSScriptRoot
$script:DiskSpdExe  = Join-Path $script:ScriptRoot 'diskspd.exe'
$script:ReportTpl   = Join-Path $script:ScriptRoot 'ReportTemplate.html'

# Single source of truth for the workload-settings hashtable contract.
# Every preset in Get-DiskSpdWorkloadProfile, every -Overrides hashtable on
# Resolve-DiskSpdSettings, and every $Settings hashtable on Build-DiskSpdArguments
# must contain exactly these keys.
$script:DiskSpdRequiredKeys = @('BlockSize','Threads','QueueDepth','WriteRatioPercent',
                                'DurationSeconds','TestFileSizeMB','RandomIO')

# --- Engine functions go here (Tasks 1-9) ---

# Returns hashtable (not PSCustomObject) so callers can merge operator overrides.
function Get-DiskSpdWorkloadProfile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
        [string]$Name
    )

    switch ($Name) {
        'FSLogixLike' {
            @{
                BlockSize         = '4K'
                Threads           = 4
                QueueDepth        = 8
                WriteRatioPercent = 30
                DurationSeconds   = 30
                TestFileSizeMB    = 1024
                RandomIO          = $true
            }
        }
        'SequentialRead' {
            @{
                BlockSize         = '64K'
                Threads           = 1
                QueueDepth        = 4
                WriteRatioPercent = 0
                DurationSeconds   = 30
                TestFileSizeMB    = 1024
                RandomIO          = $false
            }
        }
        'MixedUserLoad' {
            @{
                BlockSize         = '8K'
                Threads           = 2
                QueueDepth        = 4
                WriteRatioPercent = 20
                DurationSeconds   = 60
                TestFileSizeMB    = 1024
                RandomIO          = $true
            }
        }
        'QuickSanity' {
            @{
                BlockSize         = '64K'
                Threads           = 1
                QueueDepth        = 2
                WriteRatioPercent = 0
                DurationSeconds   = 10
                TestFileSizeMB    = 256
                RandomIO          = $true
            }
        }
        'Custom' { $null }
        default  { throw "Unhandled workload profile: $Name" }
    }
}

function Resolve-DiskSpdSettings {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
        [string]$ProfileName,

        [Parameter(Mandatory)]
        [hashtable]$Overrides
    )

    # Reject typos like @{ Treads = 16 } before they silently drop the intended override.
    $unknown = $Overrides.Keys | Where-Object { $_ -notin $script:DiskSpdRequiredKeys }
    if ($unknown) {
        throw "Unknown override key(s): $($unknown -join ', '). Expected one of: $($script:DiskSpdRequiredKeys -join ', ')"
    }

    if ($ProfileName -eq 'Custom') {
        $missing = $script:DiskSpdRequiredKeys | Where-Object { -not $Overrides.ContainsKey($_) }
        if ($missing) {
            throw "Profile 'Custom' requires all override keys. Missing: $($missing -join ', ')"
        }
        # Shallow clone is sufficient: all values are primitives (string/int/bool).
        return [hashtable]$Overrides.Clone()
    }

    $settings = Get-DiskSpdWorkloadProfile -Name $ProfileName
    foreach ($key in $Overrides.Keys) {
        $settings[$key] = $Overrides[$key]
    }
    return $settings
}

function Build-DiskSpdArguments {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    # Catch malformed settings at the boundary so diskspd doesn't get -t with no value.
    $missing = $script:DiskSpdRequiredKeys | Where-Object { -not $Settings.ContainsKey($_) }
    if ($missing) {
        throw "Build-DiskSpdArguments: Settings hashtable is missing required key(s): $($missing -join ', ')"
    }

    # Size suffix: use G for whole-GB sizes (>= 1024 MB and evenly divisible), M otherwise.
    # Explicit [int] cast so future readers don't wonder whether "1024/1024" produces "1" or "1.0".
    $size = if ($Settings.TestFileSizeMB -ge 1024 -and ($Settings.TestFileSizeMB % 1024) -eq 0) {
        "$([int]($Settings.TestFileSizeMB / 1024))G"
    } else {
        "$($Settings.TestFileSizeMB)M"
    }

    $argv = @(
        "-b$($Settings.BlockSize)"
        "-t$($Settings.Threads)"
        "-o$($Settings.QueueDepth)"
        "-w$($Settings.WriteRatioPercent)"
        "-d$($Settings.DurationSeconds)"
        "-c$size"
        '-Rxml'
        '-L'
        '-Sh'
    )
    if ($Settings.RandomIO) { $argv += '-r' }
    $argv += $TestFilePath
    return $argv
}

function ConvertFrom-DiskSpdXml {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]$Xml,
        [Parameter(Mandatory)] [string]$ProfileName
    )

    try {
        [xml]$doc = $Xml
    } catch {
        throw "Failed to parse diskspd XML output: $($_.Exception.Message)"
    }

    $timeSpan = $doc.Results.TimeSpan
    if (-not $timeSpan) { throw "diskspd XML missing <TimeSpan> - output may be a partial run." }

    $durationSec = [double]$timeSpan.TestTimeSeconds
    if ($durationSec -le 0) { throw "diskspd XML reports zero duration - test did not run." }

    # Force array semantics: PowerShell XML returns a single element (not a 1-element array)
    # when there's only one Thread, so @(...) ensures the sum/aggregate pipeline works in both
    # single-thread and multi-thread cases.
    $threads = @($timeSpan.Thread)
    $readBytes  = ($threads | ForEach-Object { [int64]$_.Target.ReadBytes  } | Measure-Object -Sum).Sum
    $writeBytes = ($threads | ForEach-Object { [int64]$_.Target.WriteBytes } | Measure-Object -Sum).Sum
    $readCount  = ($threads | ForEach-Object { [int64]$_.Target.ReadCount  } | Measure-Object -Sum).Sum
    $writeCount = ($threads | ForEach-Object { [int64]$_.Target.WriteCount } | Measure-Object -Sum).Sum
    $testFile   = $threads[0].Target.Path

    $readMBps   = [math]::Round($readBytes  / 1MB / $durationSec, 2)
    $writeMBps  = [math]::Round($writeBytes / 1MB / $durationSec, 2)
    $iops       = [math]::Round(($readCount + $writeCount) / $durationSec, 0)

    # Average latency: prefer AverageTotalMilliseconds (combined R+W average from diskspd v2.2).
    # Fall back to Read-only or Write-only averages depending on what the test contained.
    # The Write fallback matters for 100%-write workloads (FSLogix profile creation, OLTP)
    # on older diskspd builds that don't emit AverageTotalMilliseconds.
    $avgMs = if ($timeSpan.Latency.AverageTotalMilliseconds) {
        [double]$timeSpan.Latency.AverageTotalMilliseconds
    } elseif ($timeSpan.Latency.AverageReadMilliseconds) {
        [double]$timeSpan.Latency.AverageReadMilliseconds
    } elseif ($timeSpan.Latency.AverageWriteMilliseconds) {
        [double]$timeSpan.Latency.AverageWriteMilliseconds
    } else { 0 }

    # Bucket lookup: TotalMilliseconds is the combined R+W percentile latency.
    # Falls back to Read- or Write-only latency for pure-read / pure-write workloads.
    # The integer-percentile comparison is safe: 95 and 99 parse to exact doubles
    # (would NOT be safe for fractional buckets like 99.9).
    function Get-BucketLatency([object]$buckets, [int]$percentile) {
        $b = $buckets | Where-Object { [double]$_.Percentile -eq $percentile } | Select-Object -First 1
        if (-not $b) { return $null }
        if ($b.TotalMilliseconds) { return [double]$b.TotalMilliseconds }
        if ($b.ReadMilliseconds)  { return [double]$b.ReadMilliseconds }
        if ($b.WriteMilliseconds) { return [double]$b.WriteMilliseconds }
        return $null
    }

    $buckets = @($timeSpan.Latency.Bucket)
    $p95 = Get-BucketLatency -buckets $buckets -percentile 95
    $p99 = Get-BucketLatency -buckets $buckets -percentile 99
    if ($null -eq $p95) { $p95 = $avgMs }
    if ($null -eq $p99) { $p99 = $p95   }

    $cpu = [double]$timeSpan.CpuUtilization.Average.UsagePercent

    [PSCustomObject]@{
        IOPS         = [int]$iops
        ReadMBps     = $readMBps
        WriteMBps    = $writeMBps
        AvgLatencyMs = [math]::Round($avgMs, 3)
        Latency95Ms  = [math]::Round([double]$p95, 3)
        Latency99Ms  = [math]::Round([double]$p99, 3)
        CpuPercent   = [math]::Round($cpu, 2)
        TestFilePath = $testFile
        Duration     = $durationSec
        ProfileName  = $ProfileName
        RawXml       = $Xml
    }
}

function Get-DiskSpdHealthAssessment {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [PSCustomObject]$Result,
        [Parameter(Mandatory)] [ValidateSet('Local','Network')] [string]$Transport
    )

    # Threshold source of truth: CitrixVDADiagnostics/README.md. Keep these in sync
    # so the new diagnostic's color-coding matches the existing FSLogix tooling.
    # WARN band is inclusive on both edges (50/100 MB/s land in WARN, 10/20ms land
    # in WARN) — pinned by the boundary tests in Tests/DiskSpdDiagnostic.Tests.ps1.
    $thresholds = if ($Transport -eq 'Local') {
        @{
            ReadOK = 100; ReadWarn = 50
            WriteOK = 100; WriteWarn = 50
            LatencyOK = 10; LatencyWarn = 20
        }
    } else {
        @{
            ReadOK = 50; ReadWarn = 25
            WriteOK = 40; WriteWarn = 20
            LatencyOK = 20; LatencyWarn = 50
        }
    }

    # Throughput: higher is better, so > OK is OK, >= Warn is WARN, else CRIT.
    # Latency: lower is better, so < OK is OK, <= Warn is WARN, else CRIT.
    function Classify-Throughput($v, $ok, $warn) {
        if ($v -gt $ok)       { 'OK' }
        elseif ($v -ge $warn) { 'WARN' }
        else                  { 'CRIT' }
    }
    function Classify-Latency($v, $ok, $warn) {
        if ($v -lt $ok)       { 'OK' }
        elseif ($v -le $warn) { 'WARN' }
        else                  { 'CRIT' }
    }

    # P95/P99 are classified with the same latency thresholds as average. P95 in
    # particular is more operationally relevant than mean for storage triage,
    # so the HTML report (Task 10) colors all three latency rows.
    # NOTE: local var is $out (NOT $result) because PowerShell is case-insensitive
    # and $result would silently shadow the $Result parameter — meaning the
    # subsequent $Result.Latency95Ms reads would target our empty hashtable instead.
    $out = @{
        ReadMBps     = Classify-Throughput $Result.ReadMBps     $thresholds.ReadOK    $thresholds.ReadWarn
        WriteMBps    = Classify-Throughput $Result.WriteMBps    $thresholds.WriteOK   $thresholds.WriteWarn
        AvgLatencyMs = Classify-Latency    $Result.AvgLatencyMs $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    if ($null -ne $Result.Latency95Ms) {
        $out.Latency95Ms = Classify-Latency $Result.Latency95Ms $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    if ($null -ne $Result.Latency99Ms) {
        $out.Latency99Ms = Classify-Latency $Result.Latency99Ms $thresholds.LatencyOK $thresholds.LatencyWarn
    }
    $out
}

# Returns [PSCustomObject] (not hashtable) because the result is consumer-facing —
# the WPF UI binds Errors/Warnings to modal dialogs and the headless orchestrator
# logs them by name. Keep the field names (Pass, Errors, Warnings) stable.
#
# NOTE: signature-warning branches (bad Authenticode status / non-Microsoft signer
# / read-failure) are not unit-tested — a fixture exe with each signature state
# is more setup cost than the ~5 lines of logic justify. They are exercised
# manually when the bundled binary is updated.
#
# NOTE: UNC targets ('\\server\share\...') can make Test-Path / Get-Item block
# for the full SMB timeout (~30s) when the server is unreachable. The WPF UI
# (Task 13) runs preflight on a background runspace to avoid hanging the
# dispatcher — don't call this synchronously from a UI-thread event handler.
function Test-DiskSpdPreflight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)] [string]$DiskSpdPath,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [int]   $TestFileSizeMB,
        [string]    $ComputerName,
        [switch]    $BusinessHoursForce,
        [datetime]  $BusinessHoursNow = (Get-Date)
    )

    $errors   = @()
    $warnings = @()

    # 1. Binary present + Microsoft-signed.
    # A missing binary is an ERROR (we cannot proceed). A bad signature is a WARNING
    # (operator can still proceed knowingly — useful for offline lab environments).
    if (-not (Test-Path $DiskSpdPath)) {
        $errors += "diskspd.exe not found at: $DiskSpdPath"
    } else {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $DiskSpdPath -ErrorAction Stop
            if ($sig.Status -ne 'Valid') {
                $warnings += "diskspd.exe Authenticode status is '$($sig.Status)'."
            } elseif ($sig.SignerCertificate.Subject -notmatch 'Microsoft') {
                $warnings += "diskspd.exe is signed but not by Microsoft: $($sig.SignerCertificate.Subject)"
            }
        } catch {
            $warnings += "Could not verify diskspd.exe signature: $($_.Exception.Message)"
        }
    }

    # 2-3. Target reachable + writable + free space (local-mode only).
    # When -ComputerName is set, the target lives on the remote machine — we skip these
    # checks here and rely on the remote-mode admin-share check + the actual remote run.
    if (-not $ComputerName) {
        if ([string]::IsNullOrWhiteSpace($Target)) {
            $errors += "Target is empty or whitespace."
        } elseif (-not (Test-Path $Target)) {
            $errors += "Target not reachable: $Target"
        } else {
            $probe = Join-Path $Target "diskspd-preflight-$([guid]::NewGuid()).tmp"
            try {
                [IO.File]::WriteAllBytes($probe, [byte[]]@(0))
                Remove-Item $probe -Force -ErrorAction Stop
            } catch {
                $errors += "Target not writable: $Target - $($_.Exception.Message)"
            }

            # Free space check. UNC shares often don't expose PSDrive.Free reliably;
            # in that case we surface a WARNING (not an error) so the operator decides.
            try {
                $root  = (Resolve-Path $Target -ErrorAction Stop).ProviderPath
                $drive = (Get-Item $root).PSDrive
                if ($drive -and $drive.Free) {
                    $neededBytes = $TestFileSizeMB * 1.2MB
                    if ($drive.Free -lt $neededBytes) {
                        $errors += ("Insufficient free space at {0}: have {1:N0} MB, need {2:N0} MB (file size x1.2)." -f
                                    $Target, ($drive.Free/1MB), ($neededBytes/1MB))
                    }
                } else {
                    $warnings += "Could not determine free space at $Target (UNC share or unmapped drive)."
                }
            } catch {
                $warnings += "Could not check free space at ${Target}: $($_.Exception.Message)"
            }
        }
    }

    # 4. Remote reachability (only in remote mode).
    # Test-WSMan can throw on DNS failure, or return $null when -ErrorAction Stop
    # doesn't catch (varies by Windows build). Handle both by tracking the outcome
    # explicitly, then also probe the admin share as a separate check.
    if ($ComputerName) {
        $wsManReachable = $false
        try {
            $wsManResult = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
            if ($wsManResult) { $wsManReachable = $true }
        } catch {
            $errors += "Test-WSMan failed for ${ComputerName}: $($_.Exception.Message)"
        }
        if (-not $wsManReachable -and -not ($errors -match 'Test-WSMan')) {
            $errors += "Test-WSMan failed for ${ComputerName}: no response (host unreachable or WinRM not listening)"
        }
        $admin = "\\$ComputerName\C`$\Windows\Temp"
        if (-not (Test-Path $admin)) {
            $errors += "Admin share not accessible: $admin"
        }
    }

    # 5. Business hours warning. 7am-6pm Mon-Fri local time.
    # Upper bound is EXCLUSIVE: 7:00 warns, 18:00 does not (lunchtime to end-of-day).
    $isBusinessHours = ($BusinessHoursNow.DayOfWeek -in @('Monday','Tuesday','Wednesday','Thursday','Friday')) `
                       -and ($BusinessHoursNow.Hour -ge 7 -and $BusinessHoursNow.Hour -lt 18)
    if ($isBusinessHours -and -not $BusinessHoursForce) {
        $warnings += "Running during business hours ($($BusinessHoursNow.ToString('yyyy-MM-dd HH:mm:ss'))). Sustained I/O may affect users."
    }

    [PSCustomObject]@{
        Pass     = ($errors.Count -eq 0)
        Errors   = $errors
        Warnings = $warnings
    }
}

function Invoke-DiskSpdLocal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]   $DiskSpdPath,
        [Parameter(Mandatory)] [hashtable]$Settings,
        [Parameter(Mandatory)] [string]   $TestFilePath
    )

    $argv = Build-DiskSpdArguments -Settings $Settings -TestFilePath $TestFilePath

    # Capture stdout and stderr to temp files because Start-Process can't return them
    # as strings directly — it returns a Process object and requires -RedirectStandard*.
    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()

    try {
        $proc = Start-Process -FilePath $DiskSpdPath -ArgumentList $argv -NoNewWindow -PassThru `
                              -RedirectStandardOutput $stdoutFile `
                              -RedirectStandardError  $stderrFile -Wait

        $stdout = Get-Content $stdoutFile -Raw
        $stderr = Get-Content $stderrFile -Raw

        if ($proc.ExitCode -ne 0) {
            throw "diskspd exited with code $($proc.ExitCode). stderr: $stderr"
        }
        if ([string]::IsNullOrWhiteSpace($stdout) -or $stdout -notmatch '<Results>') {
            throw "diskspd produced no XML output. stderr: $stderr"
        }
        return $stdout
    } finally {
        # Cleanup regardless of success/failure. -ErrorAction SilentlyContinue
        # because Remove-Item on an already-deleted file shouldn't mask the original error.
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
        Remove-Item $TestFilePath           -Force -ErrorAction SilentlyContinue
    }
}

# --- UI / headless dispatch goes here (Tasks 10-11) ---

# Entry-point dispatch (filled in Task 12):
# if ($NoUI) { Invoke-DiskSpdHeadless ... } else { Show-DiskSpdGui }
