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

    @{
        ReadMBps     = Classify-Throughput $Result.ReadMBps     $thresholds.ReadOK    $thresholds.ReadWarn
        WriteMBps    = Classify-Throughput $Result.WriteMBps    $thresholds.WriteOK   $thresholds.WriteWarn
        AvgLatencyMs = Classify-Latency    $Result.AvgLatencyMs $thresholds.LatencyOK $thresholds.LatencyWarn
    }
}

# --- UI / headless dispatch goes here (Tasks 10-11) ---

# Entry-point dispatch (filled in Task 12):
# if ($NoUI) { Invoke-DiskSpdHeadless ... } else { Show-DiskSpdGui }
