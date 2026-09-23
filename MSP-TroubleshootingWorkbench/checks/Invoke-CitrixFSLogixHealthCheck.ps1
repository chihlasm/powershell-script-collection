#Requires -Version 5.1

<#
.SYNOPSIS
    Runs the Citrix / FSLogix fleet health collector as a workbench check.

.DESCRIPTION
    Wraps Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1 for the MSP
    Troubleshooting Workbench and returns the shared normalized check result object.

    Accepts one or more servers. Because the workbench passes a single free-text value for
    affectedDevice, a comma- or semicolon-separated list is split here, so a technician can
    type "CTXVDA01, CTXVDA02, FS01" into the one box the UI gives them.

    The collector is invoked in-process rather than as a child process: it returns objects
    directly and needs no module import, so there is nothing to gain from the extra hop.

    Preflight gaps - a missing collector script, or an unwritable output folder - return
    Warn rather than throwing, matching the other bundled checks.

.PARAMETER AffectedDevice
    Server or servers to check. Separate multiple names with commas or semicolons.
    Defaults to the local computer.

.PARAMETER DaysBack
    Days of event history to collect. Defaults to 1.

.PARAMETER SampleSeconds
    Length of the performance sampling window per server. Defaults to 15 to keep the check
    responsive inside the workbench timeout. Set 0 for a single instantaneous reading.

.EXAMPLE
    .\Invoke-CitrixFSLogixHealthCheck.ps1 -AffectedDevice CTXVDA01 -DaysBack 1

.EXAMPLE
    .\Invoke-CitrixFSLogixHealthCheck.ps1 -AffectedDevice "CTXVDA01, CTXVDA02, FS01" -DaysBack 3

.NOTES
    Read-only. Returns the shared MSP Troubleshooting Workbench check result object.
    Performance needs WinRM or DCOM to the target; events need the Remote Event Log
    Management firewall rule. Either can fail independently and the check still reports
    whatever it did collect.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$AffectedDevice = $env:COMPUTERNAME,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 1,

    [ValidateRange(0, 3600)]
    [int]$SampleSeconds = 15
)

function New-EvidenceItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet("Pass", "Warn", "Fail")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Detail
    )

    [PSCustomObject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
    }
}

function New-HealthCheckResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Pass", "Warn", "Fail")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Summary,

        [object[]]$Evidence = @(),

        [string[]]$RecommendedNextSteps = @(),

        [object]$RawOutput,

        [string]$StartedAt,

        [string]$ErrorText = ""
    )

    [PSCustomObject]@{
        CheckId              = "citrix.fslogix.health"
        Name                 = "Citrix/FSLogix Fleet Health"
        Category             = "Citrix"
        Status               = $Status
        Summary              = $Summary
        Evidence             = @($Evidence)
        RecommendedNextSteps = @($RecommendedNextSteps)
        RawOutput            = $RawOutput
        StartedAt            = $StartedAt
        FinishedAt           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error                = $ErrorText
    }
}

function Split-DeviceList {
    <#
    .SYNOPSIS
        Splits the workbench's single free-text device value into a list of server names.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }

    return @($Value -split '[,;]' |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$startedAt     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$workbenchRoot = Split-Path -Parent $PSScriptRoot
$repoRoot      = Split-Path -Parent $workbenchRoot
$collector     = Join-Path $repoRoot "Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1"
$stamp         = Get-Date -Format "yyyy-MM-dd_HHmmss"
$outputPath    = Join-Path $workbenchRoot ("output\checks\citrix.fslogix.health\{0}" -f $stamp)

$devices = Split-DeviceList -Value $AffectedDevice
if ($devices.Count -eq 0) { $devices = @($env:COMPUTERNAME) }

$rawOutput = [ordered]@{
    Devices           = @($devices)
    DaysBack          = $DaysBack
    SampleSeconds     = $SampleSeconds
    CollectorPath     = $collector
    OutputPath        = $outputPath
    ReportPath        = $null
    Hosts             = @()
    HealthyCount      = 0
    DegradedCount     = 0
    CriticalCount     = 0
    UnreachableCount  = 0
    ConsoleOutput     = @()
}

if (-not (Test-Path -LiteralPath $collector -PathType Leaf)) {
    return New-HealthCheckResult -Status "Warn" `
        -Summary "The Citrix/FSLogix health collector script was not found." `
        -Evidence @(New-EvidenceItem -Name "Preflight" -Status "Warn" -Detail "Missing script: $collector") `
        -RecommendedNextSteps @("Confirm Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1 exists in the repository.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
}

try {
    if (-not (Test-Path -LiteralPath $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force -ErrorAction Stop | Out-Null
    }

    # -NoOpen matters: the workbench runs checks in a background job, where launching a
    # browser would either fail or pop a window on the technician's desktop mid-check.
    $results = @(& $collector `
        -ComputerName $devices `
        -LastDays $DaysBack `
        -SampleSeconds $SampleSeconds `
        -OutputPath $outputPath `
        -NoOpen)

    $report = @(Get-ChildItem -LiteralPath $outputPath -Filter "CitrixFSLogixHealth_*.html" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1)
    if ($report.Count -gt 0) { $rawOutput.ReportPath = $report[0].FullName }

    if ($results.Count -eq 0) {
        return New-HealthCheckResult -Status "Warn" `
            -Summary "The health collector returned no machines." `
            -Evidence @(New-EvidenceItem -Name "Collection" -Status "Warn" -Detail "No results were produced for: $($devices -join ', ')") `
            -RecommendedNextSteps @("Confirm the server names are correct and reachable from this workstation.") `
            -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
    }

    $healthy     = @($results | Where-Object { $_.Verdict -eq 'Healthy'     }).Count
    $degraded    = @($results | Where-Object { $_.Verdict -eq 'Degraded'    }).Count
    $critical    = @($results | Where-Object { $_.Verdict -eq 'Critical'    }).Count
    $unreachable = @($results | Where-Object { $_.Verdict -eq 'Unreachable' }).Count

    $rawOutput.HealthyCount     = $healthy
    $rawOutput.DegradedCount    = $degraded
    $rawOutput.CriticalCount    = $critical
    $rawOutput.UnreachableCount = $unreachable
    $rawOutput.Hosts = @($results | Select-Object ComputerName, Verdict, CpuAveragePercent, CpuPeakPercent,
        MemoryAveragePercent, MaxDiskUsedPercent, CriticalEvents, ErrorEvents, WarningEvents, TopIssue, Reasons)

    # One evidence line per machine, so the generated ticket notes name the machine and the
    # reason together rather than making the reader open the HTML to find out what is wrong.
    $evidence = @()
    foreach ($r in ($results | Sort-Object ComputerName)) {
        $status = switch ($r.Verdict) {
            'Healthy'  { 'Pass' }
            'Degraded' { 'Warn' }
            default    { 'Fail' }
        }
        $evidence += New-EvidenceItem -Name $r.ComputerName -Status $status -Detail ("{0} - {1}" -f $r.Verdict, $r.Reasons)
    }

    if ($rawOutput.ReportPath) {
        $evidence += New-EvidenceItem -Name "HTML report" -Status "Pass" -Detail $rawOutput.ReportPath
    }

    $summary = "Checked {0} machine(s): {1} healthy, {2} need attention, {3} with serious problems, {4} unreachable." -f `
        $results.Count, $healthy, $degraded, $critical, $unreachable

    $nextSteps = @()
    if ($critical -gt 0) {
        $nextSteps += "Start with the machines marked Critical - they have either a resource at its limit or critical events logged."
    }
    if ($degraded -gt 0) {
        $nextSteps += "Review the Degraded machines before they reach their limits."
    }
    if ($unreachable -gt 0) {
        $nextSteps += "For unreachable machines, confirm the server is up and that WinRM or the Remote Event Log Management firewall rule is enabled."
    }
    if ($rawOutput.ReportPath) {
        $nextSteps += "Open the HTML report for the per-machine detail and the fleet-wide list of most common problems."
    }
    if ($nextSteps.Count -eq 0) {
        $nextSteps += "No action needed - resource use and event history are within thresholds on every machine checked."
    }

    $status = 'Pass'
    if ($degraded -gt 0) { $status = 'Warn' }
    if ($critical -gt 0 -or $unreachable -gt 0) { $status = 'Fail' }

    return New-HealthCheckResult -Status $status -Summary $summary `
        -Evidence $evidence -RecommendedNextSteps $nextSteps `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
}
catch {
    $rawOutput.ConsoleOutput = @($_.Exception.Message)
    return New-HealthCheckResult -Status "Fail" `
        -Summary "The Citrix/FSLogix health check failed before it could complete." `
        -Evidence @(New-EvidenceItem -Name "Wrapper" -Status "Fail" -Detail $_.Exception.Message) `
        -RecommendedNextSteps @("Review the error, confirm the server names, and check that the output folder is writable.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt -ErrorText $_.Exception.Message
}
