#Requires -Version 5.1

<#
.SYNOPSIS
    Runs the Active Directory account lockout diagnostics check.

.DESCRIPTION
    Wraps AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1 for the MSP
    Troubleshooting Workbench and returns the shared normalized check result
    object. Preflight failures such as a missing diagnostics script or missing
    ActiveDirectory module return Warn instead of throwing.

.PARAMETER AffectedUser
    SamAccountName, UPN, or distinguished name of the account to investigate.

.PARAMETER DaysBack
    Number of days of Security event logs to search. Defaults to 7.

.PARAMETER DomainController
    Optional domain controller name or names to query instead of auto-discovery.

.EXAMPLE
    .\Invoke-ADLockoutCheck.ps1 -AffectedUser jdoe -DaysBack 14

.EXAMPLE
    .\Invoke-ADLockoutCheck.ps1 -AffectedUser jdoe -DaysBack 7 -DomainController DC01

.NOTES
    Requires RSAT ActiveDirectory module and permission to read DC Security logs
    for a full domain run. Returns Warn for local preflight gaps.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$AffectedUser,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string[]]$DomainController
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

function New-ADLockoutResult {
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
        CheckId              = "ad.lockout"
        Name                 = "AD Lockout Diagnostics"
        Category             = "Active Directory"
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

function ConvertTo-CommandLineArgument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return ('"{0}"' -f ($Value.Replace('"', '\"')))
}

$startedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$workbenchRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $workbenchRoot
$diagnosticScript = Join-Path $repoRoot "AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1"
$stamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$outputPath = Join-Path $workbenchRoot ("output\checks\ad.lockout\{0}" -f $stamp)

$rawOutput = [ordered]@{
    AffectedUser         = $AffectedUser
    DaysBack             = $DaysBack
    DomainController     = @($DomainController)
    DiagnosticScriptPath = $diagnosticScript
    OutputPath           = $outputPath
    ReportPath           = $null
    ExitCode             = $null
    ConsoleOutput        = @()
}

if (-not (Test-Path -LiteralPath $diagnosticScript -PathType Leaf)) {
    $summary = "AD lockout diagnostics script was not found."
    return New-ADLockoutResult -Status "Warn" -Summary $summary `
        -Evidence @(New-EvidenceItem -Name "Preflight" -Status "Warn" -Detail "Missing script: $diagnosticScript") `
        -RecommendedNextSteps @("Confirm AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1 exists in the repository.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    $summary = "ActiveDirectory module is not available; install RSAT or run from a domain admin workstation."
    $rawOutput.ConsoleOutput = @($_.Exception.Message)
    return New-ADLockoutResult -Status "Warn" -Summary $summary `
        -Evidence @(New-EvidenceItem -Name "Preflight" -Status "Warn" -Detail $_.Exception.Message) `
        -RecommendedNextSteps @("Install RSAT Active Directory tools, then run the check again from a domain-connected workstation.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
}

try {
    if (-not (Test-Path -LiteralPath $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force -ErrorAction Stop | Out-Null
    }

    $powershellPath = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        $powershellPath = "powershell.exe"
    }

    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $diagnosticScript,
        "-Identity",
        $AffectedUser,
        "-DaysBack",
        [string]$DaysBack,
        "-OutputPath",
        $outputPath
    )

    if ($DomainController -and $DomainController.Count -gt 0) {
        $arguments += "-DomainController"
        foreach ($dc in @($DomainController)) {
            if (-not [string]::IsNullOrWhiteSpace($dc)) {
                $arguments += $dc
            }
        }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $powershellPath
    $startInfo.Arguments = (($arguments | ForEach-Object { ConvertTo-CommandLineArgument -Value ([string]$_) }) -join " ")
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $standardOutput = $process.StandardOutput.ReadToEnd()
    $standardError = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    $consoleLines = @()
    if (-not [string]::IsNullOrWhiteSpace($standardOutput)) {
        $consoleLines += @($standardOutput -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if (-not [string]::IsNullOrWhiteSpace($standardError)) {
        $consoleLines += @($standardError -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    $rawOutput.ExitCode = [int]$process.ExitCode
    $rawOutput.ConsoleOutput = @($consoleLines)

    $report = @(Get-ChildItem -LiteralPath $outputPath -Filter "ADLockout_*.html" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1)

    if ($report.Count -gt 0) {
        $rawOutput.ReportPath = $report[0].FullName
    }

    if ($process.ExitCode -eq 0 -and $rawOutput.ReportPath) {
        return New-ADLockoutResult -Status "Pass" `
            -Summary "AD lockout diagnostics completed for $AffectedUser." `
            -Evidence @(New-EvidenceItem -Name "HTML report" -Status "Pass" -Detail $rawOutput.ReportPath) `
            -RecommendedNextSteps @("Review the HTML report for likely sources, lockout timeline, and stale credential clues.") `
            -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
    }

    if ($process.ExitCode -eq 0) {
        return New-ADLockoutResult -Status "Warn" `
            -Summary "AD lockout diagnostics completed but no HTML report was found for $AffectedUser." `
            -Evidence @(New-EvidenceItem -Name "HTML report" -Status "Warn" -Detail "No ADLockout_*.html file was found in $outputPath.") `
            -RecommendedNextSteps @("Review console output and rerun the check if the report path was not written.") `
            -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt
    }

    $errorText = ($consoleLines -join "; ")
    return New-ADLockoutResult -Status "Fail" `
        -Summary "AD lockout diagnostics failed for $AffectedUser." `
        -Evidence @(New-EvidenceItem -Name "Diagnostics script" -Status "Fail" -Detail "Script exited with code $($process.ExitCode).") `
        -RecommendedNextSteps @("Review console output, confirm the user identity, domain connectivity, and Security log permissions.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt -ErrorText $errorText
}
catch {
    $rawOutput.ConsoleOutput = @($_.Exception.Message)
    return New-ADLockoutResult -Status "Fail" `
        -Summary "AD lockout diagnostics wrapper failed before the check could complete." `
        -Evidence @(New-EvidenceItem -Name "Wrapper" -Status "Fail" -Detail $_.Exception.Message) `
        -RecommendedNextSteps @("Review the wrapper error and confirm the output folder is writable.") `
        -RawOutput ([PSCustomObject]$rawOutput) -StartedAt $startedAt -ErrorText $_.Exception.Message
}
