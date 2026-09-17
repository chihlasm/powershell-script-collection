#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Pin discovery to the shipped module path. A broken third-party module elsewhere on
# PSModulePath that exports wildcard cmdlets can shadow built-ins like Write-Host.
$env:PSModulePath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules"

$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-notes-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    $case = [PSCustomObject]@{
        CaseId           = "CASE-20260101-120000"
        ClientName       = "Contoso"
        TicketNumber     = "10545"
        IssueType        = "Network"
        AffectedUser     = "jdoe"
        AffectedDevice   = ""
        TargetPath       = ""
        TargetAddress    = "srv01"
        CreatedAt        = "2026-01-01 12:00:00"
        UpdatedAt        = "2026-01-01 12:05:00"
        Checks           = @(
            [PSCustomObject]@{
                CheckId              = "network.quick"
                Name                 = "Network Quick Check"
                Category             = "Network"
                Status               = "Fail"
                Summary              = "Network quick check found a blocking issue for srv01."
                Evidence             = @(
                    [PSCustomObject]@{ Name = "Ping"; Status = "Pass"; Detail = "Target responded to ICMP echo." },
                    [PSCustomObject]@{ Name = "TCP port"; Status = "Fail"; Detail = "TCP port 445 is not reachable." }
                )
                RecommendedNextSteps = @("Check local routing, firewall policy, and service listener state for the target.")
                InputsUsed           = [PSCustomObject]@{ TargetAddress = "srv01"; Port = 445 }
                StartedAt            = "2026-01-01 12:01:00"
                FinishedAt           = "2026-01-01 12:01:10"
                Error                = ""
            }
        )
        Notes            = @()
        GeneratedSummary = ""
    }

    $markdown = New-TicketNotesMarkdown -Case $case

    # (?m) so $ anchors to end-of-line, not end-of-string; without it these match nothing
    # and pass vacuously even when the dangling label is present.
    Assert-True -Condition ($markdown -notmatch '(?m)^- Target path:\s*$') -Message "Blank Target path is omitted from Issue section."
    Assert-True -Condition ($markdown -notmatch '(?m)^- Affected device:\s*$') -Message "Blank Affected device is omitted from Issue section."
    Assert-True -Condition ($markdown -match '- Target address: srv01') -Message "Non-blank Target address is included."
    Assert-True -Condition ($markdown -match 'Ran Network Quick Check \(') -Message "Actions Taken bullet includes an input list."
    Assert-True -Condition ($markdown -match 'target: srv01') -Message "Actions Taken names the target address input."
    Assert-True -Condition ($markdown -match 'port: 445') -Message "Actions Taken names the port input."
    Assert-True -Condition ($markdown -match 'Likely Cause:') -Message "Likely Cause section exists."
    Assert-True -Condition ($markdown -match 'Network Quick Check: TCP port 445 is not reachable\.') -Message "Likely Cause quotes the failing evidence detail."
    Assert-True -Condition ($markdown -notmatch 'Likely related to: Network quick check found a blocking issue') -Message "Likely Cause no longer restates the check summary."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Ticket notes tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Ticket notes tests completed." -ForegroundColor Green
