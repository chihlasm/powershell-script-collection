#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
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

function Import-WorkbenchFunctions {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        throw "Unable to parse workbench script: $($parseErrors[0].Message)"
    }

    $functions = $ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    foreach ($function in $functions) {
        Invoke-Expression ("function global:{0} {1}" -f $function.Name, $function.Body.Extent.Text)
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$serverPath = Join-Path $workbenchRoot "Start-MSPTroubleshootingWorkbench.ps1"

Import-WorkbenchFunctions -Path $serverPath

$tempRoot = Join-Path $env:TEMP ("WorkbenchTask5Tests_{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$global:OutputPath = $tempRoot

try {
    $case = [PSCustomObject]@{
        CaseId           = "CASE-20260709-150501"
        ClientName       = "Contoso"
        TicketNumber     = "INC12345"
        IssueType        = "Network"
        AffectedUser     = "Alex"
        AffectedDevice   = "LAPTOP-22"
        TargetPath       = "\\server\share"
        TargetAddress    = "gateway.contoso.local"
        CreatedAt        = "2026-07-09 15:05:01"
        UpdatedAt        = "2026-07-09 15:06:01"
        Checks           = @(
            [PSCustomObject]@{
                CheckId              = "network.quick"
                Name                 = "Network Quick Check"
                Status               = "Warn"
                Summary              = "DNS resolved but TCP 443 failed."
                Evidence             = @(
                    [PSCustomObject]@{
                        Name   = "TCP 443"
                        Status = "Fail"
                        Detail = "Connection timed out."
                    }
                )
                RecommendedNextSteps = @("Confirm firewall rules for TCP 443.")
                StartedAt            = "2026-07-09 15:05:15"
                FinishedAt           = "2026-07-09 15:05:20"
            }
        )
        Notes            = @(
            [PSCustomObject]@{
                CreatedAt = "2026-07-09 15:05:30"
                Text      = "User reports VPN works but app cannot connect."
            }
        )
        GeneratedSummary = ""
    }

    Save-WorkbenchCase -Case $case -ExpectedCaseId $case.CaseId | Out-Null

    $markdown = New-TicketNotesMarkdown -Case $case
    $expectedSections = @(
        "Issue:",
        "Actions Taken:",
        "Findings:",
        "Evidence:",
        "Likely Cause:",
        "Next Steps:",
        "Customer-Facing Summary:"
    )

    foreach ($section in $expectedSections) {
        Assert-True -Condition ($markdown -match [regex]::Escape($section)) -Message "Generated markdown includes $section"
    }

    Assert-True -Condition ($markdown -match "Contoso") -Message "Generated markdown includes case fields."
    Assert-True -Condition ($markdown -match "User reports VPN works") -Message "Generated markdown includes manual notes."
    Assert-True -Condition ($markdown -match "DNS resolved but TCP 443 failed") -Message "Generated markdown includes check summaries."
    Assert-True -Condition ($markdown -match "Connection timed out") -Message "Generated markdown includes evidence details."
    Assert-True -Condition ($markdown -match "Confirm firewall rules") -Message "Generated markdown includes recommended next steps."

    $export = Export-WorkbenchCaseEvidence -Case $case
    Assert-True -Condition (Test-Path -LiteralPath $export.MarkdownPath -PathType Leaf) -Message "Export writes ticket-notes.md."
    Assert-True -Condition (Test-Path -LiteralPath $export.ReportPath -PathType Leaf) -Message "Export writes report.html."
    Assert-True -Condition (Test-Path -LiteralPath $export.EvidencePath -PathType Leaf) -Message "Export writes evidence.json."

    $exportedMarkdown = Get-Content -LiteralPath $export.MarkdownPath -Raw -ErrorAction Stop
    Assert-True -Condition ($exportedMarkdown -eq $markdown) -Message "Exported markdown matches generated notes."

    $evidence = Get-Content -LiteralPath $export.EvidencePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Assert-True -Condition ($evidence.CaseId -eq $case.CaseId) -Message "Evidence JSON includes the case id."
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

if ($script:Failures.Count -gt 0) {
    throw ("Task 5 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Task 5 regression harness completed." -ForegroundColor Green
