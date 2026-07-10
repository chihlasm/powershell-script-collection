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

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$serverSource = Get-Content -LiteralPath $serverPath -Raw -ErrorAction Stop

Assert-True -Condition ($serverSource -match '\[string\]\$OutputPath\s*=\s*""') -Message "Workbench OutputPath parameter does not default directly to PSScriptRoot."
Assert-True -Condition ($serverSource -match 'if \(\[string\]::IsNullOrWhiteSpace\(\$OutputPath\)\)') -Message "Workbench sets blank OutputPath after parameter binding."
Assert-True -Condition ($serverSource -match '\$OutputPath\s*=\s*\$PSScriptRoot') -Message "Workbench blank OutputPath falls back to the script folder."

if ($script:Failures.Count -gt 0) {
    throw ("Task 9 portability harness failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Task 9 portability harness completed." -ForegroundColor Green
