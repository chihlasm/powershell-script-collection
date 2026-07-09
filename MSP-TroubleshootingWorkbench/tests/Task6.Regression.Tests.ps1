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
$workbenchRoot = Join-Path $repoRoot "MSP-TroubleshootingWorkbench"
$checksRoot = Join-Path $workbenchRoot "checks"
$manifestPath = Join-Path $checksRoot "manifest.json"
$lockoutCheckPath = Join-Path $checksRoot "Invoke-ADLockoutCheck.ps1"

$manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$lockoutEntry = @($manifest.checks | Where-Object { $_.checkId -eq "ad.lockout" }) | Select-Object -First 1

Assert-True -Condition ($null -ne $lockoutEntry) -Message "Manifest includes ad.lockout."
Assert-True -Condition ($lockoutEntry.script -eq "Invoke-ADLockoutCheck.ps1") -Message "Manifest points ad.lockout at the wrapper script."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "affectedUser") -Message "Manifest includes affectedUser input."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "daysBack") -Message "Manifest includes daysBack input."
Assert-True -Condition (@($lockoutEntry.inputs) -contains "domainController") -Message "Manifest includes domainController input."

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($lockoutCheckPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
Assert-True -Condition ($parseErrors.Count -eq 0) -Message "AD lockout wrapper parses cleanly."

$wrapperSource = Get-Content -LiteralPath $lockoutCheckPath -Raw -ErrorAction Stop
Assert-True -Condition (($wrapperSource -match "Diagnose-ADAccountLockout\.ps1") -and ($wrapperSource -like "*Test-Path -LiteralPath `$diagnosticScript*")) -Message "Wrapper preflights the AD diagnostics script path."
Assert-True -Condition ($wrapperSource -match "Import-Module\s+ActiveDirectory") -Message "Wrapper preflights the ActiveDirectory module."

$tempRoot = Join-Path $env:TEMP ("WorkbenchTask6Tests_{0}" -f ([guid]::NewGuid().ToString("N")))
$tempChecksRoot = Join-Path $tempRoot "MSP-TroubleshootingWorkbench\checks"
New-Item -ItemType Directory -Path $tempChecksRoot -Force | Out-Null
$tempWrapperPath = Join-Path $tempChecksRoot "Invoke-ADLockoutCheck.ps1"
Copy-Item -LiteralPath $lockoutCheckPath -Destination $tempWrapperPath -Force

$result = & $tempWrapperPath -AffectedUser "jdoe" -DaysBack 3
Assert-True -Condition ($result.CheckId -eq "ad.lockout") -Message "Wrapper returns ad.lockout CheckId."
Assert-True -Condition ($result.Status -eq "Warn") -Message "Wrapper returns Warn instead of throwing when the AD diagnostics script is missing."
Assert-True -Condition ($result.Summary -match "diagnostics script") -Message "Wrapper warning summary names the missing diagnostics script."
Assert-True -Condition ($result.Error -eq "") -Message "Preflight warning does not populate a thrown-error value."

$expectedFields = @(
    "CheckId",
    "Name",
    "Category",
    "Status",
    "Summary",
    "Evidence",
    "RecommendedNextSteps",
    "RawOutput",
    "StartedAt",
    "FinishedAt",
    "Error"
)

foreach ($field in $expectedFields) {
    Assert-True -Condition ($result.PSObject.Properties.Name -contains $field) -Message "Wrapper result includes $field."
}

if ($script:Failures.Count -gt 0) {
    throw ("Task 6 regression harness failed: {0}" -f ($script:Failures -join "; "))
}

if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}

Write-Host "[PASS] Task 6 regression harness completed." -ForegroundColor Green
