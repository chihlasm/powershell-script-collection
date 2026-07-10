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
$serverSource = Get-Content -LiteralPath (Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1") -Raw
$uiSource = Get-Content -LiteralPath (Join-Path $repoRoot "MSP-TroubleshootingWorkbench\app\index.html") -Raw

Assert-True -Condition ($serverSource -match 'X-Workbench-Token') -Message "Server checks the X-Workbench-Token header."
Assert-True -Condition ($serverSource -match '__WORKBENCH_TOKEN__') -Message "Server injects the session token into the page."
Assert-True -Condition ($uiSource -match 'workbench-token') -Message "UI page carries the token meta tag."
Assert-True -Condition ($uiSource -match 'X-Workbench-Token') -Message "UI sends the token header on POSTs."
Assert-True -Condition (-not ($uiSource -match 'method:\s*"POST"[\s\S]{0,200}headers:\s*\{\s*"Content-Type":\s*"application/json"\s*\}')) -Message "No POST fetch remains without the token header."

if ($script:Failures.Count -gt 0) {
    throw ("Token tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Token tests completed." -ForegroundColor Green
