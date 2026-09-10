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
$tempRoot = Join-Path $env:TEMP ("wb-timeout-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    $catalog = @(Get-CheckCatalog)
    Assert-True -Condition ($catalog.Count -ge 3) -Message "Catalog loads at least three checks."

    foreach ($check in $catalog) {
        Assert-True -Condition ($check.PSObject.Properties.Name -contains "TimeoutSeconds") -Message ("Check '{0}' exposes TimeoutSeconds." -f $check.CheckId)
        Assert-True -Condition ($check.TimeoutSeconds -ge 1 -and $check.TimeoutSeconds -le 3600) -Message ("Check '{0}' TimeoutSeconds is within 1-3600." -f $check.CheckId)
    }

    $adCheck = @($catalog | Where-Object { $_.CheckId -eq "ad.lockout" })[0]
    Assert-True -Condition ($adCheck.TimeoutSeconds -gt 120) -Message "ad.lockout timeout exceeds its 120s child-process timeout."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Check timeout tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Check timeout tests completed." -ForegroundColor Green
