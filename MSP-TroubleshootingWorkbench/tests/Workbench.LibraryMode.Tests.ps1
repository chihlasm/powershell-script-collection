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
$tempRoot = Join-Path $env:TEMP ("wb-libmode-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    # Dot-source in library mode: must define functions and must NOT block or listen.
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    Assert-True -Condition ($null -ne (Get-Command Test-WorkbenchCaseId -ErrorAction SilentlyContinue)) -Message "Test-WorkbenchCaseId is defined after library-mode load."
    Assert-True -Condition ($null -ne (Get-Command New-TicketNotesMarkdown -ErrorAction SilentlyContinue)) -Message "New-TicketNotesMarkdown is defined after library-mode load."
    Assert-True -Condition ($null -ne (Get-Command Invoke-WorkbenchCheck -ErrorAction SilentlyContinue)) -Message "Invoke-WorkbenchCheck is defined after library-mode load."
    Assert-True -Condition ($OutputPath -eq $tempRoot) -Message "OutputPath resolves to the requested folder in library mode."
    Assert-True -Condition (Test-WorkbenchCaseId -CaseId "CASE-20260101-120000") -Message "Case id validation accepts a well-formed id."
    Assert-True -Condition (-not (Test-WorkbenchCaseId -CaseId "..\evil")) -Message "Case id validation rejects traversal input."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Library mode tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Library mode tests completed." -ForegroundColor Green
