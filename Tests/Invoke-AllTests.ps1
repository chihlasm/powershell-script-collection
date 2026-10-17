<#
.SYNOPSIS
    Runs every Pester test in the repository, excluding Integration-tagged tests.

.DESCRIPTION
    Finds every *.Tests.ps1 under the repository root (skipping dist, work-in-progress and
    .worktrees, which hold copies or abandoned work) and runs them with Pester 5. Tests that
    need a real environment are tagged 'Integration' and are excluded unless -IncludeIntegration
    is given. Exits non-zero when any test fails, so it can be used as a gate.

.PARAMETER IncludeIntegration
    Also run tests tagged 'Integration'. These touch the real machine.

.PARAMETER Path
    Limit the run to these folders or test files instead of the whole repository.

.EXAMPLE
    pwsh -NoProfile -File .\Tests\Invoke-AllTests.ps1

.NOTES
    Requires PowerShell 7 with Pester 5 (Windows PowerShell 5.1 ships Pester 3.4, which cannot
    run these suites).
#>
[CmdletBinding()]
param(
    [switch]$IncludeIntegration,
    [string[]]$Path
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

try {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
} catch {
    Write-Host '[FAIL] Pester 5 is not installed. Run: Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser' -ForegroundColor Red
    exit 2
}

if (-not $Path) {
    $skip = '[\\/](dist|work-in-progress|\.worktrees|\.git)[\\/]'
    $Path = @(Get-ChildItem -Path $repoRoot -Recurse -Filter '*.Tests.ps1' -File |
        Where-Object { $_.FullName.Substring($repoRoot.Length) -notmatch $skip } |
        Select-Object -ExpandProperty FullName)
}

$config = New-PesterConfiguration
$config.Run.Path = $Path
$config.Run.Exit = $true
$config.Output.Verbosity = 'Normal'
if (-not $IncludeIntegration) { $config.Filter.ExcludeTag = @('Integration') }

Invoke-Pester -Configuration $config
