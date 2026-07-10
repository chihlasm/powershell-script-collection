#Requires -Version 5.1

<#
.SYNOPSIS
    Guards the non-blocking accept loop.

.DESCRIPTION
    A blocking $listener.GetContext() cannot observe the Ctrl+C stop flag until the
    next request arrives, so the server appears to hang on Ctrl+C when idle. These
    are source-level assertions: the behavioral difference is demonstrated by the
    accept-loop experiment documented in the Task 7 notes, and the interactive
    Ctrl+C path needs a real console to exercise.
#>
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

Assert-True -Condition ($serverSource -match '\$listener\.GetContextAsync\(\)') -Message "Accept loop uses the async accept."
Assert-True -Condition ($serverSource -notmatch '\$context\s*=\s*\$listener\.GetContext\(\)') -Message "Blocking GetContext() is gone from the accept loop."
Assert-True -Condition ($serverSource -match 'AsyncWaitHandle\.WaitOne\(\s*250\s*\)') -Message "Accept wait is polled in short intervals so the stop flag is seen promptly."
Assert-True -Condition ($serverSource -match '(?s)while \(-not \$contextTask\.AsyncWaitHandle.*?if \(\$script:StopRequested\)') -Message "The accept wait checks StopRequested on every poll."
Assert-True -Condition ($serverSource -notmatch '\$script:WorkbenchListener') -Message "Cancel handler no longer stops the listener from the handler thread."
Assert-True -Condition ($serverSource -match '(?s)\[ConsoleCancelEventHandler\].*?\$script:StopRequested = \$true') -Message "Cancel handler sets the stop flag."

if ($script:Failures.Count -gt 0) {
    throw ("Accept loop tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Accept loop tests completed." -ForegroundColor Green
