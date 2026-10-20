#Requires -Version 5.1

<#
.SYNOPSIS
    Smoke-test runner (SQ-029 stub: not implemented yet).

.DESCRIPTION
    Placeholder so the SQ-029 tests compile. The real runner starts each GUI with its -SmokeTest
    switch, requires exit code 0 and a [PASS] line, and kills a child that does not close.

.PARAMETER ScriptPath
    The GUI scripts to smoke-test. Defaults to the Folder Permission Manager GUI.

.PARAMETER TimeoutSeconds
    How long each child may run before it is killed.

.PARAMETER LoadFunctionsOnly
    Define the functions and return. Used by the Pester tests.

.EXAMPLE
    .\Tests\Invoke-SmokeTest.ps1

.NOTES
    Stub only.
#>

[CmdletBinding()]
param(
    [string[]]$ScriptPath,

    [ValidateRange(10, 600)]
    [int]$TimeoutSeconds = 90,

    [switch]$LoadFunctionsOnly
)

function Start-SmokeProcess {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$Arguments, [Parameter(Mandatory)][string]$WorkingDirectory, [Parameter(Mandatory)][int]$TimeoutSeconds)
    throw 'Start-SmokeProcess is not implemented.'
}
function Stop-SmokeProcess {
    param([Parameter(Mandatory)]$Process)
    throw 'Stop-SmokeProcess is not implemented.'
}
function Invoke-SmokeTarget {
    param([Parameter(Mandatory)][string]$ScriptPath, [int]$TimeoutSeconds = 90)
    throw 'Invoke-SmokeTarget is not implemented.'
}

if ($LoadFunctionsOnly) { return }

throw 'Invoke-SmokeTest.ps1 is not implemented.'
