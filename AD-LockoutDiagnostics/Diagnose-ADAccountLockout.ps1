#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses why an Active Directory account keeps locking out and traces the source.
.DESCRIPTION
    Investigates repeated account lockouts (often mistaken for forced password resets).
    Reads account state and effective lockout policy (including any Fine-Grained
    Password Policy) from the PDC emulator, builds a lockout timeline from event 4740,
    traces bad-password sources via 4625/4771 across all DCs, flags admin resets (4724),
    and writes a ranked-verdict HTML report.
.PARAMETER Identity
    SamAccountName, UPN, or DN of the user to investigate.
.PARAMETER OutputPath
    Folder where the HTML report is written. Defaults to the current directory.
.PARAMETER DaysBack
    How many days of Security event logs to search. 1-90, default 7.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering all DCs.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath C:\Reports
.NOTES
    Run on a DC or admin box with RSAT. Requires permission to read DC Security logs.
    Hybrid/Entra lockouts are out of scope (lockouts originate on-prem).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Identity,

    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string[]]$DomainController,

    # Internal: dot-source the functions without running the orchestration body.
    # Used by the Pester tests so they can load helpers on a box without RSAT.
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function ConvertFrom-LockoutEvent {
    param([string]$EventXml, [string]$DcName)
    $x = [xml]$EventXml
    $d = @{}
    foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
    [PSCustomObject]@{
        Time           = [datetime]$x.Event.System.TimeCreated.SystemTime
        User           = $d['TargetUserName']
        Domain         = $d['TargetDomainName']
        CallerComputer = $d['CallerComputerName']
        DC             = $DcName
    }
}

if (-not $LoadFunctionsOnly) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Status FAIL "ActiveDirectory module not found. Install RSAT and retry."
        exit 1
    }
}
