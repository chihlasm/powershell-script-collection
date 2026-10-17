# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    STUB (SQ-003): "Why did this user get a temporary profile?" one-user verdict.
.DESCRIPTION
    Placeholder so the SQ-003 tests compile. Every function throws "not implemented".
    The implementation replaces this file; the tests in
    Citrix-FSLogix-Triage\Tests\Invoke-TempProfileInvestigation.Tests.ps1 define done.
.PARAMETER UserName
    The user, as jdoe or CONTOSO\jdoe. Alias: AffectedUser.
.PARAMETER ComputerName
    The session host. Alias: AffectedDevice.
.PARAMETER DeliveryController
    A Citrix Delivery Controller that finds the host.
.PARAMETER EventLookbackHours
    Hours of logs and events to read (1-168, default 24).
.PARAMETER OutputPath
    Folder for the report files.
.PARAMETER TicketNumber
    Ticket number for the SQ-001 ticket note.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard.
.PARAMETER FullDetail
    Keep paths and IP addresses in the ticket note.
.PARAMETER PassThru
    Return the result object instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report.
.PARAMETER LoadFunctionsOnly
    Define the functions and return (used by the tests).
.EXAMPLE
    .\Invoke-TempProfileInvestigation.ps1 -UserName jdoe -ComputerName CTX07
.NOTES
    Stub only.
#>
[CmdletBinding(DefaultParameterSetName = 'Host')]
param(
    [Parameter(Mandatory = $true)]
    [Alias('AffectedUser')]
    [string]$UserName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Host')]
    [Alias('AffectedDevice')]
    [string]$ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Broker')]
    [string]$DeliveryController,

    [ValidateRange(1, 168)]
    [int]$EventLookbackHours = 24,

    [string]$OutputPath,

    [string]$TicketNumber,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

    [switch]$LoadFunctionsOnly
)

$script:FSLogixReferenceFallback = @{}

function Get-TempProfileUserSid { param([string]$UserName) throw 'not implemented' }
function Resolve-TempProfileClientName { param([string]$Address) throw 'not implemented' }
function Get-TempProfileLockFact { param([string]$UserName, [string]$Sid, [string[]]$VhdLocations, [string[]]$CcdLocations) throw 'not implemented' }
function Read-TempProfileLogLines { param([string]$Path) throw 'not implemented' }
function ConvertFrom-TempProfileLog { param([string[]]$Lines, [string]$UserName, [string]$Sid, [hashtable]$Reference) throw 'not implemented' }
function Get-TempProfileLogFact { param([string]$ComputerName, [string]$UserName, [string]$Sid, [int]$EventLookbackHours) throw 'not implemented' }
function Get-TempProfileCrashFact { param([string]$ComputerName, [int]$EventLookbackHours) throw 'not implemented' }
function Get-TempProfileLoadedProfileFact { param([string]$ComputerName, [string]$Sid) throw 'not implemented' }
function Get-FSLogixReference { throw 'not implemented' }
function Import-CitrixBrokerSdk { throw 'not implemented' }
function Get-TempProfileVerdict { param([object]$Facts) throw 'not implemented' }
function Get-TempProfileExitCode { param([string]$Verdict) throw 'not implemented' }
function Write-TempProfileConsole { param([object]$Result) throw 'not implemented' }
function ConvertTo-TempProfileTicketNote { param([object]$Result, [string[]]$EvidencePaths) throw 'not implemented' }
function Invoke-TempProfileInvestigation {
    param(
        [string]$UserName, [string]$ComputerName, [string]$DeliveryController, [int]$EventLookbackHours = 24,
        [string]$OutputPath, [string]$TicketNumber, [switch]$NoClipboard, [switch]$FullDetail, [switch]$Quiet
    )
    throw 'not implemented'
}

if ($LoadFunctionsOnly) { return }

throw 'Invoke-TempProfileInvestigation.ps1 is not implemented yet (SQ-003).'
