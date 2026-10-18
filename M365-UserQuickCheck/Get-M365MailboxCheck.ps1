#Requires -Version 5.1

<#
.SYNOPSIS
    SQ-007 STUB. Read-only mailbox check: who can open it, forwarding, inbox rules, size,
    holds, recent message trace, and a takeover-signs verdict.
.DESCRIPTION
    Not implemented yet. Tests\MailboxCheck.Tests.ps1 defines the interface.
.PARAMETER Identity
    The mailbox to check (email address).
.PARAMETER TraceDays
    How many days of message trace to read (1 to 10).
.PARAMETER OutputPath
    Folder for the HTML report and CSVs.
.PARAMETER TicketNumber
    Ticket number for the ticket folder and note.
.EXAMPLE
    .\Get-M365MailboxCheck.ps1 -Identity accounts@contoso.com
.NOTES
    Stub only.
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [ValidateRange(1, 10)]
    [int]$TraceDays = 7,

    [string]$OutputPath,

    [string]$TicketNumber,

    [switch]$NoTrace,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

throw 'Get-M365MailboxCheck.ps1: not implemented'
