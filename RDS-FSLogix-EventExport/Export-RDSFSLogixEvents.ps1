#Requires -Version 5.1

<#
.SYNOPSIS
    Exports RDS- and FSLogix-related Windows event log entries for a specified time window to CSV and HTML.

.DESCRIPTION
    Runs locally on an RDS / Citrix session host. Collects events from:
      - Microsoft-Windows-TerminalServices-*/Operational logs (dynamically enumerated)
      - Microsoft-FSLogix-Apps/Operational, /Admin, and Microsoft-FSLogix-CloudCache/Operational
      - System and Application logs, filtered to RDS/FSLogix providers
      - Optionally Security log entries 4624/4625/4634/4647 filtered to RDP logon types (7, 10)

    Writes a flat CSV plus a self-contained dark-themed HTML report. Per-log errors are
    caught so a single unreachable or missing log does not halt the run.

.PARAMETER StartTime
    Explicit start of the time window. Mutually exclusive with -LastHours / -LastDays.

.PARAMETER EndTime
    End of the time window. Defaults to (Get-Date) when -StartTime is supplied.

.PARAMETER LastHours
    Shortcut: collect events from the last N hours. Mutually exclusive with -StartTime.

.PARAMETER LastDays
    Shortcut: collect events from the last N days. Mutually exclusive with -StartTime.

.PARAMETER OutputPath
    Directory to write CSV and HTML files. Defaults to the current directory.

.PARAMETER IncludeSecurity
    Include Security log RDP logon events (4624/4625/4634/4647, logon types 7/10). Requires admin.

.PARAMETER Level
    Event severity levels to include. Defaults to 1,2,3 (Critical, Error, Warning).
    Pass 1..4 to include Information, or 1..5 for everything.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -LastHours 4
    Exports the last 4 hours of RDS + FSLogix errors and warnings to the current directory.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -StartTime '2026-05-18 08:00' -EndTime '2026-05-18 17:00' -IncludeSecurity -OutputPath C:\Logs
    Exports a specific 9-hour window including RDP logon events to C:\Logs.

.EXAMPLE
    .\Export-RDSFSLogixEvents.ps1 -LastDays 1 -Level 1,2,3,4
    Exports the last 24 hours including Information-level events.

.NOTES
    Author: VC3 IT
    Runtime scales with event volume. For routine triage prefer narrow windows
    (a few hours). Whole-week pulls on busy brokers can take several minutes.
    Time stamps in output are local time, matching Event Viewer.
#>
[CmdletBinding(DefaultParameterSetName = 'Last')]
param(
    [Parameter(ParameterSetName = 'Explicit', Mandatory)]
    [datetime]$StartTime,

    [Parameter(ParameterSetName = 'Explicit')]
    [datetime]$EndTime,

    [Parameter(ParameterSetName = 'Last')]
    [ValidateRange(1, 720)]
    [int]$LastHours,

    [Parameter(ParameterSetName = 'Last')]
    [ValidateRange(1, 90)]
    [int]$LastDays,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$IncludeSecurity,

    [ValidateRange(1, 5)]
    [int[]]$Level = @(1, 2, 3)
)

# ---- Functions defined below; orchestration block at the bottom ----
