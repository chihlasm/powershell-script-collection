#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DiskSpd Diagnostic Tool — on-demand storage triage using Microsoft diskspd.exe.

.DESCRIPTION
    Wraps diskspd.exe with a WPF GUI for fast, authoritative storage benchmarks.
    Supports three targeting modes:
      1. Local disk on this machine
      2. UNC path from this machine
      3. Run diskspd ON a remote VDA, targeting a path from that VDA
    Preset workload profiles model FSLogix-like, sequential read, mixed user load,
    and quick-sanity workloads, with override fields for power users.
    Produces a styled HTML report with health assessments.

.PARAMETER Target
    Path or UNC for the storage to test. Required when -NoUI is set.

.PARAMETER ComputerName
    Optional. If set, diskspd runs on this remote VDA targeting -Target from there.

.PARAMETER Profile
    Workload profile: FSLogixLike, SequentialRead, MixedUserLoad, QuickSanity, Custom.

.PARAMETER BlockSize
    Block size override (e.g., 4K, 64K). Required with -Profile Custom.

.PARAMETER Threads
    Thread count override. Required with -Profile Custom.

.PARAMETER QueueDepth
    Outstanding I/Os per thread. Required with -Profile Custom.

.PARAMETER WriteRatioPercent
    Percentage of writes (0-100). Required with -Profile Custom.

.PARAMETER DurationSeconds
    Test duration in seconds. Required with -Profile Custom.

.PARAMETER TestFileSizeMB
    Test file size in MB. Required with -Profile Custom.

.PARAMETER NoUI
    Run in headless mode. Requires -Target.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to Documents\DiskSpdReports.

.PARAMETER Force
    Bypass business-hours confirmation.

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1

.EXAMPLE
    .\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' -Profile FSLogixLike

.NOTES
    Requires diskspd.exe (bundled) next to this script.
    Must run as Administrator. WPF requires the in-box PresentationFramework assembly.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Target,

    [Parameter()]
    [string]$ComputerName,

    [Parameter()]
    [ValidateSet('FSLogixLike','SequentialRead','MixedUserLoad','QuickSanity','Custom')]
    [string]$Profile = 'FSLogixLike',

    [Parameter()]
    [ValidatePattern('^\d+[KMG]?$')]
    [string]$BlockSize,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$Threads,

    [Parameter()]
    [ValidateRange(1, 256)]
    [int]$QueueDepth,

    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$WriteRatioPercent,

    [Parameter()]
    [ValidateRange(5, 3600)]
    [int]$DurationSeconds,

    [Parameter()]
    [ValidateRange(64, 102400)]
    [int]$TestFileSizeMB,

    [Parameter()]
    [switch]$NoUI,

    [Parameter()]
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'DiskSpdReports'),

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = $PSScriptRoot
$script:DiskSpdExe  = Join-Path $script:ScriptRoot 'diskspd.exe'
$script:ReportTpl   = Join-Path $script:ScriptRoot 'ReportTemplate.html'

# --- Engine functions go here (Tasks 1-9) ---

# --- UI / headless dispatch goes here (Tasks 10-11) ---

# Entry-point dispatch (filled in Task 12):
# if ($NoUI) { Invoke-DiskSpdHeadless ... } else { Show-DiskSpdGui }
