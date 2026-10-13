#Requires -Version 5.1
<#
.SYNOPSIS
    One-command performance triage for Citrix / RDS session hosts running FSLogix, including
    the Hyper-V hosts underneath them.

.DESCRIPTION
    Runs the repository's existing diagnostic tools in a fixed order against the same set of
    servers and the same time window, then rolls everything up into one summary report:

      1. Server health     Citrix-FSLogix-HealthCollector - sampled CPU / memory / disk / queue
                           plus Citrix, RDS and FSLogix events, one verdict per server
      2. FSLogix settings  Reads each server's FSLogix registry settings to find the profile
                           share (VHDLocations / CCDLocations) and the log folder (LogDir)
      3. FSLogix logs      Parse-FSLogixLogs - profile load times, re-attach loops, containers
                           running out of space, logged errors
      4. Storage events    Get-FSLogixStorageEvents - SMB, disk and profile events, lined up
                           against every re-attach found in step 3 so the trigger stands out
      5. RDS events        RDS-FSLogix-EventExport - full event export for the record
      6. Storage speed     DiskSpdDiagnostic - benchmarks the profile share from a session host
      7. Hyper-V hosts     HyperV-Host-Diagnostics + Hyper-V-Inventory - host storage, cluster,
                           event and VM configuration checks

    Each tool runs in its own Windows PowerShell 5.1 process with its own output folder and a
    time limit, so one tool failing, hanging or calling 'exit' cannot stop the others.

    Hyper-V access is often restricted. When a Hyper-V host refuses the connection, the script
    does not fail - it builds a hand-off package (the two read-only Hyper-V scripts, a one-click
    collection script and plain-English instructions) that you can give to whoever administers
    the cluster.

.PARAMETER ComputerName
    Citrix / RDS session hosts to check. Use this or -DeliveryController.

.PARAMETER DeliveryController
    Citrix Delivery Controller to discover session hosts from. Requires the Citrix Broker SDK
    on this workstation. Use this or -ComputerName.

.PARAMETER DesktopGroupName
    With -DeliveryController, limits discovery to one delivery group.

.PARAMETER ProfileSharePath
    UNC path of the FSLogix profile share to benchmark. When omitted, it is read from the
    session hosts' FSLogix settings (VHDLocations, or CCDLocations for Cloud Cache).

.PARAMETER HyperVHost
    Hyper-V hosts to check. Can be combined with -HyperVCluster.

.PARAMETER HyperVCluster
    Hyper-V failover cluster to check. Its nodes are discovered automatically.

.PARAMETER VMName
    Names of the session host VMs in Hyper-V. Defaults to the session host names (without the
    domain suffix) - set this only when the VM names differ from the computer names.

.PARAMETER LookbackHours
    How far back to read event logs and FSLogix logs. Default 24.

.PARAMETER HyperVDaysBack
    How far back to read Hyper-V host event logs. Default 7 - host storage problems often start
    well before users notice.

.PARAMETER SampleSeconds
    How long to sample performance counters on each session host. Default 60. Set 0 for a single
    instantaneous reading.

.PARAMETER BenchmarkWorkload
    DiskSpd workload for the storage speed test. Default FSLogixLike (4K random, 30% writes,
    30 seconds, 1 GB test file).

.PARAMETER BenchmarkComputerName
    Session host to run the storage speed test from. Defaults to the first session host.

.PARAMETER SkipStorageBenchmark
    Do not run the storage speed test. It writes a 1 GB test file to the profile share and puts
    real load on it for the length of the test.

.PARAMETER SkipHyperV
    Do not check the Hyper-V hosts.

.PARAMETER StepTimeoutSeconds
    Longest any single tool run (one server, one step) may take before it is stopped.
    Default 1800 (30 minutes).

.PARAMETER ThrottleLimit
    How many servers each step checks at the same time. Default 4. Higher is faster on a big
    site but puts more simultaneous load on this machine and the network.

.PARAMETER Credential
    Credential for the session hosts. Passed to every tool that accepts one. The storage speed
    test and FSLogix log reading always run as the current user.

.PARAMETER HyperVCredential
    Credential for the Hyper-V hosts, for when a colleague with Hyper-V rights enters theirs.
    Defaults to the current user.

.PARAMETER OutputPath
    Folder to create the run folder in. Defaults to the current directory.

.PARAMETER ToolRoot
    Folder holding the tool folders, when they are somewhere other than next to this script
    or next to this script's folder.

.PARAMETER CreateKit
    Build a portable kit instead of running a triage: this script plus every tool it needs,
    as a folder or (when the path ends in .zip) a zip. Copy the kit to the server you will run
    from, extract it, and run Invoke-CitrixPerfTriage.ps1 from inside it. Run this from the
    repository, where all the tools are.

.PARAMETER NoOpen
    Do not open the summary report when finished.

.PARAMETER PassThru
    Also return the result object (overall status, steps, findings) to the pipeline.

.PARAMETER LoadFunctionsOnly
    Load the helper functions without running anything. Used by the Pester tests.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1 -CreateKit C:\Temp\CitrixPerfTriageKit.zip

    Run from the repository: packs this script and all its tools into one zip to copy to a
    client server.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1

    On a Delivery Controller, with no targets given: discovers the session hosts from the
    local Controller.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01, CTXVDA02 -HyperVCluster HVCLUSTER01

    Full triage of two session hosts and the cluster they run on. The profile share is found
    from the FSLogix settings and benchmarked from CTXVDA01.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1 -DeliveryController DDC01 -DesktopGroupName 'Shared Desktop' -LookbackHours 72

    Discover the session hosts from Citrix and look back three days.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01 -HyperVHost HV01 -HyperVCredential (Get-Credential)

    A colleague with Hyper-V rights types their credential so the host checks run directly
    instead of producing a hand-off package.

.EXAMPLE
    .\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01 -SkipStorageBenchmark -SkipHyperV

    Read-only pass during business hours: no load on the profile share, no Hyper-V checks.

.NOTES
    Requirements
      - Windows PowerShell 5.1 on this workstation. The tools always run under
        powershell.exe 5.1, because the Citrix Broker SDK snap-ins do not load in PowerShell 7.
      - The sibling tool folders from this repository, next to this folder.
      - Admin rights on the session hosts; WinRM and the Remote Event Log Management firewall
        rule on them; the admin share (C$) for reading FSLogix logs.
      - The storage speed test needs this console to be elevated (DiskSpdDiagnostic declares
        #Requires -RunAsAdministrator). Without elevation the test is skipped, not failed.

    What it changes
      Nothing on the session hosts or Hyper-V hosts, with two exceptions: the storage speed
      test writes and then deletes a test file on the profile share (and copies diskspd.exe to
      the benchmark host's C:\Windows\Temp, removed afterwards); and the Hyper-V host check
      writes its log to a temporary folder on the host, which is deleted after it is read.

    REFERENCES
      FSLogix log location (default %ProgramData%\FSLogix\Logs), LogDir and
      LogFileKeepingPeriod (default 2 days):
        https://learn.microsoft.com/fslogix/reference-configuration-settings#log-settings
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics#text-based-log-files
      VHDLocations / CCDLocations - REG_SZ (semicolon-delimited) or REG_MULTI_SZ:
        https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles#incorrect-settings-in-vhdlocations-or-ccdlocations
        https://learn.microsoft.com/fslogix/concepts-configuration-examples
      Process.ExitCode is unreliable on Start-Process -PassThru objects, which is why the tools
      are launched through System.Diagnostics.Process:
        https://stackoverflow.com/a/44057975
#>
[CmdletBinding(DefaultParameterSetName = 'Explicit')]
param(
    [Parameter(ParameterSetName = 'Explicit', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Mandatory, ParameterSetName = 'Broker')]
    [ValidateNotNullOrEmpty()]
    [string]$DeliveryController,

    [Parameter(ParameterSetName = 'Broker')]
    [string]$DesktopGroupName,

    [ValidatePattern('^\\\\[^\\]+\\[^\\]+')]
    [string]$ProfileSharePath,

    [string[]]$HyperVHost,

    [string]$HyperVCluster,

    [string[]]$VMName,

    [ValidateRange(1, 720)]
    [int]$LookbackHours = 24,

    [ValidateRange(1, 365)]
    [int]$HyperVDaysBack = 7,

    [ValidateRange(0, 3600)]
    [int]$SampleSeconds = 60,

    [ValidateSet('FSLogixLike', 'MixedUserLoad', 'SequentialRead', 'QuickSanity')]
    [string]$BenchmarkWorkload = 'FSLogixLike',

    [string]$BenchmarkComputerName,

    [switch]$SkipStorageBenchmark,

    [switch]$SkipHyperV,

    [ValidateRange(60, 14400)]
    [int]$StepTimeoutSeconds = 1800,

    [ValidateRange(1, 16)]
    [int]$ThrottleLimit = 4,

    [System.Management.Automation.PSCredential]$Credential,

    [System.Management.Automation.PSCredential]$HyperVCredential,

    [string]$OutputPath = (Get-Location).Path,

    [string]$ToolRoot,

    [string]$CreateKit,

    [switch]$NoOpen,

    [switch]$PassThru,

    [switch]$LoadFunctionsOnly
)

# ---------------------------------------------------------------------------
# Tool locations - every tool is a sibling folder in this repository
# ---------------------------------------------------------------------------
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ToolPaths = [ordered]@{
    Health          = 'Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1'
    FSLogixLogs     = 'Parse-FSLogixLogs\Parse-FSLogixLogs.ps1'
    StorageEvents   = 'Get-FSLogixStorageEvents\Get-FSLogixStorageEvents.ps1'
    RdsEvents       = 'RDS-FSLogix-EventExport\Export-RDSFSLogixEvents.ps1'
    DiskSpd         = 'DiskSpdDiagnostic\Invoke-DiskSpdDiagnostic.ps1'
    HyperVHost      = 'HyperV-Host-Diagnostics\Get-HyperVHostDiagnostics.ps1'
    HyperVInventory = 'Hyper-V-Inventory\Get-HyperVInfrastructureInventory.ps1'
}

$script:LogFile  = $null
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Steps    = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-TriageLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message
    )

    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host ("[{0}] {1}" -f $Status, $Message) -ForegroundColor $color

    if ($script:LogFile) {
        $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Status, $Message
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    }
}

function Add-TriageFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'Warning', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Area,

        [AllowEmptyString()]
        [string]$Target = '',

        [Parameter(Mandatory)]
        [string]$Finding,

        [AllowEmptyString()]
        [string]$Evidence = ''
    )

    $script:Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Area     = $Area
        Target   = $Target
        Finding  = $Finding
        Evidence = $Evidence
    })
}

function Add-TriageStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Step,

        [Parameter(Mandatory)]
        [ValidateSet('Completed', 'Partial', 'Skipped', 'Failed', 'TimedOut', 'Handoff')]
        [string]$Status,

        [AllowEmptyString()]
        [string]$Detail = '',

        [TimeSpan]$Duration = [TimeSpan]::Zero,

        [AllowEmptyString()]
        [string]$ReportPath = ''
    )

    $script:Steps.Add([PSCustomObject]@{
        Step       = $Step
        Status     = $Status
        Detail     = $Detail
        Duration   = $Duration
        ReportPath = $ReportPath
    })

    $lineStatus = switch ($Status) {
        'Completed' { 'PASS' }
        'Skipped'   { 'INFO' }
        'Handoff'   { 'WARN' }
        'Partial'   { 'WARN' }
        default     { 'FAIL' }
    }
    Write-TriageLine -Status $lineStatus -Message ("{0}: {1}. {2}" -f $Step, $Status, $Detail)
}

# ---------------------------------------------------------------------------
# Pure helpers (covered by the Pester suite)
# ---------------------------------------------------------------------------
function ConvertTo-PSLiteral {
    <#
    .SYNOPSIS
        Quotes a string as a PowerShell single-quoted literal, for generated script text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Value)

    "'" + ($Value -replace "'", "''") + "'"
}

function Split-TriageNameList {
    <#
    .SYNOPSIS
        Turns "VDA01,VDA02; VDA03" into three names.
    .DESCRIPTION
        powershell.exe -File passes -ComputerName VDA01,VDA02 to the script as ONE string,
        "VDA01,VDA02" - the comma is only an array operator when PowerShell itself parses the
        command line. The kit is run with -File, so every name-list parameter is split here.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][string[]]$Value)

    if (-not $Value) { return @() }
    @($Value | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function ConvertTo-SafeFolderName {
    <#
    .SYNOPSIS
        Makes a server name safe to use as a folder name.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)

    $invalid = [regex]::Escape((-join [IO.Path]::GetInvalidFileNameChars()))
    $safe = ($Name -replace "[$invalid]", '_').Trim('. ')
    if ($safe) { $safe } else { 'server' }
}

function Get-ShortComputerName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name)

    # Citrix reports machines as DOMAIN\NAME; DNS gives name.domain.tld. Both reduce to NAME.
    $leaf = ($Name -split '\\')[-1]
    ($leaf -split '\.')[0]
}

function ConvertTo-AdminSharePath {
    <#
    .SYNOPSIS
        Turns a path as seen on a remote machine into a path this workstation can read.
    .DESCRIPTION
        'C:\ProgramData\FSLogix\Logs' on CTXVDA01 becomes '\\CTXVDA01\C$\ProgramData\FSLogix\Logs'.
        A UNC path is already reachable from here and is returned unchanged. Anything else
        (a relative path, an unexpanded variable) returns $null rather than a guess.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [AllowEmptyString()][string]$LocalPath
    )

    if ([string]::IsNullOrWhiteSpace($LocalPath)) { return $null }
    $path = $LocalPath.Trim()
    if ($path -match '^\\\\') { return $path }
    if ($path -match '^([A-Za-z]):\\?(.*)$') {
        $rest = $Matches[2].TrimEnd('\')
        $unc = "\\$ComputerName\$($Matches[1].ToUpper())`$"
        if ($rest) { $unc = "$unc\$rest" }
        return $unc
    }
    return $null
}

function Split-FSLogixLocation {
    <#
    .SYNOPSIS
        Normalizes a VHDLocations value into a list of UNC paths.
    .DESCRIPTION
        VHDLocations may be REG_SZ with multiple entries separated by semicolons, or
        REG_MULTI_SZ - both are supported by FSLogix, so both must be read.
        https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles#incorrect-settings-in-vhdlocations-or-ccdlocations
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return @() }
    @(@($Value) |
        ForEach-Object { "$_" -split ';' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ })
}

function Get-CcdConnectionPath {
    <#
    .SYNOPSIS
        Extracts the SMB paths from a Cloud Cache CCDLocations value.
    .DESCRIPTION
        CCDLocations entries look like
            type=smb,name="FILES SMB PRIMARY",connectionString=\\server\share
        separated by semicolons, as REG_SZ or REG_MULTI_SZ. Only SMB connection strings are
        returned - an Azure page blob provider has no UNC path to benchmark.
        https://learn.microsoft.com/fslogix/concepts-configuration-examples
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return @() }
    $joined = (@($Value) | ForEach-Object { "$_" }) -join ';'
    @([regex]::Matches($joined, 'connectionString=(\\\\[^;,]+)', 'IgnoreCase') |
        ForEach-Object { $_.Groups[1].Value.Trim().Trim('"') })
}

function ConvertFrom-FSLogixLogSeverity {
    <#
    .SYNOPSIS
        Maps Parse-FSLogixLogs finding severities onto this report's three levels.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Severity)

    switch ($Severity) {
        'High'   { 'Critical' }
        'Medium' { 'Warning' }
        default  { 'Info' }
    }
}

function Get-HyperVFlagFromLog {
    <#
    .SYNOPSIS
        Pulls the flagged items out of a Get-HyperVHostDiagnostics log.
    .DESCRIPTION
        That script has no object output - it prepends a FINDINGS SUMMARY block to its log
        with one "  [n] text" line per flag, ended by a blank line. Only that block is read,
        so numbered lines further down the report are not mistaken for flags.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $flags = New-Object System.Collections.Generic.List[string]
    $inSummary = $false
    foreach ($line in ($Text -split "\r?\n")) {
        if (-not $inSummary) {
            if ($line -match '^FINDINGS SUMMARY') { $inSummary = $true }
            continue
        }
        if ($line -match '^\s*\[\d+\]\s+(.+?)\s*$') { $flags.Add($Matches[1]); continue }
        if ([string]::IsNullOrWhiteSpace($line)) { break }
    }
    $flags.ToArray()
}

function Get-DiskSpdResultFromConsole {
    <#
    .SYNOPSIS
        Reads the benchmark numbers from DiskSpdDiagnostic's console output.
    .DESCRIPTION
        Invoke-DiskSpdDiagnostic -NoUI returns only the HTML report path; the numbers are
        printed as one line:
            Results: 1234 IOPS / 12.3 MB/s read / 4.5 MB/s write / 6.7 ms avg latency
        Returns $null when the line is absent, so a format change shows as "no numbers"
        rather than as wrong numbers.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $pattern = 'Results:\s*([\d.,]+)\s*IOPS\s*/\s*([\d.,]+)\s*MB/s read\s*/\s*([\d.,]+)\s*MB/s write\s*/\s*([\d.,]+)\s*ms avg latency'
    $m = [regex]::Match($Text, $pattern)
    if (-not $m.Success) { return $null }

    $num = {
        param($s)
        [double]::Parse(($s -replace ',', ''), [Globalization.CultureInfo]::InvariantCulture)
    }
    [PSCustomObject]@{
        IOPS         = & $num $m.Groups[1].Value
        ReadMBps     = & $num $m.Groups[2].Value
        WriteMBps    = & $num $m.Groups[3].Value
        AvgLatencyMs = & $num $m.Groups[4].Value
    }
}

function Get-TriageOverallStatus {
    <#
    .SYNOPSIS
        Rolls findings and step results up to one verdict.
    .DESCRIPTION
        "Healthy" is only ever returned when checks actually ran and none failed. With no
        findings because nothing ran, or because steps failed, the verdict is "Incomplete" -
        a triage that could not look must never report that it found nothing wrong.
        Problems that were found are still reported as Critical/Warning even when other
        steps failed, because those findings are real.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [object[]]$Finding = @(),
        [object[]]$Step = @()
    )

    $ran = @($Step | Where-Object { $_.Status -in 'Completed', 'Partial' }).Count
    if ($Step.Count -and $ran -eq 0) { return 'Incomplete' }
    if (@($Finding | Where-Object Severity -eq 'Critical').Count -gt 0) { return 'Critical' }
    if (@($Finding | Where-Object Severity -eq 'Warning').Count -gt 0)  { return 'Warning' }
    if (@($Step | Where-Object { $_.Status -in 'Failed', 'TimedOut' }).Count -gt 0) { return 'Incomplete' }
    'Healthy'
}

function Get-RelativeReportPath {
    <#
    .SYNOPSIS
        Makes a report path relative to the run folder so links survive the folder being
        zipped, moved or attached to a ticket.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RunFolder,
        [AllowEmptyString()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $root = $RunFolder.TrimEnd('\') + '\'
    if ($Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($root.Length)
    }
    $Path
}

# ---------------------------------------------------------------------------
# Finding the tools, and packing them into a portable kit
# ---------------------------------------------------------------------------
function Get-TriageToolSearchRoot {
    <#
    .SYNOPSIS
        The folders searched for tool folders, most specific first.
    .DESCRIPTION
        Covers the three ways the script is realistically laid out:
          -ToolRoot            an explicit override
          <script folder>      a kit: the tool folders sit next to the script
          <script folder>\..   the repository: the tool folders are siblings of Citrix-PerfTriage
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyString()][string]$ToolRoot,
        [Parameter(Mandatory)][string]$ScriptFolder
    )

    $roots = @()
    if ($ToolRoot) { $roots += $ToolRoot }
    $roots += $ScriptFolder
    $parent = Split-Path -Parent $ScriptFolder
    if ($parent) { $roots += $parent }
    @($roots | Select-Object -Unique)
}

function Resolve-TriageTool {
    <#
    .SYNOPSIS
        Finds one tool script under the search roots. Returns $null when it is not found.
    .DESCRIPTION
        Accepts the tool in its own folder (the normal layout) or loose in a search root, so a
        technician who copied the .ps1 files flat into one folder is still covered.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [string[]]$SearchRoot = @()
    )

    $leaf = Split-Path -Leaf $RelativePath
    foreach ($root in $SearchRoot) {
        foreach ($candidate in (Join-Path $root $RelativePath), (Join-Path $root $leaf)) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $candidate).ProviderPath
            }
        }
    }
    $null
}

function New-TriageKit {
    <#
    .SYNOPSIS
        Copies this script and every tool folder it uses into one portable folder or zip.
    .DESCRIPTION
        The kit keeps the tools in their own folders next to the script, which is the first
        layout Resolve-TriageTool checks, so the kit runs from wherever it is extracted.
        Test suites and DiskSpd's saved reports from earlier runs are left out.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][hashtable]$Tools
    )

    $asZip = $Destination -match '\.zip$'
    $staging = if ($asZip) {
        Join-Path $env:TEMP ('CitrixPerfTriageKit_' + [guid]::NewGuid().ToString('N'))
    } else { $Destination }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    Copy-Item -LiteralPath $ScriptPath -Destination $staging -Force

    foreach ($toolPath in $Tools.Values) {
        $srcFolder = Split-Path -Parent $toolPath
        $dstFolder = Join-Path $staging (Split-Path -Leaf $srcFolder)
        $prefixLength = $srcFolder.TrimEnd('\').Length + 1
        Get-ChildItem -LiteralPath $srcFolder -Recurse -File | Where-Object {
            $rel = $_.FullName.Substring($prefixLength)
            $rel -notmatch '(^|\\)Tests\\' -and $_.Name -notlike 'diskspd_*.html' -and $_.Name -ne '.gitignore'
        } | ForEach-Object {
            $target = Join-Path $dstFolder $_.FullName.Substring($prefixLength)
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $target -Force
        }
    }

    $readme = @"
Citrix performance triage kit
=============================
Built $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $env:USERDOMAIN\$env:USERNAME.

1. Copy this folder (or the zip, then extract it) to a server in the client's network -
   the Delivery Controller is ideal.
2. Open Windows PowerShell AS ADMINISTRATOR in this folder.
3. Run one of:

   On the Delivery Controller (finds the session hosts itself):
     powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CitrixPerfTriage.ps1 -OutputPath C:\Temp

   Anywhere else, naming the session hosts:
     powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CitrixPerfTriage.ps1 -ComputerName VDA01,VDA02 -OutputPath C:\Temp

   Useful extras:  -DesktopGroupName '<group>'   -HyperVCluster <name>   -SkipStorageBenchmark

The summary opens when it finishes. Full help:  Get-Help .\Invoke-CitrixPerfTriage.ps1 -Full
"@
    Set-Content -LiteralPath (Join-Path $staging 'README-FIRST.txt') -Value $readme -Encoding UTF8

    if ($asZip) {
        $zipParent = Split-Path -Parent $Destination
        if ($zipParent -and -not (Test-Path -LiteralPath $zipParent)) {
            New-Item -ItemType Directory -Path $zipParent -Force | Out-Null
        }
        Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $Destination -Force
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
    $Destination
}

function Test-LocalDeliveryController {
    <#
    .SYNOPSIS
        True when this machine is a Citrix Delivery Controller.
    .DESCRIPTION
        Checks for the Citrix Broker Service (service name CitrixBrokerService), which runs
        only on Controllers. The Broker SDK alone is not enough - it is also installed with
        Studio on admin workstations, where 'localhost' is not a Controller.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    [bool](Get-Service -Name 'CitrixBrokerService' -ErrorAction SilentlyContinue)
}

# ---------------------------------------------------------------------------
# Discovery and the up-front plan
# ---------------------------------------------------------------------------
function New-TriageInventoryEntry {
    <#
    .SYNOPSIS
        One session host, in the same shape the health collector's broker discovery returns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$DeliveryGroup,
        [string]$RegistrationState,
        [string]$PowerState,
        [object]$InMaintenanceMode,
        [object]$SessionCount
    )

    [PSCustomObject]@{
        ComputerName      = $ComputerName
        DeliveryGroup     = $DeliveryGroup
        RegistrationState = $RegistrationState
        PowerState        = $PowerState
        InMaintenanceMode = $InMaintenanceMode
        SessionCount      = $SessionCount
    }
}

function Get-TriageInventory {
    <#
    .SYNOPSIS
        Asks a Delivery Controller for its session hosts, before any checks start.
    .DESCRIPTION
        Uses the health collector's own discovery (Import-CitrixBrokerSdk + Get-VDAInventory,
        loaded with -LoadFunctionsOnly) so the list is exactly what the collector would have
        found, including its handling of the broker's 250-record default. Runs in a Windows
        PowerShell 5.1 process because the Citrix snap-ins do not load in PowerShell 7.

        Unregistered machines are kept - an unregistered session host may well be the problem.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CollectorPath,
        [Parameter(Mandatory)][string]$DeliveryController,
        [string]$DesktopGroupName,
        [Parameter(Mandatory)][string]$WorkFolder,
        [int]$TimeoutSeconds = 300
    )

    New-Item -ItemType Directory -Path $WorkFolder -Force | Out-Null
    # Dot-sourcing the collector binds ITS parameters (DeliveryController, DesktopGroupName...)
    # into this scope, so this script's own parameters use names the collector does not have.
    $discovery = @'
param([string]$TriageCollector, [string]$TriageController, [string]$TriageGroup)
. $TriageCollector -LoadFunctionsOnly
if (-not (Import-CitrixBrokerSdk)) {
    throw 'The Citrix Broker PowerShell SDK is not available on this machine. Run this on a Delivery Controller, or name the servers with -ComputerName.'
}
Get-VDAInventory -DeliveryController $TriageController -DesktopGroupName $TriageGroup -MaxRecordCount ([int]::MaxValue)
'@
    $discoveryPath = Join-Path $WorkFolder 'Discover-SessionHosts.ps1'
    Set-Content -LiteralPath $discoveryPath -Value $discovery -Encoding UTF8

    $run = Invoke-ToolScript -ScriptPath $discoveryPath -WorkFolder $WorkFolder -TimeoutSeconds $TimeoutSeconds -Label 'Discovery' `
        -Parameters @{ TriageCollector = $CollectorPath; TriageController = $DeliveryController; TriageGroup = "$DesktopGroupName" }

    $machines = @($run.Output | Where-Object { $_.PSObject.Properties['ComputerName'] } | ForEach-Object {
        New-TriageInventoryEntry -ComputerName $_.ComputerName -DeliveryGroup $_.DeliveryGroup `
            -RegistrationState $_.RegistrationState -PowerState $_.PowerState `
            -InMaintenanceMode $_.InMaintenanceMode -SessionCount $_.SessionCount
    } | Sort-Object ComputerName)

    [PSCustomObject]@{
        Machines = $machines
        Error    = if ($run.Status -ne 'Completed') { $run.Error } else { '' }
    }
}

function Format-NameColumns {
    <#
    .SYNOPSIS
        Lays a list of names out in aligned columns, a few per line.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [string[]]$Name = @(),
        [int]$PerLine = 5,
        [string]$Indent = '         '
    )

    if (-not $Name.Count) { return @() }
    $width = ($Name | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 2
    for ($i = 0; $i -lt $Name.Count; $i += $PerLine) {
        $chunk = $Name[$i..([math]::Min($i + $PerLine, $Name.Count) - 1)]
        $Indent + (($chunk | ForEach-Object { $_.PadRight($width) }) -join '').TrimEnd()
    }
}

function Show-TriageInventory {
    [CmdletBinding()]
    param(
        [object[]]$Inventory = @(),
        [object[]]$PoweredOff = @()
    )

    if (-not $Inventory.Count) { return }
    $groups = @($Inventory | ForEach-Object { $_.DeliveryGroup } | Where-Object { $_ } | Select-Object -Unique)
    $groupText = if ($groups.Count -eq 1) { " in delivery group '$($groups[0])'" } elseif ($groups.Count) { " in $($groups.Count) delivery groups" } else { '' }
    Write-TriageLine -Status INFO -Message "$($Inventory.Count) session host(s) to check$($groupText):"
    foreach ($line in (Format-NameColumns -Name @($Inventory | ForEach-Object { $_.ComputerName }))) { Write-TriageLine -Status INFO -Message $line }

    $unreg = @($Inventory | Where-Object { $_.RegistrationState -and $_.RegistrationState -ne 'Registered' })
    if ($unreg.Count) {
        Write-TriageLine -Status WARN -Message ("Not registered with Citrix (checked anyway): {0}" -f (($unreg | ForEach-Object { "$($_.ComputerName) ($($_.RegistrationState))" }) -join ', '))
    }
    $maint = @($Inventory | Where-Object { $_.InMaintenanceMode -eq $true })
    if ($maint.Count) {
        Write-TriageLine -Status INFO -Message ("In maintenance mode: {0}" -f (($maint | ForEach-Object { $_.ComputerName }) -join ', '))
    }
    if ($PoweredOff.Count) {
        Write-TriageLine -Status INFO -Message ("Powered off, not checked: {0}" -f (($PoweredOff | ForEach-Object { $_.ComputerName }) -join ', '))
    }
}

function Get-TriageEstimate {
    <#
    .SYNOPSIS
        A rough run-time estimate, in minutes, for the plan shown before the checks start.
    .DESCRIPTION
        Deliberately rough and stated as such: per-server figures are typical times for a
        reachable server, and every step runs -ThrottleLimit servers at once.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][int]$ServerCount,
        [Parameter(Mandatory)][int]$ThrottleLimit,
        [Parameter(Mandatory)][int]$SampleSeconds,
        [switch]$Benchmark,
        [int]$HyperVHostCount = 0
    )

    $rounds = [math]::Ceiling($ServerCount / [double]$ThrottleLimit)
    $seconds  = $rounds * ($SampleSeconds + 30)   # health: sampling plus event reads
    $seconds += $ServerCount * 3                  # FSLogix settings, one server at a time
    $seconds += $rounds * (20 + 30 + 30)          # FSLogix logs, storage events, RDS events
    if ($Benchmark) { $seconds += 60 }
    $seconds += $HyperVHostCount * 180            # host diagnostics per host
    if ($HyperVHostCount) { $seconds += 300 }     # inventory, incl. Windows Update query
    [int][math]::Max(1, [math]::Ceiling($seconds / 60))
}

function Show-TriagePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$ServerCount,
        [Parameter(Mandatory)][int]$ThrottleLimit,
        [Parameter(Mandatory)][int]$SampleSeconds,
        [Parameter(Mandatory)][hashtable]$Tool,
        [switch]$SkipStorageBenchmark,
        [bool]$IsAdmin,
        [string]$ProfileSharePath,
        [string]$HyperVText
    )

    $n = "$ServerCount server(s)"
    $bench = if ($SkipStorageBenchmark) { 'skipped (-SkipStorageBenchmark)' }
             elseif (-not $IsAdmin) { 'skipped (needs an elevated console)' }
             elseif ($ProfileSharePath) { "from the first server to $ProfileSharePath" }
             else { 'from the first server to the profile share found in step 2' }
    $hv = if ($HyperVText) { $HyperVText } else { 'skipped (no -HyperVHost / -HyperVCluster)' }
    # An ordered dictionary, not an array of two-element arrays: @( @('a','b') ... ) unrolls
    # into one flat list of strings.
    $rows = [ordered]@{
        '1. Server health'       = $(if ($Tool.Health)        { "$n - $SampleSeconds s sampling + events" } else { 'skipped (tool not found)' })
        '2. FSLogix settings'    = $n
        '3. FSLogix logs'        = $(if ($Tool.FSLogixLogs)   { 'servers with FSLogix' } else { 'skipped (tool not found)' })
        '4. Storage events'      = $(if ($Tool.StorageEvents) { $n } else { 'skipped (tool not found)' })
        '5. RDS events'          = $(if ($Tool.RdsEvents)     { $n } else { 'skipped (tool not found)' })
        '6. Profile share speed' = $(if ($Tool.DiskSpd)       { $bench } else { 'skipped (tool not found)' })
        '7. Hyper-V hosts'       = $hv
    }
    $hvCount = if ($HyperVText) { [math]::Max(1, @($HyperVText -split ',').Count) } else { 0 }
    $minutes = Get-TriageEstimate -ServerCount $ServerCount -ThrottleLimit $ThrottleLimit -SampleSeconds $SampleSeconds `
        -Benchmark:(-not $SkipStorageBenchmark -and $IsAdmin -and [bool]$Tool.DiskSpd) -HyperVHostCount $hvCount

    Write-Host ''
    Write-TriageLine -Status INFO -Message "Plan - $ThrottleLimit server(s) at a time, roughly $minutes minute(s):"
    foreach ($r in $rows.GetEnumerator()) { Write-TriageLine -Status INFO -Message ("   {0,-24}{1}" -f $r.Key, $r.Value) }
}

function Write-TriageStepHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Number,
        [Parameter(Mandatory)][string]$Name,
        [string]$Detail
    )

    Write-Host ''
    $text = "Step $Number of 7: $Name"
    if ($Detail) { $text += " - $Detail" }
    Write-TriageLine -Status INFO -Message $text
}

# ---------------------------------------------------------------------------
# Tool runner
# ---------------------------------------------------------------------------
function Start-ToolProcess {
    <#
    .SYNOPSIS
        Starts one repository tool in its own Windows PowerShell 5.1 process and returns a
        handle for Complete-ToolProcess.
    .DESCRIPTION
        Parameters go in, and pipeline output comes back, through CliXml files in the tool's
        work folder, so real objects (and PSCredentials - protected with DPAPI for this user
        on this machine) cross the process boundary intact. The child's console output is
        captured with a transcript.

        A separate process gives three guarantees the tools cannot give in-process: a hung
        tool can be stopped at the time limit, a tool calling 'exit' or changing preference
        variables cannot affect this script, and the Citrix snap-ins always load (they are
        Windows PowerShell only). It also lets several tools run at once.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$Parameters = @{},
        [Parameter(Mandatory)][string]$WorkFolder
    )

    if (-not (Test-Path -LiteralPath $WorkFolder)) {
        New-Item -ItemType Directory -Path $WorkFolder -Force | Out-Null
    }
    $paramFile   = Join-Path $WorkFolder '_parameters.clixml'
    $outputFile  = Join-Path $WorkFolder '_output.clixml'
    $statusFile  = Join-Path $WorkFolder '_status.json'
    $consoleFile = Join-Path $WorkFolder 'console.log'

    $Parameters | Export-Clixml -LiteralPath $paramFile -Depth 3

    $qParam   = ConvertTo-PSLiteral $paramFile
    $qOutput  = ConvertTo-PSLiteral $outputFile
    $qStatus  = ConvertTo-PSLiteral $statusFile
    $qConsole = ConvertTo-PSLiteral $consoleFile
    $qScript  = ConvertTo-PSLiteral $ScriptPath

    # 'exit N' inside a called script returns to this bootstrap with $LASTEXITCODE = N, so the
    # finally block always writes a status file unless the process itself is killed.
    $bootstrap = @"
`$ErrorActionPreference = 'Continue'
`$ProgressPreference = 'SilentlyContinue'
`$status = [ordered]@{ Finished = `$false; ToolExitCode = `$null; Error = `$null; ObjectCount = 0 }
try { Start-Transcript -LiteralPath $qConsole -Force | Out-Null } catch { }
try {
    `$p = Import-Clixml -LiteralPath $qParam
    `$global:LASTEXITCODE = 0
    `$out = @(& $qScript @p)
    `$status.ToolExitCode = `$global:LASTEXITCODE
    `$status.ObjectCount = `$out.Count
    if (`$out.Count -gt 0) { `$out | Export-Clixml -LiteralPath $qOutput -Depth 5 }
    `$status.Finished = `$true
}
catch {
    `$status.Error = `$_.Exception.Message
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
    [pscustomobject]`$status | ConvertTo-Json | Set-Content -LiteralPath $qStatus -Encoding UTF8
}
"@
    # Run from a file rather than -EncodedCommand: the transcript header then names a readable
    # script instead of several KB of base64, and there is no command-line length limit.
    $runner = Join-Path $WorkFolder '_run.ps1'
    Set-Content -LiteralPath $runner -Value $bootstrap -Encoding UTF8

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName         = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi.Arguments        = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $runner
    $psi.UseShellExecute  = $false
    $psi.CreateNoWindow   = $true
    $psi.WorkingDirectory = $WorkFolder

    [PSCustomObject]@{
        Process     = [Diagnostics.Process]::Start($psi)
        Timer       = [Diagnostics.Stopwatch]::StartNew()
        ParamFile   = $paramFile
        OutputFile  = $outputFile
        StatusFile  = $statusFile
        ConsoleFile = $consoleFile
    }
}

function Complete-ToolProcess {
    <#
    .SYNOPSIS
        Collects a finished (or timed-out) tool process's results. Kills it first if it is
        still running.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Handle,
        [switch]$TimedOut,
        [int]$TimeoutSeconds = 0
    )

    $proc = $Handle.Process
    if (-not $proc.HasExited) {
        try { $proc.Kill() } catch { }
        [void]$proc.WaitForExit(10000)
    }
    $Handle.Timer.Stop()

    # The parameter file can hold a DPAPI-protected credential. Only this user on this machine
    # can decrypt it, but run folders get zipped onto tickets - it has no reason to outlive the run.
    Remove-Item -LiteralPath $Handle.ParamFile -Force -ErrorAction SilentlyContinue

    $status = $null
    if (Test-Path -LiteralPath $Handle.StatusFile) {
        try { $status = Get-Content -LiteralPath $Handle.StatusFile -Raw | ConvertFrom-Json } catch { }
    }
    $output = @()
    if (Test-Path -LiteralPath $Handle.OutputFile) {
        try { $output = @(Import-Clixml -LiteralPath $Handle.OutputFile) } catch { }
    }
    $console = ''
    if (Test-Path -LiteralPath $Handle.ConsoleFile) {
        $console = Get-Content -LiteralPath $Handle.ConsoleFile -Raw -ErrorAction SilentlyContinue
    }

    $result = 'Completed'
    $errorText = ''
    if ($TimedOut) {
        $result = 'TimedOut'
        $errorText = "Stopped after $TimeoutSeconds seconds."
    }
    elseif (-not $status -or -not $status.Finished) {
        $result = 'Failed'
        $exitCode = '?'
        try { $exitCode = $proc.ExitCode } catch { }
        $errorText = if ($status -and $status.Error) { $status.Error } else { "The tool process ended without reporting a result (exit code $exitCode)." }
    }
    elseif ($status.ToolExitCode -and $status.ToolExitCode -ne 0) {
        $result = 'Failed'
        $errorText = "The tool exited with code $($status.ToolExitCode). See $($Handle.ConsoleFile)."
    }

    [PSCustomObject]@{
        Status      = $result
        Output      = $output
        Error       = $errorText
        ConsoleText = $console
        ConsoleFile = $Handle.ConsoleFile
        Duration    = $Handle.Timer.Elapsed
    }
}

function Invoke-ToolScript {
    <#
    .SYNOPSIS
        Runs one repository tool in its own process and waits for it. See Start-ToolProcess.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [hashtable]$Parameters = @{},
        [Parameter(Mandatory)][string]$WorkFolder,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 1800,
        [string]$Label = (Split-Path -Leaf $ScriptPath)
    )

    $handle = Start-ToolProcess -ScriptPath $ScriptPath -Parameters $Parameters -WorkFolder $WorkFolder
    $timedOut = $false
    $nextNotice = 60
    while (-not $handle.Process.WaitForExit(2000)) {
        if ($handle.Timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; break }
        if ($handle.Timer.Elapsed.TotalSeconds -ge $nextNotice) {
            Write-TriageLine -Status INFO -Message ("      {0} still running ({1:mm\:ss})" -f $Label, $handle.Timer.Elapsed)
            $nextNotice += 60
        }
    }
    Complete-ToolProcess -Handle $handle -TimedOut:$timedOut -TimeoutSeconds $TimeoutSeconds
}

function Format-Elapsed {
    [CmdletBinding()]
    [OutputType([string])]
    param([TimeSpan]$Elapsed)

    if ($Elapsed.TotalHours -ge 1) { return '{0}:{1:mm\:ss}' -f [int][math]::Floor($Elapsed.TotalHours), $Elapsed }
    '{0:m\:ss}' -f $Elapsed
}

function Invoke-ToolBatch {
    <#
    .SYNOPSIS
        Runs one tool against many servers, a few at a time, reporting each server as it
        finishes.
    .DESCRIPTION
        Each job is { Target; ScriptPath; Parameters; WorkFolder }. Up to -ThrottleLimit tool
        processes run at once. As each finishes, one console line reports that server's
        result, using -Describe to turn the tool's output into a short verdict. A progress
        bar shows what is still running, and a heartbeat line every minute names any server
        that is taking a while - so a 15-server run is never a silent wait.

        Returns one { Target; Result; Job } per job, in the order they were given.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Job,
        [ValidateRange(1, 32)][int]$ThrottleLimit = 4,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 1800,
        [string]$Activity = 'Running',
        [scriptblock]$Describe
    )

    $total = $Job.Count
    if ($total -eq 0) { return @() }

    $width   = [math]::Max(8, ($Job | ForEach-Object { "$($_.Target)".Length } | Measure-Object -Maximum).Maximum)
    $digits  = "$total".Length
    $pending = New-Object System.Collections.Queue
    $index   = 0
    foreach ($j in $Job) { $index++; $pending.Enqueue([PSCustomObject]@{ Index = $index; Job = $j }) }
    $running = New-Object System.Collections.Generic.List[object]
    $results = @{}
    $done = 0
    $lastActivity = [Diagnostics.Stopwatch]::StartNew()

    while ($pending.Count -or $running.Count) {
        while ($running.Count -lt $ThrottleLimit -and $pending.Count) {
            $item = $pending.Dequeue()
            try {
                $handle = Start-ToolProcess -ScriptPath $item.Job.ScriptPath -Parameters $item.Job.Parameters -WorkFolder $item.Job.WorkFolder
                $running.Add([PSCustomObject]@{ Item = $item; Handle = $handle })
            }
            catch {
                $done++
                $results[$item.Index] = [PSCustomObject]@{
                    Target = $item.Job.Target; Job = $item.Job
                    Result = [PSCustomObject]@{ Status = 'Failed'; Output = @(); Error = $_.Exception.Message; ConsoleText = ''; ConsoleFile = ''; Duration = [TimeSpan]::Zero }
                }
                Write-TriageLine -Status FAIL -Message ("   [{0}/{1}] {2}  could not start: {3}" -f "$($item.Index)".PadLeft($digits), $total, "$($item.Job.Target)".PadRight($width), $_.Exception.Message)
            }
        }

        Start-Sleep -Milliseconds 500

        foreach ($r in $running.ToArray()) {
            $timedOut = -not $r.Handle.Process.HasExited -and $r.Handle.Timer.Elapsed.TotalSeconds -ge $TimeoutSeconds
            if (-not $r.Handle.Process.HasExited -and -not $timedOut) { continue }

            $result = Complete-ToolProcess -Handle $r.Handle -TimedOut:$timedOut -TimeoutSeconds $TimeoutSeconds
            [void]$running.Remove($r)
            $done++
            $lastActivity.Restart()
            $results[$r.Item.Index] = [PSCustomObject]@{ Target = $r.Item.Job.Target; Job = $r.Item.Job; Result = $result }

            $line = switch ($result.Status) {
                'TimedOut' { @{ Status = 'FAIL'; Text = "timed out after $(Format-Elapsed ([TimeSpan]::FromSeconds($TimeoutSeconds)))" } }
                'Failed'   { @{ Status = 'FAIL'; Text = "failed: $($result.Error)" } }
                default {
                    $d = if ($Describe) { & $Describe $r.Item.Job $result } else { $null }
                    if ($d) { $d } else { @{ Status = 'PASS'; Text = 'done' } }
                }
            }
            Write-TriageLine -Status $line.Status -Message ("   [{0}/{1}] {2}  {3}  ({4})" -f `
                "$($r.Item.Index)".PadLeft($digits), $total, "$($r.Item.Job.Target)".PadRight($width), $line.Text, (Format-Elapsed $result.Duration))
        }

        $names = ($running | ForEach-Object { $_.Item.Job.Target }) -join ', '
        $statusText = if ($names) { "$done of $total done - running: $names" } else { "$done of $total done" }
        Write-Progress -Activity $Activity -Status $statusText -PercentComplete ([int](100 * $done / $total))

        if ($running.Count -and $lastActivity.Elapsed.TotalSeconds -ge 60) {
            $slow = ($running | ForEach-Object { '{0} ({1})' -f $_.Item.Job.Target, (Format-Elapsed $_.Handle.Timer.Elapsed) }) -join ', '
            Write-TriageLine -Status INFO -Message "      still running: $slow"
            $lastActivity.Restart()
        }
    }
    Write-Progress -Activity $Activity -Completed

    foreach ($i in 1..$total) { $results[$i] }
}

function Get-NewestFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$Filter
    )

    Get-ChildItem -LiteralPath $Folder -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

# ---------------------------------------------------------------------------
# FSLogix settings discovery
# ---------------------------------------------------------------------------
function Get-FSLogixHostConfig {
    <#
    .SYNOPSIS
        Reads a session host's FSLogix profile and logging settings.
    .DESCRIPTION
        Tries WinRM first (honours -Credential), then the Remote Registry service. If both
        fail it returns the documented defaults and says so, so later steps can still try
        the default log folder.
        Registry locations and defaults:
        https://learn.microsoft.com/fslogix/reference-configuration-settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $raw = $null
    $source = 'Default'
    $problem = ''

    $read = {
        $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -ErrorAction SilentlyContinue
        $l = Get-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Logging' -ErrorAction SilentlyContinue
        $dir = if ($l -and $l.LogDir) { $l.LogDir } else { '%ProgramData%\FSLogix\Logs' }
        [PSCustomObject]@{
            Installed            = [bool](Test-Path 'HKLM:\SOFTWARE\FSLogix\Apps')
            Enabled              = if ($p) { $p.Enabled } else { $null }
            VHDLocations         = if ($p) { $p.VHDLocations } else { $null }
            CCDLocations         = if ($p) { $p.CCDLocations } else { $null }
            LogDir               = [Environment]::ExpandEnvironmentVariables($dir)
            LogFileKeepingPeriod = if ($l) { $l.LogFileKeepingPeriod } else { $null }
        }
    }

    try {
        $ic = @{ ComputerName = $ComputerName; ScriptBlock = $read; ErrorAction = 'Stop' }
        if ($Credential) { $ic.Credential = $Credential }
        $raw = Invoke-Command @ic
        $source = 'WinRM'
    }
    catch {
        $problem = "WinRM: $($_.Exception.Message)"
        try {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $pk = $hklm.OpenSubKey('SOFTWARE\FSLogix\Profiles')
            $lk = $hklm.OpenSubKey('SOFTWARE\FSLogix\Logging')
            $ak = $hklm.OpenSubKey('SOFTWARE\FSLogix\Apps')
            # %ProgramData% cannot be expanded remotely through the registry API; C:\ProgramData
            # is its value on every supported Windows build unless deliberately relocated.
            $dir = if ($lk -and $lk.GetValue('LogDir')) { $lk.GetValue('LogDir') } else { '%ProgramData%\FSLogix\Logs' }
            $raw = [PSCustomObject]@{
                Installed            = [bool]$ak
                Enabled              = if ($pk) { $pk.GetValue('Enabled') } else { $null }
                VHDLocations         = if ($pk) { $pk.GetValue('VHDLocations') } else { $null }
                CCDLocations         = if ($pk) { $pk.GetValue('CCDLocations') } else { $null }
                LogDir               = $dir -replace '(?i)%ProgramData%', 'C:\ProgramData'
                LogFileKeepingPeriod = if ($lk) { $lk.GetValue('LogFileKeepingPeriod') } else { $null }
            }
            $hklm.Close()
            $source = 'RemoteRegistry'
        }
        catch {
            $problem = "$problem; Remote Registry: $($_.Exception.Message)"
        }
    }

    if (-not $raw) {
        $raw = [PSCustomObject]@{
            Installed = $null; Enabled = $null; VHDLocations = $null; CCDLocations = $null
            LogDir = 'C:\ProgramData\FSLogix\Logs'; LogFileKeepingPeriod = $null
        }
    }

    # LogFileKeepingPeriod default is 2 days when the value is absent.
    $keep = if ($null -ne $raw.LogFileKeepingPeriod) { [int]$raw.LogFileKeepingPeriod } else { 2 }

    [PSCustomObject]@{
        ComputerName    = $ComputerName
        Source          = $source
        Installed       = $raw.Installed
        ProfilesEnabled = $raw.Enabled
        VHDLocations    = @(Split-FSLogixLocation -Value $raw.VHDLocations)
        CCDLocations    = @(Get-CcdConnectionPath -Value $raw.CCDLocations)
        LogDir          = $raw.LogDir
        LogDirUnc       = ConvertTo-AdminSharePath -ComputerName $ComputerName -LocalPath $raw.LogDir
        LogKeepDays     = $keep
        Problem         = $problem
    }
}

# ---------------------------------------------------------------------------
# Hyper-V helpers
# ---------------------------------------------------------------------------
function Test-HyperVHostAccess {
    <#
    .SYNOPSIS
        Works out whether this user can run Hyper-V checks on a host, and why not if not.
    .DESCRIPTION
        Distinguishes the cases that need different fixes: the host is down or WinRM is
        blocked (Unreachable), remoting is refused (NoRemoting - you are not an admin there),
        remoting works but Hyper-V refuses Get-VM (NoHyperVRights), or the host has no Hyper-V
        module at all (NotHyperV).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )

    $probe = {
        $has = [bool](Get-Command Get-VM -ErrorAction SilentlyContinue)
        $vms = @()
        $err = $null
        if ($has) {
            try { $vms = @(Get-VM -ErrorAction Stop | ForEach-Object { $_.Name }) }
            catch { $err = $_.Exception.Message }
        }
        [PSCustomObject]@{ Host = $env:COMPUTERNAME; HasHyperV = $has; VMs = $vms; Error = $err }
    }

    try {
        $ic = @{ ComputerName = $ComputerName; ScriptBlock = $probe; ErrorAction = 'Stop' }
        if ($Credential) { $ic.Credential = $Credential }
        $r = Invoke-Command @ic
    }
    catch {
        $msg = $_.Exception.Message
        $state = if ($msg -match 'Access is denied|AccessDenied|UnauthorizedAccess' -or
                     "$($_.FullyQualifiedErrorId)" -match 'AccessDenied') { 'NoRemoting' } else { 'Unreachable' }
        return [PSCustomObject]@{ ComputerName = $ComputerName; State = $state; VMs = @(); Detail = $msg }
    }

    $state = 'OK'
    $detail = ''
    if (-not $r.HasHyperV) { $state = 'NotHyperV'; $detail = 'The Hyper-V PowerShell module is not installed on this host.' }
    elseif ($r.Error)      { $state = 'NoHyperVRights'; $detail = $r.Error }

    [PSCustomObject]@{ ComputerName = $ComputerName; State = $state; VMs = @($r.VMs); Detail = $detail }
}

function Invoke-HyperVHostDiagnosticRemote {
    <#
    .SYNOPSIS
        Runs Get-HyperVHostDiagnostics.ps1 on a Hyper-V host and returns its log text.
    .DESCRIPTION
        That script only inspects the machine it runs on, so its text is sent to the host and
        run there. Its log goes to a unique temporary folder on the host, which is read back
        and deleted. Runs as a job so a slow host cannot exceed the step time limit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$ScriptText,
        [string]$TargetVM,
        [int]$DaysBack = 7,
        [int]$TimeoutSeconds = 900,
        [System.Management.Automation.PSCredential]$Credential
    )

    $remote = {
        param($Code, $Vm, $Days)
        $dir = Join-Path $env:TEMP ('CitrixPerfTriage_' + [guid]::NewGuid().ToString('N'))
        try {
            $sb = [scriptblock]::Create($Code)
            $p = @{ DaysBack = $Days; OutputPath = $dir }
            if ($Vm) { $p.VMName = $Vm }
            & $sb @p *> $null
            $log = Get-ChildItem -LiteralPath $dir -Filter '*.log' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($log) { Get-Content -LiteralPath $log.FullName -Raw }
        }
        finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $ic = @{
        ComputerName = $ComputerName
        ScriptBlock  = $remote
        ArgumentList = @($ScriptText, $TargetVM, $DaysBack)
        AsJob        = $true
    }
    if ($Credential) { $ic.Credential = $Credential }
    $job = Invoke-Command @ic
    try {
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
            throw "Timed out after $TimeoutSeconds seconds."
        }
        $text = Receive-Job -Job $job -ErrorAction Stop
        ($text | Out-String).Trim()
    }
    finally {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

function New-HyperVHandoffPackage {
    <#
    .SYNOPSIS
        Builds a folder the Hyper-V administrators can run as-is to collect host evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][object[]]$Blocked,
        [string[]]$VMNames = @(),
        [int]$DaysBack = 7,
        [string]$Cluster,
        [Parameter(Mandatory)][string]$HostScriptPath,
        [string]$InventoryScriptPath
    )

    New-Item -ItemType Directory -Path $Folder -Force | Out-Null
    Copy-Item -LiteralPath $HostScriptPath -Destination $Folder -Force
    if ($InventoryScriptPath) { Copy-Item -LiteralPath $InventoryScriptPath -Destination $Folder -Force }

    $requestedBy = "$env:USERDOMAIN\$env:USERNAME"
    $vmList = if ($VMNames.Count) { ($VMNames | ForEach-Object { ConvertTo-PSLiteral $_ }) -join ', ' } else { '' }

    $collector = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collects read-only Hyper-V host evidence for a Citrix performance investigation.

.DESCRIPTION
    Generated by Invoke-CitrixPerfTriage.ps1 on {{GENERATED}} for {{REQUESTEDBY}}.

    Run this ON a Hyper-V host, from this folder. It runs the two scripts next to it:
      - Get-HyperVHostDiagnostics.ps1          host storage, cluster, event log and VM checks
      - Get-HyperVInfrastructureInventory.ps1  host hardware, volumes and VM configuration

    Both are read-only: they make no changes to the host or any VM. The only files written
    are the results in -OutputPath and a zip of them.

.PARAMETER OutputPath
    Where to write the results. Defaults to a folder on your desktop.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) ("HyperV-Evidence_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HHmmss')))
)

$vmNames  = @({{VMLIST}})
$daysBack = {{DAYSBACK}}
$here     = $PSScriptRoot

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$onThisHost = @()
if (Get-Command Get-VM -ErrorAction SilentlyContinue) {
    $onThisHost = @(Get-VM | Where-Object { $vmNames -contains $_.Name } | ForEach-Object { $_.Name })
}

if ($onThisHost.Count -eq 0) {
    Write-Host "None of the VMs ($($vmNames -join ', ')) are on $env:COMPUTERNAME - running the host-wide checks only." -ForegroundColor Yellow
    & (Join-Path $here 'Get-HyperVHostDiagnostics.ps1') -DaysBack $daysBack -OutputPath (Join-Path $OutputPath 'HostDiagnostics')
}
foreach ($vm in $onThisHost) {
    Write-Host "Checking VM $vm ..." -ForegroundColor Cyan
    & (Join-Path $here 'Get-HyperVHostDiagnostics.ps1') -VMName $vm -DaysBack $daysBack -OutputPath (Join-Path $OutputPath "HostDiagnostics_$vm")
}

try {
    & (Join-Path $here 'Get-HyperVInfrastructureInventory.ps1') -OutputPath (Join-Path $OutputPath 'Inventory')
}
catch {
    Write-Warning "Inventory failed: $($_.Exception.Message)"
}

$zip = "$OutputPath.zip"
Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zip -Force
Write-Host ""
Write-Host "Done. Please send this file to {{REQUESTEDBY}}:" -ForegroundColor Green
Write-Host "  $zip" -ForegroundColor Green
'@
    $collector = $collector.Replace('{{GENERATED}}', (Get-Date -Format 'yyyy-MM-dd HH:mm')).
        Replace('{{REQUESTEDBY}}', $requestedBy).
        Replace('{{VMLIST}}', $vmList).
        Replace('{{DAYSBACK}}', [string]$DaysBack)
    Set-Content -LiteralPath (Join-Path $Folder 'Collect-HyperVEvidence.ps1') -Value $collector -Encoding UTF8

    $reasonText = @{
        NoRemoting     = 'remote PowerShell was refused (not an administrator on the host)'
        NoHyperVRights = 'remote PowerShell works, but Hyper-V refused to list the VMs'
        Unreachable    = 'the host could not be contacted over WinRM from my workstation'
        NotHyperV      = 'the Hyper-V PowerShell module was not found'
        ClusterLookup  = 'the cluster''s node list could not be read'
    }
    $blockedLines = foreach ($b in $Blocked) {
        $why = if ($reasonText.ContainsKey($b.State)) { $reasonText[$b.State] } else { $b.State }
        "  - $($b.ComputerName): $why"
    }

    $ownerHint = if ($Cluster -and $VMNames.Count) {
        @(
            ''
            'To find which cluster node each VM is on:'
            ''
            "  Get-ClusterGroup -Cluster $Cluster | Where-Object Name -in $vmList | Select-Object Name, OwnerNode"
            ''
            '(A VM''s cluster role is usually named after the VM. If the list is empty, check'
            'Failover Cluster Manager > Roles.)'
        ) -join "`r`n"
    } else { '' }

    $readme = @"
Hyper-V evidence request
========================

Requested by : $requestedBy
Generated    : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Why          : Performance investigation on Citrix session hosts. I need read-only
               evidence from the Hyper-V host(s) they run on, and I could not collect it
               myself because:
$($blockedLines -join "`r`n")

VMs of interest : $(if ($VMNames.Count) { $VMNames -join ', ' } else { '(none specified - host-wide checks only)' })
Cluster         : $(if ($Cluster) { $Cluster } else { '(standalone hosts)' })


WHAT TO RUN
-----------
On each Hyper-V host that runs one of the VMs above (or on each node listed above):

  1. Copy this folder to the host (or open it from a share the host can reach).
  2. Open PowerShell AS ADMINISTRATOR in this folder.
  3. Run:

       powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-HyperVEvidence.ps1

  4. Send me the .zip it names at the end (written to your desktop).
$ownerHint

It takes a few minutes per host: it reads $DaysBack days of event logs and queries
Windows Update for pending updates.


WHAT IT DOES
------------
Read-only. It makes no changes to the host, the cluster or any VM. It reads:
  - VM state, checkpoints, virtual disk type/fragmentation, network adapters
  - Physical disk health and error counters, Cluster Shared Volume state
  - System and Hyper-V event logs (errors/warnings), host reboot history
  - Host hardware, volumes, virtual switches, VM CPU/memory configuration

The only files it writes are its own results and the zip, in the output folder.
The scripts are plain text - please review them before running if you prefer.


IF YOU WOULD RATHER GRANT ACCESS
--------------------------------
Membership of the host's local Administrators group (for the duration of the
investigation) lets me run this myself. Alternatively, you can type your own
credential into my script:  -HyperVCredential (Get-Credential)
"@
    Set-Content -LiteralPath (Join-Path $Folder 'README-HyperV-Team.txt') -Value $readme -Encoding UTF8

    $Folder
}

# ---------------------------------------------------------------------------
# HTML summary
# ---------------------------------------------------------------------------
function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-TriageHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [object[]]$Step = @(),
        [object[]]$Finding = @(),
        [object[]]$Server = @(),
        [object[]]$VmConfig = @(),
        [object]$Benchmark
    )

    $h = { param($v) ConvertTo-HtmlText $v }

    $verdictClass = @{ Healthy = 'pass'; Degraded = 'warn'; Critical = 'fail'; Unreachable = 'fail' }
    $serverHtml = ''
    if ($Server.Count) {
        $pct = { param($v) if ($null -eq $v -or "$v" -eq '') { '' } else { '{0}%' -f $v } }
        $serverRows = ($Server | Sort-Object @{ Expression = { switch ($_.Verdict) { 'Critical' { 0 } 'Unreachable' { 1 } 'Degraded' { 2 } 'Healthy' { 3 } default { 4 } } } }, Server | ForEach-Object {
            $cls = if ($verdictClass.ContainsKey("$($_.Verdict)")) { $verdictClass["$($_.Verdict)"] } else { 'unknown' }
            $link = if ($_.Report) {
                $rel = (Get-RelativeReportPath -RunFolder $Context.RunFolder -Path $_.Report) -replace '\\', '/'
                "<a href='{0}'>details</a>" -f (& $h $rel)
            } else { '' }
            $reg = if ($_.Registration -and $_.Registration -ne 'Registered') { "<span class='pill warn'>$(& $h $_.Registration)</span>" } else { & $h $_.Registration }
            "<tr><td class='mono'>{0}</td><td><span class='pill {1}'>{2}</span></td><td>{3}</td><td class='num'>{4}</td><td class='num'>{5}</td><td class='num'>{6}</td><td class='num'>{7}</td><td class='num'>{8}</td><td class='num'>{9}</td><td>{10}</td></tr>" -f `
                (& $h $_.Server), $cls, (& $h $_.Verdict), $reg, (& $h (& $pct $_.CpuAvg)), (& $h (& $pct $_.CpuPeak)),
                (& $h (& $pct $_.MemoryAvg)), (& $h (& $pct $_.FullestDisk)), (& $h $_.Sessions), (& $h $_.Issues), $link
        }) -join "`n"
        $serverHtml = @"
<section>
  <h2>Servers</h2>
  <table>
    <thead><tr><th>Server</th><th>Health</th><th>Citrix</th><th class='num'>CPU avg</th><th class='num'>CPU peak</th><th class='num'>Memory avg</th><th class='num'>Fullest disk</th><th class='num'>Sessions</th><th class='num'>Issues</th><th>Report</th></tr></thead>
    <tbody>$serverRows</tbody>
  </table>
</section>
"@
    }
    $overall = Get-TriageOverallStatus -Finding $Finding -Step $Step
    $crit = @($Finding | Where-Object Severity -eq 'Critical').Count
    $warn = @($Finding | Where-Object Severity -eq 'Warning').Count
    $info = @($Finding | Where-Object Severity -eq 'Info').Count

    $overallText = switch ($overall) {
        'Critical'   { 'Serious problems found' }
        'Warning'    { 'Problems worth looking at' }
        'Incomplete' { 'Checks did not finish - no verdict. See What ran below.' }
        default      { 'Nothing wrong found' }
    }
    $overallClass = switch ($overall) { 'Critical' { 'fail' } 'Warning' { 'warn' } 'Incomplete' { 'fail' } default { 'pass' } }

    $sevClass = @{ Critical = 'fail'; Warning = 'warn'; Info = 'unknown' }
    $sevOrder = @{ Critical = 0; Warning = 1; Info = 2 }

    $attention = @($Finding | Where-Object { $_.Severity -ne 'Info' } |
        Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Area, Target)
    $notes = @($Finding | Where-Object Severity -eq 'Info' | Sort-Object Area, Target)

    $findingRows = {
        param($rows)
        ($rows | ForEach-Object {
            "<tr><td><span class='pill {0}'>{1}</span></td><td>{2}</td><td class='mono'>{3}</td><td>{4}</td><td class='muted'>{5}</td></tr>" -f `
                $sevClass[$_.Severity], (& $h $_.Severity), (& $h $_.Area), (& $h $_.Target), (& $h $_.Finding), (& $h $_.Evidence)
        }) -join "`n"
    }

    $stepClass = @{ Completed = 'pass'; Partial = 'warn'; Handoff = 'warn'; Skipped = 'unknown'; Failed = 'fail'; TimedOut = 'fail' }
    $stepRows = ($Step | ForEach-Object {
        $link = if ($_.ReportPath) {
            $rel = Get-RelativeReportPath -RunFolder $Context.RunFolder -Path $_.ReportPath
            "<a href='{0}'>{1}</a>" -f (& $h ($rel -replace '\\', '/')), (& $h (Split-Path -Leaf $_.ReportPath))
        } else { '' }
        $took = if ($_.Duration.TotalSeconds -ge 1) { '{0:mm\:ss}' -f $_.Duration } else { '' }
        "<tr><td>{0}</td><td><span class='pill {1}'>{2}</span></td><td>{3}</td><td class='mono'>{4}</td><td>{5}</td></tr>" -f `
            (& $h $_.Step), $stepClass[$_.Status], (& $h $_.Status), (& $h $_.Detail), $took, $link
    }) -join "`n"

    $benchHtml = ''
    if ($Benchmark) {
        $benchHtml = @"
<section>
  <h2>Profile share speed</h2>
  <p class='muted'>Measured from <span class='mono'>$(& $h $Benchmark.From)</span> to <span class='mono'>$(& $h $Benchmark.Target)</span> using the $(& $h $Benchmark.Workload) workload. The DiskSpd report has the full breakdown and its own assessment.</p>
  <div class='tiles'>
    <div class='tile'><div class='tile-label'>Operations per second</div><div class='tile-value'>$(& $h ('{0:N0}' -f $Benchmark.IOPS))</div></div>
    <div class='tile'><div class='tile-label'>Average response time</div><div class='tile-value'>$(& $h ('{0:N1}' -f $Benchmark.AvgLatencyMs)) ms</div></div>
    <div class='tile'><div class='tile-label'>Read speed</div><div class='tile-value'>$(& $h ('{0:N1}' -f $Benchmark.ReadMBps)) MB/s</div></div>
    <div class='tile'><div class='tile-label'>Write speed</div><div class='tile-value'>$(& $h ('{0:N1}' -f $Benchmark.WriteMBps)) MB/s</div></div>
  </div>
</section>
"@
    }

    $vmHtml = ''
    if ($VmConfig.Count) {
        $vmRows = ($VmConfig | ForEach-Object {
            "<tr><td class='mono'>{0}</td><td class='mono'>{1}</td><td>{2}</td><td class='num'>{3}</td><td>{4}</td><td class='num'>{5}</td><td class='num'>{6}</td></tr>" -f `
                (& $h $_.VMName), (& $h $_.HostName), (& $h $_.State), (& $h $_.vCPU), (& $h $_.Mem_Dynamic), (& $h $_.Mem_StartupGB), (& $h $_.Mem_AssignedGB)
        }) -join "`n"
        $vmHtml = @"
<section>
  <h2>Session host VMs in Hyper-V</h2>
  <table>
    <thead><tr><th>VM</th><th>Hyper-V host</th><th>State</th><th class='num'>vCPUs</th><th>Dynamic memory</th><th class='num'>Startup GB</th><th class='num'>Assigned GB</th></tr></thead>
    <tbody>$vmRows</tbody>
  </table>
</section>
"@
    }

    $handoffHtml = ''
    if ($Context.HandoffFolder) {
        $rel = (Get-RelativeReportPath -RunFolder $Context.RunFolder -Path $Context.HandoffFolder) -replace '\\', '/'
        $handoffHtml = @"
<section class='callout'>
  <h2>Hyper-V checks need someone with access</h2>
  <p>Some Hyper-V hosts could not be checked from this account. A ready-to-run package is in
  <a class='mono' href='$(& $h $rel)'>$(& $h $rel)</a> - send the whole folder to the Hyper-V
  administrators. Its <span class='mono'>README-HyperV-Team.txt</span> explains what to run and confirms it changes nothing.</p>
</section>
"@
    }

    $attentionHtml = if ($attention.Count) {
        "<table><thead><tr><th>Severity</th><th>Area</th><th>Machine</th><th>What was found</th><th>Evidence</th></tr></thead><tbody>$(& $findingRows $attention)</tbody></table>"
    } elseif ($overall -eq 'Incomplete') {
        "<p class='muted'>Nothing was flagged, but not every check ran, so this is not a clean bill of health. The steps below show what failed or was skipped.</p>"
    } else {
        "<p class='muted'>No problems were flagged by any of the checks that ran. Check the steps below for anything that was skipped.</p>"
    }
    $notesHtml = if ($notes.Count) {
        "<section><h2>Other notes</h2><table><thead><tr><th>Severity</th><th>Area</th><th>Machine</th><th>Note</th><th>Evidence</th></tr></thead><tbody>$(& $findingRows $notes)</tbody></table></section>"
    } else { '' }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Citrix Performance Triage</title>
<style>
:root {
  --bg:#0e1116; --panel:#161b22; --panel2:#1c232c; --line:#2a323d;
  --text:#e6edf3; --muted:#8b98a5;
  --accent:#5dade2;
  --pass:#3fb950; --warn:#d29922; --fail:#f85149; --unknown:#6e7f91;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg:#f6f8fa; --panel:#ffffff; --panel2:#eef1f4; --line:#d0d7de;
    --text:#1f2328; --muted:#57606a;
    --accent:#1f6fa8;
    --pass:#1a7f37; --warn:#9a6700; --fail:#cf222e; --unknown:#6e7781;
  }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI", system-ui, sans-serif; }
main { max-width:1200px; margin:0 auto; padding:24px 16px 48px; }
header { border-bottom:1px solid var(--line); padding-bottom:16px; margin-bottom:20px; }
h1 { font-size:24px; margin:0 0 8px; letter-spacing:-0.01em; }
h2 { font-size:16px; margin:0 0 12px; }
.meta { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:8px 24px; color:var(--muted); }
.meta b { color:var(--text); font-weight:600; }
.mono { font-family:Consolas, "Cascadia Mono", monospace; font-size:13px; }
.muted { color:var(--muted); }
section { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:16px; margin-bottom:16px; overflow-x:auto; }
.verdict { display:flex; flex-wrap:wrap; align-items:center; gap:16px; border-left:4px solid var(--$overallClass); }
.verdict .big { font-size:20px; font-weight:700; }
.counts span { margin-right:16px; }
.callout { border-left:4px solid var(--warn); }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:var(--panel2); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); }
tr:hover td { background:var(--panel2); }
td.num, th.num { text-align:right; }
.pill { display:inline-block; padding:1px 8px; border-radius:3px; font-size:12px; font-weight:600; color:#fff; white-space:nowrap; }
.pill.pass { background:var(--pass); } .pill.warn { background:var(--warn); }
.pill.fail { background:var(--fail); } .pill.unknown { background:var(--unknown); }
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; }
.tile { background:var(--panel2); border:1px solid var(--line); border-radius:4px; padding:12px; }
.tile-label { color:var(--muted); font-size:12px; }
.tile-value { font-size:22px; font-weight:700; }
a { color:var(--accent); }
footer { color:var(--muted); font-size:12px; margin-top:24px; }
</style>
</head>
<body>
<main>
<header>
  <h1>Citrix performance triage</h1>
  <div class="meta">
    <div>Session hosts: <b class="mono">$(& $h ($Context.Targets -join ', '))</b></div>
    <div>Time window: <b>$(& $h $Context.WindowStart.ToString('yyyy-MM-dd HH:mm')) to $(& $h $Context.WindowEnd.ToString('yyyy-MM-dd HH:mm'))</b></div>
    <div>Hyper-V: <b class="mono">$(& $h $Context.HyperVText)</b></div>
    <div>Run by: <b>$(& $h $Context.RunBy)</b> on <b class="mono">$(& $h $env:COMPUTERNAME)</b></div>
  </div>
</header>

<section class="verdict">
  <span class="pill $overallClass">$(& $h $overall)</span>
  <span class="big">$(& $h $overallText)</span>
  <span class="counts muted"><span>$crit serious</span><span>$warn to review</span><span>$info notes</span></span>
</section>

<section>
  <h2>Look here first</h2>
  $attentionHtml
</section>

$serverHtml
$handoffHtml
$benchHtml
$vmHtml

<section>
  <h2>What ran</h2>
  <table>
    <thead><tr><th>Step</th><th>Result</th><th>Detail</th><th>Took</th><th>Report</th></tr></thead>
    <tbody>$stepRows</tbody>
  </table>
</section>

$notesHtml

<footer>Generated by Invoke-CitrixPerfTriage.ps1 at $(& $h (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')). Run folder: <span class="mono">$(& $h $Context.RunFolder)</span></footer>
</main>
</body>
</html>
"@
}

# -LoadFunctionsOnly lets the Pester suite dot-source everything above without running a
# collection.
if ($LoadFunctionsOnly) { return }

# ===========================================================================
# MAIN
# ===========================================================================
if ($ComputerName) { $ComputerName = Split-TriageNameList $ComputerName }
if ($HyperVHost)   { $HyperVHost   = Split-TriageNameList $HyperVHost }
if ($VMName)       { $VMName       = Split-TriageNameList $VMName }

$searchRoots = Get-TriageToolSearchRoot -ToolRoot $ToolRoot -ScriptFolder $PSScriptRoot
$tool = @{}
$missingTools = @()
foreach ($k in $script:ToolPaths.Keys) {
    $found = Resolve-TriageTool -RelativePath $script:ToolPaths[$k] -SearchRoot $searchRoots
    if ($found) { $tool[$k] = $found } else { $missingTools += (Split-Path -Parent $script:ToolPaths[$k]) }
}

$kitHint = @(
    'This script needs its tool folders next to it. The easy way is a kit - on your workstation, from the repository:'
    ''
    '    .\Citrix-PerfTriage\Invoke-CitrixPerfTriage.ps1 -CreateKit C:\Temp\CitrixPerfTriageKit.zip'
    ''
    'Copy that zip here, extract it, and run Invoke-CitrixPerfTriage.ps1 from inside the extracted folder.'
) -join "`r`n"

# --- Kit mode: pack everything up and stop --------------------------------------------------
if ($CreateKit) {
    if ($missingTools.Count) {
        throw "Cannot build a kit - these tool folders were not found: $($missingTools -join ', '). Run -CreateKit from the repository copy of this script."
    }
    $kit = New-TriageKit -Destination $CreateKit -ScriptPath $PSCommandPath -Tools $tool
    Write-TriageLine -Status PASS -Message "Kit created: $kit"
    Write-TriageLine -Status INFO -Message 'Copy it to the server you will run from (the Delivery Controller is ideal), extract it, and follow README-FIRST.txt.'
    return
}

if ($tool.Count -eq 0) {
    Write-TriageLine -Status FAIL -Message "None of the tools this script runs were found. Looked in: $($searchRoots -join '; ')"
    Write-Host ''
    Write-Host $kitHint -ForegroundColor Yellow
    return
}

# --- Targets: named hosts, a named Controller, or this machine if it is a Controller ------
if (-not $ComputerName -and -not $DeliveryController) {
    if (Test-LocalDeliveryController) {
        $DeliveryController = 'localhost'
        Write-TriageLine -Status INFO -Message 'This server is a Citrix Delivery Controller - discovering session hosts from it.'
    }
    else {
        throw 'Tell me which servers to check: -ComputerName VDA01,VDA02 - or run this on a Delivery Controller, or pass -DeliveryController <name>.'
    }
}
if (-not $ComputerName -and -not $tool.Health) {
    throw "Discovering session hosts from Citrix needs the Citrix-FSLogix-HealthCollector tool, which was not found. Pass -ComputerName instead, or use a kit.`r`n`r`n$kitHint"
}

$runStamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$runFolder   = Join-Path $OutputPath "CitrixPerfTriage_$runStamp"
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null
$script:LogFile = Join-Path $runFolder 'Triage.log'

$windowEnd   = Get-Date
$windowStart = $windowEnd.AddHours(-$LookbackHours)
$isAdmin     = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                   [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-TriageLine -Status INFO -Message "Citrix performance triage started. Results: $runFolder"
# The tools nest their own subfolders and long file names under the run folder; Windows
# PowerShell 5.1 cannot create paths past 260 characters, so warn while it is still cheap.
if ($runFolder.Length -gt 150) {
    Write-TriageLine -Status WARN -Message "The output path is $($runFolder.Length) characters long. Some tools may fail with 'path too long'; a short -OutputPath such as C:\Temp avoids this."
}
Write-TriageLine -Status INFO -Message ("Time window: {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} ({2} hours)" -f $windowStart, $windowEnd, $LookbackHours)
if ($missingTools.Count) {
    Write-TriageLine -Status WARN -Message "Not found, so their steps will be skipped: $($missingTools -join ', '). Use a kit (-CreateKit) to get everything in one copy."
}

# ---------------------------------------------------------------------------
# Discovery - who are we checking?
# ---------------------------------------------------------------------------
$inventory = @()
if ($ComputerName) {
    $inventory = @($ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique |
        ForEach-Object { New-TriageInventoryEntry -ComputerName $_ })
}
else {
    $groupText = if ($DesktopGroupName) { " (delivery group '$DesktopGroupName')" } else { ' (all delivery groups)' }
    Write-TriageLine -Status INFO -Message "Asking Delivery Controller '$DeliveryController' for session hosts$groupText..."
    $disc = Get-TriageInventory -CollectorPath $tool.Health -DeliveryController $DeliveryController `
        -DesktopGroupName $DesktopGroupName -WorkFolder (Join-Path $runFolder '0-Discovery') -TimeoutSeconds 300
    if ($disc.Error) {
        Write-TriageLine -Status FAIL -Message "Discovery failed: $($disc.Error)"
    }
    $inventory = @($disc.Machines)
}

$poweredOff = @($inventory | Where-Object { $_.PowerState -eq 'Off' })
$inventory  = @($inventory | Where-Object { $_.PowerState -ne 'Off' })
$allTargets = @($inventory | ForEach-Object { $_.ComputerName })
$targets    = $allTargets

Show-TriageInventory -Inventory $inventory -PoweredOff $poweredOff
foreach ($m in ($inventory | Where-Object { $_.RegistrationState -and $_.RegistrationState -ne 'Registered' })) {
    Add-TriageFinding -Severity Warning -Area 'Citrix' -Target $m.ComputerName `
        -Finding "Not registered with Citrix (state: $($m.RegistrationState)) - no new sessions can be sent to it, so the other servers carry its share of users." `
        -Evidence "Delivery group: $($m.DeliveryGroup)"
}

if (-not $allTargets.Count) {
    Write-TriageLine -Status FAIL -Message 'No session hosts to check. Check the Delivery Controller name and delivery group, or pass -ComputerName.'
}
else {
    Show-TriagePlan -ServerCount $allTargets.Count -ThrottleLimit $ThrottleLimit -SampleSeconds $SampleSeconds `
        -Tool $tool -SkipStorageBenchmark:$SkipStorageBenchmark -IsAdmin $isAdmin -ProfileSharePath $ProfileSharePath `
        -HyperVText $(if ($SkipHyperV) { '' } else { @(@($HyperVCluster) + @($HyperVHost) | Where-Object { $_ }) -join ', ' })
}

# ---------------------------------------------------------------------------
# Step 1 - Server health
# ---------------------------------------------------------------------------
$healthRows = @{}
$healthReports = @{}
$stepName = 'Server health (CPU, memory, disk, events)'
if (-not $tool.Health) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Citrix-FSLogix-HealthCollector was not found.'
}
elseif (-not $targets.Count) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session hosts.'
}
else {
    Write-TriageStepHeader -Number 1 -Name 'Server health' -Detail "$($targets.Count) server(s), $ThrottleLimit at a time, $SampleSeconds s of sampling each"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $stepDir = Join-Path $runFolder '1-ServerHealth'
    $jobs = foreach ($t in $targets) {
        $p = @{ ComputerName = @($t); LastHours = $LookbackHours; SampleSeconds = $SampleSeconds; NoOpen = $true
                OutputPath = (Join-Path $stepDir (ConvertTo-SafeFolderName (Get-ShortComputerName $t))) }
        if ($Credential) { $p.Credential = $Credential }
        [PSCustomObject]@{ Target = $t; ScriptPath = $tool.Health; Parameters = $p; WorkFolder = $p.OutputPath }
    }
    $describe = {
        param($job, $result)
        $row = @($result.Output | Where-Object { $_.PSObject.Properties['Verdict'] }) | Select-Object -First 1
        if (-not $row) { return @{ Status = 'FAIL'; Text = 'no result returned' } }
        $numbers = 'CPU {0}%, memory {1}%' -f $row.CpuAveragePercent, $row.MemoryAveragePercent
        $why = if ("$($row.TopIssue)".Trim()) { $row.TopIssue } else { $row.Reasons }
        switch ($row.Verdict) {
            'Healthy'  { @{ Status = 'PASS'; Text = "Healthy - $numbers" } }
            'Degraded' { @{ Status = 'WARN'; Text = "Degraded - $why" } }
            default    { @{ Status = 'FAIL'; Text = "$($row.Verdict) - $why" } }
        }
    }
    $batch = @(Invoke-ToolBatch -Job @($jobs) -ThrottleLimit $ThrottleLimit -TimeoutSeconds $StepTimeoutSeconds -Activity 'Server health' -Describe $describe)
    $timer.Stop()

    foreach ($b in $batch) {
        $row = @($b.Result.Output | Where-Object { $_.PSObject.Properties['Verdict'] }) | Select-Object -First 1
        $report = Get-NewestFile -Folder $b.Job.WorkFolder -Filter 'CitrixFSLogixHealth_*.html'
        if ($report) { $healthReports[$b.Target] = $report.FullName }
        if (-not $row) { continue }
        $healthRows[$b.Target] = $row
        $sev = switch ($row.Verdict) { 'Healthy' { $null } 'Degraded' { 'Warning' } default { 'Critical' } }
        if ($sev) {
            $evidence = 'CPU avg {0}% / peak {1}%, memory avg {2}%, fullest disk {3}%; events: {4} critical, {5} errors' -f `
                $row.CpuAveragePercent, $row.CpuPeakPercent, $row.MemoryAveragePercent, $row.MaxDiskUsedPercent, $row.CriticalEvents, $row.ErrorEvents
            Add-TriageFinding -Severity $sev -Area 'Server health' -Target $b.Target -Finding ("{0}: {1}" -f $row.Verdict, $row.Reasons) -Evidence $evidence
        }
    }

    $checked = $healthRows.Count
    $healthy = @($healthRows.Values | Where-Object Verdict -eq 'Healthy').Count
    $status = if ($checked -eq $targets.Count) { 'Completed' } elseif ($checked) { 'Partial' } else { 'Failed' }
    Add-TriageStep -Step $stepName -Status $status -Detail "$checked of $($targets.Count) server(s) checked, $healthy healthy." -Duration $timer.Elapsed -ReportPath $stepDir

    # A server that answered neither performance nor event queries will not answer the later
    # steps either - skipping it saves a connection timeout per server per step.
    $unreachable = @($healthRows.Keys | Where-Object { $healthRows[$_].Verdict -eq 'Unreachable' })
    if ($unreachable.Count) {
        $targets = @($targets | Where-Object { $_ -notin $unreachable })
        Write-TriageLine -Status WARN -Message "Leaving out of the remaining steps (unreachable): $($unreachable -join ', ')"
    }
}

# ---------------------------------------------------------------------------
# Step 2 - FSLogix settings
# ---------------------------------------------------------------------------
$configs = @()
$stepName = 'FSLogix settings'
if ($targets.Count) {
    Write-TriageStepHeader -Number 2 -Name 'FSLogix settings' -Detail "reading the registry on $($targets.Count) server(s)"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $digits = "$($targets.Count)".Length
    $width = [math]::Max(8, ($targets | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum)
    $i = 0
    $configs = @(foreach ($t in $targets) {
        $i++
        $c = Get-FSLogixHostConfig -ComputerName $t -Credential $Credential
        $text = if ($c.Source -eq 'Default') { 'could not read settings - will try the default log folder' }
                elseif ($c.Installed -eq $false) { 'FSLogix not installed' }
                else {
                    $share = @($c.VHDLocations + $c.CCDLocations) | Select-Object -First 1
                    "profile share $(if ($share) { $share } else { '(none set)' }), logs kept $($c.LogKeepDays) day(s)"
                }
        $lineStatus = if ($c.Source -eq 'Default') { 'WARN' } else { 'PASS' }
        Write-TriageLine -Status $lineStatus -Message ("   [{0}/{1}] {2}  {3}" -f "$i".PadLeft($digits), $targets.Count, $t.PadRight($width), $text)
        $c
    })
    $timer.Stop()

    $dir = Join-Path $runFolder '2-FSLogixSettings'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $csv = Join-Path $dir 'FSLogixSettings.csv'
    $configs | Select-Object ComputerName, Source, Installed, ProfilesEnabled,
        @{ n = 'VHDLocations'; e = { $_.VHDLocations -join '; ' } },
        @{ n = 'CCDLocations'; e = { $_.CCDLocations -join '; ' } },
        LogDir, LogDirUnc, LogKeepDays, Problem |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

    foreach ($c in $configs) {
        if ($c.Source -eq 'Default') {
            Add-TriageFinding -Severity Info -Area 'FSLogix settings' -Target $c.ComputerName `
                -Finding 'Could not read the FSLogix settings; assumed the default log folder.' -Evidence $c.Problem
            continue
        }
        if ($c.Installed -eq $false) {
            Add-TriageFinding -Severity Info -Area 'FSLogix settings' -Target $c.ComputerName -Finding 'FSLogix does not appear to be installed.'
        }
        elseif ("$($c.ProfilesEnabled)" -ne '1') {
            Add-TriageFinding -Severity Info -Area 'FSLogix settings' -Target $c.ComputerName `
                -Finding 'FSLogix profile containers are not turned on (Profiles\Enabled is not 1).' -Evidence "Enabled = '$($c.ProfilesEnabled)'"
        }
        if ($c.LogKeepDays * 24 -lt $LookbackHours) {
            Add-TriageFinding -Severity Info -Area 'FSLogix logs' -Target $c.ComputerName `
                -Finding "FSLogix keeps only $($c.LogKeepDays) day(s) of logs, so the start of the $LookbackHours-hour window has no FSLogix log coverage." `
                -Evidence 'HKLM\SOFTWARE\FSLogix\Logging\LogFileKeepingPeriod (default 2)'
        }
    }

    $readCount = @($configs | Where-Object Source -ne 'Default').Count
    $status = if ($readCount -eq $configs.Count) { 'Completed' } elseif ($readCount) { 'Partial' } else { 'Failed' }
    Add-TriageStep -Step $stepName -Status $status -Detail "Read from $readCount of $($configs.Count) server(s)." -Duration $timer.Elapsed -ReportPath $csv
}
else {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session hosts.'
}

# ---------------------------------------------------------------------------
# Step 3 - FSLogix logs
# ---------------------------------------------------------------------------
$reattachByHost = @{}
$reattachTotal = 0
$stepName = 'FSLogix logs (profile load, re-attach loops)'
if (-not $tool.FSLogixLogs) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Parse-FSLogixLogs was not found.'
}
elseif (-not $configs.Count) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session hosts.'
}
else {
    # Installed is $false only when the registry was read and FSLogix is definitely absent;
    # $null (settings unreadable) still tries the default log folder.
    $fslHosts = @($configs | Where-Object { $_.Installed -ne $false })
    if (-not $fslHosts.Count) {
        Add-TriageStep -Step $stepName -Status Skipped -Detail 'FSLogix is not installed on any of the servers.'
    }
    else {
        Write-TriageStepHeader -Number 3 -Name 'FSLogix logs' -Detail "$($fslHosts.Count) server(s), $ThrottleLimit at a time"
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $stepDir = Join-Path $runFolder '3-FSLogixLogs'
        $failedHosts = @()
        $jobs = @()

        foreach ($c in $fslHosts) {
            if (-not $c.LogDirUnc) {
                $failedHosts += "$($c.ComputerName) (log folder '$($c.LogDir)' is not reachable from here)"
                continue
            }
            # FSLogix writes one log per component per day: Logs\Profile\Profile-yyyyMMdd.log and
            # Logs\ODFC\ODFC-yyyyMMdd.log. Only files touched inside the window are read, so a host
            # keeping months of logs does not turn a 24-hour triage into an hour of parsing.
            # https://learn.microsoft.com/fslogix/troubleshooting-vhd-disk-compaction#log-files
            $files = @()
            $profileFolderError = $null
            foreach ($sub in 'Profile', 'ODFC') {
                try {
                    $folder = Join-Path $c.LogDirUnc $sub -ErrorAction Stop
                    $files += @(Get-ChildItem -LiteralPath $folder -Filter "$sub*.log" -File -ErrorAction Stop |
                        Where-Object { $_.LastWriteTime -ge $windowStart } |
                        ForEach-Object { $_.FullName })
                }
                catch {
                    # ODFC logging is off by default, so a missing ODFC folder is normal.
                    if ($sub -eq 'Profile') { $profileFolderError = $_.Exception.Message }
                }
            }
            if ($profileFolderError -and -not $files.Count) {
                $failedHosts += "$($c.ComputerName) ($profileFolderError)"
                continue
            }
            if (-not $files.Count) {
                Add-TriageFinding -Severity Info -Area 'FSLogix logs' -Target $c.ComputerName `
                    -Finding 'No FSLogix log files were written during the time window.' -Evidence $c.LogDirUnc
                Write-TriageLine -Status INFO -Message "   $($c.ComputerName)  no FSLogix log files written in the window"
                continue
            }
            $hostDir = Join-Path $stepDir (ConvertTo-SafeFolderName (Get-ShortComputerName $c.ComputerName))
            $jobs += [PSCustomObject]@{
                Target = $c.ComputerName; ScriptPath = $tool.FSLogixLogs; WorkFolder = $hostDir
                Parameters = @{ Path = $files; StartTime = $windowStart; EndTime = $windowEnd; ExportPath = $hostDir }
            }
        }
        foreach ($fh in $failedHosts) {
            Write-TriageLine -Status WARN -Message "   could not read logs: $fh"
        }

        $describe = {
            param($job, $result)
            $logs = @($result.Output | Where-Object { $_.PSObject.Properties['Findings'] })
            $re = @($logs | ForEach-Object { @($_.Reattaches) } | Where-Object { $_ }).Count
            $issues = @($logs | ForEach-Object { @($_.Findings) } | Where-Object { $_ -and $_.Severity -in 'High', 'Medium' }).Count
            $s = if ($issues) { 'WARN' } else { 'PASS' }
            @{ Status = $s; Text = "$($logs.Count) log file(s), $re re-attach(es), $issues issue(s)" }
        }
        $batch = @(Invoke-ToolBatch -Job @($jobs) -ThrottleLimit $ThrottleLimit -TimeoutSeconds $StepTimeoutSeconds -Activity 'FSLogix logs' -Describe $describe)
        $timer.Stop()

        $parsedFiles = 0
        foreach ($b in $batch) {
            if ($b.Result.Status -ne 'Completed') {
                $failedHosts += "$($b.Target) ($($b.Result.Error))"
                continue
            }
            $times = @()
            foreach ($log in @($b.Result.Output | Where-Object { $_.PSObject.Properties['Findings'] })) {
                $parsedFiles++
                foreach ($f in @($log.Findings)) {
                    Add-TriageFinding -Severity (ConvertFrom-FSLogixLogSeverity $f.Severity) -Area 'FSLogix logs' -Target $b.Target `
                        -Finding ("{0}: {1}" -f $f.Type, $f.Detail) -Evidence (Split-Path -Leaf "$($f.FilePath)")
                }
                $times += @($log.Reattaches | ForEach-Object { $_.Timestamp } | Where-Object { $_ -is [datetime] })
            }
            if ($times.Count) {
                $reattachByHost[$b.Target] = @($times | Sort-Object -Unique)
                $reattachTotal += $reattachByHost[$b.Target].Count
            }
        }
        foreach ($fh in $failedHosts) {
            Add-TriageFinding -Severity Info -Area 'FSLogix logs' -Target (($fh -split ' ')[0]) -Finding "FSLogix logs could not be read: $fh"
        }

        $status = if (-not $failedHosts.Count) { 'Completed' } elseif ($parsedFiles) { 'Partial' } else { 'Failed' }
        Add-TriageStep -Step $stepName -Status $status -Detail "$parsedFiles log file(s) read; $reattachTotal profile re-attach(es) found." `
            -Duration $timer.Elapsed -ReportPath $(if (Test-Path -LiteralPath $stepDir) { $stepDir } else { '' })
    }
}

# ---------------------------------------------------------------------------
# Step 4 - Storage, SMB and profile events, correlated with re-attaches
# ---------------------------------------------------------------------------
$stepName = 'Storage and network events'
if (-not $tool.StorageEvents) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Get-FSLogixStorageEvents was not found.'
}
elseif (-not $targets.Count) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session hosts.'
}
else {
    Write-TriageStepHeader -Number 4 -Name 'Storage and network events' -Detail "$($targets.Count) server(s), $ThrottleLimit at a time"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $stepDir = Join-Path $runFolder '4-StorageEvents'
    $jobs = foreach ($t in $targets) {
        $hostDir = Join-Path $stepDir (ConvertTo-SafeFolderName (Get-ShortComputerName $t))
        $p = @{ ComputerName = @($t); StartTime = $windowStart; EndTime = $windowEnd; ExportPath = $hostDir }
        # Each server's events are lined up against that server's own re-attaches.
        if ($reattachByHost.ContainsKey($t)) { $p.CorrelateWith = $reattachByHost[$t] }
        if ($Credential) { $p.Credential = $Credential }
        [PSCustomObject]@{ Target = $t; ScriptPath = $tool.StorageEvents; Parameters = $p; WorkFolder = $hostDir }
    }
    $describe = {
        param($job, $result)
        $ev = @($result.Output | Where-Object { $_.PSObject.Properties['NearReference'] })
        $near = @($ev | Where-Object { $_.NearReference }).Count
        if ($near) { @{ Status = 'WARN'; Text = "$($ev.Count) event(s), $near right next to a profile re-attach" } }
        else { @{ Status = 'PASS'; Text = "$($ev.Count) event(s)" } }
    }
    $batch = @(Invoke-ToolBatch -Job @($jobs) -ThrottleLimit $ThrottleLimit -TimeoutSeconds $StepTimeoutSeconds -Activity 'Storage and network events' -Describe $describe)
    $timer.Stop()

    $eventTotal = 0
    foreach ($b in $batch) {
        $events = @($b.Result.Output | Where-Object { $_.PSObject.Properties['NearReference'] })
        $eventTotal += $events.Count
        # Level is a localized display name in this tool's output, so severity is not inferred
        # from it. The time relationship to a re-attach is the signal that matters here.
        $near = @($events | Where-Object { $_.NearReference })
        if ($near.Count) {
            $cats = ($near | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
            Add-TriageFinding -Severity Warning -Area 'Storage events' -Target $b.Target `
                -Finding "$($near.Count) storage/network/profile event(s) logged within 60 seconds of a profile re-attach - likely what triggered it." `
                -Evidence $cats
        }
        if ($events.Count) {
            $cats = ($events | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
            Add-TriageFinding -Severity Info -Area 'Storage events' -Target $b.Target -Finding "$($events.Count) storage/network/profile event(s) in the window." -Evidence $cats
        }
    }

    $ok = @($batch | Where-Object { $_.Result.Status -eq 'Completed' }).Count
    $status = if ($ok -eq $batch.Count) { 'Completed' } elseif ($ok) { 'Partial' } else { 'Failed' }
    $detail = "$eventTotal event(s) from $ok of $($batch.Count) server(s)"
    if ($reattachTotal) { $detail += ", lined up against $reattachTotal re-attach(es)" }
    Add-TriageStep -Step $stepName -Status $status -Detail "$detail." -Duration $timer.Elapsed -ReportPath $stepDir
}

# ---------------------------------------------------------------------------
# Step 5 - RDS / FSLogix event export
# ---------------------------------------------------------------------------
$stepName = 'RDS and FSLogix event export'
if (-not $tool.RdsEvents) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'RDS-FSLogix-EventExport was not found.'
}
elseif (-not $targets.Count) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session hosts.'
}
else {
    Write-TriageStepHeader -Number 5 -Name 'RDS and FSLogix events' -Detail "$($targets.Count) server(s), $ThrottleLimit at a time"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $stepDir = Join-Path $runFolder '5-RdsEvents'
    $jobs = foreach ($t in $targets) {
        $hostDir = Join-Path $stepDir (ConvertTo-SafeFolderName (Get-ShortComputerName $t))
        $p = @{ ComputerName = @($t); LastHours = $LookbackHours; OutputPath = $hostDir }
        if ($Credential) { $p.Credential = $Credential }
        [PSCustomObject]@{ Target = $t; ScriptPath = $tool.RdsEvents; Parameters = $p; WorkFolder = $hostDir }
    }
    # Level is the numeric standard event level (1 = Critical), which is locale-independent.
    # https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
    $readRows = {
        param($folder)
        $csvFile = Get-NewestFile -Folder $folder -Filter 'RDS-FSLogix-Events_*.csv'
        if ($csvFile) { @(Import-Csv -LiteralPath $csvFile.FullName) } else { @() }
    }
    $describe = {
        param($job, $result)
        $rows = @(& $readRows $job.WorkFolder)
        $crit = @($rows | Where-Object { $_.Level -eq '1' }).Count
        if ($crit) { @{ Status = 'WARN'; Text = "$($rows.Count) event(s), $crit critical" } }
        else { @{ Status = 'PASS'; Text = "$($rows.Count) event(s)" } }
    }
    $batch = @(Invoke-ToolBatch -Job @($jobs) -ThrottleLimit $ThrottleLimit -TimeoutSeconds $StepTimeoutSeconds -Activity 'RDS and FSLogix events' -Describe $describe)
    $timer.Stop()

    $rowTotal = 0
    foreach ($b in $batch) {
        $rows = @(& $readRows $b.Job.WorkFolder)
        $rowTotal += $rows.Count
        $critRows = @($rows | Where-Object { $_.Level -eq '1' })
        if ($critRows.Count) {
            $ids = ($critRows | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 |
                ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', '
            Add-TriageFinding -Severity Warning -Area 'RDS events' -Target $b.Target -Finding "$($critRows.Count) critical RDS/FSLogix event(s) in the window." -Evidence $ids
        }
    }

    $ok = @($batch | Where-Object { $_.Result.Status -eq 'Completed' }).Count
    $status = if ($ok -eq $batch.Count) { 'Completed' } elseif ($ok) { 'Partial' } else { 'Failed' }
    Add-TriageStep -Step $stepName -Status $status -Detail "$rowTotal event(s) exported from $ok of $($batch.Count) server(s)." -Duration $timer.Elapsed -ReportPath $stepDir
}

# ---------------------------------------------------------------------------
# Step 6 - Profile share speed test
# ---------------------------------------------------------------------------
$benchmark = $null
$stepName = 'Profile share speed test'
$shareTarget = $ProfileSharePath
if (-not $shareTarget) {
    $shareTarget = @($configs | ForEach-Object { $_.VHDLocations } | Where-Object { $_ -match '^\\\\' }) | Select-Object -First 1
}
if (-not $shareTarget) {
    $shareTarget = @($configs | ForEach-Object { $_.CCDLocations } | Where-Object { $_ -match '^\\\\' }) | Select-Object -First 1
}
$benchFrom = if ($BenchmarkComputerName) { $BenchmarkComputerName } else { $targets | Select-Object -First 1 }

if ($SkipStorageBenchmark) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Skipped with -SkipStorageBenchmark.'
}
elseif (-not $tool.DiskSpd) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'DiskSpdDiagnostic was not found.'
}
elseif (-not $isAdmin) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Needs an elevated console (Run as administrator).'
}
elseif (-not $shareTarget) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No profile share found in the FSLogix settings. Pass -ProfileSharePath.'
}
elseif (-not $benchFrom) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No session host to run the test from.'
}
else {
    Write-TriageStepHeader -Number 6 -Name 'Profile share speed' -Detail "$BenchmarkWorkload test from $benchFrom to $shareTarget (loads the share while it runs, about a minute)"
    if ($Credential) {
        Write-TriageLine -Status WARN -Message 'The speed test runs as the current user; DiskSpdDiagnostic has no -Credential parameter.'
    }
    $dir = Join-Path $runFolder '6-StorageSpeed'
    $p = @{ NoUI = $true; Target = $shareTarget; Workload = $BenchmarkWorkload; OutputPath = $dir }
    $isLocal = (Get-ShortComputerName $benchFrom) -eq $env:COMPUTERNAME -or $benchFrom -eq 'localhost'
    if (-not $isLocal) { $p.ComputerName = $benchFrom }

    $run = Invoke-ToolScript -ScriptPath $tool.DiskSpd -Parameters $p -WorkFolder $dir -TimeoutSeconds $StepTimeoutSeconds -Label 'Storage speed test'
    $reportPath = @($run.Output | Where-Object { $_ -is [string] -and $_ -match '\.html$' }) | Select-Object -First 1
    $numbers = Get-DiskSpdResultFromConsole -Text $run.ConsoleText

    if ($numbers) {
        $benchmark = [PSCustomObject]@{
            From = $benchFrom; Target = $shareTarget; Workload = $BenchmarkWorkload
            IOPS = $numbers.IOPS; ReadMBps = $numbers.ReadMBps; WriteMBps = $numbers.WriteMBps; AvgLatencyMs = $numbers.AvgLatencyMs
        }
        Add-TriageFinding -Severity Info -Area 'Storage speed' -Target $benchFrom `
            -Finding ("Profile share: {0:N0} operations/s, {1:N1} ms average response time." -f $numbers.IOPS, $numbers.AvgLatencyMs) `
            -Evidence ("{0:N1} MB/s read, {1:N1} MB/s write to {2}" -f $numbers.ReadMBps, $numbers.WriteMBps, $shareTarget)
    }
    $detail = if ($numbers) { "{0:N0} IOPS, {1:N1} ms average." -f $numbers.IOPS, $numbers.AvgLatencyMs } else { "No results. $($run.Error)" }
    $status = if ($run.Status -eq 'Completed' -and -not $numbers) { 'Failed' } else { $run.Status }
    Add-TriageStep -Step $stepName -Status $status -Detail $detail -Duration $run.Duration -ReportPath $(if ($reportPath) { $reportPath } else { $run.ConsoleFile })
}

# ---------------------------------------------------------------------------
# Step 7 - Hyper-V hosts
# ---------------------------------------------------------------------------
$vmConfig = @()
$handoffFolder = $null
$stepName = 'Hyper-V hosts'
# All discovered servers, including any left out as unreachable - an unreachable session host
# is exactly the VM worth looking at from the Hyper-V side.
$vmNames = if ($VMName) { @($VMName) } else { @($allTargets | ForEach-Object { Get-ShortComputerName $_ } | Select-Object -Unique) }

if ($SkipHyperV) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'Skipped with -SkipHyperV.'
}
elseif (-not $HyperVHost -and -not $HyperVCluster) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'No Hyper-V host given. Add -HyperVHost or -HyperVCluster to include host checks.'
}
elseif (-not $tool.HyperVHost) {
    Add-TriageStep -Step $stepName -Status Skipped -Detail 'HyperV-Host-Diagnostics was not found.'
}
else {
    Write-TriageStepHeader -Number 7 -Name 'Hyper-V hosts' -Detail 'checking access first'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $dir = Join-Path $runFolder '7-HyperV'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $blocked = @()

    $hvHosts = @($HyperVHost | Where-Object { $_ })
    if ($HyperVCluster) {
        $nodes = @()
        try {
            Import-Module FailoverClusters -ErrorAction Stop
            $nodes = @(Get-ClusterNode -Cluster $HyperVCluster -ErrorAction Stop | ForEach-Object { $_.Name })
        }
        catch {
            # No RSAT clustering tools here - ask the cluster itself through remoting.
            try {
                $ic = @{ ComputerName = $HyperVCluster; ScriptBlock = { Get-ClusterNode | ForEach-Object { $_.Name } }; ErrorAction = 'Stop' }
                if ($HyperVCredential) { $ic.Credential = $HyperVCredential }
                $nodes = @(Invoke-Command @ic)
            }
            catch {
                $blocked += [PSCustomObject]@{ ComputerName = $HyperVCluster; State = 'ClusterLookup'; VMs = @(); Detail = $_.Exception.Message }
            }
        }
        if ($nodes.Count) { Write-TriageLine -Status INFO -Message "  Cluster $HyperVCluster nodes: $($nodes -join ', ')" }
        $hvHosts += $nodes
    }
    $hvHosts = @($hvHosts | Select-Object -Unique)

    $accessText = @{
        NoRemoting     = 'no access - remote PowerShell refused (not an admin there)'
        NoHyperVRights = 'no access - Hyper-V refused to list VMs'
        Unreachable    = 'unreachable over WinRM'
        NotHyperV      = 'not a Hyper-V host'
    }
    $hvDigits = "$($hvHosts.Count)".Length
    $hvWidth = [math]::Max(8, ($hvHosts | ForEach-Object { "$_".Length } | Measure-Object -Maximum).Maximum)
    $i = 0
    $access = @(foreach ($h in $hvHosts) {
        $i++
        $a = Test-HyperVHostAccess -ComputerName $h -Credential $HyperVCredential
        if ($a.State -eq 'OK') {
            $ours = @($a.VMs | Where-Object { $vmNames -contains $_ })
            $text = "OK - $(@($a.VMs).Count) VM(s)" + $(if ($ours.Count) { ", ours: $($ours -join ', ')" } else { ', none of ours' })
            Write-TriageLine -Status PASS -Message ("   [{0}/{1}] {2}  {3}" -f "$i".PadLeft($hvDigits), $hvHosts.Count, "$h".PadRight($hvWidth), $text)
        }
        else {
            Write-TriageLine -Status WARN -Message ("   [{0}/{1}] {2}  {3}" -f "$i".PadLeft($hvDigits), $hvHosts.Count, "$h".PadRight($hvWidth), $accessText[$a.State])
        }
        $a
    })
    $ok = @($access | Where-Object State -eq 'OK')
    $blocked += @($access | Where-Object { $_.State -notin 'OK', 'NotHyperV' })
    foreach ($a in ($access | Where-Object State -eq 'NotHyperV')) {
        Add-TriageFinding -Severity Info -Area 'Hyper-V' -Target $a.ComputerName -Finding 'Not a Hyper-V host (no Hyper-V PowerShell module).'
    }
    foreach ($b in ($blocked | Where-Object State -eq 'ClusterLookup')) {
        Write-TriageLine -Status WARN -Message "   Could not read the node list of cluster $($b.ComputerName): $($b.Detail)"
    }

    $hostScript = Get-Content -LiteralPath $tool.HyperVHost -Raw
    $diagCount = 0
    foreach ($a in $ok) {
        $mine = @($a.VMs | Where-Object { $vmNames -contains $_ })
        # '' means "host-wide checks only". Not $null: an if-statement returning @($null)
        # unrolls to nothing, and the loop below would silently skip the host.
        $runs = @('')
        if ($mine.Count) { $runs = $mine }
        foreach ($vm in $runs) {
            $label = if ($vm) { "$($a.ComputerName) / $vm" } else { "$($a.ComputerName) (host-wide)" }
            Write-TriageLine -Status INFO -Message "   Host diagnostics: $label - reading $HyperVDaysBack day(s) of host logs..."
            $diagTimer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $text = Invoke-HyperVHostDiagnosticRemote -ComputerName $a.ComputerName -ScriptText $hostScript -TargetVM $vm `
                    -DaysBack $HyperVDaysBack -TimeoutSeconds $StepTimeoutSeconds -Credential $HyperVCredential
                $name = if ($vm) { "$($a.ComputerName)_$vm" } else { $a.ComputerName }
                $logPath = Join-Path $dir "$($name)_HyperVHostDiagnostics.log"
                Set-Content -LiteralPath $logPath -Value $text -Encoding UTF8
                $diagCount++
                $flags = @(Get-HyperVFlagFromLog -Text $text)
                foreach ($flag in $flags) {
                    Add-TriageFinding -Severity Warning -Area 'Hyper-V host' -Target $a.ComputerName -Finding $flag -Evidence (Split-Path -Leaf $logPath)
                }
                $lineStatus = if ($flags.Count) { 'WARN' } else { 'PASS' }
                Write-TriageLine -Status $lineStatus -Message ("   Host diagnostics: {0} - {1} item(s) flagged  ({2})" -f $label, $flags.Count, (Format-Elapsed $diagTimer.Elapsed))
            }
            catch {
                Add-TriageFinding -Severity Info -Area 'Hyper-V host' -Target $a.ComputerName -Finding "Host diagnostics failed: $($_.Exception.Message)"
                Write-TriageLine -Status FAIL -Message ("   Host diagnostics: {0} - failed: {1}  ({2})" -f $label, $_.Exception.Message, (Format-Elapsed $diagTimer.Elapsed))
            }
        }
    }

    if ($ok.Count -and $tool.HyperVInventory) {
        $invDir = Join-Path $dir 'Inventory'
        $p = @{ ComputerName = @($ok | ForEach-Object { $_.ComputerName }); OutputPath = $invDir }
        if ($HyperVCredential) { $p.Credential = $HyperVCredential }
        Write-TriageLine -Status INFO -Message "   Hyper-V inventory: $($ok.Count) host(s) - includes a Windows Update check, can take a few minutes..."
        $run = Invoke-ToolScript -ScriptPath $tool.HyperVInventory -Parameters $p -WorkFolder $invDir -TimeoutSeconds $StepTimeoutSeconds -Label 'Hyper-V inventory'
        $invStatus = if ($run.Status -eq 'Completed') { 'PASS' } else { 'FAIL' }
        Write-TriageLine -Status $invStatus -Message ("   Hyper-V inventory: {0}  ({1})" -f $(if ($run.Status -eq 'Completed') { 'done' } else { "$($run.Status): $($run.Error)" }), (Format-Elapsed $run.Duration))

        $vmCsv = Join-Path $invDir 'VirtualMachines.csv'
        $hostCsv = Join-Path $invDir 'Hosts.csv'
        if (Test-Path -LiteralPath $vmCsv) {
            $allVms = @(Import-Csv -LiteralPath $vmCsv)
            $vmConfig = @($allVms | Where-Object { $vmNames -contains $_.VMName } | Sort-Object VMName)

            if (Test-Path -LiteralPath $hostCsv) {
                foreach ($hr in (Import-Csv -LiteralPath $hostCsv)) {
                    $running = @($allVms | Where-Object { $_.HostName -eq $hr.HostName -and $_.State -eq 'Running' })
                    $vcpu = ($running | ForEach-Object { [int]("0$($_.vCPU)") } | Measure-Object -Sum).Sum
                    $lp = [int]("0$($hr.CPU_LogicalProc)")
                    if ($lp -gt 0) {
                        Add-TriageFinding -Severity Info -Area 'Hyper-V host' -Target $hr.HostName `
                            -Finding ("{0} vCPUs assigned to {1} running VM(s) on {2} logical processors ({3:N1} : 1)." -f $vcpu, $running.Count, $lp, ($vcpu / $lp)) `
                            -Evidence ("Host RAM {0} GB, {1} GB free" -f $hr.RAM_GB, $hr.RAM_FreeGB)
                    }
                }
            }
        }
        if ($run.Status -ne 'Completed') {
            Add-TriageFinding -Severity Info -Area 'Hyper-V' -Target '' -Finding "Hyper-V inventory did not complete: $($run.Error)"
        }
    }

    if ($blocked.Count) {
        $handoffFolder = New-HyperVHandoffPackage -Folder (Join-Path $dir 'HyperV-Handoff') -Blocked $blocked `
            -VMNames $vmNames -DaysBack $HyperVDaysBack -Cluster $HyperVCluster `
            -HostScriptPath $tool.HyperVHost -InventoryScriptPath $tool.HyperVInventory
        Add-TriageFinding -Severity Info -Area 'Hyper-V' -Target (($blocked | ForEach-Object { $_.ComputerName }) -join ', ') `
            -Finding 'Could not check these Hyper-V hosts from this account. Hand-off package created for the Hyper-V administrators.' `
            -Evidence $handoffFolder
    }
    $timer.Stop()

    $status = if (-not $blocked.Count) { 'Completed' } elseif ($ok.Count) { 'Partial' } else { 'Handoff' }
    $detail = "$($ok.Count) of $($hvHosts.Count) host(s) checked, $diagCount diagnostic run(s)."
    if ($blocked.Count) { $detail += " Hand-off package created for: $(($blocked | ForEach-Object { $_.ComputerName }) -join ', ')." }
    Add-TriageStep -Step $stepName -Status $status -Detail $detail -Duration $timer.Elapsed -ReportPath $(if ($handoffFolder) { $handoffFolder } else { $dir })
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
# .ToArray(), not @(): in Windows PowerShell 5.1, @($script:List) on a generic List[object]
# throws "Argument types do not match" (reproduced while building this script).
$findings = $script:Findings.ToArray()
$steps    = $script:Steps.ToArray()
$overall  = Get-TriageOverallStatus -Finding $findings -Step $steps

$servers = @(foreach ($m in $inventory) {
    $row = $healthRows[$m.ComputerName]
    [PSCustomObject]@{
        Server       = $m.ComputerName
        DeliveryGroup = $m.DeliveryGroup
        Registration = $m.RegistrationState
        Verdict      = if ($row) { $row.Verdict } else { 'Not checked' }
        CpuAvg       = if ($row) { $row.CpuAveragePercent } else { $null }
        CpuPeak      = if ($row) { $row.CpuPeakPercent } else { $null }
        MemoryAvg    = if ($row) { $row.MemoryAveragePercent } else { $null }
        FullestDisk  = if ($row) { $row.MaxDiskUsedPercent } else { $null }
        Sessions     = $m.SessionCount
        Issues       = @($findings | Where-Object { $_.Target -eq $m.ComputerName -and $_.Severity -ne 'Info' }).Count
        Report       = $healthReports[$m.ComputerName]
    }
})
$servers | Select-Object Server, DeliveryGroup, Registration, Verdict, CpuAvg, CpuPeak, MemoryAvg, FullestDisk, Sessions, Issues,
    @{ n = 'Report'; e = { Get-RelativeReportPath -RunFolder $runFolder -Path $_.Report } } |
    Export-Csv -LiteralPath (Join-Path $runFolder 'Servers.csv') -NoTypeInformation -Encoding UTF8

$findings | Export-Csv -LiteralPath (Join-Path $runFolder 'Findings.csv') -NoTypeInformation -Encoding UTF8
$steps | Select-Object Step, Status, Detail, @{ n = 'Duration'; e = { '{0:hh\:mm\:ss}' -f $_.Duration } },
    @{ n = 'Report'; e = { Get-RelativeReportPath -RunFolder $runFolder -Path $_.ReportPath } } |
    Export-Csv -LiteralPath (Join-Path $runFolder 'Steps.csv') -NoTypeInformation -Encoding UTF8

$hvText = @(@($HyperVCluster) + @($HyperVHost) | Where-Object { $_ }) -join ', '
if (-not $hvText) { $hvText = 'not checked' }
$context = @{
    RunFolder     = $runFolder
    Targets       = $allTargets
    WindowStart   = $windowStart
    WindowEnd     = $windowEnd
    HyperVText    = $hvText
    RunBy         = "$env:USERDOMAIN\$env:USERNAME"
    HandoffFolder = $handoffFolder
}
$htmlPath = Join-Path $runFolder 'Summary.html'
New-TriageHtmlReport -Context $context -Step $steps -Finding $findings -Server $servers -VmConfig $vmConfig -Benchmark $benchmark |
    Set-Content -LiteralPath $htmlPath -Encoding UTF8

Write-Host ''
$crit = @($findings | Where-Object Severity -eq 'Critical').Count
$warn = @($findings | Where-Object Severity -eq 'Warning').Count
$line = "Overall: $overall - $crit serious, $warn to review. Summary: $htmlPath"
switch ($overall) {
    'Critical'   { Write-TriageLine -Status FAIL -Message $line }
    'Warning'    { Write-TriageLine -Status WARN -Message $line }
    'Incomplete' { Write-TriageLine -Status FAIL -Message "Overall: Incomplete - the checks did not finish, so there is no verdict. See 'What ran' in $htmlPath" }
    default      { Write-TriageLine -Status PASS -Message $line }
}
if ($handoffFolder) {
    Write-TriageLine -Status WARN -Message "Send this folder to the Hyper-V administrators: $handoffFolder"
}

if (-not $NoOpen) {
    try { Start-Process -FilePath $htmlPath } catch { }
}

if ($PassThru) {
    [PSCustomObject]@{
        Overall   = $overall
        RunFolder = $runFolder
        Summary   = $htmlPath
        Steps     = $steps
        Findings  = $findings
    }
}
