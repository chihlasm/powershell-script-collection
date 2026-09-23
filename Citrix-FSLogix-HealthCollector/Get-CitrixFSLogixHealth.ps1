#Requires -Version 5.1

<#
.SYNOPSIS
    Get-CitrixFSLogixHealth.ps1 - Fleet health collector for Citrix / RDS session hosts
    and FSLogix file servers. Gathers sampled performance metrics AND critical, error, and
    warning events in a single pass, then rolls each host up to one verdict.

.DESCRIPTION
    Built for handing to a client. One command produces a defensible picture of a Citrix
    and FSLogix estate: what the machines are doing right now, what has been going wrong,
    and which hosts need attention first.

    TWO WAYS TO CHOOSE TARGETS
      - Broker discovery (default): asks a Citrix Delivery Controller for every VDA, the
        same way Get-CitrixVDAResources.ps1 does. Add -AdditionalComputerName to append
        machines the broker does not know about, such as the FSLogix file servers.
      - Explicit list: -ComputerName takes any set of Windows servers. No Citrix SDK, no
        Delivery Controller, no broker involvement. Use this on RDS-only estates, on file
        servers, or anywhere the Citrix SDK is not installed.

    PERFORMANCE IS SAMPLED, NOT SNAPSHOT
    A single counter read is close to meaningless on a session host - a VDA pinned at 100%
    for forty seconds every few minutes reads as idle if you catch it between spikes.
    -SampleSeconds takes repeated readings across a window and reports average AND peak, so
    a spike cannot hide behind a calm average and a calm average is not mistaken for a spike.
    Set -SampleSeconds 0 for a single instantaneous read when speed matters more.

    EVENTS ARE DISCOVERED, NOT GUESSED
    Citrix does not publish the literal Event Viewer channel names for its VDA components,
    and those names have changed between product versions. Rather than hardcode a guess that
    would silently return zero events on a version that names things differently, this script
    enumerates the channels actually present on each target at runtime and queries what it
    finds. See Get-TargetEventChannel for the patterns used.

    TWO TRANSPORTS, TRACKED SEPARATELY
    Performance uses CIM (WinRM, falling back to DCOM). Events use Get-WinEvent, which does
    not rely on PowerShell remoting and reaches the target over RPC instead. A host can
    therefore answer one and refuse the other. Both are reported independently, and a host is
    only called Unreachable when BOTH fail - so a WinRM-blocked server still yields its event
    history instead of vanishing from the report.

.PARAMETER DeliveryController
    Delivery Controller to query for the VDA list. Passed to the Citrix SDK as -AdminAddress.
    Defaults to localhost. Broker parameter set only.

.PARAMETER DesktopGroupName
    Limit broker discovery to a single delivery group.

.PARAMETER CatalogName
    Limit broker discovery to a single machine catalog.

.PARAMETER AdditionalComputerName
    Extra machines to append to the broker-discovered fleet - typically the FSLogix file
    servers, which are not VDAs and so never appear in a broker query. Broker set only.

.PARAMETER MaxRecordCount
    Maximum machines to retrieve from the broker. Citrix caps at 250 when this is not
    supplied - see the note in Get-VDAInventory.

.PARAMETER IncludeUnregistered
    Collect from machines that are not in the Registered state. Off by default.

.PARAMETER ComputerName
    Explicit list of servers to collect from. Selecting this bypasses Citrix entirely.

.PARAMETER Credential
    Credential for the CIM and event-log connections. Omit to use the current user.

.PARAMETER SampleSeconds
    Total length of the performance sampling window, in seconds. Default 30. Use 0 for a
    single instantaneous reading.

.PARAMETER SampleIntervalSeconds
    Seconds between samples inside the window. Default 5.

.PARAMETER CpuWarnPercent
    Average CPU percent at or above which a host is flagged as a warning. Default 80.

.PARAMETER CpuCriticalPercent
    Average CPU percent at or above which a host is flagged critical. Default 90.

.PARAMETER MemoryWarnPercent
    Average memory-in-use percent at or above which a host is flagged as a warning. Default 80.

.PARAMETER MemoryCriticalPercent
    Average memory-in-use percent at or above which a host is flagged critical. Default 90.

.PARAMETER DiskWarnPercent
    Disk-used percent at or above which a host is flagged as a warning. Default 80.

.PARAMETER DiskCriticalPercent
    Disk-used percent at or above which a host is flagged critical. Default 90.

.PARAMETER QueueWarnPerCpu
    Average processor queue length PER LOGICAL PROCESSOR at or above which a host is
    flagged as a warning. Default 2. See Get-QueueStatus for why this is normalized per
    processor and why Microsoft's own published thresholds disagree with each other.

.PARAMETER QueueCriticalPerCpu
    Average processor queue length per logical processor at or above which a host is
    flagged critical. Default 5, matching Microsoft's Exchange counter guidance.

.PARAMETER StartTime
    Explicit start of the event window. Mutually exclusive with -LastHours / -LastDays.

.PARAMETER EndTime
    End of the event window. Defaults to now when -StartTime is supplied.

.PARAMETER LastHours
    Shortcut: collect events from the last N hours. Mutually exclusive with -StartTime.

.PARAMETER LastDays
    Shortcut: collect events from the last N days. Mutually exclusive with -StartTime.

.PARAMETER Level
    Event severity levels to collect. Defaults to 1,2,3 - Critical, Error, and Warning.
    Pass 1..4 to include Information. Verified numeric mapping is in Get-LevelName.

.PARAMETER MaxEventsPerLog
    Safety cap on events returned per channel per host. Default 2000.

.PARAMETER DegradedErrorCount
    Error-level events in the window at or above which a host is called Degraded. Default 5.

.PARAMETER CriticalErrorCount
    Error-level events in the window at or above which a host is called Critical. Default 25.

.PARAMETER ConnectionTimeoutSeconds
    Per-host CIM connection timeout. Default 15.

.PARAMETER SkipPerformance
    Collect events only. Useful when you only want the incident history.

.PARAMETER SkipEvents
    Collect performance only. Much faster on hosts with large event logs.

.PARAMETER OutputPath
    Directory for the CSV and HTML output. Defaults to the current directory.

.PARAMETER NoOpen
    Do not open the HTML report when the run finishes.

.PARAMETER LoadFunctionsOnly
    Dot-source the script's functions without running it. Used by the Pester suite.

.EXAMPLE
    .\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01

    Every VDA in the site, 30 seconds of sampling, last 24 hours of errors and warnings.

.EXAMPLE
    .\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01 `
        -AdditionalComputerName FS01, FS02 -LastDays 3 -OutputPath C:\Reports\Contoso

    The whole VDA fleet plus the two FSLogix file servers, three days of event history.

.EXAMPLE
    .\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02, RDS03 -SampleSeconds 120

    No Citrix anywhere. Three RDS hosts, two minutes of sampling to catch intermittent spikes.

.EXAMPLE
    .\Get-CitrixFSLogixHealth.ps1 -ComputerName (Get-Content .\hosts.txt) `
        -SampleSeconds 0 -LastHours 2 -NoOpen

    Fast triage sweep: no sampling delay, last two hours only, no browser popup.

.NOTES
    Author: VC3
    Read-only. Queries performance counters and event logs; never writes or clears them.
    Targets Windows PowerShell 5.1 so it runs on session hosts as-is.

    Complements rather than replaces:
      Get-CitrixVDAResources\Get-CitrixVDAResources.ps1  - deeper broker-side VDA detail
      Get-FSLogixStorageEvents\Get-FSLogixStorageEvents.ps1 - SMB correlation against
                                                              known re-attach timestamps
      CitrixVDADiagnostics\CitrixVDA-Consolidated.ps1    - deep single-machine diagnostics

    REFERENCES
    - Get-WinEvent (-ComputerName takes ONE computer at a time; does not rely on PowerShell
      remoting; -ListLog accepts wildcards; LogName queries hit a 256-log Windows API limit):
      https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
    - FilterHashtable keys and the Level enumeration (1=Critical, 2=Error, 3=Warning,
      4=Informational, 5=Verbose); wildcards valid only in LogName and ProviderName values:
      https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
    - StandardEventLevel enumeration:
      https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
    - Win32_PerfFormattedData_PerfOS_System (ProcessorQueueLength is a last-observed value,
      not an average; sustained >2 indicates congestion; single queue even on multiprocessor):
      https://learn.microsoft.com/en-us/previous-versions/aa394272(v=vs.85)
    - Processor queue guidance is NOT consistent across Microsoft's own documentation.
      The WMI class page says a sustained queue over 2 indicates congestion without
      normalizing; the Exchange counter guidance says "shouldn't be greater than 5 per
      processor"; the PAL guide says to divide by processor count and treats a queue
      exceeding the processor count as a bottleneck. All three agree the queue is a single
      system-wide queue, so this script normalizes per logical processor. See Get-QueueStatus.
      https://learn.microsoft.com/exchange/exchange-2013-performance-counters-exchange-2013-help#processor-and-process-counters
      https://learn.microsoft.com/biztalk/technical-guides/using-the-performance-analysis-of-logs-pal-tool#processor-queue-length-analysis
    - Win32_PerfFormattedData_PerfOS_Processor / _Total instance:
      https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-performance-data
    - Win32_ComputerSystem NumberOfLogicalProcessors (logical, not physical sockets - the
      distinction matters on every multicore VDA):
      https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem
    - Win32_OperatingSystem (memory properties are in KILOBYTES, LastBootUpTime):
      https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    - Win32_LogicalDisk (DriveType 3 = local fixed disk; Size/FreeSpace in BYTES):
      https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
    - FSLogix event channels live under Microsoft > FSLogix > Apps (Operational / Admin),
      with Cloud Cache writing to its own Admin / Operational channels:
      https://learn.microsoft.com/en-us/fslogix/troubleshooting-events-logs-diagnostics
    - New-CimSessionOption -Protocol Dcom, used as the fallback when WinRM is unavailable:
      https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsessionoption
    - Citrix publishes its event catalogs by service but not the literal Event Viewer
      channel names, which is why channels are discovered at runtime rather than hardcoded:
      https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/monitor/event-logs.html
#>

[CmdletBinding(DefaultParameterSetName = 'Broker')]
param(
    [Parameter(ParameterSetName = 'Broker')]
    [string]$DeliveryController = 'localhost',

    [Parameter(ParameterSetName = 'Broker')]
    [string]$DesktopGroupName,

    [Parameter(ParameterSetName = 'Broker')]
    [string]$CatalogName,

    [Parameter(ParameterSetName = 'Broker')]
    [string[]]$AdditionalComputerName,

    [Parameter(ParameterSetName = 'Broker')]
    [int]$MaxRecordCount = [int]::MaxValue,

    [Parameter(ParameterSetName = 'Broker')]
    [switch]$IncludeUnregistered,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateRange(0, 3600)]
    [int]$SampleSeconds = 30,

    [ValidateRange(1, 300)]
    [int]$SampleIntervalSeconds = 5,

    [ValidateRange(1, 100)]
    [int]$CpuWarnPercent = 80,

    [ValidateRange(1, 100)]
    [int]$CpuCriticalPercent = 90,

    [ValidateRange(1, 100)]
    [int]$MemoryWarnPercent = 80,

    [ValidateRange(1, 100)]
    [int]$MemoryCriticalPercent = 90,

    [ValidateRange(1, 100)]
    [int]$DiskWarnPercent = 80,

    [ValidateRange(1, 100)]
    [int]$DiskCriticalPercent = 90,

    [ValidateRange(1, 1000)]
    [double]$QueueWarnPerCpu = 2,

    [ValidateRange(1, 1000)]
    [double]$QueueCriticalPerCpu = 5,

    [datetime]$StartTime,

    [datetime]$EndTime,

    [ValidateRange(1, 720)]
    [int]$LastHours,

    [ValidateRange(1, 90)]
    [int]$LastDays,

    [ValidateRange(1, 5)]
    [int[]]$Level = @(1, 2, 3),

    [ValidateRange(1, 100000)]
    [int]$MaxEventsPerLog = 2000,

    [ValidateRange(1, 100000)]
    [int]$DegradedErrorCount = 5,

    [ValidateRange(1, 100000)]
    [int]$CriticalErrorCount = 25,

    [ValidateRange(1, 300)]
    [int]$ConnectionTimeoutSeconds = 15,

    [switch]$SkipPerformance,

    [switch]$SkipEvents,

    [string]$OutputPath = (Get-Location).Path,

    [switch]$NoOpen,

    [switch]$LoadFunctionsOnly
)

#region Console output

function Write-StatusLine {
    <#
    .SYNOPSIS
        Writes a timestamped, color-coded status line using the repo's standard prefixes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $color = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'INFO' { 'Cyan' }
    }

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ("[{0}]  {1}  {2}" -f $Status, $stamp, $Message) -ForegroundColor $color
}

#endregion

#region Shared helpers

function Get-LevelName {
    <#
    .SYNOPSIS
        Maps a Windows event Level number to its severity name.
    .DESCRIPTION
        The numbers come from the StandardEventLevel enumeration. Event Viewer shows these
        as localized strings, but the underlying values are locale-independent - which is
        why this script filters on the number and translates for display, never the reverse.
        https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
        https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[int]]$Level
    )

    switch ($Level) {
        0       { 'LogAlways' }
        1       { 'Critical' }
        2       { 'Error' }
        3       { 'Warning' }
        4       { 'Information' }
        5       { 'Verbose' }
        default { 'Unknown' }
    }
}

function Get-ResourceStatus {
    <#
    .SYNOPSIS
        Classifies a value against warn and critical thresholds.
    .DESCRIPTION
        Thresholds are inclusive: a value exactly at WarnAt is a warning, and exactly at
        CriticalAt is a failure. A null value means the metric could not be collected and
        returns UNKNOWN rather than a misleading PASS - an uncollected metric is never
        allowed to look healthy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[double]]$Value,

        [Parameter(Mandatory = $true)]
        [double]$WarnAt,

        [Parameter(Mandatory = $true)]
        [double]$CriticalAt
    )

    if ($null -eq $Value) { return 'UNKNOWN' }
    if ($Value -ge $CriticalAt) { return 'FAIL' }
    if ($Value -ge $WarnAt) { return 'WARN' }
    return 'PASS'
}

function Get-QueueStatus {
    <#
    .SYNOPSIS
        Classifies processor queue length, normalized per logical processor.
    .DESCRIPTION
        ProcessorQueueLength counts READY threads only, not running ones, and there is a
        single queue for the whole machine even when it has many processors. A raw threshold
        is therefore meaningless across a mixed fleet: a queue of 4 is severe on a 2-vCPU
        host and unremarkable on a 32-vCPU one.

        Microsoft's own published thresholds disagree, so this is worth stating plainly:
          - The WMI class page says "a sustained processor queue of greater than two threads
            generally indicates processor congestion", with no per-processor normalization.
          - The Exchange 2013 counter guidance says it "shouldn't be greater than 5 per processor".
          - The PAL guide says to divide by the processor count, calls a sustained queue
            above the processor count a bottleneck, and puts routine acceptability at under
            10 threads per processor.

        All three agree on the mechanism - one system-wide queue - so this function divides
        by the logical processor count and applies per-processor thresholds. The defaults
        (warn 2, critical 5) sit between the PAL bottleneck line and the Exchange ceiling.

        https://learn.microsoft.com/en-us/previous-versions/aa394272(v=vs.85)
        https://learn.microsoft.com/exchange/exchange-2013-performance-counters-exchange-2013-help#processor-and-process-counters
        https://learn.microsoft.com/biztalk/technical-guides/using-the-performance-analysis-of-logs-pal-tool#processor-queue-length-analysis

        Returns UNKNOWN when either the queue or the processor count is missing, rather than
        guessing at a processor count and producing a confident wrong answer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[double]]$AverageQueue,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[int]]$LogicalProcessors,

        [Parameter(Mandatory = $true)]
        [double]$WarnAt,

        [Parameter(Mandatory = $true)]
        [double]$CriticalAt
    )

    if ($null -eq $AverageQueue)      { return 'UNKNOWN' }
    if ($null -eq $LogicalProcessors) { return 'UNKNOWN' }
    if ($LogicalProcessors -le 0)     { return 'UNKNOWN' }

    $perCpu = $AverageQueue / $LogicalProcessors
    return Get-ResourceStatus -Value $perCpu -WarnAt $WarnAt -CriticalAt $CriticalAt
}

function Get-WorstStatus {
    <#
    .SYNOPSIS
        Returns the most severe status from a set, so one bad metric drives the row.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Statuses
    )

    if ($Statuses -contains 'FAIL') { return 'FAIL' }
    if ($Statuses -contains 'WARN') { return 'WARN' }
    if ($Statuses -contains 'PASS') { return 'PASS' }
    return 'UNKNOWN'
}

function Resolve-TimeWindow {
    <#
    .SYNOPSIS
        Resolves the event collection window from the script's time parameters.
    .DESCRIPTION
        Defaults to the last 24 hours when none were supplied. Callers pass only the
        parameters they want considered, so an unbound -LastHours never competes with a
        supplied -StartTime.

        Times are interpreted in the TARGET host's local time, which is how Get-WinEvent
        filters. On a fleet spanning time zones that matters - see the README.
    #>
    [CmdletBinding()]
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$LastHours,
        [int]$LastDays
    )

    $now   = Get-Date
    $bound = $PSBoundParameters

    if ($bound.ContainsKey('LastHours') -and $bound.ContainsKey('LastDays')) {
        throw "-LastHours and -LastDays are mutually exclusive. Specify only one."
    }

    if ($bound.ContainsKey('StartTime')) {
        if ($bound.ContainsKey('LastHours') -or $bound.ContainsKey('LastDays')) {
            throw "-StartTime cannot be combined with -LastHours or -LastDays."
        }
        $start = $StartTime
        $end   = if ($bound.ContainsKey('EndTime')) { $EndTime } else { $now }
    }
    elseif ($bound.ContainsKey('LastHours')) {
        $end   = $now
        $start = $now.AddHours(-$LastHours)
    }
    elseif ($bound.ContainsKey('LastDays')) {
        $end   = $now
        $start = $now.AddDays(-$LastDays)
    }
    else {
        $end   = $now
        $start = $now.AddHours(-24)
    }

    if ($end -le $start) {
        throw ("End of window ({0:yyyy-MM-dd HH:mm:ss}) must be after the start ({1:yyyy-MM-dd HH:mm:ss})." -f $end, $start)
    }

    return @{ Start = $start; End = $end }
}

#endregion

#region Discovery

function Import-CitrixBrokerSdk {
    <#
    .SYNOPSIS
        Loads the Citrix Broker SDK, trying the legacy PSSnapin before the module.
    .DESCRIPTION
        Loaded at runtime rather than via #Requires -Modules, because #Requires blocks
        execution before the script starts on servers where the SDK is present but not
        formally registered. Returns $true when Get-BrokerMachine is callable afterwards.
    #>
    [CmdletBinding()]
    param()

    if (Get-Command Get-BrokerMachine -ErrorAction SilentlyContinue) {
        return $true
    }

    try {
        Add-PSSnapin Citrix.Broker.Admin.V2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "PSSnapin Citrix.Broker.Admin.V2 unavailable: $_"
    }

    try {
        Import-Module Citrix.Broker.Admin.V2 -ErrorAction Stop
        return $true
    }
    catch {
        Write-Verbose "Module Citrix.Broker.Admin.V2 unavailable: $_"
    }

    return $false
}

function Get-VDAInventory {
    <#
    .SYNOPSIS
        Queries the Delivery Controller for VDAs and normalizes the broker fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DeliveryController,

        [string]$DesktopGroupName,

        [string]$CatalogName,

        [Parameter(Mandatory = $true)]
        [int]$MaxRecordCount
    )

    # Citrix Broker cmdlets return only the first 250 records when -MaxRecordCount is not
    # supplied; they emit a warning rather than an error. On a fleet larger than 250 VDAs
    # that silently under-reports while the output still looks complete, so the parameter
    # is always passed explicitly.
    # https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2511/Broker/about_Broker_Filtering.html
    $brokerArgs = @{
        AdminAddress   = $DeliveryController
        MaxRecordCount = $MaxRecordCount
        ErrorAction    = 'Stop'
    }

    if ($DesktopGroupName) { $brokerArgs['DesktopGroupName'] = $DesktopGroupName }
    if ($CatalogName)      { $brokerArgs['CatalogName']      = $CatalogName }

    $machines = Get-BrokerMachine @brokerArgs

    foreach ($m in $machines) {
        # Property names verified against the Citrix SDK reference:
        # https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerMachine.html
        #
        # DNSName is preferred as the connection target: MachineName is DOMAIN\NAME, which
        # is not resolvable, so handing it to New-CimSession would fail on every machine.
        $target = if ($m.DNSName) { $m.DNSName } else { ($m.MachineName -split '\\')[-1] }

        [PSCustomObject]@{
            ComputerName      = $target
            MachineName       = $m.MachineName
            Source            = 'Broker'
            CatalogName       = $m.CatalogName
            DeliveryGroup     = $m.DesktopGroupName
            RegistrationState = [string]$m.RegistrationState
            InMaintenanceMode = $m.InMaintenanceMode
            LoadIndex         = $m.LoadIndex
            SessionCount      = $m.SessionCount
            PowerState        = [string]$m.PowerState
        }
    }
}

function New-PlainTarget {
    <#
    .SYNOPSIS
        Builds an inventory entry for a machine supplied by name rather than by the broker.
    .DESCRIPTION
        Keeps explicitly named servers and broker-discovered VDAs in one shape, so every
        later stage - collection, roll-up, reporting - treats them identically. The broker
        fields are null because a file server genuinely has no delivery group, and null is
        honest where 'N/A' would be noise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Explicit', 'Additional')]
        [string]$Source
    )

    [PSCustomObject]@{
        ComputerName      = $ComputerName
        MachineName       = $ComputerName
        Source            = $Source
        CatalogName       = $null
        DeliveryGroup     = $null
        RegistrationState = $null
        InMaintenanceMode = $null
        LoadIndex         = $null
        SessionCount      = $null
        PowerState        = $null
    }
}

function Select-CollectionTarget {
    <#
    .SYNOPSIS
        Produces the final, de-duplicated target list from broker and explicit sources.
    .DESCRIPTION
        De-duplication is case-insensitive on ComputerName and keeps the FIRST entry, so a
        broker-discovered VDA retains its delivery group and catalog even if the same name
        is also passed to -AdditionalComputerName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Target,

        [switch]$IncludeUnregistered
    )

    $seen   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $result = @()

    foreach ($t in $Target) {
        if ([string]::IsNullOrWhiteSpace($t.ComputerName)) { continue }

        # Unregistered VDAs are skipped by default: a machine the broker cannot reach is
        # usually powered off, and sweeping it wastes the full connection timeout. This
        # only applies to broker-discovered machines - an explicitly named server is always
        # collected, because the operator asked for it by name.
        if ($t.Source -eq 'Broker' -and -not $IncludeUnregistered) {
            if ($t.RegistrationState -and $t.RegistrationState -ne 'Registered') { continue }
        }

        if ($seen.Add($t.ComputerName)) { $result += $t }
    }

    return $result
}

#endregion

#region Performance

function ConvertTo-MemoryMetrics {
    <#
    .SYNOPSIS
        Converts Win32_OperatingSystem memory values into GB and a used percentage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$TotalKb,

        [Parameter(Mandatory = $true)]
        [double]$FreeKb
    )

    # TotalVisibleMemorySize and FreePhysicalMemory carry a Units qualifier of "kilobytes",
    # NOT bytes. Win32_LogicalDisk in this same script reports BYTES - the two are different
    # and must never share a conversion.
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    $totalGB = [math]::Round(($TotalKb * 1KB) / 1GB, 2)
    $freeGB  = [math]::Round(($FreeKb * 1KB) / 1GB, 2)
    $usedGB  = [math]::Round($totalGB - $freeGB, 2)

    $usedPercent = $null
    if ($TotalKb -gt 0) {
        $usedPercent = [math]::Round((($TotalKb - $FreeKb) / $TotalKb) * 100, 1)
    }

    [PSCustomObject]@{
        TotalGB     = $totalGB
        UsedGB      = $usedGB
        FreeGB      = $freeGB
        UsedPercent = $usedPercent
    }
}

function ConvertTo-DiskMetrics {
    <#
    .SYNOPSIS
        Summarizes fixed disks and returns the worst used percentage across them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Disks
    )

    $parts   = @()
    $maxUsed = $null

    foreach ($disk in $Disks) {
        # Size and FreeSpace carry a units qualifier of "bytes".
        # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
        if (-not $disk.Size -or $disk.Size -le 0) { continue }

        $totalGB = [math]::Round($disk.Size / 1GB, 1)
        $freeGB  = [math]::Round($disk.FreeSpace / 1GB, 1)
        $usedGB  = [math]::Round($totalGB - $freeGB, 1)
        $pct     = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)

        $parts += "{0} {1}/{2}GB ({3}%)" -f $disk.DeviceID, $usedGB, $totalGB, $pct

        if ($null -eq $maxUsed -or $pct -gt $maxUsed) { $maxUsed = $pct }
    }

    [PSCustomObject]@{
        Summary        = ($parts -join '; ')
        MaxUsedPercent = $maxUsed
    }
}

function Get-UptimeDays {
    <#
    .SYNOPSIS
        Days since last boot, floored at zero so clock skew never yields a negative.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$LastBootUpTime,

        [Parameter(Mandatory = $true)]
        [datetime]$Now
    )

    $days = ($Now - $LastBootUpTime).TotalDays
    if ($days -lt 0) { return 0 }
    return [math]::Round($days, 1)
}

function Measure-SampleSet {
    <#
    .SYNOPSIS
        Reduces a set of readings to average, peak, and low, ignoring failed reads.
    .DESCRIPTION
        Nulls are dropped rather than treated as zero. A counter that failed on two of six
        samples must not drag the average toward zero and paint a busy host as idle.
        Returns nulls throughout when every reading failed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Value
    )

    $clean = @($Value | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })

    if ($clean.Count -eq 0) {
        return [PSCustomObject]@{ Average = $null; Peak = $null; Low = $null; Count = 0 }
    }

    $stats = $clean | Measure-Object -Average -Maximum -Minimum

    [PSCustomObject]@{
        Average = [math]::Round($stats.Average, 1)
        Peak    = [math]::Round($stats.Maximum, 1)
        Low     = [math]::Round($stats.Minimum, 1)
        Count   = $clean.Count
    }
}

function Get-SampleCount {
    <#
    .SYNOPSIS
        Works out how many readings fit in the requested sampling window.
    .DESCRIPTION
        -SampleSeconds 0 means "one instantaneous reading, no waiting". Otherwise the window
        is divided by the interval, with a floor of 2 - a "sampled" run that took a single
        reading would be a snapshot wearing a sampling label, and the peak column would be
        a lie.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$SampleSeconds,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 300)]
        [int]$IntervalSeconds
    )

    if ($SampleSeconds -le 0) { return 1 }

    $count = [math]::Floor($SampleSeconds / $IntervalSeconds)
    if ($count -lt 2) { return 2 }
    return [int]$count
}

function New-HealthCimSession {
    <#
    .SYNOPSIS
        Opens a CIM session, falling back from WinRM to DCOM.
    .DESCRIPTION
        New-CimSession speaks WSMan (WinRM) by default. Plenty of client estates have WinRM
        switched off but legacy WMI over DCOM still reachable, so a WinRM failure is retried
        over DCOM before the host is written off as unreachable.
        https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsessionoption

        Returns a hashtable with Session (or $null), Protocol, and ErrorMessage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $baseArgs = @{
        ComputerName        = $ComputerName
        OperationTimeoutSec = $TimeoutSeconds
        ErrorAction         = 'Stop'
    }
    if ($Credential) { $baseArgs['Credential'] = $Credential }

    try {
        $session = New-CimSession @baseArgs
        return @{ Session = $session; Protocol = 'WSMan'; ErrorMessage = $null }
    }
    catch {
        $wsmanError = $_.Exception.Message
        Write-Verbose "${ComputerName}: WSMan CIM session failed - $wsmanError"
    }

    try {
        $dcomOption = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession @baseArgs -SessionOption $dcomOption
        return @{ Session = $session; Protocol = 'DCOM'; ErrorMessage = $null }
    }
    catch {
        $dcomError = $_.Exception.Message
        Write-Verbose "${ComputerName}: DCOM CIM session failed - $dcomError"
        return @{
            Session      = $null
            Protocol     = 'None'
            ErrorMessage = ("WinRM: {0} | DCOM: {1}" -f $wsmanError, $dcomError)
        }
    }
}

function Get-PerformanceSample {
    <#
    .SYNOPSIS
        Collects sampled performance metrics from one host over CIM.
    .DESCRIPTION
        Static facts (processor count, total memory, disks, boot time) are read once. Volatile
        counters (CPU, processor queue, free memory) are read repeatedly across the sampling
        window and reduced to average, peak, and low.

        Sampling is what makes the numbers trustworthy on a session host. A single read of
        ProcessorQueueLength is explicitly documented as "the last observed value only; it is
        not an average", and CPU on a VDA swings hard as users log on - so one reading says
        almost nothing about the last five minutes.
        https://learn.microsoft.com/en-us/previous-versions/aa394272(v=vs.85)

        Individual counter failures are tolerated: the session opening at all proves the host
        was reachable, so a misbehaving counter yields a null metric rather than discarding
        the whole host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory = $true)]
        [int]$SampleCount,

        [Parameter(Mandatory = $true)]
        [int]$IntervalSeconds
    )

    $result = [PSCustomObject]@{
        CpuAveragePercent    = $null
        CpuPeakPercent       = $null
        MemoryAveragePercent = $null
        MemoryPeakPercent    = $null
        MemoryTotalGB        = $null
        MemoryUsedGB         = $null
        MemoryFreeGB         = $null
        QueueAverage         = $null
        QueuePeak            = $null
        QueuePerCpu          = $null
        LogicalProcessors    = $null
        DiskSummary          = $null
        MaxDiskUsedPercent   = $null
        UptimeDays           = $null
        OperatingSystem      = $null
        SampleCount          = 0
        Protocol             = 'None'
        Status               = 'Unreachable'
        ErrorMessage         = $null
        Samples              = @()
    }

    $connection = New-HealthCimSession -ComputerName $ComputerName -Credential $Credential -TimeoutSeconds $TimeoutSeconds

    if (-not $connection.Session) {
        $result.ErrorMessage = $connection.ErrorMessage
        return $result
    }

    $session          = $connection.Session
    $result.Protocol  = $connection.Protocol
    $memTotalKb       = $null

    try {
        # --- Static facts, read once -------------------------------------------------
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $session -ErrorAction Stop
            # NumberOfLogicalProcessors, not NumberOfProcessors: the latter counts physical
            # sockets, so a 1-socket 16-core VDA would report 1 and inflate queue-per-CPU 16x.
            # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem
            if ($cs.NumberOfLogicalProcessors) {
                $result.LogicalProcessors = [int]$cs.NumberOfLogicalProcessors
            }
        }
        catch {
            Write-Verbose "${ComputerName}: computer system query failed - $_"
        }

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session -ErrorAction Stop
            $memTotalKb              = [double]$os.TotalVisibleMemorySize
            $result.OperatingSystem  = $os.Caption
            $result.UptimeDays       = Get-UptimeDays -LastBootUpTime $os.LastBootUpTime -Now (Get-Date)
        }
        catch {
            Write-Verbose "${ComputerName}: OS query failed - $_"
        }

        # Fixed disks only. DriveType 3 is "Local Disk"; 2 is removable, 4 is network, 5 is
        # optical - none of which belong in a capacity verdict.
        # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
        try {
            $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -CimSession $session -ErrorAction Stop)
            $diskMetrics = ConvertTo-DiskMetrics -Disks $disks

            $result.DiskSummary        = $diskMetrics.Summary
            $result.MaxDiskUsedPercent = $diskMetrics.MaxUsedPercent
        }
        catch {
            Write-Verbose "${ComputerName}: disk query failed - $_"
        }

        # --- Volatile counters, sampled ----------------------------------------------
        $cpuReadings   = @()
        $queueReadings = @()
        $memReadings   = @()
        $samples       = @()

        for ($i = 1; $i -le $SampleCount; $i++) {
            $takenAt   = Get-Date
            $cpuValue  = $null
            $queueValue = $null
            $memValue  = $null

            # The _Total instance is the aggregate across all processors.
            # https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-performance-data
            try {
                $cpu = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor `
                    -Filter "Name = '_Total'" -CimSession $session -ErrorAction Stop
                if ($cpu) { $cpuValue = [math]::Round([double]$cpu.PercentProcessorTime, 1) }
            }
            catch {
                Write-Verbose "${ComputerName}: CPU sample $i failed - $_"
            }

            try {
                $sys = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System `
                    -CimSession $session -ErrorAction Stop | Select-Object -First 1
                if ($sys) { $queueValue = [double]$sys.ProcessorQueueLength }
            }
            catch {
                Write-Verbose "${ComputerName}: processor queue sample $i failed - $_"
            }

            # Free memory is re-read every sample: it is the half of the memory equation that
            # actually moves, and a peak matters more than an average when a host is thrashing.
            if ($null -ne $memTotalKb -and $memTotalKb -gt 0) {
                try {
                    $osSample = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session -ErrorAction Stop
                    $mem = ConvertTo-MemoryMetrics -TotalKb $memTotalKb -FreeKb ([double]$osSample.FreePhysicalMemory)
                    $memValue = $mem.UsedPercent

                    $result.MemoryTotalGB = $mem.TotalGB
                    $result.MemoryUsedGB  = $mem.UsedGB
                    $result.MemoryFreeGB  = $mem.FreeGB
                }
                catch {
                    Write-Verbose "${ComputerName}: memory sample $i failed - $_"
                }
            }

            $cpuReadings   += $cpuValue
            $queueReadings += $queueValue
            $memReadings   += $memValue

            $samples += [PSCustomObject]@{
                ComputerName        = $ComputerName
                SampleNumber        = $i
                TakenAt             = $takenAt
                CpuPercent          = $cpuValue
                ProcessorQueue      = $queueValue
                MemoryUsedPercent   = $memValue
            }

            if ($i -lt $SampleCount) { Start-Sleep -Seconds $IntervalSeconds }
        }

        $cpuStats   = Measure-SampleSet -Value $cpuReadings
        $queueStats = Measure-SampleSet -Value $queueReadings
        $memStats   = Measure-SampleSet -Value $memReadings

        $result.CpuAveragePercent    = $cpuStats.Average
        $result.CpuPeakPercent       = $cpuStats.Peak
        $result.QueueAverage         = $queueStats.Average
        $result.QueuePeak            = $queueStats.Peak
        $result.MemoryAveragePercent = $memStats.Average
        $result.MemoryPeakPercent    = $memStats.Peak
        $result.SampleCount          = $SampleCount
        $result.Samples              = $samples

        if ($null -ne $queueStats.Average -and $result.LogicalProcessors -gt 0) {
            $result.QueuePerCpu = [math]::Round($queueStats.Average / $result.LogicalProcessors, 2)
        }

        $result.Status = 'Success'
    }
    catch {
        $result.Status       = 'Unreachable'
        $result.ErrorMessage = $_.Exception.Message
    }
    finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }

    return $result
}

#endregion

#region Events

function Test-IsLocalComputer {
    <#
    .SYNOPSIS
        True when the supplied name refers to the machine this script is running on.
    .DESCRIPTION
        Matters because Get-WinEvent rejects a credential on a local connection with
        "The user credential cannot be used for local connections". Passing -Credential
        blindly would break the single most common case: running the script on one of the
        session hosts it is reporting on.

        -LocalName exists so the behaviour can be tested without depending on the ambient
        COMPUTERNAME of whatever machine the suite runs on. It defaults to the real value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ComputerName,

        [AllowEmptyString()]
        [AllowNull()]
        [string]$LocalName = $env:COMPUTERNAME
    )

    # No name at all means "right here" - that is how every cmdlet in this script behaves
    # when -ComputerName is omitted.
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }

    $name = $ComputerName.Trim()

    $local = @('localhost', '.', '127.0.0.1', '::1')
    if ($local -contains $name) { return $true }

    # COMPUTERNAME should always be set on Windows, but if it somehow is not, fall back to
    # treating only the literal loopback names above as local. Comparing against an empty
    # string would make every short-named host look local and silently drop -Credential
    # from every remote query.
    if ([string]::IsNullOrWhiteSpace($LocalName)) { return $false }

    if ($name -eq $LocalName) { return $true }

    # Match on the short name too, so CTXVDA01.contoso.local resolves as local on CTXVDA01.
    $short = ($name -split '\.')[0]
    if ([string]::IsNullOrWhiteSpace($short)) { return $false }

    return ($short -eq $LocalName)
}

function Get-EventChannelPattern {
    <#
    .SYNOPSIS
        The wildcard patterns used to discover event channels on each target.
    .DESCRIPTION
        Citrix publishes its event catalogs per service but does NOT publish the literal
        Event Viewer channel names, and those names have differed between product versions.
        Hardcoding a guessed channel name is the worst possible failure here: the query
        succeeds, returns zero rows, and the report confidently shows a clean bill of health
        for a broken VDA. So Citrix channels are matched by pattern against what the target
        actually has, and whatever is found gets queried.
        https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/monitor/event-logs.html

        FSLogix channel names ARE documented - Applications and Services Logs > Microsoft >
        FSLogix > Apps (Operational / Admin), with Cloud Cache writing to its own channels -
        so those patterns are anchored rather than open-ended.
        https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
    #>
    [CmdletBinding()]
    param()

    @(
        [PSCustomObject]@{ Pattern = 'Microsoft-FSLogix-*';                        Category = 'FSLogix' }
        [PSCustomObject]@{ Pattern = '*Citrix*';                                   Category = 'Citrix'  }
        [PSCustomObject]@{ Pattern = 'Microsoft-Windows-TerminalServices-*';       Category = 'RDS'     }
        [PSCustomObject]@{ Pattern = 'Microsoft-Windows-RemoteDesktopServices*';   Category = 'RDS'     }
        [PSCustomObject]@{ Pattern = 'Microsoft-Windows-SMBClient/*';              Category = 'Storage' }
        [PSCustomObject]@{ Pattern = 'Microsoft-Windows-SMBServer/*';              Category = 'Storage' }
        [PSCustomObject]@{ Pattern = 'Microsoft-Windows-User Profile Service/*';   Category = 'Profile' }
    )
}

function Get-ClassicLogProviderPattern {
    <#
    .SYNOPSIS
        Provider patterns used to narrow the noisy System and Application logs.
    .DESCRIPTION
        System and Application are far too busy to pull wholesale across a fleet, so they are
        filtered to the providers that actually explain Citrix and FSLogix failures - storage
        stack, SMB redirector, profile service, and the session stack.

        FilterHashtable accepts wildcards in ProviderName values, but an unmatched literal
        provider raises an error, so Resolve-EventProvider resolves these to the names present
        on each host before querying.
        https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
    #>
    [CmdletBinding()]
    param()

    @(
        [PSCustomObject]@{
            LogName  = 'System'
            Category = 'Storage'
            Patterns = @(
                'disk', 'Disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'volsnap', 'srv', 'srv2',
                'LanmanWorkstation', 'LanmanServer', 'Microsoft-Windows-StorageSpaces-*',
                'Microsoft-Windows-Storage*', 'iScsiPrt', 'mpio', 'Microsoft-Windows-FailoverClustering'
            )
        }
        [PSCustomObject]@{
            LogName  = 'System'
            Category = 'RDS'
            Patterns = @('TermService', 'TermDD', 'Microsoft-Windows-TerminalServices*', 'RemoteDesktopServices*')
        }
        [PSCustomObject]@{
            LogName  = 'System'
            Category = 'Citrix'
            Patterns = @('*Citrix*')
        }
        [PSCustomObject]@{
            LogName  = 'Application'
            Category = 'Profile'
            Patterns = @(
                'Microsoft-Windows-Winlogon', 'Microsoft-Windows-User Profiles Service',
                'Microsoft-Windows-GroupPolicy', 'Microsoft-Windows-Folder Redirection'
            )
        }
        [PSCustomObject]@{
            LogName  = 'Application'
            Category = 'Citrix'
            Patterns = @('*Citrix*')
        }
        [PSCustomObject]@{
            LogName  = 'Application'
            Category = 'FSLogix'
            Patterns = @('*FSLogix*', '*frxsvc*', '*frxccds*')
        }
    )
}

function Get-TargetEventChannel {
    <#
    .SYNOPSIS
        Discovers which of the interesting event channels actually exist on one host.
    .DESCRIPTION
        -ListLog accepts wildcards, so each pattern is resolved against the target rather
        than assumed. Channels with no records are dropped so they are not queried for
        nothing, and disabled channels are skipped for the same reason.

        Debug and analytic channels are deliberately NOT requested: -Force would be needed
        to return them, they are enormous, and they are not where administrative failures
        are reported.
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential
    )

    $channels = @()
    $seen     = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in (Get-EventChannelPattern)) {
        $listArgs = @{ ListLog = $entry.Pattern; ErrorAction = 'SilentlyContinue' }
        if (-not (Test-IsLocalComputer -ComputerName $ComputerName)) {
            $listArgs['ComputerName'] = $ComputerName
            if ($Credential) { $listArgs['Credential'] = $Credential }
        }

        try {
            $logs = @(Get-WinEvent @listArgs)
        }
        catch {
            Write-Verbose "${ComputerName}: channel discovery for '$($entry.Pattern)' failed - $_"
            continue
        }

        foreach ($log in $logs) {
            if (-not $log.IsEnabled)   { continue }
            if (-not $log.RecordCount) { continue }
            if (-not $seen.Add($log.LogName)) { continue }

            $channels += [PSCustomObject]@{
                LogName  = $log.LogName
                Category = $entry.Category
            }
        }
    }

    return $channels
}

function Resolve-EventProvider {
    <#
    .SYNOPSIS
        Resolves provider wildcards to the provider names present on one host.
    .DESCRIPTION
        Passing a literal provider that does not exist on the target makes Get-WinEvent
        throw, which would abort an otherwise good query. Resolving first means the query
        only ever names providers the host actually has - and if none match, the caller
        skips the log entirely instead of scanning it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string[]]$Pattern,

        [System.Management.Automation.PSCredential]$Credential
    )

    $listArgs = @{ ListProvider = $Pattern; ErrorAction = 'SilentlyContinue' }
    if (-not (Test-IsLocalComputer -ComputerName $ComputerName)) {
        $listArgs['ComputerName'] = $ComputerName
        if ($Credential) { $listArgs['Credential'] = $Credential }
    }

    try {
        return @(Get-WinEvent @listArgs | Select-Object -ExpandProperty Name -Unique)
    }
    catch {
        Write-Verbose "${ComputerName}: provider resolution failed - $_"
        return @()
    }
}

function Invoke-EventQuery {
    <#
    .SYNOPSIS
        Runs one FilterHashtable query against one host and returns raw event records.
    .DESCRIPTION
        "No events were found" is Get-WinEvent's way of reporting an empty result set, and
        it arrives as a terminating error. Treating it as a failure would turn every quiet,
        healthy channel into a red line in the console, so it is recognized and swallowed
        while genuine failures still surface.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Filter,

        [Parameter(Mandatory = $true)]
        [int]$MaxEvents,

        [System.Management.Automation.PSCredential]$Credential
    )

    $queryArgs = @{
        FilterHashtable = $Filter
        MaxEvents       = $MaxEvents
        ErrorAction     = 'Stop'
    }

    # -ComputerName takes exactly ONE computer at a time, which is why the caller loops
    # rather than handing in an array. Get-WinEvent does not use PowerShell remoting - it
    # reaches the target over RPC - so this works where WinRM is closed.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent
    if (-not (Test-IsLocalComputer -ComputerName $ComputerName)) {
        $queryArgs['ComputerName'] = $ComputerName
        if ($Credential) { $queryArgs['Credential'] = $Credential }
    }

    try {
        return @(Get-WinEvent @queryArgs)
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

function ConvertTo-HealthEvent {
    <#
    .SYNOPSIS
        Flattens an EventLogRecord into the shape used by the CSV and HTML output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [int]$MessageMaxLength
    )

    $message = $Record.Message
    if ([string]::IsNullOrEmpty($message)) {
        # A null Message usually means the provider's message DLL is not registered on the
        # machine running this script. Say so, rather than leaving a blank cell that reads
        # as "nothing happened".
        $message = '(no message text available - provider metadata not registered on this machine)'
    }
    elseif ($MessageMaxLength -gt 0 -and $message.Length -gt $MessageMaxLength) {
        $message = $message.Substring(0, $MessageMaxLength) + '...'
    }

    $message = ($message -replace '\s+', ' ').Trim()

    [PSCustomObject]@{
        ComputerName = $ComputerName
        TimeCreated  = $Record.TimeCreated
        Category     = $Category
        LogName      = $Record.LogName
        ProviderName = $Record.ProviderName
        Id           = $Record.Id
        Level        = $Record.Level
        LevelName    = Get-LevelName -Level $Record.Level
        Message      = $message
    }
}

function Get-HostEvent {
    <#
    .SYNOPSIS
        Collects every relevant event from one host for the requested window.
    .DESCRIPTION
        Walks the discovered channels first, then the provider-filtered classic logs. Each
        channel is queried inside its own try/catch so one permission failure or corrupt log
        cannot take the host's whole event collection with it.

        Returns a hashtable: Events, Status, ErrorMessage, ChannelsQueried.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [datetime]$Start,

        [Parameter(Mandatory = $true)]
        [datetime]$End,

        [Parameter(Mandatory = $true)]
        [int[]]$Level,

        [Parameter(Mandatory = $true)]
        [int]$MaxEvents,

        [System.Management.Automation.PSCredential]$Credential,

        [int]$MessageMaxLength = 500
    )

    $events      = @()
    $queried     = 0
    $failures    = 0
    $firstError  = $null

    # --- Discovered channels ---------------------------------------------------------
    $channels = @()
    try {
        $channels = @(Get-TargetEventChannel -ComputerName $ComputerName -Credential $Credential)
    }
    catch {
        $firstError = $_.Exception.Message
    }

    foreach ($channel in $channels) {
        $filter = @{
            LogName   = $channel.LogName
            StartTime = $Start
            EndTime   = $End
            Level     = $Level
        }

        try {
            $records = Invoke-EventQuery -ComputerName $ComputerName -Filter $filter `
                -MaxEvents $MaxEvents -Credential $Credential
            $queried++

            foreach ($r in $records) {
                $events += ConvertTo-HealthEvent -Record $r -ComputerName $ComputerName `
                    -Category $channel.Category -MessageMaxLength $MessageMaxLength
            }
        }
        catch {
            $failures++
            if (-not $firstError) { $firstError = $_.Exception.Message }
            Write-Verbose "${ComputerName}: query of '$($channel.LogName)' failed - $_"
        }
    }

    # --- Classic logs, narrowed by provider ------------------------------------------
    foreach ($group in (Get-ClassicLogProviderPattern)) {
        $providers = Resolve-EventProvider -ComputerName $ComputerName -Pattern $group.Patterns -Credential $Credential
        if (-not $providers -or $providers.Count -eq 0) { continue }

        $filter = @{
            LogName      = $group.LogName
            ProviderName = $providers
            StartTime    = $Start
            EndTime      = $End
            Level        = $Level
        }

        try {
            $records = Invoke-EventQuery -ComputerName $ComputerName -Filter $filter `
                -MaxEvents $MaxEvents -Credential $Credential
            $queried++

            foreach ($r in $records) {
                $events += ConvertTo-HealthEvent -Record $r -ComputerName $ComputerName `
                    -Category $group.Category -MessageMaxLength $MessageMaxLength
            }
        }
        catch {
            $failures++
            if (-not $firstError) { $firstError = $_.Exception.Message }
            Write-Verbose "${ComputerName}: query of '$($group.LogName)' failed - $_"
        }
    }

    # Nothing queried successfully means the event log was not reachable at all. Some
    # channels answering and others failing is normal (permissions vary per log), and is
    # reported as Partial so the report never implies coverage it did not achieve.
    $status = 'Success'
    if ($queried -eq 0)      { $status = 'Unreachable' }
    elseif ($failures -gt 0) { $status = 'Partial' }

    return @{
        Events          = $events
        Status          = $status
        ErrorMessage    = $firstError
        ChannelsQueried = $queried
    }
}

#endregion

#region Roll-up

function Get-HostVerdict {
    <#
    .SYNOPSIS
        Reduces one host's metrics and event counts to a single verdict plus the reasons.
    .DESCRIPTION
        The reasons are the point. A verdict with no explanation just moves the
        investigation rather than advancing it, so every verdict carries the plain-English
        findings that produced it - phrased for someone who started in IT last month, with
        the numbers a senior engineer needs to act on.

        Unreachable is reserved for a host that answered NEITHER performance nor events.
        A host that refused WinRM but answered the event log is not unreachable; it is a
        host with partial data, and its events still count toward its verdict.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Status,

        [Parameter(Mandatory = $true)]
        [hashtable]$Metric,

        [Parameter(Mandatory = $true)]
        [hashtable]$EventCount,

        [Parameter(Mandatory = $true)]
        [int]$DegradedErrorCount,

        [Parameter(Mandatory = $true)]
        [int]$CriticalErrorCount
    )

    $reasons = @()

    if ($Status.Performance -eq 'Unreachable' -and $Status.Events -eq 'Unreachable') {
        return [PSCustomObject]@{
            Verdict = 'Unreachable'
            Reasons = @('Could not be contacted for performance data or event logs.')
        }
    }

    if ($Status.Performance -eq 'Unreachable') {
        $reasons += 'Performance data could not be collected (WinRM and DCOM both refused). Event data below is still valid.'
    }
    if ($Status.Events -eq 'Unreachable') {
        $reasons += 'Event logs could not be read. Performance data below is still valid.'
    }
    if ($Status.Events -eq 'Partial') {
        $reasons += 'Some event logs could not be read, so the counts below may be incomplete.'
    }

    # --- Performance findings --------------------------------------------------------
    if ($Metric.CpuStatus -eq 'FAIL') {
        $reasons += ("Processor is overloaded - averaged {0}% during the sample, peaking at {1}%." -f $Metric.CpuAverage, $Metric.CpuPeak)
    }
    elseif ($Metric.CpuStatus -eq 'WARN') {
        $reasons += ("Processor is running hot - averaged {0}%, peaking at {1}%." -f $Metric.CpuAverage, $Metric.CpuPeak)
    }

    if ($Metric.MemoryStatus -eq 'FAIL') {
        $reasons += ("Memory is nearly exhausted - averaged {0}% in use, peaking at {1}%." -f $Metric.MemoryAverage, $Metric.MemoryPeak)
    }
    elseif ($Metric.MemoryStatus -eq 'WARN') {
        $reasons += ("Memory is running high - averaged {0}% in use, peaking at {1}%." -f $Metric.MemoryAverage, $Metric.MemoryPeak)
    }

    if ($Metric.DiskStatus -eq 'FAIL') {
        $reasons += ("Disk is nearly full - {0}." -f $Metric.DiskSummary)
    }
    elseif ($Metric.DiskStatus -eq 'WARN') {
        $reasons += ("Disk space is getting low - {0}." -f $Metric.DiskSummary)
    }

    if ($Metric.QueueStatus -eq 'FAIL' -or $Metric.QueueStatus -eq 'WARN') {
        $reasons += ("Work is queueing for the processor - {0} threads waiting across {1} logical processors ({2} per processor)." -f `
            $Metric.QueueAverage, $Metric.LogicalProcessors, $Metric.QueuePerCpu)
    }

    # --- Event findings --------------------------------------------------------------
    if ($EventCount.Critical -gt 0) {
        $reasons += ("{0} critical event(s) logged in the window." -f $EventCount.Critical)
    }
    if ($EventCount.Error -ge $CriticalErrorCount) {
        $reasons += ("{0} error events logged - at or above the critical threshold of {1}." -f $EventCount.Error, $CriticalErrorCount)
    }
    elseif ($EventCount.Error -ge $DegradedErrorCount) {
        $reasons += ("{0} error events logged - at or above the warning threshold of {1}." -f $EventCount.Error, $DegradedErrorCount)
    }
    elseif ($EventCount.Error -gt 0) {
        $reasons += ("{0} error event(s) logged - below the threshold that would flag this host." -f $EventCount.Error)
    }

    # --- Verdict ---------------------------------------------------------------------
    $perfWorst = Get-WorstStatus -Statuses @(
        $Metric.CpuStatus, $Metric.MemoryStatus, $Metric.DiskStatus, $Metric.QueueStatus
    )

    $verdict = 'Healthy'

    if ($perfWorst -eq 'WARN' -or $EventCount.Error -ge $DegradedErrorCount) {
        $verdict = 'Degraded'
    }

    if ($perfWorst -eq 'FAIL' -or $EventCount.Critical -gt 0 -or $EventCount.Error -ge $CriticalErrorCount) {
        $verdict = 'Critical'
    }

    if ($verdict -eq 'Healthy' -and $reasons.Count -eq 0) {
        $reasons += 'No problems found. Resource use and event history are both within thresholds.'
    }

    [PSCustomObject]@{
        Verdict = $verdict
        Reasons = $reasons
    }
}

function New-HostResult {
    <#
    .SYNOPSIS
        Merges inventory, performance, and events into the single row per host that the
        CSV and HTML are both built from.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Inventory,

        [Parameter(Mandatory = $true)]
        [object]$Performance,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Event,

        [Parameter(Mandatory = $true)]
        [string]$EventStatus,

        [Parameter(Mandatory = $true)]
        [hashtable]$Threshold
    )

    $cpuStatus = Get-ResourceStatus -Value $Performance.CpuAveragePercent `
        -WarnAt $Threshold.CpuWarn -CriticalAt $Threshold.CpuCritical
    $memStatus = Get-ResourceStatus -Value $Performance.MemoryAveragePercent `
        -WarnAt $Threshold.MemoryWarn -CriticalAt $Threshold.MemoryCritical
    $diskStatus = Get-ResourceStatus -Value $Performance.MaxDiskUsedPercent `
        -WarnAt $Threshold.DiskWarn -CriticalAt $Threshold.DiskCritical
    $queueStatus = Get-QueueStatus -AverageQueue $Performance.QueueAverage `
        -LogicalProcessors $Performance.LogicalProcessors `
        -WarnAt $Threshold.QueueWarnPerCpu -CriticalAt $Threshold.QueueCriticalPerCpu

    $counts = @{
        Critical = @($Event | Where-Object { $_.Level -eq 1 }).Count
        Error    = @($Event | Where-Object { $_.Level -eq 2 }).Count
        Warning  = @($Event | Where-Object { $_.Level -eq 3 }).Count
        Total    = @($Event).Count
    }

    $verdict = Get-HostVerdict `
        -Status @{ Performance = $Performance.Status; Events = $EventStatus } `
        -Metric @{
            CpuStatus         = $cpuStatus
            CpuAverage        = $Performance.CpuAveragePercent
            CpuPeak           = $Performance.CpuPeakPercent
            MemoryStatus      = $memStatus
            MemoryAverage     = $Performance.MemoryAveragePercent
            MemoryPeak        = $Performance.MemoryPeakPercent
            DiskStatus        = $diskStatus
            DiskSummary       = $Performance.DiskSummary
            QueueStatus       = $queueStatus
            QueueAverage      = $Performance.QueueAverage
            QueuePerCpu       = $Performance.QueuePerCpu
            LogicalProcessors = $Performance.LogicalProcessors
        } `
        -EventCount $counts `
        -DegradedErrorCount $Threshold.DegradedErrorCount `
        -CriticalErrorCount $Threshold.CriticalErrorCount

    # Top offender, for the "what is actually wrong" column. Grouping by provider and event
    # ID rather than by message, because messages carry per-instance detail (user names,
    # paths) that would split one recurring fault into dozens of unique strings.
    $topIssue = $null
    $errorish = @($Event | Where-Object { $_.Level -le 2 })
    if ($errorish.Count -gt 0) {
        $group = $errorish | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 1
        if ($group) {
            $sample = $group.Group[0]
            $topIssue = "{0} (ID {1}) x{2}" -f $sample.ProviderName, $sample.Id, $group.Count
        }
    }

    [PSCustomObject]@{
        ComputerName         = $Inventory.ComputerName
        Verdict              = $verdict.Verdict
        Reasons              = ($verdict.Reasons -join ' ')
        Source               = $Inventory.Source
        DeliveryGroup        = $Inventory.DeliveryGroup
        CatalogName          = $Inventory.CatalogName
        RegistrationState    = $Inventory.RegistrationState
        InMaintenanceMode    = $Inventory.InMaintenanceMode
        SessionCount         = $Inventory.SessionCount
        LoadIndex            = $Inventory.LoadIndex
        OperatingSystem      = $Performance.OperatingSystem
        LogicalProcessors    = $Performance.LogicalProcessors
        CpuAveragePercent    = $Performance.CpuAveragePercent
        CpuPeakPercent       = $Performance.CpuPeakPercent
        CpuStatus            = $cpuStatus
        MemoryAveragePercent = $Performance.MemoryAveragePercent
        MemoryPeakPercent    = $Performance.MemoryPeakPercent
        MemoryTotalGB        = $Performance.MemoryTotalGB
        MemoryUsedGB         = $Performance.MemoryUsedGB
        MemoryStatus         = $memStatus
        DiskSummary          = $Performance.DiskSummary
        MaxDiskUsedPercent   = $Performance.MaxDiskUsedPercent
        DiskStatus           = $diskStatus
        QueueAverage         = $Performance.QueueAverage
        QueuePeak            = $Performance.QueuePeak
        QueuePerCpu          = $Performance.QueuePerCpu
        QueueStatus          = $queueStatus
        UptimeDays           = $Performance.UptimeDays
        CriticalEvents       = $counts.Critical
        ErrorEvents          = $counts.Error
        WarningEvents        = $counts.Warning
        TotalEvents          = $counts.Total
        TopIssue             = $topIssue
        SampleCount          = $Performance.SampleCount
        Protocol             = $Performance.Protocol
        PerformanceStatus    = $Performance.Status
        EventStatus          = $EventStatus
        ErrorMessage         = $Performance.ErrorMessage
    }
}

#endregion

#region Reporting

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        Escapes text for safe inclusion in HTML.
    .DESCRIPTION
        Event messages are attacker-adjacent data - they carry file paths, user names, and
        whatever a failing application decided to log. None of it is trusted into the DOM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    # Ampersand first, or it would double-escape the entities added after it.
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Format-MetricCell {
    <#
    .SYNOPSIS
        Renders one metric as a labelled bar, or an explicit "not collected" marker.
    .DESCRIPTION
        A missing metric renders as a dash with a tooltip rather than a zero-width bar,
        because an empty bar reads as "zero percent" - the single most dangerous
        misreading available in a health report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[double]]$Percent,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [AllowNull()]
        [System.Nullable[double]]$Peak
    )

    if ($null -eq $Percent) {
        return '<span class="nodata" title="This metric could not be collected from this host">--</span>'
    }

    $class = switch ($Status) {
        'FAIL'  { 'bar-fail' }
        'WARN'  { 'bar-warn' }
        'PASS'  { 'bar-pass' }
        default { 'bar-unknown' }
    }

    $width = [math]::Min([math]::Max($Percent, 0), 100)

    $peakMark = ''
    if ($null -ne $Peak -and $Peak -gt $Percent) {
        $peakPos = [math]::Min([math]::Max($Peak, 0), 100)
        $peakMark = '<span class="peak" style="left:{0}%" title="Peak {1}%"></span>' -f $peakPos, $Peak
    }

    $label = '{0}%' -f $Percent
    if ($null -ne $Peak -and $Peak -gt $Percent) {
        $label = '{0}% <span class="peaktext">pk {1}%</span>' -f $Percent, $Peak
    }

    return ('<div class="metric"><div class="track"><div class="fill {0}" style="width:{1}%"></div>{2}</div><div class="mval">{3}</div></div>' -f `
        $class, $width, $peakMark, $label)
}

function Get-ReportStyle {
    <#
    .SYNOPSIS
        The report's stylesheet. Kept in one place so the visual language stays consistent.
    #>
    [CmdletBinding()]
    param()

    # Single-quoted here-string: the CSS must reach the page exactly as written, with no
    # PowerShell expansion of anything that looks like a variable.
    return @'
:root{
  --bg:#0e1116; --panel:#161b22; --panel2:#1c232c; --line:#2a323d;
  --ink:#e6edf3; --ink2:#9fb0c3; --ink3:#6e7f91;
  --accent:#5dade2; --accent2:#3d8fc4;
  --pass:#3fb950; --warn:#d29922; --fail:#f85149; --unknown:#6e7f91;
}
*{box-sizing:border-box}
body{margin:0;padding:0;background:var(--bg);color:var(--ink);
  font-family:"Segoe UI",system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.5}
header{padding:28px 32px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 6px;font-size:24px;font-weight:700;letter-spacing:-.02em}
h1 .mark{color:var(--accent)}
.sub{color:var(--ink2);font-size:13px}
.sub strong{color:var(--ink);font-weight:600}
main{padding:24px 32px 56px}
h2{font-size:15px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--ink2);margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h2:first-of-type{margin-top:8px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:8px}
.tile{flex:1 1 150px;background:var(--panel);border:1px solid var(--line);
  border-left:3px solid var(--ink3);border-radius:6px;padding:14px 16px}
.tile .n{font-size:28px;font-weight:700;letter-spacing:-.02em}
.tile .l{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--ink2);margin-top:2px}
.tile.ok{border-left-color:var(--pass)} .tile.ok .n{color:var(--pass)}
.tile.deg{border-left-color:var(--warn)} .tile.deg .n{color:var(--warn)}
.tile.crit{border-left-color:var(--fail)} .tile.crit .n{color:var(--fail)}
.tile.unk{border-left-color:var(--unknown)} .tile.unk .n{color:var(--ink3)}
.tile.acc{border-left-color:var(--accent)} .tile.acc .n{color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--panel);
  border:1px solid var(--line);border-radius:6px;overflow:hidden}
th{background:var(--panel2);text-align:left;padding:10px 12px;font-size:11px;
  text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);
  font-weight:700;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--panel2)}
.host{font-weight:600;font-family:Consolas,"Cascadia Mono",monospace;font-size:13px}
.ctx{color:var(--ink3);font-size:11px;margin-top:2px}
.pill{display:inline-block;padding:3px 9px;border-radius:4px;font-size:11px;
  font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.p-ok{background:rgba(63,185,80,.15);color:var(--pass);border:1px solid rgba(63,185,80,.35)}
.p-deg{background:rgba(210,153,34,.15);color:var(--warn);border:1px solid rgba(210,153,34,.35)}
.p-crit{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.35)}
.p-unk{background:rgba(110,127,145,.15);color:var(--ink3);border:1px solid rgba(110,127,145,.35)}
.metric{display:flex;align-items:center;gap:8px;min-width:120px}
.track{position:relative;flex:1;height:7px;background:var(--panel2);
  border-radius:4px;overflow:visible;border:1px solid var(--line)}
.fill{height:100%;border-radius:3px}
.bar-pass{background:var(--pass)} .bar-warn{background:var(--warn)}
.bar-fail{background:var(--fail)} .bar-unknown{background:var(--unknown)}
.peak{position:absolute;top:-3px;width:2px;height:13px;background:var(--ink);opacity:.75;border-radius:1px}
.mval{font-size:12px;font-variant-numeric:tabular-nums;white-space:nowrap;min-width:38px;text-align:right}
.peaktext{color:var(--ink3);font-size:10px}
.nodata{color:var(--ink3);font-style:italic}
.num{font-variant-numeric:tabular-nums;text-align:right}
.c-crit{color:var(--fail);font-weight:700}
.c-err{color:var(--warn);font-weight:600}
.c-zero{color:var(--ink3)}
.why{color:var(--ink2);font-size:12px;max-width:520px}
.issue{font-family:Consolas,"Cascadia Mono",monospace;font-size:11px;color:var(--ink2)}
.msg{color:var(--ink2);font-size:12px;max-width:640px}
.legend{margin-top:10px;color:var(--ink3);font-size:11px}
footer{padding:20px 32px 40px;color:var(--ink3);font-size:11px;border-top:1px solid var(--line)}
footer code{color:var(--ink2)}
.empty{padding:24px;text-align:center;color:var(--ink3);background:var(--panel);
  border:1px solid var(--line);border-radius:6px}
'@
}

function New-HealthHtmlReport {
    <#
    .SYNOPSIS
        Builds the self-contained fleet health report.
    .DESCRIPTION
        No external stylesheets, fonts, or scripts - the file has to survive being emailed
        to a client and opened on a machine with no internet access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Event,

        [Parameter(Mandatory = $true)]
        [hashtable]$RunContext
    )

    $sb = New-Object System.Text.StringBuilder

    $total       = @($Result).Count
    $healthy     = @($Result | Where-Object Verdict -eq 'Healthy').Count
    $degraded    = @($Result | Where-Object Verdict -eq 'Degraded').Count
    $critical    = @($Result | Where-Object Verdict -eq 'Critical').Count
    $unreachable = @($Result | Where-Object Verdict -eq 'Unreachable').Count

    $critEvents = @($Event | Where-Object { $_.Level -eq 1 }).Count
    $errEvents  = @($Event | Where-Object { $_.Level -eq 2 }).Count

    $windowText = '{0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}' -f $RunContext.Start, $RunContext.End
    $sampleText = if ($RunContext.SampleSeconds -le 0) {
        'single instantaneous reading'
    } else {
        '{0} readings over {1}s' -f $RunContext.SampleCount, $RunContext.SampleSeconds
    }

    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine('<title>Citrix / FSLogix Health Report</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine((Get-ReportStyle))
    [void]$sb.AppendLine('</style></head><body>')

    # --- Header: always say what you are looking at ---------------------------------
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine('<h1><span class="mark">//</span> Citrix &amp; FSLogix Health Report</h1>')
    [void]$sb.AppendLine(('<div class="sub">Scope: <strong>{0}</strong> &nbsp;&middot;&nbsp; Event window: <strong>{1}</strong> &nbsp;&middot;&nbsp; Performance: <strong>{2}</strong></div>' -f `
        (ConvertTo-HtmlSafe -Text $RunContext.ScopeText), (ConvertTo-HtmlSafe -Text $windowText), (ConvertTo-HtmlSafe -Text $sampleText)))
    [void]$sb.AppendLine(('<div class="sub">Generated <strong>{0}</strong> on <strong>{1}</strong> by <strong>{2}</strong></div>' -f `
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), (ConvertTo-HtmlSafe -Text $env:COMPUTERNAME), (ConvertTo-HtmlSafe -Text $env:USERNAME)))
    [void]$sb.AppendLine('</header><main>')

    # --- Summary tiles ---------------------------------------------------------------
    [void]$sb.AppendLine('<h2>At a glance</h2><div class="tiles">')
    [void]$sb.AppendLine(('<div class="tile acc"><div class="n">{0}</div><div class="l">Machines checked</div></div>' -f $total))
    [void]$sb.AppendLine(('<div class="tile ok"><div class="n">{0}</div><div class="l">Healthy</div></div>' -f $healthy))
    [void]$sb.AppendLine(('<div class="tile deg"><div class="n">{0}</div><div class="l">Needs attention</div></div>' -f $degraded))
    [void]$sb.AppendLine(('<div class="tile crit"><div class="n">{0}</div><div class="l">Serious problems</div></div>' -f $critical))
    [void]$sb.AppendLine(('<div class="tile unk"><div class="n">{0}</div><div class="l">Could not reach</div></div>' -f $unreachable))
    [void]$sb.AppendLine(('<div class="tile crit"><div class="n">{0}</div><div class="l">Critical events</div></div>' -f $critEvents))
    [void]$sb.AppendLine(('<div class="tile deg"><div class="n">{0}</div><div class="l">Error events</div></div>' -f $errEvents))
    [void]$sb.AppendLine('</div>')

    # --- Host table ------------------------------------------------------------------
    [void]$sb.AppendLine('<h2>Every machine</h2>')

    if ($total -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No machines were collected. Check the target parameters and try again.</div>')
    }
    else {
        [void]$sb.AppendLine('<table><thead><tr>')
        [void]$sb.AppendLine('<th>Machine</th><th>Verdict</th><th>Processor</th><th>Memory</th><th>Disk</th>')
        [void]$sb.AppendLine('<th class="num">Users</th><th class="num">Up (d)</th>')
        [void]$sb.AppendLine('<th class="num">Crit</th><th class="num">Err</th><th class="num">Warn</th>')
        [void]$sb.AppendLine('<th>Most frequent problem</th><th>What we found</th>')
        [void]$sb.AppendLine('</tr></thead><tbody>')

        # Worst first: a report that buries the broken machine on page three has failed.
        $order = @{ 'Critical' = 0; 'Unreachable' = 1; 'Degraded' = 2; 'Healthy' = 3 }
        $sorted = $Result | Sort-Object @{ Expression = { $order[$_.Verdict] } }, @{ Expression = { $_.ErrorEvents } ; Descending = $true }, ComputerName

        foreach ($r in $sorted) {
            $pill = switch ($r.Verdict) {
                'Healthy'     { 'p-ok'   }
                'Degraded'    { 'p-deg'  }
                'Critical'    { 'p-crit' }
                default       { 'p-unk'  }
            }

            $verdictLabel = switch ($r.Verdict) {
                'Healthy'     { 'Healthy'      }
                'Degraded'    { 'Attention'    }
                'Critical'    { 'Serious'      }
                default       { 'No contact'   }
            }

            $ctxParts = @()
            if ($r.DeliveryGroup)     { $ctxParts += $r.DeliveryGroup }
            if ($r.OperatingSystem)   { $ctxParts += $r.OperatingSystem }
            if ($r.LogicalProcessors) { $ctxParts += ('{0} vCPU' -f $r.LogicalProcessors) }
            if ($r.MemoryTotalGB)     { $ctxParts += ('{0} GB RAM' -f $r.MemoryTotalGB) }
            if ($r.InMaintenanceMode -eq $true) { $ctxParts += 'MAINTENANCE MODE' }
            $ctx = ($ctxParts -join ' &middot; ')

            $critCls = if ($r.CriticalEvents -gt 0) { 'c-crit' } else { 'c-zero' }
            $errCls  = if ($r.ErrorEvents    -gt 0) { 'c-err'  } else { 'c-zero' }
            $warnCls = if ($r.WarningEvents  -gt 0) { ''       } else { 'c-zero' }

            [void]$sb.AppendLine('<tr>')
            [void]$sb.AppendLine(('<td><div class="host">{0}</div><div class="ctx">{1}</div></td>' -f `
                (ConvertTo-HtmlSafe -Text $r.ComputerName), $ctx))
            [void]$sb.AppendLine(('<td><span class="pill {0}">{1}</span></td>' -f $pill, $verdictLabel))
            [void]$sb.AppendLine(('<td>{0}</td>' -f (Format-MetricCell -Percent $r.CpuAveragePercent -Status $r.CpuStatus -Peak $r.CpuPeakPercent)))
            [void]$sb.AppendLine(('<td>{0}</td>' -f (Format-MetricCell -Percent $r.MemoryAveragePercent -Status $r.MemoryStatus -Peak $r.MemoryPeakPercent)))
            [void]$sb.AppendLine(('<td>{0}</td>' -f (Format-MetricCell -Percent $r.MaxDiskUsedPercent -Status $r.DiskStatus -Peak $null)))
            [void]$sb.AppendLine(('<td class="num">{0}</td>' -f $(if ($null -ne $r.SessionCount) { $r.SessionCount } else { '--' })))
            [void]$sb.AppendLine(('<td class="num">{0}</td>' -f $(if ($null -ne $r.UptimeDays) { $r.UptimeDays } else { '--' })))
            [void]$sb.AppendLine(('<td class="num {0}">{1}</td>' -f $critCls, $r.CriticalEvents))
            [void]$sb.AppendLine(('<td class="num {0}">{1}</td>' -f $errCls, $r.ErrorEvents))
            [void]$sb.AppendLine(('<td class="num {0}">{1}</td>' -f $warnCls, $r.WarningEvents))
            [void]$sb.AppendLine(('<td class="issue">{0}</td>' -f $(if ($r.TopIssue) { ConvertTo-HtmlSafe -Text $r.TopIssue } else { '<span class="c-zero">none</span>' })))
            [void]$sb.AppendLine(('<td class="why">{0}</td>' -f (ConvertTo-HtmlSafe -Text $r.Reasons)))
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('<div class="legend">Bars show the average across the sampling window. The vertical tick marks the peak reading.</div>')
    }

    # --- Fleet-wide top issues -------------------------------------------------------
    [void]$sb.AppendLine('<h2>Most common problems across the fleet</h2>')

    $errorish = @($Event | Where-Object { $_.Level -le 2 })
    if ($errorish.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No critical or error events were logged anywhere in the window.</div>')
    }
    else {
        $groups = $errorish | Group-Object Category, ProviderName, Id |
            Sort-Object Count -Descending | Select-Object -First 20

        [void]$sb.AppendLine('<table><thead><tr>')
        [void]$sb.AppendLine('<th class="num">Count</th><th class="num">Machines</th><th>Area</th><th>Source</th>')
        [void]$sb.AppendLine('<th class="num">Event ID</th><th>Severity</th><th>Example message</th>')
        [void]$sb.AppendLine('</tr></thead><tbody>')

        foreach ($g in $groups) {
            $sample    = $g.Group[0]
            $hostCount = @($g.Group | Select-Object -ExpandProperty ComputerName -Unique).Count
            $sevCls    = if ($sample.Level -eq 1) { 'c-crit' } else { 'c-err' }

            [void]$sb.AppendLine('<tr>')
            [void]$sb.AppendLine(('<td class="num"><strong>{0}</strong></td>' -f $g.Count))
            [void]$sb.AppendLine(('<td class="num">{0}</td>' -f $hostCount))
            [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-HtmlSafe -Text $sample.Category)))
            [void]$sb.AppendLine(('<td class="issue">{0}</td>' -f (ConvertTo-HtmlSafe -Text $sample.ProviderName)))
            [void]$sb.AppendLine(('<td class="num">{0}</td>' -f $sample.Id))
            [void]$sb.AppendLine(('<td class="{0}">{1}</td>' -f $sevCls, (ConvertTo-HtmlSafe -Text $sample.LevelName)))
            [void]$sb.AppendLine(('<td class="msg">{0}</td>' -f (ConvertTo-HtmlSafe -Text $sample.Message)))
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody></table>')
        [void]$sb.AppendLine('<div class="legend">Grouped by area, source, and event ID. &quot;Machines&quot; is how many distinct hosts logged it.</div>')
    }

    [void]$sb.AppendLine('</main>')
    [void]$sb.AppendLine(('<footer>Read-only collection. Event times are the local time of each machine that logged them.<br>Full detail is in the CSV files written alongside this report: <code>{0}</code></footer>' -f `
        (ConvertTo-HtmlSafe -Text $RunContext.OutputPath)))
    [void]$sb.AppendLine('</body></html>')

    return $sb.ToString()
}

#endregion

#region Orchestration

# -LoadFunctionsOnly lets the Pester suite dot-source everything above without running a
# collection. It must be the first thing checked after the functions are defined.
if ($LoadFunctionsOnly) { return }

$runStart = Get-Date

Write-StatusLine -Status 'INFO' -Message 'Citrix / FSLogix fleet health collection starting'

# --- Validate threshold pairs before doing any work ----------------------------------
# A warn threshold above its critical threshold would silently make the critical band
# unreachable, and every overloaded host would report as a mere warning.
$thresholdPairs = @(
    @{ Name = 'CPU';           Warn = $CpuWarnPercent;      Critical = $CpuCriticalPercent      }
    @{ Name = 'Memory';        Warn = $MemoryWarnPercent;   Critical = $MemoryCriticalPercent   }
    @{ Name = 'Disk';          Warn = $DiskWarnPercent;     Critical = $DiskCriticalPercent     }
    @{ Name = 'Queue per CPU'; Warn = $QueueWarnPerCpu;     Critical = $QueueCriticalPerCpu     }
)
foreach ($pair in $thresholdPairs) {
    if ($pair.Warn -gt $pair.Critical) {
        throw ("{0} warning threshold ({1}) cannot be higher than its critical threshold ({2})." -f $pair.Name, $pair.Warn, $pair.Critical)
    }
}
if ($DegradedErrorCount -gt $CriticalErrorCount) {
    throw ("-DegradedErrorCount ({0}) cannot be higher than -CriticalErrorCount ({1})." -f $DegradedErrorCount, $CriticalErrorCount)
}

if ($SkipPerformance -and $SkipEvents) {
    throw '-SkipPerformance and -SkipEvents cannot both be set - that would collect nothing.'
}

# --- Resolve the event window --------------------------------------------------------
$windowArgs = @{}
if ($PSBoundParameters.ContainsKey('StartTime')) { $windowArgs['StartTime'] = $StartTime }
if ($PSBoundParameters.ContainsKey('EndTime'))   { $windowArgs['EndTime']   = $EndTime   }
if ($PSBoundParameters.ContainsKey('LastHours')) { $windowArgs['LastHours'] = $LastHours }
if ($PSBoundParameters.ContainsKey('LastDays'))  { $windowArgs['LastDays']  = $LastDays  }

$window = Resolve-TimeWindow @windowArgs

# --- Output directory ----------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-StatusLine -Status 'INFO' -Message "Created output directory: $OutputPath"
    }
    catch {
        throw "Could not create output directory '$OutputPath': $($_.Exception.Message)"
    }
}
$resolvedOutput = (Resolve-Path -LiteralPath $OutputPath).Path

# --- Build the target list -----------------------------------------------------------
$targets   = @()
$scopeText = ''

if ($PSCmdlet.ParameterSetName -eq 'Explicit') {
    foreach ($name in $ComputerName) {
        $targets += New-PlainTarget -ComputerName $name.Trim() -Source 'Explicit'
    }
    $scopeText = '{0} named server(s)' -f @($ComputerName).Count
    Write-StatusLine -Status 'INFO' -Message ("Target list supplied directly: {0} machine(s)" -f @($ComputerName).Count)
}
else {
    if (-not (Import-CitrixBrokerSdk)) {
        throw @'
The Citrix Broker SDK is not available on this machine, so the VDA list cannot be discovered.

Either run this on a Delivery Controller or a machine with Citrix Studio / the PowerShell
SDK installed, or skip Citrix entirely and name the servers yourself:

    .\Get-CitrixFSLogixHealth.ps1 -ComputerName SERVER1, SERVER2
'@
    }

    Write-StatusLine -Status 'INFO' -Message "Asking Delivery Controller '$DeliveryController' for the machine list"

    try {
        $inventoryArgs = @{
            DeliveryController = $DeliveryController
            MaxRecordCount     = $MaxRecordCount
        }
        if ($DesktopGroupName) { $inventoryArgs['DesktopGroupName'] = $DesktopGroupName }
        if ($CatalogName)      { $inventoryArgs['CatalogName']      = $CatalogName }

        $targets += @(Get-VDAInventory @inventoryArgs)
    }
    catch {
        throw "Could not retrieve the machine list from '$DeliveryController': $($_.Exception.Message)"
    }

    $brokerCount = @($targets).Count
    Write-StatusLine -Status 'PASS' -Message "Delivery Controller returned $brokerCount machine(s)"

    foreach ($name in $AdditionalComputerName) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $targets += New-PlainTarget -ComputerName $name.Trim() -Source 'Additional'
    }

    $scopeParts = @("$brokerCount VDA(s) from $DeliveryController")
    if ($DesktopGroupName)        { $scopeParts += "delivery group '$DesktopGroupName'" }
    if ($CatalogName)             { $scopeParts += "catalog '$CatalogName'" }
    if ($AdditionalComputerName)  { $scopeParts += "{0} extra server(s)" -f @($AdditionalComputerName).Count }
    $scopeText = ($scopeParts -join ', ')
}

$targets = @(Select-CollectionTarget -Target $targets -IncludeUnregistered:$IncludeUnregistered)

if ($targets.Count -eq 0) {
    Write-StatusLine -Status 'FAIL' -Message 'No machines to collect from. Nothing to do.'
    return
}

Write-StatusLine -Status 'INFO' -Message ("Collecting from {0} machine(s)" -f $targets.Count)

$sampleCount = Get-SampleCount -SampleSeconds $SampleSeconds -IntervalSeconds $SampleIntervalSeconds

if ($SkipPerformance) {
    Write-StatusLine -Status 'INFO' -Message 'Performance collection skipped (-SkipPerformance)'
}
elseif ($SampleSeconds -le 0) {
    Write-StatusLine -Status 'WARN' -Message 'Sampling disabled - taking a single instantaneous reading per machine. Peaks will not be detected.'
}
else {
    $perHost = ($sampleCount - 1) * $SampleIntervalSeconds
    Write-StatusLine -Status 'INFO' -Message ("Sampling {0} readings per machine over ~{1}s each" -f $sampleCount, $perHost)
}

if (-not $SkipEvents) {
    Write-StatusLine -Status 'INFO' -Message ("Event window: {0:yyyy-MM-dd HH:mm:ss} to {1:yyyy-MM-dd HH:mm:ss}, levels {2}" -f `
        $window.Start, $window.End, (($Level | ForEach-Object { Get-LevelName -Level $_ }) -join ', '))
}

$thresholds = @{
    CpuWarn             = $CpuWarnPercent
    CpuCritical         = $CpuCriticalPercent
    MemoryWarn          = $MemoryWarnPercent
    MemoryCritical      = $MemoryCriticalPercent
    DiskWarn            = $DiskWarnPercent
    DiskCritical        = $DiskCriticalPercent
    QueueWarnPerCpu     = $QueueWarnPerCpu
    QueueCriticalPerCpu = $QueueCriticalPerCpu
    DegradedErrorCount  = $DegradedErrorCount
    CriticalErrorCount  = $CriticalErrorCount
}

# --- Collect -------------------------------------------------------------------------
$results    = @()
$allEvents  = @()
$allSamples = @()
$index      = 0

foreach ($target in $targets) {
    $index++
    $hostName = $target.ComputerName

    Write-Progress -Activity 'Collecting Citrix / FSLogix health' `
        -Status ("[{0}/{1}] {2}" -f $index, $targets.Count, $hostName) `
        -PercentComplete (($index / $targets.Count) * 100)

    # --- Performance ---
    if ($SkipPerformance) {
        $perf = [PSCustomObject]@{
            CpuAveragePercent = $null; CpuPeakPercent = $null
            MemoryAveragePercent = $null; MemoryPeakPercent = $null
            MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            QueueAverage = $null; QueuePeak = $null; QueuePerCpu = $null
            LogicalProcessors = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; OperatingSystem = $null; SampleCount = 0
            Protocol = 'Skipped'; Status = 'Skipped'; ErrorMessage = $null; Samples = @()
        }
    }
    else {
        $perfArgs = @{
            ComputerName    = $hostName
            TimeoutSeconds  = $ConnectionTimeoutSeconds
            SampleCount     = $sampleCount
            IntervalSeconds = $SampleIntervalSeconds
        }
        if ($Credential) { $perfArgs['Credential'] = $Credential }

        $perf = Get-PerformanceSample @perfArgs
        $allSamples += $perf.Samples

        if ($perf.Status -eq 'Unreachable') {
            Write-StatusLine -Status 'WARN' -Message "$hostName - no performance data (WinRM and DCOM both refused)"
        }
    }

    # --- Events ---
    if ($SkipEvents) {
        $eventResult = @{ Events = @(); Status = 'Skipped'; ErrorMessage = $null; ChannelsQueried = 0 }
    }
    else {
        $eventArgs = @{
            ComputerName = $hostName
            Start        = $window.Start
            End          = $window.End
            Level        = $Level
            MaxEvents    = $MaxEventsPerLog
        }
        if ($Credential) { $eventArgs['Credential'] = $Credential }

        try {
            $eventResult = Get-HostEvent @eventArgs
        }
        catch {
            $eventResult = @{ Events = @(); Status = 'Unreachable'; ErrorMessage = $_.Exception.Message; ChannelsQueried = 0 }
        }

        if ($eventResult.Status -eq 'Unreachable') {
            Write-StatusLine -Status 'WARN' -Message "$hostName - event logs could not be read"
        }

        $allEvents += $eventResult.Events
    }

    $row = New-HostResult -Inventory $target -Performance $perf `
        -Event $eventResult.Events -EventStatus $eventResult.Status -Threshold $thresholds

    $results += $row

    $lineStatus = switch ($row.Verdict) {
        'Healthy'  { 'PASS' }
        'Degraded' { 'WARN' }
        'Critical' { 'FAIL' }
        default    { 'FAIL' }
    }
    Write-StatusLine -Status $lineStatus -Message ("{0} - {1} (crit {2} / err {3} / warn {4})" -f `
        $hostName, $row.Verdict, $row.CriticalEvents, $row.ErrorEvents, $row.WarningEvents)
}

Write-Progress -Activity 'Collecting Citrix / FSLogix health' -Completed

# --- Export --------------------------------------------------------------------------
$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$baseName = "CitrixFSLogixHealth_$stamp"

$hostsCsv   = Join-Path $resolvedOutput "${baseName}_Hosts.csv"
$eventsCsv  = Join-Path $resolvedOutput "${baseName}_Events.csv"
$samplesCsv = Join-Path $resolvedOutput "${baseName}_Samples.csv"
$htmlPath   = Join-Path $resolvedOutput "$baseName.html"

try {
    $results | Export-Csv -LiteralPath $hostsCsv -NoTypeInformation -Encoding UTF8
    Write-StatusLine -Status 'PASS' -Message "Per-machine summary: $hostsCsv"
}
catch {
    Write-StatusLine -Status 'FAIL' -Message "Could not write the host CSV: $($_.Exception.Message)"
}

if ($allEvents.Count -gt 0) {
    try {
        $allEvents | Sort-Object TimeCreated -Descending |
            Export-Csv -LiteralPath $eventsCsv -NoTypeInformation -Encoding UTF8
        Write-StatusLine -Status 'PASS' -Message "Event detail ($($allEvents.Count) rows): $eventsCsv"
    }
    catch {
        Write-StatusLine -Status 'FAIL' -Message "Could not write the event CSV: $($_.Exception.Message)"
    }
}
else {
    Write-StatusLine -Status 'INFO' -Message 'No events matched the window and severity filter - event CSV not written'
}

# The raw samples are what make a performance claim auditable after the fact, so they are
# kept as their own file rather than collapsed into the averages.
if ($allSamples.Count -gt 0) {
    try {
        $allSamples | Export-Csv -LiteralPath $samplesCsv -NoTypeInformation -Encoding UTF8
        Write-StatusLine -Status 'PASS' -Message "Raw performance samples ($($allSamples.Count) rows): $samplesCsv"
    }
    catch {
        Write-StatusLine -Status 'FAIL' -Message "Could not write the sample CSV: $($_.Exception.Message)"
    }
}

try {
    $runContext = @{
        Start         = $window.Start
        End           = $window.End
        SampleSeconds = $SampleSeconds
        SampleCount   = $sampleCount
        ScopeText     = $scopeText
        OutputPath    = $resolvedOutput
    }

    $html = New-HealthHtmlReport -Result $results -Event $allEvents -RunContext $runContext
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
    Write-StatusLine -Status 'PASS' -Message "Report: $htmlPath"
}
catch {
    Write-StatusLine -Status 'FAIL' -Message "Could not write the HTML report: $($_.Exception.Message)"
    $htmlPath = $null
}

# --- Console summary -----------------------------------------------------------------
$healthyCount     = @($results | Where-Object Verdict -eq 'Healthy').Count
$degradedCount    = @($results | Where-Object Verdict -eq 'Degraded').Count
$criticalCount    = @($results | Where-Object Verdict -eq 'Critical').Count
$unreachableCount = @($results | Where-Object Verdict -eq 'Unreachable').Count

Write-Host ''
Write-Host ('=' * 78) -ForegroundColor DarkGray
Write-Host ' FLEET SUMMARY' -ForegroundColor White
Write-Host ('=' * 78) -ForegroundColor DarkGray

Write-StatusLine -Status 'PASS' -Message "Healthy .............. $healthyCount"
Write-StatusLine -Status $(if ($degradedCount    -gt 0) { 'WARN' } else { 'INFO' }) -Message "Needs attention ...... $degradedCount"
Write-StatusLine -Status $(if ($criticalCount    -gt 0) { 'FAIL' } else { 'INFO' }) -Message "Serious problems ..... $criticalCount"
Write-StatusLine -Status $(if ($unreachableCount -gt 0) { 'WARN' } else { 'INFO' }) -Message "Could not reach ...... $unreachableCount"

$elapsed = (Get-Date) - $runStart
Write-StatusLine -Status 'INFO' -Message ("Completed in {0:mm\:ss}" -f $elapsed)

# Name the machines that need work, so the console alone is actionable without the report.
$needsWork = @($results | Where-Object { $_.Verdict -in @('Critical', 'Degraded', 'Unreachable') })
if ($needsWork.Count -gt 0) {
    Write-Host ''
    Write-Host ' MACHINES NEEDING ATTENTION' -ForegroundColor White
    foreach ($r in ($needsWork | Sort-Object Verdict, ComputerName)) {
        Write-Host ("  {0,-24} {1,-12} {2}" -f $r.ComputerName, $r.Verdict, $r.Reasons) -ForegroundColor Gray
    }
}

if ($htmlPath -and -not $NoOpen) {
    try { Start-Process $htmlPath -ErrorAction Stop }
    catch { Write-StatusLine -Status 'INFO' -Message "Open the report manually: $htmlPath" }
}

# Emit the rows so the script composes into a pipeline as well as writing files.
return $results

#endregion
