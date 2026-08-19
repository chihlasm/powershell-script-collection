#Requires -Version 5.1

<#
.SYNOPSIS
    Get-CitrixVDAResources.ps1 - Fleet-wide resource report for all Citrix VDAs in an environment.

.DESCRIPTION
    Discovers every VDA registered with a Citrix Delivery Controller, then collects CPU,
    memory, disk, and uptime for each machine over CIM (WinRM). Produces a CSV for the
    internal record and a self-contained HTML report with embedded charts for stakeholders.

    Machines that cannot be reached still appear in both outputs with a clear status, so an
    unreachable VDA is never mistaken for a healthy one.

    Complements CitrixVDADiagnostics\CitrixVDA-Consolidated.ps1, which goes deep on a single
    machine. This script goes wide across the fleet.

.PARAMETER DeliveryController
    Delivery Controller to query. Passed to the Citrix SDK as -AdminAddress. Defaults to localhost.

.PARAMETER DesktopGroupName
    Limit the report to a single delivery group.

.PARAMETER CatalogName
    Limit the report to a single machine catalog.

.PARAMETER MachineName
    Explicit machine names to report on. Bypasses delivery group and catalog filtering.

.PARAMETER Credential
    Credentials for the CIM connections. Omit to use the current user's context.

.PARAMETER CpuWarnPercent
    CPU percentage at or above which a machine is flagged as a warning. Default 80.

.PARAMETER CpuCriticalPercent
    CPU percentage at or above which a machine is flagged as critical. Default 90.

.PARAMETER MemoryWarnPercent
    Memory-in-use percentage at or above which a machine is flagged as a warning. Default 80.

.PARAMETER MemoryCriticalPercent
    Memory-in-use percentage at or above which a machine is flagged as critical. Default 90.

.PARAMETER DiskWarnPercent
    Disk-used percentage at or above which a machine is flagged as a warning. Default 80.

.PARAMETER DiskCriticalPercent
    Disk-used percentage at or above which a machine is flagged as critical. Default 90.

.PARAMETER MaxRecordCount
    Maximum machines to retrieve from the broker. Defaults to no practical limit. Citrix
    caps at 250 when this is not supplied - see the note in the code.

.PARAMETER ConnectionTimeoutSeconds
    Per-machine CIM connection timeout. Default 15.

.PARAMETER IncludeUnregistered
    Attempt collection on machines that are not in the Registered state. Off by default.

.PARAMETER OutputPath
    Directory for the CSV and HTML output. Defaults to the current directory.

.PARAMETER NoOpen
    Do not open the HTML report when the run finishes.

.PARAMETER LoadFunctionsOnly
    Dot-source the script's functions without running it. Used by the Pester suite.

.EXAMPLE
    .\Get-CitrixVDAResources.ps1 -DeliveryController DDC01
    # Report on every VDA in the site.

.EXAMPLE
    .\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -DesktopGroupName "Finance Desktops"
    # Limit the report to one delivery group.

.EXAMPLE
    .\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -CpuWarnPercent 70 -OutputPath C:\Reports
    # Lower the CPU warning threshold and write both files to C:\Reports.

.NOTES
    Author: VC3
    Requires: PowerShell 5.1, Citrix Broker SDK, WinRM reachable on the VDAs.

    REFERENCES
    - Get-BrokerMachine (properties and filter parameters):
      https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerMachine.html
    - Broker filtering / MaxRecordCount default of 250:
      https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2511/Broker/about_Broker_Filtering.html
    - Win32_LogicalDisk (DriveType, Size, FreeSpace in bytes):
      https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
    - Win32_OperatingSystem (memory properties in kilobytes, LastBootUpTime):
      https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    - Monitoring performance data (Win32_PerfFormattedData_* classes, _Total instance):
      https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-performance-data
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DeliveryController = 'localhost',

    [Parameter(Mandatory = $false)]
    [string]$DesktopGroupName,

    [Parameter(Mandatory = $false)]
    [string]$CatalogName,

    [Parameter(Mandatory = $false)]
    [string[]]$MachineName,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$CpuWarnPercent = 80,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$CpuCriticalPercent = 90,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$MemoryWarnPercent = 80,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$MemoryCriticalPercent = 90,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$DiskWarnPercent = 80,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$DiskCriticalPercent = 90,

    [Parameter(Mandatory = $false)]
    [int]$MaxRecordCount = [int]::MaxValue,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 300)]
    [int]$ConnectionTimeoutSeconds = 15,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeUnregistered,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [switch]$NoOpen,

    [Parameter(Mandatory = $false)]
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

#region Analysis

function Get-ResourceStatus {
    <#
    .SYNOPSIS
        Classifies a percentage against warn and critical thresholds.
    .DESCRIPTION
        Thresholds are inclusive: a value exactly at WarnAt is a warning, and exactly at
        CriticalAt is a failure. A null value means the metric could not be collected and
        returns UNKNOWN rather than a misleading PASS.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[double]]$Value,

        [Parameter(Mandatory = $true)]
        [int]$WarnAt,

        [Parameter(Mandatory = $true)]
        [int]$CriticalAt
    )

    if ($null -eq $Value) { return 'UNKNOWN' }
    if ($Value -ge $CriticalAt) { return 'FAIL' }
    if ($Value -ge $WarnAt) { return 'WARN' }
    return 'PASS'
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

#endregion

#region Discovery

function Import-CitrixBrokerSdk {
    <#
    .SYNOPSIS
        Loads the Citrix Broker SDK, trying the legacy PSSnapin before the module.
    .DESCRIPTION
        Loaded at runtime rather than via #Requires -Modules, because #Requires blocks
        execution before the script starts on servers where the SDK is present but not
        formally registered.
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

        [Parameter(Mandatory = $false)]
        [string]$DesktopGroupName,

        [Parameter(Mandatory = $false)]
        [string]$CatalogName,

        [Parameter(Mandatory = $false)]
        [string[]]$MachineName,

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

    if ($MachineName)      { $brokerArgs['MachineName']      = $MachineName }
    if ($DesktopGroupName) { $brokerArgs['DesktopGroupName'] = $DesktopGroupName }
    if ($CatalogName)      { $brokerArgs['CatalogName']      = $CatalogName }

    $machines = Get-BrokerMachine @brokerArgs

    foreach ($m in $machines) {
        # Property names verified against the Citrix SDK reference:
        # https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerMachine.html
        [PSCustomObject]@{
            MachineName       = $m.MachineName
            DnsName           = $m.DNSName
            CatalogName       = $m.CatalogName
            DeliveryGroup     = $m.DesktopGroupName
            RegistrationState = $m.RegistrationState
            InMaintenanceMode = $m.InMaintenanceMode
            LoadIndex         = $m.LoadIndex
            SessionCount      = $m.SessionCount
            PowerState        = $m.PowerState
        }
    }
}

#endregion

#region Metrics

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
    # NOT bytes. Win32_LogicalDisk in the same script reports bytes - the two are different
    # and must not share a conversion.
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

    $parts    = @()
    $maxUsed  = $null

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

#endregion

#region Collection

function Get-VDAResourceSnapshot {
    <#
    .SYNOPSIS
        Collects CPU, memory, disk, and uptime from one machine over a CIM session.
    .DESCRIPTION
        One machine per call. Every query is individually guarded so a single failed
        counter does not discard the metrics that did come back, and the session is always
        torn down. The caller decides what to do with a failure - this never throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $result = [PSCustomObject]@{
        CpuPercent         = $null
        MemoryTotalGB      = $null
        MemoryUsedGB       = $null
        MemoryFreeGB       = $null
        MemoryUsedPercent  = $null
        DiskSummary        = $null
        MaxDiskUsedPercent = $null
        UptimeDays         = $null
        CollectionStatus   = 'Unreachable'
        ErrorMessage       = $null
    }

    $session = $null

    try {
        $sessionArgs = @{
            ComputerName        = $ComputerName
            OperationTimeoutSec = $TimeoutSeconds
            ErrorAction         = 'Stop'
        }
        if ($Credential) { $sessionArgs['Credential'] = $Credential }

        $session = New-CimSession @sessionArgs

        # Memory and uptime.
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $session -ErrorAction Stop
            $mem = ConvertTo-MemoryMetrics -TotalKb $os.TotalVisibleMemorySize -FreeKb $os.FreePhysicalMemory

            $result.MemoryTotalGB     = $mem.TotalGB
            $result.MemoryUsedGB      = $mem.UsedGB
            $result.MemoryFreeGB      = $mem.FreeGB
            $result.MemoryUsedPercent = $mem.UsedPercent
            $result.UptimeDays        = Get-UptimeDays -LastBootUpTime $os.LastBootUpTime -Now (Get-Date)
        }
        catch {
            Write-Verbose "${ComputerName}: OS query failed - $_"
        }

        # Fixed disks only. DriveType 3 is "Local Disk"; 2 is removable, 4 is network, 5 is
        # optical - none of which belong in a VDA capacity report.
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

        # CPU. The _Total instance is the aggregate across all processors.
        # https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-performance-data
        try {
            $cpu = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name = '_Total'" -CimSession $session -ErrorAction Stop
            if ($cpu) {
                $result.CpuPercent = [math]::Round([double]$cpu.PercentProcessorTime, 1)
            }
        }
        catch {
            Write-Verbose "${ComputerName}: CPU query failed - $_"
        }

        # The session opened, so the machine was reachable even if a counter misbehaved.
        $result.CollectionStatus = 'Success'
    }
    catch {
        $result.CollectionStatus = 'Unreachable'
        $result.ErrorMessage     = $_.Exception.Message
    }
    finally {
        if ($session) {
            Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
        }
    }

    return $result
}

function New-VDAResultRow {
    <#
    .SYNOPSIS
        Merges an inventory entry with its resource snapshot and applies thresholds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Inventory,

        [Parameter(Mandatory = $true)]
        [object]$Snapshot,

        [Parameter(Mandatory = $true)]
        [hashtable]$Thresholds
    )

    $cpuStatus  = Get-ResourceStatus -Value $Snapshot.CpuPercent         -WarnAt $Thresholds.CpuWarn    -CriticalAt $Thresholds.CpuCritical
    $memStatus  = Get-ResourceStatus -Value $Snapshot.MemoryUsedPercent  -WarnAt $Thresholds.MemoryWarn -CriticalAt $Thresholds.MemoryCritical
    $diskStatus = Get-ResourceStatus -Value $Snapshot.MaxDiskUsedPercent -WarnAt $Thresholds.DiskWarn   -CriticalAt $Thresholds.DiskCritical

    [PSCustomObject]@{
        MachineName        = $Inventory.MachineName
        DnsName            = $Inventory.DnsName
        CatalogName        = $Inventory.CatalogName
        DeliveryGroup      = $Inventory.DeliveryGroup
        RegistrationState  = $Inventory.RegistrationState
        InMaintenanceMode  = $Inventory.InMaintenanceMode
        LoadIndex          = $Inventory.LoadIndex
        SessionCount       = $Inventory.SessionCount
        PowerState         = $Inventory.PowerState
        CpuPercent         = $Snapshot.CpuPercent
        CpuStatus          = $cpuStatus
        MemoryTotalGB      = $Snapshot.MemoryTotalGB
        MemoryUsedGB       = $Snapshot.MemoryUsedGB
        MemoryFreeGB       = $Snapshot.MemoryFreeGB
        MemoryUsedPercent  = $Snapshot.MemoryUsedPercent
        MemoryStatus       = $memStatus
        DiskSummary        = $Snapshot.DiskSummary
        MaxDiskUsedPercent = $Snapshot.MaxDiskUsedPercent
        DiskStatus         = $diskStatus
        UptimeDays         = $Snapshot.UptimeDays
        CollectionStatus   = $Snapshot.CollectionStatus
        ErrorMessage       = $Snapshot.ErrorMessage
        OverallStatus      = Get-WorstStatus -Statuses @($cpuStatus, $memStatus, $diskStatus)
    }
}

#endregion

#region Reporting

function ConvertTo-HtmlSafe {
    <#
    .SYNOPSIS
        Escapes text for safe inclusion in HTML. Machine names come from AD and can
        contain characters that would otherwise corrupt the document.
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
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function New-VDABarSvg {
    <#
    .SYNOPSIS
        Builds one inline SVG horizontal bar for a single metric.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Nullable[double]]$Percent,

        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    $fill = switch ($Status) {
        'PASS'    { '#4a9d5f' }
        'WARN'    { '#d1a144' }
        'FAIL'    { '#c8503f' }
        default   { '#4a5058' }
    }

    if ($null -eq $Percent) {
        return '<svg class="bar" viewBox="0 0 100 12" preserveAspectRatio="none"><rect x="0" y="0" width="100" height="12" fill="#2a2e35"/></svg>'
    }

    $width = [math]::Min([math]::Max($Percent, 0), 100)

    return ('<svg class="bar" viewBox="0 0 100 12" preserveAspectRatio="none">' +
            '<rect x="0" y="0" width="100" height="12" fill="#2a2e35"/>' +
            ('<rect x="0" y="0" width="{0}" height="12" fill="{1}"/>' -f $width, $fill) +
            '</svg>')
}

function New-VDAHtmlReport {
    <#
    .SYNOPSIS
        Builds the complete self-contained HTML report as a string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [datetime]$GeneratedAt,

        [Parameter(Mandatory = $true)]
        [hashtable]$Thresholds
    )

    $total       = $Rows.Count
    $unreachable = @($Rows | Where-Object { $_.CollectionStatus -eq 'Unreachable' }).Count
    $skipped     = @($Rows | Where-Object { $_.CollectionStatus -eq 'Skipped' }).Count
    $critical    = @($Rows | Where-Object { $_.OverallStatus -eq 'FAIL' }).Count
    $warning     = @($Rows | Where-Object { $_.OverallStatus -eq 'WARN' }).Count
    $healthy     = @($Rows | Where-Object { $_.OverallStatus -eq 'PASS' }).Count

    $cpuValues = @($Rows | Where-Object { $null -ne $_.CpuPercent } | ForEach-Object { $_.CpuPercent })
    $memValues = @($Rows | Where-Object { $null -ne $_.MemoryUsedPercent } | ForEach-Object { $_.MemoryUsedPercent })

    $avgCpu = if ($cpuValues.Count -gt 0) { [math]::Round(($cpuValues | Measure-Object -Average).Average, 1) } else { 0 }
    $avgMem = if ($memValues.Count -gt 0) { [math]::Round(($memValues | Measure-Object -Average).Average, 1) } else { 0 }

    # Worst machines first - the ones that need attention lead the report.
    $statusRank = @{ 'FAIL' = 0; 'WARN' = 1; 'UNKNOWN' = 2; 'PASS' = 3 }
    $sorted = $Rows | Sort-Object -Property @{ Expression = { $statusRank[$_.OverallStatus] } },
                                            @{ Expression = { if ($null -eq $_.MemoryUsedPercent) { -1 } else { $_.MemoryUsedPercent } }; Descending = $true }

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Citrix VDA Resource Report</title>')
    [void]$sb.AppendLine(@'
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; padding:32px; background:#16181d; color:#e6e8eb;
       font-family:"Segoe UI",system-ui,-apple-system,sans-serif; font-size:14px; line-height:1.5; }
h1 { margin:0 0 4px; font-size:26px; font-weight:650; letter-spacing:-0.02em; }
h2 { margin:36px 0 12px; font-size:15px; font-weight:650; text-transform:uppercase;
     letter-spacing:0.08em; color:#9aa3ad; }
.sub { color:#9aa3ad; font-size:13px; margin-bottom:28px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:8px; }
.card { background:#1e2127; border:1px solid #2a2e35; border-left:3px solid #5dade2;
        border-radius:4px; padding:14px 18px; min-width:130px; }
.card .n { font-size:26px; font-weight:650; letter-spacing:-0.02em; }
.card .l { font-size:11px; text-transform:uppercase; letter-spacing:0.07em; color:#9aa3ad; margin-top:2px; }
.card.fail { border-left-color:#c8503f; }
.card.warn { border-left-color:#d1a144; }
.card.pass { border-left-color:#4a9d5f; }
.card.unkn { border-left-color:#6b7280; }
.wrap { overflow-x:auto; border:1px solid #2a2e35; border-radius:4px; }
table { border-collapse:collapse; width:100%; min-width:900px; }
th { background:#1e2127; text-align:left; padding:10px 12px; font-size:11px;
     text-transform:uppercase; letter-spacing:0.07em; color:#9aa3ad;
     border-bottom:1px solid #2a2e35; white-space:nowrap; }
td { padding:9px 12px; border-bottom:1px solid #23262c; vertical-align:middle; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:#1c1f25; }
/* Row-level severity accent. Individual metric bars keep their own true colour - a
   machine can fail on memory while its CPU is genuinely fine - so the row edge carries
   the overall verdict without misrepresenting any single number. */
tr.row-FAIL td:first-child { box-shadow: inset 3px 0 0 #c8503f; }
tr.row-WARN td:first-child { box-shadow: inset 3px 0 0 #d1a144; }
tr.row-UNKNOWN td:first-child { box-shadow: inset 3px 0 0 #4a5058; }
.mono { font-variant-numeric:tabular-nums; }
.name { font-weight:600; white-space:nowrap; }
.bar { width:88px; height:12px; border-radius:2px; display:block; }
.metric { display:flex; align-items:center; gap:9px; }
.pill { display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px;
        font-weight:650; letter-spacing:0.04em; }
.pill.PASS { background:#1c3b26; color:#7ed99a; }
.pill.WARN { background:#3d3218; color:#e8c37a; }
.pill.FAIL { background:#3d1f1a; color:#f0918a; }
.pill.UNKNOWN { background:#2a2e35; color:#9aa3ad; }
.err { color:#f0918a; font-size:12px; }
.muted { color:#6b7280; }
.note { color:#9aa3ad; font-size:12px; }
.legend { color:#9aa3ad; font-size:12px; margin:10px 0 0; }
</style>
'@)
    [void]$sb.AppendLine('</head><body>')

    [void]$sb.AppendLine('<h1>Citrix VDA Resource Report</h1>')
    [void]$sb.AppendLine(('<div class="sub">{0} &middot; generated {1}</div>' -f
        (ConvertTo-HtmlSafe -Text $Scope), $GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss')))

    # Fleet summary.
    [void]$sb.AppendLine('<div class="cards">')
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}</div><div class="l">VDAs found</div></div>' -f $total))
    [void]$sb.AppendLine(('<div class="card pass"><div class="n">{0}</div><div class="l">Healthy</div></div>' -f $healthy))
    [void]$sb.AppendLine(('<div class="card warn"><div class="n">{0}</div><div class="l">Needs attention</div></div>' -f $warning))
    [void]$sb.AppendLine(('<div class="card fail"><div class="n">{0}</div><div class="l">Critical</div></div>' -f $critical))
    [void]$sb.AppendLine(('<div class="card unkn"><div class="n">{0}</div><div class="l">Unreachable</div></div>' -f $unreachable))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}%</div><div class="l">Average CPU</div></div>' -f $avgCpu))
    [void]$sb.AppendLine(('<div class="card"><div class="n">{0}%</div><div class="l">Average memory</div></div>' -f $avgMem))
    [void]$sb.AppendLine('</div>')

    if ($unreachable -gt 0 -or $skipped -gt 0) {
        [void]$sb.AppendLine(('<p class="legend">{0} machine(s) could not be contacted and {1} were skipped. They are listed below with no resource figures - treat them as unknown, not healthy.</p>' -f $unreachable, $skipped))
    }

    # Detail table.
    [void]$sb.AppendLine('<h2>Machines &mdash; most in need of attention first</h2>')
    [void]$sb.AppendLine('<div class="wrap"><table>')
    [void]$sb.AppendLine('<thead><tr><th>Machine</th><th>Delivery group</th><th>Status</th><th>CPU in use</th><th>Memory in use</th><th>Disk in use</th><th>Sessions</th><th>Up (days)</th><th>Notes</th></tr></thead><tbody>')

    foreach ($r in $sorted) {
        $cpuText  = if ($null -eq $r.CpuPercent)         { '<span class="muted">n/a</span>' } else { ('{0}%' -f $r.CpuPercent) }
        $memText  = if ($null -eq $r.MemoryUsedPercent)  { '<span class="muted">n/a</span>' } else { ('{0}% of {1} GB' -f $r.MemoryUsedPercent, $r.MemoryTotalGB) }
        $diskText = if ($null -eq $r.MaxDiskUsedPercent) { '<span class="muted">n/a</span>' } else { ('{0}%' -f $r.MaxDiskUsedPercent) }
        $upText   = if ($null -eq $r.UptimeDays)         { '<span class="muted">n/a</span>' } else { $r.UptimeDays }

        # A skip is an expected condition (powered off, not registered), so it reads as a
        # neutral note. Only a real collection failure is styled as an error - colouring
        # routine states red trains the reader to ignore red.
        $note = if ($r.ErrorMessage -and $r.CollectionStatus -eq 'Unreachable') {
                    '<span class="err">' + (ConvertTo-HtmlSafe -Text $r.ErrorMessage) + '</span>'
                }
                elseif ($r.ErrorMessage) {
                    '<span class="note">' + (ConvertTo-HtmlSafe -Text $r.ErrorMessage) + '</span>'
                }
                elseif ($r.InMaintenanceMode) { '<span class="muted">In maintenance mode</span>' }
                else { '' }

        [void]$sb.AppendLine(('<tr class="row-{0}">' -f $r.OverallStatus))
        [void]$sb.AppendLine(('<td class="name">{0}</td>' -f (ConvertTo-HtmlSafe -Text $r.MachineName)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-HtmlSafe -Text $r.DeliveryGroup)))
        [void]$sb.AppendLine(('<td><span class="pill {0}">{0}</span></td>' -f $r.OverallStatus))
        [void]$sb.AppendLine(('<td><div class="metric">{0}<span class="mono">{1}</span></div></td>' -f (New-VDABarSvg -Percent $r.CpuPercent -Status $r.CpuStatus), $cpuText))
        [void]$sb.AppendLine(('<td><div class="metric">{0}<span class="mono">{1}</span></div></td>' -f (New-VDABarSvg -Percent $r.MemoryUsedPercent -Status $r.MemoryStatus), $memText))
        [void]$sb.AppendLine(('<td><div class="metric">{0}<span class="mono">{1}</span></div></td>' -f (New-VDABarSvg -Percent $r.MaxDiskUsedPercent -Status $r.DiskStatus), $diskText))
        [void]$sb.AppendLine(('<td class="mono">{0}</td>' -f $r.SessionCount))
        [void]$sb.AppendLine(('<td class="mono">{0}</td>' -f $upText))
        [void]$sb.AppendLine(('<td>{0}</td>' -f $note))
        [void]$sb.AppendLine('</tr>')
    }

    [void]$sb.AppendLine('</tbody></table></div>')
    [void]$sb.AppendLine(('<p class="legend">Amber from {0}% in use, red from {1}% in use.</p>' -f $Thresholds.MemoryWarn, $Thresholds.MemoryCritical))
    [void]$sb.AppendLine('</body></html>')

    return $sb.ToString()
}

#endregion

# Functions are defined above this line. When dot-sourced by the test suite we stop here
# so that no discovery or collection is attempted.
if ($LoadFunctionsOnly) { return }

#region Main

$script:StartTime = Get-Date

# Resolve output directory before doing any work, so a bad path fails fast.
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Could not create output directory '$OutputPath': $_"
        exit 1
    }
}

if (-not (Import-CitrixBrokerSdk)) {
    Write-Error "Citrix Broker SDK not found. Run this from a Delivery Controller or a machine with Citrix Studio / the Citrix PowerShell SDK installed."
    exit 1
}

Write-StatusLine -Status INFO -Message "Connecting to Delivery Controller: $DeliveryController"

$scopeLabel = if ($MachineName)          { "Machines: $($MachineName -join ', ')" }
              elseif ($DesktopGroupName) { "Delivery group: $DesktopGroupName" }
              elseif ($CatalogName)      { "Catalog: $CatalogName" }
              else                       { 'All delivery groups' }

try {
    $inventoryArgs = @{
        DeliveryController = $DeliveryController
        MaxRecordCount     = $MaxRecordCount
    }
    if ($DesktopGroupName) { $inventoryArgs['DesktopGroupName'] = $DesktopGroupName }
    if ($CatalogName)      { $inventoryArgs['CatalogName']      = $CatalogName }
    if ($MachineName)      { $inventoryArgs['MachineName']      = $MachineName }

    $inventory = @(Get-VDAInventory @inventoryArgs)
}
catch {
    Write-Error "Failed to query the Delivery Controller '$DeliveryController': $_"
    exit 1
}

if ($inventory.Count -eq 0) {
    Write-StatusLine -Status WARN -Message "No VDAs found ($scopeLabel). Nothing to report."
    exit 0
}

Write-StatusLine -Status INFO -Message ("Discovered {0} VDAs ({1})" -f $inventory.Count, $scopeLabel)
Write-StatusLine -Status INFO -Message 'Collecting resources (sequential)...'

$thresholds = @{
    CpuWarn        = $CpuWarnPercent
    CpuCritical    = $CpuCriticalPercent
    MemoryWarn     = $MemoryWarnPercent
    MemoryCritical = $MemoryCriticalPercent
    DiskWarn       = $DiskWarnPercent
    DiskCritical   = $DiskCriticalPercent
}

$results = @()
$index   = 0

foreach ($machine in $inventory) {
    $index++
    $target = if ($machine.DnsName) { $machine.DnsName } else { $machine.MachineName }

    Write-Progress -Activity 'Collecting VDA resources' `
                   -Status ("{0} ({1} of {2})" -f $target, $index, $inventory.Count) `
                   -PercentComplete (($index / $inventory.Count) * 100)

    # Skip machines that are off or unregistered - a failed connection to a powered-down
    # VDA is expected, not a finding worth alarming on.
    $skipReason = $null
    if ($machine.PowerState -eq 'Off') {
        $skipReason = 'Powered off'
    }
    elseif (-not $IncludeUnregistered -and $machine.RegistrationState -ne 'Registered') {
        $skipReason = "Not registered ($($machine.RegistrationState))"
    }

    if ($skipReason) {
        $snapshot = [PSCustomObject]@{
            CpuPercent = $null; MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            MemoryUsedPercent = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; CollectionStatus = 'Skipped'; ErrorMessage = $skipReason
        }
    }
    else {
        $snapArgs = @{
            ComputerName   = $target
            TimeoutSeconds = $ConnectionTimeoutSeconds
        }
        if ($Credential) { $snapArgs['Credential'] = $Credential }

        $snapshot = Get-VDAResourceSnapshot @snapArgs
    }

    $row = New-VDAResultRow -Inventory $machine -Snapshot $snapshot -Thresholds $thresholds
    $results += $row

    switch ($row.CollectionStatus) {
        'Success' {
            $line = "{0,-20} CPU {1,4}%  MEM {2,4}%  DISK {3,4}%  up {4}d" -f `
                    $row.MachineName, $row.CpuPercent, $row.MemoryUsedPercent, $row.MaxDiskUsedPercent, $row.UptimeDays
            $status = if ($row.OverallStatus -eq 'UNKNOWN') { 'INFO' } else { $row.OverallStatus }
            Write-StatusLine -Status $status -Message $line
        }
        'Unreachable' {
            Write-StatusLine -Status WARN -Message ("{0,-20} Unreachable - {1}" -f $row.MachineName, $row.ErrorMessage)
        }
        'Skipped' {
            Write-StatusLine -Status INFO -Message ("{0,-20} Skipped - {1}" -f $row.MachineName, $row.ErrorMessage)
        }
    }
}

Write-Progress -Activity 'Collecting VDA resources' -Completed

$collected = @($results | Where-Object { $_.CollectionStatus -eq 'Success' }).Count
$failed    = @($results | Where-Object { $_.CollectionStatus -eq 'Unreachable' }).Count

Write-StatusLine -Status INFO -Message ("Collected {0} of {1} ({2} unreachable)" -f $collected, $inventory.Count, $failed)

# Write outputs.
$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$csvPath  = Join-Path $OutputPath "CitrixVDAResources_$stamp.csv"
$htmlPath = Join-Path $OutputPath "CitrixVDAResources_$stamp.html"

try {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-StatusLine -Status PASS -Message "CSV:  $csvPath"
}
catch {
    Write-Error "Failed to write the CSV to '$csvPath': $_"
    exit 1
}

try {
    $html = New-VDAHtmlReport -Rows $results -Scope $scopeLabel -GeneratedAt $script:StartTime -Thresholds $thresholds
    Set-Content -Path $htmlPath -Value $html -Encoding UTF8 -ErrorAction Stop
    Write-StatusLine -Status PASS -Message "HTML: $htmlPath"
}
catch {
    Write-Error "Failed to write the HTML report to '$htmlPath': $_"
    exit 1
}

if (-not $NoOpen) {
    try { Start-Process $htmlPath -ErrorAction Stop }
    catch { Write-Verbose "Could not open the report automatically: $_" }
}

# Emit the rows so the script composes in a pipeline.
$results

#endregion
