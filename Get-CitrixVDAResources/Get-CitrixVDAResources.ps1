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

# Functions are defined above this line. When dot-sourced by the test suite we stop here
# so that no discovery or collection is attempted.
if ($LoadFunctionsOnly) { return }
