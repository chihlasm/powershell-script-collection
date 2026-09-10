# Get-CitrixVDAResources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a PowerShell tool that discovers every Citrix VDA from the Delivery Controller, collects CPU/memory/disk/uptime per machine over CIM, and emits a CSV plus a self-contained HTML report with embedded charts.

**Architecture:** One self-contained `.ps1` with four internal stages — discovery (Citrix Broker SDK), collection (CIM sessions, sequential), analysis (pure threshold functions), reporting (CSV + HTML string builder). Pure functions are separated from I/O so the Pester suite runs with no live Citrix site. A `-LoadFunctionsOnly` switch lets tests dot-source the script without executing it.

**Tech Stack:** Windows PowerShell 5.1, Citrix Broker SDK (`Citrix.Broker.Admin.V2`), CIM/WinRM, Pester.

**Spec:** `docs/superpowers/specs/2026-08-19-citrix-vda-resources-design.md`

## Global Constraints

- **PowerShell 5.1** — `#Requires -Version 5.1`. No PS7-only syntax: no `??`, no `?.`, no ternary, no `ForEach-Object -Parallel`.
- **No external modules** — no `ImportExcel`, no PSGallery dependencies. Built-in Windows/RSAT/Citrix SDK only.
- **No `#Requires -Modules`** — load the Citrix SDK at runtime via `Add-PSSnapin` then `Import-Module` in try/catch, per CLAUDE.md.
- **Every remote cmdlet is targeted** — no cmdlet may assume it runs on the VDA. All CIM calls go through `-CimSession`.
- **Cite documented facts inline** — every Microsoft/Citrix constant gets a comment with its source URL, and `.NOTES` carries a `REFERENCES` block.
- **Status prefixes** — `[PASS]` Green, `[WARN]` Yellow, `[FAIL]` Red, `[INFO]` Cyan.
- **Timestamps** — `yyyy-MM-dd HH:mm:ss` in logs, `yyyy-MM-dd_HHmmss` in filenames.
- **CSV export** — `Export-Csv -NoTypeInformation -Encoding UTF8`.
- **Verified constants (do not re-derive from memory):**
  - `Win32_LogicalDisk.DriveType = 3` means Local Disk. `Size` and `FreeSpace` are in **bytes**.
  - `Win32_OperatingSystem.TotalVisibleMemorySize` and `FreePhysicalMemory` are in **kilobytes**.
  - `Win32_PerfFormattedData_PerfOS_Processor` aggregate instance is `Name = '_Total'`, value `PercentProcessorTime`.
  - Citrix Broker cmdlets return only the first **250** records unless `-MaxRecordCount` is passed.

---

## File Structure

| File | Responsibility |
|---|---|
| `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` | Everything: param block, help, all functions, main execution |
| `Get-CitrixVDAResources/README.md` | Overview, requirements, parameter table, usage examples |
| `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1` | Pester suite over the pure functions |

Single-script layout matches the repo's flat one-tool-per-folder pattern.

---

### Task 1: Script skeleton, help, and `-LoadFunctionsOnly`

Establishes the file so every later task has somewhere to add functions, and makes the test harness possible from the start.

**Files:**
- Create: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1`
- Create: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: nothing
- Produces: a dot-sourceable script that defines functions and exits early when `-LoadFunctionsOnly` is passed. Every later task's tests depend on this.

- [ ] **Step 1: Write the failing test**

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Get-CitrixVDAResources.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without attempting discovery' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — the script file does not exist.

- [ ] **Step 3: Write minimal implementation**

Create the script with the full comment-based help, param block, and the early-exit guard. The param block is written in full here so later tasks never have to guess a parameter name.

```powershell
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

# Functions are defined above this line. When dot-sourced by the test suite we stop here
# so that no discovery or collection is attempted.
if ($LoadFunctionsOnly) { return }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: Get-CitrixVDAResources skeleton with help, params, and test harness"
```

---

### Task 2: Threshold classification (`Get-ResourceStatus`)

Pure function, no I/O. Every status shown in console, CSV, and HTML flows through it, so its boundary behavior is worth pinning down first.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (add to a new `#region Analysis`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: `Write-StatusLine` (Task 1) is unrelated; this task needs nothing.
- Produces: `Get-ResourceStatus -Value <double> -WarnAt <int> -CriticalAt <int>` returns the string `'PASS'`, `'WARN'`, `'FAIL'`, or `'UNKNOWN'`. Tasks 4, 6, and 7 call this.

- [ ] **Step 1: Write the failing test**

Boundary values are tested explicitly because an off-by-one here silently misclassifies machines rather than erroring.

```powershell
Describe 'Get-ResourceStatus' {
    It 'returns PASS below the warn threshold' {
        Get-ResourceStatus -Value 79.9 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }

    It 'returns WARN exactly at the warn threshold' {
        Get-ResourceStatus -Value 80 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns WARN between warn and critical' {
        Get-ResourceStatus -Value 85 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'returns FAIL exactly at the critical threshold' {
        Get-ResourceStatus -Value 90 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns FAIL above the critical threshold' {
        Get-ResourceStatus -Value 99.5 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns UNKNOWN for a null value rather than throwing' {
        Get-ResourceStatus -Value $null -WarnAt 80 -CriticalAt 90 | Should -Be 'UNKNOWN'
    }

    It 'returns PASS at zero' {
        Get-ResourceStatus -Value 0 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }
}

Describe 'Get-WorstStatus' {
    It 'picks FAIL over WARN and PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'FAIL') | Should -Be 'FAIL'
    }

    It 'picks WARN over PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'PASS') | Should -Be 'WARN'
    }

    It 'returns PASS when everything passes' {
        Get-WorstStatus -Statuses @('PASS', 'PASS') | Should -Be 'PASS'
    }

    It 'ignores UNKNOWN when a real status is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'WARN') | Should -Be 'WARN'
    }

    It 'returns UNKNOWN when nothing else is present' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'UNKNOWN') | Should -Be 'UNKNOWN'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `Get-ResourceStatus` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS — all 12 cases.

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: threshold classification with inclusive boundaries and UNKNOWN handling"
```

---

### Task 3: Citrix SDK loading and broker discovery (`Get-VDAInventory`)

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (new `#region Discovery`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: `Write-StatusLine` (Task 1)
- Produces:
  - `Import-CitrixBrokerSdk` returns `$true`/`$false`.
  - `Get-VDAInventory -DeliveryController <string> [-DesktopGroupName <string>] [-CatalogName <string>] [-MachineName <string[]>] -MaxRecordCount <int>` returns `PSCustomObject[]` with fields `MachineName`, `DnsName`, `CatalogName`, `DeliveryGroup`, `RegistrationState`, `InMaintenanceMode`, `LoadIndex`, `SessionCount`, `PowerState`. Task 5 iterates this.

- [ ] **Step 1: Write the failing test**

`Get-BrokerMachine` does not exist on the test machine, so the test defines a stub before mocking it.

```powershell
Describe 'Get-VDAInventory' {
    BeforeAll {
        # Get-BrokerMachine only exists on a Delivery Controller. Define a stub so Pester
        # has a command to mock, then mock it.
        function Get-BrokerMachine { param($AdminAddress, $DesktopGroupName, $CatalogName, $MachineName, $MaxRecordCount) }
    }

    It 'maps broker properties onto the output schema' {
        Mock Get-BrokerMachine {
            [PSCustomObject]@{
                MachineName       = 'CONTOSO\VDA-0001'
                DNSName           = 'vda-0001.contoso.local'
                CatalogName       = 'Win2019 Catalog'
                DesktopGroupName  = 'Finance Desktops'
                RegistrationState = 'Registered'
                InMaintenanceMode = $false
                LoadIndex         = 3200
                SessionCount      = 7
                PowerState        = 'On'
            }
        }

        $result = @(Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000)

        $result.Count                | Should -Be 1
        $result[0].MachineName       | Should -Be 'CONTOSO\VDA-0001'
        $result[0].DnsName           | Should -Be 'vda-0001.contoso.local'
        $result[0].DeliveryGroup     | Should -Be 'Finance Desktops'
        $result[0].RegistrationState | Should -Be 'Registered'
        $result[0].SessionCount      | Should -Be 7
    }

    It 'always passes MaxRecordCount so the broker does not silently cap at 250' {
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 5000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            $MaxRecordCount -eq 5000
        }
    }

    It 'passes the delivery group filter through when supplied' {
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -DesktopGroupName 'Finance Desktops' -MaxRecordCount 1000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            $DesktopGroupName -eq 'Finance Desktops'
        }
    }

    It 'omits the delivery group filter when not supplied' {
        Mock Get-BrokerMachine { @() }

        Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000 | Out-Null

        Should -Invoke Get-BrokerMachine -Times 1 -ParameterFilter {
            $null -eq $DesktopGroupName
        }
    }

    It 'returns an empty collection when the broker returns nothing' {
        Mock Get-BrokerMachine { @() }

        $result = @(Get-VDAInventory -DeliveryController 'DDC01' -MaxRecordCount 1000)

        $result.Count | Should -Be 0
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `Get-VDAInventory` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: broker discovery with explicit MaxRecordCount to avoid the 250-record cap"
```

---

### Task 4: Metric conversion helpers

The unit conversions get their own task because memory and disk arrive in *different* units — a mistake here produces plausible-looking numbers that are wrong by a factor of 1024.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (new `#region Metrics`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: `Get-ResourceStatus` (Task 2)
- Produces:
  - `ConvertTo-MemoryMetrics -TotalKb <double> -FreeKb <double>` → object with `TotalGB`, `UsedGB`, `FreeGB`, `UsedPercent`.
  - `ConvertTo-DiskMetrics -Disks <object[]>` → object with `Summary` (string), `MaxUsedPercent` (double). Input objects need `DeviceID`, `Size`, `FreeSpace` in bytes.
  - `Get-UptimeDays -LastBootUpTime <datetime> -Now <datetime>` → double.
  Task 5 calls all three.

- [ ] **Step 1: Write the failing test**

```powershell
Describe 'ConvertTo-MemoryMetrics' {
    It 'treats input as kilobytes per Win32_OperatingSystem' {
        # 16 GB total, 4 GB free, expressed in KB as WMI reports it.
        $m = ConvertTo-MemoryMetrics -TotalKb (16 * 1024 * 1024) -FreeKb (4 * 1024 * 1024)

        $m.TotalGB     | Should -Be 16
        $m.FreeGB      | Should -Be 4
        $m.UsedGB      | Should -Be 12
        $m.UsedPercent | Should -Be 75
    }

    It 'returns null percent when total is zero rather than dividing by zero' {
        $m = ConvertTo-MemoryMetrics -TotalKb 0 -FreeKb 0
        $m.UsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-DiskMetrics' {
    It 'treats input as bytes per Win32_LogicalDisk and reports the worst drive' {
        $disks = @(
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 40GB }  # 60% used
            [PSCustomObject]@{ DeviceID = 'D:'; Size = 200GB; FreeSpace = 20GB }  # 90% used
        )

        $d = ConvertTo-DiskMetrics -Disks $disks

        $d.MaxUsedPercent | Should -Be 90
        $d.Summary        | Should -Match 'C:'
        $d.Summary        | Should -Match 'D:'
    }

    It 'ignores a zero-size disk without dividing by zero' {
        $disks = @(
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 50GB }
            [PSCustomObject]@{ DeviceID = 'E:'; Size = 0;     FreeSpace = 0 }
        )

        $d = ConvertTo-DiskMetrics -Disks $disks

        $d.MaxUsedPercent | Should -Be 50
    }

    It 'returns null max when there are no disks' {
        $d = ConvertTo-DiskMetrics -Disks @()
        $d.MaxUsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'Get-UptimeDays' {
    It 'computes whole and fractional days between boot and now' {
        $boot = [datetime]'2026-08-01 00:00:00'
        $now  = [datetime]'2026-08-11 12:00:00'

        Get-UptimeDays -LastBootUpTime $boot -Now $now | Should -Be 10.5
    }

    It 'returns 0 when boot time is in the future rather than a negative number' {
        $boot = [datetime]'2026-08-20 00:00:00'
        $now  = [datetime]'2026-08-19 00:00:00'

        Get-UptimeDays -LastBootUpTime $boot -Now $now | Should -Be 0
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `ConvertTo-MemoryMetrics` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: metric conversion with documented KB vs bytes unit handling"
```

---

### Task 5: Per-machine CIM collection (`Get-VDAResourceSnapshot`)

The only function that touches the network. Isolated to one machine so parallelism can be added later without reshaping anything.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (new `#region Collection`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: `ConvertTo-MemoryMetrics`, `ConvertTo-DiskMetrics`, `Get-UptimeDays` (Task 4)
- Produces: `Get-VDAResourceSnapshot -ComputerName <string> [-Credential <PSCredential>] -TimeoutSeconds <int>` returns an object with `CpuPercent`, `MemoryTotalGB`, `MemoryUsedGB`, `MemoryFreeGB`, `MemoryUsedPercent`, `DiskSummary`, `MaxDiskUsedPercent`, `UptimeDays`, `CollectionStatus`, `ErrorMessage`. Task 6 merges this with the inventory row.

- [ ] **Step 1: Write the failing test**

```powershell
Describe 'Get-VDAResourceSnapshot' {
    It 'returns Success with populated metrics when every query works' {
        Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 16 * 1024 * 1024
                        FreePhysicalMemory     = 4 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-5)
                    }
                }
                'Win32_LogicalDisk' {
                    [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 40GB }
                }
                'Win32_PerfFormattedData_PerfOS_Processor' {
                    [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 42 }
                }
            }
        }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-0001' -TimeoutSeconds 15

        $snap.CollectionStatus   | Should -Be 'Success'
        $snap.CpuPercent         | Should -Be 42
        $snap.MemoryUsedPercent  | Should -Be 75
        $snap.MaxDiskUsedPercent | Should -Be 60
        $snap.UptimeDays         | Should -BeGreaterThan 4
    }

    It 'returns Unreachable with the error message when the session cannot be created' {
        Mock New-CimSession { throw 'WinRM cannot complete the operation' }
        Mock Remove-CimSession { }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-DEAD' -TimeoutSeconds 15

        $snap.CollectionStatus | Should -Be 'Unreachable'
        $snap.ErrorMessage     | Should -Match 'WinRM'
        $snap.CpuPercent       | Should -BeNullOrEmpty
    }

    It 'still returns other metrics when only the CPU query fails' {
        Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 8 * 1024 * 1024
                        FreePhysicalMemory     = 2 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-1)
                    }
                }
                'Win32_LogicalDisk' {
                    [PSCustomObject]@{ DeviceID = 'C:'; Size = 50GB; FreeSpace = 25GB }
                }
                'Win32_PerfFormattedData_PerfOS_Processor' { throw 'perf counters unavailable' }
            }
        }

        $snap = Get-VDAResourceSnapshot -ComputerName 'VDA-0002' -TimeoutSeconds 15

        $snap.CollectionStatus  | Should -Be 'Success'
        $snap.CpuPercent        | Should -BeNullOrEmpty
        $snap.MemoryUsedPercent | Should -Be 75
    }

    It 'always removes the CIM session even when a query throws' {
        Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
        Mock Remove-CimSession { }
        Mock Get-CimInstance { throw 'boom' }

        Get-VDAResourceSnapshot -ComputerName 'VDA-0003' -TimeoutSeconds 15 | Out-Null

        Should -Invoke Remove-CimSession -Times 1
    }

    It 'filters to fixed disks only using DriveType 3' {
        Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
        Mock Remove-CimSession { }
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' {
                    [PSCustomObject]@{
                        TotalVisibleMemorySize = 8 * 1024 * 1024
                        FreePhysicalMemory     = 4 * 1024 * 1024
                        LastBootUpTime         = (Get-Date).AddDays(-1)
                    }
                }
                'Win32_LogicalDisk' { [PSCustomObject]@{ DeviceID = 'C:'; Size = 50GB; FreeSpace = 25GB } }
                'Win32_PerfFormattedData_PerfOS_Processor' { [PSCustomObject]@{ Name = '_Total'; PercentProcessorTime = 10 } }
            }
        }

        Get-VDAResourceSnapshot -ComputerName 'VDA-0004' -TimeoutSeconds 15 | Out-Null

        Should -Invoke Get-CimInstance -Times 1 -ParameterFilter {
            $ClassName -eq 'Win32_LogicalDisk' -and $Filter -match 'DriveType\s*=\s*3'
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `Get-VDAResourceSnapshot` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
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
            ComputerName  = $ComputerName
            OperationTimeoutSec = $TimeoutSeconds
            ErrorAction   = 'Stop'
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

#endregion
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: per-machine CIM collection with per-query isolation and guaranteed teardown"
```

---

### Task 6: Row assembly (`New-VDAResultRow`)

Merges an inventory row with a snapshot and applies thresholds. Pure, so it is fully testable.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (add to `#region Analysis`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: `Get-ResourceStatus`, `Get-WorstStatus` (Task 2)
- Produces: `New-VDAResultRow -Inventory <object> -Snapshot <object> -Thresholds <hashtable>` returns the final flat row used by CSV, console, and HTML. `-Thresholds` keys: `CpuWarn`, `CpuCritical`, `MemoryWarn`, `MemoryCritical`, `DiskWarn`, `DiskCritical`.

- [ ] **Step 1: Write the failing test**

```powershell
Describe 'New-VDAResultRow' {
    BeforeAll {
        $script:Thresholds = @{
            CpuWarn = 80; CpuCritical = 90
            MemoryWarn = 80; MemoryCritical = 90
            DiskWarn = 80; DiskCritical = 90
        }

        $script:Inv = [PSCustomObject]@{
            MachineName       = 'CONTOSO\VDA-0001'
            DnsName           = 'vda-0001.contoso.local'
            CatalogName       = 'Win2019'
            DeliveryGroup     = 'Finance'
            RegistrationState = 'Registered'
            InMaintenanceMode = $false
            LoadIndex         = 3200
            SessionCount      = 7
            PowerState        = 'On'
        }
    }

    It 'carries broker fields onto the row' {
        $snap = [PSCustomObject]@{
            CpuPercent = 10; MemoryTotalGB = 16; MemoryUsedGB = 4; MemoryFreeGB = 12
            MemoryUsedPercent = 25; DiskSummary = 'C: 30/100GB (30%)'; MaxDiskUsedPercent = 30
            UptimeDays = 5; CollectionStatus = 'Success'; ErrorMessage = $null
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MachineName   | Should -Be 'CONTOSO\VDA-0001'
        $row.DeliveryGroup | Should -Be 'Finance'
        $row.SessionCount  | Should -Be 7
        $row.OverallStatus | Should -Be 'PASS'
    }

    It 'escalates OverallStatus to FAIL when memory is critical' {
        $snap = [PSCustomObject]@{
            CpuPercent = 10; MemoryTotalGB = 16; MemoryUsedGB = 15; MemoryFreeGB = 1
            MemoryUsedPercent = 94; DiskSummary = 'C: 30/100GB (30%)'; MaxDiskUsedPercent = 30
            UptimeDays = 5; CollectionStatus = 'Success'; ErrorMessage = $null
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MemoryStatus  | Should -Be 'FAIL'
        $row.OverallStatus | Should -Be 'FAIL'
    }

    It 'produces a row for an unreachable machine rather than dropping it' {
        $snap = [PSCustomObject]@{
            CpuPercent = $null; MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            MemoryUsedPercent = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; CollectionStatus = 'Unreachable'; ErrorMessage = 'WinRM timed out'
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.MachineName      | Should -Be 'CONTOSO\VDA-0001'
        $row.CollectionStatus | Should -Be 'Unreachable'
        $row.ErrorMessage     | Should -Be 'WinRM timed out'
        $row.OverallStatus    | Should -Be 'UNKNOWN'
    }

    It 'marks a skipped machine as UNKNOWN overall' {
        $snap = [PSCustomObject]@{
            CpuPercent = $null; MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
            MemoryUsedPercent = $null; DiskSummary = $null; MaxDiskUsedPercent = $null
            UptimeDays = $null; CollectionStatus = 'Skipped'; ErrorMessage = 'Not registered'
        }

        $row = New-VDAResultRow -Inventory $script:Inv -Snapshot $snap -Thresholds $script:Thresholds

        $row.OverallStatus | Should -Be 'UNKNOWN'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `New-VDAResultRow` is not recognized.

- [ ] **Step 3: Write minimal implementation**

```powershell
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: result row assembly merging broker state with resource metrics"
```

---

### Task 7: HTML report generation (`New-VDAHtmlReport`)

Pure string builder — takes rows, returns HTML. No filesystem access, so it is fully testable.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (new `#region Reporting`)
- Test: `Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1`

**Interfaces:**
- Consumes: rows from `New-VDAResultRow` (Task 6)
- Produces: `New-VDAHtmlReport -Rows <object[]> -Scope <string> -GeneratedAt <datetime> -Thresholds <hashtable>` returns a complete HTML document as a single string. Task 8 writes it to disk.

- [ ] **Step 1: Write the failing test**

The escaping test matters: machine names come from AD and a `&` in one would corrupt the document.

```powershell
Describe 'ConvertTo-HtmlSafe' {
    It 'escapes the characters that would break the document' {
        ConvertTo-HtmlSafe -Text 'A&B<C>D"E' | Should -Be 'A&amp;B&lt;C&gt;D&quot;E'
    }

    It 'returns an empty string for null input' {
        ConvertTo-HtmlSafe -Text $null | Should -Be ''
    }
}

Describe 'New-VDAHtmlReport' {
    BeforeAll {
        $script:Thresholds = @{
            CpuWarn = 80; CpuCritical = 90
            MemoryWarn = 80; MemoryCritical = 90
            DiskWarn = 80; DiskCritical = 90
        }

        $script:Rows = @(
            [PSCustomObject]@{
                MachineName = 'VDA-0001'; DnsName = 'vda-0001.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 1000; SessionCount = 3; PowerState = 'On'
                CpuPercent = 12; CpuStatus = 'PASS'
                MemoryTotalGB = 16; MemoryUsedGB = 6; MemoryFreeGB = 10
                MemoryUsedPercent = 38; MemoryStatus = 'PASS'
                DiskSummary = 'C: 45/120GB (37%)'; MaxDiskUsedPercent = 37; DiskStatus = 'PASS'
                UptimeDays = 6; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'PASS'
            },
            [PSCustomObject]@{
                MachineName = 'VDA-0012'; DnsName = 'vda-0012.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 9000; SessionCount = 22; PowerState = 'On'
                CpuPercent = 71; CpuStatus = 'PASS'
                MemoryTotalGB = 16; MemoryUsedGB = 15; MemoryFreeGB = 1
                MemoryUsedPercent = 94; MemoryStatus = 'FAIL'
                DiskSummary = 'C: 109/120GB (91%)'; MaxDiskUsedPercent = 91; DiskStatus = 'FAIL'
                UptimeDays = 118; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'FAIL'
            },
            [PSCustomObject]@{
                MachineName = 'VDA-0019'; DnsName = 'vda-0019.contoso.local'
                CatalogName = 'Win2019'; DeliveryGroup = 'Finance'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 0; SessionCount = 0; PowerState = 'On'
                CpuPercent = $null; CpuStatus = 'UNKNOWN'
                MemoryTotalGB = $null; MemoryUsedGB = $null; MemoryFreeGB = $null
                MemoryUsedPercent = $null; MemoryStatus = 'UNKNOWN'
                DiskSummary = $null; MaxDiskUsedPercent = $null; DiskStatus = 'UNKNOWN'
                UptimeDays = $null; CollectionStatus = 'Unreachable'
                ErrorMessage = 'WinRM connection timed out'
                OverallStatus = 'UNKNOWN'
            }
        )
    }

    It 'produces a complete standalone HTML document' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All delivery groups' -GeneratedAt ([datetime]'2026-08-19 10:14:02') -Thresholds $script:Thresholds

        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '</html>\s*$'
    }

    It 'references no external resources so it survives being emailed' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Not -Match 'src="http'
        $html | Should -Not -Match 'href="http'
        $html | Should -Not -Match '<script src'
    }

    It 'includes every machine, unreachable ones included' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'VDA-0001'
        $html | Should -Match 'VDA-0012'
        $html | Should -Match 'VDA-0019'
    }

    It 'surfaces the unreachable count in the summary' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'Unreachable'
    }

    It 'escapes machine names so an ampersand cannot corrupt the document' {
        $rows = @(
            [PSCustomObject]@{
                MachineName = 'VDA&<01>'; DnsName = 'x'; CatalogName = 'c'; DeliveryGroup = 'd'
                RegistrationState = 'Registered'; InMaintenanceMode = $false
                LoadIndex = 0; SessionCount = 0; PowerState = 'On'
                CpuPercent = 1; CpuStatus = 'PASS'
                MemoryTotalGB = 8; MemoryUsedGB = 1; MemoryFreeGB = 7
                MemoryUsedPercent = 12; MemoryStatus = 'PASS'
                DiskSummary = 'C: 1/10GB (10%)'; MaxDiskUsedPercent = 10; DiskStatus = 'PASS'
                UptimeDays = 1; CollectionStatus = 'Success'; ErrorMessage = $null
                OverallStatus = 'PASS'
            }
        )

        $html = New-VDAHtmlReport -Rows $rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        $html | Should -Match 'VDA&amp;&lt;01&gt;'
        $html | Should -Not -Match 'VDA&<01>'
    }

    It 'sorts the chart worst-first so problem machines lead' {
        $html = New-VDAHtmlReport -Rows $script:Rows -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds

        # VDA-0012 is the worst machine and must appear before the healthy VDA-0001.
        $html.IndexOf('VDA-0012') | Should -BeLessThan $html.IndexOf('VDA-0001')
    }

    It 'handles an empty row set without throwing' {
        { New-VDAHtmlReport -Rows @() -Scope 'All' -GeneratedAt (Get-Date) -Thresholds $script:Thresholds } | Should -Not -Throw
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: FAIL — `ConvertTo-HtmlSafe` is not recognized.

- [ ] **Step 3: Write minimal implementation**

Dark theme per the CLAUDE.md design direction. Status is communicated by both color and text label, never color alone.

```powershell
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
    $reachable   = @($Rows | Where-Object { $_.CollectionStatus -eq 'Success' }).Count
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
.mono { font-variant-numeric:tabular-nums; }
.name { font-weight:600; }
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

        $note = if ($r.ErrorMessage) { '<span class="err">' + (ConvertTo-HtmlSafe -Text $r.ErrorMessage) + '</span>' }
                elseif ($r.InMaintenanceMode) { '<span class="muted">In maintenance mode</span>' }
                else { '' }

        [void]$sb.AppendLine('<tr>')
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1" "Get-CitrixVDAResources/Tests/Get-CitrixVDAResources.Tests.ps1"
git commit -m "feat: self-contained dark-theme HTML report with inline SVG bars"
```

---

### Task 8: Main execution block

Wires the stages together. This is the only part not unit-tested — it is verified by running the script.

**Files:**
- Modify: `Get-CitrixVDAResources/Get-CitrixVDAResources.ps1` (append below the `-LoadFunctionsOnly` guard)

**Interfaces:**
- Consumes: every function from Tasks 1-7
- Produces: the script's runtime behavior; emits result rows to the pipeline and writes two files.

- [ ] **Step 1: Write the main block**

Append after the `if ($LoadFunctionsOnly) { return }` line.

```powershell
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

$scopeLabel = if ($MachineName)      { "Machines: $($MachineName -join ', ')" }
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
```

- [ ] **Step 2: Verify the full suite still passes**

The main block sits below the `-LoadFunctionsOnly` guard, so dot-sourcing must remain unaffected.

Run: `Invoke-Pester "Get-CitrixVDAResources\Tests\Get-CitrixVDAResources.Tests.ps1"`
Expected: PASS — every test from Tasks 1-7, with no attempt to contact a Delivery Controller.

- [ ] **Step 3: Verify the script parses and its help renders**

Run:
```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path "Get-CitrixVDAResources\Get-CitrixVDAResources.ps1"), [ref]$null, [ref]$errors)
$errors   # expect no output
Get-Help "Get-CitrixVDAResources\Get-CitrixVDAResources.ps1" -Full
```
Expected: no parse errors; help shows every parameter and all three examples.

- [ ] **Step 4: Verify graceful failure with no Citrix SDK present**

Run on a machine without the SDK: `.\Get-CitrixVDAResources\Get-CitrixVDAResources.ps1 -OutputPath $env:TEMP`
Expected: a clear "Citrix Broker SDK not found" error and a non-zero exit — not a crash or an empty report.

- [ ] **Step 5: Commit**

```bash
git add "Get-CitrixVDAResources/Get-CitrixVDAResources.ps1"
git commit -m "feat: main execution wiring discovery, collection, and both report outputs"
```

---

### Task 9: README

**Files:**
- Create: `Get-CitrixVDAResources/README.md`

**Interfaces:**
- Consumes: the finished parameter set from Task 1
- Produces: documentation only

- [ ] **Step 1: Write the README**

```markdown
# Get-CitrixVDAResources

Fleet-wide resource report for Citrix VDAs. Discovers every VDA registered with a Delivery
Controller, collects CPU, memory, disk, and uptime from each one, and produces a CSV for
the record plus a self-contained HTML report for stakeholders.

Machines that cannot be contacted still appear in both outputs with a clear status, so an
unreachable VDA is never mistaken for a healthy one.

Complements [`CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1`](../CitrixVDADiagnostics/),
which goes deep on a single machine. This script goes wide across the fleet — run it first
to find the machine worth investigating.

## Requirements

- Windows PowerShell 5.1
- Citrix Broker SDK (present on a Delivery Controller, or install Citrix Studio / the
  Citrix PowerShell SDK)
- WinRM reachable on the target VDAs
- An account with Citrix read rights and CIM access to the VDAs

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-DeliveryController` | `localhost` | Delivery Controller to query |
| `-DesktopGroupName` | — | Limit to one delivery group |
| `-CatalogName` | — | Limit to one machine catalog |
| `-MachineName` | — | Explicit machine names; bypasses group/catalog filters |
| `-Credential` | — | Credentials for the CIM connections |
| `-CpuWarnPercent` | `80` | CPU warning threshold |
| `-CpuCriticalPercent` | `90` | CPU critical threshold |
| `-MemoryWarnPercent` | `80` | Memory warning threshold |
| `-MemoryCriticalPercent` | `90` | Memory critical threshold |
| `-DiskWarnPercent` | `80` | Disk warning threshold |
| `-DiskCriticalPercent` | `90` | Disk critical threshold |
| `-MaxRecordCount` | no practical limit | Broker record cap — see note below |
| `-ConnectionTimeoutSeconds` | `15` | Per-machine CIM timeout |
| `-IncludeUnregistered` | off | Also try to collect from unregistered machines |
| `-OutputPath` | current directory | Where the CSV and HTML are written |
| `-NoOpen` | off | Do not open the HTML when finished |

## Examples

Report on every VDA in the site:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01
```

Limit to one delivery group and write to a share:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -DesktopGroupName "Finance Desktops" -OutputPath \\fileserver\reports
```

Lower the CPU warning threshold for a busy environment, without opening the report:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -CpuWarnPercent 70 -NoOpen
```

## Notes

**On fleet size.** Citrix Broker cmdlets return only the first 250 records unless
`-MaxRecordCount` is supplied — they warn rather than error, so a naive query on a large
site silently under-reports while still looking complete. This script always passes the
parameter explicitly and prints how many machines it discovered against how many it
collected, so a partial run is visible.

**On collection time.** Collection is sequential, roughly a second or two per machine.
A 50-VDA site takes about a minute. Very large fleets will take proportionally longer.

**On unreachable machines.** Powered-off and unregistered machines are skipped without a
connection attempt (that is expected, not a fault). Machines that should be reachable but
are not appear as `Unreachable` with the underlying error.

## Testing

```powershell
Invoke-Pester .\Tests\Get-CitrixVDAResources.Tests.ps1
```

The suite mocks the broker and CIM layers, so it runs anywhere — no Citrix site required.
```

- [ ] **Step 2: Verify the links resolve**

Confirm `../CitrixVDADiagnostics/` exists relative to the README.

- [ ] **Step 3: Commit**

```bash
git add "Get-CitrixVDAResources/README.md"
git commit -m "docs: README for Get-CitrixVDAResources"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| Folder layout | 1, 9 |
| `Get-VDAInventory` + MaxRecordCount fix | 3 |
| `Get-VDAResourceSnapshot` | 5 |
| `Get-ResourceStatus` | 2 |
| `New-VDAHtmlReport` | 7 |
| `Write-StatusLine` | 1 |
| Parameters table | 1 |
| Output row schema | 6 |
| Error handling table | 5 (per-machine), 8 (script-level) |
| Console output format | 1, 8 |
| HTML report structure | 7 |
| Testing table | 2, 3, 4, 5, 6, 7 |
| Verified facts + citations | 3, 4, 5 |
| `.NOTES` REFERENCES block | 1 |

No gaps.

**Placeholder scan:** No TBDs. Every code step carries real code; every test step carries real assertions. Task 1 flags one typo to remove in the block it appears in.

**Type consistency check:**
- `Get-ResourceStatus` returns `PASS`/`WARN`/`FAIL`/`UNKNOWN` — consumed with those exact values in Tasks 6 and 7.
- `Get-VDAInventory` emits `DnsName` (not `DNSName`) — Tasks 6 and 8 use `DnsName`.
- `ConvertTo-DiskMetrics` returns `.Summary`/`.MaxUsedPercent` — Task 5 maps these to `DiskSummary`/`MaxDiskUsedPercent`, which Tasks 6 and 7 use consistently.
- `$Thresholds` keys (`CpuWarn`, `CpuCritical`, `MemoryWarn`, `MemoryCritical`, `DiskWarn`, `DiskCritical`) are identical in Tasks 6, 7, and 8.
- `CollectionStatus` values `Success`/`Unreachable`/`Skipped` are consistent across Tasks 5, 6, 7, and 8.

**One known deviation from strict TDD:** Task 8 (main execution) is verified by running the script rather than by unit tests, because it is the I/O wiring layer. All logic it calls is covered by Tasks 2-7.
