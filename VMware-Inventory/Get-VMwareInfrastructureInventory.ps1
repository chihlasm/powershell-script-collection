<#
.SYNOPSIS
    Collects a VMware ESXi / vCenter host and guest VM inventory with capacity rollups.

.DESCRIPTION
    MSP-portable inventory script. Targets one or more vCenter Servers and/or standalone
    ESXi hosts and exports: host hardware and ESXi build, per-VM configuration (power
    state, vCPU, memory, provisioned vs used disk, guest OS, IPs, VMware Tools, hardware
    version), datastore capacity, snapshots, and clusters (vCenter only).

    On top of the raw inventory it computes capacity rollups intended for a vCIO or
    architect to interpret:

      - Per host:      vCPU allocated vs physical cores (consolidation ratio),
                       RAM allocated vs physical (overcommit ratio)
      - Per datastore: provisioned vs capacity (thin overallocation ratio),
                       snapshot consumption as a share of used space
      - Per target:    aggregate totals, powered-on vs powered-off counts

    This script REPORTS. It deliberately renders no verdicts, applies no thresholds, and
    makes no recommendations - every rollup is published alongside the raw inputs it was
    derived from so the reader can audit the arithmetic and draw their own conclusions.

    Read-only. Nothing is powered on or off, no snapshot is consolidated, no host is
    placed into or taken out of maintenance mode.

.PARAMETER Server
    One or more vCenter Servers or standalone ESXi hosts. Accepts NetBIOS, FQDN, or IP.
    A vCenter target returns its entire managed inventory; a standalone ESXi target
    returns only itself. The two can be mixed freely in a single run.

.PARAMETER HostListFile
    Path to a newline-delimited text file of additional targets. Blank lines and lines
    beginning with # are ignored. Combined with anything passed to -Server.

.PARAMETER Credential
    Credential applied to every target in the run. When omitted, each connection is
    attempted without explicit credentials so that PowerCLI consults its own credential
    store (%APPDATA%\VMware\credstore\vicredentials.xml), falling back to an interactive
    prompt. See the CREDENTIAL STORE section in .NOTES for unattended runs.

.PARAMETER OutputPath
    Folder for exports. Defaults to .\VMwareInventory_<timestamp> in the current directory.

.PARAMETER SkipSnapshots
    Skips snapshot collection. Snapshot sizing requires the vSphere "Datastore > Browse
    datastore" privilege and reads from the datastore, so it is the slowest part of a
    large run. Use this for a fast pass; the per-datastore snapshot rollup is omitted.

.PARAMETER InstallPowerCLI
    Installs the PowerCLI module for the current user if it is not already present, then
    proceeds with collection. Equivalent to running
    Install-Module VMware.PowerCLI -Scope CurrentUser by hand first.

.EXAMPLE
    .\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01.contoso.local

    Connects to a single vCenter and inventories everything it manages.

.EXAMPLE
    .\Get-VMwareInfrastructureInventory.ps1 -Server 192.168.10.21,192.168.10.22 -Credential (Get-Credential root)

    Inventories two standalone ESXi hosts using the same root credential.

.EXAMPLE
    .\Get-VMwareInfrastructureInventory.ps1 -HostListFile .\client-hosts.txt -OutputPath C:\Reports

    Reads targets from a file and writes the export set to C:\Reports.

.EXAMPLE
    .\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01 -SkipSnapshots

    Fast pass with no snapshot enumeration.

.NOTES
    Author:  VC3 - powershell-script-collection
    Requires: PowerCLI (VMware.VimAutomation.Core). Read-only against vSphere.

    ---------------------------------------------------------------------------
    WHY WINDOWS POWERSHELL 5.1
    ---------------------------------------------------------------------------
    This script targets Windows PowerShell 5.1. It runs under PowerShell 7.x, but two
    PowerCLI features are unavailable there and both matter to this script:

      - Connect-VIServer -SaveCredentials is "not supported on the Core edition of
        PowerShell", so the credential store cannot be populated from PS 7.
      - InvalidCertificateAction supports only Fail and Ignore on PowerShell Core;
        Warn and Prompt are Windows PowerShell only.

    ---------------------------------------------------------------------------
    CREDENTIAL STORE (unattended / mixed-credential runs)
    ---------------------------------------------------------------------------
    Omitting -Credential lets PowerCLI use its own per-host credential store, which is
    the practical answer for a client with several standalone hosts that do not share a
    password. Populate it once per host, from Windows PowerShell 5.1:

        New-VICredentialStoreItem -Host esxi01.contoso.local -User root -Password '<pw>'

    Entries are written to %APPDATA%\VMware\credstore\vicredentials.xml under the
    profile of the user that created them. Inspect with Get-VICredentialStoreItem.

    NOTE: the exact precedence between the credential store, explicit credentials, and
    integrated authentication is documented in the about_server_authentication help
    topic, which Broadcom does not publish on the web. Confirm locally with:
        Get-Help about_server_authentication

    ---------------------------------------------------------------------------
    KNOWN BEHAVIOUR TO VERIFY ON FIRST STANDALONE RUN
    ---------------------------------------------------------------------------
    Broadcom does not document whether Get-Cluster against a standalone ESXi host
    returns an empty result or raises an error. This script does not depend on either:
    it branches on $DefaultVIServer.ProductLine ('vpx' = vCenter, 'embeddedEsx' =
    standalone ESXi) AND wraps the call in try/catch with a null check, which is correct
    under both behaviours.

    ---------------------------------------------------------------------------
    REFERENCES
    ---------------------------------------------------------------------------
    Connect-VIServer (-Server is String[]; -SaveCredentials unsupported on PS Core)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/connect-viserver
    Set-PowerCLIConfiguration (-ParticipateInCeip, -InvalidCertificateAction values/scopes)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/set-powercliconfiguration
    New-VICredentialStoreItem (default store path)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/new-vicredentialstoreitem
    VMHost type (ConnectionState, IsStandalone, CpuTotalMhz, MemoryTotalGB, ...)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.inventory.vmhost
    VMHostState enum = Connected | Disconnected | Maintenance | NotResponding
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.host.vmhoststate
    Get-VMHostHardware (first-class BiosVersion / SerialNumber)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-vmhosthardware
    VirtualMachine type (HardwareVersion string vs Version enum, ProvisionedSpaceGB, ...)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.inventory.virtualmachine
    PowerState enum = PoweredOff | PoweredOn | Suspended (VM; distinct from VMHostPowerState)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.inventory.powerstate
    VMVersion enum (capped at v18 - why HardwareVersion string is preferred)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.vm.vmversion
    GuestInfo (toolsStatus deprecated since vSphere API 4.0; use ToolsRunningStatus /
    ToolsVersionStatus2)
      https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.GuestInfo.html
    DatastoreSummary.uncommitted (bytes; valid only when accessible is true)
      https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.Datastore.Summary.html
    Get-Snapshot (SizeGB requires Datastore > Browse datastore privilege)
      https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-snapshot
    Host uptime / boot time via ExtensionData
      https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.Summary.QuickStats.html
      https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.RuntimeInfo.html
    PowerCLI modules (VMware.PowerCLI is a meta-module; core cmdlets live in
    VMware.VimAutomation.Core)
      https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/introduction-to-vmware-vsphere-powercli/vmware-vsphere-powercli-specific-concepts/vmware-powercli-modules.html
    PowerCLI compatibility matrix (Windows PowerShell 5.1 and PowerShell 7.x supported)
      https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/vmware-powercli-compatibility-matrix.html
    Install PowerCLI
      https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli.html
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]] $Server,

    [ValidateScript({
        if (Test-Path -LiteralPath $_ -PathType Leaf) { $true }
        else { throw "HostListFile not found: $_" }
    })]
    [string] $HostListFile,

    [System.Management.Automation.PSCredential] $Credential,

    [string] $OutputPath = ".\VMwareInventory_$(Get-Date -Format 'yyyy-MM-dd_HHmmss')",

    [switch] $SkipSnapshots,

    [switch] $InstallPowerCLI
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# Console output helpers
# =============================================================================

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string] $Level,
        [Parameter(Mandatory)][string] $Message
    )
    $color = switch ($Level) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'INFO' { 'Cyan' }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Write-Section {
    param([Parameter(Mandatory)][string] $Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

# Rounds a ratio to two places, returning $null rather than dividing by zero so that a
# missing denominator reads as "not available" in the CSV instead of a bogus 0.
function Get-SafeRatio {
    param($Numerator, $Denominator)
    if ($null -eq $Numerator -or $null -eq $Denominator) { return $null }
    if ($Denominator -eq 0) { return $null }
    return [math]::Round([double]$Numerator / [double]$Denominator, 2)
}

# =============================================================================
# PowerCLI bootstrap
# =============================================================================

# The core cmdlets used here (Connect-VIServer, Get-VMHost, Get-VM, Get-Datastore,
# Get-Snapshot, Get-Cluster) all live in VMware.VimAutomation.Core. VMware.PowerCLI is
# only a meta-module that pulls in the whole product, so importing the sub-module is
# sufficient; its own dependencies (VMware.VimAutomation.Sdk / .Common) auto-load.
# https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/introduction-to-vmware-vsphere-powercli/vmware-vsphere-powercli-specific-concepts/vmware-powercli-modules.html
#
# Deliberately NOT using #Requires -Modules: that directive refuses to start the script
# at all when the module is not on the standard path, which hides the actionable
# "here is how to install it" message below behind an opaque failure.
function Initialize-PowerCLI {
    param([switch] $AutoInstall)

    if (Get-Module -Name VMware.VimAutomation.Core) { return $true }

    if (-not (Get-Module -ListAvailable -Name VMware.VimAutomation.Core)) {
        if ($AutoInstall) {
            Write-Status INFO 'PowerCLI not found. Installing VMware.PowerCLI for the current user...'
            Write-Status INFO 'This downloads from the PowerShell Gallery and may take several minutes.'
            try {
                # -Scope CurrentUser installs into the user profile and does not require
                # elevation, which matters when running from a locked-down workstation.
                Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Status PASS 'PowerCLI installed.'
            } catch {
                Write-Status FAIL "PowerCLI installation failed: $($_.Exception.Message)"
                return $false
            }
        } else {
            Write-Status FAIL 'PowerCLI is not installed on this machine.'
            Write-Host ''
            Write-Host '  Install it for the current user (no administrator rights required):' -ForegroundColor White
            Write-Host ''
            Write-Host '      Install-Module VMware.PowerCLI -Scope CurrentUser' -ForegroundColor Cyan
            Write-Host ''
            Write-Host '  ...or re-run this script with -InstallPowerCLI to do that automatically.' -ForegroundColor White
            Write-Host '  For air-gapped machines see the offline install procedure:' -ForegroundColor White
            Write-Host '      https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli-offline.html' -ForegroundColor DarkGray
            Write-Host ''
            return $false
        }
    }

    try {
        Write-Status INFO 'Loading PowerCLI...'
        Import-Module -Name VMware.VimAutomation.Core -ErrorAction Stop
    } catch {
        Write-Status FAIL "Could not load PowerCLI: $($_.Exception.Message)"
        return $false
    }

    return $true
}

# Two PowerCLI defaults derail an otherwise unattended run: the CEIP opt-in prompt on
# first use, and a hard connection failure against the self-signed certificate that
# every standalone ESXi host ships with.
#
# Scope notes:
#   - InvalidCertificateAction is set at Session scope so this script never rewrites the
#     operator's persisted preference. On PowerShell Core only Fail and Ignore are valid
#     values (Warn/Prompt are Windows PowerShell only), and Ignore is valid on both.
#   - ParticipateInCeip CANNOT be set at Session scope - Broadcom documents it as valid
#     "only for the AllUsers and User configuration scopes" - so it is set at User scope
#     and only when no preference has been recorded yet.
# https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/set-powercliconfiguration
function Set-InventorySessionConfiguration {
    try {
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false -ErrorAction Stop | Out-Null
    } catch {
        Write-Status WARN "Could not set certificate handling for this session: $($_.Exception.Message)"
        Write-Status WARN 'Connections to hosts with self-signed certificates may fail.'
    }

    try {
        $ceip = (Get-PowerCLIConfiguration -Scope User).ParticipateInCEIP
        if ($null -eq $ceip) {
            Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope User -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Status INFO 'CEIP participation defaulted to off to suppress the first-run prompt (change with Set-PowerCLIConfiguration).'
        }
    } catch {
        # Non-fatal: worst case the operator sees the CEIP prompt once.
        Write-Verbose "Could not read or set CEIP preference: $($_.Exception.Message)"
    }
}

# =============================================================================
# Target resolution
# =============================================================================

function Resolve-TargetList {
    param([string[]] $FromParameter, [string] $FromFile)

    $targets = New-Object System.Collections.Generic.List[string]

    foreach ($t in $FromParameter) {
        if (-not [string]::IsNullOrWhiteSpace($t)) { $targets.Add($t.Trim()) }
    }

    if ($FromFile) {
        # Blank lines and # comments let an operator keep a per-client host file with
        # decommissioned hosts commented out rather than deleted.
        Get-Content -LiteralPath $FromFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#')) { $targets.Add($line) }
        }
    }

    # Case-insensitive de-duplication: the same host named in both -Server and the file
    # would otherwise be connected twice and double-counted in every rollup.
    return $targets | Sort-Object -Unique
}

# =============================================================================
# Collection - hosts
# =============================================================================

function Get-HostInventory {
    param([Parameter(Mandatory)] $Connection)

    $rows = New-Object System.Collections.Generic.List[object]

    $vmHosts = @(Get-VMHost -Server $Connection -ErrorAction Stop)
    Write-Status INFO "  Hosts: $($vmHosts.Count)"

    foreach ($h in $vmHosts) {
        # Per-host isolation: one host in a bad state (disconnected mid-run, hardware
        # service not responding) must never drop the remaining hosts from the report.
        try {
            $note = ''

            # BIOS version and serial number. Get-VMHostHardware exposes both as
            # first-class properties; it queries the host's hardware service, which is
            # unavailable on a disconnected or not-responding host, hence the fallback
            # to the raw ExtensionData paths.
            # https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-vmhosthardware
            $biosVersion = $null
            $serial      = $null
            try {
                $hw = Get-VMHostHardware -VMHost $h -ErrorAction Stop
                $biosVersion = $hw.BiosVersion
                $serial      = $hw.SerialNumber
            } catch {
                $biosVersion = $h.ExtensionData.Hardware.BiosInfo.BiosVersion
                # Hardware.SystemInfo.SerialNumber exists only since vSphere API 6.7;
                # on older hosts it is absent and OtherIdentifyingInfo is the fallback.
                # https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.SystemInfo.html
                $serial = $h.ExtensionData.Hardware.SystemInfo.SerialNumber
                if (-not $serial) {
                    $serial = ($h.ExtensionData.Hardware.SystemInfo.OtherIdentifyingInfo |
                        Where-Object { $_.IdentifierType.Key -eq 'SerialNumberTag' } |
                        Select-Object -First 1).IdentifierValue
                }
                $note = 'Hardware service unavailable; BIOS/serial read from ExtensionData.'
            }

            # There is no Uptime property and no Get-VMHostStartTime cmdlet. QuickStats
            # carries uptime in SECONDS; Runtime.BootTime is the boot timestamp.
            # https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.Summary.QuickStats.html
            # https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.host.RuntimeInfo.html
            $uptimeSeconds = $h.ExtensionData.Summary.QuickStats.Uptime
            $uptimeDays    = if ($uptimeSeconds) { [math]::Round($uptimeSeconds / 86400, 1) } else { $null }
            $bootTime      = $h.ExtensionData.Runtime.BootTime

            # Cluster membership is a vCenter-only construct. Guarded twice - by the
            # ProductLine branch at the call site and by try/catch here - because
            # Broadcom does not document whether Get-Cluster against standalone ESXi
            # errors or returns empty.
            $clusterName = $null
            if (-not $h.IsStandalone) {
                try {
                    $clusterName = (Get-Cluster -VMHost $h -Server $Connection -ErrorAction Stop | Select-Object -First 1).Name
                } catch {
                    $clusterName = $null
                }
            }

            $rows.Add([PSCustomObject]@{
                Target            = $Connection.Name
                HostName          = $h.Name
                ConnectionState   = [string]$h.ConnectionState
                PowerState        = [string]$h.PowerState
                InMaintenanceMode = ($h.ConnectionState -eq 'Maintenance')
                IsStandalone      = $h.IsStandalone
                Cluster           = $clusterName
                Manufacturer      = $h.Manufacturer
                Model             = $h.Model
                SerialNumber      = $serial
                BiosVersion       = $biosVersion
                ESXiVersion       = $h.Version
                ESXiBuild         = $h.Build
                ProcessorType     = $h.ProcessorType
                CpuSockets        = $h.ExtensionData.Summary.Hardware.NumCpuPkgs
                CpuCoresTotal     = $h.ExtensionData.Summary.Hardware.NumCpuCores
                CpuThreadsTotal   = $h.ExtensionData.Summary.Hardware.NumCpuThreads
                HyperthreadingOn  = $h.HyperthreadingActive
                NumCpu            = $h.NumCpu
                CpuTotalMhz       = $h.CpuTotalMhz
                CpuUsageMhz       = $h.CpuUsageMhz
                CpuUsagePercent   = if ($h.CpuTotalMhz) { [math]::Round(($h.CpuUsageMhz / $h.CpuTotalMhz) * 100, 1) } else { $null }
                MemoryTotalGB     = if ($null -ne $h.MemoryTotalGB) { [math]::Round($h.MemoryTotalGB, 1) } else { $null }
                MemoryUsageGB     = if ($null -ne $h.MemoryUsageGB) { [math]::Round($h.MemoryUsageGB, 1) } else { $null }
                MemoryUsagePct    = if ($h.MemoryTotalGB) { [math]::Round(($h.MemoryUsageGB / $h.MemoryTotalGB) * 100, 1) } else { $null }
                UptimeDays        = $uptimeDays
                BootTime          = $bootTime
                CollectionNote    = $note
            })
        } catch {
            # Emit the host anyway so it is never silently missing from a count.
            $rows.Add([PSCustomObject]@{
                Target            = $Connection.Name
                HostName          = $h.Name
                ConnectionState   = [string]$h.ConnectionState
                PowerState        = [string]$h.PowerState
                InMaintenanceMode = $null; IsStandalone = $null; Cluster = $null
                Manufacturer = $null; Model = $null; SerialNumber = $null; BiosVersion = $null
                ESXiVersion = $h.Version; ESXiBuild = $h.Build; ProcessorType = $null
                CpuSockets = $null; CpuCoresTotal = $null; CpuThreadsTotal = $null
                HyperthreadingOn = $null; NumCpu = $null; CpuTotalMhz = $null
                CpuUsageMhz = $null; CpuUsagePercent = $null
                MemoryTotalGB = $null; MemoryUsageGB = $null; MemoryUsagePct = $null
                UptimeDays = $null; BootTime = $null
                CollectionNote    = "PARTIAL: $($_.Exception.Message)"
            })
            Write-Status WARN "  Host '$($h.Name)' collected partially: $($_.Exception.Message)"
        }
    }

    return $rows
}

# =============================================================================
# Collection - virtual machines
# =============================================================================

function Get-VMInventory {
    param([Parameter(Mandatory)] $Connection)

    $rows = New-Object System.Collections.Generic.List[object]

    $vms = @(Get-VM -Server $Connection -ErrorAction Stop)
    Write-Status INFO "  VMs: $($vms.Count)"

    foreach ($vm in $vms) {
        # Per-VM isolation, same reasoning as hosts: a single VM with an inaccessible
        # config file or an unresponsive guest agent must not abort the whole run.
        try {
            $guest = $vm.Guest
            $ext   = $vm.ExtensionData

            # Guest IPs. VMGuest.IPAddress is a String[] and position 0 is documented as
            # the primary address. Both the primary and the full list are reported,
            # because secondary addresses on a multi-homed VM matter for a migration plan.
            # https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-vm
            $ipAddresses = @($guest.IPAddress | Where-Object { $_ })
            $primaryIP   = if ($ipAddresses.Count -gt 0) { $ipAddresses[0] } else { $null }

            # VMware Tools. GuestInfo.toolsStatus is DEPRECATED as of vSphere API 4.0 in
            # favour of toolsRunningStatus and toolsVersionStatus2, so the deprecated
            # field is not read here at all.
            # https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.vm.GuestInfo.html
            $toolsRunning       = $ext.Guest.ToolsRunningStatus
            $toolsVersionStatus = $ext.Guest.ToolsVersionStatus2

            # Datastores backing this VM, de-duplicated: a VM with several disks on one
            # datastore should list that datastore once.
            $datastoreNames = @()
            try {
                $datastoreNames = @($vm.DatastoreIdList | ForEach-Object {
                    (Get-View -Id $_ -Property Name -Server $Connection -ErrorAction Stop).Name
                } | Sort-Object -Unique)
            } catch {
                $datastoreNames = @()
            }

            # Hardware version: HardwareVersion is a String and reports newer versions
            # ("vmx-21") faithfully. The Version property is a VMVersion ENUM capped at
            # v18, so anything newer surfaces there as "Unknown" - a confidently wrong
            # value in a report. Both are emitted, with the string as the primary column.
            # https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/structures/vmware.vimautomation.vicore.types.v1.vm.vmversion
            $rows.Add([PSCustomObject]@{
                Target              = $Connection.Name
                VMName              = $vm.Name
                PowerState          = [string]$vm.PowerState
                VMHost              = $vm.VMHost.Name
                Cluster             = $null   # filled in by the caller from the host map
                Folder              = $vm.Folder.Name
                ResourcePool        = $vm.ResourcePool.Name
                vCPU                = $vm.NumCpu
                CoresPerSocket      = $vm.CoresPerSocket
                MemoryGB            = if ($null -ne $vm.MemoryGB) { [math]::Round($vm.MemoryGB, 2) } else { $null }
                ProvisionedSpaceGB  = if ($null -ne $vm.ProvisionedSpaceGB) { [math]::Round($vm.ProvisionedSpaceGB, 2) } else { $null }
                UsedSpaceGB         = if ($null -ne $vm.UsedSpaceGB) { [math]::Round($vm.UsedSpaceGB, 2) } else { $null }
                Datastores          = ($datastoreNames -join ' | ')
                GuestOSConfigured   = $vm.GuestId
                GuestOSRunning      = $guest.OSFullName
                GuestState          = [string]$guest.State
                GuestHostName       = $guest.HostName
                PrimaryIP           = $primaryIP
                AllIPs              = ($ipAddresses -join ' | ')
                ToolsVersion        = $guest.ToolsVersion
                ToolsRunningStatus  = [string]$toolsRunning
                ToolsVersionStatus  = [string]$toolsVersionStatus
                HardwareVersion     = $vm.HardwareVersion
                HardwareVersionEnum = [string]$vm.Version
                CreateDate          = $vm.CreateDate
                Notes               = $vm.Notes
                CollectionNote      = ''
            })
        } catch {
            $rows.Add([PSCustomObject]@{
                Target = $Connection.Name; VMName = $vm.Name
                PowerState = [string]$vm.PowerState; VMHost = $null; Cluster = $null
                Folder = $null; ResourcePool = $null; vCPU = $vm.NumCpu
                CoresPerSocket = $null; MemoryGB = $null
                ProvisionedSpaceGB = $null; UsedSpaceGB = $null; Datastores = $null
                GuestOSConfigured = $null; GuestOSRunning = $null; GuestState = $null
                GuestHostName = $null; PrimaryIP = $null; AllIPs = $null
                ToolsVersion = $null; ToolsRunningStatus = $null; ToolsVersionStatus = $null
                HardwareVersion = $null; HardwareVersionEnum = $null
                CreateDate = $null; Notes = $null
                CollectionNote = "PARTIAL: $($_.Exception.Message)"
            })
            Write-Status WARN "  VM '$($vm.Name)' collected partially: $($_.Exception.Message)"
        }
    }

    return $rows
}

# =============================================================================
# Collection - datastores
# =============================================================================

function Get-DatastoreInventory {
    param([Parameter(Mandatory)] $Connection)

    $rows = New-Object System.Collections.Generic.List[object]

    $datastores = @(Get-Datastore -Server $Connection -ErrorAction Stop)
    Write-Status INFO "  Datastores: $($datastores.Count)"

    foreach ($ds in $datastores) {
        try {
            $capacityGB = if ($null -ne $ds.CapacityGB)  { [math]::Round($ds.CapacityGB, 2) }  else { $null }
            $freeGB     = if ($null -ne $ds.FreeSpaceGB) { [math]::Round($ds.FreeSpaceGB, 2) } else { $null }
            $usedGB     = if ($null -ne $capacityGB -and $null -ne $freeGB) { [math]::Round($capacityGB - $freeGB, 2) } else { $null }

            # Summary.Uncommitted is the additional storage space POTENTIALLY used by all
            # VMs on this datastore - i.e. the unwritten remainder of thin-provisioned
            # disks, NOT the total provisioned figure. It is in BYTES while CapacityGB
            # and FreeSpaceGB are in GB, and it is valid ONLY when accessible is true.
            # Total provisioned therefore = used + uncommitted, and the datastore is
            # overcommitted when that exceeds capacity (equivalently: uncommitted > free).
            # Treating Uncommitted as "total provisioned" would overstate provisioning by
            # the amount already written - a plausible, confidently wrong number.
            # https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.Datastore.Summary.html
            $uncommittedGB = $null
            if ($ds.Accessible -and $null -ne $ds.ExtensionData.Summary.Uncommitted) {
                $uncommittedGB = [math]::Round($ds.ExtensionData.Summary.Uncommitted / 1GB, 2)
            }

            $provisionedGB = if ($null -ne $usedGB -and $null -ne $uncommittedGB) {
                [math]::Round($usedGB + $uncommittedGB, 2)
            } else { $null }

            $rows.Add([PSCustomObject]@{
                Target                = $Connection.Name
                DatastoreName         = $ds.Name
                Type                  = $ds.Type
                State                 = [string]$ds.State
                Accessible            = $ds.Accessible
                CapacityGB            = $capacityGB
                UsedGB                = $usedGB
                FreeGB                = $freeGB
                UsedPercent           = if ($capacityGB) { [math]::Round(($usedGB / $capacityGB) * 100, 1) } else { $null }
                UncommittedGB         = $uncommittedGB
                ProvisionedGB         = $provisionedGB
                ProvisionedVsCapacity = Get-SafeRatio -Numerator $provisionedGB -Denominator $capacityGB
                IsOvercommitted       = if ($null -ne $provisionedGB -and $null -ne $capacityGB) { $provisionedGB -gt $capacityGB } else { $null }
                SnapshotGB            = $null   # filled in by the caller once snapshots are known
                SnapshotPctOfUsed     = $null   # filled in by the caller
                CollectionNote        = if ($ds.Accessible) { '' } else { 'Datastore not accessible; uncommitted/provisioned figures unavailable.' }
            })
        } catch {
            $rows.Add([PSCustomObject]@{
                Target = $Connection.Name; DatastoreName = $ds.Name; Type = $ds.Type
                State = [string]$ds.State; Accessible = $ds.Accessible
                CapacityGB = $null; UsedGB = $null; FreeGB = $null; UsedPercent = $null
                UncommittedGB = $null; ProvisionedGB = $null; ProvisionedVsCapacity = $null
                IsOvercommitted = $null; SnapshotGB = $null; SnapshotPctOfUsed = $null
                CollectionNote = "PARTIAL: $($_.Exception.Message)"
            })
            Write-Status WARN "  Datastore '$($ds.Name)' collected partially: $($_.Exception.Message)"
        }
    }

    return $rows
}

# =============================================================================
# Collection - snapshots
# =============================================================================

function Get-SnapshotInventory {
    param(
        [Parameter(Mandatory)] $Connection,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $VMs
    )

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $VMs -or $VMs.Count -eq 0) { return $rows }

    # Get-Snapshot requires -VM, so it is scoped to the VMs already retrieved rather than
    # queried globally. Sizing reads from the datastore, which is what makes this the
    # slowest phase of a large run (hence -SkipSnapshots).
    $snapshots = @()
    try {
        $snapshots = @(Get-Snapshot -VM $VMs -Server $Connection -ErrorAction Stop)
    } catch {
        Write-Status WARN "  Snapshot enumeration failed: $($_.Exception.Message)"
        return $rows
    }

    Write-Status INFO "  Snapshots: $($snapshots.Count)"

    $now = Get-Date
    foreach ($snap in $snapshots) {
        try {
            # SizeGB is populated only when the account holds the vSphere
            # "Datastore > Browse datastore" privilege; without it PowerCLI emits a
            # warning and the size is absent. Reporting that absence explicitly keeps a
            # least-privilege service account from silently producing a zeroed-out
            # snapshot report that reads as "no snapshot consumption".
            # https://developer.broadcom.com/powercli/latest/vmware.vimautomation.core/commands/get-snapshot
            $sizeGB       = if ($null -ne $snap.SizeGB)       { [math]::Round($snap.SizeGB, 2) }       else { $null }
            $sizeOnDiskGB = if ($null -ne $snap.SizeOnDiskGB) { [math]::Round($snap.SizeOnDiskGB, 2) } else { $null }

            $ageDays = if ($snap.Created) { [math]::Round(($now - $snap.Created).TotalDays, 1) } else { $null }

            $rows.Add([PSCustomObject]@{
                Target             = $Connection.Name
                VMName             = $snap.VM.Name
                SnapshotName       = $snap.Name
                Description        = $snap.Description
                Created            = $snap.Created
                AgeDays            = $ageDays
                SizeGB             = $sizeGB
                SizeOnDiskGB       = $sizeOnDiskGB
                IsCurrent          = $snap.IsCurrent
                Quiesced           = $snap.Quiesced
                PowerStateAtCreate = [string]$snap.PowerState
                ParentSnapshot     = $snap.ParentSnapshot.Name
                ChildCount         = @($snap.Children).Count
                CollectionNote     = if ($null -eq $sizeGB) { 'Size unavailable - requires the Datastore > Browse datastore privilege.' } else { '' }
            })
        } catch {
            $rows.Add([PSCustomObject]@{
                Target = $Connection.Name; VMName = $snap.VM.Name; SnapshotName = $snap.Name
                Description = $null; Created = $snap.Created; AgeDays = $null
                SizeGB = $null; SizeOnDiskGB = $null; IsCurrent = $null; Quiesced = $null
                PowerStateAtCreate = $null; ParentSnapshot = $null; ChildCount = $null
                CollectionNote = "PARTIAL: $($_.Exception.Message)"
            })
        }
    }

    return $rows
}

# =============================================================================
# Collection - clusters (vCenter only)
# =============================================================================

function Get-ClusterInventory {
    param([Parameter(Mandatory)] $Connection)

    $rows = New-Object System.Collections.Generic.List[object]

    # Clusters are a vCenter construct and cannot exist on a standalone ESXi host.
    # Broadcom documents neither an error nor an empty result for Get-Cluster against
    # standalone ESXi, so this is guarded both by the ProductLine check at the call site
    # and by try/catch here - correct under either undocumented behaviour.
    $clusters = @()
    try {
        $clusters = @(Get-Cluster -Server $Connection -ErrorAction Stop)
    } catch {
        Write-Verbose "Get-Cluster unavailable on $($Connection.Name): $($_.Exception.Message)"
        return $rows
    }

    if ($clusters.Count -eq 0) { return $rows }
    Write-Status INFO "  Clusters: $($clusters.Count)"

    foreach ($cl in $clusters) {
        try {
            $clusterHosts = @(Get-VMHost -Location $cl -Server $Connection -ErrorAction SilentlyContinue)

            $rows.Add([PSCustomObject]@{
                Target            = $Connection.Name
                ClusterName       = $cl.Name
                HAEnabled         = $cl.HAEnabled
                HAAdmissionCtrl   = $cl.HAAdmissionControlEnabled
                HAFailoverLevel   = $cl.HAFailoverLevel
                HARestartPriority = [string]$cl.HARestartPriority
                DrsEnabled        = $cl.DrsEnabled
                DrsAutomation     = [string]$cl.DrsAutomationLevel
                EVCMode           = $cl.EVCMode
                HostCount         = $clusterHosts.Count
                CpuCoresTotal     = ($clusterHosts | Measure-Object -Property NumCpu -Sum).Sum
                CpuTotalMhz       = ($clusterHosts | Measure-Object -Property CpuTotalMhz -Sum).Sum
                MemoryTotalGB     = [math]::Round((($clusterHosts | Measure-Object -Property MemoryTotalGB -Sum).Sum), 1)
                CollectionNote    = ''
            })
        } catch {
            $rows.Add([PSCustomObject]@{
                Target = $Connection.Name; ClusterName = $cl.Name
                HAEnabled = $null; HAAdmissionCtrl = $null; HAFailoverLevel = $null
                HARestartPriority = $null; DrsEnabled = $null; DrsAutomation = $null
                EVCMode = $null; HostCount = $null; CpuCoresTotal = $null
                CpuTotalMhz = $null; MemoryTotalGB = $null
                CollectionNote = "PARTIAL: $($_.Exception.Message)"
            })
        }
    }

    return $rows
}

# =============================================================================
# Rollups
# =============================================================================
#
# Every rollup below publishes its inputs alongside its result so the arithmetic can be
# audited from the CSV. No thresholds are applied and no verdict is rendered - what
# counts as an acceptable consolidation ratio or overcommit level is a judgement for the
# reader, and it varies by workload, licensing, and the client's risk appetite.

function Get-HostRollup {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $HostRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $VMRows
    )

    $rollup = New-Object System.Collections.Generic.List[object]

    foreach ($h in $HostRows) {
        $hostVMs   = @($VMRows | Where-Object { $_.VMHost -eq $h.HostName })
        $poweredOn = @($hostVMs | Where-Object { $_.PowerState -eq 'PoweredOn' })

        # Allocation is counted over POWERED-ON VMs only. A powered-off VM reserves no
        # CPU or memory on its host, so including it would overstate live contention;
        # the all-VM totals are published beside it for the capacity-planning view.
        $vCPUOn     = ($poweredOn | Measure-Object -Property vCPU -Sum).Sum
        $vCPUAll    = ($hostVMs   | Measure-Object -Property vCPU -Sum).Sum
        $memOnGB    = ($poweredOn | Measure-Object -Property MemoryGB -Sum).Sum
        $memAllGB   = ($hostVMs   | Measure-Object -Property MemoryGB -Sum).Sum

        $rollup.Add([PSCustomObject]@{
            Target                  = $h.Target
            HostName                = $h.HostName
            Cluster                 = $h.Cluster
            ConnectionState         = $h.ConnectionState
            VMsTotal                = $hostVMs.Count
            VMsPoweredOn            = $poweredOn.Count
            VMsPoweredOff           = ($hostVMs.Count - $poweredOn.Count)
            PhysicalCores           = $h.CpuCoresTotal
            PhysicalThreads         = $h.CpuThreadsTotal
            vCPUAllocatedPoweredOn  = $vCPUOn
            vCPUAllocatedAll        = $vCPUAll
            vCPUPerCorePoweredOn    = Get-SafeRatio -Numerator $vCPUOn  -Denominator $h.CpuCoresTotal
            vCPUPerCoreAll          = Get-SafeRatio -Numerator $vCPUAll -Denominator $h.CpuCoresTotal
            PhysicalMemoryGB        = $h.MemoryTotalGB
            MemoryAllocatedOnGB     = if ($null -ne $memOnGB)  { [math]::Round($memOnGB, 2) }  else { 0 }
            MemoryAllocatedAllGB    = if ($null -ne $memAllGB) { [math]::Round($memAllGB, 2) } else { 0 }
            MemoryOvercommitOn      = Get-SafeRatio -Numerator $memOnGB  -Denominator $h.MemoryTotalGB
            MemoryOvercommitAll     = Get-SafeRatio -Numerator $memAllGB -Denominator $h.MemoryTotalGB
            HostCpuUsagePercent     = $h.CpuUsagePercent
            HostMemoryUsagePercent  = $h.MemoryUsagePct
        })
    }

    return $rollup
}

function Add-SnapshotDataToDatastores {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $DatastoreRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $SnapshotRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $VMRows
    )

    if (-not $SnapshotRows -or $SnapshotRows.Count -eq 0) { return }

    # Map VM -> datastores so snapshot bytes can be attributed to a datastore. A VM
    # spanning several datastores cannot be split accurately without walking each disk,
    # so its snapshot size is attributed to every datastore it touches and the note
    # records that. Over-attribution is visible and explicable; silently dropping those
    # snapshots would leave a full datastore with no explanation, which is worse.
    $vmToDatastores = @{}
    foreach ($vm in $VMRows) {
        if ($vm.Datastores) {
            $vmToDatastores[$vm.VMName] = @($vm.Datastores -split ' \| ' | Where-Object { $_ })
        }
    }

    $spanningVMs = New-Object System.Collections.Generic.HashSet[string]
    $dsSnapshotGB = @{}

    foreach ($snap in $SnapshotRows) {
        if ($null -eq $snap.SizeGB) { continue }
        $names = $vmToDatastores[$snap.VMName]
        if (-not $names -or $names.Count -eq 0) { continue }
        if ($names.Count -gt 1) { [void]$spanningVMs.Add($snap.VMName) }

        foreach ($n in $names) {
            if (-not $dsSnapshotGB.ContainsKey($n)) { $dsSnapshotGB[$n] = 0 }
            $dsSnapshotGB[$n] += $snap.SizeGB
        }
    }

    foreach ($ds in $DatastoreRows) {
        if ($dsSnapshotGB.ContainsKey($ds.DatastoreName)) {
            $snapGB = [math]::Round($dsSnapshotGB[$ds.DatastoreName], 2)
            $ds.SnapshotGB = $snapGB
            if ($ds.UsedGB -and $ds.UsedGB -gt 0) {
                $ds.SnapshotPctOfUsed = [math]::Round(($snapGB / $ds.UsedGB) * 100, 1)
            }
        } else {
            $ds.SnapshotGB = 0
            $ds.SnapshotPctOfUsed = 0
        }
    }

    if ($spanningVMs.Count -gt 0) {
        Write-Status WARN "  $($spanningVMs.Count) VM(s) span multiple datastores; their snapshot size is counted against each datastore they touch."
        foreach ($ds in $DatastoreRows) {
            if ($ds.SnapshotGB -gt 0) {
                $existing = if ($ds.CollectionNote) { "$($ds.CollectionNote) " } else { '' }
                $ds.CollectionNote = "${existing}SnapshotGB may include VMs spanning multiple datastores."
            }
        }
    }
}

function Get-EnvironmentSummary {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $HostRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $VMRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $DatastoreRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $SnapshotRows
    )

    $summary = New-Object System.Collections.Generic.List[object]

    $targets = @($HostRows | Select-Object -ExpandProperty Target -Unique)

    foreach ($t in $targets) {
        $h  = @($HostRows      | Where-Object { $_.Target -eq $t })
        $v  = @($VMRows        | Where-Object { $_.Target -eq $t })
        $d  = @($DatastoreRows | Where-Object { $_.Target -eq $t })
        $s  = @($SnapshotRows  | Where-Object { $_.Target -eq $t })

        $poweredOn = @($v | Where-Object { $_.PowerState -eq 'PoweredOn' })

        $physCores  = ($h | Measure-Object -Property CpuCoresTotal -Sum).Sum
        $physMemGB  = ($h | Measure-Object -Property MemoryTotalGB -Sum).Sum
        $vCPUOn     = ($poweredOn | Measure-Object -Property vCPU -Sum).Sum
        $memOnGB    = ($poweredOn | Measure-Object -Property MemoryGB -Sum).Sum

        $dsCapacity = ($d | Measure-Object -Property CapacityGB -Sum).Sum
        $dsUsed     = ($d | Measure-Object -Property UsedGB -Sum).Sum
        $dsProv     = ($d | Measure-Object -Property ProvisionedGB -Sum).Sum
        $snapGB     = ($s | Measure-Object -Property SizeGB -Sum).Sum

        $oldestSnap = $s | Where-Object { $_.Created } | Sort-Object Created | Select-Object -First 1

        $summary.Add([PSCustomObject]@{
            Target                   = $t
            Hosts                    = $h.Count
            HostsInMaintenance       = @($h | Where-Object { $_.InMaintenanceMode -eq $true }).Count
            HostsNotConnected        = @($h | Where-Object { $_.ConnectionState -and $_.ConnectionState -ne 'Connected' }).Count
            VMsTotal                 = $v.Count
            VMsPoweredOn             = $poweredOn.Count
            VMsPoweredOff            = @($v | Where-Object { $_.PowerState -eq 'PoweredOff' }).Count
            VMsSuspended             = @($v | Where-Object { $_.PowerState -eq 'Suspended' }).Count
            PhysicalCoresTotal       = $physCores
            vCPUAllocatedPoweredOn   = $vCPUOn
            vCPUPerCore              = Get-SafeRatio -Numerator $vCPUOn -Denominator $physCores
            PhysicalMemoryGB         = if ($null -ne $physMemGB) { [math]::Round($physMemGB, 1) } else { $null }
            MemoryAllocatedOnGB      = if ($null -ne $memOnGB)   { [math]::Round($memOnGB, 1) }   else { 0 }
            MemoryOvercommitRatio    = Get-SafeRatio -Numerator $memOnGB -Denominator $physMemGB
            Datastores               = $d.Count
            DatastoreCapacityGB      = if ($null -ne $dsCapacity) { [math]::Round($dsCapacity, 1) } else { $null }
            DatastoreUsedGB          = if ($null -ne $dsUsed)     { [math]::Round($dsUsed, 1) }     else { $null }
            DatastoreProvisionedGB   = if ($null -ne $dsProv)     { [math]::Round($dsProv, 1) }     else { $null }
            ProvisionedVsCapacity    = Get-SafeRatio -Numerator $dsProv -Denominator $dsCapacity
            DatastoresOvercommitted  = @($d | Where-Object { $_.IsOvercommitted -eq $true }).Count
            SnapshotsTotal           = $s.Count
            SnapshotSizeGB           = if ($null -ne $snapGB) { [math]::Round($snapGB, 2) } else { $null }
            OldestSnapshotDays       = if ($oldestSnap) { $oldestSnap.AgeDays } else { $null }
            OldestSnapshotVM         = if ($oldestSnap) { $oldestSnap.VMName } else { $null }
        })
    }

    return $summary
}

# =============================================================================
# Main
# =============================================================================

Write-Section 'VMware Infrastructure Inventory'
Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ''

if (-not (Initialize-PowerCLI -AutoInstall:$InstallPowerCLI)) {
    exit 1
}
Set-InventorySessionConfiguration

$targets = @(Resolve-TargetList -FromParameter $Server -FromFile $HostListFile)
if ($targets.Count -eq 0) {
    Write-Status FAIL 'No targets specified. Use -Server and/or -HostListFile.'
    Write-Host ''
    Write-Host '  Example:  .\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01.contoso.local' -ForegroundColor Cyan
    Write-Host ''
    exit 1
}

Write-Status INFO "Targets: $($targets -join ', ')"

$allHosts      = New-Object System.Collections.Generic.List[object]
$allVMs        = New-Object System.Collections.Generic.List[object]
$allDatastores = New-Object System.Collections.Generic.List[object]
$allSnapshots  = New-Object System.Collections.Generic.List[object]
$allClusters   = New-Object System.Collections.Generic.List[object]
$connectionLog = New-Object System.Collections.Generic.List[object]

foreach ($target in $targets) {
    Write-Host ''
    Write-Status INFO "Connecting to $target ..."

    $connection = $null
    try {
        $connectArgs = @{
            Server      = $target
            ErrorAction = 'Stop'
            # -NotDefault keeps $global:DefaultVIServer clean so an operator's existing
            # interactive session is not hijacked, and every cmdlet below passes -Server
            # explicitly rather than relying on an implicit default connection.
            NotDefault  = $true
        }
        # Omitting -Credential entirely (rather than passing $null) is what lets PowerCLI
        # fall back to its own credential store and then to an interactive prompt.
        if ($Credential) { $connectArgs['Credential'] = $Credential }

        $connection = Connect-VIServer @connectArgs
    } catch {
        # Per-target isolation: one unreachable host must not end the run.
        Write-Status FAIL "  Could not connect to ${target}: $($_.Exception.Message)"
        $connectionLog.Add([PSCustomObject]@{
            Target = $target; Connected = $false; ProductLine = $null
            Version = $null; Build = $null; Error = $_.Exception.Message
        })
        continue
    }

    # ProductLine distinguishes a vCenter connection from a direct ESXi connection:
    # 'vpx' = vCenter Server, 'embeddedEsx' = standalone ESXi host.
    $productLine = $connection.ProductLine
    $isVCenter   = ($productLine -eq 'vpx')
    $kind        = if ($isVCenter) { 'vCenter Server' } else { "ESXi host ($productLine)" }

    Write-Status PASS "  Connected to $target - $kind $($connection.Version) build $($connection.Build)"
    $connectionLog.Add([PSCustomObject]@{
        Target = $target; Connected = $true; ProductLine = $productLine
        Version = $connection.Version; Build = $connection.Build; Error = $null
    })

    try {
        $hostRows = Get-HostInventory -Connection $connection
        $vmRows   = Get-VMInventory   -Connection $connection
        $dsRows   = Get-DatastoreInventory -Connection $connection

        # Cluster collection is attempted only against vCenter. Clusters cannot exist on
        # a standalone host, and Broadcom documents neither an error nor an empty result
        # for Get-Cluster in that case.
        $clusterRows = @()
        if ($isVCenter) {
            $clusterRows = Get-ClusterInventory -Connection $connection
        }

        # Stamp each VM with its host's cluster so VirtualMachines.csv can be filtered by
        # cluster without a manual join back to Hosts.csv.
        $hostToCluster = @{}
        foreach ($h in $hostRows) { $hostToCluster[$h.HostName] = $h.Cluster }
        foreach ($v in $vmRows) {
            if ($v.VMHost -and $hostToCluster.ContainsKey($v.VMHost)) {
                $v.Cluster = $hostToCluster[$v.VMHost]
            }
        }

        $snapRows = @()
        if ($SkipSnapshots) {
            Write-Status INFO '  Snapshots: skipped (-SkipSnapshots)'
        } else {
            # Re-query the live VM objects: Get-Snapshot needs actual VirtualMachine
            # objects, not the flattened PSCustomObject rows built above.
            $liveVMs = @(Get-VM -Server $connection -ErrorAction SilentlyContinue)
            $snapRows = Get-SnapshotInventory -Connection $connection -VMs $liveVMs
            Add-SnapshotDataToDatastores -DatastoreRows $dsRows -SnapshotRows $snapRows -VMRows $vmRows
        }

        foreach ($r in $hostRows)    { $allHosts.Add($r) }
        foreach ($r in $vmRows)      { $allVMs.Add($r) }
        foreach ($r in $dsRows)      { $allDatastores.Add($r) }
        foreach ($r in $snapRows)    { $allSnapshots.Add($r) }
        foreach ($r in $clusterRows) { $allClusters.Add($r) }

    } catch {
        Write-Status FAIL "  Collection failed for ${target}: $($_.Exception.Message)"
    } finally {
        try {
            Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Disconnect from $target reported: $($_.Exception.Message)"
        }
    }
}

if ($allHosts.Count -eq 0) {
    Write-Host ''
    Write-Status FAIL 'No data collected from any target.'
    exit 1
}

# --- Rollups -----------------------------------------------------------------

Write-Host ''
Write-Status INFO 'Computing capacity rollups...'

$hostRollup = Get-HostRollup -HostRows $allHosts -VMRows $allVMs
$summary    = Get-EnvironmentSummary -HostRows $allHosts -VMRows $allVMs `
                                     -DatastoreRows $allDatastores -SnapshotRows $allSnapshots

# --- Export ------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$resolvedOutput = (Resolve-Path -LiteralPath $OutputPath).Path

function Export-InventoryCsv {
    param(
        [AllowEmptyCollection()][object[]] $Data,
        [Parameter(Mandatory)][string] $FileName
    )
    if (-not $Data -or $Data.Count -eq 0) { return }
    $path = Join-Path $resolvedOutput $FileName
    $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
}

Export-InventoryCsv -Data $allHosts      -FileName 'Hosts.csv'
Export-InventoryCsv -Data $allVMs        -FileName 'VirtualMachines.csv'
Export-InventoryCsv -Data $allDatastores -FileName 'Datastores.csv'
Export-InventoryCsv -Data $allSnapshots  -FileName 'Snapshots.csv'
Export-InventoryCsv -Data $allClusters   -FileName 'Clusters.csv'
Export-InventoryCsv -Data $hostRollup    -FileName 'HostCapacityRollup.csv'
Export-InventoryCsv -Data $summary       -FileName 'Summary.csv'
Export-InventoryCsv -Data $connectionLog -FileName 'ConnectionLog.csv'

$full = [PSCustomObject]@{
    CollectedAt       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    CollectedBy       = "$env:USERDOMAIN\$env:USERNAME"
    CollectedFrom     = $env:COMPUTERNAME
    Targets           = $targets
    SnapshotsSkipped  = [bool]$SkipSnapshots
    Connections       = $connectionLog
    Hosts             = $allHosts
    VirtualMachines   = $allVMs
    Datastores        = $allDatastores
    Snapshots         = $allSnapshots
    Clusters          = $allClusters
    HostCapacityRollup= $hostRollup
    Summary           = $summary
}
$full | ConvertTo-Json -Depth 6 | Out-File (Join-Path $resolvedOutput 'FullInventory.json') -Encoding UTF8

# --- Console summary ---------------------------------------------------------

Write-Section 'Summary'

foreach ($s in $summary) {
    Write-Host ''
    Write-Host "  $($s.Target)" -ForegroundColor White
    Write-Host ("  {0}" -f ('-' * 74)) -ForegroundColor DarkGray
    Write-Host ("    Hosts:       {0} ({1} in maintenance, {2} not connected)" -f $s.Hosts, $s.HostsInMaintenance, $s.HostsNotConnected)
    Write-Host ("    VMs:         {0} total - {1} on, {2} off, {3} suspended" -f $s.VMsTotal, $s.VMsPoweredOn, $s.VMsPoweredOff, $s.VMsSuspended)
    Write-Host ("    CPU:         {0} vCPU allocated over {1} physical cores (ratio {2})" -f $s.vCPUAllocatedPoweredOn, $s.PhysicalCoresTotal, $s.vCPUPerCore)
    Write-Host ("    Memory:      {0} GB allocated over {1} GB physical (ratio {2})" -f $s.MemoryAllocatedOnGB, $s.PhysicalMemoryGB, $s.MemoryOvercommitRatio)
    Write-Host ("    Storage:     {0} GB used / {1} GB capacity; {2} GB provisioned (ratio {3})" -f $s.DatastoreUsedGB, $s.DatastoreCapacityGB, $s.DatastoreProvisionedGB, $s.ProvisionedVsCapacity)
    if ($s.DatastoresOvercommitted -gt 0) {
        Write-Host ("    {0} of {1} datastores are thin-overcommitted" -f $s.DatastoresOvercommitted, $s.Datastores) -ForegroundColor Yellow
    }
    if (-not $SkipSnapshots) {
        Write-Host ("    Snapshots:   {0} totalling {1} GB" -f $s.SnapshotsTotal, $s.SnapshotSizeGB)
        if ($s.OldestSnapshotDays) {
            Write-Host ("                 oldest {0} days ({1})" -f $s.OldestSnapshotDays, $s.OldestSnapshotVM)
        }
    }
}

$failedConnections = @($connectionLog | Where-Object { -not $_.Connected })
if ($failedConnections.Count -gt 0) {
    Write-Host ''
    Write-Status WARN "$($failedConnections.Count) target(s) could not be reached - see ConnectionLog.csv:"
    foreach ($f in $failedConnections) {
        Write-Host "    $($f.Target): $($f.Error)" -ForegroundColor DarkGray
    }
}

$partialRows = @(
    @($allHosts      | Where-Object { $_.CollectionNote -like 'PARTIAL:*' }).Count
    @($allVMs        | Where-Object { $_.CollectionNote -like 'PARTIAL:*' }).Count
    @($allDatastores | Where-Object { $_.CollectionNote -like 'PARTIAL:*' }).Count
) | Measure-Object -Sum

if ($partialRows.Sum -gt 0) {
    Write-Host ''
    Write-Status WARN "$($partialRows.Sum) record(s) were collected only partially - see the CollectionNote column."
}

$sizelessSnapshots = @($allSnapshots | Where-Object { $null -eq $_.SizeGB }).Count
if ($sizelessSnapshots -gt 0) {
    Write-Host ''
    Write-Status WARN "$sizelessSnapshots snapshot(s) have no size. This account likely lacks the"
    Write-Status WARN '  "Datastore > Browse datastore" privilege; snapshot totals are understated.'
}

Write-Host ''
Write-Status PASS "Inventory written to: $resolvedOutput"
Write-Host ("  Hosts: {0} | VMs: {1} | Datastores: {2} | Snapshots: {3}" -f `
    $allHosts.Count, $allVMs.Count, $allDatastores.Count, $allSnapshots.Count) -ForegroundColor DarkGray
Write-Host ''
