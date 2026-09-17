<#
.SYNOPSIS
    Collects a full Hyper-V host + guest VM inventory for server infrastructure analysis.

.DESCRIPTION
    MSP-portable inventory script. Targets one or more Hyper-V hosts (or a cluster)
    and exports: host hardware/OS, Windows roles & features, Windows Update status,
    physical disks/volumes/CSVs, virtual switches, and per-VM config (vCPU, memory,
    VHD location/size, network adapters, integration services, replication state).

    Output is written as timestamped CSV (one per category) plus a single JSON blob,
    so it can be re-run on any client and the results diffed or rolled into a report.

    Does NOT inventory the SAN or the Synology/QNAP NAS - those are out-of-band devices
    with no Windows agent. See the footer notes for how to capture those separately.

.PARAMETER ComputerName
    One or more Hyper-V hosts. Defaults to the local machine. Accepts NetBIOS, FQDN, or IP.

.PARAMETER Cluster
    Name of a failover cluster. If set, all cluster nodes are enumerated automatically
    and ComputerName is ignored.

.PARAMETER Credential
    Credential for remote hosts. Omit when running locally or with current context.

.PARAMETER OutputPath
    Folder for exports. Defaults to .\Inventory_<timestamp>.

.EXAMPLE
    .\Get-HyperVInfrastructureInventory.ps1 -ComputerName HV01,HV02 -Credential (Get-Credential)

.EXAMPLE
    .\Get-HyperVInfrastructureInventory.ps1 -Cluster WILLIAMS-CL01

.NOTES
    Reference: Hyper-V PowerShell module - https://learn.microsoft.com/en-us/powershell/module/hyper-v/
    Requires: Hyper-V PowerShell module + WinRM/PS Remoting to targets. Run as admin.
    Tested intent: Windows Server 2016/2019/2022/2025 hosts. Read-only - makes no changes.
#>

[CmdletBinding(DefaultParameterSetName = 'Hosts')]
param(
    [Parameter(ParameterSetName = 'Hosts')]
    [string[]] $ComputerName = $env:COMPUTERNAME,

    [Parameter(ParameterSetName = 'Cluster')]
    [string] $Cluster,

    [System.Management.Automation.PSCredential] $Credential,

    [string] $OutputPath = ".\Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = 'Stop'

# --- Resolve target list -----------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Cluster') {
    Write-Verbose "Enumerating nodes of cluster '$Cluster'"
    $cimArgs = @{ ComputerName = $Cluster }
    if ($Credential) { $cimArgs['Credential'] = $Credential }
    $targets = (Get-ClusterNode -Cluster $Cluster).Name
} else {
    $targets = $ComputerName
}

if (-not $targets) { throw "No target hosts resolved." }
Write-Host "Targets: $($targets -join ', ')" -ForegroundColor Cyan

# --- Build remoting splat per host -------------------------------------------
function Get-InvokeArgs {
    param([string]$Computer)
    $splat = @{ ScriptBlock = $null }
    if ($Computer -ne $env:COMPUTERNAME -and $Computer -ne 'localhost') {
        $splat['ComputerName'] = $Computer
        if ($Credential) { $splat['Credential'] = $Credential }
    }
    return $splat
}

# --- Collection script block (runs on each host) -----------------------------
$collect = {
    # Remote sessions don't inherit the caller's preference. Keep non-terminating
    # errors non-fatal so one failed lookup can't drop a whole node's inventory.
    $ErrorActionPreference = 'Continue'

    $host_os   = Get-CimInstance Win32_OperatingSystem
    $host_cs   = Get-CimInstance Win32_ComputerSystem
    $host_proc = Get-CimInstance Win32_Processor

    $hostInfo = [pscustomobject]@{
        HostName        = $env:COMPUTERNAME
        Manufacturer    = $host_cs.Manufacturer
        Model           = $host_cs.Model
        OSName          = $host_os.Caption
        OSVersion       = $host_os.Version
        OSBuild         = $host_os.BuildNumber
        LastBootTime    = $host_os.LastBootUpTime
        CPU_Sockets     = ($host_proc | Measure-Object).Count
        CPU_Model       = ($host_proc | Select-Object -First 1).Name
        CPU_Cores       = ($host_proc | Measure-Object -Property NumberOfCores -Sum).Sum
        CPU_LogicalProc = ($host_proc | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        RAM_GB          = [math]::Round($host_cs.TotalPhysicalMemory / 1GB, 1)
        RAM_FreeGB      = [math]::Round($host_os.FreePhysicalMemory / 1MB, 1)
    }

    # Windows roles & features (installed only)
    $features = @()
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $features = Get-WindowsFeature | Where-Object Installed |
            Select-Object @{n='HostName';e={$env:COMPUTERNAME}}, Name, DisplayName, FeatureType
    }

    # Windows Update status (last installed + pending count via Update session)
    $patchInfo = $null
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $pending  = $searcher.Search("IsInstalled=0 and IsHidden=0").Updates.Count
        $lastHotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $patchInfo = [pscustomobject]@{
            HostName        = $env:COMPUTERNAME
            PendingUpdates  = $pending
            LastHotfixID    = $lastHotfix.HotFixID
            LastHotfixDate  = $lastHotfix.InstalledOn
        }
    } catch {
        $patchInfo = [pscustomobject]@{
            HostName = $env:COMPUTERNAME; PendingUpdates = 'ERROR'
            LastHotfixID = $null; LastHotfixDate = $null
        }
    }

    # Physical disks & volumes (local storage on the host)
    $volumes = Get-Volume | Where-Object DriveLetter |
        Select-Object @{n='HostName';e={$env:COMPUTERNAME}}, DriveLetter, FileSystemLabel,
            FileSystem, @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},
            @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}

    # Cluster Shared Volumes (if clustered)
    $csv = @()
    if (Get-Command Get-ClusterSharedVolume -ErrorAction SilentlyContinue) {
        try {
            $csv = Get-ClusterSharedVolume | ForEach-Object {
                $_.SharedVolumeInfo | Select-Object @{n='HostName';e={$env:COMPUTERNAME}},
                    FriendlyVolumeName,
                    @{n='SizeGB';e={[math]::Round($_.Partition.Size/1GB,1)}},
                    @{n='FreeGB';e={[math]::Round($_.Partition.FreeSpace/1GB,1)}}
            }
        } catch {}
    }

    # Hyper-V virtual switches
    $vswitch = @()
    $vms     = @()
    if (Get-Command Get-VMHost -ErrorAction SilentlyContinue) {
        $vswitch = Get-VMSwitch | Select-Object @{n='HostName';e={$env:COMPUTERNAME}},
            Name, SwitchType, NetAdapterInterfaceDescription

        $vms = Get-VM | ForEach-Object {
            $vm = $_
            # Per-VM isolation: a single bad VM (e.g. a VHD not openable from this
            # node) must never abort the rest of the node's collection.
            try {
                $mem  = Get-VMMemory   -VMName $vm.Name -ErrorAction SilentlyContinue
                $proc = Get-VMProcessor -VMName $vm.Name -ErrorAction SilentlyContinue
                $disks = Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = $_.Path
                    $size = $null
                    # Get-VHD can fail when the VHD's CSV is owned by another node.
                    # Try it, then fall back to the raw file size off the CSV path.
                    $vhd = Get-VHD -Path $p -ErrorAction SilentlyContinue
                    if ($vhd) {
                        $size = [math]::Round($vhd.FileSize/1GB,1)
                    } else {
                        $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                        if ($fi) { $size = [math]::Round($fi.Length/1GB,1) }
                    }
                    if ($null -eq $size) { "$p (size n/a)" } else { "$p ($size GB)" }
                }
                $nics = Get-VMNetworkAdapter -VMName $vm.Name -ErrorAction SilentlyContinue |
                    ForEach-Object { "$($_.SwitchName):$($_.MacAddress)" }

                [pscustomobject]@{
                    HostName          = $env:COMPUTERNAME
                    VMName            = $vm.Name
                    State             = $vm.State
                    Generation        = $vm.Generation
                    Version           = $vm.Version
                    vCPU              = $proc.Count
                    Mem_Dynamic       = $mem.DynamicMemoryEnabled
                    Mem_StartupGB     = [math]::Round($mem.Startup/1GB,2)
                    Mem_MinGB         = [math]::Round($mem.Minimum/1GB,2)
                    Mem_MaxGB         = [math]::Round($mem.Maximum/1GB,2)
                    Mem_AssignedGB    = [math]::Round($vm.MemoryAssigned/1GB,2)
                    IntegrationSvcVer = $vm.IntegrationServicesVersion
                    ReplicationState  = $vm.ReplicationState
                    Uptime            = $vm.Uptime
                    VHDs              = ($disks -join ' | ')
                    NICs              = ($nics  -join ' | ')
                    ConfigPath        = $vm.ConfigurationLocation
                    CollectionNote    = ''
                }
            } catch {
                # Still emit the VM so it's never silently dropped from the count.
                [pscustomobject]@{
                    HostName = $env:COMPUTERNAME; VMName = $vm.Name; State = $vm.State
                    Generation = $vm.Generation; Version = $vm.Version; vCPU = $null
                    Mem_Dynamic = $null; Mem_StartupGB = $null; Mem_MinGB = $null
                    Mem_MaxGB = $null; Mem_AssignedGB = [math]::Round($vm.MemoryAssigned/1GB,2)
                    IntegrationSvcVer = $vm.IntegrationServicesVersion
                    ReplicationState = $vm.ReplicationState; Uptime = $vm.Uptime
                    VHDs = ''; NICs = ''; ConfigPath = $vm.ConfigurationLocation
                    CollectionNote = "PARTIAL: $($_.Exception.Message)"
                }
            }
        }
    }

    [pscustomobject]@{
        Host     = $hostInfo
        Features = $features
        Patch    = $patchInfo
        Volumes  = $volumes
        CSV      = $csv
        VSwitch  = $vswitch
        VMs      = $vms
    }
}

# --- Run against each target -------------------------------------------------
$all = @()
foreach ($t in $targets) {
    Write-Host "Collecting from $t ..." -ForegroundColor Yellow
    $args = Get-InvokeArgs -Computer $t
    $args['ScriptBlock'] = $collect
    try {
        $all += Invoke-Command @args
    } catch {
        Write-Warning "Failed on ${t}: $($_.Exception.Message)"
    }
}

if (-not $all) { throw "No data collected from any target." }

# --- Export ------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$all.Host     | Export-Csv (Join-Path $OutputPath 'Hosts.csv')        -NoTypeInformation
$all.Features | Export-Csv (Join-Path $OutputPath 'Features.csv')     -NoTypeInformation
$all.Patch    | Export-Csv (Join-Path $OutputPath 'WindowsUpdate.csv') -NoTypeInformation
$all.Volumes  | Export-Csv (Join-Path $OutputPath 'HostVolumes.csv')  -NoTypeInformation
$all.CSV      | Export-Csv (Join-Path $OutputPath 'ClusterSharedVolumes.csv') -NoTypeInformation
$all.VSwitch  | Export-Csv (Join-Path $OutputPath 'VirtualSwitches.csv') -NoTypeInformation
$all.VMs      | Export-Csv (Join-Path $OutputPath 'VirtualMachines.csv') -NoTypeInformation

$all | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputPath 'FullInventory.json')

Write-Host "`nDone. Output written to: $OutputPath" -ForegroundColor Green
Write-Host ("Hosts: {0} | VMs: {1}" -f $all.Host.Count, ($all.VMs | Measure-Object).Count)

<#
================================================================================
 OUT-OF-BAND DEVICES (not covered by this script - collect separately)
================================================================================

 SAN / NAS have no Windows agent, so inventory them from their own management
 plane and cross-reference back to the Host/VM CSVs above.

 SYNOLOGY (DSM):
   - Control Panel > Info Center, and Storage Manager: model, DSM version,
     volume/pool layout, RAID type, disk health (SMART), capacity.
   - Export: Storage Manager supports a report; or enable SNMP (Control Panel >
     Terminal & SNMP) and poll OID tree 1.3.6.1.4.1.6574 for scripted pulls.
   - Connectivity: note SMB shares vs iSCSI LUNs and which Hyper-V hosts mount them.

 QNAP (QTS/QuTS hero):
   - Control Panel > System > System Status, and Storage & Snapshots:
     model, firmware, pool/volume/RAID, disk SMART, capacity.
   - Export: System logs export; or enable SNMP (Control Panel > Network &
     File Services > SNMP), enterprise OID 1.3.6.1.4.1.24681.
   - Connectivity: same - map iSCSI LUNs / SMB shares to consuming hosts.

 CROSS-REFERENCE: match iSCSI target IPs/IQNs seen on the hosts
   (Get-IscsiTarget / Get-IscsiConnection) to LUNs on the SAN/NAS so storage
   maps cleanly to the workloads that depend on it.
================================================================================
#>
