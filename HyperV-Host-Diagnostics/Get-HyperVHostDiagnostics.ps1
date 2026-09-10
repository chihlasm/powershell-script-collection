<#
.SYNOPSIS
    Read-only Hyper-V HOST diagnostics to correlate a guest VM's data-loss/reboot
    symptoms with host-level storage, network, cluster, and VM configuration issues.

.DESCRIPTION
    Run this ON THE HYPER-V HOST (not the guest). Generalized for any Hyper-V
    host being investigated after a guest VM showed unexplained data loss,
    unexpected reboot, or storage-related symptoms. Makes no changes to the
    host or any VM - inventory and event log review only.

.PARAMETER VMName
    Name of the specific guest VM to focus on (checkpoints, VHD health,
    network adapter stats). If omitted, only host-wide checks run.

.PARAMETER DaysBack
    Event log lookback window. Default 30. Widen for older incidents
    (e.g. -DaysBack 210 to reach a December incident from a June baseline).

.PARAMETER IncidentDates
    Optional array of dates (yyyy-MM-dd) to specifically correlate against -
    pulls a +/- 24 hour window across host System/Hyper-V logs for each date.
    Use the guest's incident dates and/or its last-boot date here.

.EXAMPLE
    .\Get-HyperVHostDiagnostics.ps1 -VMName "CAPD-APPS" -DaysBack 210 -IncidentDates '2025-12-05','2026-06-27'
#>

[CmdletBinding()]
param(
    [string]$VMName,
    [int]$DaysBack = 30,
    [string[]]$IncidentDates,
    [string]$OutputPath = "C:\ProgramData\VC3\Diagnostics"
)

$ErrorActionPreference = 'Continue'
$hostName  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$startTime = (Get-Date).AddDays(-$DaysBack)
$flags     = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
$reportFile = Join-Path $OutputPath "$($hostName)_HyperVHostDiagnostics_$timestamp.log"

function Write-Section { param([string]$Title) "`r`n" + ("=" * 80) + "`r`n$Title`r`n" + ("=" * 80) | Out-File -FilePath $reportFile -Append }
function Write-Line    { param([string]$Text = "") $Text | Out-File -FilePath $reportFile -Append }

Write-Line "Hyper-V Host Diagnostics"
Write-Line "Host: $hostName"
Write-Line "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line "Lookback: $DaysBack days (since $($startTime.ToString('yyyy-MM-dd')))"
if ($VMName) { Write-Line "Target VM: $VMName" }

$hasHyperV = Get-Command Get-VM -ErrorAction SilentlyContinue
if (-not $hasHyperV) {
    Write-Line "Hyper-V PowerShell module not found on this host. Run this ON the Hyper-V host itself, not the guest."
    $flags.Add("Hyper-V module not present - script must run on the Hyper-V host, not a guest VM")
}

# ---------------------------------------------------------------------------
# HOST OVERVIEW
# ---------------------------------------------------------------------------
Write-Section "HOST OVERVIEW"
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Line "Host OS: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Line "Host Last Boot: $($os.LastBootUpTime)  |  Uptime: $([math]::Round($uptime.TotalDays,1)) days"
} catch { Write-Line "Could not retrieve host OS info: $($_.Exception.Message)" }

$isClustered = $false
try {
    Import-Module FailoverClusters -ErrorAction Stop
    $cluster = Get-Cluster -ErrorAction Stop
    $isClustered = $true
    Write-Line "Cluster: $($cluster.Name) (host is a cluster node)"
} catch {
    Write-Line "Not a clustered host (or FailoverClusters module unavailable) - standalone Hyper-V."
}

# ---------------------------------------------------------------------------
# VM INVENTORY
# ---------------------------------------------------------------------------
Write-Section "VM INVENTORY"
if ($hasHyperV) {
    try {
        $vms = Get-VM -ErrorAction Stop
        $vms | Select-Object Name, State, Status, Uptime, IntegrationServicesState, ReplicationState |
            Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        foreach ($vm in $vms) {
            if ($vm.State -ne 'Running') { $flags.Add("VM '$($vm.Name)' state is $($vm.State), not Running") }
        }
    } catch { Write-Line "Error querying Get-VM: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# TARGET VM DETAIL: CHECKPOINTS, VHD HEALTH, NETWORK ADAPTER
# ---------------------------------------------------------------------------
if ($VMName -and $hasHyperV) {
    Write-Section "TARGET VM DETAIL: $VMName"
    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        Write-Line "State: $($vm.State)  |  Uptime: $($vm.Uptime)  |  Version: $($vm.Version)"
        Write-Line "Automatic Stop Action: $($vm.AutomaticStopAction)  |  Automatic Start Action: $($vm.AutomaticStartAction)"

        Write-Line "`r`n--- Checkpoints/Snapshots ---"
        $checkpoints = Get-VMSnapshot -VMName $VMName -ErrorAction SilentlyContinue
        if ($checkpoints) {
            $checkpoints | Select-Object Name, CreationTime, SnapshotType | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
            $flags.Add("VM '$VMName' has $($checkpoints.Count) checkpoint(s) - old/chained checkpoints on a production SQL VM are a common cause of storage growth and merge-related I/O issues")
        } else {
            Write-Line "No checkpoints found."
        }

        Write-Line "`r`n--- Virtual Hard Disks ---"
        $vhds = Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop
        foreach ($vhd in $vhds) {
            try {
                $vhdInfo = Get-VHD -Path $vhd.Path -ErrorAction Stop
                Write-Line "$($vhd.Path)"
                Write-Line "  Type: $($vhdInfo.VhdType)  |  Size: $([math]::Round($vhdInfo.Size/1GB,1)) GB  |  FileSize: $([math]::Round($vhdInfo.FileSize/1GB,1)) GB  |  Fragmentation: $($vhdInfo.FragmentationPercentage)%"
                if ($vhdInfo.VhdType -eq 'Dynamic' -and $vhdInfo.FragmentationPercentage -gt 30) {
                    $flags.Add("VHD '$($vhd.Path)' is Dynamic with $($vhdInfo.FragmentationPercentage)% fragmentation - consider compact/convert to Fixed")
                }
                $vhdDrive = ($vhd.Path -split ':')[0]
                if ($vhdDrive) {
                    $vol = Get-Volume -DriveLetter $vhdDrive -ErrorAction SilentlyContinue
                    if ($vol) {
                        $pctFree = [math]::Round(($vol.SizeRemaining / $vol.Size) * 100, 1)
                        Write-Line "  Host volume $($vhdDrive): $pctFree% free"
                        if ($pctFree -lt 10) { $flags.Add("Host volume $($vhdDrive): (hosting a VHD for $VMName) only $pctFree% free") }
                    }
                }
            } catch { Write-Line "  Could not read VHD info for $($vhd.Path): $($_.Exception.Message)" }
        }

        Write-Line "`r`n--- Network Adapter ---"
        $vmNic = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
        $vmNic | Select-Object Name, SwitchName, IPAddresses, Status | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    } catch { Write-Line "Error retrieving VM detail for '$VMName': $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# HOST STORAGE HEALTH
# ---------------------------------------------------------------------------
Write-Section "HOST PHYSICAL DISK HEALTH"
try {
    $physDisks = Get-PhysicalDisk -ErrorAction Stop
    $physDisks | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Usage |
        Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    foreach ($pd in $physDisks) {
        if ($pd.HealthStatus -ne 'Healthy') { $flags.Add("Host physical disk '$($pd.FriendlyName)' HealthStatus: $($pd.HealthStatus)") }
        try {
            $rel = Get-StorageReliabilityCounter -PhysicalDisk $pd -ErrorAction Stop
            Write-Line "$($pd.FriendlyName): ReadErrors=$($rel.ReadErrorsTotal) WriteErrors=$($rel.WriteErrorsTotal) Temp=$($rel.Temperature)"
            if ($rel.ReadErrorsTotal -gt 0 -or $rel.WriteErrorsTotal -gt 0) {
                $flags.Add("Host physical disk '$($pd.FriendlyName)' has nonzero R/W error counters (R:$($rel.ReadErrorsTotal) W:$($rel.WriteErrorsTotal))")
            }
        } catch { Write-Line "  (reliability counters not supported - check vendor RAID tool, e.g. PERC/RACADM, HPE SSA, StorCLI)" }
    }
} catch { Write-Line "Error querying Get-PhysicalDisk: $($_.Exception.Message)" }

if ($isClustered) {
    Write-Section "CLUSTER SHARED VOLUMES"
    try {
        $csvs = Get-ClusterSharedVolume -ErrorAction Stop
        $csvs | Select-Object Name, State, Node | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        foreach ($csv in $csvs) {
            if ($csv.State -like '*Redirected*') { $flags.Add("CSV '$($csv.Name)' is in Redirected Access mode - indicates a storage path problem on that node") }
            elseif ($csv.State -ne 'Online') { $flags.Add("CSV '$($csv.Name)' state is $($csv.State)") }
        }
    } catch { Write-Line "Error querying CSVs: $($_.Exception.Message)" }

    Write-Section "CLUSTER NODES / RESOURCES"
    try {
        Get-ClusterNode | Select-Object Name, State | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        Get-ClusterResource | Where-Object { $_.State -ne 'Online' } | Select-Object Name, State, OwnerGroup |
            Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
    } catch { Write-Line "Error querying cluster nodes/resources: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# HOST-LEVEL DISK/STORAGE EVENTS
# ---------------------------------------------------------------------------
Write-Section "HOST DISK/STORAGE ERROR EVENTS (System log, last $DaysBack days)"
try {
    $diskEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop |
        Where-Object {
            ($_.ProviderName -in @('disk','Disk','Ntfs','volmgr','volsnap','storahci','stornvme','iaStorA','iaStorAC','partmgr','ClusSvc') -and $_.Id -ne 129) -or
            $_.Id -in @(7,15,51,55,140,153,154,157)
        }
    if ($diskEvents) {
        $diskEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $flags.Add("$($diskEvents.Count) host-level disk/storage error events found (IDs: $((($diskEvents.Id | Sort-Object -Unique) -join ', ')))")
    } else {
        Write-Line "No matching host disk/storage error events found."
    }
} catch { Write-Line "Error querying System log: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# HYPER-V SPECIFIC EVENT LOGS
# ---------------------------------------------------------------------------
Write-Section "HYPER-V EVENT LOGS (Error/Warning, last $DaysBack days)"
$hvLogs = @(
    'Microsoft-Windows-Hyper-V-VMMS-Admin',
    'Microsoft-Windows-Hyper-V-Worker-Admin',
    'Microsoft-Windows-Hyper-V-SynthStor-Admin',
    'Microsoft-Windows-Hyper-V-StorageVSP-Admin',
    'Microsoft-Windows-Hyper-V-High-Availability-Admin',
    'Microsoft-Windows-Hyper-V-Compute-Admin'
)
foreach ($logName in $hvLogs) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $startTime; Level = 1,2,3 } -ErrorAction Stop
        if ($events) {
            Write-Line "`r`n--- $logName ---"
            $events | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, LevelDisplayName,
                @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
            $flags.Add("$($events.Count) error/warning event(s) in $logName")
        }
    } catch { }  # log may not exist on this build/role config - expected, continue
}

# ---------------------------------------------------------------------------
# HOST REBOOT / UNEXPECTED SHUTDOWN HISTORY
# ---------------------------------------------------------------------------
Write-Section "HOST REBOOT / SHUTDOWN HISTORY (last $DaysBack days)"
try {
    $rebootEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startTime; Id = 1074,6005,6006,6008,41 } -ErrorAction Stop
    if ($rebootEvents) {
        $rebootEvents | Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id,
            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
        $unexpected = $rebootEvents | Where-Object { $_.Id -in @(6008,41) }
        if ($unexpected) { $flags.Add("$($unexpected.Count) UNEXPECTED shutdown/power-loss event(s) on the host (Event ID 6008 or 41) - check timing against guest incident dates") }
    } else {
        Write-Line "No reboot/shutdown events found in window."
    }
} catch { Write-Line "Error querying reboot history: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# NETWORK HEALTH
# ---------------------------------------------------------------------------
Write-Section "HOST NETWORK / VIRTUAL SWITCH HEALTH"
try {
    Get-VMSwitch -ErrorAction SilentlyContinue | Select-Object Name, SwitchType, NetAdapterInterfaceDescription |
        Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append

    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    foreach ($nic in $adapters) {
        Write-Line "$($nic.Name) ($($nic.InterfaceDescription)): LinkSpeed=$($nic.LinkSpeed)"
        try {
            $stats = Get-NetAdapterStatistics -Name $nic.Name -ErrorAction Stop
            Write-Line "  ReceivedErrors=$($stats.ReceivedDiscardedPackets)  OutboundErrors=$($stats.OutboundPacketErrors)"
            if ($stats.OutboundPacketErrors -gt 0 -or $stats.ReceivedDiscardedPackets -gt 1000) {
                $flags.Add("NIC '$($nic.Name)' shows packet errors/discards - possible contributor to network-related outage symptoms")
            }
        } catch { }
    }
} catch { Write-Line "Error querying network adapters/switches: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------
# INCIDENT DATE CORRELATION
# ---------------------------------------------------------------------------
if ($IncidentDates) {
    Write-Section "EVENTS NEAR SPECIFIED INCIDENT DATES (+/- 24 hours, System + Hyper-V logs)"
    foreach ($d in $IncidentDates) {
        try {
            $day = [datetime]$d
            $rangeStart = $day.AddHours(-24)
            $rangeEnd   = $day.AddHours(24)
            Write-Line "`r`n--- Around $d ($rangeStart) to ($rangeEnd) ---"
            $logsToCheck = @('System') + $hvLogs
            foreach ($logName in $logsToCheck) {
                try {
                    $evts = Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $rangeStart; EndTime = $rangeEnd } -ErrorAction Stop
                    if ($evts) {
                        Write-Line "[$logName]"
                        $evts | Sort-Object TimeCreated | Select-Object TimeCreated, Id, LevelDisplayName,
                            @{N='Message';E={($_.Message -split "`n")[0]}} | Format-Table -AutoSize | Out-String -Width 300 | Out-File -FilePath $reportFile -Append
                    }
                } catch { }
            }
        } catch { Write-Line "Could not parse incident date '$d': $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
$summaryLines = @(("=" * 80), "FINDINGS SUMMARY - $hostName - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", ("=" * 80))
if ($flags.Count -gt 0) {
    $summaryLines += "$($flags.Count) item(s) flagged for review:"
    $i = 1
    foreach ($f in $flags) { $summaryLines += "  [$i] $f"; $i++ }
} else {
    $summaryLines += "No automated flags raised. Review full report below."
}
$summaryLines += ""

$fullContent = Get-Content $reportFile -Raw
$summaryLines -join "`r`n" | Out-File -FilePath $reportFile -Encoding utf8
$fullContent | Out-File -FilePath $reportFile -Append -Encoding utf8

Write-Host "Diagnostics complete. Report saved to: $reportFile"
if ($flags.Count -gt 0) { Write-Host "$($flags.Count) item(s) flagged - see top of report." -ForegroundColor Yellow }
