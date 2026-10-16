#Requires -Version 3.0
<#
.SYNOPSIS
    Diagnoses Active Directory replication and DFS Replication (DFSR) / DFS Namespace (DFSN) health across domain controllers.

.DESCRIPTION
    Read-only. Runs from a management server or a domain controller and checks every DC
    (auto-discovered, or the ones named in -DomainControllers):

      1. AD replication - current replication failures and per-partner last success times
         (kept short on purpose; Invoke-ADAudit.ps1 gives the full picture).
      2. DFSR service state on each DC (queried remotely with CIM).
      3. DFS Replication groups (including SYSVOL), members, connections, replicated
         folders and per-connection backlog.
      4. DFS Namespaces - roots, root targets, folders and folder targets.

    Each server is queried in its own try/catch, so one unreachable DC does not stop the run.
    The DFSR and DFSN modules are optional: if they are missing, that half is skipped with
    a [WARN] and install instructions.

    Output: a log file with everything shown on screen, plus CSV exports of AD replication
    status and DFSR backlog, written to -OutputPath.

.PARAMETER DomainControllers
    Optional DC names. Default: all domain controllers in the current domain.

.PARAMETER OutputPath
    Directory for the log and CSV files. Defaults to the current directory.
    Alias: LogFile (for backward compatibility; a value with a file extension is used as the log file path).

.PARAMETER StaleHours
    A replication partnership with no successful replication in this many hours is reported
    as stale. Default 24.

.PARAMETER BacklogWarningThreshold
    Backlog file count at or above which a DFSR connection is reported as a problem. Default 1.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without running (used by the Pester tests).

.EXAMPLE
    .\Diagnose-AD-DFS-Replication.ps1
    Checks every DC in the current domain and writes the log to the current directory.

.EXAMPLE
    .\Diagnose-AD-DFS-Replication.ps1 -DomainControllers DC1, DC2 -OutputPath C:\Logs

.NOTES
    Requires: Windows PowerShell 3.0 or later, ActiveDirectory module (imported at run time).
    Optional modules: DFSR (Get-Dfsr*, Get-DfsReplicationGroup, Get-DfsReplicatedFolder) and
    DFSN (Get-Dfsn*) - install the "DFS Management Tools" RSAT feature, or run on a DC with DFS roles.
    Run as a domain admin (or an account with read access to the DFS configuration and
    remote CIM/WMI access to the DCs).

    Cmdlet notes (verified on Learn):
      - The module names are DFSR and DFSN (there is no "DFSReplication" module).
      - Members: Get-DfsrMember; connections: Get-DfsrConnection (SourceComputerName /
        DestinationComputerName); backlog: Get-DfsrBacklog (-SourceComputerName and
        -DestinationComputerName required). Get-DfsrBacklog lists at most 100 files; the
        true count is only written to the verbose stream ("... Count: 2400"), so the script
        reads the verbose stream.
      - Get-DfsReplicationGroup omits the SYSVOL group unless -IncludeSysvol is given.
      - Namespaces: Get-DfsnRoot -Domain, Get-DfsnRootTarget -Path, Get-DfsnFolder -Path
        (wildcards allowed), Get-DfsnFolderTarget -Path.
      - Get-ADReplicationFailure requires -Target (a DC, site, domain or forest name).
    Not verified on Learn: the property names of the ADReplicationPartnerMetadata output
    (Partner, Partition, LastReplicationSuccess, ConsecutiveReplicationFailures); the script
    reads them defensively.

    Previous versions called Get-DfsReplicationGroupMember, Get-DfsReplicationGroupConnection,
    Get-DfsReplicationBacklog, Get-DfsNamespace and Get-DfsReplicationTarget, none of which
    exist, and Get-Service -ComputerName, which does not exist in PowerShell 6+.

    REFERENCES
    - DFSR module:   https://learn.microsoft.com/powershell/module/dfsr/
      Get-DfsReplicationGroup: https://learn.microsoft.com/powershell/module/dfsr/get-dfsreplicationgroup
      Get-DfsrMember:          https://learn.microsoft.com/powershell/module/dfsr/get-dfsrmember
      Get-DfsrConnection:      https://learn.microsoft.com/powershell/module/dfsr/get-dfsrconnection
      Get-DfsReplicatedFolder: https://learn.microsoft.com/powershell/module/dfsr/get-dfsreplicatedfolder
      Get-DfsrBacklog:         https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog
    - DFSN module:   https://learn.microsoft.com/powershell/module/dfsn/
      Get-DfsnRoot:            https://learn.microsoft.com/powershell/module/dfsn/get-dfsnroot
      Get-DfsnRootTarget:      https://learn.microsoft.com/powershell/module/dfsn/get-dfsnroottarget
      Get-DfsnFolder:          https://learn.microsoft.com/powershell/module/dfsn/get-dfsnfolder
      Get-DfsnFolderTarget:    https://learn.microsoft.com/powershell/module/dfsn/get-dfsnfoldertarget
    - AD replication cmdlets:
      https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationfailure
      https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationpartnermetadata
    - DFSR event 2213 (dirty shutdown) and SYSVOL initial sync:
      https://learn.microsoft.com/troubleshoot/windows-server/networking/troubleshoot-missing-sysvol-and-netlogon-shares
#>

[CmdletBinding()]
param(
    [string[]]$DomainControllers = @(),

    [Alias('LogFile')]
    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(1, 8760)]
    [int]$StaleHours = 24,

    [ValidateRange(1, 1000000)]
    [int]$BacklogWarningThreshold = 1,

    [switch]$LoadFunctionsOnly
)

$script:LogFile = $null

#region Functions

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 }
}

function Write-Table {
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin { $items = @() }
    process { if ($null -ne $InputObject) { $items += $InputObject } }
    end {
        if ($items.Count -eq 0) { return }
        $text = ($items | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
        Write-Host $text
        if ($script:LogFile) { $text | Out-File -FilePath $script:LogFile -Append -Encoding UTF8 }
    }
}

function Get-DfsrServiceState {
    # Get-Service -ComputerName does not exist in PowerShell 6+; CIM works from 3.0 onward.
    param([Parameter(Mandatory)][string]$ComputerName)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='DFSR'" -ComputerName $ComputerName -ErrorAction Stop
    if (-not $svc) { return 'NotInstalled' }
    return [string]$svc.State
}

function Get-DfsrBacklogCount {
    # Get-DfsrBacklog returns at most 100 file records; the full count is only in the
    # verbose stream: 'The replicated folder has a backlog of files. Replicated folder: "RF01". Count: 2400'
    # https://learn.microsoft.com/powershell/module/dfsr/get-dfsrbacklog
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$FolderName,
        [Parameter(Mandatory)][string]$SourceComputerName,
        [Parameter(Mandatory)][string]$DestinationComputerName
    )
    $out = @(Get-DfsrBacklog -GroupName $GroupName -FolderName $FolderName `
        -SourceComputerName $SourceComputerName -DestinationComputerName $DestinationComputerName `
        -Verbose -ErrorAction Stop 4>&1)
    $count = $null
    foreach ($o in $out) {
        if ($o -is [System.Management.Automation.VerboseRecord] -and $o.Message -match 'Count:\s*(\d+)') {
            $count = [int]$Matches[1]
        }
    }
    if ($null -eq $count) {
        $count = @($out | Where-Object { $_ -isnot [System.Management.Automation.VerboseRecord] }).Count
    }
    return $count
}

function Get-PartnerName {
    # ADReplicationPartnerMetadata.Partner is a DN such as 'CN=NTDS Settings,CN=DC2,CN=Servers,...'.
    param($Partner)
    $text = [string]$Partner
    if ($text -match 'CN=NTDS Settings,CN=([^,]+),') { return $Matches[1] }
    return $text
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Setup

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "[FAIL] ActiveDirectory module not available: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '[INFO] Install RSAT (Install-WindowsFeature RSAT-AD-PowerShell) or run on a domain controller.' -ForegroundColor Cyan
    exit 1
}

$startTime = Get-Date
if ([System.IO.Path]::GetExtension($OutputPath)) {
    $script:LogFile = $OutputPath
    $outDir = Split-Path -Parent $OutputPath
    if (-not $outDir) { $outDir = (Get-Location).Path }
}
else {
    $outDir = $OutputPath
    $script:LogFile = Join-Path $outDir ("AD-DFS-Replication_{0:yyyy-MM-dd_HHmmss}.log" -f $startTime)
}
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$csvStem = Join-Path $outDir ("AD-DFS-Replication_{0:yyyy-MM-dd_HHmmss}" -f $startTime)

Write-Status INFO "AD/DFS replication diagnostics started on $($env:COMPUTERNAME) by $($env:USERNAME)"
Write-Status INFO "Log: $script:LogFile"

# Discover domain controllers
$dnsRoot = $null
try { $dnsRoot = (Get-ADDomain -ErrorAction Stop).DNSRoot } catch { Write-Status WARN "Could not read domain name: $($_.Exception.Message)" }

$DCs = @()
if ($DomainControllers.Count -eq 0) {
    try {
        $DCs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
        Write-Status PASS "Auto-detected $($DCs.Count) domain controller(s)."
    }
    catch {
        Write-Status FAIL "Failed to retrieve domain controllers: $($_.Exception.Message)"
        exit 1
    }
}
else {
    foreach ($dc in $DomainControllers) {
        try { $DCs += @(Get-ADDomainController -Identity $dc -ErrorAction Stop) }
        catch { Write-Status FAIL "Failed to find domain controller ${dc}: $($_.Exception.Message)" }
    }
    if ($DCs.Count -eq 0) {
        Write-Status FAIL 'No valid domain controllers specified.'
        exit 1
    }
}
foreach ($dc in $DCs) { Write-Status INFO "  $($dc.HostName)" }

#endregion

#region Active Directory replication (kept short - see Invoke-ADAudit.ps1 for the full audit)

Write-Status INFO '=== ACTIVE DIRECTORY REPLICATION ==='

try {
    # -Target is mandatory; pass every DC name (Server scope).
    $failures = @(Get-ADReplicationFailure -Target @($DCs | ForEach-Object { $_.HostName }) -ErrorAction Stop)
    if ($failures.Count -gt 0) {
        Write-Status FAIL "$($failures.Count) replication failure(s) reported:"
        $failures | Select-Object Server, Partner, FailureType, FailureCount, FirstFailureTime, LastError | Write-Table
    }
    else {
        Write-Status PASS 'No AD replication failures reported.'
    }
}
catch { Write-Status FAIL "Failed to check AD replication failures: $($_.Exception.Message)" }

$replicationStatus = @()
$staleThreshold = (Get-Date).AddHours(-$StaleHours)
foreach ($dc in $DCs) {
    try {
        $partners = @(Get-ADReplicationPartnerMetadata -Target $dc.HostName -Partition * -ErrorAction Stop)
        foreach ($partner in $partners) {
            $failed = [int]$partner.ConsecutiveReplicationFailures
            $replicationStatus += [PSCustomObject]@{
                TargetDC               = $dc.HostName
                SourceDC               = Get-PartnerName $partner.Partner
                Partition              = $partner.Partition
                LastReplicationAttempt = $partner.LastReplicationAttempt
                LastReplicationSuccess = $partner.LastReplicationSuccess
                ConsecutiveFailures    = $failed
                Status                 = if ($failed -gt 0 -or -not $partner.LastReplicationSuccess -or $partner.LastReplicationSuccess -lt $staleThreshold) { 'Stale' } else { 'OK' }
            }
        }
    }
    catch { Write-Status FAIL "Failed to get replication metadata for $($dc.HostName): $($_.Exception.Message)" }
}
$replicationStatus | Write-Table
$stale = @($replicationStatus | Where-Object { $_.Status -eq 'Stale' })
if ($stale.Count -gt 0) { Write-Status WARN "$($stale.Count) AD replication partnership(s) are failing or have no success in $StaleHours hours." }
else { Write-Status PASS 'All AD replication partnerships appear healthy.' }
if ($replicationStatus.Count -gt 0) {
    $replicationStatus | Export-Csv -LiteralPath "$csvStem-ADReplication.csv" -NoTypeInformation -Encoding UTF8
}

#endregion

#region DFS Replication

Write-Status INFO '=== DFS REPLICATION (DFSR) ==='

$stoppedServices = @()
foreach ($dc in $DCs) {
    try {
        $state = Get-DfsrServiceState -ComputerName $dc.HostName
        if ($state -eq 'Running') { Write-Status PASS "  $($dc.HostName): DFSR service Running" }
        else { Write-Status FAIL "  $($dc.HostName): DFSR service $state"; $stoppedServices += $dc.HostName }
    }
    catch {
        Write-Status FAIL "  $($dc.HostName): could not check DFSR service - $($_.Exception.Message)"
        $stoppedServices += $dc.HostName
    }
}

$backlogRows = @()
$dfsrAvailable = [bool](Get-Module -ListAvailable -Name DFSR)
if ($dfsrAvailable) {
    try { Import-Module DFSR -ErrorAction Stop } catch { $dfsrAvailable = $false; Write-Status WARN "DFSR module failed to load: $($_.Exception.Message)" }
}
if (-not $dfsrAvailable) {
    Write-Status WARN 'DFSR PowerShell module not available - skipping replication group checks. Install the "DFS Management Tools" RSAT feature or run on a DC with the DFS Replication role.'
}
else {
    $domainArgs = @{}
    if ($dnsRoot) { $domainArgs['DomainName'] = $dnsRoot }
    $groups = @()
    try {
        $groups = @(Get-DfsReplicationGroup -GroupName '*' -IncludeSysvol @domainArgs -ErrorAction Stop)
        if ($groups.Count -gt 0) {
            Write-Status PASS "Found $($groups.Count) replication group(s):"
            $groups | Select-Object GroupName, DomainName, State, Description | Write-Table
        }
        else { Write-Status WARN 'No DFS Replication groups found.' }
    }
    catch { Write-Status FAIL "Failed to retrieve DFS Replication groups: $($_.Exception.Message)" }

    foreach ($group in $groups) {
        Write-Status INFO "Replication group: $($group.GroupName)"
        $groupArgs = @{ GroupName = $group.GroupName }
        if ($dnsRoot) { $groupArgs['DomainName'] = $dnsRoot }

        try {
            $members = @(Get-DfsrMember @groupArgs -ErrorAction Stop)
            Write-Status INFO '  Members:'
            $members | Select-Object ComputerName, DnsName, Site, State | Write-Table
        }
        catch { Write-Status FAIL "  Failed to get members of $($group.GroupName): $($_.Exception.Message)" }

        $connections = @()
        try {
            $connections = @(Get-DfsrConnection @groupArgs -ErrorAction Stop)
            Write-Status INFO '  Connections:'
            $connections | Select-Object SourceComputerName, DestinationComputerName, Enabled, State, RdcEnabled | Write-Table
        }
        catch { Write-Status FAIL "  Failed to get connections of $($group.GroupName): $($_.Exception.Message)" }

        $folders = @()
        try { $folders = @(Get-DfsReplicatedFolder @groupArgs -ErrorAction Stop) }
        catch { Write-Status FAIL "  Failed to get replicated folders of $($group.GroupName): $($_.Exception.Message)" }

        # Backlog is checked on each enabled connection (source -> destination) for each replicated folder.
        foreach ($conn in @($connections | Where-Object { $_.Enabled })) {
            foreach ($folder in $folders) {
                $label = "$($conn.SourceComputerName) -> $($conn.DestinationComputerName) [$($folder.FolderName)]"
                try {
                    $count = Get-DfsrBacklogCount -GroupName $group.GroupName -FolderName $folder.FolderName `
                        -SourceComputerName $conn.SourceComputerName -DestinationComputerName $conn.DestinationComputerName
                    if ($count -ge $BacklogWarningThreshold) { Write-Status WARN "  ${label}: $count file(s) in backlog" }
                    else { Write-Status PASS "  ${label}: no backlog" }
                    $backlogRows += [PSCustomObject]@{
                        GroupName    = $group.GroupName
                        FolderName   = $folder.FolderName
                        Source       = $conn.SourceComputerName
                        Destination  = $conn.DestinationComputerName
                        BacklogCount = $count
                    }
                }
                catch { Write-Status FAIL "  Failed to check backlog ${label}: $($_.Exception.Message)" }
            }
        }
    }
    if ($backlogRows.Count -gt 0) {
        $backlogRows | Export-Csv -LiteralPath "$csvStem-DfsrBacklog.csv" -NoTypeInformation -Encoding UTF8
    }
}

#endregion

#region DFS Namespaces

Write-Status INFO '=== DFS NAMESPACES (DFSN) ==='

$dfsnAvailable = [bool](Get-Module -ListAvailable -Name DFSN)
if ($dfsnAvailable) {
    try { Import-Module DFSN -ErrorAction Stop } catch { $dfsnAvailable = $false; Write-Status WARN "DFSN module failed to load: $($_.Exception.Message)" }
}
if (-not $dfsnAvailable) {
    Write-Status WARN 'DFSN PowerShell module not available - skipping namespace checks. Install the "DFS Management Tools" RSAT feature.'
}
else {
    try {
        $rootArgs = @{}
        if ($dnsRoot) { $rootArgs['Domain'] = $dnsRoot }
        $roots = @(Get-DfsnRoot @rootArgs -ErrorAction Stop)
        if ($roots.Count -eq 0) { Write-Status INFO 'No domain-based DFS namespaces found.' }
        else {
            Write-Status PASS "Found $($roots.Count) namespace(s):"
            $roots | Select-Object Path, Type, State, Description | Write-Table

            foreach ($root in $roots) {
                try {
                    $rootTargets = @(Get-DfsnRootTarget -Path $root.Path -ErrorAction Stop)
                    Write-Status INFO "  Root targets for $($root.Path):"
                    $rootTargets | Write-Table
                    $offline = @($rootTargets | Where-Object { $_.State -and $_.State -ne 'Online' })
                    if ($offline.Count -gt 0) { Write-Status WARN "  $($offline.Count) root target(s) of $($root.Path) are not Online." }
                }
                catch { Write-Status FAIL "  Failed to get root targets for $($root.Path): $($_.Exception.Message)" }

                try {
                    $nsFolders = @(Get-DfsnFolder -Path "$($root.Path)\*" -ErrorAction Stop)
                    foreach ($nsFolder in $nsFolders) {
                        $folderTargets = @(Get-DfsnFolderTarget -Path $nsFolder.Path -ErrorAction Stop)
                        Write-Status INFO "  Folder targets for $($nsFolder.Path):"
                        $folderTargets | Select-Object TargetPath, State, ReferralPriorityClass, ReferralPriorityRank | Write-Table
                    }
                }
                catch { Write-Status FAIL "  Failed to get folders/targets for $($root.Path): $($_.Exception.Message)" }
            }
        }
    }
    catch { Write-Status FAIL "Failed to retrieve DFS namespaces: $($_.Exception.Message)" }
}

#endregion

#region Summary

Write-Status INFO '=== DIAGNOSTIC SUMMARY ==='
$issues = @()
if ($stale.Count -gt 0) { $issues += "AD replication: $($stale.Count) failing or stale partnership(s)" }
$backlogged = @($backlogRows | Where-Object { $_.BacklogCount -ge $BacklogWarningThreshold })
if ($backlogged.Count -gt 0) { $issues += "DFSR: $($backlogged.Count) connection/folder pair(s) with a backlog" }
if ($stoppedServices.Count -gt 0) { $issues += "DFSR service not running or unreachable on $($stoppedServices -join ', ')" }

if ($issues.Count -eq 0) { Write-Status PASS 'No major issues detected.' }
else {
    Write-Status WARN "$($issues.Count) issue(s) found:"
    foreach ($i in $issues) { Write-Status WARN "  - $i" }
}
Write-Status INFO ("Completed in {0:N1} seconds. Log: {1}" -f ((Get-Date) - $startTime).TotalSeconds, $script:LogFile)

#endregion
