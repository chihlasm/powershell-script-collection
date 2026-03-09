<#
.SYNOPSIS
    Audits DHCP failover health across all authorized DHCP servers in the domain.

.DESCRIPTION
    Discovers authorized DHCP servers from Active Directory, checks failover relationship
    status, scope coverage, lease utilization, option consistency, exclusion ranges, and
    reservation sync. Produces a color-coded console report and a timestamped text file.

.PARAMETER OutputPath
    Directory for the output report file. Defaults to the current directory.

.EXAMPLE
    .\Audit-DHCPFailover.ps1
    .\Audit-DHCPFailover.ps1 -OutputPath "C:\Reports"

.NOTES
    Requires RSAT DHCP Server tools (DhcpServer module).
    Must be run from a domain-joined machine with appropriate permissions.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path
)

# Verify the DhcpServer module is available at runtime
try {
    Import-Module DhcpServer -ErrorAction Stop
}
catch {
    Write-Host '[FAIL] The DhcpServer PowerShell module is not available.' -ForegroundColor Red
    Write-Host '       Install RSAT DHCP tools or run this script on a DHCP server.' -ForegroundColor Red
    Write-Host "       Error: $_" -ForegroundColor Yellow
    return
}

# ── Helper functions ──────────────────────────────────────────────────────────

function Write-StatusLine {
    param(
        [string]$Message,
        [ValidateSet('Pass','Warn','Fail','Info','Header')]
        [string]$Status = 'Info'
    )
    $prefix = switch ($Status) {
        'Pass'   { '[PASS]' }
        'Warn'   { '[WARN]' }
        'Fail'   { '[FAIL]' }
        'Info'   { '[INFO]' }
        'Header' { '=====' }
    }
    $color = switch ($Status) {
        'Pass'   { 'Green' }
        'Warn'   { 'Yellow' }
        'Fail'   { 'Red' }
        'Info'   { 'Cyan' }
        'Header' { 'White' }
    }
    $line = "$prefix $Message"
    Write-Host $line -ForegroundColor $color
    $script:ReportLines += $line
}

function Write-ReportLine {
    param([string]$Message)
    Write-Host $Message
    $script:ReportLines += $Message
}

function Write-SectionHeader {
    param([string]$Title)
    $border = '=' * 80
    Write-ReportLine ''
    Write-ReportLine $border
    Write-StatusLine $Title -Status Header
    Write-ReportLine $border
}

# ── Initialisation ────────────────────────────────────────────────────────────

$script:ReportLines = [System.Collections.Generic.List[string]]::new()
$timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$reportFile = Join-Path $OutputPath "DHCPFailoverAudit_$timestamp.txt"

# Counters for summary
$totalScopes        = 0
$protectedScopes    = 0
$unprotectedScopes  = 0
$warningCount       = 0
$failCount          = 0

Write-SectionHeader 'DHCP FAILOVER AUDIT REPORT'
Write-ReportLine "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-ReportLine "Report File: $reportFile"

# ── 1. Discover DHCP servers ─────────────────────────────────────────────────

Write-SectionHeader '1. DHCP SERVER DISCOVERY'

try {
    $dhcpServers = Get-DhcpServerInDC -ErrorAction Stop
    if (-not $dhcpServers -or $dhcpServers.Count -eq 0) {
        Write-StatusLine 'No authorized DHCP servers found in Active Directory.' -Status Fail
        $failCount++
        $script:ReportLines | Out-File -FilePath $reportFile -Encoding UTF8
        return
    }
    Write-StatusLine "Found $($dhcpServers.Count) authorized DHCP server(s):" -Status Pass
    foreach ($srv in $dhcpServers) {
        Write-ReportLine "  - $($srv.DnsName) ($($srv.IPAddress))"
    }
}
catch {
    Write-StatusLine "Failed to query AD for DHCP servers: $_" -Status Fail
    $script:ReportLines | Out-File -FilePath $reportFile -Encoding UTF8
    return
}

# ── Gather data from each server ─────────────────────────────────────────────

$serverData = @{}  # key = server FQDN, value = hashtable of results
$reachableServers = [System.Collections.Generic.List[string]]::new()

foreach ($srv in $dhcpServers) {
    $name = $srv.DnsName
    $data = @{
        Reachable    = $false
        Failovers    = @()
        Scopes       = @()
        ScopeStats   = @{}
        ScopeOptions = @{}
        Exclusions   = @{}
        Reservations = @{}
    }

    try {
        # Quick connectivity test via a lightweight cmdlet
        $null = Get-DhcpServerSetting -ComputerName $name -ErrorAction Stop
        $data.Reachable = $true
        $reachableServers.Add($name)
        Write-StatusLine "Server $name is reachable." -Status Pass
    }
    catch {
        Write-StatusLine "Server $name is UNREACHABLE: $_" -Status Fail
        $failCount++
        $serverData[$name] = $data
        continue
    }

    # Failover relationships
    try {
        $data.Failovers = @(Get-DhcpServerv4Failover -ComputerName $name -ErrorAction Stop)
    }
    catch {
        Write-StatusLine "Could not retrieve failover relationships from $name : $_" -Status Warn
        $warningCount++
    }

    # Scopes
    try {
        $data.Scopes = @(Get-DhcpServerv4Scope -ComputerName $name -ErrorAction Stop)
    }
    catch {
        Write-StatusLine "Could not retrieve scopes from $name : $_" -Status Warn
        $warningCount++
    }

    # Statistics, options, exclusions, reservations per scope
    foreach ($scope in $data.Scopes) {
        $sid = $scope.ScopeId.ToString()

        # Statistics
        try {
            $data.ScopeStats[$sid] = Get-DhcpServerv4ScopeStatistics -ComputerName $name -ScopeId $scope.ScopeId -ErrorAction Stop
        }
        catch { }

        # Scope options
        try {
            $data.ScopeOptions[$sid] = @(Get-DhcpServerv4OptionValue -ComputerName $name -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
        }
        catch { }

        # Exclusion ranges
        try {
            $data.Exclusions[$sid] = @(Get-DhcpServerv4ExclusionRange -ComputerName $name -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
        }
        catch { }

        # Reservations
        try {
            $data.Reservations[$sid] = @(Get-DhcpServerv4Reservation -ComputerName $name -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
        }
        catch { }
    }

    $serverData[$name] = $data
}

if ($reachableServers.Count -eq 0) {
    Write-StatusLine 'No DHCP servers were reachable. Cannot continue audit.' -Status Fail
    $script:ReportLines | Out-File -FilePath $reportFile -Encoding UTF8
    return
}

# ── 2. Failover Relationship Status ──────────────────────────────────────────

Write-SectionHeader '2. FAILOVER RELATIONSHIP STATUS'

# Deduplicate relationships (both partners report the same relationship)
$seenRelationships = @{}

foreach ($serverName in $reachableServers) {
    foreach ($fo in $serverData[$serverName].Failovers) {
        $relKey = ($fo.Name)
        if ($seenRelationships.ContainsKey($relKey)) { continue }
        $seenRelationships[$relKey] = $true

        Write-ReportLine ''
        Write-ReportLine "  Relationship : $($fo.Name)"
        Write-ReportLine "  Primary      : $($fo.PrimaryServerName)"
        Write-ReportLine "  Partner      : $($fo.PartnerServer)"
        Write-ReportLine "  Mode         : $($fo.Mode)"

        if ($fo.Mode -eq 'LoadBalance') {
            Write-ReportLine "  LB Split     : $($fo.LoadBalancePercent)% / $([int](100 - $fo.LoadBalancePercent))%"
        }
        if ($fo.Mode -eq 'HotStandby') {
            Write-ReportLine "  Standby Role : $($fo.ServerRole)"
            Write-ReportLine "  Reserve %    : $($fo.ReservePercent)%"
        }

        Write-ReportLine "  MCLT         : $($fo.MaxClientLeadTime)"
        Write-ReportLine "  AutoStateTransition : $($fo.AutoStateTransition)"
        Write-ReportLine "  StateSwitchInterval : $($fo.StateSwitchInterval)"
        Write-ReportLine "  Shared Secret: $(if ($fo.SharedSecret) { 'Configured' } else { 'Not Configured' })"

        # State check
        $state = $fo.State
        Write-ReportLine "  State        : $state"
        if ($state -eq 'Normal') {
            Write-StatusLine "  Relationship '$($fo.Name)' is in Normal state." -Status Pass
        }
        elseif ($state -eq 'CommunicationInterrupted') {
            Write-StatusLine "  Relationship '$($fo.Name)' has COMMUNICATION INTERRUPTED." -Status Fail
            $failCount++
        }
        elseif ($state -eq 'PartnerDown') {
            Write-StatusLine "  Relationship '$($fo.Name)' partner is DOWN." -Status Fail
            $failCount++
        }
        else {
            Write-StatusLine "  Relationship '$($fo.Name)' is in state: $state" -Status Warn
            $warningCount++
        }
    }
}

if ($seenRelationships.Count -eq 0) {
    Write-StatusLine 'No failover relationships found on any server.' -Status Fail
    $failCount++
}

# ── 3. Scope Coverage Audit ──────────────────────────────────────────────────

Write-SectionHeader '3. SCOPE COVERAGE AUDIT'

# Build a map of all scopes across all servers
$allScopeIds = @{}  # scopeId -> list of server names
foreach ($serverName in $reachableServers) {
    foreach ($scope in $serverData[$serverName].Scopes) {
        $sid = $scope.ScopeId.ToString()
        if (-not $allScopeIds.ContainsKey($sid)) {
            $allScopeIds[$sid] = [System.Collections.Generic.List[string]]::new()
        }
        $allScopeIds[$sid].Add($serverName)
    }
}

# Build a set of scope IDs that are in failover relationships
$failoverScopeMap = @{}  # scopeId -> relationship name
foreach ($serverName in $reachableServers) {
    foreach ($fo in $serverData[$serverName].Failovers) {
        foreach ($sid in $fo.ScopeId) {
            $failoverScopeMap[$sid.ToString()] = $fo.Name
        }
    }
}

$totalScopes = $allScopeIds.Count

foreach ($sid in ($allScopeIds.Keys | Sort-Object)) {
    $servers = $allScopeIds[$sid]
    $inFailover = $failoverScopeMap.ContainsKey($sid)

    if ($servers.Count -eq 1 -and -not $inFailover) {
        Write-StatusLine "Scope $sid exists ONLY on $($servers[0]) — NOT in failover (UNPROTECTED)" -Status Fail
        $unprotectedScopes++
        $failCount++
    }
    elseif ($servers.Count -gt 1 -and -not $inFailover) {
        Write-StatusLine "Scope $sid exists on multiple servers but is NOT in a failover relationship (UNPROTECTED)" -Status Warn
        $unprotectedScopes++
        $warningCount++
    }
    elseif ($inFailover) {
        Write-StatusLine "Scope $sid is protected by failover relationship '$($failoverScopeMap[$sid])'" -Status Pass
        $protectedScopes++
    }
}

if ($totalScopes -eq 0) {
    Write-StatusLine 'No DHCP scopes found on any server.' -Status Warn
    $warningCount++
}

# ── 4. Lease Utilization Per Scope ───────────────────────────────────────────

Write-SectionHeader '4. LEASE UTILIZATION'

$utilizationThreshold = 80

foreach ($serverName in $reachableServers) {
    Write-ReportLine ''
    Write-ReportLine "  Server: $serverName"
    Write-ReportLine "  $('-' * 70)"
    Write-ReportLine ("  {0,-18} {1,10} {2,10} {3,10} {4,10}" -f 'ScopeId','Total','InUse','Free','% Used')
    Write-ReportLine ("  {0,-18} {1,10} {2,10} {3,10} {4,10}" -f '-------','-----','-----','----','------')

    foreach ($scope in ($serverData[$serverName].Scopes | Sort-Object ScopeId)) {
        $sid = $scope.ScopeId.ToString()
        $stats = $serverData[$serverName].ScopeStats[$sid]
        if (-not $stats) { continue }

        $total   = $stats.AddressesFree + $stats.AddressesInUse
        $inUse   = $stats.AddressesInUse
        $free    = $stats.AddressesFree
        $pctUsed = if ($total -gt 0) { [math]::Round(($inUse / $total) * 100, 1) } else { 0 }

        $line = "  {0,-18} {1,10} {2,10} {3,10} {4,9}%" -f $sid, $total, $inUse, $free, $pctUsed

        if ($pctUsed -ge $utilizationThreshold) {
            Write-StatusLine "$line  <-- HIGH UTILIZATION" -Status Warn
            $warningCount++
        }
        else {
            Write-ReportLine $line
        }
    }
}

# ── 5. Scope Option Consistency ──────────────────────────────────────────────

Write-SectionHeader '5. SCOPE OPTION CONSISTENCY (Failover-Paired Scopes)'

# Only compare scopes that are in failover and exist on at least 2 reachable servers
foreach ($sid in ($failoverScopeMap.Keys | Sort-Object)) {
    $serversWithScope = $allScopeIds[$sid]
    if (-not $serversWithScope -or $serversWithScope.Count -lt 2) { continue }

    # Use the first two servers that have this scope
    $srvA = $serversWithScope[0]
    $srvB = $serversWithScope[1]

    $optsA = $serverData[$srvA].ScopeOptions[$sid]
    $optsB = $serverData[$srvB].ScopeOptions[$sid]

    if (-not $optsA -and -not $optsB) { continue }

    # Build lookup by OptionId
    $optMapA = @{}
    $optMapB = @{}
    if ($optsA) { foreach ($o in $optsA) { $optMapA[$o.OptionId] = $o } }
    if ($optsB) { foreach ($o in $optsB) { $optMapB[$o.OptionId] = $o } }

    $allOptionIds = @($optMapA.Keys) + @($optMapB.Keys) | Select-Object -Unique | Sort-Object
    $mismatchFound = $false

    foreach ($oid in $allOptionIds) {
        $a = $optMapA[$oid]
        $b = $optMapB[$oid]

        if ($a -and -not $b) {
            Write-StatusLine "Scope $sid Option $oid ($($a.Name)) exists on $srvA but NOT on $srvB" -Status Warn
            $warningCount++
            $mismatchFound = $true
        }
        elseif ($b -and -not $a) {
            Write-StatusLine "Scope $sid Option $oid ($($b.Name)) exists on $srvB but NOT on $srvA" -Status Warn
            $warningCount++
            $mismatchFound = $true
        }
        else {
            # Compare values
            $valA = ($a.Value | ForEach-Object { $_.ToString() }) -join ','
            $valB = ($b.Value | ForEach-Object { $_.ToString() }) -join ','
            if ($valA -ne $valB) {
                Write-StatusLine "Scope $sid Option $oid ($($a.Name)) MISMATCH:" -Status Warn
                Write-ReportLine "    $srvA : $valA"
                Write-ReportLine "    $srvB : $valB"
                $warningCount++
                $mismatchFound = $true
            }
        }
    }

    if (-not $mismatchFound) {
        Write-StatusLine "Scope $sid — options consistent across both servers." -Status Pass
    }
}

# ── 6. Exclusion Range Comparison ────────────────────────────────────────────

Write-SectionHeader '6. EXCLUSION RANGE COMPARISON (Failover-Paired Scopes)'

foreach ($sid in ($failoverScopeMap.Keys | Sort-Object)) {
    $serversWithScope = $allScopeIds[$sid]
    if (-not $serversWithScope -or $serversWithScope.Count -lt 2) { continue }

    $srvA = $serversWithScope[0]
    $srvB = $serversWithScope[1]

    $exclA = $serverData[$srvA].Exclusions[$sid]
    $exclB = $serverData[$srvB].Exclusions[$sid]

    # Normalise to string sets for comparison
    $setA = @()
    $setB = @()
    if ($exclA) { $setA = $exclA | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" } }
    if ($exclB) { $setB = $exclB | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" } }

    $onlyA = $setA | Where-Object { $_ -notin $setB }
    $onlyB = $setB | Where-Object { $_ -notin $setA }

    if ($onlyA -or $onlyB) {
        Write-StatusLine "Scope $sid has MISMATCHED exclusion ranges:" -Status Warn
        $warningCount++
        if ($onlyA) {
            foreach ($r in $onlyA) {
                Write-ReportLine "    Only on $srvA : $r"
            }
        }
        if ($onlyB) {
            foreach ($r in $onlyB) {
                Write-ReportLine "    Only on $srvB : $r"
            }
        }

        # Check for split-scope style (non-overlapping complementary exclusions)
        if ($onlyA -and $onlyB -and -not ($setA | Where-Object { $_ -in $setB })) {
            Write-StatusLine "  FINDING: Scope $sid appears to use split-scope exclusions rather than proper failover." -Status Fail
            $failCount++
        }
    }
    else {
        Write-StatusLine "Scope $sid — exclusion ranges match." -Status Pass
    }
}

# ── 7. Reservation Sync Check ───────────────────────────────────────────────

Write-SectionHeader '7. RESERVATION SYNC CHECK (Failover-Paired Scopes)'

foreach ($sid in ($failoverScopeMap.Keys | Sort-Object)) {
    $serversWithScope = $allScopeIds[$sid]
    if (-not $serversWithScope -or $serversWithScope.Count -lt 2) { continue }

    $srvA = $serversWithScope[0]
    $srvB = $serversWithScope[1]

    $resA = $serverData[$srvA].Reservations[$sid]
    $resB = $serverData[$srvB].Reservations[$sid]

    # Build lookup by IP address
    $mapA = @{}
    $mapB = @{}
    if ($resA) { foreach ($r in $resA) { $mapA[$r.IPAddress.ToString()] = $r } }
    if ($resB) { foreach ($r in $resB) { $mapB[$r.IPAddress.ToString()] = $r } }

    $allIPs = @($mapA.Keys) + @($mapB.Keys) | Select-Object -Unique | Sort-Object

    $mismatchFound = $false
    foreach ($ip in $allIPs) {
        $a = $mapA[$ip]
        $b = $mapB[$ip]

        if ($a -and -not $b) {
            Write-StatusLine "Scope $sid Reservation $ip ($($a.Name)) exists on $srvA but NOT on $srvB" -Status Warn
            $warningCount++
            $mismatchFound = $true
        }
        elseif ($b -and -not $a) {
            Write-StatusLine "Scope $sid Reservation $ip ($($b.Name)) exists on $srvB but NOT on $srvA" -Status Warn
            $warningCount++
            $mismatchFound = $true
        }
        else {
            # Both exist — compare MAC address
            $macA = $a.ClientId
            $macB = $b.ClientId
            if ($macA -ne $macB) {
                Write-StatusLine "Scope $sid Reservation $ip MAC mismatch: $srvA=$macA vs $srvB=$macB" -Status Warn
                $warningCount++
                $mismatchFound = $true
            }
        }
    }

    if (-not $mismatchFound) {
        $count = $allIPs.Count
        Write-StatusLine "Scope $sid — $count reservation(s) in sync." -Status Pass
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-SectionHeader 'AUDIT SUMMARY'

Write-ReportLine ''
Write-ReportLine "  DHCP Servers Discovered  : $($dhcpServers.Count)"
Write-ReportLine "  DHCP Servers Reachable   : $($reachableServers.Count)"
Write-ReportLine "  Failover Relationships   : $($seenRelationships.Count)"
Write-ReportLine "  Total Unique Scopes      : $totalScopes"
Write-ReportLine "  Scopes Protected (FO)    : $protectedScopes"
Write-ReportLine "  Scopes UNPROTECTED       : $unprotectedScopes"
Write-ReportLine "  Warnings                 : $warningCount"
Write-ReportLine "  Failures                 : $failCount"
Write-ReportLine ''

if ($failCount -eq 0 -and $warningCount -eq 0) {
    Write-StatusLine 'OVERALL HEALTH: HEALTHY — No issues detected.' -Status Pass
}
elseif ($failCount -eq 0) {
    Write-StatusLine "OVERALL HEALTH: CAUTION — $warningCount warning(s) found. Review recommended." -Status Warn
}
else {
    Write-StatusLine "OVERALL HEALTH: ACTION REQUIRED — $failCount failure(s) and $warningCount warning(s) found." -Status Fail
}

# ── Write report file ────────────────────────────────────────────────────────

Write-ReportLine ''
$script:ReportLines | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host ''
Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
