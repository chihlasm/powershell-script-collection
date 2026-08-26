#Requires -Version 5.1

<#
.SYNOPSIS
    Exports authentication failure evidence from domain controller Security logs and
    resolves each source IP address to a device identity.
.DESCRIPTION
    Answers "which physical device is generating these bad passwords?" across the whole
    domain, not for one account.

    Collects events 4625, 4771, 4776 and 4740 from every domain controller, normalizes
    their differing field layouts into one flat row shape, then resolves every distinct
    source IP through four independent sources until one answers:

      1. EVENT LOG CORRELATION  A successful logon (4624/4768) from the same IP names the
                                machine. Strongest evidence - the DC itself recorded it.
      2. DHCP LEASE             Lease or reservation on any authorized DHCP server. Gives
                                hostname AND MAC address; the MAC's OUI prefix identifies
                                appliance vendors, separating a firewall from a desktop.
      3. REVERSE DNS (PTR)      Cheap, but PTR records go stale. Rated Low confidence.
      4. AD COMPUTER OBJECT     Confirms domain membership and supplies OS, OU and last
                                logon - the difference between "our workstation" and
                                "unknown device on the network".

    WHY THIS EXISTS ALONGSIDE THE LOCKOUT TOOLS

    The tools in AD-LockoutDiagnostics answer "why is THIS account locking out" and render
    a ranked verdict. This script deliberately does not judge. It emits wide, flat CSV
    evidence intended to be cross-referenced against inventory you already hold - RMM
    exports, Intune, switch MAC tables, DHCP scopes - to identify a device the domain
    itself cannot name.

    WHAT THE EVENTS CAN AND CANNOT TELL YOU

    Not every event carries an IP address, and none of them carry both an IP and a
    reliable name:

      4625  WorkstationName + IpAddress + IpPort + LogonType + ProcessName  (richest)
      4771  IpAddress + IpPort only - NO workstation name, NO logon type
      4776  Workstation NAME only - NO IP address at all
      4740  Caller machine NAME only - NO IP address, and never an IP even for
            non-domain devices

    So a Kerberos-only source appears as a bare IP, and an NTLM-only source appears as a
    bare name. Correlating the two is the point of the AuthSources output.

    Read-only. Makes no changes to Active Directory, DHCP or DNS.
.PARAMETER DaysBack
    How many days of Security event log to search. 1-90, default 7. Large windows on a
    busy domain produce very large exports; start small.
.PARAMETER OutputPath
    Folder where the CSV files are written, created if missing. Defaults to an
    "Account Lockout Diagnostics" folder beside this script - the same folder the full
    investigation uses - so output lands in one predictable place regardless of the
    current working directory.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering every DC.
.PARAMETER DhcpServer
    Optional. One or more DHCP servers to query instead of auto-discovering via
    Get-DhcpServerInDC. Supply this when DHCP runs on non-Windows equipment that is not
    registered in AD, or when the authorized-server list is stale.
.PARAMETER SkipDhcp
    Skip DHCP lookups entirely. Use when no Windows DHCP server exists, or when the DHCP
    query is slow enough to be not worth waiting for.
.PARAMETER SkipDns
    Skip reverse DNS lookups. Use on networks where PTR records are absent and each failed
    lookup costs a DNS timeout.
.PARAMETER EnableCorrelation
    OFF BY DEFAULT. Turns on the event-log correlation pass, which names bare IP
    addresses by reading successful logons (4624/4768) from each DC.

    This is disabled by default because it proved unusable on a production domain
    controller: reading 4624 events was slow enough to stall the export for minutes,
    both when querying per-IP and when taking a single time-indexed sweep. See the
    CORRELATION PERFORMANCE note in .NOTES for the measurements.

    Correlation is enrichment, not evidence. With it off, unnamed IPs are still resolved
    by DHCP, reverse DNS and AD, and every source still appears in both CSVs with its
    full failure counts and timestamps. Enable it only on a domain controller where
    reading successful logons is known to be fast.
.PARAMETER CorrelationMaxEvents
    How many recent successful logons each DC's correlation sweep may read. Default
    20000. This is the knob that bounds correlation cost: raise it to name more IPs on a
    busy DC, lower it if the sweep is slow. Has no effect with -UseTargetedCorrelation.
.PARAMETER UseTargetedCorrelation
    Query the event log once per batch of unresolved IPs instead of taking one bounded
    sweep. Faster ONLY when most unresolved addresses genuinely appear in the log; when
    they do not, each query must read the entire Security log to prove absence (measured:
    52 seconds per batch against a 742,000-record log). The sweep default is bounded and
    predictable; use this only on a small log or when the sweep window misses events you
    know are there.
.PARAMETER CorrelationTimeoutSeconds
    Abandon the correlation pass on a given DC after this many seconds and continue with
    whatever names were found. Default 120. Set 0 to disable the budget entirely. Applies
    to -UseTargetedCorrelation; the sweep is bounded by -CorrelationMaxEvents instead.
.PARAMETER IncludeSuccesses
    Also export successful logons FOR THE SOURCE IPs ALREADY UNDER INVESTIGATION, giving a
    suspect device a full timeline rather than only its failures. Scoped to those
    addresses on purpose - collecting every 4624 on a domain controller is prohibitively
    slow, because it is the highest-volume event in the Security log.
.PARAMETER MinFailures
    Only include sources with at least this many failures in the sources CSV. Default 1
    (report everything). Raise it to cut noise on a busy domain.
.PARAMETER ThrottleLimit
    How many domain controllers to query at once. Default 4. Collection is dominated by
    waiting on each DC, so querying several concurrently cuts wall-clock time roughly in
    proportion on a multi-DC domain. Set 1 to collect serially, which makes -Verbose
    output readable when diagnosing a slow DC.
.PARAMETER OuiDatabasePath
    Path to a local copy of the IEEE OUI registry (oui.txt) for full MAC vendor coverage.
    Without it, vendor lookup uses a built-in table of roughly 35 high-signal
    manufacturers - enough to spot firewalls and hypervisors, but it will miss most
    consumer hardware. Download from https://standards-oui.ieee.org/oui/oui.txt
.PARAMETER InventoryCsv
    Path to any CSV of your own equipment records - an RMM export, an Intune device list,
    an asset spreadsheet, a switch MAC table. Each source is matched against it and every
    column of the matching row is added to the sources export, prefixed Inv_.

    Column names are detected, not required: hostname columns (ComputerName, Device Name,
    Hostname, Machine...), MAC columns (MAC Address, macaddress, Physical Address...) and
    IP columns (IPAddress, IPv4 Address...) are recognized in any capitalization.

    Matching is strongest-first: MAC (survives renames and re-imaging), then hostname,
    then IP (weakest - addresses get reassigned). The key that matched is recorded in
    InventoryMatchedOn so a weak match is visible as one.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1
    Last 7 days, all DCs, both CSVs into .\Reports\.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1 -DaysBack 14 -MinFailures 5
    Two weeks, only sources responsible for 5 or more failures.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1 -DomainController DC01,DC02 -DhcpServer DHCP01 -OutputPath C:\Evidence
    Explicit DC and DHCP targeting.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1 -SkipDhcp -SkipDns
    AD lookups only - no DHCP or DNS dependency.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1 -InventoryCsv C:\Exports
mm-devices.csv
    Cross-reference every source against your RMM export; matching records are added to
    the sources CSV as Inv_ columns.
.EXAMPLE
    .\Export-ADAuthSourceEvidence.ps1 -EnableCorrelation
    Also name bare IPs from successful logons. Off by default because it stalls on busy
    domain controllers - see the CORRELATION PERFORMANCE note in .NOTES before using it.
.NOTES
    Run on a DC or an admin workstation with RSAT. Requires permission to read the
    Security event log on each domain controller. DHCP lookups additionally require the
    DhcpServer RSAT module and read access to the DHCP servers.

    CORRELATION PERFORMANCE - why -EnableCorrelation is off by default
    -----------------------------------------------------------------
    Naming a bare IP from successful logons is the highest-confidence resolution
    available, and it was the original centrepiece of this script. It is nonetheless
    DISABLED BY DEFAULT, because on a real production domain controller it made the
    export unusable.

    Measured on a DC holding 742,767 Security records (1 GB circular log, 4.2 days of
    retention, ~29 unnamed IPs in a 7-day window):

      Get-WinEvent -FilterHashtable Id=4624 + StartTime      0.9s   (indexed time seek)
      XPath with timediff() time bound                       0.9s   (NOT the culprit)
      XPath EventData IpAddress filter, no match            11.2s   (full log scan)
      XPath timediff + 10 IPs (20 OR terms), no match       52.0s   (full log scan)
      FilterXml, SystemTime range + EventData, no match     52.9s   (full log scan)
      Trivial query, 5 events                                0.3s   (remoting is fine)

    The mechanism: an EventData predicate that matches NOTHING cannot terminate early -
    the log must read every record to prove absence. Cost therefore scales with the
    number of addresses that CANNOT be resolved, which is precisely the population the
    pass exists to serve. Pushing the IP list into the query made each scan more
    expensive, not less.

    A single StartTime-bounded sweep (Get-IpNameMapBySweep) was written to replace it,
    on the theory that one indexed query costing 0.9s beats N unindexed scans. In
    practice the export still stalled on this DC, so reading 4624/4768 events at all is
    expensive here for reasons the query shape does not explain - possibly log size,
    disk, or DC load.

    Conclusion: correlation is ENRICHMENT, not evidence. Everything it would have
    supplied is also available from DHCP (which additionally yields the MAC address),
    reverse DNS and Active Directory, and an unresolved source still carries its full
    failure counts, account list and timestamps. Blocking an evidence export on an
    optional nicety is the wrong trade, so the default run does not attempt it.

    Both diagnostics used to reach these numbers are kept beside this script:
      Debug-CorrelationQuery.ps1   times each query shape against a real Security log
      Debug-CorrelationQuery2.ps1  tests whether MATCHING EventData queries are fast

    Companion tools in AD-LockoutDiagnostics:
      Test-ADAuditPolicy.ps1        Run FIRST. If failure auditing is off, this script
                                    returns an empty export that looks identical to a
                                    clean result.
      Get-ADLockoutHistory.ps1      Which ACCOUNTS are locking out (domain-wide).
      Diagnose-ADAccountLockout.ps1 Why one specific account is locking out.

    REFERENCES
      Event 4625 (failed logon), field layout and SubStatus codes
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
      Event 4771 (Kerberos pre-auth failed), Status field and ::ffff: address format
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
      Event 4776 (NTLM credential validation), Workstation field, 0x0 = success
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
      Event 4740 (account locked out), caller machine in TargetDomainName
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
      Event 4624 (successful logon), used for IP-to-name correlation
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
      NTSTATUS values
        https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
      Get-DhcpServerInDC
        https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverindc
      Get-DhcpServerv4Lease
        https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4lease

    Verified against Microsoft Learn on 2026-08-20.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    # Defaults to a "Reports" folder beside this script, resolved from $PSScriptRoot so
    # output location does not depend on the caller's working directory.
    [string]$OutputPath,

    [string[]]$DomainController,

    [string[]]$DhcpServer,

    [switch]$SkipDhcp,

    [switch]$SkipDns,

    [switch]$EnableCorrelation,

    [switch]$UseTargetedCorrelation,

    [ValidateRange(100, 500000)]
    [int]$CorrelationMaxEvents = 20000,

    [ValidateRange(0, 3600)]
    [int]$CorrelationTimeoutSeconds = 120,

    [switch]$IncludeSuccesses,

    [ValidateRange(1, 10000)]
    [int]$MinFailures = 1,

    [string]$InventoryCsv,

    [string]$OuiDatabasePath,

    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 4,

    # Dot-source hook for the Pester tests: load the functions without executing the
    # collection pass. Matches the pattern used by the AD-LockoutDiagnostics scripts.
    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Documented Microsoft constants.
#
# Shared with the lockout tools via LockoutReference.psd1 where available. That file is
# the single source of truth precisely because duplicated copies of these values have
# drifted and produced wrong answers before (4776 0x0 was once labelled a failure, which
# reported healthy workstations as the top attacker).
#
# The fallbacks below keep this script self-contained when copied to a server on its own.
# -----------------------------------------------------------------------------
$script:Ref = $null
foreach ($candidate in @(
    (Join-Path $PSScriptRoot 'LockoutReference.psd1'),
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'AD-LockoutDiagnostics\LockoutReference.psd1')
)) {
    if (Test-Path -LiteralPath $candidate) {
        try { $script:Ref = Import-PowerShellDataFile -LiteralPath $candidate; break } catch { }
    }
}

# Status values meaning "no error", in every form the logs render them. Event 4776 and
# 4771 are written for BOTH success and failure; the status code is the ONLY discriminator.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
$script:SuccessStatusCodes = if ($script:Ref -and $script:Ref.SuccessStatusCodes) {
    $script:Ref.SuccessStatusCodes
} else {
    @('0x0', '0x00000000', '0', '')
}

$script:StatusCodes = if ($script:Ref -and $script:Ref.StatusCodes) {
    $script:Ref.StatusCodes
} else {
    @{
        '0x0'        = 'Success (KDC_ERR_NONE)'
        '0x6'        = 'Username does not exist (KDC_ERR_C_PRINCIPAL_UNKNOWN)'
        '0xC'        = 'KDC policy rejects request (KDC_ERR_POLICY)'
        '0x10'       = 'KDC has no support for PADATA type - usually smart-card related'
        '0x12'       = 'Client credentials revoked - disabled, expired, or LOCKED OUT'
        '0x17'       = 'Password has expired (KDC_ERR_KEY_EXPIRED)'
        '0x18'       = 'Bad password - pre-authentication failed (KDC_ERR_PREAUTH_FAILED)'
        '0x19'       = 'Additional pre-authentication required'
        '0x25'       = 'Clock skew too great (KRB_AP_ERR_SKEW)'
        '0x00000000' = 'Success (no errors)'
        '0xC000005E' = 'No logon servers available'
        '0xC0000064' = 'Username does not exist'
        '0xC000006A' = 'Bad password'
        '0xC000006D' = 'Generic logon failure - bad username/password or LM level mismatch'
        '0xC000006F' = 'Logon outside authorized hours'
        '0xC0000070' = 'Logon from unauthorized workstation'
        '0xC0000071' = 'Password expired'
        '0xC0000072' = 'Account disabled'
        '0xC000015B' = 'Logon type not granted at this machine'
        '0xC0000192' = 'Netlogon service was not started'
        '0xC0000193' = 'Account expired'
        '0xC0000224' = 'Change password at next logon is flagged'
        '0xC0000234' = 'Account locked out'
        '0xC0000371' = 'Local account store has no secret material for this account'
        '0xC0000413' = 'Blocked by authentication firewall'
    }
}

$script:LogonTypes = if ($script:Ref -and $script:Ref.LogonTypes) {
    $script:Ref.LogonTypes
} else {
    @{
        2  = 'Interactive - someone typed credentials at the console'
        3  = 'Network - mapped drive, file share, or service account connection'
        4  = 'Batch - scheduled task'
        5  = 'Service - a Windows service running as this account'
        7  = 'Unlock - workstation unlock'
        8  = 'NetworkCleartext - credentials sent unhashed'
        9  = 'NewCredentials - RunAs /netonly'
        10 = 'RemoteInteractive - RDP / Terminal Services'
        11 = 'CachedInteractive - logged on with locally cached credentials'
    }
}

# -----------------------------------------------------------------------------
# OUI prefixes for equipment that commonly appears as a SINGLE source IP behind which
# many real devices sit - firewalls, VPN concentrators, load balancers, WAPs.
#
# Recognizing these prevents the most expensive wrong turn in a lockout investigation:
# chasing "the device at 10.0.0.1" when that address is a NAT gateway and the real
# offender is any of two hundred machines behind it.
#
# This is a deliberately SHORT list of high-signal vendors, not an OUI database. An
# unknown prefix returns empty rather than a guess.
# Registry: https://standards-oui.ieee.org/oui/oui.txt
# -----------------------------------------------------------------------------
# Populated from -OuiDatabasePath when supplied; empty otherwise.
$script:OuiDatabase = @{}

$script:OuiVendors = @{
    '00090F' = 'Fortinet'
    '000C29' = 'VMware (virtual machine)'
    '005056' = 'VMware (virtual machine)'
    '001C7F' = 'Check Point'
    '0017C5' = 'SonicWall'
    '00170C' = 'SonicWall'
    '001B17' = 'Palo Alto Networks'
    'B40C25' = 'Palo Alto Networks'
    '00040F' = 'Cisco'
    '000142' = 'Cisco'
    '0050E2' = 'Cisco'
    '001A1E' = 'Aruba / HPE Networking'
    '186472' = 'Aruba / HPE Networking'
    '24DEC6' = 'Ubiquiti'
    '788A20' = 'Ubiquiti'
    '802AA8' = 'Ubiquiti'
    '000D9D' = 'Hewlett Packard'
    '001560' = 'Hewlett Packard'
    '0025B3' = 'Hewlett Packard'
    '00155D' = 'Microsoft Hyper-V (virtual machine)'
    '001DD8' = 'Microsoft Hyper-V (virtual machine)'
    '080027' = 'VirtualBox (virtual machine)'
    '525400' = 'KVM/QEMU (virtual machine)'
    '00163E' = 'Xen (virtual machine)'
    '001BC5' = 'Meraki'
    'E0CB1D' = 'Meraki'
    '0018BA' = 'Juniper'
    '2C6BF5' = 'Juniper'
    '001C73' = 'Arista'
    '00E02B' = 'Extreme Networks'
    '0007B4' = 'Zyxel'
    '001349' = 'WatchGuard'
    '000FF7' = 'Barracuda'
}

# =============================================================================
# Output helpers
# =============================================================================

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

# =============================================================================
# Event parsing
# =============================================================================

function ConvertTo-NormalizedIp {
    <#
    .SYNOPSIS
        Reduces the several textual forms a client address takes into one joinable value.
    .DESCRIPTION
        Event 4771 renders client addresses in IPv4-mapped IPv6 form (::ffff:10.0.0.12),
        while 4625 usually renders the plain IPv4 address for the same machine. Left
        as-is, the same device produces two different "sources" and never matches a DHCP
        lease or PTR record.

        Loopback arrives as ::1 or 127.0.0.1 depending on the event, and "-" is the
        logs' placeholder for "not recorded".
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771
    #>
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return '' }
    $a = $Address.Trim()

    # '-' is the event log's own placeholder for an absent value, not an address.
    if ($a -eq '-') { return '' }

    if ($a -eq '::1') { return '127.0.0.1' }

    # Strip the IPv4-mapped IPv6 prefix, but only when a genuine IPv4 address follows -
    # otherwise a real IPv6 address gets mangled.
    if ($a -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') { return $Matches[1] }

    return $a
}

function Get-StatusMeaning {
    <#
    .SYNOPSIS
        Translates a Kerberos or Winlogon status code into plain English.
    .DESCRIPTION
        Codes are matched case-insensitively and in both padded and unpadded hex forms,
        because the logs are inconsistent: the same failure appears as 0xc000006a in one
        event and 0xC000006A in another.
    #>
    param([string]$Code)

    if ([string]::IsNullOrWhiteSpace($Code)) { return '' }
    $c = $Code.Trim()

    foreach ($key in $script:StatusCodes.Keys) {
        if ($key -ieq $c) { return $script:StatusCodes[$key] }
    }

    # Try normalizing 0x0000000C style padding down to 0xC and back up again.
    if ($c -match '^0x0*([0-9a-fA-F]+)$') {
        $bare = $Matches[1]
        foreach ($key in $script:StatusCodes.Keys) {
            if ($key -match '^0x0*([0-9a-fA-F]+)$' -and $Matches[1] -ieq $bare) {
                return $script:StatusCodes[$key]
            }
        }
    }

    return "Unrecognized status code $Code"
}

function Test-IsFailureStatus {
    <#
    .SYNOPSIS
        Decides whether a status code represents a failure.
    .DESCRIPTION
        Events 4776, 4771 and 4768 are written for BOTH successful and failed
        authentication. The status code is the only discriminator - 0x0 means SUCCESS.
        Treating the presence of the event as evidence of failure reports healthy
        machines as the top source of bad passwords.
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776
    #>
    param([string]$Code)

    $c = if ($null -eq $Code) { '' } else { $Code.Trim() }
    foreach ($ok in $script:SuccessStatusCodes) {
        if ($c -ieq $ok) { return $false }
    }
    return $true
}

function ConvertFrom-AuthEvent {
    <#
    .SYNOPSIS
        Parses one Security event into the common row shape used by both exports.
    .DESCRIPTION
        The four event types have genuinely different field layouts. Their differences
        are not cosmetic and cannot be papered over with a single field-name lookup:

          4625  WorkstationName / IpAddress / IpPort / LogonType / ProcessName
                Specific reason is in SubStatus; Status is often the generic
                0xC000006D wrapper.
          4771  IpAddress / IpPort only. The value shown in Event Viewer as
                "Failure Code" is named Status in the XML.
          4776  Workstation (NOT WorkstationName). No IP field exists at all.
          4740  Caller machine is in TargetDomainName. There is NO CallerComputerName
                element, despite Event Viewer labelling it that way.
    #>
    param(
        [Parameter(Mandatory)][string]$EventXml,
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][string]$DcName
    )

    $x = [xml]$EventXml
    $d = @{}
    foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }

    $time = if ($x.Event.System.TimeCreated.SystemTime) {
        [datetime]$x.Event.System.TimeCreated.SystemTime
    } else { $null }

    $sourceHost = ''
    $sourceIp   = ''
    $sourcePort = ''
    $logonType  = ''
    $statusCode = ''
    $processName = ''
    $authPackage = ''
    $serviceName = ''

    switch ($EventId) {

        4625 {
            $sourceHost  = $d['WorkstationName']
            $sourceIp    = ConvertTo-NormalizedIp -Address $d['IpAddress']
            $sourcePort  = $d['IpPort']
            $logonType   = $d['LogonType']
            $processName = $d['ProcessName']
            $authPackage = $d['AuthenticationPackageName']

            # The specific failure reason lives in SubStatus. Status is frequently the
            # generic 0xC000006D regardless of the real cause, so reading Status alone
            # loses the distinction between "bad password" and "account disabled".
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
            # Prefer SubStatus whenever it carries a non-zero value; fall back to Status
            # when SubStatus is 0x0 or absent.
            $sub = $d['SubStatus']
            if (-not [string]::IsNullOrWhiteSpace($sub) -and (Test-IsFailureStatus -Code $sub)) {
                $statusCode = $sub
            } else {
                $statusCode = $d['Status']
            }
        }

        4771 {
            # No WorkstationName and no LogonType exist on this event. The client address
            # arrives IPv4-mapped (::ffff:10.0.0.12) and must be normalized to join.
            $sourceIp    = ConvertTo-NormalizedIp -Address $d['IpAddress']
            $sourcePort  = $d['IpPort']
            $serviceName = $d['ServiceName']
            # "Failure Code" in Event Viewer is the Status element in the XML.
            $statusCode  = $d['Status']
        }

        4768 {
            # Kerberos TGT request - collected only for IP-to-name correlation.
            $sourceIp    = ConvertTo-NormalizedIp -Address $d['IpAddress']
            $sourcePort  = $d['IpPort']
            $serviceName = $d['ServiceName']
            $statusCode  = $d['Status']
        }

        4776 {
            # Carries a machine NAME and no IP address whatsoever. The field is
            # Workstation, not WorkstationName - the 4625 spelling returns null here.
            $sourceHost  = $d['Workstation']
            $authPackage = $d['PackageName']
            $statusCode  = $d['Status']
        }

        4740 {
            # The caller machine is in TargetDomainName. There is no CallerComputerName
            # element in the event XML even though Event Viewer displays that label.
            # 4740 NEVER carries an IP - Microsoft notes that even a non-domain device
            # yields a name here, not an address.
            # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740
            $sourceHost = $d['TargetDomainName']
            $statusCode = ''
        }

        4624 {
            # Successful logon - collected only to name an IP seen in failure events.
            $sourceHost = $d['WorkstationName']
            $sourceIp   = ConvertTo-NormalizedIp -Address $d['IpAddress']
            $sourcePort = $d['IpPort']
            $logonType  = $d['LogonType']
            $statusCode = ''
        }
    }

    # 4625 and 4740 are failure-only events; the rest are dual-outcome and must be
    # judged by their status code.
    $isFailure = switch ($EventId) {
        4625    { $true }
        4740    { $true }
        4624    { $false }
        default { Test-IsFailureStatus -Code $statusCode }
    }

    $logonTypeMeaning = ''
    if (-not [string]::IsNullOrWhiteSpace($logonType)) {
        $lt = 0
        if ([int]::TryParse($logonType, [ref]$lt) -and $script:LogonTypes.ContainsKey($lt)) {
            $logonTypeMeaning = $script:LogonTypes[$lt]
        }
    }

    # Normalize hex casing so the same code groups as one value in a pivot table.
    $normalizedStatus = if ($statusCode -match '^0x[0-9a-fA-F]+$') {
        '0x' + $statusCode.Substring(2).ToUpperInvariant()
    } else { $statusCode }

    [PSCustomObject]@{
        Time             = $time
        DC               = $DcName
        EventId          = $EventId
        Account          = $d['TargetUserName']
        AccountDomain    = if ($EventId -eq 4740) { '' } else { $d['TargetDomainName'] }
        SourceHost       = $sourceHost
        SourceIp         = $sourceIp
        SourcePort       = $sourcePort
        LogonType        = $logonType
        LogonTypeMeaning = $logonTypeMeaning
        StatusCode       = $normalizedStatus
        StatusMeaning    = Get-StatusMeaning -Code $normalizedStatus
        IsFailure        = $isFailure
        ProcessName      = $processName
        AuthPackage      = $authPackage
        ServiceName      = $serviceName
        TargetSid        = $d['TargetSid']
        TargetUserSid    = $d['TargetUserSid']
    }
}

# =============================================================================
# Identity resolution
# =============================================================================

function Import-OuiDatabase {
    <#
    .SYNOPSIS
        Loads the IEEE OUI registry from a local copy of oui.txt.
    .DESCRIPTION
        The built-in vendor table covers roughly 35 high-signal manufacturers - enough to
        spot a firewall or a hypervisor, but it will miss most consumer hardware. The IEEE
        publishes the full registry, and pointing at a local copy turns "unknown MAC
        prefix" into a real manufacturer name for tens of thousands of vendors.

        Shipping the file is not an option (several megabytes, and it changes), so this
        reads whatever copy the operator downloaded.

        Registry format, one entry per pair of lines:
          00-1A-2B   (hex)      Acme Networks Inc.
          001A2B     (base 16)  Acme Networks Inc.
        Only the (hex) form is parsed; the (base 16) line repeats the same data.
        https://standards-oui.ieee.org/oui/oui.txt
    #>
    param([string]$Path)

    $db = @{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $db }

    try {
        foreach ($line in [System.IO.File]::ReadLines($Path)) {
            # "00-1A-2B   (hex)\t\tAcme Networks Inc."
            if ($line -match '^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$') {
                $prefix = ($Matches[1] + $Matches[2] + $Matches[3]).ToUpperInvariant()
                if (-not $db.ContainsKey($prefix)) { $db[$prefix] = $Matches[4].Trim() }
            }
        }
    } catch {
        Write-Verbose "Could not read OUI database ${Path}: $($_.Exception.Message)"
    }

    return $db
}

function Get-SourceTimingPattern {
    <#
    .SYNOPSIS
        Characterizes the rhythm of one source's failures.
    .DESCRIPTION
        Timing separates a machine from a person, which narrows the cause list before any
        other evidence is considered:

          Regular    Evenly spaced attempts - a service, scheduled task or sync client
                     retrying on a timer. A human does not retry every 30 minutes exactly.
          Burst      Many attempts within moments - a retry loop, or a spray working
                     through an account list.
          Irregular  No discernible rhythm; consistent with human activity.

        Deliberately conservative: fewer than three events is reported as Insufficient
        rather than guessed at, and the regularity threshold is loose enough that ordinary
        jitter does not read as machine-like.
    #>
    param([datetime[]]$Times)

    $sorted = @($Times | Where-Object { $_ } | Sort-Object)
    if ($sorted.Count -lt 3) {
        return [PSCustomObject]@{
            Pattern           = 'Insufficient'
            Description       = 'Too few events to characterize timing'
            MedianGapMinutes  = 0
        }
    }

    $gaps = @()
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $gaps += ($sorted[$i] - $sorted[$i - 1]).TotalMinutes
    }

    $ordered = @($gaps | Sort-Object)
    $mid     = [int][math]::Floor($ordered.Count / 2)
    $median  = if ($ordered.Count % 2 -eq 0) { ($ordered[$mid - 1] + $ordered[$mid]) / 2 } else { $ordered[$mid] }

    # Everything inside a couple of minutes is a burst regardless of regularity.
    if ($median -lt 2) {
        return [PSCustomObject]@{
            Pattern          = 'Burst'
            Description      = 'Rapid burst of attempts - consistent with a retry loop or an account-list sweep, not a person typing'
            MedianGapMinutes = [math]::Round($median, 2)
        }
    }

    # Regular if every gap sits close to the median. Relative tolerance so a 30-minute
    # timer and a 4-hour timer are judged on the same terms.
    $tolerance = [math]::Max(1.0, $median * 0.25)
    $regular   = $true
    foreach ($g in $gaps) {
        if ([math]::Abs($g - $median) -gt $tolerance) { $regular = $false; break }
    }

    if ($regular) {
        return [PSCustomObject]@{
            Pattern          = 'Regular'
            Description      = ("Evenly spaced roughly every {0} minutes - consistent with an automated service, scheduled task or sync client retrying on a timer" -f [math]::Round($median))
            MedianGapMinutes = [math]::Round($median, 2)
        }
    }

    return [PSCustomObject]@{
        Pattern          = 'Irregular'
        Description      = 'No consistent rhythm - consistent with human activity or several unrelated processes'
        MedianGapMinutes = [math]::Round($median, 2)
    }
}

function Get-OuiVendor {
    <#
    .SYNOPSIS
        Maps a MAC address prefix to a known equipment vendor.
    .DESCRIPTION
        The first three octets of a MAC are the IEEE Organizationally Unique Identifier.
        Recognizing appliance vendors matters because a firewall or VPN concentrator
        appears as one source IP for traffic originating from many machines - the bad
        password is not coming from "that device", it is passing through it.

        Returns empty for an unrecognized prefix rather than guessing.
    #>
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) { return '' }

    # Accept 00-09-0F-.., 00:09:0f:.., and 00090faabbcc alike.
    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean.Length -lt 6) { return '' }

    $prefix = $clean.Substring(0, 6)

    # A loaded IEEE registry wins - it is both larger and authoritative. The built-in
    # table stays as the offline fallback and for the appliance annotations it carries
    # (e.g. "VMware (virtual machine)") that the raw registry does not.
    if ($script:OuiDatabase -and $script:OuiDatabase.Count -gt 0 -and $script:OuiDatabase.ContainsKey($prefix)) {
        return $script:OuiDatabase[$prefix]
    }
    if ($script:OuiVendors.ContainsKey($prefix)) { return $script:OuiVendors[$prefix] }
    return ''
}

# =============================================================================
# Inventory cross-reference
#
# The whole point of this export is to be joined against records you already hold - RMM,
# Intune, an asset spreadsheet, a switch MAC table. Doing that join by hand in Excel on
# every investigation is the manual step this removes.
# =============================================================================

function ConvertTo-MacKey {
    <#
    .SYNOPSIS
        Reduces any MAC formatting to one comparable key.
    .DESCRIPTION
        The same adapter is written differently by every source: DHCP gives
        00-09-0F-11-22-33, Cisco gives 0009.0f11.2233, exports often give 00090F112233.
        Compared as strings these never match, so the join silently returns nothing -
        the worst kind of failure, because it looks like "no inventory record exists".
    #>
    param([string]$Mac)

    if ([string]::IsNullOrWhiteSpace($Mac)) { return '' }
    $clean = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    # A MAC is exactly 12 hex digits. Anything else is a serial number or free text.
    if ($clean.Length -ne 12) { return '' }
    return $clean
}

function Get-InventoryColumnMap {
    <#
    .SYNOPSIS
        Works out which columns of an arbitrary inventory CSV can be joined on.
    .DESCRIPTION
        Inventory exports have no standard schema - "ComputerName", "Device Name",
        "Hostname" and "Machine" all mean the same thing depending on the vendor.
        Detecting them means the user points at whatever their RMM produced rather than
        editing headers before every run.

        Matching is case-insensitive and ignores spaces and underscores, so
        "MAC_Address", "mac address" and "MACAddress" are all recognized.
    #>
    param([string[]]$Columns)

    $norm = { param($x) ($x -replace '[\s_-]', '').ToLowerInvariant() }

    $hostNames = @('computername','devicename','hostname','host','machinename','machine','name','systemname','clientname','deviceid')
    $macNames  = @('macaddress','mac','physicaladdress','ethernetaddress','hardwareaddress','wifimac','wiredmac')
    $ipNames   = @('ipaddress','ip','ipv4address','ipv4','lastknownip','ipaddresses')

    $result = [PSCustomObject]@{ Host = ''; Mac = ''; Ip = '' }

    foreach ($c in @($Columns)) {
        $n = & $norm $c
        if (-not $result.Host -and $hostNames -contains $n) { $result.Host = $c }
        if (-not $result.Mac  -and $macNames  -contains $n) { $result.Mac  = $c }
        if (-not $result.Ip   -and $ipNames   -contains $n) { $result.Ip   = $c }
    }

    return $result
}

function Join-InventoryRecord {
    <#
    .SYNOPSIS
        Finds the inventory row matching one source, and returns everything it holds.
    .DESCRIPTION
        Join keys are tried strongest-first:

          1. MAC   - survives renames, re-imaging and DHCP changes. The best key.
          2. Name  - good, but a machine renamed since the export will miss.
          3. IP    - weakest, because addresses are reassigned. Used only as a fallback.

        Every column of the matched row is returned, not a fixed subset, so whatever the
        user's inventory happens to carry - owner, location, asset tag, last check-in -
        lands in the export without this script needing to know about it.
    #>
    param(
        [object[]]$Inventory,
        [object]$ColumnMap,
        [string]$ResolvedName,
        [string]$MacAddress,
        [string]$SourceIp
    )

    $none = [PSCustomObject]@{ Matched = $false; MatchedOn = ''; Fields = @{} }
    if (-not $Inventory -or @($Inventory).Count -eq 0) { return $none }

    # 1. MAC.
    if ($ColumnMap.Mac -and $MacAddress) {
        $key = ConvertTo-MacKey -Mac $MacAddress
        if ($key) {
            foreach ($row in $Inventory) {
                if ((ConvertTo-MacKey -Mac ([string]$row.($ColumnMap.Mac))) -eq $key) {
                    return [PSCustomObject]@{ Matched = $true; MatchedOn = 'MAC'; Fields = (ConvertTo-FieldHash -Row $row) }
                }
            }
        }
    }

    # 2. Name. Compared on the short name so FQDN vs NetBIOS does not defeat it.
    if ($ColumnMap.Host -and $ResolvedName) {
        $short = (($ResolvedName -split '\.')[0] -replace '\$$', '')
        foreach ($row in $Inventory) {
            $invName = (([string]$row.($ColumnMap.Host) -split '\.')[0]).Trim()
            if ($invName -and $invName -ieq $short) {
                return [PSCustomObject]@{ Matched = $true; MatchedOn = 'Name'; Fields = (ConvertTo-FieldHash -Row $row) }
            }
        }
    }

    # 3. IP. Weakest key - an address may have been reassigned since the export was taken.
    if ($ColumnMap.Ip -and $SourceIp) {
        foreach ($row in $Inventory) {
            $invIp = ([string]$row.($ColumnMap.Ip)).Trim()
            if ($invIp -and $invIp -eq $SourceIp) {
                return [PSCustomObject]@{ Matched = $true; MatchedOn = 'IP'; Fields = (ConvertTo-FieldHash -Row $row) }
            }
        }
    }

    return $none
}

function ConvertTo-FieldHash {
    # Every column of an inventory row as a hashtable, so callers can surface any of them.
    param([object]$Row)
    $h = @{}
    foreach ($p in $Row.PSObject.Properties) { $h[$p.Name] = $p.Value }
    return $h
}

function Test-LeaseCoversTime {
    <#
    .SYNOPSIS
        Decides whether a DHCP lease was actually in force when a failure occurred.
    .DESCRIPTION
        A lease maps an address to a client FOR A WINDOW OF TIME. Matching a two-week-old
        failure against today's lease and reporting the name at High confidence asserts
        something the data does not support: on a busy DHCP scope the address may have
        belonged to a different machine when the failure happened, and the investigation
        then goes to the wrong desk.

        A RESERVATION is different. It pins an address to a MAC indefinitely, so there is
        no expiry to compare and the mapping was as true last month as it is today.
        https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4lease
    #>
    param(
        # Nullable: a reservation has no expiry, and a lease record may omit it. A plain
        # [datetime] throws on $null rather than letting the logic below handle it.
        [Nullable[datetime]]$LeaseExpires,
        [Nullable[datetime]]$FailureTime,
        [switch]$IsReservation
    )

    if ($IsReservation) {
        return [PSCustomObject]@{ Covers = $true; Reason = 'Reservation - a fixed address-to-MAC mapping with no expiry' }
    }

    if (-not $FailureTime -or $FailureTime -eq [datetime]::MinValue) {
        return [PSCustomObject]@{ Covers = $false; Reason = 'Failure time unknown - lease coverage cannot be confirmed' }
    }

    if (-not $LeaseExpires -or $LeaseExpires -eq [datetime]::MinValue) {
        return [PSCustomObject]@{ Covers = $false; Reason = 'Lease has no expiry recorded - coverage unknown' }
    }

    # The lease must not have expired BEFORE the failure. A lease expiring after the
    # failure was still in force at that moment.
    if ($LeaseExpires -lt $FailureTime) {
        return [PSCustomObject]@{
            Covers = $false
            Reason = "Lease expired $($LeaseExpires.ToString('yyyy-MM-dd HH:mm')) but the failure was $($FailureTime.ToString('yyyy-MM-dd HH:mm')) - the address may have belonged to another device then"
        }
    }

    return [PSCustomObject]@{ Covers = $true; Reason = 'Lease was in force when the failure occurred' }
}

function Get-ResolutionConfidence {
    <#
    .SYNOPSIS
        Rates how much to trust a resolved name, given how it was obtained.
    .DESCRIPTION
        A name is only as good as its source. Recording the method alongside the answer
        prevents a stale PTR record from being treated as hard evidence in a ticket.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('EventLogCorrelation', 'DhcpLease', 'DhcpReservation', 'ReverseDns', 'ActiveDirectory', 'Unresolved')]
        [string]$Method,

        # Whether the lease was actually in force when the failure happened. Defaults to
        # true so callers that cannot determine it keep the previous behaviour, but
        # Resolve-SourceIdentity always passes a real answer.
        [bool]$LeaseCoversFailure = $true
    )

    # A lease that cannot have covered the failure is not evidence of who held the
    # address then, no matter how current it looks now.
    if ($Method -eq 'DhcpLease' -and -not $LeaseCoversFailure) { return 'Low' }

    switch ($Method) {
        # The DC itself logged this name for this IP. Nothing beats that.
        'EventLogCorrelation' { 'High' }
        # A current lease is authoritative for the window it covers.
        'DhcpLease'           { 'High' }
        'DhcpReservation'     { 'Medium' }
        'ActiveDirectory'     { 'Medium' }
        # PTR records are frequently stale or absent on client subnets.
        'ReverseDns'          { 'Low' }
        'Unresolved'          { 'None' }
    }
}

function Resolve-DeviceClass {
    <#
    .SYNOPSIS
        Rolls the evidence for one source into a device category.
    .DESCRIPTION
        Turns "10.0.0.1, MAC 00-09-0F-.., no AD object" into "NetworkDevice (Fortinet)",
        which is the difference between chasing a phantom desktop and looking behind a
        firewall.

        Order matters: loopback is decided first because a local address can never be
        another machine, and appliance OUIs outrank a missing AD object because network
        gear is legitimately absent from AD.
    #>
    param(
        [string]$SourceIp,
        [string]$ResolvedName,
        [object]$AdComputer,
        [string]$OuiVendor
    )

    # Local activity on the DC itself - never a remote device.
    if ($SourceIp -eq '127.0.0.1' -or $SourceIp -eq '::1') {
        return [PSCustomObject]@{
            DeviceClass = 'LocalOrConsole'
            Detail      = 'Authentication originated on the domain controller itself'
        }
    }

    if ($AdComputer) {
        if ($AdComputer.IsDomainController) {
            return [PSCustomObject]@{
                DeviceClass = 'DomainController'
                Detail      = "Domain controller: $($AdComputer.Name)"
            }
        }
        $os = [string]$AdComputer.OperatingSystem
        if ($os -match 'Server') {
            return [PSCustomObject]@{
                DeviceClass = 'Server'
                Detail      = "Domain-joined server: $os"
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($os)) {
            return [PSCustomObject]@{
                DeviceClass = 'DomainJoinedWorkstation'
                Detail      = "Domain-joined workstation: $os"
            }
        }
        return [PSCustomObject]@{
            DeviceClass = 'DomainJoinedWorkstation'
            Detail      = "AD computer object exists; operating system not recorded"
        }
    }

    # Appliance OUIs are checked after AD (a domain-joined VM has a VMware OUI but is
    # still a workstation) and before "unknown" (network gear is rightly absent from AD).
    if (-not [string]::IsNullOrWhiteSpace($OuiVendor)) {
        return [PSCustomObject]@{
            DeviceClass = 'NetworkDevice'
            Detail      = "Hardware vendor $OuiVendor - may be a gateway masking the real source"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedName)) {
        return [PSCustomObject]@{
            DeviceClass = 'NonDomainDevice'
            Detail      = "Named '$ResolvedName' but has no Active Directory computer object"
        }
    }

    return [PSCustomObject]@{
        DeviceClass = 'Unknown'
        Detail      = 'No name from any source - cross-reference against switch MAC tables or RMM inventory'
    }
}

function Group-AuthSource {
    <#
    .SYNOPSIS
        Collapses per-event rows into one row per distinct source device.
    .DESCRIPTION
        This is the short list an investigator actually works from.

        Sources are keyed by IP where one exists, and by hostname otherwise, because
        4776 and 4740 carry a name with no address at all. Keying only on IP would
        silently drop every NTLM-only source.

        Names seen for an IP on ANY event type are carried across, which is how a bare
        Kerberos IP (4771 has no name field) inherits the workstation name recorded by a
        4625 from the same address.

        Sources that only ever succeeded are excluded - 4776 and 4771 are logged for both
        outcomes, and a healthy machine authenticating normally is not evidence.
    #>
    param([object[]]$Events)

    if (-not $Events -or $Events.Count -eq 0) { return @() }

    $keyed = $Events | ForEach-Object {
        $key = if (-not [string]::IsNullOrWhiteSpace($_.SourceIp)) {
            $_.SourceIp
        } elseif (-not [string]::IsNullOrWhiteSpace($_.SourceHost)) {
            $_.SourceHost
        } else {
            '(not recorded)'
        }
        $_ | Add-Member -NotePropertyName SourceKey -NotePropertyValue $key -PassThru -Force
    }

    $groups = foreach ($g in ($keyed | Group-Object -Property SourceKey)) {

        $failures = @($g.Group | Where-Object { $_.IsFailure })
        # A source with no failures is a healthy machine, not evidence.
        if ($failures.Count -eq 0) { continue }

        $names = @($g.Group |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.SourceHost) } |
            Select-Object -ExpandProperty SourceHost -Unique |
            Sort-Object)

        $accounts = @($failures |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.Account) } |
            Select-Object -ExpandProperty Account -Unique |
            Sort-Object)

        $ip = @($g.Group |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.SourceIp) } |
            Select-Object -ExpandProperty SourceIp -Unique)[0]

        $times = @($g.Group | Where-Object { $_.Time } | Select-Object -ExpandProperty Time | Sort-Object)

        # Timing separates an automated retry from a person - computed here because this
        # is the only place the full ordered list of times for the source exists.
        $timing = Get-SourceTimingPattern -Times @($failures | Where-Object { $_.Time } | Select-Object -ExpandProperty Time)

        [PSCustomObject]@{
            SourceKey        = $g.Name
            SourceIp         = if ($ip) { $ip } else { '' }
            TimingPattern    = $timing.Pattern
            TimingDetail     = $timing.Description
            MedianGapMinutes = $timing.MedianGapMinutes
            NamesSeenInLog   = ($names -join ', ')
            FailureCount     = $failures.Count
            TotalEvents      = $g.Group.Count
            DistinctAccounts = $accounts.Count
            Accounts         = ($accounts -join ', ')
            EventIds         = (@($failures | Select-Object -ExpandProperty EventId -Unique | Sort-Object) -join ', ')
            LogonTypes       = (@($failures |
                                  Where-Object { -not [string]::IsNullOrWhiteSpace($_.LogonTypeMeaning) } |
                                  Select-Object -ExpandProperty LogonTypeMeaning -Unique) -join '; ')
            TopStatus        = (@($failures |
                                  Where-Object { -not [string]::IsNullOrWhiteSpace($_.StatusMeaning) } |
                                  Group-Object StatusMeaning |
                                  Sort-Object Count -Descending |
                                  Select-Object -First 1 -ExpandProperty Name))
            DCsSeen          = (@($g.Group | Select-Object -ExpandProperty DC -Unique | Sort-Object) -join ', ')
            FirstSeen        = if ($times.Count) { $times[0] } else { $null }
            LastSeen         = if ($times.Count) { $times[-1] } else { $null }
        }
    }

    # Most failures first - the device to chase is at the top.
    @($groups) | Sort-Object -Property FailureCount, DistinctAccounts -Descending
}

# =============================================================================
# Collection
# =============================================================================

function Get-TargetDomainController {
    <#
    .SYNOPSIS
        Returns the DCs to query, discovering them from AD unless explicitly supplied.
    .DESCRIPTION
        Bad passwords land on whichever DC the client happened to contact, so querying
        one DC finds a fraction of the evidence. Discovery is preferred over a hardcoded
        list because a DC added since the last run would otherwise be silently skipped.
    #>
    param([string[]]$Explicit)

    if ($Explicit -and $Explicit.Count -gt 0) { return $Explicit }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop |
                 Select-Object -ExpandProperty HostName | Sort-Object)
        if ($dcs.Count -eq 0) { throw 'Get-ADDomainController returned no results' }
        return $dcs
    } catch {
        Write-Status "Could not enumerate domain controllers: $($_.Exception.Message)" 'FAIL'
        Write-Status "Supply -DomainController explicitly to continue." 'INFO'
        return @()
    }
}

function Get-SecurityLogCoverage {
    <#
    .SYNOPSIS
        Reports how far back the Security log on a DC actually reaches.
    .DESCRIPTION
        The Security log wraps. A 30-day request against a log that holds 4 days returns
        4 days of data and looks exactly like a quiet month. Reporting the true coverage
        turns a silently truncated result into a visible one.
    #>
    param([string]$ComputerName)

    try {
        $oldest = Get-WinEvent -ComputerName $ComputerName -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        return [PSCustomObject]@{
            OldestEvent = $oldest.TimeCreated
            DaysHeld    = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 1)
        }
    } catch {
        return $null
    }
}

function Get-AuthEventFromDc {
    <#
    .SYNOPSIS
        Pulls the requested event IDs from one DC and normalizes them.
    .DESCRIPTION
        Wrapped so a single unreachable or slow DC degrades the result rather than
        halting the run. A partial export that names its gaps is more useful than no
        export at all.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int[]]$EventIds,
        [Parameter(Mandatory)][datetime]$StartTime
    )

    $filter = @{
        LogName   = 'Security'
        Id        = $EventIds
        StartTime = $StartTime
    }

    # -ErrorAction Stop so the caller's catch sees connection failures; NoRecordsFound
    # is a normal outcome and handled separately.
    $events = @()
    try {
        $events = @(Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return @()
        }
        throw
    }

    foreach ($evt in $events) {
        try {
            ConvertFrom-AuthEvent -EventXml $evt.ToXml() -EventId $evt.Id -DcName $ComputerName
        } catch {
            Write-Verbose "Skipping unparsable event $($evt.RecordId) on ${ComputerName}: $($_.Exception.Message)"
        }
    }
}

function New-IpCorrelationXPath {
    <#
    .SYNOPSIS
        Builds an XPath query selecting successful logons from a specific set of IPs.
    .DESCRIPTION
        WHY THIS EXISTS - THE ALTERNATIVE HANGS THE SCRIPT.

        Naming an IP requires finding a successful logon (4624/4768) from that address.
        Pulling every success in the window and filtering client-side is catastrophic on
        a domain controller: 4624 is the highest-volume event in the Security log by a
        wide margin (every file share access, every service ticket, every machine account
        re-authenticating on its own schedule). A DC holding only a few days of log can
        still hold hundreds of thousands of them, and Get-WinEvent materializes the whole
        set over RPC before a single row is examined. The script appears to hang.

        Pushing the address list into the query makes the DC do the filtering and return
        only matching events - typically a handful.

        BATCHING IS MANDATORY, NOT AN OPTIMIZATION.

        Windows Event Log supports a subset of XPath 1.0 and rejects any compound
        expression containing more than 20 expressions with "The specified query is
        invalid". Verified empirically against a live log: 20 terms succeed, 22 fail.

        EACH ADDRESS COSTS TWO TERMS, not one, because both the plain and the IPv4-mapped
        form must be matched. The effective ceiling is therefore 10 ADDRESSES per query -
        verified empirically: 10 addresses (20 terms) succeed, 11 (22 terms) fail.
        https://learn.microsoft.com/windows/win32/wes/consuming-events

        Note that a <named-data> FilterHashtable key (@{IpAddress='10.0.0.1'}) does NOT
        work reliably against the Security log - it silently matches zero events rather
        than erroring, because that form depends on provider manifest metadata. Silent
        emptiness is the worst possible failure here, so this uses structural XPath
        against Data[@Name='IpAddress'] instead.
    #>
    param(
        [Parameter(Mandatory)][string[]]$IpAddress,
        [Parameter(Mandatory)][int[]]$EventIds,
        [Parameter(Mandatory)][datetime]$StartTime
    )

    # 10, not 20: each address expands to two OR terms (plain and ::ffff: forms) and the
    # Windows Event Log XPath ceiling is 20 expressions.
    if ($IpAddress.Count -gt 10) {
        throw "New-IpCorrelationXPath accepts at most 10 addresses per query (each expands to 2 XPath terms against a 20-expression limit); got $($IpAddress.Count). Batch the list before calling."
    }

    # Escape single quotes so a malformed address cannot break out of the literal.
    $ipTerms = ($IpAddress | ForEach-Object {
        $safe = $_ -replace "'", "''"
        # 4771/4768 render addresses IPv4-mapped, 4624 usually plain. The log stores what
        # it stored, so both forms must be matched to find every success for an address.
        "Data[@Name='IpAddress']='$safe' or Data[@Name='IpAddress']='::ffff:$safe'"
    }) -join ' or '

    $idTerms = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '

    # timediff against the current time, in milliseconds, is the documented way to bound
    # an XPath query by age.
    $ageMs = [math]::Max(1, [long]((Get-Date) - $StartTime).TotalMilliseconds)

    "*[System[($idTerms) and TimeCreated[timediff(@SystemTime) <= $ageMs]] and EventData[$ipTerms]]"
}

function Get-IpNameMapBySweep {
    <#
    .SYNOPSIS
        Builds an IP-to-name map from one bounded pass over recent successful logons.
    .DESCRIPTION
        THE DEFAULT CORRELATION STRATEGY, because its cost is FIXED and PREDICTABLE.

        The obvious approach - query the log once per unresolved IP - has a fatal
        property at scale: an IP that does NOT appear in the log cannot be found early,
        so the log must read every record to prove its absence. Measured on a production
        DC holding 742,767 records: a single non-matching IP cost 11 seconds, and a batch
        of 20 OR-terms cost 52 seconds. With three batches of unresolvable addresses that
        is over two and a half minutes of apparent hang - and it grows with the number of
        addresses you cannot resolve, which is exactly the case you are trying to fix.

        This function inverts the problem. It reads a capped, time-bounded window of
        4624/4768 events ONCE, indexed by StartTime (which the log satisfies from its
        time index, unlike an EventData predicate), and builds the whole IP-to-name map
        in memory. Cost is bounded by -MaxEvents no matter how many IPs are unresolved.

        The trade-off is honest and worth stating: a sweep sees only the most recent
        -MaxEvents successes, so an IP whose only successful logon falls outside that
        window goes unnamed. Unnamed is the status quo for those addresses anyway, and
        DHCP/DNS/AD still get their turn. A bounded partial answer beats an unbounded
        complete one.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [int]$MaxEvents = 20000
    )

    $map = @{}

    try {
        # StartTime in a FilterHashtable is served from the log's time index. Measured at
        # 0.9s against the same 742k-record log where EventData predicates took 52s.
        $events = @(Get-WinEvent -ComputerName $ComputerName `
                                 -FilterHashtable @{ LogName = 'Security'; Id = @(4624, 4768); StartTime = $StartTime } `
                                 -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found') { return $map }
        throw
    }

    foreach ($evt in $events) {
        try {
            $row = ConvertFrom-AuthEvent -EventXml $evt.ToXml() -EventId $evt.Id -DcName $ComputerName
            if ($row.SourceIp -and -not [string]::IsNullOrWhiteSpace($row.SourceHost)) {
                if (-not $map.ContainsKey($row.SourceIp)) {
                    # Machine accounts appear as WKS01$; the bare name is what joins
                    # against DHCP, DNS and AD.
                    $map[$row.SourceIp] = ($row.SourceHost -replace '\$$', '')
                }
            }
        } catch {
            Write-Verbose "Unparsable sweep event on ${ComputerName}: $($_.Exception.Message)"
        }
    }

    return $map
}

function Get-IpNameCorrelation {
    <#
    .SYNOPSIS
        Finds a workstation name for each supplied IP from successful logon events.
    .DESCRIPTION
        Returns a hashtable of normalized IP -> workstation name.

        Addresses are queried in batches of 20 (the XPath expression ceiling), and each
        batch is independently wrapped so one failed batch costs only its own addresses
        rather than the whole correlation pass.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string[]]$IpAddress,
        [Parameter(Mandatory)][datetime]$StartTime,
        [int]$MaxEventsPerBatch = 2000,
        # Abandon the whole correlation pass after this long. Correlation is an
        # ENRICHMENT step - an unnamed IP is still perfectly usable evidence, so it must
        # never be allowed to consume the run. Zero disables the budget.
        [int]$TimeBudgetSeconds = 120
    )

    $found = @{}
    if (-not $IpAddress -or $IpAddress.Count -eq 0) { return $found }

    $sw = [Diagnostics.Stopwatch]::StartNew()

    # 10 addresses per query - see New-IpCorrelationXPath for the term-count arithmetic.
    $batchSize = 10
    $batchTotal = [math]::Ceiling($IpAddress.Count / $batchSize)
    $batchNum = 0

    for ($i = 0; $i -lt $IpAddress.Count; $i += $batchSize) {
        $batch = @($IpAddress[$i..([math]::Min($i + $batchSize - 1, $IpAddress.Count - 1))])
        $batchNum++

        if ($TimeBudgetSeconds -gt 0 -and $sw.Elapsed.TotalSeconds -ge $TimeBudgetSeconds) {
            Write-Status ("Correlation time budget (${TimeBudgetSeconds}s) reached on $ComputerName after $($batchNum - 1) of $batchTotal batch(es) - continuing with $($found.Count) name(s) found. Raise -CorrelationTimeoutSeconds, or omit -EnableCorrelation to skip this pass.") 'WARN'
            break
        }

        # Progress on every batch, so a slow DC shows as slow rather than as a hang.
        Write-Progress -Activity "Correlating IPs on $ComputerName" `
                       -Status "Batch $batchNum of $batchTotal ($($found.Count) named so far)" `
                       -PercentComplete ([int](100 * ($batchNum - 1) / [math]::Max(1, $batchTotal)))

        try {
            $xpath = New-IpCorrelationXPath -IpAddress $batch -EventIds @(4624, 4768) -StartTime $StartTime

            # -MaxEvents caps the worst case: a single hammering address could otherwise
            # still return a very large set.
            $events = @(Get-WinEvent -ComputerName $ComputerName -LogName Security `
                                     -FilterXPath $xpath -MaxEvents $MaxEventsPerBatch -ErrorAction Stop)

            foreach ($evt in $events) {
                try {
                    $row = ConvertFrom-AuthEvent -EventXml $evt.ToXml() -EventId $evt.Id -DcName $ComputerName
                    if ($row.SourceIp -and
                        -not [string]::IsNullOrWhiteSpace($row.SourceHost) -and
                        -not $found.ContainsKey($row.SourceIp)) {
                        # Machine accounts appear as WKS01$; the bare name is what joins
                        # against DHCP, DNS and AD.
                        $found[$row.SourceIp] = ($row.SourceHost -replace '\$$', '')
                    }
                } catch {
                    Write-Verbose "Unparsable correlation event on ${ComputerName}: $($_.Exception.Message)"
                }
            }
        } catch {
            if ($_.Exception.Message -match 'No events were found') { continue }
            Write-Verbose "Correlation batch failed on ${ComputerName}: $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity "Correlating IPs on $ComputerName" -Completed
    return $found
}

function Get-DhcpLeaseIndex {
    <#
    .SYNOPSIS
        Builds an IP-to-lease lookup from every authorized DHCP server.
    .DESCRIPTION
        DHCP is the highest-value external source here because it supplies BOTH a
        hostname and a MAC address. The MAC is what survives a DHCP renewal and what
        matches a switch table, and its OUI identifies appliances.

        Servers are discovered via Get-DhcpServerInDC rather than hardcoded, per repo
        convention. Each server is queried in its own try/catch so one dead server does
        not cost the whole index.
        https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverindc
    #>
    param([string[]]$Explicit)

    $index = @{}

    try {
        Import-Module DhcpServer -ErrorAction Stop
    } catch {
        Write-Status "DhcpServer module unavailable - skipping DHCP lookups. Install RSAT DHCP tools or use -SkipDhcp to silence this." 'WARN'
        return $index
    }

    $servers = @()
    if ($Explicit -and $Explicit.Count -gt 0) {
        $servers = $Explicit
    } else {
        try {
            $servers = @(Get-DhcpServerInDC -ErrorAction Stop | Select-Object -ExpandProperty DnsName)
        } catch {
            Write-Status "Could not enumerate authorized DHCP servers: $($_.Exception.Message)" 'WARN'
            return $index
        }
    }

    if ($servers.Count -eq 0) {
        Write-Status "No DHCP servers found in AD. Supply -DhcpServer explicitly if DHCP runs on unregistered or non-Windows equipment." 'WARN'
        return $index
    }

    foreach ($server in $servers) {
        try {
            $scopes = @(Get-DhcpServerv4Scope -ComputerName $server -ErrorAction Stop)
            $leaseCount = 0

            foreach ($scope in $scopes) {
                try {
                    # -AllLeases is REQUIRED for historical work. Without it the cmdlet
                    # returns only ACTIVE leases, so a device whose lease expired days ago
                    # is invisible - which is exactly the case an old failure needs.
                    # https://learn.microsoft.com/powershell/module/dhcpserver/get-dhcpserverv4lease
                    foreach ($lease in @(Get-DhcpServerv4Lease -ComputerName $server -ScopeId $scope.ScopeId -AllLeases -ErrorAction Stop)) {
                        $ip = [string]$lease.IPAddress
                        if ([string]::IsNullOrWhiteSpace($ip)) { continue }

                        # A reservation is a stable mapping; a lease is only true for its
                        # window. Recording which one answered feeds the confidence rating.
                        $method = if ($lease.AddressState -match 'Reservation') { 'DhcpReservation' } else { 'DhcpLease' }

                        $index[$ip] = [PSCustomObject]@{
                            HostName     = ($lease.HostName -replace '\.$', '')
                            MacAddress   = [string]$lease.ClientId
                            LeaseExpires = $lease.LeaseExpiryTime
                            AddressState = [string]$lease.AddressState
                            DhcpServer   = $server
                            Scope        = [string]$scope.ScopeId
                            Method       = $method
                        }
                        $leaseCount++
                    }
                } catch {
                    Write-Verbose "Scope $($scope.ScopeId) on ${server}: $($_.Exception.Message)"
                }
            }

            Write-Status "DHCP $server - $leaseCount leases across $($scopes.Count) scopes" 'PASS'
        } catch {
            Write-Status "DHCP $server unreachable: $($_.Exception.Message)" 'WARN'
        }
    }

    return $index
}

function Resolve-SourceIdentity {
    <#
    .SYNOPSIS
        Runs one source IP through the resolution chain and returns everything learned.
    .DESCRIPTION
        Sources are tried strongest-first and the chain stops at the first name found,
        but every source that CAN answer still contributes its extra fields - a DHCP hit
        supplies the MAC even when the event log already supplied the name, because the
        MAC is what matches a switch table.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceKey,
        [string]$SourceIp,
        [string]$NamesFromLog,
        [hashtable]$DhcpIndex,
        [switch]$NoDns,
        # When this source's failures occurred, used to test whether a DHCP lease was
        # actually in force at the time. Without it a lease can only be reported as
        # "coverage unknown".
        [Nullable[datetime]]$LastFailureTime
    )

    $name       = ''
    $method     = 'Unresolved'
    $mac        = ''
    $vendor     = ''
    $leaseInfo  = ''
    $ptrName    = ''
    $leaseCovers = $true
    $leaseNote   = ''

    # 1. Event log correlation - the DC's own record of that address.
    if (-not [string]::IsNullOrWhiteSpace($NamesFromLog)) {
        $name   = ($NamesFromLog -split ',')[0].Trim()
        $method = 'EventLogCorrelation'
    }

    # 2. DHCP. Queried even when a name is already known, for the MAC address.
    if ($SourceIp -and $DhcpIndex -and $DhcpIndex.ContainsKey($SourceIp)) {
        $lease = $DhcpIndex[$SourceIp]
        $mac    = $lease.MacAddress
        $vendor = Get-OuiVendor -MacAddress $mac
        $leaseInfo = "$($lease.AddressState) on $($lease.DhcpServer) scope $($lease.Scope)"
        if ($lease.LeaseExpires) { $leaseInfo += " (expires $($lease.LeaseExpires))" }

        # Was this lease actually in force when the failures happened? A current lease
        # says nothing about who held the address two weeks ago.
        $expires = $null
        if ($lease.LeaseExpires) { $expires = [datetime]$lease.LeaseExpires }
        $coverage = Test-LeaseCoversTime -LeaseExpires $expires `
                                         -FailureTime $LastFailureTime `
                                         -IsReservation:($lease.Method -eq 'DhcpReservation')
        $leaseCovers = $coverage.Covers
        $leaseNote   = $coverage.Reason
        if (-not $coverage.Covers) { $leaseInfo += " [$($coverage.Reason)]" }

        if ([string]::IsNullOrWhiteSpace($name) -and -not [string]::IsNullOrWhiteSpace($lease.HostName)) {
            $name   = $lease.HostName
            $method = $lease.Method
        }
    }

    # 3. Reverse DNS. Last resort for a name - PTR records go stale.
    if ([string]::IsNullOrWhiteSpace($name) -and $SourceIp -and -not $NoDns) {
        try {
            $ptr = [System.Net.Dns]::GetHostEntry($SourceIp)
            if ($ptr -and -not [string]::IsNullOrWhiteSpace($ptr.HostName)) {
                $ptrName = $ptr.HostName
                $name    = ($ptr.HostName -split '\.')[0]
                $method  = 'ReverseDns'
            }
        } catch {
            # No PTR record is the common case on client subnets, not an error.
            Write-Verbose "No PTR for ${SourceIp}"
        }
    }

    # 4. AD computer object - confirms domain membership and supplies OS/OU context.
    $adComputer = $null
    $lookupName = if (-not [string]::IsNullOrWhiteSpace($name)) { $name } else { $SourceKey }
    if (-not [string]::IsNullOrWhiteSpace($lookupName) -and $lookupName -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $short = ($lookupName -split '\.')[0] -replace '\$$', ''
        try {
            $ad = Get-ADComputer -Identity $short -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, DistinguishedName, Enabled, Description -ErrorAction Stop
            $adComputer = [PSCustomObject]@{
                Name               = $ad.Name
                OperatingSystem    = $ad.OperatingSystem
                OperatingSystemVer = $ad.OperatingSystemVersion
                LastLogonDate      = $ad.LastLogonDate
                DistinguishedName  = $ad.DistinguishedName
                Enabled            = $ad.Enabled
                Description        = $ad.Description
                # Domain controllers live in the OU of the same name; this is the
                # locale-independent way to spot one from its DN.
                IsDomainController = ($ad.DistinguishedName -match 'OU=Domain Controllers')
            }
            if ($method -eq 'Unresolved') { $method = 'ActiveDirectory' }
        } catch {
            Write-Verbose "No AD computer object for ${short}"
        }
    }

    $class = Resolve-DeviceClass -SourceIp $SourceIp -ResolvedName $name -AdComputer $adComputer -OuiVendor $vendor

    [PSCustomObject]@{
        ResolvedName       = $name
        ResolutionMethod   = $method
        Confidence         = Get-ResolutionConfidence -Method $method -LeaseCoversFailure $leaseCovers
        MacAddress         = $mac
        MacVendor          = $vendor
        DhcpLease          = $leaseInfo
        LeaseCoversFailure = $leaseCovers
        LeaseCoverageNote  = $leaseNote
        ReverseDnsName     = $ptrName
        DeviceClass        = $class.DeviceClass
        DeviceDetail       = $class.Detail
        AdOperatingSystem  = if ($adComputer) { $adComputer.OperatingSystem } else { '' }
        AdLastLogonDate    = if ($adComputer) { $adComputer.LastLogonDate } else { $null }
        AdDistinguishedName= if ($adComputer) { $adComputer.DistinguishedName } else { '' }
        AdEnabled          = if ($adComputer) { $adComputer.Enabled } else { '' }
        AdDescription      = if ($adComputer) { $adComputer.Description } else { '' }
    }
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    # Same folder name the orchestrator uses, so output from a standalone run lands
    # alongside full investigations instead of in a separate per-tool Reports folder.
    $OutputPath = Join-Path $PSScriptRoot 'Account Lockout Diagnostics'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$stamp     = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$startTime = (Get-Date).AddDays(-$DaysBack)

Write-Host ''
Write-Status "AD authentication source evidence export" 'INFO'
Write-Status "Window: last $DaysBack days (since $($startTime.ToString('yyyy-MM-dd HH:mm:ss')))" 'INFO'
Write-Host ''

# --- Domain controllers -------------------------------------------------------
$dcs = Get-TargetDomainController -Explicit $DomainController
if ($dcs.Count -eq 0) {
    Write-Status "No domain controllers to query. Aborting." 'FAIL'
    exit 1
}
Write-Status "Querying $($dcs.Count) domain controller(s): $($dcs -join ', ')" 'INFO'
Write-Host ''

# --- Collect failure events ---------------------------------------------------
# 4740 is included because its caller NAME sometimes identifies a source that produced
# no IP-bearing event at all.
$failureEventIds = @(4625, 4771, 4776, 4740)

$allEvents  = New-Object System.Collections.Generic.List[object]
$dcCoverage = New-Object System.Collections.Generic.List[object]
$failedDcs  = New-Object System.Collections.Generic.List[string]

# Collection is dominated by waiting on each DC, so DCs are queried concurrently. Each
# runspace carries its own copy of the parsing functions - runspaces do not inherit the
# caller's function table - and returns a result object rather than writing to the
# console, so output stays ordered instead of interleaving.
$workerScript = {
    param(
        [string]$ComputerName,
        [int[]]$EventIds,
        [datetime]$StartTime,
        [int]$DaysBack,
        [string]$FunctionDefs
    )

    # Rehydrate the parsing helpers inside this runspace.
    . ([scriptblock]::Create($FunctionDefs))

    $out = [PSCustomObject]@{
        DC          = $ComputerName
        Rows        = @()
        OldestEvent = $null
        DaysHeld    = $null
        Error       = ''
    }

    try {
        try {
            $oldest = Get-WinEvent -ComputerName $ComputerName -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
            $out.OldestEvent = $oldest.TimeCreated
            $out.DaysHeld    = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 1)
        } catch {
            # Coverage reporting is best-effort; never let it cost the collection.
        }

        $events = @()
        try {
            $events = @(Get-WinEvent -ComputerName $ComputerName `
                                     -FilterHashtable @{ LogName = 'Security'; Id = $EventIds; StartTime = $StartTime } `
                                     -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -notmatch 'No events were found') { throw }
        }

        $rows = foreach ($evt in $events) {
            try { ConvertFrom-AuthEvent -EventXml $evt.ToXml() -EventId $evt.Id -DcName $ComputerName } catch { }
        }
        $out.Rows = @($rows)
    } catch {
        $out.Error = $_.Exception.Message
    }

    return $out
}

# The functions each runspace needs, extracted from this script's own definitions so
# there is exactly one copy of the parsing logic to maintain.
$fnNames = @('ConvertFrom-AuthEvent', 'ConvertTo-NormalizedIp', 'Get-StatusMeaning', 'Test-IsFailureStatus')
$fnDefs  = ($fnNames | ForEach-Object {
    "function $_ {`n$((Get-Command $_ -CommandType Function).Definition)`n}"
}) -join "`n"

# Constants the rehydrated functions close over.
$constDefs = @"
`$script:SuccessStatusCodes = @($(($script:SuccessStatusCodes | ForEach-Object { "'$_'" }) -join ','))
`$script:StatusCodes = @{$(($script:StatusCodes.GetEnumerator() | ForEach-Object { "'$($_.Key)'=" + "'" + ($_.Value -replace "'","''") + "'" }) -join ';')}
`$script:LogonTypes = @{$(($script:LogonTypes.GetEnumerator() | ForEach-Object { "$($_.Key)=" + "'" + ($_.Value -replace "'","''") + "'" }) -join ';')}
"@
$fnDefs = $constDefs + "`n" + $fnDefs

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$jobs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($dc in $dcs) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($workerScript)
    [void]$ps.AddParameter('ComputerName', $dc)
    [void]$ps.AddParameter('EventIds',     $failureEventIds)
    [void]$ps.AddParameter('StartTime',    $startTime)
    [void]$ps.AddParameter('DaysBack',     $DaysBack)
    [void]$ps.AddParameter('FunctionDefs', $fnDefs)
    $jobs.Add(@{ PowerShell = $ps; Handle = $ps.BeginInvoke(); DC = $dc })
}

if ($ThrottleLimit -gt 1 -and $dcs.Count -gt 1) {
    Write-Status "Querying $($dcs.Count) DC(s), $ThrottleLimit at a time..." 'INFO'
}

$done = 0
$remaining = [System.Collections.Generic.List[hashtable]]::new($jobs)
while ($remaining.Count -gt 0) {
    $completed = @($remaining | Where-Object { $_.Handle.IsCompleted })

    foreach ($job in $completed) {
        $done++
        Write-Progress -Activity 'Collecting from domain controllers' `
                       -Status "$done of $($jobs.Count) complete" `
                       -PercentComplete ([int](100 * $done / [math]::Max(1, $jobs.Count)))
        try {
            $res = $job.PowerShell.EndInvoke($job.Handle) | Select-Object -First 1

            if ($res -and $res.Error) {
                $failedDcs.Add($job.DC)
                Write-Status "$($job.DC) - collection failed: $($res.Error)" 'FAIL'
            } elseif ($res) {
                if ($res.OldestEvent) {
                    $dcCoverage.Add([PSCustomObject]@{ DC = $job.DC; OldestEvent = $res.OldestEvent; DaysHeld = $res.DaysHeld })
                    if ($res.DaysHeld -lt $DaysBack) {
                        Write-Status "$($job.DC) - Security log only reaches back $($res.DaysHeld) days; the $DaysBack-day window is truncated here" 'WARN'
                    }
                }
                foreach ($r in @($res.Rows)) { $allEvents.Add($r) }
                Write-Status "$($job.DC) - $(@($res.Rows).Count) authentication events collected" 'PASS'
            } else {
                $failedDcs.Add($job.DC)
                Write-Status "$($job.DC) - returned no result" 'WARN'
            }
        } catch {
            $failedDcs.Add($job.DC)
            Write-Status "$($job.DC) - collection failed: $($_.Exception.Message)" 'FAIL'
        } finally {
            $job.PowerShell.Dispose()
            [void]$remaining.Remove($job)
        }
    }

    if ($remaining.Count -gt 0) { Start-Sleep -Milliseconds 200 }
}

Write-Progress -Activity 'Collecting from domain controllers' -Completed
$pool.Close()
$pool.Dispose()

Write-Host ''

$failureRows = @($allEvents | Where-Object { $_.IsFailure })

if ($failureRows.Count -eq 0) {
    Write-Status "No authentication FAILURES found in the window." 'WARN'
    Write-Status "Before concluding the domain is clean, run Test-ADAuditPolicy.ps1 - if failure auditing is disabled, this result is a tooling artifact, not a clean bill of health." 'WARN'
    if ($failedDcs.Count -gt 0) {
        Write-Status "Note that $($failedDcs.Count) DC(s) could not be queried: $($failedDcs -join ', ')" 'WARN'
    }
    exit 0
}

Write-Status "$($failureRows.Count) failure events from $($allEvents.Count) total collected" 'INFO'

# --- Group into distinct sources ---------------------------------------------
$sources = @(Group-AuthSource -Events $allEvents)
Write-Status "$($sources.Count) distinct source device(s) identified" 'INFO'
Write-Host ''

# --- Correlation pass: name the bare IPs -------------------------------------
# Only IPs that appear in failures and still have no name are worth the query, so the
# success-event pull stays narrow instead of dragging in every 4624 on the domain.
$unnamedIps = @($sources |
    Where-Object { $_.SourceIp -and [string]::IsNullOrWhiteSpace($_.NamesSeenInLog) } |
    Select-Object -ExpandProperty SourceIp -Unique)

$correlatedNames = @{}
if (-not $EnableCorrelation -and $unnamedIps.Count -gt 0) {
    # Default path. Event-log correlation is off because reading 4624/4768 events proved
    # pathologically slow on a real DC - see the CORRELATION PERFORMANCE note in .NOTES.
    Write-Status "$($unnamedIps.Count) IP(s) have no name from the failure events; resolving via DHCP/DNS/AD. (Event-log correlation is off by default - see -EnableCorrelation.)" 'INFO'
}
if ($unnamedIps.Count -gt 0 -and $EnableCorrelation) {

    # STRATEGY: one bounded sweep per DC, NOT one query per unresolved IP.
    #
    # Measured on a production DC with 742,767 Security records: an EventData predicate
    # that matches nothing must read every record to prove absence - 11s for a single IP,
    # 52s for a 20-term batch. Cost therefore GROWS with the number of addresses you
    # cannot resolve, which is precisely the population this pass exists to handle.
    #
    # A StartTime-bounded sweep is served from the log's time index instead (0.9s on the
    # same log) and its cost is capped by -CorrelationMaxEvents regardless of how many
    # IPs are unresolved. See Get-IpNameMapBySweep.
    Write-Status "Correlating $($unnamedIps.Count) unnamed IP(s) against successful logons (4624/4768)..." 'INFO'

    foreach ($dc in $dcs) {
        if ($failedDcs -contains $dc) { continue }

        # Stop early once every address has a name; remaining DCs cannot improve on that.
        $stillUnnamed = @($unnamedIps | Where-Object { -not $correlatedNames.ContainsKey($_) })
        if ($stillUnnamed.Count -eq 0) { break }

        $swCorr = [Diagnostics.Stopwatch]::StartNew()
        try {
            if ($UseTargetedCorrelation) {
                # Opt-in legacy path: one query per batch of addresses. Faster ONLY when
                # most addresses genuinely appear in the log; pathological otherwise.
                $names = Get-IpNameCorrelation -ComputerName $dc -IpAddress $stillUnnamed `
                                               -StartTime $startTime -TimeBudgetSeconds $CorrelationTimeoutSeconds
            } else {
                $map = Get-IpNameMapBySweep -ComputerName $dc -StartTime $startTime -MaxEvents $CorrelationMaxEvents
                # Keep only the addresses actually under investigation.
                $names = @{}
                foreach ($ip in $stillUnnamed) {
                    if ($map.ContainsKey($ip)) { $names[$ip] = $map[$ip] }
                }
                Write-Verbose "$dc sweep produced $($map.Count) IP->name mappings; $($names.Count) matched an unnamed source"
            }

            foreach ($k in $names.Keys) {
                if (-not $correlatedNames.ContainsKey($k)) { $correlatedNames[$k] = $names[$k] }
            }
            $swCorr.Stop()
            Write-Status ("$dc - named {0} of {1} remaining IP(s) in {2:N1}s" -f $names.Count, $stillUnnamed.Count, $swCorr.Elapsed.TotalSeconds) 'PASS'
        } catch {
            $swCorr.Stop()
            Write-Status "$dc - success correlation failed: $($_.Exception.Message)" 'WARN'
        }
    }
    Write-Status "Named $($correlatedNames.Count) of $($unnamedIps.Count) unnamed IP(s) from the event log" 'PASS'
}

# -IncludeSuccesses adds successful logons for the IPs ALREADY under investigation, so a
# suspect device gets a full timeline (what it authenticated as successfully, alongside
# what failed).
#
# WARNING: this reads 4624/4768 events, the same operation that makes correlation slow
# enough to be disabled by default. On a DC where that is slow, this switch will be slow
# too. It is opt-in, so the default run never pays that cost.
if ($IncludeSuccesses) {
    $suspectIps = @($sources | Where-Object { $_.SourceIp } | Select-Object -ExpandProperty SourceIp -Unique)
    if ($suspectIps.Count -gt 0) {
        Write-Host ''
        Write-Status "Collecting successful logons for $($suspectIps.Count) source IP(s) (-IncludeSuccesses)..." 'INFO'
        Write-Status "This reads 4624/4768 events and may be slow on a busy DC - the same reason event-log correlation is off by default." 'WARN'
        foreach ($dc in $dcs) {
            if ($failedDcs -contains $dc) { continue }
            # Same bounded-sweep reasoning as the correlation pass: read a capped,
            # time-indexed window once and keep the rows for suspect addresses, rather
            # than issuing per-IP queries that each risk a full log scan.
            $added = 0
            try {
                $suspectSet = @{}
                foreach ($ip in $suspectIps) { $suspectSet[$ip] = $true }

                foreach ($evt in @(Get-WinEvent -ComputerName $dc `
                                                -FilterHashtable @{ LogName='Security'; Id=@(4624,4768); StartTime=$startTime } `
                                                -MaxEvents $CorrelationMaxEvents -ErrorAction Stop)) {
                    try {
                        $row = ConvertFrom-AuthEvent -EventXml $evt.ToXml() -EventId $evt.Id -DcName $dc
                        if ($row.SourceIp -and $suspectSet.ContainsKey($row.SourceIp)) {
                            $allEvents.Add($row)
                            $added++
                        }
                    } catch { }
                }
            } catch {
                if ($_.Exception.Message -notmatch 'No events were found') {
                    Write-Verbose "Success collection failed on ${dc}: $($_.Exception.Message)"
                }
            }
            Write-Status "$dc - $added successful logon(s) added" 'PASS'
        }
    }
}

# --- DHCP index ---------------------------------------------------------------
if ($OuiDatabasePath) {
    $script:OuiDatabase = Import-OuiDatabase -Path $OuiDatabasePath
    if ($script:OuiDatabase.Count -gt 0) {
        Write-Status "OUI database loaded: $($script:OuiDatabase.Count) vendor prefixes" 'PASS'
    } else {
        Write-Status "Could not read OUI database at $OuiDatabasePath - falling back to the built-in vendor table" 'WARN'
    }
}

$dhcpIndex = @{}
if (-not $SkipDhcp) {
    Write-Host ''
    Write-Status "Building DHCP lease index..." 'INFO'
    $dhcpIndex = Get-DhcpLeaseIndex -Explicit $DhcpServer
    Write-Status "$($dhcpIndex.Count) DHCP address mappings indexed" 'INFO'
}

# --- Resolve every source -----------------------------------------------------
Write-Host ''
Write-Status "Resolving source identities..." 'INFO'

try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
    Write-Status "ActiveDirectory module unavailable - AD computer lookups will be skipped." 'WARN'
}

$resolvedSources = foreach ($src in $sources) {
    $namesFromLog = $src.NamesSeenInLog
    if ([string]::IsNullOrWhiteSpace($namesFromLog) -and $src.SourceIp -and $correlatedNames.ContainsKey($src.SourceIp)) {
        $namesFromLog = $correlatedNames[$src.SourceIp]
    }

    $identity = Resolve-SourceIdentity -SourceKey $src.SourceKey `
                                       -SourceIp $src.SourceIp `
                                       -NamesFromLog $namesFromLog `
                                       -DhcpIndex $dhcpIndex `
                                       -NoDns:$SkipDns `
                                       -LastFailureTime $src.LastSeen

    [PSCustomObject]@{
        SourceKey          = $src.SourceKey
        SourceIp           = $src.SourceIp
        ResolvedName       = $identity.ResolvedName
        DeviceClass        = $identity.DeviceClass
        Confidence         = $identity.Confidence
        ResolutionMethod   = $identity.ResolutionMethod
        MacAddress         = $identity.MacAddress
        MacVendor          = $identity.MacVendor
        FailureCount       = $src.FailureCount
        DistinctAccounts   = $src.DistinctAccounts
        Accounts           = $src.Accounts
        TopStatus          = $src.TopStatus
        LogonTypes         = $src.LogonTypes
        EventIds           = $src.EventIds
        FirstSeen          = $src.FirstSeen
        LastSeen           = $src.LastSeen
        TimingPattern      = $src.TimingPattern
        MedianGapMinutes   = $src.MedianGapMinutes
        TimingDetail       = $src.TimingDetail
        DCsSeen            = $src.DCsSeen
        NamesSeenInLog     = $src.NamesSeenInLog
        ReverseDnsName     = $identity.ReverseDnsName
        DhcpLease          = $identity.DhcpLease
        LeaseCoversFailure = $identity.LeaseCoversFailure
        LeaseCoverageNote  = $identity.LeaseCoverageNote
        DeviceDetail       = $identity.DeviceDetail
        AdOperatingSystem  = $identity.AdOperatingSystem
        AdLastLogonDate    = $identity.AdLastLogonDate
        AdEnabled          = $identity.AdEnabled
        AdDescription      = $identity.AdDescription
        AdDistinguishedName= $identity.AdDistinguishedName
        TotalEvents        = $src.TotalEvents
    }
}

$resolvedSources = @($resolvedSources | Where-Object { $_.FailureCount -ge $MinFailures })

# --- Inventory cross-reference ------------------------------------------------
# Optional join against the user's own equipment records. This is the step that turns
# "10.0.0.99, unidentified" into "Reception iPad, owned by facilities, floor 1".
$inventory    = @()
$inventoryMap = $null
if ($InventoryCsv) {
    Write-Host ''
    if (-not (Test-Path -LiteralPath $InventoryCsv)) {
        Write-Status "Inventory CSV not found: $InventoryCsv - continuing without it" 'WARN'
    } else {
        try {
            $inventory = @(Import-Csv -LiteralPath $InventoryCsv -ErrorAction Stop)
            if ($inventory.Count -eq 0) {
                Write-Status "Inventory CSV is empty: $InventoryCsv" 'WARN'
            } else {
                $cols = @($inventory[0].PSObject.Properties.Name)
                $inventoryMap = Get-InventoryColumnMap -Columns $cols

                $keys = @()
                if ($inventoryMap.Mac)  { $keys += "MAC ($($inventoryMap.Mac))" }
                if ($inventoryMap.Host) { $keys += "name ($($inventoryMap.Host))" }
                if ($inventoryMap.Ip)   { $keys += "IP ($($inventoryMap.Ip))" }

                if ($keys.Count -eq 0) {
                    # Say exactly why nothing will match, rather than reporting zero hits
                    # later and letting it read as "none of these devices are ours".
                    Write-Status "Inventory has no recognizable hostname, MAC or IP column - nothing to join on. Columns found: $($cols -join ', ')" 'WARN'
                    $inventory = @()
                } else {
                    Write-Status "Inventory loaded: $($inventory.Count) record(s), joining on $($keys -join ', ')" 'PASS'
                }
            }
        } catch {
            Write-Status "Could not read inventory CSV: $($_.Exception.Message)" 'WARN'
            $inventory = @()
        }
    }
}

if ($inventory.Count -gt 0 -and $inventoryMap) {
    $matched = 0
    $enriched = foreach ($rs in $resolvedSources) {
        $hit = Join-InventoryRecord -Inventory $inventory -ColumnMap $inventoryMap `
                                    -ResolvedName $rs.ResolvedName -MacAddress $rs.MacAddress -SourceIp $rs.SourceIp
        if ($hit.Matched) {
            $matched++
            $rs | Add-Member -NotePropertyName 'InventoryMatchedOn' -NotePropertyValue $hit.MatchedOn -Force
            foreach ($k in $hit.Fields.Keys) {
                # Prefixed so an inventory column can never collide with one of ours.
                $rs | Add-Member -NotePropertyName ("Inv_$k") -NotePropertyValue $hit.Fields[$k] -Force
            }
        } else {
            $rs | Add-Member -NotePropertyName 'InventoryMatchedOn' -NotePropertyValue '' -Force
        }
        $rs
    }
    $resolvedSources = @($enriched)
    Write-Status "Inventory matched $matched of $($resolvedSources.Count) source(s)" 'INFO'
}

# --- Join resolution back onto the per-event rows -----------------------------
$sourceLookup = @{}
foreach ($rs in $resolvedSources) { $sourceLookup[$rs.SourceKey] = $rs }

$eventExport = foreach ($e in $allEvents) {
    if (-not $IncludeSuccesses -and -not $e.IsFailure) { continue }

    $key = if (-not [string]::IsNullOrWhiteSpace($e.SourceIp)) {
        $e.SourceIp
    } elseif (-not [string]::IsNullOrWhiteSpace($e.SourceHost)) {
        $e.SourceHost
    } else { '(not recorded)' }

    $rs = $sourceLookup[$key]

    [PSCustomObject]@{
        Time             = $e.Time
        DC               = $e.DC
        EventId          = $e.EventId
        Account          = $e.Account
        AccountDomain    = $e.AccountDomain
        SourceHost       = $e.SourceHost
        SourceIp         = $e.SourceIp
        SourcePort       = $e.SourcePort
        ResolvedName     = if ($rs) { $rs.ResolvedName } else { '' }
        DeviceClass      = if ($rs) { $rs.DeviceClass } else { '' }
        Confidence       = if ($rs) { $rs.Confidence } else { '' }
        MacAddress       = if ($rs) { $rs.MacAddress } else { '' }
        MacVendor        = if ($rs) { $rs.MacVendor } else { '' }
        LogonType        = $e.LogonType
        LogonTypeMeaning = $e.LogonTypeMeaning
        StatusCode       = $e.StatusCode
        StatusMeaning    = $e.StatusMeaning
        IsFailure        = $e.IsFailure
        ProcessName      = $e.ProcessName
        AuthPackage      = $e.AuthPackage
        ServiceName      = $e.ServiceName
        TargetSid        = $e.TargetSid
    }
}

# --- Write output -------------------------------------------------------------
$eventsCsv  = Join-Path $OutputPath "AuthEvents_$stamp.csv"
$sourcesCsv = Join-Path $OutputPath "AuthSources_$stamp.csv"

@($eventExport)     | Sort-Object Time     | Export-Csv -Path $eventsCsv  -NoTypeInformation -Encoding UTF8
@($resolvedSources) | Export-Csv -Path $sourcesCsv -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Status "Events  : $eventsCsv  ($(@($eventExport).Count) rows)" 'PASS'
Write-Status "Sources : $sourcesCsv ($(@($resolvedSources).Count) rows)" 'PASS'

# --- Console summary ----------------------------------------------------------
Write-Host ''
Write-Host 'TOP SOURCES BY FAILURE COUNT' -ForegroundColor White
Write-Host ('-' * 78) -ForegroundColor DarkGray

@($resolvedSources | Select-Object -First 15) |
    Format-Table -AutoSize -Property `
        @{ N = 'Source';     E = { $_.SourceKey } },
        @{ N = 'Name';       E = { if ($_.ResolvedName) { $_.ResolvedName } else { '(unresolved)' } } },
        @{ N = 'Class';      E = { $_.DeviceClass } },
        @{ N = 'Conf';       E = { $_.Confidence } },
        @{ N = 'Fails';      E = { $_.FailureCount } },
        @{ N = 'Accts';      E = { $_.DistinctAccounts } },
        @{ N = 'Vendor';     E = { $_.MacVendor } }

# Unresolved sources are the ones needing manual cross-reference, so they are called out
# explicitly rather than left for the reader to notice in the CSV.
$unresolved = @($resolvedSources | Where-Object { $_.DeviceClass -eq 'Unknown' })
if ($unresolved.Count -gt 0) {
    Write-Host ''
    Write-Status "$($unresolved.Count) source(s) could not be identified from AD, DHCP or DNS:" 'WARN'
    foreach ($u in ($unresolved | Select-Object -First 10)) {
        Write-Host ("       {0}  ({1} failures, {2} accounts)" -f $u.SourceKey, $u.FailureCount, $u.DistinctAccounts) -ForegroundColor Yellow
    }
    Write-Status "Cross-reference these against switch MAC tables, RMM inventory, or VPN logs." 'INFO'
}

# A gateway OUI means the address is likely masking the real originator - the single
# most misleading result this export can produce if it goes unnoticed.
$gateways = @($resolvedSources | Where-Object { $_.DeviceClass -eq 'NetworkDevice' })
if ($gateways.Count -gt 0) {
    Write-Host ''
    Write-Status "$($gateways.Count) source(s) look like network equipment. Traffic may be NATed - the real device is behind these:" 'WARN'
    foreach ($g in $gateways) {
        Write-Host ("       {0}  {1}" -f $g.SourceKey, $g.MacVendor) -ForegroundColor Yellow
    }
}

if ($failedDcs.Count -gt 0) {
    Write-Host ''
    Write-Status "$($failedDcs.Count) DC(s) could not be queried - this export is INCOMPLETE: $($failedDcs -join ', ')" 'FAIL'
}

$thinLogs = @($dcCoverage | Where-Object { $_.DaysHeld -lt $DaysBack })
if ($thinLogs.Count -gt 0) {
    Write-Host ''
    Write-Status "$($thinLogs.Count) DC(s) hold less log history than the requested $DaysBack-day window:" 'WARN'
    foreach ($t in $thinLogs) {
        Write-Host ("       {0}  {1} days" -f $t.DC, $t.DaysHeld) -ForegroundColor Yellow
    }
    Write-Status "Run Set-DCSecurityLogRetention.ps1 to size the logs for longer investigations." 'INFO'
}

Write-Host ''
