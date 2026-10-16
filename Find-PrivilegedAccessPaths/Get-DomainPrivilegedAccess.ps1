#Requires -Version 3.0
<#
.SYNOPSIS
    Domain-wide Privileged Access Audit - finds every user with any form of admin
    access and explains exactly HOW they got it.

.DESCRIPTION
    Scans the entire domain for users who have elevated privileges through ANY path:

    - Direct membership in built-in privileged groups
    - Nested (indirect) membership in privileged groups, with the nesting path
    - Membership through primaryGroupID (does not appear in the group's member attribute)
    - Orphaned AdminCount = 1 (previously privileged, never cleaned up)
    - SID History carrying privileged SIDs from old domains
    - Service Principal Names (Kerberoastable service accounts)
    - Non-standard primaryGroupID (hidden privilege that does not show in memberOf)

    Privileged groups are identified by their well-known SID / RID, NOT by their name, so
    domains with localized group names (for example "Domaenen-Admins") are audited
    correctly. DnsAdmins and DHCP Administrators have no well-known SID and are the only
    groups located by name.

    Group nesting is walked by hand, one level at a time (cycle-safe, depth-limited), so the
    path from each group to each user is preserved. Get-ADGroupMember -Recursive is not used
    because it returns leaf members only and discards that path.

    Outputs a color-coded console report AND exports to CSV for documentation.

.PARAMETER OutputPath
    Where to write the CSV. A directory (the file name PrivilegedAccessAudit_<timestamp>.csv
    is generated) or a full path ending in .csv. Defaults to the current directory.
    The old name -ExportPath still works.

.PARAMETER Server
    Domain controller or domain DNS name to query. Defaults to the domain of the machine the
    script runs on. Passed to every Active Directory cmdlet.

.PARAMETER Credential
    Credential used for every Active Directory query. Defaults to the current user.

.PARAMETER IncludeDisabled
    If specified, includes disabled accounts in the audit.

.PARAMETER MaxNestingDepth
    How many levels of nested groups to follow below each privileged group. Default 10.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without querying AD (used by the Pester tests).

.EXAMPLE
    .\Get-DomainPrivilegedAccess.ps1

.EXAMPLE
    .\Get-DomainPrivilegedAccess.ps1 -OutputPath "C:\Reports" -IncludeDisabled

.EXAMPLE
    .\Get-DomainPrivilegedAccess.ps1 -Server dc01.contoso.com -Credential (Get-Credential)

.NOTES
    Requires: Windows PowerShell 3.0 or later; ActiveDirectory module (RSAT), imported at
              runtime in a try/catch.
    Run as:   Domain Admin or equivalent read access
    Time:     ~1-5 minutes depending on domain size

    The helper functions Get-PrivilegedGroupDefinition, Get-NameOnlyPrivilegedGroup,
    Find-PrivilegedGroupBySid and Resolve-ReportFilePath are shared verbatim with
    Find-PrivilegedAccessPaths.ps1; Tests\PrivilegedAccess.Tests.ps1 fails if they drift.

    REFERENCES
    - Well-known SIDs/RIDs: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - primaryGroupID:       https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    - Get-ADGroupMember:    https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember
    - Get-ADUser -Filter:   https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('ExportPath')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
    [int]$MaxNestingDepth = 10,

    [Parameter(Mandatory = $false)]
    [switch]$LoadFunctionsOnly
)

# Splatted into EVERY Active Directory cmdlet so -Server / -Credential are honoured everywhere.
$ADParams = @{}
if ($Server) { $ADParams['Server'] = $Server }
if ($Credential -and $Credential.UserName) { $ADParams['Credential'] = $Credential }

#region Shared helpers (kept identical in Find-PrivilegedAccessPaths.ps1)

function Get-PrivilegedGroupDefinition {
    <#
        Well-known privileged groups, identified by SID so localized group names do not
        matter. Domain-relative groups are S-1-5-21-<domain>-<RID>; BUILTIN groups are
        S-1-5-32-<RID>.
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
        - 512 Domain Admins, 516 Domain Controllers, 517 Cert Publishers, 518 Schema Admins,
          519 Enterprise Admins, 520 Group Policy Creator Owners, 521 Read-only Domain
          Controllers, 525 Protected Users,
          526 Key Admins, 527 Enterprise Key Admins, 553 RAS and IAS Servers.
        - S-1-5-32-544 Administrators, 548 Account Operators, 549 Server Operators,
          550 Print Operators, 551 Backup Operators, 552 Replicators, 555 Remote Desktop
          Users, 578 Hyper-V Administrators, 580 Remote Management Users.
        AdminSdHolder marks the groups Microsoft lists as protected by AdminSDHolder/SDProp
        (RIDs 512, 516, 518, 519, 521, 526, 527, 544, 548, 549, 550, 551, 552), which is what
        sets adminCount = 1 on their members:
        https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
        That page lists Key Admins (526) under the forest root domain and Enterprise Key
        Admins (527) under "domain", which is the reverse of how AD creates them. Groups that
        can exist at forest-root level (518, 519, 526, 527) are therefore emitted for both the
        domain SID and the forest root SID; a SID that does not exist is simply skipped when
        it is looked up.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [string]$RootDomainSid
    )

    $domainRelative = @(
        @{ Rid = 512; Name = 'Domain Admins';               Risk = 'CRITICAL'; Note = 'Full domain control';                          Forest = $false }
        @{ Rid = 516; Name = 'Domain Controllers';          Risk = 'CRITICAL'; Note = 'Domain controller computer accounts';          Forest = $false }
        @{ Rid = 517; Name = 'Cert Publishers';             Risk = 'MEDIUM';   Note = 'Can publish certificates to AD';               Forest = $false }
        @{ Rid = 518; Name = 'Schema Admins';               Risk = 'CRITICAL'; Note = 'Can modify AD schema (forest-wide)';           Forest = $true  }
        @{ Rid = 519; Name = 'Enterprise Admins';           Risk = 'CRITICAL'; Note = 'Full forest control';                          Forest = $true  }
        @{ Rid = 520; Name = 'Group Policy Creator Owners'; Risk = 'HIGH';     Note = 'Can create/edit GPOs';                         Forest = $false }
        @{ Rid = 521; Name = 'Read-only Domain Controllers'; Risk = 'HIGH';    Note = 'Read-only domain controller computer accounts'; Forest = $false }
        @{ Rid = 525; Name = 'Protected Users';             Risk = 'INFO';     Note = 'Security hardening group - not a privilege, but notable'; Forest = $false }
        @{ Rid = 526; Name = 'Key Admins';                  Risk = 'MEDIUM';   Note = 'Can perform admin actions on key objects';     Forest = $true  }
        @{ Rid = 527; Name = 'Enterprise Key Admins';       Risk = 'MEDIUM';   Note = 'Forest-wide key administration';               Forest = $true  }
        @{ Rid = 553; Name = 'RAS and IAS Servers';         Risk = 'LOW';      Note = 'Remote access servers';                        Forest = $false }
    )
    $builtin = @(
        @{ Rid = 544; Name = 'Administrators';              Risk = 'CRITICAL'; Note = 'Local admin on DCs = domain admin' }
        @{ Rid = 548; Name = 'Account Operators';           Risk = 'HIGH';     Note = 'Can manage most AD accounts and groups' }
        @{ Rid = 549; Name = 'Server Operators';            Risk = 'HIGH';     Note = 'Can log on to DCs, manage services and shares' }
        @{ Rid = 550; Name = 'Print Operators';             Risk = 'MEDIUM';   Note = 'Can log on to DCs, load drivers' }
        @{ Rid = 551; Name = 'Backup Operators';            Risk = 'HIGH';     Note = 'Can back up/restore any file, log on to DCs' }
        @{ Rid = 552; Name = 'Replicators';                 Risk = 'MEDIUM';   Note = 'File replication support' }
        @{ Rid = 555; Name = 'Remote Desktop Users';        Risk = 'LOW';      Note = 'RDP access - check if applied to DCs' }
        @{ Rid = 578; Name = 'Hyper-V Administrators';      Risk = 'HIGH';     Note = 'Can compromise VMs including virtual DCs' }
        @{ Rid = 580; Name = 'Remote Management Users';    Risk = 'MEDIUM';   Note = 'WinRM/PowerShell remoting access' }
    )

    $adminSdHolderRids = @(512, 516, 518, 519, 521, 526, 527, 544, 548, 549, 550, 551, 552)

    $defs = New-Object System.Collections.Generic.List[object]
    foreach ($d in $domainRelative) {
        $prot = ($adminSdHolderRids -contains $d.Rid)
        $defs.Add([PSCustomObject]@{ Sid = "$DomainSid-$($d.Rid)"; Rid = $d.Rid; Scope = 'Domain'; Name = $d.Name; Risk = $d.Risk; Note = $d.Note; AdminSdHolder = $prot })
        if ($d.Forest -and $RootDomainSid -and $RootDomainSid -ne $DomainSid) {
            $defs.Add([PSCustomObject]@{ Sid = "$RootDomainSid-$($d.Rid)"; Rid = $d.Rid; Scope = 'Domain'; Name = $d.Name; Risk = $d.Risk; Note = $d.Note; AdminSdHolder = $prot })
        }
    }
    foreach ($b in $builtin) {
        $prot = ($adminSdHolderRids -contains $b.Rid)
        $defs.Add([PSCustomObject]@{ Sid = "S-1-5-32-$($b.Rid)"; Rid = $b.Rid; Scope = 'Builtin'; Name = $b.Name; Risk = $b.Risk; Note = $b.Note; AdminSdHolder = $prot })
    }
    return $defs.ToArray()
}

function Get-NameOnlyPrivilegedGroup {
    <#
        Groups that matter but have NO well-known SID: DnsAdmins and DHCP Administrators are
        created when the role is installed and get an ordinary RID. These can only be located
        by name, so they are not found on a domain where the group has been renamed or
        localized. Everything else is matched by SID.
    #>
    return @(
        [PSCustomObject]@{ Name = 'DnsAdmins';           Risk = 'HIGH';   Note = 'Can load arbitrary DLLs on DCs via DNS service - privilege escalation path' }
        [PSCustomObject]@{ Name = 'DHCP Administrators'; Risk = 'MEDIUM'; Note = 'Full DHCP management' }
    )
}

function Find-PrivilegedGroupBySid {
    <#
        Returns the definition whose SID equals -Sid, or $null. With -AnyDomain a
        domain-relative SID from ANY domain (S-1-5-21-a-b-c-<RID>) matches on its RID; this is
        for SID History, where the privileged SID belongs to the old domain. The match is on
        the whole RID, never a string suffix, so RID 12 can not match RID 512.
    #>
    param(
        [string]$Sid,
        [object[]]$Definitions,
        [switch]$AnyDomain
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) { return $null }

    foreach ($d in $Definitions) {
        if ($d.Sid -eq $Sid) { return $d }
    }
    if ($AnyDomain -and $Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        $rid = [int]$Matches[1]
        foreach ($d in $Definitions) {
            if ($d.Scope -eq 'Domain' -and $d.Rid -eq $rid) { return $d }
        }
    }
    return $null
}

function Resolve-ReportFilePath {
    <#
        Turns -OutputPath into a CSV file path. A path ending in .csv is used as given;
        anything else is a directory that receives -DefaultFileName. Missing directories are
        created. An empty path means the current directory.
    #>
    param(
        [string]$Path,
        [Parameter(Mandatory = $true)][string]$DefaultFileName
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = (Get-Location).Path }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

    if ($full -match '\.csv$') {
        $dir = Split-Path -Parent $full
        $file = $full
    }
    else {
        $dir = $full
        $file = Join-Path $full $DefaultFileName
    }
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $file
}

#endregion

#region Group membership resolution

function Get-ForestRootDomainSid {
    try {
        $forest = Get-ADForest @ADParams -ErrorAction Stop
        $root = Get-ADDomain -Identity $forest.RootDomain @ADParams -ErrorAction Stop
        return $root.DomainSID.Value
    }
    catch {
        return $null
    }
}

function Get-GroupMemberPath {
    <#
        Walks one group's membership tree breadth-first, one level at a time, and returns a row
        per user: MembershipType (Direct / Nested / Primary), NestingDepth and NestedVia (the
        chain of nested groups, root group excluded, e.g. "IT-Admins -> Helpdesk").

        Get-ADGroupMember -Recursive is deliberately NOT used: per Microsoft it "gets all
        members in the hierarchy of the group that do not contain child objects", i.e. leaves
        only, with the path discarded.
        https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember

        Cycle safety: every group DN is added to a visited set before it is queued, so a
        circular nest (A contains B contains A) is expanded once. Breadth-first order means
        the path recorded for a user is the shortest one.

        primaryGroupID: "Contains the relative identifier (RID) for the primary group of the
        user. By default, this is the RID for the Domain Users group." It is not a linked
        attribute, so those users are NOT in any group's member attribute. For every group
        reached, users whose primaryGroupID equals the group's RID are merged in. A user who
        is both a member and has the group as primary group is reported once, as Primary.
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    #>
    param(
        [Parameter(Mandatory = $true)]$Group,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [int]$MaxNestingDepth = 10
    )

    $comparer = [StringComparer]::OrdinalIgnoreCase
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $comparer
    $seenUsers = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    $reached = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Queue

    [void]$visited.Add([string]$Group.DistinguishedName)
    $queue.Enqueue(@{ Group = $Group; Path = ''; Depth = 0 })

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        $current = $item.Group
        $reached.Add($item)

        if ($item.Depth -ge $MaxNestingDepth) {
            Write-Warning "Nesting depth limit ($MaxNestingDepth) reached at '$($current.Name)' under '$($Group.Name)'; not descending further."
            continue
        }

        $members = @()
        try {
            $members = @(Get-ADGroupMember -Identity $current.DistinguishedName @ADParams -ErrorAction Stop)
        }
        catch {
            Write-Warning "Could not read members of '$($current.Name)': $($_.Exception.Message)"
            continue
        }

        foreach ($m in $members) {
            $mDn = [string]$m.distinguishedName
            if ($m.objectClass -eq 'group') {
                if ($visited.Add($mDn)) {
                    $childPath = if ($item.Path) { "$($item.Path) -> $($m.Name)" } else { [string]$m.Name }
                    $queue.Enqueue(@{ Group = $m; Path = $childPath; Depth = ($item.Depth + 1) })
                }
            }
            elseif ($m.objectClass -eq 'user') {
                if (-not $seenUsers.ContainsKey($mDn)) {
                    $row = [PSCustomObject]@{
                        UserDN         = $mDn
                        UserSid        = $m.SID
                        MembershipType = $(if ($item.Depth -eq 0) { 'Direct' } else { 'Nested' })
                        NestingDepth   = $item.Depth
                        NestedVia      = $item.Path
                    }
                    $seenUsers[$mDn] = $row
                    $rows.Add($row)
                }
            }
        }
    }

    # Merge users whose primaryGroupID points at any group we reached.
    foreach ($item in $reached) {
        $sid = $item.Group.SID
        $sidText = if ($sid) { [string]$sid.Value } else { '' }
        if (-not $sidText -and $sid) { $sidText = [string]$sid }
        if ($sidText -notmatch '-(\d+)$') { continue }
        $rid = [int]$Matches[1]
        # A primary group has to be in the user's own domain.
        if (-not $sidText.StartsWith("$DomainSid-")) { continue }

        $primaryUsers = @()
        try {
            $primaryUsers = @(Get-ADUser -Filter "primaryGroupID -eq $rid" @ADParams -ErrorAction Stop -Properties primaryGroupID)
        }
        catch {
            Write-Warning "Could not query primary-group members of '$($item.Group.Name)': $($_.Exception.Message)"
            continue
        }

        foreach ($u in $primaryUsers) {
            $uDn = [string]$u.DistinguishedName
            if ($seenUsers.ContainsKey($uDn)) {
                # Member AND primary group of the root: one membership, held as Primary.
                if ($item.Depth -eq 0 -and $seenUsers[$uDn].MembershipType -eq 'Direct') {
                    $seenUsers[$uDn].MembershipType = 'Primary'
                }
                continue
            }
            $via = if ($item.Depth -eq 0) { '' } else { "$($item.Path) (primary group)" }
            $row = [PSCustomObject]@{
                UserDN         = $uDn
                UserSid        = $u.SID
                MembershipType = $(if ($item.Depth -eq 0) { 'Primary' } else { 'Nested' })
                NestingDepth   = $item.Depth
                NestedVia      = $via
            }
            $seenUsers[$uDn] = $row
            $rows.Add($row)
        }
    }

    return $rows.ToArray()
}

function Get-PrivilegedGroupMembership {
    <#
        Resolves every privileged group (by SID, then the two name-only groups) and returns a
        hashtable: user DN -> list of memberships { GroupName, GroupSID, MembershipType,
        NestingDepth, NestedVia, Risk, Note }. GroupName is the stable English label from the
        definition table, not the (possibly localized) name found in AD.
    #>
    param(
        [Parameter(Mandatory = $true)][object[]]$Definitions,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [object[]]$NameOnly = @(),
        [int]$MaxNestingDepth = 10
    )

    $map = @{}
    $targets = New-Object System.Collections.Generic.List[object]

    foreach ($d in $Definitions) {
        try {
            $g = Get-ADGroup -Identity $d.Sid @ADParams -ErrorAction Stop
        }
        catch {
            # Group does not exist here (e.g. Enterprise Admins in a child domain).
            continue
        }
        $targets.Add(@{ Label = $d.Name; Sid = $d.Sid; Risk = $d.Risk; Note = $d.Note; Group = $g })
    }
    foreach ($n in $NameOnly) {
        try {
            $g = Get-ADGroup -Filter "Name -eq '$($n.Name)'" @ADParams -ErrorAction Stop | Select-Object -First 1
        }
        catch { continue }
        if ($g) {
            $targets.Add(@{ Label = $n.Name; Sid = [string]$g.SID.Value; Risk = $n.Risk; Note = $n.Note; Group = $g })
        }
    }

    $i = 0
    foreach ($t in $targets) {
        $i++
        Write-Host "  [$i/$($targets.Count)] $($t.Label)..." -ForegroundColor Gray -NoNewline
        $rows = @(Get-GroupMemberPath -Group $t.Group -DomainSid $DomainSid -MaxNestingDepth $MaxNestingDepth)
        $direct = @($rows | Where-Object { $_.MembershipType -ne 'Nested' }).Count
        $nested = @($rows | Where-Object { $_.MembershipType -eq 'Nested' }).Count
        Write-Host " $direct direct/primary, $nested nested" -ForegroundColor DarkGray

        foreach ($r in $rows) {
            if (-not $map.ContainsKey($r.UserDN)) {
                $map[$r.UserDN] = New-Object System.Collections.ArrayList
            }
            [void]$map[$r.UserDN].Add([PSCustomObject]@{
                GroupName      = $t.Label
                GroupSID       = $t.Sid
                MembershipType = $r.MembershipType
                NestingDepth   = $r.NestingDepth
                NestedVia      = $r.NestedVia
                Risk           = $t.Risk
                Note           = $t.Note
            })
        }
    }
    return $map
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Setup
$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Install RSAT or run from a DC."
    return
}

$DomainInfo = Get-ADDomain @ADParams
$DomainSID = $DomainInfo.DomainSID.Value
$DomainName = $DomainInfo.NetBIOSName
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportFile = Resolve-ReportFilePath -Path $OutputPath -DefaultFileName "PrivilegedAccessAudit_$Timestamp.csv"

# Master results collection
$Results = New-Object System.Collections.ArrayList

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  DOMAIN-WIDE PRIVILEGED ACCESS AUDIT" -ForegroundColor Cyan
Write-Host "  Domain:  $DomainName ($($DomainInfo.DNSRoot))" -ForegroundColor Cyan
Write-Host "  Date:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "  Export:  $ExportFile" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$RootDomainSid = Get-ForestRootDomainSid
$PrivilegedGroupDefs = @(Get-PrivilegedGroupDefinition -DomainSid $DomainSID -RootDomainSid $RootDomainSid)
$riskOrder = @{ "CRITICAL" = 4; "HIGH" = 3; "MEDIUM" = 2; "LOW" = 1; "INFO" = 0 }
#endregion

#region PHASE 1 - Privileged group members (direct, nested, primary group)
Write-Host "-- PHASE 1: RESOLVING GROUP MEMBERSHIPS -------------------------" -ForegroundColor Yellow
Write-Host ""

$GroupMembershipMap = Get-PrivilegedGroupMembership -Definitions $PrivilegedGroupDefs -DomainSid $DomainSID `
    -NameOnly @(Get-NameOnlyPrivilegedGroup) -MaxNestingDepth $MaxNestingDepth

Write-Host ""
Write-Host "  Found $($GroupMembershipMap.Count) unique users with privileged group access." -ForegroundColor White
Write-Host ""
#endregion

#region PHASE 2 - AdminCount, SID history, SPNs, primary group
Write-Host "-- PHASE 2: SCANNING FOR ADMINCOUNT, SID HISTORY & SPNs ---------" -ForegroundColor Yellow
Write-Host ""

$enabledClause = if ($IncludeDisabled) { '' } else { ' -and Enabled -eq $true' }

$AdminCountUsers = @(Get-ADUser -Filter "AdminCount -eq 1$enabledClause" @ADParams -Properties AdminCount, MemberOf, SIDHistory, `
    ServicePrincipalName, PrimaryGroupID, Enabled, LastLogonDate, whenCreated, Description, PasswordLastSet)
Write-Host "  Found $($AdminCountUsers.Count) users with AdminCount = 1" -ForegroundColor Gray

$SIDHistoryUsers = @(Get-ADUser -Filter * @ADParams -Properties SIDHistory -ErrorAction SilentlyContinue |
    Where-Object { @($_.SIDHistory).Count -gt 0 })
Write-Host "  Found $($SIDHistoryUsers.Count) users with SID History" -ForegroundColor Gray

$SPNUsers = @(Get-ADUser -Filter "ServicePrincipalName -like '*'$enabledClause" @ADParams -Properties ServicePrincipalName, Enabled, LastLogonDate, Description)
Write-Host "  Found $($SPNUsers.Count) users with Service Principal Names" -ForegroundColor Gray

# 513 = Domain Users, 514 = Domain Guests - anything else is unusual
$PrimaryGroupUsers = @(Get-ADUser -Filter * @ADParams -Properties PrimaryGroupID -ErrorAction SilentlyContinue |
    Where-Object { $_.PrimaryGroupID -ne 513 -and $_.PrimaryGroupID -ne 514 })
Write-Host "  Found $($PrimaryGroupUsers.Count) users with non-standard PrimaryGroupID" -ForegroundColor Gray
Write-Host ""
#endregion

#region PHASE 3 - Master report
Write-Host "-- PHASE 3: BUILDING MASTER REPORT ------------------------------" -ForegroundColor Yellow
Write-Host ""

$AllFlaggedDNs = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($dn in $GroupMembershipMap.Keys) { [void]$AllFlaggedDNs.Add($dn) }
foreach ($u in $AdminCountUsers)          { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $SIDHistoryUsers)          { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $SPNUsers)                 { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }
foreach ($u in $PrimaryGroupUsers)        { [void]$AllFlaggedDNs.Add($u.DistinguishedName) }

Write-Host "  Total unique flagged users: $($AllFlaggedDNs.Count)" -ForegroundColor White
Write-Host ""

foreach ($dn in $AllFlaggedDNs) {
    try {
        $adUser = Get-ADUser -Identity $dn @ADParams -Properties `
            SamAccountName, Name, Enabled, AdminCount, SIDHistory, `
            ServicePrincipalName, PrimaryGroupID, MemberOf, `
            LastLogonDate, PasswordLastSet, whenCreated, Description, Title, Department
    } catch {
        continue
    }

    if (-not $IncludeDisabled -and -not $adUser.Enabled) { continue }

    $flags = New-Object System.Collections.ArrayList
    $highestRisk = "INFO"

    # Flag 1: Privileged group memberships (direct, nested with path, primary group)
    if ($GroupMembershipMap.ContainsKey($dn)) {
        foreach ($membership in $GroupMembershipMap[$dn]) {
            $flagText = switch ($membership.MembershipType) {
                'Primary' { "Primary-group member of $($membership.GroupName)" }
                default   { "$($membership.MembershipType) member of $($membership.GroupName)" }
            }
            $detailText = "$($membership.Note)"
            if ($membership.NestedVia) { $detailText += " | Via: $($membership.NestedVia)" }
            if ($membership.MembershipType -eq 'Primary') { $detailText += " | Held through primaryGroupID, not the member attribute" }
            [void]$flags.Add(@{
                Category = "Group Membership"
                Flag     = $flagText
                Risk     = $membership.Risk
                Detail   = $detailText
                Via      = $membership.NestedVia
            })
            if ($riskOrder[$membership.Risk] -gt $riskOrder[$highestRisk]) {
                $highestRisk = $membership.Risk
            }
        }
    }

    # Flag 2: Orphaned AdminCount
    if ($adUser.AdminCount -eq 1) {
        if (-not $GroupMembershipMap.ContainsKey($dn)) {
            [void]$flags.Add(@{
                Category = "Orphaned AdminCount"
                Flag     = "AdminCount = 1 but NOT in any privileged group"
                Risk     = "HIGH"
                Detail   = "Was previously privileged. Clear AdminCount and re-enable ACL inheritance."
                Via      = ''
            })
            if ($riskOrder["HIGH"] -gt $riskOrder[$highestRisk]) { $highestRisk = "HIGH" }
        } else {
            [void]$flags.Add(@{
                Category = "AdminCount"
                Flag     = "AdminCount = 1 (active - currently in protected group)"
                Risk     = "INFO"
                Detail   = "Expected behavior for current privileged users"
                Via      = ''
            })
        }
    }

    # Flag 3: SID History (matched on the whole RID of a privileged SID from any domain)
    if ($adUser.SIDHistory -and @($adUser.SIDHistory).Count -gt 0) {
        foreach ($sid in $adUser.SIDHistory) {
            $sidStr = $sid.Value
            $privDef = Find-PrivilegedGroupBySid -Sid $sidStr -Definitions $PrivilegedGroupDefs -AnyDomain

            if ($privDef) {
                [void]$flags.Add(@{
                    Category = "SID History"
                    Flag     = "Carries privileged SID: $sidStr ($($privDef.Name))"
                    Risk     = "CRITICAL"
                    Detail   = "Old SID grants admin access from a previous domain"
                    Via      = ''
                })
                if ($riskOrder["CRITICAL"] -gt $riskOrder[$highestRisk]) { $highestRisk = "CRITICAL" }
            } else {
                [void]$flags.Add(@{
                    Category = "SID History"
                    Flag     = "SID History present: $sidStr"
                    Risk     = "LOW"
                    Detail   = "Non-privileged old SID - from domain migration"
                    Via      = ''
                })
            }
        }
    }

    # Flag 4: SPNs
    if ($adUser.ServicePrincipalName -and @($adUser.ServicePrincipalName).Count -gt 0) {
        $spnList = (@($adUser.ServicePrincipalName) | Select-Object -First 3) -join "; "
        $spnRisk = if ($GroupMembershipMap.ContainsKey($dn)) { "HIGH" } else { "MEDIUM" }
        [void]$flags.Add(@{
            Category = "Service Principal Name"
            Flag     = "Has SPNs set - Kerberoastable"
            Risk     = $spnRisk
            Detail   = "SPNs: $spnList"
            Via      = ''
        })
        if ($riskOrder[$spnRisk] -gt $riskOrder[$highestRisk]) { $highestRisk = $spnRisk }
    }

    # Flag 5: Non-standard PrimaryGroupID. The group is identified by RID -> SID, not by name.
    if ($adUser.PrimaryGroupID -notin @(513, 514)) {
        $pgSid = "$DomainSID-$($adUser.PrimaryGroupID)"
        $pgDef = Find-PrivilegedGroupBySid -Sid $pgSid -Definitions $PrivilegedGroupDefs
        $pgRisk = "MEDIUM"
        $pgName = "Unknown (RID: $($adUser.PrimaryGroupID))"
        if ($pgDef) { $pgRisk = $pgDef.Risk; $pgName = $pgDef.Name }
        [void]$flags.Add(@{
            Category = "PrimaryGroupID"
            Flag     = "Non-standard PrimaryGroupID: $($adUser.PrimaryGroupID) ($pgName)"
            Risk     = $pgRisk
            Detail   = "This membership is HIDDEN from the memberOf attribute!"
            Via      = ''
        })
        if ($riskOrder[$pgRisk] -gt $riskOrder[$highestRisk]) { $highestRisk = $pgRisk }
    }

    foreach ($flag in $flags) {
        [void]$Results.Add([PSCustomObject]@{
            Username          = $adUser.SamAccountName
            DisplayName       = $adUser.Name
            Enabled           = $adUser.Enabled
            HighestRisk       = $highestRisk
            FlagCategory      = $flag.Category
            Flag              = $flag.Flag
            FlagRisk          = $flag.Risk
            Detail            = $flag.Detail
            NestedVia         = $flag.Via
            Title             = $adUser.Title
            Department        = $adUser.Department
            Description       = $adUser.Description
            LastLogon         = $adUser.LastLogonDate
            PasswordLastSet   = $adUser.PasswordLastSet
            AccountCreated    = $adUser.whenCreated
            DistinguishedName = $adUser.DistinguishedName
        })
    }
}
#endregion

#region Console report
Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$UserGroups = @($Results | Group-Object Username | Sort-Object {
    $riskOrder[($_.Group | Select-Object -First 1).HighestRisk]
} -Descending)

foreach ($userGroup in $UserGroups) {
    $first = $userGroup.Group | Select-Object -First 1
    $riskColor = switch ($first.HighestRisk) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Yellow" }
        "MEDIUM"   { "DarkYellow" }
        "LOW"      { "Gray" }
        default    { "White" }
    }
    $enabledStr = if ($first.Enabled) { "" } else { " [DISABLED]" }

    Write-Host "  + " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($first.Username)" -ForegroundColor White -NoNewline
    Write-Host " ($($first.DisplayName))$enabledStr" -ForegroundColor DarkGray -NoNewline
    Write-Host " [$($first.HighestRisk)]" -ForegroundColor $riskColor

    if ($first.Title -or $first.Department) {
        $titleDept = (@($first.Title, $first.Department) | Where-Object { $_ }) -join " / "
        Write-Host "  |  $titleDept" -ForegroundColor DarkGray
    }
    if ($first.LastLogon) {
        Write-Host "  |  Last logon: $($first.LastLogon)" -ForegroundColor DarkGray
    }

    foreach ($row in $userGroup.Group) {
        $flagColor = switch ($row.FlagRisk) {
            "CRITICAL" { "Red" }
            "HIGH"     { "Yellow" }
            "MEDIUM"   { "DarkYellow" }
            "LOW"      { "Gray" }
            default    { "DarkGray" }
        }
        Write-Host "  |  " -NoNewline
        Write-Host "[$($row.FlagRisk.PadRight(8))] " -ForegroundColor $flagColor -NoNewline
        Write-Host "$($row.Flag)" -ForegroundColor White
        if ($row.Detail) {
            Write-Host "  |     > $($row.Detail)" -ForegroundColor DarkGray
        }
    }
    Write-Host "  +----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
}
#endregion

#region Summary
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$uniqueUsers = @($Results | Select-Object -ExpandProperty Username -Unique)
$critUsers = @($Results | Where-Object HighestRisk -eq "CRITICAL" | Select-Object -ExpandProperty Username -Unique).Count
$highUsers = @($Results | Where-Object HighestRisk -eq "HIGH" | Select-Object -ExpandProperty Username -Unique).Count
$medUsers  = @($Results | Where-Object HighestRisk -eq "MEDIUM" | Select-Object -ExpandProperty Username -Unique).Count
$orphanedAdminCount = @($Results | Where-Object FlagCategory -eq "Orphaned AdminCount" | Select-Object -ExpandProperty Username -Unique).Count
$nestedOnly = @($Results | Where-Object { $_.Flag -match "^Nested member" } | Select-Object -ExpandProperty Username -Unique).Count
$primaryHeld = @($Results | Where-Object { $_.Flag -match "^Primary-group member" } | Select-Object -ExpandProperty Username -Unique).Count

Write-Host "  Total privileged users found:  $($uniqueUsers.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  Risk Breakdown:" -ForegroundColor White
Write-Host "    CRITICAL:  $critUsers users" -ForegroundColor Red
Write-Host "    HIGH:      $highUsers users" -ForegroundColor Yellow
Write-Host "    MEDIUM:    $medUsers users" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Notable Findings:" -ForegroundColor White
Write-Host "    Orphaned AdminCount (stale):     $orphanedAdminCount users" -ForegroundColor $(if ($orphanedAdminCount -gt 0) { "Yellow" } else { "Gray" })
Write-Host "    Nested privileged access:        $nestedOnly users" -ForegroundColor $(if ($nestedOnly -gt 0) { "Yellow" } else { "Gray" })
Write-Host "    Via primary group (hidden):      $primaryHeld users" -ForegroundColor $(if ($primaryHeld -gt 0) { "Yellow" } else { "Gray" })
Write-Host ""

Write-Host "  Privileged Group Membership Counts:" -ForegroundColor White
$groupCounts = @($Results | Where-Object FlagCategory -eq "Group Membership" |
    ForEach-Object { ($_.Flag -replace "^(Direct|Nested|Primary-group) member of ", "") } |
    Group-Object | Sort-Object Count -Descending)

foreach ($gc in $groupCounts) {
    $gcRisk = ($PrivilegedGroupDefs | Where-Object Name -eq $gc.Name | Select-Object -First 1).Risk
    if (-not $gcRisk) { $gcRisk = (Get-NameOnlyPrivilegedGroup | Where-Object Name -eq $gc.Name | Select-Object -First 1).Risk }
    $gcColor = switch ($gcRisk) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Yellow" }
        "MEDIUM"   { "DarkYellow" }
        default    { "Gray" }
    }
    Write-Host "    $($gc.Name): " -ForegroundColor $gcColor -NoNewline
    Write-Host "$($gc.Count) users" -ForegroundColor White
}
Write-Host ""
#endregion

#region Export
try {
    $Results | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "  [PASS] Report exported to: $ExportFile" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export CSV: $_"
    $fallback = Join-Path $env:TEMP "PrivilegedAccessAudit_$Timestamp.csv"
    try {
        $Results | Export-Csv -Path $fallback -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "  [PASS] Report exported to fallback: $fallback" -ForegroundColor Green
    } catch {
        Write-Warning "Could not export report. Results displayed above."
    }
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""
#endregion
