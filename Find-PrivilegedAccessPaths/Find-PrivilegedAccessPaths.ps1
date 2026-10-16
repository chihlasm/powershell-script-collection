#Requires -Version 3.0
<#
.SYNOPSIS
    Traces all paths through which a user may be flagged as privileged/admin in Active Directory.

.DESCRIPTION
    When a user shows up on a Privileged Account Report and you can't figure out WHY,
    this script checks every common path to admin-level access:

    1. Direct membership in built-in admin groups (Domain Admins, Enterprise Admins, etc.)
    2. NESTED group membership, with the path (user -> group -> group -> privileged group)
    3. AdminCount attribute = 1 (set by AdminSDHolder and often orphaned)
    4. AdminSDHolder protection status
    5. SID History (can carry admin SIDs from old domains)
    6. Delegated permissions on OUs (sometimes grants admin-equivalent access)
    7. Service Principal Names (service accounts running under the user's identity)
    8. primaryGroupID: a privileged primary group does not appear in memberOf

    Privileged groups are recognised by their well-known SID / RID, not by name, so
    localized group names are detected too. DnsAdmins and DHCP Administrators have no
    well-known SID and are matched by name.

.PARAMETER Username
    The sAMAccountName of the user to investigate.

.PARAMETER OutputPath
    Optional. If specified, exports the findings as CSV. A directory (the file name
    PrivilegedAccessPaths_<user>_<timestamp>.csv is generated) or a full path ending in .csv.
    The old name -ExportPath still works.

.PARAMETER Server
    Domain controller or domain DNS name to query. Defaults to the machine's own domain.
    Passed to every Active Directory cmdlet and to the OU ACL reads.

.PARAMETER Credential
    Credential used for every Active Directory query. Defaults to the current user.

.PARAMETER MaxNestingDepth
    How many levels of parent groups to follow upward from the user. Default 10.

.PARAMETER LoadFunctionsOnly
    Define the functions and return without querying AD (used by the Pester tests).

.EXAMPLE
    .\Find-PrivilegedAccessPaths.ps1 -Username "jsmith"

.EXAMPLE
    .\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -OutputPath "C:\Reports"

.EXAMPLE
    .\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -Server dc01.contoso.com -Credential (Get-Credential)

.NOTES
    Requires: Windows PowerShell 3.0 or later; ActiveDirectory module (RSAT), imported at
              runtime in a try/catch.
    Run as:   Domain Admin or equivalent read access

    Limits: group membership is read from each object's memberOf attribute, so groups in
    OTHER domains of the forest that the user belongs to through a universal group are only
    seen if this DC can resolve them.

    The helper functions Get-PrivilegedGroupDefinition, Get-NameOnlyPrivilegedGroup,
    Find-PrivilegedGroupBySid and Resolve-ReportFilePath are shared verbatim with
    Get-DomainPrivilegedAccess.ps1; Tests\PrivilegedAccess.Tests.ps1 fails if they drift.

    REFERENCES
    - Well-known SIDs/RIDs: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    - Protected groups (AdminSDHolder): https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
    - primaryGroupID: https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    - DirectoryEntry.ObjectSecurity: https://learn.microsoft.com/dotnet/api/system.directoryservices.directoryentry.objectsecurity
    - CommonObjectSecurity.GetAccessRules: https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.commonobjectsecurity.getaccessrules
#>

[CmdletBinding(DefaultParameterSetName = 'Investigate')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Investigate', HelpMessage = "Enter the sAMAccountName of the user to investigate")]
    [string]$Username,

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
    [ValidateRange(1, 50)]
    [int]$MaxNestingDepth = 10,

    [Parameter(Mandatory = $true, ParameterSetName = 'LoadOnly')]
    [switch]$LoadFunctionsOnly
)

# Splatted into EVERY Active Directory cmdlet so -Server / -Credential are honoured everywhere.
$ADParams = @{}
if ($Server) { $ADParams['Server'] = $Server }
if ($Credential -and $Credential.UserName) { $ADParams['Credential'] = $Credential }

#region Shared helpers (kept identical in Get-DomainPrivilegedAccess.ps1)
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

#region Functions

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

function Get-UserGroupPath {
    <#
        Walks UP from the user, breadth-first, through memberOf and returns one row per group
        the user belongs to: MembershipType (Direct / Primary / Nested), NestingDepth and
        NestedVia (the groups between the user and this one, e.g. "Helpdesk -> IT-Admins").

        primaryGroupID is not part of memberOf, so the primary group is added as a separate
        starting point; its own parents are then followed like any other group.
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid

        Cycle safety: a group DN is added to the visited set before it is queued, so circular
        nesting is expanded once. Breadth-first order records the shortest path.

        Each row has .Privileged = the matching privileged-group definition (by SID, or by
        name for the name-only groups) or $null.
    #>
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [object[]]$Definitions = @(),
        [object[]]$NameOnly = @(),
        [int]$MaxNestingDepth = 10
    )

    $comparer = [StringComparer]::OrdinalIgnoreCase
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $comparer
    $rows = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Queue

    $addGroup = {
        param($g, $type, $depth, $via, $chain)
        $sidText = ''
        if ($g.SID) { $sidText = [string]$g.SID.Value; if (-not $sidText) { $sidText = [string]$g.SID } }
        $priv = Find-PrivilegedGroupBySid -Sid $sidText -Definitions $Definitions
        if (-not $priv) {
            foreach ($n in $NameOnly) { if ($n.Name -eq [string]$g.Name) { $priv = $n } }
        }
        $row = [PSCustomObject]@{
            Group          = $g
            GroupName      = [string]$g.Name
            GroupSid       = $sidText
            MembershipType = $type
            NestingDepth   = $depth
            NestedVia      = $via
            Privileged     = $priv
        }
        $rows.Add($row)
        $queue.Enqueue(@{ Group = $g; Chain = $chain; Depth = $depth })
    }

    foreach ($groupDn in @($User.MemberOf)) {
        if (-not $groupDn) { continue }
        if (-not $visited.Add([string]$groupDn)) { continue }
        try { $g = Get-ADGroup -Identity $groupDn @ADParams -Properties MemberOf, GroupCategory, GroupScope -ErrorAction Stop }
        catch { Write-Warning "Could not read group '$groupDn': $($_.Exception.Message)"; continue }
        & $addGroup $g 'Direct' 0 '' ([string]$g.Name)
    }

    if ($User.PrimaryGroupID) {
        try {
            $pg = Get-ADGroup -Identity "$DomainSid-$($User.PrimaryGroupID)" @ADParams -Properties MemberOf, GroupCategory, GroupScope -ErrorAction Stop
            if ($visited.Add([string]$pg.DistinguishedName)) {
                & $addGroup $pg 'Primary' 0 '' "$($pg.Name) (primary group)"
            }
        }
        catch { Write-Warning "Could not read primary group RID $($User.PrimaryGroupID): $($_.Exception.Message)" }
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        if ($item.Depth -ge $MaxNestingDepth) {
            Write-Warning "Nesting depth limit ($MaxNestingDepth) reached at '$($item.Group.Name)'; not descending further."
            continue
        }
        foreach ($parentDn in @($item.Group.MemberOf)) {
            if (-not $parentDn) { continue }
            if (-not $visited.Add([string]$parentDn)) { continue }
            try { $p = Get-ADGroup -Identity $parentDn @ADParams -Properties MemberOf, GroupCategory, GroupScope -ErrorAction Stop }
            catch { continue }
            & $addGroup $p 'Nested' ($item.Depth + 1) $item.Chain "$($item.Chain) -> $($p.Name)"
        }
    }

    return $rows.ToArray()
}

function Get-OuAccessRule {
    <#
        Reads an OU's ACL through System.DirectoryServices so -Server and -Credential apply
        (the AD: drive always uses the default DC). Rules come back as SIDs so they can be
        compared with the user's and groups' SIDs without name resolution.
    #>
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    $path = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
    if ($ADParams.ContainsKey('Credential')) {
        $net = $ADParams['Credential'].GetNetworkCredential()
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $ADParams['Credential'].UserName, $net.Password)
    }
    else {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
    }
    try {
        $security = $entry.ObjectSecurity
        return @($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    }
    finally {
        $entry.Dispose()
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity, # HIGH, MEDIUM, LOW, INFO
        [string]$Detail
    )

    $color = switch ($Severity) {
        "HIGH"   { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW"    { "DarkYellow" }
        "INFO"   { "Gray" }
        default  { "White" }
    }
    $icon = switch ($Severity) {
        "HIGH"   { "[!!]" }
        "MEDIUM" { "[!] " }
        "LOW"    { "[~] " }
        "INFO"   { "[i] " }
        default  { "    " }
    }

    Write-Host "  $icon " -ForegroundColor $color -NoNewline
    Write-Host "$Finding" -ForegroundColor White
    if ($Detail) {
        Write-Host "       $Detail" -ForegroundColor DarkGray
    }

    [void]$Findings.Add([PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Finding  = $Finding
        Detail   = $Detail
    })
}

#endregion

if ($LoadFunctionsOnly) { return }

#region Setup & Validation
$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "ActiveDirectory module not found. Install RSAT or run from a DC."
    return
}

try {
    $User = Get-ADUser -Identity $Username @ADParams -Properties `
        MemberOf, AdminCount, SIDHistory, PrimaryGroupID, `
        DistinguishedName, ObjectSID, ServicePrincipalName, `
        whenCreated, whenChanged, Enabled, PasswordLastSet, `
        LastLogonDate, Description
} catch {
    Write-Error "User '$Username' not found in Active Directory."
    return
}

$DomainInfo = Get-ADDomain @ADParams
$DomainDN = $DomainInfo.DistinguishedName
$DomainSID = $DomainInfo.DomainSID.Value
$PrivilegedGroupDefs = @(Get-PrivilegedGroupDefinition -DomainSid $DomainSID -RootDomainSid (Get-ForestRootDomainSid))
$NameOnlyGroups = @(Get-NameOnlyPrivilegedGroup)

Write-Host "`n" -NoNewline
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  PRIVILEGED ACCESS PATH ANALYSIS" -ForegroundColor Cyan
Write-Host "  User: $($User.SamAccountName) ($($User.Name))" -ForegroundColor Cyan
Write-Host "  DN:   $($User.DistinguishedName)" -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# Collector for export
$Findings = New-Object System.Collections.ArrayList

# Every group the user belongs to, with the path (one query pass shared by sections 1-3 and 6-7)
$MembershipRows = @(Get-UserGroupPath -User $User -DomainSid $DomainSID -Definitions $PrivilegedGroupDefs `
    -NameOnly $NameOnlyGroups -MaxNestingDepth $MaxNestingDepth)
#endregion

#region 1. Direct and primary-group privileged membership
Write-Host "-- 1. DIRECT PRIVILEGED GROUP MEMBERSHIP ------------------------" -ForegroundColor Yellow
Write-Host ""

$foundDirect = $false
foreach ($row in @($MembershipRows | Where-Object { $_.MembershipType -eq 'Direct' -and $_.Privileged })) {
    Add-Finding -Category "Direct Membership" -Severity "HIGH" `
        -Finding "DIRECT member of: $($row.Privileged.Name)" `
        -Detail "AD name: $($row.GroupName) | SID: $($row.GroupSid) | Scope: $($row.Group.GroupScope)"
    $foundDirect = $true
}
# primaryGroupID is not in memberOf, so this is the "hidden" one.
foreach ($row in @($MembershipRows | Where-Object { $_.MembershipType -eq 'Primary' -and $_.Privileged })) {
    Add-Finding -Category "Primary Group" -Severity "HIGH" `
        -Finding "Primary Group is privileged: $($row.Privileged.Name)" `
        -Detail "PrimaryGroupID: $($User.PrimaryGroupID) - This does NOT show in memberOf!"
    $foundDirect = $true
}
if (-not $foundDirect) {
    Add-Finding -Category "Direct Membership" -Severity "INFO" `
        -Finding "No direct membership in well-known privileged groups" -Detail $null
}
Write-Host ""
#endregion

#region 2. Nested group membership
Write-Host "-- 2. NESTED PRIVILEGED GROUP MEMBERSHIP ------------------------" -ForegroundColor Yellow
Write-Host ""

$foundNested = $false
foreach ($row in @($MembershipRows | Where-Object { $_.MembershipType -eq 'Nested' -and $_.Privileged })) {
    Add-Finding -Category "Nested Membership" -Severity "HIGH" `
        -Finding "NESTED member of: $($row.Privileged.Name)" `
        -Detail "Path: $($User.SamAccountName) -> $($row.NestedVia) -> $($row.GroupName) (depth $($row.NestingDepth))"
    $foundNested = $true
}
if (-not $foundNested) {
    Add-Finding -Category "Nested Membership" -Severity "INFO" `
        -Finding "No nested privileged group memberships detected" -Detail $null
}
Write-Host ""
#endregion

#region 3. AdminCount & AdminSDHolder
Write-Host "-- 3. ADMINCOUNT & ADMINSDHOLDER STATUS -------------------------" -ForegroundColor Yellow
Write-Host ""

if ($User.AdminCount -eq 1) {
    # Protected = a group AdminSDHolder/SDProp protects (see Get-PrivilegedGroupDefinition).
    $currentlyProtected = @($MembershipRows | Where-Object { $_.Privileged -and $_.Privileged.AdminSdHolder }).Count -gt 0

    if ($currentlyProtected) {
        Add-Finding -Category "AdminCount" -Severity "MEDIUM" `
            -Finding "AdminCount = 1 (ACTIVE - user IS in a protected group)" `
            -Detail "AdminSDHolder is actively protecting this account's ACL"
    } else {
        Add-Finding -Category "AdminCount" -Severity "HIGH" `
            -Finding "AdminCount = 1 but user is NOT in any protected group - ORPHANED!" `
            -Detail "This is likely your culprit. User was PREVIOUSLY in a privileged group. AdminCount was never cleared."
        Add-Finding -Category "AdminCount" -Severity "INFO" `
            -Finding "  -> FIX: Clear AdminCount and re-enable inheritance on the AD object" `
            -Detail "Set AdminCount to 0 (or clear it), then on the Security tab re-enable 'Include inheritable permissions'"
    }
} else {
    Add-Finding -Category "AdminCount" -Severity "INFO" `
        -Finding "AdminCount is not set (normal)" -Detail $null
}
Write-Host ""
#endregion

#region 4. SID History
Write-Host "-- 4. SID HISTORY -----------------------------------------------" -ForegroundColor Yellow
Write-Host ""

if ($User.SIDHistory -and @($User.SIDHistory).Count -gt 0) {
    foreach ($sid in $User.SIDHistory) {
        # Whole-RID match on a privileged SID from ANY domain (the old domain's SID).
        $privDef = Find-PrivilegedGroupBySid -Sid $sid.Value -Definitions $PrivilegedGroupDefs -AnyDomain
        if ($privDef) {
            Add-Finding -Category "SID History" -Severity "HIGH" `
                -Finding "SID History contains a PRIVILEGED SID!" `
                -Detail "SID: $($sid.Value) - maps to: $($privDef.Name)"
        } else {
            Add-Finding -Category "SID History" -Severity "MEDIUM" `
                -Finding "SID History entry found (non-privileged)" `
                -Detail "SID: $($sid.Value) - from a previous domain migration?"
        }
    }
} else {
    Add-Finding -Category "SID History" -Severity "INFO" `
        -Finding "No SID History entries" -Detail $null
}
Write-Host ""
#endregion

#region 5. Service Principal Names
Write-Host "-- 5. SERVICE PRINCIPAL NAMES -----------------------------------" -ForegroundColor Yellow
Write-Host ""

if ($User.ServicePrincipalName -and @($User.ServicePrincipalName).Count -gt 0) {
    Add-Finding -Category "SPN" -Severity "MEDIUM" `
        -Finding "User has Service Principal Names set (Kerberoastable!)" `
        -Detail "This means the account is running a service - may flag on priv reports"
    foreach ($spn in $User.ServicePrincipalName) {
        Add-Finding -Category "SPN" -Severity "INFO" `
            -Finding "  SPN: $spn" -Detail $null
    }
} else {
    Add-Finding -Category "SPN" -Severity "INFO" `
        -Finding "No Service Principal Names set" -Detail $null
}
Write-Host ""
#endregion

#region 6. Delegated permissions on OUs
Write-Host "-- 6. DELEGATED OU PERMISSIONS ----------------------------------" -ForegroundColor Yellow
Write-Host ""

# SIDs that carry the user's rights: the user plus every group (nested and primary included).
$principalSids = @{}
$principalSids[[string]$User.ObjectSID.Value] = $User.SamAccountName
foreach ($row in $MembershipRows) { if ($row.GroupSid) { $principalSids[$row.GroupSid] = $row.GroupName } }

$OUsToCheck = @($DomainDN) + @(Get-ADOrganizationalUnit -Filter * -SearchScope OneLevel @ADParams |
    Select-Object -ExpandProperty DistinguishedName | Select-Object -First 10)

$foundDelegation = $false
foreach ($ou in $OUsToCheck) {
    try {
        $rules = @(Get-OuAccessRule -DistinguishedName $ou)
    } catch {
        continue   # Skip OUs we can't read
    }
    foreach ($ace in $rules) {
        $sidKey = [string]$ace.IdentityReference.Value
        if (-not $principalSids.ContainsKey($sidKey)) { continue }
        if ($ace.AccessControlType -eq "Allow" -and $ace.ActiveDirectoryRights.ToString() -match "GenericAll|WriteDacl|WriteOwner|GenericWrite") {
            $who = $principalSids[$sidKey]
            $isUser = ($sidKey -eq [string]$User.ObjectSID.Value)
            $finding = if ($isUser) { "Delegated '$($ace.ActiveDirectoryRights)' on OU" } else { "Group '$who' has delegated '$($ace.ActiveDirectoryRights)' on OU" }
            $detail = if ($isUser) { "OU: $ou" } else { "OU: $ou - User is a member of this group" }
            Add-Finding -Category "Delegation" -Severity "MEDIUM" -Finding $finding -Detail $detail
            $foundDelegation = $true
        }
    }
}

if (-not $foundDelegation) {
    Add-Finding -Category "Delegation" -Severity "INFO" `
        -Finding "No direct delegation found on top-level OUs" `
        -Detail "Note: Only checked the domain root and up to 10 top-level OUs. Deep delegation may exist further down."
}
Write-Host ""
#endregion

#region 7. Complete group membership listing
Write-Host "-- 7. ALL GROUP MEMBERSHIPS -------------------------------------" -ForegroundColor Yellow
Write-Host ""

Write-Host "  All memberships (direct, primary group and nested):" -ForegroundColor White
foreach ($row in @($MembershipRows | Sort-Object NestingDepth, GroupName)) {
    $marker = ""
    if ($row.Privileged) { $marker += " <- PRIVILEGED ($($row.Privileged.Name))" }
    if ($row.MembershipType -eq 'Primary') { $marker += " (primary group)" }
    if ($row.MembershipType -eq 'Nested') { $marker += " (nested via $($row.NestedVia))" }
    $color = if ($row.Privileged) { "Red" } elseif ($row.MembershipType -eq 'Nested') { "Yellow" } else { "Gray" }
    Write-Host "    * $($row.GroupName)$marker" -ForegroundColor $color
}
Write-Host ""
#endregion

#region 8. Account details
Write-Host "-- 8. ACCOUNT DETAILS -------------------------------------------" -ForegroundColor Yellow
Write-Host ""

Write-Host "  Enabled:          $($User.Enabled)" -ForegroundColor Gray
Write-Host "  Created:          $($User.whenCreated)" -ForegroundColor Gray
Write-Host "  Last Modified:    $($User.whenChanged)" -ForegroundColor Gray
Write-Host "  Last Logon:       $($User.LastLogonDate)" -ForegroundColor Gray
Write-Host "  Password Set:     $($User.PasswordLastSet)" -ForegroundColor Gray
Write-Host "  Description:      $($User.Description)" -ForegroundColor Gray
Write-Host "  AdminCount:       $($User.AdminCount)" -ForegroundColor $(if ($User.AdminCount -eq 1) { "Red" } else { "Gray" })
Write-Host "  PrimaryGroupID:   $($User.PrimaryGroupID)" -ForegroundColor $(if ($User.PrimaryGroupID -ne 513) { "Yellow" } else { "Gray" })
Write-Host "  SID:              $($User.ObjectSID)" -ForegroundColor Gray
Write-Host ""
#endregion

#region Summary & Export
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

$highCount = @($Findings | Where-Object Severity -eq "HIGH").Count
$medCount  = @($Findings | Where-Object Severity -eq "MEDIUM").Count

if ($highCount -gt 0) {
    Write-Host "  [FAIL] $highCount HIGH severity finding(s) detected!" -ForegroundColor Red
}
if ($medCount -gt 0) {
    Write-Host "  [WARN] $medCount MEDIUM severity finding(s) detected." -ForegroundColor Yellow
}
if ($highCount -eq 0 -and $medCount -eq 0) {
    Write-Host "  [PASS] No obvious privileged access paths found." -ForegroundColor Green
    Write-Host "         The report tool may be keying on something else (local admin, GPO user rights, etc.)" -ForegroundColor Gray
}

Write-Host ""

if ($OutputPath) {
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $exportFile = Resolve-ReportFilePath -Path $OutputPath -DefaultFileName "PrivilegedAccessPaths_$($User.SamAccountName)_$stamp.csv"
    $Findings | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "  Report exported to: $exportFile" -ForegroundColor Green
    Write-Host ""
}

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""
#endregion
