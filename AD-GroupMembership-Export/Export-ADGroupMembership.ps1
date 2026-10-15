<#
.SYNOPSIS
    Exports Active Directory groups and their members to a flat CSV (one row per group-member pair).

.DESCRIPTION
    Enumerates AD groups and resolves the members of each one, producing a single flat CSV
    where every row is one membership fact: "this principal is in this group". That shape
    pivots cleanly in Excel and pastes into tickets.

    By default every group in the domain is exported. Narrow the scope with -GroupName
    (wildcards supported), -SearchBase (a specific OU), -GroupCategory, -GroupScope, or
    -ExcludeBuiltin.

    Four behaviors set this apart from a naive Get-ADGroupMember loop, each of which
    otherwise produces a confident, wrong answer:

    1. NESTED GROUPS ARE WALKED MANUALLY, NOT VIA -Recursive.
       Get-ADGroupMember -Recursive returns only leaf objects and discards the nesting
       path, so an auditor cannot see HOW a user got access. This script walks the tree
       itself and records MembershipType (Direct/Nested), NestingDepth, and the full
       NestedVia path.

    2. PRIMARY GROUP MEMBERSHIP IS RECONSTRUCTED.
       A user's primary group (normally "Domain Users") is stored in the user's
       primaryGroupID attribute and is NOT written to the group's member attribute.
       Microsoft does not document whether Get-ADGroupMember adds them back, and in
       practice it can, so neither source alone is reliable. This script queries
       primaryGroupID directly, marks those members MembershipType 'Primary', and
       merges them with Get-ADGroupMember's output so each appears once - not as a
       false "duplicate access" Direct + Primary pair. Suppress with
       -SkipPrimaryGroupMembers on very large domains.

    3. NON-USER MEMBERS ARE KEPT.
       Groups can contain users, groups, and computers. Filtering to users only makes a
       group whose members are all nested groups look empty. Use -UserMembersOnly if you
       genuinely want just users.

    4. REDUNDANT ACCESS PATHS ARE REPORTED, NOT COLLAPSED (-UserReport).
       Nesting routinely grants the same group by several routes at once - directly and
       again through a nested chain, or through two branches that both lead to the same
       place. A report that silently de-duplicates hides this, and the consequence is a
       failed access removal: the account is pulled from one group, the ticket closes, and
       the user still has the access through the route nobody saw. The user-centric report
       shows one entry per group but flags every group reachable more than once, lists the
       other routes, and ranks users by how many surplus paths they hold.

.PARAMETER Server
    Domain controller or domain to query. Passed to every AD cmdlet as -Server. Defaults to
    the DC the local machine authenticates against.

.PARAMETER Credential
    Credentials for the AD queries. Defaults to the calling user.

.PARAMETER GroupName
    One or more group names to export. Wildcards are supported ('HR-*'). Matched against
    both Name and SamAccountName. Omit to export every group in scope.

.PARAMETER SearchBase
    Distinguished name of an OU to search under. Omit to search the whole domain.

.PARAMETER GroupCategory
    Limit to 'Security' or 'Distribution' groups.

.PARAMETER GroupScope
    Limit to 'DomainLocal', 'Global', or 'Universal' groups.

.PARAMETER ExcludeBuiltin
    Skip groups in the CN=Builtin container and the well-known low-RID service groups,
    which are rarely interesting in an access review.

.PARAMETER IncludeNested
    Expand nested groups and report the inherited members with their nesting path.
    Without this, only direct members are reported.

.PARAMETER MaxNestingDepth
    Safety limit on nested-group recursion. Defaults to 10. Circular nesting is detected
    and broken regardless of this value.

.PARAMETER UserMembersOnly
    Emit only user members. By default users, groups, and computers are all reported.

.PARAMETER SkipPrimaryGroupMembers
    Skip reconstruction of primary-group membership. Faster on large domains, at the cost
    of "Domain Users" and similar groups appearing empty.

.PARAMETER IncludeEmptyGroups
    Emit a placeholder row for groups with no members, so the export lists every group.
    Without this, empty groups are absent from the CSV.

.PARAMETER UserReport
    Additionally write a user-centric view of the same data: one entry per user listing
    every group they hold and how they got it. Produces an HTML report for reading and a
    pivoted CSV for filtering, alongside the normal group CSV. No extra AD queries are
    issued - the user view is a transform over rows already collected.

    Groups reachable by more than one path are flagged as duplicates rather than collapsed;
    see the DESCRIPTION above for why that matters. Combine with -IncludeNested, without
    which there are no inherited paths to compare.

.PARAMETER IncludeDisabled
    Include disabled user accounts in the user-centric report. By default only enabled
    accounts appear, since an access review is normally about who can currently log in.
    Has no effect on the group CSV, which always reports what the directory contains.

.PARAMETER OutputPath
    Directory for the CSV and log. Defaults to the current directory.

.EXAMPLE
    .\Export-ADGroupMembership.ps1
    Exports every group in the current domain with its direct members.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -IncludeNested -ExcludeBuiltin
    The usual access-review run: real groups only, with nested membership expanded and
    the nesting path recorded.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -GroupName 'HR-*','Finance-*' -IncludeNested
    Exports the HR and Finance group trees.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -Server DC01.contoso.com -SearchBase 'OU=Groups,DC=contoso,DC=com' -OutputPath C:\Reports
    Queries a specific DC, limited to one OU.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -IncludeNested -ExcludeBuiltin -UserReport -OutputPath C:\Reports
    The access-review run. Writes the group CSV plus a user-centric HTML report and CSV
    showing every enabled user, the groups they hold, how they got each one, and which
    groups they hold by more than one path.

.EXAMPLE
    .\Export-ADGroupMembership.ps1 -IncludeNested -UserReport -IncludeDisabled
    Same as above but keeps disabled accounts, for offboarding verification.

.NOTES
    Author  : VC3 Scripts Collection
    Requires: PowerShell 3.0 or later, ActiveDirectory RSAT module, read access to the
              directory. Administrator rights are NOT required - directory read is enough.
              Runs on Windows Server 2012 (PS 3.0) and 2012 R2 (PS 4.0) as shipped; no
              WMF upgrade is needed.

    REFERENCES
    - PowerShell Support Lifecycle (Windows PowerShell release history: 3.0 shipped with
      Windows Server 2012, 4.0 with Windows Server 2012 R2, 5.1 with Windows Server 2016)
      https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
    - Install Remote Server Administration Tools (Install-WindowsFeature on Windows
      Server; Add-WindowsCapability is the Windows client method)
      https://learn.microsoft.com/windows-server/administration/install-remote-server-administration-tools
    - Get-ADGroupMember (-Recursive returns only members "that do not contain child
      objects"; members "can be users, groups, and computers"; fails on cross-forest
      members without AD Web Service)
      https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember
    - Get-ADGroup (-Filter / -SearchBase syntax, GroupCategory and GroupScope values,
      default vs -Properties property sets)
      https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup
    - Primary-Group-ID attribute ("Contains the relative identifier (RID) for the primary
      group of the user. By default, this is the RID for the Domain Users group."
      Link-Id is empty, so it is not a linked attribute and does not appear in 'member')
      https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    - Is-Member-Of-DL (memberOf): a back-link (Link-Id 3) held on the DC queried; used to
      follow nesting upward for the Nesting tab, so cross-domain parents may not appear
      https://learn.microsoft.com/windows/win32/adschema/a-memberof
    - Protected accounts and groups (Appendix C): the groups the Nesting tab highlights
      https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
    - Well-known SIDs: S-1-5-32-544/548/549/550/551/552 and domain RIDs 512/516/518/519/
      521/526/527, used to recognise protected groups whatever their name
      https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
#>

# 3.0, not 5.1: Server 2012 ships PowerShell 3.0 and 2012 R2 ships 4.0, and a 5.1
# requirement blocks the script before any code runs on those servers. Nothing here needs
# more than 3.0 ([Parameter(Mandatory)] and [PSCustomObject] are the 3.0 floor). Keep it
# that way: no '::new()', no class/enum, no 5.x-only cmdlets. Tests\Compatibility.Tests.ps1
# enforces this.
# https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#Requires -Version 3.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string[]]$GroupName,

    [Parameter(Mandatory = $false)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Security', 'Distribution')]
    [string]$GroupCategory,

    [Parameter(Mandatory = $false)]
    [ValidateSet('DomainLocal', 'Global', 'Universal')]
    [string]$GroupScope,

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeBuiltin,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNested,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
    [int]$MaxNestingDepth = 10,

    [Parameter(Mandatory = $false)]
    [switch]$UserMembersOnly,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPrimaryGroupMembers,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeEmptyGroups,

    [Parameter(Mandatory = $false)]
    [switch]$UserReport,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path
)

#region Setup

$ErrorActionPreference = 'Stop'
$script:LogLines = New-Object System.Collections.Generic.List[string]
$script:LogFile = $null

function Write-Status {
    <#
        Dual output: color-coded console plus an accumulated log written at the end.
        Status prefixes follow the repo convention: [PASS] [WARN] [FAIL] [INFO].
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )

    $color = switch ($Level) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Cyan' }
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$Level] $Message" -ForegroundColor $color
    $script:LogLines.Add("[$timestamp] [$Level] $Message")
}

function Confirm-FileWritten {
    <#
        Re-reads a file after writing it and reports its real size on disk.

        Out-File and Export-Csv returning without an exception is not proof that content
        landed: a full disk, a quota, or a sync client can leave a zero-byte file behind
        while the write appears to succeed. Reporting [PASS] on an empty file sends someone
        away with a blank report and no idea anything went wrong, so the size is checked
        and a zero-length result is downgraded to a failure.

        Returns $true when the file exists and holds at least MinimumBytes.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [int]$MinimumBytes = 1
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Status "$Description was not created at $Path" 'FAIL'
        return $false
    }

    $size = (Get-Item -LiteralPath $Path).Length

    if ($size -eq 0) {
        Write-Status "$Description is empty (0 bytes) at $Path - the write reported success but no content reached disk. Check free space, and that the target is not a cloud-sync placeholder folder." 'FAIL'
        return $false
    }

    if ($size -lt $MinimumBytes) {
        Write-Status "$Description is smaller than expected ($size bytes, expected at least $MinimumBytes) at $Path - the file is likely truncated. Re-run before using it." 'FAIL'
        return $false
    }

    $friendly = if ($size -ge 1MB) { '{0:N1} MB' -f ($size / 1MB) }
                elseif ($size -ge 1KB) { '{0:N1} KB' -f ($size / 1KB) }
                else { "$size bytes" }
    Write-Status "$Description written ($friendly): $Path" 'PASS'
    return $true
}

# Splatted onto every AD cmdlet so remote targeting and credentials are never forgotten
# on an individual call.
$ADParams = @{}
if ($PSBoundParameters.ContainsKey('Server') -and $Server) { $ADParams['Server'] = $Server }
if ($PSBoundParameters.ContainsKey('Credential') -and $Credential) { $ADParams['Credential'] = $Credential }

#endregion

#region Module load

# Runtime import rather than '#Requires -Modules ActiveDirectory': the Requires directive
# aborts before the script runs when the module is not registered in the standard path,
# which is common on servers where RSAT cmdlets are otherwise usable.
try {
    if (-not (Get-Module -Name ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    }
}
catch {
    Write-Host "[FAIL] Could not load the ActiveDirectory module: $($_.Exception.Message)" -ForegroundColor Red
    # Add-WindowsCapability does not exist on Windows Server; servers use Install-WindowsFeature.
    # https://learn.microsoft.com/windows-server/administration/install-remote-server-administration-tools
    Write-Host "[INFO] Install RSAT on Windows Server : Install-WindowsFeature RSAT-AD-Tools -IncludeAllSubFeature" -ForegroundColor Cyan
    Write-Host "[INFO] Install RSAT on Windows 10/11  : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Cyan
    exit 1
}

#endregion

#region Output path

if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Host "[FAIL] Could not create output directory '$OutputPath': $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path

# Writing into a cloud-synced folder is legal but risky to hand off: the sync client can
# convert the files to placeholders, and copying a placeholder elsewhere copies the stub
# rather than the content - producing files that exist but are zero bytes on arrival.
# Warn rather than block, since writing to a synced folder is sometimes exactly what is
# wanted; the danger is only in copying them onward before they have hydrated.
# Each name must be a whole path segment, or innocent folders like C:\Boxing match too.
if ($OutputPath -match '(?i)\\(OneDrive( - [^\\]+)?|Dropbox|Box|Google Drive|iCloudDrive)(\\|$)') {
    Write-Host "[WARN] Output is inside a cloud-synced folder ($OutputPath)." -ForegroundColor Yellow
    Write-Host "[WARN] Before copying these files anywhere, confirm they show a real size and not 0 bytes - un-synced placeholders copy as empty files." -ForegroundColor Yellow
}
$runStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$csvFile = Join-Path $OutputPath "ADGroupMembership_$runStamp.csv"
$script:LogFile = Join-Path $OutputPath "ADGroupMembership_$runStamp.log"

#endregion

#region Helpers

function Get-DomainContext {
    <#
        Resolves the domain SID and DNS name once. The domain SID is required to turn a
        user's primaryGroupID (a RID) back into a full group SID.
    #>
    try {
        $domain = Get-ADDomain @ADParams -ErrorAction Stop
        return [PSCustomObject]@{
            DomainSid  = $domain.DomainSID.Value
            DnsRoot    = $domain.DNSRoot
            NetBIOS    = $domain.NetBIOSName
            DomainDN   = $domain.DistinguishedName
        }
    }
    catch {
        Write-Status "Could not read domain information: $($_.Exception.Message)" 'FAIL'
        throw
    }
}

function Get-TargetGroup {
    <#
        Builds the group list. -Filter '*' plus client-side name matching is used instead
        of embedding wildcards in the AD filter, so that '*' behaves like a PowerShell
        wildcard against both Name and SamAccountName rather than an LDAP substring match.
    #>
    $searchParams = @{ Filter = '*' } + $ADParams
    $searchParams['Properties'] = @(
        'Description', 'GroupCategory', 'GroupScope', 'Created', 'Modified',
        'ManagedBy', 'mail', 'info', 'MemberOf'
    )
    if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }

    Write-Status "Enumerating groups$(if ($SearchBase) { " under $SearchBase" })..."
    $groups = @(Get-ADGroup @searchParams)
    Write-Status "Found $($groups.Count) group(s) before filtering."

    if ($GroupCategory) {
        $groups = @($groups | Where-Object { $_.GroupCategory -eq $GroupCategory })
        Write-Status "After GroupCategory '$GroupCategory' filter: $($groups.Count)."
    }

    if ($GroupScope) {
        $groups = @($groups | Where-Object { $_.GroupScope -eq $GroupScope })
        Write-Status "After GroupScope '$GroupScope' filter: $($groups.Count)."
    }

    if ($GroupName) {
        $groups = @($groups | Where-Object {
            $g = $_
            $GroupName | Where-Object { $g.Name -like $_ -or $g.SamAccountName -like $_ }
        })
        Write-Status "After name filter: $($groups.Count)."
    }

    if ($ExcludeBuiltin) {
        # CN=Builtin holds the well-known local groups. The RID test additionally drops
        # the built-in domain groups (Domain Admins 512, Domain Users 513, ...) that live
        # in CN=Users; RIDs below 1000 are reserved for well-known principals.
        $groups = @($groups | Where-Object {
            $_.DistinguishedName -notmatch ',CN=Builtin,' -and
            -not ($_.SID.Value -match '-(\d+)$' -and [int]$Matches[1] -lt 1000)
        })
        Write-Status "After -ExcludeBuiltin: $($groups.Count)."
    }

    return $groups
}

function New-MembershipRow {
    <#
        The single place where a CSV row is shaped, so every emission path stays schema-identical.
    #>
    param(
        $Group,
        $Member,
        [string]$MembershipType,
        [int]$NestingDepth,
        [string]$NestedVia,
        $UserDetail
    )

    [PSCustomObject]@{
        GroupName          = $Group.Name
        GroupSamAccountName = $Group.SamAccountName
        GroupCategory      = $Group.GroupCategory
        GroupScope         = $Group.GroupScope
        GroupDescription   = $Group.Description
        GroupDN            = $Group.DistinguishedName
        MemberName         = if ($Member) { $Member.Name } else { $null }
        MemberSamAccountName = if ($Member) { $Member.SamAccountName } else { $null }
        MemberType         = if ($Member) { $Member.objectClass } else { $null }
        MembershipType     = $MembershipType
        NestingDepth       = $NestingDepth
        NestedVia          = $NestedVia
        DisplayName        = if ($UserDetail) { $UserDetail.DisplayName } else { $null }
        UserPrincipalName  = if ($UserDetail) { $UserDetail.UserPrincipalName } else { $null }
        EmailAddress       = if ($UserDetail) { $UserDetail.EmailAddress } else { $null }
        Department         = if ($UserDetail) { $UserDetail.Department } else { $null }
        Title              = if ($UserDetail) { $UserDetail.Title } else { $null }
        Enabled            = if ($UserDetail) { $UserDetail.Enabled } else { $null }
        LastLogonDate      = if ($UserDetail) { $UserDetail.LastLogonDate } else { $null }
        PasswordLastSet    = if ($UserDetail) { $UserDetail.PasswordLastSet } else { $null }
        MemberDN           = if ($Member) { $Member.DistinguishedName } else { $null }
        ExportDate         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

$script:UserCache = @{}

function Get-UserDetail {
    <#
        Looks up the descriptive attributes for a user or computer member, cached by DN
        because a single account commonly appears in many groups.
    #>
    param([string]$DistinguishedName, [string]$ObjectClass)

    if ($script:UserCache.ContainsKey($DistinguishedName)) {
        return $script:UserCache[$DistinguishedName]
    }

    $detail = $null
    try {
        if ($ObjectClass -eq 'user') {
            $detail = Get-ADUser -Identity $DistinguishedName @ADParams -ErrorAction Stop -Properties `
                DisplayName, UserPrincipalName, EmailAddress, Department, Title,
                Enabled, LastLogonDate, PasswordLastSet
        }
        elseif ($ObjectClass -eq 'computer') {
            $c = Get-ADComputer -Identity $DistinguishedName @ADParams -ErrorAction Stop -Properties `
                DisplayName, Enabled, LastLogonDate
            # Shaped to match the user schema so the CSV columns stay consistent.
            $detail = [PSCustomObject]@{
                DisplayName       = $c.DisplayName
                UserPrincipalName = $null
                EmailAddress      = $null
                Department        = $null
                Title             = $null
                Enabled           = $c.Enabled
                LastLogonDate     = $c.LastLogonDate
                PasswordLastSet   = $null
            }
        }
    }
    catch {
        # A member that cannot be resolved (deleted, cross-forest, or no read access)
        # still belongs in the export as a membership fact - just without detail.
        Write-Verbose "Could not resolve detail for '$DistinguishedName': $($_.Exception.Message)"
    }

    $script:UserCache[$DistinguishedName] = $detail
    return $detail
}

# Group-in-group links seen anywhere in the walk, for the report's Nesting tab:
# parentDN -> @{ childDN = $true }. Hashtable keys ignore case, so a DN seen with different
# casing from two roots is stored once.
$script:NestEdges = @{}
$script:NestNames = @{}

function Add-NestEdge {
    # Records "ChildDN is a direct member of ParentDN".
    param(
        [Parameter(Mandatory)][hashtable]$Edges,
        [Parameter(Mandatory)][string]$ParentDN,
        [Parameter(Mandatory)][string]$ChildDN
    )
    if (-not $Edges.ContainsKey($ParentDN)) { $Edges[$ParentDN] = @{} }
    $Edges[$ParentDN][$ChildDN] = $true
}

function Test-ProtectedGroupSid {
    <#
        Microsoft's protected groups (Appendix C), matched by SID so a renamed or localised
        group is still recognised. Domain-relative groups match by RID on any S-1-5-21 SID,
        which also catches forest-root groups (Schema/Enterprise Admins) seen from a child
        domain. The Administrator and Krbtgt accounts are on the list too but are not groups.
        https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>
    param([AllowEmptyString()][AllowNull()][string]$Sid)
    if (-not $Sid) { return $false }
    if ($Sid -match '^S-1-5-32-(544|548|549|550|551|552)$') { return $true }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(512|516|518|519|521|526|527)$') { return $true }
    return $false
}

function Test-BuiltinGroup {
    # Built-in: in CN=Builtin, a BUILTIN (S-1-5-32) SID, or a well-known RID below 1000 -
    # the same rule -ExcludeBuiltin uses.
    param([AllowEmptyString()][string]$DistinguishedName, [AllowEmptyString()][AllowNull()][string]$Sid)
    if ($DistinguishedName -match '(?i),CN=Builtin,') { return $true }
    if ($Sid -match '^S-1-5-32-') { return $true }
    if ($Sid -match '^S-1-5-21-.*-(\d+)$' -and [int]$Matches[1] -lt 1000) { return $true }
    return $false
}

function Resolve-NestGraph {
    <#
        Completes the nesting graph upward, for the report's Nesting tab.

        Exported groups bring their memberOf (requested in Get-TargetGroup, no extra query).
        Any group not in the export - a parent found through memberOf, or a child group the
        walk saw - is looked up once with Get-ADGroup (via -Lookup), and its own memberOf is
        followed, until nothing new appears. memberOf is a back-link held on the DC queried,
        so nesting into groups in other domains of a forest may not appear.
        https://learn.microsoft.com/windows/win32/adschema/a-memberof

        Bounded: each DN is looked up at most once, and at most -Cap lookups are made. A
        lookup that fails (deleted, no rights, other forest) and anything left past the cap
        become 'unresolved' nodes, so every edge still points at a node and the run continues.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Groups,
        [Parameter(Mandatory)][hashtable]$Edges,
        [Parameter(Mandatory)][scriptblock]$Lookup,
        [hashtable]$Names = @{},
        [int]$Cap = 1000
    )

    $nodes = @{}
    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $lookups = 0
    $capReached = $false

    function Add-ResolvedNode($Group, [bool]$InExport) {
        $sid = ''
        if ($Group.SID -is [string]) { $sid = $Group.SID }
        elseif ($Group.SID) { $sid = [string]$Group.SID.Value }
        $nodes[[string]$Group.DistinguishedName] = [PSCustomObject]@{
            DN = [string]$Group.DistinguishedName; Name = [string]$Group.Name; Sam = [string]$Group.SamAccountName
            Category = [string]$Group.GroupCategory; Scope = [string]$Group.GroupScope; Sid = $sid
            InExport = $InExport; Unresolved = $false
        }
        foreach ($parent in $Group.MemberOf) {
            if (-not $parent) { continue }
            Add-NestEdge -Edges $Edges -ParentDN ([string]$parent) -ChildDN ([string]$Group.DistinguishedName)
            if (-not $nodes.ContainsKey([string]$parent)) { $queue.Enqueue([string]$parent) }
        }
    }
    function Add-UnresolvedNode([string]$DN) {
        $name = if ($Names.ContainsKey($DN)) { [string]$Names[$DN] } else { Get-DnFirstValue $DN }
        $nodes[$DN] = [PSCustomObject]@{ DN = $DN; Name = $name; Sam = ''; Category = ''; Scope = ''; Sid = ''
            InExport = $false; Unresolved = $true }
    }

    foreach ($g in $Groups) { if ($g) { Add-ResolvedNode $g $true } }
    foreach ($parent in [string[]]$Edges.Keys) {
        if (-not $nodes.ContainsKey($parent)) { $queue.Enqueue($parent) }
        foreach ($child in [string[]]$Edges[$parent].Keys) {
            if (-not $nodes.ContainsKey($child)) { $queue.Enqueue($child) }
        }
    }

    while ($queue.Count -gt 0) {
        $dn = $queue.Dequeue()
        if ($nodes.ContainsKey($dn)) { continue }
        if ($lookups -ge $Cap) { $capReached = $true; Add-UnresolvedNode $dn; continue }
        $lookups++
        $found = $null
        try { $found = & $Lookup $dn } catch { $found = $null }
        if ($found) { Add-ResolvedNode $found $false } else { Add-UnresolvedNode $dn }
    }

    return [PSCustomObject]@{ Nodes = $nodes; CapReached = $capReached; Lookups = $lookups }
}

function Resolve-GroupMembership {
    <#
        Walks a group's membership tree.

        Deliberately does NOT use Get-ADGroupMember -Recursive. Per Microsoft's docs that
        switch "gets all members in the hierarchy of the group that do not contain child
        objects" - it returns leaves only and discards the path taken to reach them, which
        is precisely the information an access review needs. Walking manually preserves
        NestingDepth and NestedVia, and lets nested groups themselves appear as members.

        $VisitedGroups guards against circular nesting (A contains B contains A), which AD
        permits and which would otherwise recurse until MaxNestingDepth on every branch.
    #>
    param(
        $Group,
        $RootGroup,
        [int]$Depth = 0,
        [string]$Path = '',
        [System.Collections.Generic.HashSet[string]]$VisitedGroups
    )

    $rows = New-Object System.Collections.Generic.List[object]

    if ($Depth -gt $MaxNestingDepth) {
        Write-Status "Nesting depth limit ($MaxNestingDepth) reached under '$($RootGroup.Name)' at '$($Group.Name)'; not descending further." 'WARN'
        return $rows
    }

    $members = @()
    try {
        # No -Recursive: one level at a time, so the path is preserved.
        $members = @(Get-ADGroupMember -Identity $Group.DistinguishedName @ADParams -ErrorAction Stop)
    }
    catch {
        # Per Microsoft's docs this cmdlet fails outright when a group holds members from
        # another forest without AD Web Service reachable. Isolate it to this group so one
        # bad group does not abort the export.
        Write-Status "Could not read members of '$($Group.Name)': $($_.Exception.Message)" 'WARN'
        return $rows
    }

    foreach ($member in $members) {
        $membershipType = if ($Depth -eq 0) { 'Direct' } else { 'Nested' }

        if ($member.objectClass -eq 'group') {
            # Recorded before the cycle check below, so a loop's closing link is kept too.
            Add-NestEdge -Edges $script:NestEdges -ParentDN $Group.DistinguishedName -ChildDN $member.DistinguishedName
            $script:NestNames[$Group.DistinguishedName] = $Group.Name
            $script:NestNames[$member.DistinguishedName] = $member.Name

            # Record the nested group itself as a member unless the caller asked for users
            # only. Omitting this is what makes a container group look empty.
            if (-not $UserMembersOnly) {
                $rows.Add((New-MembershipRow -Group $RootGroup -Member $member `
                    -MembershipType $membershipType -NestingDepth $Depth -NestedVia $Path -UserDetail $null))
            }

            if ($IncludeNested) {
                if (-not $VisitedGroups.Add($member.DistinguishedName)) {
                    Write-Status "Circular nesting detected under '$($RootGroup.Name)': '$($member.Name)' already visited; skipping." 'WARN'
                    continue
                }

                $childPath = if ($Path) { "$Path -> $($member.Name)" } else { $member.Name }
                $childGroup = [PSCustomObject]@{
                    Name              = $member.Name
                    DistinguishedName = $member.DistinguishedName
                }

                # @(...) is required: PowerShell unrolls a single-element List to a bare
                # object on return, which AddRange rejects - silently losing deeply
                # nested members. Forcing an array keeps one-member branches intact.
                $childRows = @(Resolve-GroupMembership -Group $childGroup -RootGroup $RootGroup `
                    -Depth ($Depth + 1) -Path $childPath -VisitedGroups $VisitedGroups)
                if ($childRows.Count -gt 0) { $rows.AddRange([object[]]$childRows) }
            }
        }
        else {
            if ($UserMembersOnly -and $member.objectClass -ne 'user') { continue }

            $detail = Get-UserDetail -DistinguishedName $member.DistinguishedName -ObjectClass $member.objectClass
            $rows.Add((New-MembershipRow -Group $RootGroup -Member $member `
                -MembershipType $membershipType -NestingDepth $Depth -NestedVia $Path -UserDetail $detail))
        }
    }

    return $rows
}

function Get-PrimaryGroupMember {
    <#
        Reconstructs primary-group membership.

        primaryGroupID holds "the relative identifier (RID) for the primary group of the
        user. By default, this is the RID for the Domain Users group." It is not a linked
        attribute, so these members never appear in the group's 'member' attribute and
        Get-ADGroupMember cannot see them. Without this, "Domain Users" exports as empty -
        a wrong answer that looks like a correct one.

        The group SID is <domain SID>-<RID>, so the RID is recovered from the tail of the
        group's SID and users are matched on it.
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    #>
    param($Group, $Context)

    $rows = New-Object System.Collections.Generic.List[object]

    $groupSid = $Group.SID.Value
    if ($groupSid -notmatch '-(\d+)$') { return $rows }
    $rid = [int]$Matches[1]

    # Primary group must be a Global or Universal group in the same domain; a DomainLocal
    # group cannot be a primary group, so skip the query entirely for those.
    if ($Group.GroupScope -eq 'DomainLocal') { return $rows }
    if (-not $groupSid.StartsWith($Context.DomainSid)) { return $rows }

    try {
        $primaryMembers = @(Get-ADUser -Filter "primaryGroupID -eq $rid" @ADParams -ErrorAction Stop -Properties `
            DisplayName, UserPrincipalName, EmailAddress, Department, Title,
            Enabled, LastLogonDate, PasswordLastSet, primaryGroupID)
    }
    catch {
        Write-Status "Could not query primary-group members for '$($Group.Name)': $($_.Exception.Message)" 'WARN'
        return $rows
    }

    foreach ($u in $primaryMembers) {
        $memberStub = [PSCustomObject]@{
            Name              = $u.Name
            SamAccountName    = $u.SamAccountName
            objectClass       = 'user'
            DistinguishedName = $u.DistinguishedName
        }

        $rows.Add((New-MembershipRow -Group $Group -Member $memberStub `
            -MembershipType 'Primary' -NestingDepth 0 -NestedVia '' -UserDetail $u))
    }

    return $rows
}

function Merge-PrimaryGroupRows {
    <#
        Combines a group's member rows with its primary-group rows so each primary member
        appears once.

        Get-ADGroupMember can return users whose primaryGroupID points at the group, even
        though they are not in its 'member' attribute (Microsoft does not document this
        either way). Adding the Get-PrimaryGroupMember rows on top then gave those users a
        Direct row AND a Primary row for the same group, and the user report flagged them
        "1 duplicate - 1 extra path". That is false: AD only allows a primary group the
        user is already a member of, so it is one membership, not two removable routes.

        The Primary row is kept (it says how the access is held) and the depth-0 Direct
        row for the same member is dropped. Nested rows are kept: reaching the group again
        through a nested group IS a separate route that has to be removed on its own.
        When Get-ADGroupMember does not return primary members, nothing overlaps and the
        output is unchanged.
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    #>
    param(
        [AllowEmptyCollection()][object[]]$MemberRows,
        [AllowEmptyCollection()][object[]]$PrimaryRows
    )

    $merged = New-Object System.Collections.Generic.List[object]
    $primaryDns = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @($PrimaryRows)) { if ($p -and $p.MemberDN) { [void]$primaryDns.Add($p.MemberDN) } }

    $collapsed = 0
    foreach ($r in @($MemberRows)) {
        if (-not $r) { continue }
        if ($r.MembershipType -eq 'Direct' -and $r.MemberDN -and $primaryDns.Contains($r.MemberDN)) {
            $collapsed++
            continue
        }
        $merged.Add($r)
    }

    $added = 0
    foreach ($p in @($PrimaryRows)) { if ($p) { $merged.Add($p); $added++ } }

    if ($added -gt 0) {
        $note = if ($collapsed -gt 0) { " ($collapsed already returned by Get-ADGroupMember; counted once)" } else { '' }
        Write-Status "  + $added primary-group member(s)$note."
    }

    # Unrolls on return; callers wrap the call in @() as everywhere else in this script.
    return $merged.ToArray()
}

#endregion

#region User-centric report
# Everything below is a pure transform over the flat membership rows already collected.
# No additional AD queries are issued: every fact needed for the user view (nesting path,
# membership type, user detail) is already present on the rows produced by
# New-MembershipRow. Keeping this side-effect free is what makes it testable without a
# domain.

function Get-StrongestPathRank {
    <#
        Lower rank wins. Direct access is the strongest claim on a group, then primary-group
        membership, then nested membership ordered by how far away it is. Used to decide
        which of several paths to a group is shown as the headline path.
    #>
    param(
        [Parameter(Mandatory)][string]$MembershipType,
        [int]$NestingDepth = 0
    )

    switch ($MembershipType) {
        'Direct'  { return 0 }
        'Primary' { return 1 }
        # Nested paths rank behind Direct/Primary and then by distance, so a depth-1
        # inheritance is reported ahead of a depth-4 one.
        'Nested'  { return 100 + $NestingDepth }
        default   { return 1000 }
    }
}

function Format-AccessPath {
    <#
        Renders one membership route as human-readable text. NestedVia already holds the
        chain of groups traversed to reach the member; the group itself is appended so the
        route reads end to end.
    #>
    param(
        [Parameter(Mandatory)]$Row
    )

    switch ($Row.MembershipType) {
        'Direct'  { return 'Direct member' }
        'Primary' { return 'Primary group (primaryGroupID)' }
        'Nested'  {
            if ([string]::IsNullOrWhiteSpace($Row.NestedVia)) {
                return "Nested (depth $($Row.NestingDepth))"
            }
            return "$($Row.NestedVia) -> $($Row.GroupName)"
        }
        default   { return $Row.MembershipType }
    }
}

function ConvertTo-UserAccessModel {
    <#
        Pivots flat group-member rows into one object per user, each carrying that user's
        groups and every route by which they reach each group.

        Redundant grants are the reason this does not simply de-duplicate. When a user
        reaches the same group by more than one route, removing one route does not remove
        their access - which is how access-removal tickets get closed while the user still
        has the access. Those cases are counted and flagged rather than collapsed away.

        Users are keyed by MemberDN because the distinguished name is the stable identity;
        two objects can share a display name, and SamAccountName is absent on some
        foreign security principals.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
        [switch]$IncludeDisabled
    )

    $userRows = @($Rows | Where-Object {
        $_.MemberType -eq 'user' -and $_.MemberDN -and $_.MembershipType -ne 'EmptyGroup'
    })

    if (-not $IncludeDisabled) {
        # Enabled is $null when user detail could not be read (for example a member from a
        # trusted domain). Those are kept rather than silently dropped: an unknown state is
        # not evidence of a disabled account.
        $userRows = @($userRows | Where-Object { $_.Enabled -ne $false })
    }

    $users = New-Object System.Collections.Generic.List[object]

    foreach ($userGroup in ($userRows | Group-Object -Property MemberDN)) {

        # Any row for this user carries the same user detail; take the first that has it.
        $sample = $userGroup.Group | Where-Object { $_.DisplayName } | Select-Object -First 1
        if (-not $sample) { $sample = $userGroup.Group[0] }

        $groupEntries = New-Object System.Collections.Generic.List[object]

        foreach ($byGroup in ($userGroup.Group | Group-Object -Property GroupDN)) {

            $paths = @($byGroup.Group | Sort-Object {
                Get-StrongestPathRank -MembershipType $_.MembershipType -NestingDepth $_.NestingDepth
            })

            $primaryPath = $paths[0]
            $extraPaths = @($paths | Select-Object -Skip 1)

            $groupEntries.Add([PSCustomObject]@{
                GroupName           = $primaryPath.GroupName
                GroupSamAccountName = $primaryPath.GroupSamAccountName
                GroupCategory       = $primaryPath.GroupCategory
                GroupScope          = $primaryPath.GroupScope
                GroupDescription    = $primaryPath.GroupDescription
                GroupDN             = $primaryPath.GroupDN
                MembershipType      = $primaryPath.MembershipType
                NestingDepth        = $primaryPath.NestingDepth
                NestedVia           = $primaryPath.NestedVia
                PrimaryPathText     = (Format-AccessPath -Row $primaryPath)
                PathCount           = $paths.Count
                IsRedundant         = ($paths.Count -gt 1)
                AllPaths            = @($paths | ForEach-Object { Format-AccessPath -Row $_ })
                ExtraPathCount      = $extraPaths.Count
            })
        }

        $sorted = @($groupEntries | Sort-Object @{ Expression = 'IsRedundant'; Descending = $true },
                                                @{ Expression = { Get-StrongestPathRank -MembershipType $_.MembershipType -NestingDepth $_.NestingDepth } },
                                                @{ Expression = 'GroupName' })

        $users.Add([PSCustomObject]@{
            SamAccountName    = $sample.MemberSamAccountName
            MemberName        = $sample.MemberName
            DisplayName       = $sample.DisplayName
            UserPrincipalName = $sample.UserPrincipalName
            EmailAddress      = $sample.EmailAddress
            Department        = $sample.Department
            Title             = $sample.Title
            Enabled           = $sample.Enabled
            LastLogonDate     = $sample.LastLogonDate
            PasswordLastSet   = $sample.PasswordLastSet
            MemberDN          = $sample.MemberDN
            Groups            = $sorted
            GroupCount        = $sorted.Count
            DirectCount       = @($sorted | Where-Object { $_.MembershipType -eq 'Direct' }).Count
            NestedCount       = @($sorted | Where-Object { $_.MembershipType -eq 'Nested' }).Count
            PrimaryCount      = @($sorted | Where-Object { $_.MembershipType -eq 'Primary' }).Count
            RedundantCount    = @($sorted | Where-Object { $_.IsRedundant }).Count
            # Surplus paths, not just how many groups are affected. A group reachable three
            # ways needs two removals before access actually stops, so it outranks a group
            # reachable twice. This is the severity signal the report sorts on.
            SurplusPathCount  = (@($sorted | Measure-Object -Property ExtraPathCount -Sum).Sum)
        })
    }

    return @($users | Sort-Object @{ Expression = 'SurplusPathCount'; Descending = $true },
                                  @{ Expression = 'RedundantCount'; Descending = $true },
                                  @{ Expression = { if ($_.DisplayName) { $_.DisplayName } else { $_.SamAccountName } } })
}

function ConvertTo-UserAccessCsvRow {
    <#
        Flattens the user model to one row per user for spreadsheet work. Group detail is
        collapsed into delimited cells; the HTML report is the readable view, this is the
        filterable one.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Users
    )

    foreach ($u in $Users) {

        $groupCells = foreach ($g in $u.Groups) {
            $label = switch ($g.MembershipType) {
                'Direct'  { 'direct' }
                'Primary' { 'primary' }
                'Nested'  { "nested via $($g.NestedVia)" }
                default   { $g.MembershipType }
            }
            if ($g.IsRedundant) {
                "$($g.GroupName) [$label] (REDUNDANT x$($g.PathCount))"
            }
            else {
                "$($g.GroupName) [$label]"
            }
        }

        $redundantCells = foreach ($g in ($u.Groups | Where-Object { $_.IsRedundant })) {
            "$($g.GroupName): " + ($g.AllPaths -join ' | ')
        }

        [PSCustomObject]@{
            SamAccountName    = $u.SamAccountName
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            EmailAddress      = $u.EmailAddress
            Department        = $u.Department
            Title             = $u.Title
            Enabled           = $u.Enabled
            GroupCount        = $u.GroupCount
            DirectCount       = $u.DirectCount
            NestedCount       = $u.NestedCount
            PrimaryCount      = $u.PrimaryCount
            RedundantCount    = $u.RedundantCount
            SurplusPathCount  = $u.SurplusPathCount
            Groups            = ($groupCells -join '; ')
            RedundantGroups   = ($redundantCells -join ' || ')
            LastLogonDate     = $u.LastLogonDate
            PasswordLastSet   = $u.PasswordLastSet
            MemberDN          = $u.MemberDN
            ExportDate        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }
}

#endregion

#region Group-centric model (Groups and Overlap tabs)
# Like the user model above, a pure transform over rows already collected - no AD queries.
# The result is embedded in the HTML as JSON and the browser computes overlap from it, so
# filtering and the Effective/Direct toggle need no re-run.

function ConvertFrom-DnEscape {
    # Undoes DN escaping in one RDN value: '\,' -> ',' and '\2C' -> ','.
    param([AllowEmptyString()][string]$Value)
    $Value = [regex]::Replace($Value, '\\([0-9A-Fa-f]{2})', {
        param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16)
    })
    return ($Value -replace '\\(.)', '$1')
}

function Get-DnRdnList {
    # Splits a DN into its RDNs, respecting escaped commas ('CN=Doe\, Jane,OU=Staff').
    param([AllowEmptyString()][string]$DistinguishedName)
    $list = New-Object System.Collections.Generic.List[object]
    if (-not $DistinguishedName) { return $list.ToArray() }
    foreach ($m in [regex]::Matches($DistinguishedName, '(?:^|,)\s*([A-Za-z0-9-]+)=((?:\\.|[^,\\])*)')) {
        $list.Add([PSCustomObject]@{ Type = $m.Groups[1].Value; Value = (ConvertFrom-DnEscape $m.Groups[2].Value) })
    }
    return $list.ToArray()
}

function Get-DnFirstValue {
    # 'CN=Doe\, Jane,OU=Staff,DC=contoso,DC=com' -> 'Doe, Jane'. Used for ManagedBy, which
    # holds a DN; showing the name avoids an extra AD lookup per group.
    param([AllowEmptyString()][string]$DistinguishedName)
    $rdns = @(Get-DnRdnList $DistinguishedName)
    if ($rdns.Count -gt 0) { return $rdns[0].Value }
    return $DistinguishedName
}

function ConvertTo-OuPath {
    # 'CN=HR-Staff,OU=Groups,OU=HR,DC=contoso,DC=com' -> 'HR / Groups': where the object
    # lives, top-down, without the domain components.
    param([AllowEmptyString()][string]$DistinguishedName)
    $rdns = @(Get-DnRdnList $DistinguishedName)
    $names = New-Object System.Collections.Generic.List[string]
    for ($i = $rdns.Count - 1; $i -ge 1; $i--) {
        if ($rdns[$i].Type -ne 'DC') { $names.Add($rdns[$i].Value) }
    }
    return ($names.ToArray() -join ' / ')
}

function ConvertTo-GroupAccessModel {
    <#
        Builds the per-group data behind the Groups and Overlap tabs.

        People: users only, with the same enabled/disabled rule as the People tab, so the
        three tabs never disagree about who is in scope. Each person is stored once and
        referenced by index; a 500-group domain stays well under a megabyte.

        Groups: one entry per exported group, including empty ones. For every person the
        strongest route is kept with a 'how' code - 0 direct, 1 primary group, 2 nested -
        so the browser derives both views from one list: Direct = codes 0 and 1 (membership
        configured on the group itself, which includes the primary group), Effective = all.
        Computers and nested groups are kept separately: they are real members worth
        listing, but overlap is about people.

        'k' lists the exported groups this group contains at any depth, so the Overlap tab
        can label a parent/child pair "Contains" instead of reporting it as a suspicious
        100% overlap.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Groups,
        [switch]$IncludeDisabled
    )

    $people = New-Object System.Collections.Generic.List[object]
    $personIndex = @{}
    $groupIndex = @{}
    $work = New-Object System.Collections.Generic.List[object]

    # Plain 'foreach ($x in $List)', never 'foreach ($x in @($List))': $Rows is the main
    # flow's List[object], and @() on a List[object] throws "Argument types do not match"
    # on PowerShell 5.1.26100 and 7.6 (observed on a real run; plain arrays and List[string]
    # are unaffected, which is why tests passing arrays missed it). foreach over $null runs
    # zero times on PS 3.0+. Tests\EndToEnd.Tests.ps1 runs the whole script to catch this.
    foreach ($g in $Groups) {
        if (-not $g -or -not $g.DistinguishedName -or $groupIndex.ContainsKey($g.DistinguishedName)) { continue }
        $groupIndex[$g.DistinguishedName] = $work.Count
        $work.Add([PSCustomObject]@{
            Group    = $g
            People   = @{}
            Others   = @{}
            Contains = @{}
        })
    }

    foreach ($r in $Rows) {
        if (-not $r -or -not $r.MemberDN -or $r.MembershipType -eq 'EmptyGroup') { continue }
        if (-not $groupIndex.ContainsKey($r.GroupDN)) { continue }
        $entry = $work[$groupIndex[$r.GroupDN]]

        $how = switch ($r.MembershipType) { 'Direct' { 0 } 'Primary' { 1 } default { 2 } }
        $via = if ($how -eq 2) { [string]$r.NestedVia } else { '' }
        $rank = Get-StrongestPathRank -MembershipType $r.MembershipType -NestingDepth $r.NestingDepth

        if ($r.MemberType -eq 'user') {
            # Enabled is $null when detail could not be read; unknown is not disabled.
            if (-not $IncludeDisabled -and $r.Enabled -eq $false) { continue }
            if (-not $personIndex.ContainsKey($r.MemberDN)) {
                $personIndex[$r.MemberDN] = $people.Count
                $people.Add([PSCustomObject]@{
                    n = if ($r.DisplayName) { [string]$r.DisplayName } else { [string]$r.MemberName }
                    s = [string]$r.MemberSamAccountName
                    d = [string]$r.Department
                    t = [string]$r.Title
                    e = ($r.Enabled -ne $false)
                })
            }
            $personId = $personIndex[$r.MemberDN]
            if (-not $entry.People.ContainsKey($personId) -or $rank -lt $entry.People[$personId].Rank) {
                $entry.People[$personId] = @{ Rank = $rank; How = $how; Via = $via }
            }
        }
        else {
            if ($r.MemberType -eq 'group' -and $groupIndex.ContainsKey($r.MemberDN)) {
                $childId = $groupIndex[$r.MemberDN]
                if ($childId -ne $groupIndex[$r.GroupDN]) { $entry.Contains[$childId] = $true }
            }
            if (-not $entry.Others.ContainsKey($r.MemberDN) -or $rank -lt $entry.Others[$r.MemberDN].Rank) {
                $entry.Others[$r.MemberDN] = @{
                    Rank = $rank; How = $how; Via = $via
                    Name = [string]$r.MemberName; Type = [string]$r.MemberType
                }
            }
        }
    }

    $groupsOut = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $work) {
        $g = $entry.Group
        $members = New-Object System.Collections.Generic.List[object]
        foreach ($personId in ($entry.People.Keys | Sort-Object { $entry.People[$_].How }, { $people[$_].n })) {
            $p = $entry.People[$personId]
            $members.Add(@([int]$personId, [int]$p.How, [string]$p.Via))
        }
        $others = New-Object System.Collections.Generic.List[object]
        foreach ($dn in ($entry.Others.Keys | Sort-Object { $entry.Others[$_].Type }, { $entry.Others[$_].Name })) {
            $o = $entry.Others[$dn]
            $others.Add(@([string]$o.Name, [string]$o.Type, [int]$o.How, [string]$o.Via))
        }

        $groupsOut.Add([PSCustomObject]@{
            n  = [string]$g.Name
            s  = [string]$g.SamAccountName
            c  = [string]$g.GroupCategory
            sc = [string]$g.GroupScope
            ds = [string]$g.Description
            ou = ConvertTo-OuPath $g.DistinguishedName
            ow = if ($g.ManagedBy) { Get-DnFirstValue ([string]$g.ManagedBy) } else { '' }
            m  = $members.ToArray()
            o  = $others.ToArray()
            k  = @($entry.Contains.Keys | ForEach-Object { [int]$_ } | Sort-Object)
        })
    }

    return [PSCustomObject]@{
        People = $people.ToArray()
        Groups = $groupsOut.ToArray()
    }
}

function ConvertTo-JsonText {
    <#
        JSON string literal that is safe inside <script type="application/json">.

        Hand-rolled rather than ConvertTo-Json so the escaping is identical on PowerShell
        3.0 through 7: '<', '>' and '&' become < etc., so a group named '</script>'
        cannot end the data block early, and everything outside printable ASCII is \u-escaped
        so the data survives whatever encoding the file is opened with.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not $Value) { return '""' }
    if ($Value -notmatch '[^\x20-\x7E]|["\\<>&]') { return '"' + $Value + '"' }

    $sb = New-Object System.Text.StringBuilder ($Value.Length + 16)
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34)     { [void]$sb.Append('\"') }
        elseif ($code -eq 92) { [void]$sb.Append('\\') }
        elseif ($code -lt 32 -or $code -gt 126 -or $code -eq 60 -or $code -eq 62 -or $code -eq 38) {
            [void]$sb.Append(('\u{0:x4}' -f $code))
        }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-ReportJson {
    # Serialises the group model compactly; see ConvertTo-JsonText for the escaping rules.
    param([Parameter(Mandatory)]$Model)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"people":[')
    $first = $true
    foreach ($p in @($Model.People)) {
        if (-not $first) { [void]$sb.Append(',') }; $first = $false
        [void]$sb.Append('{"n":').Append((ConvertTo-JsonText $p.n))
        [void]$sb.Append(',"s":').Append((ConvertTo-JsonText $p.s))
        [void]$sb.Append(',"d":').Append((ConvertTo-JsonText $p.d))
        [void]$sb.Append(',"t":').Append((ConvertTo-JsonText $p.t))
        [void]$sb.Append(',"e":').Append($(if ($p.e) { 'true' } else { 'false' })).Append('}')
    }
    [void]$sb.Append('],"groups":[')
    $first = $true
    foreach ($g in @($Model.Groups)) {
        if (-not $first) { [void]$sb.Append(',') }; $first = $false
        [void]$sb.Append('{')
        foreach ($key in 'n', 's', 'c', 'sc', 'ds', 'ou', 'ow') {
            if ($key -ne 'n') { [void]$sb.Append(',') }
            [void]$sb.Append('"').Append($key).Append('":').Append((ConvertTo-JsonText $g.$key))
        }
        $members = @($g.m | ForEach-Object { '[' + $_[0] + ',' + $_[1] + ',' + (ConvertTo-JsonText $_[2]) + ']' })
        $others  = @($g.o | ForEach-Object { '[' + (ConvertTo-JsonText $_[0]) + ',' + (ConvertTo-JsonText $_[1]) + ',' + $_[2] + ',' + (ConvertTo-JsonText $_[3]) + ']' })
        [void]$sb.Append(',"m":[').Append(($members -join ',')).Append(']')
        [void]$sb.Append(',"o":[').Append(($others -join ',')).Append(']')
        [void]$sb.Append(',"k":[').Append((@($g.k) -join ',')).Append(']}')
    }
    [void]$sb.Append(']}')
    return $sb.ToString()
}

function ConvertTo-NestModel {
    <#
        Compact nesting data for the Nesting tab: only groups with at least one group-in-group
        link, indexed, with direct parents (Up) and direct children (Down). Loops, depth and
        paths are worked out in the browser (NestCore).
    #>
    param(
        [Parameter(Mandatory)]$Graph,
        [Parameter(Mandatory)][hashtable]$Edges,
        [switch]$NestedExpanded
    )

    $involved = @{}
    foreach ($parent in [string[]]$Edges.Keys) {
        $involved[$parent] = $true
        foreach ($child in [string[]]$Edges[$parent].Keys) { $involved[$child] = $true }
    }

    $dns = [string[]]($involved.Keys | Sort-Object {
        if ($Graph.Nodes.ContainsKey($_)) { $Graph.Nodes[$_].Name } else { $_ }
    })
    $ids = @{}
    $nodesOut = New-Object System.Collections.Generic.List[object]
    foreach ($dn in $dns) {
        $ids[$dn] = $nodesOut.Count
        $n = if ($Graph.Nodes.ContainsKey($dn)) { $Graph.Nodes[$dn] } else {
            [PSCustomObject]@{ DN = $dn; Name = (Get-DnFirstValue $dn); Sam = ''; Category = ''; Scope = ''; Sid = ''; InExport = $false; Unresolved = $true }
        }
        $nodesOut.Add([PSCustomObject]@{
            n  = [string]$n.Name
            s  = [string]$n.Sam
            c  = [string]$n.Category
            sc = [string]$n.Scope
            ou = ConvertTo-OuPath $dn
            x  = [bool]$n.InExport
            p  = (Test-ProtectedGroupSid $n.Sid)
            b  = (Test-BuiltinGroup -DistinguishedName $dn -Sid $n.Sid)
            u  = [bool]$n.Unresolved
        })
    }

    $up = New-Object 'object[]' $nodesOut.Count
    $down = New-Object 'object[]' $nodesOut.Count
    for ($i = 0; $i -lt $nodesOut.Count; $i++) {
        $up[$i] = New-Object System.Collections.Generic.List[int]
        $down[$i] = New-Object System.Collections.Generic.List[int]
    }
    foreach ($parent in [string[]]$Edges.Keys) {
        foreach ($child in [string[]]$Edges[$parent].Keys) {
            $down[$ids[$parent]].Add($ids[$child])
            $up[$ids[$child]].Add($ids[$parent])
        }
    }
    for ($i = 0; $i -lt $nodesOut.Count; $i++) {
        $up[$i] = $up[$i].ToArray()
        $down[$i] = $down[$i].ToArray()
    }

    return [PSCustomObject]@{
        Nodes = $nodesOut.ToArray(); Up = $up; Down = $down
        NestedExpanded = [bool]$NestedExpanded; CapReached = [bool]$Graph.CapReached
    }
}

function ConvertTo-NestJson {
    # Serialises ConvertTo-NestModel output; strings via ConvertTo-JsonText (safe in <script>).
    param([Parameter(Mandatory)]$Model)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"nodes":[')
    for ($i = 0; $i -lt $Model.Nodes.Count; $i++) {
        $n = $Model.Nodes[$i]
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('{"n":').Append((ConvertTo-JsonText $n.n))
        [void]$sb.Append(',"s":').Append((ConvertTo-JsonText $n.s))
        [void]$sb.Append(',"c":').Append((ConvertTo-JsonText $n.c))
        [void]$sb.Append(',"sc":').Append((ConvertTo-JsonText $n.sc))
        [void]$sb.Append(',"ou":').Append((ConvertTo-JsonText $n.ou))
        foreach ($flag in 'x', 'p', 'b', 'u') {
            [void]$sb.Append(',"').Append($flag).Append('":').Append($(if ($n.$flag) { 'true' } else { 'false' }))
        }
        [void]$sb.Append('}')
    }
    [void]$sb.Append('],"up":[')
    for ($i = 0; $i -lt $Model.Up.Count; $i++) {
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('[').Append(([string[]]$Model.Up[$i] -join ',')).Append(']')
    }
    [void]$sb.Append('],"down":[')
    for ($i = 0; $i -lt $Model.Down.Count; $i++) {
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append('[').Append(([string[]]$Model.Down[$i] -join ',')).Append(']')
    }
    [void]$sb.Append('],"flags":{"nestedExpanded":').Append($(if ($Model.NestedExpanded) { 'true' } else { 'false' }))
    [void]$sb.Append(',"capReached":').Append($(if ($Model.CapReached) { 'true' } else { 'false' })).Append('}}')
    return $sb.ToString()
}

#endregion

#region User-report HTML

function ConvertTo-HtmlSafe {
    <#
        Group names, descriptions and titles are attacker-influenced free text in the sense
        that anyone who can create an AD object controls them. Encoding them keeps a group
        named '<script>' from breaking the report.
    #>
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-OverlapCoreScript {
    <#
        The overlap math, as browser JavaScript with no DOM access, so it is unit-tested with
        Node (Tests\OverlapCore.Tests.ps1) exactly as the report runs it.

        ES5 only - no arrow functions, let/const, Map/Set or NodeList.forEach - because the
        report is opened on Server 2012 / 2012 R2, whose built-in browser is Internet
        Explorer 10/11.

        Pairs are counted from each person's list of groups rather than by comparing every
        group with every other, so the cost is the sum over people of k(k-1)/2 for the k
        groups they hold. estimateWork reports that sum so the page can ask for a narrower
        filter instead of freezing on a pathological selection.
    #>
    return @'
var OverlapCore = (function () {
  'use strict';
  var RANK = { duplicate: 0, subset: 1, partial: 2, contains: 3 };

  function members(g, mode) {
    var out = [], m = g.m, i;
    for (i = 0; i < m.length; i++) {
      if (mode !== 'direct' || m[i][1] < 2) { out.push(m[i][0]); }
    }
    return out;
  }

  function sizeOf(data, mode, gid) { return members(data.groups[gid], mode).length; }

  function personGroups(data, mode, ids) {
    var byPerson = {}, i, j, list, p;
    for (i = 0; i < ids.length; i++) {
      list = members(data.groups[ids[i]], mode);
      for (j = 0; j < list.length; j++) {
        p = list[j];
        if (!byPerson.hasOwnProperty(p)) { byPerson[p] = []; }
        byPerson[p].push(ids[i]);
      }
    }
    return byPerson;
  }

  function estimateWork(byPerson) {
    var w = 0, p, k;
    for (p in byPerson) {
      if (byPerson.hasOwnProperty(p)) { k = byPerson[p].length; w += k * (k - 1) / 2; }
    }
    return w;
  }

  function countPairs(byPerson) {
    var counts = {}, p, gs, i, j, a, b, key;
    for (p in byPerson) {
      if (!byPerson.hasOwnProperty(p)) { continue; }
      gs = byPerson[p];
      for (i = 0; i < gs.length; i++) {
        for (j = i + 1; j < gs.length; j++) {
          a = gs[i]; b = gs[j];
          key = a < b ? a + '|' + b : b + '|' + a;
          counts[key] = (counts[key] || 0) + 1;
        }
      }
    }
    return counts;
  }

  function containsMap(data) {
    var map = {}, i, j, k;
    for (i = 0; i < data.groups.length; i++) {
      k = data.groups[i].k || [];
      for (j = 0; j < k.length; j++) { map[i + '|' + k[j]] = true; }
    }
    return map;
  }

  // Near-duplicate: shared people are 90%+ of the LARGER group, so both groups are
  // almost the same people. Subset: every person in the smaller group is in the larger.
  // Contains: one group is nested in the other, so overlap is expected, not a finding.
  function label(shared, sizeA, sizeB, nested) {
    var small = Math.min(sizeA, sizeB), big = Math.max(sizeA, sizeB);
    if (nested) { return 'contains'; }
    if (big > 0 && shared / big >= 0.9) { return 'duplicate'; }
    if (shared === small) { return 'subset'; }
    return 'partial';
  }

  function computePairs(data, opts) {
    var byPerson = personGroups(data, opts.mode, opts.ids);
    var work = estimateWork(byPerson);
    if (opts.maxWork && work > opts.maxWork) { return { tooLarge: true, work: work, pairs: [] }; }
    var counts = countPairs(byPerson), cmap = containsMap(data), size = {}, pairs = [];
    var minShared = opts.minShared || 1, minPct = opts.minPct || 0;
    var i, key, parts, a, b, t, shared, small, pct, lab, nestedAB, nestedBA;
    for (i = 0; i < opts.ids.length; i++) { size[opts.ids[i]] = sizeOf(data, opts.mode, opts.ids[i]); }
    for (key in counts) {
      if (!counts.hasOwnProperty(key)) { continue; }
      parts = key.split('|'); a = +parts[0]; b = +parts[1]; shared = counts[key];
      small = Math.min(size[a], size[b]);
      pct = small ? shared / small : 0;
      if (shared < minShared || pct < minPct) { continue; }
      nestedAB = !!cmap[a + '|' + b]; nestedBA = !!cmap[b + '|' + a];
      lab = label(shared, size[a], size[b], nestedAB || nestedBA);
      // Display order: the container first for 'contains', otherwise the larger group.
      if ((lab === 'contains' && nestedBA && !nestedAB) || (lab !== 'contains' && size[b] > size[a])) {
        t = a; a = b; b = t;
      }
      pairs.push({ a: a, b: b, shared: shared, pct: pct, label: lab, sizeA: size[a], sizeB: size[b] });
    }
    pairs.sort(function (x, y) {
      if (RANK[x.label] !== RANK[y.label]) { return RANK[x.label] - RANK[y.label]; }
      if (y.pct !== x.pct) { return y.pct - x.pct; }
      if (y.shared !== x.shared) { return y.shared - x.shared; }
      return data.groups[x.a].n < data.groups[y.a].n ? -1 : 1;
    });
    return { tooLarge: false, work: work, pairs: pairs };
  }

  function grid(data, opts) {
    var byPerson = personGroups(data, opts.mode, opts.ids);
    var work = estimateWork(byPerson);
    if (opts.maxWork && work > opts.maxWork) { return { tooLarge: true, work: work }; }
    var size = {}, i;
    for (i = 0; i < opts.ids.length; i++) { size[opts.ids[i]] = sizeOf(data, opts.mode, opts.ids[i]); }
    return { tooLarge: false, work: work, ids: opts.ids, size: size, counts: countPairs(byPerson) };
  }

  function sharedCount(gridResult, a, b) {
    if (a === b) { return gridResult.size[a]; }
    return gridResult.counts[a < b ? a + '|' + b : b + '|' + a] || 0;
  }

  // People who hold every group in ids (the combination check, and the "who are they"
  // list behind a pair or a grid cell).
  function intersect(data, mode, ids) {
    if (!ids.length) { return []; }
    var seen = {}, i, j, list, p, out = [];
    for (i = 0; i < ids.length; i++) {
      list = members(data.groups[ids[i]], mode);
      for (j = 0; j < list.length; j++) {
        p = list[j];
        if (i === 0) { seen[p] = 1; } else if (seen[p] === i) { seen[p] = i + 1; }
      }
    }
    for (p in seen) {
      if (seen.hasOwnProperty(p) && seen[p] === ids.length) { out.push(+p); }
    }
    return out;
  }

  // Groups holding at least the threshold share of everyone in the report (All Staff and the like).
  // They overlap with everything, so they are hidden from overlap by default.
  function largeGroupIds(data, mode, threshold) {
    var total = data.people.length, out = [], i;
    if (!total) { return out; }
    for (i = 0; i < data.groups.length; i++) {
      if (sizeOf(data, mode, i) >= threshold * total && sizeOf(data, mode, i) >= 2) { out.push(i); }
    }
    return out;
  }

  return {
    members: members, sizeOf: sizeOf, personGroups: personGroups, estimateWork: estimateWork,
    countPairs: countPairs, label: label, computePairs: computePairs, grid: grid,
    sharedCount: sharedCount, intersect: intersect, largeGroupIds: largeGroupIds
  };
}());
if (typeof module !== 'undefined' && module.exports) { module.exports = OverlapCore; }
'@
}

function Get-NestCoreScript {
    <#
        Nesting-tab logic as browser JavaScript with no DOM access, unit-tested with Node
        (Tests\NestCore.Tests.ps1). ES5 only, for Internet Explorer on Server 2012 / 2012 R2.

        Loops are found as strongly connected components (Tarjan). Depth is measured on the
        graph with each loop collapsed to one node, so a longest chain is well defined even
        when groups loop. Trees mark a group already on the current branch as a loop and a
        group already expanded elsewhere in the same tree as "shown above", which keeps
        cross-nested domains from multiplying.
    #>
    return @'
var NestCore = (function () {
  'use strict';

  function byName(nest) { return function (a, b) { var x = nest.nodes[a].n.toLowerCase(), y = nest.nodes[b].n.toLowerCase(); return x < y ? -1 : (x > y ? 1 : a - b); }; }

  function indexOfInt(arr, v) { var i; for (i = 0; i < arr.length; i++) { if (arr[i] === v) { return i; } } return -1; }

  function analyze(nest) {
    var n = nest.nodes.length, index = [], low = [], onStack = [], stack = [], comp = [], counter = 0, compCount = 0, i, j;
    for (i = 0; i < n; i++) { index.push(-1); low.push(0); onStack.push(false); comp.push(-1); }
    function strong(v) {
      var k, w;
      index[v] = low[v] = counter++; stack.push(v); onStack[v] = true;
      for (k = 0; k < nest.down[v].length; k++) {
        w = nest.down[v][k];
        if (index[w] === -1) { strong(w); low[v] = Math.min(low[v], low[w]); }
        else if (onStack[w]) { low[v] = Math.min(low[v], index[w]); }
      }
      if (low[v] === index[v]) {
        do { w = stack.pop(); onStack[w] = false; comp[w] = compCount; } while (w !== v);
        compCount++;
      }
    }
    for (i = 0; i < n; i++) { if (index[i] === -1) { strong(i); } }

    var size = [], selfLoop = [], inLoop = [], loopComp = [], loops = 0, c;
    for (c = 0; c < compCount; c++) { size.push(0); }
    for (i = 0; i < n; i++) { size[comp[i]]++; selfLoop.push(indexOfInt(nest.down[i], i) > -1); }
    for (c = 0; c < compCount; c++) { loopComp.push(size[c] > 1); }
    for (i = 0; i < n; i++) { if (selfLoop[i]) { loopComp[comp[i]] = true; } }
    for (c = 0; c < compCount; c++) { if (loopComp[c]) { loops++; } }
    for (i = 0; i < n; i++) { inLoop.push(loopComp[comp[i]]); }

    // Component DAG edges, deduplicated.
    var cUp = [], cDown = [], cProt = [], seen = {}, a, b, key;
    for (c = 0; c < compCount; c++) { cUp.push([]); cDown.push([]); cProt.push(false); }
    for (i = 0; i < n; i++) {
      if (nest.nodes[i].p) { cProt[comp[i]] = true; }
      for (j = 0; j < nest.down[i].length; j++) {
        a = comp[i]; b = comp[nest.down[i][j]];
        if (a === b) { continue; }
        key = a + '|' + b;
        if (!seen[key]) { seen[key] = true; cDown[a].push(b); cUp[b].push(a); }
      }
    }
    var memoUp = [], memoDown = [], memoProt = [];
    for (c = 0; c < compCount; c++) { memoUp.push(-1); memoDown.push(-1); memoProt.push(-1); }
    function depthUp(cc) {
      if (memoUp[cc] > -1) { return memoUp[cc]; }
      var best = 0, k;
      for (k = 0; k < cUp[cc].length; k++) { best = Math.max(best, 1 + depthUp(cUp[cc][k])); }
      memoUp[cc] = best; return best;
    }
    function depthDown(cc) {
      if (memoDown[cc] > -1) { return memoDown[cc]; }
      var best = 0, k;
      for (k = 0; k < cDown[cc].length; k++) { best = Math.max(best, 1 + depthDown(cDown[cc][k])); }
      memoDown[cc] = best; return best;
    }
    function protAbove(cc) {
      if (memoProt[cc] > -1) { return memoProt[cc] === 1; }
      var hit = false, k;
      for (k = 0; k < cUp[cc].length && !hit; k++) { hit = cProt[cUp[cc][k]] || protAbove(cUp[cc][k]); }
      memoProt[cc] = hit ? 1 : 0; return hit;
    }
    var upDepth = [], downDepth = [], chain = [], toProtected = [], deepest = 0;
    for (i = 0; i < n; i++) {
      upDepth.push(depthUp(comp[i])); downDepth.push(depthDown(comp[i]));
      chain.push(upDepth[i] + downDepth[i]);
      deepest = Math.max(deepest, chain[i]);
      // Inside a protected group, or in a loop together with one. A protected group inside
      // another protected group is AD's default (Administrators contains Domain Admins and
      // Enterprise Admins), so it is not flagged - the alert is for unexpected nesting.
      toProtected.push(!nest.nodes[i].p && (protAbove(comp[i]) || (loopComp[comp[i]] && cProt[comp[i]])));
    }
    return { comp: comp, inLoop: inLoop, selfLoop: selfLoop, upDepth: upDepth, downDepth: downDepth,
             chain: chain, toProtected: toProtected, loops: loops, deepest: deepest };
  }

  function tree(nest, id, dir, maxChildren) {
    var edges = dir === 'up' ? nest.up : nest.down, onPath = {}, expanded = {}, sorter = byName(nest);
    function build(v, level) {
      var node = { id: v, level: level, kind: 'node', children: [], more: 0 }, list = edges[v].slice(0).sort(sorter), i, c;
      onPath[v] = true; expanded[v] = true;
      for (i = 0; i < list.length && i < maxChildren; i++) {
        c = list[i];
        if (onPath[c]) { node.children.push({ id: c, level: level + 1, kind: 'loop', children: [], more: 0 }); }
        else if (expanded[c]) { node.children.push({ id: c, level: level + 1, kind: 'seen', children: [], more: 0 }); }
        else { node.children.push(build(c, level + 1)); }
      }
      if (list.length > maxChildren) { node.more = list.length - maxChildren; }
      onPath[v] = false;
      return node;
    }
    return build(id, 0);
  }

  // Complete routes from id to a top (dir 'up') or bottom (dir 'down') group. Counting stops
  // at 10,000 so a heavily cross-nested domain cannot hang the page.
  function paths(nest, id, dir, limit) {
    var edges = dir === 'up' ? nest.up : nest.down, out = { list: [], more: 0, capped: false }, onPath = {}, route = [], total = 0;
    function record(isLoop) {
      total++;
      if (out.list.length < limit) { out.list.push({ ids: route.slice(0), loop: isLoop }); } else { out.more++; }
      if (total >= 10000) { out.capped = true; }
    }
    function walk(v) {
      var next = edges[v], i, c;
      route.push(v); onPath[v] = true;
      if (!next.length && route.length > 1) { record(false); }
      for (i = 0; i < next.length && !out.capped; i++) {
        c = next[i];
        if (onPath[c]) { route.push(c); record(true); route.pop(); }
        else { walk(c); }
      }
      onPath[v] = false; route.pop();
    }
    walk(id);
    return out;
  }

  // Plain-text paths for pasting into a ticket. Says how many were left out, so a pasted
  // list is never mistaken for a complete one.
  function copyText(nest, id, limit) {
    var lines = ['Nesting for ' + nest.nodes[id].n], dirs = [['up', 'Is inside:', 'upward'], ['down', 'Contains:', 'downward']], d, k, p, ids, names, j;
    for (d = 0; d < dirs.length; d++) {
      p = paths(nest, id, dirs[d][0], limit);
      lines.push(dirs[d][1]);
      for (k = 0; k < p.list.length; k++) {
        ids = dirs[d][0] === 'up' ? p.list[k].ids.slice(0).reverse() : p.list[k].ids;
        names = [];
        for (j = 0; j < ids.length; j++) { names.push(nest.nodes[ids[j]].n); }
        lines.push('  ' + names.join(' > ') + (p.list[k].loop ? '  (loop)' : ''));
      }
      if (!p.list.length) { lines.push('  (none)'); }
      if (p.more) { lines.push('  (+ ' + p.more + (p.capped ? '+' : '') + ' more ' + dirs[d][2] + ' paths not shown)'); }
    }
    return lines.join('\r\n');
  }

  return { analyze: analyze, tree: tree, paths: paths, copyText: copyText };
}());
if (typeof module !== 'undefined' && module.exports) { module.exports = NestCore; }
'@
}

function Get-NestUiScript {
    # Nesting-tab rendering. ES5 (see Get-NestCoreScript). Uses eachEl/hasCls/setCls from
    # the People script and its own esc() for everything put into innerHTML.
    return @'
<script>
(function () {
  var el = document.getElementById('nest-data');
  if (!el) { return; }
  var nest = JSON.parse(el.text || el.textContent);
  var A = NestCore.analyze(nest), MAX_CHILDREN = 50, MAX_PATHS = 100;
  var st = { q: '', loops: false, prot: false, sort: 'deep', sel: -1, pinned: false }, timer = null;
  var bySam = {}, i;
  for (i = 0; i < nest.nodes.length; i++) { if (nest.nodes[i].s) { bySam[nest.nodes[i].s.toLowerCase()] = i; } }

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function name(id) { return nest.nodes[id].n; }
  function link(id, extra) {
    var n = nest.nodes[id], cls = 'nlink' + (n.x ? '' : ' ext') + (n.p ? ' prot' : '') + (extra || '');
    return '<span class="' + cls + '" data-n="' + id + '" title="' + esc(n.n) + (n.x ? '' : ' (not in export)') + (n.p ? ' - protected group' : '') + '">' + esc(n.n) + '</span>';
  }
  function levels(n) { return n + ' level' + (n === 1 ? '' : 's'); }
  function indexOfInt(arr, v) { var k; for (k = 0; k < arr.length; k++) { if (arr[k] === v) { return k; } } return -1; }

  function renderSummary() {
    var prot = 0, j;
    for (j = 0; j < nest.nodes.length; j++) { if (A.toProtected[j]) { prot++; } }
    $('nsum').innerHTML =
      '<div class="stat"><div class="n">' + nest.nodes.length + '</div><div class="l">Groups in nesting</div></div>' +
      '<div class="stat"><div class="n">' + A.deepest + '</div><div class="l">Deepest chain (levels)</div></div>' +
      '<div class="stat click' + (A.loops ? ' alert' : '') + '" data-f="loops" title="Show only groups in a loop"><div class="n">' + A.loops + '</div><div class="l">Loops</div></div>' +
      '<div class="stat click' + (prot ? ' alert' : '') + '" data-f="prot" title="Show only groups nested into protected groups"><div class="n">' + prot + '</div><div class="l">Nested into protected groups</div></div>';
  }

  function renderList() {
    var ids = [], j, html = [], n;
    for (j = 0; j < nest.nodes.length; j++) {
      if (st.q && nest.nodes[j].n.toLowerCase().indexOf(st.q) < 0) { continue; }
      if (st.loops && !A.inLoop[j]) { continue; }
      if (st.prot && !A.toProtected[j]) { continue; }
      ids.push(j);
    }
    ids.sort(function (a, b) {
      if (st.sort === 'deep' && A.chain[b] !== A.chain[a]) { return A.chain[b] - A.chain[a]; }
      var x = name(a).toLowerCase(), y = name(b).toLowerCase(); return x < y ? -1 : (x > y ? 1 : 0);
    });
    if (st.sel < 0 || (indexOfInt(ids, st.sel) < 0 && !st.pinned)) { st.sel = ids.length ? ids[0] : -1; }
    for (j = 0; j < ids.length; j++) {
      n = nest.nodes[ids[j]];
      html.push('<div class="gl-item' + (ids[j] === st.sel ? ' on' : '') + (n.x ? '' : ' ext') + '" data-n="' + ids[j] + '">' +
        '<span class="nm2" title="' + esc(n.n) + '">' + esc(n.n) + '</span>' +
        (A.inLoop[ids[j]] ? '<span class="mk loop">loop</span>' : '') +
        (A.toProtected[ids[j]] ? '<span class="mk prot">&rarr; protected</span>' : '') +
        '<span class="n">' + levels(A.chain[ids[j]]) + '</span></div>');
    }
    if (!ids.length) { html.push('<div class="hint">No groups match this filter.</div>'); }
    $('nlist').innerHTML = html.join('');
    renderDetail();
  }

  function treeHtml(node, out) {
    var k, pad = node.level * 22, glyph = node.level ? '<span class="glyph">&#9492;&#9472;</span> ' : '';
    if (node.kind === 'loop') {
      out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + '<span class="loopm">&#8635; ' + esc(name(node.id)) + ' &mdash; loops back</span><span class="lv">level ' + node.level + '</span></div>');
      return;
    }
    if (node.kind === 'seen') {
      out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + link(node.id) + ' <span class="seen">&#8599; shown above</span><span class="lv">level ' + node.level + '</span></div>');
      return;
    }
    out.push('<div class="row" style="padding-left:' + pad + 'px">' + glyph + link(node.id, node.level ? '' : ' sel') +
      (node.level ? '<span class="lv">level ' + node.level + '</span>' : '') + '</div>');
    for (k = 0; k < node.children.length; k++) { treeHtml(node.children[k], out); }
    if (node.more) { out.push('<div class="row seen" style="padding-left:' + (pad + 22) + 'px">+ ' + node.more + ' more</div>'); }
  }

  function pathHtml(p, dir) {
    var ids = dir === 'up' ? p.ids.slice(0).reverse() : p.ids, parts = [], k, isLoopEnd;
    for (k = 0; k < ids.length; k++) {
      isLoopEnd = p.loop && ((dir === 'down' && k === ids.length - 1) || (dir === 'up' && k === 0));
      parts.push(isLoopEnd ? '<span class="loopm">&#8635; ' + esc(name(ids[k])) + '</span>' : link(ids[k], ids[k] === st.sel ? ' sel' : ''));
    }
    return '<div class="npath">' + parts.join('<span class="sep">&rsaquo;</span>') + (p.loop ? '<span class="badge3">LOOP</span>' : '') + '</div>';
  }

  function renderDetail() {
    var d = $('ndetail');
    if (st.sel < 0) { d.innerHTML = '<div class="hint">No group selected.</div>'; return; }
    var n = nest.nodes[st.sel], h = [], up = NestCore.tree(nest, st.sel, 'up', MAX_CHILDREN), down = NestCore.tree(nest, st.sel, 'down', MAX_CHILDREN);
    var pu = NestCore.paths(nest, st.sel, 'up', MAX_PATHS), pd = NestCore.paths(nest, st.sel, 'down', MAX_PATHS), k;
    if (nest.flags.capReached) { h.push('<div class="notice">Upward chains may be incomplete: the export stopped looking up parent groups at its limit.</div>'); }
    h.push('<h2>' + esc(n.n) + '</h2>');
    h.push('<div class="badges">' +
      (n.p ? '<span class="badge2 dup">Protected group</span>' : '') +
      (n.b && !n.p ? '<span class="badge2">Built-in</span>' : '') +
      (n.x ? '' : '<span class="badge2">Not in the export &mdash; fetched to complete the chain</span>') +
      (n.u ? '<span class="badge2">Could not be read from AD</span>' : '') +
      (A.inLoop[st.sel] ? '<span class="badge2 dup">Part of a loop</span>' : '') + '</div>');
    h.push('<div class="kv">' + (n.c ? '<b>Type</b><span>' + esc(n.c) + ' &middot; ' + esc(n.sc) + '</span>' : '') +
      (n.ou ? '<b>Where</b><span>' + esc(n.ou) + '</span>' : '') +
      '<b>Chain</b><span>' + levels(A.upDepth[st.sel]) + ' above, ' + levels(A.downDepth[st.sel]) + ' below</span></div>');
    h.push('<div class="h3">Is inside (its members get these groups&rsquo; access)</div><div class="tree">');
    if (up.children.length) { treeHtml(up, h); } else { h.push('<div class="seen">Not inside any other group.</div>'); }
    h.push('</div><div class="h3">Contains (members of these groups get its access)</div><div class="tree">');
    if (down.children.length) { treeHtml(down, h); } else { h.push('<div class="seen">Contains no groups.</div>'); }
    if (!nest.flags.nestedExpanded) { h.push('<div class="notice">Nested groups were not expanded in this run, so only one level down is shown. Re-run with -IncludeNested.</div>'); }
    h.push('</div><div class="h3">All paths <button class="btn" id="ncopy" style="margin-left:10px;font-size:11.5px;padding:3px 9px">Copy paths</button> <span id="ncopied" class="off"></span></div>');
    for (k = 0; k < pu.list.length; k++) { h.push(pathHtml(pu.list[k], 'up')); }
    if (pu.more) { h.push('<div class="seen">+ ' + pu.more + (pu.capped ? '+' : '') + ' more upward paths</div>'); }
    for (k = 0; k < pd.list.length; k++) { h.push(pathHtml(pd.list[k], 'down')); }
    if (pd.more) { h.push('<div class="seen">+ ' + pd.more + (pd.capped ? '+' : '') + ' more downward paths</div>'); }
    if (!pu.list.length && !pd.list.length) { h.push('<div class="seen">No paths.</div>'); }
    h.push('<p class="off" style="font-size:12px;margin-top:14px">Nesting into groups in other domains of the forest may not appear: group parents are read from the domain controller that was queried.</p>');
    d.innerHTML = h.join('');
    d.setAttribute('data-copy', NestCore.copyText(nest, st.sel, MAX_PATHS));
  }

  function copy(text) {
    var ok = false, ta;
    if (window.clipboardData && window.clipboardData.setData) { ok = window.clipboardData.setData('Text', text); }
    if (!ok) {
      ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
    }
    $('ncopied').innerHTML = ok ? 'Copied.' : 'Copy blocked by the browser &mdash; select the paths and press Ctrl+C.';
  }

  function select(id) {
    st.sel = id; st.pinned = true;
    eachEl('#nlist .gl-item', function (it) { setCls(it, 'on', parseInt(it.getAttribute('data-n'), 10) === id); });
    renderDetail();
  }

  window.renderNesting = function () { renderSummary(); renderList(); };
  window.nestSummaryFor = function (sam) {
    var id = sam ? bySam[sam.toLowerCase()] : undefined;
    if (id === undefined) { return null; }
    return { up: nest.up[id].length, down: nest.down[id].length };
  };
  window.showNesting = function (sam) {
    var id = sam ? bySam[sam.toLowerCase()] : undefined;
    if (id === undefined) { return; }
    st.q = ''; $('nq').value = ''; st.loops = false; $('nloops').checked = false; st.prot = false; $('nprot').checked = false;
    st.sel = id; st.pinned = true;
    window.showTab('nesting');
  };

  $('nq').oninput = $('nq').onkeyup = function () {
    var v = this.value;
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { st.q = v.toLowerCase().replace(/^\s+|\s+$/g, ''); st.pinned = false; renderList(); }, 200);
  };
  $('nloops').onclick = function () { st.loops = this.checked; st.pinned = false; renderList(); };
  $('nprot').onclick = function () { st.prot = this.checked; st.pinned = false; renderList(); };
  $('nsort').onchange = function () { st.sort = this.value; renderList(); };
  $('nsum').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    while (t && t !== this && !(t.getAttribute && t.getAttribute('data-f'))) { t = t.parentNode; }
    if (!t || t === this) { return; }
    if (t.getAttribute('data-f') === 'loops') { st.loops = !st.loops; $('nloops').checked = st.loops; }
    else { st.prot = !st.prot; $('nprot').checked = st.prot; }
    st.pinned = false; renderList();
  };
  $('nlist').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    while (t && t !== this && !(t.className && hasCls(t, 'gl-item'))) { t = t.parentNode; }
    if (t && t !== this) { select(parseInt(t.getAttribute('data-n'), 10)); }
  };
  $('ndetail').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    if (t.id === 'ncopy') { copy(this.getAttribute('data-copy') || ''); return; }
    if (t.getAttribute && t.getAttribute('data-n') !== null) { select(parseInt(t.getAttribute('data-n'), 10)); }
  };

  if ((location.hash || '') === '#nesting') { window.showTab('nesting'); }
}());
</script>
'@
}

function New-UserAccessHtml {
    <#
        Renders the user-centric access report as one self-contained HTML file: no external
        CSS, no CDN scripts, no network access at all, so it opens on an isolated server and
        survives being emailed as an attachment.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()]$Users,
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$ScopeNote,
        [switch]$ScopeIsNarrowed,
        [switch]$IncludeDisabled,
        [switch]$NestedExpanded,
        [Parameter(Mandatory)][int]$GroupsProcessed,
        # From ConvertTo-GroupAccessModel. When omitted the report is the People view only.
        $GroupModel,
        # From ConvertTo-NestModel. When omitted (or empty) there is no Nesting tab.
        $NestModel
    )

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $hasGroups = $null -ne $GroupModel
    $hasNest = $hasGroups -and $null -ne $NestModel -and $NestModel.Nodes.Count -gt 0
    $totalUsers = @($Users).Count
    $usersWithRedundancy = @($Users | Where-Object { $_.RedundantCount -gt 0 }).Count
    $totalSurplus = (@($Users | Measure-Object -Property SurplusPathCount -Sum).Sum)
    if (-not $totalSurplus) { $totalSurplus = 0 }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $sb.AppendLine("<title>AD User Access Report - $(ConvertTo-HtmlSafe $DomainName)</title>")

    # Dark-first, blue accent, dense but not cramped - matches the repo's stated direction.
    $null = $sb.AppendLine(@'
<style>
:root{
  --bg:#12151a; --panel:#181c23; --panel-2:#1e232c; --line:#2a3038;
  --text:#e6eaf0; --muted:#93a0b4; --dim:#6c7a90;
  --accent:#5dade2; --accent-dim:#2b6c96;
  --warn:#e8a33d; --warn-bg:#2e2415; --warn-line:#5c4520;
  --ok:#5cc98f; --off:#7d8798;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
}
[data-theme="light"]{
  --bg:#f4f6f9; --panel:#ffffff; --panel-2:#f0f3f7; --line:#d8dee7;
  --text:#161a20; --muted:#556072; --dim:#7b8798;
  --accent:#1d6ea8; --accent-dim:#8fbfdf;
  --warn:#9a6212; --warn-bg:#fdf3e2; --warn-line:#e6cfa4;
  --ok:#1f7d4d; --off:#6b7688;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif;}
header{background:var(--panel);border-bottom:1px solid var(--line);
  padding:20px 28px;position:sticky;top:0;z-index:10}
.htop{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;flex-wrap:wrap}
h1{margin:0;font-size:20px;font-weight:650;letter-spacing:-.2px}
h1 .dom{color:var(--accent)}
.sub{color:var(--muted);font-size:12.5px;margin-top:4px}
.btn{background:var(--panel-2);color:var(--text);border:1px solid var(--line);
  border-radius:5px;padding:7px 13px;font-size:12.5px;cursor:pointer;font-family:inherit}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.on{background:var(--accent);border-color:var(--accent);color:#0d1116;font-weight:600}
.stats{display:flex;gap:26px;flex-wrap:wrap;margin-top:16px;padding-top:14px;
  border-top:1px solid var(--line)}
.stat .n{font-size:21px;font-weight:650;font-variant-numeric:tabular-nums}
.stat .l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.6px}
.stat.alert .n{color:var(--warn)}
.controls{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
input[type=search]{flex:1;min-width:220px;background:var(--panel-2);border:1px solid var(--line);
  color:var(--text);border-radius:5px;padding:8px 12px;font-size:13px;font-family:inherit}
input[type=search]:focus{outline:none;border-color:var(--accent)}
main{padding:22px 28px 60px;max-width:1180px}
main.wide{max-width:none}
.note{background:var(--warn-bg);border:1px solid var(--warn-line);border-left:3px solid var(--warn);
  border-radius:4px;padding:12px 15px;margin-bottom:20px;font-size:12.5px;color:var(--text)}
.note b{color:var(--warn)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:7px;
  margin-bottom:11px;overflow:hidden}
.card.flag{border-left:3px solid var(--warn)}
.uhead{display:flex;align-items:center;gap:13px;padding:13px 16px;cursor:pointer;
  user-select:none}
.uhead:hover{background:var(--panel-2)}
.caret{color:var(--dim);font-size:10px;width:10px;transition:transform .15s}
.card.open .caret{transform:rotate(90deg)}
.who{flex:1;min-width:0}
.nm{font-weight:600}
.sam{font-family:var(--mono);color:var(--accent);font-size:12.5px;margin-left:8px}
.meta{color:var(--dim);font-size:12px;margin-top:2px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tags{display:flex;gap:6px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.tag{font-size:11px;padding:2.5px 8px;border-radius:20px;border:1px solid var(--line);
  color:var(--muted);white-space:nowrap;font-variant-numeric:tabular-nums}
.tag.w{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600}
.tag.d{color:var(--off);border-style:dashed}
.body{display:none;border-top:1px solid var(--line);background:var(--panel-2);padding:6px 0}
.card.open .body{display:block}
.g{display:flex;gap:11px;padding:8px 16px 8px 20px;border-bottom:1px solid rgba(255,255,255,.03)}
.g:last-child{border-bottom:0}
.g.r{background:var(--warn-bg)}
.dot{color:var(--accent);font-size:8px;padding-top:6px}
.g.r .dot{color:var(--warn)}
.gmain{flex:1;min-width:0}
.gname{font-weight:550}
.gpath{font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-top:3px}
.gpath .arw{color:var(--accent-dim)}
.extra{margin-top:5px;padding:6px 10px;background:rgba(0,0,0,.18);border-radius:4px;
  border-left:2px solid var(--warn)}
.extra .lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--warn);
  font-weight:600;margin-bottom:3px}
.extra div.p{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.badge{font-size:10.5px;padding:2px 7px;border-radius:3px;background:var(--warn);color:#1a1206;
  font-weight:700;letter-spacing:.3px;flex-shrink:0;height:fit-content;margin-top:1px}
.kind{font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;
  flex-shrink:0;padding-top:2px;width:62px;text-align:right}
.empty{text-align:center;color:var(--dim);padding:50px 20px}
footer{color:var(--dim);font-size:11.5px;padding:20px 28px;border-top:1px solid var(--line)}
mark{background:var(--accent);color:#0d1116;border-radius:2px}
/* ---- tabs ---- */
.tabs{display:flex;gap:2px;margin-top:14px}
.tabbtn{background:none;border:1px solid transparent;border-bottom:0;color:var(--muted);font:inherit;
  font-size:13px;padding:7px 15px;border-radius:6px 6px 0 0;cursor:pointer}
.tabbtn:hover{color:var(--text)}
.tabbtn.on{background:var(--bg);border-color:var(--line);color:var(--text);font-weight:600}
.tabbtn .cnt{color:var(--dim);font-weight:400;margin-left:5px;font-variant-numeric:tabular-nums}
header.tabbed{padding-bottom:0}
.tabpane{display:none}.tabpane.on{display:block}
.pbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.pbar input[type=search]{flex:1;min-width:220px}
/* ---- shared filter bar (Groups / Overlap) ---- */
.fbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.fbar input[type=search]{flex:1;min-width:200px}
.fbar select,.fbar label.chk{background:var(--panel-2);border:1px solid var(--line);color:var(--text);
  border-radius:5px;padding:6px 8px;font:inherit;font-size:12.5px}
.fbar label.chk{gap:6px;align-items:center;cursor:pointer}
.seg{display:flex;border:1px solid var(--line);border-radius:5px;overflow:hidden}
.seg button{background:var(--panel-2);border:0;color:var(--muted);font:inherit;font-size:12.5px;padding:6px 11px;cursor:pointer}
.seg button.on{background:var(--accent);color:#0d1116;font-weight:600}
.fbar .only-ov,.fbar .only-gr{display:none}
.fbar.show-ov .only-ov,.fbar.show-gr .only-gr{display:flex}
.focus{display:flex;gap:10px;align-items:center;font-size:13px;margin-bottom:10px;color:var(--muted)}
.focus b{color:var(--text)}
/* ---- Groups tab: list + detail ---- */
.gl-wrap{display:flex;border:1px solid var(--line);border-radius:7px;overflow:hidden;min-height:420px;background:var(--panel)}
.gl-list{width:38%;max-width:420px;border-right:1px solid var(--line);overflow-y:auto;max-height:70vh}
.gl-item{display:flex;align-items:center;gap:7px;padding:8px 12px;border-bottom:1px solid var(--line);cursor:pointer;font-size:13px}
.gl-item:hover{background:var(--panel-2)}
.gl-item.on{background:var(--panel-2);box-shadow:inset 3px 0 0 var(--accent)}
.gl-item .nm2{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.gl-item .n{color:var(--dim);font-variant-numeric:tabular-nums;font-size:12px}
.gl-item.empty .nm2{color:var(--off)}
.mk{font-size:10px;padding:1px 6px;border-radius:9px;border:1px solid var(--line);color:var(--muted)}
.mk.dup{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600}
.mk.emp{border-style:dashed;color:var(--off)}
.gd{flex:1;padding:16px 20px;min-width:0;overflow-y:auto;max-height:70vh}
.gd h2{margin:0;font-size:18px}
.gd .sam{margin-left:8px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:12.5px;margin:10px 0 12px;color:var(--muted)}
.kv b{color:var(--dim);font-weight:600}
.badges{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.badge2{font-size:11px;padding:3px 9px;border-radius:12px;border:1px solid var(--line);color:var(--muted);background:none;font-family:inherit}
.badge2.dup{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600;cursor:pointer}
.badge2.dup:hover{text-decoration:underline}
table.mt{width:100%;border-collapse:collapse;font-size:12.5px;margin-bottom:16px}
table.mt th{text-align:left;color:var(--dim);font-weight:600;font-size:10.5px;text-transform:uppercase;
  letter-spacing:.5px;padding:5px 8px;border-bottom:1px solid var(--line)}
table.mt td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
table.mt .how{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.off{color:var(--off)}
.h3{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);margin:6px 0 6px;font-weight:600}
.hint{color:var(--dim);font-size:12.5px;padding:30px 10px;text-align:center}
/* ---- Overlap tab ---- */
.subtabs{display:flex;gap:18px;border-bottom:1px solid var(--line);margin-bottom:14px}
.subtabs button{background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);font:inherit;
  font-size:13px;padding:6px 0;cursor:pointer;margin-bottom:-1px}
.subtabs button.on{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
.ov-pair{background:var(--panel);border:1px solid var(--line);border-radius:6px;margin-bottom:6px}
.ov-ph{display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer}
.ov-ph:hover{background:var(--panel-2)}
.ov-ph .gn{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ov-ph .x{color:var(--dim);margin:0 6px}
.ov-ph .ct{color:var(--dim);font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}
.meter{width:70px;height:6px;background:var(--line);border-radius:3px;overflow:hidden;flex-shrink:0}
.meter i{display:block;height:100%;background:var(--accent)}
.pct{width:44px;text-align:right;font-variant-numeric:tabular-nums}
.lab{font-size:10.5px;padding:2px 8px;border-radius:10px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.lab.duplicate{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600}
.lab.subset{color:var(--accent);border-color:var(--accent-dim)}
.lab.contains{color:var(--off);border-style:dashed}
.ov-pair.contains .gn{color:var(--muted)}
.ov-body{display:none;border-top:1px solid var(--line);padding:8px 12px;background:var(--panel-2)}
.ov-pair.open .ov-body{display:block}
.plist{font-size:12.5px;columns:3 220px;column-gap:20px}
.plist div{break-inside:avoid;padding:2px 0}
.more{margin:10px auto;display:block}
.gridwrap{overflow:auto;max-height:70vh;border:1px solid var(--line);border-radius:6px;background:var(--panel)}
table.gx{border-collapse:separate;border-spacing:2px;font-size:11.5px}
table.gx th{color:var(--muted);font-weight:500;white-space:nowrap;padding:3px 6px;text-align:left;
  position:sticky;background:var(--panel)}
table.gx thead th{top:0;height:120px;vertical-align:bottom}
table.gx thead th span{display:inline-block;writing-mode:vertical-rl;transform:rotate(180deg);max-height:115px;overflow:hidden;text-overflow:ellipsis}
table.gx tbody th{left:0;max-width:200px;overflow:hidden;text-overflow:ellipsis}
table.gx td{width:30px;min-width:30px;height:26px;text-align:center;border-radius:3px;cursor:pointer;font-variant-numeric:tabular-nums}
table.gx td.z{color:var(--dim);cursor:default}
table.gx td.self{background:var(--line);color:var(--muted);cursor:default}
table.gx td:not(.z):not(.self):hover{outline:2px solid var(--accent)}
.combo{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.chip{display:inline-flex;gap:6px;align-items:center;background:var(--panel-2);border:1px solid var(--accent-dim);
  color:var(--accent);border-radius:14px;padding:3px 6px 3px 11px;font-size:12.5px}
.chip button{background:none;border:0;color:var(--muted);cursor:pointer;font-size:14px;line-height:1;padding:0 3px}
.chip button:hover{color:var(--text)}
.result{font-size:14px;margin:10px 0}
.result b{color:var(--warn)}
/* ---- Nesting tab ---- */
.nsum{display:flex;gap:26px;flex-wrap:wrap;margin-bottom:14px}
.nsum .stat.click{cursor:pointer}.nsum .stat.click:hover .l{color:var(--accent)}
.mk.loop{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn);font-weight:600}
.mk.prot{border-color:var(--warn-line);color:var(--warn)}
.gl-item.ext .nm2{font-style:italic;color:var(--muted)}
.tree{font-family:var(--mono);font-size:12.5px;line-height:1.9;margin:4px 0 14px}
.tree .row{display:flex;align-items:center;gap:8px;white-space:nowrap}
.tree .lv{color:var(--dim);font-size:11px;margin-left:auto;padding-left:20px}
.tree .glyph{color:var(--accent-dim)}
.nlink{cursor:pointer;border-bottom:1px dotted var(--accent-dim)}.nlink:hover{color:var(--accent)}
.nlink.sel{background:var(--accent);color:#0d1116;border-radius:3px;padding:0 5px;font-weight:700;border:0}
.nlink.ext{border:1px dashed var(--dim);border-radius:3px;padding:0 4px;font-style:italic}
.nlink.prot{color:var(--warn)}
.tree .loopm,.npath .loopm{color:var(--warn);font-weight:700}.tree .seen,.seen{color:var(--dim)}
.npath{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:5px 9px;background:var(--panel);border:1px solid var(--line);border-radius:5px;margin-bottom:5px;font-size:12.5px}
.npath .sep{color:var(--accent-dim)}
.npath .badge3{margin-left:auto;font-size:10px;padding:1px 7px;border-radius:9px;border:1px solid var(--warn-line);background:var(--warn-bg);color:var(--warn);font-weight:600}
.notice{font-size:12.5px;color:var(--muted);border-left:3px solid var(--warn);background:var(--warn-bg);padding:7px 10px;border-radius:4px;margin-bottom:10px}
@media(max-width:760px){
  .gl-wrap{flex-direction:column}.gl-list{width:auto;max-width:none;max-height:40vh;border-right:0;border-bottom:1px solid var(--line)}
  .uhead{flex-wrap:wrap}.tags{width:100%;justify-content:flex-start}
  main,header{padding-left:16px;padding-right:16px}
}
</style>
'@)
    $null = $sb.AppendLine('</head><body>')

    # ---- header ----
    $headerClass = if ($hasGroups) { ' class="tabbed"' } else { '' }
    $null = $sb.AppendLine("<header$headerClass><div class=""htop""><div>")
    $null = $sb.AppendLine("<h1>Who has access to what &mdash; <span class=""dom"">$(ConvertTo-HtmlSafe $DomainName)</span></h1>")
    $null = $sb.AppendLine("<div class=""sub"">Generated $generated &middot; $(ConvertTo-HtmlSafe $ScopeNote)</div>")
    $null = $sb.AppendLine('</div><div style="display:flex;gap:8px">')
    $null = $sb.AppendLine('<button class="btn" id="tgTheme" onclick="toggleTheme()">Light mode</button>')
    $null = $sb.AppendLine('</div></div>')

    if ($hasGroups) {
        $groupCount = @($GroupModel.Groups).Count
        $null = $sb.AppendLine('<nav class="tabs" role="tablist">')
        $null = $sb.AppendLine("<button class=""tabbtn on"" id=""tb-people"" onclick=""showTab('people')"">People<span class=""cnt"">$totalUsers</span></button>")
        $null = $sb.AppendLine("<button class=""tabbtn"" id=""tb-groups"" onclick=""showTab('groups')"">Groups<span class=""cnt"">$groupCount</span></button>")
        $null = $sb.AppendLine('<button class="tabbtn" id="tb-overlap" onclick="showTab(''overlap'')">Overlap<span class="cnt" id="ovCount"></span></button>')
        if ($hasNest) {
            $null = $sb.AppendLine("<button class=""tabbtn"" id=""tb-nesting"" onclick=""showTab('nesting')"">Nesting<span class=""cnt"">$($NestModel.Nodes.Count)</span></button>")
        }
        $null = $sb.AppendLine('</nav>')
    }
    $null = $sb.AppendLine('</header>')

    $null = $sb.AppendLine('<main>')

    # Scope notes apply to every tab, so they sit above the tab panes.
    if ($ScopeIsNarrowed) {
        $null = $sb.AppendLine('<div class="note"><b>Partial view.</b> This run was limited to a subset of groups, so each person&rsquo;s list below covers only the groups that were scanned &mdash; it is not their complete domain membership.</div>')
    }
    if (-not $NestedExpanded) {
        $null = $sb.AppendLine('<div class="note"><b>Direct membership only.</b> Nested groups were not expanded, so inherited access is missing and duplicate paths cannot be detected. Re-run with <code>-IncludeNested</code> for an access review.</div>')
    }

    # ---- People tab ----
    $null = $sb.AppendLine('<section class="tabpane on" id="tab-people">')
    $null = $sb.AppendLine('<div class="stats" style="margin:0 0 16px;border:0;padding:0">')
    $null = $sb.AppendLine("<div class=""stat""><div class=""n"">$totalUsers</div><div class=""l"">Users</div></div>")
    $null = $sb.AppendLine("<div class=""stat""><div class=""n"">$GroupsProcessed</div><div class=""l"">Groups scanned</div></div>")
    $alertCls = if ($usersWithRedundancy -gt 0) { ' alert' } else { '' }
    $null = $sb.AppendLine("<div class=""stat$alertCls""><div class=""n"">$usersWithRedundancy</div><div class=""l"">Users w/ duplicate access</div></div>")
    $null = $sb.AppendLine("<div class=""stat$alertCls""><div class=""n"">$totalSurplus</div><div class=""l"">Extra access paths</div></div>")
    $null = $sb.AppendLine('</div>')

    $null = $sb.AppendLine('<div class="pbar">')
    $null = $sb.AppendLine('<input type="search" id="q" placeholder="Filter by name, username, department, or group..." oninput="applyFilter()">')
    $null = $sb.AppendLine('<button class="btn" id="tgRed" onclick="toggleRedundant()">Show only duplicate access</button>')
    $null = $sb.AppendLine('<button class="btn" onclick="setAll(true)">Expand all</button>')
    $null = $sb.AppendLine('<button class="btn" onclick="setAll(false)">Collapse all</button>')
    $null = $sb.AppendLine('</div>')

    if ($usersWithRedundancy -gt 0) {
        $null = $sb.AppendLine("<div class=""note""><b>$usersWithRedundancy user(s) hold the same group through more than one path.</b> Removing one path will not remove their access &mdash; every route has to go. These are listed first and marked <b>DUPLICATE</b> below.</div>")
    }

    if ($totalUsers -eq 0) {
        $null = $sb.AppendLine('<div class="empty">No users matched this run.</div>')
    }

    foreach ($u in $Users) {
        $name = if ($u.DisplayName) { $u.DisplayName } elseif ($u.MemberName) { $u.MemberName } else { $u.SamAccountName }
        $flag = if ($u.RedundantCount -gt 0) { ' flag' } else { '' }

        # Everything filterable is pooled into one lowercase attribute so the client-side
        # filter is a single substring test rather than a walk of the DOM.
        $hay = (@($name, $u.SamAccountName, $u.UserPrincipalName, $u.Department, $u.Title) +
                @($u.Groups | ForEach-Object { $_.GroupName })) -join ' '
        $hayAttr = ConvertTo-HtmlSafe ($hay.ToLowerInvariant())

        $null = $sb.AppendLine("<div class=""card$flag"" data-r=""$($u.RedundantCount)"" data-h=""$hayAttr"">")
        $null = $sb.AppendLine('<div class="uhead" onclick="this.parentNode.classList.toggle(''open'')">')
        $null = $sb.AppendLine('<span class="caret">&#9654;</span><div class="who">')
        $null = $sb.AppendLine("<span class=""nm"">$(ConvertTo-HtmlSafe $name)</span><span class=""sam"">$(ConvertTo-HtmlSafe $u.SamAccountName)</span>")

        $metaBits = @()
        if ($u.Department) { $metaBits += (ConvertTo-HtmlSafe $u.Department) }
        if ($u.Title)      { $metaBits += (ConvertTo-HtmlSafe $u.Title) }
        if ($u.UserPrincipalName) { $metaBits += (ConvertTo-HtmlSafe $u.UserPrincipalName) }
        if ($metaBits.Count -gt 0) {
            $null = $sb.AppendLine("<div class=""meta"">$($metaBits -join ' &middot; ')</div>")
        }
        $null = $sb.AppendLine('</div><div class="tags">')

        if ($u.RedundantCount -gt 0) {
            $null = $sb.AppendLine("<span class=""tag w"">$($u.RedundantCount) duplicate &middot; $($u.SurplusPathCount) extra path(s)</span>")
        }
        $null = $sb.AppendLine("<span class=""tag"">$($u.GroupCount) group(s)</span>")
        if ($u.DirectCount  -gt 0) { $null = $sb.AppendLine("<span class=""tag"">$($u.DirectCount) direct</span>") }
        if ($u.NestedCount  -gt 0) { $null = $sb.AppendLine("<span class=""tag"">$($u.NestedCount) inherited</span>") }
        if ($u.PrimaryCount -gt 0) { $null = $sb.AppendLine("<span class=""tag"">$($u.PrimaryCount) primary</span>") }
        if ($u.Enabled -eq $false) { $null = $sb.AppendLine('<span class="tag d">disabled</span>') }
        $null = $sb.AppendLine('</div></div>')

        $null = $sb.AppendLine('<div class="body">')
        foreach ($g in $u.Groups) {
            $rc = if ($g.IsRedundant) { ' r' } else { '' }
            $kind = switch ($g.MembershipType) {
                'Direct'  { 'direct' }
                'Primary' { 'primary' }
                'Nested'  { "depth $($g.NestingDepth)" }
                default   { $g.MembershipType }
            }
            $null = $sb.AppendLine("<div class=""g$rc""><span class=""dot"">&#9679;</span><div class=""gmain"">")
            $null = $sb.AppendLine("<div class=""gname"">$(ConvertTo-HtmlSafe $g.GroupName)</div>")
            $pathHtml = (ConvertTo-HtmlSafe $g.PrimaryPathText) -replace ' -&gt; ', ' <span class="arw">&rarr;</span> '
            $null = $sb.AppendLine("<div class=""gpath"">$pathHtml</div>")

            if ($g.IsRedundant) {
                $null = $sb.AppendLine('<div class="extra"><div class="lbl">Also reachable by</div>')
                foreach ($p in @($g.AllPaths | Select-Object -Skip 1)) {
                    $ph = (ConvertTo-HtmlSafe $p) -replace ' -&gt; ', ' <span class="arw">&rarr;</span> '
                    $null = $sb.AppendLine("<div class=""p"">$ph</div>")
                }
                $null = $sb.AppendLine('</div>')
            }
            $null = $sb.AppendLine('</div>')
            if ($g.IsRedundant) {
                $null = $sb.AppendLine("<span class=""badge"">DUPLICATE &times;$($g.PathCount)</span>")
            }
            $null = $sb.AppendLine("<span class=""kind"">$(ConvertTo-HtmlSafe $kind)</span></div>")
        }
        $null = $sb.AppendLine('</div></div>')
    }

    $null = $sb.AppendLine('<div class="empty" id="noMatch" style="display:none">No users match this filter.</div>')
    $null = $sb.AppendLine('</section>')

    if ($hasGroups) {
        # ---- shared filter bar + Groups and Overlap tabs (rendered by script from the data) ----
        $null = $sb.AppendLine(@'
<div class="fbar" id="fbar" style="display:none">
<input type="search" id="gq" placeholder="Filter by group name, or by a person's name or username...">
<select id="gtype" title="Group type"><option value="">All types</option><option value="Security">Security</option><option value="Distribution">Distribution</option></select>
<select id="gscope" title="Group scope"><option value="">All scopes</option><option value="DomainLocal">Domain local</option><option value="Global">Global</option><option value="Universal">Universal</option></select>
<div class="seg" title="Effective: everyone with the group's access, including through nested groups. Direct: only people added to the group itself (including those with it as their primary group).">
<button id="mEff" class="on">Effective</button><button id="mDir">Direct</button></div>
<select id="gsort" class="only-gr"><option value="size">Sort: largest first</option><option value="name">Sort: name</option></select>
<select id="gmin" class="only-ov" title="Only show pairs where at least this share of the smaller group is in both"><option value="0.25">Min overlap 25%</option><option value="0.5" selected>Min overlap 50%</option><option value="0.75">Min overlap 75%</option><option value="0.9">Min overlap 90%</option></select>
<label class="chk only-ov" title="Groups like All Staff overlap with everything and drown out real findings"><input type="checkbox" id="ghide" checked> Hide groups with 90%+ of users</label>
</div>
<section class="tabpane" id="tab-groups">
<div class="gl-wrap"><div class="gl-list" id="glist"></div><div class="gd" id="gdetail"></div></div>
</section>
<section class="tabpane" id="tab-overlap">
<div class="subtabs"><button id="st-pairs" class="on">Overlapping pairs</button><button id="st-grid">Grid</button><button id="st-combo">Check a combination</button></div>
<div id="ovbody"></div>
</section>
'@)
        if ($hasNest) {
            $null = $sb.AppendLine(@'
<section class="tabpane" id="tab-nesting">
<div class="nsum" id="nsum"></div>
<div class="fbar" style="display:flex">
<input type="search" id="nq" placeholder="Filter groups by name...">
<label class="chk" style="display:flex"><input type="checkbox" id="nloops"> Only loops</label>
<label class="chk" style="display:flex"><input type="checkbox" id="nprot"> Only nested into protected groups</label>
<select id="nsort"><option value="deep">Sort: deepest chain first</option><option value="name">Sort: name</option></select>
</div>
<div class="gl-wrap"><div class="gl-list" id="nlist"></div><div class="gd" id="ndetail"></div></div>
</section>
'@)
        }
    }

    $null = $sb.AppendLine('</main>')
    $disabledNote = if ($IncludeDisabled) { 'Disabled accounts included.' } else { 'Enabled accounts only - re-run with -IncludeDisabled to include disabled users.' }
    $null = $sb.AppendLine("<footer>$(ConvertTo-HtmlSafe $disabledNote) Generated by Export-ADGroupMembership.ps1 -UserReport on $generated.</footer>")

    # ES5 throughout (see Get-OverlapCoreScript): no NodeList.forEach, classList.toggle(x, bool)
    # or dataset, none of which work in Internet Explorer on Server 2012 / 2012 R2.
    $null = $sb.AppendLine(@'
<script>
function eachEl(sel, fn) { var l = document.querySelectorAll(sel), i; for (i = 0; i < l.length; i++) { fn(l[i]); } }
function hasCls(el, c) { return (' ' + el.className + ' ').indexOf(' ' + c + ' ') > -1; }
function setCls(el, c, on) {
  if (!el) { return; }
  var has = hasCls(el, c);
  if (on && !has) { el.className = (el.className ? el.className + ' ' : '') + c; }
  else if (!on && has) { el.className = (' ' + el.className + ' ').replace(' ' + c + ' ', ' ').replace(/^\s+|\s+$/g, ''); }
}
function setAll(open) { eachEl('#tab-people .card', function (c) { if (c.style.display !== 'none') { setCls(c, 'open', open); } }); }
var redOnly = false;
function toggleRedundant() { redOnly = !redOnly; setCls(document.getElementById('tgRed'), 'on', redOnly); applyFilter(); }
function applyFilter() {
  var q = document.getElementById('q').value.toLowerCase().replace(/^\s+|\s+$/g, ''), shown = 0;
  eachEl('#tab-people .card', function (c) {
    var okQ = !q || (c.getAttribute('data-h') || '').indexOf(q) > -1;
    var okR = !redOnly || parseInt(c.getAttribute('data-r'), 10) > 0;
    var vis = okQ && okR;
    c.style.display = vis ? '' : 'none';
    if (vis) { shown++; if (q) { setCls(c, 'open', true); } }
  });
  document.getElementById('noMatch').style.display = shown ? 'none' : '';
}
function toggleTheme() {
  var r = document.documentElement, to = r.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  r.setAttribute('data-theme', to);
  document.getElementById('tgTheme').textContent = to === 'light' ? 'Dark mode' : 'Light mode';
}
</script>
'@)

    if ($hasGroups) {
        $null = $sb.Append('<script type="application/json" id="report-data">')
        $null = $sb.Append((ConvertTo-ReportJson -Model $GroupModel))
        $null = $sb.AppendLine('</script>')
        if ($hasNest) {
            $null = $sb.Append('<script type="application/json" id="nest-data">')
            $null = $sb.Append((ConvertTo-NestJson -Model $NestModel))
            $null = $sb.AppendLine('</script>')
        }
        $null = $sb.AppendLine('<script>')
        $null = $sb.AppendLine((Get-OverlapCoreScript))
        $null = $sb.AppendLine('</script>')
        if ($hasNest) {
            $null = $sb.AppendLine('<script>')
            $null = $sb.AppendLine((Get-NestCoreScript))
            $null = $sb.AppendLine('</script>')
        }
        $null = $sb.AppendLine(@'
<script>
(function () {
  var dataEl = document.getElementById('report-data');
  var data = JSON.parse(dataEl.text || dataEl.textContent);
  var C = OverlapCore;
  var MAX_WORK = 3000000, GRID_MAX = 40, PAGE = 200, LARGE = 0.9, COMBO_MAX = 5;
  var LABELS = { duplicate: 'Near-duplicate', subset: 'Subset', partial: 'Partial', contains: 'Contains' };
  var st = { tab: 'people', mode: 'effective', q: '', type: '', scope: '', sort: 'size', minPct: 0.5,
             hide: true, sel: -1, sub: 'pairs', shown: PAGE, combo: [], focus: -1 };
  var dupCache = {}, largeCache = {}, timer = null;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmt(n) { return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function closest(el, cls, stop) { while (el && el !== stop) { if (el.className && hasCls(el, cls)) { return el; } el = el.parentNode; } return null; }
  function indexOf(arr, v) { var i; for (i = 0; i < arr.length; i++) { if (arr[i] === v) { return i; } } return -1; }
  function byName(a, b) { var x = data.groups[a].n.toLowerCase(), y = data.groups[b].n.toLowerCase(); return x < y ? -1 : (x > y ? 1 : 0); }
  function size(gid) { return C.sizeOf(data, st.mode, gid); }
  function howText(how, via) { return how === 0 ? 'direct' : (how === 1 ? 'primary group' : 'via ' + via); }
  function personLabel(p) { return esc(p.n || p.s) + (p.e ? '' : ' <span class="off">&middot; disabled</span>'); }

  // ---- filtering ----
  function passesType(gid) {
    var g = data.groups[gid];
    return (!st.type || g.c === st.type) && (!st.scope || g.sc === st.scope);
  }
  function passesQuery(gid) {
    var g = data.groups[gid], q = st.q, i, p;
    if (!q) { return true; }
    if ((g.n + ' ' + g.s).toLowerCase().indexOf(q) > -1) { return true; }
    for (i = 0; i < g.m.length; i++) {
      if (st.mode === 'direct' && g.m[i][1] === 2) { continue; }
      p = data.people[g.m[i][0]];
      if ((p.n + ' ' + p.s).toLowerCase().indexOf(q) > -1) { return true; }
    }
    for (i = 0; i < g.o.length; i++) { if (g.o[i][0].toLowerCase().indexOf(q) > -1) { return true; } }
    return false;
  }
  function largeSet() {
    if (!largeCache[st.mode]) {
      var ids = C.largeGroupIds(data, st.mode, LARGE), set = {}, i;
      for (i = 0; i < ids.length; i++) { set[ids[i]] = true; }
      largeCache[st.mode] = set;
    }
    return largeCache[st.mode];
  }
  function collect(useQuery, useHide) {
    var out = [], i, large = useHide && st.hide ? largeSet() : {};
    for (i = 0; i < data.groups.length; i++) {
      if (passesType(i) && (!useQuery || passesQuery(i)) && !large[i]) { out.push(i); }
    }
    return out;
  }

  // Near-duplicate partners for the Groups tab badges, across all groups, per mode.
  function dupPartners() {
    if (dupCache[st.mode]) { return dupCache[st.mode]; }
    var all = [], map = {}, i, res, p;
    for (i = 0; i < data.groups.length; i++) { all.push(i); }
    res = C.computePairs(data, { mode: st.mode, ids: all, minPct: 0.9, minShared: 2, maxWork: MAX_WORK });
    for (i = 0; i < res.pairs.length; i++) {
      p = res.pairs[i];
      if (p.label !== 'duplicate') { continue; }
      (map[p.a] = map[p.a] || []).push(p);
      (map[p.b] = map[p.b] || []).push(p);
    }
    dupCache[st.mode] = map;
    return map;
  }

  // ---- Groups tab ----
  function renderGroups() {
    var ids = collect(true, false), dups = dupPartners(), html = [], i, gid, g, empty;
    ids.sort(function (a, b) { return st.sort === 'name' ? byName(a, b) : (size(b) - size(a) || byName(a, b)); });
    if (indexOf(ids, st.sel) < 0) { st.sel = ids.length ? ids[0] : -1; }
    for (i = 0; i < ids.length; i++) {
      gid = ids[i]; g = data.groups[gid]; empty = !g.m.length && !g.o.length;
      html.push('<div class="gl-item' + (gid === st.sel ? ' on' : '') + (empty ? ' empty' : '') + '" data-g="' + gid + '">' +
        '<span class="nm2" title="' + esc(g.n) + '">' + esc(g.n) + '</span>' +
        (dups[gid] ? '<span class="mk dup" title="Near-duplicate of another group">dup</span>' : '') +
        (empty ? '<span class="mk emp">empty</span>' : '') +
        '<span class="n">' + fmt(size(gid)) + '</span></div>');
    }
    if (!ids.length) { html.push('<div class="hint">No groups match this filter.</div>'); }
    $('glist').innerHTML = html.join('');
    renderDetail();
  }

  function renderDetail() {
    var el = $('gdetail');
    if (st.sel < 0) { el.innerHTML = '<div class="hint">No group selected.</div>'; return; }
    var g = data.groups[st.sel], h = [], rows = [], other = [], i, m, p, o, n = [0, 0, 0], parts = [], dups = dupPartners()[st.sel] || [];
    for (i = 0; i < g.m.length; i++) {
      m = g.m[i];
      if (st.mode === 'direct' && m[1] === 2) { continue; }
      n[m[1]]++; p = data.people[m[0]];
      rows.push('<tr><td>' + personLabel(p) + '</td><td class="how">' + esc(p.s) + '</td><td class="how">' +
        esc(howText(m[1], m[2])) + '</td><td>' + esc(p.d) + '</td></tr>');
    }
    for (i = 0; i < g.o.length; i++) {
      o = g.o[i];
      if (st.mode === 'direct' && o[2] === 2) { continue; }
      other.push('<tr><td>' + esc(o[0]) + '</td><td>' + esc(o[1]) + '</td><td class="how">' + esc(howText(o[2], o[3])) + '</td></tr>');
    }
    if (n[0]) { parts.push(n[0] + ' direct'); }
    if (n[1]) { parts.push(n[1] + ' by primary group'); }
    if (n[2]) { parts.push(n[2] + ' through nested groups'); }
    h.push('<h2>' + esc(g.n) + (g.s && g.s !== g.n ? '<span class="sam">' + esc(g.s) + '</span>' : '') + '</h2>');
    h.push('<div class="kv"><b>Type</b><span>' + esc(g.c) + ' &middot; ' + esc(g.sc) + '</span>' +
      (g.ou ? '<b>Where</b><span>' + esc(g.ou) + '</span>' : '') +
      '<b>Owner</b><span>' + (g.ow ? esc(g.ow) : '<span class="off">not set</span>') + '</span>' +
      (g.ds ? '<b>Description</b><span>' + esc(g.ds) + '</span>' : '') +
      '<b>People</b><span>' + (rows.length ? rows.length + (parts.length ? ' (' + parts.join(', ') + ')' : '') : 'none') + '</span></div>');
    if (dups.length || g.k.length) {
      h.push('<div class="badges">');
      for (i = 0; i < dups.length; i++) {
        o = dups[i].a === st.sel ? dups[i].b : dups[i].a;
        h.push('<button class="badge2 dup" data-goto="' + o + '" title="Show this group\'s overlaps on the Overlap tab">Near-duplicate of ' +
          esc(data.groups[o].n) + ': ' + fmt(dups[i].shared) + ' of ' + fmt(Math.max(dups[i].sizeA, dups[i].sizeB)) + ' people in common</button>');
      }
      if (g.k.length) { h.push('<span class="badge2">Contains ' + g.k.length + ' group' + (g.k.length === 1 ? '' : 's') + '</span>'); }
      h.push('</div>');
    }
    var ns = window.nestSummaryFor ? window.nestSummaryFor(g.s) : null;
    if (ns && (ns.up || ns.down)) {
      h.push('<p style="font-size:12.5px;margin:0 0 12px">Nesting: inside ' + ns.up + ' group' + (ns.up === 1 ? '' : 's') +
        ', contains ' + ns.down + ' group' + (ns.down === 1 ? '' : 's') + ' &mdash; <button class="badge2" data-nestgo="' + esc(g.s) + '" style="cursor:pointer">View chain</button></p>');
    }
    if (rows.length) {
      h.push('<div class="h3">People</div><table class="mt"><tr><th>Name</th><th>Username</th><th>How</th><th>Department</th></tr>' + rows.join('') + '</table>');
    }
    if (other.length) {
      h.push('<div class="h3">Groups and computers</div><table class="mt"><tr><th>Name</th><th>Type</th><th>How</th></tr>' + other.join('') + '</table>');
    }
    if (!rows.length && !other.length) {
      h.push('<div class="hint">' + (st.mode === 'direct' && g.m.length ? 'No members were added to this group directly. Switch to Effective to see members through nested groups.' : 'This group has no members.') + '</div>');
    }
    el.innerHTML = h.join('');
  }

  // ---- Overlap tab ----
  function setPairCount(text) { $('ovCount').innerHTML = text ? esc(text) : ''; }

  function peopleList(ids) {
    var ppl = C.intersect(data, st.mode, ids), out = [], i;
    ppl.sort(function (a, b) { var x = (data.people[a].n || '').toLowerCase(), y = (data.people[b].n || '').toLowerCase(); return x < y ? -1 : (x > y ? 1 : 0); });
    for (i = 0; i < ppl.length; i++) { out.push('<div>' + personLabel(data.people[ppl[i]]) + ' <span class="how off">' + esc(data.people[ppl[i]].s) + '</span></div>'); }
    return '<div class="plist">' + (out.length ? out.join('') : '<div class="off">Nobody.</div>') + '</div>';
  }

  function renderPairs(body) {
    // Pairs come from every group passing the type/scope filters; the search then keeps
    // pairs where EITHER group matches, so searching one group shows all of its partners.
    var ids = collect(false, true);
    var res = C.computePairs(data, { mode: st.mode, ids: ids, minPct: st.minPct, minShared: 2, maxWork: MAX_WORK });
    if (res.tooLarge) {
      setPairCount('');
      body.innerHTML = '<div class="hint">This selection is too large to compare quickly (' + fmt(res.work) + ' group combinations). Turn on &ldquo;Hide groups with 90%+ of users&rdquo; or narrow the type and scope filters.</div>';
      return;
    }
    var pairs = [], i, p, a, b, pc, h = [];
    for (i = 0; i < res.pairs.length; i++) {
      p = res.pairs[i];
      if (st.focus >= 0) { if (p.a === st.focus || p.b === st.focus) { pairs.push(p); } }
      else if (!st.q || passesQuery(p.a) || passesQuery(p.b)) { pairs.push(p); }
    }
    setPairCount(st.focus >= 0 ? '' : fmt(pairs.length));
    if (st.focus >= 0) {
      h.push('<div class="focus">Showing pairs that include <b>' + esc(data.groups[st.focus].n) + '</b>' +
        '<button class="btn" data-act="unfocus">Show all pairs</button></div>');
    }
    if (!pairs.length) {
      body.innerHTML = h.join('') + '<div class="hint">No pairs of groups share ' + Math.round(st.minPct * 100) + '% or more of their people' +
        (st.q || st.focus >= 0 ? ' for this selection' : '') + '. Try a lower minimum overlap.</div>';
      return;
    }
    for (i = 0; i < pairs.length && i < st.shown; i++) {
      p = pairs[i]; a = data.groups[p.a]; b = data.groups[p.b]; pc = Math.round(p.pct * 100);
      h.push('<div class="ov-pair ' + p.label + '" data-a="' + p.a + '" data-b="' + p.b + '"><div class="ov-ph">' +
        '<span class="gn" title="' + esc(a.n) + ' / ' + esc(b.n) + '">' + esc(a.n) + '<span class="x">' + (p.label === 'contains' ? 'contains' : '&times;') + '</span>' + esc(b.n) + '</span>' +
        '<span class="ct">' + fmt(p.shared) + ' shared &middot; ' + fmt(p.sizeA) + ' / ' + fmt(p.sizeB) + '</span>' +
        '<div class="meter"><i style="width:' + pc + '%"></i></div><span class="pct">' + pc + '%</span>' +
        (p.label === 'contains' && window.showNesting
          ? '<span class="lab contains" data-nestgo="' + esc(a.s) + '" title="View the nesting chain" style="cursor:pointer">' + LABELS[p.label] + '</span>'
          : '<span class="lab ' + p.label + '">' + LABELS[p.label] + '</span>') + '</div><div class="ov-body"></div></div>');
    }
    if (pairs.length > st.shown) {
      h.push('<button class="btn more" data-act="more">Show more (' + fmt(pairs.length - st.shown) + ' remaining)</button>');
    }
    body.innerHTML = h.join('');
  }

  function renderGrid(body) {
    var ids = collect(true, true), h = [], i, j, a, b, n, small, pct, gr;
    if (ids.length < 2) {
      body.innerHTML = '<div class="hint">The grid needs at least two groups. Widen the filter' + (st.hide ? ', or turn off &ldquo;Hide groups with 90%+ of users&rdquo;' : '') + '.</div>';
      return;
    }
    if (ids.length > GRID_MAX) {
      body.innerHTML = '<div class="hint">' + ids.length + ' groups match. Narrow the filter to ' + GRID_MAX +
        ' or fewer to see the grid &mdash; for example type part of a group name, or a person&rsquo;s username to see how their groups relate.</div>';
      return;
    }
    ids.sort(function (x, y) { return size(y) - size(x) || byName(x, y); });
    gr = C.grid(data, { mode: st.mode, ids: ids, maxWork: MAX_WORK });
    if (gr.tooLarge) { body.innerHTML = '<div class="hint">This selection is too large to compare quickly. Narrow the filter.</div>'; return; }
    h.push('<p class="off" style="font-size:12.5px;margin:0 0 8px">Number = people in both groups. Darker = a larger share of the smaller group. The diagonal is each group&rsquo;s size. Click a number to see who.</p>');
    h.push('<div class="gridwrap"><table class="gx"><thead><tr><th></th>');
    for (j = 0; j < ids.length; j++) { h.push('<th title="' + esc(data.groups[ids[j]].n) + '"><span>' + esc(data.groups[ids[j]].n) + '</span></th>'); }
    h.push('</tr></thead><tbody>');
    for (i = 0; i < ids.length; i++) {
      a = ids[i];
      h.push('<tr><th title="' + esc(data.groups[a].n) + '">' + esc(data.groups[a].n) + '</th>');
      for (j = 0; j < ids.length; j++) {
        b = ids[j];
        if (a === b) { h.push('<td class="self" title="' + esc(data.groups[a].n) + ': ' + gr.size[a] + ' people">' + fmt(gr.size[a]) + '</td>'); continue; }
        n = C.sharedCount(gr, a, b);
        if (!n) { h.push('<td class="z">&middot;</td>'); continue; }
        small = Math.min(gr.size[a], gr.size[b]); pct = small ? n / small : 0;
        h.push('<td data-a="' + a + '" data-b="' + b + '" title="' + esc(data.groups[a].n) + ' and ' + esc(data.groups[b].n) + ': ' + n + ' shared (' + Math.round(pct * 100) + '% of the smaller group)" style="background:rgba(93,173,226,' +
          (0.15 + 0.8 * pct).toFixed(2) + ')' + (pct > 0.55 ? ';color:#0d1116;font-weight:600' : '') + '">' + fmt(n) + '</td>');
      }
      h.push('</tr>');
    }
    h.push('</tbody></table></div><div id="gridPeople" style="margin-top:12px"></div>');
    body.innerHTML = h.join('');
  }

  function renderCombo(body) {
    var h = [], i, gid, ppl, row, j, k, m, how;
    h.push('<div class="combo"><input type="search" id="cinput" list="gnames" placeholder="Type a group name..." style="flex:0 1 320px">' +
      '<button class="btn" data-act="cadd">Add group</button>');
    for (i = 0; i < st.combo.length; i++) {
      h.push('<span class="chip">' + esc(data.groups[st.combo[i]].n) + '<button data-act="cdel" data-g="' + st.combo[i] + '" title="Remove">&times;</button></span>');
    }
    h.push('</div><datalist id="gnames">');
    for (i = 0; i < data.groups.length; i++) { h.push('<option value="' + esc(data.groups[i].n) + '">'); }
    h.push('</datalist><div id="cmsg" class="off" style="font-size:12.5px"></div>');
    if (st.combo.length < 2) {
      h.push('<div class="hint">Add two to ' + COMBO_MAX + ' groups to see everyone who holds all of them &mdash; for example two groups that should not go together.</div>');
      body.innerHTML = h.join('');
      return;
    }
    ppl = C.intersect(data, st.mode, st.combo);
    h.push('<div class="result"><b>' + ppl.length + ' ' + (ppl.length === 1 ? 'person holds' : 'people hold') + '</b> all ' + st.combo.length + ' groups' +
      (st.mode === 'direct' ? ' (direct membership only)' : '') + '.</div>');
    if (ppl.length) {
      h.push('<table class="mt"><tr><th>Name</th><th>Username</th>');
      for (i = 0; i < st.combo.length; i++) { h.push('<th>' + esc(data.groups[st.combo[i]].n) + '</th>'); }
      h.push('</tr>');
      for (j = 0; j < ppl.length; j++) {
        row = '<tr><td>' + personLabel(data.people[ppl[j]]) + '</td><td class="how">' + esc(data.people[ppl[j]].s) + '</td>';
        for (i = 0; i < st.combo.length; i++) {
          gid = st.combo[i]; how = '';
          for (k = 0; k < data.groups[gid].m.length; k++) {
            m = data.groups[gid].m[k];
            if (m[0] === ppl[j]) { how = howText(m[1], m[2]); break; }
          }
          row += '<td class="how">' + esc(how) + '</td>';
        }
        h.push(row + '</tr>');
      }
      h.push('</table>');
    }
    body.innerHTML = h.join('');
  }

  function addCombo() {
    var input = $('cinput'), name = (input.value || '').toLowerCase().replace(/^\s+|\s+$/g, ''), i, found = -1;
    if (!name) { return; }
    for (i = 0; i < data.groups.length; i++) {
      if (data.groups[i].n.toLowerCase() === name || data.groups[i].s.toLowerCase() === name) { found = i; break; }
    }
    if (found < 0) { $('cmsg').innerHTML = 'No group named &ldquo;' + esc(input.value) + '&rdquo;. Pick one from the suggestions.'; return; }
    if (indexOf(st.combo, found) > -1) { $('cmsg').innerHTML = 'That group is already added.'; return; }
    if (st.combo.length >= COMBO_MAX) { $('cmsg').innerHTML = 'Up to ' + COMBO_MAX + ' groups at a time.'; return; }
    st.combo.push(found);
    renderCombo($('ovbody'));
    $('cinput').focus();
  }

  function renderOverlap() {
    setCls($('st-pairs'), 'on', st.sub === 'pairs');
    setCls($('st-grid'), 'on', st.sub === 'grid');
    setCls($('st-combo'), 'on', st.sub === 'combo');
    var body = $('ovbody');
    if (st.sub === 'grid') { renderGrid(body); }
    else if (st.sub === 'combo') { renderCombo(body); }
    else { renderPairs(body); }
  }

  function render() {
    if (st.tab === 'groups') { renderGroups(); }
    else if (st.tab === 'overlap') { renderOverlap(); }
    else if (st.tab === 'nesting' && window.renderNesting) { window.renderNesting(); }
  }

  window.showTab = function (name) {
    var tabs = ['people', 'groups', 'overlap', 'nesting'], i, fbar = $('fbar');
    st.tab = name;
    for (i = 0; i < tabs.length; i++) { setCls($('tab-' + tabs[i]), 'on', tabs[i] === name); setCls($('tb-' + tabs[i]), 'on', tabs[i] === name); }
    fbar.style.display = (name === 'groups' || name === 'overlap') ? '' : 'none';
    // Groups and Overlap use the full window (list + detail, wide grids); People keeps
    // its comfortable reading width.
    setCls(document.getElementsByTagName('main')[0], 'wide', name !== 'people');
    fbar.className = 'fbar' + (name === 'groups' ? ' show-gr' : (name === 'overlap' ? ' show-ov' : ''));
    // The filter bar lives outside the panes; move it to the top of the active pane.
    if (name === 'groups' || name === 'overlap') { $('tab-' + name).insertBefore(fbar, $('tab-' + name).firstChild); }
    render();
  };

  // Focus on one exact group rather than searching its name: a text search would also
  // match people and other groups whose names contain the same letters.
  function gotoPair(gid) {
    st.focus = gid; st.q = ''; $('gq').value = '';
    st.sub = 'pairs'; st.hide = false; $('ghide').checked = false;
    if (st.minPct > 0.9) { st.minPct = 0.9; $('gmin').value = '0.9'; }
    st.shown = PAGE;
    window.showTab('overlap');
  }

  // ---- events ----
  $('gq').oninput = $('gq').onkeyup = function () {
    var v = this.value;
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { var q = v.toLowerCase().replace(/^\s+|\s+$/g, ''); if (q !== st.q) { st.q = q; st.focus = -1; st.shown = PAGE; render(); } }, 200);
  };
  $('gtype').onchange = function () { st.type = this.value; st.shown = PAGE; render(); };
  $('gscope').onchange = function () { st.scope = this.value; st.shown = PAGE; render(); };
  $('gsort').onchange = function () { st.sort = this.value; render(); };
  $('gmin').onchange = function () { st.minPct = parseFloat(this.value); st.shown = PAGE; render(); };
  $('ghide').onclick = function () { st.hide = this.checked; st.shown = PAGE; render(); };
  $('mEff').onclick = function () { st.mode = 'effective'; setCls($('mEff'), 'on', true); setCls($('mDir'), 'on', false); render(); };
  $('mDir').onclick = function () { st.mode = 'direct'; setCls($('mDir'), 'on', true); setCls($('mEff'), 'on', false); render(); };
  $('st-pairs').onclick = function () { st.sub = 'pairs'; renderOverlap(); };
  $('st-grid').onclick = function () { st.sub = 'grid'; renderOverlap(); };
  $('st-combo').onclick = function () { st.sub = 'combo'; renderOverlap(); };

  $('glist').onclick = function (e) {
    var item = closest((e || window.event).target || (e || window.event).srcElement, 'gl-item', this);
    if (!item) { return; }
    st.sel = parseInt(item.getAttribute('data-g'), 10);
    eachEl('#glist .gl-item', function (el) { setCls(el, 'on', el === item); });
    renderDetail();
  };
  $('gdetail').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement;
    if (t && t.getAttribute && t.getAttribute('data-nestgo') !== null && window.showNesting) { window.showNesting(t.getAttribute('data-nestgo')); return; }
    if (t && t.getAttribute && t.getAttribute('data-goto') !== null) { gotoPair(st.sel); }
  };
  $('ovbody').onclick = function (e) {
    var t = (e || window.event).target || (e || window.event).srcElement, act = t.getAttribute ? t.getAttribute('data-act') : null, pair, body, a, b;
    if (t.getAttribute && t.getAttribute('data-nestgo') !== null && window.showNesting) { window.showNesting(t.getAttribute('data-nestgo')); return; }
    if (act === 'more') { st.shown += PAGE; renderPairs($('ovbody')); return; }
    if (act === 'unfocus') { st.focus = -1; st.shown = PAGE; renderPairs($('ovbody')); return; }
    if (act === 'cadd') { addCombo(); return; }
    if (act === 'cdel') { st.combo.splice(indexOf(st.combo, parseInt(t.getAttribute('data-g'), 10)), 1); renderCombo($('ovbody')); return; }
    if (t.tagName === 'TD' && t.getAttribute('data-a') !== null) {
      a = parseInt(t.getAttribute('data-a'), 10); b = parseInt(t.getAttribute('data-b'), 10);
      $('gridPeople').innerHTML = '<div class="h3">In both ' + esc(data.groups[a].n) + ' and ' + esc(data.groups[b].n) + '</div>' + peopleList([a, b]);
      return;
    }
    pair = closest(t, 'ov-pair', this);
    if (pair && closest(t, 'ov-ph', pair)) {
      body = pair.lastChild;
      if (!hasCls(pair, 'open')) {
        body.innerHTML = peopleList([parseInt(pair.getAttribute('data-a'), 10), parseInt(pair.getAttribute('data-b'), 10)]);
      }
      setCls(pair, 'open', !hasCls(pair, 'open'));
    }
  };
  $('ovbody').onkeydown = function (e) {
    var ev = e || window.event, t = ev.target || ev.srcElement;
    if (t && t.id === 'cinput' && (ev.keyCode === 13)) { addCombo(); }
  };

  // Pair count on the tab label, with the default filters.
  setTimeout(function () {
    var res = C.computePairs(data, { mode: st.mode, ids: collect(false, true), minPct: st.minPct, minShared: 2, maxWork: MAX_WORK });
    setPairCount(res.tooLarge ? '' : fmt(res.pairs.length));
  }, 0);

  var start = (location.hash || '').replace('#', '');
  if (start === 'groups' || start === 'overlap') { window.showTab(start); }
}());
</script>
'@)
        if ($hasNest) { $null = $sb.AppendLine((Get-NestUiScript)) }
    }
    $null = $sb.AppendLine('</body></html>')

    return $sb.ToString()
}

#endregion

#region Main

Write-Status '=== AD Group Membership Export ==='
Write-Status "Target server      : $(if ($Server) { $Server } else { 'default (auto-discovered DC)' })"
Write-Status "Include nested     : $($IncludeNested.IsPresent)"
Write-Status "Primary group scan : $(-not $SkipPrimaryGroupMembers.IsPresent)"
Write-Status "User report        : $($UserReport.IsPresent)$(if ($UserReport -and $IncludeDisabled) { ' (incl. disabled)' })"
Write-Status "Output path        : $OutputPath"

try {
    $context = Get-DomainContext
    Write-Status "Domain: $($context.DnsRoot) [$($context.DomainSid)]"
}
catch {
    $script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8
    exit 1
}

try {
    $groups = Get-TargetGroup
}
catch {
    Write-Status "Group enumeration failed: $($_.Exception.Message)" 'FAIL'
    $script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8
    exit 1
}

if ($groups.Count -eq 0) {
    Write-Status 'No groups matched the given filters. Nothing to export.' 'WARN'
    $script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8
    exit 0
}

$allRows = New-Object System.Collections.Generic.List[object]
$groupsWithMembers = 0
$groupsEmpty = 0
$groupsFailed = 0
$index = 0

foreach ($group in $groups) {
    $index++
    Write-Progress -Activity 'Exporting AD group membership' `
        -Status "$index of $($groups.Count): $($group.Name)" `
        -PercentComplete (($index / $groups.Count) * 100)

    try {
        $visited = New-Object 'System.Collections.Generic.HashSet[string]'
        [void]$visited.Add($group.DistinguishedName)

        # @(...) guards against PowerShell unrolling a single-element List into a bare
        # object, which would break the .Count / .AddRange calls below.
        $rows = New-Object System.Collections.Generic.List[object]
        $directRows = @(Resolve-GroupMembership -Group $group -RootGroup $group -Depth 0 -Path '' -VisitedGroups $visited)
        if ($directRows.Count -gt 0) { $rows.AddRange([object[]]$directRows) }

        if (-not $SkipPrimaryGroupMembers) {
            # Merged rather than appended: Get-ADGroupMember may already have returned
            # these users, and appending made them look like duplicate access.
            $primaryRows = @(Get-PrimaryGroupMember -Group $group -Context $context)
            $merged = @(Merge-PrimaryGroupRows -MemberRows $rows.ToArray() -PrimaryRows $primaryRows)
            $rows = New-Object System.Collections.Generic.List[object]
            if ($merged.Count -gt 0) { $rows.AddRange([object[]]$merged) }
        }

        if ($rows.Count -gt 0) {
            $allRows.AddRange([object[]]$rows)
            $groupsWithMembers++
            Write-Status "$($group.Name): $($rows.Count) membership row(s)."
        }
        else {
            $groupsEmpty++
            Write-Status "$($group.Name): no members." 'WARN'
            if ($IncludeEmptyGroups) {
                $allRows.Add((New-MembershipRow -Group $group -Member $null `
                    -MembershipType 'EmptyGroup' -NestingDepth 0 -NestedVia '' -UserDetail $null))
            }
        }
    }
    catch {
        # One unreadable group must not halt the run.
        $groupsFailed++
        Write-Status "Failed to process '$($group.Name)': $($_.Exception.Message)" 'FAIL'
        continue
    }
}

Write-Progress -Activity 'Exporting AD group membership' -Completed

if ($allRows.Count -eq 0) {
    Write-Status 'No membership rows produced. Re-run with -IncludeEmptyGroups to list groups that have no members.' 'WARN'
    $script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8
    exit 0
}

try {
    $allRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    if (Confirm-FileWritten -Path $csvFile -Description "Group CSV ($($allRows.Count) row(s))") {
        $writeVerified = $true
    }
    else {
        $writeVerified = $false
    }
}
catch {
    Write-Status "Failed to write CSV: $($_.Exception.Message)" 'FAIL'
    $script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8
    exit 1
}

#region User-centric report output

$userReportFiles = @()
$userStats = $null

if ($UserReport) {

    Write-Status 'Building user-centric report...'

    # Without -IncludeNested there are no inherited paths, so nothing can be redundant and
    # the report understates access. Warn rather than refuse: a direct-only user view is
    # still a legitimate thing to want.
    if (-not $IncludeNested) {
        Write-Status 'User report without -IncludeNested shows direct membership only; inherited access and duplicate paths cannot be detected.' 'WARN'
    }

    try {
        $userModel = @(ConvertTo-UserAccessModel -Rows $allRows -IncludeDisabled:$IncludeDisabled)

        if ($userModel.Count -eq 0) {
            Write-Status 'No users matched the user report filter; skipping user report.' 'WARN'
        }
        else {
            # A run narrowed by OU or group name yields a per-user list that covers only the
            # groups scanned. Saying so in the report is the difference between a partial
            # view and a misleading one.
            $scopeIsNarrowed = [bool]($SearchBase -or $GroupName -or $GroupCategory -or $GroupScope)

            $scopeBits = @()
            if ($GroupName)     { $scopeBits += "groups matching $($GroupName -join ', ')" }
            if ($SearchBase)    { $scopeBits += "under $SearchBase" }
            if ($GroupCategory) { $scopeBits += "$GroupCategory groups" }
            if ($GroupScope)    { $scopeBits += "$GroupScope scope" }
            if ($ExcludeBuiltin){ $scopeBits += 'builtin excluded' }
            if ($IncludeNested) { $scopeBits += 'nested membership expanded' }
            if ($scopeBits.Count -eq 0) { $scopeBits = @('all groups in the domain') }
            $scopeNote = ($scopeBits -join ', ')

            $userHtmlFile = Join-Path $OutputPath "ADUserAccess_$runStamp.html"
            $userCsvFile  = Join-Path $OutputPath "ADUserAccess_$runStamp.csv"

            # Same rows, same enabled/disabled rule: the Groups and Overlap tabs never
            # disagree with the People tab about who is in scope.
            $groupModel = ConvertTo-GroupAccessModel -Rows $allRows -Groups $groups -IncludeDisabled:$IncludeDisabled

            # Nesting tab: complete the group graph upward. Isolated so a failure here costs
            # only the tab, never the rest of the report.
            $nestModel = $null
            try {
                $nestGraph = Resolve-NestGraph -Groups $groups -Edges $script:NestEdges -Names $script:NestNames -Lookup {
                    param($dn)
                    Get-ADGroup -Identity $dn @ADParams -Properties MemberOf, GroupCategory, GroupScope, SID -ErrorAction Stop
                }
                $nestModel = ConvertTo-NestModel -Graph $nestGraph -Edges $script:NestEdges -NestedExpanded:$IncludeNested
                $capNote = if ($nestGraph.CapReached) { '; lookup limit reached, upward chains may be incomplete' } else { '' }
                Write-Status "Nesting: $($nestModel.Nodes.Count) group(s) involved, $($nestGraph.Lookups) extra lookup(s)$capNote."
            }
            catch {
                Write-Status "Nesting tab skipped: $($_.Exception.Message)" 'WARN'
                $script:LogLines.Add("[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN] Stack: $($_.ScriptStackTrace -replace '\r?\n', ' <- ')")
            }

            $html = New-UserAccessHtml -Users $userModel -DomainName $context.DnsRoot `
                -ScopeNote $scopeNote -ScopeIsNarrowed:$scopeIsNarrowed `
                -IncludeDisabled:$IncludeDisabled -NestedExpanded:$IncludeNested `
                -GroupsProcessed $groups.Count -GroupModel $groupModel -NestModel $nestModel

            $html | Out-File -FilePath $userHtmlFile -Encoding UTF8
            # A valid report is tens of KB at minimum; anything smaller means the write was
            # truncated even if no exception was raised.
            $htmlOk = Confirm-FileWritten -Path $userHtmlFile `
                -Description "User report for $($userModel.Count) user(s)" -MinimumBytes 1024

            @(ConvertTo-UserAccessCsvRow -Users $userModel) |
                Export-Csv -Path $userCsvFile -NoTypeInformation -Encoding UTF8
            $csvOk = Confirm-FileWritten -Path $userCsvFile -Description 'User CSV'

            if (-not ($htmlOk -and $csvOk)) {
                Write-Status 'The user report did not write correctly. Do not distribute these files - re-run the report.' 'FAIL'
            }

            $userReportFiles = @($userHtmlFile, $userCsvFile)
            $userStats = [PSCustomObject]@{
                Users          = $userModel.Count
                WithRedundancy = @($userModel | Where-Object { $_.RedundantCount -gt 0 }).Count
                SurplusPaths   = (@($userModel | Measure-Object -Property SurplusPathCount -Sum).Sum)
            }
        }
    }
    catch {
        # The group CSV is already on disk and is the primary artifact; a failure here must
        # not discard it or change the exit code.
        Write-Status "User report failed: $($_.Exception.Message)" 'FAIL'
        # The message alone ("Argument types do not match") rarely says where; the stack
        # trace in the log lets a failure on a client server be fixed without a repro.
        $script:LogLines.Add("[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [FAIL] Stack: $($_.ScriptStackTrace -replace '\r?\n', ' <- ')")
    }
}

#endregion

$uniquePrincipals = ($allRows | Where-Object { $_.MemberDN } | Select-Object -ExpandProperty MemberDN -Unique).Count
$primaryCount = @($allRows | Where-Object { $_.MembershipType -eq 'Primary' }).Count
$nestedCount = @($allRows | Where-Object { $_.MembershipType -eq 'Nested' }).Count

Write-Status '=== Summary ==='
Write-Status "Groups processed        : $($groups.Count)"
Write-Status "Groups with members     : $groupsWithMembers"
Write-Status "Groups with no members  : $groupsEmpty"
Write-Status "Groups failed           : $groupsFailed"
Write-Status "Membership rows         : $($allRows.Count)"
Write-Status "Unique principals       : $uniquePrincipals"
Write-Status "Nested (inherited) rows : $nestedCount"
Write-Status "Primary-group rows      : $primaryCount"
if ($userStats) {
    Write-Status "Users in user report    : $($userStats.Users)"
    if ($userStats.WithRedundancy -gt 0) {
        Write-Status "Users w/ duplicate access: $($userStats.WithRedundancy) (holding $($userStats.SurplusPaths) surplus path(s))" 'WARN'
    }
    else {
        Write-Status "Users w/ duplicate access: 0" 'PASS'
    }
}

Write-Status "CSV : $csvFile"
foreach ($f in $userReportFiles) { Write-Status "User: $f" }
Write-Status "Log : $($script:LogFile)"

if ($userStats -and $userStats.WithRedundancy -gt 0) {
    Write-Status "$($userStats.WithRedundancy) user(s) reach a group by more than one path. Removing a single group will NOT remove their access - open the HTML report and look for the DUPLICATE badges." 'WARN'
}

if (-not $IncludeNested -and $nestedCount -eq 0) {
    Write-Status 'Only DIRECT members were exported. Re-run with -IncludeNested to expand nested groups.' 'INFO'
}

$script:LogLines | Out-File -FilePath $script:LogFile -Encoding UTF8

#endregion
