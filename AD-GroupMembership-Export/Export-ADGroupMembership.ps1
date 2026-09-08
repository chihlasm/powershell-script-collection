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
       Get-ADGroupMember therefore reports Domain Users as empty on a healthy domain.
       This script reconstructs those members by SID and marks them MembershipType
       'Primary'. Suppress with -SkipPrimaryGroupMembers on very large domains.

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
    Requires: PowerShell 5.1, ActiveDirectory RSAT module, read access to the directory.
              Administrator rights are NOT required - directory read is enough.

    REFERENCES
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
#>

#Requires -Version 5.1

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
    Write-Host "[INFO] Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Cyan
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
        'ManagedBy', 'mail', 'info'
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

    if ($rows.Count -gt 0) {
        Write-Status "  + $($rows.Count) primary-group member(s) not present in the member attribute."
    }

    return $rows
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
        [Parameter(Mandatory)][int]$GroupsProcessed
    )

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
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
@media(max-width:760px){
  .uhead{flex-wrap:wrap}.tags{width:100%;justify-content:flex-start}
  main,header{padding-left:16px;padding-right:16px}
}
</style>
'@)
    $null = $sb.AppendLine('</head><body>')

    # ---- header ----
    $null = $sb.AppendLine('<header><div class="htop"><div>')
    $null = $sb.AppendLine("<h1>Who has access to what &mdash; <span class=""dom"">$(ConvertTo-HtmlSafe $DomainName)</span></h1>")
    $null = $sb.AppendLine("<div class=""sub"">Generated $generated &middot; $(ConvertTo-HtmlSafe $ScopeNote)</div>")
    $null = $sb.AppendLine('</div><div style="display:flex;gap:8px">')
    $null = $sb.AppendLine('<button class="btn" id="tgTheme" onclick="toggleTheme()">Light mode</button>')
    $null = $sb.AppendLine('<button class="btn" onclick="setAll(true)">Expand all</button>')
    $null = $sb.AppendLine('<button class="btn" onclick="setAll(false)">Collapse all</button>')
    $null = $sb.AppendLine('</div></div>')

    $null = $sb.AppendLine('<div class="stats">')
    $null = $sb.AppendLine("<div class=""stat""><div class=""n"">$totalUsers</div><div class=""l"">Users</div></div>")
    $null = $sb.AppendLine("<div class=""stat""><div class=""n"">$GroupsProcessed</div><div class=""l"">Groups scanned</div></div>")
    $alertCls = if ($usersWithRedundancy -gt 0) { ' alert' } else { '' }
    $null = $sb.AppendLine("<div class=""stat$alertCls""><div class=""n"">$usersWithRedundancy</div><div class=""l"">Users w/ duplicate access</div></div>")
    $null = $sb.AppendLine("<div class=""stat$alertCls""><div class=""n"">$totalSurplus</div><div class=""l"">Extra access paths</div></div>")
    $null = $sb.AppendLine('</div>')

    $null = $sb.AppendLine('<div class="controls">')
    $null = $sb.AppendLine('<input type="search" id="q" placeholder="Filter by name, username, department, or group..." oninput="applyFilter()">')
    $null = $sb.AppendLine('<button class="btn" id="tgRed" onclick="toggleRedundant()">Show only duplicate access</button>')
    $null = $sb.AppendLine('</div></header>')

    $null = $sb.AppendLine('<main>')

    if ($ScopeIsNarrowed) {
        $null = $sb.AppendLine('<div class="note"><b>Partial view.</b> This run was limited to a subset of groups, so each person&rsquo;s list below covers only the groups that were scanned &mdash; it is not their complete domain membership.</div>')
    }
    if (-not $NestedExpanded) {
        $null = $sb.AppendLine('<div class="note"><b>Direct membership only.</b> Nested groups were not expanded, so inherited access is missing and duplicate paths cannot be detected. Re-run with <code>-IncludeNested</code> for an access review.</div>')
    }
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

    $null = $sb.AppendLine('</main>')
    $disabledNote = if ($IncludeDisabled) { 'Disabled accounts included.' } else { 'Enabled accounts only - re-run with -IncludeDisabled to include disabled users.' }
    $null = $sb.AppendLine("<footer>$(ConvertTo-HtmlSafe $disabledNote) Generated by Export-ADGroupMembership.ps1 -UserReport on $generated.</footer>")

    $null = $sb.AppendLine(@'
<script>
function setAll(open){document.querySelectorAll('.card').forEach(function(c){
  if(c.style.display!=='none')c.classList.toggle('open',open);});}
var redOnly=false;
function toggleRedundant(){redOnly=!redOnly;
  document.getElementById('tgRed').classList.toggle('on',redOnly);applyFilter();}
function applyFilter(){
  var q=document.getElementById('q').value.toLowerCase().trim(),shown=0;
  document.querySelectorAll('.card').forEach(function(c){
    var okQ=!q||c.dataset.h.indexOf(q)>-1;
    var okR=!redOnly||parseInt(c.dataset.r,10)>0;
    var vis=okQ&&okR;c.style.display=vis?'':'none';if(vis)shown++;
    if(vis&&q&&!c.classList.contains('open'))c.classList.add('open');});
  var e=document.getElementById('noMatch');
  if(e)e.style.display=shown?'none':'';}
function toggleTheme(){
  var r=document.documentElement,to=r.getAttribute('data-theme')==='light'?'dark':'light';
  r.setAttribute('data-theme',to);
  document.getElementById('tgTheme').textContent=to==='light'?'Dark mode':'Light mode';}
document.addEventListener('DOMContentLoaded',function(){
  var m=document.createElement('div');m.id='noMatch';m.className='empty';
  m.style.display='none';m.textContent='No users match this filter.';
  document.querySelector('main').appendChild(m);});
</script>
'@)
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
            $primaryRows = @(Get-PrimaryGroupMember -Group $group -Context $context)
            if ($primaryRows.Count -gt 0) { $rows.AddRange([object[]]$primaryRows) }
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

            $html = New-UserAccessHtml -Users $userModel -DomainName $context.DnsRoot `
                -ScopeNote $scopeNote -ScopeIsNarrowed:$scopeIsNarrowed `
                -IncludeDisabled:$IncludeDisabled -NestedExpanded:$IncludeNested `
                -GroupsProcessed $groups.Count

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
