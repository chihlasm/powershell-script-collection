# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1
# and Tests\Compatibility.Tests.ps1 guard it.
#Requires -Version 3.0

<#
.SYNOPSIS
    "Can this user open this folder?" - works out which share and folder permissions apply to an
    Active Directory user, through which of their groups, and gives a careful verdict.
.DESCRIPTION
    Built for "I get Access denied on a folder" tickets. The first line of output is the answer:

        Can Jane Doe open \\FS01\Finance\Budgets 2027?  PROBABLY NO

    followed by the reason, what limits it (share permissions or folder permissions), and the
    next steps. The answer is always PROBABLY YES, PROBABLY NO or CAN'T TELL, never a bare yes
    or no: this tool reads the permissions the way Windows evaluates them, but Windows'
    Effective Access tab is the final word, and the last next step always sends you there.

    WHAT IT READS (and nothing is ever changed)

      1. The user: their SID, tokenGroups (every security group they are in, nested, including
         the primary group) and an upward memberOf walk that explains the path, for example
         "FIN-Staff -> FIN-All" or "Domain Users (primary group)".
      2. The folder permissions (NTFS), with Get-Acl over the UNC path. The entries are walked in
         the order they are stored, exactly as Windows' access check does.
      3. The share permissions, over CIM (WinRM first, then DCOM) from the file server's
         Win32_LogicalShareSecuritySetting. No SmbShare module is needed on this machine.
      4. Local groups on the file server (for example BUILTIN\Users) named in an entry, read over
         the same CIM session, that group only.

    VERDICT
      PROBABLY YES  both the share and the folder permissions allow the access
      PROBABLY NO   the folder permissions or the share permissions do not allow it (or deny it)
      CAN'T TELL    something that decides the answer could not be read: the folder permissions,
                    the share permissions, a local group on the server, an unknown account,
                    claims-based conditions, an administrative share or a DFS path

    By default the check is "open the folder and list it" (Read). -Access Modify checks
    "change files in it" instead.
.PARAMETER Identity
    The user: sAMAccountName, UserPrincipalName, DOMAIN\user, DistinguishedName, or (as a
    fallback) a display name. No match, or more than one, lists the candidates and exits 2.
.PARAMETER Path
    The full network path of the folder, for example \\FS01\Finance\Budgets 2027. A drive
    letter path (S:\Budgets) is refused: use the UNC path behind the mapped drive.
.PARAMETER Access
    Read (default): open the folder and list what is in it. Modify: change files in it.
.PARAMETER Server
    Optional domain controller or domain for the Active Directory lookups.
.PARAMETER Credential
    Optional credential for Active Directory and for the CIM connection to the file server.
    It is never written to the console or a report.
.PARAMETER OutputPath
    Optional folder. When given, an HTML report and a CSV of the evidence rows named
    FolderAccessCheck_<sam>_<yyyy-MM-dd_HHmmss> are written there.
.PARAMETER MaxNestingDepth
    How many levels of parent groups the path walk follows upward (1-50, default 10). Matching
    itself uses tokenGroups, which is complete; deeper groups show "nested (path not traced)".
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027'
    Can jdoe open the folder? Console only.
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027' -Access Modify -OutputPath C:\Temp
    Can jdoe change files in it? Also saves an HTML report and a CSV for the ticket.
.NOTES
    Exit codes: 0 = PROBABLY YES, 1 = PROBABLY NO, 2 = bad path, user not found or ambiguous,
    3 = ActiveDirectory module or connectivity failure, 4 = CAN'T TELL.

    Read-only by construction: it calls Get-ADUser, Get-ADGroup, Get-ADDomain, Get-Acl,
    Get-CimInstance, Get-CimAssociatedInstance and Invoke-CimMethod with GetSecurityDescriptor
    only. Reading the share permissions needs administrator rights on the file server; without
    them the share layer is CAN'T TELL, never assumed.

    Not checked: files and subfolders inside the folder, central access policy (Dynamic Access
    Control), ownership rights, integrity labels. Access-based enumeration only hides what the
    user can't read anyway, so it does not change the answer.

    The helpers Get-PrivilegedGroupDefinition, Get-NameOnlyPrivilegedGroup and
    Find-PrivilegedGroupBySid are copied verbatim from
    Find-PrivilegedAccessPaths\Find-PrivilegedAccessPaths.ps1 (for the SQ-013 privileged-group
    warning); Tests\Get-FolderAccessCheck.Tests.ps1 fails if they drift.

    REFERENCES
      How DACLs control access to an object (stored order; a Deny of any requested, not yet
      granted right stops the check; allows add rights until all are granted; no DACL = full access)
        https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object
      Order of ACEs in a DACL (explicit before inherited is the preferred order, not a rule)
        https://learn.microsoft.com/windows/win32/secauthz/order-of-aces-in-a-dacl
      Null DACLs and empty DACLs (null = everyone, empty = no one)
        https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
      File security and access rights (FILE_GENERIC_READ / WRITE / EXECUTE mapping)
        https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
      File access rights constants
        https://learn.microsoft.com/windows/win32/fileio/file-access-rights-constants
      Generic access rights (GENERIC_ALL / EXECUTE / WRITE / READ bits)
        https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights
      FileSystemRights (Read 131209, Modify 197055, Synchronize 1048576, FullControl 2032127)
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemrights
      SDDL ACE strings (A, D, XA/XD callback = conditional, flags OI CI NP IO ID)
        https://learn.microsoft.com/windows/win32/secauthz/ace-strings
      Conditional ACEs
        https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-
      RawSecurityDescriptor (parses the SDDL string into the stored ACE list)
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor.-ctor
      Get-Acl
        https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl
      Win32_LogicalShareSecuritySetting and its GetSecurityDescriptor method (return codes 0/2/8/9/21;
      "may not be able to retrieve hidden shares")
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-logicalsharesecuritysetting
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/getsecuritydescriptor-method-in-class-win32-logicalsharesecuritysetting
      Win32_SecurityDescriptor (ControlFlags SE_DACL_PRESENT 0x4: not set, or set with a NULL DACL,
      = full access to everyone), Win32_ACE (AceType 0 allow / 1 deny, AccessMask, AceFlags),
      Win32_Trustee (SIDString)
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-ace
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-trustee
      Win32_ComputerSystem.DomainRole (4 backup DC, 5 primary DC)
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem
      Win32_Group (LocalAccount=TRUE limits the query to the machine's own groups), Win32_GroupUser
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-group
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-groupuser
      New-CimSessionOption -Protocol Dcom, Get-CimAssociatedInstance, Invoke-CimMethod
        https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsessionoption
        https://learn.microsoft.com/powershell/module/cimcmdlets/get-cimassociatedinstance
        https://learn.microsoft.com/powershell/module/cimcmdlets/invoke-cimmethod
      Well-known SIDs (Everyone S-1-1-0, NETWORK S-1-5-2, Authenticated Users S-1-5-11,
      This Organization S-1-5-15, CREATOR OWNER S-1-3-0, BUILTIN S-1-5-32-*)
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
      tokenGroups (constructed, BASE-scope read, transitive expansion) and primaryGroupID
        https://learn.microsoft.com/windows/win32/adschema/a-tokengroups
        https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/01002598-92db-4c59-822e-b22f53168c90
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
      Administrative shares (<drive>$, ADMIN$, IPC$, PRINT$, FAX$)
        https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares
      DFS Namespaces (a domain-based namespace path begins with the domain name, \\Contoso\Public)
        https://learn.microsoft.com/windows-server/storage/dfs-namespaces/dfs-overview
      Get-ADUser, Get-ADGroup, Get-ADDomain
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
        https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
      CSV formula injection (cells starting with = + - @ are prefixed with ')
        https://owasp.org/www-community/attacks/CSV_Injection

    NOT VERIFIED ON LEARN: that tokenGroups read from a domain controller includes that domain's
    BUILTIN groups (Learn and MS-ADTS defer to the MS-DRSR algorithm). It only matters when the
    file server is itself a DC, where BUILTIN entries are matched against tokenGroups directly.
    Also not stated on Learn: whether WMI returns an empty share DACL as an empty array or as
    NULL. A present-but-NULL DACL is treated as "everyone", as Win32_SecurityDescriptor documents.
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Check', Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [ValidateSet('Read', 'Modify')]
    [string]$Access = 'Read',

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath,

    [ValidateRange(1, 50)]
    [int]$MaxNestingDepth = 10,

    [Parameter(ParameterSetName = 'Load')]
    [switch]$LoadFunctionsOnly
)

# No global $ErrorActionPreference change here (the functions are dot-sourced by the tests):
# every call that must stop says -ErrorAction Stop.

# --- Documented constants ------------------------------------------------------------------
# Requested rights. FileSystemRights.Read (131209 = ReadData | ReadExtendedAttributes |
# ReadAttributes | ReadPermissions) plus Synchronize (1048576) is FILE_GENERIC_READ (0x120089);
# FileSystemRights.Modify (197055) plus Synchronize is 0x1301BF.
# https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemrights
# https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
$script:FolderAccessRequest = @{ Read = [int64]0x120089; Modify = [int64]0x1301BF }

# Generic rights (the four high bits) and what a file object maps them to:
# https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights
# FILE_GENERIC_READ = FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | STANDARD_RIGHTS_READ | SYNCHRONIZE,
# FILE_GENERIC_WRITE = FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE,
# FILE_GENERIC_EXECUTE = FILE_EXECUTE | FILE_READ_ATTRIBUTES | STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
# GENERIC_ALL = every file right (FileSystemRights.FullControl 2032127 = 0x1F01FF).
# https://learn.microsoft.com/windows/win32/fileio/file-security-and-access-rights
$script:GenericFileMapping = @(
    @{ Bit = [int64]2147483648; Rights = [int64]0x120089 }   # GENERIC_READ    0x80000000
    @{ Bit = [int64]1073741824; Rights = [int64]0x120116 }   # GENERIC_WRITE   0x40000000
    @{ Bit = [int64]536870912;  Rights = [int64]0x1200A0 }   # GENERIC_EXECUTE 0x20000000
    @{ Bit = [int64]268435456;  Rights = [int64]0x1F01FF }   # GENERIC_ALL     0x10000000
)

# Win32_SecurityDescriptor.ControlFlags SE_DACL_PRESENT:
# https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor
$script:SE_DACL_PRESENT = 0x4

# Well-known SIDs every network logon of a domain user carries: Everyone, NETWORK ("all users
# who are signed in via a network connection"), Authenticated Users, and This Organization
# ("added only by a domain controller").
# https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:NetworkLogonSids = @('S-1-1-0', 'S-1-5-2', 'S-1-5-11', 'S-1-5-15')

# Names for well-known SIDs that show up in file and share permissions (same page).
$script:WellKnownSidNames = @{
    'S-1-1-0'  = 'Everyone';         'S-1-3-0' = 'CREATOR OWNER';  'S-1-3-1' = 'CREATOR GROUP'
    'S-1-3-4'  = 'OWNER RIGHTS';     'S-1-5-2' = 'NETWORK';        'S-1-5-4' = 'INTERACTIVE'
    'S-1-5-6'  = 'SERVICE';          'S-1-5-7' = 'ANONYMOUS LOGON'; 'S-1-5-9' = 'Enterprise Domain Controllers'
    'S-1-5-11' = 'Authenticated Users'; 'S-1-5-13' = 'Terminal Server User'; 'S-1-5-14' = 'Remote Interactive Logon'
    'S-1-5-15' = 'This Organization'; 'S-1-5-18' = 'SYSTEM';       'S-1-5-19' = 'LOCAL SERVICE'
    'S-1-5-20' = 'NETWORK SERVICE'
    'S-1-5-32-544' = 'BUILTIN\Administrators'; 'S-1-5-32-545' = 'BUILTIN\Users'; 'S-1-5-32-546' = 'BUILTIN\Guests'
    'S-1-5-32-547' = 'BUILTIN\Power Users'; 'S-1-5-32-548' = 'BUILTIN\Account Operators'; 'S-1-5-32-549' = 'BUILTIN\Server Operators'
    'S-1-5-32-550' = 'BUILTIN\Print Operators'; 'S-1-5-32-551' = 'BUILTIN\Backup Operators'; 'S-1-5-32-552' = 'BUILTIN\Replicators'
    'S-1-5-32-555' = 'BUILTIN\Remote Desktop Users'; 'S-1-5-32-578' = 'BUILTIN\Hyper-V Administrators'
    'S-1-5-32-580' = 'BUILTIN\Remote Management Users'
}

# Administrative shares Windows creates by itself: <drive letter>$, ADMIN$, IPC$, PRINT$, FAX$.
# https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares
$script:AdminSharePattern = '^(?i)([A-Z]|ADMIN|IPC|PRINT|FAX)\$$'

$script:BadPathMessage = 'Enter the full network path, for example \\FS01\Finance\Budgets 2027'
$script:AdminShareMessage = "administrative share: run it again with the folder's real share path"
$script:DfsMessage = "this is a DFS path: run it again with the real server path (find it in the folder's Properties > DFS tab)"
$script:ConditionalMessage = 'this folder uses claims-based conditions; only Effective Access can evaluate them'
$script:CimTimeoutSeconds = 30

# =============================================================================
# Small helpers
# =============================================================================

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function ConvertTo-LdapFilterValue {
    # RFC 4515 escaping so a name containing ( ) * \ cannot change the filter.
    param([string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-AdSplat {
    param([string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $h = @{}
    if ($Server) { $h['Server'] = $Server }
    if ($Credential) { $h['Credential'] = $Credential }
    return $h
}

function Get-DomainDnsFromDn {
    param([string]$DistinguishedName)
    $parts = @(($DistinguishedName -split '(?<!\\),') | Where-Object { $_ -match '^\s*DC=' } | ForEach-Object { ($_ -replace '^\s*DC=', '').Trim() })
    return ($parts -join '.')
}

function Get-SidText {
    # A SecurityIdentifier, a CIM/AD SID property or a string -> 'S-1-...'.
    param([object]$Sid)
    if ($null -eq $Sid) { return '' }
    if ($Sid.PSObject.Properties['Value'] -and $Sid.Value) { return [string]$Sid.Value }
    return [string]$Sid
}

#region Shared helpers (copied verbatim from Find-PrivilegedAccessPaths.ps1; used by SQ-013)
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
#endregion

# =============================================================================
# Pure interpretation (no AD, CIM or file system calls - unit tested directly)
# =============================================================================

function Split-FolderAccessPath {
    <#
    .SYNOPSIS
        \\server\share\folder -> Server, Share, Folder and Kind (Normal / Admin / Dfs).
    .DESCRIPTION
        Only a UNC path is accepted: a drive letter is a mapping on the user's PC that this
        machine can't see. Kind Admin = an administrative share Windows creates itself (C$, D$,
        ADMIN$...); a hidden share someone made (Finance$) is Normal.
        https://learn.microsoft.com/troubleshoot/windows-server/networking/remove-administrative-shares
        Kind Dfs = the server part is the AD domain's DNS or NetBIOS name, which is how a
        domain-based DFS namespace path begins (\\Contoso\Public).
        https://learn.microsoft.com/windows-server/storage/dfs-namespaces/dfs-overview
    #>
    param([string]$Path, [string[]]$DomainName)

    $result = [PSCustomObject]@{ Valid = $false; Server = ''; Share = ''; Folder = ''; Kind = 'Normal'; Message = $script:BadPathMessage }
    $p = ([string]$Path).Trim()
    if ($p -notmatch '^\\\\([^\\/:*?"<>|]+)\\([^\\/]+)(\\.*)?$') { return $result }
    $result.Valid = $true
    $result.Server = $Matches[1]
    $result.Share = $Matches[2]
    $result.Folder = $p.TrimEnd('\')
    $result.Message = ''
    $domains = @($DomainName | Where-Object { $_ })
    if (@($domains | Where-Object { $_ -ieq $result.Server }).Count -gt 0) {
        $result.Kind = 'Dfs'; $result.Message = $script:DfsMessage
    } elseif ($result.Share -match $script:AdminSharePattern) {
        $result.Kind = 'Admin'; $result.Message = $script:AdminShareMessage
    }
    return $result
}

function ConvertTo-FileAccessMask {
    # Access mask (signed or unsigned) -> unsigned int64 with generic bits mapped to file rights.
    # https://learn.microsoft.com/windows/win32/secauthz/generic-access-rights
    param([object]$Mask)
    $m = [int64]$Mask
    if ($m -lt 0) { $m += [int64]4294967296 }
    foreach ($g in $script:GenericFileMapping) {
        if (($m -band $g.Bit) -ne 0) { $m = ($m -bxor $g.Bit) -bor $g.Rights }
    }
    return $m
}

function Format-AccessRights {
    # The names the Security and Share Permissions tabs use, else "Special (0x...)".
    param([object]$Mask, [string]$Layer = 'Folder')
    $m = ConvertTo-FileAccessMask $Mask
    $sync = [int64]0x100000
    $names = if ($Layer -eq 'Share') {
        @{ 0x1F01FF = 'Full Control'; 0x1301BF = 'Change'; 0x1200A9 = 'Read' }
    } else {
        @{ 0x1F01FF = 'Full control'; 0x1301BF = 'Modify'; 0x1201BF = 'Read, write and run'; 0x1200A9 = 'Read & execute'
           0x120089 = 'Read'; 0x120116 = 'Write'; 0x100020 = 'Traverse folder only' }
    }
    foreach ($candidate in @($m, ($m -bor $sync))) {
        foreach ($k in $names.Keys) { if ([int64]$k -eq $candidate) { return $names[$k] } }
    }
    return ('Special (0x{0:X})' -f $m)
}

function Get-AceAppliesTo {
    # AceFlags -> the "Applies to" wording of the Advanced Security dialog.
    # OBJECT_INHERIT 0x1, CONTAINER_INHERIT 0x2, INHERIT_ONLY 0x8:
    # https://learn.microsoft.com/windows/win32/secauthz/ace-strings
    param([int]$AceFlags)
    $oi = (($AceFlags -band 0x1) -ne 0); $ci = (($AceFlags -band 0x2) -ne 0); $io = (($AceFlags -band 0x8) -ne 0)
    if ($io) {
        if ($oi -and $ci) { return 'Subfolders and files only' }
        if ($ci) { return 'Subfolders only' }
        if ($oi) { return 'Files only' }
        return 'Below this folder only'
    }
    if ($oi -and $ci) { return 'This folder, subfolders and files' }
    if ($ci) { return 'This folder and subfolders' }
    if ($oi) { return 'This folder and files' }
    return 'This folder only'
}

function ConvertFrom-FolderSddl {
    <#
    .SYNOPSIS
        Folder SDDL -> the DACL entries in stored order, plus DaclState and Conditional.
    .DESCRIPTION
        RawSecurityDescriptor keeps the entries exactly as stored, including conditional
        (callback, SDDL XA / XD) entries that the .Access collection does not show, and the
        INHERIT_ONLY (IO) and INHERITED (ID) flags.
        https://learn.microsoft.com/windows/win32/secauthz/ace-strings
        https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor.-ctor
        A folder with no DACL at all grants everyone full access, so it is represented as one
        Everyone / Full control entry.
        https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
    #>
    param([Parameter(Mandatory = $true)][string]$Sddl)

    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $Sddl
    $aces = New-Object System.Collections.Generic.List[object]
    $conditional = $false
    $unsupported = New-Object System.Collections.Generic.List[string]
    if ($null -eq $sd.DiscretionaryAcl) {
        $aces.Add([PSCustomObject]@{
            Sid = 'S-1-1-0'; Principal = 'Everyone (the folder has no permission list, which lets everyone in)'; Type = 'Allow'
            Mask = [int64]0x1F01FF; Inherited = $false; InheritOnly = $false; Unresolved = $false; IsServerLocal = $false
            AppliesTo = 'This folder only'; Conditional = $false; Unsupported = $false
        })
        return [PSCustomObject]@{ DaclState = 'Null'; Aces = $aces.ToArray(); Conditional = $false; Unsupported = @() }
    }
    foreach ($ace in $sd.DiscretionaryAcl) {
        $flags = [int]$ace.AceFlags
        $kind = [string]$ace.AceType
        $isCallback = ($kind -match 'Callback')
        if ($isCallback -and ($flags -band 0x8) -eq 0) { $conditional = $true }   # an inherit-only condition does not decide this folder
        $isCommon = ($ace -is [System.Security.AccessControl.CommonAce])
        if (-not $isCommon) { $unsupported.Add($kind) }
        $sid = ''
        if ($ace.PSObject.Properties['SecurityIdentifier'] -and $ace.SecurityIdentifier) { $sid = $ace.SecurityIdentifier.Value }
        $mask = [int64]0
        if ($ace.PSObject.Properties['AccessMask']) { $mask = [int64]$ace.AccessMask }
        $aces.Add([PSCustomObject]@{
            Sid = $sid; Principal = $null; Type = $(if ($kind -match 'Denied') { 'Deny' } else { 'Allow' })
            Mask = $mask; Inherited = (($flags -band 0x10) -ne 0); InheritOnly = (($flags -band 0x8) -ne 0)
            Unresolved = $false; IsServerLocal = $false; AppliesTo = (Get-AceAppliesTo -AceFlags $flags)
            Conditional = $isCallback; Unsupported = (-not $isCommon)
        })
    }
    $state = if ($aces.Count -eq 0) { 'Empty' } else { 'Present' }
    return [PSCustomObject]@{ DaclState = $state; Aces = $aces.ToArray(); Conditional = $conditional; Unsupported = $unsupported.ToArray() }
}

function ConvertFrom-ShareDescriptor {
    <#
    .SYNOPSIS
        Win32_SecurityDescriptor (from GetSecurityDescriptor) -> DaclState and ACE objects.
    .DESCRIPTION
        SE_DACL_PRESENT (0x4) "not set, or set and the DACL is NULL" = full access to everyone
        (DaclState Null); present with no entries = no one (Empty).
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor
        https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
        Win32_ACE: AceType 0 = access allowed, 1 = access denied; AccessMask; Trustee.SIDString.
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-ace
    #>
    param([Parameter(Mandatory = $true)][object]$Descriptor)
    $flags = 0
    if ($null -ne $Descriptor.ControlFlags) { $flags = [int]$Descriptor.ControlFlags }
    $dacl = $Descriptor.DACL
    if ((($flags -band $script:SE_DACL_PRESENT) -eq 0) -or $null -eq $dacl) {
        return [PSCustomObject]@{ DaclState = 'Null'; Aces = @() }
    }
    $aces = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($dacl)) {
        if ($null -eq $a) { continue }
        $type = switch ([int]$a.AceType) { 0 { 'Allow' } 1 { 'Deny' } default { $null } }
        if (-not $type) { continue }
        $t = $a.Trustee
        $name = ''
        if ($t -and $t.Name) { $name = $(if ($t.Domain) { "$($t.Domain)\$($t.Name)" } else { [string]$t.Name }) }
        $aceFlags = 0
        if ($null -ne $a.AceFlags) { $aceFlags = [int]$a.AceFlags }
        $aces.Add([PSCustomObject]@{
            Sid = $(if ($t) { [string]$t.SIDString } else { '' }); Principal = $(if ($name) { $name } else { $null })
            Type = $type; Mask = [int64]$a.AccessMask; Inherited = $false; InheritOnly = (($aceFlags -band 0x8) -ne 0)
            Unresolved = $false; IsServerLocal = $false; AppliesTo = 'The share'; Conditional = $false; Unsupported = $false
        })
    }
    $state = if ($aces.Count -eq 0) { 'Empty' } else { 'Present' }
    return [PSCustomObject]@{ DaclState = $state; Aces = $aces.ToArray() }
}

function Get-AccessVia {
    # How the user matches a SID: the walk's path, a direct entry, a well-known logon SID, or
    # a tokenGroups SID the walk did not reach.
    param([string]$Sid, [string]$UserName, [string]$UserSid, [hashtable]$GroupPaths)
    if ($GroupPaths -and $GroupPaths.ContainsKey($Sid) -and $GroupPaths[$Sid]) { return [string]$GroupPaths[$Sid] }
    if ($UserSid -and $Sid -eq $UserSid) { return "$UserName (direct entry)" }
    if ($script:WellKnownSidNames.ContainsKey($Sid)) { return $script:WellKnownSidNames[$Sid] }
    return 'nested (path not traced)'
}

function Invoke-DaclWalk {
    <#
    .SYNOPSIS
        Walks one layer's entries in stored order the way Windows' access check does.
    .DESCRIPTION
        "The system examines each ACE in sequence until ... an access-denied ACE explicitly
        denies any of the requested access rights ..., or ... access-allowed ACEs ... grant all
        the requested access rights", otherwise access is implicitly denied. Inherit-only ACEs
        do not control access to the folder itself.
        https://learn.microsoft.com/windows/win32/secauthz/how-dacls-control-access-to-an-object
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-ace

        An entry whose account is unknown, or a server-local group whose members could not be
        read, is "not checked". It makes the layer Unknown only when it could change the result:
        a Deny reached before the access was granted, or an Allow reached before the walk ended
        without the access.
    #>
    param(
        [string]$Layer, [object[]]$Aces, [int64]$Requested, [string]$UserName, [string]$Server,
        [string[]]$UserSids, [hashtable]$GroupPaths = @{}, [hashtable]$LocalGroupExpansions = @{},
        [bool]$ServerIsDomainController = $false
    )

    $sidSet = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($UserSids)) { if ($s) { [void]$sidSet.Add([string]$s) } }
    $userSid = @($UserSids)[0]
    if (-not $GroupPaths) { $GroupPaths = @{} }
    if (-not $LocalGroupExpansions) { $LocalGroupExpansions = @{} }

    $rows = New-Object System.Collections.Generic.List[object]
    $notChecked = New-Object System.Collections.Generic.List[string]
    $deciding = New-Object System.Collections.Generic.List[string]
    $allows = New-Object System.Collections.Generic.List[object]
    $granted = [int64]0
    $state = 'Open'
    $denyRow = $null
    $matchedAny = $false
    $couldDeny = $false
    $couldAllow = $false
    $order = 0

    foreach ($ace in @($Aces)) {
        if ($null -eq $ace) { continue }
        $order++
        $sid = [string]$ace.Sid
        $principal = if ($ace.Principal) { [string]$ace.Principal } elseif ($script:WellKnownSidNames.ContainsKey($sid)) { $script:WellKnownSidNames[$sid] } else { $sid }
        $mask = ConvertTo-FileAccessMask $ace.Mask
        $relevant = $mask -band $Requested
        $inheritOnly = [bool]$ace.InheritOnly
        $appliesTo = if ($ace.PSObject.Properties['AppliesTo'] -and $ace.AppliesTo) { [string]$ace.AppliesTo } elseif ($inheritOnly) { 'Below this folder only' } elseif ($Layer -eq 'Share') { 'The share' } else { 'This folder' }
        $isConditional = ($ace.PSObject.Properties['Conditional'] -and [bool]$ace.Conditional)
        $isUnsupported = ($ace.PSObject.Properties['Unsupported'] -and [bool]$ace.Unsupported)

        # Does it match the user, and how?
        $match = $false; $via = ''; $unknown = $null; $soft = $null
        if ($sidSet.Contains($sid)) {
            $match = $true
            $via = Get-AccessVia -Sid $sid -UserName $UserName -UserSid $userSid -GroupPaths $GroupPaths
        } elseif (-not $ServerIsDomainController -and $LocalGroupExpansions.ContainsKey($sid)) {
            $exp = $LocalGroupExpansions[$sid]
            $groupName = if ($exp.Name) { [string]$exp.Name } else { $principal }
            if ($exp.Readable) {
                $hits = @(@($exp.MemberSids) | Where-Object { $_ -and $sidSet.Contains([string]$_) })
                if ($hits.Count -gt 0) {
                    $traced = @($hits | Where-Object { $GroupPaths.ContainsKey([string]$_) })
                    $member = if ($traced.Count -gt 0) { [string]$traced[0] } else { [string]$hits[0] }
                    $match = $true
                    $via = '{0} -> {1}' -f (Get-AccessVia -Sid $member -UserName $UserName -UserSid $userSid -GroupPaths $GroupPaths), $groupName
                }
            } else {
                $err = if ($exp.Error) { " ($($exp.Error))" } else { '' }
                $unknown = "couldn't read the members of $groupName on $Server$err"
            }
        } elseif ([bool]$ace.IsServerLocal -and -not $ServerIsDomainController) {
            # Nothing was read from the server at all (unreachable, or a DFS path).
            $soft = "members of $principal on ${Server}: not read"
        } elseif ([bool]$ace.Unresolved) {
            $unknown = if ($ace.Principal) { "$($ace.Principal) ($sid) is from another domain" } else { "unknown account $sid" }
        }

        $effect = ''
        if ($inheritOnly) {
            $effect = 'applies below this folder only'
        } elseif ($isConditional) {
            $effect = 'claims-based condition: not evaluated'
        } elseif ($isUnsupported) {
            $effect = 'entry type not evaluated'
        } elseif ($unknown) {
            $effect = "not checked: $unknown"
            $notChecked.Add($unknown)
            if ($state -eq 'Open' -and ($relevant -band (-bnot $granted)) -ne 0) {
                if ($ace.Type -eq 'Deny') { $couldDeny = $true } else { $couldAllow = $true }
                $deciding.Add($unknown)
            }
        } elseif ($soft) {
            $effect = "not checked: $soft"
            $notChecked.Add($soft)
        } elseif ($match) {
            $matchedAny = $true
            if ($ace.Type -eq 'Deny') {
                if ($state -eq 'Granted') { $effect = 'overridden by an earlier allow' }
                elseif ($state -eq 'Denied') { $effect = 'not reached: an earlier Deny decides' }
                elseif ($relevant -eq 0) { $effect = "doesn't affect this access" }
                elseif (($relevant -band (-bnot $granted)) -eq 0) { $effect = 'overridden by an earlier allow' }
                else { $effect = 'applies'; $state = 'Denied' }
            } else {
                if ($state -eq 'Granted') { $effect = 'not needed (already allowed)' }
                elseif ($state -eq 'Denied') { $effect = 'not reached: an earlier Deny decides' }
                elseif ($relevant -eq 0) { $effect = "doesn't include this access" }
                else {
                    $granted = $granted -bor $relevant
                    if ($granted -eq $Requested) { $effect = 'allows'; $state = 'Granted' } else { $effect = 'allows part of what is needed' }
                }
            }
        } else {
            $effect = "does not apply to $UserName"
        }

        $row = [PSCustomObject]@{
            Layer = $Layer; Order = $order; Principal = $principal; SID = $sid; Type = [string]$ace.Type
            Inherited = [bool]$ace.Inherited; AppliesTo = $appliesTo; Rights = (Format-AccessRights -Mask $ace.Mask -Layer $Layer)
            MatchesUser = $match; Via = $via; Effect = $effect
        }
        $rows.Add($row)
        if ($effect -eq 'applies') { $denyRow = $row }
        if ($effect -eq 'allows' -or $effect -eq 'allows part of what is needed') { $allows.Add($row) }
    }

    $final = if ($state -eq 'Open') { 'NotGranted' } else { $state }
    $uncertain = (($couldDeny -and $final -eq 'Granted') -or ($couldAllow -and $final -ne 'Granted'))
    return [PSCustomObject]@{
        Result = $final; Uncertain = $uncertain; MatchedAny = $matchedAny; DenyRow = $denyRow; AllowRows = $allows.ToArray()
        Rows = $rows.ToArray(); NotChecked = $notChecked.ToArray(); Deciding = $deciding.ToArray()
    }
}

function Get-FolderAccessAssessment {
    <#
    .SYNOPSIS
        Turns the share and folder evidence into PROBABLY YES / PROBABLY NO / CAN'T TELL.
    .DESCRIPTION
        Access over the network needs both layers. Gates, in order:
          folder permissions unreadable, or claims-based conditions -> CAN'T TELL
          folder permissions don't allow it                         -> PROBABLY NO (whatever the share says)
          share permissions don't allow it                          -> PROBABLY NO
          an unknown entry could change the folder result           -> CAN'T TELL
          share permissions not read (error, admin share, DFS path) -> CAN'T TELL
          both allow it                                             -> PROBABLY YES
        UserSids: the user's own SID first, then tokenGroups and the network-logon SIDs.
        GroupPaths: SID -> "FIN-Staff -> FIN-All". LocalGroupExpansions: SID -> Readable,
        Name, MemberSids, Error for a local group on the file server.
    #>
    param(
        [string]$UserName, [string]$DisplayName, [string]$Path, [string]$Server,
        [ValidateSet('Normal', 'Admin', 'Dfs')][string]$PathKind = 'Normal',
        [ValidateSet('Read', 'Modify')][string]$Access = 'Read',
        [bool]$ServerIsDomainController = $false,
        [string[]]$UserSids, [hashtable]$GroupPaths = @{},
        [object[]]$FolderAces, [string]$FolderError, [bool]$FolderConditional = $false,
        [object[]]$ShareAces, [ValidateSet('Present', 'Null', 'Empty')][string]$ShareDaclState = 'Present', [string]$ShareError,
        [hashtable]$LocalGroupExpansions = @{}
    )

    $requested = $script:FolderAccessRequest[$Access]
    $doing = if ($Access -eq 'Modify') { 'change files in' } else { 'open' }
    $notAllow = if ($Access -eq 'Modify') { "doesn't allow changing files in the folder" } else { "doesn't allow opening the folder" }
    $who = if ($DisplayName) { $DisplayName } else { $UserName }

    $reasons = New-Object System.Collections.Generic.List[string]
    $couldNot = New-Object System.Collections.Generic.List[string]
    $steps = New-Object System.Collections.Generic.List[string]
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-Step([string]$Text) { if (-not $steps.Contains($Text)) { $steps.Add($Text) } }
    function Add-CouldNot([string]$Text) { if (-not $couldNot.Contains($Text)) { $couldNot.Add($Text) } }

    $walkArgs = @{
        Requested = $requested; UserName = $UserName; Server = $Server; UserSids = $UserSids; GroupPaths = $GroupPaths
        LocalGroupExpansions = $LocalGroupExpansions; ServerIsDomainController = $ServerIsDomainController
    }

    # --- Share layer: Yes / No / Unknown / NotRead ---
    $share = $null; $shareState = 'NotRead'; $shareWhy = ''
    if ($PathKind -eq 'Admin') { $shareWhy = $script:AdminShareMessage; Add-CouldNot 'share permissions: not read (administrative share)' }
    elseif ($PathKind -eq 'Dfs') { $shareWhy = $script:DfsMessage; Add-CouldNot 'share permissions: not read (DFS path)' }
    elseif ($ShareError) { $shareWhy = "couldn't read the share permissions on $Server"; Add-CouldNot "share permissions: not read ($ShareError)" }
    elseif ($ShareDaclState -eq 'Null') { $shareState = 'Yes' }
    elseif ($ShareDaclState -eq 'Empty') { $shareState = 'No' }
    else {
        $share = Invoke-DaclWalk -Layer 'Share' -Aces $ShareAces @walkArgs
        foreach ($r in $share.Rows) { $rows.Add($r) }
        foreach ($n in $share.NotChecked) { Add-CouldNot "share permissions: $n" }
        $shareState = if ($share.Uncertain) { 'Unknown' } elseif ($share.Result -eq 'Granted') { 'Yes' } else { 'No' }
    }

    # --- Folder layer: Unreadable / Conditional / Yes / No / Unknown ---
    $folder = $null; $folderState = 'Unreadable'
    $unsupported = @()
    if ($FolderError) {
        Add-CouldNot "folder permissions: not read ($FolderError)"
    } else {
        $folder = Invoke-DaclWalk -Layer 'Folder' -Aces $FolderAces @walkArgs
        foreach ($r in $folder.Rows) { $rows.Add($r) }
        foreach ($n in $folder.NotChecked) { Add-CouldNot "folder permissions: $n" }
        $conditional = $FolderConditional -or (@($FolderAces | Where-Object { $_ -and $_.PSObject.Properties['Conditional'] -and $_.Conditional -and -not $_.InheritOnly }).Count -gt 0)
        $unsupported = @($FolderAces | Where-Object { $_ -and $_.PSObject.Properties['Unsupported'] -and $_.Unsupported -and -not $_.InheritOnly })
        $folderState = if ($conditional) { 'Conditional' } elseif ($unsupported.Count -gt 0) { 'Unsupported' } elseif ($folder.Result -eq 'Denied' -and -not $folder.Uncertain) { 'No' } elseif ($folder.Result -eq 'NotGranted' -and -not $folder.Uncertain) { 'No' } elseif ($folder.Uncertain) { 'Unknown' } else { 'Yes' }
    }

    # Plain-English reason for a layer that says no.
    function Get-NoReason($Walk, [string]$LayerWord) {
        if ($Walk.DenyRow) {
            $d = $Walk.DenyRow
            return ("a Deny entry in the $LayerWord permissions for {0} blocks {1} (matched through {2})" -f $d.Principal, $UserName, $d.Via)
        }
        if (-not $Walk.MatchedAny) { return "no $LayerWord permission entry matches $UserName or their groups" }
        if ($LayerWord -eq 'folder') { return "${UserName}'s groups have an entry here, but it $notAllow" }
        return "${UserName}'s groups have a share permission entry, but it $notAllow"
    }
    function Get-YesReason($Walk, [string]$LayerWord) {
        $parts = @($Walk.AllowRows | ForEach-Object { '{0} ({1})' -f $_.Principal, $_.Via })
        return ("the $LayerWord permissions allow it through " + ($parts -join ', '))
    }

    $verdict = "CAN'T TELL"; $limitedBy = ''
    if ($folderState -eq 'Unreadable') {
        if ($FolderError -match '(?i)unauthori[sz]ed|access (is )?denied') {
            $reasons.Add("your account can't read this folder's permissions ($FolderError)")
            Add-Step "Run it again as an account that can read the folder's permissions (for example an administrator of $Server)."
        } else {
            # Not found, network errors, paths over 260 characters: say what failed, not "access denied".
            $reasons.Add("couldn't read this folder's permissions ($FolderError)")
            Add-Step 'Check the path is right and the folder exists. A path longer than 260 characters cannot be read this way: check a shorter parent path or use Effective Access.'
        }
    } elseif ($folderState -eq 'Conditional') {
        $reasons.Add($script:ConditionalMessage)
        Add-Step 'Use Effective Access (the last step): it is the only place the claims-based conditions on this folder are evaluated.'
    } elseif ($folderState -eq 'Unsupported') {
        $kinds = @($unsupported | ForEach-Object { $_.Type }) -join ', '
        $reasons.Add("this folder has a permission entry type this tool doesn't evaluate ($kinds); only Effective Access can")
    } elseif ($folderState -eq 'No') {
        $verdict = 'PROBABLY NO'
        $limitedBy = if ($shareState -eq 'No') { 'share and folder permissions' } else { 'folder permissions' }
        $reasons.Add((Get-NoReason $folder 'folder'))
        if ($folder.DenyRow) {
            Add-Step ("Find out why {0} is denied before changing anything: removing a Deny opens the folder to everyone else in {0} as well." -f $folder.DenyRow.Principal)
        } else {
            Add-Step 'Ask whoever owns the folder which group should have access, then add that group (not the user) with FolderPermissionManager.'
        }
    } elseif ($shareState -eq 'No') {
        $verdict = 'PROBABLY NO'; $limitedBy = 'share permissions'
        if ($ShareDaclState -eq 'Empty') { $reasons.Add('the share permission list is empty, which lets nobody in') }
        else { $reasons.Add((Get-NoReason $share 'share')) }
    } elseif ($folderState -eq 'Unknown') {
        foreach ($d in @($folder.Deciding)) { $reasons.Add("the folder has an entry that could change the answer: $d") }
    } elseif ($shareState -eq 'NotRead') {
        $reasons.Add($shareWhy)
    } elseif ($shareState -eq 'Unknown') {
        foreach ($d in @($share.Deciding)) { $reasons.Add("the share has an entry that could change the answer: $d") }
    } else {
        $verdict = 'PROBABLY YES'
        if ($ShareDaclState -eq 'Null') { $reasons.Add('the share has no permission list at all (a null DACL), which lets everyone in') }
        elseif ($share) { $reasons.Add((Get-YesReason $share 'share')) }
        $reasons.Add((Get-YesReason $folder 'folder'))
        Add-Step "If $UserName still gets 'Access denied', check they are using this exact path, and if they were added to a group recently ask them to sign out and back in."
    }

    # Next steps for whatever could not be checked, then the share-layer fix, then Effective Access.
    if ($shareState -eq 'No' -and $verdict -eq 'PROBABLY NO') {
        $shareName = if ([string]$Path -match '^\\\\[^\\]+\\([^\\]+)') { $Matches[1] } else { 'the share' }
        Add-Step "Check the share permissions of $shareName on $Server (Computer Management > Shared Folders > Shares > Properties > Share Permissions). Usually the share allows Authenticated Users and the folder permissions do the limiting."
    }
    if ($verdict -ne 'PROBABLY NO' -or $folderState -ne 'No') {
        if ($PathKind -eq 'Dfs') { Add-Step "Find the real server path in the folder's Properties > DFS tab, then run it again with that path." }
        elseif ($PathKind -eq 'Admin') { Add-Step 'Run it again with the path the user actually opens (their mapped drive or shortcut), not an administrative share.' }
        elseif ($ShareError) { Add-Step "Check that $Server answers WinRM or WMI (DCOM) from this machine and that your account is an administrator there, then run it again; or read the share permissions in Computer Management on $Server." }
    }
    if (@($couldNot | Where-Object { $_ -match 'unknown account|from another domain' }).Count -gt 0) {
        Add-Step "Look at the unknown entries in the folder's Properties > Security tab: an entry shown only as a SID is usually a deleted account or one from another domain."
    }
    if (@($couldNot | Where-Object { $_ -match "couldn't read the members of" }).Count -gt 0) {
        Add-Step "Check the members of the local group on $Server (Computer Management > Local Users and Groups), or run it again as an administrator of $Server."
    }
    Add-Step "Confirm in the folder's Properties > Security > Advanced > Effective Access for $UserName."

    $exit = switch ($verdict) { 'PROBABLY YES' { 0 } 'PROBABLY NO' { 1 } default { 4 } }
    return [PSCustomObject]@{
        Verdict = $verdict; LimitedBy = $limitedBy; Reasons = $reasons.ToArray(); CouldNotCheck = $couldNot.ToArray()
        NextSteps = $steps.ToArray(); EvidenceRows = $rows.ToArray(); ExitCode = $exit
        Headline = ('Can {0} {1} {2}?  {3}' -f $who, $doing, $Path, $verdict)
        Access = $Access; FolderState = $folderState; ShareState = $shareState
    }
}

# =============================================================================
# Directory access
# =============================================================================

function Resolve-QuickCheckUser {
    <#
    .SYNOPSIS
        Finds exactly one user, or reports NotFound / Ambiguous with candidates. Never guesses.
    .DESCRIPTION
        Copied from AD-UserQuickCheck\Get-ADUserQuickCheck.ps1 so both tools find people the
        same way. Order: distinguished name -> exact sAMAccountName / UPN -> name search (ANR
        or exact displayName). Connectivity errors are thrown to the caller (exit 3).
    #>
    param([string]$Identity, [string]$Server, [System.Management.Automation.PSCredential]$Credential)

    $ad = Get-AdSplat -Server $Server -Credential $Credential
    $props = @('DisplayName', 'SamAccountName', 'UserPrincipalName', 'DistinguishedName', 'Department', 'userAccountControl')
    $id = $Identity.Trim()
    $found = @()
    $matchedBy = ''

    if ($id -match '^(?i)CN=.+,(OU|DC|CN)=') {
        try {
            $found = @(Get-ADUser -Identity $id @ad -Properties $props -ErrorAction Stop)
            $matchedBy = 'distinguished name'
        } catch {
            if ($_.Exception.GetType().Name -notmatch 'ADIdentityNotFound') { throw }
        }
    } else {
        $name = $id
        if ($name -match '^[^\\@]+\\(.+)$') { $name = $Matches[1] }   # DOMAIN\user -> user
        $e = ConvertTo-LdapFilterValue $name
        $found = @(Get-ADUser @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$e)(userPrincipalName=$e)))" -Properties $props -ErrorAction Stop)
        $matchedBy = 'sign-in name'
        if ($found.Count -eq 0) {
            $e2 = ConvertTo-LdapFilterValue $id
            $found = @(Get-ADUser @ad -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(anr=$e2)(displayName=$e2)))" -Properties $props -ResultSetSize 25 -ErrorAction Stop)
            $matchedBy = 'name search'
        }
    }

    $status = 'Found'
    if ($found.Count -eq 0) { $status = 'NotFound' }
    elseif ($found.Count -gt 1) { $status = 'Ambiguous' }
    return [PSCustomObject]@{
        Status = $status; User = $(if ($found.Count -eq 1) { $found[0] } else { $null })
        Candidates = @($found); MatchedBy = $matchedBy
    }
}

function Get-UserGroupPath {
    <#
        Adapted from Find-PrivilegedAccessPaths\Find-PrivilegedAccessPaths.ps1 (privileged
        matching removed, AD splat passed in). Walks UP from the user, breadth-first, through
        memberOf and returns one row per group: GroupSid, GroupName, MembershipType (Direct /
        Primary / Nested), NestingDepth and Via (the whole path, e.g. "FIN-Staff -> FIN-All").

        primaryGroupID is not part of memberOf, so the primary group is added as a separate
        starting point; its own parents are then followed like any other group. A primary group
        that is also in memberOf is listed once.
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid

        Cycle safety: a group DN is added to the visited set before it is queued, so circular
        nesting is expanded once. Breadth-first order records the shortest path.
    #>
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][string]$DomainSid,
        [hashtable]$AdSplat = @{},
        [int]$MaxNestingDepth = 10
    )

    $comparer = [StringComparer]::OrdinalIgnoreCase
    $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $comparer
    $rows = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Queue

    $addGroup = {
        param($g, $type, $depth, $chain)
        $rows.Add([PSCustomObject]@{
            GroupName      = [string]$g.Name
            GroupSid       = (Get-SidText $g.SID)
            MembershipType = $type
            NestingDepth   = $depth
            Via            = $chain
        })
        $queue.Enqueue(@{ Group = $g; Chain = $chain; Depth = $depth })
    }

    foreach ($groupDn in @($User.MemberOf)) {
        if (-not $groupDn) { continue }
        if (-not $visited.Add([string]$groupDn)) { continue }
        try { $g = Get-ADGroup -Identity $groupDn @AdSplat -Properties MemberOf -ErrorAction Stop }
        catch { Write-Verbose "Could not read group '$groupDn': $($_.Exception.Message)"; continue }
        & $addGroup $g 'Direct' 0 ([string]$g.Name)
    }

    if ($User.PrimaryGroupID) {
        try {
            $pg = Get-ADGroup -Identity "$DomainSid-$($User.PrimaryGroupID)" @AdSplat -Properties MemberOf -ErrorAction Stop
            if ($visited.Add([string]$pg.DistinguishedName)) {
                & $addGroup $pg 'Primary' 0 "$($pg.Name) (primary group)"
            }
        }
        catch { Write-Verbose "Could not read primary group RID $($User.PrimaryGroupID): $($_.Exception.Message)" }
    }

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        if ($item.Depth -ge $MaxNestingDepth) {
            Write-Verbose "Nesting depth limit ($MaxNestingDepth) reached at '$($item.Group.Name)'; not descending further."
            continue
        }
        foreach ($parentDn in @($item.Group.MemberOf)) {
            if (-not $parentDn) { continue }
            if (-not $visited.Add([string]$parentDn)) { continue }
            try { $p = Get-ADGroup -Identity $parentDn @AdSplat -Properties MemberOf -ErrorAction Stop }
            catch { continue }
            & $addGroup $p 'Nested' ($item.Depth + 1) "$($item.Chain) -> $($p.Name)"
        }
    }

    return $rows.ToArray()
}

function Get-UserSidSet {
    <#
    .SYNOPSIS
        The SIDs a network logon of this user carries, and how the user is in each group.
    .DESCRIPTION
        user SID + tokenGroups (one BASE-scope read; the transitive expansion, including the
        primary group) + the network-logon well-known SIDs. Paths come from the upward
        memberOf walk; a tokenGroups SID the walk did not reach is matched as "nested (path not
        traced)".
        https://learn.microsoft.com/windows/win32/adschema/a-tokengroups
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>
    param([object]$ResolvedUser, [string]$Server, [System.Management.Automation.PSCredential]$Credential, [int]$MaxNestingDepth = 10)

    $ad = Get-AdSplat -Server $Server -Credential $Credential
    $u = Get-ADUser -Identity ([string]$ResolvedUser.DistinguishedName) @ad -Properties @('tokenGroups', 'memberOf', 'primaryGroupID', 'DisplayName', 'SamAccountName') -ErrorAction Stop
    $userSid = Get-SidText $u.SID
    $domainSid = $userSid -replace '-\d+$', ''

    $walk = @(Get-UserGroupPath -User $u -DomainSid $domainSid -AdSplat $ad -MaxNestingDepth $MaxNestingDepth)
    $paths = @{}; $names = @{}
    foreach ($w in $walk) { if ($w.GroupSid) { $paths[$w.GroupSid] = $w.Via; $names[$w.GroupSid] = $w.GroupName } }

    $sids = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $add = { param($s) if ($s -and $seen.Add([string]$s)) { $sids.Add([string]$s) } }
    & $add $userSid
    $token = @($u.tokenGroups | ForEach-Object { Get-SidText $_ } | Where-Object { $_ })
    foreach ($t in $token) { & $add $t }
    if ($u.primaryGroupID) { & $add "$domainSid-$($u.primaryGroupID)" }
    foreach ($w in $script:NetworkLogonSids) { & $add $w }

    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($w in $walk) { $groups.Add($w) }
    foreach ($t in $token) {
        if (-not $paths.ContainsKey($t)) {
            $groups.Add([PSCustomObject]@{ GroupName = ''; GroupSid = $t; MembershipType = 'Token'; NestingDepth = $null; Via = 'nested (path not traced)' })
        }
    }

    return [PSCustomObject]@{
        UserSid = $userSid; DomainSid = $domainSid; Sids = $sids.ToArray(); GroupPaths = $paths; GroupNames = $names
        Groups = $groups.ToArray(); SamAccountName = [string]$u.SamAccountName
        DisplayName = $(if ($u.DisplayName) { [string]$u.DisplayName } else { [string]$u.SamAccountName })
    }
}

# =============================================================================
# File server access (read-only)
# =============================================================================

function New-FolderAccessCimSession {
    <#
    .SYNOPSIS
        Opens a CIM session, falling back from WinRM to DCOM.
    .DESCRIPTION
        Copied from Citrix-FSLogix-HealthCollector\Get-CitrixFSLogixHealth.ps1. New-CimSession
        speaks WSMan (WinRM) by default; many file servers have WinRM off but WMI over DCOM
        reachable, so a WinRM failure is retried over DCOM.
        https://learn.microsoft.com/powershell/module/cimcmdlets/new-cimsessionoption

        Returns a hashtable with Session (or $null), Protocol, and ErrorMessage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds
    )

    $baseArgs = @{
        ComputerName        = $ComputerName
        OperationTimeoutSec = $TimeoutSeconds
        ErrorAction         = 'Stop'
    }
    if ($Credential) { $baseArgs['Credential'] = $Credential }

    try {
        $session = New-CimSession @baseArgs
        return @{ Session = $session; Protocol = 'WSMan'; ErrorMessage = $null }
    }
    catch {
        $wsmanError = $_.Exception.Message
        Write-Verbose "${ComputerName}: WSMan CIM session failed - $wsmanError"
    }

    try {
        $dcomOption = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession @baseArgs -SessionOption $dcomOption
        return @{ Session = $session; Protocol = 'DCOM'; ErrorMessage = $null }
    }
    catch {
        $dcomError = $_.Exception.Message
        Write-Verbose "${ComputerName}: DCOM CIM session failed - $dcomError"
        return @{
            Session      = $null
            Protocol     = 'None'
            ErrorMessage = ("WinRM: {0} | DCOM: {1}" -f $wsmanError, $dcomError)
        }
    }
}

function Get-ShareSecurity {
    <#
    .SYNOPSIS
        Share permissions through Win32_LogicalShareSecuritySetting.GetSecurityDescriptor.
    .DESCRIPTION
        Return codes: 0 success, 2 access denied, 8 unknown failure, 9 privilege missing,
        21 invalid parameter. Learn notes the method "may not be able to retrieve hidden shares".
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/getsecuritydescriptor-method-in-class-win32-logicalsharesecuritysetting
        Returns DaclState, Aces and Error (a message, or $null).
    #>
    param([Parameter(Mandatory = $true)]$Session, [string]$Server, [string]$Share)
    $codes = @{ 2 = 'access denied'; 8 = 'unknown failure'; 9 = 'privilege missing'; 21 = 'invalid parameter' }
    try {
        # WQL string literal: backslash and single quote are escaped with a backslash.
        $wqlName = $Share.Replace('\', '\\').Replace("'", "\'")
        $setting = Get-CimInstance -CimSession $Session -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$wqlName'" -ErrorAction Stop
        if (-not $setting) { return [PSCustomObject]@{ DaclState = 'Present'; Aces = @(); Error = "there is no share named '$Share' on $Server" } }
        $r = Invoke-CimMethod -CimSession $Session -InputObject $setting -MethodName GetSecurityDescriptor -ErrorAction Stop
        $rc = [int]$r.ReturnValue
        if ($rc -ne 0) {
            $what = if ($codes.ContainsKey($rc)) { $codes[$rc] } else { 'see WMI return codes' }
            return [PSCustomObject]@{ DaclState = 'Present'; Aces = @(); Error = "GetSecurityDescriptor returned $rc ($what)" }
        }
        $parsed = ConvertFrom-ShareDescriptor -Descriptor $r.Descriptor
        return [PSCustomObject]@{ DaclState = $parsed.DaclState; Aces = $parsed.Aces; Error = $null }
    } catch {
        return [PSCustomObject]@{ DaclState = 'Present'; Aces = @(); Error = $_.Exception.Message }
    }
}

function Get-ServerLocalGroup {
    <#
    .SYNOPSIS
        One local group on the file server and its members' SIDs, over the CIM session.
    .DESCRIPTION
        Win32_Group with LocalAccount = TRUE (only the machine's own groups) and that SID, then
        its Win32_GroupUser associations. Local groups can't contain local groups, so one level
        is the whole membership; domain groups among the members are matched against tokenGroups.
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-group
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-groupuser
        A group that doesn't exist on the server has no members (Readable, Found = $false).
    #>
    param([Parameter(Mandatory = $true)]$Session, [string]$Server, [string]$Sid, [string]$FallbackName)
    try {
        $g = Get-CimInstance -CimSession $Session -ClassName Win32_Group -Filter "LocalAccount = TRUE AND SID = '$Sid'" -ErrorAction Stop
        $g = @($g)[0]
        if (-not $g) { return [PSCustomObject]@{ Readable = $true; Found = $false; Name = $FallbackName; MemberSids = @(); Error = $null } }
        $name = if ($g.Domain) { "$($g.Domain)\$($g.Name)" } else { [string]$g.Name }
        $members = @(Get-CimAssociatedInstance -CimSession $Session -InputObject $g -Association Win32_GroupUser -ErrorAction Stop)
        return [PSCustomObject]@{
            Readable = $true; Found = $true; Name = $name; Error = $null
            MemberSids = @($members | ForEach-Object { [string]$_.SID } | Where-Object { $_ })
        }
    } catch {
        return [PSCustomObject]@{ Readable = $false; Found = $false; Name = $FallbackName; MemberSids = @(); Error = $_.Exception.Message }
    }
}

function Resolve-FolderAccessPrincipal {
    <#
    .SYNOPSIS
        Fills in Principal, Unresolved and IsServerLocal on an ACE object. Never translates SIDs
        through this machine (which would answer for the wrong computer); asks AD and the file
        server instead.
    .DESCRIPTION
        - well-known SIDs by table (BUILTIN groups are local to the file server unless it is a DC)
        - the user, and groups from the walk, by the names already read
        - other SIDs of the user's domain via Get-ADGroup / Get-ADUser; not found = orphaned
        - any other account SID: a local group of the file server if Win32_Group finds it there,
          otherwise an unknown account (deleted, or from another domain)
    #>
    param([Parameter(Mandatory = $true)][object]$Ace, [Parameter(Mandatory = $true)][hashtable]$Context)
    $sid = [string]$Ace.Sid
    $c = $Context
    if (-not $c.Cache.ContainsKey($sid)) {
        $info = @{ Principal = $null; Unresolved = $false; IsServerLocal = $false }
        if ($sid -match '^S-1-5-32-(\d+)$') {
            $info.Principal = $(if ($script:WellKnownSidNames.ContainsKey($sid)) { $script:WellKnownSidNames[$sid] } else { "BUILTIN\(RID $($Matches[1]))" })
            $info.IsServerLocal = (-not $c.ServerIsDC)
        } elseif ($script:WellKnownSidNames.ContainsKey($sid)) {
            $info.Principal = $script:WellKnownSidNames[$sid]
        } elseif ($sid -match '^S-1-5-80-') {
            # NT SERVICE\<service>: "the operating system controls the membership" (understand-security-identifiers);
            # a service identity on the server, never in a user's network logon.
            $info.Principal = 'NT SERVICE account'
        } elseif ($sid -eq $c.UserSid) {
            $info.Principal = $c.UserLabel
        } elseif ($c.GroupNames.ContainsKey($sid)) {
            $info.Principal = [string]$c.GroupNames[$sid]
        } elseif ($c.DomainSid -and $sid -match ('^' + [regex]::Escape($c.DomainSid) + '-\d+$')) {
            $adSplat = $c.Ad
            try {
                $g = Get-ADGroup -Identity $sid @adSplat -ErrorAction Stop
                $info.Principal = [string]$g.Name
            } catch {
                try {
                    $u = Get-ADUser -Identity $sid @adSplat -ErrorAction Stop
                    $info.Principal = "$($c.NetBios)\$($u.SamAccountName)"
                } catch { $info.Unresolved = $true }
            }
        } else {
            $local = $null
            if ($c.Session -and -not $c.ServerIsDC -and $sid -match '^S-1-5-21-') {
                $local = Get-ServerLocalGroup -Session $c.Session -Server $c.Server -Sid $sid -FallbackName $Ace.Principal
                if ($local.Found) { $c.LocalGroups[$sid] = $local }
            }
            if ($local -and $local.Found) { $info.Principal = $local.Name; $info.IsServerLocal = $true }
            else { $info.Unresolved = $true }
        }
        $c.Cache[$sid] = $info
    }
    $hit = $c.Cache[$sid]
    if (-not $Ace.Principal -and $hit.Principal) { $Ace.Principal = $hit.Principal }
    $Ace.Unresolved = [bool]$hit.Unresolved
    $Ace.IsServerLocal = [bool]$hit.IsServerLocal
}

function Invoke-FolderAccessCheck {
    <#
    .SYNOPSIS
        Validate, resolve, collect, assess (and write the reports with -OutputPath). Never calls
        exit; returns a result object with ExitCode.
    #>
    param(
        [string]$Identity, [string]$Path, [ValidateSet('Read', 'Modify')][string]$Access = 'Read', [string]$Server,
        [System.Management.Automation.PSCredential]$Credential, [string]$OutputPath,
        [int]$MaxNestingDepth = 10, [datetime]$Now = (Get-Date)
    )

    $result = [PSCustomObject]@{
        Status = 'Error'; ExitCode = 3; Identity = $Identity; Path = $Path; Access = $Access; Message = ''; Candidates = @(); MatchedBy = ''
        User = $null; Groups = @(); Assessment = $null; PathInfo = $null; Protocol = ''; Files = $null; ReportError = ''; Now = $Now
    }

    # 1. The path, before anything is read.
    $parsed = Split-FolderAccessPath -Path $Path
    if (-not $parsed.Valid) {
        $result.Status = 'BadInput'; $result.ExitCode = 2; $result.Message = $script:BadPathMessage
        return $result
    }

    # 2. The user.
    try {
        $res = Resolve-QuickCheckUser -Identity $Identity -Server $Server -Credential $Credential
    } catch {
        $result.Message = "Could not query Active Directory: $($_.Exception.Message)"
        return $result
    }
    $result.MatchedBy = $res.MatchedBy
    if ($res.Status -eq 'NotFound') {
        $result.Status = 'NotFound'; $result.ExitCode = 2
        $result.Message = "No user matched '$Identity'. Check the spelling, or try their sign-in name (for example jdoe or jdoe@contoso.com)."
        return $result
    }
    if ($res.Status -eq 'Ambiguous') {
        $result.Status = 'Ambiguous'; $result.ExitCode = 2; $result.Candidates = @($res.Candidates)
        $result.Message = "'$Identity' matches $(@($res.Candidates).Count) people. Run it again with the exact sign-in name of the right one."
        return $result
    }

    $ad = Get-AdSplat -Server $Server -Credential $Credential
    try {
        $sidSet = Get-UserSidSet -ResolvedUser $res.User -Server $Server -Credential $Credential -MaxNestingDepth $MaxNestingDepth
        $domain = Get-ADDomain -Identity (Get-DomainDnsFromDn -DistinguishedName ([string]$res.User.DistinguishedName)) @ad -ErrorAction Stop
    } catch {
        $result.Message = "Could not read the account's groups from Active Directory: $($_.Exception.Message)"
        return $result
    }
    $result.User = $sidSet
    $result.Groups = @($sidSet.Groups)

    # 3. Path kind now that the domain names are known (domain-based DFS).
    $parsed = Split-FolderAccessPath -Path $Path -DomainName @([string]$domain.DNSRoot, [string]$domain.NetBIOSName)
    $result.PathInfo = $parsed

    # 4. Folder permissions.
    $folderAces = @(); $folderError = $null; $folderConditional = $false
    try {
        $acl = Get-Acl -LiteralPath $parsed.Folder -ErrorAction Stop
        $fp = ConvertFrom-FolderSddl -Sddl ([string]$acl.Sddl)
        $folderAces = @($fp.Aces); $folderConditional = [bool]$fp.Conditional
    } catch {
        $folderError = $_.Exception.Message
    }

    # 5. The file server: DC or not, share permissions, local groups. Not for a DFS path, whose
    #    server part is the domain rather than the server holding the folder.
    $session = $null; $isDc = $false; $shareAces = @(); $shareState = 'Present'; $shareError = $null
    $expansions = @{}
    try {
        if ($parsed.Kind -ne 'Dfs') {
            $cim = New-FolderAccessCimSession -ComputerName $parsed.Server -Credential $Credential -TimeoutSeconds $script:CimTimeoutSeconds
            $session = $cim.Session
            $result.Protocol = $cim.Protocol
            if ($session) {
                try {
                    $cs = @(Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop)[0]
                    # DomainRole 4 = backup DC, 5 = primary DC; on a DC the BUILTIN groups are domain groups.
                    # https://learn.microsoft.com/windows/win32/cimwin32prov/win32-computersystem
                    $isDc = ($null -ne $cs -and [int]$cs.DomainRole -ge 4)
                } catch { Write-Verbose "Win32_ComputerSystem on $($parsed.Server): $($_.Exception.Message)" }
                if ($parsed.Kind -eq 'Normal') {
                    $sh = Get-ShareSecurity -Session $session -Server $parsed.Server -Share $parsed.Share
                    if ($sh.Error) { $shareError = $sh.Error } else { $shareAces = @($sh.Aces); $shareState = $sh.DaclState }
                }
            } elseif ($parsed.Kind -eq 'Normal') {
                $shareError = $cim.ErrorMessage
            }
        }

        $ctx = @{
            UserSid = $sidSet.UserSid; UserLabel = "$($domain.NetBIOSName)\$($sidSet.SamAccountName)"; GroupNames = $sidSet.GroupNames
            DomainSid = $sidSet.DomainSid; NetBios = [string]$domain.NetBIOSName; Ad = $ad; Session = $session; ServerIsDC = $isDc
            Server = $parsed.Server; Cache = @{}; LocalGroups = @{}
        }
        foreach ($ace in @($folderAces) + @($shareAces)) {
            if ($null -eq $ace -or -not $ace.Sid) { continue }
            Resolve-FolderAccessPrincipal -Ace $ace -Context $ctx
        }
        if ($session -and -not $isDc) {
            foreach ($ace in @($folderAces) + @($shareAces)) {
                if ($null -eq $ace -or -not $ace.IsServerLocal -or $ace.InheritOnly -or $expansions.ContainsKey($ace.Sid)) { continue }
                if (@($sidSet.Sids) -contains $ace.Sid) { continue }
                $lg = if ($ctx.LocalGroups.ContainsKey($ace.Sid)) { $ctx.LocalGroups[$ace.Sid] } else { Get-ServerLocalGroup -Session $session -Server $parsed.Server -Sid $ace.Sid -FallbackName $ace.Principal }
                $expansions[$ace.Sid] = $lg
            }
        }
    } finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }

    # 6. Verdict.
    $assessment = Get-FolderAccessAssessment -UserName $sidSet.SamAccountName -DisplayName $sidSet.DisplayName -Path $parsed.Folder `
        -Server $parsed.Server -PathKind $parsed.Kind -Access $Access -ServerIsDomainController $isDc `
        -UserSids $sidSet.Sids -GroupPaths $sidSet.GroupPaths `
        -FolderAces $folderAces -FolderError $folderError -FolderConditional $folderConditional `
        -ShareAces $shareAces -ShareDaclState $shareState -ShareError $shareError -LocalGroupExpansions $expansions
    $result.Status = 'Ok'; $result.ExitCode = $assessment.ExitCode; $result.Assessment = $assessment

    if ($OutputPath) {
        try { $result.Files = Export-FolderAccessReport -Result $result -OutputPath $OutputPath }
        catch { $result.ReportError = "Could not write the report to ${OutputPath}: $($_.Exception.Message)" }
    }
    return $result
}

# =============================================================================
# Output
# =============================================================================

function Format-ConsoleLine {
    # The console never shows a bare yes/no word outside the verdict (AC21), so the "no ...
    # permission entry matches" reason is worded "none of the ... entries match" on screen.
    param([string]$Text)
    return ($Text -replace '\bno (folder|share) permission entry matches\b', 'none of the $1 permission entries match')
}

function Write-FolderAccessConsole {
    param([Parameter(Mandatory = $true)][object]$Result)

    if ($Result.Status -eq 'BadInput' -or $Result.Status -eq 'NotFound') { Write-Status $Result.Message 'FAIL'; return }
    if ($Result.Status -eq 'Ambiguous') {
        Write-Status $Result.Message 'FAIL'
        foreach ($c in @($Result.Candidates)) {
            $en = if ($null -ne $c.userAccountControl -and (([int]$c.userAccountControl) -band 2)) { 'disabled' } else { 'enabled' }
            Write-Host ("       {0,-28} {1,-20} {2,-32} {3}" -f $c.DisplayName, $c.SamAccountName, $c.UserPrincipalName, $en) -ForegroundColor Gray
        }
        return
    }
    if ($Result.Status -ne 'Ok') { Write-Status $Result.Message 'FAIL'; return }

    $a = $Result.Assessment
    $color = switch ($a.Verdict) { 'PROBABLY YES' { 'Green' } 'PROBABLY NO' { 'Red' } default { 'Yellow' } }
    $level = switch ($a.Verdict) { 'PROBABLY YES' { 'PASS' } 'PROBABLY NO' { 'FAIL' } default { 'WARN' } }
    Write-Host ''
    Write-Host $a.Headline -ForegroundColor $color
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    if ($a.LimitedBy) { Write-Host ("Limited by: {0}" -f $a.LimitedBy) -ForegroundColor White }
    Write-Host 'Why:' -ForegroundColor White
    foreach ($r in @($a.Reasons)) { Write-Status (Format-ConsoleLine $r) $level }
    if (@($a.CouldNotCheck).Count -gt 0) {
        Write-Host ''
        Write-Host "Couldn't check:" -ForegroundColor White
        foreach ($n in @($a.CouldNotCheck)) { Write-Status (Format-ConsoleLine $n) 'WARN' }
    }
    Write-Host ''
    Write-Host 'Next steps:' -ForegroundColor White
    $i = 0
    foreach ($s in @($a.NextSteps)) { $i++; Write-Host ("  {0}. {1}" -f $i, (Format-ConsoleLine $s)) -ForegroundColor Gray }

    foreach ($layer in 'Share', 'Folder') {
        $rows = @($a.EvidenceRows | Where-Object { $_.Layer -eq $layer })
        Write-Host ''
        Write-Host ("{0} permissions, in the order Windows checks them" -f $layer) -ForegroundColor White
        Write-Host ('-' * 70) -ForegroundColor DarkGray
        if ($rows.Count -eq 0) {
            $why = if ($layer -eq 'Share' -and $a.ShareState -eq 'Yes') { 'none listed (the share has no permission list, which lets everyone in)' } elseif ($layer -eq 'Share' -and $a.ShareState -eq 'No') { 'the list is empty' } else { 'not read' }
            Write-Host ("  {0}" -f $why) -ForegroundColor Gray
            continue
        }
        foreach ($r in $rows) {
            $inh = if ($r.Inherited) { 'inherited' } else { 'explicit' }
            $c = if ($r.Effect -eq 'applies' -and $r.Type -eq 'Deny') { 'Red' } elseif ($r.MatchesUser) { 'White' } else { 'Gray' }
            Write-Host ("  {0,2}. {1,-5} {2,-34} {3,-22} {4,-9} {5}" -f $r.Order, $r.Type, $r.Principal, $r.Rights, $inh, $r.AppliesTo) -ForegroundColor $c
            $via = if ($r.MatchesUser) { "matches through $($r.Via); " } else { '' }
            Write-Host ("        {0}{1}" -f $via, $r.Effect) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    $traced = @($Result.Groups | Where-Object { $_.MembershipType -ne 'Token' }).Count
    Write-Status ("{0} is in {1} groups (paths traced for {2})." -f $Result.User.SamAccountName, @($Result.Groups).Count, $traced) 'INFO'
    if ($Result.Files) {
        Write-Status "Report saved: $($Result.Files.Html)" 'PASS'
        Write-Status "CSV saved   : $($Result.Files.Csv)" 'PASS'
    }
    if ($Result.ReportError) { Write-Status $Result.ReportError 'WARN' }
    Write-Status 'This only reads permissions; it changes nothing. Not checked: files and subfolders inside the folder, central access policy, ownership rights.' 'INFO'
}

function ConvertTo-FolderAccessCsvValue {
    <#
        A value that starts with = + - @, a tab or a carriage return is prefixed with ' so a
        spreadsheet shows it as text instead of running it as a formula. Folder and group names
        come from the client's file servers and directory, so they are untrusted.
        https://owasp.org/www-community/attacks/CSV_Injection
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if (-not [string]::IsNullOrEmpty($Text) -and $Text -match "^[=+\-@`t`r]") { return ("'" + $Text) }
    return $Text
}

function Get-FolderAccessCsvRows {
    # One row per evidence entry (share and folder), formula-safe.
    param([Parameter(Mandatory = $true)][object]$Result)
    foreach ($r in @($Result.Assessment.EvidenceRows)) {
        $row = [PSCustomObject]@{
            Layer = $r.Layer; Order = $r.Order; Principal = $r.Principal; SID = $r.SID; Type = $r.Type; Inherited = $r.Inherited
            AppliesTo = $r.AppliesTo; Rights = $r.Rights; MatchesUser = $r.MatchesUser; Via = $r.Via; Effect = $r.Effect
        }
        foreach ($p in $row.PSObject.Properties) { if ($p.Value -is [string]) { $p.Value = ConvertTo-FolderAccessCsvValue -Text $p.Value } }
        $row
    }
}

function ConvertTo-FolderAccessHtml {
    # Every value from AD, the file server and the path is HTML-encoded (AC23).
    param([Parameter(Mandatory = $true)][object]$Result)
    function Enc([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $a = $Result.Assessment
    $cls = switch ($a.Verdict) { 'PROBABLY YES' { 'ok' } 'PROBABLY NO' { 'bad' } default { 'warn' } }
    $tag = switch ($a.Verdict) { 'PROBABLY YES' { 'PASS' } 'PROBABLY NO' { 'FAIL' } default { 'WARN' } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>Folder access check - $(Enc $Result.User.DisplayName)</title>")
    [void]$sb.AppendLine('<style>body{background:#15181c;color:#e8eaed;font-family:"Segoe UI",sans-serif;max-width:1100px;margin:0 auto;padding:32px;line-height:1.5}' +
        '.verdict{border-left:6px solid;padding:6px 0 6px 18px;margin-bottom:24px}.verdict h1{margin:0;font-size:24px;word-break:break-all}' +
        '.ok{border-color:#5fc98a}.bad{border-color:#e2686a}.warn{border-color:#e0a458}' +
        '.reason{background:#1d2126;border:1px solid #333a44;border-radius:4px;padding:10px 14px;margin:8px 0}' +
        'table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}td,th{padding:6px 10px;border-bottom:1px solid #242931;text-align:left;vertical-align:top}' +
        'th{color:#98a2b0}h2{font-size:15px;letter-spacing:.1em;text-transform:uppercase;color:#98a2b0;margin-top:32px}tr.hit td{color:#fff}tr.deny td{color:#e2686a}' +
        '.FAIL{color:#e2686a}.WARN{color:#e0a458}.INFO{color:#5dade2}.PASS{color:#5fc98a}code{color:#98a2b0}</style></head><body>')
    [void]$sb.AppendLine("<div class=`"verdict $cls`"><h1>$(Enc $a.Headline)</h1><div>Checked $(Enc $Result.Now.ToString('yyyy-MM-dd HH:mm')) for <code>$(Enc $Result.User.SamAccountName)</code>$(if ($a.LimitedBy) { ' - limited by: ' + (Enc $a.LimitedBy) })</div></div>")
    [void]$sb.AppendLine('<h2>Why</h2>')
    foreach ($r in @($a.Reasons)) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"$tag`">[$tag]</span> $(Enc $r)</div>") }
    if (@($a.CouldNotCheck).Count -gt 0) {
        [void]$sb.AppendLine("<h2>Couldn't check</h2>")
        foreach ($n in @($a.CouldNotCheck)) { [void]$sb.AppendLine("<div class=`"reason`"><span class=`"WARN`">[WARN]</span> $(Enc $n)</div>") }
    }
    [void]$sb.AppendLine('<h2>Next steps</h2><ol>')
    foreach ($s in @($a.NextSteps)) { [void]$sb.AppendLine("<li>$(Enc $s)</li>") }
    [void]$sb.AppendLine('</ol>')
    foreach ($layer in 'Share', 'Folder') {
        [void]$sb.AppendLine("<h2>$layer permissions (in the order Windows checks them)</h2><table><tr><th>#</th><th>Type</th><th>Who</th><th>Rights</th><th>Inherited</th><th>Applies to</th><th>Matches the user through</th><th>Effect</th></tr>")
        foreach ($r in @($a.EvidenceRows | Where-Object { $_.Layer -eq $layer })) {
            $rc = if ($r.Effect -eq 'applies' -and $r.Type -eq 'Deny') { ' class="deny"' } elseif ($r.MatchesUser) { ' class="hit"' } else { '' }
            [void]$sb.AppendLine("<tr$rc><td>$(Enc $r.Order)</td><td>$(Enc $r.Type)</td><td>$(Enc $r.Principal)<br><code>$(Enc $r.SID)</code></td><td>$(Enc $r.Rights)</td><td>$(Enc $(if ($r.Inherited) { 'inherited' } else { 'explicit' }))</td><td>$(Enc $r.AppliesTo)</td><td>$(Enc $r.Via)</td><td>$(Enc $r.Effect)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    }
    [void]$sb.AppendLine("<h2>$(Enc $Result.User.SamAccountName)'s groups</h2><table><tr><th>Group</th><th>SID</th><th>How</th><th>Path</th></tr>")
    foreach ($g in @($Result.Groups)) { [void]$sb.AppendLine("<tr><td>$(Enc $g.GroupName)</td><td><code>$(Enc $g.GroupSid)</code></td><td>$(Enc $g.MembershipType)</td><td>$(Enc $g.Via)</td></tr>") }
    [void]$sb.AppendLine('</table><p class="INFO">This only reads permissions; it changes nothing. Not checked: files and subfolders inside the folder, central access policy, ownership rights. Effective Access is the final word.</p></body></html>')
    return $sb.ToString()
}

function Export-FolderAccessReport {
    # Writes FolderAccessCheck_<sam>_<yyyy-MM-dd_HHmmss>.html and .csv. Returns the two paths.
    param([Parameter(Mandatory = $true)][object]$Result, [Parameter(Mandatory = $true)][string]$OutputPath)
    if (-not (Test-Path -LiteralPath $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop }
    $sam = ([string]$Result.User.SamAccountName) -replace '[^\w\.\-]', '_'
    $stem = Join-Path $OutputPath ("FolderAccessCheck_{0}_{1}" -f $sam, $Result.Now.ToString('yyyy-MM-dd_HHmmss'))
    $csv = "$stem.csv"; $html = "$stem.html"
    @(Get-FolderAccessCsvRows -Result $Result) | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    [System.IO.File]::WriteAllText($html, (ConvertTo-FolderAccessHtml -Result $Result), (New-Object System.Text.UTF8Encoding($true)))
    return [PSCustomObject]@{ Html = $html; Csv = $csv }
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

if (-not (Split-FolderAccessPath -Path $Path).Valid) {
    Write-Status $script:BadPathMessage 'FAIL'
    exit 2
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status "The ActiveDirectory PowerShell module is not available: $($_.Exception.Message)" 'FAIL'
    Write-Status 'Install the RSAT Active Directory tools, or run this on an admin server that has them.' 'INFO'
    exit 3
}

$result = Invoke-FolderAccessCheck -Identity $Identity -Path $Path -Access $Access -Server $Server -Credential $Credential `
    -OutputPath $OutputPath -MaxNestingDepth $MaxNestingDepth
Write-FolderAccessConsole -Result $result
exit $result.ExitCode
