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

    WHAT TO DO ABOUT IT
      PROBABLY NO   names the narrowest existing group that would let them in (fewest direct
                    members, non-privileged first), never Everyone, Authenticated Users, Domain
                    Users, Domain Computers, a BUILTIN or server-local group, or a user account.
                    A group that is in Domain Admins (or another privileged group), or has
                    adminCount = 1, carries a warning. With no such group it points to
                    FolderPermissionManager, to add a group rather than the user.
      PROBABLY YES  if every group that grants it was joined after the user's last sign-in (the
                    newest lastLogon across all DCs), the answer reads "PROBABLY YES after <user>
                    signs out and back in". When either time can't be read, that is listed under
                    "Couldn't check" and no such claim is made.

    Every run ends with a four-part ticket note (Checked, Ruled out, Could not check, Next step)
    copied to the clipboard, and saved in the ticket folder with -TicketNumber.
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
.PARAMETER TicketNumber
    Optional ticket number (letters, digits, - or _, up to 32 characters). The HTML, the CSV and
    the ticket note are saved in <root>\Ticket_<number>, where root is -OutputPath if given,
    else %USERPROFILE%\Documents\TicketNotes. TicketNote\Join-TicketNotes.ps1 later joins every
    tool's note in that folder into one. A number that does not fit is refused with a [FAIL]
    line and exit code 3, before anything is checked.
.PARAMETER NoClipboard
    Do not copy the ticket note to the clipboard. Without it the note goes to the clipboard
    marked to stay out of clipboard history (Win+V) and the cloud clipboard; only when that
    fails (e.g. an MTA host) is Set-Clipboard used, which cannot opt out.
.PARAMETER FullDetail
    Keep the folder path (and any IP address) in the ticket note. By default the note is
    paste-safe: share paths become [share path removed]. The reports always keep the full path.
.PARAMETER PassThru
    Return the result object (Status, ExitCode, Identity, Path, Message, Candidates, User,
    Groups, Assessment, PathInfo, Files, Now, Domain, TicketNote) instead of setting an exit code.
.PARAMETER Quiet
    Do not write the console report. Combine with -PassThru or -OutputPath. Also leaves the
    clipboard alone, because another script is the caller.
.PARAMETER LoadFunctionsOnly
    Define the functions and return without running a check (used by the tests).
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027'
    Can jdoe open the folder? Console only.
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027' -Access Modify -OutputPath C:\Temp
    Can jdoe change files in it? Also saves an HTML report and a CSV for the ticket.
.EXAMPLE
    .\Get-FolderAccessCheck.ps1 -Identity jdoe -Path '\\FS01\Finance\Budgets 2027' -TicketNumber 482113
    Same answer; the HTML, the CSV and the ticket note go into
    %USERPROFILE%\Documents\TicketNotes\Ticket_482113, and the note is copied to the clipboard.
.NOTES
    Exit codes (without -PassThru): 0 = PROBABLY YES (also "after they sign out and back in"),
    1 = PROBABLY NO, 2 = bad path, user not found or ambiguous, 3 = ActiveDirectory module or
    connectivity failure, or an unusable -TicketNumber, 4 = CAN'T TELL.

    Read-only by construction: it calls Get-ADUser, Get-ADGroup, Get-ADDomain,
    Get-ADDomainController, Get-ADReplicationAttributeMetadata, Get-Acl, Get-CimInstance,
    Get-CimAssociatedInstance and Invoke-CimMethod with GetSecurityDescriptor only
    (Tests\Get-FolderAccessCheck.Tests.ps1 holds an allowlist of every command and .NET method
    the script calls). The only files it writes are the reports and the ticket note.

    TICKET NOTE. A layer is only "Ruled out" when it was really read and the answer is PROBABLY
    YES or PROBABLY NO: an unreadable folder or share, an administrative share or a DFS path is
    listed under "Could not check" instead. The note is built by CaseKit.ps1 in this folder (a
    copy of TicketNote\CaseKit.ps1; Tests\CaseKitParity.Tests.ps1 fails if it drifts). If it is
    missing the check still runs, without a note. Reading the share permissions needs administrator rights on the file server; without
    them the share layer is CAN'T TELL, never assumed.

    Not checked: files and subfolders inside the folder, central access policy (Dynamic Access
    Control), ownership rights, integrity labels. Access-based enumeration only hides what the
    user can't read anyway, so it does not change the answer. A standalone DFS namespace path
    (\\FS01\Public\Link) is checked as an ordinary share: the share permissions are the
    namespace root's share, not the share the link points to.

    The helpers Get-PrivilegedGroupDefinition, Get-NameOnlyPrivilegedGroup and
    Find-PrivilegedGroupBySid are copied verbatim from
    Find-PrivilegedAccessPaths\Find-PrivilegedAccessPaths.ps1 (for the privileged-group warning);
    Tests\Get-FolderAccessCheck.Tests.ps1 fails if they drift.

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
      Win32_Group (LocalAccount=TRUE limits the query to the machine's own groups), Win32_GroupUser,
      Win32_UserAccount (LocalAccount=TRUE; query one instance, not the whole domain)
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-group
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-groupuser
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-useraccount
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
      Get-ADUser, Get-ADGroup, Get-ADDomain, Get-ADDomainController (-Filter *)
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
        https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomain
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller
      Get-ADReplicationAttributeMetadata: -Object, -Properties, -Server (mandatory; a domain name
      or a directory server), -ShowAllLinkedValues ("returns all linked values if the attribute
      returned is multi-valued"); output ADReplicationAttributeMetadata
        https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationattributemetadata
      DS_REPL_VALUE_META_DATA (per linked value: ftimeCreated "the time this attribute was
      created", ftimeLastOriginatingChange; replication does not change either)
        https://learn.microsoft.com/windows/win32/api/ntdsapi/ns-ntdsapi-ds_repl_value_meta_data
      lastLogon - NOT replicated, kept per DC; the largest value across all DCs is the true last logon
        https://learn.microsoft.com/windows/win32/adschema/a-lastlogon
      Access tokens (made at sign-in; every process of the session carries a copy, so a group
      joined later doesn't count until the next sign-in)
        https://learn.microsoft.com/windows/win32/secauthz/access-tokens
      adminCount ("ACLs changed to a more secure value by the system because it was a member of
      one of the administrative groups (directly or transitively)"), AdminSDHolder and SDProp
        https://learn.microsoft.com/windows/win32/adschema/a-admincount
        https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
      Ticket note clipboard (in CaseKit.ps1): the WinForms clipboard first; Set-Clipboard is
      5.0, so the fallback is behind a Get-Command check; never clip.exe
        https://learn.microsoft.com/powershell/scripting/whats-new/what-s-new-in-windows-powershell-50
        https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats
      CSV formula injection (cells starting with = + - @ are prefixed with ')
        https://owasp.org/www-community/attacks/CSV_Injection

    NOT VERIFIED ON LEARN: that tokenGroups read from a domain controller includes that domain's
    BUILTIN groups (Learn and MS-ADTS defer to the MS-DRSR algorithm). It only matters when the
    file server is itself a DC, where BUILTIN entries are matched against tokenGroups directly.
    Also not stated on Learn: whether WMI returns an empty share DACL as an empty array or as
    NULL. A descriptor with SE_DACL_PRESENT set but a NULL DACL is therefore not guessed at: the
    share layer is "not read" (CAN'T TELL when the folder would allow it). Present bit unset
    (documented: everyone) and present with an empty list (no one) are evaluated.
    Also not stated on Learn: that the cmdlet's FirstOriginatingCreateTime is the value
    metadata's ftimeCreated (the names and the DS_REPL_VALUE_META_DATA fields line up), and how a
    membership older than linked-value replication is returned. A missing or 1601 time is
    treated as "not dated", so it can only lead to "Couldn't check", never to a claim.
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

    # Checked in the script body (Test-TicketNumber in CaseKit.ps1), not with ValidatePattern,
    # so a mistyped number gets a plain-English [FAIL] line instead of a parameter-binding error.
    [string]$TicketNumber,

    [switch]$NoClipboard,

    [switch]$FullDetail,

    [switch]$PassThru,

    [switch]$Quiet,

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
$script:NoGroupStep = 'No existing group grants this. Ask who owns the folder which group should have access, then add that group (not the user) with FolderPermissionManager, which logs the change.'
$script:NarrowestStepPrefix = 'Narrowest existing group that grants this: '
# D-017: when only privileged groups would let the user in, tier 1 escalates instead of adding
# anyone to them.
$script:PrivilegedOnlyStepPrefix = 'Only privileged groups grant this. Escalate to a senior engineer: '
# A new group membership only reaches the user's access token at the next sign-in; locking and
# unlocking reuses the session's token. https://learn.microsoft.com/windows/win32/secauthz/access-tokens
$script:SignOutStep = 'Ask them to sign out of Windows and any Citrix/RDS session, then sign in again (locking and unlocking is not enough)'
# Never recommended as "the group to add them to": Domain Users (513) and Domain Computers (515)
# are as broad as Everyone in practice. Well-known and BUILTIN SIDs are excluded by shape (only
# S-1-5-21-<domain>-<RID> groups qualify).
# https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
$script:BroadDomainRids = @(513, 515)
# A standalone DFS namespace path (\\FS01\Public\Link) looks like an ordinary share path, and
# without the DFSN module the only share this tool can see is the namespace root's share.
# https://learn.microsoft.com/windows-server/storage/dfs-namespaces/dfs-overview
$script:NotCheckedFooter = 'Not checked: files and subfolders inside the folder, central access policy, ownership rights. ' +
    "For a standalone DFS namespace path (\\FS01\Public\Link) the share permissions shown are the namespace root's share, not the share the link points to."

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
            Conditional = $isCallback; Unsupported = (-not $isCommon); AceKind = $kind
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
        SE_DACL_PRESENT (0x4) not set = no DACL = full access to everyone (DaclState Null);
        present with no entries = no one (Empty).
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-securitydescriptor
        https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
        Win32_ACE: AceType 0 = access allowed, 1 = access denied; AccessMask; Trustee.SIDString.
        https://learn.microsoft.com/previous-versions/windows/desktop/secrcw32prov/win32-ace

        Present bit set but DACL $null (DaclState Unreadable): Win32_SecurityDescriptor calls
        that a NULL DACL, but Learn does not say whether WMI hands an EMPTY DACL back as an
        empty array or as NULL, and the two mean the opposite (everyone vs no one). Guessing
        either way could be a confident wrong answer, so it is not evaluated.
    #>
    param([Parameter(Mandatory = $true)][object]$Descriptor)
    $flags = 0
    if ($null -ne $Descriptor.ControlFlags) { $flags = [int]$Descriptor.ControlFlags }
    $dacl = $Descriptor.DACL
    if (($flags -band $script:SE_DACL_PRESENT) -eq 0) {
        return [PSCustomObject]@{ DaclState = 'Null'; Aces = @() }
    }
    if ($null -eq $dacl) {
        return [PSCustomObject]@{ DaclState = 'Unreadable'; Aces = @() }
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
        $match = $false; $via = ''; $unknown = $null
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
            # A server-local group with no expansion at all: nothing was read from the server
            # (unreachable, or a DFS path). Its members are unknown, so it is handled exactly
            # like an unreadable group: it decides the answer when it could change it (AC13).
            $unknown = "couldn't read the members of $principal on $Server (nothing could be read from the server)"
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

function Find-FolderAccessPrivilegedSid {
    <#
        The well-known privileged group this SID is (Get-PrivilegedGroupDefinition), or $null.
        Matched with Find-PrivilegedGroupBySid -AnyDomain, so a domain-relative group of any
        domain counts (Enterprise Admins of the forest root as well as this domain's Domain
        Admins); BUILTIN groups match on their S-1-5-32 SID. Protected Users is left out, as in
        Get-FolderAccessCandidateGroup: "not a privilege".
    #>
    param([string]$Sid)
    if ($Sid -notmatch '^S-1-5-(?:21-\d+-\d+-\d+|32)-\d+$') { return $null }
    $defs = @(Get-PrivilegedGroupDefinition -DomainSid ($Sid -replace '-\d+$', '') | Where-Object { $_.Risk -ne 'INFO' })
    return (Find-PrivilegedGroupBySid -Sid $Sid -Definitions $defs -AnyDomain)
}

function Test-FolderAccessCandidateEligible {
    <#
        Can this folder-layer principal be recommended as "the group to add them to"? Only a domain
        security group (S-1-5-21-<domain>-<RID>), never Domain Users / Domain Computers, a
        well-known or BUILTIN SID (Everyone, Authenticated Users, INTERACTIVE, NETWORK,
        BUILTIN\Users...), a group local to the file server, a user account or the user.
        Never a privileged group itself (D-017): a well-known one matched on its own SID (Domain
        Admins, Domain Controllers, Schema Admins, Enterprise Admins, Group Policy Creator
        Owners, Read-only Domain Controllers...), or one the upward walk named after the group
        itself (DnsAdmins, which has no well-known SID). A group merely nested in one stays a
        candidate, with the approval warning.
    #>
    param([object]$Candidate, [string]$UserSid, [hashtable]$ServerLocalSids = @{})
    if ($null -eq $Candidate) { return $false }
    $sid = [string]$Candidate.Sid
    if ([string]$Candidate.ObjectClass -ne 'group') { return $false }
    if (-not $sid -or $sid -eq $UserSid -or $ServerLocalSids.ContainsKey($sid)) { return $false }
    if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-(\d+)$') { return $false }
    if ($script:BroadDomainRids -contains [int]$Matches[1]) { return $false }
    if (Test-FolderAccessGroupIsPrivileged -Candidate $Candidate) { return $false }
    return $true
}

function Test-FolderAccessGroupIsPrivileged {
    # Is this candidate a privileged group itself (not merely nested in one)? See Test-FolderAccessCandidateEligible.
    param([object]$Candidate)
    if (Find-FolderAccessPrivilegedSid -Sid ([string]$Candidate.Sid)) { return $true }
    return (@($Candidate.PrivilegedVia) -contains [string]$Candidate.Name)
}

function Get-FolderAccessCandidateWarning {
    <#
        The approval warning for a recommended group, or $null. PrivilegedVia names the well-known
        privileged groups the candidate is nested in (Find-PrivilegedGroupBySid); a group that is
        privileged itself is never recommended (Test-FolderAccessCandidateEligible).
        adminCount = 1 "indicates that a given object has had its ACLs changed to a more secure
        value by the system because it was a member of one of the administrative groups (directly
        or transitively)"; SDProp keeps such objects in line with AdminSDHolder.
        https://learn.microsoft.com/windows/win32/adschema/a-admincount
        https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
        Incomplete: the upward walk could not be finished (a parent group could not be read, the
        nesting limit was reached), so the candidate may be in a privileged group: fail closed.
    #>
    param([object]$Candidate, [string]$UserName)
    $name = [string]$Candidate.Name
    $others = @(@($Candidate.PrivilegedVia) | Where-Object { $_ -and $_ -ne $name })
    if ($others.Count -gt 0) {
        $what = if ($others -contains 'Domain Admins') { 'domain admin rights' } else { 'the rights of ' + ($others -join ', ') }
        return ('Warning: {0} is also in {1}. Adding {2} gives them {3}. Get senior approval first.' -f $name, ($others -join ', '), $UserName, $what)
    }
    if ([int]$Candidate.AdminCount -eq 1) {
        return ('Warning: {0} is protected by AdminSDHolder (adminCount = 1), so it is, or was, in a privileged group. Check what it is nested in before adding {1}. Get senior approval first.' -f $name, $UserName)
    }
    if ([bool]$Candidate.Incomplete) {
        return ("Couldn't confirm {0} is not in a privileged group. Get senior approval first." -f $name)
    }
    return $null
}

function Test-FolderAccessWouldGrant {
    <#
        Would both layers let the user in with these SIDs added to their own? Both are walked
        again; a null share DACL lets everyone in, an empty one no one. A share that was not read
        is already listed under "Couldn't check", so it does not stop a candidate here.
    #>
    param(
        [string[]]$ExtraSids, [hashtable]$WalkArgs, [object[]]$FolderAces, [object[]]$ShareAces,
        [string]$ShareDaclState, [bool]$ShareRead
    )
    $tryArgs = @{}
    foreach ($k in $WalkArgs.Keys) { $tryArgs[$k] = $WalkArgs[$k] }
    $tryArgs['UserSids'] = @($WalkArgs.UserSids) + @($ExtraSids | Where-Object { $_ })
    $f = Invoke-DaclWalk -Layer 'Folder' -Aces $FolderAces @tryArgs
    if ($f.Result -ne 'Granted' -or $f.Uncertain) { return $false }
    if ($ShareRead) {
        if ($ShareDaclState -eq 'Empty') { return $false }
        if ($ShareDaclState -eq 'Present') {
            $s = Invoke-DaclWalk -Layer 'Share' -Aces $ShareAces @tryArgs
            if ($s.Result -ne 'Granted' -or $s.Uncertain) { return $false }
        }
    }
    return $true
}

function Select-FolderAccessNarrowestGroup {
    <#
    .SYNOPSIS
        The existing group that would grant the access with the fewest direct members, or $null.
    .DESCRIPTION
        Each eligible candidate is tried by walking both layers again with its SID, and the SIDs
        of every group it is nested in (ParentSids, which the user's token would then carry too),
        added to the user's: one that is denied at the folder, or that the share would still stop,
        is skipped.
        Ranking: verified non-privileged first, then those whose privilege check is incomplete,
        then those nested in a privileged group or with adminCount = 1; within each, the fewest
        direct members (the `member` attribute), then the name.
    #>
    param(
        [object[]]$CandidateGroups, [hashtable]$WalkArgs, [object[]]$FolderAces, [object[]]$ShareAces,
        [string]$ShareDaclState, [bool]$ShareRead, [string]$UserName, [hashtable]$ServerLocalSids = @{}
    )
    $userSid = @($WalkArgs.UserSids)[0]
    $passing = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($CandidateGroups)) {
        if (-not (Test-FolderAccessCandidateEligible -Candidate $c -UserSid $userSid -ServerLocalSids $ServerLocalSids)) { continue }
        $extra = @([string]$c.Sid) + @(@($c.ParentSids) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if (-not (Test-FolderAccessWouldGrant -ExtraSids $extra -WalkArgs $WalkArgs -FolderAces $FolderAces -ShareAces $ShareAces -ShareDaclState $ShareDaclState -ShareRead $ShareRead)) { continue }
        $warning = Get-FolderAccessCandidateWarning -Candidate $c -UserName $UserName
        $privileged = (@(@($c.PrivilegedVia) | Where-Object { $_ }).Count -gt 0 -or [int]$c.AdminCount -eq 1)
        $rank = if ($privileged) { 2 } elseif ([bool]$c.Incomplete) { 1 } else { 0 }
        $passing.Add([PSCustomObject]@{
            Name = [string]$c.Name; Sid = [string]$c.Sid; MemberCount = [int]$c.MemberCount; Warning = $warning; Rank = $rank
        })
    }
    if ($passing.Count -eq 0) { return $null }
    $best = @($passing.ToArray() | Sort-Object -Property @{ Expression = { $_.Rank } }, @{ Expression = { $_.MemberCount } }, @{ Expression = { $_.Name } })[0]
    return [PSCustomObject]@{ Name = $best.Name; Sid = $best.Sid; MemberCount = $best.MemberCount; Warning = $best.Warning }
}

function Get-FolderAccessPrivilegedGrant {
    <#
    .SYNOPSIS
        The names of the privileged groups whose folder entries would let the user in.
    .DESCRIPTION
        For the case where no group can be recommended: if a privileged group (a well-known one by
        SID, BUILTIN\Administrators included, or a candidate that is privileged itself such as
        DnsAdmins) would grant the access, the next step is to escalate (D-017), not to add the
        user to it. Each is tried the way Select-FolderAccessNarrowestGroup tries a candidate.
    #>
    param(
        [object[]]$CandidateGroups, [hashtable]$WalkArgs, [object[]]$FolderAces, [object[]]$ShareAces,
        [string]$ShareDaclState, [bool]$ShareRead
    )
    $tries = New-Object System.Collections.Generic.List[object]
    foreach ($ace in @($FolderAces)) {
        if ($null -eq $ace -or $ace.Type -ne 'Allow' -or [bool]$ace.InheritOnly) { continue }
        $def = Find-FolderAccessPrivilegedSid -Sid ([string]$ace.Sid)
        if ($def) { $tries.Add([PSCustomObject]@{ Sid = [string]$ace.Sid; Name = $(if ($ace.Principal) { [string]$ace.Principal } else { [string]$def.Name }) }) }
    }
    foreach ($c in @($CandidateGroups)) {
        if ($c -and (Test-FolderAccessGroupIsPrivileged -Candidate $c)) { $tries.Add([PSCustomObject]@{ Sid = [string]$c.Sid; Name = [string]$c.Name }) }
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($t in $tries) {
        if (-not $seen.Add($t.Sid)) { continue }
        if (Test-FolderAccessWouldGrant -ExtraSids @($t.Sid) -WalkArgs $WalkArgs -FolderAces $FolderAces -ShareAces $ShareAces -ShareDaclState $ShareDaclState -ShareRead $ShareRead) {
            $names.Add($t.Name)
        }
    }
    return $names.ToArray()
}

function Get-FolderAccessStaleToken {
    <#
    .SYNOPSIS
        Was the user added to every group that grants the access after their last sign-in?
    .DESCRIPTION
        A user's group memberships are fixed in the access token made at sign-in, so a group they
        were added to since then does not count until they sign in again.
        https://learn.microsoft.com/windows/win32/secauthz/access-tokens
        Granting paths are the folder-layer Allow rows that contributed rights. A path with no
        entry in MembershipLinks (Everyone, a direct entry for the user) doesn't depend on a
        recent change, so the token is not stale. Only when EVERY path's newest link is later
        than the newest lastLogon is it stale; when a time needed for that claim is unknown the
        result is Unknown (could-not-check), never a claim.
        Returns State (None / Stale / Unknown), Group, Added, LastLogon and Note.
    #>
    param([object[]]$GrantingRows, [hashtable]$MembershipLinks = @{}, [object]$LastLogon, [string]$UserName)
    $none = [PSCustomObject]@{ State = 'None'; Group = $null; Added = $null; LastLogon = $null; Note = '' }
    $rows = @($GrantingRows | Where-Object { $_ })
    if ($rows.Count -eq 0 -or -not $MembershipLinks) { return $none }
    $links = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if (-not $MembershipLinks.ContainsKey([string]$r.SID)) { return $none }
        $l = $MembershipLinks[[string]$r.SID]
        $links.Add([PSCustomObject]@{
            Group = $(if ($l -and $l.Group) { [string]$l.Group } else { [string]$r.Principal })
            Added = $(if ($l -and $l.Added -is [datetime]) { [datetime]$l.Added } else { $null })
        })
    }
    $logon = if ($LastLogon -is [datetime]) { [datetime]$LastLogon } else { $null }
    if ($null -ne $logon -and @($links | Where-Object { $null -ne $_.Added -and $_.Added -le $logon }).Count -gt 0) { return $none }
    if ($null -eq $logon) {
        return [PSCustomObject]@{ State = 'Unknown'; Group = $null; Added = $null; LastLogon = $null
            Note = "when $UserName was added to the group, compared with their last sign-in: their last sign-in time couldn't be read from every domain controller" }
    }
    $unknown = @($links | Where-Object { $null -eq $_.Added } | ForEach-Object { $_.Group } | Select-Object -Unique)
    if ($unknown.Count -gt 0) {
        return [PSCustomObject]@{ State = 'Unknown'; Group = $null; Added = $null; LastLogon = $logon
            Note = ("when $UserName was added to the group ({0}): the directory's replication data for that membership couldn't be read" -f ($unknown -join ', ')) }
    }
    # Every path is newer than the last sign-in: name the earliest, the strongest evidence.
    $first = @($links.ToArray() | Sort-Object -Property @{ Expression = { $_.Added } })[0]
    return [PSCustomObject]@{
        State = 'Stale'; Group = $first.Group; Added = $first.Added; LastLogon = $logon
        Note = ('added to {0} on {1}, after their last sign-in on {2}: the access they have now was made at that sign-in and does not include the group yet' -f $first.Group, $first.Added.ToString('yyyy-MM-dd'), $logon.ToString('yyyy-MM-dd'))
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

        What to do about it (SQ-013):
          CandidateGroups: the folder-layer Allow principals looked up in AD (Sid, Name,
            ObjectClass, MemberCount, AdminCount, PrivilegedVia, ParentSids, Incomplete). On
            PROBABLY NO the narrowest eligible one becomes the Recommendation
            (Select-FolderAccessNarrowestGroup); a recommendation with a warning puts "Get senior
            approval first" inside the add step. A privileged group itself is never recommended:
            when only such groups would grant it, the step is to escalate (D-017).
          MembershipLinks: granting group SID -> Group, Added (the newest link on the user's path
            to it, $null when unknown). LastLogon: the newest lastLogon across all DCs, or $null.
            On PROBABLY YES, a path added after the last sign-in makes VerdictText "PROBABLY YES
            after <user> signs out and back in" (Get-FolderAccessStaleToken). Verdict and
            ExitCode never change for it.
    #>
    param(
        [string]$UserName, [string]$DisplayName, [string]$Path, [string]$Server,
        [ValidateSet('Normal', 'Admin', 'Dfs')][string]$PathKind = 'Normal',
        [ValidateSet('Read', 'Modify')][string]$Access = 'Read',
        [bool]$ServerIsDomainController = $false,
        [string[]]$UserSids, [hashtable]$GroupPaths = @{},
        [object[]]$FolderAces, [string]$FolderError, [bool]$FolderConditional = $false,
        [object[]]$ShareAces, [ValidateSet('Present', 'Null', 'Empty', 'Unreadable')][string]$ShareDaclState = 'Present', [string]$ShareError,
        [hashtable]$LocalGroupExpansions = @{},
        [object[]]$CandidateGroups = @(), [hashtable]$MembershipLinks = @{}, [object]$LastLogon
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
    elseif ($ShareDaclState -eq 'Unreadable') {
        $shareWhy = "the share's permission list on $Server came back empty or unreadable; check it in Computer Management"
        Add-CouldNot 'share permissions: not read (the permission list came back empty or unreadable)'
    }
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
    $verdictText = $null; $staleToken = $null
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
        $kinds = @($unsupported | ForEach-Object { if ($_.PSObject.Properties['AceKind'] -and $_.AceKind) { $_.AceKind } else { $_.Type } } | Select-Object -Unique) -join ', '
        $reasons.Add("this folder has a permission entry type this tool doesn't evaluate ($kinds); only Effective Access can")
    } elseif ($folderState -eq 'No') {
        $verdict = 'PROBABLY NO'
        $limitedBy = if ($shareState -eq 'No') { 'share and folder permissions' } else { 'folder permissions' }
        $reasons.Add((Get-NoReason $folder 'folder'))
        if ($folder.DenyRow) {
            Add-Step ("Find out why {0} is denied before changing anything: removing a Deny opens the folder to everyone else in {0} as well." -f $folder.DenyRow.Principal)
        } else {
            Add-Step "Ask whoever owns the folder whether $UserName should have access, and through which group."
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
        $stale = Get-FolderAccessStaleToken -GrantingRows $folder.AllowRows -MembershipLinks $MembershipLinks -LastLogon $LastLogon -UserName $UserName
        if ($stale.State -eq 'Stale') {
            $staleToken = [PSCustomObject]@{ Group = $stale.Group; Added = $stale.Added; LastLogon = $stale.LastLogon }
            $verdictText = "PROBABLY YES after $UserName signs out and back in"
            $reasons.Add($stale.Note)
            Add-Step $script:SignOutStep
        } elseif ($stale.State -eq 'Unknown') {
            Add-CouldNot $stale.Note
        }
        Add-Step "If $UserName still gets 'Access denied', check they are using this exact path."
    }

    # The narrowest existing group that would let them in (never a broad or per-user entry).
    $recommendation = $null
    if ($verdict -eq 'PROBABLY NO') {
        $serverLocal = @{}
        foreach ($k in $LocalGroupExpansions.Keys) { $serverLocal[[string]$k] = $true }
        foreach ($ace in @($FolderAces)) { if ($ace -and [bool]$ace.IsServerLocal) { $serverLocal[[string]$ace.Sid] = $true } }
        $shareRead = ($shareState -ne 'NotRead')
        $recommendation = Select-FolderAccessNarrowestGroup -CandidateGroups $CandidateGroups -WalkArgs $walkArgs -FolderAces $FolderAces `
            -ShareAces $ShareAces -ShareDaclState $ShareDaclState -ShareRead $shareRead -UserName $UserName -ServerLocalSids $serverLocal
        if ($recommendation) {
            $members = if ($recommendation.MemberCount -eq 1) { '1 direct member' } else { "$($recommendation.MemberCount) direct members" }
            if ($recommendation.Warning) {
                # The approval is a condition of the action, so it comes first inside the step;
                # the warning that explains it follows as its own step.
                Add-Step ("{0}{1} ({2}). Get senior approval first, then add {3} to {1} in Active Directory if the folder's owner agrees, and have them sign out and back in." -f $script:NarrowestStepPrefix, $recommendation.Name, $members, $UserName)
                Add-Step $recommendation.Warning
            } else {
                Add-Step ("{0}{1} ({2}). If the folder's owner agrees, add {3} to it in Active Directory, then have them sign out and back in." -f $script:NarrowestStepPrefix, $recommendation.Name, $members, $UserName)
            }
        } elseif ($folderState -eq 'No') {
            $privileged = @(Get-FolderAccessPrivilegedGrant -CandidateGroups $CandidateGroups -WalkArgs $walkArgs -FolderAces $FolderAces `
                -ShareAces $ShareAces -ShareDaclState $ShareDaclState -ShareRead $shareRead)
            if ($privileged.Count -gt 0) {
                $them = if ($privileged.Count -eq 1) { 'it' } else { 'any of them' }
                Add-Step ("{0}only {1} would let {2} in, and adding {2} to {3} gives them that group's rights, far beyond this folder. Ask the folder's owner whether a group of its own should be given access instead." -f $script:PrivilegedOnlyStepPrefix, ($privileged -join ', '), $UserName, $them)
            } else {
                Add-Step $script:NoGroupStep
            }
        }
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
        elseif ($ShareDaclState -eq 'Unreadable') { Add-Step "Read the share permissions in Computer Management on $Server (Shared Folders > Shares > Properties > Share Permissions)." }
    }
    if (@($couldNot | Where-Object { $_ -match 'unknown account|from another domain' }).Count -gt 0) {
        Add-Step "Look at the unknown entries in the folder's Properties > Security tab: an entry shown only as a SID is usually a deleted account or one from another domain."
    }
    if (@($couldNot | Where-Object { $_ -match "couldn't read the members of" }).Count -gt 0) {
        Add-Step "Check the members of the local group on $Server (Computer Management > Local Users and Groups), or run it again as an administrator of $Server."
    }
    Add-Step "Confirm in the folder's Properties > Security > Advanced > Effective Access for $UserName."

    $exit = switch ($verdict) { 'PROBABLY YES' { 0 } 'PROBABLY NO' { 1 } default { 4 } }
    if (-not $verdictText) { $verdictText = $verdict }
    return [PSCustomObject]@{
        Verdict = $verdict; VerdictText = $verdictText; LimitedBy = $limitedBy; Reasons = $reasons.ToArray(); CouldNotCheck = $couldNot.ToArray()
        NextSteps = $steps.ToArray(); EvidenceRows = $rows.ToArray(); ExitCode = $exit
        Headline = ('Can {0} {1} {2}?  {3}' -f $who, $doing, $Path, $verdictText)
        Access = $Access; FolderState = $folderState; ShareState = $shareState
        Recommendation = $recommendation; StaleToken = $staleToken
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
    $props = @('DisplayName', 'SamAccountName', 'UserPrincipalName', 'DistinguishedName', 'userAccountControl')
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
        Primary / Nested), NestingDepth, Via (the whole path, e.g. "FIN-Staff -> FIN-All"), Dn
        and ParentDns (its memberOf), which date the membership links (SQ-013).

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
            Dn             = [string]$g.DistinguishedName
            ParentDns      = @($g.MemberOf | Where-Object { $_ } | ForEach-Object { [string]$_ })
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
        Groups = $groups.ToArray(); SamAccountName = [string]$u.SamAccountName; DistinguishedName = [string]$u.DistinguishedName
        MemberOfDns = @($u.memberOf | Where-Object { $_ } | ForEach-Object { [string]$_ })
        PrimaryGroupSid = $(if ($u.primaryGroupID) { "$domainSid-$($u.primaryGroupID)" } else { '' })
        DisplayName = $(if ($u.DisplayName) { [string]$u.DisplayName } else { [string]$u.SamAccountName })
    }
}

function Get-FolderAccessCandidateGroup {
    <#
    .SYNOPSIS
        The folder-layer Allow principals of the user's domain, read from AD as recommendation
        candidates: Sid, Name, ObjectClass, MemberCount, AdminCount, PrivilegedVia, ParentSids,
        Incomplete.
    .DESCRIPTION
        MemberCount is the number of direct `member` values (cheap and deterministic; a
        recursive count is expensive on DCs). PrivilegedVia: the candidate, and every group it is
        nested in (memberOf walked upward, cycle-safe, up to MaxNestingDepth), matched by SID
        against Get-PrivilegedGroupDefinition with Find-PrivilegedGroupBySid -AnyDomain (so a
        forest-root Enterprise Admins matches too), plus the name-only groups (DnsAdmins...).
        Protected Users is left out: "not a privilege". A principal that isn't a group (a user
        account), a distribution group, or one that can't be read is not a candidate.
        ParentSids: the SIDs of every group the walk reached above the candidate.
        https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup

        The privilege check fails closed: Incomplete is $true when the walk could not finish, so
        "not privileged" was never confirmed. That is a parent group that could not be read, or
        the MaxNestingDepth limit reached with parents left unread. A parent in another domain
        of the forest (its DN's DC= parts differ) is read from that domain with -Server <its DNS
        name>; when that fails too, the candidate is Incomplete.
        https://learn.microsoft.com/powershell/module/activedirectory/get-adgroup#-server
    #>
    param([object[]]$FolderAces, [string]$DomainSid, [hashtable]$AdSplat = @{}, [int]$MaxNestingDepth = 10)

    $defs = @(Get-PrivilegedGroupDefinition -DomainSid $DomainSid | Where-Object { $_.Risk -ne 'INFO' })
    $nameOnly = @(Get-NameOnlyPrivilegedGroup | ForEach-Object { $_.Name })
    $cache = @{}
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $pattern = '^' + [regex]::Escape($DomainSid) + '-\d+$'

    foreach ($ace in @($FolderAces)) {
        if ($null -eq $ace -or $ace.Type -ne 'Allow' -or [bool]$ace.InheritOnly -or [bool]$ace.Unresolved) { continue }
        $sid = [string]$ace.Sid
        if ($sid -notmatch $pattern -or -not $seen.Add($sid)) { continue }
        try {
            $g = Get-ADGroup -Identity $sid @AdSplat -Properties member, adminCount, memberOf -ErrorAction Stop
        } catch {
            Write-Verbose "Not a recommendation candidate (${sid}): $($_.Exception.Message)"
            continue
        }
        if ([string]$g.GroupCategory -eq 'Distribution') { continue }

        # Upward walk for "privileged elsewhere".
        $via = New-Object System.Collections.Generic.List[string]
        $parentSids = New-Object System.Collections.Generic.List[string]
        $incomplete = $false
        $homeDomain = Get-DomainDnsFromDn -DistinguishedName ([string]$g.DistinguishedName)
        $visited = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $queue = New-Object System.Collections.Queue
        [void]$visited.Add([string]$g.DistinguishedName)
        $queue.Enqueue(@{ Group = $g; Depth = 0 })
        while ($queue.Count -gt 0) {
            $item = $queue.Dequeue()
            $cur = $item.Group
            $def = Find-PrivilegedGroupBySid -Sid (Get-SidText $cur.SID) -Definitions $defs -AnyDomain
            $hit = if ($def) { [string]$def.Name } elseif ($nameOnly -contains [string]$cur.Name) { [string]$cur.Name } else { $null }
            if ($hit -and -not $via.Contains($hit)) { $via.Add($hit) }
            if ($item.Depth -ge $MaxNestingDepth) {
                if (@(@($cur.MemberOf) | Where-Object { $_ -and -not $visited.Contains([string]$_) }).Count -gt 0) {
                    Write-Verbose "Nesting depth limit ($MaxNestingDepth) reached above '$($g.Name)'; its privilege check is incomplete."
                    $incomplete = $true
                }
                continue
            }
            foreach ($parentDn in @($cur.MemberOf)) {
                if (-not $parentDn -or -not $visited.Add([string]$parentDn)) { continue }
                $key = [string]$parentDn
                if (-not $cache.ContainsKey($key)) {
                    $splat = @{}
                    foreach ($k in $AdSplat.Keys) { $splat[$k] = $AdSplat[$k] }
                    $parentDomain = Get-DomainDnsFromDn -DistinguishedName $key
                    if ($parentDomain -and $homeDomain -and $parentDomain -ne $homeDomain) { $splat['Server'] = $parentDomain }
                    try { $cache[$key] = Get-ADGroup -Identity $key @splat -Properties memberOf -ErrorAction Stop }
                    catch { Write-Verbose "Could not read group '$key': $($_.Exception.Message)"; $cache[$key] = $null }
                }
                if ($cache[$key]) {
                    $parentSids.Add((Get-SidText $cache[$key].SID))
                    $queue.Enqueue(@{ Group = $cache[$key]; Depth = $item.Depth + 1 })
                } else {
                    $incomplete = $true
                }
            }
        }

        $out.Add([PSCustomObject]@{
            Sid = $sid; Name = [string]$g.Name; ObjectClass = 'group'; MemberCount = @($g.member | Where-Object { $_ }).Count
            AdminCount = $(if ($null -ne $g.adminCount) { [int]$g.adminCount } else { 0 }); PrivilegedVia = $via.ToArray()
            ParentSids = $parentSids.ToArray(); Incomplete = $incomplete
        })
    }
    return $out.ToArray()
}

function ConvertFrom-FolderAccessFileTime {
    # AD FILETIME -> local DateTime, or $null: 0 means "never" (not 1601-01-01).
    # https://learn.microsoft.com/windows/win32/adschema/a-lastlogon
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $n = [int64]0
    try { $n = [int64]$Value } catch { return $null }
    if ($n -le 0 -or $n -ge [int64]::MaxValue) { return $null }
    try { return [datetime]::FromFileTime($n) } catch { return $null }
}

function Get-UserNewestLastLogon {
    <#
    .SYNOPSIS
        The user's newest lastLogon across every DC of the domain, or $null when unknown.
    .DESCRIPTION
        lastLogon "is not replicated and is maintained separately on each domain controller ...
        The largest value that is retrieved is the true last logon time" (same per-DC pattern as
        AD-UserQuickCheck). If any DC can't be read the newest value is only a lower bound, which
        could make a false "added after their last sign-in" claim, so the result is $null.
        https://learn.microsoft.com/windows/win32/adschema/a-lastlogon
        https://learn.microsoft.com/powershell/module/activedirectory/get-addomaincontroller
    #>
    param([string]$UserDn, [string]$DomainDns, [string]$Server, [System.Management.Automation.PSCredential]$Credential)
    $ad = Get-AdSplat -Server $(if ($Server) { $Server } else { $DomainDns }) -Credential $Credential
    try {
        $dcs = @(Get-ADDomainController -Filter * @ad -ErrorAction Stop | ForEach-Object { [string]$_.HostName } | Where-Object { $_ })
    } catch {
        Write-Verbose "Could not list the domain controllers: $($_.Exception.Message)"
        return $null
    }
    if ($dcs.Count -eq 0) { return $null }
    $newest = $null
    foreach ($dc in $dcs) {
        try {
            $dcAd = Get-AdSplat -Server $dc -Credential $Credential
            $u = Get-ADUser -Identity $UserDn @dcAd -Properties lastLogon -ErrorAction Stop
        } catch {
            Write-Verbose "${dc}: lastLogon not read - $($_.Exception.Message)"
            return $null
        }
        $t = ConvertFrom-FolderAccessFileTime -Value $u.lastLogon
        if ($null -ne $t -and ($null -eq $newest -or $t -gt $newest)) { $newest = $t }
    }
    return $newest
}

function Get-FolderAccessMembershipLink {
    <#
    .SYNOPSIS
        Since when has the user been in each granting group? Granting group SID -> Group (the
        group holding the deciding link), Added ($null when it can't be dated).
    .DESCRIPTION
        Each link is dated from the replication metadata:
          - user -> group, and group -> parent group: the `member` value's
            FirstOriginatingCreateTime (Get-ADReplicationAttributeMetadata -ShowAllLinkedValues
            returns one row per linked value; the value metadata records when it was created);
          - the primary group: the user's primaryGroupID LastOriginatingChangeTime (primary group
            membership is that attribute, not a `member` value).
        A group reached through a parent is held from the later of "held the child" and "the
        child was added to it". With several routes into a group (a direct membership and a
        nested one, say) the earliest route counts, so an old route is never hidden by a new one.
        Any route that can't be dated makes the group "not dated" rather than risk a false
        "added after their last sign-in".

        A grant through a local group on the file server is dated through the user's domain
        groups inside it. Grants through Everyone, Authenticated Users or a direct entry for the
        user get no link: they don't depend on a recent group change.
        https://learn.microsoft.com/powershell/module/activedirectory/get-adreplicationattributemetadata
        https://learn.microsoft.com/windows/win32/api/ntdsapi/ns-ntdsapi-ds_repl_value_meta_data
        https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
    #>
    param(
        [object[]]$GrantingRows, [object]$SidSet, [hashtable]$LocalGroupExpansions = @{},
        [string]$MetadataServer, [System.Management.Automation.PSCredential]$Credential
    )
    $userDn = [string]$SidSet.DistinguishedName
    $groupsByDn = @{}; $groupsBySid = @{}
    foreach ($g in @($SidSet.Groups)) {
        if ($g.MembershipType -eq 'Token' -or -not $g.Dn) { continue }
        $groupsByDn[[string]$g.Dn] = $g
        $groupsBySid[[string]$g.GroupSid] = $g
    }
    $directDns = @($SidSet.MemberOfDns)
    $meta = @{}
    $memo = @{}
    $inProgress = @{}

    function Get-MetaRows([string]$Dn, [string]$Attribute) {
        $key = "$Dn|$Attribute"
        if (-not $meta.ContainsKey($key)) {
            $m = @{ Object = $Dn; Server = $MetadataServer; Properties = $Attribute; ErrorAction = 'Stop' }
            if ($Credential) { $m['Credential'] = $Credential }
            try {
                $meta[$key] = @(if ($Attribute -eq 'member') { Get-ADReplicationAttributeMetadata @m -ShowAllLinkedValues } else { Get-ADReplicationAttributeMetadata @m })
            } catch {
                Write-Verbose "Replication metadata not read for ${Dn} ($Attribute): $($_.Exception.Message)"
                $meta[$key] = @()
            }
        }
        # One row per pipeline object, so callers can filter the rows directly.
        $meta[$key]
    }
    # A replication time of 1601 (FILETIME 0) means "not recorded".
    function Get-KnownTime($Value) { if ($Value -is [datetime] -and $Value.Year -gt 1601) { return [datetime]$Value } return $null }
    function Get-MemberLinkTime([string]$GroupDn, [string]$ChildDn) {
        $hit = @(Get-MetaRows $GroupDn 'member' | Where-Object { [string]$_.AttributeName -eq 'member' -and [string]$_.AttributeValue -eq $ChildDn })
        if ($hit.Count -eq 0) { return $null }
        return (Get-KnownTime $hit[0].FirstOriginatingCreateTime)
    }

    function Get-HeldSince([string]$Dn) {
        # -> Time (earliest dated route), Group (the group holding that route's newest link),
        #    Unknown (a route couldn't be dated), Partial (a route was skipped as a cycle).
        if ($memo.ContainsKey($Dn)) { return $memo[$Dn] }
        $g = $groupsByDn[$Dn]
        $name = [string]$g.GroupName
        $inProgress[$Dn] = $true
        $routes = New-Object System.Collections.Generic.List[object]
        $partial = $false
        if ($directDns -contains $Dn) {
            $t = Get-MemberLinkTime $Dn $userDn
            $routes.Add([PSCustomObject]@{ Time = $t; Group = $name })
        }
        if ($SidSet.PrimaryGroupSid -and [string]$g.GroupSid -eq [string]$SidSet.PrimaryGroupSid) {
            $hit = @(Get-MetaRows $userDn 'primaryGroupID' | Where-Object { [string]$_.AttributeName -eq 'primaryGroupID' })
            $t = if ($hit.Count -gt 0) { Get-KnownTime $hit[0].LastOriginatingChangeTime } else { $null }
            $routes.Add([PSCustomObject]@{ Time = $t; Group = $name })
        }
        foreach ($child in @($groupsByDn.Values)) {
            if (@($child.ParentDns) -notcontains $Dn) { continue }
            if ($inProgress[[string]$child.Dn]) { $partial = $true; continue }
            $held = Get-HeldSince ([string]$child.Dn)
            if ($held.Partial) { $partial = $true }
            $link = Get-MemberLinkTime $Dn ([string]$child.Dn)
            if ($held.Unknown -or $null -eq $held.Time -or $null -eq $link) {
                $routes.Add([PSCustomObject]@{ Time = $null; Group = $name }); continue
            }
            if ($link -ge $held.Time) { $routes.Add([PSCustomObject]@{ Time = $link; Group = $name }) }
            else { $routes.Add([PSCustomObject]@{ Time = $held.Time; Group = $held.Group }) }
        }
        $inProgress[$Dn] = $false
        $dated = @($routes.ToArray() | Where-Object { $null -ne $_.Time } | Sort-Object -Property @{ Expression = { $_.Time } })
        $res = [PSCustomObject]@{
            Time = $(if ($dated.Count -gt 0) { $dated[0].Time } else { $null })
            Group = $(if ($dated.Count -gt 0) { $dated[0].Group } else { $name })
            Unknown = ($routes.Count -eq 0 -or $dated.Count -lt $routes.Count)
            Partial = $partial
        }
        # A result that skipped a route because of circular nesting is only complete for the
        # group the walk started from, so it is not reused.
        if (-not $partial) { $memo[$Dn] = $res }
        return $res
    }

    $links = @{}
    foreach ($row in @($GrantingRows)) {
        $sid = [string]$row.SID
        if (-not $sid -or $links.ContainsKey($sid)) { continue }
        $starts = @()
        if ($groupsBySid.ContainsKey($sid)) {
            $starts = @($groupsBySid[$sid])
        } elseif ($LocalGroupExpansions.ContainsKey($sid)) {
            # Held through any of the user's SIDs inside the local group: a well-known SID or the
            # user's own SID in it means it doesn't depend on a group change at all.
            $inside = @(@($LocalGroupExpansions[$sid].MemberSids) | Where-Object { $_ -and @($SidSet.Sids) -contains [string]$_ })
            if (@($inside | Where-Object { -not $groupsBySid.ContainsKey([string]$_) -and ([string]$_ -eq $SidSet.UserSid -or $script:WellKnownSidNames.ContainsKey([string]$_)) }).Count -gt 0) { continue }
            $starts = @($inside | Where-Object { $groupsBySid.ContainsKey([string]$_) } | ForEach-Object { $groupsBySid[[string]$_] })
            if ($starts.Count -lt $inside.Count) { $starts += @($null) }   # a token-only SID inside: not dated
        } elseif ($sid -eq $SidSet.UserSid -or $script:WellKnownSidNames.ContainsKey($sid)) {
            continue
        } else {
            # A tokenGroups SID the walk didn't reach: there is no path to date.
            $links[$sid] = [PSCustomObject]@{ Group = [string]$row.Principal; Added = $null }
            continue
        }

        $best = $null; $unknown = ($starts.Count -eq 0)
        foreach ($st in $starts) {
            if ($null -eq $st) { $unknown = $true; continue }
            $held = Get-HeldSince ([string]$st.Dn)
            # Partial: circular nesting hid a route, so the time could be too late. Not dated.
            if ($held.Unknown -or $held.Partial -or $null -eq $held.Time) { $unknown = $true; continue }
            if ($null -eq $best -or $held.Time -lt $best.Time) { $best = $held }
        }
        $links[$sid] = if ($unknown -or $null -eq $best) {
            [PSCustomObject]@{ Group = [string]$row.Principal; Added = $null }
        } else {
            [PSCustomObject]@{ Group = $best.Group; Added = $best.Time }
        }
    }
    return $links
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
        A custom local group (S-1-5-21-<machine>-<RID>) that doesn't exist on the server has no
        members (Readable, Found = $false). A BUILTIN group (S-1-5-32-*) always exists on a
        member server, so "not found" there means the query didn't really answer: it is
        unreadable, never "no members".
        https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers
    #>
    param([Parameter(Mandatory = $true)]$Session, [string]$Server, [string]$Sid, [string]$FallbackName)
    try {
        $g = Get-CimInstance -CimSession $Session -ClassName Win32_Group -Filter "LocalAccount = TRUE AND SID = '$Sid'" -ErrorAction Stop
        $g = @($g)[0]
        if (-not $g) {
            if ($Sid -match '^S-1-5-32-') {
                return [PSCustomObject]@{ Readable = $false; Found = $false; Name = $FallbackName; MemberSids = @(); Error = "$Server didn't return this built-in group" }
            }
            return [PSCustomObject]@{ Readable = $true; Found = $false; Name = $FallbackName; MemberSids = @(); Error = $null }
        }
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

function Get-ServerLocalUser {
    <#
    .SYNOPSIS
        One local user account on the file server, by SID, over the CIM session.
    .DESCRIPTION
        Win32_UserAccount with LocalAccount = TRUE ("the account is defined on the local
        computer") and that SID; querying one instance avoids enumerating the domain's accounts,
        which Learn warns is slow on a large network.
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-useraccount
        Returns Found and Name ("FS01\scanner"), or Found = $false when there is no such account
        or it couldn't be read.
    #>
    param([Parameter(Mandatory = $true)]$Session, [string]$Sid)
    try {
        $u = @(Get-CimInstance -CimSession $Session -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE AND SID = '$Sid'" -ErrorAction Stop)[0]
    } catch {
        Write-Verbose "Win32_UserAccount $Sid on the file server: $($_.Exception.Message)"
        $u = $null
    }
    if (-not $u) { return [PSCustomObject]@{ Found = $false; Name = $null } }
    $name = if ($u.Domain) { "$($u.Domain)\$($u.Name)" } else { [string]$u.Name }
    return [PSCustomObject]@{ Found = $true; Name = $name }
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
          a local user of the file server if Win32_UserAccount does (never matches a domain
          user), otherwise an unknown account (deleted, or from another domain)
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
                if (-not $local.Found) {
                    # A local user account on the server: known, but a domain user's network
                    # logon never carries it, so its "expansion" has no members to match.
                    $lu = Get-ServerLocalUser -Session $c.Session -Sid $sid
                    if ($lu.Found) {
                        $local = [PSCustomObject]@{ Readable = $true; Found = $true; Name = "$($lu.Name) (local account on $($c.Server))"; MemberSids = @(); Error = $null }
                    }
                }
                if ($local.Found) { $c.LocalAccounts[$sid] = $local }
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
        Domain = ''; TicketNote = $null; TicketNoteError = ''
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
    $result.Domain = [string]$domain.DNSRoot

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
    $session = $null; $isDc = $false; $roleKnown = $false; $roleError = ''
    $shareAces = @(); $shareState = 'Present'; $shareError = $null
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
                    if ($null -ne $cs -and $null -ne $cs.DomainRole) {
                        $isDc = ([int]$cs.DomainRole -ge 4); $roleKnown = $true
                    } else { $roleError = 'Win32_ComputerSystem returned no DomainRole' }
                } catch {
                    $roleError = $_.Exception.Message
                    Write-Verbose "Win32_ComputerSystem on $($parsed.Server): $roleError"
                }
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
            Server = $parsed.Server; Cache = @{}; LocalAccounts = @{}
        }
        foreach ($ace in @($folderAces) + @($shareAces)) {
            if ($null -eq $ace -or -not $ace.Sid) { continue }
            Resolve-FolderAccessPrincipal -Ace $ace -Context $ctx
        }
        # Members of every server-local group an entry names. When they can't be read (no
        # session, a DFS path, or the server role unknown for a BUILTIN group) the expansion
        # says so, and the walk decides whether that entry could change the answer (AC13).
        if (-not $isDc) {
            $noSessionWhy = if ($parsed.Kind -eq 'Dfs') { "this is a DFS path, so the server holding the folder isn't known" }
                            else { "couldn't connect to $($parsed.Server)" }
            foreach ($ace in @($folderAces) + @($shareAces)) {
                if ($null -eq $ace -or -not $ace.IsServerLocal -or $ace.InheritOnly -or $expansions.ContainsKey($ace.Sid)) { continue }
                if (@($sidSet.Sids) -contains $ace.Sid) { continue }
                $isBuiltin = ([string]$ace.Sid -match '^S-1-5-32-')
                $lg = if (-not $session) {
                    [PSCustomObject]@{ Readable = $false; Found = $false; Name = $ace.Principal; MemberSids = @(); Error = $noSessionWhy }
                } elseif ($isBuiltin -and -not $roleKnown) {
                    # On a DC the BUILTIN groups are domain groups (already in tokenGroups); on a
                    # member server they are local. Without the role, neither can be assumed.
                    [PSCustomObject]@{ Readable = $false; Found = $false; Name = $ace.Principal; MemberSids = @(); Error = "couldn't tell whether $($parsed.Server) is a domain controller: $roleError" }
                } elseif ($ctx.LocalAccounts.ContainsKey($ace.Sid)) {
                    $ctx.LocalAccounts[$ace.Sid]
                } else {
                    Get-ServerLocalGroup -Session $session -Server $parsed.Server -Sid $ace.Sid -FallbackName $ace.Principal
                }
                $expansions[$ace.Sid] = $lg
            }
        }
    } finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }

    # 6. Verdict.
    $assessArgs = @{
        UserName = $sidSet.SamAccountName; DisplayName = $sidSet.DisplayName; Path = $parsed.Folder
        Server = $parsed.Server; PathKind = $parsed.Kind; Access = $Access; ServerIsDomainController = $isDc
        UserSids = $sidSet.Sids; GroupPaths = $sidSet.GroupPaths
        FolderAces = $folderAces; FolderError = $folderError; FolderConditional = $folderConditional
        ShareAces = $shareAces; ShareDaclState = $shareState; ShareError = $shareError; LocalGroupExpansions = $expansions
    }
    $assessment = Get-FolderAccessAssessment @assessArgs

    # 7. What to do about it, read only when it can matter, then assessed again (pure, cheap):
    #    PROBABLY NO  -> the folder's groups as candidates for the narrowest group;
    #    PROBABLY YES -> when the granting groups were joined, against the newest sign-in.
    if ($assessment.Verdict -eq 'PROBABLY NO') {
        $assessArgs['CandidateGroups'] = @(Get-FolderAccessCandidateGroup -FolderAces $folderAces -DomainSid $sidSet.DomainSid -AdSplat $ad -MaxNestingDepth $MaxNestingDepth)
        $assessment = Get-FolderAccessAssessment @assessArgs
    } elseif ($assessment.Verdict -eq 'PROBABLY YES') {
        $granting = @($assessment.EvidenceRows | Where-Object { $_.Layer -eq 'Folder' -and ($_.Effect -eq 'allows' -or $_.Effect -eq 'allows part of what is needed') })
        $metaServer = if ($Server) { $Server } else { [string]$domain.DNSRoot }
        $assessArgs['MembershipLinks'] = Get-FolderAccessMembershipLink -GrantingRows $granting -SidSet $sidSet -LocalGroupExpansions $expansions -MetadataServer $metaServer -Credential $Credential
        if ($assessArgs['MembershipLinks'].Count -gt 0) {
            $assessArgs['LastLogon'] = Get-UserNewestLastLogon -UserDn $sidSet.DistinguishedName -DomainDns ([string]$domain.DNSRoot) -Server $Server -Credential $Credential
        }
        $assessment = Get-FolderAccessAssessment @assessArgs
    }
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
    foreach ($r in @($a.Reasons)) { Write-Status $r $level }
    if (@($a.CouldNotCheck).Count -gt 0) {
        Write-Host ''
        Write-Host "Couldn't check:" -ForegroundColor White
        foreach ($n in @($a.CouldNotCheck)) { Write-Status $n 'WARN' }
    }
    Write-Host ''
    Write-Host 'Next steps:' -ForegroundColor White
    $i = 0
    foreach ($s in @($a.NextSteps)) { $i++; Write-Host ("  {0}. {1}" -f $i, $s) -ForegroundColor Gray }

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
    Write-Status "This only reads permissions; it changes nothing. $script:NotCheckedFooter" 'INFO'
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
    [void]$sb.AppendLine("</table><p class=`"INFO`">This only reads permissions; it changes nothing. $(Enc $script:NotCheckedFooter) Effective Access is the final word.</p></body></html>")
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

# =============================================================================
# Ticket note (CaseKit.ps1)
# =============================================================================

function ConvertTo-FolderAccessTicketNote {
    <#
    .SYNOPSIS
        Maps a folder-access result to a ticket note. The gate decisions for this tool live here.
    .DESCRIPTION
        The reasons go under Checked (PROBLEM for PROBABLY NO, WARNING for CAN'T TELL and for
        "added after their last sign-in", INFO for PROBABLY YES), every Couldn't-check line
        under Could not check, and the next steps (ending with Effective Access) under Next step.

        Ruled out only holds a layer that was really read and decided: a CAN'T TELL rules
        nothing out, because whatever couldn't be read may be the cause, and a layer that was not
        read (an unreadable ACL or share, an administrative share, a DFS path) never appears there.

        The headline says "the folder". The path is in the scope line only with -FullDetail;
        without it (paste-safe, D-009) the scope line leaves the path out entirely rather than
        relying on the kit's filter to find where a folder name ends. Any other path (an error
        message) is still removed by the kit's paste-safe filter. -Credential only contributes
        its user name.
    #>
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [string[]]$EvidencePaths = @(),
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$FullDetail
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next = New-Object System.Collections.Generic.List[string]
    $id = [string]$Result.Identity
    $domain = [string]$Result.Domain

    if ($Result.Status -eq 'Ok') {
        $a = $Result.Assessment; $u = $Result.User
        $who = if ($u.DisplayName) { [string]$u.DisplayName } else { [string]$u.SamAccountName }
        $doing = if ($a.Access -eq 'Modify') { 'change files in' } else { 'open' }
        $what = if ($a.Access -eq 'Modify') { 'change files in it' } else { 'open and list it' }
        $headline = 'Can {0} {1} the folder?  {2}' -f $who, $doing, $a.VerdictText
        $folderText = if ($FullDetail) { '"{0}"' -f [string]$Result.PathInfo.Folder } else { 'the folder' }
        $scopeLine = 'Share and folder permissions of {0} for {1}, checked for: {2}.' -f $folderText, $u.SamAccountName, $what

        $kind = switch ($a.Verdict) { 'PROBABLY YES' { 'Info' } 'PROBABLY NO' { 'Problem' } default { 'Warning' } }
        if ($a.LimitedBy) { $items.Add((New-TicketNoteItem -Kind $kind -Text "Limited by: $($a.LimitedBy).")) }
        foreach ($r in @($a.Reasons)) {
            $k = if ($a.StaleToken -and $r -match 'after their last sign-in') { 'Warning' } else { $kind }
            $items.Add((New-TicketNoteItem -Kind $k -Text $r))
        }
        if ($a.Recommendation -and $a.Recommendation.Warning) { $items.Add((New-TicketNoteItem -Kind Warning -Text $a.Recommendation.Warning)) }
        foreach ($n in @($a.CouldNotCheck)) { $items.Add((New-TicketNoteItem -Kind NotChecked -Text $n)) }

        if ($a.Verdict -eq 'PROBABLY YES' -or $a.Verdict -eq 'PROBABLY NO') {
            $sam = [string]$u.SamAccountName
            if ($a.ShareState -eq 'Yes' -and $Result.PathInfo.Kind -eq 'Normal') {
                $items.Add((New-TicketNoteItem -Kind Clear -Text "Share permissions on $($Result.PathInfo.Server): they let $sam in." -CouldLook $true))
            }
            if ($a.FolderState -eq 'Yes') {
                $items.Add((New-TicketNoteItem -Kind Clear -Text "Folder permissions: they let $sam $what." -CouldLook $true))
            }
            $applyingDeny = @($a.EvidenceRows | Where-Object { $_.Layer -eq 'Folder' -and $_.Type -eq 'Deny' -and $_.Effect -eq 'applies' })
            if (($a.FolderState -eq 'Yes' -or $a.FolderState -eq 'No') -and $applyingDeny.Count -eq 0) {
                $items.Add((New-TicketNoteItem -Kind Clear -Text "Deny entries: none in the folder permissions blocks $sam." -CouldLook $true))
            }
        }
        foreach ($s in @($a.NextSteps)) { $next.Add($s) }
    } else {
        $notRun = 'The share and folder permissions were not read.'
        switch ($Result.Status) {
            'BadInput' {
                $headline = 'Folder access check did not run - the path is not a network path'
                $next.Add($script:BadPathMessage)
            }
            'NotFound' {
                $headline = "Folder access check did not run - no user matched '$id'"
                $next.Add('Check the spelling, or try their sign-in name (for example jdoe or jdoe@contoso.com), then run the check again.')
            }
            'Ambiguous' {
                $cands = @($Result.Candidates)
                $headline = "Folder access check did not run - '$id' matches $($cands.Count) people"
                # Enough to recognise the right person; not a directory dump in the ticket.
                foreach ($c in @($cands | Select-Object -First 5)) {
                    $items.Add((New-TicketNoteItem -Kind Info -Text ('Matches {0} ({1}).' -f $c.DisplayName, $c.SamAccountName)))
                }
                if ($cands.Count -gt 5) { $items.Add((New-TicketNoteItem -Kind Info -Text "...and $($cands.Count - 5) more (refine the search).")) }
                if ($cands.Count -gt 0) { $domain = Get-DomainDnsFromDn -DistinguishedName ([string]$cands[0].DistinguishedName) }
                $next.Add('Run it again with the exact sign-in name of the right person.')
            }
            default {
                $headline = "Folder access check for '$id' did not run - could not read Active Directory"
                if ($Result.Message) { $items.Add((New-TicketNoteItem -Kind Problem -Text $Result.Message)) }
                $next.Add('Check that this PC can reach a domain controller (and that -Server / -Credential are right), then run the check again.')
            }
        }
        $scopeLine = "Looked up '$id' in Active Directory."
        $items.Add((New-TicketNoteItem -Kind NotChecked -Text $notRun))
    }

    if (-not $domain) { $domain = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN.ToLower() } else { 'not known' } }
    $stampArgs = @{ ScopeLabel = 'Domain'; Scope = $domain }
    if ($Result.Now -is [datetime]) { $stampArgs['Now'] = $Result.Now }
    if ($Credential) { $stampArgs['RunAs'] = $Credential.UserName }
    $stamp = New-TicketNoteStamp @stampArgs

    return New-TicketNote -Tool 'FolderAccess-Check' -Headline $headline -ScopeLine $scopeLine -Items $items.ToArray() `
        -NextSteps $next.ToArray() -Stamp $stamp -EvidencePaths $EvidencePaths
}

# The ticket-note kit ships beside this script (a copy of TicketNote\CaseKit.ps1). Without it
# the check still runs; only the note is skipped.
$kit = Join-Path $PSScriptRoot 'CaseKit.ps1'
if (Test-Path -LiteralPath $kit) { . $kit } else { $script:CaseKitMissing = $true }

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

# A result for the cases where the check cannot start (-PassThru callers get it instead of an exit code).
function New-FolderAccessStartFailure([string]$Status, [int]$ExitCode, [string]$Message) {
    [PSCustomObject]@{
        Status = $Status; ExitCode = $ExitCode; Identity = $Identity; Path = $Path; Access = $Access; Message = $Message
        Candidates = @(); MatchedBy = ''; User = $null; Groups = @(); Assessment = $null; PathInfo = $null; Protocol = ''
        Files = $null; ReportError = ''; Now = (Get-Date); Domain = ''; TicketNote = $null; TicketNoteError = ''
    }
}

if ($TicketNumber -and $script:CaseKitMissing) {
    if (-not $Quiet) { Write-Status "CaseKit.ps1 is missing from this folder, so -TicketNumber $TicketNumber was ignored: the reports go to -OutputPath (if given) and there is no ticket note this time." 'WARN' }
    $TicketNumber = ''
    $script:CaseKitWarned = $true
}
if ($TicketNumber -and -not (Test-TicketNumber -TicketNumber $TicketNumber)) {
    $msg = "'$TicketNumber' is not a usable ticket number. Use letters, digits, - or _ (up to 32 characters, starting with a letter or digit), for example 482113."
    if (-not $Quiet) { Write-Status $msg 'FAIL' }
    if ($PassThru) { return (New-FolderAccessStartFailure 'Error' 3 $msg) }
    exit 3
}

if (-not (Split-FolderAccessPath -Path $Path).Valid) {
    if (-not $Quiet) { Write-Status $script:BadPathMessage 'FAIL' }
    if ($PassThru) { return (New-FolderAccessStartFailure 'BadInput' 2 $script:BadPathMessage) }
    exit 2
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    $msg = "The ActiveDirectory PowerShell module is not available: $($_.Exception.Message)"
    if (-not $Quiet) {
        Write-Status $msg 'FAIL'
        Write-Status 'Install the RSAT Active Directory tools, or run this on an admin server that has them.' 'INFO'
    }
    if ($PassThru) { return (New-FolderAccessStartFailure 'Error' 3 $msg) }
    exit 3
}

# Where the files go: with -TicketNumber, <OutputPath or the default root>\Ticket_<n> (reports
# and note together, so the note's evidence names sit beside it); with only -OutputPath, that
# folder; with neither, no files: the note goes to the clipboard, or the console (D-012, D-013).
$folder = $OutputPath
if ($TicketNumber) {
    $root = if ($OutputPath) { $OutputPath } else { Get-TicketNoteDefaultRoot }
    try {
        $folder = Resolve-TicketFolder -TicketNumber $TicketNumber -Root $root
    } catch {
        if (-not $Quiet) { Write-Status "Could not create the ticket folder under ${root}: $($_.Exception.Message)" 'WARN' }
    }
}

$result = Invoke-FolderAccessCheck -Identity $Identity -Path $Path -Access $Access -Server $Server -Credential $Credential `
    -OutputPath $folder -MaxNestingDepth $MaxNestingDepth
if (-not $Quiet) { Write-FolderAccessConsole -Result $result }

$evidence = @()
if ($result.Files) { $evidence = @($result.Files.Html, $result.Files.Csv) }

if ($script:CaseKitMissing) {
    if (-not $Quiet -and -not $script:CaseKitWarned) { Write-Status 'CaseKit.ps1 is missing from this folder - no ticket note this time.' 'WARN' }
} else {
    # The note is extra: a failure while building or saving it never changes the answer or the
    # exit code. The check's own result above stands. The note goes on the result as soon as it
    # is built, so a failed save still leaves it there for a -PassThru caller.
    try {
        $result.TicketNote = ConvertTo-FolderAccessTicketNote -Result $result -EvidencePaths $evidence -Credential $Credential -FullDetail:$FullDetail
    } catch {
        $result.TicketNoteError = "Could not make the ticket note: $($_.Exception.Message)"
        if (-not $Quiet) { Write-Status "$($result.TicketNoteError). The check above is still valid." 'WARN' }
    }
    if ($result.TicketNote) {
        if ($Quiet) {
            # Another script is the caller: no console and no clipboard. The note is still saved
            # when a folder is in play; a save that fails is recorded on the result.
            if ($folder) {
                try { $null = Save-TicketNote -Note $result.TicketNote -Folder $folder -PasteSafe:(-not $FullDetail) }
                catch { $result.TicketNoteError = "Could not save the ticket note in ${folder}: $($_.Exception.Message)" }
            }
        } else {
            Write-Host ''
            try { $null = Publish-TicketNote -Note $result.TicketNote -Folder $folder -PasteSafe:(-not $FullDetail) -NoClipboard:$NoClipboard }
            catch {
                $result.TicketNoteError = "Could not save or copy the ticket note: $($_.Exception.Message)"
                Write-Status "$($result.TicketNoteError). The check above is still valid." 'WARN'
            }
        }
    }
}

if ($PassThru) { return $result }
exit $result.ExitCode
