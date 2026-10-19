#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds (or removes) a small, self-contained test lab on a TEST domain controller for
    AD-UserQuickCheck, FolderAccess-Check, FolderPermissionManager and the ticket note.

.DESCRIPTION
    Creates everything under one OU, one folder and two shares, all prefixed so nothing else is
    touched:

      AD (OU "ToolTestLab" at the domain root)
        Groups  TL-Finance-Staff  (member of TL-Finance-All: nesting test)
                TL-Finance-All
                TL-Deny            (gets a Deny on one folder)
                TL-Primary         (used as a user's primary group)
        Users   tl.jdoe       normal, enabled; in TL-Finance-Staff (nested access)
                tl.denied     in TL-Finance-Staff AND TL-Deny (Allow overridden by Deny)
                tl.primary    primary group TL-Primary, memberOf empty of it (primary-group bug)
                tl.noaccess   enabled, in no TL group
                tl.disabled   disabled account
                tl.expired    account expired yesterday
                tl.mustchange must change password at next logon
                tl.locked     enabled; lock it yourself (see .NOTES) to test lockout

      Folders (on this machine, under -RootPath, default C:\ToolTestLab)
        Finance              TL-Finance-All Modify (inherits down)
        Finance\Budgets      inherits from Finance
        Denied               TL-Finance-All Modify + Deny TL-Deny Modify
        PrimaryOnly          TL-Primary Read (only reachable through the primary group)
        BuiltinOnly          inheritance off; BUILTIN\Users Read + Administrators/SYSTEM Full
        Locked               inheritance off; only SYSTEM + tl.jdoe (tests take ownership)
        HR [old]             brackets in the name (literal-path handling)
        FPMTest\A\B          scratch tree for FolderPermissionManager add/remove/undo

      Shares
        ToolTestLab          -> RootPath; share: Authenticated Users Change, Administrators Full
        ToolTestLabRead      -> RootPath; share: Authenticated Users Read (share layer limits Modify)

    Passwords are random, printed once to the console and never written to disk.

.PARAMETER RootPath
    Local folder that holds the test folders. Default C:\ToolTestLab. Must not exist yet unless
    it was created by this script (it carries a marker file).

.PARAMETER Remove
    Tear the lab down: removes the two shares, the RootPath folder (only if it carries the marker
    file) and the ToolTestLab OU with everything in it.

.PARAMETER Force
    Skip the confirmation prompt.

.EXAMPLE
    .\New-ToolTestLab.ps1 -WhatIf
    Shows everything it would create, changes nothing.

.EXAMPLE
    .\New-ToolTestLab.ps1
    Builds the lab after confirming the domain name.

.EXAMPLE
    .\New-ToolTestLab.ps1 -Remove -Force
    Removes the lab.

.NOTES
    Run on a TEST domain controller only (or a member server with RSAT; the folders and shares are
    created on the machine you run it on). It refuses to run on a domain that has no "test"/"lab"
    in its DNS name unless you pass -Force.

    To test lockout: sign in as tl.locked with a wrong password more times than the domain's
    lockout threshold (runas /user:<DOMAIN>\tl.locked cmd), then run AD-UserQuickCheck.

    REFERENCES
      New-ADUser:              https://learn.microsoft.com/powershell/module/activedirectory/new-aduser
      New-ADGroup:             https://learn.microsoft.com/powershell/module/activedirectory/new-adgroup
      New-ADOrganizationalUnit https://learn.microsoft.com/powershell/module/activedirectory/new-adorganizationalunit
      Remove-ADOrganizationalUnit (-Recursive): https://learn.microsoft.com/powershell/module/activedirectory/remove-adorganizationalunit
      primaryGroupID:          https://learn.microsoft.com/windows/win32/adschema/a-primarygroupid
      primaryGroupToken:       https://learn.microsoft.com/windows/win32/adschema/a-primarygrouptoken
      New-SmbShare:            https://learn.microsoft.com/powershell/module/smbshare/new-smbshare
      FileSystemAccessRule:    https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemaccessrule
      SetAccessRuleProtection: https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()][string]$RootPath = 'C:\ToolTestLab',
    [switch]$Remove,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$OuName      = 'ToolTestLab'
$ShareChange = 'ToolTestLab'
$ShareRead   = 'ToolTestLabRead'
$MarkerFile  = '.tooltestlab'

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function New-LabPassword {
    # 20 chars from a mixed set; meets default domain complexity.
    $sets = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+=?@'
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 20
    $rng.GetBytes($bytes)
    $chars = for ($i = 0; $i -lt 20; $i++) { $set = $sets[$i % 4]; $set[$bytes[$i] % $set.Length] }
    -join $chars
}

function Set-LabAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Rules,   # @{ Identity; Rights; Type }
        [switch]$Protect                          # break inheritance, drop inherited entries
    )
    $acl = Get-Acl -LiteralPath $Path
    if ($Protect) { $acl.SetAccessRuleProtection($true, $false) }
    foreach ($r in $Rules) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $r.Identity, $r.Rights, 'ContainerInherit, ObjectInherit', 'None', $r.Type)
        $acl.AddAccessRule($rule)
    }
    if ($PSCmdlet.ShouldProcess($Path, 'Set test permissions')) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

# --- Preconditions -------------------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status "The ActiveDirectory module is not available here: $($_.Exception.Message)" FAIL
    exit 1
}
$domain  = Get-ADDomain
$ouPath  = "OU=$OuName,$($domain.DistinguishedName)"
$netbios = $domain.NetBIOSName

if ($domain.DNSRoot -notmatch '(?i)test|lab' -and -not $Force) {
    Write-Status "Domain '$($domain.DNSRoot)' does not look like a test/lab domain. Re-run with -Force if you are sure." FAIL
    exit 1
}

$action = if ($Remove) { 'REMOVE the test lab from' } else { 'build a test lab in' }
Write-Status "About to $action domain $($domain.DNSRoot) (OU $ouPath), folder $RootPath, shares $ShareChange / $ShareRead." WARN
if (-not $Force -and -not $WhatIfPreference) {
    $answer = Read-Host 'Continue? (y/N)'
    if ($answer -notmatch '^(?i)y') { Write-Status 'Nothing was changed.' INFO; exit 0 }
}

# --- Remove --------------------------------------------------------------------------------
if ($Remove) {
    foreach ($s in $ShareChange, $ShareRead) {
        if (Get-SmbShare -Name $s -ErrorAction SilentlyContinue) {
            if ($PSCmdlet.ShouldProcess($s, 'Remove SMB share')) { Remove-SmbShare -Name $s -Force }
            Write-Status "Share $s removed." PASS
        }
    }
    if (Test-Path -LiteralPath $RootPath) {
        if (Test-Path -LiteralPath (Join-Path $RootPath $MarkerFile)) {
            if ($PSCmdlet.ShouldProcess($RootPath, 'Delete test folder tree')) {
                # Take ownership first so the Locked folder can be deleted.
                & takeown.exe /F $RootPath /R /A /D Y | Out-Null
                & icacls.exe $RootPath /reset /T /C /Q | Out-Null
                Remove-Item -LiteralPath $RootPath -Recurse -Force
            }
            Write-Status "Folder $RootPath removed." PASS
        } else {
            Write-Status "$RootPath has no $MarkerFile marker, so it was not created by this script. Left alone." WARN
        }
    }
    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $domain.DistinguishedName -SearchScope OneLevel
    if ($ou) {
        if ($PSCmdlet.ShouldProcess($ou.DistinguishedName, 'Remove OU and everything in it')) {
            Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false
            Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
        }
        Write-Status "OU $($ou.DistinguishedName) removed (users and groups with it)." PASS
    }
    Write-Status 'Test lab removed.' PASS
    exit 0
}

# --- Build: refuse to reuse things we didn't create ----------------------------------------
if ((Test-Path -LiteralPath $RootPath) -and -not (Test-Path -LiteralPath (Join-Path $RootPath $MarkerFile))) {
    Write-Status "$RootPath already exists and was not created by this script. Choose another -RootPath." FAIL
    exit 1
}

# --- AD: OU, groups, users -----------------------------------------------------------------
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $domain.DistinguishedName -SearchScope OneLevel)) {
    if ($PSCmdlet.ShouldProcess($ouPath, 'Create OU')) {
        New-ADOrganizationalUnit -Name $OuName -Path $domain.DistinguishedName -ProtectedFromAccidentalDeletion $true
    }
    Write-Status "OU $ouPath created." PASS
}

foreach ($g in 'TL-Finance-Staff', 'TL-Finance-All', 'TL-Deny', 'TL-Primary') {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$g'")) {
        if ($PSCmdlet.ShouldProcess($g, 'Create security group')) {
            New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -GroupCategory Security -Path $ouPath
        }
        Write-Status "Group $g created." PASS
    }
}
if (-not $WhatIfPreference) {
    Add-ADGroupMember -Identity 'TL-Finance-All' -Members 'TL-Finance-Staff'
}

$users = @(
    @{ Sam = 'tl.jdoe';       Given = 'Jane';   Surname = 'Doe';      Groups = @('TL-Finance-Staff') }
    @{ Sam = 'tl.denied';     Given = 'Dana';   Surname = 'Denied';   Groups = @('TL-Finance-Staff', 'TL-Deny') }
    @{ Sam = 'tl.primary';    Given = 'Pat';    Surname = 'Primary';  Groups = @('TL-Primary'); Primary = 'TL-Primary' }
    @{ Sam = 'tl.noaccess';   Given = 'Nora';   Surname = 'Noaccess'; Groups = @() }
    @{ Sam = 'tl.disabled';   Given = 'Dave';   Surname = 'Disabled'; Groups = @(); Disabled = $true }
    @{ Sam = 'tl.expired';    Given = 'Eve';    Surname = 'Expired';  Groups = @(); Expires = (Get-Date).AddDays(-1) }
    @{ Sam = 'tl.mustchange'; Given = 'Max';    Surname = 'Change';   Groups = @(); MustChange = $true }
    @{ Sam = 'tl.locked';     Given = 'Lou';    Surname = 'Locked';   Groups = @() }
)

$created = @()
foreach ($u in $users) {
    if (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'") {
        Write-Status "User $($u.Sam) already exists, left as is." INFO
        continue
    }
    $pw = New-LabPassword
    $params = @{
        Name                  = "$($u.Given) $($u.Surname) (test)"
        SamAccountName        = $u.Sam
        UserPrincipalName     = "$($u.Sam)@$($domain.DNSRoot)"
        GivenName             = $u.Given
        Surname               = $u.Surname
        DisplayName           = "$($u.Given) $($u.Surname)"
        Path                  = $ouPath
        AccountPassword       = (ConvertTo-SecureString $pw -AsPlainText -Force)
        Enabled               = -not $u.Disabled
        ChangePasswordAtLogon = [bool]$u.MustChange
    }
    if ($u.Expires) { $params.AccountExpirationDate = $u.Expires }
    if ($PSCmdlet.ShouldProcess($u.Sam, 'Create user')) {
        New-ADUser @params
        foreach ($g in $u.Groups) { Add-ADGroupMember -Identity $g -Members $u.Sam }
        if ($u.Primary) {
            # primaryGroupID must be the RID of a group the user is already a member of; after
            # the switch the group no longer appears in the user's memberOf, and Domain Users
            # (the old primary group) no longer applies to the user at all.
            $token = (Get-ADGroup -Identity $u.Primary -Properties primaryGroupToken).primaryGroupToken
            Set-ADUser -Identity $u.Sam -Replace @{ primaryGroupID = $token }
        }
    }
    $created += [PSCustomObject]@{ User = "$netbios\$($u.Sam)"; Password = $pw }
    Write-Status "User $($u.Sam) created." PASS
}

# --- Folders and permissions ---------------------------------------------------------------
$folders = 'Finance', 'Finance\Budgets', 'Denied', 'PrimaryOnly', 'BuiltinOnly', 'Locked', 'HR [old]', 'FPMTest\A\B'
foreach ($f in @('') + $folders) {
    $p = if ($f) { Join-Path $RootPath $f } else { $RootPath }
    if (-not (Test-Path -LiteralPath $p)) {
        if ($PSCmdlet.ShouldProcess($p, 'Create folder')) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}
if (-not $WhatIfPreference) {
    Set-Content -LiteralPath (Join-Path $RootPath $MarkerFile) -Value "Created by New-ToolTestLab.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Set-Content -LiteralPath (Join-Path $RootPath 'Finance\Budgets\budget.txt') -Value 'test file'
    Set-Content -LiteralPath (Join-Path $RootPath 'HR [old]\readme.txt') -Value 'test file'

    $all  = "$netbios\TL-Finance-All"
    Set-LabAcl -Path (Join-Path $RootPath 'Finance') -Rules @(@{ Identity = $all; Rights = 'Modify'; Type = 'Allow' })
    Set-LabAcl -Path (Join-Path $RootPath 'Denied') -Rules @(
        @{ Identity = $all; Rights = 'Modify'; Type = 'Allow' }
        @{ Identity = "$netbios\TL-Deny"; Rights = 'Modify'; Type = 'Deny' })
    Set-LabAcl -Path (Join-Path $RootPath 'PrimaryOnly') -Rules @(@{ Identity = "$netbios\TL-Primary"; Rights = 'ReadAndExecute'; Type = 'Allow' })
    Set-LabAcl -Path (Join-Path $RootPath 'BuiltinOnly') -Protect -Rules @(
        @{ Identity = 'BUILTIN\Users';          Rights = 'ReadAndExecute'; Type = 'Allow' }
        @{ Identity = 'BUILTIN\Administrators'; Rights = 'FullControl';    Type = 'Allow' }
        @{ Identity = 'NT AUTHORITY\SYSTEM';    Rights = 'FullControl';    Type = 'Allow' })
    Set-LabAcl -Path (Join-Path $RootPath 'HR [old]') -Rules @(@{ Identity = $all; Rights = 'ReadAndExecute'; Type = 'Allow' })
    Set-LabAcl -Path (Join-Path $RootPath 'FPMTest') -Rules @(@{ Identity = "$netbios\TL-Finance-Staff"; Rights = 'ReadAndExecute'; Type = 'Allow' })
    # Locked last: Administrators lose access, so set the owner to tl.jdoe too.
    $locked = Join-Path $RootPath 'Locked'
    Set-Content -LiteralPath (Join-Path $locked 'secret.txt') -Value 'test file'
    Set-LabAcl -Path $locked -Protect -Rules @(
        @{ Identity = 'NT AUTHORITY\SYSTEM'; Rights = 'FullControl'; Type = 'Allow' }
        @{ Identity = "$netbios\tl.jdoe";    Rights = 'FullControl'; Type = 'Allow' })
    $acl = Get-Acl -LiteralPath $locked
    $acl.SetOwner((New-Object System.Security.Principal.NTAccount("$netbios\tl.jdoe")))
    Set-Acl -LiteralPath $locked -AclObject $acl
    Write-Status "Folders and permissions set under $RootPath." PASS
}

# --- Shares --------------------------------------------------------------------------------
if (-not (Get-SmbShare -Name $ShareChange -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($ShareChange, 'Create SMB share')) {
        New-SmbShare -Name $ShareChange -Path $RootPath -ChangeAccess 'Authenticated Users' -FullAccess 'Administrators' | Out-Null
    }
    Write-Status "Share \\$env:COMPUTERNAME\$ShareChange created." PASS
}
if (-not (Get-SmbShare -Name $ShareRead -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($ShareRead, 'Create SMB share')) {
        New-SmbShare -Name $ShareRead -Path $RootPath -ReadAccess 'Authenticated Users' -FullAccess 'Administrators' | Out-Null
    }
    Write-Status "Share \\$env:COMPUTERNAME\$ShareRead created." PASS
}

# --- Summary -------------------------------------------------------------------------------
if ($created) {
    Write-Status 'Passwords for the new users (shown once, not saved):' WARN
    $created | Format-Table -AutoSize | Out-Host
}
$s = "\\$env:COMPUTERNAME\$ShareChange"
Write-Host @"

What to try (expected result in brackets):
  AD-UserQuickCheck  tl.jdoe [YES]  tl.disabled [NO]  tl.expired [NO]  tl.mustchange [NO, must change]
                     tl.locked [NO after you lock it]  tl.primary [YES; Domain Users absent is fine]
  FolderAccess-Check tl.jdoe     $s\Finance\Budgets        [PROBABLY YES via TL-Finance-Staff -> TL-Finance-All]
                     tl.denied   $s\Denied                 [PROBABLY NO, Deny TL-Deny]
                     tl.primary  $s\PrimaryOnly            [PROBABLY YES via TL-Primary (primary group)]
                     tl.noaccess $s\Finance                [PROBABLY NO]
                     tl.noaccess $s\BuiltinOnly            [PROBABLY YES via BUILTIN\Users; CAN'T TELL if the server can't be read]
                     tl.jdoe     \\$env:COMPUTERNAME\$ShareRead\Finance -Access Modify [PROBABLY NO, limited by share]
                     tl.jdoe     $s\HR [old]               [PROBABLY YES; brackets handled]
  FolderPermissionManager  open $RootPath\FPMTest\A: add/remove a permission, take ownership (this folder only),
                     check Logs\Backups and Logs\Changes_<date>.csv, then undo one from the README.
                     $RootPath\Locked: take ownership (this folder only) -> backup says 'Could not read'.
  Ticket note        add -TicketNumber T1 -OutputPath C:\Temp to the runs above, then
                     .\TicketNote\Join-TicketNotes.ps1 -TicketNumber T1 -OutputPath C:\Temp

Tear down later with: .\TestLab-Setup\New-ToolTestLab.ps1 -Remove
"@
