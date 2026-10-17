<#
    Tests for Get-FolderAccessCheck.ps1 (SQ-004: access evidence and hedged verdict, AC1-AC27).
    Pester 5, run under pwsh:  Invoke-Pester .\FolderAccess-Check\Tests

    Nothing here touches a real domain, file server, share or ACL:
      - ActiveDirectory is replaced by Tests\FakeAD (synthetic contoso.com, see its header).
      - Every other AD / SMB / DNS / DFS cmdlet the tool must NOT use is a file-level stub that
        throws, so a wrong call fails the test instead of reaching a real system.
      - CIM (share security, Win32_ComputerSystem, Win32_Group) and Get-Acl are mocked from the
        $script:World table; ACLs are built from synthetic SDDL strings so ACE order,
        inheritance and conditional ACEs are exact.
    Most ACs drive the pure Get-FolderAccessAssessment with fixtures; AC1-AC4, AC14-AC16,
    AC22-AC24 and AC27 run Invoke-FolderAccessCheck end to end against the fakes.

    Pinned shapes (the implementer must match these):
      Get-FolderAccessAssessment -UserName -DisplayName -Path -Server -PathKind -Access
          -ServerIsDomainController -UserSids -GroupPaths -FolderAces -FolderError
          -FolderConditional -ShareAces -ShareDaclState -ShareError -LocalGroupExpansions
        returns Verdict, LimitedBy, Reasons, CouldNotCheck, NextSteps, EvidenceRows, ExitCode,
        Headline.
      ACE objects (folder and share): Sid, Principal, Type (Allow|Deny), Mask (int),
        Inherited, InheritOnly, Unresolved, IsServerLocal.
      Evidence row: Layer, Order, Principal, SID, Type, Inherited, AppliesTo, Rights,
        MatchesUser, Via, Effect.
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Get-FolderAccessCheck.ps1'
    $script:FakeRoot = Join-Path $PSScriptRoot 'FakeAD'
    Import-Module (Join-Path $script:FakeRoot 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global

    # --- Throwing stubs: any AD / SMB / DNS / DFS cmdlet the tool must not call -------------
    # (and the write cmdlets AC22 forbids). Defining them here means a stray call can never
    # fall through to the real module and the real domain.
    $script:GlobalStubs = @('Get-ADPrincipalGroupMembership', 'Get-ADGroupMember', 'Get-ADObject',
        'Get-ADReplicationAttributeMetadata', 'Get-SmbShareAccess', 'Get-SmbShare',
        'Resolve-DnsName', 'Get-DfsnRoot', 'Get-DfsnFolderTarget',
        'Add-ADGroupMember', 'Remove-ADGroupMember', 'Set-ADUser', 'Set-ADGroup')
    foreach ($name in $script:GlobalStubs) {
        Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create("throw 'Unexpected call to ${name}: the tool must not use it (or must never reach a real system).'"))
    }

    . $script:ScriptPath -LoadFunctionsOnly

    # --- Synthetic identifiers -------------------------------------------------------------
    $script:Dom = 'S-1-5-21-1111111111-2222222222-3333333333'
    $script:Sid = @{
        Jdoe = "$($script:Dom)-1104"; DomUsers = "$($script:Dom)-513"; FinStaff = "$($script:Dom)-1105"
        FinAll = "$($script:Dom)-1106"; FinMgr = "$($script:Dom)-1107"; FinContr = "$($script:Dom)-1108"
        Unknown = "$($script:Dom)-9999"; Everyone = 'S-1-1-0'; AuthUsers = 'S-1-5-11'
        BuiltinUsers = 'S-1-5-32-545'; CreatorOwner = 'S-1-3-0'; BuiltinAdmins = 'S-1-5-32-544'
        Local = 'S-1-5-21-5555555555-6666666666-7777777777-1001'
    }
    $script:WellKnown = @('S-1-1-0', 'S-1-5-11', 'S-1-5-2', 'S-1-5-15')
    # FileSystemRights bit masks: the request is ReadData|ReadEA|ReadAttributes|ReadPermissions|Synchronize
    $script:Mask = @{ Read = 0x1200A9; Change = 0x1301BF; Full = 0x1F01FF; Traverse = 0x100020 }
    $script:Unc = '\\FS01\Finance\Budgets 2027'
    $script:EffectiveStep = "Confirm in the folder's Properties > Security > Advanced > Effective Access for jdoe."

    # ACE fixture. Order is the position in the array handed to the assessment.
    function New-Ace {
        param([string]$Sid, [string]$Name, [int]$Mask, [string]$Type = 'Allow', [bool]$Inherited = $false,
              [bool]$InheritOnly = $false, [bool]$Unresolved = $false, [bool]$IsServerLocal = $false)
        [PSCustomObject]@{
            Sid = $Sid; Principal = $(if ($Unresolved) { $null } else { $Name }); Type = $Type; Mask = $Mask
            Inherited = $Inherited; InheritOnly = $InheritOnly; Unresolved = $Unresolved; IsServerLocal = $IsServerLocal
        }
    }
    # Pure assessment with sane defaults: Jane Doe, share allowing Everyone Change, FS01 a
    # member server. jdoe's SID set = her SID + the four network-logon well-known SIDs + ExtraSids.
    function Invoke-Assess {
        param([hashtable]$With = @{})
        $sids = @($script:Sid.Jdoe) + $script:WellKnown
        if ($With.ContainsKey('ExtraSids')) { $sids += @($With.ExtraSids); $With.Remove('ExtraSids') }
        $p = @{
            UserName = 'jdoe'; DisplayName = 'Jane Doe'; Path = $script:Unc; Server = 'FS01'; PathKind = 'Normal'
            Access = 'Read'; ServerIsDomainController = $false; UserSids = $sids; GroupPaths = @{}
            FolderAces = @(); FolderError = $null; FolderConditional = $false
            ShareAces = @(New-Ace $script:Sid.Everyone 'Everyone' $script:Mask.Change)
            ShareDaclState = 'Present'; ShareError = $null; LocalGroupExpansions = @{}
        }
        foreach ($k in $With.Keys) { $p[$k] = $With[$k] }
        Get-FolderAccessAssessment @p
    }
    function Get-Row($Result, [string]$Layer, [string]$Sid) {
        @($Result.EvidenceRows | Where-Object { $_.Layer -eq $Layer -and $_.SID -eq $Sid })[0]
    }
    function Join-Text($Result) { (@($Result.Reasons) + @($Result.CouldNotCheck) + @($Result.NextSteps)) -join "`n" }

    # --- End-to-end world: what the mocks answer ---------------------------------------------
    function New-Sddl {
        # entries: @{T='A'|'D'; S=sid; M=mask; F='ID'|'CIIO'|''}; stored order = array order
        param([object[]]$Entries)
        'D:PAI' + (($Entries | ForEach-Object { '({0};{1};0x{2:x};;;{3})' -f $_.T, $_.F, [int]$_.M, $_.S }) -join '')
    }
    function New-ShareAce($Sid, $Name, [int]$Mask, [int]$AceType = 0) {
        [PSCustomObject]@{ AceType = $AceType; AccessMask = $Mask; AceFlags = 0
            Trustee = [PSCustomObject]@{ SIDString = $Sid; Name = $Name; Domain = '' } }
    }
    function New-ShareSd($Aces, [int]$Control = 0x8004) {
        # ControlFlags 0x4 = SE_DACL_PRESENT. Present bit clear = NULL DACL (grants everyone);
        # present with no ACEs = EMPTY DACL (grants no one).
        [PSCustomObject]@{ ReturnValue = 0; Descriptor = [PSCustomObject]@{ ControlFlags = $Control; DACL = $Aces } }
    }
    function Reset-World {
        # FS01 is a member server (DomainRole 3) whose BUILTIN\Administrators holds Domain Admins,
        # as on a real member server: a BUILTIN group always exists there, and one the server
        # doesn't return counts as unreadable, not empty.
        $script:World = @{
            FolderSddl = (New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinAdmins; M = $script:Mask.Full; F = '' }))
            FolderThrow = $null
            ShareSd = (New-ShareSd @(New-ShareAce 'S-1-1-0' 'Everyone' $script:Mask.Change))
            WsmanFail = $null; DcomFail = $null; DomainRole = 3; RoleThrow = $null
            LocalGroups = @{ $script:Sid.BuiltinAdmins = @{ Name = 'Administrators'; Members = @(@{ Name = 'Domain Admins'; Domain = 'CONTOSO'; SID = "$($script:Dom)-512" }) } }
            LocalUsers = @{}
        }
        $env:FAC_OVERRIDE = ''; $env:FAC_DOWN = ''
    }
    Reset-World

    # Default mocks for everything external. CIM cmdlets keep their real parameters, so the
    # CimSession / CimInstance parameter types are removed (the mocks hand back plain objects).
    Mock Get-Acl {
        if ($script:World.FolderThrow) { throw $script:World.FolderThrow }
        [PSCustomObject]@{ Sddl = $script:World.FolderSddl; Path = $LiteralPath }
    }
    Mock New-CimSession {
        $dcom = ($SessionOption -and $SessionOption.GetType().Name -match 'DCom')
        if ($dcom -and $script:World.DcomFail) { throw $script:World.DcomFail }
        if (-not $dcom -and $script:World.WsmanFail) { throw $script:World.WsmanFail }
        [PSCustomObject]@{ ComputerName = $ComputerName; Protocol = $(if ($dcom) { 'Dcom' } else { 'Wsman' }) }
    }
    Mock Remove-CimSession {} -RemoveParameterType 'CimSession'
    Mock Get-CimInstance {
        switch ($ClassName) {
            'Win32_ComputerSystem' {
                if ($script:World.RoleThrow) { throw $script:World.RoleThrow }
                [PSCustomObject]@{ DomainRole = $script:World.DomainRole; Name = 'FS01' }
            }
            'Win32_UserAccount' {
                if ($Filter -match "SID\s*=\s*'([^']+)'" -and $script:World.LocalUsers.ContainsKey($Matches[1])) {
                    [PSCustomObject]@{ Name = $script:World.LocalUsers[$Matches[1]]; Domain = 'FS01'; SID = $Matches[1]; LocalAccount = $true }
                }
            }
            'Win32_LogicalShareSecuritySetting' { [PSCustomObject]@{ Name = 'Finance' } }
            'Win32_Group' {
                if ($Filter -match "SID\s*=\s*'([^']+)'" -and $script:World.LocalGroups.ContainsKey($Matches[1])) {
                    [PSCustomObject]@{ Name = $script:World.LocalGroups[$Matches[1]].Name; Domain = 'FS01'; SID = $Matches[1] }
                }
            }
            default { throw "Unexpected Get-CimInstance class $ClassName" }
        }
    } -RemoveParameterType 'CimSession'
    Mock Invoke-CimMethod {
        if ($MethodName -ne 'GetSecurityDescriptor') { throw "Unexpected CIM method $MethodName" }
        $script:World.ShareSd
    } -RemoveParameterType 'CimSession', 'InputObject'
    Mock Get-CimAssociatedInstance {
        @($script:World.LocalGroups[$InputObject.SID].Members | ForEach-Object { [PSCustomObject]$_ })
    } -RemoveParameterType 'CimSession', 'InputObject'

    function Invoke-Check {
        param([string]$Identity = 'jdoe', [string]$Path = $script:Unc, [string]$OutputPath, [datetime]$Now = (Get-Date))
        $p = @{ Identity = $Identity; Path = $Path; Now = $Now }
        if ($OutputPath) { $p.OutputPath = $OutputPath }
        Invoke-FolderAccessCheck @p
    }
    function Get-ConsoleText($Result) {
        $records = @(Write-FolderAccessConsole -Result $Result 6>&1)
        (@($records | ForEach-Object { $_.ToString() })) -join "`n"
    }
}

AfterAll {
    Remove-Item Env:\FAC_OVERRIDE, Env:\FAC_DOWN -ErrorAction SilentlyContinue
    # Leave the session as it was: the throwing stubs and the fake module would otherwise
    # shadow the real cmdlets for whatever runs next in this PowerShell process.
    foreach ($name in $script:GlobalStubs) { Remove-Item -Path "function:global:$name" -ErrorAction SilentlyContinue }
    Remove-Module ActiveDirectory -Force -ErrorAction SilentlyContinue
}

Describe 'path handling (AC1, AC2, AC27)' {
    BeforeEach { Reset-World }

    It 'AC1_NonUncPathIsRejectedBeforeAnythingIsRead: <_>' -ForEach @('S:\Budgets', 'C:\Data') {
        Mock Get-ADUser { throw 'AC1: AD must not be queried' }
        $r = Invoke-Check -Path $_
        $r.ExitCode | Should -Be 2
        $r.Message | Should -Match ([regex]::Escape('Enter the full network path, for example \\FS01\Finance\Budgets 2027'))
        Should -Invoke Get-ADUser -Times 0 -Exactly
        Should -Invoke Get-Acl -Times 0 -Exactly
        Should -Invoke New-CimSession -Times 0 -Exactly
    }

    It 'AC2_ParsesServerShareAndFolder' {
        $p = Split-FolderAccessPath -Path '\\FS01\Finance\Budgets 2027'
        $p.Valid | Should -BeTrue
        $p.Server | Should -Be 'FS01'
        $p.Share | Should -Be 'Finance'
        $p.Folder | Should -Be '\\FS01\Finance\Budgets 2027'
        $p.Kind | Should -Be 'Normal'
    }
    It 'AC2_AdministrativeShareIsFlagged: <_>' -ForEach @('C$', 'D$', 'ADMIN$') {
        $p = Split-FolderAccessPath -Path "\\FS01\$_\Data"
        $p.Kind | Should -Be 'Admin'
        $p.Share | Should -Be $_
        $p.Message | Should -Be "administrative share: run it again with the folder's real share path"
    }
    It 'AC2_AHiddenUserShareIsNotAnAdministrativeShare' {
        (Split-FolderAccessPath -Path '\\FS01\Finance$\Data').Kind | Should -Be 'Normal'
    }
    It 'AC2_AdministrativeShareEndsAsCantTell_EvenWhenTheFolderGrants' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.AuthUsers; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check -Path '\\FS01\D$\Finance'
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        $r.ExitCode | Should -Be 4
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("administrative share: run it again with the folder's real share path"))
    }

    It 'AC27_ServerPartThatIsTheDomainNameIsADfsPath: <_>' -ForEach @('contoso.com', 'CONTOSO', 'contoso') {
        (Split-FolderAccessPath -Path "\\$_\Finance\Budgets" -DomainName @('contoso.com', 'CONTOSO')).Kind | Should -Be 'Dfs'
    }
    It 'AC27_DfsPath_ShareLayerCantTell_FolderStillRead_AndNoCimSessionIsOpened' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.AuthUsers; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check -Path '\\contoso.com\Finance\Budgets'
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("this is a DFS path: run it again with the real server path (find it in the folder's Properties > DFS tab)"))
        @($r.Assessment.EvidenceRows | Where-Object Layer -eq 'Folder').Count | Should -BeGreaterThan 0
        Should -Invoke Get-Acl -Times 1 -Exactly
        Should -Invoke New-CimSession -Times 0 -Exactly
    }
    It 'AC27_DfsPath_FolderNo_StillProbablyNo_WithShareNotRead' {
        # domain groups only: nothing server-local is involved (fix round 1 fixture correction)
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinMgr; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check -Path '\\contoso.com\Finance\Budgets'
        $r.Assessment.Verdict | Should -Be 'PROBABLY NO'
        $r.Assessment.LimitedBy | Should -Be 'folder permissions'
        (@($r.Assessment.CouldNotCheck) -join "`n") | Should -Match 'share permissions: not read'
    }
}

Describe 'finding the user (AC3, AC4)' {
    BeforeEach { Reset-World }

    It 'AC3_UnknownUserListsNothingAndReadsNoShareOrFolderData' {
        $r = Invoke-Check -Identity 'nobody'
        $r.Status | Should -Be 'NotFound'
        $r.ExitCode | Should -Be 2
        $r.Message | Should -Match "No user matched 'nobody'"
        Should -Invoke Get-Acl -Times 0 -Exactly
        Should -Invoke New-CimSession -Times 0 -Exactly
    }
    It 'AC3_AmbiguousNameListsTheCandidatesAndReadsNothing' {
        $r = Invoke-Check -Identity 'Pat Smith'
        $r.Status | Should -Be 'Ambiguous'
        $r.ExitCode | Should -Be 2
        @($r.Candidates).Count | Should -Be 2
        Should -Invoke Get-Acl -Times 0 -Exactly
        Should -Invoke New-CimSession -Times 0 -Exactly
    }

    It 'AC4_PrimaryGroupWithEmptyMemberOf_ProbablyYes_AndDomainUsersListedOnce' {
        # past bugs: memberOf-only answered NO; appending the primary group to a group listing
        # that already holds it showed Domain Users twice
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.DomUsers; M = $script:Mask.Read; F = '' })
        $script:World.ShareSd = New-ShareSd @(New-ShareAce 'S-1-1-0' 'Everyone' $script:Mask.Read)
        $r = Invoke-Check -Identity 'nogroups'
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r.Assessment 'Folder' $script:Sid.DomUsers).Via | Should -Be 'Domain Users (primary group)'
        @($r.Groups | Where-Object { $_.GroupSid -eq $script:Sid.DomUsers }).Count | Should -Be 1
    }
    It 'AC4_PrimaryGroupAlsoInMemberOf_IsStillListedOnce' {
        $env:FAC_OVERRIDE = '{"nogroups":{"memberOf":["Domain Users"]}}'
        $r = Invoke-Check -Identity 'nogroups'
        @($r.Groups | Where-Object { $_.GroupSid -eq $script:Sid.DomUsers }).Count | Should -Be 1
    }
}

Describe 'group paths and the DACL walk (AC5-AC13, AC18-AC20)' {
    It 'AC5_NestedGroupGrantsAccess_AndShowsThePath' {
        Reset-World
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinAll; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r.Assessment 'Folder' $script:Sid.FinAll).Via | Should -Be 'FIN-Staff -> FIN-All'
    }

    It 'AC6_ShareAllowsButFolderEntryIsForAnotherGroup_LimitedByFolderPermissions' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinStaff); GroupPaths = @{ $script:Sid.FinStaff = 'FIN-Staff' }
            ShareAces = @(New-Ace $script:Sid.AuthUsers 'Authenticated Users' $script:Mask.Change)
            FolderAces = @(New-Ace $script:Sid.FinMgr 'FIN-Managers' $script:Mask.Change)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $r.LimitedBy | Should -Be 'folder permissions'
        (@($r.Reasons) -join "`n") | Should -Match 'no folder permission entry matches jdoe or their groups'
    }

    It 'AC7_FolderGrantsButShareOnlyAllowsAnotherGroup_LimitedBySharePermissions' {
        $r = Invoke-Assess @{
            FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read)
            ShareAces = @(New-Ace $script:Sid.FinMgr 'FIN-Managers' $script:Mask.Change)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $r.LimitedBy | Should -Be 'share permissions'
    }

    It 'AC8_ExplicitDenyBeforeAnAllow_ProbablyNo_DenyNamedWithItsGroupPath' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinContr, $script:Sid.DomUsers)
            GroupPaths = @{ $script:Sid.FinContr = 'FIN-Contractors'; $script:Sid.DomUsers = 'Domain Users (primary group)' }
            FolderAces = @(
                (New-Ace $script:Sid.FinContr 'FIN-Contractors' $script:Mask.Read 'Deny')
                (New-Ace $script:Sid.DomUsers 'Domain Users' $script:Mask.Read)
            )
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $deny = Get-Row $r 'Folder' $script:Sid.FinContr
        $deny.Type | Should -Be 'Deny'
        $deny.MatchesUser | Should -BeTrue
        $deny.Via | Should -Be 'FIN-Contractors'
        $deny.Effect | Should -Be 'applies'
        (@($r.Reasons) -join "`n") | Should -Match 'FIN-Contractors'
    }

    It 'AC9_InheritedDenyAfterAnExplicitAllow_ProbablyYes_DenyOverridden' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinContr, $script:Sid.FinStaff)
            GroupPaths = @{ $script:Sid.FinContr = 'FIN-Contractors'; $script:Sid.FinStaff = 'FIN-Staff' }
            FolderAces = @(
                (New-Ace $script:Sid.FinStaff 'FIN-Staff' $script:Mask.Read)
                (New-Ace $script:Sid.FinContr 'FIN-Contractors' $script:Mask.Read 'Deny' $true)
            )
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r 'Folder' $script:Sid.FinContr).Effect | Should -Be 'overridden by an earlier allow'
    }

    It 'AC10_OnlyTraverseFolderGranted_ProbablyNo_WithTheTraverseMessage' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinStaff); GroupPaths = @{ $script:Sid.FinStaff = 'FIN-Staff' }
            FolderAces = @(New-Ace $script:Sid.FinStaff 'FIN-Staff' $script:Mask.Traverse)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        (@($r.Reasons) -join "`n") | Should -Match ([regex]::Escape("jdoe's groups have an entry here, but it doesn't allow opening the folder"))
    }

    It 'AC11_InheritOnlyEntriesAreShownButNotCounted' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinStaff); GroupPaths = @{ $script:Sid.FinStaff = 'FIN-Staff' }
            FolderAces = @(
                (New-Ace $script:Sid.CreatorOwner 'CREATOR OWNER' $script:Mask.Full 'Allow' $false $true)
                (New-Ace $script:Sid.FinStaff 'FIN-Staff' $script:Mask.Read 'Allow' $false $true)
            )
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        (Get-Row $r 'Folder' $script:Sid.CreatorOwner).Effect | Should -Be 'applies below this folder only'
        (Get-Row $r 'Folder' $script:Sid.FinStaff).Effect | Should -Be 'applies below this folder only'
    }

    It 'AC12_BuiltinUsersExpandedOnTheServer_ProbablyYesViaPrimaryGroupThenLocalGroup' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.DomUsers); GroupPaths = @{ $script:Sid.DomUsers = 'Domain Users (primary group)' }
            FolderAces = @(New-Ace $script:Sid.BuiltinUsers 'BUILTIN\Users' $script:Mask.Read)
            LocalGroupExpansions = @{ $script:Sid.BuiltinUsers = @{ Readable = $true; Name = 'FS01\Users'; MemberSids = @($script:Sid.DomUsers); Error = $null } }
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r 'Folder' $script:Sid.BuiltinUsers).Via | Should -Be 'Domain Users (primary group) -> FS01\Users'
    }
    It 'AC12_OnADomainControllerTheBuiltinGroupsComeFromTheToken_NoExpansionNeeded' {
        $r = Invoke-Assess @{
            ServerIsDomainController = $true; ExtraSids = @($script:Sid.BuiltinUsers)
            FolderAces = @(New-Ace $script:Sid.BuiltinUsers 'BUILTIN\Users' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
    }
    It 'AC12_EndToEnd_LocalGroupMembersAreReadOverCimForThatGroupOnly' {
        Reset-World
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $script:World.LocalGroups = @{ $script:Sid.BuiltinUsers = @{ Name = 'Users'; Members = @(@{ Name = 'Domain Users'; Domain = 'CONTOSO'; SID = $script:Sid.DomUsers }) } }
        $r = Invoke-Check -Identity 'nogroups'
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r.Assessment 'Folder' $script:Sid.BuiltinUsers).Via | Should -Be 'Domain Users (primary group) -> FS01\Users'
        Should -Invoke Get-CimAssociatedInstance -Times 1 -Exactly
    }

    Context 'AC13 server-local group whose members cannot be read' {
        BeforeAll {
            $script:LocalUnreadable = @{ $script:Sid.Local = @{ Readable = $false; Name = 'FS01\Contractors'; MemberSids = @(); Error = 'Access is denied' } }
        }
        It 'AC13_TheOnlyAllow_CantTell_NamingTheGroupAndServer' {
            $r = Invoke-Assess @{
                FolderAces = @(New-Ace $script:Sid.Local 'FS01\Contractors' $script:Mask.Read 'Allow' $false $false $false $true)
                LocalGroupExpansions = $script:LocalUnreadable
            }
            $r.Verdict | Should -Be "CAN'T TELL"
            (Join-Text $r) | Should -Match 'FS01\\Contractors'
        }
        It 'AC13_ADeny_CantTell' {
            $r = Invoke-Assess @{
                ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
                FolderAces = @(
                    (New-Ace $script:Sid.Local 'FS01\Contractors' $script:Mask.Read 'Deny' $false $false $false $true)
                    (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
                )
                LocalGroupExpansions = $script:LocalUnreadable
            }
            $r.Verdict | Should -Be "CAN'T TELL"
        }
        It 'AC13_AlreadyYesThroughADomainGroup_StaysProbablyYes_AndListsTheGroupAsNotChecked' {
            $r = Invoke-Assess @{
                ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
                FolderAces = @(
                    (New-Ace $script:Sid.Local 'FS01\Contractors' $script:Mask.Read 'Allow' $false $false $false $true)
                    (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
                )
                LocalGroupExpansions = $script:LocalUnreadable
            }
            $r.Verdict | Should -Be 'PROBABLY YES'
            (@($r.CouldNotCheck) -join "`n") | Should -Match 'FS01\\Contractors'
        }
    }

    It 'AC18_NullShareDacl_GrantsEveryone' {
        $r = Invoke-Assess @{
            ShareAces = @(); ShareDaclState = 'Null'
            FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
    }
    It 'AC18_EmptyShareDacl_GrantsNoOne' {
        $r = Invoke-Assess @{
            ShareAces = @(); ShareDaclState = 'Empty'
            FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $r.LimitedBy | Should -Be 'share permissions'
    }
    It 'AC18_EndToEnd_CimDescriptorWithoutTheDaclPresentBitIsANullDacl' {
        Reset-World
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        $script:World.ShareSd = New-ShareSd $null 0x8000     # DACL-present bit clear
        (Invoke-Check).Assessment.Verdict | Should -Be 'PROBABLY YES'
        $script:World.ShareSd = New-ShareSd @() 0x8004       # present, no ACEs
        (Invoke-Check).Assessment.Verdict | Should -Be 'PROBABLY NO'
    }

    It 'AC19_UnresolvableAllow_ListedAsNotChecked_VerdictStaysYesWhenAnotherEntryGrants' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
            FolderAces = @(
                (New-Ace $script:Sid.Unknown $null $script:Mask.Read 'Allow' $false $false $true)
                (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
            )
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r 'Folder' $script:Sid.Unknown).Effect | Should -Be "not checked: unknown account $($script:Sid.Unknown)"
        (@($r.CouldNotCheck) -join "`n") | Should -Match "unknown account $($script:Sid.Unknown)"
    }
    It 'AC19_UnresolvableAllow_WhenTheAnswerWouldBeNo_IsCantTell' {
        $r = Invoke-Assess @{ FolderAces = @(New-Ace $script:Sid.Unknown $null $script:Mask.Read 'Allow' $false $false $true) }
        $r.Verdict | Should -Be "CAN'T TELL"
    }
    It 'AC19_UnresolvableDeny_IsCantTell_EvenWhenAnAllowFollows' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
            FolderAces = @(
                (New-Ace $script:Sid.Unknown $null $script:Mask.Read 'Deny' $false $false $true)
                (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
            )
        }
        $r.Verdict | Should -Be "CAN'T TELL"
    }

    It 'AC20_TokenGroupSidTheWalkDidNotReach_CountsAsAMatchWithPathNotTraced' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinAll)   # in tokenGroups, but GroupPaths has no walk result for it
            FolderAces = @(New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r 'Folder' $script:Sid.FinAll).Via | Should -Be 'nested (path not traced)'
    }
}

Describe 'cannot read something (AC14-AC17)' {
    BeforeEach { Reset-World }

    It 'AC14_FolderAclAccessDenied_CantTell_NeitherYesNorNoIsPrinted' {
        $script:World.FolderThrow = 'Attempted to perform an unauthorized operation.'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("your account can't read this folder's permissions"))
        (Get-ConsoleText $r) | Should -Not -Match 'PROBABLY (YES|NO)'
    }

    It 'AC15_ShareUnreadableOnBothProtocols_FolderGrants_CantTell_WithBothErrors' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        $script:World.WsmanFail = 'WinRM cannot process the request (wsman-refused-marker)'
        $script:World.DcomFail = 'The RPC server is unavailable (dcom-refused-marker)'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("couldn't read the share permissions on FS01"))
        $evidence = (@($r.Assessment.CouldNotCheck) + @($r.Assessment.Reasons)) -join "`n"
        $evidence | Should -Match 'wsman-refused-marker'
        $evidence | Should -Match 'dcom-refused-marker'
    }
    It 'AC15_WsmanRefusedButDcomWorks_TheShareIsStillRead' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        $script:World.WsmanFail = 'WinRM cannot process the request'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
    }

    It 'AC16_ShareUnreadable_FolderDoesNotGrant_ProbablyNo_ShareListedAsNotRead' {
        # domain groups only: nothing server-local is involved (fix round 1 fixture correction)
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinMgr; M = $script:Mask.Read; F = '' })
        $script:World.WsmanFail = 'WinRM refused'
        $script:World.DcomFail = 'RPC unavailable'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY NO'
        $r.Assessment.LimitedBy | Should -Be 'folder permissions'
        (@($r.Assessment.CouldNotCheck) -join "`n") | Should -Match 'share permissions: not read'
    }

    It 'AC17_ConditionalAceInTheSddl_CantTell_ClaimsMessage' {
        $script:World.FolderSddl = 'D:PAI(XA;;0x1200a9;;;S-1-1-0;(Member_of {SID(S-1-5-32-544)}))(A;;0x1200a9;;;' + $script:Sid.FinStaff + ')'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape('this folder uses claims-based conditions; only Effective Access can evaluate them'))
    }
}

Describe 'verdict wording, exit codes, read-only, report (AC21-AC24)' {
    BeforeEach { Reset-World }

    It 'AC21_VerdictIsAlwaysOneOfThreePhrases_AndNextStepsEndWithEffectiveAccess' {
        $fixtures = @(
            (Invoke-Assess @{ FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read) })
            (Invoke-Assess @{ FolderAces = @() })
            (Invoke-Assess @{ FolderError = 'Access is denied' })
            (Invoke-Assess @{ PathKind = 'Dfs'; FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read) })
        )
        foreach ($f in $fixtures) {
            $f.Verdict | Should -BeIn @('PROBABLY YES', 'PROBABLY NO', "CAN'T TELL")
            @($f.NextSteps)[-1] | Should -Be $script:EffectiveStep
        }
    }
    It 'AC21_ConsoleHeadlineNamesThePersonAndPath_AndNeverPrintsABareYesOrNo' {
        # Fix round 1 (lead decision): the bare-YES/NO check covers the headline and verdict
        # lines, case-sensitively - what AC21 is about - so the reasons can keep the spec's
        # wording ("no folder permission entry matches ...") on screen as in the HTML.
        $r = Invoke-Check
        $text = Get-ConsoleText $r
        $text | Should -Match 'Can Jane Doe open \\\\FS01\\Finance\\Budgets 2027\?\s+PROBABLY NO'
        $verdictLines = @($text -split "`n" | Where-Object { $_ -match '^Can .+\?\s{2}' -or $_ -match '^Limited by:' })
        $verdictLines.Count | Should -BeGreaterThan 0
        foreach ($line in $verdictLines) { $line | Should -Not -MatchExactly '(?<!PROBABLY )\b(YES|NO)\b' }
        $text | Should -Match ([regex]::Escape($script:EffectiveStep))
    }
    It 'AC21_ConsoleReasonUsesTheSameWordingAsTheAssessment' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinMgr; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check
        (Get-ConsoleText $r) | Should -Match 'no folder permission entry matches jdoe or their groups'
    }

    It 'AC22_ReadOnly_NoWriteCmdletIsEverCalled_AndCimMethodIsGetSecurityDescriptorOnly' {
        $script:Out = $TestDrive
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        foreach ($c in 'Set-Acl', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Set-ADUser', 'Set-ADGroup', 'Set-CimInstance') { Mock $c {} }
        Mock New-Item {}
        $null = Invoke-Check -OutputPath $TestDrive
        foreach ($c in 'Set-Acl', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'Set-ADUser', 'Set-ADGroup', 'Set-CimInstance') {
            Should -Invoke $c -Times 0 -Exactly
        }
        Should -Invoke New-Item -Times 0 -Exactly -ParameterFilter { "$Path" -notlike "$($script:Out)*" }
        Should -Invoke Invoke-CimMethod -Times 0 -Exactly -ParameterFilter { $MethodName -ne 'GetSecurityDescriptor' }
        Should -Invoke Invoke-CimMethod -Times 1 -Exactly -ParameterFilter { $MethodName -eq 'GetSecurityDescriptor' }
        Should -Invoke Remove-CimSession -Times 1 -Exactly
    }
    It 'AC22_TheCimSessionIsClosedEvenWhenALaterStepThrows' {
        Mock Resolve-FolderAccessPrincipal { throw 'simulated failure after the session opened' }
        { Invoke-Check } | Should -Throw '*simulated failure*'
        Should -Invoke New-CimSession -Times 1 -Exactly
        Should -Invoke Remove-CimSession -Times 1 -Exactly
    }

    Context 'AC22 read-only by construction: every command and .NET method the script calls is known' {
        BeforeAll {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
            $script:CommandAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
            $script:ExternalCommands = @($script:CommandAsts | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -and $defined -notcontains $_ } | Sort-Object -Unique)
            $script:MemberAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))
            $script:Methods = @($script:MemberAsts | ForEach-Object { $_.Member.Extent.Text } | Sort-Object -Unique)
            $script:NewObjectTypes = @($script:CommandAsts | Where-Object { $_.GetCommandName() -eq 'New-Object' } | ForEach-Object { $_.CommandElements[1].Extent.Text.Trim("'") } | Sort-Object -Unique)
            # Report writers, allowed only inside Export-FolderAccessReport (under -OutputPath).
            $script:ReportWriters = @('New-Item', 'Export-Csv', 'WriteAllText')
            $script:ReportFunction = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Export-FolderAccessReport' }, $true)
        }
        It 'calls only allowlisted commands' {
            $allowed = @(
                'Get-ADUser', 'Get-ADGroup', 'Get-ADDomain', 'Import-Module',
                'Get-Acl', 'New-CimSession', 'New-CimSessionOption', 'Get-CimInstance', 'Get-CimAssociatedInstance', 'Invoke-CimMethod', 'Remove-CimSession',
                'Export-Csv', 'New-Item', 'Test-Path', 'Join-Path', 'Get-Date',
                'ForEach-Object', 'Where-Object', 'Select-Object', 'New-Object', 'Write-Host', 'Write-Verbose'
            )
            foreach ($c in $script:ExternalCommands) { $allowed | Should -Contain $c -Because "$c is not on the read-only allowlist" }
        }
        It 'calls only allowlisted .NET methods (no SetAccessControl, Delete, Put, ...)' {
            $allowed = @(
                'Add', 'AppendLine', 'Contains', 'ContainsKey', 'Dequeue', 'Enqueue', 'Escape', 'GetType', 'HtmlEncode',
                'IsNullOrEmpty', 'IsNullOrWhiteSpace', 'Replace', 'ToArray', 'ToString', 'Trim', 'TrimEnd', 'WriteAllText'
            )
            foreach ($m in $script:Methods) { $allowed | Should -Contain $m -Because ".$m() is not on the read-only allowlist" }
            foreach ($bad in 'SetAccessControl', 'Delete', 'Put', 'Create', 'Remove', 'SetSecurityDescriptor', 'MoveTo', 'CopyTo') { $script:Methods | Should -Not -Contain $bad }
        }
        It 'creates only allowlisted .NET types' {
            $allowed = @(
                'System.Collections.Generic.HashSet[string]', 'System.Collections.Generic.List[object]', 'System.Collections.Generic.List[string]',
                'System.Collections.Queue', 'System.Security.AccessControl.RawSecurityDescriptor', 'System.Text.StringBuilder', 'System.Text.UTF8Encoding'
            )
            foreach ($t in $script:NewObjectTypes) { $allowed | Should -Contain $t }
        }
        It 'invokes the CIM method GetSecurityDescriptor only' {
            $calls = @($script:CommandAsts | Where-Object { $_.GetCommandName() -eq 'Invoke-CimMethod' })
            $calls.Count | Should -BeGreaterThan 0
            foreach ($c in $calls) {
                $i = [array]::IndexOf(@($c.CommandElements | ForEach-Object { if ($_ -is [System.Management.Automation.Language.CommandParameterAst]) { $_.ParameterName } else { '' } }), 'MethodName')
                $c.CommandElements[$i + 1].Extent.Text | Should -Be 'GetSecurityDescriptor'
            }
        }
        It 'writes files only inside Export-FolderAccessReport' {
            $script:ReportFunction | Should -Not -BeNullOrEmpty
            $writers = @($script:CommandAsts | Where-Object { $script:ReportWriters -contains $_.GetCommandName() }) + @($script:MemberAsts | Where-Object { $script:ReportWriters -contains $_.Member.Extent.Text })
            $writers.Count | Should -BeGreaterThan 0
            foreach ($w in $writers) {
                ($w.Extent.StartOffset -ge $script:ReportFunction.Extent.StartOffset -and $w.Extent.EndOffset -le $script:ReportFunction.Extent.EndOffset) | Should -BeTrue -Because "$($w.Extent.Text) is outside Export-FolderAccessReport"
            }
        }
    }

    It 'AC23_WritesHtmlAndCsvNamedBySamAndTimestamp_CsvHasOneRowPerEvidenceEntry' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' }, @{ T = 'A'; S = $script:Sid.BuiltinAdmins; M = $script:Mask.Full; F = '' })
        $dir = Join-Path $TestDrive 'out'
        $null = New-Item -ItemType Directory -Path $dir
        $r = Invoke-Check -OutputPath $dir -Now ([datetime]'2026-10-17 14:30:05')
        (Get-ChildItem -LiteralPath $dir -Name) | Sort-Object | Should -Be @('FolderAccessCheck_jdoe_2026-10-17_143005.csv', 'FolderAccessCheck_jdoe_2026-10-17_143005.html')
        $csvPath = Join-Path $dir 'FolderAccessCheck_jdoe_2026-10-17_143005.csv'
        (Get-Content -LiteralPath $csvPath -TotalCount 1) | Should -Not -Match '^#TYPE'
        $rows = @(Import-Csv -LiteralPath $csvPath)
        $rows.Count | Should -Be @($r.Assessment.EvidenceRows).Count
        $rows.Count | Should -BeGreaterThan 0
        $cols = $rows[0].PSObject.Properties.Name
        foreach ($c in 'Layer', 'Order', 'Principal', 'SID', 'Type', 'Inherited', 'AppliesTo', 'Rights', 'MatchesUser', 'Via', 'Effect') { $cols | Should -Contain $c }
    }
    It 'AC23_FolderNameIsHtmlEncodedInTheReport' {
        $dir = Join-Path $TestDrive 'out2'
        $null = New-Item -ItemType Directory -Path $dir
        $null = Invoke-Check -Path '\\FS01\Finance\<script>alert(1)</script>' -OutputPath $dir
        $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $dir -Filter '*.html').FullName -Raw
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
    }

    It 'AC24_ExitCodes_YesZero_NoOne_CantTellFour' {
        (Invoke-Assess @{ FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read) }).ExitCode | Should -Be 0
        (Invoke-Assess @{ FolderAces = @() }).ExitCode | Should -Be 1
        (Invoke-Assess @{ FolderError = 'Access is denied' }).ExitCode | Should -Be 4
    }
    It 'AC24_ExitCodes_BadInputAndNotFoundAreTwo' {
        (Invoke-Check -Path 'S:\Budgets').ExitCode | Should -Be 2
        (Invoke-Check -Identity 'nobody').ExitCode | Should -Be 2
        (Invoke-Check -Identity 'Pat Smith').ExitCode | Should -Be 2
    }
    It 'AC24_ExitCodes_DirectoryUnreachableIsThree' {
        $env:FAC_DOWN = '1'
        $r = Invoke-Check
        $r.ExitCode | Should -Be 3
        $r.Message | Should -Match 'Active Directory'
    }
}

Describe 'server-local entries when the server can not be read (AC13, AC16, AC27)' {
    BeforeEach { Reset-World }
    BeforeAll {
        # A valid machine-domain SID (each sub-authority fits 32 bits, so SDDL keeps it as written).
        $script:MachineSid = 'S-1-5-21-1555555555-1666666666-1777777777-1001'
    }

    It 'AC13_NoCimSession_FolderGrantsOnlyBuiltinUsers_CantTell' {
        # A false PROBABLY NO here would be the confident wrong answer the tool exists to avoid:
        # on a member server BUILTIN\Users holds Domain Users by default.
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $script:World.WsmanFail = 'WinRM refused'
        $script:World.DcomFail = 'RPC unavailable'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        $r.ExitCode | Should -Be 4
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("couldn't read the members of BUILTIN\Users on FS01"))
    }
    It 'AC13_NoCimSession_FolderGrantsOnlyBuiltinAdministrators_CantTell' {
        # jdoe might be an administrator of FS01; nothing on FS01 could be read to rule it out
        $script:World.WsmanFail = 'WinRM refused'
        $script:World.DcomFail = 'RPC unavailable'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape('BUILTIN\Administrators'))
    }
    It 'AC27_DfsPath_FolderGrantsOnlyBuiltinUsers_CantTell' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check -Path '\\contoso.com\Finance\Budgets'
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        $r.Assessment.FolderState | Should -Be 'Unknown'
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("couldn't read the members of BUILTIN\Users"))
        Should -Invoke New-CimSession -Times 0 -Exactly
    }
    It 'AC13_ServerLocalEntryWithNoExpansion_AlreadyGrantedByADomainGroup_StaysYes_AndIsListedAsNotChecked' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
            FolderAces = @(
                (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
                (New-Ace $script:Sid.BuiltinUsers 'BUILTIN\Users' $script:Mask.Read 'Allow' $false $false $false $true)
            )
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (@($r.CouldNotCheck) -join "`n") | Should -Match ([regex]::Escape('BUILTIN\Users'))
    }
    It 'AC13_ServerLocalEntryWithNoExpansion_TheOnlyAllow_CantTell' {
        $r = Invoke-Assess @{ FolderAces = @(New-Ace $script:Sid.BuiltinUsers 'BUILTIN\Users' $script:Mask.Read 'Allow' $false $false $false $true) }
        $r.Verdict | Should -Be "CAN'T TELL"
    }
    It 'AC13_ServerLocalDenyWithNoExpansion_BeforeTheGrant_CantTell' {
        $r = Invoke-Assess @{
            ExtraSids = @($script:Sid.FinAll); GroupPaths = @{ $script:Sid.FinAll = 'FIN-All' }
            FolderAces = @(
                (New-Ace $script:Sid.BuiltinUsers 'BUILTIN\Users' $script:Mask.Read 'Deny' $false $false $false $true)
                (New-Ace $script:Sid.FinAll 'FIN-All' $script:Mask.Read)
            )
        }
        $r.Verdict | Should -Be "CAN'T TELL"
    }

    It 'AC13_BuiltinGroupTheServerDoesNotReturn_IsUnreadable_NotEmpty' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $script:World.LocalGroups = @{}
        $r = Invoke-Check -Identity 'nogroups'
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("FS01 didn't return this built-in group"))
    }
    It 'AC13_GetServerLocalGroup_MissingCustomGroupIsEmpty_MissingBuiltinGroupIsUnreadable' {
        $session = [PSCustomObject]@{ ComputerName = 'FS01' }
        $script:World.LocalGroups = @{}
        $custom = Get-ServerLocalGroup -Session $session -Server 'FS01' -Sid $script:Sid.Local -FallbackName 'FS01\Gone'
        $custom.Readable | Should -BeTrue
        $custom.Found | Should -BeFalse
        $builtin = Get-ServerLocalGroup -Session $session -Server 'FS01' -Sid $script:Sid.BuiltinUsers -FallbackName 'BUILTIN\Users'
        $builtin.Readable | Should -BeFalse
        $builtin.Error | Should -Match 'built-in group'
    }
    It 'AC13_ServerRoleUnreadable_BuiltinEntryIsNotExpanded_CantTell' {
        # On a DC BUILTIN groups are domain groups, on a member server local ones: without the
        # role neither can be assumed, even though FS01 would hand back a member list.
        $script:World.RoleThrow = 'Access denied reading Win32_ComputerSystem'
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $script:World.LocalGroups = @{ $script:Sid.BuiltinUsers = @{ Name = 'Users'; Members = @(@{ Name = 'Domain Users'; Domain = 'CONTOSO'; SID = $script:Sid.DomUsers }) } }
        $r = Invoke-Check -Identity 'nogroups'
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("couldn't tell whether FS01 is a domain controller"))
        Should -Invoke Get-CimAssociatedInstance -Times 0 -Exactly
    }
    It 'AC13_ServerRoleUnreadable_ADomainGroupAlreadyGrants_StaysProbablyYes' {
        $script:World.RoleThrow = 'Access denied reading Win32_ComputerSystem'
        $script:World.FolderSddl = New-Sddl @(
            @{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' }
            @{ T = 'A'; S = $script:Sid.BuiltinUsers; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        (@($r.Assessment.CouldNotCheck) -join "`n") | Should -Match 'domain controller'
    }

    It 'AC19_LocalUserAccountOnTheServer_IsResolved_AndNeverMatchesADomainUser' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:MachineSid; M = $script:Mask.Read; F = '' })
        $script:World.LocalUsers = @{ $script:MachineSid = 'scanner' }
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY NO'
        $row = Get-Row $r.Assessment 'Folder' $script:MachineSid
        $row.Principal | Should -Be 'FS01\scanner (local account on FS01)'
        $row.MatchesUser | Should -BeFalse
        $row.Effect | Should -Be 'does not apply to jdoe'
        (Join-Text $r.Assessment) | Should -Not -Match 'unknown account'
    }
    It 'AC19_ServerSidThatIsNeitherALocalGroupNorALocalUser_IsAnUnknownAccount' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:MachineSid; M = $script:Mask.Read; F = '' })
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match "unknown account $($script:MachineSid)"
    }
}

Describe 'share and folder descriptors (AC17, AC18)' {
    BeforeEach { Reset-World }

    It 'AC18_ShareDescriptorStates_BitClearIsNull_PresentWithNoEntriesIsEmpty_PresentWithNullIsUnreadable' {
        (ConvertFrom-ShareDescriptor -Descriptor ([PSCustomObject]@{ ControlFlags = 0x8000; DACL = $null })).DaclState | Should -Be 'Null'
        (ConvertFrom-ShareDescriptor -Descriptor ([PSCustomObject]@{ ControlFlags = 0x8004; DACL = @() })).DaclState | Should -Be 'Empty'
        (ConvertFrom-ShareDescriptor -Descriptor ([PSCustomObject]@{ ControlFlags = 0x8004; DACL = $null })).DaclState | Should -Be 'Unreadable'
    }
    It 'AC18_DaclPresentButNull_FolderGrants_CantTell_WithAPlainReason' {
        # Learn doesn't say whether WMI returns an empty DACL as NULL; everyone vs no one is not guessed
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        $script:World.ShareSd = New-ShareSd $null 0x8004
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (Join-Text $r.Assessment) | Should -Match ([regex]::Escape("the share's permission list on FS01 came back empty or unreadable; check it in Computer Management"))
    }
    It 'AC18_DaclPresentButNull_FolderDoesNotGrant_ProbablyNo_ShareListedAsNotRead' {
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinMgr; M = $script:Mask.Read; F = '' })
        $script:World.ShareSd = New-ShareSd $null 0x8004
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY NO'
        $r.Assessment.LimitedBy | Should -Be 'folder permissions'
        (@($r.Assessment.CouldNotCheck) -join "`n") | Should -Match 'share permissions: not read'
    }

    It 'AC18_FolderWithNoDacl_IsEveryoneFullControl' {
        # https://learn.microsoft.com/windows/win32/secauthz/null-dacls-and-empty-dacls
        $script:World.FolderSddl = 'D:NO_ACCESS_CONTROL'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        $row = Get-Row $r.Assessment 'Folder' 'S-1-1-0'
        $row.Principal | Should -Match '^Everyone'
        $row.Rights | Should -Be 'Full control'
        $row.Effect | Should -Be 'allows'
    }
    It 'AC17_InheritOnlyConditionalEntry_DoesNotMakeItCantTell' {
        $script:World.FolderSddl = 'D:PAI(XA;CIIO;0x1200a9;;;S-1-1-0;(Member_of {SID(S-1-5-32-544)}))(A;;0x1200a9;;;' + $script:Sid.FinStaff + ')'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r.Assessment 'Folder' 'S-1-1-0').Effect | Should -Be 'applies below this folder only'
    }
    It 'AC17_UnsupportedEntryType_CantTell_NamingTheType' {
        $script:World.FolderSddl = 'D:(OA;;0x1200a9;bf967aba-0de6-11d0-a285-00aa003049e2;;S-1-1-0)(A;;0x1200a9;;;' + $script:Sid.FinStaff + ')'
        $r = Invoke-Check
        $r.Assessment.Verdict | Should -Be "CAN'T TELL"
        (@($r.Assessment.Reasons) -join "`n") | Should -Match "permission entry type this tool doesn't evaluate \(AccessAllowedObject\)"
    }
}

Describe '-Access Modify (D-018)' {
    BeforeAll { $script:ModifyMask = 0x1301BF }

    It 'a Read-only folder entry is PROBABLY NO for Modify' {
        $r = Invoke-Assess @{
            Access = 'Modify'; ExtraSids = @($script:Sid.FinStaff); GroupPaths = @{ $script:Sid.FinStaff = 'FIN-Staff' }
            FolderAces = @(New-Ace $script:Sid.FinStaff 'FIN-Staff' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $r.LimitedBy | Should -Be 'folder permissions'
        (@($r.Reasons) -join "`n") | Should -Match ([regex]::Escape("jdoe's groups have an entry here, but it doesn't allow changing files in the folder"))
        (Get-Row $r 'Folder' $script:Sid.FinStaff).Effect | Should -Be 'allows part of what is needed'
    }
    It 'a Modify folder entry with a Change share is PROBABLY YES' {
        $r = Invoke-Assess @{
            Access = 'Modify'; ExtraSids = @($script:Sid.FinStaff); GroupPaths = @{ $script:Sid.FinStaff = 'FIN-Staff' }
            FolderAces = @(New-Ace $script:Sid.FinStaff 'FIN-Staff' $script:ModifyMask)
            ShareAces = @(New-Ace $script:Sid.AuthUsers 'Authenticated Users' $script:Mask.Change)
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
        (Get-Row $r 'Folder' $script:Sid.FinStaff).Rights | Should -Be 'Modify'
        (Get-Row $r 'Share' $script:Sid.AuthUsers).Rights | Should -Be 'Change'
    }
    It 'the headline says "change files in"' {
        $r = Invoke-Assess @{ Access = 'Modify'; FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:ModifyMask) }
        $r.Headline | Should -Be "Can Jane Doe change files in $($script:Unc)?  PROBABLY YES"
        @($r.NextSteps)[-1] | Should -Be $script:EffectiveStep
    }
    It 'a share that allows only Read is PROBABLY NO for Modify, limited by share permissions' {
        $r = Invoke-Assess @{
            Access = 'Modify'; FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:ModifyMask)
            ShareAces = @(New-Ace $script:Sid.Everyone 'Everyone' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY NO'
        $r.LimitedBy | Should -Be 'share permissions'
        (@($r.Reasons) -join "`n") | Should -Match ([regex]::Escape("jdoe's groups have a share permission entry, but it doesn't allow changing files in the folder"))
        (Get-Row $r 'Share' $script:Sid.Everyone).Rights | Should -Be 'Read'
    }
    It 'the same Read share is enough for the default Read check' {
        $r = Invoke-Assess @{
            FolderAces = @(New-Ace $script:Sid.Jdoe 'CONTOSO\jdoe' $script:Mask.Read)
            ShareAces = @(New-Ace $script:Sid.Everyone 'Everyone' $script:Mask.Read)
        }
        $r.Verdict | Should -Be 'PROBABLY YES'
    }
    It 'end to end: -Access Modify reaches the assessment and the headline' {
        Reset-World
        $script:World.FolderSddl = New-Sddl @(@{ T = 'A'; S = $script:Sid.FinStaff; M = $script:Mask.Read; F = '' })
        $r = Invoke-FolderAccessCheck -Identity 'jdoe' -Path $script:Unc -Access Modify
        $r.Assessment.Verdict | Should -Be 'PROBABLY NO'
        $r.Assessment.Headline | Should -Be "Can Jane Doe change files in $($script:Unc)?  PROBABLY NO"
    }
}

Describe 'AC26 helpers copied from Find-PrivilegedAccessPaths are identical' {
    BeforeAll {
        function script:Get-FunctionText {
            param([string]$Path, [string]$Name)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
            if (-not $fn) { return $null }
            return ($fn.Body.Extent.Text -replace '\s+', ' ').Trim()
        }
        $script:Source = Join-Path (Split-Path -Parent $script:Root) 'Find-PrivilegedAccessPaths\Find-PrivilegedAccessPaths.ps1'
    }
    It 'AC26_SharedHelperIsTextuallyIdentical: <_>' -ForEach @('Get-PrivilegedGroupDefinition', 'Get-NameOnlyPrivilegedGroup', 'Find-PrivilegedGroupBySid') {
        $original = Get-FunctionText -Path $script:Source -Name $_
        $original | Should -Not -BeNullOrEmpty
        $copy = Get-FunctionText -Path $script:ScriptPath -Name $_
        $copy | Should -Not -BeNullOrEmpty
        $copy | Should -Be $original
    }
}

Describe 'parameter names match the real ActiveDirectory module (SQUAD.md: mocks can lie)' {
    BeforeAll {
        $script:RealParams = $null
        # Child process: the real module is never imported into this session, and the AD
        # drive is not created (ADPS_LoadDefaultDrive=0), so nothing connects to the domain.
        # If RSAT is not installed the child prints nothing and the checks are skipped.
        $cmd = '$env:ADPS_LoadDefaultDrive = 0; Import-Module ActiveDirectory -ErrorAction Stop; ' +
            'foreach ($c in "Get-ADUser","Get-ADGroup","Get-ADDomain") { "$c|" + ((Get-Command $c).Parameters.Keys -join ",") }'
        $lines = @(& pwsh -NoProfile -Command $cmd 2>$null)
        $script:RealParams = @{}
        foreach ($l in $lines) { if ($l -match '^(Get-AD\w+)\|(.*)$') { $script:RealParams[$Matches[1]] = @($Matches[2] -split ',') } }
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
        $script:AdCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and @('Get-ADUser', 'Get-ADGroup', 'Get-ADDomain') -contains $n.GetCommandName() }, $true))
    }
    It 'the fake module only declares parameters the real cmdlets have' {
        if (-not $script:RealParams -or $script:RealParams.Count -eq 0) { Set-ItResult -Skipped -Because 'ActiveDirectory (RSAT) is not installed'; return }
        foreach ($name in 'Get-ADUser', 'Get-ADGroup', 'Get-ADDomain') {
            $fake = @((Get-Command -Module ActiveDirectory -Name $name).Parameters.Keys | Where-Object { [System.Management.Automation.PSCmdlet]::CommonParameters -notcontains $_ })
            foreach ($p in $fake) { $script:RealParams[$name] | Should -Contain $p }
        }
    }
    It 'the script calls Get-ADUser / Get-ADGroup only with parameters the real cmdlets have' {
        $script:AdCalls.Count | Should -BeGreaterThan 0
        if (-not $script:RealParams -or $script:RealParams.Count -eq 0) { Set-ItResult -Skipped -Because 'ActiveDirectory (RSAT) is not installed'; return }
        foreach ($c in $script:AdCalls) {
            foreach ($p in @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] })) {
                $script:RealParams[$c.GetCommandName()] | Should -Contain $p.ParameterName
            }
        }
    }
}

Describe 'parameter names match the real CIM cmdlets and Get-Acl (SQUAD.md: mocks can lie)' {
    BeforeAll {
        # Child process so the Pester mocks in this session can't answer for the real cmdlets.
        # Get-Command only: nothing is connected to. CimCmdlets and Get-Acl ship with PowerShell.
        $script:CimNames = @('New-CimSession', 'New-CimSessionOption', 'Get-CimInstance', 'Get-CimAssociatedInstance', 'Invoke-CimMethod', 'Remove-CimSession', 'Get-Acl')
        $cmd = 'foreach ($c in "' + ($script:CimNames -join '","') + '") { foreach ($s in (Get-Command $c).ParameterSets) { "$c|$($s.Name)|" + (($s.Parameters | ForEach-Object { $_.Name }) -join ",") } }'
        $script:Sets = @{}
        foreach ($l in @(& pwsh -NoProfile -Command $cmd 2>$null)) {
            if ($l -match '^([\w-]+)\|([^|]*)\|(.*)$') {
                if (-not $script:Sets.ContainsKey($Matches[1])) { $script:Sets[$Matches[1]] = New-Object System.Collections.Generic.List[object] }
                $script:Sets[$Matches[1]].Add(@($Matches[3] -split ','))
            }
        }
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
        $script:CimCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $script:CimNames -contains $n.GetCommandName() }, $true))
        # Keys of a splatted hashtable: '$x = @{ Key = ... }' and '$x[''Key''] = ...' anywhere in the script.
        $script:SplatKeys = @{}
        foreach ($a in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))) {
            $left = $a.Left
            if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $a.Right.Expression -is [System.Management.Automation.Language.HashtableAst]) {
                $script:SplatKeys[$left.VariablePath.UserPath] = @($script:SplatKeys[$left.VariablePath.UserPath]) + @($a.Right.Expression.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text.Trim("'") })
            } elseif ($left -is [System.Management.Automation.Language.IndexExpressionAst] -and $left.Target -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $script:SplatKeys[$left.Target.VariablePath.UserPath] = @($script:SplatKeys[$left.Target.VariablePath.UserPath]) + @($left.Index.Extent.Text.Trim("'"))
            }
        }
    }
    It 'every CIM / Get-Acl call uses a parameter combination one real parameter set accepts' {
        $script:CimCalls.Count | Should -BeGreaterThan 0
        $script:Sets.Count | Should -Be $script:CimNames.Count
        foreach ($c in $script:CimCalls) {
            $name = $c.GetCommandName()
            $used = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
            foreach ($splat in @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted })) {
                $used += @($script:SplatKeys[$splat.VariablePath.UserPath] | Where-Object { $_ })
            }
            $used = @($used | Sort-Object -Unique)
            $fits = @($script:Sets[$name] | Where-Object { $set = $_; @($used | Where-Object { $set -notcontains $_ }).Count -eq 0 })
            $fits.Count | Should -BeGreaterThan 0 -Because "$name -$($used -join ' -') must fit one parameter set of the real cmdlet ($($c.Extent.Text))"
        }
    }
    It 'Invoke-CimMethod is called with -CimSession and -InputObject together, which the real cmdlet allows' {
        $set = @($script:Sets['Invoke-CimMethod'] | Where-Object { $_ -contains 'CimSession' -and $_ -contains 'InputObject' -and $_ -contains 'MethodName' })
        $set.Count | Should -BeGreaterThan 0
    }
}
