<#
    Tests for SQ-025: change an existing permission entry in place (WPF app FolderPermissionManager-GUI.ps1
    and the core FolderPermissions.Core.ps1; Pester 5, run under pwsh). One test per acceptance criterion,
    AC1-AC29 of squad/specs/SQ-025.md, named AC<n>_... . AC24 (the result message) is in
    FolderPermissions.Core.Tests.ps1, as the spec says. Owner decisions D-047 (Q-A = A), D-048 (Q-B = A)
    and D-049 (Q-C = A) apply: the ACs as drafted.

    The app is never started and no window is shown: it is dot-sourced with -LoadFunctionsOnly. Nothing
    touches a real ACL: Get-Acl is mocked to hand out in-memory DirectorySecurity / FileSecurity objects
    built from SDDL (plus whatever the mocked Set-Acl was given), Set-Acl is a recording fake, and
    Invoke-AclTool, takeown and icacls are throwing backstops. Items that must exist (Test-Path) are
    folders and files in $TestDrive; backups and logs go to $TestDrive. The current identity's token is
    never read (Get-CurrentIdentitySids is a seam that is mocked; Get-SelfDenyWarning takes the SIDs).
    No dialog is shown (Show-ChangePermissionDialog and Show-ConfirmDialog are mocked).

    Names and signatures pinned here for the implementer (the spec leaves them open; the stubs in
    FolderPermissions.Core.ps1 and FolderPermissionManager-GUI.ps1 already carry them):

    Core (FolderPermissions.Core.ps1)
      Format-AppliesTo -ItemType Folder|File -InheritanceFlags -PropagationFlags         -> string
      Find-InheritanceSource -Path <child path> -Row <inherited row>
          -> [PSCustomObject]@{ Source (folder path or $null); Root (drive or share root that was reached); Error ($null or reason text) }
      Set-FolderPermissionEntry -Path -Sid -Type -RightsValue [int] -InheritanceFlags -PropagationFlags
          -NewRights FullControl|Modify|ReadAndExecute|Read|Write|Current -NewType Allow|Deny -LogFolder
          [SupportsShouldProcess]; through Invoke-SingleItemAclChange; Action 'Change permission', ActionSlug
          'ChangePermission'; Detail "From Allow Modify to Deny Modify for BUILTIN\Users (applies to: This folder,
          subfolders and files)". Builds the new rule from the SID (never New-PermissionRule / a name lookup).
          The core's own refusal texts: non-canonical (AC16), entry gone -> Result 'Skipped (entry not found)' (AC14).
      Get-ChangeResultMessage        'Change permission' case (AC24, core suite)

    App (FolderPermissionManager-GUI.ps1)
      ConvertTo-AclViewModel rows gain RightsValue [int], InheritanceFlags, PropagationFlags, AppliesTo (Sid exists already)
      Get-ChangePermissionState [-Row <row>] [-Files]
          -> Enabled, ToolTip, Mode ('Edit'|'Inherited'|$null) and, for -Files, Entries (that file's explicit rows).
          Reads $script:Current, $script:ViewState.FolderPermissions, $script:ChangeTask / $script:ChangePending
          (Get-ChangeControlState) and, for -Files, Get-SelectedFileRows and $script:FileAclCache.
      Invoke-AclRowDoubleClick -Row            calls Open-ChangePermission -Scope Folder -Row <row>
      Open-ChangePermission -Scope Folder|Files [-Row]
          Edit mode: Test-ReadyForChange, Enter-ChangePending, Start-ChangeLookup (target resolution, SQ-018),
          then Get-ChangeDialogModel, Show-ChangePermissionDialog -Model, Invoke-ChangePermission.
          Inherited mode: a background read ($script:InheritanceSourceWork via Start-ReadTask), its result
          ignored when $script:UI.FolderAclGrid.SelectedItem is no longer the row; then the Close-only dialog.
      Get-ChangeDialogModel -Row [-AllRows] [-Path] [-Source <Find-InheritanceSource result>] [-Choices <rows>]
          -> Row, Title, AccountText, AccountNote, Level (tag), LevelChoices (@{Tag;Label}), Type, AppliesTo,
             SubmitLabel, Note, Mode, Message (inherited text), ShowSubmit, Choices (files: entry picker labels)
      Get-ChangeDialogAnswer -Model -Level -Type          -> Ok, Problem, Answer (Row, Level, Type)
      Show-ChangePermissionDialog -Model [-TargetText]    -> Row, Level, Type, or $null when cancelled
      Test-ChangeTakesAccessAway -OldType -OldRightsValue -NewType -NewRights      -> bool
      Get-CurrentIdentitySids                              -> UserSid, GroupSid (the seam for the real token)
      Get-SelfDenyWarning -Type -Sid -UserSid -GroupSid    -> the confirm line or $null
      Invoke-ChangePermission -Scope -Row -Level -Type [-Targets] [-Label] [-RefreshState]
          confirm (Get-ConfirmSpec -Action ChangePermission) when access is taken away, a root, or a remembered
          mapping; then Start-ChangeTask -Work $script:ChangePermissionWork -ArgumentList (the work's param order).
      Get-ConfirmSpec -Action ChangePermission -Targets -Type <new type> -Change @{Identity;From;To;AppliesTo}
          [-SelfDenyWarning <text>]
      Set-PermissionSubmitStyle -Mode Change ...  also sets Content ('Change to Deny' / 'Change Permission')
      Get-PermissionDialogXaml -Mode Change        account text box PermAccountText with IsReadOnly="True"
      $script:ChangePermissionWork  param([string[]]$Paths, [string]$Sid, [string]$OldType, [int]$RightsValue,
          [string]$InheritanceFlags, [string]$PropagationFlags, [string]$NewRights, [string]$NewType,
          [string]$LogFolder, [bool]$WhatIf, [string]$CorePath)  -> as the other work blocks (Ok, Entries, LogPath, Message)
      Get-ReadBackProblem / Add-ChangeReadBack -Kind Change ... (used by the work block; AC23 is tested through the work block)
      Get-DryRunSummary                            'Change permission' case (AC25)

    Fixture note: the AC1 ACL is written in canonical order (explicit Deny before explicit Allow); the spec lists
    the entries in a different order, but the change function refuses a non-canonical ACL (AC16).

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\FolderPermissionManager-ChangePermission.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:AppPath = Join-Path $script:Root 'FolderPermissionManager-GUI.ps1'
    $script:CorePath = Join-Path $script:Root 'FolderPermissions.Core.ps1'
    $script:ReadmePath = Join-Path $script:Root 'README.md'
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)

    . $script:CorePath -LoadFunctionsOnly
    . $script:AppPath -LoadFunctionsOnly

    $script:BU = 'S-1-5-32-545'
    $script:BA = 'S-1-5-32-544'
    $script:SY = 'S-1-5-18'
    $script:CO = 'S-1-3-0'
    $script:Orphan = 'S-1-5-21-1-2-3-1234'
    # Explicit Deny Write (no inheritance), explicit Allow Modify (CI,OI), inherited Allow Read & execute for SYSTEM.
    # Masks: Modify 0x1301bf (with Synchronize), Write 0x116, Read & execute 0x1200a9.
    $script:SddlAC1 = 'O:BAG:SYD:(D;;0x116;;;BU)(A;OICI;0x1301bf;;;BU)(A;ID;0x1200a9;;;SY)'
    $script:FullText = 'This folder, subfolders and files'
    $script:ChangeButtons = 'AddPermissionBtn', 'RemovePermissionBtn', 'TakeOwnershipBtn', 'TakeOwnershipTreeBtn',
    'CopyPermissionsBtn', 'AddFilePermissionBtn', 'RemoveFilePermissionBtn', 'TakeFileOwnershipBtn'
    $script:RightsModify = [int][System.Security.AccessControl.FileSystemRights]'Modify'
    $script:RightsRead = [int][System.Security.AccessControl.FileSystemRights]'Read'
    $script:NoSync = -bnot 0x100000

    function script:New-AclFromSddl {
        param([string]$Sddl, [switch]$File)
        $acl = if ($File) { New-Object System.Security.AccessControl.FileSecurity } else { New-Object System.Security.AccessControl.DirectorySecurity }
        $acl.SetSecurityDescriptorSddlForm($Sddl)
        $acl
    }
    function script:Get-AclRows {
        param([string]$Sddl, [switch]$File)
        @((ConvertTo-AclViewModel -Acl (New-AclFromSddl $Sddl -File:$File)).Rows)
    }
    function script:New-Folder {
        param([string]$Name)
        $p = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }
    function script:New-File {
        param([string]$Folder, [string]$Name)
        $p = Join-Path $Folder $Name
        Set-Content -LiteralPath $p -Value 'x'
        $p
    }
    function script:New-FakeChangeUi {
        $ui = @{}
        foreach ($n in $script:ChangeButtons) { $ui[$n] = [PSCustomObject]@{ IsEnabled = $true } }
        $ui
    }
    function script:New-FakeTarget {
        param([string]$Display, [string]$Resolved, [bool]$Remembered = $false, [bool]$Local = $false)
        if (-not $Resolved) { $Resolved = $Display }
        [PSCustomObject]@{ Ok = $true; Refusal = $null; DisplayPath = $Display; ResolvedPath = $Resolved; IsRemembered = $Remembered; IsLocal = $Local }
    }
    function script:Get-LastStatus { if ($script:Status.Count -gt 0) { $script:Status[$script:Status.Count - 1] } }
    function script:Get-AllLogTextIn {
        param([string]$Folder)
        $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue)
        ($files | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
    }
    # The change arguments of the explicit rule of $Sid / $Type found in $Sddl, as the core takes them.
    function script:Get-EntryArgs {
        param([string]$Sddl, [string]$Sid, [string]$Type, [string]$NewRights, [string]$NewType, [int]$Skip = 0, [switch]$File)
        $acl = New-AclFromSddl $Sddl -File:$File
        $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.IdentityReference.Value -eq $Sid -and "$($_.AccessControlType)" -eq $Type })
        $r = $rules[$Skip]
        @{
            Sid = $Sid; Type = $Type; RightsValue = [int]$r.FileSystemRights
            InheritanceFlags = "$($r.InheritanceFlags)"; PropagationFlags = "$($r.PropagationFlags)"
            NewRights = $NewRights; NewType = $NewType
        }
    }
    function script:Get-ExplicitRule {
        param($Acl, [string]$Sid)
        @($Acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $Sid })
    }
    function script:Get-WorkArgs {
        # The work block's arguments, in its parameter order.
        param([string]$Path, [hashtable]$Entry, [string]$LogFolder, [bool]$WhatIf = $false)
        @([string[]]@($Path), $Entry.Sid, $Entry.Type, [int]$Entry.RightsValue, "$($Entry.InheritanceFlags)", "$($Entry.PropagationFlags)",
            $Entry.NewRights, $Entry.NewType, $LogFolder, $WhatIf, $null)
    }
    function script:Test-RuleBits {
        param($Rule, [int]$Mask)
        (([int]$Rule.FileSystemRights -band $script:NoSync) -band ($Mask -band $script:NoSync)) -eq ($Mask -band $script:NoSync)
    }
}


Describe 'FolderPermissionManager: change a permission in place (SQ-025)' {
    BeforeEach {
        # The fake file system: Get-Acl hands out SDDL-built objects (or the ACL Set-Acl was last given);
        # Set-Acl records and applies. Backstops for everything else that could write.
        $script:Sddls = @{}
        $script:Applied = @{}
        $script:SetAclCalls = [System.Collections.Generic.List[object]]::new()
        $script:SetAclThrow = $null
        $script:AtSetAcl = $null
        $script:LogDirForSetAcl = $null
        $script:GetAclFailsAfterSetAcl = $false
        $script:SetAclDone = $false
        $script:AclThrowFor = @{}
        $script:AllowSetAcl = $false
        $script:BackstopHit = [System.Collections.Generic.List[string]]::new()
        Mock Get-Acl {
            $p = "$LiteralPath"
            if ($script:AclThrowFor.ContainsKey($p)) { throw $script:AclThrowFor[$p] }
            if ($script:GetAclFailsAfterSetAcl -and $script:SetAclDone) { throw 'the permissions cannot be read now (test)' }
            if ($script:Applied.ContainsKey($p)) { return $script:Applied[$p] }
            $isFile = Test-Path -LiteralPath $p -PathType Leaf
            $sddl = if ($script:Sddls.ContainsKey($p)) { $script:Sddls[$p] } else { 'O:BAG:SYD:' }
            New-AclFromSddl $sddl -File:$isFile
        }
        Mock Set-Acl {
            $p = "$LiteralPath"
            $at = if ($script:LogDirForSetAcl) { Get-AllLogTextIn $script:LogDirForSetAcl } else { '' }
            $script:SetAclCalls.Add([PSCustomObject]@{ Path = $p; Acl = $AclObject; LogAndBackups = $at })
            if ($script:SetAclThrow) { throw $script:SetAclThrow }
            $script:SetAclDone = $true
            $script:Applied[$p] = $AclObject
        }
        Mock Invoke-AclTool { $script:BackstopHit.Add('Invoke-AclTool'); throw 'Invoke-AclTool was reached without a test mock.' }
        Mock takeown { $script:BackstopHit.Add('takeown'); throw 'takeown was reached.' }
        Mock icacls { $script:BackstopHit.Add('icacls'); throw 'icacls was reached.' }

        $script:Shown = [System.Collections.Generic.List[string]]::new()
        $script:Status = [System.Collections.Generic.List[object]]::new()
        $script:Confirms = [System.Collections.Generic.List[object]]::new()
        $script:ConfirmAnswer = $true
        $script:Captured = $null
        $script:Dialogs = [System.Collections.Generic.List[object]]::new()
        $script:DialogAnswer = $null
        $script:Reads = [System.Collections.Generic.List[object]]::new()
        Mock Show-AppMessage { $script:Shown.Add($Message) }
        Mock Show-AppQuestion { $false }
        Mock Set-Status { $script:Status.Add([PSCustomObject]@{ Text = $Text; Kind = $Kind }) }
        Mock Show-ConfirmDialog { $script:Confirms.Add($Spec); $script:ConfirmAnswer }
        Mock Show-ChangePermissionDialog { $script:Dialogs.Add($Model); $script:DialogAnswer }
        Mock Get-AppDfsTarget { $null }
        Mock Get-ThisComputerNames { @('TESTPC', 'testpc.contoso.com') }
        Mock Test-Path { $false } -ParameterFilter { "$LiteralPath" -like '\\*' -or "$Path" -like '\\*' }
        Mock Update-CurrentFolder { }
        Mock Update-FileSelection { }
        Mock Reset-FolderNode { }
        Mock Select-Folder { }
        Mock Start-ChangeTask { $script:Captured = @{ Action = $Action; Path = $Path; Work = $Work; ArgumentList = $ArgumentList; OnDone = $OnDone; State = $State }; $true }
        Mock Start-ReadTask { $script:Reads.Add(@{ Action = $Action; Path = $Path; Work = $Work; ArgumentList = $ArgumentList; OnDone = $OnDone; State = $State }) }
        Mock Get-AppReparseInfo { [PSCustomObject]@{ Exists = $true; IsReparsePoint = $false; Tag = $null } }
        Mock Get-RemoteShareLocalPath { "D:\Shares\$Share" }
        Mock Get-AppProfilesDirectory { 'C:\Users' }
        Mock Get-RelaunchFileSize { $null }
        Mock Get-Win32PathName { $Path }
        # The seam for the real token: the tech is in Everyone and Users only, unless a test says otherwise.
        $script:MySids = [PSCustomObject]@{ UserSid = 'S-1-5-21-9-9-9-1001'; GroupSid = @('S-1-1-0', 'S-1-5-32-545') }
        Mock Get-CurrentIdentitySids { $script:MySids }

        $script:WhatIfMode = $false
        $script:ChangeTask = $null
        $script:ChangePending = $null
        $script:CurrentNode = $null
        $script:UI = New-FakeChangeUi
        $script:ChangeLogFolder = Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N'))
        $script:MappedDrives = @{}
        $script:MappedDriveSources = @{}
        $script:SelectedRows = @()
        $script:FileAclCache = @{}
        $script:FileAclPending = @{}
        Mock Get-SelectedFileRows { $script:SelectedRows }
        $folder = New-Folder 'Data'
        $script:Current = [PSCustomObject]@{ DisplayPath = $folder; RealPath = $folder }
        $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Path = $folder; Owner = 'x'; Rows = @(Get-AclRows $script:SddlAC1); Error = $null }
    }

    AfterEach {
        @($script:BackstopHit) | Should -BeNullOrEmpty -Because 'no test may reach a real write'
        if (-not $script:AllowSetAcl) { $script:SetAclCalls.Count | Should -Be 0 -Because 'this test must not write an ACL' }
    }

    Describe 'Rows and dialog' {
        It 'AC1_RowCarriesEntryKey' {
            $rows = Get-AclRows $script:SddlAC1
            $rows.Count | Should -Be 3
            $deny = $rows[0]; $modify = $rows[1]; $inherited = $rows[2]
            $modify.Sid | Should -Be $script:BU
            $modify.RightsValue | Should -BeOfType [int]
            $modify.RightsValue | Should -Be 0x1301bf
            "$($modify.InheritanceFlags)" | Should -Be 'ContainerInherit, ObjectInherit'
            "$($modify.PropagationFlags)" | Should -Be 'None'
            $modify.AppliesTo | Should -Be $script:FullText
            $deny.Sid | Should -Be $script:BU
            $deny.RightsValue | Should -Be 0x116
            "$($deny.InheritanceFlags)" | Should -Be 'None'
            $deny.AppliesTo | Should -Be 'This folder only'
            $inherited.Sid | Should -Be $script:SY
            $inherited.IsInherited | Should -BeTrue
            $inherited.RightsValue | Should -Be 0x1200a9
            # The existing columns are unchanged (SQ-017 AC19).
            $modify.Identity | Should -Be 'BUILTIN\Users'
            $modify.Type | Should -Be 'Allow'
            $modify.PermissionLevel | Should -Be 'Modify'
            $modify.IsInherited | Should -BeFalse
            $modify.InheritedText | Should -Be ''
            $inherited.InheritedText | Should -Be 'Inherited'
            $modify.PSObject.Properties.Name | Should -Contain 'Rights'
        }

        It 'AC2_AppliesToText' {
            $cases = @(
                ,@('Folder', 'None', 'None', 'This folder only')
                ,@('Folder', 'ContainerInherit, ObjectInherit', 'None', 'This folder, subfolders and files')
                ,@('Folder', 'ContainerInherit', 'None', 'This folder and subfolders')
                ,@('Folder', 'ObjectInherit', 'None', 'This folder and files')
                ,@('Folder', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Subfolders and files only')
                ,@('Folder', 'ContainerInherit', 'InheritOnly', 'Subfolders only')
                ,@('Folder', 'ObjectInherit', 'InheritOnly', 'Files only')
                ,@('Folder', 'ContainerInherit, ObjectInherit', 'NoPropagateInherit', 'This folder, subfolders and files (one level down only)')
                ,@('Folder', 'ContainerInherit', 'NoPropagateInherit', 'This folder and subfolders (one level down only)')
                ,@('Folder', 'ObjectInherit', 'NoPropagateInherit', 'This folder and files (one level down only)')
                ,@('File', 'None', 'None', 'This file only')
            )
            foreach ($c in $cases) {
                Format-AppliesTo -ItemType $c[0] -InheritanceFlags $c[1] -PropagationFlags $c[2] | Should -Be $c[3] -Because "$($c[0]) $($c[1]) / $($c[2])"
            }
            $both = 'InheritOnly, NoPropagateInherit'
            Format-AppliesTo -ItemType Folder -InheritanceFlags 'ContainerInherit, ObjectInherit' -PropagationFlags $both |
                Should -Be 'Subfolders and files only (one level down only)'
        }

        It 'AC3_ChangeButtonState' {
            $rows = Get-AclRows $script:SddlAC1
            $explicit = $rows[1]; $inherited = $rows[2]

            $none = Get-ChangePermissionState -Row $null
            $none.Enabled | Should -BeFalse
            $none.ToolTip | Should -Be 'Select a permission in the list first.'

            $edit = Get-ChangePermissionState -Row $explicit
            $edit.Enabled | Should -BeTrue
            $edit.Mode | Should -Be 'Edit'

            $inh = Get-ChangePermissionState -Row $inherited
            $inh.Enabled | Should -BeTrue
            $inh.Mode | Should -Be 'Inherited'

            $script:ChangeTask = [PSCustomObject]@{ Path = 'D:\Data\HR' }
            $busy = Get-ChangePermissionState -Row $explicit
            $busy.Enabled | Should -BeFalse -Because "SQ-018's one-change rule"
            $busy.ToolTip | Should -Match 'A change is running on D:\\Data\\HR'
            $script:ChangeTask = $null

            $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $false; Path = $script:Current.RealPath; Rows = @(); Error = 'denied' }
            $failed = Get-ChangePermissionState -Row $explicit
            $failed.Enabled | Should -BeFalse
            $failed.ToolTip | Should -Not -BeNullOrEmpty

            'ChangePermissionBtn' | Should -BeIn @(Get-ChangeControlNames) -Because 'it is switched off while a change runs'
            'ChangeFilePermissionBtn' | Should -BeIn @(Get-ChangeControlNames)
        }

        It 'AC4_DoubleClickOpensChange' {
            $row = (Get-AclRows $script:SddlAC1)[1]
            $script:R = $row
            Mock Open-ChangePermission { }
            Invoke-AclRowDoubleClick -Row $row
            Should -Invoke Open-ChangePermission -Times 1 -Exactly -ParameterFilter { [object]::ReferenceEquals($Row, $script:R) }

            Invoke-AclRowDoubleClick -Row $null
            Should -Invoke Open-ChangePermission -Times 1 -Exactly -Because 'a double-click on the header, empty space or a scroll bar has no row'

            $script:ChangeTask = [PSCustomObject]@{ Path = 'D:\Data\HR' }
            Invoke-AclRowDoubleClick -Row $row
            Should -Invoke Open-ChangePermission -Times 1 -Exactly -Because 'a change is running'
            (Get-LastStatus).Text | Should -Be 'Another change is still running on D:\Data\HR. Wait for it to finish.'
            $script:ChangeTask = $null

            $init = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Initialize-PermissionWindow' }, $true))[0]
            $init | Should -Not -BeNullOrEmpty
            $wire = @($init.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                        $n.Expression.Extent.Text -eq '$ui.FolderAclGrid' -and $n.Member.Extent.Text -eq 'Add_MouseDoubleClick' }, $true))
            $wire.Count | Should -Be 1 -Because 'FolderAclGrid registers MouseDoubleClick'
            $called = @($wire[0].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
            $called | Should -Contain 'Invoke-AclRowDoubleClick'
        }

        It 'AC5_DialogPrefilled' {
            $rows = Get-AclRows $script:SddlAC1
            $m = Get-ChangeDialogModel -Row $rows[1] -AllRows $rows -Path 'D:\Data\HR'
            $m.Title | Should -Be 'Change Permission Entry'
            $m.AccountText | Should -Be 'BUILTIN\Users'
            $m.Level | Should -Be 'Modify'
            $m.Type | Should -Be 'Allow'
            $m.AppliesTo | Should -Be $script:FullText
            $m.SubmitLabel | Should -Be 'Change Permission'
            [object]::ReferenceEquals($m.Row, $rows[1]) | Should -BeTrue

            $xaml = Get-PermissionDialogXaml -Mode Change
            $x = [xml]$xaml
            $account = $x.SelectSingleNode("//*[@*[local-name()='Name' and .='PermAccountText']]")
            $account | Should -Not -BeNullOrEmpty -Because 'the Change dialog shows the account in PermAccountText'
            $account.GetAttribute('IsReadOnly') | Should -Be 'True'
        }

        It 'AC6_NonStandardLevel' {
            $standard = 'FullControl', 'Modify', 'ReadAndExecute', 'Read', 'Write'
            $mix = Get-AclRows 'O:BAG:SYD:(A;OICI;0x1301ff;;;BU)'
            $mix[0].PermissionLevel | Should -Be 'DeleteSubdirectoriesAndFiles, Modify'
            $m = Get-ChangeDialogModel -Row $mix[0] -AllRows $mix -Path 'D:\Data'
            @($m.LevelChoices).Count | Should -Be 6
            $m.LevelChoices[0].Tag | Should -Be 'Current'
            $m.LevelChoices[0].Label | Should -Be 'Keep current (DeleteSubdirectoriesAndFiles, Modify)'
            $m.Level | Should -Be 'Current' -Because 'Keep current is preselected'
            (@($m.LevelChoices | Select-Object -Skip 1 | ForEach-Object { $_.Tag }) -join ',') | Should -Be ($standard -join ',')

            foreach ($sddl in 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)', 'O:BAG:SYD:(A;OICI;0x301bf;;;BU)') {
                $rows = Get-AclRows $sddl
                $std = Get-ChangeDialogModel -Row $rows[0] -AllRows $rows -Path 'D:\Data'
                @($std.LevelChoices).Count | Should -Be 5
                @($std.LevelChoices | Where-Object { $_.Tag -eq 'Current' }).Count | Should -Be 0
                $std.Level | Should -Be 'Modify'
            }

            $generic = Get-AclRows 'O:BAG:SYD:(A;OICIIO;GA;;;CO)'
            $g = Get-ChangeDialogModel -Row $generic[0] -AllRows $generic -Path 'D:\Data'
            $g.LevelChoices[0].Tag | Should -Be 'Current'
            $g.LevelChoices[0].Label | Should -Be 'Keep current (Full control)'
        }

        It 'AC7_OtherEntriesNote' {
            $rows = Get-AclRows $script:SddlAC1
            $one = Get-ChangeDialogModel -Row $rows[1] -AllRows $rows -Path 'D:\Data'
            $one.Note | Should -Be 'BUILTIN\Users has 1 other permission entry set on this folder. Only the selected one is changed.'

            $three = Get-AclRows 'O:BAG:SYD:(D;;0x116;;;BU)(A;OICI;0x1301bf;;;BU)(A;;0x120089;;;BU)(A;ID;0x1200a9;;;SY)'
            $two = Get-ChangeDialogModel -Row $three[1] -AllRows $three -Path 'D:\Data'
            $two.Note | Should -Be 'BUILTIN\Users has 2 other permission entries set on this folder. Only the selected one is changed.'

            $alone = Get-AclRows 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;SY)'
            $none = Get-ChangeDialogModel -Row $alone[0] -AllRows $alone -Path 'D:\Data'
            $none.Note | Should -BeNullOrEmpty -Because 'an inherited entry for the same account is not counted'
        }

        It 'AC8_NothingToChange' {
            $rows = Get-AclRows $script:SddlAC1
            $m = Get-ChangeDialogModel -Row $rows[1] -AllRows $rows -Path 'D:\Data'
            $a = Get-ChangeDialogAnswer -Model $m -Level 'Modify' -Type 'Allow'
            $a.Ok | Should -BeFalse
            $a.Problem | Should -Be 'Nothing to change yet: choose a different permission level or Allow/Deny.'
            $changed = Get-ChangeDialogAnswer -Model $m -Level 'Read' -Type 'Allow'
            $changed.Ok | Should -BeTrue
            $changed.Answer.Level | Should -Be 'Read'
            $changed.Answer.Type | Should -Be 'Allow'
            $flip = Get-ChangeDialogAnswer -Model $m -Level 'Modify' -Type 'Deny'
            $flip.Ok | Should -BeTrue

            # Open-ChangePermission does not start a change when the dialog hands nothing back.
            $script:DialogAnswer = $null
            Open-ChangePermission -Scope Folder -Row $rows[1]
            $r = $script:Reads[0]
            & $r.OnDone ([PSCustomObject]@{ Ok = $true; Targets = @(New-FakeTarget -Display $script:Current.DisplayPath); Refusal = $null }) $r.State
            Should -Invoke Start-ChangeTask -Times 0 -Exactly
        }

        It 'AC9_InheritedEntrySource' {
            $p = Join-Path $TestDrive 'P'
            $child = Join-Path $p 'C'
            $inheritedSddl = 'O:BAG:SYD:AI(A;ID;0x1200a9;;;BU)'
            $script:Sddls[$p] = 'O:BAG:SYD:(A;OICI;0x1200a9;;;BU)'
            $script:Sddls[$child] = $inheritedSddl
            $row = (Get-AclRows $inheritedSddl)[0]
            $row.IsInherited | Should -BeTrue

            $found = Find-InheritanceSource -Path $child -Row $row
            $found.Source | Should -Be $p
            $found.Error | Should -BeNullOrEmpty

            $m = Get-ChangeDialogModel -Row $row -AllRows @($row) -Path $child -Source $found
            $m.Mode | Should -Be 'Inherited'
            $m.Message | Should -Be "BUILTIN\Users gets Allow Read & execute here from $p. To change it, open that folder."
            $m.ShowSubmit | Should -BeFalse

            # A parent that cannot be read.
            $script:AclThrowFor[$p] = 'boom (test)'
            $bad = Find-InheritanceSource -Path $child -Row $row
            $bad.Source | Should -BeNullOrEmpty
            $bad.Error | Should -Match 'boom \(test\)'
            $mBad = Get-ChangeDialogModel -Row $row -AllRows @($row) -Path $child -Source $bad
            $mBad.Message | Should -BeLike 'BUILTIN\Users gets Allow Read & execute here from a folder above this one. The tool could not check which (*boom (test)*).'
            $script:AclThrowFor.Clear()

            # No folder up to the drive root has it.
            $script:Sddls.Remove($p)
            $none = Find-InheritanceSource -Path $child -Row $row
            $none.Source | Should -BeNullOrEmpty
            $none.Error | Should -BeNullOrEmpty
            $none.Root | Should -Not -BeNullOrEmpty
            $mNone = Get-ChangeDialogModel -Row $row -AllRows @($row) -Path $child -Source $none
            $mNone.Message | Should -Be "BUILTIN\Users gets Allow Read & execute here from above $($none.Root) (on the server, or the folder above no longer has it)."

            # The lookup runs as a background read task, and a result for another selection is ignored.
            $script:Current = [PSCustomObject]@{ DisplayPath = $child; RealPath = $child }
            $script:UI['FolderAclGrid'] = [PSCustomObject]@{ SelectedItem = $row }
            Open-ChangePermission -Scope Folder -Row $row
            $script:Reads.Count | Should -Be 1
            $script:Reads[0].Work.ToString() | Should -Be $script:InheritanceSourceWork.ToString()
            $script:UI['FolderAclGrid'].SelectedItem = $null
            & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Source = $p; Root = $null; Error = $null }) $script:Reads[0].State
            $script:Dialogs.Count | Should -Be 0 -Because 'the selection changed while the lookup ran'
            $script:Reads.Clear()
            $script:UI['FolderAclGrid'].SelectedItem = $row
            Open-ChangePermission -Scope Folder -Row $row
            & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Source = $p; Root = $null; Error = $null }) $script:Reads[0].State
            $script:Dialogs.Count | Should -Be 1
            $script:Dialogs[0].Message | Should -BeLike "*from $p. To change it, open that folder."
        }
    }

    Describe 'The change itself (core)' {
        BeforeEach {
            $script:Dir = New-Folder 'cp'
            # A log folder per test: TestDrive keeps files across the It blocks of this Describe.
            $script:Log = Join-Path $TestDrive ('cp-logs-' + [guid]::NewGuid().ToString('N'))
            $script:AllowSetAcl = $true
        }

        It 'AC10_OneWriteReplacesEntry' {
            (New-AclFromSddl $script:SddlAC1).AreAccessRulesCanonical | Should -BeTrue -Because 'the fixture is canonical'
            $script:Sddls[$script:Dir] = $script:SddlAC1
            $e = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)

            $script:SetAclCalls.Count | Should -Be 1
            $acl = $script:SetAclCalls[0].Acl
            $bu = Get-ExplicitRule $acl $script:BU
            @($bu | Where-Object { "$($_.AccessControlType)" -eq 'Allow' }).Count | Should -Be 0 -Because 'the Allow Modify entry is gone'
            $deny = @($bu | Where-Object { "$($_.AccessControlType)" -eq 'Deny' })
            @($deny | Where-Object { (Test-RuleBits $_ $script:RightsModify) -and "$($_.InheritanceFlags)" -eq 'ContainerInherit, ObjectInherit' -and "$($_.PropagationFlags)" -eq 'None' }).Count |
                Should -Be 1 -Because 'a Deny Modify (CI,OI) replaces it'
            @($deny | Where-Object { ([int]$_.FileSystemRights) -eq 0x116 -and "$($_.InheritanceFlags)" -eq 'None' }).Count | Should -Be 1 -Because 'the Deny Write is unchanged'
            @($bu).Count | Should -Be 2
            $sy = @($acl.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $script:SY })
            $sy.Count | Should -Be 1 -Because 'the inherited entry is unchanged'
            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Done'
            $rows[0].Action | Should -Be 'Change permission'
        }

        It 'AC11_KeepsAppliesTo' {
            $cases = @(
                @{ Sddl = 'O:BAG:SYD:(A;;0x1301bf;;;BU)'; Inh = 'None'; Prop = 'None'; File = $false }
                @{ Sddl = 'O:BAG:SYD:(A;OIIO;0x1301bf;;;BU)'; Inh = 'ObjectInherit'; Prop = 'InheritOnly'; File = $false }
                @{ Sddl = 'O:BAG:SYD:(A;CINP;0x1301bf;;;BU)'; Inh = 'ContainerInherit'; Prop = 'NoPropagateInherit'; File = $false }
                @{ Sddl = 'O:BAG:SYD:(A;;0x1301bf;;;BU)'; Inh = 'None'; Prop = 'None'; File = $true }
            )
            $n = 0
            foreach ($c in $cases) {
                $n++
                $path = if ($c.File) { New-File $script:Dir "f$n.txt" } else { New-Folder "cp11-$n" }
                $script:Sddls[$path] = $c.Sddl
                $script:SetAclCalls.Clear()
                $e = Get-EntryArgs -Sddl $c.Sddl -Sid $script:BU -Type Allow -NewRights Read -NewType Allow -File:$c.File
                $rows = @(Set-FolderPermissionEntry -Path $path @e -LogFolder $script:Log -Confirm:$false)
                $rows[0].Result | Should -Be 'Done' -Because "case $n"
                $script:SetAclCalls.Count | Should -Be 1
                $bu = Get-ExplicitRule $script:SetAclCalls[0].Acl $script:BU
                @($bu).Count | Should -Be 1
                Test-RuleBits $bu[0] $script:RightsRead | Should -BeTrue
                "$($bu[0].InheritanceFlags)" | Should -Be $c.Inh -Because "case $n keeps the inheritance flags (not the default CI,OI)"
                "$($bu[0].PropagationFlags)" | Should -Be $c.Prop -Because "case $n keeps the propagation flags"
            }
        }

        It 'AC12_OnlyTheChosenEntry' {
            $sddl = 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)(A;;0x100116;;;BU)'
            $script:Sddls[$script:Dir] = $sddl
            $e = Get-EntryArgs -Sddl $sddl -Sid $script:BU -Type Allow -NewRights Read -NewType Allow -Skip 0
            $e.RightsValue | Should -Be 0x1301bf -Because 'the Modify entry is the one chosen'
            [void](Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $script:SetAclCalls.Count | Should -Be 1
            $bu = Get-ExplicitRule $script:SetAclCalls[0].Acl $script:BU
            @($bu | Where-Object { ([int]$_.FileSystemRights -band $script:NoSync) -eq 0x116 -and "$($_.InheritanceFlags)" -eq 'None' }).Count |
                Should -Be 1 -Because 'the Write entry is still there unchanged'
            @($bu | Where-Object { Test-RuleBits $_ $script:RightsModify }).Count | Should -Be 0
            @($bu | Where-Object { (Test-RuleBits $_ $script:RightsRead) -and "$($_.InheritanceFlags)" -eq 'ContainerInherit, ObjectInherit' }).Count | Should -BeGreaterThan 0
        }

        It 'AC13_KeepCurrentRights' {
            $mixSddl = 'O:BAG:SYD:(A;OICI;0x1301ff;;;BU)'
            $script:Sddls[$script:Dir] = $mixSddl
            $e = Get-EntryArgs -Sddl $mixSddl -Sid $script:BU -Type Allow -NewRights Current -NewType Deny
            [void](Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $bu = Get-ExplicitRule $script:SetAclCalls[0].Acl $script:BU
            $bu.Count | Should -Be 1
            "$($bu[0].AccessControlType)" | Should -Be 'Deny'
            ([int]$bu[0].FileSystemRights -band $script:NoSync) | Should -Be (0x1301ff -band $script:NoSync) -Because 'the exact rights are kept'

            $script:SetAclCalls.Clear(); $script:Applied.Clear()
            $genSddl = 'O:BAG:SYD:(A;OICIIO;GA;;;CO)'
            $dir2 = New-Folder 'cp13b'
            $script:Sddls[$dir2] = $genSddl
            $g = Get-EntryArgs -Sddl $genSddl -Sid $script:CO -Type Allow -NewRights Current -NewType Deny
            [void](Set-FolderPermissionEntry -Path $dir2 @g -LogFolder $script:Log -Confirm:$false)
            $co = Get-ExplicitRule $script:SetAclCalls[0].Acl $script:CO
            $co.Count | Should -Be 1
            "$($co[0].AccessControlType)" | Should -Be 'Deny'
            ([int]$co[0].FileSystemRights -band $script:NoSync) | Should -Be ((ConvertTo-SpecificFileRight ([System.Security.AccessControl.FileSystemRights]'FullControl')) -band $script:NoSync) -Because 'GENERIC_ALL is written as its mapped file rights'
            "$($co[0].PropagationFlags)" | Should -Be 'InheritOnly'
        }

        It 'AC14_EntryGoneNothingWritten' {
            $e = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Read -NewType Allow
            $script:Sddls[$script:Dir] = 'O:BAG:SYD:(D;;0x116;;;BU)(A;ID;0x1200a9;;;SY)'
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $script:SetAclCalls.Count | Should -Be 0
            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Skipped (entry not found)'
            $text = 'The permission entry changed since it was shown (someone else may have changed it). Nothing was changed. Press Refresh and try again.'
            $msg = Get-ChangeResultMessage -Entries $rows -LogPath $null -LogFolder $script:Log
            $msg | Should -BeLike "$text*"
            $status = Get-ChangeStatus -Entries $rows -LogPath $null -Message $msg
            $status.Kind | Should -Be 'Warning'
            $status.Text | Should -BeLike "*$text*"
        }

        It 'AC15_FailedWriteKeepsOldEntry' {
            $script:Sddls[$script:Dir] = $script:SddlAC1
            $script:SetAclThrow = 'Access to the path is denied (test)'
            $e = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $rows.Count | Should -Be 1
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].OldValue | Should -Not -BeNullOrEmpty
            $rows[0].NewValue | Should -Be $rows[0].OldValue -Because 'the permissions read back after the failure are the old ones'
            $rows[0].Error | Should -Match '(?i)nothing was changed'
            $rows[0].BackupFile | Should -Not -BeNullOrEmpty -Because 'the row names the backup file'
            $msg = Get-ChangeResultMessage -Entries $rows -LogPath 'C:\log.csv' -LogFolder $script:Log
            $msg | Should -BeLike "Change permission failed on $([WildcardPattern]::Escape($script:Dir)):*"
        }

        It 'AC16_NonCanonicalRefused' {
            $sddl = 'O:BAG:SYD:(A;;0x1301bf;;;BU)(D;;0x116;;;BU)'
            (New-AclFromSddl $sddl).AreAccessRulesCanonical | Should -BeFalse -Because 'the fixture has a Deny after an Allow'
            $script:Sddls[$script:Dir] = $sddl
            $e = Get-EntryArgs -Sddl $sddl -Sid $script:BU -Type Allow -NewRights Read -NewType Allow
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $script:SetAclCalls.Count | Should -Be 0
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -BeLike "The permissions on $([WildcardPattern]::Escape($script:Dir)) are not in the order Windows expects, so the tool will not edit them. Nothing was changed. Ask a senior admin to check them in Explorer (Advanced Security Settings)*"
        }

        It 'AC17_BackupLogStartedFirst' {
            $script:Sddls[$script:Dir] = $script:SddlAC1
            $script:LogDirForSetAcl = $script:Log
            $e = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny
            $workArgs = @(Get-WorkArgs -Path $script:Dir -Entry $e -LogFolder $script:Log); $result = & $script:ChangePermissionWork @workArgs
            $result.Ok | Should -BeTrue -Because "$($result.Error)"
            $script:SetAclCalls.Count | Should -Be 1
            $before = $script:SetAclCalls[0].LogAndBackups
            $before | Should -Match 'Started' -Because 'the Started log row is written before Set-Acl'
            $before | Should -Match ([regex]::Escape($script:Dir)) -Because 'the backup CSV holds the folder before Set-Acl'
            @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -File).Count | Should -Be 1

            $logFile = @(Get-ChildItem -LiteralPath $script:Log -Filter 'Changes_*.csv')[0]
            $logRows = @(Import-Csv -LiteralPath $logFile.FullName)
            $done = @($logRows | Where-Object { $_.Result -eq 'Done' })
            $done.Count | Should -Be 1
            (($done[0].PSObject.Properties.Name) -join ',') | Should -Be 'Time,Technician,Computer,Action,Target,ItemType,Detail,OldValue,NewValue,Result,Error,BackupFile'
            $done[0].Action | Should -Be 'Change permission'
            $done[0].Detail | Should -Be "From Allow Modify to Deny Modify for BUILTIN\Users (applies to: $script:FullText)"
            $done[0].OldValue | Should -Match '^O:'
            $done[0].NewValue | Should -Match '^O:'
            $done[0].NewValue | Should -Not -Be $done[0].OldValue

            # A backup that cannot be written: nothing is written to the ACL.
            $script:SetAclCalls.Clear(); $script:Applied.Clear()
            $blocker = New-File $script:Dir 'blocker.txt'
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder (Join-Path $blocker 'logs') -Confirm:$false)
            $script:SetAclCalls.Count | Should -Be 0
            $rows[0].Result | Should -Be 'Failed'
            $rows[0].Error | Should -BeLike 'Could not save a backup of the current permissions*Nothing was changed.'
        }

        It 'AC18_ActsOnSid' {
            $sddl = "O:BAG:SYD:(A;OICI;0x1301bf;;;$($script:Orphan))"
            $row = (Get-AclRows $sddl)[0]
            $row.Sid | Should -Be $script:Orphan
            $m = Get-ChangeDialogModel -Row $row -AllRows @($row) -Path 'D:\Data'
            $m.AccountText | Should -Be $script:Orphan
            $m.AccountNote | Should -Be "Windows can't look up this account from here (it may be deleted, or local to the server)"

            # The rules are built from the SID: no name lookup at all.
            Mock New-PermissionRule { throw 'the rule was built from a name' }
            Mock ConvertTo-IdentitySid { throw 'the name was translated again' }
            $script:Sddls[$script:Dir] = $sddl
            $e = Get-EntryArgs -Sddl $sddl -Sid $script:Orphan -Type Allow -NewRights Modify -NewType Deny
            $rows = @(Set-FolderPermissionEntry -Path $script:Dir @e -LogFolder $script:Log -Confirm:$false)
            $rows[0].Result | Should -Be 'Done' -Because "$($rows[0].Error)"
            $acl = $script:SetAclCalls[0].Acl
            $rules = Get-ExplicitRule $acl $script:Orphan
            @($rules | Where-Object { "$($_.AccessControlType)" -eq 'Allow' }).Count | Should -Be 0 -Because 'the removed rule carried that SID'
            @($rules | Where-Object { "$($_.AccessControlType)" -eq 'Deny' }).Count | Should -Be 1 -Because 'the new rule carries that SID'

            # A translatable account: still built from the SID.
            $script:SetAclCalls.Clear(); $script:Applied.Clear()
            $dir2 = New-Folder 'cp18b'
            $script:Sddls[$dir2] = $script:SddlAC1
            $e2 = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Read -NewType Allow
            $rows2 = @(Set-FolderPermissionEntry -Path $dir2 @e2 -LogFolder $script:Log -Confirm:$false)
            $rows2[0].Result | Should -Be 'Done' -Because "$($rows2[0].Error)"
            Should -Invoke New-PermissionRule -Times 0 -Exactly
            Should -Invoke ConvertTo-IdentitySid -Times 0 -Exactly
        }
    }

    Describe 'Safety, confirm, results' {
        It 'AC19_DenyConfirm' {
            $btn = [PSCustomObject]@{ Style = $null; IsDefault = $true; Content = $null }
            Set-PermissionSubmitStyle -Mode Change -Type Deny -Button $btn -DangerStyle 'DANGER' -NormalStyle 'NORMAL'
            $btn.Style | Should -Be 'DANGER'
            $btn.Content | Should -Be 'Change to Deny'
            $btn.IsDefault | Should -BeFalse
            Set-PermissionSubmitStyle -Mode Change -Type Allow -Button $btn -DangerStyle 'DANGER' -NormalStyle 'NORMAL'
            $btn.Style | Should -Be 'NORMAL'
            $btn.Content | Should -Be 'Change Permission'

            $target = New-FakeTarget -Display 'H:\Data\HR' -Resolved '\\fs02\real\Data\HR'
            $change = [PSCustomObject]@{ Identity = 'BUILTIN\Users'; From = 'Allow Modify'; To = 'Deny Modify'; AppliesTo = $script:FullText }
            $spec = Get-ConfirmSpec -Action ChangePermission -Targets @($target) -Type Deny -Change $change
            $spec.IsDestructive | Should -BeTrue
            $spec.Title | Should -Be 'Change to Deny?'
            $spec.ActionLabel | Should -Be 'Change to Deny'
            $spec.Body | Should -Match ([regex]::Escape('BUILTIN\Users'))
            $spec.Body | Should -Match ([regex]::Escape('From: Allow Modify'))
            $spec.Body | Should -Match ([regex]::Escape('To: Deny Modify'))
            $spec.Body | Should -Match ([regex]::Escape("Applies to: $script:FullText"))
            $spec.Body | Should -Match ([regex]::Escape('H:\Data\HR'))
            $spec.Body | Should -Match ([regex]::Escape('\\fs02\real\Data\HR')) -Because 'the real location'
            $spec.Body | Should -Match 'A Deny blocks access even where another permission on the same folder allows it'

            $action = [PSCustomObject]@{ Content = $null; Style = $null; IsDefault = $true }
            Set-ConfirmDialog -Spec $spec -TitleBlock ([PSCustomObject]@{ Text = '' }) -BodyBox ([PSCustomObject]@{ Text = '' }) -ActionButton $action -DangerStyle 'DANGER' -NormalStyle 'NORMAL'
            $action.Content | Should -Be 'Change to Deny'
            $action.Style | Should -Be 'DANGER'
            $action.IsDefault | Should -BeFalse -Because 'Cancel stays the default'
        }

        It 'AC20_WhenToConfirm' {
            $mod = $script:RightsModify
            $full = [int][System.Security.AccessControl.FileSystemRights]'FullControl'
            $mix = 0x1301ff
            Test-ChangeTakesAccessAway -OldType Allow -OldRightsValue $mod -NewType Deny -NewRights Modify | Should -BeTrue
            Test-ChangeTakesAccessAway -OldType Allow -OldRightsValue $mod -NewType Allow -NewRights Read | Should -BeTrue
            Test-ChangeTakesAccessAway -OldType Allow -OldRightsValue $full -NewType Allow -NewRights Modify | Should -BeTrue
            Test-ChangeTakesAccessAway -OldType Allow -OldRightsValue $mix -NewType Allow -NewRights Read | Should -BeTrue
            Test-ChangeTakesAccessAway -OldType Allow -OldRightsValue $script:RightsRead -NewType Allow -NewRights Modify | Should -BeFalse
            Test-ChangeTakesAccessAway -OldType Deny -OldRightsValue $mod -NewType Allow -NewRights Modify | Should -BeFalse

            $target = New-FakeTarget -Display $script:Current.DisplayPath
            $sddl = 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)'
            $readSddl = 'O:BAG:SYD:(A;OICI;0x120089;;;BU)'
            $denySddl = 'O:BAG:SYD:(D;;0x116;;;BU)'
            $run = {
                param($Sddl, $Level, $Type, $Target)
                $script:Confirms.Clear(); $script:Captured = $null
                $row = (Get-AclRows $Sddl)[0]
                Invoke-ChangePermission -Scope Folder -Row $row -Level $Level -Type $Type -Targets @($Target)
            }
            # Lowered Allow: the confirm opens, labelled with a verb, and is destructive.
            & $run $sddl 'Read' 'Allow' $target
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].ActionLabel | Should -Be 'Change Permission'
            $script:Confirms[0].IsDestructive | Should -BeTrue
            # To Deny.
            & $run $sddl 'Modify' 'Deny' $target
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].ActionLabel | Should -Be 'Change to Deny'
            $script:Confirms[0].IsDestructive | Should -BeTrue
            # Only more access: the dialog was the confirmation, no extra confirm.
            & $run $readSddl 'Modify' 'Allow' $target
            $script:Confirms.Count | Should -Be 0
            $script:Captured | Should -Not -BeNullOrEmpty
            # Deny to Allow.
            & $run $denySddl 'Modify' 'Allow' $target
            $script:Confirms.Count | Should -Be 0
            $script:Captured | Should -Not -BeNullOrEmpty
            # A drive root confirms even a harmless change.
            & $run $readSddl 'Modify' 'Allow' (New-FakeTarget -Display 'D:\')
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].IsDestructive | Should -BeTrue
            # Declined: nothing starts.
            $script:ConfirmAnswer = $false
            & $run $sddl 'Read' 'Allow' $target
            $script:Captured | Should -BeNullOrEmpty
        }

        It 'AC21_SelfDenyWarning' {
            $text = 'This Deny also applies to you (you are in BUILTIN\Administrators). You could lose access to this folder, and the tool may not be able to read it back.'
            $user = 'S-1-5-21-9-9-9-1001'
            $groups = @('S-1-1-0', $script:BA)
            Get-SelfDenyWarning -Type Deny -Sid $script:BA -UserSid $user -GroupSid $groups | Should -Be $text
            Get-SelfDenyWarning -Type Deny -Sid $script:BU -UserSid $user -GroupSid $groups | Should -BeNullOrEmpty
            Get-SelfDenyWarning -Type Allow -Sid $script:BA -UserSid $user -GroupSid $groups | Should -BeNullOrEmpty

            $change = [PSCustomObject]@{ Identity = 'BUILTIN\Administrators'; From = 'Allow Modify'; To = 'Deny Modify'; AppliesTo = $script:FullText }
            $spec = Get-ConfirmSpec -Action ChangePermission -Targets @((New-FakeTarget -Display 'D:\Data')) -Type Deny -Change $change -SelfDenyWarning $text
            $spec.Body | Should -Match ([regex]::Escape($text))

            # End to end: the app reads the SIDs through the seam and puts the line in the confirm.
            $script:MySids = [PSCustomObject]@{ UserSid = $user; GroupSid = @($script:BA) }
            $row = (Get-AclRows "O:BAG:SYD:(A;OICI;0x1301bf;;;BA)")[0]
            Invoke-ChangePermission -Scope Folder -Row $row -Level 'Modify' -Type 'Deny' -Targets @((New-FakeTarget -Display $script:Current.DisplayPath))
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].Body | Should -Match ([regex]::Escape('This Deny also applies to you (you are in BUILTIN\Administrators)'))
        }

        It 'AC22_SameTargetChecks' {
            $script:MappedDrives = @{ H = '\\fs01\home' }
            $script:MappedDriveSources = @{ H = 'Live' }
            $script:Current = [PSCustomObject]@{ DisplayPath = 'H:\Data'; RealPath = '\\fs01\home\Data' }
            $row = (Get-AclRows 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)')[0]
            $script:ViewState.FolderPermissions = [PSCustomObject]@{ Ok = $true; Path = '\\fs01\home\Data'; Rows = @($row); Error = $null }

            # A mapped drive: the target is looked up in the background before any dialog or task.
            $script:DialogAnswer = [PSCustomObject]@{ Row = $row; Level = 'Modify'; Type = 'Deny' }
            Open-ChangePermission -Scope Folder -Row $row
            $script:Reads.Count | Should -Be 1
            $script:Reads[0].Work.ToString() | Should -Be $script:ChangeTargetWork.ToString()
            @($script:Reads[0].ArgumentList[0]) | Should -Be @('H:\Data')
            $script:Dialogs.Count | Should -Be 0
            $script:Captured | Should -BeNullOrEmpty
            $real = New-FakeTarget -Display 'H:\Data' -Resolved '\\fs02\real\Data'
            & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @($real); Refusal = $null }) $script:Reads[0].State
            $script:Dialogs.Count | Should -Be 1
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].Body | Should -Match ([regex]::Escape('\\fs02\real\Data')) -Because 'the confirm shows the real location'
            @($script:Captured.ArgumentList[0]) | Should -Be @('\\fs02\real\Data') -Because 'the core gets the resolved path'

            # A DFS path with two targets is refused listing the servers (D-043): no dialog, no task.
            $script:Reads.Clear(); $script:Dialogs.Clear(); $script:Confirms.Clear(); $script:Captured = $null; $script:ChangePending = $null
            Open-ChangePermission -Scope Folder -Row $row
            $refusal = 'H:\Data is a DFS folder with 2 targets (\\fs01\Data and \\fs02\Data), so nothing was changed.'
            & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $false; Targets = @(); Refusal = $refusal }) $script:Reads[0].State
            $script:Shown | Should -Contain $refusal
            $script:Dialogs.Count | Should -Be 0
            $script:Captured | Should -BeNullOrEmpty

            # A remembered mapping: the warning shows in the confirm, even for a change that only adds access.
            $script:Reads.Clear(); $script:Dialogs.Clear(); $script:Confirms.Clear(); $script:Captured = $null; $script:ChangePending = $null
            $script:DialogAnswer = [PSCustomObject]@{ Row = $row; Level = 'FullControl'; Type = 'Allow' }
            Open-ChangePermission -Scope Folder -Row $row
            $remembered = New-FakeTarget -Display 'H:\Data' -Resolved '\\fs02\real\Data' -Remembered $true
            & $script:Reads[0].OnDone ([PSCustomObject]@{ Ok = $true; Targets = @($remembered); Refusal = $null }) $script:Reads[0].State
            $script:Confirms.Count | Should -Be 1
            $script:Confirms[0].Body | Should -Match 'remembered drive mapping'
            @($script:Captured.ArgumentList[0]) | Should -Be @('\\fs02\real\Data')
        }

        It 'AC23_ReadBackAndResult' {
            $dir = New-Folder 'cp23'
            $e = Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny
            $script:AllowSetAcl = $true

            # The change is there when read back: success, with the backup and log paths.
            $script:Sddls[$dir] = $script:SddlAC1
            $log = Join-Path $TestDrive 'cp23-ok'
            $workArgs = @(Get-WorkArgs -Path $dir -Entry $e -LogFolder $log); $r = & $script:ChangePermissionWork @workArgs
            $r.Ok | Should -BeTrue -Because "$($r.Error)"
            $r.Message | Should -BeLike "Changed BUILTIN\Users from Allow Modify to Deny Modify on $([WildcardPattern]::Escape($dir))*"
            $r.Message | Should -Match 'Backed up to .*Backups.* and logged to '
            $ok = Get-ChangeStatus -Entries $r.Entries -LogPath $r.LogPath -Message $r.Message
            $ok.Kind | Should -Be 'Success'

            # The write did not stick (the old entry is still there when read back): items to check.
            $script:Applied.Clear(); $script:SetAclCalls.Clear()
            Mock Set-Acl { $script:SetAclCalls.Add([PSCustomObject]@{ Path = "$LiteralPath"; Acl = $AclObject; LogAndBackups = '' }) }
            $log2 = Join-Path $TestDrive 'cp23-stale'
            $workArgs = @(Get-WorkArgs -Path $dir -Entry $e -LogFolder $log2); $r2 = & $script:ChangePermissionWork @workArgs
            $s2 = Get-ChangeStatus -Entries $r2.Entries -LogPath $r2.LogPath -Message $r2.Message
            $s2.Kind | Should -Be 'Warning'
            $s2.Text | Should -BeLike 'Done, with items to check: *'
            $s2.Text | Should -Match ('Check this: ' + [regex]::Escape($dir) + ' - ')

            # The re-read itself fails.
            $script:Applied.Clear(); $script:SetAclCalls.Clear()
            Mock Set-Acl { $script:SetAclCalls.Add([PSCustomObject]@{ Path = "$LiteralPath"; Acl = $AclObject; LogAndBackups = '' }); $script:SetAclDone = $true }
            $script:GetAclFailsAfterSetAcl = $true
            $script:SetAclDone = $false
            $log3 = Join-Path $TestDrive 'cp23-noread'
            $workArgs = @(Get-WorkArgs -Path $dir -Entry $e -LogFolder $log3); $r3 = & $script:ChangePermissionWork @workArgs
            $s3 = Get-ChangeStatus -Entries $r3.Entries -LogPath $r3.LogPath -Message $r3.Message
            $s3.Text | Should -BeLike 'Done, with items to check: *'
            $s3.Text | Should -Match 'could not read the permissions back'
        }

        It 'AC25_WhatIfEndToEnd' {
            $script:WhatIfMode = $true
            $dir = New-Folder 'cp25'
            $file = New-File $dir 'a.txt'
            $script:Sddls[$dir] = $script:SddlAC1
            $fileSddl = 'O:BAG:SYD:(A;;0x1301bf;;;BU)'
            $script:Sddls[$file] = $fileSddl
            $log = Join-Path $TestDrive 'cp25-logs'
            $cases = @(
                @{ Path = $dir; Entry = (Get-EntryArgs -Sddl $script:SddlAC1 -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny); Applies = $script:FullText }
                @{ Path = $file; Entry = (Get-EntryArgs -Sddl $fileSddl -Sid $script:BU -Type Allow -NewRights Modify -NewType Deny -File); Applies = 'This file only' }
            )
            foreach ($c in $cases) {
                $workArgs = @(Get-WorkArgs -Path $c.Path -Entry $c.Entry -LogFolder $log -WhatIf $true); $r = & $script:ChangePermissionWork @workArgs
                $r.Ok | Should -BeTrue -Because "$($r.Error)"
                @($r.Entries | ForEach-Object { $_.Result }) | Should -Be @('Skipped (WhatIf)')
                $script:SetAclCalls.Count | Should -Be 0
                Test-Path -LiteralPath $log | Should -BeFalse -Because 'a dry run writes no backup and no log'
                $summary = Get-DryRunSummary -Entries $r.Entries
                $summary.Text | Should -Match ([regex]::Escape('BUILTIN\Users'))
                $summary.Text | Should -Match ([regex]::Escape('from Allow Modify to Deny Modify'))
                $summary.Text | Should -Match ([regex]::Escape($c.Applies))
                $summary.Text | Should -Match ([regex]::Escape($c.Path))
                $summary.Text | Should -Match '(?i)nothing was changed'
            }

            # The app passes -WhatIf and -Confirm:$false to the core call explicitly.
            $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Set-FolderPermissionEntry' }, $true))
            $calls.Count | Should -BeGreaterThan 0 -Because 'the change work block calls the core function'
            foreach ($call in $calls) {
                $names = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
                $names | Should -Contain 'WhatIf'
                $names | Should -Contain 'Confirm'
                $confirm = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Confirm' })[0]
                "$($confirm.Argument)" | Should -Be '$false'
            }
        }

        It 'AC26_OnlyThroughChangeGate' {
            $work = @($script:Ast.FindAll({ param($n)
                        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                        $n.Left.VariablePath.UserPath -eq 'script:ChangePermissionWork' }, $true))
            $work.Count | Should -Be 1
            $calls = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Set-FolderPermissionEntry' }, $true))
            $calls.Count | Should -BeGreaterThan 0 -Because 'the change work block calls Set-FolderPermissionEntry'
            foreach ($c in $calls) {
                $inside = $false
                for ($p = $c.Parent; $p; $p = $p.Parent) { if ($work -contains $p) { $inside = $true; break } }
                $inside | Should -BeTrue -Because "line $($c.Extent.StartLineNumber): Set-FolderPermissionEntry must sit inside the change work block"
            }
            $refs = @($script:Ast.FindAll({ param($n)
                        $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'script:ChangePermissionWork' }, $true) |
                    Where-Object { -not ($_.Parent -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Parent.Left -eq $_) })
            $refs.Count | Should -BeGreaterThan 0 -Because 'the block must be passed to Start-ChangeTask'
            foreach ($v in $refs) {
                $cmd = $v.Parent
                while ($cmd -and $cmd -isnot [System.Management.Automation.Language.CommandAst]) { $cmd = $cmd.Parent }
                $cmd | Should -Not -BeNullOrEmpty
                $cmd.GetCommandName() | Should -Be 'Start-ChangeTask' -Because "line $($v.Extent.StartLineNumber): the block may only be passed to Start-ChangeTask"
            }
        }

        It 'AC27_RefreshAfterChange' {
            # A folder change: the refresh state names the folder; the plan reloads its permissions.
            $folder = $script:Current.DisplayPath
            $row = (Get-AclRows 'O:BAG:SYD:(A;OICI;0x1301bf;;;BU)')[0]
            Invoke-ChangePermission -Scope Folder -Row $row -Level 'Read' -Type 'Allow' -Targets @((New-FakeTarget -Display $folder)) -Label $folder
            $script:Captured | Should -Not -BeNullOrEmpty
            $state = $script:Captured.State
            $state.Scope | Should -Be 'Folder'
            $plan = Get-RefreshPlan -Scope $state.Scope -Path $state.Paths[0] -CurrentPath $folder
            $plan.ReloadPermissions | Should -BeTrue
            Invoke-ChangeRefresh -State $state
            Should -Invoke Update-CurrentFolder -Times 1 -Exactly

            # A file change: that file's cached permissions are dropped and reloaded.
            $dir = New-Folder 'cp27'
            $file = New-File $dir 'a.txt'
            $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
            $script:SelectedRows = @([PSCustomObject]@{ Path = $file })
            $fileRows = Get-AclRows 'O:BAG:SYD:(A;;0x1301bf;;;BU)' -File
            $script:FileAclCache = @{ $file = [PSCustomObject]@{ Ok = $true; Path = $file; Rows = $fileRows } }
            $script:Captured = $null
            Invoke-ChangePermission -Scope Files -Row $fileRows[0] -Level 'Read' -Type 'Allow' -Targets @((New-FakeTarget -Display $file))
            $fstate = $script:Captured.State
            $fstate.Scope | Should -Be 'Files'
            @($fstate.ChangedFiles) | Should -Contain $file
            Invoke-ChangeRefresh -State $fstate
            $script:FileAclCache.ContainsKey($file) | Should -BeFalse -Because 'the changed file''s cached permissions are dropped'
            Should -Invoke Update-FileSelection -Times 1 -Exactly -Because 'and it is read again'
        }

        It 'AC28_FilesOneAtATime' {
            $dir = New-Folder 'cp28'
            $f1 = New-File $dir 'a.txt'; $f2 = New-File $dir 'b.txt'
            $script:Current = [PSCustomObject]@{ DisplayPath = $dir; RealPath = $dir }
            $tip = 'Select one file to change one of its permissions.'

            $script:SelectedRows = @()
            $zero = Get-ChangePermissionState -Files
            $zero.Enabled | Should -BeFalse
            $zero.ToolTip | Should -Be $tip

            $script:SelectedRows = @([PSCustomObject]@{ Path = $f1 }, [PSCustomObject]@{ Path = $f2 })
            $two = Get-ChangePermissionState -Files
            $two.Enabled | Should -BeFalse
            $two.ToolTip | Should -Be $tip

            # One file with explicit entries: enabled; the picker lists only its explicit entries.
            $rows = Get-AclRows 'O:BAG:SYD:(D;;0x116;;;BU)(A;;0x1301bf;;;BU)(A;ID;0x1200a9;;;SY)' -File
            $script:SelectedRows = @([PSCustomObject]@{ Path = $f1 })
            $script:FileAclCache = @{ $f1 = [PSCustomObject]@{ Ok = $true; Path = $f1; Rows = $rows } }
            $one = Get-ChangePermissionState -Files
            $one.Enabled | Should -BeTrue
            @($one.Entries).Count | Should -Be 2 -Because 'the inherited entry is not offered'
            @($one.Entries | Where-Object { $_.IsInherited }).Count | Should -Be 0
            $m = Get-ChangeDialogModel -Row $one.Entries[0] -AllRows $rows -Path $f1 -Choices @($one.Entries)
            @($m.Choices).Count | Should -Be 2
            $m.AccountText | Should -Be 'BUILTIN\Users'
            $m.Type | Should -Be 'Deny' -Because 'the rest of the dialog is filled from the first entry'

            # One file with only inherited entries: disabled, and says where to change them.
            $inhRows = Get-AclRows 'O:BAG:SYD:AI(A;ID;0x1200a9;;;SY)' -File
            $script:FileAclCache = @{ $f1 = [PSCustomObject]@{ Ok = $true; Path = $f1; Rows = $inhRows } }
            $inh = Get-ChangePermissionState -Files
            $inh.Enabled | Should -BeFalse
            $inh.ToolTip | Should -Be 'This file only has inherited permissions. Change them on the folder they come from.'

            'ChangeFilePermissionBtn' | Should -BeIn @(Get-ChangeControlNames)
        }

        It 'AC29_Docs' {
            $text = Get-Content -LiteralPath $script:ReadmePath -Raw
            $text | Should -Match '(?i)change a permission|change permission'
            $text | Should -Match '(?i)double-click'
            $text | Should -Match '(?i)applies to'
            $text | Should -Match '(?i)inherited'
            $text | Should -Match '(?i)folder above'
            $text | Should -Match '(?i)deny'
            $text | Should -Match '(?i)one write'
            $text | Should -Match '(?i)backup'
            $text | Should -Match '-WhatIf'
            $text | Should -Match '(?i)one file'
            $text | Should -Match '(?i)(command-line|command line).{0,200}(browser).{0,200}(no change|do not have|does not have|not have a change)|(browser).{0,200}(command-line|command line).{0,200}(no change|do not have|does not have|not have a change)'
        }
    }
}
