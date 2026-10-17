<#
    Tests for the command-line script FolderPermissionManager.ps1 (SQ-014, ACs 19-20; D-010).
    Pester 5, run under pwsh.

    The script is only dot-sourced with -LoadFunctionsOnly (which also loads the core); it is
    never run end to end. Its work lives in Invoke-FolderPermissionCli so the core functions
    can be mocked from here (a mock cannot override a function a running script defines for
    itself). Set-Acl, Invoke-AclTool, Read-Host and the bare takeown/icacls names are mocked.

    Pinned for the implementer:
      Invoke-FolderPermissionCli -Path <dir> [-LogFolder <dir>] [-Force] [-WhatIf] [-Confirm]
        [CmdletBinding(SupportsShouldProcess)]; never throws for a declined prompt.
      Confirmations are asked with Read-Host (as the old script did); 'y'/'Y' means yes, anything
      else means no. Taking ownership asks BEFORE the take-ownership call, and copying the
      top-level permissions to the subfolders asks again on its own. -Force asks nothing.
      -WhatIf never prompts. Changes go through the core (backups and change log).
      The script is #Requires -Version 4.0 or lower. If it adds -RunAsAdministrator, check
      elevation at run time instead: a #Requires -RunAsAdministrator line stops these tests
      (and CI) from loading the script in a normal session.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '..\FolderPermissionManager.ps1') -LoadFunctionsOnly
    # Guard: the real Invoke-AclTool runs takeown.exe and icacls.exe by full path, which the
    # bare 'Mock takeown' / 'Mock icacls' cannot catch. Replaced here (same parameters) so a
    # test that forgets to mock it fails instead of changing real owners.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }
}

Describe 'FolderPermissionManager.ps1 (command line)' {
    BeforeEach {
        $root = Join-Path $TestDrive ('cli-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'sub2') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('cli-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Answers = [System.Collections.Generic.Queue[string]]::new()
        $script:Prompts = [System.Collections.Generic.List[string]]::new()
        $script:Lines = [System.Collections.Generic.List[string]]::new()

        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Read-Host {
            $script:Prompts.Add("$Prompt")
            if ($script:Answers.Count -gt 0) { $script:Answers.Dequeue() } else { 'n' }
        }
        Mock Write-Host { $script:Lines.Add("$Object") }
    }

    It 'AC19_Cli_WhatIf_CallsNoNativeToolAndNoSetAcl' {
        $script:Answers.Enqueue('y'); $script:Answers.Enqueue('y')

        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse -Because 'WhatIf writes no backup'
    }

    It 'AC19_Cli_WhatIfWithForce_CallsNoNativeToolAndNoSetAcl' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force -WhatIf

        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_ConfirmationDeclinedBeforeOwnership_NothingIsChanged' {
        $script:Answers.Enqueue('n')

        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        # Two questions: ownership (declined), then the copy step (default answer: no).
        Should -Invoke Read-Host -Times 2 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse -Because 'nothing was backed up, so nothing was about to change'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -Because 'ownership must not be taken before the user agrees'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_CopyConfirmationDeclined_PermissionsAreNotCopied' {
        $script:Answers.Enqueue('y')   # take ownership: yes
        $script:Answers.Enqueue('n')   # copy permissions to subfolders: no

        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $script:Prompts.Count | Should -BeGreaterOrEqual 2
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        # Ownership was agreed to, so it went through the wrapper (backed up first).
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -ParameterFilter { $Tool -eq 'takeown' } -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_Force_AsksNothingAndTakesOwnershipThroughTheCoreWithABackup' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -ParameterFilter { $Tool -eq 'takeown' } -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_TakeOwnership.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:Log -Filter 'Changes_*.csv').Count | Should -Be 1
    }

    It 'AC19_Cli_HasAHelpBlockAndTheNewSwitches' {
        $help = Get-Help (Join-Path $PSScriptRoot '..\FolderPermissionManager.ps1') -Full
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match 'FolderPermissionManager\.ps1'   # Get-Help falls back to the syntax line when there is no help
        $help.description | Should -Not -BeNullOrEmpty
        @($help.examples.example).Count | Should -BeGreaterThan 0
        $help.alertSet | Should -Not -BeNullOrEmpty -Because '.NOTES is required'
        $names = @($help.parameters.parameter | ForEach-Object { $_.name })
        $names | Should -Contain 'Path'
        $names | Should -Contain 'Force'
        $names | Should -Contain 'LogFolder'
        $names | Should -Contain 'WhatIf'
    }

    # --- Fix round 1 (SQ-014 review) ---------------------------------------------------------

    It 'AC20_Cli_OwnershipDeclinedThenCopyAccepted_CopiesThroughTheCoreWithABackupAndLeavesOwnersAlone' {
        # Fixture (SQ-015): copy only copies the top folder's own rules, and a new $TestDrive
        # folder only inherits, so it gets one rule of its own (in memory, nothing is written).
        $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
        Mock Get-Acl {
            $acl = & $script:RealGetAcl -LiteralPath $LiteralPath
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Users', 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            $acl
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
        $script:Answers.Enqueue('n')   # take ownership: no
        $script:Answers.Enqueue('y')   # copy permissions to subfolders: yes

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -Because 'ownership was declined'
        Should -Invoke Set-Acl -Times 2 -Exactly -Scope It -Because 'one write per subfolder (sub1, sub2), through Copy-FolderPermission'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_CopyPermissions.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_TakeOwnership.csv').Count | Should -Be 0
        @($script:Lines | Where-Object { $_ -like '`[INFO`] Copying permissions (next) does not depend on taking ownership*' }).Count | Should -Be 1
        $log = @(Import-Csv -LiteralPath @(Get-ChildItem -LiteralPath $script:Log -Filter 'Changes_*.csv')[0].FullName)
        @($log | ForEach-Object { $_.Action } | Sort-Object -Unique) | Should -Be @('Copy permissions')
    }

    It 'AC20_Cli_ShowsTheItemCountBeforeAskingAndAsksYesNoWithNoAsTheDefault' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $script:Prompts[0] | Should -Be 'Continue? (y/N)'
        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope.Count | Should -Be 1
        $scope[0] | Should -BeLike "*the owner of 3 item(s): $($script:Dir) and every subfolder and file under it*"
    }

    It 'AC19_Cli_WhatIf_ShowsTheItemCount' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf

        @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes * 3 item(s): *' }).Count | Should -Be 1
        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
    }

    It 'AC18_Cli_FolderThatCannotBeListed_IsAWarningNotAPass' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked -and -not $Recurse }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $result = @($script:Lines | Where-Object { $_ -match '^\[(PASS|WARN|FAIL)\] Took ownership' })
        $result.Count | Should -Be 1
        $result[0] | Should -Match '^\[WARN\] '
        $result[0] | Should -BeLike "*could not be opened ($locked)*cannot be restored from this backup*"
    }

    It 'AC17_Cli_ExitCodeIsOneWhenOwnershipIsPartlyDoneOrFailed' -ForEach @(
        @{ Name = 'partly done'; Takeown = 0; Icacls = 1 }
        @{ Name = 'failed'; Takeown = 1; Icacls = 1 }
    ) {
        $script:Exit = @{ takeown = $Takeown; icacls = $Icacls }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = $script:Exit[$Tool]; Output = 'ERROR: Access is denied.' } }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $code | Should -Be 1
    }

    It 'AC17_Cli_ExitCodeIsZeroWhenDoneDeclinedOrWhatIf' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force | Should -Be 0
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log | Should -Be 0
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf | Should -Be 0
    }

    It 'AC19_Cli_RelativePathWithTrailingBackslash_IsResolvedOnce' {
        Push-Location -LiteralPath (Split-Path -Parent $script:Dir)
        try {
            $null = Invoke-FolderPermissionCli -Path ('.\' + (Split-Path -Leaf $script:Dir) + '\') -LogFolder $script:Log -Force
        } finally { Pop-Location }

        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' -and $Arguments[1] -eq $script:Dir }
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'icacls' -and $Arguments[0] -eq $script:Dir }
    }

    # --- Fix round 2 (SQ-014 review) ---------------------------------------------------------

    It 'AC18_Cli_FolderThatCannotBeListed_WarnsItsPermissionsAreReplacedAndBackedUp_AndExitsOne' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope.Count | Should -Be 1
        $scope[0] | Should -BeLike '*The permissions of the 1 folder(s) that could not be opened are replaced with full control for you (*) only. Their current permissions are backed up first.*'
        $code | Should -Be 1 -Because 'a folder that could not be opened leaves the result incomplete'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_TakeOwnership_Permissions.csv').Count | Should -Be 1
    }

    It 'AC18_Cli_FolderThatCannotBeListedOrRead_WarnsItsPermissionsAreLost' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        Mock Get-Acl { throw 'Attempted to perform an unauthorized operation. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf

        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope[0] | Should -BeLike "*replaced with full control for you (*) only. 0 of them are backed up first; 1 cannot be read, so their current permissions cannot be backed up and are lost: $locked.*"
    }

    It 'AC17_Cli_ExitCodeIsOneWhenOwnersCouldNotBeReadBack' {
        $script:RealGetItemOwner = ${function:Get-ItemOwner}
        $script:ToolsRan = $false
        Mock Invoke-AclTool { $script:ToolsRan = $true; [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Get-ItemOwner {
            if ($script:ToolsRan -and $Path -like '*sub2') { return [PSCustomObject]@{ Owner = 'Could not read'; OwnerSid = '' } }
            & $script:RealGetItemOwner -Path $Path
        }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $code | Should -Be 1
        @($script:Lines | Where-Object { $_ -like '`[WARN`] Took ownership*' }).Count | Should -Be 1
    }

    It 'AC16_Cli_JunctionIsCountedInTheWarningAndTheResultAndIsSkippedByTheCopy' {
        # Fixture (SQ-015): copy only copies the top folder's own rules, and a new $TestDrive
        # folder only inherits, so it gets one rule of its own (in memory, nothing is written).
        $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
        Mock Get-Acl {
            $acl = & $script:RealGetAcl -LiteralPath $LiteralPath
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Users', 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            $acl
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
        $elsewhere = Join-Path $TestDrive ('cli-junction-target-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $elsewhere 'inside') -Force | Out-Null
        $link = Join-Path $script:Dir 'link'
        New-Item -ItemType Junction -Path $link -Target $elsewhere | Out-Null
        $script:SetAclPaths = [System.Collections.Generic.List[string]]::new()
        Mock Set-Acl { $script:SetAclPaths.Add("$LiteralPath") }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $code | Should -Be 1
        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope[0] | Should -BeLike "*It contains 1 junction(s) or symbolic link(s), which are listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them*$link*"
        @($script:Lines | Where-Object { $_ -like '`[WARN`] Took ownership*1 junction(s) or symbolic link(s)*' }).Count | Should -Be 1
        @($script:SetAclPaths | Sort-Object) | Should -Be @((Join-Path $script:Dir 'sub1'), (Join-Path $script:Dir 'sub2')) -Because 'the copy goes to real subfolders only, not into or onto the junction'
        @($script:Lines | Where-Object { $_ -like '`[INFO`] 1 junction(s) or symbolic link(s) are skipped*' }).Count | Should -Be 1
    }

    It 'AC20_Cli_CopyStepListsSubfoldersWithoutRecursingGetChildItem' {
        # Fixture (SQ-015): copy only copies the top folder's own rules, and a new $TestDrive
        # folder only inherits, so it gets one rule of its own (in memory, nothing is written).
        $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
        Mock Get-Acl {
            $acl = & $script:RealGetAcl -LiteralPath $LiteralPath
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Users', 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            $acl
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
        New-Item -ItemType Directory -Path (Join-Path $script:Dir 'sub1\deeper') -Force | Out-Null
        $script:Answers.Enqueue('n')   # take ownership: no
        $script:Answers.Enqueue('y')   # copy: yes
        # Whether Get-ChildItem -Recurse follows links depends on the PowerShell version; the CLI
        # lists each folder on its own (Get-OwnerTreeItem) instead.
        Mock Get-ChildItem { throw 'Get-ChildItem -Recurse must not be used (test)' } -ParameterFilter { $Recurse }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        Should -Invoke Get-ChildItem -Times 0 -Exactly -Scope It -ParameterFilter { $Recurse }
        Should -Invoke Set-Acl -Times 3 -Exactly -Scope It -Because 'sub1, sub1\deeper and sub2'
    }

    It 'AC20_Cli_SaysHowToRecogniseAnInterruptedRunBeforeTakingOwnership' {
        $script:InterruptNoteBeforeTools = $null
        Mock Invoke-AclTool {
            if ($null -eq $script:InterruptNoteBeforeTools) {
                $script:InterruptNoteBeforeTools = @($script:Lines | Where-Object { $_ -like '`[INFO`] If this is interrupted*TakeOwnership.csv*no matching row in the change log*' }).Count -eq 1
            }
            [PSCustomObject]@{ ExitCode = 0; Output = '' }
        }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $script:InterruptNoteBeforeTools | Should -BeTrue
    }

    # --- Fix round 1 (SQ-015 review) ---------------------------------------------------------

    Context 'copy step over subfolders that inherit the top folder''s rule' {
        BeforeEach {
            # The top folder has Allow Modify for Users (S-1-5-32-545) as its own rule; sub1 and
            # sub2 carry it as inherited (ID flag), as Windows puts it there. In memory only.
            $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
            $script:Sddl = @{
                $script:Dir                       = 'O:BAG:SYD:AI(A;OICI;0x1301bf;;;S-1-5-32-545)'
                (Join-Path $script:Dir 'sub1')    = 'O:BAG:SYD:AI(A;OICIID;0x1301bf;;;S-1-5-32-545)'
                (Join-Path $script:Dir 'sub2')    = 'O:BAG:SYD:AI(A;OICIID;0x1301bf;;;S-1-5-32-545)'
            }
            Mock Get-Acl {
                $p = "$LiteralPath"   # -LiteralPath is a string array
                $acl = & $script:RealGetAcl -LiteralPath $p
                if ($script:Sddl.ContainsKey($p)) { $acl.SetSecurityDescriptorSddlForm($script:Sddl[$p]) }
                $acl
            }
            $script:Answers.Enqueue('n')   # take ownership: no
            $script:Answers.Enqueue('y')   # copy: yes
        }

        It 'Review1_Cli_SubfoldersThatInheritTheRule_AreNotWrittenAndTheResultIsInfo' {
            # Regression: each subfolder got the rule again as its own, so removing it from the
            # top folder later left it on every subfolder.
            $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

            $code | Should -Be 0
            Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
            $result = @($script:Lines | Where-Object { $_ -like '*2 folder(s) already had these permissions*' })
            $result.Count | Should -Be 1
            $result[0] | Should -BeLike '`[INFO`] *'
        }

        It 'Review1_Cli_OneSubfolderDoneAndOneUpToDate_IsAPass' {
            $script:Sddl[(Join-Path $script:Dir 'sub2')] = 'O:BAG:SYD:AI'

            $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

            $code | Should -Be 0
            Should -Invoke Set-Acl -Times 1 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq (Join-Path $script:Dir 'sub2') }
            $result = @($script:Lines | Where-Object { $_ -like '*Permissions copied from *' })
            $result.Count | Should -Be 1
            $result[0] | Should -BeLike '`[PASS`] *1 folder(s) already had these permissions*'
        }
    }
}
