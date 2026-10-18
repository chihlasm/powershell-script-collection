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
        $result[0] | Should -BeLike "*Escalate: 1 folder(s) could not be opened, so they were left alone. Not opened: $locked.*cannot be restored from this backup*"
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

    # Fix round 2 pinned /D Y here (permissions replaced with full control, saved to
    # *_TakeOwnership_Permissions.csv); D-034 superseded that: such folders are skipped.
    It 'AC18_Cli_FolderThatCannotBeListed_WarnsItIsSkippedAndLeftAlone_AndExitsOne' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope.Count | Should -Be 1
        $scope[0] | Should -BeLike "*1 folder(s) cannot be opened, so they are skipped and left alone: $locked.*"
        $scope[0] | Should -Not -Match 'full control'
        $code | Should -Be 1 -Because 'a folder that could not be opened leaves the result incomplete'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_TakeOwnership_Permissions.csv').Count | Should -Be 0
    }

    It 'AC18_Cli_FolderThatCannotBeListedOrRead_WarnsItIsSkippedNotThatItsPermissionsAreLost' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        Mock Get-Acl { throw 'Attempted to perform an unauthorized operation. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf

        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope[0] | Should -BeLike "*1 folder(s) cannot be opened, so they are skipped and left alone: $locked.*"
        $scope[0] | Should -Not -Match 'lost'
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

    # --- Revision (SQ-014 review 2026-10-17): D-034 and D-036 -------------------------------
    # Pinned: Invoke-FolderPermissionCli and the script take -AllowSystemFolder. Without it a
    # volume root or a folder under %SystemRoot%, %ProgramFiles%, %ProgramFiles(x86)% or
    # %ProgramData% is refused with a [FAIL] line (naming the path and -AllowSystemFolder) and
    # exit code 1, before any question, snapshot or tool call.

    It 'AC16b_Cli_TakeownRunsWithDNeverDY' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter {
            $Tool -eq 'takeown' -and ($Arguments -join ' ') -eq "/F $($script:Dir) /R /A /D N"
        }
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' -and $Arguments -contains 'Y' }
    }

    It 'AC16c_Cli_FolderThatCannotBeOpened_IsSkippedWarnedWithEscalateAndItsPermissionsAreNeitherSavedNorChanged' {
        $locked = Join-Path $script:Dir 'sub1'
        $script:RealGetItemOwner = ${function:Get-ItemOwner}
        $script:LockedPath = $locked
        $script:ToolsRan = $false
        Mock Invoke-AclTool { $script:ToolsRan = $true; [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:LockedPath }
        # takeown /D N leaves a folder it cannot open alone, so its owner is still the old one.
        Mock Get-ItemOwner {
            if ($script:ToolsRan -and $Path -eq $script:LockedPath) { return [PSCustomObject]@{ Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' } }
            & $script:RealGetItemOwner -Path $Path
        }
        $script:Answers.Enqueue('y')   # take ownership: yes
        $script:Answers.Enqueue('n')   # copy permissions to subfolders: no

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 1
        $result = @($script:Lines | Where-Object { $_ -match '^\[WARN\] Partly done' })
        $result.Count | Should -Be 1
        $result[0] | Should -Match ([regex]::Escape('Escalate: 1 folder(s) could not be opened, so they were left alone.'))
        $result[0] | Should -Match ([regex]::Escape($locked))
        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope.Count | Should -Be 1
        $scope[0] | Should -Match 'cannot be opened'
        $scope[0] | Should -Match '(?i)skipped|left alone'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_Permissions.csv').Count | Should -Be 0
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC16c_Cli_NoWarningSaysPermissionsAreReplacedWithFullControl' {
        $locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $locked }
        Mock Get-Acl { throw 'Attempted to perform an unauthorized operation. (test)' } -ParameterFilter { $LiteralPath -eq $locked }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        @($script:Lines | Where-Object { $_ -match 'full control for you|replaced with full control|cannot be backed up and are lost|backed up first\.$' }).Count | Should -Be 0
    }

    It 'AC16d_Cli_VolumeRoot_IsRefusedWithAFailLineAndNothingIsDone' {
        $root = [System.IO.Path]::GetPathRoot($TestDrive)
        # If the refusal is missing, these keep the test from walking the whole drive.
        Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @(); Unlisted = @(); Links = @() } }
        Mock Save-OwnerSnapshot { throw 'snapshot must not be taken (test)' }
        $script:Answers.Enqueue('y'); $script:Answers.Enqueue('y')

        $code = Invoke-FolderPermissionCli -Path $root -LogFolder $script:Log

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape($root))
        $fail[0] | Should -Match '-AllowSystemFolder'
        $fail[0] | Should -Match 'Nothing was changed'
        Should -Invoke Read-Host -Times 0 -Exactly -Scope It -Because 'a refused folder is not asked about'
        Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
    }

    It 'AC16d_Cli_FolderUnderAProtectedPath_IsRefusedUnlessAllowSystemFolderIsGiven' {
        $base = Join-Path $TestDrive ('cli-protected-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $dir 'sub') -Force | Out-Null
        $script:ProtectedDir = $dir
        $old = [Environment]::GetEnvironmentVariable('ProgramData', 'Process')
        [Environment]::SetEnvironmentVariable('ProgramData', $base, 'Process')
        try {
            $refusedCode = Invoke-FolderPermissionCli -Path $script:ProtectedDir -LogFolder $script:Log -Force
            $refusedLines = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            $script:Lines.Clear()

            $allowedCode = Invoke-FolderPermissionCli -Path $script:ProtectedDir -LogFolder $script:Log -Force -AllowSystemFolder
        } finally {
            [Environment]::SetEnvironmentVariable('ProgramData', $old, 'Process')
        }

        $refusedCode | Should -Be 1
        $refusedLines.Count | Should -Be 1
        $refusedLines[0] | Should -Match ([regex]::Escape($dir))
        $refusedLines[0] | Should -Match '-AllowSystemFolder'
        $allowedCode | Should -Be 0
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
    }

    It 'AC16d_Cli_ScriptHasAnAllowSystemFolderSwitchWithHelp' {
        $path = Join-Path $PSScriptRoot '..\FolderPermissionManager.ps1'
        $parameter = (Get-Command $path).Parameters['AllowSystemFolder']
        $parameter | Should -Not -BeNullOrEmpty
        $parameter.ParameterType | Should -Be ([switch])
        $help = Get-Help $path -Full
        $entry = @($help.parameters.parameter | Where-Object { $_.name -eq 'AllowSystemFolder' })
        $entry.Count | Should -Be 1
        "$($entry[0].description.Text)" | Should -Not -BeNullOrEmpty
    }

    # --- Fix round 1 (SQ-014 review 2026-10-17) ------------------------------------------------
    # Pinned: the refusal also follows junctions (Get-TreeOwnershipTargetRefusal), and after the
    # take-ownership result the CLI prints every folder that could not be opened, one per line.

    It 'AC16d_Cli_JunctionToAProtectedFolder_IsRefusedWithAFailLine' {
        $base = Join-Path $TestDrive ('cli-protected-' + [guid]::NewGuid().ToString('N'))
        $target = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $target 'sub') -Force | Out-Null
        $link = Join-Path $TestDrive ('cli-jn-' + [guid]::NewGuid().ToString('N'))
        try { New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null } catch { }
        if (-not (Test-Path -LiteralPath $link)) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
        $old = [Environment]::GetEnvironmentVariable('ProgramData', 'Process')
        [Environment]::SetEnvironmentVariable('ProgramData', $base, 'Process')
        try {
            $code = Invoke-FolderPermissionCli -Path $link -LogFolder $script:Log -Force
        } finally {
            [Environment]::SetEnvironmentVariable('ProgramData', $old, 'Process')
        }

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape($link))
        $fail[0] | Should -Match '-AllowSystemFolder'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
    }

    It 'AC16c_Cli_PrintsEveryFolderThatCouldNotBeOpened' {
        $script:LockedSet = @(1..5 | ForEach-Object {
            $p = Join-Path $script:Dir ('locked{0}' -f $_)
            New-Item -ItemType Directory -Path $p | Out-Null
            $p
        })
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $script:LockedSet -contains $LiteralPath }
        $script:Answers.Enqueue('y')   # take ownership: yes
        $script:Answers.Enqueue('n')   # copy: no

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $result = @($script:Lines | Where-Object { $_ -match '^\[WARN\] (Took ownership|Partly done)' })
        $result.Count | Should -Be 1
        $result[0] | Should -Match 'and 2 more'
        $after = @($script:Lines | Select-Object -Skip ([array]::IndexOf($script:Lines.ToArray(), $result[0]) + 1))
        foreach ($p in $script:LockedSet) {
            @($after | Where-Object { $_.Trim() -eq $p }).Count | Should -Be 1 -Because "$p is printed on its own line after the result"
        }
    }
}
