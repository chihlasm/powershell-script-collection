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
      else means no. Taking ownership asks BEFORE the take-ownership call; there is no
      copy-to-subfolders step (D-035). -Force asks nothing.
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
    # Guard: the real Get-DfsTarget asks the DFS client (NetDfsGetClientInfo) and reads the
    # network path. Replaced here (same parameter) so a test that forgets to mock it never
    # reaches a real share; the code under test treats the throw as "could not be found out".
    $script:RealGetDfsTarget = ${function:Get-DfsTarget}
    function Get-DfsTarget {
        param([Parameter(Mandatory)][string]$Path)
        throw "Get-DfsTarget ($Path) was called without a mock in a test."
    }
    # Guard: the real Resolve-NetworkDrivePath reads this computer's drive letters and asks
    # Windows (WNetGetConnection) which server path a network drive is mapped to. Replaced here
    # (same parameter) so nothing reaches a real drive mapping, then mocked to hand every path
    # back as given; tests about mapped drives mock it themselves. The WNetGetConnection
    # wrapper is replaced the same way, for the tests of the real function.
    $script:RealResolveNetworkDrivePath = ${function:Resolve-NetworkDrivePath}
    function Resolve-NetworkDrivePath {
        param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
        throw "Resolve-NetworkDrivePath ($Path) was called without a mock in a test."
    }
    function Get-NetworkDriveRemoteName {
        param([Parameter(Mandatory)][string]$Letter)
        throw "Get-NetworkDriveRemoteName ($Letter) was called without a mock in a test."
    }
    Mock Resolve-NetworkDrivePath { $Path }
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
        # The test host may be non-interactive; these tests are about a technician at a console.
        Mock Test-CliHostInteractive { $true }
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

        # One question: ownership (declined). There is no copy step to ask about (D-035).
        Should -Invoke Read-Host -Times 1 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse -Because 'nothing was backed up, so nothing was about to change'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It -Because 'ownership must not be taken before the user agrees'
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
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

    It 'AC16_Cli_JunctionIsCountedInTheWarningAndTheResult' {
        $elsewhere = Join-Path $TestDrive ('cli-junction-target-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $elsewhere 'inside') -Force | Out-Null
        $link = Join-Path $script:Dir 'link'
        New-Item -ItemType Junction -Path $link -Target $elsewhere | Out-Null

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $code | Should -Be 1
        $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
        $scope[0] | Should -BeLike "*It contains 1 junction(s) or symbolic link(s), which are listed but not gone into. Microsoft's documentation does not say whether takeown and icacls follow them*$link*"
        @($script:Lines | Where-Object { $_ -like '`[WARN`] Took ownership*1 junction(s) or symbolic link(s)*' }).Count | Should -Be 1
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

    # --- Fix round 2 (SQ-014 review 2026-10-18) ------------------------------------------------
    # Pinned: a junction or symbolic link inside the folder that leads into a protected folder
    # (or somewhere that cannot be checked) refuses the whole folder with one [FAIL] line naming
    # the link and -AllowSystemFolder, before anything is asked or saved.

    It 'AC16d_Cli_JunctionInsideTheFolderToAProtectedFolder_IsRefusedWithAFailLine' {
        $base = Join-Path $TestDrive ('cli-protected-' + [guid]::NewGuid().ToString('N'))
        $target = Join-Path $base 'Contoso'
        New-Item -ItemType Directory -Path (Join-Path $target 'sub') -Force | Out-Null
        $link = Join-Path $script:Dir 'sub1\app'
        try { New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null } catch { }
        if (-not (Test-Path -LiteralPath $link)) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
        $old = [Environment]::GetEnvironmentVariable('ProgramData', 'Process')
        [Environment]::SetEnvironmentVariable('ProgramData', $base, 'Process')
        try {
            $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force
        } finally {
            [Environment]::SetEnvironmentVariable('ProgramData', $old, 'Process')
        }

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape($link))
        $fail[0] | Should -Match '-AllowSystemFolder'
        $fail[0] | Should -Match 'Nothing was changed\.'
        @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' }).Count | Should -Be 0
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath (Join-Path $script:Log 'Backups') | Should -BeFalse
    }

    # --- Revision (SQ-014 review 2026-10-18, D-040) --------------------------------------------
    # Pinned: a DFS reparse point (tag 0x8000000A, no name-surrogate bit) inside the folder counts
    # as a link, so one that leads to a protected folder or a system share is refused with one
    # [FAIL] line naming the link and -AllowSystemFolder, before anything is asked or saved.

    It 'AC20a_Cli_DfsReparsePointInsideTheFolderToASystemShare_IsRefusedWithAFailLine' -ForEach @(
        @{ Name = 'NETLOGON share'; Target = '\\dc01\NETLOGON' }
        @{ Name = 'Windows folder'; Target = (Join-Path $env:SystemRoot 'System32') }
    ) {
        $script:DfsLink = Join-Path $script:Dir 'dfs'
        New-Item -ItemType Directory -Path $script:DfsLink | Out-Null
        $script:DfsTarget = $Target
        Mock Get-ChildItem {
            [PSCustomObject]@{
                FullName = $script:DfsLink; Name = 'dfs'; PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
        Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:DfsLink }
        Mock Get-Win32PathName { $script:DfsTarget } -ParameterFilter { $Path -eq $script:DfsLink }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape($script:DfsLink))
        $fail[0] | Should -Match '-AllowSystemFolder'
        $fail[0] | Should -Match 'Nothing was changed\.'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
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

# --- Fix round 1 of the D-040 revision (SQ-014 review 2026-10-19) ------------------------------
# Pinned: Get-DfsTarget is mocked everywhere (the file-level stub throws). A link whose
# destination cannot be found out is refused with a [FAIL] line that does NOT suggest
# -AllowSystemFolder but "Take ownership of the folders beside the link instead, or ask a senior
# engineer."; a protected-folder refusal still suggests -AllowSystemFolder. A DFS link inside a
# tree on a network path, and a chosen folder on a network path, are looked up with
# Get-DfsTarget. The warning and the copy step name what kind of link was found.
Describe 'FolderPermissionManager.ps1 (command line): DFS targets, unresolvable links, link kinds' {
    BeforeAll {
        $script:BesideTheLink = 'Take ownership of the folders beside the link instead, or ask a senior engineer.'
        function New-FakeReparseChild {
            param([string]$Path)
            [PSCustomObject]@{
                FullName = $Path; Name = (Split-Path -Leaf $Path); PSIsContainer = $true
                Attributes = [System.IO.FileAttributes]'Directory, ReparsePoint'
            }
        }
        # A folder tree on a network path, with nothing read from the network (see the same
        # helper in FolderPermissions.Tree.Tests.ps1).
        function Set-UncTreeMock {
            param([string]$Top, [string]$Final, [string[]]$Links = @())
            $script:UncTop = $Top
            $script:UncFinal = $Final
            $script:UncLinks = @($Links)
            $script:SnapFile = Join-Path $TestDrive ('snap-' + [guid]::NewGuid().ToString('N') + '_TakeOwnership.csv')
            Set-Content -LiteralPath $script:SnapFile -Value 'Path,ItemType,Owner,OwnerSid'
            $script:LocalAcl = Get-Acl -LiteralPath $TestDrive
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-Win32PathName { if ($Path -eq $script:UncTop -and $script:UncFinal) { $script:UncFinal } else { $Path } } -ParameterFilter { "$Path" -like '\\*' }
            Mock Get-Acl { $script:LocalAcl } -ParameterFilter { "$LiteralPath" -like '\\*' }
            Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @([PSCustomObject]@{ Path = $script:UncTop; ItemType = 'Folder' }); Unlisted = @(); Links = @($script:UncLinks) } }
            Mock Save-OwnerSnapshot {
                [PSCustomObject]@{
                    File = $script:SnapFile; Count = 1
                    Items = @([PSCustomObject]@{ Path = $script:UncTop; ItemType = 'Folder'; Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' })
                    Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = @($script:UncLinks).Count; LinkPaths = @($script:UncLinks)
                }
            }
            Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Unchecked = 0; Changed = 1; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        }
    }
    BeforeEach {
        $root = Join-Path $TestDrive ('cli-d040-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('cli-d040-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Lines = [System.Collections.Generic.List[string]]::new()
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Read-Host { 'n' }
        Mock Write-Host { $script:Lines.Add("$Object") }
        Mock Get-DfsTarget { }
    }

    Context 'A link inside the folder whose destination cannot be found out' {
        BeforeEach {
            $script:LinkPath = Join-Path $script:Dir 'redirected'
            New-Item -ItemType Directory -Path $script:LinkPath | Out-Null
            Mock Get-ChildItem { New-FakeReparseChild -Path $script:LinkPath } -ParameterFilter { $LiteralPath -eq $script:Dir }
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:LinkPath }
            Mock Get-Item { [PSCustomObject]@{ FullName = $script:LinkPath; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { $LiteralPath -eq $script:LinkPath }
        }

        It 'AC20c_Cli_UnresolvableLink_FailLineSuggestsTheFoldersBesideTheLinkNotAllowSystemFolder_<Case>' -ForEach @(
            @{ Case = 'final path unknown'; Final = 'none' }
            @{ Case = 'final path is its own path'; Final = 'self' }
        ) {
            $script:FinalKind = $Final
            Mock Get-Win32PathName { if ($script:FinalKind -eq 'self') { $Path } else { $null } } -ParameterFilter { $Path -eq $script:LinkPath }

            $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match ([regex]::Escape($script:LinkPath))
            $fail[0] | Should -Match 'where it leads could not be found out'
            $fail[0] | Should -Match 'DFS link'
            $fail[0] | Should -Not -Match 'AllowSystemFolder'
            $fail[0] | Should -Match ([regex]::Escape($script:BesideTheLink))
            $fail[0] | Should -Match 'Nothing was changed\.'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
            Should -Invoke Get-Item -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $script:LinkPath }
        }

        It 'AC20a_Cli_ProtectedFolderRefusal_StillSuggestsAllowSystemFolder' {
            Mock Get-Win32PathName { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq $script:LinkPath }

            $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match '-AllowSystemFolder'
            $fail[0] | Should -Not -Match ([regex]::Escape($script:BesideTheLink))
        }
    }

    Context 'A DFS link inside a folder on a network path' {
        BeforeEach {
            $script:Top = '\\fs01\share\Dept'
            $script:DfsLink = '\\fs01\share\Dept\Apps'
            Set-UncTreeMock -Top $script:Top -Links @($script:DfsLink)
            Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq $script:DfsLink }
        }

        It 'AC20a_Cli_DfsLinkToNetlogon_IsRefusedWithAFailLine' {
            Mock Get-DfsTarget { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq $script:DfsLink }

            $code = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match ([regex]::Escape($script:DfsLink))
            $fail[0] | Should -Match 'NETLOGON'
            $fail[0] | Should -Match '-AllowSystemFolder'
            Should -Invoke Save-OwnerSnapshot -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_Cli_DfsLinkToAnOrdinaryShareFolder_IsAllowedAndTheWarningNamesItAsADfsLink' {
            Mock Get-DfsTarget { '\\fs02\Apps$\Current' } -ParameterFilter { $Path -eq $script:DfsLink }

            $null = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' }).Count | Should -Be 0
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
            $scope = @($script:Lines | Where-Object { $_ -like '`[WARN`] Taking ownership makes *' })
            $scope.Count | Should -Be 1
            $scope[0] | Should -Match 'DFS link'
            $scope[0] | Should -Match ([regex]::Escape($script:DfsLink))
            $scope[0] | Should -Not -Match ([regex]::Escape('junction(s) or symbolic link(s)'))
            # The "[INFO] ... are skipped" line came from the copy-to-subfolders step, which D-035
            # removed from the CLI, so it is no longer asserted here.
        }

        It 'AC20c_Cli_DfsLinkWhoseTargetCannotBeFound_IsRefusedWithoutTheAllowSystemFolderHint' {
            Mock Get-DfsTarget { throw 'The network path was not found. (test)' } -ParameterFilter { $Path -eq $script:DfsLink }

            $code = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match ([regex]::Escape($script:DfsLink))
            $fail[0] | Should -Not -Match 'AllowSystemFolder'
            $fail[0] | Should -Match ([regex]::Escape($script:BesideTheLink))
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }
    }

    Context 'The chosen folder is a DFS link or under a DFS namespace' {
        BeforeEach {
            $script:Top = '\\contoso.com\dfs\HR'
        }

        It 'AC20a_Cli_TopLevelDfsToNetlogon_IsRefused_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            $script:Target = '\\dc01\NETLOGON\scripts'
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { $script:Target } else { '' })
            Mock Get-DfsTarget { $script:Target } -ParameterFilter { $Path -eq $script:Top }

            $code = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match ([regex]::Escape($script:Top))
            $fail[0] | Should -Match 'NETLOGON'
            $fail[0] | Should -Match '-AllowSystemFolder'
            Should -Invoke Get-OwnerTreeItem -Times 0 -Exactly -Scope It
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }

        It 'AC20a_Cli_TopLevelDfsToAnOrdinaryFolder_IsAllowed_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            $script:Target = '\\fs02\HR$\Dept'
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { $script:Target } else { '' })
            Mock Get-DfsTarget { $script:Target } -ParameterFilter { $Path -eq $script:Top }

            $null = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' }).Count | Should -Be 0
            Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
        }

        It 'AC20c_Cli_TopLevelDfsThatCannotBeResolved_IsRefused_FinalPathIs<FinalIs>' -ForEach @(
            @{ FinalIs = 'the target' }
            @{ FinalIs = 'the path as given' }
        ) {
            Set-UncTreeMock -Top $script:Top -Final $(if ($FinalIs -eq 'the target') { '\\fs02\HR$\Dept' } else { '' })
            Mock Get-DfsTarget { throw 'NetDfsGetClientInfo failed (test)' } -ParameterFilter { $Path -eq $script:Top }

            $code = Invoke-FolderPermissionCli -Path $script:Top -LogFolder $script:Log -Force

            $code | Should -Be 1
            $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
            $fail.Count | Should -Be 1
            $fail[0] | Should -Match ([regex]::Escape($script:Top))
            $fail[0] | Should -Match 'where it leads could not be found out'
            $fail[0] | Should -Not -Match 'AllowSystemFolder'
            Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        }
    }
}

# --- Fix round 2 of the D-040 revision (SQ-014 review 2026-10-19) ------------------------------
# Pinned: Resolve-NetworkDrivePath is mocked everywhere (the file-level stub throws). The command
# line keeps the drive letter it was given (Resolve-AclTargetPath), and the core turns a mapped
# network drive into its server path before any check. A refusal about the chosen folder itself
# (no link involved: a network drive or a DFS lookup that could not be resolved) tells the
# technician to check the path and use the real server path, not "the folders beside the link".
Describe 'FolderPermissionManager.ps1 (command line): mapped network drives and network paths' {
    BeforeAll {
        $script:BesideTheLink = 'Take ownership of the folders beside the link instead, or ask a senior engineer.'
        $script:CheckThePath = 'Check the path is reachable and run this against the real server path (Properties > DFS tab), or ask a senior engineer.'
        # A folder tree on mapped network drive H: (see Set-MappedDriveTreeMock in
        # FolderPermissions.Tree.Tests.ps1): nothing is read from a drive or the network.
        function Set-MappedDriveTreeMock {
            param([string]$Top, [string]$Unc, [string[]]$Links = @(), [string]$LinkFinal, [switch]$Unresolvable)
            $script:MapTop = $Top
            $script:MapUnc = $Unc
            $script:MapLinks = @($Links)
            $script:MapLinkFinal = $LinkFinal
            $script:SnapFile = Join-Path $TestDrive ('snap-' + [guid]::NewGuid().ToString('N') + '_TakeOwnership.csv')
            Set-Content -LiteralPath $script:SnapFile -Value 'Path,ItemType,Owner,OwnerSid'
            $script:LocalAcl = Get-Acl -LiteralPath $TestDrive
            Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like 'H:\*' -or "$LiteralPath" -like '\\*' }
            Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like 'H:\*' -or "$LiteralPath" -like '\\*' }
            Mock Get-Win32PathName {
                if ($Kind -eq 'Final' -and @($script:MapLinks) -contains $Path -and $script:MapLinkFinal) { return $script:MapLinkFinal }
                $null
            } -ParameterFilter { "$Path" -like 'H:\*' }
            Mock Get-Acl { $script:LocalAcl } -ParameterFilter { "$LiteralPath" -like 'H:\*' }
            if ($Unresolvable) {
                Mock Resolve-NetworkDrivePath { throw 'The device is not currently connected, but it is a persistent connection. (test)' } -ParameterFilter { "$Path" -like 'H:*' }
            } else {
                Mock Resolve-NetworkDrivePath { $script:MapUnc + "$Path".Substring(2) } -ParameterFilter { "$Path" -like 'H:*' }
            }
            Mock Get-OwnerTreeItem { [PSCustomObject]@{ Items = @([PSCustomObject]@{ Path = $script:MapTop; ItemType = 'Folder' }); Unlisted = @(); Links = @($script:MapLinks) } }
            Mock Save-OwnerSnapshot {
                [PSCustomObject]@{
                    File = $script:SnapFile; Count = 1
                    Items = @([PSCustomObject]@{ Path = $script:MapTop; ItemType = 'Folder'; Owner = 'CONTOSO\old.owner'; OwnerSid = 'S-1-5-21-1-2-3-1105' })
                    Unreadable = 0; Unlisted = 0; UnlistedFolders = @(); Links = @($script:MapLinks).Count; LinkPaths = @($script:MapLinks)
                }
            }
            Mock Get-OwnerReadBack { [PSCustomObject]@{ Mine = 1; NotMine = 0; Unchecked = 0; Changed = 1; AdministratorsOnly = $false; WatchedChanged = @(); WatchedUnchecked = @() } }
        }
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('cli-r2-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Lines = [System.Collections.Generic.List[string]]::new()
        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Read-Host { 'n' }
        Mock Write-Host { $script:Lines.Add("$Object") }
        Mock Get-DfsTarget { }
    }

    It 'AC20a_Cli_MappedDriveWithNoFinalPathInDfsToNetlogon_IsRefused' {
        Set-MappedDriveTreeMock -Top 'H:\HR' -Unc '\\contoso.com\dfs'
        Mock Get-DfsTarget { '\\dc01\NETLOGON' } -ParameterFilter { $Path -eq '\\contoso.com\dfs\HR' }

        $code = Invoke-FolderPermissionCli -Path 'H:\HR' -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape('H:\HR'))
        $fail[0] | Should -Match 'NETLOGON'
        $fail[0] | Should -Match 'Nothing was changed\.'
        Should -Invoke Get-OwnerTreeItem -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }

    It 'AC20c_Cli_MappedDriveThatCannotBeResolved_IsRefusedWithTheCheckThePathNextStep' {
        Set-MappedDriveTreeMock -Top 'H:\HR' -Unresolvable

        $code = Invoke-FolderPermissionCli -Path 'H:\HR' -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape('H:\HR'))
        $fail[0] | Should -Match 'where it leads could not be found out'
        $fail[0] | Should -Match ([regex]::Escape($script:CheckThePath))
        $fail[0] | Should -Not -Match ([regex]::Escape($script:BesideTheLink))
        $fail[0] | Should -Not -Match 'AllowSystemFolder'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }

    It 'AC20c_Cli_DfsLinkUnderAMappedDriveWithNoDfsTarget_IsRefused' {
        Set-MappedDriveTreeMock -Top 'H:\Dept' -Unc '\\fs01\share' -Links @('H:\Dept\Apps') -LinkFinal '\\?\UNC\fs02\Apps$\Current'
        Mock Get-ReparsePointTag { [uint32]'0x8000000A' } -ParameterFilter { $Path -eq 'H:\Dept\Apps' }

        $code = Invoke-FolderPermissionCli -Path 'H:\Dept' -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape('H:\Dept\Apps'))
        $fail[0] | Should -Match 'DFS link'
        $fail[0] | Should -Match 'where it leads could not be found out'
        $fail[0] | Should -Match ([regex]::Escape($script:BesideTheLink))
        Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\Dept\Apps' }
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_MappedDriveToAnOrdinaryShareNotInDfs_IsAllowed' {
        Set-MappedDriveTreeMock -Top 'H:\HR' -Unc '\\fs01\share'

        $null = Invoke-FolderPermissionCli -Path 'H:\HR' -LogFolder $script:Log -Force

        @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' }).Count | Should -Be 0
        Should -Invoke Get-DfsTarget -Scope It -ParameterFilter { $Path -eq '\\fs01\share\HR' }
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
    }

    It 'AC20c_Cli_TopLevelDfsLookupThatFails_SuggestsCheckingThePathNotTheFoldersBesideALink' {
        $top = '\\contoso.com\dfs\HR'
        $script:Top = $top
        Mock Test-Path { $true } -ParameterFilter { "$LiteralPath" -like '\\*' }
        Mock Get-Item { [PSCustomObject]@{ FullName = "$LiteralPath"; Attributes = [System.IO.FileAttributes]::Directory } } -ParameterFilter { "$LiteralPath" -like '\\*' }
        Mock Get-Win32PathName { $Path } -ParameterFilter { "$Path" -like '\\*' }
        Mock Get-DfsTarget { throw 'NetDfsGetClientInfo failed (test)' } -ParameterFilter { $Path -eq $script:Top }

        $code = Invoke-FolderPermissionCli -Path $top -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Match ([regex]::Escape($script:CheckThePath))
        $fail[0] | Should -Not -Match ([regex]::Escape($script:BesideTheLink))
        $fail[0] | Should -Not -Match 'AllowSystemFolder'
    }

    It 'AC20_Cli_NextStep_IsPickedByTheSharedMarkers' {
        Get-CliRefusalNextStep -Refusal "x is on a network path, and $script:UnresolvedDestinationText, $script:ChosenFolderUncheckedText." | Should -BeExactly $script:CheckThePath
        Get-CliRefusalNextStep -Refusal "x is a junction, and $script:UnresolvedDestinationText, so it cannot be checked." | Should -BeExactly $script:BesideTheLink
        Get-CliRefusalNextStep -Refusal 'x is in a Windows system folder.' | Should -Match '-AllowSystemFolder'
    }
}
