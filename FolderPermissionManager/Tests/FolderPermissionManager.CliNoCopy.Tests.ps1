<#
    Tests for D-035 (SQ-015 revision): the old command-line script FolderPermissionManager.ps1
    has no copy-to-subfolders step. It only takes ownership and shows permissions; to grant
    access, add it on the folder the person needs (inheritance passes it on). Pester 5, run
    under pwsh.

    Everything is mocked; folders live in $TestDrive. The script is only dot-sourced with
    -LoadFunctionsOnly.
#>

BeforeAll {
    $script:CliPath = (Resolve-Path (Join-Path $PSScriptRoot '..\FolderPermissionManager.ps1')).Path
    $script:ReadmePath = (Resolve-Path (Join-Path $PSScriptRoot '..\README.md')).Path
    . $script:CliPath -LoadFunctionsOnly
    # Guard: a test that forgets to mock the native-tool wrapper must fail, not change owners.
    function Invoke-AclTool {
        param(
            [Parameter(Mandatory)][ValidateSet('icacls', 'takeown')][string]$Tool,
            [Parameter(Mandatory)][string[]]$Arguments
        )
        throw "Invoke-AclTool ($Tool) was called without a mock in a test."
    }
}

Describe 'FolderPermissionManager.ps1 has no copy-to-subfolders step (D-035)' {
    BeforeEach {
        $root = Join-Path $TestDrive ('d035-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'sub2') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('d035-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Prompts = [System.Collections.Generic.List[string]]::new()
        $script:Lines = [System.Collections.Generic.List[string]]::new()

        Mock Set-Acl { }
        Mock Copy-FolderPermission { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        # The test host may be non-interactive; these tests are about a technician at a console.
        Mock Test-CliHostInteractive { $true }
        # Every question is answered yes, so a copy prompt would lead to a copy.
        Mock Read-Host { $script:Prompts.Add("$Prompt"); 'y' }
        Mock Write-Host { $script:Lines.Add("$Object") }
        # The top folder has a rule of its own that its subfolders lack: the old step would
        # have copied it (in memory only, nothing is written).
        $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
        Mock Get-Acl {
            $acl = & $script:RealGetAcl -LiteralPath "$LiteralPath"
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList 'BUILTIN\Users', 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
            $acl
        } -ParameterFilter { $LiteralPath -eq $script:Dir }
    }

    It 'AC15_CliHasNoCopyStep_AsksOnlyTheTakeOwnershipQuestionAndNeverCopies' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        Should -Invoke Read-Host -Times 1 -Exactly -Scope It -Because 'only the take-ownership question is asked'
        Should -Invoke Copy-FolderPermission -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        @($script:Lines | Where-Object { $_ -match '(?i)cop(y|ies|ied)' -and $_ -notmatch '(?i)copied to the clipboard' }).Count | Should -Be 0 -Because 'no copy prompt or scope line is printed'
        @(Get-ChildItem -LiteralPath (Join-Path $script:Log 'Backups') -Filter '*_CopyPermissions.csv' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }

    It 'AC15_CliHasNoCopyStep_WithForceAsksNothingAndNeverCopies' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        Should -Invoke Copy-FolderPermission -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
    }

    It 'AC15_CliHasNoCopyStep_WhatIfNeverCopies' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf

        Should -Invoke Copy-FolderPermission -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
    }

    It 'AC15_CliHasNoCopyStep_StillShowsTheTopFolderOwnerAndPermissions' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        @($script:Lines | Where-Object { $_ -like "Permissions on the top-level folder ($($script:Dir)):" }).Count | Should -Be 1
        @($script:Lines | Where-Object { $_ -like 'Subfolders and their owners*' }).Count | Should -Be 1
    }

    It 'AC15_CliHasNoCopyStep_ScriptHasNoCopyCallsStatically' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:CliPath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $called | Should -Not -Contain 'Copy-FolderPermission'
        $called | Should -Not -Contain 'Get-CliSubfolder'
        $called | Should -Not -Contain 'Set-Acl'
        $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        $defined | Should -Not -Contain 'Get-CliSubfolder' -Because 'the helper only served the copy step'
    }

    It 'AC15_CliHelpSaysToGrantAccessOnceOnTheTopFolder' {
        $help = Get-Help $script:CliPath -Full
        $text = (@($help.Synopsis, ($help.description | Out-String), ($help.alertSet | Out-String), ($help.examples | Out-String)) -join "`n") -replace '\s+', ' '
        # Fix round 1: the advice is scoped to the folder the person needs (it was "add it once
        # on the top folder", which on a share root grants everything below).
        $text | Should -Match '(?i)add it on the folder they need'
        $text | Should -Match '(?i)gives them everything inside it that inherits'
        $text | Should -Not -Match '(?i)add it once on the top folder'
        $text | Should -Match '(?i)inherit'
        $text | Should -Match '(?i)block inheritance'
        $text | Should -Match '(?i)explicit Deny'
        # Fix round 2: the example grants read and execute; Modify only when they must change files.
        $text | Should -Match ([regex]::Escape('/grant "DOMAIN\user:(OI)(CI)RX"'))
        $text | Should -Match '(?i)use M only if they must change or delete files'
        $text | Should -Not -Match ([regex]::Escape('(OI)(CI)M"'))
        $text | Should -Match '(?i)do not add /T'
        $text | Should -Match '(?i)Security tab'
        $text | Should -Not -Match '(?i)copies the permissions set directly'
        $text | Should -Not -Match '(?i)before copying permissions'
    }

    It 'AC15_CliReadmeSaysToGrantAccessOnceOnTheTopFolder' {
        $readme = Get-Content -LiteralPath $script:ReadmePath -Raw
        $match = [regex]::Match($readme, '(?s)### FolderPermissionManager\.ps1 \(CLI\)(.*?)\r?\n## Requirements')
        $match.Success | Should -BeTrue
        $section = $match.Groups[1].Value -replace '\s+', ' '
        $section | Should -Match '(?i)add it on the folder they need'
        $section | Should -Match '(?i)gives them everything inside it that inherits'
        $section | Should -Not -Match '(?i)add it once on the top folder'
        $section | Should -Match '(?i)inherit'
        $section | Should -Match '(?i)block inheritance'
        $section | Should -Match '(?i)explicit Deny'
        # Fix round 2: the example grants read and execute; Modify only when they must change files.
        $section | Should -Match ([regex]::Escape('/grant "DOMAIN\user:(OI)(CI)RX"'))
        $section | Should -Match '(?i)use M only if they must change or delete files'
        $section | Should -Not -Match ([regex]::Escape('(OI)(CI)M"'))
        $section | Should -Match '(?i)do not add /T'
        $section | Should -Match '(?i)Security tab'
        $section | Should -Not -Match '(?i)again before copying'
        $section | Should -Not -Match '(?i)The copy step'
    }
}

# --- Fix round 1 (SQ-015 D-035 review) ------------------------------------------------------
# Pinned: the closing advice is scoped ("add it on the folder they need"; adding it on <Path>
# gives everything inside it that inherits), names the subfolders that block inheritance
# (AreAccessRulesProtected, from the Get-Acl the owner listing already does), says an explicit
# Deny still wins, and gives the icacls command for hosts without a browser (no /T). The owner
# heading says what it leaves out. A non-interactive host without -Force or -WhatIf is refused
# before anything is asked or changed (Test-CliHostInteractive, mockable).

Describe 'FolderPermissionManager.ps1 closing advice, owner list and non-interactive hosts' {
    BeforeEach {
        $root = Join-Path $TestDrive ('d035r1-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'sub2\deeper') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('d035r1-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Lines = [System.Collections.Generic.List[string]]::new()
        $script:Protected = @()

        Mock Set-Acl { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Test-CliHostInteractive { $true }
        # Ownership is declined, so the core (which reads owners itself) never runs.
        Mock Read-Host { 'n' }
        Mock Write-Host { $script:Lines.Add("$Object") }
        # A folder in $script:Protected blocks inheritance (in memory only, nothing is written).
        $script:RealGetAcl = Get-Command Get-Acl -CommandType Cmdlet
        Mock Get-Acl {
            $acl = & $script:RealGetAcl -LiteralPath "$LiteralPath"
            if ($script:Protected -contains "$LiteralPath") { $acl.SetAccessRuleProtection($true, $true) }
            $acl
        }
    }

    It 'AC15_CliAccessAdvice_IsScopedToTheFolderTheyNeedAndGivesTheSafeCommand' {
        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0
        $info = @($script:Lines | Where-Object { $_ -like '`[INFO`] *' }) -join "`n"
        $info | Should -Match ([regex]::Escape("To give someone access: add it on the folder they need. Adding it on $($script:Dir) gives them everything inside it that inherits."))
        $info | Should -Not -Match '(?i)add it once on the top folder'
        $info | Should -Match '(?i)explicit Deny .*still wins'
        $info | Should -Match '(?i)Security tab'
        # Fix round 2: the command is not pre-filled with the top folder (pasting it would grant
        # everything below); it names a placeholder under it and grants read and execute.
        $info | Should -Match ([regex]::Escape("icacls ""$(Join-Path $script:Dir '<folder they need>')"" /grant ""DOMAIN\user:(OI)(CI)RX"""))
        $info | Should -Not -Match ([regex]::Escape("icacls ""$($script:Dir)"""))
        $info | Should -Match '(?i)use M only if they must change or delete files'
        $info | Should -Match '(?i)do not add /T'
    }

    It 'AC15_CliAccessAdvice_NamesTheSubfoldersThatBlockInheritance' {
        $script:Protected = @((Join-Path $script:Dir 'sub2'))

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $block = @($script:Lines | Where-Object { $_ -like '`[INFO`] *subfolder(s) block inheritance*' })
        $block.Count | Should -Be 1
        $block[0] | Should -Match '1 subfolder\(s\) block inheritance'
        $block[0] | Should -Match ([regex]::Escape((Join-Path $script:Dir 'sub2')))
        $block[0] | Should -Not -Match ([regex]::Escape((Join-Path $script:Dir 'sub1')))
        $block[0] | Should -Match '(?i)folders inside them'
    }

    It 'AC15_CliAccessAdvice_SaysWhenNoListedSubfolderBlocksInheritance' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        @($script:Lines | Where-Object { $_ -like '`[INFO`] None of the subfolders listed above block inheritance*' }).Count | Should -Be 1
        @($script:Lines | Where-Object { $_ -match 'subfolder\(s\) block inheritance' }).Count | Should -Be 0
    }

    It 'AC15_CliOwnerList_LeavesOutJunctionsAndUnlistedFoldersAndSaysSo' {
        $elsewhere = Join-Path $TestDrive ('d035r1-target-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $elsewhere -Force | Out-Null
        $script:Link = Join-Path $script:Dir 'link'
        try { New-Item -ItemType Junction -Path $script:Link -Target $elsewhere -ErrorAction Stop | Out-Null } catch { }
        if (-not (Test-Path -LiteralPath $script:Link)) { Set-ItResult -Skipped -Because 'a junction could not be created here'; return }
        $script:Locked = Join-Path $script:Dir 'sub1'
        Mock Get-ChildItem { throw 'Access to the path is denied. (test)' } -ParameterFilter { $LiteralPath -eq $script:Locked }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0 -Because 'ownership was declined'
        $heading = @($script:Lines | Where-Object { $_ -like 'Subfolders and their owners*' })
        $heading.Count | Should -Be 1
        $heading[0] | Should -Be 'Subfolders and their owners (2, not counting 1 that could not be opened and 1 junction or symbolic link, listed above):'
        @($script:Lines | Where-Object { $_ -like "  $($script:Link) - Owner:*" }).Count | Should -Be 0
        @($script:Lines | Where-Object { $_ -like "  $($script:Locked) - Owner:*" }).Count | Should -Be 0
        Should -Invoke Get-Acl -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $script:Link }
        Should -Invoke Get-Acl -Times 0 -Exactly -Scope It -ParameterFilter { $LiteralPath -eq $script:Locked }
    }

    It 'AC15_CliOwnerList_HeadingHasNoExclusionsWhenNothingIsLeftOut' {
        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        @($script:Lines | Where-Object { $_ -eq 'Subfolders and their owners (3):' }).Count | Should -Be 1
    }

    It 'AC20_Cli_OwnershipDeclined_StillShowsThePermissionsAndExitsZero' {
        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0
        @($script:Lines | Where-Object { $_ -eq '[INFO] Ownership was not changed.' }).Count | Should -Be 1
        @($script:Lines | Where-Object { $_ -eq "Permissions on the top-level folder ($($script:Dir)):" }).Count | Should -Be 1
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_NonInteractiveHostWithoutForceOrWhatIf_IsRefusedBeforeAnythingIsAsked' {
        Mock Test-CliHostInteractive { $false }
        Mock Get-OwnerTreeItem { throw 'the folder must not be counted (test)' }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Be '[FAIL] Run with -Force, or -WhatIf for a dry run; this host cannot ask. Nothing was changed.'
        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath $script:Log | Should -BeFalse -Because 'not even the log folder is created'
    }

    It 'AC20_Cli_NonInteractiveHostWithForceOrWhatIf_Runs' {
        Mock Test-CliHostInteractive { $false }

        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force | Should -Be 0
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -WhatIf | Should -Be 0

        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        @($script:Lines | Where-Object { $_ -like '*this host cannot ask*' }).Count | Should -Be 0
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
    }

    It 'AC20_Cli_NonInteractiveHostWithForceButNoPath_IsRefusedInsteadOfAskingForTheFolder' {
        Mock Test-CliHostInteractive { $false }

        $code = Invoke-FolderPermissionCli -LogFolder $script:Log -Force

        $code | Should -Be 1
        @($script:Lines | Where-Object { $_ -eq '[FAIL] Give the folder with -Path; this host cannot ask. Nothing was changed.' }).Count | Should -Be 1
        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
    }
}

Describe 'Test-CliHostInteractive' {
    # Fix round 2 (SQ-015 D-035 review): the rule is the -NonInteractive switch only. A process
    # without a user interface (Environment.UserInteractive false, as in an Enter-PSSession
    # host or psexec without -i) can still answer Read-Host, so it no longer counts as "cannot
    # ask"; a Read-Host that fails anyway is caught where it is asked.
    It 'AC20_Cli_HostIsInteractiveUnlessStartedWithTheNonInteractiveSwitch (<Name>)' -ForEach @(
        @{ Name = 'normal console'; CmdArgs = @('powershell.exe', '-File', 'x.ps1'); Expected = $true }
        @{ Name = 'remoting host (Enter-PSSession), no user interface'; CmdArgs = @('C:\Windows\system32\wsmprovhost.exe', '-Embedding'); Expected = $true }
        @{ Name = 'psexec without -i, no user interface'; CmdArgs = @('powershell.exe'); Expected = $true }
        @{ Name = '-NonInteractive'; CmdArgs = @('powershell.exe', '-NonInteractive', '-File', 'x.ps1'); Expected = $false }
        @{ Name = '-noni in capitals'; CmdArgs = @('pwsh.exe', '-NoProfile', '-NONI', '-File', 'x.ps1'); Expected = $false }
        @{ Name = '/NonInteractive'; CmdArgs = @('powershell.exe', '/NonInteractive', '-Command', 'x'); Expected = $false }
        @{ Name = '--noninteractive (pwsh)'; CmdArgs = @('pwsh.exe', '--noninteractive', '-File', 'x.ps1'); Expected = $false }
        @{ Name = '--noni (pwsh)'; CmdArgs = @('pwsh.exe', '-NoProfile', '--noni', '-c', 'x'); Expected = $false }
        @{ Name = 'a script argument after -File'; CmdArgs = @('powershell.exe', '-File', 'x.ps1', '-NonInteractive'); Expected = $true }
        @{ Name = 'a script argument after --file'; CmdArgs = @('pwsh.exe', '--file', 'x.ps1', '--noninteractive'); Expected = $true }
        @{ Name = 'text after -c'; CmdArgs = @('pwsh.exe', '-c', 'echo', '-noninteractive'); Expected = $true }
    ) {
        Test-CliHostInteractive -CommandLineArgs $CmdArgs | Should -Be $Expected -Because $Name
    }

    It 'AC20_Cli_HostInteractiveDefaultsToThisProcess' {
        $result = Test-CliHostInteractive
        $result | Should -BeOfType [bool]
    }

    It 'AC20_Cli_HostInteractiveDoesNotDependOnUserInteractive' {
        $command = Get-Command Test-CliHostInteractive
        $command.Parameters.Keys | Should -Not -Contain 'UserInteractive'
        $command.ScriptBlock.ToString() | Should -Not -Match '\[Environment\]::UserInteractive'
    }
}

# --- Fix round 2 (SQ-015 D-035 review) ------------------------------------------------------
# Pinned: a remote console (no user interface, no -NonInteractive switch) is asked as usual. A
# Read-Host that throws (the host cannot ask after all) ends the run with one [FAIL] line and
# exit code 1 before anything is changed or the log folder is created; the log folder line comes
# after the confirmation. A subfolder whose permissions cannot be read is counted as not
# checked, so the script never claims that none block inheritance. The function's synopsis
# gives the scoped advice.

Describe 'FolderPermissionManager.ps1 remote consoles, prompts that fail and unreadable subfolders' {
    BeforeEach {
        $root = Join-Path $TestDrive ('d035r2-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'sub2') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('d035r2-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Lines = [System.Collections.Generic.List[string]]::new()
        $script:LinesAtPrompt = $null

        Mock Set-Acl { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Write-Host { $script:Lines.Add("$Object") }
        $script:RealHostTest = ${function:Test-CliHostInteractive}
    }

    It 'AC20_Cli_RemoteConsoleWithoutUserInterface_IsStillAsked' {
        # The command line of an Enter-PSSession host: no -NonInteractive switch.
        Mock Test-CliHostInteractive { & $script:RealHostTest -CommandLineArgs @('C:\Windows\system32\wsmprovhost.exe', '-Embedding') }
        Mock Read-Host { 'n' }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0
        Should -Invoke Read-Host -Times 1 -Exactly -Scope It -ParameterFilter { $Prompt -eq 'Continue? (y/N)' }
        @($script:Lines | Where-Object { $_ -like '*cannot ask*' }).Count | Should -Be 0
    }

    It 'AC20_Cli_ConfirmationReadHostThrows_FailsCleanlyWithNothingChanged' {
        Mock Test-CliHostInteractive { $true }
        Mock Read-Host { throw 'PowerShell is in NonInteractive mode. Read and Prompt functionality is not available. (test)' }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Be '[FAIL] This host cannot ask; run with -Force, or -WhatIf for a dry run. Nothing was changed.'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath $script:Log | Should -BeFalse -Because 'the log folder is only created after the technician agrees'
        @($script:Lines | Where-Object { $_ -like '*Changes are backed up and logged*' }).Count | Should -Be 0
        @($script:Lines | Where-Object { $_ -like 'Permissions on the top-level folder*' }).Count | Should -Be 0
    }

    It 'AC20_Cli_PathReadHostThrows_FailsCleanlyWithNothingChanged' {
        Mock Test-CliHostInteractive { $true }
        Mock Read-Host { throw 'PowerShell is in NonInteractive mode. Read and Prompt functionality is not available. (test)' }

        $code = Invoke-FolderPermissionCli -LogFolder $script:Log -Force

        $code | Should -Be 1
        $fail = @($script:Lines | Where-Object { $_ -like '`[FAIL`] *' })
        $fail.Count | Should -Be 1
        $fail[0] | Should -Be '[FAIL] Give the folder with -Path; this host cannot ask. Nothing was changed.'
        Should -Invoke Invoke-AclTool -Times 0 -Exactly -Scope It
        Should -Invoke Set-Acl -Times 0 -Exactly -Scope It
        Test-Path -LiteralPath $script:Log | Should -BeFalse
    }

    It 'AC20_Cli_LogFolderLineComesAfterTheConfirmation' {
        Mock Test-CliHostInteractive { $true }
        Mock Read-Host { $script:LinesAtPrompt = $script:Lines.ToArray(); 'y' }

        $null = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        @($script:LinesAtPrompt | Where-Object { $_ -like '*Changes are backed up and logged*' }).Count | Should -Be 0 -Because 'nothing is set up before the technician agrees'
        @($script:Lines | Where-Object { $_ -eq "[INFO] Changes are backed up and logged to $($script:Log)" }).Count | Should -Be 1
        Should -Invoke Invoke-AclTool -Times 1 -Exactly -Scope It -ParameterFilter { $Tool -eq 'takeown' }
    }

    It 'AC15_CliAccessAdvice_SubfolderWhosePermissionsCannotBeRead_IsCountedAsNotChecked' {
        Mock Test-CliHostInteractive { $true }
        Mock Read-Host { 'n' }
        $script:Unreadable = Join-Path $script:Dir 'sub1'
        Mock Get-Acl { throw 'Attempted to perform an unauthorized operation. (test)' } -ParameterFilter { $LiteralPath -eq $script:Unreadable }

        $code = Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log

        $code | Should -Be 0 -Because 'ownership was declined'
        @($script:Lines | Where-Object { $_ -like '`[INFO`] None of the subfolders listed above block inheritance*' }).Count | Should -Be 0
        $unchecked = @($script:Lines | Where-Object { $_ -match '1 could not be checked' })
        $unchecked.Count | Should -Be 1
        $unchecked[0] | Should -Match ([regex]::Escape($script:Unreadable))
        $unchecked[0] | Should -Not -Match ([regex]::Escape((Join-Path $script:Dir 'sub2')))
    }

    It 'AC15_CliFunctionSynopsis_GivesTheScopedAdvice' {
        $synopsis = (Get-Help Invoke-FolderPermissionCli).Synopsis -replace '\s+', ' '
        $synopsis | Should -Not -Match '(?i)added once on the top folder'
        $synopsis | Should -Match '(?i)on the folder they need'
    }
}
