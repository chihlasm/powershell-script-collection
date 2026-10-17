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

        Mock Set-Acl { }
        Mock takeown { }
        Mock icacls { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
        Mock Read-Host {
            $script:Prompts.Add("$Prompt")
            if ($script:Answers.Count -gt 0) { $script:Answers.Dequeue() } else { 'n' }
        }
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

        Should -Invoke Read-Host -Times 1 -Scope It
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
        Should -Invoke Invoke-AclTool -Times 1 -ParameterFilter { $Tool -eq 'takeown' } -Scope It
        Should -Invoke takeown -Times 0 -Exactly -Scope It
        Should -Invoke icacls -Times 0 -Exactly -Scope It
    }

    It 'AC20_Cli_Force_AsksNothingAndTakesOwnershipThroughTheCoreWithABackup' {
        Invoke-FolderPermissionCli -Path $script:Dir -LogFolder $script:Log -Force

        Should -Invoke Read-Host -Times 0 -Exactly -Scope It
        Should -Invoke Invoke-AclTool -Times 1 -ParameterFilter { $Tool -eq 'takeown' } -Scope It
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
}
