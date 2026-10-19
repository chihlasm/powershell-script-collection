<#
    Tests for D-035 (SQ-015 revision): the old command-line script FolderPermissionManager.ps1
    has no copy-to-subfolders step. It only takes ownership and shows permissions; to grant
    access, add it once on the top folder (inheritance passes it on). Pester 5, run under pwsh.

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
        $root = Join-Path $TestDrive ('nocopy-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $root 'sub1') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $root 'sub2') -Force | Out-Null
        $script:Dir = $root
        $script:Log = Join-Path $TestDrive ('nocopy-logs-' + [guid]::NewGuid().ToString('N'))
        $script:Prompts = [System.Collections.Generic.List[string]]::new()
        $script:Lines = [System.Collections.Generic.List[string]]::new()

        Mock Set-Acl { }
        Mock Copy-FolderPermission { }
        Mock Invoke-AclTool { [PSCustomObject]@{ ExitCode = 0; Output = '' } }
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
        $text | Should -Match '(?i)add it once on the top folder'
        $text | Should -Match '(?i)inherit'
        $text | Should -Not -Match '(?i)copies the permissions set directly'
        $text | Should -Not -Match '(?i)before copying permissions'
    }

    It 'AC15_CliReadmeSaysToGrantAccessOnceOnTheTopFolder' {
        $readme = Get-Content -LiteralPath $script:ReadmePath -Raw
        $match = [regex]::Match($readme, '(?s)### FolderPermissionManager\.ps1 \(CLI\)(.*?)\r?\n## Requirements')
        $match.Success | Should -BeTrue
        $section = $match.Groups[1].Value -replace '\s+', ' '
        $section | Should -Match '(?i)add it once on the top folder'
        $section | Should -Match '(?i)inherit'
        $section | Should -Not -Match '(?i)again before copying'
        $section | Should -Not -Match '(?i)The copy step'
    }
}
