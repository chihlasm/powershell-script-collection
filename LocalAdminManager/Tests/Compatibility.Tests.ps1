<#
    Regression guard: LocalAdminManager must run on Windows Server 2012 (PowerShell 3.0) as
    shipped. A parse-time feature like '::new()' or a class definition makes the whole script
    fail to load on PS 3/4 with no useful message.

    https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
    Run with Pester 5:  Invoke-Pester .\LocalAdminManager\Tests
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'LocalAdminManager.ps1'
    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = $errors
    $script:Ps5OnlyCommands = @(
        'Compress-Archive', 'Expand-Archive', 'New-TemporaryFile', 'Get-ItemPropertyValue',
        'Get-Clipboard', 'Set-Clipboard', 'Write-Information', 'Format-Hex',
        'ConvertFrom-String', 'Clear-RecycleBin', 'New-Guid',
        # LocalAccounts cmdlets are 5.1 and have no -ComputerName (the original bug).
        'Get-LocalGroupMember', 'Add-LocalGroupMember', 'Remove-LocalGroupMember',
        'Get-LocalGroup', 'Get-LocalUser'
    )
}

Describe 'LocalAdminManager.ps1 stays PowerShell 3.0 compatible' {

    It 'AC17_parses without errors' {
        @($script:ParseErrors).Count | Should -Be 0
    }

    It 'AC17_requires no more than PowerShell 3.0, and declares it' {
        $required = $script:Ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]'3.0')
    }

    It 'AC17_does not use #Requires -RunAsAdministrator (PowerShell 4.0)' {
        $script:Ast.ScriptRequirements.IsElevationRequired | Should -BeFalse
    }

    It 'AC17_defines no classes or enums' {
        $types = $script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)
        @($types).Count | Should -Be 0
    }

    It 'AC17_does not call ::new()' {
        $news = $script:Ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Static -and $n.Member.Extent.Text -eq 'new'
        }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }

    It 'AC17_has_no_using_statements' {
        @($script:Ast.UsingStatements).Count | Should -Be 0
    }

    It 'AC17_does_not_use_the_.Where()_or_.ForEach()_methods (PowerShell 4.0)' {
        $calls = $script:Ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            -not $n.Static -and ($n.Member.Extent.Text -in 'Where', 'ForEach')
        }, $true)
        @($calls | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }

    It 'AC17_calls_no_PowerShell_5_only_cmdlets' {
        $offenders = $script:Ast.FindAll({
            $c = $args[0]
            $c -is [System.Management.Automation.Language.CommandAst] -and
            $script:Ps5OnlyCommands -contains $c.GetCommandName()
        }, $true)
        @($offenders | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }
}
