<#
    Regression guard (SQ-014): the FolderPermissionManager command-line script and the shared
    core run on old file servers (PowerShell 3.0 / 4.0), so they may not use 5.0 syntax or
    declare a higher version than they need. Pattern: AD-GroupMembership-Export\Tests\Compatibility.Tests.ps1.

    The core must stay at 3.0; the CLI may declare up to 4.0 (root CLAUDE.md version rules).
    The GUI is a 5.1 admin-workstation tool and is not covered here.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests
    https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#>

BeforeDiscovery {
    $script:Targets = @(
        @{ Name = 'FolderPermissions.Core.ps1'; MaxVersion = '3.0' }
        @{ Name = 'FolderPermissionManager.ps1'; MaxVersion = '4.0' }
    )
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    function Get-ScriptAst {
        param([string]$Name)
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $Name), [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw "Parse errors in ${Name}: $($errors[0].Message)" }
        $ast
    }
}

Describe '<Name> stays old-server compatible' -ForEach $script:Targets {
    BeforeAll { $ast = Get-ScriptAst -Name $Name }

    It 'declares a PowerShell version, and no more than <MaxVersion>' {
        $required = $ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]$MaxVersion)
    }

    It 'defines no classes or enums and has no using statements' {
        @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)).Count | Should -Be 0
        @($ast.UsingStatements).Count | Should -Be 0
    }

    It 'does not call ::new()' {
        $news = $ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and $n.Member.Extent.Text -eq 'new'
        }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }

    It 'does not use #Requires -Modules' {
        @($ast.ScriptRequirements.RequiredModules | Where-Object { $_ }).Count | Should -Be 0
    }
}
