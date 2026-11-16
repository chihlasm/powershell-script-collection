<#
    Regression guard: PortMonitor.ps1 must load on Windows Server 2012 (PowerShell 3.0) and
    2012 R2 (PowerShell 4.0) as shipped, because its console mode (-NoGui / -Once) is meant for
    RMM checks on whatever server a client has. A parse-time feature like '::new()' or a class
    makes the whole script fail to load on PS 3/4 with no useful message.

    Run with Pester 5:  Invoke-Pester .\PortMonitor\Tests

    https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
#>

BeforeAll {
    $script:File = Join-Path (Split-Path -Parent $PSScriptRoot) 'PortMonitor.ps1'
    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:File, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = @($errors)

    # Cmdlets that first shipped in PowerShell 5.0/5.1.
    $script:Ps5OnlyCommands = @(
        'Compress-Archive', 'Expand-Archive', 'New-TemporaryFile', 'Get-ItemPropertyValue',
        'Get-Clipboard', 'Set-Clipboard', 'Write-Information', 'Format-Hex', 'ConvertFrom-String',
        'Clear-RecycleBin', 'New-Guid', 'Import-PowerShellDataFile', 'Get-ComputerInfo',
        'Get-LocalUser', 'ConvertFrom-SddlString'
    )
}

Describe 'PortMonitor.ps1 stays PowerShell 3.0 compatible' {
    It 'parses without errors' {
        $script:ParseErrors | Should -BeNullOrEmpty
    }
    It 'requires no more than PowerShell 3.0' {
        $required = $script:Ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]'3.0')
    }
    It 'defines no classes or enums (PowerShell 5.0 syntax)' {
        @($script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)).Count | Should -Be 0
    }
    It 'does not call ::new() (PowerShell 5.0 syntax)' {
        $news = $script:Ast.FindAll({
                $n = $args[0]
                $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and $n.Member.Extent.Text -eq 'new'
            }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }
    It 'does not use the .Where() / .ForEach() collection methods (PowerShell 4.0)' {
        $m = $script:Ast.FindAll({
                $n = $args[0]
                $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and -not $n.Static -and ('Where', 'ForEach') -contains $n.Member.Extent.Text
            }, $true)
        @($m | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }
    It 'has no using statements (PowerShell 5.0 syntax)' {
        @($script:Ast.UsingStatements).Count | Should -Be 0
    }
    It 'calls no PowerShell 5-only cmdlets' {
        $offenders = $script:Ast.FindAll({
                $c = $args[0]
                $c -is [System.Management.Automation.Language.CommandAst] -and $script:Ps5OnlyCommands -contains $c.GetCommandName()
            }, $true)
        @($offenders | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }
    It 'uses -NoNewline only on Write-Host (Out-File/Set-Content/Add-Content -NoNewline are 5.0)' {
        $p = $script:Ast.FindAll({
                $n = $args[0]
                $n -is [System.Management.Automation.Language.CommandAst] -and
                ('Out-File', 'Set-Content', 'Add-Content') -contains $n.GetCommandName() -and
                @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'NoNewline' }).Count -gt 0
            }, $true)
        @($p | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }
    It 'is pure ASCII, so it needs no BOM to survive Windows PowerShell' {
        $bytes = [System.IO.File]::ReadAllBytes($script:File)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}
