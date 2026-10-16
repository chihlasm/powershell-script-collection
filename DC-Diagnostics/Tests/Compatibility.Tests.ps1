<#
    Regression guard: Get-DCDiagnostics.ps1 must run on Windows Server 2012 (PowerShell 3.0)
    and 2012 R2 (PowerShell 4.0) as shipped. Old DCs are exactly the servers that get
    diagnosed before a migration, so a '#Requires -Version 5.1' (or a ::new() / class
    definition, which fail to PARSE on 3.0/4.0) would stop the script before it prints
    anything useful.

    Also covers the repadmin /replsummary parser: matching the word 'FAIL' flagged every
    run because the column header itself reads 'fails/total'.

    Run with Pester 5:  Invoke-Pester .\DC-Diagnostics\Tests

    https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle
    https://learn.microsoft.com/troubleshoot/windows-server/active-directory/replication-error-8418
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Get-DCDiagnostics.ps1'

    $tokens = $null; $errors = $null
    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$tokens, [ref]$errors)
    $script:ParseErrors = @($errors)

    function Get-ScriptFunctionText {
        param([string]$Name)
        $fn = $script:Ast.Find({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $Name
        }, $true)
        if (-not $fn) { throw "Function $Name not found" }
        return $fn.Extent.Text
    }

    # Cmdlets that first shipped in PowerShell 5.0/5.1.
    $script:Ps5OnlyCommands = @(
        'Compress-Archive', 'Expand-Archive', 'New-TemporaryFile', 'Get-ItemPropertyValue',
        'Get-Clipboard', 'Set-Clipboard', 'Write-Information', 'Format-Hex', 'ConvertFrom-String',
        'Clear-RecycleBin', 'New-Guid', 'Get-ComputerInfo', 'Get-LocalUser', 'Get-LocalGroup'
    )
}

Describe 'Get-DCDiagnostics stays PowerShell 3.0 compatible' {

    It 'parses without errors' {
        $script:ParseErrors.Count | Should -Be 0
    }

    It 'requires no more than PowerShell 3.0 and declares it' {
        $required = $script:Ast.ScriptRequirements.RequiredPSVersion
        $required | Should -Not -BeNullOrEmpty
        $required | Should -BeLessOrEqual ([version]'3.0')
    }

    It 'does not use #Requires -Modules or -RunAsAdministrator (4.0)' {
        $script:Ast.ScriptRequirements.RequiredModules | Should -BeNullOrEmpty
        $script:Ast.ScriptRequirements.IsElevationRequired | Should -BeFalse
    }

    It 'defines no classes or enums (PowerShell 5.0 syntax)' {
        $types = $script:Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst] }, $true)
        @($types).Count | Should -Be 0
    }

    It 'does not call ::new() (PowerShell 5.0 syntax)' {
        $news = $script:Ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $n.Static -and $n.Member.Extent.Text -eq 'new'
        }, $true)
        @($news | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
    }

    It 'does not use the .Where() / .ForEach() collection methods (PowerShell 4.0)' {
        $calls = $script:Ast.FindAll({
            $n = $args[0]
            $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            -not $n.Static -and $n.Member.Extent.Text -in @('Where', 'ForEach')
        }, $true)
        @($calls | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Extent.Text)" }) | Should -BeNullOrEmpty
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
}

Describe 'Get-DCDiagnostics defaults' {
    It 'does not default OutputPath to a client-specific folder' {
        (Get-Content -LiteralPath $script:ScriptPath -Raw) | Should -Not -Match 'VC3'
    }

    It 'defaults OutputPath to the current directory' {
        $p = $script:Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'OutputPath' }
        $p.DefaultValue.Extent.Text | Should -Match 'Get-Location'
    }

    It 'is local-only: no -ComputerName parameter' {
        $names = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names | Should -Not -Contain 'ComputerName'
    }
}

Describe 'Test-ReplSummaryProblem' {
    BeforeAll { . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Test-ReplSummaryProblem'))) }

    It 'does not flag a healthy summary (the header contains the word "fails")' {
        $lines = @(
            'Replication Summary Start Time: 2026-06-20 10:00:00',
            'Source DSA          largest delta    fails/total %%   error',
            ' DC01                      04m:11s    0 /   5    0',
            'Destination DSA     largest delta    fails/total %%   error',
            ' DC02                      01h:02m:16s    0 /   5    0'
        )
        Test-ReplSummaryProblem -Lines $lines | Should -BeFalse
    }

    It 'flags a row with a non-zero failure count' {
        $lines = @(
            'Source DSA          largest delta    fails/total %%   error',
            ' DC01                      04h:02m:16s    4 /   5   80  (8418)'
        )
        Test-ReplSummaryProblem -Lines $lines | Should -BeTrue
    }

    It 'flags a delta measured in days' {
        $lines = @(
            'Destination DSA     largest delta    fails/total %%   error',
            ' DC02                      02d.04h:11m:22s    0 /   5    0'
        )
        Test-ReplSummaryProblem -Lines $lines | Should -BeTrue
    }
}

Describe 'Get-EventsSafe' {
    BeforeAll { . ([scriptblock]::Create((Get-ScriptFunctionText -Name 'Get-EventsSafe'))) }

    It 'returns an empty array when no events match (not an error)' {
        Mock Get-WinEvent {
            $ex = New-Object System.Exception 'No events were found that match the specified selection criteria.'
            $er = New-Object System.Management.Automation.ErrorRecord($ex, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            throw $er
        }
        @(Get-EventsSafe -Filter @{ LogName = 'System' }).Count | Should -Be 0
    }

    It 'rethrows other failures such as a missing log' {
        Mock Get-WinEvent { throw 'There is not an event log on the localhost computer that matches "DFS Replication".' }
        { Get-EventsSafe -Filter @{ LogName = 'DFS Replication' } } | Should -Throw
    }
}
