<#
    Static guards for FolderPermissionManager (SQ-015, ACs 4, 11 and 14; Pester 5, pwsh).

    Nothing is run or launched: the scripts are only read as text or parsed into a syntax tree.

    AC4   no script still resets permissions down a tree (the string /reset).
    AC11  every file-system cmdlet that is given a path uses -LiteralPath, so folders called
          "HR [old]" work everywhere (with -Path, [ ] is a wildcard range:
          https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_wildcards).
    AC14  the "Copy Permissions To..." modal, its JavaScript and its handler have no
          "apply recursively" option left.
#>

BeforeAll {
    $script:ToolFolder = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:ScriptFiles = @(Get-ChildItem -LiteralPath $script:ToolFolder -Recurse -File -Filter '*.ps1' |
        Where-Object { $_.FullName.Substring($script:ToolFolder.Length) -notmatch '^[\\/]Tests[\\/]' })
    $script:GuiPath = Join-Path $script:ToolFolder 'FolderPermissionManager-GUI.ps1'

    # Cmdlets (and their usual aliases) that take a file-system path.
    $script:PathCommands = 'Test-Path', 'Get-Item', 'Get-ChildItem', 'Get-Acl', 'Set-Acl', 'Resolve-Path',
        'gi', 'gci', 'ls', 'dir'
    # Switch parameters: they do not take the next word as a value.
    $script:SwitchParameters = 'Force', 'Recurse', 'Directory', 'File', 'Hidden', 'System', 'ReadOnly',
        'Name', 'Audit', 'Relative', 'FollowSymlink', 'IsValid', 'Debug', 'Verbose', 'WhatIf',
        'Confirm', 'UseTransaction'

    function Get-PathArgumentViolation {
        param([string]$File)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$null, [ref]$null)
        $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($c in $commands) {
            $name = $c.GetCommandName()
            if (-not $name -or $script:PathCommands -notcontains $name) { continue }
            $usesPath = $false
            $positional = $false
            $els = $c.CommandElements
            for ($i = 1; $i -lt $els.Count; $i++) {
                $e = $els[$i]
                if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
                    if ($e.ParameterName -eq 'Path') { $usesPath = $true }
                    # "-Name value": the next element is that parameter's value, not a positional path.
                    if (-not $e.Argument -and $script:SwitchParameters -notcontains $e.ParameterName) { $i++ }
                } elseif ($e -is [System.Management.Automation.Language.VariableExpressionAst] -and $e.Splatted) {
                    continue
                } else {
                    $positional = $true
                }
            }
            if ($usesPath -or $positional) {
                $how = if ($usesPath) { 'uses -Path' } else { 'passes a positional path' }
                '{0}:{1} {2} {3}' -f (Split-Path $File -Leaf), $c.Extent.StartLineNumber, $name, $how
            }
        }
    }
}

Describe 'FolderPermissionManager static guards (SQ-015)' {
    It 'AC4_NoScriptContainsIcaclsReset' {
        $script:ScriptFiles.Count | Should -BeGreaterThan 2
        $hits = @($script:ScriptFiles | ForEach-Object {
            $f = $_
            Select-String -LiteralPath $f.FullName -Pattern '/reset' -SimpleMatch |
                ForEach-Object { '{0}:{1}' -f $f.Name, $_.LineNumber }
        })
        $hits -join '; ' | Should -BeNullOrEmpty -Because 'icacls /reset /T wipes every custom permission below the target'
    }

    It 'AC11_EveryFileSystemCmdletUsesLiteralPath' {
        $script:ScriptFiles.Count | Should -BeGreaterThan 2
        $violations = @($script:ScriptFiles | ForEach-Object { Get-PathArgumentViolation $_.FullName })
        $violations -join "`n" | Should -BeNullOrEmpty -Because "-Path treats [ and ] as wildcards, so 'HR [old]' is not found:`n$($violations -join "`n")"
    }

    It 'AC14_CopyModalHasNoRecursiveOptionAndHandlerIgnoresTheField' {
        $raw = Get-Content -LiteralPath $script:GuiPath -Raw
        # Booleans, not the text itself: a failure must not dump the whole GUI script.
        ($raw -match 'replicateRecursive') | Should -BeFalse -Because 'the "Apply recursively" checkbox is gone'

        $fn = [regex]::Match($raw, '(?s)function submitReplicate\(\) \{.*?\n\}')
        $fn.Success | Should -BeTrue
        ($fn.Value -match '(?i)recursive') | Should -BeFalse -Because 'submitReplicate() must not send a recursive field'

        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GuiPath, [ref]$null, [ref]$null)
        $handler = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-ReplicatePermissions' }, $false)
        $handler | Should -Not -BeNullOrEmpty
        ($handler.Extent.Text -match '\.recursive|\$recursive') | Should -BeFalse -Because '/api/replicate must not read $body.recursive'
    }
}
