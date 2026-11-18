#Requires -Modules Pester
<#
    Every WPF window in the collection runs in a PowerShell process of its own.

    Why: pwsh.exe crashed (Application Error 1000, Win32Exception 1816 ERROR_NOT_ENOUGH_QUOTA in
    HwndTarget.UpdateWindowSettings) when Server-EventTimeline's window was opened from a
    PowerShell session that had been open for hours - the VS Code PowerShell extension or a
    Windows Terminal tab - and the crash took the whole session with it. A window in a process of
    its own leaves the session it was started from untouched. Each script carries its own copy of
    the check (the folders are self-contained), so every copy is tested here, and a new XAML
    window that skips the check fails this suite.
#>

BeforeDiscovery {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $skip = '\\(dist|work-in-progress|\.worktrees|Tests)\\'
    $script:GuiScripts = @(Get-ChildItem -LiteralPath $repoRoot -Recurse -Filter *.ps1 -File |
            Where-Object { $_.FullName -notmatch $skip } |
            Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'XamlReader' } |
            ForEach-Object { @{ Name = $_.FullName.Substring($repoRoot.Length + 1); Path = $_.FullName } })
}

Describe 'XAML windows run in their own PowerShell process' {
    It 'finds the GUI scripts (so the checks below are not vacuous)' {
        $GuiScripts.Count | Should -BeGreaterOrEqual 7
    }

    Context '<Name>' -ForEach $GuiScripts {
        BeforeAll {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $fn = @($ast.FindAll({
                        param($n)
                        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like 'Test-*OwnProcess'
                    }, $true))
            $script:FnName = if ($fn.Count -eq 1) { $fn[0].Name } else { $null }
            if ($script:FnName) {
                # Defined in this scope only, so each script's own copy is the one tested.
                . ([scriptblock]::Create($fn[0].Extent.Text))
            }
            $script:Calls = @($ast.FindAll({
                        param($n)
                        $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $script:FnName
                    }, $true))
            $script:Tool = 'C:\Tools\Tool\Tool.ps1'
        }

        It 'has one Test-*OwnProcess function' {
            $FnName | Should -Not -BeNullOrEmpty
        }

        It 'calls it at startup' {
            $Calls.Count | Should -BeGreaterOrEqual 1
        }

        It 'is its own process when started with -File and this script, as the relaunch does' {
            & $FnName -CommandLineArgs @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$Tool`"") -ScriptPath $Tool | Should -BeTrue
        }

        It 'is not its own process in the VS Code PowerShell extension' {
            & $FnName -CommandLineArgs @('pwsh.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', 'SQBtAHAA') -ScriptPath $Tool | Should -BeFalse
        }

        It 'is not its own process in an interactive terminal' {
            & $FnName -CommandLineArgs @('pwsh.exe') -ScriptPath $Tool | Should -BeFalse
        }

        It 'is not its own process with -NoExit (the console is meant to stay)' {
            & $FnName -CommandLineArgs @('powershell.exe', '-NoExit', '-File', $Tool) -ScriptPath $Tool | Should -BeFalse
        }

        It 'is not its own process when -File ran a different script' {
            & $FnName -CommandLineArgs @('powershell.exe', '-File', 'C:\Tools\Other\Launcher.ps1') -ScriptPath $Tool | Should -BeFalse
        }
    }
}
