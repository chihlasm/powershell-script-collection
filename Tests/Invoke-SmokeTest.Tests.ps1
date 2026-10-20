<#
.SYNOPSIS
    Pester 5 tests for SQ-029: the smoke-test runner Tests\Invoke-SmokeTest.ps1.

.DESCRIPTION
    AC18 .. AC22 are unit tests. The runner starts a child process only through the seam function
    Start-SmokeProcess and ends it only through Stop-SmokeProcess; every unit test mocks both
    (and Start-Process throws), so no process is ever started.

    The seam contract these tests pin (the runner implements it):
      Start-SmokeProcess -FilePath <exe> -Arguments <string> -WorkingDirectory <dir> -TimeoutSeconds <int>
          -> object with ExitCode (int), Output (string[], stdout and stderr lines), TimedOut (bool),
             Process (the System.Diagnostics.Process it started)
      Stop-SmokeProcess -Process <that Process object>      (kills only its own child)
      Invoke-SmokeTarget -ScriptPath <gui script> [-TimeoutSeconds <int>]
          -> object with Name, Status (Passed | Failed | TimedOut), Message, Output
      Runner exit code: 0 all passed, 1 any failed, 2 any timed out (2 wins over 1).

    AC23 .. AC25 really start the app (the runner under Windows PowerShell 5.1, which starts the
    GUI with -SmokeTest). They are tagged Integration, so the gate excludes them, and the squad
    never runs them; Michael runs them once at review:
        Invoke-Pester .\Tests\Invoke-SmokeTest.Tests.ps1 -TagFilter Integration

    Run (unit tests):  Invoke-Pester .\Tests\Invoke-SmokeTest.Tests.ps1 -ExcludeTagFilter Integration
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:RunnerPath = Join-Path $PSScriptRoot 'Invoke-SmokeTest.ps1'
    $script:GuiPath = Join-Path $script:RepoRoot 'FolderPermissionManager\FolderPermissionManager-GUI.ps1'
    $script:CorePath = Join-Path $script:RepoRoot 'FolderPermissionManager\FolderPermissions.Core.ps1'
    $global:PassLine = '[PASS] FolderPermissionManager-GUI.ps1: the window opened and closed by itself (render 1234 ms, background check 56 ms)'
    . $script:RunnerPath -LoadFunctionsOnly

    # What the seam returns for a faked child.
    function script:New-FakeRun {
        param([int]$ExitCode = 0, [string[]]$Output = @(), [bool]$TimedOut = $false)
        [PSCustomObject]@{ ExitCode = $ExitCode; Output = $Output; TimedOut = $TimedOut; Process = [PSCustomObject]@{ Id = 4242; Marker = [guid]::NewGuid() } }
    }

    # Runs the whole runner in this process (the seam is mocked); never throws.
    function script:Invoke-RunnerInProcess {
        param([hashtable]$Splat = @{})
        $global:LASTEXITCODE = 99
        $err = $null
        $out = $null
        try { $out = & $script:RunnerPath @Splat *>&1 }
        catch { $err = "$($_.Exception.Message)" }
        [PSCustomObject]@{ Text = (@($out | ForEach-Object { "$_" }) -join "`n"); ExitCode = $global:LASTEXITCODE; Error = $err }
    }
}

Describe 'Runner (unit; no process is started)' {
    AfterAll {
        # Shared with the fakes through globals: in a mock body $script: is the runner run's scope.
        foreach ($n in 'PassLine', 'TimedOutRun', 'Captured') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    }
    BeforeEach {
        # Backstops: nothing but the seam may start or stop a process.
        Mock Start-Process { throw 'Start-Process must not run in the runner tests.' }
        Mock Start-SmokeProcess { throw 'Start-SmokeProcess needs a test-specific fake.' }
        Mock Stop-SmokeProcess { }
    }

    It 'AC18_RunnerPassesOnExitZeroWithPassLine' {
        Mock Start-SmokeProcess { New-FakeRun -ExitCode 0 -Output @('starting', $global:PassLine) }
        $result = $null
        $out = @(& { $global:Captured = Invoke-SmokeTarget -ScriptPath $script:GuiPath } *>&1 | ForEach-Object { "$_" })
        $global:Captured.Status | Should -Be 'Passed'
        ($out -join "`n") | Should -Match '\[PASS\] FolderPermissionManager-GUI\.ps1'
        Should -Invoke Stop-SmokeProcess -Times 0 -Exactly

        $r = Invoke-RunnerInProcess
        $r.ExitCode | Should -Be 0 -Because "a passing target exits 0 (error: $($r.Error))"
        $r.Text | Should -Match '\[PASS\] FolderPermissionManager-GUI\.ps1'
    }

    It 'AC19_RunnerFailsOnExitZeroWithoutPassLine' {
        # What 193a907 looked like: the script returned before the window and PowerShell said 0.
        Mock Start-SmokeProcess { New-FakeRun -ExitCode 0 -Output @() }
        $out = @(& { $global:Captured = Invoke-SmokeTarget -ScriptPath $script:GuiPath } *>&1 | ForEach-Object { "$_" })
        $global:Captured.Status | Should -Be 'Failed'
        "$($global:Captured.Message)" | Should -Match 'the app ended without opening its window \(no PASS line\)'

        $r = Invoke-RunnerInProcess
        $r.Text | Should -Match '\[FAIL\].*the app ended without opening its window \(no PASS line\)'
        $r.ExitCode | Should -Be 1
    }

    It 'AC20_RunnerFailsOnNonZeroExit' {
        Mock Start-SmokeProcess { New-FakeRun -ExitCode 1 -Output @('[FAIL] the background check failed: boom') }
        $out = @(& { $global:Captured = Invoke-SmokeTarget -ScriptPath $script:GuiPath } *>&1 | ForEach-Object { "$_" })
        $global:Captured.Status | Should -Be 'Failed'

        $r = Invoke-RunnerInProcess
        $r.Text | Should -Match '\[FAIL\] FolderPermissionManager-GUI\.ps1' -Because "the runner reports the target (error: $($r.Error))"
        $r.Text | Should -Match '(?i)exit code 1' -Because 'the exit code is printed'
        $r.Text | Should -Match 'the background check failed: boom' -Because "the child's [FAIL] line is printed"
        $r.ExitCode | Should -Be 1
    }

    It 'AC21_RunnerTimeoutKillsChild' {
        $lines = 1..30 | ForEach-Object { "output line $_" }
        $global:TimedOutRun = New-FakeRun -ExitCode -1 -Output $lines -TimedOut $true
        Mock Start-SmokeProcess { $global:TimedOutRun }
        $r = Invoke-RunnerInProcess
        Should -Invoke Start-SmokeProcess -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 90 } -Because 'the default timeout is 90 seconds'
        Should -Invoke Stop-SmokeProcess -Times 1 -Exactly -ParameterFilter { [object]::ReferenceEquals($Process, $global:TimedOutRun.Process) } -Because "only the runner's own child is killed, by its process object (error: $($r.Error))"
        $r.Text | Should -Match 'did not close by itself within 90 seconds'
        $r.Text | Should -Match 'output line 30' -Because 'the last output lines are printed'
        $r.Text | Should -Match 'output line 11'
        $r.Text | Should -Not -Match 'output line 10\b' -Because 'only the last 20 lines are printed'
        $r.ExitCode | Should -Be 2

        $out = @(& { $global:Captured = Invoke-SmokeTarget -ScriptPath $script:GuiPath } *>&1)
        $global:Captured.Status | Should -Be 'TimedOut'

        # 2 wins over 1 when targets differ.
        Mock Start-SmokeProcess {
            if ($Arguments -match 'one\.ps1') { New-FakeRun -ExitCode 1 -Output @('[FAIL] x') } else { $global:TimedOutRun }
        }
        $r = Invoke-RunnerInProcess -Splat @{ ScriptPath = @((Join-Path $TestDrive 'one.ps1'), (Join-Path $TestDrive 'two.ps1')) }
        $r.ExitCode | Should -Be 2 -Because "one failed and one timed out (error: $($r.Error))"

        # The timeout is bounded.
        $global:LASTEXITCODE = 0
        { & $script:RunnerPath -TimeoutSeconds 5 } | Should -Throw
        { & $script:RunnerPath -TimeoutSeconds 601 } | Should -Throw
    }

    It 'AC22_RunnerCommandLine' {
        $global:Captured = $null
        Mock Start-SmokeProcess {
            $global:Captured = [PSCustomObject]@{ FilePath = $FilePath; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory }
            New-FakeRun -ExitCode 0 -Output @($global:PassLine)
        }
        # Started from another folder: the path comes from the runner's own folder.
        Push-Location -LiteralPath $TestDrive
        try { $r = Invoke-RunnerInProcess } finally { Pop-Location }
        Should -Invoke Start-SmokeProcess -Times 1 -Exactly -Because "the default list is the Folder Permission Manager GUI (error: $($r.Error))"
        $global:Captured.FilePath | Should -Be (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        $expectedGui = [System.IO.Path]::GetFullPath($script:GuiPath)
        $global:Captured.Arguments | Should -Be ('-NoProfile -ExecutionPolicy Bypass -STA -File "' + $expectedGui + '" -SmokeTest')
        $global:Captured.Arguments | Should -Not -Match '-LogFolder|-DriveMap|-NoExit'
        [System.IO.Path]::GetFullPath($global:Captured.WorkingDirectory).TrimEnd('\') | Should -Be ([System.IO.Path]::GetFullPath($script:RepoRoot).TrimEnd('\'))

        # -ScriptPath replaces the default list.
        $other = Join-Path $TestDrive 'app\Other-GUI.ps1'
        $r = Invoke-RunnerInProcess -Splat @{ ScriptPath = $other }
        Should -Invoke Start-SmokeProcess -Times 1 -Exactly -ParameterFilter { $Arguments -match [regex]::Escape($other) }
        $global:Captured.Arguments | Should -Match ([regex]::Escape('-File "' + $other + '" -SmokeTest'))
    }

    It 'Backstop_OnlyTheSeamStartsAProcess' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:RunnerPath, [ref]$null, [ref]$null)
        $process = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -and $n.TypeName.FullName -match '^System\.Diagnostics\.Process(StartInfo)?$' }, $true)
        foreach ($n in $process) {
            $fn = $n.Parent
            while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
            $fn | Should -Not -BeNullOrEmpty -Because '[System.Diagnostics.Process] must sit inside a function'
            $fn.Name | Should -Be 'Start-SmokeProcess' -Because '[System.Diagnostics.Process] may appear only inside Start-SmokeProcess'
        }
        $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -match '^(Start-Process|saps|start)$' }, $true)
        @($cmds).Count | Should -Be 0 -Because 'the runner never uses Start-Process'
    }

    It 'Backstop_RunnerIsAsciiAndDeclaresFiveOne' {
        $bytes = [IO.File]::ReadAllBytes($script:RunnerPath)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0 -Because 'the runner is pure ASCII'
        (Get-Content -LiteralPath $script:RunnerPath -TotalCount 1) | Should -Be '#Requires -Version 5.1'
    }
}

Describe 'Real launch' -Tag 'Integration' {
    # These start the real app (off-screen window). Excluded from the gate; not run by the squad.
    BeforeAll {
        $script:PsExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        function script:Invoke-RealRunner {
            param([string[]]$ExtraArgs = @())
            $out = & $script:PsExe -NoProfile -ExecutionPolicy Bypass -File $script:RunnerPath @ExtraArgs 2>&1
            [PSCustomObject]@{ Text = (@($out | ForEach-Object { "$_" }) -join "`n"); ExitCode = $LASTEXITCODE }
        }
    }

    It 'AC23_RealSmokePasses' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-RealRunner
        $sw.Stop()
        $r.ExitCode | Should -Be 0 -Because $r.Text
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 90
        $r.Text | Should -Match '\[PASS\] FolderPermissionManager-GUI\.ps1'
        # No UAC: the child ran under this test's own token and printed no relaunch line.
        $r.Text | Should -Not -Match '(?i)administrator'
    }

    It 'AC24_RealSmokeLeavesNoFiles' {
        $appDir = Join-Path $TestDrive 'app'
        $dataDir = Join-Path $TestDrive 'appdata'
        $tempDir = Join-Path $TestDrive 'temp'
        New-Item -ItemType Directory -Path $appDir, $dataDir, $tempDir -Force | Out-Null
        Copy-Item -LiteralPath $script:GuiPath, $script:CorePath -Destination $appDir
        $saved = @{ LOCALAPPDATA = $env:LOCALAPPDATA; TEMP = $env:TEMP; TMP = $env:TMP }
        try {
            $env:LOCALAPPDATA = $dataDir; $env:TEMP = $tempDir; $env:TMP = $tempDir
            $r = Invoke-RealRunner -ExtraArgs @('-ScriptPath', (Join-Path $appDir 'FolderPermissionManager-GUI.ps1'))
        }
        finally { $env:LOCALAPPDATA = $saved.LOCALAPPDATA; $env:TEMP = $saved.TEMP; $env:TMP = $saved.TMP }
        $r.ExitCode | Should -Be 0 -Because $r.Text
        @(Get-ChildItem -LiteralPath $appDir -Force | Select-Object -ExpandProperty Name | Sort-Object) | Should -Be @('FolderPermissionManager-GUI.ps1', 'FolderPermissions.Core.ps1')
        @(Get-ChildItem -LiteralPath $dataDir -Recurse -Force).Count | Should -Be 0
    }

    It 'AC25_RealSmokeCatchesTheStartupGuardBug' {
        $appDir = Join-Path $TestDrive 'regress'
        New-Item -ItemType Directory -Path $appDir -Force | Out-Null
        Copy-Item -LiteralPath $script:CorePath -Destination $appDir
        # 193a907 put back: the core's -LoadFunctionsOnly is no longer kept apart from the app's.
        $text = [IO.File]::ReadAllText($script:GuiPath)
        $broken = $text -replace '(?m)^\$loadOnly = .*\r?\n', '' -replace '(?m)^\$LoadFunctionsOnly = \[switch\]\$loadOnly\r?\n', ''
        $broken | Should -Not -Be $text -Because 'the regression must really be put back'
        $copy = Join-Path $appDir 'FolderPermissionManager-GUI.ps1'
        [IO.File]::WriteAllText($copy, $broken, [System.Text.Encoding]::ASCII)
        $r = Invoke-RealRunner -ExtraArgs @('-ScriptPath', $copy)
        $r.ExitCode | Should -Be 1 -Because $r.Text
        $r.Text | Should -Match 'the app ended without opening its window'
    }
}
