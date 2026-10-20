<#
.SYNOPSIS
    Pester 5 tests for SQ-029: the -SmokeTest start mode of FolderPermissionManager-GUI.ps1.

.DESCRIPTION
    One test per acceptance criterion (AC1 .. AC17), named AC<n>_<Behavior>. Same loading pattern
    as FolderPermissionManager-App.Tests.ps1: the core and then the app are dot-sourced with
    -LoadFunctionsOnly.

    The in-process runs (AC3 .. AC8, AC16, AC17) run the real top of the script with
    `& $AppPath -SmokeTest`. Pester mocks are aliases, so they outrank the functions the script
    defines when it runs. Everything that touches the machine is a fake that throws, and each
    throwing fake is also asserted with `Should -Invoke -Times 0 -Exactly`, so a missed path fails
    loudly instead of reading a drive, the registry or a file. Start-PermissionWindow,
    Initialize-BackgroundPool and Invoke-AppShutdown are recording fakes (no window, no
    Environment.Exit in the test host). Add-Type is faked too, so the WPF assemblies are not
    loaded by these runs (AC9 must never be able to show a real message box).

    The state a faked Start-PermissionWindow sets (the smoke state) lives in the script scope of
    the app run, which the fake cannot reach by name: Get-AppScopeVariable walks the call stack
    for it. The smoke state holds Rendered, ProbeOk, ProbeDone, TimedOut, RenderMs, ProbeMs and
    Started, so the fake sets properties on the object it finds.

    Nothing here launches the app as a process. The tests that do (real -SmokeTest start) are in
    Tests\Invoke-SmokeTest.Tests.ps1 and are tagged Integration.

    Run:  Invoke-Pester .\FolderPermissionManager\Tests\FolderPermissionManager-SmokeTest.Tests.ps1
#>

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:AppPath = Join-Path $script:Root 'FolderPermissionManager-GUI.ps1'
    $script:CorePath = Join-Path $script:Root 'FolderPermissions.Core.ps1'
    $script:ReadmePath = Join-Path $script:Root 'README.md'
    $script:IsSta = ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')

    $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AppPath, [ref]$null, [ref]$null)
    $script:ParamNames = @()
    if ($script:Ast.ParamBlock) { $script:ParamNames = @($script:Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
    . $script:CorePath -LoadFunctionsOnly
    . $script:AppPath -LoadFunctionsOnly
    if ($script:IsSta) { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase }

    function script:Set-TestAppPaths {
        $script:AppDataFolder = Join-Path $TestDrive 'appdata\FolderPermissionManager'
        $script:SettingsPath = Join-Path $script:AppDataFolder 'settings.json'
        $script:ErrorLogPath = Join-Path $script:AppDataFolder 'gui-errors.log'
    }
    Set-TestAppPaths

    # Backstops (same as the other FolderPermissionManager suites).
    Mock Set-Acl { throw 'Set-Acl must not run in the SQ-029 tests.' }
    Mock Invoke-AclTool { throw 'Invoke-AclTool must not run in the SQ-029 tests.' }

    # The app run by `& $AppPath` keeps its variables in its own script scope. A faked function
    # reaches them by walking the scopes upwards from itself (nearest first).
    function script:Get-AppScopeVariable {
        param([Parameter(Mandatory)][string]$Name)
        for ($i = 1; $i -lt 40; $i++) {
            try { $v = Get-Variable -Name $Name -Scope $i -ValueOnly -ErrorAction Stop }
            catch {
                if ($_.Exception -is [System.Management.Automation.ItemNotFoundException]) { continue }
                break
            }
            if ($null -ne $v) { return $v }
        }
        $null
    }

    # What a faked Start-PermissionWindow does for "the window rendered and the probe came back".
    function script:Set-FakeSmokeState {
        param([bool]$Rendered = $true, [bool]$ProbeOk = $true)
        $state = Get-AppScopeVariable -Name 'SmokeState'
        if ($null -eq $state) { return }
        $state.Rendered = $Rendered
        $state.ProbeOk = $ProbeOk
        $state.ProbeDone = $ProbeOk
        $state.RenderMs = 1234
        $state.ProbeMs = 56
    }

    # Runs the app in this process; never throws, so a missed path shows as a failed assertion
    # with the reason, not as a crash.
    function script:Invoke-AppInProcess {
        param([string]$Path = $script:AppPath, [hashtable]$Splat = @{ SmokeTest = $true })
        $global:LASTEXITCODE = 99
        $err = $null
        $out = $null
        try { $out = & $Path @Splat *>&1 }
        catch { $err = "$($_.Exception.Message)" }
        [PSCustomObject]@{
            Text     = (@($out | ForEach-Object { "$_" }) -join "`n")
            ExitCode = $global:LASTEXITCODE
            Error    = $err
        }
    }
}

# The mocks every in-process run needs. Called from BeforeEach (Mock in a helper function would
# be scoped to the helper).
Describe 'App in smoke mode' {
    BeforeEach {
        $script:SmokeMode = $false
        $script:SmokeFailures = [System.Collections.Generic.List[string]]::new()
    }
    AfterEach {
        $script:SmokeMode = $false
        Set-TestAppPaths
    }

    Context 'Declaration and startup action' {
        It 'AC1_SmokeTestSwitchIsDocumented' {
            $p = $script:Ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SmokeTest' }
            $p | Should -Not -BeNullOrEmpty -Because 'the app needs a -SmokeTest parameter'
            $p.StaticType | Should -Be ([switch]) -Because '-SmokeTest is a switch'

            $help = $script:Ast.GetHelpContent()
            $help.Parameters.Keys | Should -Contain 'SMOKETEST'
            @($help.Examples | Where-Object { "$_" -match '-SmokeTest' }).Count | Should -BeGreaterThan 0 -Because 'an .EXAMPLE must show -SmokeTest'

            $text = "$($help.Parameters['SMOKETEST'])"
            $text | Should -Match '(?i)administrator' -Because 'the help says the smoke test asks for no administrator rights'
            $text | Should -Match '(?i)single-instance|instance lock|lock' -Because 'it takes no single-instance lock'
            $text | Should -Match '(?i)drives' -Because 'it lists no drives'
            $text | Should -Match '(?i)settings' -Because 'it reads no settings'
            $text | Should -Match '(?i)writes? no file|no file|nothing is written' -Because 'it writes no file'
            $text | Should -Match 'Logs' -Because 'no Logs folder is created'
            $text | Should -Match 'settings\.json'
            $text | Should -Match 'gui-errors\.log'
            $text | Should -Match '(?i)probe'

            $readme = [IO.File]::ReadAllText($script:ReadmePath)
            $m = [regex]::Match($readme, '(?ms)^#{1,4}\s+Smoke test.*?(?=^#{1,4}\s|\z)')
            $m.Success | Should -BeTrue -Because 'the README needs a "Smoke test" section'
            $m.Value | Should -Match 'Invoke-SmokeTest\.ps1' -Because 'the section shows the runner command'
            $m.Value | Should -Match '(?i)exit code' -Because 'the section lists the exit codes'
            $m.Value | Should -Match '\b2\b' -Because 'exit code 2 (timeout) is listed'
        }

        It 'AC2_StartupActionInSmokeMode' {
            Get-StartupAction -IsSta:$true -IsAdmin:$false -SmokeTest | Should -Be 'Continue'
            Get-StartupAction -IsSta:$true -IsAdmin:$true -SmokeTest | Should -Be 'Continue'
            Get-StartupAction -IsSta:$false -IsAdmin:$false -SmokeTest | Should -Be 'SmokeNeedsSta'
            Get-StartupAction -IsSta:$false -IsAdmin:$true -SmokeTest | Should -Be 'SmokeNeedsSta'
            # Unchanged without -SmokeTest (AC9 of the App suite).
            Get-StartupAction -IsSta:$false -IsAdmin:$false | Should -Be 'RelaunchSta'
            Get-StartupAction -IsSta:$false -IsAdmin:$true | Should -Be 'RelaunchSta'
            Get-StartupAction -IsSta:$true -IsAdmin:$false | Should -Be 'RelaunchElevated'
            Get-StartupAction -IsSta:$true -IsAdmin:$true | Should -Be 'Continue'
        }
    }

    Context 'In-process smoke runs' {
        BeforeEach {
            # Answers as the real function would for a non-admin STA caller.
            Mock Get-StartupAction { if ($SmokeTest) { 'Continue' } else { 'RelaunchElevated' } }
            Mock Add-Type { }
            Mock Start-PermissionWindow { }
            Mock Initialize-BackgroundPool { }
            Mock Invoke-AppShutdown { }
            Mock Get-LocalAppDataFolder { Join-Path $TestDrive 'appdata' }
            # Anything that would elevate, relaunch, lock or touch the machine throws.
            Mock Request-Elevation { throw 'Request-Elevation must not run in smoke mode.' }
            Mock Start-Process { throw 'Start-Process must not run in smoke mode.' }
            Mock Enter-SingleInstance { throw 'Enter-SingleInstance must not run in smoke mode.' }
            Mock Get-InstanceMutexName { throw 'Get-InstanceMutexName must not run in smoke mode.' }
            Mock Get-CimInstance { throw 'Get-CimInstance must not run in smoke mode.' }
            Mock Limit-AppErrorLog { throw 'Limit-AppErrorLog must not run in smoke mode.' }
            Mock Resolve-ChangeLogFolder { throw 'Resolve-ChangeLogFolder must not run in smoke mode.' }
            Mock Test-LogFolderWritable { throw 'Test-LogFolderWritable must not run in smoke mode.' }
            Mock Get-SavedTheme { throw 'Get-SavedTheme must not run in smoke mode.' }
            Mock Set-SavedTheme { throw 'Set-SavedTheme must not run in smoke mode.' }
            Mock Save-UnloggedChangeRows { throw 'Save-UnloggedChangeRows must not run in smoke mode.' }
            Mock Get-LiveDriveMap { throw 'Get-LiveDriveMap must not run in smoke mode.' }
            Mock Get-RememberedDriveMap { throw 'Get-RememberedDriveMap must not run in smoke mode.' }
            Mock Get-OneDriveFolder { throw 'Get-OneDriveFolder must not run in smoke mode.' }
            Mock Get-OneDriveSyncRoot { throw 'Get-OneDriveSyncRoot must not run in smoke mode.' }
            Mock Update-DriveList { throw 'Update-DriveList must not run in smoke mode.' }
            Mock Get-ChildItem { throw 'Registry read (Get-ChildItem HKCU:) must not run in smoke mode.' } -ParameterFilter { "$Path$LiteralPath" -like 'HKCU:*' }
            Mock Get-ItemProperty { throw 'Registry read (Get-ItemProperty HKCU:) must not run in smoke mode.' } -ParameterFilter { "$Path$LiteralPath" -like 'HKCU:*' }
        }

        It 'AC3_SmokeNeverElevatesOrRelaunches' {
            $r = Invoke-AppInProcess
            Should -Invoke Request-Elevation -Times 0 -Exactly
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Start-PermissionWindow -Times 1 -Exactly -Because "the smoke run must reach the window (error: $($r.Error))"
        }

        It 'AC4_SmokeTakesNoInstanceLock' {
            $script:InstanceMutex = $null
            $r = Invoke-AppInProcess
            Should -Invoke Enter-SingleInstance -Times 0 -Exactly
            Should -Invoke Get-InstanceMutexName -Times 0 -Exactly
            $script:InstanceMutex | Should -BeNullOrEmpty
            Should -Invoke Invoke-AppShutdown -Times 1 -Exactly -ParameterFilter { $null -eq $Mutex } -Because "shutdown gets no mutex (error: $($r.Error))"
        }

        It 'AC5_SmokeReadsAndWritesNoAppFiles' {
            $appDir = Join-Path $TestDrive 'app'
            $dataDir = Join-Path $TestDrive 'appdata'
            New-Item -ItemType Directory -Path $appDir, $dataDir -Force | Out-Null
            Copy-Item -LiteralPath $script:AppPath, $script:CorePath -Destination $appDir
            $r = Invoke-AppInProcess -Path (Join-Path $appDir 'FolderPermissionManager-GUI.ps1')
            foreach ($name in 'Limit-AppErrorLog', 'Resolve-ChangeLogFolder', 'Test-LogFolderWritable', 'Get-SavedTheme', 'Set-SavedTheme', 'Save-UnloggedChangeRows') {
                Should -Invoke $name -Times 0 -Exactly -Because "$name must not run in smoke mode (error: $($r.Error))"
            }
            Test-Path -LiteralPath (Join-Path $appDir 'Logs') | Should -BeFalse -Because 'no Logs folder next to the script'
            @(Get-ChildItem -LiteralPath $dataDir -Recurse -Force).Count | Should -Be 0 -Because 'nothing is written under LOCALAPPDATA'
            Should -Invoke Start-PermissionWindow -Times 1 -Exactly -Because "the run must get to the window (error: $($r.Error))"
        }

        It 'AC6_SmokeReadsNoDrivesOrRegistry' {
            $script:SeenDriveMap = 'not set'
            Mock Start-PermissionWindow { $script:SeenDriveMap = Get-AppScopeVariable -Name 'MappedDrives' }
            $r = Invoke-AppInProcess
            foreach ($name in 'Get-LiveDriveMap', 'Get-RememberedDriveMap', 'Get-CimInstance', 'Get-OneDriveFolder', 'Get-OneDriveSyncRoot', 'Update-DriveList') {
                Should -Invoke $name -Times 0 -Exactly -Because "$name must not run in smoke mode (error: $($r.Error))"
            }
            Should -Invoke Get-ChildItem -Times 0 -Exactly -ParameterFilter { "$Path$LiteralPath" -like 'HKCU:*' }
            Should -Invoke Get-ItemProperty -Times 0 -Exactly -ParameterFilter { "$Path$LiteralPath" -like 'HKCU:*' }
            $script:SeenDriveMap | Should -Not -Be 'not set' -Because "the window must be started (error: $($r.Error))"
            $null -ne $script:SeenDriveMap | Should -BeTrue -Because 'the window is handed a drive map, an empty one'
            @($script:SeenDriveMap.Keys).Count | Should -Be 0 -Because 'the drive map handed to the window is empty'
        }

        It 'AC7_SmokeWithoutStaFailsWithoutRelaunch' {
            Mock Get-StartupAction { 'SmokeNeedsSta' }
            $r = Invoke-AppInProcess
            $r.Text | Should -Match '\[FAIL\].*-STA' -Because 'one [FAIL] line names -STA'
            @($r.Text -split "`n" | Where-Object { $_ -match '^\[FAIL\]' }).Count | Should -Be 1
            Should -Invoke Start-Process -Times 0 -Exactly
            Should -Invoke Start-PermissionWindow -Times 0 -Exactly
            $r.ExitCode | Should -Be 1
        }

        It 'AC8_SmokeRefusesLogFolderAndDriveMap' {
            Mock Get-DriveMapSet { throw 'Get-DriveMapSet must not run when -SmokeTest is refused.' }
            foreach ($splat in @{ SmokeTest = $true; LogFolder = (Join-Path $TestDrive 'logs') }, @{ SmokeTest = $true; DriveMap = 'H=\\fs01\home' }) {
                $r = Invoke-AppInProcess -Splat $splat
                $r.Text | Should -Match '(?s)\[FAIL\].*-LogFolder.*-DriveMap' -Because "the refusal names both ($($splat.Keys -join ','))"
                $r.ExitCode | Should -Be 1
            }
            Should -Invoke Get-DriveMapSet -Times 0 -Exactly
            Should -Invoke Get-StartupAction -Times 0 -Exactly
            Should -Invoke Start-PermissionWindow -Times 0 -Exactly

            # -WhatIf is accepted: the dry-run pill is part of what renders.
            $r = Invoke-AppInProcess -Splat @{ SmokeTest = $true; WhatIf = $true }
            Should -Invoke Start-PermissionWindow -Times 1 -Exactly -Because "-SmokeTest -WhatIf must start (error: $($r.Error))"
        }

        It 'AC16_SmokeExitCodeReachesShutdown' {
            Mock Start-PermissionWindow { Set-FakeSmokeState -Rendered $true -ProbeOk $true }
            $r = Invoke-AppInProcess
            $r.Text | Should -Match '\[PASS\]' -Because "a [PASS] line is written (error: $($r.Error))"
            Should -Invoke Invoke-AppShutdown -Times 1 -Exactly -ParameterFilter { $ExitCode -eq 0 }
            $r.ExitCode | Should -Be 0

            Mock Start-PermissionWindow { Set-FakeSmokeState -Rendered $false -ProbeOk $true }
            $r = Invoke-AppInProcess
            $r.Text | Should -Match '\[FAIL\]' -Because "a [FAIL] line is written (error: $($r.Error))"
            $r.Text | Should -Not -Match '\[PASS\]'
            Should -Invoke Invoke-AppShutdown -Times 1 -Exactly -ParameterFilter { $ExitCode -eq 1 }
            $r.ExitCode | Should -Be 1
        }
    }

    Context 'Normal start is unchanged' {
        It 'AC17_NormalStartUnchanged' {
            Mock Get-StartupAction { 'RelaunchElevated' }
            Mock Add-Type { }
            Mock Get-LiveDriveMap { @{} }
            Mock Get-RememberedDriveMap { @{} }
            Mock Get-LocalAppDataFolder { Join-Path $TestDrive 'appdata' }
            Mock Limit-AppErrorLog { }
            Mock Request-Elevation { $true }
            Mock Start-Process { throw 'Start-Process must not run in this test.' }
            Mock Enter-SingleInstance { throw 'Enter-SingleInstance must not run in this test.' }
            Mock Start-PermissionWindow { throw 'Start-PermissionWindow must not run in this test.' }
            Mock Initialize-BackgroundPool { }
            Mock Invoke-AppShutdown { }
            $r = Invoke-AppInProcess -Splat @{}
            Should -Invoke Get-LiveDriveMap -Times 1 -Exactly -Because "the normal start reads the live drives (error: $($r.Error))"
            Should -Invoke Get-RememberedDriveMap -Times 1 -Exactly
            Should -Invoke Request-Elevation -Times 1 -Exactly
        }
    }

    Context 'Smoke-mode helpers' {
        It 'AC9_SmokeShowsNoMessageBox' {
            # Guard: never call the real functions unless they check smoke mode first, or the
            # test itself would block on a modal message box.
            foreach ($f in 'Show-AppMessage', 'Show-AppQuestion') {
                (Get-Command $f -CommandType Function).ScriptBlock.ToString() | Should -Match 'SmokeMode' -Because "$f must check `$script:SmokeMode before showing a box (test not run to avoid a real message box)"
            }
            $script:SmokeMode = $true
            $out = @(Show-AppMessage -Icon Error -Message 'x' *>&1 | ForEach-Object { "$_" })
            ($out -join "`n") | Should -Match '\[FAIL\].*x'
            $script:SmokeFailures.Count | Should -Be 1
            $out = @(Show-AppQuestion -Message 'y' *>&1)
            $answer = @($out | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
            ($out | ForEach-Object { "$_" }) -join "`n" | Should -Match '\[FAIL\].*y'
            $answer.Count | Should -Be 1
            $answer[0] | Should -BeFalse -Because 'the safe answer is No'
            $script:SmokeFailures.Count | Should -Be 2
        }

        It 'AC10_SmokeErrorLogGoesToConsole' {
            $script:SmokeMode = $true
            $script:ErrorLogPath = Join-Path $TestDrive 'smoke-log\gui-errors.log'
            $out = @(Write-AppError 'boom' *>&1 | ForEach-Object { "$_" })
            Test-Path -LiteralPath $script:ErrorLogPath | Should -BeFalse -Because 'smoke mode writes no log file'
            Test-Path -LiteralPath (Split-Path -Parent $script:ErrorLogPath) | Should -BeFalse
            ($out -join "`n") | Should -Match '\[FAIL\].*boom'
            $script:SmokeFailures.Count | Should -Be 1
        }

        It 'AC11_SmokeVerdict' {
            $pass = Get-SmokeVerdict -Rendered $true -ProbeOk $true -TimedOut $false -Failures @() -RenderMs 1234 -ProbeMs 56
            $pass.ExitCode | Should -Be 0
            @($pass.Lines).Count | Should -Be 1
            $pass.Lines[0] | Should -Match '^\[PASS\]'
            $pass.Lines[0] | Should -Match '1234' -Because 'the render time (ms) is in the line'
            $pass.Lines[0] | Should -Match '56' -Because 'the probe time (ms) is in the line'

            # Every other combination fails.
            foreach ($c in @(
                    @{ R = $false; P = $true; T = $false; F = @() }
                    @{ R = $true; P = $false; T = $false; F = @() }
                    @{ R = $true; P = $true; T = $true; F = @() }
                    @{ R = $true; P = $true; T = $false; F = @('something broke') }
                    @{ R = $false; P = $false; T = $true; F = @('a', 'b') })) {
                $v = Get-SmokeVerdict -Rendered $c.R -ProbeOk $c.P -TimedOut $c.T -Failures $c.F -RenderMs 0 -ProbeMs 0
                $v.ExitCode | Should -Be 1 -Because ($c | ConvertTo-Json -Compress)
                @($v.Lines).Count | Should -BeGreaterThan 0
                foreach ($l in $v.Lines) { $l | Should -Match '^\[FAIL\]' }
                $v.Lines | Should -Not -Match '\[PASS\]'
            }

            $v = Get-SmokeVerdict -Rendered $false -ProbeOk $true -TimedOut $true -Failures @() -RenderMs 0 -ProbeMs 0
            ($v.Lines -join "`n") | Should -Match 'the window did not finish rendering within 30 seconds'
            $v = Get-SmokeVerdict -Rendered $true -ProbeOk $false -TimedOut $true -Failures @() -RenderMs 5 -ProbeMs 0
            ($v.Lines -join "`n") | Should -Match 'the background check did not come back'
            $v = Get-SmokeVerdict -Rendered $true -ProbeOk $false -TimedOut $false -Failures @() -RenderMs 5 -ProbeMs 0
            ($v.Lines -join "`n") | Should -Match 'the background check failed'
            $v = Get-SmokeVerdict -Rendered $true -ProbeOk $true -TimedOut $false -Failures @('first problem', 'second problem') -RenderMs 5 -ProbeMs 5
            @($v.Lines).Count | Should -Be 2 -Because 'one [FAIL] line per cause'
            ($v.Lines -join "`n") | Should -Match 'first problem'
            ($v.Lines -join "`n") | Should -Match 'second problem'
        }

        It 'AC12_SmokeProbeRunsInTheRealPool' {
            $work = (Get-Variable -Name SmokeProbeWork -Scope Script -ErrorAction SilentlyContinue).Value
            $work | Should -Not -BeNullOrEmpty -Because '$script:SmokeProbeWork must exist'
            $text = $work.ToString()
            foreach ($bad in 'Get-PSDrive', 'Get-ChildItem', 'Get-Acl', 'Get-CimInstance', 'Test-Path') {
                $text | Should -Not -Match ([regex]::Escape($bad)) -Because "the probe must not use $bad"
            }
            $text | Should -Not -Match '(?i)HK(CU|LM):|Registry::' -Because 'the probe must not read the registry'

            Initialize-BackgroundPool
            try {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $script:BgPool
                [void]$ps.AddScript($text)
                $r = $ps.Invoke() | Select-Object -Last 1
                $ps.Dispose()
                $r.Ok | Should -BeTrue
                $r.HasItemOwner | Should -BeTrue -Because 'the core function Get-ItemOwner exists in the pool'
                $r.HasDriveListModel | Should -BeTrue -Because 'the app helper Get-DriveListModel exists in the pool'
                $r.ReparseTagCount | Should -Be @($script:RedirectFreeReparseTags.Keys).Count
                $r.ReparseTagCount | Should -BeGreaterThan 0
            }
            finally { if ($script:BgPool) { $script:BgPool.Close() }; $script:BgPool = $null }
        }

        It 'AC13_SmokeWindowIsOffScreenAndQuiet' -Skip:(-not ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA')) {
            $win = [System.Windows.Markup.XamlReader]::Parse((Get-MainWindowXaml))
            try {
                Set-SmokeWindowMode -Window $win
                $win.WindowStartupLocation | Should -Be 'Manual'
                $win.ShowInTaskbar | Should -BeFalse
                $win.ShowActivated | Should -BeFalse
                $vl = [System.Windows.SystemParameters]::VirtualScreenLeft
                $vt = [System.Windows.SystemParameters]::VirtualScreenTop
                $vr = $vl + [System.Windows.SystemParameters]::VirtualScreenWidth
                $vb = $vt + [System.Windows.SystemParameters]::VirtualScreenHeight
                $left = $win.Left; $top = $win.Top
                $right = $left + $win.Width; $bottom = $top + $win.Height
                $outside = ($right -le $vl) -or ($left -ge $vr) -or ($bottom -le $vt) -or ($top -ge $vb)
                $outside | Should -BeTrue -Because "the window ($left,$top,$right,$bottom) must lie outside the virtual screen ($vl,$vt,$vr,$vb)"
            }
            finally { $win.Close() }
        }

        It 'AC14_SmokeTickClosesOrTimesOut' {
            $deadline = [TimeSpan]::FromSeconds(30)
            $script:SmokeDeadline | Should -Be $deadline -Because 'the default deadline is 30 seconds'
            $early = [TimeSpan]::FromSeconds(5)
            $late = [TimeSpan]::FromSeconds(30)
            Get-SmokeTickAction -Rendered:$false -ProbeDone:$false -Elapsed $early -Deadline $deadline | Should -Be 'Wait'
            Get-SmokeTickAction -Rendered:$true -ProbeDone:$false -Elapsed $early -Deadline $deadline | Should -Be 'Wait'
            Get-SmokeTickAction -Rendered:$false -ProbeDone:$true -Elapsed $early -Deadline $deadline | Should -Be 'Wait'
            Get-SmokeTickAction -Rendered:$true -ProbeDone:$true -Elapsed $early -Deadline $deadline | Should -Be 'Close'
            Get-SmokeTickAction -Rendered:$false -ProbeDone:$false -Elapsed $late -Deadline $deadline | Should -Be 'TimedOut'
            Get-SmokeTickAction -Rendered:$true -ProbeDone:$false -Elapsed $late -Deadline $deadline | Should -Be 'TimedOut'
            Get-SmokeTickAction -Rendered:$false -ProbeDone:$true -Elapsed $late -Deadline $deadline | Should -Be 'TimedOut'
        }

        It 'AC15_SmokeRefusesChangeActions' {
            $script:SmokeMode = $true
            $ran = @{ N = 0 }
            Invoke-UiAction { $ran.N++ }.GetNewClosure()
            $ran.N | Should -Be 0 -Because 'the action block must not run during the smoke test'
            $script:SmokeFailures.Count | Should -Be 1
            "$($script:SmokeFailures[0])" | Should -Match '(?i)change action'
        }
    }
}
