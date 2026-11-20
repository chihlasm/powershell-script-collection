<#
    Pester 5 tests for the background engine (Start/Update/Stop/Close-TimelineEngine).
    Uses a real runspace pool with injected fake probe and log scripts: nothing contacts a
    server or reads a real event log.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Engine.ps1')

    $script:Window = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-17 03:00') -PlusMinusMinutes 15

    $script:OkProbe = {
        param($EnginePath, $Server, $Credential, $WindowStartLocal)
        [PSCustomObject]@{ Server = $Server; Reachable = $true; Transport = 'WinRM'; UtcOffsetMinutes = -300; TimeZoneId = 'X'
            Channels = @(); FailureKind = ''; Reason = '' }
    }
    $script:TwoEventLog = {
        param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
        $mk = { param($m) [PSCustomObject]@{ TimeCreatedUtc = ([datetime]$StartUtc).AddMinutes($m); Id = 7036; ProviderName = 'Service Control Manager'
            Level = 4; LogName = $LogName; Message = "event from $Server"; RecordId = $m; UserSid = ''; MachineName = $Server } }
        # Level 4 events are routine: only the routine read returns them, so the important read
        # comes back empty and the counts stay at two per log.
        if ($Part -ne 'Routine') { return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' } }
        $offset = if ($Server -eq 'srv-fake-02') { 1 } else { 2 }
        [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 2; Events = @((& $mk $offset), (& $mk ($offset + 10))); Reason = '' }
    }

    function Wait-Engine {
        param($Engine, [int]$TimeoutSec = 20)
        $rows = New-Object System.Collections.Generic.List[object]
        $sw = [Diagnostics.Stopwatch]::StartNew()
        do {
            $u = Update-TimelineEngine -Engine $Engine
            foreach ($r in @($u.NewRows)) { $rows.Add($r) }
            if ($u.Finished) { break }
            Start-Sleep -Milliseconds 50
        } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)
        [PSCustomObject]@{ Rows = $rows.ToArray(); Finished = $u.Finished; Seconds = $sw.Elapsed.TotalSeconds }
    }
}

Describe 'Timeline engine' {
    AfterEach {
        if ($script:Engine) { Close-TimelineEngine -Engine $script:Engine; $script:Engine = $null }
    }

    It 'merges two servers into rows ordered by UTC, both Done' {
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01', 'srv-fake-02') -Window $script:Window -SelectedLogs @('System') -ProbeScript $script:OkProbe -LogScript $script:TwoEventLog
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        @($r.Rows).Count | Should -Be 4
        $sorted = @(Merge-TimelineRows -Rows $r.Rows)
        $sorted[0].Server | Should -Be 'srv-fake-02'
        $script:Engine.Status['srv-fake-01'].State | Should -Be 'Done'
        $script:Engine.Status['srv-fake-02'].State | Should -Be 'Done'
        $script:Engine.Status['srv-fake-01'].EventCount | Should -Be 2
        $sorted[0].TimeServerLocal | Should -Be ([datetime]'2026-11-17 02:46')
    }

    It 'never blocks the window long when a log returns thousands of events (it froze: Not Responding)' {
        # The window's heartbeat calls Update-TimelineEngine every 250 ms on the UI thread. Turning
        # 5,000 events into rows there took 3-4 s per log, so the window stopped responding.
        $bigLog = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            if ($Part -ne 'Routine') { return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' } }
            $events = foreach ($m in 0..4999) {
                [PSCustomObject]@{ TimeCreatedUtc = ([datetime]$StartUtc).AddSeconds($m / 10); Id = 7036; ProviderName = 'Service Control Manager'
                    Level = 4; LogName = $LogName; Message = "event $m from $Server"; RecordId = $m; UserSid = ''; MachineName = $Server }
            }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 5000; Events = @($events); Reason = '' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System') -ProbeScript $script:OkProbe -LogScript $bigLog
        $rows = 0; $slowest = 0.0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        do {
            $t = [Diagnostics.Stopwatch]::StartNew()
            $u = Update-TimelineEngine -Engine $script:Engine
            $slowest = [Math]::Max($slowest, $t.Elapsed.TotalMilliseconds)
            $rows += @($u.NewRows).Count
            if ($u.Finished) { break }
            Start-Sleep -Milliseconds 50
        } while ($sw.Elapsed.TotalSeconds -lt 60)
        $rows | Should -Be 5000
        $slowest | Should -BeLessThan 400
        $script:Engine.Status['srv-fake-01'].EventCount | Should -Be 5000
    }

    It 'keeps going when one server is unreachable' {
        $probe = {
            param($EnginePath, $Server, $Credential, $WindowStartLocal)
            if ($Server -eq 'srv-fake-dead') {
                return [PSCustomObject]@{ Server = $Server; Reachable = $false; Transport = ''; UtcOffsetMinutes = 0; TimeZoneId = ''
                    Channels = @(); FailureKind = 'Connection'; Reason = 'WinRM and remote event log are both unreachable from here.' }
            }
            [PSCustomObject]@{ Server = $Server; Reachable = $true; Transport = 'WinRM'; UtcOffsetMinutes = 0; TimeZoneId = ''; Channels = @(); FailureKind = ''; Reason = '' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-dead', 'srv-fake-01') -Window $script:Window -SelectedLogs @('System') -ProbeScript $probe -LogScript $script:TwoEventLog
        $r = Wait-Engine -Engine $script:Engine
        $script:Engine.Status['srv-fake-dead'].State | Should -Be 'Unreachable'
        $script:Engine.Status['srv-fake-dead'].Reason | Should -BeLike '*both unreachable*'
        $script:Engine.Status['srv-fake-01'].State | Should -Be 'Done'
        @($r.Rows).Count | Should -Be 2
    }

    It 'times out a slow log without holding up the others' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            if ($LogName -eq 'Application' -and $Part -eq 'Important') { Start-Sleep -Seconds 10 }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application') -TimeoutSec 1 -ProbeScript $script:OkProbe -LogScript $log
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        $r.Seconds | Should -BeLessThan 5
        $s = $script:Engine.Status['srv-fake-01']
        $s.State | Should -Be 'DoneWithGaps'
        ($s.Logs | Where-Object Log -eq 'Application').Outcome | Should -Be 'TimedOut'
        ($s.Logs | Where-Object Log -eq 'System').Outcome | Should -Be 'Read'
    }

    It 'cancels at once and reports Cancelled' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            Start-Sleep -Seconds 30
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01', 'srv-fake-02') -Window $script:Window -SelectedLogs @('System') -ProbeScript $script:OkProbe -LogScript $log
        $sw = [Diagnostics.Stopwatch]::StartNew()
        do { $null = Update-TimelineEngine -Engine $script:Engine; Start-Sleep -Milliseconds 50 }
        until (@($script:Engine.Status.Values | Where-Object State -eq 'Querying').Count -eq 2 -or $sw.Elapsed.TotalSeconds -gt 10)

        $sw.Restart()
        Stop-TimelineEngine -Engine $script:Engine
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 1
        @($script:Engine.Status.Values | Where-Object State -ne 'Cancelled').Count | Should -Be 0
        (Update-TimelineEngine -Engine $script:Engine).Finished | Should -BeTrue
    }

    It 'stops reading routine events at the server total and marks the rest Trimmed' {
        # The total limits routine events only: the important reads stay Read and the server Done.
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application', 'Security') -ServerTotalCap 3 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $script:TwoEventLog
        $r = Wait-Engine -Engine $script:Engine
        @($r.Rows).Count | Should -Be 3
        $s = $script:Engine.Status['srv-fake-01']
        @($s.Logs | Where-Object Outcome -ne 'Read').Count | Should -Be 0
        $trimmed = @($s.Logs | Where-Object RoutineOutcome -eq 'Trimmed')
        $trimmed.Count | Should -BeGreaterThan 0
        $trimmed[0].RoutineReason | Should -BeLike '*stopped at the 3 event total for this server*'
        $s.State | Should -Be 'Done'
        $s.Reason | Should -BeNullOrEmpty
    }

    It 'surfaces a capped log in the status' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Capped'; Count = 0; Events = @(); Reason = 'stopped at 5,000 events' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System') -ProbeScript $script:OkProbe -LogScript $log
        $null = Wait-Engine -Engine $script:Engine
        ($script:Engine.Status['srv-fake-01'].Logs | Where-Object Log -eq 'System').Outcome | Should -Be 'Capped'
        $script:Engine.Status['srv-fake-01'].State | Should -Be 'DoneWithGaps'
    }
    It 'background runspaces can load the engine file the default tasks dot-source' {
        $probe = {
            param($EnginePath, $Server, $Credential, $WindowStartLocal)
            . $EnginePath
            $ok = [bool](Get-Command Invoke-ServerProbe -ErrorAction SilentlyContinue) -and [bool](Get-Command Invoke-LogQuery -ErrorAction SilentlyContinue)
            [PSCustomObject]@{ Server = $Server; Reachable = $false; Transport = ''; UtcOffsetMinutes = 0; TimeZoneId = ''
                Channels = @(); FailureKind = 'Other'; Reason = "loaded=$ok path=$EnginePath" }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System') -ProbeScript $probe -LogScript $script:TwoEventLog
        $null = Wait-Engine -Engine $script:Engine
        $script:Engine.Status['srv-fake-01'].Reason | Should -BeLike 'loaded=True path=*ServerEventTimeline.Engine.ps1'
    }
}

Describe 'Timeline engine: review fixes' {
    AfterEach {
        if ($script:Engine) { Close-TimelineEngine -Engine $script:Engine; $script:Engine = $null }
    }

    It 'marks routine events cut short by the server total cap as Trimmed, even in the last log' {
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application') -ServerTotalCap 3 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $script:TwoEventLog
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        $app = $s.Logs | Where-Object Log -eq 'Application'
        $app.Outcome | Should -Be 'Read'
        $app.RoutineOutcome | Should -Be 'Trimmed'
        $app.RoutineReason | Should -BeLike '*3 event total*'
        $app.RoutineCount | Should -Be 1
        $s.State | Should -Be 'Done'
        $s.EventCount | Should -Be 3
        $s.RoutineEventCount | Should -Be 3
    }

    It 'does not count skipped (missing or turned-off) logs as gaps' {
        $probe = {
            param($EnginePath, $Server, $Credential, $WindowStartLocal)
            [PSCustomObject]@{ Server = $Server; Reachable = $true; Transport = 'WinRM'; UtcOffsetMinutes = 0; TimeZoneId = ''; FailureKind = ''; Reason = ''
                Channels = @([PSCustomObject]@{ Name = 'System'; IsEnabled = $true; RecordCount = 10 }) }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Microsoft-Windows-FailoverClustering/Operational') -ProbeScript $probe -LogScript $script:TwoEventLog
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        ($s.Logs | Where-Object Log -eq 'Microsoft-Windows-FailoverClustering/Operational').Outcome | Should -Be 'Skipped'
        $s.State | Should -Be 'Done'
    }

    It 'a stopped task that is still running does not make queued logs time out' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            if ($LogName -eq 'System' -and $Part -eq 'Important') { [System.Threading.Thread]::Sleep(6000) }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application') -TimeoutSec 2 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $log
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        ($s.Logs | Where-Object Log -eq 'System').Outcome | Should -Be 'TimedOut'
        ($s.Logs | Where-Object Log -eq 'Application').Outcome | Should -Be 'Read'
    }
}

Describe 'Timeline engine: important first' {
    BeforeAll {
        # Fakes run in the pool's runspaces, where a closure can't reach them; they read their
        # settings and record their calls through process-wide AppDomain data instead.
        $script:FakeKey = 'ServerEventTimeline.Tests.Fake'
        $script:CallKey = 'ServerEventTimeline.Tests.Calls'
        function Set-PartFake {
            param([hashtable]$Settings)
            [AppDomain]::CurrentDomain.SetData($script:FakeKey, $Settings)
            $calls = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            [AppDomain]::CurrentDomain.SetData($script:CallKey, $calls)
            , $calls
        }
        $script:PartFake = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            $cfg = [AppDomain]::CurrentDomain.GetData('ServerEventTimeline.Tests.Fake')
            $calls = [AppDomain]::CurrentDomain.GetData('ServerEventTimeline.Tests.Calls')
            if ($null -ne $calls) { [void]$calls.Add(('{0}|{1}|{2}' -f $Part, $LogName, $Cap)) }
            $mk = { param($m, $level) [PSCustomObject]@{ TimeCreatedUtc = ([datetime]$StartUtc).AddMinutes($m); Id = 7036; ProviderName = 'Service Control Manager'
                Level = $level; LogName = $LogName; Message = "$Part event"; RecordId = $m; UserSid = ''; MachineName = $Server } }
            if ($Part -eq 'Important') {
                if ($cfg.ImportantSleep) { Start-Sleep -Seconds $cfg.ImportantSleep }
                if ($cfg.ImportantFail) { return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Failed'; Count = 0; Events = @(); Reason = $cfg.ImportantFail } }
                $n = [int]$cfg.Important
                $events = @(for ($i = 1; $i -le $n; $i++) { & $mk $i 2 })
                if ($cfg.ImportantCapped) {
                    return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Capped'; Count = $n; Events = $events
                        Reason = ('more than {0:N0} errors and warnings - kept the newest {0:N0}' -f $Cap) }
                }
                return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = $n; Events = $events; Reason = '' }
            }
            if ($cfg.RoutineSleep) { Start-Sleep -Seconds $cfg.RoutineSleep }
            if ($cfg.RoutineFail) { return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Failed'; Count = 0; Events = @(); Reason = $cfg.RoutineFail } }
            if ($cfg.RoutineThrow) { throw $cfg.RoutineThrow }
            $n = [Math]::Min([int]$cfg.Routine, [int]$Cap)
            $events = @(for ($i = 1; $i -le $n; $i++) { & $mk (20 + $i) 4 })
            if ($cfg.RoutineCapped) {
                return [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Capped'; Count = $n; Events = $events
                    Reason = ('kept the newest {0:N0} routine events; older ones in the window weren''t read' -f $Cap) }
            }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = $n; Events = $events; Reason = '' }
        }
        function Start-PartEngine {
            param([string[]]$Logs = @('System'), [int]$Cap = 5000, [int]$ServerTotalCap = 50000, [int]$TimeoutSec = 60, [int]$MaxConcurrency = 8)
            Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs $Logs -Cap $Cap -ServerTotalCap $ServerTotalCap `
                -TimeoutSec $TimeoutSec -MaxConcurrency $MaxConcurrency -ProbeScript $script:OkProbe -LogScript $script:PartFake
        }
        function Wait-RunningTask {
            # Deterministic: polls the engine until a log task of the given part is running.
            param($Engine, [string]$Part)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            do { $null = Update-TimelineEngine -Engine $Engine; Start-Sleep -Milliseconds 50 }
            until (@($Engine.Running | Where-Object { $_.Kind -eq 'Log' -and $_.Part -eq $Part }).Count -gt 0 -or $sw.Elapsed.TotalSeconds -gt 15)
            @($Engine.Running | Where-Object { $_.Kind -eq 'Log' -and $_.Part -eq $Part }).Count
        }
    }
    AfterEach {
        if ($script:Engine) { Close-TimelineEngine -Engine $script:Engine; $script:Engine = $null }
        [AppDomain]::CurrentDomain.SetData($script:FakeKey, $null)
        [AppDomain]::CurrentDomain.SetData($script:CallKey, $null)
    }

    It 'reads important first, then routine with the room left' {
        $calls = Set-PartFake @{ Important = 3; Routine = 10 }
        $script:Engine = Start-PartEngine -Cap 5
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        @($calls) | Should -Be @('Important|System|5', 'Routine|System|2')
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Read'
        $log.Count | Should -Be 3
        $log.RoutineOutcome | Should -Be 'Read'
        $log.RoutineCount | Should -Be 2
        $s.EventCount | Should -Be 5
        $s.RoutineEventCount | Should -Be 2
        @($r.Rows).Count | Should -Be 5
        $s.State | Should -Be 'Done'
    }

    It 'no routine read when important events fill the cap' {
        $calls = Set-PartFake @{ Important = 5; ImportantCapped = $true; Routine = 10 }
        $script:Engine = Start-PartEngine -Cap 5
        $null = Wait-Engine -Engine $script:Engine
        @($calls | Where-Object { $_ -like 'Routine|*' }).Count | Should -Be 0
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Capped'
        $log.Count | Should -Be 5
        $log.RoutineOutcome | Should -Be 'Trimmed'
        $log.RoutineReason | Should -BeLike '*no room left after 5 important events*'
        $s.State | Should -Be 'DoneWithGaps'
    }

    It 'no routine read after the important read times out' {
        $calls = Set-PartFake @{ ImportantSleep = 10; Routine = 2 }
        $script:Engine = Start-PartEngine -TimeoutSec 1
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        @($calls | Where-Object { $_ -like 'Routine|*' }).Count | Should -Be 0
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'TimedOut'
        $log.Reason | Should -BeLike 'errors and warnings not read*'
        $log.RoutineOutcome | Should -Be 'NotRead'
        $log.RoutineReason | Should -BeLike "*errors and warnings weren't read*"
        $s.State | Should -Be 'DoneWithGaps'
    }

    It 'no routine read after the important read fails' {
        $calls = Set-PartFake @{ ImportantFail = 'access denied - the account running this tool may not read this log'; Routine = 2 }
        $script:Engine = Start-PartEngine
        $null = Wait-Engine -Engine $script:Engine
        @($calls | Where-Object { $_ -like 'Routine|*' }).Count | Should -Be 0
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Failed'
        $log.Reason | Should -BeLike 'errors and warnings not read*access denied*'
        $log.RoutineOutcome | Should -Be 'NotRead'
        $log.RoutineReason | Should -BeLike "*errors and warnings weren't read*"
        $s.State | Should -Be 'DoneWithGaps'
    }

    It 'no routine read after the important task throws' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)
            if ($Part -eq 'Important') { throw 'Access is denied' }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = 'routine ran' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System') -ProbeScript $script:OkProbe -LogScript $log
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        $l = $s.Logs | Where-Object Log -eq 'System'
        $l.Outcome | Should -Be 'Failed'
        $l.Reason | Should -BeLike 'errors and warnings not read*Access is denied*'
        $l.RoutineOutcome | Should -Be 'NotRead'
        $s.State | Should -Be 'DoneWithGaps'
    }

    It 'a routine read that hit its cap is Trimmed, leaves the server Done and shows on the card note' {
        $null = Set-PartFake @{ Important = 1; Routine = 10; RoutineCapped = $true }
        $script:Engine = Start-PartEngine -Cap 4
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.RoutineOutcome | Should -Be 'Trimmed'
        $log.RoutineReason | Should -BeLike 'kept the newest*'
        $s.State | Should -Be 'Done'
        Get-TimelineRoutineNote -Status $s | Should -Be 'older routine events trimmed in 1 log'
    }

    It 'a routine read returned as Failed leaves the server Done with errors and warnings intact' {
        $null = Set-PartFake @{ Important = 1; Routine = 2; RoutineFail = 'access denied' }
        $script:Engine = Start-PartEngine
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Read'
        $log.RoutineOutcome | Should -Be 'Failed'
        $log.RoutineReason | Should -BeLike 'routine events not read (*); errors and warnings were read'
        $s.State | Should -Be 'Done'
        $s.Reason | Should -BeNullOrEmpty
    }

    It 'a routine task that throws leaves the server Done with errors and warnings intact' {
        $null = Set-PartFake @{ Important = 1; Routine = 2; RoutineThrow = 'Access is denied' }
        $script:Engine = Start-PartEngine
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Read'
        $log.RoutineOutcome | Should -Be 'Failed'
        $log.RoutineReason | Should -BeLike 'routine events not read (*); errors and warnings were read'
        $s.State | Should -Be 'Done'
        $s.Reason | Should -BeNullOrEmpty
    }

    It 'a routine timeout leaves the server Done' {
        $null = Set-PartFake @{ Important = 1; Routine = 2; RoutineSleep = 10 }
        $script:Engine = Start-PartEngine -TimeoutSec 2
        $r = Wait-Engine -Engine $script:Engine
        $r.Finished | Should -BeTrue
        $s = $script:Engine.Status['srv-fake-01']
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Read'
        $log.RoutineOutcome | Should -Be 'TimedOut'
        $log.RoutineReason | Should -Be "routine events not read (didn't answer within 2 s); errors and warnings were read"
        $s.State | Should -Be 'Done'
        $s.Reason | Should -BeNullOrEmpty
    }

    It 'the server total trims routine events only' {
        $null = Set-PartFake @{ Important = 2; Routine = 2 }
        $script:Engine = Start-PartEngine -Logs @('System', 'Application') -ServerTotalCap 3 -MaxConcurrency 1
        $r = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        @($s.Logs).Count | Should -Be 2
        foreach ($log in @($s.Logs)) {
            $log.Outcome | Should -Be 'Read'
            $log.Count | Should -Be 2
        }
        @($r.Rows).Count | Should -Be 7
        ($s.Logs | Measure-Object -Property RoutineCount -Sum).Sum | Should -Be 3
        $s.RoutineEventCount | Should -Be 3
        $s.EventCount | Should -Be 7
        $trimmed = @($s.Logs | Where-Object RoutineOutcome -eq 'Trimmed')
        $trimmed.Count | Should -BeGreaterThan 0
        $trimmed[0].RoutineReason | Should -BeLike '*3 event total*'
        $s.State | Should -Be 'Done'
    }

    It 'cancel after the important reads keeps the server Done' {
        $null = Set-PartFake @{ Important = 1; Routine = 2; RoutineSleep = 30 }
        $script:Engine = Start-PartEngine
        Wait-RunningTask -Engine $script:Engine -Part 'Routine' | Should -Be 1

        Stop-TimelineEngine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        $s.State | Should -Be 'Done'
        $s.Reason | Should -BeNullOrEmpty
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Read'
        $log.RoutineOutcome | Should -Be 'Cancelled'
        (Update-TimelineEngine -Engine $script:Engine).Finished | Should -BeTrue
    }

    It 'cancel with an important read still running marks the server Cancelled, both parts' {
        $null = Set-PartFake @{ ImportantSleep = 30; Routine = 2 }
        $script:Engine = Start-PartEngine
        Wait-RunningTask -Engine $script:Engine -Part 'Important' | Should -Be 1

        Stop-TimelineEngine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        $s.State | Should -Be 'Cancelled'
        $log = $s.Logs | Where-Object Log -eq 'System'
        $log.Outcome | Should -Be 'Cancelled'
        $log.RoutineOutcome | Should -Be 'Cancelled'
    }

    It 'a skipped log gets RoutineOutcome Skipped; a queried log starts Pending' {
        $st = [PSCustomObject]@{ Logs = New-Object System.Collections.ArrayList }
        Set-TimelineLogOutcome -Status $st -Log 'A' -Outcome 'Skipped' -Reason 'off'
        Set-TimelineLogOutcome -Status $st -Log 'B' -Outcome 'Pending'
        ($st.Logs | Where-Object Log -eq 'A').RoutineOutcome | Should -Be 'Skipped'
        ($st.Logs | Where-Object Log -eq 'B').RoutineOutcome | Should -Be 'Pending'
        Set-TimelineLogOutcome -Status $st -Log 'B' -Outcome 'Read' -Count 4 -Reason 'r' -Part Routine
        $b = $st.Logs | Where-Object Log -eq 'B'
        $b.Outcome | Should -Be 'Pending'
        $b.RoutineOutcome | Should -Be 'Read'
        $b.RoutineCount | Should -Be 4
        $b.RoutineReason | Should -Be 'r'
    }

    It 'queues log tasks as Important with the per-log cap' {
        $null = Set-PartFake @{ ImportantSleep = 30 }
        $script:Engine = Start-PartEngine -Cap 7
        Wait-RunningTask -Engine $script:Engine -Part 'Important' | Should -Be 1
        $t = @($script:Engine.Running | Where-Object Kind -eq 'Log')[0]
        $t.Parameters['Part'] | Should -Be 'Important'
        $t.Parameters['Cap'] | Should -Be 7
    }
}
