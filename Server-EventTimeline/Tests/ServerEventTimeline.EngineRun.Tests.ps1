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
        param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
        $mk = { param($m) [PSCustomObject]@{ TimeCreatedUtc = ([datetime]$StartUtc).AddMinutes($m); Id = 7036; ProviderName = 'Service Control Manager'
            Level = 4; LogName = $LogName; Message = "event from $Server"; RecordId = $m; UserSid = ''; MachineName = $Server } }
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
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
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
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
            if ($LogName -eq 'Application') { Start-Sleep -Seconds 10 }
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
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
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

    It 'stops reading a server at the total cap and marks the rest NotRead' {
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application', 'Security') -ServerTotalCap 3 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $script:TwoEventLog
        $r = Wait-Engine -Engine $script:Engine
        @($r.Rows).Count | Should -BeLessOrEqual 4
        $notRead = @($script:Engine.Status['srv-fake-01'].Logs | Where-Object Outcome -eq 'NotRead')
        $notRead.Count | Should -BeGreaterThan 0
        $notRead[0].Reason | Should -BeLike '*stopped at the 3 event total for this server*'
    }

    It 'surfaces a capped log in the status' {
        $log = {
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
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

    It 'marks a log cut short by the server total cap as Capped, even when it is the last log' {
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application') -ServerTotalCap 3 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $script:TwoEventLog
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        $app = $s.Logs | Where-Object Log -eq 'Application'
        $app.Outcome | Should -Be 'Capped'
        $app.Reason | Should -BeLike '*3 event total*'
        $s.State | Should -Be 'DoneWithGaps'
        $s.EventCount | Should -Be 3
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
            param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential)
            if ($LogName -eq 'System') { [System.Threading.Thread]::Sleep(6000) }
            [PSCustomObject]@{ Server = $Server; Log = $LogName; Outcome = 'Read'; Count = 0; Events = @(); Reason = '' }
        }
        $script:Engine = Start-TimelineEngine -Servers @('srv-fake-01') -Window $script:Window -SelectedLogs @('System', 'Application') -TimeoutSec 2 -MaxConcurrency 1 -ProbeScript $script:OkProbe -LogScript $log
        $null = Wait-Engine -Engine $script:Engine
        $s = $script:Engine.Status['srv-fake-01']
        ($s.Logs | Where-Object Log -eq 'System').Outcome | Should -Be 'TimedOut'
        ($s.Logs | Where-Object Log -eq 'Application').Outcome | Should -Be 'Read'
    }
}
