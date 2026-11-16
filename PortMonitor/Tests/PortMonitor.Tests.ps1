<#
    Pester 5 tests for PortMonitor.ps1.

    Unit tests (the gate) touch no network and no real user folder: every file goes to
    $TestDrive and the background engine is replaced by fake jobs. The 'Integration' tests open
    a loopback TcpListener, resolve a reserved .invalid name, and start PortMonitor.ps1 -Once in
    child Windows PowerShell 5.1 and PowerShell 7 processes, so they stay out of the gate.

    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\PortMonitor\Tests
          Invoke-Pester .\PortMonitor\Tests -TagFilter Integration   # loopback + child processes
#>

BeforeAll {
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'PortMonitor.ps1'
    . $script:ScriptPath -LoadFunctionsOnly

    function New-WrappedSocketException {
        # What Test-TcpPort's catch sees: MethodInvocationException -> AggregateException -> SocketException.
        param([int]$Code)
        $socket = New-Object System.Net.Sockets.SocketException -ArgumentList $Code
        $aggregate = New-Object System.AggregateException -ArgumentList @(, [System.Exception[]]@($socket))
        New-Object System.Management.Automation.MethodInvocationException -ArgumentList 'Exception calling "Wait"', $aggregate
    }

    function New-FakeJob {
        # Stands in for a running check: a completed handle and a PowerShell that returns $Result.
        param($State, $Result, [string]$HostName = $State.Host, [int]$Port = $State.Port)
        $ps = [PSCustomObject]@{ Result = $Result; Disposed = $false; Streams = [PSCustomObject]@{ Error = @() } }
        $ps | Add-Member -MemberType ScriptMethod -Name EndInvoke -Value { param($h) , @($this.Result) }
        $ps | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed = $true }
        [PSCustomObject]@{
            Id = $State.Id; Host = $HostName; Port = $Port; PowerShell = $ps
            Handle = [PSCustomObject]@{ IsCompleted = $true }; Started = (Get-Date)
        }
    }

    function New-FakeEngine {
        [PSCustomObject]@{
            Pool           = $null
            InFlight       = New-Object System.Collections.ArrayList
            Draining       = New-Object System.Collections.ArrayList
            MaxConcurrency = 16
        }
    }
}

Describe 'Get-PortCheckFailure classifies connect errors' {
    It 'maps WSAECONNREFUSED (10061) to Refused through the PowerShell/Task wrappers' {
        (Get-PortCheckFailure -Exception (New-WrappedSocketException 10061) -Port 443).Status | Should -Be 'Refused'
    }
    It 'maps WSAETIMEDOUT (10060) to Timeout' {
        (Get-PortCheckFailure -Exception (New-WrappedSocketException 10060)).Status | Should -Be 'Timeout'
    }
    It 'maps any other socket error to Error and names it' {
        $f = Get-PortCheckFailure -Exception (New-WrappedSocketException 10065)
        $f.Status | Should -Be 'Error'
        $f.Detail | Should -Match 'HostUnreachable'
    }
    It 'maps a non-socket exception to Error with its message' {
        $f = Get-PortCheckFailure -Exception (New-Object System.InvalidOperationException -ArgumentList 'boom')
        $f.Status | Should -Be 'Error'
        $f.Detail | Should -Match 'boom'
    }
}

Describe 'Test-TcpPort input handling (no network)' {
    It 'rejects port 0 and 65536 at the parameter' {
        { Test-TcpPort -HostName 'x' -Port 0 } | Should -Throw
        { Test-TcpPort -HostName 'x' -Port 65536 } | Should -Throw
    }
    It 'rejects a timeout outside 100-30000 ms' {
        { Test-TcpPort -HostName 'x' -Port 1 -TimeoutMs 99 } | Should -Throw
        { Test-TcpPort -HostName 'x' -Port 1 -TimeoutMs 30001 } | Should -Throw
    }
    It 'returns Error without connecting when the host is only spaces' {
        $r = Test-TcpPort -HostName '   ' -Port 80
        $r.Status | Should -Be 'Error'
        $r.Address | Should -BeNullOrEmpty
    }
    It 'defaults to a 3000 ms timeout (Windows needs ~2.1 s to report a refused connection)' {
        (Get-Command Test-TcpPort).Parameters['TimeoutMs'].Attributes | Out-Null
        $ast = (Get-Command Test-TcpPort).ScriptBlock.Ast
        $p = $ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TimeoutMs' }
        $p.DefaultValue.Extent.Text | Should -Be '3000'
    }
}

Describe 'ConvertTo-PortTarget and Test-PortTargetDefinition' {
    It 'fills defaults: 30 s interval, 3000 ms timeout, enabled, label Host:Port' {
        $t = ConvertTo-PortTarget ([PSCustomObject]@{ Host = ' dc01 '; Port = '389' })
        $t.Host | Should -Be 'dc01'
        $t.Port | Should -Be 389
        $t.IntervalSec | Should -Be 30
        $t.TimeoutMs | Should -Be 3000
        $t.Enabled | Should -BeTrue
        $t.Label | Should -Be 'dc01:389'
    }
    It 'accepts a hashtable and string booleans' {
        $t = ConvertTo-PortTarget @{ host = 'a'; port = 1; enabled = 'false' }
        $t.Host | Should -Be 'a'
        $t.Enabled | Should -BeFalse
    }
    It 'keeps the saved field order (new fields are added at the end)' {
        $names = @((ConvertTo-PortTarget @{ Host = 'a'; Port = 1 }).PSObject.Properties | ForEach-Object Name)
        $names -join ',' | Should -Be 'Label,Host,Port,IntervalSec,TimeoutMs,Enabled,FailAfter,RecoverAfter,MeasureLoss,LossPings,LossAlertPercent'
    }
    It 'turns a non-number into 0 so validation reports it (no silent default)' {
        (ConvertTo-PortTarget @{ Host = 'a'; Port = 'https' }).Port | Should -Be 0
        (ConvertTo-PortTarget @{ Host = 'a'; Port = 1; IntervalSec = 'often' }).IntervalSec | Should -Be 0
    }
    It 'finds no problem in a valid target (and returns an empty list, not a list holding an empty list)' {
        @(Test-PortTargetDefinition @{ Host = 'a'; Port = 1; IntervalSec = 1; TimeoutMs = 100 }).Count | Should -Be 0
        @(Test-PortTargetDefinition @{ Host = 'a'; Port = 65535; IntervalSec = 1; TimeoutMs = 30000 }).Count | Should -Be 0
    }
    It 'reports <Case>' -TestCases @(
        @{ Case = 'blank host'; Target = @{ Host = ''; Port = 1 }; Pattern = 'Host is blank' }
        @{ Case = 'host with a space'; Target = @{ Host = 'a b'; Port = 1 }; Pattern = 'spaces' }
        @{ Case = 'port 0'; Target = @{ Host = 'a'; Port = 0 }; Pattern = 'Port must' }
        @{ Case = 'port 65536'; Target = @{ Host = 'a'; Port = 65536 }; Pattern = 'Port must' }
        @{ Case = 'interval 0'; Target = @{ Host = 'a'; Port = 1; IntervalSec = 0 }; Pattern = 'at least 1 second' }
        @{ Case = 'timeout 99'; Target = @{ Host = 'a'; Port = 1; TimeoutMs = 99 }; Pattern = 'Timeout must' }
        @{ Case = 'timeout 30001'; Target = @{ Host = 'a'; Port = 1; TimeoutMs = 30001 }; Pattern = 'Timeout must' }
    ) {
        param($Case, $Target, $Pattern)
        $problems = @(Test-PortTargetDefinition $Target)
        $problems.Count | Should -Be 1
        $problems[0] | Should -Match $Pattern
    }
}

Describe 'Read-PortMonitorConfig' {
    It 'returns an empty list and no warning when the file is missing' {
        $r = Read-PortMonitorConfig -Path (Join-Path $TestDrive 'nope.json')
        @($r.Targets).Count | Should -Be 0
        @($r.Warnings).Count | Should -Be 0
        $r.NeedsBackup | Should -BeFalse
    }
    It 'returns an empty list for an empty file' {
        $p = Join-Path $TestDrive 'empty.json'; Set-Content -LiteralPath $p -Value '' -Encoding ASCII
        @((Read-PortMonitorConfig -Path $p).Targets).Count | Should -Be 0
    }
    It 'warns (does not throw) on invalid JSON and asks for a backup before the first save' {
        $p = Join-Path $TestDrive 'bad.json'; Set-Content -LiteralPath $p -Value '[ { "Host": "a", ' -Encoding ASCII
        $r = Read-PortMonitorConfig -Path $p
        @($r.Targets).Count | Should -Be 0
        $r.Warnings[0] | Should -Match 'not valid JSON'
        $r.NeedsBackup | Should -BeTrue
    }
    It 'reads a one-element array as one target (5.1 returns the array, 7 unrolls it)' {
        $p = Join-Path $TestDrive 'one.json'
        Set-Content -LiteralPath $p -Value '[ { "Label": "Web", "Host": "web01", "Port": 443 } ]' -Encoding ASCII
        $r = Read-PortMonitorConfig -Path $p
        @($r.Targets).Count | Should -Be 1
        $r.Targets[0].Label | Should -Be 'Web'
    }
    It 'reads an object with a Targets array' {
        $p = Join-Path $TestDrive 'wrapped.json'
        Set-Content -LiteralPath $p -Value '{ "Targets": [ { "Host": "a", "Port": 1 }, { "Host": "b", "Port": 2 } ] }' -Encoding ASCII
        @((Read-PortMonitorConfig -Path $p).Targets).Count | Should -Be 2
    }
    It 'skips an invalid entry with a warning and keeps the others' {
        $p = Join-Path $TestDrive 'mixed.json'
        Set-Content -LiteralPath $p -Value '[ { "Label": "ok", "Host": "a", "Port": 1 }, { "Label": "broken", "Host": "b", "Port": 70000 } ]' -Encoding ASCII
        $r = Read-PortMonitorConfig -Path $p
        @($r.Targets).Count | Should -Be 1
        $r.Warnings[0] | Should -Match 'Entry 2 \(broken\) was skipped'
        $r.NeedsBackup | Should -BeTrue
    }
    It 'reads a UTF-8 file with a BOM' {
        $p = Join-Path $TestDrive 'bom.json'
        [System.IO.File]::WriteAllText($p, '[{"Host":"a","Port":1}]', (New-Object System.Text.UTF8Encoding -ArgumentList $true))
        @((Read-PortMonitorConfig -Path $p).Targets).Count | Should -Be 1
    }
}

Describe 'Save-PortMonitorConfig' {
    It 'saves one target as a JSON array, and it reads back the same' {
        $p = Join-Path $TestDrive 'save1\targets.json'
        $saved = Save-PortMonitorConfig -Path $p -Targets @((ConvertTo-PortTarget @{ Label = 'L'; Host = 'h'; Port = 22; IntervalSec = 5; TimeoutMs = 500; Enabled = $false }))
        $saved.Count | Should -Be 1
        (Get-Content -LiteralPath $p -Raw).TrimStart() | Should -Match '^\['
        $back = @((Read-PortMonitorConfig -Path $p).Targets)
        $back.Count | Should -Be 1
        $back[0].Port | Should -Be 22
        $back[0].IntervalSec | Should -Be 5
        $back[0].TimeoutMs | Should -Be 500
        $back[0].Enabled | Should -BeFalse
    }
    It 'saves an empty list as []' {
        $p = Join-Path $TestDrive 'empty-save.json'
        [void](Save-PortMonitorConfig -Path $p -Targets @())
        (Get-Content -LiteralPath $p -Raw).Trim() | Should -Be '[]'
    }
    It 'writes only the saved fields, not live monitoring state' {
        $p = Join-Path $TestDrive 'state-save.json'
        $state = New-PortTargetState @{ Host = 'h'; Port = 1 }
        $state.Status = 'Open'
        [void](Save-PortMonitorConfig -Path $p -Targets @($state))
        $raw = Get-Content -LiteralPath $p -Raw
        $raw | Should -Not -Match '"Id"'
        $raw | Should -Not -Match '"Status"'
        $raw | Should -Not -Match '"FailCount"'
    }
    It 'writes UTF-8 without a BOM' {
        $p = Join-Path $TestDrive 'nobom.json'
        [void](Save-PortMonitorConfig -Path $p -Targets @(@{ Host = 'h'; Port = 1 }))
        $bytes = [System.IO.File]::ReadAllBytes($p)
        $bytes[0] | Should -Not -Be 0xEF
    }
    It 'overwrites an existing file and leaves no temp file behind' {
        $p = Join-Path $TestDrive 'over.json'
        [void](Save-PortMonitorConfig -Path $p -Targets @(@{ Host = 'a'; Port = 1 }))
        [void](Save-PortMonitorConfig -Path $p -Targets @(@{ Host = 'a'; Port = 1 }, @{ Host = 'b'; Port = 2 }))
        @((Read-PortMonitorConfig -Path $p).Targets).Count | Should -Be 2
        Test-Path -LiteralPath "$p.tmp" | Should -BeFalse
    }
    It 'with -BackupExisting keeps the old file as .bak-<timestamp> first' {
        $dir = Join-Path $TestDrive 'backup'
        New-Item -ItemType Directory -Path $dir | Out-Null
        $p = Join-Path $dir 'targets.json'
        Set-Content -LiteralPath $p -Value 'this was not JSON' -Encoding ASCII
        $saved = Save-PortMonitorConfig -Path $p -Targets @(@{ Host = 'a'; Port = 1 }) -BackupExisting
        $saved.BackupPath | Should -Match '\.bak-\d{4}-\d{2}-\d{2}_\d{6}$'
        Get-Content -LiteralPath $saved.BackupPath -Raw | Should -Match 'this was not JSON'
    }
}

Describe 'Monitoring state' {
    It 'logs the first result as a change from Not checked' {
        $s = New-PortTargetState @{ Label = 'L'; Host = 'h'; Port = 1 }
        $now = Get-Date '2026-11-16 10:00:00'
        $c = Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 4.2; Detail = 'ok' }) -Now $now
        $c.PreviousStatus | Should -Be 'Not checked'
        $c.NewStatus | Should -Be 'Open'
        $c.LatencyMs | Should -Be 4.2
        $s.LastStateChange | Should -Be $now
    }
    It 'returns nothing when the status did not change, and keeps the last change time' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        $t1 = Get-Date '2026-11-16 10:00:00'; $t2 = $t1.AddSeconds(30)
        [void](Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 1 }) -Now $t1)
        Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 2 }) -Now $t2 | Should -BeNullOrEmpty
        $s.LastStateChange | Should -Be $t1
        $s.LastChecked | Should -Be $t2
        $s.LatencyMs | Should -Be 2
    }
    It 'records Open -> Timeout, clears latency, and counts failures and uptime' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; FailAfter = 1 }   # report on the first failure
        [void](Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 1 }))
        [void](Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 1 }))
        [void](Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 1 }))
        $c = Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Timeout'; LatencyMs = $null })
        $c.PreviousStatus | Should -Be 'Open'
        $c.NewStatus | Should -Be 'Timeout'
        $s.LatencyMs | Should -BeNullOrEmpty
        $s.FailCount | Should -Be 1
        $s.UptimePercent | Should -Be 75
    }
    It 'shows Disabled when turned off, and on re-enable checks at once and still logs a change that happened meanwhile' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; FailAfter = 1 }
        [void](Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 1 }))
        Set-PortTargetEnabled -State $s -Enabled $false
        $s.Status | Should -Be 'Disabled'
        Set-PortTargetEnabled -State $s -Enabled $true
        $s.Status | Should -Be 'Not checked'
        $s.NextDue | Should -Be ([datetime]::MinValue)
        (Update-PortTargetState -State $s -Result ([PSCustomObject]@{ Status = 'Refused' })).PreviousStatus | Should -Be 'Open'
    }
    It 'a disabled target starts as Disabled' {
        (New-PortTargetState @{ Host = 'h'; Port = 1; Enabled = $false }).Status | Should -Be 'Disabled'
    }
    It 'Get-DuePortTargets skips disabled, running and not-yet-due targets, oldest first' {
        $now = Get-Date '2026-11-16 10:00:00'
        $a = New-PortTargetState @{ Label = 'a'; Host = 'h'; Port = 1 }; $a.NextDue = $now.AddSeconds(-5)
        $b = New-PortTargetState @{ Label = 'b'; Host = 'h'; Port = 2 }; $b.NextDue = $now.AddSeconds(-50)
        $off = New-PortTargetState @{ Label = 'off'; Host = 'h'; Port = 3; Enabled = $false }
        $busy = New-PortTargetState @{ Label = 'busy'; Host = 'h'; Port = 4 }; $busy.InFlight = $true
        $later = New-PortTargetState @{ Label = 'later'; Host = 'h'; Port = 5 }; $later.NextDue = $now.AddSeconds(5)
        $due = @(Get-DuePortTargets -States @($a, $b, $off, $busy, $later) -Now $now)
        ($due | ForEach-Object Label) -join ',' | Should -Be 'b,a'
    }
}

Describe 'Write-PortStateChangeLog' {
    BeforeEach { $script:LogDir = Join-Path $TestDrive ("logs-" + [guid]::NewGuid().ToString('N')) }
    It 'writes PortMonitor_yyyyMMdd.csv (date of the change) with the documented columns' {
        $change = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 23:59:58'); Label = 'L'; Host = 'h'; Port = 443; PreviousStatus = 'Open'; NewStatus = 'Timeout'; LatencyMs = $null }
        $r = Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $change
        $r.Ok | Should -BeTrue
        Split-Path -Leaf $r.Path | Should -Be 'PortMonitor_20261116.csv'
        $lines = @(Get-Content -LiteralPath $r.Path)
        $lines[0] | Should -Be '"Timestamp","Label","Host","Port","PreviousStatus","NewStatus","LatencyMs"'
        $lines[1] | Should -Be '"2026-11-16 23:59:58","L","h","443","Open","Timeout",""'
    }
    It 'appends rows without repeating the header, and starts a new file the next day' {
        $c1 = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 10:00:00'); Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Not checked'; NewStatus = 'Open'; LatencyMs = 1.5 }
        $c2 = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 11:00:00'); Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Open'; NewStatus = 'Refused'; LatencyMs = $null }
        $c3 = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-17 00:00:01'); Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Refused'; NewStatus = 'Open'; LatencyMs = 2 }
        $p = (Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $c1).Path
        [void](Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $c2)
        $p3 = (Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $c3).Path
        @(Get-Content -LiteralPath $p).Count | Should -Be 3
        Split-Path -Leaf $p3 | Should -Be 'PortMonitor_20261117.csv'
    }
    It 'writes latency with a dot whatever the culture' {
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]'de-DE'
            $c = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 10:00:00'); Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Not checked'; NewStatus = 'Open'; LatencyMs = 12.5 }
            $p = (Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $c).Path
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
        (Get-Content -LiteralPath $p)[1] | Should -Match '"12\.5"$'
    }
    It 'returns Ok = $false (does not throw) when the file is locked, for example open in Excel' {
        New-Item -ItemType Directory -Path $script:LogDir | Out-Null
        $file = Join-Path $script:LogDir 'PortMonitor_20261116.csv'
        $lock = [System.IO.File]::Open($file, 'OpenOrCreate', 'ReadWrite', 'None')
        try {
            $c = [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 10:00:00'); Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Open'; NewStatus = 'Timeout'; LatencyMs = $null }
            $r = Write-PortStateChangeLog -LogDirectory $script:LogDir -Change $c
            $r.Ok | Should -BeFalse
            $r.Error | Should -Not -BeNullOrEmpty
        }
        finally { $lock.Dispose() }
    }
}

Describe 'Receive-PortCheckResult and Invoke-PortMonitorCycle (fake engine, no network)' {
    It 'applies a finished result, disposes the job and returns the change' {
        $engine = New-FakeEngine
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }; $s.InFlight = $true
        $job = New-FakeJob -State $s -Result ([PSCustomObject]@{ Status = 'Open'; LatencyMs = 3; Detail = 'ok' })
        [void]$engine.InFlight.Add($job)
        $r = Receive-PortCheckResult -Engine $engine -States @($s)
        $r.Processed | Should -Be 1
        @($r.Changes).Count | Should -Be 1
        $s.Status | Should -Be 'Open'
        $s.InFlight | Should -BeFalse
        $job.PowerShell.Disposed | Should -BeTrue
        $engine.InFlight.Count | Should -Be 0
    }
    It 'drops a result for a target whose host or port was edited while it ran' {
        $engine = New-FakeEngine
        $s = New-PortTargetState @{ Host = 'new-host'; Port = 1 }; $s.InFlight = $true
        [void]$engine.InFlight.Add((New-FakeJob -State $s -Result ([PSCustomObject]@{ Status = 'Open' }) -HostName 'old-host'))
        $r = Receive-PortCheckResult -Engine $engine -States @($s)
        $r.Processed | Should -Be 0
        $s.Status | Should -Be 'Not checked'
        $s.InFlight | Should -BeFalse
    }
    It 'drops a result for a removed target' {
        $engine = New-FakeEngine
        $gone = New-PortTargetState @{ Host = 'h'; Port = 1 }
        [void]$engine.InFlight.Add((New-FakeJob -State $gone -Result ([PSCustomObject]@{ Status = 'Open' })))
        (Receive-PortCheckResult -Engine $engine -States @()).Processed | Should -Be 0
        $engine.InFlight.Count | Should -Be 0
    }
    It 'turns a check that returned nothing into Error' {
        $engine = New-FakeEngine
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        [void]$engine.InFlight.Add((New-FakeJob -State $s -Result $null))
        [void](Receive-PortCheckResult -Engine $engine -States @($s))
        $s.Status | Should -Be 'Error'
    }
    It 'after Stop, disposes the draining checks without applying their results' {
        $engine = New-FakeEngine
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }; $s.InFlight = $true
        $job = New-FakeJob -State $s -Result ([PSCustomObject]@{ Status = 'Open' })
        [void]$engine.InFlight.Add($job)
        Suspend-PortMonitorChecks -Engine $engine -States @($s)
        $s.InFlight | Should -BeFalse
        $r = Receive-PortCheckResult -Engine $engine -States @($s)
        $r.Processed | Should -Be 0
        $s.Status | Should -Be 'Not checked'
        $job.PowerShell.Disposed | Should -BeTrue
        $engine.Draining.Count | Should -Be 0
    }
    It 'Invoke-PortMonitorCycle logs each change to the log folder and starts due checks up to the pool size' {
        $engine = New-FakeEngine
        $engine.MaxConcurrency = 1
        $logDir = Join-Path $TestDrive 'cycle-logs'
        $done = New-PortTargetState @{ Label = 'done'; Host = 'h'; Port = 1 }; $done.InFlight = $true; $done.NextDue = (Get-Date).AddMinutes(5)
        [void]$engine.InFlight.Add((New-FakeJob -State $done -Result ([PSCustomObject]@{ Status = 'Refused' })))
        $due1 = New-PortTargetState @{ Label = 'due1'; Host = 'h'; Port = 2 }
        $due2 = New-PortTargetState @{ Label = 'due2'; Host = 'h'; Port = 3 }
        Mock Start-PortCheck { $State.InFlight = $true; [void]$Engine.InFlight.Add([PSCustomObject]@{ Id = $State.Id; Handle = [PSCustomObject]@{ IsCompleted = $false } }) }
        $cycle = Invoke-PortMonitorCycle -Engine $engine -States @($done, $due1, $due2) -LogDirectory $logDir
        @($cycle.Changes).Count | Should -Be 1
        $cycle.Started | Should -Be 1
        Should -Invoke Start-PortCheck -Times 1 -Exactly
        @(Get-ChildItem -LiteralPath $logDir -Filter 'PortMonitor_*.csv').Count | Should -Be 1
    }
    It 'Invoke-PortMonitorCycle -NoLog writes nothing' {
        $engine = New-FakeEngine
        $logDir = Join-Path $TestDrive 'nolog'
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }; $s.NextDue = (Get-Date).AddMinutes(5)
        [void]$engine.InFlight.Add((New-FakeJob -State $s -Result ([PSCustomObject]@{ Status = 'Open' })))
        [void](Invoke-PortMonitorCycle -Engine $engine -States @($s) -LogDirectory $logDir -NoLog)
        Test-Path -LiteralPath $logDir | Should -BeFalse
    }
}

Describe 'Packet loss and slow answers (no network)' {
    BeforeAll {
        function New-LossResult {
            # A port result as Invoke-PortTargetCheck returns it, with a ping burst of $Sent pings
            # of which $Received answered.
            param([string]$Status = 'Open', [int]$Sent = 10, [int]$Received = 10, $Latency = 2)
            $trips = @(for ($i = 0; $i -lt $Sent; $i++) { if ($i -lt $Received) { 10 + ($i % 2) * 4 } else { $null } })
            $loss = ConvertTo-PortPingSummary -RoundTrips $trips
            $loss | Add-Member -NotePropertyName Error -NotePropertyValue $null
            $lat = $null; if ($Status -eq 'Open') { $lat = $Latency }
            [PSCustomObject]@{ Status = $Status; LatencyMs = $lat; Detail = 'd'; Address = '10.0.0.1'; Loss = $loss }
        }
        function Step {
            param($State, $Result)
            [void](Update-PortTargetState -State $State -Result $Result)
            Update-PortTargetQuality -State $State -Result $Result
        }
    }

    It 'loss measuring is off by default, with 10 pings and a 5 % alert level, and validates its ranges' {
        $t = ConvertTo-PortTarget @{ Host = 'h'; Port = 1 }
        $t.MeasureLoss | Should -BeFalse
        $t.LossPings | Should -Be 10
        $t.LossAlertPercent | Should -Be 5
        (ConvertTo-PortTarget @{ Host = 'h'; Port = 1; MeasureLoss = 'yes' }).MeasureLoss | Should -BeTrue
        @(Test-PortTargetDefinition @{ Host = 'h'; Port = 1; LossPings = 0 })[0] | Should -Match 'Pings per check'
        @(Test-PortTargetDefinition @{ Host = 'h'; Port = 1; LossPings = 51 })[0] | Should -Match 'Pings per check'
        @(Test-PortTargetDefinition @{ Host = 'h'; Port = 1; LossAlertPercent = 101 })[0] | Should -Match 'Alert above'
    }
    It 'a list saved before loss measuring existed loads with it off' {
        $p = Join-Path $TestDrive 'v11.json'
        Set-Content -LiteralPath $p -Encoding ASCII -Value '[{"Label":"L","Host":"h","Port":1,"IntervalSec":30,"TimeoutMs":3000,"Enabled":true,"FailAfter":2,"RecoverAfter":1}]'
        $t = @((Read-PortMonitorConfig -Path $p).Targets)[0]
        $t.MeasureLoss | Should -BeFalse
        $t.LossPings | Should -Be 10
    }
    It 'the loss settings survive a save and reload' {
        $p = Join-Path $TestDrive 'loss-save.json'
        [void](Save-PortMonitorConfig -Path $p -Targets @(@{ Host = 'h'; Port = 1; MeasureLoss = $true; LossPings = 20; LossAlertPercent = 3 }))
        $t = @((Read-PortMonitorConfig -Path $p).Targets)[0]
        $t.MeasureLoss | Should -BeTrue
        $t.LossPings | Should -Be 20
        $t.LossAlertPercent | Should -Be 3
    }

    It 'ping summary: <Case>' -TestCases @(
        @{ Case = 'all answered'; Trips = @(10, 12, 11, 15); Received = 4; Loss = 0; Avg = 12; Jitter = 2.3 }
        @{ Case = 'one lost of four'; Trips = @(10, $null, 12, 14); Received = 3; Loss = 25; Avg = 12; Jitter = 2 }
        @{ Case = 'none answered'; Trips = @($null, $null); Received = 0; Loss = 100; Avg = $null; Jitter = $null }
        @{ Case = 'one reply: no jitter'; Trips = @(10, $null); Received = 1; Loss = 50; Avg = 10; Jitter = $null }
    ) {
        param($Case, $Trips, $Received, $Loss, $Avg, $Jitter)
        $r = ConvertTo-PortPingSummary -RoundTrips $Trips
        $r.Sent | Should -Be @($Trips).Count
        $r.Received | Should -Be $Received
        $r.LossPercent | Should -Be $Loss
        $r.AvgMs | Should -Be $Avg
        $r.JitterMs | Should -Be $Jitter
    }
    It 'Measure-PingLoss refuses a name (it pings the address the port check used) without sending anything' {
        $r = Measure-PingLoss -Address 'server01' -Count 1
        $r.Error | Should -Match 'not an IP address'
        $r.LossPercent | Should -BeNullOrEmpty
    }
    It 'Invoke-PortTargetCheck pings only with -MeasureLoss, only when the port check found an address, and caps each ping at 2000 ms' {
        Mock Test-TcpPort { [PSCustomObject]@{ Status = 'Open'; LatencyMs = 1; Address = '10.0.0.9'; Detail = '' } }
        Mock Measure-PingLoss { [PSCustomObject]@{ Sent = $Count; Received = $Count; LossPercent = 0; AvgMs = 1; JitterMs = 0; Error = $null } }
        (Invoke-PortTargetCheck -HostName 'h' -Port 1).Loss | Should -BeNullOrEmpty
        Should -Invoke Measure-PingLoss -Times 0 -Exactly
        $r = Invoke-PortTargetCheck -HostName 'h' -Port 1 -TimeoutMs 9000 -MeasureLoss -LossPings 7
        $r.Loss.Sent | Should -Be 7
        Should -Invoke Measure-PingLoss -Times 1 -Exactly -ParameterFilter { $Address -eq '10.0.0.9' -and $TimeoutMs -eq 2000 -and $Count -eq 7 }
        Mock Test-TcpPort { [PSCustomObject]@{ Status = 'DNS Failure'; LatencyMs = $null; Address = $null; Detail = '' } }
        (Invoke-PortTargetCheck -HostName 'h' -Port 1 -MeasureLoss).Loss | Should -BeNullOrEmpty
        Should -Invoke Measure-PingLoss -Times 1 -Exactly
    }
    It 'the background pool is given every function the check needs' {
        $src = Get-Content -LiteralPath $script:ScriptPath -Raw
        foreach ($name in 'Invoke-PortTargetCheck', 'Test-TcpPort', 'Get-PortCheckFailure', 'Measure-PingLoss', 'ConvertTo-PortPingSummary') {
            $src | Should -Match "foreach \(\`$name in @\([^)]*'$name'"
        }
    }

    It 'a target that does not measure loss gets no loss state, even if a result carries pings' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        Step $s (New-LossResult -Received 2) | Should -BeNullOrEmpty
        $s.LossText | Should -Be ''
        $s.LossStatus | Should -BeNullOrEmpty
    }
    It 'the first measurement is logged at once as Not checked -> OK, with the figures' {
        $s = New-PortTargetState @{ Label = 'DC'; Host = 'h'; Port = 1; MeasureLoss = $true }
        $c = Step $s (New-LossResult -Received 10)
        $c.Kind | Should -Be 'Loss'
        $c.PreviousStatus | Should -Be 'Not checked'
        $c.NewStatus | Should -Be 'OK'
        $c.LossPercent | Should -Be 0
        $s.LossText | Should -Be '0.0'
        $s.JitterMs | Should -Be 4
        $s.Detail | Should -Match '10 of 10 pings answered \(0\.0 % lost, jitter 4 ms\)'
    }
    It 'high loss is confirmed after FailAfter bursts in a row, and the port status is untouched' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true; FailAfter = 2 }
        [void](Step $s (New-LossResult -Received 10))
        Step $s (New-LossResult -Received 8) | Should -BeNullOrEmpty -Because 'one bad burst is a blip'
        $s.LossStatus | Should -Be 'OK'
        $s.Detail | Should -Match 'Confirming High loss \(1 of 2 in a row\)'
        $c = Step $s (New-LossResult -Received 9)
        $c.PreviousStatus | Should -Be 'OK'
        $c.NewStatus | Should -Be 'High loss'
        $c.LossPercent | Should -Be 10
        $s.LossStatus | Should -Be 'High loss'
        $s.Status | Should -Be 'Open'
    }
    It 'loss below the alert level is OK (4 % lost with a 5 % alert level)' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true; LossPings = 25; LossAlertPercent = 5; FailAfter = 1 }
        (Step $s (New-LossResult -Sent 25 -Received 24)).NewStatus | Should -Be 'OK'
        (Step $s (New-LossResult -Sent 20 -Received 19)).NewStatus | Should -Be 'High loss' -Because '5 % is at the alert level'
    }
    It 'comes back to OK after RecoverAfter good bursts' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true; FailAfter = 1; RecoverAfter = 2 }
        [void](Step $s (New-LossResult -Received 10)); [void](Step $s (New-LossResult -Received 5))
        Step $s (New-LossResult -Received 10) | Should -BeNullOrEmpty
        (Step $s (New-LossResult -Received 10)).NewStatus | Should -Be 'OK'
    }
    It 'no ping answered while the port is open means ping is blocked, not 100 % loss' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true }
        $c = Step $s (New-LossResult -Received 0)
        $c.NewStatus | Should -Be 'No replies'
        $s.LossText | Should -Be 'no reply'
        $s.Detail | Should -Match 'firewall probably blocks ping'
        Get-PortChangeNotification -Changes @($c) | Should -BeNullOrEmpty -Because 'a blocked ping is a setup matter, not news'
    }
    It 'while the port is down the loss state is left alone (the outage is already reported)' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true; FailAfter = 1 }
        [void](Step $s (New-LossResult -Received 10))
        Step $s (New-LossResult -Status 'Timeout' -Received 0) | Should -BeNullOrEmpty
        $s.LossStatus | Should -Be 'OK'
        $s.LossHighStreak | Should -Be 0
    }
    It 'a ping that could not be sent says so and changes nothing' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true }
        $r = New-LossResult; $r.Loss = [PSCustomObject]@{ Sent = $null; Received = $null; LossPercent = $null; AvgMs = $null; JitterMs = $null; Error = 'Ping could not be sent to 10.0.0.1: x' }
        Step $s $r | Should -BeNullOrEmpty
        $s.LossText | Should -Be 'error'
        $s.Detail | Should -Match 'Packet loss not measured: Ping could not be sent'
    }
    It 'Reset-PortTargetLoss clears what was seen (loss turned on or off in Edit)' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true }
        [void](Step $s (New-LossResult -Received 5))
        Reset-PortTargetLoss -State $s
        $s.LossStatus | Should -BeNullOrEmpty
        $s.LastKnownLossStatus | Should -BeNullOrEmpty
        $s.PingsSent | Should -Be 0
        $s.LossText | Should -Be ''
    }

    It 'slow answer: <Case>' -TestCases @(
        @{ Case = 'too little history'; History = @(1, 1, 1, 1); Latency = 3000; Expect = $null }
        @{ Case = 'LAN target resent once'; History = @(1, 1, 2, 1, 1); Latency = 1003; Expect = $true }
        @{ Case = 'LAN target a bit slower'; History = @(1, 1, 2, 1, 1); Latency = 6; Expect = $false }
        @{ Case = 'WAN target, normal wobble'; History = @(120, 118, 125, 122, 119); Latency = 300; Expect = $false }
        @{ Case = 'WAN target resent once'; History = @(120, 118, 125, 122, 119); Latency = 1150; Expect = $true }
    ) {
        param($Case, $History, $Latency, $Expect)
        $r = Get-PortLatencySpike -History $History -LatencyMs $Latency
        if ($null -eq $Expect) { $r | Should -BeNullOrEmpty }
        else { $r.IsSpike | Should -Be $Expect }
    }
    It 'a slow answer counts and is explained in the details, but is not a change or a notification' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        foreach ($i in 1..6) { [void](Step $s (New-LossResult -Latency 2)) }
        Step $s (New-LossResult -Latency 1100) | Should -BeNullOrEmpty
        $s.SlowCount | Should -Be 1
        $s.Detail | Should -Match '^Slow answer: 1100 ms \(usually 2 ms\), often a lost packet'
        $s.Status | Should -Be 'Open'
    }
    It 'keeps only the last 20 connect times' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        foreach ($i in 1..30) { [void](Step $s (New-LossResult -Latency $i)) }
        $s.LatencyHistory.Count | Should -Be 20
        $s.LatencyHistory[0] | Should -Be 11
    }

    It 'Receive-PortCheckResult returns both the port change and the loss change' {
        $engine = New-FakeEngine
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; MeasureLoss = $true }; $s.InFlight = $true
        [void]$engine.InFlight.Add((New-FakeJob -State $s -Result (New-LossResult -Received 10)))
        $r = Receive-PortCheckResult -Engine $engine -States @($s)
        @($r.Changes | ForEach-Object Kind) -join ',' | Should -Be 'State,Loss'
    }
    It 'Invoke-PortMonitorCycle writes loss changes to their own daily file and leaves the status log columns alone' {
        $engine = New-FakeEngine
        $logDir = Join-Path $TestDrive 'loss-logs'
        $s = New-PortTargetState @{ Label = 'DC'; Host = 'h'; Port = 1; MeasureLoss = $true }; $s.InFlight = $true; $s.NextDue = (Get-Date).AddMinutes(5)
        [void]$engine.InFlight.Add((New-FakeJob -State $s -Result (New-LossResult -Received 7)))
        [void](Invoke-PortMonitorCycle -Engine $engine -States @($s) -LogDirectory $logDir)
        $status = @(Get-ChildItem -LiteralPath $logDir -Filter 'PortMonitor_2*.csv')
        $loss = @(Get-ChildItem -LiteralPath $logDir -Filter 'PortMonitor_Loss_*.csv')
        $status.Count | Should -Be 1
        $loss.Count | Should -Be 1
        (Get-Content -LiteralPath $status[0].FullName -TotalCount 1) | Should -Be '"Timestamp","Label","Host","Port","PreviousStatus","NewStatus","LatencyMs"'
        $row = @(Import-Csv -LiteralPath $loss[0].FullName)[0]
        $row.NewStatus | Should -Be 'High loss'
        $row.LossPercent | Should -Be '30'
        $row.Sent | Should -Be '10'
        $row.Received | Should -Be '7'
    }
    It 'Start-PortCheck asks the pool for pings only on targets that measure loss' {
        $src = (Get-Command Start-PortCheck).Definition
        $src | Should -Match "AddCommand\('Invoke-PortTargetCheck'\)"
        $src | Should -Match "if \(\`$State\.MeasureLoss\) \{ \[void\]\`$ps\.AddParameter\('MeasureLoss', \`$true\)"
    }
    It 'presets ping the host from the first port only (loss is per host)' {
        $dc = @(Get-PortMonitorPortSets | Where-Object { $_.Name -eq 'Domain controller' })[0]
        $made = @(New-PortTargetsFromSet -Set $dc -HostName 'dc01' -MeasureLoss $true -LossPings 15 -LossAlertPercent 2)
        @($made | Where-Object { $_.MeasureLoss }).Count | Should -Be 1
        $made[0].MeasureLoss | Should -BeTrue
        $made[0].LossPings | Should -Be 15
        @($made | ForEach-Object LossAlertPercent | Sort-Object -Unique) | Should -Be @(2)
    }

    It 'console line for a loss change' {
        $c = [PSCustomObject]@{ Kind = 'Loss'; Timestamp = (Get-Date '2026-11-16 09:00:00'); Label = 'DC'; Host = 'dc01'; Port = 389; PreviousStatus = 'OK'; NewStatus = 'High loss'; LossPercent = 12.5; JitterMs = 8 }
        Format-PortStateChangeLine -Change $c | Should -Be '2026-11-16 09:00:00  DC (dc01)  Packet loss: OK -> High loss (12.5 % lost, jitter 8 ms)'
    }
    It 'console table shows Loss % (marked ! when high) only for targets that measure it' {
        $s = New-PortTargetState @{ Label = 'L'; Host = 'h'; Port = 1; MeasureLoss = $true }
        $s.LossText = '12.0'; $s.LossStatus = 'High loss'
        (Format-PortMonitorTableRow -State $s).Rest | Should -Match '\s!12\.0\s'
        $off = New-PortTargetState @{ Label = 'L'; Host = 'h'; Port = 1 }; $off.LossText = '12.0'
        (Format-PortMonitorTableRow -State $off).Rest | Should -Not -Match '12\.0'
    }
    It 'notification: <Case>' -TestCases @(
        @{ Case = 'starts losing packets'; Prev = 'OK'; New = 'High loss'; Kind = 'Down'; Title = 'DC01 is losing packets'; Text = '^dc01: 12\.5 % of pings lost, jitter 8 ms at 14:35:00\. The port still answers' }
        @{ Case = 'high on the first check'; Prev = 'Not checked'; New = 'High loss'; Kind = 'Down'; Title = 'DC01 is losing packets'; Text = '^dc01: 12\.5 %' }
        @{ Case = 'back to normal'; Prev = 'High loss'; New = 'OK'; Kind = 'Up'; Title = 'DC01: packet loss back to normal'; Text = '^dc01: 12\.5 % of pings lost' }
    ) {
        param($Case, $Prev, $New, $Kind, $Title, $Text)
        $c = [PSCustomObject]@{ Kind = 'Loss'; Timestamp = (Get-Date '2026-11-16 14:35:00'); Label = 'DC01'; Host = 'dc01'; Port = 389; PreviousStatus = $Prev; NewStatus = $New; LossPercent = 12.5; JitterMs = 8 }
        $n = Get-PortChangeNotification -Changes @($c)
        $n.Kind | Should -Be $Kind
        $n.Title | Should -Be $Title
        $n.Text | Should -Match $Text
    }
    It 'no notification for a first OK' {
        $c = [PSCustomObject]@{ Kind = 'Loss'; Timestamp = (Get-Date); Label = 'DC01'; Host = 'dc01'; Port = 389; PreviousStatus = 'Not checked'; NewStatus = 'OK'; LossPercent = 0; JitterMs = 1 }
        Get-PortChangeNotification -Changes @($c) | Should -BeNullOrEmpty
    }
    It 'tray: amber "losing packets" when every port answers but a host is losing packets' {
        $a = New-PortTargetState @{ Label = 'A'; Host = 'h'; Port = 1 }; $a.Status = 'Open'; $a.LossStatus = 'High loss'
        $b = New-PortTargetState @{ Label = 'B'; Host = 'h'; Port = 2 }; $b.Status = 'Open'
        $sum = Get-PortMonitorTraySummary -States @($a, $b) -Running $true
        $sum.State | Should -Be 'Degraded'
        $sum.Text | Should -Be 'Port Monitor - A losing packets'
        $b.Status = 'Timeout'
        (Get-PortMonitorTraySummary -States @($a, $b) -Running $true).State | Should -Be 'Problem' -Because 'a port that does not answer outranks packet loss'
    }

    It 'report: periods of high loss per host, closed by OK or by a restart, and an ongoing one' {
        $t0 = Get-Date '2026-11-16 08:00:00'
        $row = { param($m, $h, $prev, $new, $loss) [PSCustomObject]@{ Timestamp = $t0.AddMinutes($m); Label = "L-$h"; Host = $h; Port = '1'; PreviousStatus = $prev; NewStatus = $new; LossPercent = $loss } }
        $rows = @(
            & $row 0 'a' 'Not checked' 'OK' 0
            & $row 10 'a' 'OK' 'High loss' 20
            & $row 40 'a' 'High loss' 'OK' 0
            & $row 0 'b' 'Not checked' 'High loss' 50
            & $row 30 'b' 'Not checked' 'OK' 0
            & $row 50 'c' 'OK' 'High loss' 8
        )
        $r = Get-PortLossReport -Rows $rows -From $t0 -To $t0.AddHours(2)
        @($r.Periods).Count | Should -Be 3
        $a = @($r.Periods | Where-Object Host -eq 'a')[0]
        $a.Duration.TotalMinutes | Should -Be 30
        $a.LossAtStart | Should -Be 20
        (@($r.Periods | Where-Object Host -eq 'b')[0]).EndUncertain | Should -BeTrue
        $c = @($r.Periods | Where-Object Host -eq 'c')[0]
        $c.Ongoing | Should -BeTrue
        $c.End | Should -Be $t0.AddHours(2)
    }
    It 'report HTML: a Packet loss section, and a warning verdict when everything stayed up but loss happened' {
        $t0 = Get-Date '2026-11-16 08:00:00'
        $outages = Get-PortOutageReport -Rows @([PSCustomObject]@{ Timestamp = $t0; Label = 'DC'; Host = 'dc01'; Port = '389'; PreviousStatus = 'Not checked'; NewStatus = 'Open' }) -From $t0 -To $t0.AddHours(2)
        $loss = Get-PortLossReport -Rows @(
            [PSCustomObject]@{ Timestamp = $t0.AddMinutes(5); Label = 'DC'; Host = 'dc01'; Port = '389'; PreviousStatus = 'OK'; NewStatus = 'High loss'; LossPercent = 15 }
            [PSCustomObject]@{ Timestamp = $t0.AddMinutes(25); Label = 'DC'; Host = 'dc01'; Port = '389'; PreviousStatus = 'High loss'; NewStatus = 'OK'; LossPercent = 0 }) -From $t0 -To $t0.AddHours(2)
        $html = ConvertTo-PortOutageReportHtml -Report $outages -LossReport $loss
        $html | Should -Match 'class="verdict warn">All 1 target\(s\) stayed up, but 1 host\(s\) had periods of high packet loss'
        $html | Should -Match '<h2>Packet loss</h2>'
        $html | Should -Match '15\.0 %'
        (ConvertTo-PortOutageReportHtml -Report $outages) | Should -Not -Match 'Packet loss</h2>'
    }
    It 'Export-PortOutageReport reads the loss logs too, and the status log reader ignores them' {
        $logs = Join-Path $TestDrive 'export-loss'
        $now = Get-Date
        [void](Write-PortStateChangeLog -LogDirectory $logs -Change ([PSCustomObject]@{ Timestamp = $now.AddHours(-3); Label = 'DC'; Host = 'dc01'; Port = 389; PreviousStatus = 'Not checked'; NewStatus = 'Open'; LatencyMs = 1 }))
        foreach ($c in @(
                [PSCustomObject]@{ Kind = 'Loss'; Timestamp = $now.AddHours(-2); Label = 'DC'; Host = 'dc01'; Port = 389; PreviousStatus = 'OK'; NewStatus = 'High loss'; LossPercent = 20; JitterMs = 3; AvgMs = 9; Sent = 10; Received = 8 }
                [PSCustomObject]@{ Kind = 'Loss'; Timestamp = $now.AddHours(-1); Label = 'DC'; Host = 'dc01'; Port = 389; PreviousStatus = 'High loss'; NewStatus = 'OK'; LossPercent = 0; JitterMs = 1; AvgMs = 9; Sent = 10; Received = 10 })) {
            (Write-PortLossChangeLog -LogDirectory $logs -Change $c).Ok | Should -BeTrue
        }
        @((Read-PortStateLog -LogDirectory $logs).Rows).Count | Should -Be 1
        $out = Export-PortOutageReport -LogDirectory $logs -OutputPath (Join-Path $TestDrive 'export-out') -Days 1
        @($out.LossReport.Periods).Count | Should -Be 1
        @($out.LogFiles).Count | Should -Be 2
    }
}

Describe 'Defaults and window layout' {
    It 'defaults to %APPDATA%\PortMonitor' {
        $old = $env:APPDATA
        try {
            $env:APPDATA = Join-Path $TestDrive 'Roaming'
            Get-PortMonitorDefaultRoot | Should -Be (Join-Path $TestDrive 'Roaming\PortMonitor')
        }
        finally { $env:APPDATA = $old }
    }
    It 'falls back to LOCALAPPDATA when APPDATA is not set' {
        $oldA = $env:APPDATA; $oldL = $env:LOCALAPPDATA
        try {
            $env:APPDATA = $null
            $env:LOCALAPPDATA = Join-Path $TestDrive 'Local'
            Get-PortMonitorDefaultRoot | Should -Be (Join-Path $TestDrive 'Local\PortMonitor')
        }
        finally { $env:APPDATA = $oldA; $env:LOCALAPPDATA = $oldL }
    }
    It 'both XAML documents are well-formed XML' {
        { [xml](Get-PortMonitorMainXaml) } | Should -Not -Throw
        { [xml](Get-PortTargetDialogXaml) } | Should -Not -Throw
    }
    It 'every element the code looks up exists in the XAML' {
        $source = Get-Content -LiteralPath $script:ScriptPath -Raw
        $main = Get-PortMonitorMainXaml
        $dialog = Get-PortTargetDialogXaml
        $mainList = [regex]::Match($source, "foreach \(\`$n in ('Grid'[^)]+)\)").Groups[1].Value
        $dialogList = [regex]::Match($source, "foreach \(\`$n in ('Heading'[^)]+)\)").Groups[1].Value
        $mainList | Should -Not -BeNullOrEmpty
        $dialogList | Should -Not -BeNullOrEmpty
        foreach ($name in [regex]::Matches($mainList, "'(\w+)'") | ForEach-Object { $_.Groups[1].Value }) { $main | Should -Match "x:Name=`"$name`"" }
        foreach ($name in [regex]::Matches($dialogList, "'(\w+)'") | ForEach-Object { $_.Groups[1].Value }) { $dialog | Should -Match "x:Name=`"$name`"" }
    }
    It 'the window XAML loads in WPF (STA hosts only; nothing is shown)' -Skip:([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
        $w = [System.Windows.Markup.XamlReader]::Parse((Get-PortMonitorMainXaml))
        $w.FindName('Grid').Columns.Count | Should -Be 13
        @($w.FindName('Grid').Columns | ForEach-Object { [string]$_.Header }) | Should -Contain 'Loss %'
        $d = [System.Windows.Markup.XamlReader]::Parse((Get-PortTargetDialogXaml))
        $d.FindName('BtnSave') | Should -Not -BeNullOrEmpty
    }
    It 'no grid column takes a theme colour directly (a column is not in the visual tree, so it would never resolve)' {
        # Regression: Details used Foreground="{DynamicResource TextMuted}" on the column and came
        # out black, unreadable in dark mode. The colour belongs on the cell (ElementStyle).
        $xaml = Get-PortMonitorMainXaml
        [regex]::Matches($xaml, '<DataGrid\w*Column[^>]*>') | ForEach-Object { $_.Value | Should -Not -Match 'DynamicResource' }
    }
    It 'the sample targets.example.json loads with 3 valid targets' {
        $r = Read-PortMonitorConfig -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'targets.example.json')
        @($r.Warnings).Count | Should -Be 0
        @($r.Targets).Count | Should -Be 3
    }
}

Describe 'Ignoring one-off blips (FailAfter / RecoverAfter)' {
    BeforeAll {
        function Step { param($State, [string]$Status) Update-PortTargetState -State $State -Result ([PSCustomObject]@{ Status = $Status; LatencyMs = 1; Detail = 'd' }) }
    }
    It 'defaults to down after 2 failures and back up after 1 success, and validates 1-10' {
        $t = ConvertTo-PortTarget @{ Host = 'h'; Port = 1 }
        $t.FailAfter | Should -Be 2
        $t.RecoverAfter | Should -Be 1
        @(Test-PortTargetDefinition @{ Host = 'h'; Port = 1; FailAfter = 0 })[0] | Should -Match 'Down after'
        @(Test-PortTargetDefinition @{ Host = 'h'; Port = 1; RecoverAfter = 11 })[0] | Should -Match 'Back up after'
    }
    It 'loads a version 1.0 list (no FailAfter/RecoverAfter) with the defaults' {
        $p = Join-Path $TestDrive 'v10.json'
        Set-Content -LiteralPath $p -Encoding ASCII -Value '[{"Label":"L","Host":"h","Port":1,"IntervalSec":30,"TimeoutMs":3000,"Enabled":true}]'
        $t = @((Read-PortMonitorConfig -Path $p).Targets)[0]
        $t.FailAfter | Should -Be 2
        $t.RecoverAfter | Should -Be 1
    }
    It 'a single failure after Open is not reported; the status stays Open and the details say it is being confirmed' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        [void](Step $s 'Open')
        Step $s 'Timeout' | Should -BeNullOrEmpty
        $s.Status | Should -Be 'Open'
        $s.Detail | Should -Match '^Confirming: Timeout \(1 of 2 in a row\)'
        $s.FailCount | Should -Be 1 -Because 'raw failures still count toward Fail Count and Uptime %'
        Step $s 'Open' | Should -BeNullOrEmpty -Because 'the blip ended before it was confirmed'
        $s.Status | Should -Be 'Open'
    }
    It 'the second failure in a row is reported as Open -> the failure' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        [void](Step $s 'Open')
        [void](Step $s 'Timeout')
        $c = Step $s 'Refused'
        $c.PreviousStatus | Should -Be 'Open'
        $c.NewStatus | Should -Be 'Refused'
        $s.Status | Should -Be 'Refused'
    }
    It 'reports a failure on the very first check at once (nothing known-good to protect)' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; FailAfter = 3 }
        (Step $s 'DNS Failure').NewStatus | Should -Be 'DNS Failure'
    }
    It 'reports a change between two failure kinds at once (it is down either way)' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; FailAfter = 1 }
        [void](Step $s 'Open'); [void](Step $s 'Timeout')
        (Step $s 'Refused').PreviousStatus | Should -Be 'Timeout'
    }
    It 'with RecoverAfter 3, it comes back up only after 3 good checks in a row' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1; FailAfter = 1; RecoverAfter = 3 }
        [void](Step $s 'Open'); [void](Step $s 'Timeout')
        Step $s 'Open' | Should -BeNullOrEmpty
        Step $s 'Open' | Should -BeNullOrEmpty
        $s.Status | Should -Be 'Timeout'
        (Step $s 'Open').NewStatus | Should -Be 'Open'
    }
    It 'turning a target off and on clears a half-finished streak' {
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
        [void](Step $s 'Open'); [void](Step $s 'Timeout')
        Set-PortTargetEnabled -State $s -Enabled $false
        Set-PortTargetEnabled -State $s -Enabled $true
        Step $s 'Timeout' | Should -BeNullOrEmpty -Because 'the earlier failure must not count toward the new streak'
    }
}

Describe 'Role presets (port sets)' {
    It 'has the documented ports for each role' {
        $sets = @{}
        foreach ($s in Get-PortMonitorPortSets) { $sets[$s.Name] = @($s.Ports | ForEach-Object { $_.Port }) }
        # Microsoft Learn: service overview and network port requirements; Exchange network ports;
        # Standard TCP/IP port monitor (RAW 9100).
        $sets['Domain controller'] -join ',' | Should -Be '53,88,135,389,445,464,636,3268,3269'
        $sets['File server'] -join ',' | Should -Be '445'
        $sets['Remote Desktop server'] -join ',' | Should -Be '3389,443'
        $sets['SQL Server'] -join ',' | Should -Be '1433'
        $sets['Exchange server'] -join ',' | Should -Be '443,25,587'
        $sets['Web server'] -join ',' | Should -Be '80,443'
        $sets['Network printer'] -join ',' | Should -Be '9100,515'
        $sets['Remote management (WinRM)'] -join ',' | Should -Be '5985,5986'
    }
    It 'every preset port is valid and listed once per role' {
        foreach ($s in Get-PortMonitorPortSets) {
            $ports = @($s.Ports | ForEach-Object { $_.Port })
            @($ports | Select-Object -Unique).Count | Should -Be $ports.Count -Because $s.Name
            foreach ($p in $s.Ports) { $p.Port | Should -BeGreaterThan 0; $p.Port | Should -BeLessOrEqual 65535; $p.Service | Should -Not -BeNullOrEmpty }
        }
    }
    It 'makes one target per port, labelled "<name> - <service>", with the shared settings' {
        $dc = Get-PortMonitorPortSets | Where-Object { $_.Name -eq 'Domain controller' }
        $t = @(New-PortTargetsFromSet -Set $dc -HostName ' dc01.example.local ' -Name 'Contoso DC01' -IntervalSec 60 -FailAfter 3)
        $t.Count | Should -Be 9
        $t[0].Label | Should -Be 'Contoso DC01 - DNS'
        $t[0].Host | Should -Be 'dc01.example.local'
        ($t | Where-Object { $_.Port -eq 3268 }).Label | Should -Be 'Contoso DC01 - Global Catalog'
        @($t | Where-Object { $_.IntervalSec -ne 60 -or $_.FailAfter -ne 3 }).Count | Should -Be 0
        @($t | ForEach-Object { @(Test-PortTargetDefinition $_).Count } | Where-Object { $_ -gt 0 }).Count | Should -Be 0
    }
    It 'uses the host as the name when none is given, keeps only ticked ports, and skips ports already monitored' {
        $web = Get-PortMonitorPortSets | Where-Object { $_.Name -eq 'Web server' }
        (@(New-PortTargetsFromSet -Set $web -HostName 'web01'))[0].Label | Should -Be 'web01 - HTTP'
        @(New-PortTargetsFromSet -Set $web -HostName 'web01' -Ports 443).Port | Should -Be 443
        $existing = @(New-PortTargetState @{ Host = 'WEB01'; Port = 80 })
        @(New-PortTargetsFromSet -Set $web -HostName 'web01' -ExistingTargets $existing).Port | Should -Be 443
    }
}

Describe 'Uptime and outage report' {
    BeforeAll {
        function Row { param([string]$When, [string]$Prev, [string]$New, [string]$Label = 'DC01 LDAP', [string]$HostName = 'dc01', [string]$Port = '389')
            [PSCustomObject]@{ Timestamp = [datetime]::ParseExact($When, 'yyyy-MM-dd HH:mm', $null); Label = $Label; Host = $HostName; Port = $Port; PreviousStatus = $Prev; NewStatus = $New } }
        $script:From = [datetime]'2026-11-10 00:00'
        $script:To = [datetime]'2026-11-11 00:00'
    }
    It 'finds an outage from going down to coming back, and works out uptime over the monitored time' {
        $rows = @(
            Row '2026-11-10 00:00' 'Not checked' 'Open'
            Row '2026-11-10 06:00' 'Open' 'Timeout'
            Row '2026-11-10 06:30' 'Timeout' 'Refused'
            Row '2026-11-10 08:00' 'Refused' 'Open')
        $r = Get-PortOutageReport -Rows $rows -From $script:From -To $script:To
        @($r.Outages).Count | Should -Be 1 -Because 'Timeout -> Refused is the same outage'
        $o = $r.Outages[0]
        $o.Start | Should -Be ([datetime]'2026-11-10 06:00')
        $o.End | Should -Be ([datetime]'2026-11-10 08:00')
        $o.Status | Should -Be 'Refused'
        $r.Targets[0].Downtime | Should -Be ([TimeSpan]::FromHours(2))
        $r.Targets[0].UptimePercent | Should -Be 91.67
    }
    It 'marks an outage still going at the end as ongoing' {
        $rows = @((Row '2026-11-10 00:00' 'Not checked' 'Open'), (Row '2026-11-10 23:00' 'Open' 'Timeout'))
        $r = Get-PortOutageReport -Rows $rows -From $script:From -To $script:To
        $r.Outages[0].Ongoing | Should -BeTrue
        $r.Targets[0].Ongoing | Should -BeTrue
        $r.Targets[0].Downtime | Should -Be ([TimeSpan]::FromHours(1))
    }
    It 'closes an outage at a restart ("Not checked" row) and marks its end uncertain' {
        $rows = @(
            Row '2026-11-10 00:00' 'Not checked' 'Open'
            Row '2026-11-10 10:00' 'Open' 'Timeout'
            Row '2026-11-10 12:00' 'Not checked' 'Open')
        $o = (Get-PortOutageReport -Rows $rows -From $script:From -To $script:To).Outages[0]
        $o.End | Should -Be ([datetime]'2026-11-10 12:00')
        $o.EndUncertain | Should -BeTrue
    }
    It 'counts only the part of an outage inside the period, but lists its real start' {
        $rows = @(
            Row '2026-11-09 20:00' 'Not checked' 'Open'
            Row '2026-11-09 22:00' 'Open' 'Timeout'
            Row '2026-11-10 02:00' 'Timeout' 'Open')
        $r = Get-PortOutageReport -Rows $rows -From $script:From -To $script:To
        $r.Outages[0].Start | Should -Be ([datetime]'2026-11-09 22:00')
        $r.Targets[0].Downtime | Should -Be ([TimeSpan]::FromHours(2))
        $r.Targets[0].UptimePercent | Should -Be 91.67
    }
    It 'leaves out outages wholly outside the period and ignores rows after it' {
        $rows = @(
            Row '2026-11-09 00:00' 'Not checked' 'Open'
            Row '2026-11-09 01:00' 'Open' 'Timeout'
            Row '2026-11-09 02:00' 'Timeout' 'Open'
            Row '2026-11-11 05:00' 'Open' 'Timeout')
        $r = Get-PortOutageReport -Rows $rows -From $script:From -To $script:To
        @($r.Outages).Count | Should -Be 0
        $r.Targets[0].UptimePercent | Should -Be 100
    }
    It 'keeps targets apart by host and port' {
        $rows = @(
            Row '2026-11-10 00:00' 'Not checked' 'Open'
            Row '2026-11-10 00:00' 'Not checked' 'Open' -Label 'DC01 DNS' -Port '53'
            Row '2026-11-10 01:00' 'Open' 'Refused' -Label 'DC01 DNS' -Port '53')
        $r = Get-PortOutageReport -Rows $rows -From $script:From -To $script:To
        @($r.Targets).Count | Should -Be 2
        $r.Targets[0].Label | Should -Be 'DC01 DNS' -Because 'the target with the most downtime comes first'
    }
    It 'HTML: verdict first, values HTML-encoded, plain-English verdict for a clean period' {
        $rows = @((Row '2026-11-10 00:00' 'Not checked' 'Open' -Label '<script>x</script>'), (Row '2026-11-10 01:00' 'Open' 'Timeout' -Label '<script>x</script>'))
        $html = ConvertTo-PortOutageReportHtml -Report (Get-PortOutageReport -Rows $rows -From $script:From -To $script:To)
        $html | Should -Not -Match '<script>x'
        $html | Should -Match '&lt;script&gt;x'
        $html.IndexOf('class="verdict bad"') | Should -BeLessThan $html.IndexOf('<h2>Targets</h2>')
        $clean = ConvertTo-PortOutageReportHtml -Report (Get-PortOutageReport -Rows @(Row '2026-11-10 00:00' 'Not checked' 'Open') -From $script:From -To $script:To)
        $clean | Should -Match 'All 1 target\(s\) were up for the whole period'
        ConvertTo-PortOutageReportHtml -Report (Get-PortOutageReport -Rows @() -From $script:From -To $script:To) | Should -Match 'Was Port Monitor running\?'
    }
    It 'reads the daily CSV files written by Write-PortStateChangeLog, up to the end date' {
        $dir = Join-Path $TestDrive 'report-logs'
        foreach ($c in @(
                [PSCustomObject]@{ Timestamp = [datetime]'2026-11-09 10:00:00'; Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Not checked'; NewStatus = 'Open'; LatencyMs = 1 }
                [PSCustomObject]@{ Timestamp = [datetime]'2026-11-10 10:00:00'; Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Open'; NewStatus = 'Timeout'; LatencyMs = $null }
                [PSCustomObject]@{ Timestamp = [datetime]'2026-11-12 10:00:00'; Label = 'L'; Host = 'h'; Port = 1; PreviousStatus = 'Timeout'; NewStatus = 'Open'; LatencyMs = 2 })) {
            [void](Write-PortStateChangeLog -LogDirectory $dir -Change $c)
        }
        $log = Read-PortStateLog -LogDirectory $dir -To ([datetime]'2026-11-11 00:00')
        @($log.Files).Count | Should -Be 2
        @($log.Rows).Count | Should -Be 2
        $log.Rows[1].Timestamp | Should -Be ([datetime]'2026-11-10 10:00:00')
    }
    It 'Export-PortOutageReport writes PortMonitor_Report_<timestamp>.html to the output folder' {
        $out = Export-PortOutageReport -LogDirectory (Join-Path $TestDrive 'none') -OutputPath (Join-Path $TestDrive 'reports') -Days 7 -Now ([datetime]'2026-11-16 14:00:00')
        Split-Path -Leaf $out.Path | Should -Be 'PortMonitor_Report_2026-11-16_140000.html'
        Get-Content -LiteralPath $out.Path -Raw | Should -Match 'last 7 day'
    }
    It 'Format-PortDuration reads naturally' {
        Format-PortDuration ([TimeSpan]::FromSeconds(45)) | Should -Be '45 s'
        Format-PortDuration ([TimeSpan]::FromMinutes(12.5)) | Should -Be '12 min'
        Format-PortDuration ([TimeSpan]::FromMinutes(125)) | Should -Be '2 h 5 min'
        Format-PortDuration ([TimeSpan]::FromHours(76)) | Should -Be '3 d 4 h'
    }
}

Describe 'Look and remembered settings' {
    It 'every colour key the XAML uses exists in both the dark and light palettes' {
        $keys = @([regex]::Matches((Get-PortMonitorMainXaml) + (Get-PortTargetDialogXaml), 'DynamicResource (\w+)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $keys.Count | Should -BeGreaterThan 10
        foreach ($theme in 'Dark', 'Light') {
            $palette = Get-PortMonitorPalette -Theme $theme
            foreach ($k in $keys) { $palette.ContainsKey($k) | Should -BeTrue -Because "$theme palette needs '$k'" }
            foreach ($k in 'Badge', 'BadgeRunning') { $palette.ContainsKey($k) | Should -BeTrue }
        }
    }
    It 'the dark and light palettes have the same keys and valid colours' {
        $dark = Get-PortMonitorPalette -Theme Dark; $light = Get-PortMonitorPalette -Theme Light
        (@($dark.Keys | Sort-Object) -join ',') | Should -Be (@($light.Keys | Sort-Object) -join ',')
        foreach ($v in @($dark.Values) + @($light.Values)) { $v | Should -Match '^#[0-9A-F]{6}$' }
    }
    It 'saves and reads back theme, window placement and sort order; ignores unknown values' {
        $p = Join-Path $TestDrive 'look\settings.json'
        Save-PortMonitorSettings -Path $p -Settings @{ StartupOffered = $true; Theme = 'Light'; SortColumn = 'Status'; SortDirection = 'Descending'
            Window = @{ Left = 100; Top = 50; Width = 1200; Height = 700; Maximized = $true } }
        $s = Read-PortMonitorSettings -Path $p
        $s.StartupOffered | Should -BeTrue
        $s.Theme | Should -Be 'Light'
        $s.SortColumn | Should -Be 'Status'
        $s.SortDirection | Should -Be 'Descending'
        $s.Window.Width | Should -Be 1200
        $s.Window.Maximized | Should -BeTrue
        Set-Content -LiteralPath $p -Encoding ASCII -Value '{ "Theme": "Purple", "SortDirection": "Sideways" }'
        $s = Read-PortMonitorSettings -Path $p
        $s.Theme | Should -Be 'Dark'
        $s.SortDirection | Should -Be 'Ascending'
        $s.Window | Should -BeNullOrEmpty
    }
    It 'a settings file from version 1.0 (StartupOffered only) still loads' {
        $p = Join-Path $TestDrive 'v10-settings.json'
        Set-Content -LiteralPath $p -Encoding ASCII -Value '{ "StartupOffered": true }'
        $s = Read-PortMonitorSettings -Path $p
        $s.StartupOffered | Should -BeTrue
        $s.Theme | Should -Be 'Dark'
    }
    It 'window placement: <Case>' -TestCases @(
        @{ Case = 'on the main screen'; B = @{ Left = 100; Top = 100; Width = 1200; Height = 700 }; Ok = $true }
        @{ Case = 'on a second monitor to the right'; B = @{ Left = 2100; Top = 100; Width = 1200; Height = 700 }; Ok = $true }
        @{ Case = 'on a monitor that was unplugged'; B = @{ Left = 4200; Top = 100; Width = 1200; Height = 700 }; Ok = $false }
        @{ Case = 'title bar above the top of the screen'; B = @{ Left = 100; Top = -500; Width = 1200; Height = 700 }; Ok = $false }
        @{ Case = 'only a sliver left on screen'; B = @{ Left = 3780; Top = 100; Width = 1200; Height = 700 }; Ok = $false }
        @{ Case = 'nonsense size'; B = @{ Left = 100; Top = 100; Width = 10; Height = 10 }; Ok = $false }
    ) {
        param($Case, $B, $Ok)
        $screens = @([PSCustomObject]@{ Left = 0; Top = 0; Width = 1920; Height = 1040 }, [PSCustomObject]@{ Left = 1920; Top = 0; Width = 1920; Height = 1040 })
        Test-PortMonitorWindowBounds -Bounds ([PSCustomObject]$B) -Screens $screens | Should -Be $Ok
    }
    It 'regression: the Add dialog hands back its targets one by one, not wrapped in one array' {
        # A trailing ", @(...)" made a Domain controller preset (8 targets) arrive as ONE item,
        # which became a single row with port 0.
        $ast = (Get-Command Show-PortTargetDialog).ScriptBlock.Ast
        $last = $ast.Body.EndBlock.Statements[-1]
        $last.Extent.Text | Should -Not -Match '^\s*,'
        $last.Extent.Text | Should -Match 'foreach'
    }
    It 'the Add dialog XAML loads and has the role, port tick-list and blip fields (STA only; nothing is shown)' -Skip:([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
        $d = [System.Windows.Markup.XamlReader]::Parse((Get-PortTargetDialogXaml))
        foreach ($n in 'CmbRole', 'PortChecks', 'PortBox', 'TxtFailAfter', 'TxtRecoverAfter') { $d.FindName($n) | Should -Not -BeNullOrEmpty -Because $n }
        Set-PortMonitorTheme -Element $d -Palette (Get-PortMonitorPalette -Theme Light)
        $d.Resources['Text'].Color.ToString() | Should -Be '#FF1B1E22'
    }
}

Describe 'Tray mode pieces (no tray icon is shown, nothing outside $TestDrive is written)' {
    BeforeAll {
        function New-Change {
            param([string]$Label = 'DC01', [string]$Prev, [string]$New, $Latency = $null)
            [PSCustomObject]@{ Timestamp = (Get-Date '2026-11-16 14:35:00'); Label = $Label; Host = 'dc01'; Port = 389; PreviousStatus = $Prev; NewStatus = $New; LatencyMs = $Latency }
        }
    }

    It 'says nothing when a target is Open on its first check' {
        Get-PortChangeNotification -Changes @(New-Change -Prev 'Not checked' -New 'Open' -Latency 3) | Should -BeNullOrEmpty
        Get-PortChangeNotification -Changes @() | Should -BeNullOrEmpty
    }
    It 'reports a target that fails its first check' {
        $n = Get-PortChangeNotification -Changes @(New-Change -Prev 'Not checked' -New 'Timeout')
        $n.Kind | Should -Be 'Down'
        $n.Title | Should -Be 'DC01 is not answering'
        $n.Text | Should -Match 'Timeout on the first check at 14:35:00'
    }
    It 'reports going down and coming back' {
        $down = Get-PortChangeNotification -Changes @(New-Change -Prev 'Open' -New 'Refused')
        $down.Kind | Should -Be 'Down'
        $down.Text | Should -Be 'dc01:389: Open -> Refused at 14:35:00.'
        $up = Get-PortChangeNotification -Changes @(New-Change -Prev 'Timeout' -New 'Open' -Latency 12.5)
        $up.Kind | Should -Be 'Up'
        $up.Title | Should -Be 'DC01 is back up'
        $up.Text | Should -Match 'answered in 12.5 ms at 14:35:00 \(was Timeout\)'
    }
    It 'combines several changes in one tick into one notification, down first in the title' {
        $changes = @(1..6 | ForEach-Object { New-Change -Label "T$_" -Prev 'Open' -New 'Timeout' }) + @(New-Change -Label 'Up1' -Prev 'Refused' -New 'Open')
        $n = Get-PortChangeNotification -Changes $changes
        $n.Kind | Should -Be 'Down'
        $n.Title | Should -Be '7 targets changed (6 down)'
        @($n.Text -split "`n").Count | Should -Be 5
        $n.Text | Should -Match 'and 3 more$'
    }
    It 'keeps notification title within 63 and text within 255 characters (NOTIFYICONDATA)' {
        $long = 'L' * 300
        $n = Get-PortChangeNotification -Changes @(New-Change -Label $long -Prev 'Open' -New 'Timeout')
        $n.Title.Length | Should -BeLessOrEqual 63
        $n.Text.Length | Should -BeLessOrEqual 255
        $many = @(1..4 | ForEach-Object { New-Change -Label ('X' * 120) -Prev 'Open' -New 'Error' })
        (Get-PortChangeNotification -Changes $many).Text.Length | Should -BeLessOrEqual 255
    }

    It 'tray summary: <Case>' -TestCases @(
        @{ Case = 'stopped'; Running = $false; Statuses = @('Open'); State = 'Stopped'; Text = 'Port Monitor - stopped' }
        @{ Case = 'nothing enabled'; Running = $true; Statuses = @(); State = 'Stopped'; Text = 'Port Monitor - nothing to check' }
        @{ Case = 'all open'; Running = $true; Statuses = @('Open', 'Open'); State = 'Ok'; Text = 'Port Monitor - all 2 open' }
        @{ Case = 'still checking'; Running = $true; Statuses = @('Open', 'Not checked'); State = 'Checking'; Text = 'Port Monitor - checking 2 target(s)' }
        @{ Case = 'one down'; Running = $true; Statuses = @('Open', 'DNS Failure'); State = 'Problem'; Text = 'Port Monitor - T2 not answering' }
        @{ Case = 'two down'; Running = $true; Statuses = @('Error', 'Timeout', 'Open'); State = 'Problem'; Text = 'Port Monitor - 2 of 3 not answering' }
    ) {
        param($Case, $Running, $Statuses, $State, $Text)
        $i = 0
        $states = @(foreach ($st in $Statuses) { $i++; $s = New-PortTargetState @{ Label = "T$i"; Host = 'h'; Port = $i }; $s.Status = $st; $s })
        $summary = Get-PortMonitorTraySummary -States $states -Running $Running
        $summary.State | Should -Be $State
        $summary.Text | Should -Be $Text
    }
    It 'tray tooltip stays within 63 characters (NotifyIcon.Text limit on Windows PowerShell)' {
        $s = New-PortTargetState @{ Label = ('Very long label ' * 10); Host = 'h'; Port = 1 }; $s.Status = 'Timeout'
        (Get-PortMonitorTraySummary -States @($s) -Running $true).Text.Length | Should -BeLessOrEqual 63
    }
    It 'draws a 16x16 tray icon' {
        $icon = New-PortMonitorTrayIcon -Color '#3FB950'
        try { $icon.Width | Should -Be 16; $icon.Height | Should -Be 16 } finally { $icon.Dispose() }
    }

    It 'Startup command runs Windows PowerShell hidden with -Tray, and adds paths only when not default' {
        $cmd = Get-PortMonitorStartupCommand -ScriptPath 'C:\Tools\PortMonitor.ps1' -ConfigPath 'C:\a\targets.json' -LogPath 'C:\a\Logs' -DefaultConfigPath 'C:\a\targets.json' -DefaultLogPath 'C:\a\Logs'
        $cmd.TargetPath | Should -Match 'System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$'
        $cmd.Arguments | Should -Be '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "C:\Tools\PortMonitor.ps1" -Tray'
        $cmd.ScriptPath | Should -Be 'C:\Tools\PortMonitor.ps1'
        $custom = Get-PortMonitorStartupCommand -ScriptPath 'C:\Tools\PortMonitor.ps1' -ConfigPath '\\fs\it\client.json' -LogPath 'C:\a\Logs' -DefaultConfigPath 'C:\a\targets.json' -DefaultLogPath 'C:\a\Logs'
        $custom.Arguments | Should -Match ' -ConfigPath "\\\\fs\\it\\client\.json"$'
    }
    It 'Startup shortcut is named Port Monitor.lnk in the given (or the user''s) Startup folder' {
        Get-PortMonitorStartupShortcutPath -StartupFolder 'C:\X' | Should -Be 'C:\X\Port Monitor.lnk'
        Get-PortMonitorStartupShortcutPath | Should -Be (Join-Path ([Environment]::GetFolderPath('Startup')) 'Port Monitor.lnk')
    }
    It 'creates the Startup shortcut minimized with the command, and removes only that file' {
        $folder = Join-Path $TestDrive 'Startup'
        $lnk = Get-PortMonitorStartupShortcutPath -StartupFolder $folder
        $cmd = Get-PortMonitorStartupCommand -ScriptPath 'C:\Tools\PortMonitor.ps1' -ConfigPath 'a' -LogPath 'b' -DefaultConfigPath 'a' -DefaultLogPath 'b'
        Set-PortMonitorStartup -Enabled $true -ShortcutPath $lnk -Command $cmd
        Test-Path -LiteralPath $lnk | Should -BeTrue
        $shell = New-Object -ComObject WScript.Shell
        $read = $shell.CreateShortcut($lnk)
        $read.TargetPath | Should -Be $cmd.TargetPath
        $read.Arguments | Should -Be $cmd.Arguments
        $read.WindowStyle | Should -Be 7
        $other = Join-Path $folder 'Something else.lnk'
        Set-Content -LiteralPath $other -Value 'x'
        Set-PortMonitorStartup -Enabled $false -ShortcutPath $lnk
        Test-Path -LiteralPath $lnk | Should -BeFalse
        Test-Path -LiteralPath $other | Should -BeTrue
        { Set-PortMonitorStartup -Enabled $false -ShortcutPath $lnk } | Should -Not -Throw
    }
    It 'remembers that the Startup offer was shown, and reads a missing or broken file as not shown' {
        $p = Join-Path $TestDrive 'settings\settings.json'
        (Read-PortMonitorSettings -Path $p).StartupOffered | Should -BeFalse
        Save-PortMonitorSettings -Path $p -Settings @{ StartupOffered = $true }
        (Read-PortMonitorSettings -Path $p).StartupOffered | Should -BeTrue
        Set-Content -LiteralPath $p -Value '{ broken' -Encoding ASCII
        (Read-PortMonitorSettings -Path $p).StartupOffered | Should -BeFalse
    }
    It 'single instance: the first copy owns the lock, a second does not, and the lock frees on exit' {
        $name = 'PortMonitor.Test.' + [guid]::NewGuid().ToString('N')
        $first = Enter-PortMonitorInstance -Name $name
        try {
            $first.Owned | Should -BeTrue
            # A second copy runs in another process; a thread stands in for it (a mutex is
            # re-entrant on the same thread).
            $job = Start-ThreadJob -ScriptBlock {
                param($fn, $n)
                $m = New-Object System.Threading.Mutex -ArgumentList $false, "Local\$n"
                $got = $m.WaitOne(0); if ($got) { $m.ReleaseMutex() }; $m.Dispose(); $got
            } -ArgumentList 'x', $name
            Receive-Job -Job $job -Wait -AutoRemoveJob | Should -BeFalse
            # The second copy's "show yourself" signal reaches the first.
            $signal = New-Object System.Threading.EventWaitHandle -ArgumentList $false, ([System.Threading.EventResetMode]::AutoReset), "Local\$name.Show"
            [void]$signal.Set(); $signal.Dispose()
            $first.ShowEvent.WaitOne(0) | Should -BeTrue
        }
        finally { Exit-PortMonitorInstance -Instance $first }
        $again = Enter-PortMonitorInstance -Name $name
        try { $again.Owned | Should -BeTrue } finally { Exit-PortMonitorInstance -Instance $again }
    }
}

Describe 'Real checks and console mode' -Tag 'Integration' {
    BeforeAll {
        $script:Listener = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::Loopback), 0
        $script:Listener.Start()
        $script:OpenPort = $script:Listener.LocalEndpoint.Port
        $probe = New-Object System.Net.Sockets.TcpListener -ArgumentList ([System.Net.IPAddress]::Loopback), 0
        $probe.Start(); $script:ClosedPort = $probe.LocalEndpoint.Port; $probe.Stop()

        function Invoke-OnceChild {
            param([string]$Exe, [string]$Config, [string]$Logs)
            $out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.txt')
            $p = Start-Process -FilePath $Exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script:ScriptPath`"", '-Once',
                '-ConfigPath', "`"$Config`"", '-LogPath', "`"$Logs`"") -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out
            [PSCustomObject]@{ ExitCode = $p.ExitCode; Output = (Get-Content -LiteralPath $out -Raw) }
        }
        $script:Hosts = @(
            @{ Name = 'Windows PowerShell 5.1'; Exe = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') }
            @{ Name = 'PowerShell 7'; Exe = (Get-Process -Id $PID).Path }
        )
    }
    AfterAll { $script:Listener.Stop() }

    It 'Open on a listening loopback port, with latency' {
        $r = Test-TcpPort -HostName '127.0.0.1' -Port $script:OpenPort -TimeoutMs 3000
        $r.Status | Should -Be 'Open'
        $r.LatencyMs | Should -BeGreaterOrEqual 0
    }
    It 'Refused on a closed loopback port (Windows reports it after ~2.1 s)' {
        (Test-TcpPort -HostName '127.0.0.1' -Port $script:ClosedPort -TimeoutMs 5000).Status | Should -Be 'Refused'
    }
    It 'DNS Failure for a reserved .invalid name (RFC 6761)' {
        (Test-TcpPort -HostName 'portmonitor-test.invalid' -Port 80 -TimeoutMs 5000).Status | Should -Be 'DNS Failure'
    }
    It 'resolves localhost by name before connecting' {
        $r = Test-TcpPort -HostName 'localhost' -Port $script:OpenPort -TimeoutMs 3000
        $r.Status | Should -Be 'Open'
        $r.Address | Should -Be '127.0.0.1'
    }
    It '-Once under <Name>: exit 0 when all open, 1 when one is not, and changes logged' -TestCases @(
        @{ Name = 'Windows PowerShell 5.1' }, @{ Name = 'PowerShell 7' }
    ) {
        param($Name)
        $exe = ($script:Hosts | Where-Object { $_.Name -eq $Name }).Exe
        $dir = Join-Path $TestDrive ($Name -replace '\W', '')
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $good = Join-Path $dir 'good.json'
        Set-Content -LiteralPath $good -Encoding ASCII -Value "[ { `"Label`": `"open`", `"Host`": `"127.0.0.1`", `"Port`": $script:OpenPort } ]"
        $mixed = Join-Path $dir 'mixed.json'
        Set-Content -LiteralPath $mixed -Encoding ASCII -Value "[ { `"Label`": `"open`", `"Host`": `"127.0.0.1`", `"Port`": $script:OpenPort }, { `"Label`": `"closed`", `"Host`": `"127.0.0.1`", `"Port`": $script:ClosedPort } ]"
        $logs = Join-Path $dir 'Logs'

        $r1 = Invoke-OnceChild -Exe $exe -Config $good -Logs $logs
        $r1.ExitCode | Should -Be 0 -Because $r1.Output
        $r1.Output | Should -Match '\[PASS\]'

        $r2 = Invoke-OnceChild -Exe $exe -Config $mixed -Logs $logs
        $r2.ExitCode | Should -Be 1 -Because $r2.Output
        $r2.Output | Should -Match 'closed \(Refused\)'

        $csv = @(Get-ChildItem -LiteralPath $logs -Filter 'PortMonitor_*.csv')
        $csv.Count | Should -Be 1
        $rows = @(Import-Csv -LiteralPath $csv[0].FullName)
        @($rows | Where-Object { $_.NewStatus -eq 'Refused' -and $_.Label -eq 'closed' }).Count | Should -Be 1
    }
    It 'Measure-PingLoss: every ping to loopback is answered' {
        $r = Measure-PingLoss -Address '127.0.0.1' -Count 5 -TimeoutMs 1000 -GapMs 50
        $r.Error | Should -BeNullOrEmpty
        $r.Sent | Should -Be 5
        $r.Received | Should -Be 5
        $r.LossPercent | Should -Be 0
    }
    It 'Invoke-PortTargetCheck on loopback: port Open and loss measured' {
        $r = Invoke-PortTargetCheck -HostName 'localhost' -Port $script:OpenPort -MeasureLoss -LossPings 3
        $r.Status | Should -Be 'Open'
        $r.Loss.Received | Should -Be 3
    }
    It '-Once with packet loss measured under <Name>: exit 0, loss logged as OK in its own file' -TestCases @(
        @{ Name = 'Windows PowerShell 5.1' }, @{ Name = 'PowerShell 7' }
    ) {
        param($Name)
        $exe = ($script:Hosts | Where-Object { $_.Name -eq $Name }).Exe
        $dir = Join-Path $TestDrive ('loss-' + ($Name -replace '\W', ''))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $cfg = Join-Path $dir 'loss.json'
        Set-Content -LiteralPath $cfg -Encoding ASCII -Value "[ { `"Label`": `"open`", `"Host`": `"127.0.0.1`", `"Port`": $script:OpenPort, `"MeasureLoss`": true, `"LossPings`": 3 } ]"
        $logs = Join-Path $dir 'Logs'
        $r = Invoke-OnceChild -Exe $exe -Config $cfg -Logs $logs
        $r.ExitCode | Should -Be 0 -Because $r.Output
        $r.Output | Should -Match 'Loss %'
        $loss = @(Get-ChildItem -LiteralPath $logs -Filter 'PortMonitor_Loss_*.csv')
        $loss.Count | Should -Be 1
        (@(Import-Csv -LiteralPath $loss[0].FullName)[0]).NewStatus | Should -Be 'OK'
    }
    It '-Once exits 2 when there is nothing to check' {
        $cfg = Join-Path $TestDrive 'none.json'
        Set-Content -LiteralPath $cfg -Value '[]' -Encoding ASCII
        (Invoke-OnceChild -Exe (Get-Process -Id $PID).Path -Config $cfg -Logs (Join-Path $TestDrive 'nl')).ExitCode | Should -Be 2
    }
    It '-Report under <Name> writes the HTML report from the logs and says how many outages' -TestCases @(
        @{ Name = 'Windows PowerShell 5.1' }, @{ Name = 'PowerShell 7' }
    ) {
        param($Name)
        $exe = ($script:Hosts | Where-Object { $_.Name -eq $Name }).Exe
        $dir = Join-Path $TestDrive ('report-' + ($Name -replace '\W', ''))
        $logs = Join-Path $dir 'Logs'
        $now = Get-Date
        foreach ($c in @(
                [PSCustomObject]@{ Timestamp = $now.AddHours(-5); Label = 'DC01'; Host = 'dc01'; Port = 389; PreviousStatus = 'Not checked'; NewStatus = 'Open'; LatencyMs = 1 }
                [PSCustomObject]@{ Timestamp = $now.AddHours(-3); Label = 'DC01'; Host = 'dc01'; Port = 389; PreviousStatus = 'Open'; NewStatus = 'Timeout'; LatencyMs = $null }
                [PSCustomObject]@{ Timestamp = $now.AddHours(-2); Label = 'DC01'; Host = 'dc01'; Port = 389; PreviousStatus = 'Timeout'; NewStatus = 'Open'; LatencyMs = 2 })) {
            [void](Write-PortStateChangeLog -LogDirectory $logs -Change $c)
        }
        $out = Join-Path $dir 'out.txt'
        $p = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script:ScriptPath`"", '-Report', '-Days', '1',
            '-LogPath', "`"$logs`"", '-OutputPath', "`"$dir`"") -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out
        $text = Get-Content -LiteralPath $out -Raw
        $p.ExitCode | Should -Be 0 -Because $text
        $text | Should -Match '\[WARN\] 1 outage'
        $html = @(Get-ChildItem -LiteralPath $dir -Filter 'PortMonitor_Report_*.html')
        $html.Count | Should -Be 1
        Get-Content -LiteralPath $html[0].FullName -Raw | Should -Match '1 of 1 target\(s\) had outages'
    }
    It '-SmokeTest passes under <Name>' -TestCases @(
        @{ Name = 'Windows PowerShell 5.1' }, @{ Name = 'PowerShell 7' }
    ) {
        param($Name)
        $exe = ($script:Hosts | Where-Object { $_.Name -eq $Name }).Exe
        $out = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.txt')
        $p = Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', "`"$script:ScriptPath`"", '-SmokeTest') -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out
        $text = Get-Content -LiteralPath $out -Raw
        $p.ExitCode | Should -Be 0 -Because $text
        $text | Should -Match '\[PASS\] PortMonitor\.ps1'
    }
}
