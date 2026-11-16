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
    It 'keeps the saved field order Label, Host, Port, IntervalSec, TimeoutMs, Enabled' {
        $names = @((ConvertTo-PortTarget @{ Host = 'a'; Port = 1 }).PSObject.Properties | ForEach-Object Name)
        $names -join ',' | Should -Be 'Label,Host,Port,IntervalSec,TimeoutMs,Enabled'
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
    It 'writes only the six saved fields, not live monitoring state' {
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
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
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
        $s = New-PortTargetState @{ Host = 'h'; Port = 1 }
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
        $w.FindName('Grid').Columns.Count | Should -Be 11
        $d = [System.Windows.Markup.XamlReader]::Parse((Get-PortTargetDialogXaml))
        $d.FindName('BtnSave') | Should -Not -BeNullOrEmpty
    }
    It 'the sample targets.example.json loads with 3 valid targets' {
        $r = Read-PortMonitorConfig -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'targets.example.json')
        @($r.Warnings).Count | Should -Be 0
        @($r.Targets).Count | Should -Be 3
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
    It '-Once exits 2 when there is nothing to check' {
        $cfg = Join-Path $TestDrive 'none.json'
        Set-Content -LiteralPath $cfg -Value '[]' -Encoding ASCII
        (Invoke-OnceChild -Exe (Get-Process -Id $PID).Path -Config $cfg -Logs (Join-Path $TestDrive 'nl')).ExitCode | Should -Be 2
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
