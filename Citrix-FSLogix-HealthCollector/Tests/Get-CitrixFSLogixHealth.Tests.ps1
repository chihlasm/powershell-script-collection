BeforeAll {
    . "$PSScriptRoot/../Get-CitrixFSLogixHealth.ps1" -LoadFunctionsOnly
}

Describe 'Script loading' {
    It 'dot-sources with -LoadFunctionsOnly without attempting collection' {
        Get-Command Write-StatusLine -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-LevelName' {
    # The numbers are locale-independent; the display names are not. Filtering must always
    # be on the number, which is why this mapping is pinned by test.
    # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
    It 'maps <Number> to <Expected>' -ForEach @(
        @{ Number = 0; Expected = 'LogAlways'     }
        @{ Number = 1; Expected = 'Critical'      }
        @{ Number = 2; Expected = 'Error'         }
        @{ Number = 3; Expected = 'Warning'       }
        @{ Number = 4; Expected = 'Information'   }
        @{ Number = 5; Expected = 'Verbose'       }
    ) {
        Get-LevelName -Level $Number | Should -Be $Expected
    }

    It 'returns Unknown for an unmapped level rather than guessing' {
        Get-LevelName -Level 99 | Should -Be 'Unknown'
    }

    It 'returns Unknown for a null level' {
        Get-LevelName -Level $null | Should -Be 'Unknown'
    }
}

Describe 'Get-ResourceStatus' {
    It 'returns PASS below the warn threshold' {
        Get-ResourceStatus -Value 79.9 -WarnAt 80 -CriticalAt 90 | Should -Be 'PASS'
    }

    It 'treats thresholds as inclusive at warn' {
        Get-ResourceStatus -Value 80 -WarnAt 80 -CriticalAt 90 | Should -Be 'WARN'
    }

    It 'treats thresholds as inclusive at critical' {
        Get-ResourceStatus -Value 90 -WarnAt 80 -CriticalAt 90 | Should -Be 'FAIL'
    }

    It 'returns UNKNOWN for a null value instead of a misleading PASS' {
        Get-ResourceStatus -Value $null -WarnAt 80 -CriticalAt 90 | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-QueueStatus' {
    # Regression guard for the per-processor normalization. Microsoft's own pages disagree
    # on the raw threshold, and every one of them describes a single system-wide queue -
    # so an un-normalized comparison would flag healthy multi-vCPU hosts as congested.
    # https://learn.microsoft.com/en-us/previous-versions/aa394272(v=vs.85)
    It 'passes a queue of 8 on a 16 vCPU host (0.5 per processor)' {
        Get-QueueStatus -AverageQueue 8 -LogicalProcessors 16 -WarnAt 2 -CriticalAt 5 | Should -Be 'PASS'
    }

    It 'fails the same queue of 8 on a 1 vCPU host' {
        Get-QueueStatus -AverageQueue 8 -LogicalProcessors 1 -WarnAt 2 -CriticalAt 5 | Should -Be 'FAIL'
    }

    It 'warns exactly at the per-processor warn threshold' {
        Get-QueueStatus -AverageQueue 8 -LogicalProcessors 4 -WarnAt 2 -CriticalAt 5 | Should -Be 'WARN'
    }

    It 'fails exactly at the per-processor critical threshold' {
        Get-QueueStatus -AverageQueue 20 -LogicalProcessors 4 -WarnAt 2 -CriticalAt 5 | Should -Be 'FAIL'
    }

    It 'returns UNKNOWN when the processor count is missing rather than assuming one CPU' {
        Get-QueueStatus -AverageQueue 8 -LogicalProcessors $null -WarnAt 2 -CriticalAt 5 | Should -Be 'UNKNOWN'
    }

    It 'returns UNKNOWN when the processor count is zero rather than dividing by zero' {
        Get-QueueStatus -AverageQueue 8 -LogicalProcessors 0 -WarnAt 2 -CriticalAt 5 | Should -Be 'UNKNOWN'
    }

    It 'returns UNKNOWN when the queue was not collected' {
        Get-QueueStatus -AverageQueue $null -LogicalProcessors 8 -WarnAt 2 -CriticalAt 5 | Should -Be 'UNKNOWN'
    }
}

Describe 'Get-WorstStatus' {
    It 'lets FAIL win over everything' {
        Get-WorstStatus -Statuses @('PASS', 'WARN', 'FAIL', 'UNKNOWN') | Should -Be 'FAIL'
    }

    It 'lets WARN win over PASS' {
        Get-WorstStatus -Statuses @('PASS', 'WARN') | Should -Be 'WARN'
    }

    It 'returns UNKNOWN for an empty set' {
        Get-WorstStatus -Statuses @() | Should -Be 'UNKNOWN'
    }

    It 'returns UNKNOWN when nothing was collected' {
        Get-WorstStatus -Statuses @('UNKNOWN', 'UNKNOWN') | Should -Be 'UNKNOWN'
    }
}

Describe 'Measure-SampleSet' {
    It 'averages and peaks a clean set' {
        $r = Measure-SampleSet -Value @(10, 20, 90)
        $r.Average | Should -Be 40
        $r.Peak    | Should -Be 90
        $r.Low     | Should -Be 10
        $r.Count   | Should -Be 3
    }

    It 'drops failed reads instead of counting them as zero' {
        # If nulls became zeros, the average here would be 30 and a busy host would read idle.
        $r = Measure-SampleSet -Value @(60, $null, 60, $null)
        $r.Average | Should -Be 60
        $r.Count   | Should -Be 2
    }

    It 'returns nulls when every reading failed' {
        $r = Measure-SampleSet -Value @($null, $null)
        $r.Average | Should -BeNullOrEmpty
        $r.Peak    | Should -BeNullOrEmpty
        $r.Count   | Should -Be 0
    }

    It 'handles an empty set' {
        $r = Measure-SampleSet -Value @()
        $r.Count | Should -Be 0
    }
}

Describe 'Get-SampleCount' {
    It 'returns a single reading when sampling is disabled' {
        Get-SampleCount -SampleSeconds 0 -IntervalSeconds 5 | Should -Be 1
    }

    It 'divides the window by the interval' {
        Get-SampleCount -SampleSeconds 30 -IntervalSeconds 5 | Should -Be 6
    }

    It 'never returns a single reading for a sampled run' {
        # A "sampled" run of one reading would make the peak column a lie.
        Get-SampleCount -SampleSeconds 3 -IntervalSeconds 5 | Should -Be 2
    }

    It 'handles a window that exactly matches one interval' {
        Get-SampleCount -SampleSeconds 5 -IntervalSeconds 5 | Should -Be 2
    }
}

Describe 'ConvertTo-MemoryMetrics' {
    # TotalVisibleMemorySize / FreePhysicalMemory are in KILOBYTES, not bytes.
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
    It 'treats the OS memory values as kilobytes' {
        $r = ConvertTo-MemoryMetrics -TotalKb 16777216 -FreeKb 8388608
        $r.TotalGB | Should -Be 16
        $r.FreeGB  | Should -Be 8
        $r.UsedGB  | Should -Be 8
    }

    It 'computes the used percentage' {
        $r = ConvertTo-MemoryMetrics -TotalKb 1000 -FreeKb 250
        $r.UsedPercent | Should -Be 75
    }

    It 'returns a null percentage rather than dividing by zero' {
        $r = ConvertTo-MemoryMetrics -TotalKb 0 -FreeKb 0
        $r.UsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'ConvertTo-DiskMetrics' {
    # Win32_LogicalDisk Size / FreeSpace are in BYTES - a different unit from the OS class.
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk
    It 'reports the worst used percentage across several disks' {
        $disks = @(
            [PSCustomObject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 50GB }
            [PSCustomObject]@{ DeviceID = 'D:'; Size = 100GB; FreeSpace = 5GB  }
        )
        $r = ConvertTo-DiskMetrics -Disks $disks
        $r.MaxUsedPercent | Should -Be 95
        $r.Summary        | Should -Match 'C:'
        $r.Summary        | Should -Match 'D:'
    }

    It 'skips zero-sized disks rather than dividing by zero' {
        $disks = @([PSCustomObject]@{ DeviceID = 'A:'; Size = 0; FreeSpace = 0 })
        $r = ConvertTo-DiskMetrics -Disks $disks
        $r.MaxUsedPercent | Should -BeNullOrEmpty
    }

    It 'returns null for an empty disk set' {
        $r = ConvertTo-DiskMetrics -Disks @()
        $r.MaxUsedPercent | Should -BeNullOrEmpty
    }
}

Describe 'Get-UptimeDays' {
    It 'computes whole days since boot' {
        $now = Get-Date '2026-09-18 12:00:00'
        Get-UptimeDays -LastBootUpTime $now.AddDays(-10) -Now $now | Should -Be 10
    }

    It 'floors at zero so clock skew never yields a negative uptime' {
        $now = Get-Date '2026-09-18 12:00:00'
        Get-UptimeDays -LastBootUpTime $now.AddDays(5) -Now $now | Should -Be 0
    }
}

Describe 'Resolve-TimeWindow' {
    It 'defaults to the last 24 hours' {
        $w = Resolve-TimeWindow
        [math]::Round(($w.End - $w.Start).TotalHours) | Should -Be 24
    }

    It 'honours -LastHours' {
        $w = Resolve-TimeWindow -LastHours 6
        [math]::Round(($w.End - $w.Start).TotalHours) | Should -Be 6
    }

    It 'honours -LastDays' {
        $w = Resolve-TimeWindow -LastDays 3
        [math]::Round(($w.End - $w.Start).TotalDays) | Should -Be 3
    }

    It 'honours an explicit window' {
        $w = Resolve-TimeWindow -StartTime (Get-Date '2026-09-01 08:00') -EndTime (Get-Date '2026-09-01 17:00')
        ($w.End - $w.Start).TotalHours | Should -Be 9
    }

    It 'rejects -LastHours combined with -LastDays' {
        { Resolve-TimeWindow -LastHours 4 -LastDays 2 } | Should -Throw '*mutually exclusive*'
    }

    It 'rejects -StartTime combined with -LastHours' {
        { Resolve-TimeWindow -StartTime (Get-Date) -LastHours 4 } | Should -Throw '*cannot be combined*'
    }

    It 'rejects a window that ends before it starts' {
        { Resolve-TimeWindow -StartTime (Get-Date '2026-09-02') -EndTime (Get-Date '2026-09-01') } |
            Should -Throw '*must be after*'
    }
}

Describe 'Test-IsLocalComputer' {
    # Get-WinEvent rejects a credential on a local connection, so this gate decides whether
    # -Credential is passed at all. Getting it wrong breaks the most common usage: running
    # the script on one of the hosts it reports on.
    # -LocalName is injected rather than read from the environment so these assertions mean
    # the same thing on any machine the suite happens to run on.
    It 'recognises the machine name' {
        Test-IsLocalComputer -ComputerName 'CTXVDA01' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'matches the machine name case-insensitively' {
        Test-IsLocalComputer -ComputerName 'ctxvda01' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'recognises localhost' {
        Test-IsLocalComputer -ComputerName 'localhost' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'recognises a dot' {
        Test-IsLocalComputer -ComputerName '.' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'recognises the loopback addresses' {
        Test-IsLocalComputer -ComputerName '127.0.0.1' -LocalName 'CTXVDA01' | Should -BeTrue
        Test-IsLocalComputer -ComputerName '::1'       -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'recognises the fully qualified form of the local machine' {
        Test-IsLocalComputer -ComputerName 'CTXVDA01.contoso.local' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'treats a genuinely remote name as remote' {
        Test-IsLocalComputer -ComputerName 'SOME-OTHER-VDA' -LocalName 'CTXVDA01' | Should -BeFalse
    }

    It 'treats a remote FQDN as remote' {
        Test-IsLocalComputer -ComputerName 'CTXVDA02.contoso.local' -LocalName 'CTXVDA01' | Should -BeFalse
    }

    It 'treats an omitted target as local' {
        Test-IsLocalComputer -ComputerName '' -LocalName 'CTXVDA01' | Should -BeTrue
    }

    It 'does NOT call every host local when COMPUTERNAME is unset' {
        # Comparing against an empty local name would make every short-named host look
        # local, which would silently strip -Credential from every remote query.
        Test-IsLocalComputer -ComputerName 'CTXVDA02' -LocalName '' | Should -BeFalse
    }

    It 'still recognises loopback names when COMPUTERNAME is unset' {
        Test-IsLocalComputer -ComputerName 'localhost' -LocalName '' | Should -BeTrue
    }
}

Describe 'Select-CollectionTarget' {
    It 'de-duplicates case-insensitively and keeps the broker entry first' {
        $targets = @(
            [PSCustomObject]@{ ComputerName = 'VDA01'; Source = 'Broker';     RegistrationState = 'Registered'; DeliveryGroup = 'Finance' }
            [PSCustomObject]@{ ComputerName = 'vda01'; Source = 'Additional'; RegistrationState = $null;        DeliveryGroup = $null }
        )
        $r = @(Select-CollectionTarget -Target $targets)
        $r.Count              | Should -Be 1
        $r[0].DeliveryGroup   | Should -Be 'Finance'
    }

    It 'skips unregistered VDAs by default' {
        $targets = @(
            [PSCustomObject]@{ ComputerName = 'VDA01'; Source = 'Broker'; RegistrationState = 'Registered'   }
            [PSCustomObject]@{ ComputerName = 'VDA02'; Source = 'Broker'; RegistrationState = 'Unregistered' }
        )
        $r = @(Select-CollectionTarget -Target $targets)
        $r.Count           | Should -Be 1
        $r[0].ComputerName | Should -Be 'VDA01'
    }

    It 'includes unregistered VDAs when asked' {
        $targets = @(
            [PSCustomObject]@{ ComputerName = 'VDA01'; Source = 'Broker'; RegistrationState = 'Registered'   }
            [PSCustomObject]@{ ComputerName = 'VDA02'; Source = 'Broker'; RegistrationState = 'Unregistered' }
        )
        @(Select-CollectionTarget -Target $targets -IncludeUnregistered).Count | Should -Be 2
    }

    It 'never filters an explicitly named server on registration state' {
        # The operator named it. A file server has no registration state and must not vanish.
        $targets = @([PSCustomObject]@{ ComputerName = 'FS01'; Source = 'Explicit'; RegistrationState = $null })
        @(Select-CollectionTarget -Target $targets).Count | Should -Be 1
    }

    It 'drops blank names' {
        $targets = @(
            [PSCustomObject]@{ ComputerName = '';    Source = 'Explicit'; RegistrationState = $null }
            [PSCustomObject]@{ ComputerName = '   '; Source = 'Explicit'; RegistrationState = $null }
            [PSCustomObject]@{ ComputerName = 'OK';  Source = 'Explicit'; RegistrationState = $null }
        )
        @(Select-CollectionTarget -Target $targets).Count | Should -Be 1
    }
}

Describe 'Get-HostVerdict' {
    BeforeAll {
        function New-CleanMetric {
            @{
                CpuStatus = 'PASS'; CpuAverage = 10; CpuPeak = 15
                MemoryStatus = 'PASS'; MemoryAverage = 30; MemoryPeak = 35
                DiskStatus = 'PASS'; DiskSummary = 'C: 20/100GB (20%)'
                QueueStatus = 'PASS'; QueueAverage = 1; QueuePerCpu = 0.25; LogicalProcessors = 4
            }
        }
        function New-CleanCount { @{ Critical = 0; Error = 0; Warning = 0; Total = 0 } }
    }

    It 'calls a clean host Healthy' {
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Healthy'
    }

    It 'calls a host Unreachable only when BOTH collections failed' {
        $v = Get-HostVerdict -Status @{ Performance = 'Unreachable'; Events = 'Unreachable' } `
            -Metric (New-CleanMetric) -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Unreachable'
    }

    It 'does NOT call a host Unreachable when only WinRM failed' {
        # Events arrive over RPC, not WinRM. A WinRM-blocked host still has a usable event
        # history and must not disappear from the report.
        $v = Get-HostVerdict -Status @{ Performance = 'Unreachable'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Not -Be 'Unreachable'
        ($v.Reasons -join ' ') | Should -Match 'Event data below is still valid'
    }

    It 'escalates to Critical on any critical-level event' {
        $counts = New-CleanCount; $counts.Critical = 1
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount $counts `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Critical'
    }

    It 'escalates to Degraded at the degraded error threshold' {
        $counts = New-CleanCount; $counts.Error = 5
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount $counts `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Degraded'
    }

    It 'escalates to Critical at the critical error threshold' {
        $counts = New-CleanCount; $counts.Error = 25
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount $counts `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Critical'
    }

    It 'stays Healthy on a handful of errors below the threshold' {
        $counts = New-CleanCount; $counts.Error = 2
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount $counts `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Healthy'
    }

    It 'escalates to Critical on a failing performance metric' {
        $metric = New-CleanMetric; $metric.CpuStatus = 'FAIL'; $metric.CpuAverage = 97; $metric.CpuPeak = 100
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric $metric -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Critical'
        ($v.Reasons -join ' ') | Should -Match 'Processor is overloaded'
    }

    It 'explains a healthy host rather than leaving the reason blank' {
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric (New-CleanMetric) -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Reasons.Count | Should -BeGreaterThan 0
    }

    It 'does not let an UNKNOWN metric escalate the verdict' {
        # An uncollected metric must not masquerade as a problem, nor as health.
        $metric = New-CleanMetric; $metric.CpuStatus = 'UNKNOWN'; $metric.CpuAverage = $null
        $v = Get-HostVerdict -Status @{ Performance = 'Success'; Events = 'Success' } `
            -Metric $metric -EventCount (New-CleanCount) `
            -DegradedErrorCount 5 -CriticalErrorCount 25
        $v.Verdict | Should -Be 'Healthy'
    }
}

Describe 'ConvertTo-HtmlSafe' {
    It 'escapes angle brackets so event text cannot inject markup' {
        ConvertTo-HtmlSafe -Text '<script>alert(1)</script>' | Should -Not -Match '<script>'
    }

    It 'escapes the ampersand first so entities are not double-escaped' {
        ConvertTo-HtmlSafe -Text '&' | Should -Be '&amp;'
    }

    It 'escapes quotes used in attributes' {
        ConvertTo-HtmlSafe -Text '"x"' | Should -Be '&quot;x&quot;'
    }

    It 'returns empty for null' {
        ConvertTo-HtmlSafe -Text $null | Should -Be ''
    }
}

Describe 'Format-MetricCell' {
    It 'renders a dash for an uncollected metric, never an empty bar' {
        # An empty bar reads as "zero percent" - the most dangerous misreading in the report.
        $html = Format-MetricCell -Percent $null -Status 'UNKNOWN' -Peak $null
        $html | Should -Match '--'
        $html | Should -Not -Match 'width:0%'
    }

    It 'clamps a percentage above 100 so the bar cannot overflow its track' {
        $html = Format-MetricCell -Percent 150 -Status 'FAIL' -Peak $null
        $html | Should -Match 'width:100%'
    }

    It 'shows a peak marker when the peak exceeds the average' {
        $html = Format-MetricCell -Percent 40 -Status 'PASS' -Peak 95
        $html | Should -Match 'peak'
        $html | Should -Match 'pk 95'
    }

    It 'omits the peak marker when peak equals average' {
        $html = Format-MetricCell -Percent 40 -Status 'PASS' -Peak 40
        $html | Should -Not -Match 'pk 40'
    }
}

Describe 'New-HealthHtmlReport' {
    BeforeAll {
        $script:ctx = @{
            Start = (Get-Date).AddHours(-24); End = (Get-Date)
            SampleSeconds = 30; SampleCount = 6
            ScopeText = '2 VDA(s) from DDC01'; OutputPath = 'C:\Reports'
        }
        $script:row = [PSCustomObject]@{
            ComputerName = 'VDA01'; Verdict = 'Critical'; Reasons = 'Processor is overloaded.'
            Source = 'Broker'; DeliveryGroup = 'Finance'; CatalogName = 'Win2022'
            RegistrationState = 'Registered'; InMaintenanceMode = $false; SessionCount = 12
            LoadIndex = 9000; OperatingSystem = 'Windows Server 2022'; LogicalProcessors = 8
            CpuAveragePercent = 95; CpuPeakPercent = 100; CpuStatus = 'FAIL'
            MemoryAveragePercent = 50; MemoryPeakPercent = 60; MemoryTotalGB = 32
            MemoryUsedGB = 16; MemoryStatus = 'PASS'
            DiskSummary = 'C: 50/100GB (50%)'; MaxDiskUsedPercent = 50; DiskStatus = 'PASS'
            QueueAverage = 2; QueuePeak = 4; QueuePerCpu = 0.25; QueueStatus = 'PASS'
            UptimeDays = 14; CriticalEvents = 1; ErrorEvents = 30; WarningEvents = 5
            TotalEvents = 36; TopIssue = 'Microsoft-FSLogix-Apps (ID 26) x14'
            SampleCount = 6; Protocol = 'WSMan'; PerformanceStatus = 'Success'
            EventStatus = 'Success'; ErrorMessage = $null
        }
        $script:evt = [PSCustomObject]@{
            ComputerName = 'VDA01'; TimeCreated = (Get-Date); Category = 'FSLogix'
            LogName = 'Microsoft-FSLogix-Apps/Operational'; ProviderName = 'Microsoft-FSLogix-Apps'
            Id = 26; Level = 2; LevelName = 'Error'; Message = 'Failed to attach VHD'
        }
    }

    It 'produces a self-contained document with no external references' {
        $html = New-HealthHtmlReport -Result @($script:row) -Event @($script:evt) -RunContext $script:ctx
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Not -Match '<link[^>]*href'
        $html | Should -Not -Match '<script[^>]*src'
    }

    It 'always shows where you are - the scope and window are in the header' {
        $html = New-HealthHtmlReport -Result @($script:row) -Event @($script:evt) -RunContext $script:ctx
        $html | Should -Match 'DDC01'
        $html | Should -Match 'VDA01'
    }

    It 'renders without throwing when there is nothing to report' {
        { New-HealthHtmlReport -Result @() -Event @() -RunContext $script:ctx } | Should -Not -Throw
    }

    It 'says so plainly when no machines were collected' {
        $html = New-HealthHtmlReport -Result @() -Event @() -RunContext $script:ctx
        $html | Should -Match 'No machines were collected'
    }

    It 'says so plainly when the fleet logged no errors' {
        $html = New-HealthHtmlReport -Result @($script:row) -Event @() -RunContext $script:ctx
        $html | Should -Match 'No critical or error events'
    }

    It 'escapes hostile event text rather than emitting it into the DOM' {
        $nasty = $script:evt.PSObject.Copy()
        $nasty.Message = '<img src=x onerror=alert(1)>'
        $html = New-HealthHtmlReport -Result @($script:row) -Event @($nasty) -RunContext $script:ctx
        $html | Should -Not -Match '<img src=x'
    }

    It 'reports a single instantaneous reading honestly when sampling is off' {
        $ctx = $script:ctx.Clone(); $ctx.SampleSeconds = 0; $ctx.SampleCount = 1
        $html = New-HealthHtmlReport -Result @($script:row) -Event @() -RunContext $ctx
        $html | Should -Match 'single instantaneous reading'
    }
}

Describe 'Event channel and provider patterns' {
    It 'anchors the documented FSLogix channels' {
        # https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics
        (Get-EventChannelPattern).Pattern | Should -Contain 'Microsoft-FSLogix-*'
    }

    It 'discovers Citrix channels by pattern rather than hardcoding a guessed name' {
        # Citrix does not publish literal channel names, and a wrong guess returns zero rows
        # while looking successful.
        $citrix = (Get-EventChannelPattern) | Where-Object Category -eq 'Citrix'
        $citrix.Pattern | Should -Match '\*'
    }

    It 'covers SMB client and server, so file servers are not left out' {
        $patterns = (Get-EventChannelPattern).Pattern
        $patterns | Should -Contain 'Microsoft-Windows-SMBClient/*'
        $patterns | Should -Contain 'Microsoft-Windows-SMBServer/*'
    }

    It 'narrows the noisy classic logs to System and Application only' {
        (Get-ClassicLogProviderPattern).LogName | Sort-Object -Unique | Should -Be @('Application', 'System')
    }

    It 'assigns every channel pattern a category' {
        (Get-EventChannelPattern) | ForEach-Object { $_.Category | Should -Not -BeNullOrEmpty }
    }
}
