BeforeAll {
    . "$PSScriptRoot\..\Get-SourceMachineActivity.ps1" -LoadFunctionsOnly

    function New-Act {
        param([string]$Kind, [string]$Time)
        [PSCustomObject]@{ Time = [datetime]$Time; Kind = $Kind; Label = $Kind; EventId = 0; Detail = '' }
    }
}

Describe 'ConvertFrom-ActivityEvent (event mapping verified against Microsoft Learn)' {
    It 'classifies startup, shutdown, sleep and wake from the System log' {
        # https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
        # https://learn.microsoft.com/defender-endpoint/troubleshoot-mdav-scan-issues
        $t = [datetime]'2026-10-14T08:00:00'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 12  -Time $t).Kind | Should -Be 'Startup'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-General' -EventId 13  -Time $t).Kind | Should -Be 'Shutdown'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-Power'   -EventId 42  -Time $t).Kind | Should -Be 'Sleep'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-Power'   -EventId 107 -Time $t).Kind | Should -Be 'Wake'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-Power'   -EventId 506 -Time $t).Kind | Should -Be 'StandbyEnter'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'Microsoft-Windows-Kernel-Power'   -EventId 41  -Time $t).Kind | Should -Be 'UnexpectedRestart'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'EventLog'                         -EventId 6008 -Time $t).Kind | Should -Be 'UnexpectedRestart'
        (ConvertFrom-ActivityEvent -LogName System -ProviderName 'User32'                           -EventId 1074 -Time $t).Kind | Should -Be 'ShutdownRequest'
    }

    It 'classifies lock and unlock from the Security log' {
        # https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4800
        $t = [datetime]'2026-10-14T08:00:00'
        (ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4800 -Time $t).Kind | Should -Be 'Lock'
        (ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4801 -Time $t).Kind | Should -Be 'Unlock'
    }

    It 'ignores the same event ID from a different provider' {
        # System event 12 is not always Kernel-General; matching on ID alone would mark
        # unrelated events as a startup.
        ConvertFrom-ActivityEvent -LogName System -ProviderName 'Some-Other-Provider' -EventId 12 -Time ([datetime]'2026-10-14') | Should -BeNullOrEmpty
    }

    It 'keeps the first line of the message and the user as detail' {
        $r = ConvertFrom-ActivityEvent -LogName Security -ProviderName 'Microsoft-Windows-Security-Auditing' -EventId 4801 `
                 -Time ([datetime]'2026-10-14') -Message "The workstation was unlocked.`r`n`r`nSubject: ..." -UserName 'CONTOSO\mjohnson'
        $r.Detail | Should -Be 'CONTOSO\mjohnson - The workstation was unlocked.'
    }
}

Describe 'Get-ActivityInterval' {
    It 'builds off, asleep and locked periods, and records the resume points' {
        $ev = @(
            (New-Act Shutdown '2026-10-13T18:00'); (New-Act Startup '2026-10-14T08:00')
            (New-Act Sleep    '2026-10-14T12:00'); (New-Act Wake    '2026-10-14T13:00')
            (New-Act Lock     '2026-10-14T15:00'); (New-Act Unlock  '2026-10-14T15:30')
        )
        $p = Get-ActivityInterval -Events $ev
        @($p.Intervals | Where-Object Kind -eq 'Off').Count    | Should -Be 1
        @($p.Intervals | Where-Object Kind -eq 'Asleep').Count | Should -Be 1
        @($p.Intervals | Where-Object Kind -eq 'Locked').Count | Should -Be 1
        @($p.ResumePoints).Kind | Should -Be @('Startup', 'Wake', 'Unlock')
    }

    It 'closes a sleep with a boot, because hibernate resumes by booting' {
        $p = Get-ActivityInterval -Events @((New-Act Sleep '2026-10-14T12:00'), (New-Act Startup '2026-10-14T14:00'))
        @($p.Intervals | Where-Object Kind -eq 'Asleep').Count | Should -Be 1
    }

    It 'does not invent a period that never closed' {
        $p = Get-ActivityInterval -Events @((New-Act Sleep '2026-10-14T12:00'))
        @($p.Intervals).Count | Should -Be 0
    }
}

Describe 'Repair-ResumeTime (wake logged with the stopped clock)' {
    BeforeAll {
        # Real sequence from a Windows 11 laptop: hibernate at 07:29:35, "resumed from sleep"
        # (107) stamped four seconds later with the stopped clock, then two weeks later the
        # clock reset and the resume record at the real wake time.
        $script:LongSleep = @(
            (New-Act Sleep '2026-09-28T07:29:35'); (New-Act Wake '2026-09-28T07:29:39')
            ([PSCustomObject]@{ Time = [datetime]'2026-10-12T02:14:12'; Kind = 'ClockChange'; Label = 'System clock changed'; EventId = 1; Detail = ''
                                ClockFrom = [datetime]'2026-09-28T07:29:39'; ClockTo = [datetime]'2026-10-12T02:14:12'; ResumeType = ''; WakeSource = '' })
            ([PSCustomObject]@{ Time = [datetime]'2026-10-12T02:14:15'; Kind = 'ResumeRecord'; Label = 'Resume record'; EventId = 1; Detail = ''
                                ClockFrom = [datetime]'2026-09-28T07:28:54'; ClockTo = [datetime]'2026-10-12T02:14:12'; ResumeType = 'Hibernate'; WakeSource = '' })
        )
    }

    It 'moves the wake to the real time' {
        $out = @(Repair-ResumeTime -Events $script:LongSleep)
        $w = @($out | Where-Object { $_.Kind -eq 'Wake' })
        $w.Count | Should -Be 1
        $w[0].Time | Should -Be ([datetime]'2026-10-12T02:14:12')
        @($out | Where-Object { $_.Kind -in 'ClockChange', 'ResumeRecord' }).Count | Should -Be 0
    }

    It 'classes a failure in the middle of the sleep as while asleep, not after resuming' {
        # Regression: with the stale 107 taken at face value the sleep "ended" four seconds
        # after it began, so this failure was counted as the machine being on.
        $before = Measure-FailureState -FailureTimes @([datetime]'2026-10-05T10:00') -Events $script:LongSleep
        $after  = Measure-FailureState -FailureTimes @([datetime]'2026-10-05T10:00') -Events (Repair-ResumeTime -Events $script:LongSleep)
        $before.WhileAsleep | Should -Be 0
        $after.WhileAsleep | Should -Be 1
    }

    It 'keeps the last power event before the window so the window opens asleep' {
        $win = @(Select-ActivityWindow -Events (Repair-ResumeTime -Events $script:LongSleep) -StartTime '2026-10-01')
        $win[0].Kind | Should -Be 'Sleep'
        $c = Measure-FailureState -FailureTimes @([datetime]'2026-10-05T10:00') -Events $win
        $c.WhileAsleep | Should -Be 1
    }
}

Describe 'Get-ActivityVerdict' {
    BeforeAll {
        $script:Ev = @(
            (New-Act Shutdown '2026-10-13T18:00'); (New-Act Startup '2026-10-14T08:00')
            (New-Act Sleep    '2026-10-14T12:00'); (New-Act Wake    '2026-10-14T13:00')
            (New-Act StandbyEnter '2026-10-14T16:00'); (New-Act StandbyExit '2026-10-14T17:00')
        )
    }

    It 'names a replay on resume when failures follow wake and startup' {
        $f = @('2026-10-14T08:01', '2026-10-14T08:02', '2026-10-14T13:01', '2026-10-14T13:03') | ForEach-Object { [datetime]$_ }
        $c = Measure-FailureState -FailureTimes $f -Events $script:Ev -WindowMinutes 5
        $c.AfterResume | Should -Be 4
        $v = Get-ActivityVerdict -Computer 'CON-LT-0142' -Counts $c -HasFailureData $true
        $v.Key  | Should -Be 'AfterResume'
        $v.Line | Should -Match 'waking from sleep \(2\)'
        $v.Line | Should -Match 'starting up \(2\)'
        $v.Next | Should -Match 'net use'
    }

    It 'credits the wake, not the unlock seconds later, when both are in the window' {
        $ev = @((New-Act Sleep '2026-10-14T12:00'); (New-Act Wake '2026-10-14T13:00'); (New-Act Unlock '2026-10-14T13:00:25'))
        $f = @('2026-10-14T13:01', '2026-10-14T13:02') | ForEach-Object { [datetime]$_ }
        $c = Measure-FailureState -FailureTimes $f -Events $ev
        $c.ResumeKinds['Wake']   | Should -Be 2
        $c.ResumeKinds['Unlock'] | Should -BeNullOrEmpty
    }

    It 'says the machine is probably NOT the source when it failed while shut down' {
        $f = @('2026-10-13T20:00', '2026-10-13T22:00', '2026-10-14T02:00', '2026-10-14T12:30') | ForEach-Object { [datetime]$_ }
        $c = Measure-FailureState -FailureTimes $f -Events $script:Ev
        ([int]$c.WhileOff + [int]$c.WhileAsleep) | Should -Be 4
        $v = Get-ActivityVerdict -Computer 'CON-LT-0142' -Counts $c -HasFailureData $true
        $v.Key  | Should -Be 'WhileOff'
        $v.Next | Should -Match 'probably NOT the source'
    }

    It 'never treats Modern Standby as off - the network can stay connected' {
        # https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby
        $f = @('2026-10-14T16:20', '2026-10-14T16:30', '2026-10-14T16:40') | ForEach-Object { [datetime]$_ }
        $c = Measure-FailureState -FailureTimes $f -Events $script:Ev
        $c.InStandby | Should -Be 3
        $v = Get-ActivityVerdict -Computer 'X' -Counts $c -HasFailureData $true
        $v.Key  | Should -Not -Be 'WhileOff'
        $v.Next | Should -Match 'Modern Standby'
    }

    It 'flags failures while locked as a background process' {
        $ev = @((New-Act Startup '2026-10-14T08:00'); (New-Act Lock '2026-10-14T09:00'); (New-Act Unlock '2026-10-14T11:00'))
        $f = @('2026-10-14T09:30', '2026-10-14T10:00', '2026-10-14T10:30') | ForEach-Object { [datetime]$_ }
        $v = Get-ActivityVerdict -Computer 'X' -Counts (Measure-FailureState -FailureTimes $f -Events $ev) -HasFailureData $true
        $v.Key | Should -Be 'WhileLocked'
    }

    It 'does not judge failures that fall before the machine''s log begins' {
        $f = @('2026-10-01T09:00', '2026-10-01T09:05') | ForEach-Object { [datetime]$_ }
        $c = Measure-FailureState -FailureTimes $f -Events $script:Ev -CoverageStart ([datetime]'2026-10-10')
        $c.BeforeCoverage | Should -Be 2
        (Get-ActivityVerdict -Computer 'X' -Counts $c -HasFailureData $true).Key | Should -Be 'NoOverlap'
    }

    It 'reports an unreachable machine plainly' {
        $v = Get-ActivityVerdict -Computer 'X' -Counts $null -HasFailureData $true -Reachable $false -UnreachableReason 'Did not answer.'
        $v.Key  | Should -Be 'Unreachable'
        $v.Line | Should -Match 'could not be reached'
    }

    It 'says it is a timeline only when no failure times were given' {
        (Get-ActivityVerdict -Computer 'X' -Counts (Measure-FailureState -FailureTimes @() -Events $script:Ev) -HasFailureData $false).Key | Should -Be 'TimelineOnly'
    }
}

Describe 'Select-TimelineTarget' {
    It 'picks the top workstations by failures, skipping servers and duplicates' {
        $src = @(
            [PSCustomObject]@{ ResolvedName='SQLSRV02';    DeviceClass='Server';                  FailureCount='42'; SourceIp='10.20.1.40'; Accounts='a' }
            [PSCustomObject]@{ ResolvedName='CON-LT-0142'; DeviceClass='DomainJoinedWorkstation'; FailureCount='84'; SourceIp='10.20.4.142'; Accounts='m' }
            [PSCustomObject]@{ ResolvedName='CON-WS-0087'; DeviceClass='DomainJoinedWorkstation'; FailureCount='12'; SourceIp='10.20.5.87'; Accounts='b' }
            [PSCustomObject]@{ ResolvedName='con-lt-0142.contoso.com'; DeviceClass='DomainJoinedWorkstation'; FailureCount='3'; SourceIp=''; Accounts='m' }
            [PSCustomObject]@{ ResolvedName='CON-LT-0207'; DeviceClass='DomainJoinedWorkstation'; FailureCount='1'; SourceIp='10.20.4.207'; Accounts='h' }
            [PSCustomObject]@{ ResolvedName='';            DeviceClass='DomainJoinedWorkstation'; FailureCount='99'; SourceIp='10.9.9.9'; Accounts='x' }
        )
        $t = @(Select-TimelineTarget -Sources $src -Top 3)
        $t.Computer | Should -Be @('CON-LT-0142', 'CON-WS-0087', 'CON-LT-0207')
    }
}

Describe 'Get-FailureTimesForComputer' {
    It 'matches failures by resolved name, event name or address, and skips successes' {
        $ev = @(
            [PSCustomObject]@{ Time='2026-10-14 09:00:00'; ResolvedName='CON-LT-0142'; SourceHost='';             SourceIp='10.20.4.142'; IsFailure='True' }
            [PSCustomObject]@{ Time='2026-10-14 09:05:00'; ResolvedName='';            SourceHost='\\CON-LT-0142'; SourceIp='';           IsFailure='True' }
            [PSCustomObject]@{ Time='2026-10-14 09:10:00'; ResolvedName='';            SourceHost='';             SourceIp='10.20.4.142'; IsFailure='True' }
            [PSCustomObject]@{ Time='2026-10-14 09:15:00'; ResolvedName='CON-LT-0142'; SourceHost='';             SourceIp='10.20.4.142'; IsFailure='False' }
            [PSCustomObject]@{ Time='2026-10-14 09:20:00'; ResolvedName='OTHER';       SourceHost='';             SourceIp='10.0.0.1';    IsFailure='True' }
        )
        @(Get-FailureTimesForComputer -AuthEvents $ev -Computer 'CON-LT-0142' -SourceIp '10.20.4.142').Count | Should -Be 3
    }
}

Describe 'New-TimelineRow' {
    It 'collapses each run of failures into one row so the wake event stays visible' {
        $ev = @((New-Act Sleep '2026-10-14T12:00'); (New-Act Wake '2026-10-14T13:00'))
        $f  = @('2026-10-14T13:00:30', '2026-10-14T13:01', '2026-10-14T13:02') | ForEach-Object { [datetime]$_ }
        $p  = Get-ActivityInterval -Events $ev
        $rows = @(New-TimelineRow -Events $ev -FailureTimes $f -Intervals $p.Intervals -ResumePoints $p.ResumePoints)
        $rows.Count | Should -Be 3
        $rows[2].Label | Should -Match '^3 failed sign-ins right after it resumed'
    }

    It 'builds a timeline-only report when no failure times are supplied' {
        # Regression: the main flow passes $null here when there is no -AuthEventsCsv, which
        # [object[]] binds as @($null) and used to throw "Cannot convert null to DateTime".
        $ev = @((New-Act Sleep '2026-10-14T12:00'); (New-Act Wake '2026-10-14T13:00'))
        $p  = Get-ActivityInterval -Events $ev
        $rows = @(New-TimelineRow -Events $ev -FailureTimes $null -Intervals $p.Intervals -ResumePoints $p.ResumePoints)
        $rows.Count | Should -Be 2
        @($rows | Where-Object { $_.IsFailure }).Count | Should -Be 0
    }
}

Describe 'Get-RemoteErrorText' {
    It 'explains an unreachable machine' {
        Get-RemoteErrorText -Message 'The RPC server is unavailable.' | Should -Match 'did not answer'
    }
    It 'explains access denied' {
        Get-RemoteErrorText -Message 'Attempted to perform an unauthorized operation. Access is denied.' | Should -Match 'administrator rights'
    }
}

Describe 'New-SourceActivityHtml' {
    It 'leads with the most telling machine and escapes hostile names' {
        $m = @(
            [PSCustomObject]@{ Computer='<b>evil</b>'; Reachable=$true; HasFailureData=$true; Notes=@(); CoverageStart=$null; Timeline=@()
                               Counts=[PSCustomObject]@{ Total=1; AfterResume=0; WhileOff=0; WhileAsleep=0; WhileLocked=0 }
                               Verdict=[PSCustomObject]@{ Class='ok'; Key='Awake'; Line='quiet'; Next='n' } }
            [PSCustomObject]@{ Computer='CON-LT-0142'; Reachable=$true; HasFailureData=$true; Notes=@(); CoverageStart=$null; Timeline=@()
                               Counts=[PSCustomObject]@{ Total=9; AfterResume=8; WhileOff=0; WhileAsleep=0; WhileLocked=0 }
                               Verdict=[PSCustomObject]@{ Class='bad'; Key='AfterResume'; Line='8 of 9 failures came right after waking'; Next='n' } }
        )
        $html = New-SourceActivityHtml -Machines $m -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match '<p class="line">8 of 9 failures came right after waking'
        $html | Should -Not -Match '<b>evil</b>'
        $html | Should -Match '&lt;b&gt;evil'
    }

    It 'renders a valid page with no machines' {
        $html = New-SourceActivityHtml -Machines @() -DaysBack 7 -GeneratedOn 'now'
        $html | Should -Match 'No source machines to check'
        $html | Should -Match '</html>'
    }
}
