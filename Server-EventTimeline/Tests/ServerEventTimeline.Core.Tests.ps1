<#
    Pester 5 tests for ServerEventTimeline.Core.ps1 (pure logic: no network, no UI, no real
    event logs). Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')
}

Describe 'ConvertTo-ServerList' {
    It 'splits, trims, drops empties and de-duplicates case-insensitively keeping the first spelling' {
        $text = "app01, APP01;sql01.contoso.local`n`n 10.0.0.5,"
        $result = @(ConvertTo-ServerList -Text $text)
        $result | Should -Be @('app01', 'sql01.contoso.local', '10.0.0.5')
    }

    It 'returns an empty array for blank input' {
        @(ConvertTo-ServerList -Text "  `n ,; ").Count | Should -Be 0
    }
}

Describe 'New-TimelineWindow' {
    It 'Around gives the time plus and minus the minutes, as server-local wall-clock' {
        $w = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-17 03:00') -PlusMinusMinutes 15
        $w.StartLocal | Should -Be ([datetime]'2026-11-17 02:45')
        $w.EndLocal   | Should -Be ([datetime]'2026-11-17 03:15')
        $w.StartLocal.Kind | Should -Be ([DateTimeKind]::Unspecified)
    }

    It 'Range rejects From after To with a plain message' {
        { New-TimelineWindow -Mode Range -From ([datetime]'2026-11-17 04:00') -To ([datetime]'2026-11-17 03:00') } |
            Should -Throw -ExpectedMessage '*From must be before To*'
    }

    It 'Around without -At throws a plain message' {
        { New-TimelineWindow -Mode Around -PlusMinusMinutes 15 } | Should -Throw -ExpectedMessage '*time*'
    }

    It 'Range across the 2026-11-01 US DST change keeps the typed wall-clock values' {
        $w = New-TimelineWindow -Mode Range -From ([datetime]'2026-11-01 00:30') -To ([datetime]'2026-11-01 03:30')
        $w.StartLocal | Should -Be ([datetime]'2026-11-01 00:30')
        $w.EndLocal   | Should -Be ([datetime]'2026-11-01 03:30')
    }

    It 'Relative keeps the minutes' {
        (New-TimelineWindow -Mode Relative -LastMinutes 60).LastMinutes | Should -Be 60
    }
}

Describe 'ConvertTo-UtcWindow' {
    It 'subtracts the server UTC offset for Around/Range' {
        $w = New-TimelineWindow -Mode Around -At ([datetime]'2026-11-17 03:00') -PlusMinusMinutes 15
        $u = ConvertTo-UtcWindow -Window $w -UtcOffsetMinutes -300
        $u.StartUtc | Should -Be ([datetime]'2026-11-17 07:45')
        $u.EndUtc   | Should -Be ([datetime]'2026-11-17 08:15')
        $u.StartUtc.Kind | Should -Be ([DateTimeKind]::Utc)
    }

    It 'Relative counts back from NowUtc' {
        $w = New-TimelineWindow -Mode Relative -LastMinutes 60
        $now = [datetime]::SpecifyKind([datetime]'2026-11-17 12:00', [DateTimeKind]::Utc)
        $u = ConvertTo-UtcWindow -Window $w -UtcOffsetMinutes 120 -NowUtc $now
        $u.StartUtc | Should -Be ([datetime]'2026-11-17 11:00')
        $u.EndUtc   | Should -Be ([datetime]'2026-11-17 12:00')
    }
}

Describe 'Get-TimelineLogCatalog' {
    BeforeAll { $script:Catalog = @(Get-TimelineLogCatalog) }

    It 'has System and Application ticked by default' {
        ($script:Catalog | Where-Object Name -eq 'System').Default      | Should -BeTrue
        ($script:Catalog | Where-Object Name -eq 'Application').Default | Should -BeTrue
    }

    It 'has Security unticked by default' {
        ($script:Catalog | Where-Object Name -eq 'Security').Default | Should -BeFalse
    }

    It 'has at most 12 operational logs, all ticked by default' {
        $ops = @($script:Catalog | Where-Object Group -eq 'Operational')
        $ops.Count | Should -BeGreaterThan 0
        $ops.Count | Should -BeLessOrEqual 12
        @($ops | Where-Object { -not $_.Default }).Count | Should -Be 0
    }

    It 'has no duplicate names and every entry has a label' {
        $names = @($script:Catalog | ForEach-Object Name)
        @($names | Select-Object -Unique).Count | Should -Be $names.Count
        @($script:Catalog | Where-Object { -not $_.Label }).Count | Should -Be 0
    }
}

Describe 'Get-EventFlag' {
    It 'flags User32 1074 as a restart' {
        (Get-EventFlag -Log System -Provider User32 -Id 1074).Category | Should -Be 'Restart'
    }

    It 'does not flag the same ID from a different provider' {
        Get-EventFlag -Log System -Provider 'Some-Other' -Id 1074 | Should -BeNullOrEmpty
    }

    It 'flags Service Control Manager 7031 as a service crash' {
        (Get-EventFlag -Log System -Provider 'Service Control Manager' -Id 7031).Category | Should -Be 'ServiceCrash'
    }

    It 'flags Application Error 1000 in the Application log as an app crash' {
        (Get-EventFlag -Log Application -Provider 'Application Error' -Id 1000).Category | Should -Be 'AppCrash'
    }

    It 'tells the two 1001 events apart by log and provider' {
        (Get-EventFlag -Log System -Provider 'Microsoft-Windows-WER-SystemErrorReporting' -Id 1001).Category | Should -Be 'Bugcheck'
        (Get-EventFlag -Log Application -Provider 'Windows Error Reporting' -Id 1001).Category | Should -Be 'AppCrash'
    }

    It 'matches the controller driver for disk controller event 11 (stornvme, storahci)' {
        (Get-EventFlag -Log System -Provider 'stornvme' -Id 11).Category | Should -Be 'Disk'
        (Get-EventFlag -Log System -Provider 'storahci' -Id 11).Category | Should -Be 'Disk'
        Get-EventFlag -Log System -Provider 'Microsoft-Windows-Kernel-General' -Id 11 | Should -BeNullOrEmpty
    }

    It 'matches both spellings of the NTFS provider' {
        (Get-EventFlag -Log System -Provider 'Ntfs' -Id 55).Category | Should -Be 'Disk'
        (Get-EventFlag -Log System -Provider 'Microsoft-Windows-Ntfs' -Id 55).Category | Should -Be 'Disk'
    }

    It 'leaves dropped (unverified) IDs unflagged' {
        Get-EventFlag -Log System -Provider 'Service Control Manager' -Id 7023 | Should -BeNullOrEmpty
    }

    It 'every catalog entry has a category and a label' {
        @($script:FlagCatalog | Where-Object { -not $_.Category -or -not $_.Label }).Count | Should -Be 0
    }
}

Describe 'ConvertTo-TimelineRow' {
    BeforeAll {
        function New-FakeEvent {
            param($Level = 4, $Message = 'Line one', $Provider = 'Service Control Manager', $Id = 7036,
                  $Time = '2026-11-17 08:00:00', $Log = 'System', $RecordId = 1)
            [PSCustomObject]@{
                TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc)
                Id = $Id; ProviderName = $Provider; Level = $Level; LogName = $Log; Message = $Message
                RecordId = $RecordId; UserSid = 'S-1-5-18'; MachineName = 'app01.contoso.local'
            }
        }
    }

    It 'maps numeric levels to names (never the localized display name)' {
        (ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Level 1) -UtcOffsetMinutes 0).LevelName | Should -Be 'Critical'
        (ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Level 2) -UtcOffsetMinutes 0).LevelName | Should -Be 'Error'
        (ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Level 3) -UtcOffsetMinutes 0).LevelName | Should -Be 'Warning'
        (ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Level 0) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
        (ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Level 4) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
    }

    It 'explains a missing message instead of leaving it blank' {
        $row = ConvertTo-TimelineRow -Server SQL01 -EventRecord (New-FakeEvent -Message $null -Provider MSSQLSERVER -Id 17883 -Log Application) -UtcOffsetMinutes 0
        $expected = "(No message text: Windows couldn't render the message for event 17883 from MSSQLSERVER. Over the remote event log route this is normal when that software isn't installed on this workstation.)"
        $row.Message | Should -Be $expected
        $row.MessageFirstLine | Should -Be $expected
    }

    It 'uses the first non-empty line as the short message' {
        $row = ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Message "`r`n  `r`nFirst real line`r`nSecond") -UtcOffsetMinutes 0
        $row.MessageFirstLine | Should -Be 'First real line'
    }

    It 'shows server-local time as UTC plus the offset and fills the flag' {
        $row = ConvertTo-TimelineRow -Server APP01 -EventRecord (New-FakeEvent -Provider User32 -Id 1074) -UtcOffsetMinutes -300
        $row.TimeServerLocal | Should -Be ([datetime]'2026-11-17 03:00:00')
        $row.TimeUtc | Should -Be ([datetime]'2026-11-17 08:00:00')
        $row.FlagCategory | Should -Be 'Restart'
        $row.Flag | Should -Not -BeNullOrEmpty
        $row.Server | Should -Be 'APP01'
        $row.EventId | Should -Be 1074
    }
}

Describe 'Merge-TimelineRows' {
    It 'orders rows from several servers by UTC time' {
        $mk = { param($s, $t) [PSCustomObject]@{ Server = $s; TimeUtc = [datetime]$t; RecordId = 1 } }
        $rows = @((& $mk 'SQL01' '2026-11-17 08:05'), (& $mk 'APP01' '2026-11-17 08:01'), (& $mk 'DC01' '2026-11-17 08:03'))
        (@(Merge-TimelineRows -Rows $rows) | ForEach-Object Server) | Should -Be @('APP01', 'DC01', 'SQL01')
    }
}

Describe 'Test-RowMatchesFilter' {
    BeforeAll {
        function New-Row { param($Level = 4, $Flag = '', $Server = 'APP01', $Log = 'System', $EventId = 7036, $Message = 'The service entered the running state.', $Provider = 'Service Control Manager')
            [PSCustomObject]@{ Level = $Level; Flag = $Flag; Server = $Server; Log = $Log; EventId = $EventId; Message = $Message; Provider = $Provider } }
        $script:All = @{ MinLevel = 'All'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '' }
        function New-Filter { param([hashtable]$Change) $f = $script:All.Clone(); foreach ($k in $Change.Keys) { $f[$k] = $Change[$k] }; $f }
    }

    It 'All shows every level' {
        Test-RowMatchesFilter -Row (New-Row -Level 4) -Filter $script:All | Should -BeTrue
    }

    It 'Warning+ keeps 1,2,3 and drops 0,4,5' {
        $f = New-Filter @{ MinLevel = 'Warning' }
        foreach ($l in 1, 2, 3) { Test-RowMatchesFilter -Row (New-Row -Level $l) -Filter $f | Should -BeTrue }
        foreach ($l in 0, 4, 5) { Test-RowMatchesFilter -Row (New-Row -Level $l) -Filter $f | Should -BeFalse }
    }

    It 'Error+ keeps 1,2 and drops 3' {
        $f = New-Filter @{ MinLevel = 'Error' }
        Test-RowMatchesFilter -Row (New-Row -Level 2) -Filter $f | Should -BeTrue
        Test-RowMatchesFilter -Row (New-Row -Level 3) -Filter $f | Should -BeFalse
    }

    It 'Critical keeps only 1' {
        $f = New-Filter @{ MinLevel = 'Critical' }
        Test-RowMatchesFilter -Row (New-Row -Level 1) -Filter $f | Should -BeTrue
        Test-RowMatchesFilter -Row (New-Row -Level 2) -Filter $f | Should -BeFalse
    }

    It 'filters by server and by log' {
        Test-RowMatchesFilter -Row (New-Row -Server SQL01) -Filter (New-Filter @{ Server = 'APP01' }) | Should -BeFalse
        Test-RowMatchesFilter -Row (New-Row -Log Application) -Filter (New-Filter @{ Log = 'System' }) | Should -BeFalse
    }

    It 'Flagged only drops rows without a flag' {
        $f = New-Filter @{ FlaggedOnly = $true }
        Test-RowMatchesFilter -Row (New-Row -Flag '') -Filter $f | Should -BeFalse
        Test-RowMatchesFilter -Row (New-Row -Flag 'Service crashed') -Filter $f | Should -BeTrue
    }

    It 'text matches the event ID, provider or message, case-insensitively' {
        Test-RowMatchesFilter -Row (New-Row -EventId 7031) -Filter (New-Filter @{ Text = '7031' }) | Should -BeTrue
        Test-RowMatchesFilter -Row (New-Row) -Filter (New-Filter @{ Text = 'control manager' }) | Should -BeTrue
        Test-RowMatchesFilter -Row (New-Row) -Filter (New-Filter @{ Text = 'RUNNING STATE' }) | Should -BeTrue
        Test-RowMatchesFilter -Row (New-Row) -Filter (New-Filter @{ Text = 'nothing like this' }) | Should -BeFalse
    }

    It 'treats regex characters in the text literally' {
        { Test-RowMatchesFilter -Row (New-Row) -Filter (New-Filter @{ Text = '[x' }) } | Should -Not -Throw
        Test-RowMatchesFilter -Row (New-Row -Message 'path C:\[x]\y') -Filter (New-Filter @{ Text = '[x' }) | Should -BeTrue
    }
}

Describe 'Exports' {
    BeforeAll {
        $script:Rows = @(
            [PSCustomObject]@{ Server = 'APP01'; Log = 'System'; TimeUtc = [datetime]'2026-11-17 08:02:14'; TimeServerLocal = [datetime]'2026-11-17 03:02:14'
                Level = 2; LevelName = 'Error'; FlagCategory = 'ServiceCrash'; Flag = 'Service stopped unexpectedly'; Provider = 'Service Control Manager'
                EventId = 7034; Message = "<script>alert(1)</script> & `"q`"`r`nsecond line"; MessageFirstLine = '<script>alert(1)</script> & "q"'
                RecordId = 10; User = 'S-1-5-18'; Machine = 'app01' }
        )
        $script:Context = @{
            WindowText = 'Around 2026-11-17 03:00 +/- 15 min (server local time)'; Servers = @('APP01', 'DC01'); Logs = @('System')
            FiltersText = 'All levels'; GeneratedAt = [datetime]'2026-11-17 09:00'
            ServerOutcomes = @(
                [PSCustomObject]@{ Server = 'APP01'; State = 'DoneWithGaps'; Transport = 'WinRM'; Reason = ''; EventCount = 5000
                    Logs = @([PSCustomObject]@{ Log = 'System'; Outcome = 'Capped'; Count = 5000; Reason = 'stopped at 5,000 events' }) }
                [PSCustomObject]@{ Server = 'DC01'; State = 'Unreachable'; Transport = ''; Reason = 'WinRM and remote event log are both unreachable from here.'; EventCount = 0; Logs = @() }
            )
        }
    }

    It 'text lines show server-local time, server, level, provider, ID and the first line' {
        $text = ConvertTo-TimelineText -Rows $script:Rows
        $text | Should -BeLike '2026-11-17 03:02:14 (server local) | APP01 | Error | Service Control Manager | 7034 | <script>*'
    }

    It 'CSV keeps both time columns' {
        $path = Join-Path $TestDrive 'out.csv'
        Export-TimelineCsv -Rows $script:Rows -Path $path
        $back = @(Import-Csv -Path $path)
        $back.Count | Should -Be 1
        $back[0].PSObject.Properties.Name | Should -Contain 'TimeServerLocal'
        $back[0].PSObject.Properties.Name | Should -Contain 'TimeUtc'
        $back[0].EventId | Should -Be '7034'
    }

    It 'HTML encodes hostile message text' {
        $html = ConvertTo-TimelineHtml -Rows $script:Rows -Context $script:Context
        $html | Should -BeLike '*&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;*'
        $html | Should -Not -BeLike '*<script>alert*'
    }

    It 'HTML lists the capped log and the unreachable server' {
        $html = ConvertTo-TimelineHtml -Rows $script:Rows -Context $script:Context
        $html | Should -BeLike '*APP01*System*stopped at 5,000 events*'
        $html | Should -BeLike '*DC01*both unreachable from here*'
    }
}

Describe 'Get-RemoteFailureKind' {
    BeforeAll {
        function New-Err { param([Exception]$Exception, [string]$Id = 'X')
            New-Object System.Management.Automation.ErrorRecord ($Exception, $Id, [System.Management.Automation.ErrorCategory]::NotSpecified, $null) }
    }

    It 'calls a remoting access-denied error AccessDenied' {
        $ex = New-Object System.Management.Automation.Remoting.PSRemotingTransportException 'Connecting to remote server srv-fake-01 failed with the following error message : Access is denied.'
        $ex.ErrorCode = 5
        Get-RemoteFailureKind -ErrorRecord (New-Err $ex 'AccessDenied,PSSessionStateBroken') | Should -Be 'AccessDenied'
    }

    It 'calls a WinRM transport error Connection' {
        $ex = New-Object System.Management.Automation.Remoting.PSRemotingTransportException 'WinRM cannot complete the operation. Verify that the specified computer name is valid.'
        $ex.ErrorCode = 53
        Get-RemoteFailureKind -ErrorRecord (New-Err $ex 'WinRMOperationTimeout,PSSessionStateBroken') | Should -Be 'Connection'
    }

    It 'calls UnauthorizedAccessException AccessDenied' {
        Get-RemoteFailureKind -ErrorRecord (New-Err (New-Object UnauthorizedAccessException 'Attempted to perform an unauthorized operation.')) | Should -Be 'AccessDenied'
    }

    It 'calls RPC server unavailable (0x800706BA) Connection' {
        $ex = New-Object System.Diagnostics.Eventing.Reader.EventLogException 'The RPC server is unavailable.'
        $ex.HResult = [int]0x800706BA
        Get-RemoteFailureKind -ErrorRecord (New-Err $ex) | Should -Be 'Connection'
    }

    It 'calls anything else Other' {
        Get-RemoteFailureKind -ErrorRecord (New-Err (New-Object System.Management.Automation.RuntimeException 'Something odd')) | Should -Be 'Other'
    }

    It 'words access denied in plain English with the next step' {
        Get-FailureText -Kind AccessDenied -Server DC01 | Should -Be "Access denied on DC01: check you're an admin there, or use Run as."
    }
}

Describe 'Select-TimelineRows' {
    BeforeAll {
        $script:Mixed = @(
            [PSCustomObject]@{ Level = 2; Flag = 'Service crashed'; Server = 'APP01'; Log = 'System'; EventId = 7031; Message = 'The SQL service terminated'; Provider = 'Service Control Manager' }
            [PSCustomObject]@{ Level = 4; Flag = ''; Server = 'SQL01'; Log = 'Application'; EventId = 100; Message = 'All fine'; Provider = 'MSSQLSERVER' }
            [PSCustomObject]@{ Level = 3; Flag = ''; Server = 'APP01'; Log = 'Application'; EventId = 200; Message = 'Slow [x] thing'; Provider = 'App' }
        )
    }

    It 'gives the same rows as Test-RowMatchesFilter for every filter combination' {
        $filters = @(
            @{ MinLevel = 'All'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '' }
            @{ MinLevel = 'Warning'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '' }
            @{ MinLevel = 'All'; Server = 'APP01'; Log = 'Application'; FlaggedOnly = $false; Text = '' }
            @{ MinLevel = 'All'; Server = '*'; Log = '*'; FlaggedOnly = $true; Text = '' }
            @{ MinLevel = 'All'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '[x' }
            @{ MinLevel = 'Error'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = 'sql' }
        )
        foreach ($f in $filters) {
            $expected = @($script:Mixed | Where-Object { Test-RowMatchesFilter -Row $_ -Filter $f } | ForEach-Object EventId)
            $actual = @(Select-TimelineRows -Rows $script:Mixed -Filter $f | ForEach-Object EventId)
            ($actual -join ',') | Should -Be ($expected -join ',')
        }
    }

    It 'returns an empty array when nothing matches' {
        @(Select-TimelineRows -Rows $script:Mixed -Filter @{ MinLevel = 'Critical'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '' }).Count | Should -Be 0
    }
}

Describe 'ConvertFrom-TimelineInputs' {
    It 'builds the request for an Around search' {
        $r = ConvertFrom-TimelineInputs -ServersText 'app01, sql01' -Mode Around -AtText '2026-11-17 03:00' -PlusMinusMinutes 15 -CapText '5000' -TimeoutText '60'
        $r.Ok | Should -BeTrue
        $r.Servers | Should -Be @('app01', 'sql01')
        $r.Window.StartLocal | Should -Be ([datetime]'2026-11-17 02:45')
        $r.Cap | Should -Be 5000
        $r.TimeoutSec | Should -Be 60
    }

    It 'asks for at least one server' {
        $r = ConvertFrom-TimelineInputs -ServersText '  ' -Mode Around -AtText '2026-11-17 03:00' -PlusMinusMinutes 15 -CapText '5000' -TimeoutText '60'
        $r.Ok | Should -BeFalse
        $r.Message | Should -Be 'Enter at least one server name.'
    }

    It 'explains a date it cannot read' {
        $r = ConvertFrom-TimelineInputs -ServersText 'app01' -Mode Around -AtText 'yesterday-ish' -PlusMinusMinutes 15 -CapText '5000' -TimeoutText '60'
        $r.Ok | Should -BeFalse
        $r.Message | Should -BeLike '*yyyy-MM-dd HH:mm*'
    }

    It 'rejects a From/To range that runs backwards' {
        $r = ConvertFrom-TimelineInputs -ServersText 'app01' -Mode Range -FromText '2026-11-17 04:00' -ToText '2026-11-17 03:00' -CapText '5000' -TimeoutText '60'
        $r.Ok | Should -BeFalse
        $r.Message | Should -BeLike '*From must be before To*'
    }

    It 'rejects a cap or timeout that is not a positive whole number' {
        (ConvertFrom-TimelineInputs -ServersText 'app01' -Mode Around -AtText '2026-11-17 03:00' -PlusMinusMinutes 15 -CapText 'lots' -TimeoutText '60').Message | Should -BeLike '*events per log*'
        (ConvertFrom-TimelineInputs -ServersText 'app01' -Mode Around -AtText '2026-11-17 03:00' -PlusMinusMinutes 15 -CapText '5000' -TimeoutText '0').Message | Should -BeLike '*seconds*'
    }

    It 'Relative needs no date text' {
        $r = ConvertFrom-TimelineInputs -ServersText 'app01' -Mode Relative -LastMinutes 60 -CapText '5000' -TimeoutText '60'
        $r.Ok | Should -BeTrue
        $r.Window.LastMinutes | Should -Be 60
    }
}

Describe 'Status wording' {
    BeforeAll {
        $script:Status = [ordered]@{
            'APP01' = [PSCustomObject]@{ Server = 'APP01'; State = 'DoneWithGaps'; Transport = 'WinRM'; Reason = ''; EventCount = 5200; UtcOffsetMinutes = -300
                Logs = @([PSCustomObject]@{ Log = 'System'; Outcome = 'Capped'; Count = 5000; Reason = 'stopped at 5,000 events' }
                         [PSCustomObject]@{ Log = 'Application'; Outcome = 'TimedOut'; Count = 0; Reason = "didn't answer within 60 s" }
                         [PSCustomObject]@{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Outcome = 'Skipped'; Count = 0; Reason = 'Task Scheduler log is turned off on APP01' }) }
            'LON-SQL01' = [PSCustomObject]@{ Server = 'LON-SQL01'; State = 'Done'; Transport = 'RPC'; Reason = ''; EventCount = 12; UtcOffsetMinutes = 0; Logs = @() }
            'DC01' = [PSCustomObject]@{ Server = 'DC01'; State = 'Unreachable'; Transport = ''; Reason = 'WinRM and remote event log are both unreachable from here.'; EventCount = 0; UtcOffsetMinutes = 0; Logs = @() }
        }
    }

    It 'describes each server in one plain line' {
        $lines = @(Get-TimelineStatusLines -Status $script:Status)
        $lines[0] | Should -Be 'APP01: done with gaps - 5,200 events (via WinRM)'
        $lines[1] | Should -Be 'LON-SQL01: done - 12 events (via remote event log)'
        $lines[2] | Should -Be "DC01: couldn't reach - WinRM and remote event log are both unreachable from here."
    }

    It 'banners capped and timed-out logs with what to do, but not skipped ones' {
        $banner = Get-TimelineBannerText -Status $script:Status
        $banner | Should -BeLike '*APP01 System: stopped at 5,000 events - narrow the window or raise the cap*'
        $banner | Should -BeLike "*APP01 Application: didn't answer within 60 s*"
        $banner | Should -Not -BeLike '*Task Scheduler*'
    }

    It 'notes different time zones only when the reached servers differ' {
        Get-TimelineTimeZoneNote -Status $script:Status | Should -BeLike '*different time zones*UTC column*'
        $same = [ordered]@{ 'A' = [PSCustomObject]@{ Server = 'A'; Transport = 'WinRM'; UtcOffsetMinutes = 60 }; 'B' = [PSCustomObject]@{ Server = 'B'; Transport = 'RPC'; UtcOffsetMinutes = 60 } }
        Get-TimelineTimeZoneNote -Status $same | Should -BeNullOrEmpty
    }
}

Describe 'The old Pick from AD functions are gone' {
    # Replaced by the server list (ServerEventTimeline.ServerList.ps1): suggestions while typing
    # and the "Add several servers" dialog, both from one background AD load.
    It 'no longer defines Get-AdServerCandidates or Add-ServerNames' {
        Get-Command Get-AdServerCandidates -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Command Add-ServerNames -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Describe 'The default AD loader (stubbed AD cmdlets, run in this process)' {
    BeforeAll {
        $script:SavedAdpsDrive = $env:ADPS_LoadDefaultDrive
        $env:ADPS_LoadDefaultDrive = '0'
        # Stubs with the real parameter names (checked with Get-Command against RSAT);
        # functions win over the module's cmdlets, so no DC is ever contacted.
        function global:Get-ADDomain { param($Identity, $Server, $Credential) throw 'stub: mock me' }
        function global:Get-ADDomainController { param($Identity, $Filter, $Server, $Credential) throw 'stub: mock me' }
        function global:Get-ADComputer { param($Identity, $Filter, $Properties, $ResultSetSize, $SearchBase, $Server, $Credential) throw 'stub: mock me' }
    }
    AfterAll {
        Remove-Item -Path Function:\global:Get-ADDomain, Function:\global:Get-ADDomainController, Function:\global:Get-ADComputer -ErrorAction SilentlyContinue
        if ($null -eq $script:SavedAdpsDrive) { Remove-Item Env:\ADPS_LoadDefaultDrive -ErrorAction SilentlyContinue } else { $env:ADPS_LoadDefaultDrive = $script:SavedAdpsDrive }
    }
    BeforeEach {
        Mock Import-Module { } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADDomain { [PSCustomObject]@{ DNSRoot = 'contoso.local' } }
        Mock Get-ADDomainController { @([PSCustomObject]@{ HostName = 'dc01.contoso.local'; Name = 'DC01' }) }
        Mock Get-ADComputer { @(
                [PSCustomObject]@{ Name = 'DC01'; DNSHostName = 'dc01.contoso.local'; OperatingSystem = 'Windows Server 2022'; Enabled = $true; lastLogonTimestamp = 0; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=local' },
                [PSCustomObject]@{ Name = 'PC01'; DNSHostName = ''; OperatingSystem = 'Windows 11 Pro'; Enabled = $false; lastLogonTimestamp = $null; DistinguishedName = 'CN=PC01,OU=Desks,DC=contoso,DC=local' }) }
    }

    It 'reads every computer account and marks the domain controllers' {
        $r = & $script:DefaultDirectoryLoader -ListPath $script:ServerListFilePath -Server '' -Credential $null
        $r.Domain | Should -Be 'contoso.local'
        @($r.Entries).Count | Should -Be 2
        @($r.Entries)[0].IsDC | Should -BeTrue
        @($r.Entries)[1].Enabled | Should -BeFalse
        Should -Invoke Get-ADComputer -Times 1 -ParameterFilter {
            $Filter -eq '*' -and $Properties -contains 'lastLogonTimestamp' -and $Properties -contains 'OperatingSystem' -and $Properties -contains 'Enabled' -and -not $Server
        }
    }

    It 'does not mount the AD: drive (it would first try this computer''s own domain)' {
        Remove-Item Env:\ADPS_LoadDefaultDrive -ErrorAction SilentlyContinue
        $null = & $script:DefaultDirectoryLoader -ListPath $script:ServerListFilePath -Server '' -Credential $null
        $env:ADPS_LoadDefaultDrive | Should -Be '0'
    }

    It 'reads the chosen domain or DC, as the Run as account' {
        $cred = New-Object System.Management.Automation.PSCredential ('CONTOSO\admin', (New-Object System.Security.SecureString))
        $null = & $script:DefaultDirectoryLoader -ListPath $script:ServerListFilePath -Server 'dc01.contoso.local' -Credential $cred
        Should -Invoke Get-ADDomain -Times 1 -ParameterFilter { $Server -eq 'dc01.contoso.local' -and $Credential.UserName -eq 'CONTOSO\admin' }
        Should -Invoke Get-ADComputer -Times 1 -ParameterFilter { $Server -eq 'dc01.contoso.local' -and $Credential.UserName -eq 'CONTOSO\admin' }
    }
}

Describe 'Add-TimelineRows (incremental merge for the window)' {
    BeforeAll {
        function New-R { param($Server, $Min, $Log = 'System')
            [PSCustomObject]@{ Server = $Server; Log = $Log; TimeUtc = ([datetime]'2026-11-17 08:00').AddMinutes($Min); RecordId = $Min } }
    }

    It 'keeps every row in UTC order as batches arrive and collects the log names' {
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows @((New-R 'APP01' 5), (New-R 'APP01' 1))
        Add-TimelineRows -Store $store -NewRows @((New-R 'SQL01' 3 'Application'), (New-R 'SQL01' 9 'Application'))
        (@($store.Rows) | ForEach-Object { $_.TimeUtc.Minute }) | Should -Be @(1, 3, 5, 9)
        @($store.Logs) | Sort-Object | Should -Be @('Application', 'System')
    }

    It 'merges a 5,000-row batch into 100,000 rows quickly (window responsiveness guard)' {
        $base = [datetime]'2026-11-17 00:00'
        $big = foreach ($i in 0..99999) { [PSCustomObject]@{ Server = 'A'; Log = 'System'; TimeUtc = $base.AddSeconds($i * 2); RecordId = $i } }
        $batch = foreach ($i in 0..4999) { [PSCustomObject]@{ Server = 'B'; Log = 'Application'; TimeUtc = $base.AddSeconds($i * 40 + 1); RecordId = $i } }
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows $big
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Add-TimelineRows -Store $store -NewRows $batch
        $sw.Elapsed.TotalMilliseconds | Should -BeLessThan 500
        $store.Rows.Count | Should -Be 105000
        $store.Rows[1].Server | Should -Be 'B'
    }
}

Describe 'Review fixes: wording' {
    It 'a blank message names the event without blaming a particular machine' {
        $e = [PSCustomObject]@{ TimeCreatedUtc = [datetime]::SpecifyKind([datetime]'2026-11-17 08:00', 'Utc'); Id = 17883; ProviderName = 'MSSQLSERVER'
            Level = 2; LogName = 'Application'; Message = $null; RecordId = 1; UserSid = ''; MachineName = 'sql01' }
        $row = ConvertTo-TimelineRow -Server SQL01 -EventRecord $e -UtcOffsetMinutes 0
        $row.Message | Should -Be "(No message text: Windows couldn't render the message for event 17883 from MSSQLSERVER. Over the remote event log route this is normal when that software isn't installed on this workstation.)"
    }

    It 'a done server shows its note (for example an assumed time zone)' {
        $status = [ordered]@{ 'APP01' = [PSCustomObject]@{ Server = 'APP01'; State = 'Done'; Transport = 'RPC'; Reason = "Couldn't read the time zone; assumed this workstation's."; EventCount = 3; UtcOffsetMinutes = 0; Logs = @() } }
        @(Get-TimelineStatusLines -Status $status)[0] | Should -Be "APP01: done - 3 events (via remote event log) - Couldn't read the time zone; assumed this workstation's."
    }
}

Describe 'This computer' {
    BeforeAll { $script:Names = @('WS01', 'ws01.contoso.local', 'localhost', '.', '127.0.0.1', '::1') }

    It 'recognizes every way of naming this computer' {
        foreach ($n in 'localhost', '.', '127.0.0.1', '::1', 'WS01', 'ws01', 'WS01.contoso.local') {
            Test-IsLocalComputer -Name $n -LocalNames $script:Names | Should -BeTrue -Because $n
        }
    }

    It 'does not treat other machines as this computer' {
        Test-IsLocalComputer -Name 'SRV01' -LocalNames $script:Names | Should -BeFalse
        Test-IsLocalComputer -Name 'ws01.fabrikam.local' -LocalNames $script:Names | Should -BeFalse
    }

    It 'lists this computer by its own name, the short name first' {
        Mock Get-LocalComputerIdentity { [PSCustomObject]@{ Name = 'WS01'; DomainName = 'contoso.local' } }
        $n = @(Get-LocalComputerNames)
        $n[0] | Should -Be 'WS01'
        $n | Should -Contain 'ws01.contoso.local'
        $n | Should -Contain 'localhost'
    }

    It 'turns localhost and friends into this computer''s name, once' {
        Mock Get-LocalComputerNames { $script:Names }
        $r = ConvertFrom-TimelineInputs -ServersText 'localhost, SRV01, ws01, 127.0.0.1' -Mode Relative -LastMinutes 60 -CapText '5000' -TimeoutText '60'
        $r.Servers | Should -Be @('WS01', 'SRV01')
    }

    It 'says a directly-read server was read directly' {
        $status = [ordered]@{ 'WS01' = [PSCustomObject]@{ Server = 'WS01'; State = 'Done'; Transport = 'Local'; Reason = ''; EventCount = 7; UtcOffsetMinutes = 0; Logs = @() } }
        @(Get-TimelineStatusLines -Status $status)[0] | Should -Be 'WS01: done - 7 events (this computer, read directly)'
    }
}

Describe 'Get-LogSelectionSummary' {
    It 'lists two logs by name' {
        Get-LogSelectionSummary -Labels @('System', 'Application') | Should -Be 'System, Application'
    }
    It 'shortens a long selection' {
        $labels = @('System', 'Application') + @(1..8 | ForEach-Object { "Log $_" })
        Get-LogSelectionSummary -Labels $labels | Should -Be 'System, Application + 8 more'
    }
    It 'says when nothing is selected' {
        Get-LogSelectionSummary -Labels @() | Should -Be 'No logs selected'
    }
    It 'mentions all logs' {
        Get-LogSelectionSummary -Labels @() -AllLogs | Should -Be 'All logs with events'
        Get-LogSelectionSummary -Labels @('System') -AllLogs | Should -Be 'System + all logs with events'
    }
}

Describe 'Save folder settings' {
    It 'reads nothing from a missing settings file' {
        (Read-TimelineSettings -Path (Join-Path $TestDrive 'none\settings.json')).SaveFolder | Should -BeNullOrEmpty
    }

    It 'reads nothing from a damaged settings file' {
        $p = Join-Path $TestDrive 'bad.json'
        Set-Content -LiteralPath $p -Value '{ not json'
        (Read-TimelineSettings -Path $p).SaveFolder | Should -BeNullOrEmpty
    }

    It 'remembers the save folder' {
        $p = Join-Path $TestDrive 'cfg\settings.json'
        Save-TimelineSettings -Path $p -SaveFolder 'D:\Tickets\INC1'
        (Read-TimelineSettings -Path $p).SaveFolder | Should -Be 'D:\Tickets\INC1'
    }

    It 'remembers the domain to read servers from, and keeps it when the save folder changes' {
        $p = Join-Path $TestDrive 'cfg-ad\settings.json'
        (Read-TimelineSettings -Path $p).AdTarget | Should -Be ''
        Save-TimelineSettings -Path $p -AdTarget 'contoso.local'
        (Read-TimelineSettings -Path $p).AdTarget | Should -Be 'contoso.local'
        Save-TimelineSettings -Path $p -SaveFolder 'D:\X'
        (Read-TimelineSettings -Path $p).AdTarget | Should -Be 'contoso.local'
        Save-TimelineSettings -Path $p -AdTarget ''
        (Read-TimelineSettings -Path $p).AdTarget | Should -Be ''
        (Read-TimelineSettings -Path $p).SaveFolder | Should -Be 'D:\X'
    }

    It 'uses -OutputPath first, then the remembered folder, then the default' {
        $remembered = Join-Path $TestDrive 'remembered'
        New-Item -ItemType Directory -Path $remembered | Out-Null
        Resolve-TimelineOutputFolder -OutputPath 'E:\Given' -Remembered $remembered -Default 'C:\Default' | Should -Be 'E:\Given'
        Resolve-TimelineOutputFolder -OutputPath '' -Remembered $remembered -Default 'C:\Default' | Should -Be $remembered
        Resolve-TimelineOutputFolder -OutputPath '' -Remembered '' -Default 'C:\Default' | Should -Be 'C:\Default'
    }

    It 'falls back to the default when the remembered folder is gone' {
        Resolve-TimelineOutputFolder -OutputPath '' -Remembered (Join-Path $TestDrive 'gone') -Default 'C:\Default' | Should -Be 'C:\Default'
    }

    It 'keeps the settings under the user profile application data' {
        Get-TimelineSettingsPath | Should -BeLike '*ServerEventTimeline*settings.json'
    }
}

Describe 'Get-TimelineServerCards (the sidebar''s EACH SERVER block)' {
    BeforeAll {
        function New-St { param($Server, $State, $Transport = 'WinRM', $Count = 0, $Reason = '')
            [PSCustomObject]@{ Server = $Server; State = $State; Transport = $Transport; EventCount = $Count; Reason = $Reason; UtcOffsetMinutes = 0; Logs = @() } }
        $script:Status = [ordered]@{}
        $script:Status['APP02'] = New-St 'APP02' 'Done' 'Local' 412
        $script:Status['AD-01.c'] = New-St 'AD-01.c' 'Querying'
        $script:Status['AD-03.c'] = New-St 'AD-03.c' 'DoneWithGaps' 'RPC' 5000
        $script:Status['OLD.c'] = New-St 'OLD.c' 'Unreachable' '' 0 'WinRM and the remote event log both refused'
        $script:Lines = @('APP02: nothing flagged in 412 events', 'AD-01.c: still reading... so far 1 app crash or hang',
            'AD-03.c: 1 system time change, 4 updates installed (some logs incomplete)', "OLD.c: couldn't be read",
            'Security log not read: tick it under Which logs? to see sign-in or lockout problems.')
    }

    It 'gives one card per server with its state and what was found' {
        $cards = @(Get-TimelineServerCards -Status $script:Status -SummaryLines $script:Lines)
        $cards.Count | Should -Be 4
        $cards[0].Server | Should -Be 'APP02'
        $cards[0].Heading | Should -Be '✓ APP02 · 412 events · this computer'
        $cards[0].Findings | Should -Be 'nothing flagged in 412 events'
        $cards[0].Warn | Should -BeFalse
        $cards[1].Heading | Should -Be '… AD-01.c · reading (WinRM)'
        $cards[1].Findings | Should -Be 'still reading... so far 1 app crash or hang'
        $cards[2].Heading | Should -Be '✓ AD-03.c · 5,000 events · with gaps · remote event log'
        $cards[2].Warn | Should -BeTrue
        $cards[3].Heading | Should -Be "✗ OLD.c · couldn't reach"
        $cards[3].Findings | Should -Be 'WinRM and the remote event log both refused'
        $cards[3].Warn | Should -BeTrue
    }

    It 'returns the lines that are not about one server as notes' {
        @(Get-TimelineServerNotes -Status $script:Status -SummaryLines $script:Lines) | Should -Be @('Security log not read: tick it under Which logs? to see sign-in or lockout problems.')
    }
}

Describe 'The time range filter (FromUtc / ToUtc)' {
    BeforeAll {
        $script:RangeRows = @(foreach ($m in 0..9) {
                [PSCustomObject]@{ Server = 'AD-01'; Log = 'System'; TimeUtc = [datetime]::SpecifyKind(([datetime]'2026-11-18 17:00').AddMinutes($m), [DateTimeKind]::Utc)
                    Level = 4; Flag = ''; Provider = 'P'; EventId = 1; Message = "m$m" }
            })
        $script:From = [datetime]::SpecifyKind([datetime]'2026-11-18 17:02', [DateTimeKind]::Utc)
        $script:To = [datetime]::SpecifyKind([datetime]'2026-11-18 17:05', [DateTimeKind]::Utc)
    }

    It 'keeps rows inside FromUtc to ToUtc, the end not included' {
        $f = @{ MinLevel = 'All'; FromUtc = $script:From; ToUtc = $script:To }
        $kept = @(Select-TimelineRows -Rows $script:RangeRows -Filter $f)
        @($kept | ForEach-Object Message) | Should -Be @('m2', 'm3', 'm4')
        @($script:RangeRows | Where-Object { Test-RowMatchesFilter -Row $_ -Filter $f } | ForEach-Object Message) | Should -Be @('m2', 'm3', 'm4')
    }

    It 'ignores a missing FromUtc or ToUtc' {
        @(Select-TimelineRows -Rows $script:RangeRows -Filter @{ MinLevel = 'All'; FromUtc = $script:From }).Count | Should -Be 8
        @(Select-TimelineRows -Rows $script:RangeRows -Filter @{ MinLevel = 'All'; ToUtc = $script:To }).Count | Should -Be 5
        @(Select-TimelineRows -Rows $script:RangeRows -Filter @{ MinLevel = 'All'; FromUtc = $null; ToUtc = $null }).Count | Should -Be 10
    }

    It 'Select-TimelineRows and Test-RowMatchesFilter agree on the time range with other filters' {
        $f = @{ MinLevel = 'All'; Text = 'm'; FromUtc = $script:From; ToUtc = $script:To; Server = 'AD-01' }
        @(Select-TimelineRows -Rows $script:RangeRows -Filter $f).Count | Should -Be @($script:RangeRows | Where-Object { Test-RowMatchesFilter -Row $_ -Filter $f }).Count
    }
}
