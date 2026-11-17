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
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 1) -UtcOffsetMinutes 0).LevelName | Should -Be 'Critical'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 2) -UtcOffsetMinutes 0).LevelName | Should -Be 'Error'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 3) -UtcOffsetMinutes 0).LevelName | Should -Be 'Warning'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 0) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
        (ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Level 4) -UtcOffsetMinutes 0).LevelName | Should -Be 'Information'
    }

    It 'explains a missing message instead of leaving it blank' {
        $row = ConvertTo-TimelineRow -Server SQL01 -Event (New-FakeEvent -Message $null -Provider MSSQLSERVER -Id 17883 -Log Application) -UtcOffsetMinutes 0
        $expected = "(No message text: the event's provider isn't installed on this workstation. Event 17883 from MSSQLSERVER.)"
        $row.Message | Should -Be $expected
        $row.MessageFirstLine | Should -Be $expected
    }

    It 'uses the first non-empty line as the short message' {
        $row = ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Message "`r`n  `r`nFirst real line`r`nSecond") -UtcOffsetMinutes 0
        $row.MessageFirstLine | Should -Be 'First real line'
    }

    It 'shows server-local time as UTC plus the offset and fills the flag' {
        $row = ConvertTo-TimelineRow -Server APP01 -Event (New-FakeEvent -Provider User32 -Id 1074) -UtcOffsetMinutes -300
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
