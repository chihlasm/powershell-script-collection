<#
    Pester 5 tests for the second round of Server Event Timeline features (pure logic in
    ServerEventTimeline.Core.ps1): the per-server summary, hide/only-this-event filters,
    collapsed repeats, recent server lists, the per-server total limit, log names for the
    console mode and the ticket note. No network, no UI, no real event log, no clipboard.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')

    function New-TestRow {
        param([string]$Server = 'APP01', [string]$Provider = 'Service Control Manager', [int]$Id = 7036,
            [string]$Log = 'System', [int]$Level = 4, [string]$Time = '2026-11-17 08:00:00', [int]$RecordId = 1,
            [string]$Message = 'Something happened.')
        $e = [PSCustomObject]@{
            TimeCreatedUtc = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Utc)
            Id = $Id; ProviderName = $Provider; Level = $Level; LogName = $Log; Message = $Message
            RecordId = $RecordId; UserSid = ''; MachineName = $Server
        }
        ConvertTo-TimelineRow -Server $Server -EventRecord $e -UtcOffsetMinutes 0
    }

    function New-TestStatus {
        param([string]$Server, [string]$State = 'Done', [int]$EventCount = 0, [object[]]$Logs = @(), [string]$Reason = '', [string]$Transport = 'WinRM')
        [PSCustomObject]@{ Server = $Server; State = $State; Transport = $Transport; Reason = $Reason; EventCount = $EventCount
            UtcOffsetMinutes = 0; Logs = $Logs }
    }

    $script:BusyRows = @(
        New-TestRow -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1 -Time '2026-11-17 08:01:00' -RecordId 1
        New-TestRow -Provider 'EventLog' -Id 6008 -Level 2 -Time '2026-11-17 08:01:05' -RecordId 2
        New-TestRow -Provider 'EventLog' -Id 6005 -Time '2026-11-17 08:01:06' -RecordId 3
        New-TestRow -Provider 'Microsoft-Windows-Kernel-General' -Id 12 -Time '2026-11-17 08:01:01' -RecordId 4
        New-TestRow -Id 7031 -Level 2 -Time '2026-11-17 08:02:00' -RecordId 5
        New-TestRow -Id 7031 -Level 2 -Time '2026-11-17 08:03:00' -RecordId 6
        New-TestRow -Id 7000 -Level 2 -Time '2026-11-17 08:04:00' -RecordId 7
        New-TestRow -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19 -Time '2026-11-17 08:05:00' -RecordId 8
        New-TestRow -Id 7036 -Time '2026-11-17 08:06:00' -RecordId 9
    )
}

Describe 'Get-TimelineSummaryLines (the strip above the grid)' {
    It 'counts one unexpected restart once, even though Windows logs it as both 41 and 6008' {
        $status = [ordered]@{ APP01 = (New-TestStatus -Server APP01 -EventCount 9) }
        $lines = @(Get-TimelineSummaryLines -Rows $script:BusyRows -Status $status)
        $lines[0] | Should -Be 'APP01: 1 unexpected restart, 3 service failures, 1 update installed, 1 Windows start'
    }

    It 'says when nothing was flagged, with the number of events read' {
        $rows = @(1..3 | ForEach-Object { New-TestRow -Server SQL01 -RecordId $_ })
        $status = [ordered]@{ SQL01 = (New-TestStatus -Server SQL01 -EventCount 1240) }
        @(Get-TimelineSummaryLines -Rows $rows -Status $status)[0] | Should -Be 'SQL01: nothing flagged in 1,240 events'
    }

    It 'says when a server had no events at all in the window' {
        $status = [ordered]@{ SQL01 = (New-TestStatus -Server SQL01 -EventCount 0) }
        @(Get-TimelineSummaryLines -Rows @() -Status $status)[0] | Should -Be 'SQL01: no events in this window'
    }

    It 'names unreachable and still-reading servers, and marks incomplete ones' {
        $gap = @([PSCustomObject]@{ Log = 'System'; Outcome = 'Capped'; Count = 5000; Reason = 'stopped at 5,000 events' })
        $status = [ordered]@{
            DC01  = (New-TestStatus -Server DC01 -State Unreachable -Reason 'Access denied')
            APP01 = (New-TestStatus -Server APP01 -State Querying)
            FS01  = (New-TestStatus -Server FS01 -State DoneWithGaps -EventCount 5000 -Logs $gap)
        }
        $lines = @(Get-TimelineSummaryLines -Rows @() -Status $status)
        $lines[0] | Should -Be "DC01: couldn't be read"
        $lines[1] | Should -Be 'APP01: still reading...'
        $lines[2] | Should -Be 'FS01: nothing flagged in 5,000 events (some logs incomplete)'
    }

    It 'singular and plural wording' {
        $rows = @(
            New-TestRow -Provider 'Disk' -Id 51 -Level 3 -RecordId 1
            New-TestRow -Provider 'Disk' -Id 153 -Level 3 -RecordId 2
            New-TestRow -Provider 'Application Error' -Id 1000 -Log Application -Level 2 -RecordId 3
        )
        $status = [ordered]@{ APP01 = (New-TestStatus -Server APP01 -EventCount 3) }
        @(Get-TimelineSummaryLines -Rows $rows -Status $status)[0] | Should -Be 'APP01: 2 disk errors, 1 app crash or hang'
    }
}

Describe 'Hide a source / only this event' {
    BeforeAll {
        $script:NoFilter = @{ MinLevel = 'All'; Server = '*'; Log = '*'; FlaggedOnly = $false; Text = '' }
        $script:Mixed = @(
            New-TestRow -Provider 'Microsoft-Windows-TaskScheduler' -Id 107 -Log 'Microsoft-Windows-TaskScheduler/Operational' -RecordId 1
            New-TestRow -Provider 'Microsoft-Windows-TaskScheduler' -Id 102 -Log 'Microsoft-Windows-TaskScheduler/Operational' -RecordId 2
            New-TestRow -Id 7036 -RecordId 3
            New-TestRow -Id 7031 -Level 2 -RecordId 4
        )
    }

    It 'hides every event from a hidden source' {
        $f = $script:NoFilter.Clone(); $f.HiddenSources = @('Microsoft-Windows-TaskScheduler')
        $out = @(Select-TimelineRows -Rows $script:Mixed -Filter $f)
        $out.Count | Should -Be 2
        @($out | Where-Object Provider -eq 'Microsoft-Windows-TaskScheduler').Count | Should -Be 0
        Test-RowMatchesFilter -Row $script:Mixed[0] -Filter $f | Should -BeFalse
        Test-RowMatchesFilter -Row $script:Mixed[2] -Filter $f | Should -BeTrue
    }

    It 'shows only one kind of event (source and ID) when asked' {
        $f = $script:NoFilter.Clone(); $f.EventKey = 'Service Control Manager|7031'
        $out = @(Select-TimelineRows -Rows $script:Mixed -Filter $f)
        $out.Count | Should -Be 1
        $out[0].EventId | Should -Be 7031
        Test-RowMatchesFilter -Row $script:Mixed[3] -Filter $f | Should -BeTrue
        Test-RowMatchesFilter -Row $script:Mixed[2] -Filter $f | Should -BeFalse
    }

    It 'builds the event key from a row' {
        Get-TimelineEventKey -Row $script:Mixed[3] | Should -Be 'Service Control Manager|7031'
    }

    It 'gives the exact time to search around, in the server''s local time' {
        $row = New-TestRow -Time '2026-11-17 08:04:37'
        Get-AroundEventText -Row $row | Should -Be '2026-11-17 08:04:37'
        $req = ConvertFrom-TimelineInputs -ServersText 'srv-fake-01' -Mode Around -AtText (Get-AroundEventText -Row $row) -PlusMinusMinutes 5
        $req.Ok | Should -BeTrue
        $req.Window.StartLocal | Should -Be ([datetime]'2026-11-17 07:59:37')
    }
}

Describe 'Group-TimelineRepeats (collapse repeats)' {
    BeforeAll {
        $script:Repeats = @(
            New-TestRow -Provider 'Microsoft-Windows-TaskScheduler' -Id 107 -Time '2026-11-17 08:00:00' -RecordId 1 -Message 'Task triggered on scheduler'
            New-TestRow -Id 7031 -Level 2 -Time '2026-11-17 08:00:30' -RecordId 2
            New-TestRow -Provider 'Microsoft-Windows-TaskScheduler' -Id 107 -Time '2026-11-17 08:01:00' -RecordId 3 -Message 'Task triggered on scheduler'
            New-TestRow -Id 7031 -Level 2 -Time '2026-11-17 08:01:30' -RecordId 4
            New-TestRow -Provider 'Microsoft-Windows-TaskScheduler' -Id 107 -Time '2026-11-17 08:02:00' -RecordId 5 -Message 'Task triggered on scheduler'
            New-TestRow -Server SQL01 -Provider 'Microsoft-Windows-TaskScheduler' -Id 107 -Time '2026-11-17 08:02:30' -RecordId 6
        )
        $script:Grouped = @(Group-TimelineRepeats -Rows $script:Repeats)
    }

    It 'turns the same unflagged event on the same server into one row at its first time' {
        $script:Grouped.Count | Should -Be 4
        $first = $script:Grouped[0]
        $first.RepeatCount | Should -Be 3
        $first.TimeUtc | Should -Be ([datetime]'2026-11-17 08:00:00')
        $first.LastTimeServerLocal | Should -Be ([datetime]'2026-11-17 08:02:00')
        $first.MessageFirstLine | Should -Be '[3x, last at 08:02:00] Task triggered on scheduler'
        @($first.Members).Count | Should -Be 3
    }

    It 'never collapses flagged events, so each crash keeps its own time' {
        @($script:Grouped | Where-Object EventId -eq 7031).Count | Should -Be 2
    }

    It 'keeps the same event on another server separate' {
        $sql = @($script:Grouped | Where-Object Server -eq 'SQL01')
        $sql.Count | Should -Be 1
        $sql[0].PSObject.Properties['Members'] | Should -BeNullOrEmpty
        $sql[0].MessageFirstLine | Should -Be 'Something happened.'
    }

    It 'leaves the original rows untouched' {
        $script:Repeats[0].MessageFirstLine | Should -Be 'Task triggered on scheduler'
    }

    It 'expands back to every original row for exports' {
        @(Expand-TimelineRepeats -Rows $script:Grouped).Count | Should -Be 6
    }
}

Describe 'Recent server lists' {
    It 'puts the newest list first, without repeating a list already there' {
        $r = @(Add-RecentServerList -Recent @('DC01', 'APP01, SQL01') -Servers @('sql01', 'app01'))
        $r | Should -Be @('sql01, app01', 'DC01')
    }

    It 'keeps at most the given number' {
        $r = @(Add-RecentServerList -Recent @('A', 'B', 'C') -Servers @('D') -Max 3)
        $r | Should -Be @('D', 'A', 'B')
    }

    It 'remembers recent lists and the save folder side by side' {
        $p = Join-Path $TestDrive 'cfg\settings.json'
        Save-TimelineSettings -Path $p -SaveFolder 'D:\Tickets'
        Save-TimelineSettings -Path $p -RecentServerLists @('APP01, SQL01', 'DC01')
        $s = Read-TimelineSettings -Path $p
        $s.SaveFolder | Should -Be 'D:\Tickets'
        @($s.RecentServerLists) | Should -Be @('APP01, SQL01', 'DC01')
    }

    It 'reads no recent lists from an old settings file' {
        $p = Join-Path $TestDrive 'old.json'
        Set-Content -LiteralPath $p -Value '{ "SaveFolder": "D:\\X" }'
        @((Read-TimelineSettings -Path $p).RecentServerLists).Count | Should -Be 0
    }
}

Describe 'Per-server total limit' {
    It 'reads the total limit from the window' {
        $req = ConvertFrom-TimelineInputs -ServersText 'srv-fake-01' -Mode Relative -TotalCapText '120000'
        $req.Ok | Should -BeTrue
        $req.TotalCap | Should -Be 120000
    }

    It 'defaults to 50,000' {
        (ConvertFrom-TimelineInputs -ServersText 'srv-fake-01' -Mode Relative).TotalCap | Should -Be 50000
    }

    It 'rejects a total limit that is not a whole number above 0' {
        $req = ConvertFrom-TimelineInputs -ServersText 'srv-fake-01' -Mode Relative -TotalCapText 'lots'
        $req.Ok | Should -BeFalse
        $req.Message | Should -BeLike '*total*whole number*'
    }
}

Describe 'Resolve-TimelineLogNames (console mode)' {
    It 'accepts the checkbox labels or the log names, in any case' {
        @(Resolve-TimelineLogNames -Names @('system', 'Task Scheduler', 'Microsoft-Windows-GroupPolicy/Operational')) |
            Should -Be @('System', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-GroupPolicy/Operational')
    }

    It 'passes any other log name through, once' {
        @(Resolve-TimelineLogNames -Names @('Directory Service', 'directory service')) | Should -Be @('Directory Service')
    }

    It 'gives the default logs when none are named' {
        $d = @(Resolve-TimelineLogNames -Names @())
        $d | Should -Contain 'System'
        $d | Should -Contain 'Application'
        $d | Should -Not -Contain 'Security'
    }
}

Describe 'New-TimelineTicketNote' {
    BeforeAll {
        $script:NoteRows = @($script:BusyRows) + @(New-TestRow -Server SQL01 -RecordId 20)
        $gapLogs = @(
            [PSCustomObject]@{ Log = 'System'; Outcome = 'Read'; Count = 9; Reason = '' }
            [PSCustomObject]@{ Log = 'Application'; Outcome = 'Capped'; Count = 5000; Reason = 'stopped at 5,000 events' }
            [PSCustomObject]@{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Outcome = 'Skipped'; Count = 0; Reason = 'Task Scheduler log is turned off on APP01' }
        )
        $script:NoteStatus = [ordered]@{
            APP01 = (New-TestStatus -Server APP01 -State DoneWithGaps -EventCount 5009 -Logs $gapLogs)
            SQL01 = (New-TestStatus -Server SQL01 -State Done -EventCount 12 -Logs @([PSCustomObject]@{ Log = 'System'; Outcome = 'Read'; Count = 12; Reason = '' }))
            DC01  = (New-TestStatus -Server DC01 -State Unreachable -Transport '' -Reason "Access denied on DC01: check you're an admin there, or use Run as.")
        }
        $script:Note = New-TimelineTicketNote -Status $script:NoteStatus -Rows $script:NoteRows -WindowText 'Around 2026-11-17 08:00 +/- 15 min' -Now ([datetime]'2026-11-17 09:00')
    }

    It 'is a Server-EventTimeline note whose headline says the window and how many events were flagged' {
        $script:Note.Tool | Should -Be 'Server-EventTimeline'
        $script:Note.Headline | Should -BeLike '*Around 2026-11-17 08:00 +/- 15 min*'
        $script:Note.Headline | Should -BeLike '*8 flagged events*'
    }

    It 'lists serious findings as problems and the rest as warnings or info' {
        $script:Note.Checked | Should -Contain 'PROBLEM: APP01: 1 unexpected restart'
        $script:Note.Checked | Should -Contain 'WARNING: APP01: 3 service failures'
        $script:Note.Checked | Should -Contain 'INFO: APP01: 1 update installed, 1 Windows start'
    }

    It 'lists the first flagged events with their server-local time' {
        ($script:Note.Checked -join "`n") | Should -BeLike '*APP01 2026-11-17 08:01:00 (server local): Restarted without a clean shutdown*Kernel-Power 41*'
    }

    It 'rules out a server only when every log was read' {
        $script:Note.RuledOut | Should -Contain 'SQL01: no flagged events in 12 events'
        @($script:Note.RuledOut | Where-Object { $_ -like 'APP01*' }).Count | Should -Be 0
    }

    It 'puts unreachable servers, incomplete logs and missing logs under Could not check' {
        $could = $script:Note.CouldNotCheck -join "`n"
        $could | Should -BeLike "*DC01: couldn't be read - Access denied on DC01*"
        $could | Should -BeLike '*APP01 Application: stopped at 5,000 events*'
        $could | Should -BeLike '*Task Scheduler log is turned off on APP01*'
    }

    It 'suggests next steps for what it found' {
        ($script:Note.NextSteps -join "`n") | Should -BeLike '*power*APP01*unexpected restart*'
        ($script:Note.NextSteps -join "`n") | Should -BeLike '*DC01*'
        ($script:Note.NextSteps -join "`n") | Should -BeLike '*narrower window*'
    }

    It 'stamps the servers and says nothing was changed' {
        $script:Note.Stamp.Changed | Should -BeFalse
        $script:Note.Stamp.Scope | Should -Be 'APP01, SQL01, DC01'
        $text = @(ConvertTo-TicketNoteText -Note $script:Note -PasteSafe) -join "`n"
        $text | Should -BeLike '*Changed anything: No*'
    }
}

Describe 'HTML report verdict' {
    It 'puts the per-server summary at the top of the report' {
        $ctx = @{ WindowText = 'The last 60 minutes'; Servers = @('APP01'); Logs = @('System'); FiltersText = 'none'; GeneratedAt = (Get-Date)
            ServerOutcomes = @(); Summary = @('APP01: 1 unexpected restart <script>') }
        $html = ConvertTo-TimelineHtml -Rows @() -Context $ctx
        $html | Should -BeLike '*<h2>What was found</h2>*APP01: 1 unexpected restart &lt;script&gt;*How each server went*'
    }
}
