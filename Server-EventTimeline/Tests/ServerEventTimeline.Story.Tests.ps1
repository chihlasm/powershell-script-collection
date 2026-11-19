<#
    Pester 5 tests for ServerEventTimeline.Story.ps1: the plain-English "What happened" story
    and the timeline picture's layout. Pure logic: no network, no UI, no real event logs.
    Run:  pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests
#>

BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1')

    $script:Rec = 0
    # One row as ConvertTo-TimelineRow makes it. Times are server local; the server is UTC-5
    # unless -OffsetMinutes says otherwise. The flag comes from the real catalog.
    function New-TestRow {
        param([string]$Server = 'AD-01', [string]$Time, [string]$Log = 'System', [string]$Provider = 'Service Control Manager',
            [int]$Id = 7036, [int]$Level = 4, [string]$Message = 'Something happened', [int]$OffsetMinutes = -300)
        $script:Rec++
        $local = [datetime]::SpecifyKind([datetime]$Time, [DateTimeKind]::Unspecified)
        $flag = Get-EventFlag -Log $Log -Provider $Provider -Id $Id
        [PSCustomObject]@{
            Server = $Server; Log = $Log
            TimeUtc = [datetime]::SpecifyKind($local.AddMinutes(-$OffsetMinutes), [DateTimeKind]::Utc)
            TimeServerLocal = $local; Level = $Level; LevelName = 'x'
            FlagCategory = if ($flag) { $flag.Category } else { '' }; Flag = if ($flag) { $flag.Label } else { '' }
            Provider = $Provider; EventId = $Id; Message = $Message; MessageFirstLine = $Message
            RecordId = $script:Rec; User = ''; Machine = $Server
        }
    }
    function Disk153 { param($Time, $Server = 'AD-01') New-TestRow -Server $Server -Time $Time -Provider 'Disk' -Id 153 -Level 3 -Message 'The IO operation was retried.' }
    function Sort-Rows { param($Rows) @($Rows | Sort-Object TimeUtc) }
    function Events { param($Story) @($Story.Lines | Where-Object Kind -eq 'Event') }
}

Describe 'Get-TimelineStory' {
    It 'returns no lines and MoreCount 0 for no rows' {
        $s = Get-TimelineStory -Rows @()
        @($s.Lines).Count | Should -Be 0
        $s.MoreCount | Should -Be 0
    }

    It 'returns no lines when nothing is flagged' {
        $s = Get-TimelineStory -Rows @((New-TestRow -Time '2026-11-18 17:00'), (New-TestRow -Time '2026-11-18 17:01' -Level 2))
        @($s.Lines).Count | Should -Be 0
    }

    It 'returns one line for one flagged row' {
        $s = Get-TimelineStory -Rows @(New-TestRow -Time '2026-11-18 17:57' -Log Application -Provider 'Application Error' -Id 1000 -Level 2 -Message 'Faulting application name: dfsrs.exe')
        @($s.Lines).Count | Should -Be 1
        $s.Lines[0].Kind | Should -Be 'Event'
        $s.Lines[0].Text | Should -Be 'Application crashed'
        $s.Lines[0].Detail | Should -Be 'Faulting application name: dfsrs.exe'
        $s.Lines[0].Category | Should -Be 'AppCrash'
        $s.Lines[0].Server | Should -Be 'AD-01'
    }

    It 'leaves out the WER crash report and a lone clean shutdown' {
        $rows = @(
            New-TestRow -Time '2026-11-18 17:00' -Log Application -Provider 'Windows Error Reporting' -Id 1001
            New-TestRow -Time '2026-11-18 17:30' -Provider 'EventLog' -Id 6006
        )
        @((Get-TimelineStory -Rows $rows).Lines).Count | Should -Be 0
    }

    It 'folds the same flag on one server within 10 minutes' {
        $rows = @((Disk153 '2026-11-18 17:49'), (Disk153 '2026-11-18 17:50:30'), (Disk153 '2026-11-18 17:52'), (Disk153 '2026-11-18 18:05'))
        $lines = Events (Get-TimelineStory -Rows $rows)
        $lines.Count | Should -Be 2
        $lines[0].Count | Should -Be 3
        $lines[0].Text | Should -BeLike '* (3 in 3 min)'
        $lines[0].RowId | Should -Be (Get-TimelineRowId -Row $rows[0])
        $lines[1].Count | Should -Be 1
    }

    It 'does not fold across servers' {
        $rows = Sort-Rows @((Disk153 '2026-11-18 17:49'), (Disk153 '2026-11-18 17:50' -Server 'AD-03'))
        (Events (Get-TimelineStory -Rows $rows)).Count | Should -Be 2
    }

    It 'folds an unexpected restart and the start into one line' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 17:58:03' -Level 2 -Message 'The DFS Replication service terminated unexpectedly.' -Provider 'Other' -Id 1
            New-TestRow -Time '2026-11-18 18:03:58' -Provider 'Microsoft-Windows-Kernel-General' -Id 12
            New-TestRow -Time '2026-11-18 18:04:00' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1
            New-TestRow -Time '2026-11-18 18:04:01' -Provider 'EventLog' -Id 6008 -Level 2
            New-TestRow -Time '2026-11-18 18:04:02' -Provider 'EventLog' -Id 6005
        )
        $lines = Events (Get-TimelineStory -Rows $rows)
        $lines.Count | Should -Be 1
        $lines[0].Text | Should -Be 'Restarted without a clean shutdown - back up at 18:03'
        $lines[0].Detail | Should -BeLike '*(no events for about 6 min before that)*'
        $lines[0].Category | Should -Be 'Restart'
    }

    It 'calls it a blue screen when the bugcheck report is part of the restart' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 18:04:00' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1
            New-TestRow -Time '2026-11-18 18:04:02' -Provider 'EventLog' -Id 6005
            New-TestRow -Time '2026-11-18 18:05:30' -Provider 'Microsoft-Windows-WER-SystemErrorReporting' -Id 1001 -Level 2
        )
        $lines = Events (Get-TimelineStory -Rows $rows)
        $lines.Count | Should -Be 1
        $lines[0].Text | Should -Be 'Restarted after a blue screen (bugcheck) - back up at 18:04'
        $lines[0].Category | Should -Be 'Bugcheck'
    }

    It 'keeps the restart line without "back up at" when no start event is in the window' {
        $rows = Sort-Rows @(New-TestRow -Time '2026-11-18 18:04:00' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1)
        $lines = Events (Get-TimelineStory -Rows $rows)
        $lines.Count | Should -Be 1
        $lines[0].Text | Should -Be 'Restarted without a clean shutdown'
    }

    It 'folds a requested restart' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 02:00:00' -Provider 'User32' -Id 1074 -Message 'The process TiWorker.exe has initiated the restart'
            New-TestRow -Time '2026-11-18 02:00:20' -Provider 'EventLog' -Id 6006
            New-TestRow -Time '2026-11-18 02:03:10' -Provider 'EventLog' -Id 6005
        )
        $lines = Events (Get-TimelineStory -Rows $rows)
        $lines.Count | Should -Be 1
        $lines[0].Text | Should -Be 'Restarted on request - back up at 02:03'
        $lines[0].Detail | Should -Be 'The process TiWorker.exe has initiated the restart'
    }

    It 'counts unrecognised errors in the 5 minutes before a crash' {
        $rows = @(foreach ($m in 0..6) { New-TestRow -Time ('2026-11-18 17:53:{0:00}' -f ($m * 8)) -Level 2 -Provider 'Ntfs' -Id 999 })
        $rows += New-TestRow -Time '2026-11-18 17:16' -Level 2 -Provider 'Ntfs' -Id 999
        $rows += New-TestRow -Time '2026-11-18 17:57' -Log Application -Provider 'Application Error' -Id 1000 -Level 2 -Message 'Faulting application name: dfsrs.exe'
        $lines = Events (Get-TimelineStory -Rows (Sort-Rows $rows))
        $lines[0].Detail | Should -BeLike '*(7 errors in the 5 minutes before)*'
    }

    It 'puts a gap line between lines 10 minutes or more apart' {
        $rows = @((Disk153 '2026-11-18 17:00'), (New-TestRow -Time '2026-11-18 17:25' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19))
        $s = Get-TimelineStory -Rows $rows
        @($s.Lines).Count | Should -Be 3
        $s.Lines[1].Kind | Should -Be 'Gap'
        $s.Lines[1].Text | Should -Be '25 minutes later'

        $close = @((Disk153 '2026-11-18 17:00'), (New-TestRow -Time '2026-11-18 17:09' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19))
        @((Get-TimelineStory -Rows $close).Lines | Where-Object Kind -eq 'Gap').Count | Should -Be 0
    }

    It 'orders lines by UTC across servers and shows server-local time' {
        # AD-03 is UTC+0: 22:51 there is 17:51 on AD-01 (UTC-5), between AD-01's two events.
        $rows = Sort-Rows @(
            (Disk153 '2026-11-18 17:49')
            (New-TestRow -Server 'AD-03' -Time '2026-11-18 22:51' -Provider 'Microsoft-Windows-Kernel-General' -Id 1 -OffsetMinutes 0)
            (New-TestRow -Time '2026-11-18 17:55' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19)
        )
        $lines = Events (Get-TimelineStory -Rows $rows)
        @($lines | ForEach-Object Server) | Should -Be @('AD-01', 'AD-03', 'AD-01')
        $lines[1].TimeServerLocal | Should -Be ([datetime]'2026-11-18 22:51')
    }

    It 'sorts rows it is given out of order' {
        $rows = @((New-TestRow -Time '2026-11-18 17:55' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19), (Disk153 '2026-11-18 17:49'))
        (Events (Get-TimelineStory -Rows $rows))[0].Category | Should -Be 'Disk'
    }

    It 'stops at MaxLines and reports the rest' {
        $rows = @(foreach ($i in 0..69) { Disk153 (([datetime]'2026-11-18 00:00').AddMinutes($i * 11).ToString('yyyy-MM-dd HH:mm')) })
        $s = Get-TimelineStory -Rows $rows -MaxLines 60
        (Events $s).Count | Should -Be 60
        $s.MoreCount | Should -Be 10
        $s.Lines[-1].Kind | Should -Be 'Event'
    }
}

Describe 'Get-TimelineRowId and Format-TimelineGap' {
    It 'Get-TimelineRowId names one row' {
        Get-TimelineRowId -Row ([PSCustomObject]@{ Server = 'AD-01'; Log = 'System'; RecordId = 4242 }) | Should -Be 'AD-01|System|4242'
    }

    It 'Format-TimelineGap words the gap' {
        Format-TimelineGap -Minutes 10 | Should -Be '10 minutes later'
        Format-TimelineGap -Minutes 60 | Should -Be '1 hour later'
        Format-TimelineGap -Minutes 180 | Should -Be '3 hours later'
        Format-TimelineGap -Minutes 2880 | Should -Be '2 days later'
    }
}

Describe 'The story in the ticket note and the HTML report' {
    BeforeAll {
        function New-NoteStatus {
            param([string[]]$Servers = @('AD-01'))
            $st = [ordered]@{}
            foreach ($s in $Servers) {
                $st[$s] = [PSCustomObject]@{ Server = $s; State = 'Done'; Transport = 'WinRM'; EventCount = 10; Reason = ''
                    Logs = @([PSCustomObject]@{ Log = 'System'; Outcome = 'Read'; Count = 10; Reason = '' }) }
            }
            $st
        }
        function New-ReportContext {
            param([string[]]$Servers = @('AD-01'))
            @{ WindowText = 'Around 2026-11-18 17:50 +/- 15 min'; Servers = $Servers; Logs = @('System'); FiltersText = 'none'
                GeneratedAt = [datetime]'2026-11-18 18:10'; Summary = @('AD-01: 3 disk errors'); ServerOutcomes = @() }
        }
    }

    It 'the ticket note lists story lines instead of raw flagged rows' {
        $rows = @((Disk153 '2026-11-18 17:49'), (Disk153 '2026-11-18 17:50:30'), (Disk153 '2026-11-18 17:52'))
        $note = New-TimelineTicketNote -Status (New-NoteStatus) -Rows $rows -WindowText 'w' -Now ([datetime]'2026-11-18 18:00')
        $text = $note.Checked -join "`n"
        $text | Should -BeLike '*AD-01 2026-11-18 17:49 (server local): Disk I/O had to be retried (3 in 3 min)*'
        $text | Should -Not -BeLike '*Disk 153*'
    }

    It 'the ticket note keeps 15 story lines and says how many more' {
        $rows = @(foreach ($i in 0..19) { Disk153 (([datetime]'2026-11-18 00:00').AddMinutes($i * 11).ToString('yyyy-MM-dd HH:mm')) })
        $note = New-TimelineTicketNote -Status (New-NoteStatus) -Rows $rows -WindowText 'w' -Now ([datetime]'2026-11-18 18:00')
        @($note.Checked | Where-Object { $_ -like '*(server local):*' }).Count | Should -Be 15
        ($note.Checked -join "`n") | Should -BeLike '*... and 5 more flagged events (see the report)*'
        ($note.Checked -join "`n") | Should -Not -BeLike '*minutes later*'
    }

    It 'Format-TimelineStoryText gives one line per event and no gap or detail lines' {
        $rows = @((Disk153 '2026-11-18 17:00'), (New-TestRow -Time '2026-11-18 17:25' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19 -Message 'Installed KB1'))
        $lines = @(Format-TimelineStoryText -Story (Get-TimelineStory -Rows $rows))
        $lines | Should -Be @('AD-01 2026-11-18 17:00 (server local): Disk I/O had to be retried', 'AD-01 2026-11-18 17:25 (server local): Windows Update installed an update')
    }

    It 'the HTML report has a What happened section after What was found' {
        $html = ConvertTo-TimelineHtml -Rows @(Disk153 '2026-11-18 17:49') -Context (New-ReportContext)
        $at = $html.IndexOf('<h2>What happened</h2>')
        $at | Should -BeGreaterThan $html.IndexOf('<h2>What was found</h2>')
        $html.Substring($at) | Should -BeLike '*Disk I/O had to be retried*'
    }

    It 'the HTML story is built from the rows the report was given' {
        $html = ConvertTo-TimelineHtml -Rows @(Disk153 '2026-11-18 17:49' -Server 'AD-03') -Context (New-ReportContext -Servers 'AD-01', 'AD-03')
        $section = $html.Substring($html.IndexOf('<h2>What happened</h2>'))
        $section = $section.Substring(0, $section.IndexOf('<h2>', 5))
        $section | Should -BeLike '*AD-03*'
        $section | Should -Not -BeLike '*AD-01*'
    }

    It 'the HTML story encodes text' {
        $row = New-TestRow -Time '2026-11-18 17:57' -Log Application -Provider 'Application Error' -Id 1000 -Level 2 -Message '<script>alert(1)</script>'
        $html = ConvertTo-TimelineHtml -Rows @($row) -Context (New-ReportContext)
        $html | Should -Not -BeLike '*<script>*'
        $html | Should -BeLike '*&lt;script&gt;*'
    }
}
