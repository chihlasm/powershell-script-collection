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

Describe 'Get-TimelineStripModel (the picture strip)' {
    BeforeAll {
        $script:S0 = [datetime]::SpecifyKind([datetime]'2026-11-18 22:45', [DateTimeKind]::Utc)
        $script:S1 = [datetime]::SpecifyKind([datetime]'2026-11-18 23:05', [DateTimeKind]::Utc)
        function Get-Strip { param($Rows, [string[]]$Servers = @('AD-01', 'AD-03', 'AD-04'), [double]$Width = 800)
            Get-TimelineStripModel -Rows @($Rows) -Servers $Servers -StartUtc $script:S0 -EndUtc $script:S1 -Width $Width }
    }

    It 'gives each server a lane, in the order given' {
        $m = Get-Strip @()
        @($m.Lanes | ForEach-Object Server) | Should -Be @('AD-01', 'AD-03', 'AD-04')
        @($m.Lanes | ForEach-Object Index) | Should -Be @(0, 1, 2)
    }

    It 'draws a mark only for flagged rows the story counts' {
        $rows = @(
            (Disk153 '2026-11-18 17:50')
            (New-TestRow -Time '2026-11-18 17:51' -Log Application -Provider 'Windows Error Reporting' -Id 1001)
            (New-TestRow -Time '2026-11-18 17:52')
        )
        $m = Get-Strip $rows
        @($m.Marks).Count | Should -Be 1
        $m.Marks[0].Shape | Should -Be 'Triangle'
        $m.Marks[0].Color | Should -Be '#E0B43A'
        $m.Marks[0].Lane | Should -Be 0
        $m.Marks[0].X | Should -Be 200
        $m.Marks[0].RowId | Should -Be (Get-TimelineRowId -Row $rows[0])
        (Get-TimelineStripToolTip -Item $m.Marks[0]) | Should -BeLike 'Disk I/O had to be retried*AD-01*2026-11-18 17:50:00*Disk 153*'
    }

    It 'picks the symbol and colour by category, grey for anything unknown' {
        $crash = New-TestRow -Time '2026-11-18 17:57' -Log Application -Provider 'Application Error' -Id 1000 -Level 2
        $odd = New-TestRow -Time '2026-11-18 17:58' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19
        $odd.FlagCategory = 'Lockout'
        $m = Get-Strip @($crash, $odd)
        $m.Marks[0].Shape | Should -Be 'Cross'
        $m.Marks[0].Color | Should -Be '#E06C5A'
        $m.Marks[1].Shape | Should -Be 'Circle'
        $m.Marks[1].Color | Should -Be '#8B94A3'
    }

    It 'merges marks of one kind that would sit on the same spot, and says how many' {
        $rows = @(foreach ($s in 0..4) { Disk153 ('2026-11-18 17:50:0{0}' -f $s) })
        $m = Get-Strip $rows
        @($m.Marks).Count | Should -Be 1
        (Get-TimelineStripToolTip -Item $m.Marks[0]) | Should -BeLike '5 x Disk I/O had to be retried*'
    }

    It 'puts errors into slices about 6 px wide, one dot per slice, with the count' {
        $rows = @(foreach ($i in 0..299) { New-TestRow -Time '2026-11-18 17:50' -Level 2 -Provider 'Ntfs' -Id 5 })
        $rows += @(foreach ($i in 0..4) { New-TestRow -Time '2026-11-18 17:50' -Level 4 })
        $m = Get-Strip $rows
        @($m.Dots).Count | Should -Be 1
        $m.Dots[0].Count | Should -Be 300
        $m.Dots[0].Opacity | Should -Be 1.0
        (Get-TimelineStripToolTip -Item $m.Dots[0]) | Should -BeLike '300 errors*AD-01*'
        @($m.Marks).Count | Should -Be 0
    }

    It 'makes a lone error dot faint' {
        (Get-Strip @(New-TestRow -Time '2026-11-18 17:50' -Level 2 -Provider 'Ntfs' -Id 5)).Dots[0].Opacity | Should -Be 0.35
    }

    It 'draws a down bar from the last event before an unexpected restart to the restart' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 17:58' -Level 2 -Provider 'Other' -Id 1
            New-TestRow -Time '2026-11-18 18:04' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1
            New-TestRow -Time '2026-11-18 18:04:02' -Provider 'EventLog' -Id 6005
        )
        $m = Get-Strip $rows
        @($m.DownBars).Count | Should -Be 1
        $m.DownBars[0].X1 | Should -Be 520
        $m.DownBars[0].X2 | Should -Be 760
        $m.DownBars[0].Text | Should -Be 'no events for about 6 min, then restarted without a clean shutdown'
    }

    It 'draws no down bar for a requested restart' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 17:58' -Provider 'User32' -Id 1074
            New-TestRow -Time '2026-11-18 18:01' -Provider 'EventLog' -Id 6005
        )
        @((Get-Strip $rows).DownBars).Count | Should -Be 0
    }

    It 'labels the axis in local time when every server shares an offset, in UTC when they differ' {
        $same = @((Disk153 '2026-11-18 17:50'), (Disk153 '2026-11-18 17:55' -Server 'AD-03'))
        $m = Get-Strip $same
        $m.AxisIsUtc | Should -BeFalse
        @($m.Ticks | ForEach-Object Label) | Should -Contain '17:50'

        $mixed = @((Disk153 '2026-11-18 17:50'), (New-TestRow -Server 'AD-03' -Time '2026-11-18 22:55' -Provider 'Microsoft-Windows-Kernel-General' -Id 1 -OffsetMinutes 0))
        $m2 = Get-Strip $mixed
        $m2.AxisIsUtc | Should -BeTrue
        @($m2.Ticks | ForEach-Object Label) | Should -Contain '22:50'
    }

    It 'places ticks across the window, left to right' {
        $m = Get-Strip @(Disk153 '2026-11-18 17:50')
        $xs = @($m.Ticks | ForEach-Object X)
        $xs.Count | Should -BeGreaterThan 2
        $xs.Count | Should -BeLessThan 10
        ($xs | Sort-Object) | Should -Be $xs
        $xs[0] | Should -BeGreaterOrEqual 0
        $xs[-1] | Should -BeLessOrEqual 800
    }

    It 'drops rows outside the window and servers without a lane' {
        $m = Get-Strip @((Disk153 '2026-11-18 16:00'), (Disk153 '2026-11-18 17:50' -Server 'AD-99'))
        @($m.Marks).Count | Should -Be 0
    }

    It 'works for one row and for no rows' {
        $one = Get-Strip @(New-TestRow -Time '2026-11-18 17:50')
        , $one.Marks | Should -BeOfType [object[]]
        , $one.Dots | Should -BeOfType [object[]]
        , $one.DownBars | Should -BeOfType [object[]]
        @($one.Lanes).Count | Should -Be 3
        $none = Get-TimelineStripModel -Rows @() -Servers @('AD-01') -StartUtc $script:S0 -EndUtc $script:S1 -Width 800
        @($none.Marks).Count | Should -Be 0
        @($none.Lanes).Count | Should -Be 1
    }

    It 'the store path draws the same picture, and finds the quiet gap from information rows' {
        $rows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 17:50' -Level 2 -Provider 'Ntfs' -Id 5
            New-TestRow -Time '2026-11-18 17:58'
            New-TestRow -Time '2026-11-18 18:04' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1
            New-TestRow -Time '2026-11-18 18:04:02' -Provider 'EventLog' -Id 6005
            (Disk153 '2026-11-18 17:52' -Server 'AD-03')
        )
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows $rows
        $viaStore = Get-TimelineStoreStripModel -Store $store -Filter @{ MinLevel = 'All' } -Servers @('AD-01', 'AD-03', 'AD-04') -StartUtc $script:S0 -EndUtc $script:S1 -Width 800
        $direct = Get-Strip $rows
        @($viaStore.Marks | ForEach-Object { '{0}|{1}|{2}' -f $_.Lane, $_.X, $_.Shape }) | Should -Be @($direct.Marks | ForEach-Object { '{0}|{1}|{2}' -f $_.Lane, $_.X, $_.Shape })
        @($viaStore.Dots).Count | Should -Be @($direct.Dots).Count
        # The last event before the restart is an Information row (17:58), not a notable one.
        $viaStore.DownBars[0].X1 | Should -Be 520
        $viaStore.DownBars[0].X2 | Should -Be 760
        $viaStore.AxisIsUtc | Should -BeFalse
    }

    It 'the store path follows the filters' {
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows @((Disk153 '2026-11-18 17:50'), (New-TestRow -Time '2026-11-18 17:55' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19))
        $m = Get-TimelineStoreStripModel -Store $store -Filter @{ MinLevel = 'Warning' } -Servers @('AD-01') -StartUtc $script:S0 -EndUtc $script:S1 -Width 800
        @($m.Marks | ForEach-Object Shape) | Should -Be @('Triangle')
    }

    It 'builds the picture for a 40,000-row search in under 100 ms' {
        $servers = 'AD-01', 'AD-02', 'AD-03', 'AD-04'
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 40000; $i++) {
            $t = $script:S0.AddMilliseconds($i * 30)
            $kind = $i % 100
            $level = if ($kind -lt 10) { 2 } else { 4 }
            $flag = if ($kind -eq 50) { 'Disk I/O had to be retried' } else { '' }
            $rows.Add([PSCustomObject]@{ Server = $servers[$i % 4]; Log = 'System'; TimeUtc = $t; TimeServerLocal = $t.AddHours(-5); Level = $level
                    Flag = $flag; FlagCategory = $(if ($flag) { 'Disk' } else { '' }); Provider = 'Disk'; EventId = 153; RecordId = $i; Message = ''; MessageFirstLine = '' })
        }
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows $rows.ToArray()
        $filter = @{ MinLevel = 'All'; Server = '*'; Log = '*' }
        [void](Get-TimelineStoreStripModel -Store $store -Filter $filter -Servers $servers -StartUtc $script:S0 -EndUtc $script:S1 -Width 900)
        $best = [double]::MaxValue
        foreach ($try in 1..3) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            [void](Get-TimelineStoreStripModel -Store $store -Filter $filter -Servers $servers -StartUtc $script:S0 -EndUtc $script:S1 -Width 900)
            $best = [Math]::Min($best, $sw.Elapsed.TotalMilliseconds)
        }
        $best | Should -BeLessThan 100
    }

    It 'builds the picture for a 40,000-row search in under 100 ms on Windows PowerShell 5.1' -Skip:(-not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
        $core = Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1'
        $script = @"
`$ErrorActionPreference = 'Stop'
. '$core'
`$s0 = [datetime]::SpecifyKind([datetime]'2026-11-18 22:45', [DateTimeKind]::Utc)
`$servers = 'AD-01', 'AD-02', 'AD-03', 'AD-04'
`$rows = New-Object System.Collections.Generic.List[object]
for (`$i = 0; `$i -lt 40000; `$i++) {
    `$t = `$s0.AddMilliseconds(`$i * 30); `$kind = `$i % 100
    `$flag = if (`$kind -eq 50) { 'Disk I/O had to be retried' } else { '' }
    `$rows.Add([PSCustomObject]@{ Server = `$servers[`$i % 4]; Log = 'System'; TimeUtc = `$t; TimeServerLocal = `$t.AddHours(-5); Level = `$(if (`$kind -lt 10) { 2 } else { 4 })
        Flag = `$flag; FlagCategory = `$(if (`$flag) { 'Disk' } else { '' }); Provider = 'Disk'; EventId = 153; RecordId = `$i; Message = ''; MessageFirstLine = '' })
}
`$store = New-TimelineRowStore
Add-TimelineRows -Store `$store -NewRows `$rows.ToArray()
`$e = `$s0.AddMinutes(20); `$f = @{ MinLevel = 'All'; Server = '*'; Log = '*' }
[void](Get-TimelineStoreStripModel -Store `$store -Filter `$f -Servers `$servers -StartUtc `$s0 -EndUtc `$e -Width 900)
`$best = [double]::MaxValue
foreach (`$try in 1..3) { `$sw = [Diagnostics.Stopwatch]::StartNew(); [void](Get-TimelineStoreStripModel -Store `$store -Filter `$f -Servers `$servers -StartUtc `$s0 -EndUtc `$e -Width 900); `$best = [Math]::Min(`$best, `$sw.Elapsed.TotalMilliseconds) }
[int]`$best
"@
        $file = Join-Path $TestDrive 'strip-timing.ps1'
        Set-Content -LiteralPath $file -Value $script -Encoding UTF8
        $out = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | ForEach-Object { "$_" })
        $last = $out | Select-Object -Last 1
        # A number, not an error that happens to convert to 0.
        $last | Should -Match '^\d+$' -Because ($out -join "`n")
        [int]$last | Should -BeLessThan 100
    }
}

Describe 'The picture in the HTML report' {
    BeforeAll {
        $script:R0 = [datetime]::SpecifyKind([datetime]'2026-11-18 22:45', [DateTimeKind]::Utc)
        $script:R1 = [datetime]::SpecifyKind([datetime]'2026-11-18 23:05', [DateTimeKind]::Utc)
        $script:ReportRows = Sort-Rows @(
            (Disk153 '2026-11-18 17:50')
            (New-TestRow -Time '2026-11-18 17:51' -Level 2 -Provider 'Ntfs' -Id 5)
            (New-TestRow -Time '2026-11-18 17:58' -Level 2 -Provider 'Other' -Id 9)
            (New-TestRow -Time '2026-11-18 18:04' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1)
            (New-TestRow -Server 'AD-03' -Time '2026-11-18 17:55' -Provider 'Microsoft-Windows-WindowsUpdateClient' -Id 19)
        )
        function New-SvgContext {
            param([string[]]$Servers = @('AD-01', 'AD-03'), [switch]$NoWindow)
            $c = @{ WindowText = 'w'; Servers = $Servers; Logs = @('System'); FiltersText = 'none'; GeneratedAt = [datetime]'2026-11-18 18:10'
                Summary = @(); ServerOutcomes = @() }
            if (-not $NoWindow) { $c.StartUtc = $script:R0; $c.EndUtc = $script:R1 }
            $c
        }
    }

    It 'has a title on every mark, dot, down bar and server name' {
        $m = Get-TimelineStripModel -Rows $script:ReportRows -Servers @('AD-01', 'AD-03') -StartUtc $script:R0 -EndUtc $script:R1 -Width 900
        $svg = ConvertTo-TimelineStripSvg -Model $m -Width 900
        ([regex]::Matches($svg, '<title>')).Count | Should -Be (@($m.Marks).Count + @($m.Dots).Count + @($m.DownBars).Count + @($m.Lanes).Count)
        $svg | Should -BeLike '<svg*'
        $svg | Should -BeLike '*Disk I/O had to be retried*'
        $svg | Should -BeLike '*server local time*'
    }

    It 'the report has the picture under a Timeline heading, before What happened' {
        $html = ConvertTo-TimelineHtml -Rows $script:ReportRows -Context (New-SvgContext)
        ([regex]::Matches($html, '<svg')).Count | Should -Be 1
        $html.IndexOf('<h2>Timeline</h2>') | Should -BeGreaterThan 0
        $html.IndexOf('<h2>Timeline</h2>') | Should -BeLessThan $html.IndexOf('<h2>What happened</h2>')
    }

    It 'the SVG encodes every piece of text' {
        $row = Disk153 '2026-11-18 17:50' -Server 'a<b'
        $html = ConvertTo-TimelineHtml -Rows @($row) -Context (New-SvgContext -Servers 'a<b')
        $svgPart = $html.Substring($html.IndexOf('<svg'), $html.IndexOf('</svg>') - $html.IndexOf('<svg'))
        $svgPart | Should -BeLike '*a&lt;b*'
        $svgPart | Should -Not -BeLike '*a<b*'
    }

    It 'the report still has no script' {
        $html = ConvertTo-TimelineHtml -Rows $script:ReportRows -Context (New-SvgContext)
        $html | Should -Not -BeLike '*<script*'
    }

    It 'a report with no rows still renders' {
        $html = ConvertTo-TimelineHtml -Rows @() -Context (New-SvgContext -NoWindow)
        $html | Should -BeLike '*</html>'
    }

    It 'takes the time span from the rows when the caller gives none' {
        $html = ConvertTo-TimelineHtml -Rows $script:ReportRows -Context (New-SvgContext -NoWindow)
        $html | Should -BeLike '*<svg*'
    }

    It 'both report callers pass the time span' {
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-ServerEventTimeline.ps1') -Raw
        $export = $src.Substring($src.IndexOf('function Get-ExportContext'), 1400)
        $export | Should -Match 'StartUtc'
        $console = $src.Substring($src.IndexOf('$context = @{'), 500)
        $console | Should -Match 'StartUtc'
    }
}

Describe 'Review fixes' {
    BeforeAll {
        # An error long before, then routine events, then an unexpected restart (offset -300).
        $script:QuietRows = Sort-Rows @(
            New-TestRow -Time '2026-11-18 05:00' -Level 2 -Provider 'Ntfs' -Id 5
            New-TestRow -Time '2026-11-18 07:50'
            New-TestRow -Time '2026-11-18 07:57'
            New-TestRow -Time '2026-11-18 08:00' -Provider 'Microsoft-Windows-Kernel-General' -Id 12
            New-TestRow -Time '2026-11-18 08:00:30' -Provider 'Microsoft-Windows-Kernel-Power' -Id 41 -Level 1
        )
    }

    It 'the story from the notable rows with every row as context matches the story from every row' {
        $store = New-TimelineRowStore
        Add-TimelineRows -Store $store -NewRows $script:QuietRows
        $full = Get-TimelineStory -Rows $script:QuietRows
        $fast = Get-TimelineStory -Rows $store.Notable.ToArray() -ContextRows $store.Rows.ToArray()
        @($fast.Lines | ForEach-Object { $_.Text + '|' + $_.Detail }) | Should -Be @($full.Lines | ForEach-Object { $_.Text + '|' + $_.Detail })
        @($fast.Lines | Where-Object Kind -eq 'Event')[-1].Detail | Should -BeLike '*about 3 min*'
    }

    It 'the window builds the story from the notable rows' {
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-ServerEventTimeline.ps1') -Raw
        $summary = $src.Substring($src.IndexOf('function Update-Summary'), 2000)
        $summary | Should -Match 'Get-TimelineStory -Rows \$ui\.Store\.Notable\.ToArray\(\) -ContextRows \$ui\.Store\.Rows\.ToArray\(\)'
    }

    It 'builds the story for a 40,000-row search in under 100 ms on Windows PowerShell 5.1' -Skip:(-not (Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
        $core = Join-Path (Split-Path -Parent $PSScriptRoot) 'ServerEventTimeline.Core.ps1'
        $script = @"
`$ErrorActionPreference = 'Stop'
. '$core'
`$s0 = [datetime]::SpecifyKind([datetime]'2026-11-18 22:45', [DateTimeKind]::Utc)
`$servers = 'AD-01', 'AD-02', 'AD-03', 'AD-04'
`$rows = New-Object System.Collections.Generic.List[object]
for (`$i = 0; `$i -lt 40000; `$i++) {
    `$t = `$s0.AddMilliseconds(`$i * 30); `$kind = `$i % 100
    `$flag = if (`$kind -eq 50) { 'Disk I/O had to be retried' } else { '' }
    `$rows.Add([PSCustomObject]@{ Server = `$servers[`$i % 4]; Log = 'System'; TimeUtc = `$t; TimeServerLocal = `$t.AddHours(-5); Level = `$(if (`$kind -lt 10) { 2 } else { 4 })
        Flag = `$flag; FlagCategory = `$(if (`$flag) { 'Disk' } else { '' }); Provider = 'Disk'; EventId = 153; RecordId = `$i; Message = ''; MessageFirstLine = 'm' })
}
`$store = New-TimelineRowStore
Add-TimelineRows -Store `$store -NewRows `$rows.ToArray()
[void](Get-TimelineStory -Rows `$store.Notable.ToArray() -ContextRows `$store.Rows.ToArray())
`$best = [double]::MaxValue
foreach (`$try in 1..3) { `$sw = [Diagnostics.Stopwatch]::StartNew(); [void](Get-TimelineStory -Rows `$store.Notable.ToArray() -ContextRows `$store.Rows.ToArray()); `$best = [Math]::Min(`$best, `$sw.Elapsed.TotalMilliseconds) }
[int]`$best
"@
        $file = Join-Path $TestDrive 'story-timing.ps1'
        Set-Content -LiteralPath $file -Value $script -Encoding UTF8
        $out = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file 2>&1 | ForEach-Object { "$_" })
        $last = $out | Select-Object -Last 1
        $last | Should -Match '^\d+$' -Because ($out -join "`n")
        [int]$last | Should -BeLessThan 100
    }

    It 'a filtered report measures the quiet gap from every row, not just the shown ones' {
        $errorsOnly = @($script:QuietRows | Where-Object { $_.Level -in 1, 2 })
        $ctx = @{ WindowText = 'w'; Servers = @('AD-01'); Logs = @('System'); FiltersText = 'Errors'; GeneratedAt = [datetime]'2026-11-18 09:00'; Summary = @(); ServerOutcomes = @()
            StartUtc = [datetime]::SpecifyKind([datetime]'2026-11-18 10:00', [DateTimeKind]::Utc); EndUtc = [datetime]::SpecifyKind([datetime]'2026-11-18 13:10', [DateTimeKind]::Utc) }
        $html = ConvertTo-TimelineHtml -Rows $errorsOnly -Context $ctx -ContextRows $script:QuietRows
        $html | Should -Not -BeLike '*about 180 min*'
        $html | Should -BeLike '*no events for about 3 min*'
    }

    It 'both report callers pass every row as context' {
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-ServerEventTimeline.ps1') -Raw
        ([regex]::Matches($src, 'ConvertTo-TimelineHtml -Rows [^\r\n]*-ContextRows')).Count | Should -Be 3
    }

    It 'takes the time zones from what the search learned, not from a sample of rows' {
        # Only AD-01 (UTC-5) has rows; AD-03 is quiet but known to be UTC+0.
        $rows = @(Disk153 '2026-11-18 17:50')
        $m = Get-TimelineStripModel -Rows $rows -Servers @('AD-01', 'AD-03') -StartUtc ([datetime]'2026-11-18 22:45') -EndUtc ([datetime]'2026-11-18 23:05') -Width 800 -UtcOffsets @{ 'AD-01' = -300; 'AD-03' = 0 }
        $m.AxisIsUtc | Should -BeTrue
        $same = Get-TimelineStripModel -Rows $rows -Servers @('AD-01', 'AD-03') -StartUtc ([datetime]'2026-11-18 22:45') -EndUtc ([datetime]'2026-11-18 23:05') -Width 800 -UtcOffsets @{ 'AD-01' = -300; 'AD-03' = -300 }
        $same.AxisIsUtc | Should -BeFalse
        $same.AxisOffsetMinutes | Should -Be -300
    }

    It 'the report takes the time zones from the server outcomes' {
        $ctx = @{ WindowText = 'w'; Servers = @('AD-01', 'AD-03'); Logs = @('System'); FiltersText = 'none'; GeneratedAt = [datetime]'2026-11-18 18:10'; Summary = @()
            ServerOutcomes = @([PSCustomObject]@{ Server = 'AD-01'; State = 'Done'; Transport = 'WinRM'; UtcOffsetMinutes = -300; EventCount = 1; Reason = ''; Logs = @() },
                [PSCustomObject]@{ Server = 'AD-03'; State = 'Done'; Transport = 'WinRM'; UtcOffsetMinutes = 0; EventCount = 0; Reason = ''; Logs = @() })
            StartUtc = [datetime]::SpecifyKind([datetime]'2026-11-18 22:45', [DateTimeKind]::Utc); EndUtc = [datetime]::SpecifyKind([datetime]'2026-11-18 23:05', [DateTimeKind]::Utc) }
        $html = ConvertTo-TimelineHtml -Rows @(Disk153 '2026-11-18 17:50') -Context $ctx
        $html | Should -BeLike '*times in UTC*'
    }

    It 'the window passes the time zones it learned to the picture' {
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'Start-ServerEventTimeline.ps1') -Raw
        $strip = $src.Substring($src.IndexOf('function Update-Strip'), 1800)
        $strip | Should -Match '-UtcOffsets \(Get-TimelineServerOffsets -Status \$ui\.Engine\.Status\)'
    }
}
