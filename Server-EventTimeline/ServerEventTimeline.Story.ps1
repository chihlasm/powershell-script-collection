#Requires -Version 5.1
<#
    "What happened": the flagged events turned into a short plain-English story, in order, and
    the timeline picture's layout. Pure functions (no UI, no network), dot-sourced by
    ServerEventTimeline.Core.ps1, which defines $script:SummaryKindByLabel used here.

    Restart facts (cited in Core's .NOTES REFERENCES too):
    https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
    - Kernel-Power 41 ("has rebooted without cleanly shutting down first") and EventLog 6008
      ("the previous system shutdown at <time> was unexpected") are written when the server
      comes back up, not when it went down. So the story says when it was back, and only
      estimates the outage from the quiet gap before - Windows records no "went down" time
      we can read without parsing the localised 6008 message.
    - 1074 is written when a process requests a restart or shutdown; a normal reboot is 1074
      then 13, then the start events. A blue screen adds WER-SystemErrorReporting 1001 next to
      41 and 6008, so it belongs to the same restart line.
#>

# Restart-family flags fold into one line per restart. Rank: the strongest role names the line.
$script:StoryRestartRoles = @{
    'Restarted without a clean shutdown (crash or power loss)' = 'Unexpected'
    'Previous shutdown was unexpected'                         = 'Unexpected'
    'Restarted after a blue screen (bugcheck)'                 = 'Bugcheck'
    'Restart or shutdown requested'                            = 'Requested'
    'Windows started (event log service started)'             = 'Started'
    'Windows started'                                          = 'Started'
    'Windows shut down cleanly'                                = 'Shutdown'
    'Windows shut down'                                        = 'Shutdown'
}
$script:StoryRoleRank = @{ Shutdown = 0; Started = 1; Requested = 2; Unexpected = 3; Bugcheck = 4 }
# Summary kinds whose lines say how many unrecognised errors came just before.
$script:StoryCrashKinds = @('AppCrash', 'ServiceFailure')

$script:StoryFoldMinutes = 10
$script:StoryRestartMinutes = 5
$script:StoryErrorsBeforeMinutes = 5
$script:StoryGapMinutes = 10

function Get-TimelineRowId {
    <# One row's identity: server, log and record number ('AD-01|System|4242'). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row)
    '{0}|{1}|{2}' -f $Row.Server, $Row.Log, $Row.RecordId
}

function Format-TimelineGap {
    <# A quiet stretch in words: '25 minutes later', '3 hours later', '2 days later'. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][double]$Minutes)
    $unit = 'minute'; $n = [int][Math]::Round($Minutes)
    if ($Minutes -ge 1440) { $unit = 'day'; $n = [int][Math]::Round($Minutes / 1440) }
    elseif ($Minutes -ge 60) { $unit = 'hour'; $n = [int][Math]::Round($Minutes / 60) }
    if ($n -eq 1) { "1 $unit later" } else { "$n ${unit}s later" }
}

function Format-StoryErrorCount {
    param([int]$Count)
    if ($Count -le 0) { return '' }
    $noun = if ($Count -eq 1) { 'error' } else { 'errors' }
    '({0} {1} in the {2} minutes before)' -f $Count, $noun, $script:StoryErrorsBeforeMinutes
}

function Join-StoryDetail {
    param([string[]]$Parts)
    (@($Parts | Where-Object { $_ }) -join ' ').Trim()
}

function New-StoryLineObject {
    param([string]$Kind, $Server = '', $TimeUtc, $LastTimeUtc, $TimeServerLocal, [string]$Category = '',
        [string]$Text, [string]$Detail = '', [string]$RowId = '', [int]$Count = 0)
    [PSCustomObject]@{
        Kind = $Kind; Server = [string]$Server; TimeUtc = $TimeUtc; LastTimeUtc = $LastTimeUtc; TimeServerLocal = $TimeServerLocal
        Category = $Category; Text = $Text; Detail = $Detail; RowId = $RowId; Count = $Count
    }
}

function Get-TimelineStory {
    <#
        The flagged events as story lines, in UTC order across servers (times shown server
        local). Lines = Event lines (Server, TimeUtc, LastTimeUtc, TimeServerLocal, Category,
        Text, Detail, RowId of the line's telling row, Count) with Gap lines ('25 minutes
        later') between lines 10 minutes or more apart. MoreCount = Event lines past MaxLines.

        - Flags with no summary kind are left out (a lone clean shutdown, the WER crash report
          that follows every app crash), except clean shutdowns inside a restart.
        - The same flag on the same server within 10 minutes of the previous one folds into one
          line with a count.
        - Restart-family events on one server within 5 minutes of each other fold into one line.
        - Crash lines count the unrecognised errors on that server in the 5 minutes before.
    #>
    [CmdletBinding()]
    param([object[]]$Rows, [int]$MaxLines = 60)

    $rows = @($Rows | Where-Object { $null -ne $_ })
    for ($i = 1; $i -lt $rows.Count; $i++) {
        if ([datetime]$rows[$i].TimeUtc -lt [datetime]$rows[$i - 1].TimeUtc) { $rows = @($rows | Sort-Object TimeUtc); break }
    }

    $states = @{}
    $built = New-Object System.Collections.Generic.List[object]
    $seq = 0

    $closeGroup = {
        param($g)
        if (-not $g -or $g.Role -eq 'Shutdown') { return }
        $text = switch ($g.Role) {
            'Bugcheck' { 'Restarted after a blue screen (bugcheck)' }
            'Unexpected' { 'Restarted without a clean shutdown' }
            'Requested' { if ($g.BackUp) { 'Restarted on request' } else { 'Restart or shutdown requested' } }
            default { 'Windows started' }
        }
        if ($g.BackUp -and $g.Role -ne 'Started') { $text += ' - back up at {0:HH:mm}' -f $g.BackUp }
        $detail = ''
        if ($g.Role -eq 'Requested' -and $g.RequestRow) { $detail = [string]$g.RequestRow.MessageFirstLine }
        if ($g.Role -in @('Unexpected', 'Bugcheck')) {
            $quiet = ''
            if ($g.PlainBefore) {
                $mins = [int][Math]::Round(([datetime]$g.First.TimeUtc - [datetime]$g.PlainBefore).TotalMinutes)
                if ($mins -ge 1) { $quiet = '(no events for about {0} min before that)' -f $mins }
            }
            $detail = Join-StoryDetail @($quiet, (Format-StoryErrorCount -Count $g.Errors))
        }
        $built.Add(@{
                Seq = $g.Seq; Server = $g.First.Server; TimeUtc = [datetime]$g.First.TimeUtc; LastTimeUtc = $g.Last
                TimeServerLocal = $g.First.TimeServerLocal; Category = $(if ($g.Role -eq 'Bugcheck') { 'Bugcheck' } else { 'Restart' })
                Text = $text; Detail = $detail; RowId = (Get-TimelineRowId -Row $g.KeyRow); Count = 1
            })
    }

    foreach ($r in $rows) {
        $server = [string]$r.Server
        $s = $states[$server]
        if (-not $s) {
            $s = @{ PlainBefore = $null; Errors = New-Object 'System.Collections.Generic.Queue[datetime]'; Folds = @{}; Group = $null }
            $states[$server] = $s
        }
        $t = [datetime]$r.TimeUtc
        $label = [string]$r.Flag
        $role = if ($label) { $script:StoryRestartRoles[$label] } else { $null }

        # Unrecognised errors older than the "just before" window no longer count.
        $cut = $t.AddMinutes(-$script:StoryErrorsBeforeMinutes)
        while ($s.Errors.Count -gt 0 -and $s.Errors.Peek() -lt $cut) { [void]$s.Errors.Dequeue() }

        if ($role) {
            $g = $s.Group
            if ($g -and ($t - $g.Last).TotalMinutes -le $script:StoryRestartMinutes) {
                $g.Last = $t
                if ($script:StoryRoleRank[$role] -gt $script:StoryRoleRank[$g.Role]) { $g.Role = $role; $g.KeyRow = $r }
            }
            else {
                & $closeGroup $g
                $seq++
                $g = @{ Seq = $seq; First = $r; Last = $t; Role = $role; KeyRow = $r; BackUp = $null; RequestRow = $null
                    PlainBefore = $s.PlainBefore; Errors = $s.Errors.Count }
                $s.Group = $g
            }
            if ($role -eq 'Started' -and -not $g.BackUp) { $g.BackUp = $r.TimeServerLocal }
            if ($role -eq 'Requested' -and -not $g.RequestRow) { $g.RequestRow = $r }
            continue
        }

        if ($label -and $script:SummaryKindByLabel.ContainsKey($label)) {
            $fold = $s.Folds[$label]
            if ($fold -and ($t - $fold.LastTimeUtc).TotalMinutes -le $script:StoryFoldMinutes) {
                $fold.Count++
                $fold.LastTimeUtc = $t
            }
            else {
                $seq++
                $errors = if ($script:StoryCrashKinds -contains $script:SummaryKindByLabel[$label].Key) { $s.Errors.Count } else { 0 }
                $fold = @{ Seq = $seq; Server = $server; TimeUtc = $t; LastTimeUtc = $t; TimeServerLocal = $r.TimeServerLocal
                    Category = [string]$r.FlagCategory; Label = $label; Message = [string]$r.MessageFirstLine
                    ErrorText = (Format-StoryErrorCount -Count $errors); RowId = (Get-TimelineRowId -Row $r); Count = 1 }
                $s.Folds[$label] = $fold
                $built.Add($fold)
            }
        }
        elseif (-not $label -and ([int]$r.Level -eq 1 -or [int]$r.Level -eq 2)) {
            $s.Errors.Enqueue($t)
        }
        $s.PlainBefore = $t
    }
    foreach ($s in $states.Values) { & $closeGroup $s.Group }

    # One order across servers: UTC time, then the order the lines were started.
    $built.Sort([Comparison[object]] {
            param($a, $b)
            $c = ([datetime]$a.TimeUtc).CompareTo([datetime]$b.TimeUtc)
            if ($c -ne 0) { $c } else { ([int]$a.Seq).CompareTo([int]$b.Seq) }
        })

    $lines = New-Object System.Collections.Generic.List[object]
    $shown = 0
    $previous = $null
    foreach ($b in $built) {
        if ($shown -ge $MaxLines) { break }
        if ($previous) {
            $quiet = ([datetime]$b.TimeUtc - [datetime]$previous.LastTimeUtc).TotalMinutes
            if ($quiet -ge $script:StoryGapMinutes) {
                $lines.Add((New-StoryLineObject -Kind Gap -TimeUtc ([datetime]$b.TimeUtc) -Text (Format-TimelineGap -Minutes $quiet)))
            }
        }
        $text = $b.Text
        $detail = $b.Detail
        if ($b.ContainsKey('Label')) {
            # A folded flag: the label, with how many and over how long.
            $text = $b.Label
            if ($b.Count -gt 1) {
                $span = ([datetime]$b.LastTimeUtc - [datetime]$b.TimeUtc).TotalMinutes
                $text += if ($span -lt 1) { ' ({0} in under a minute)' -f $b.Count } else { ' ({0} in {1} min)' -f $b.Count, [int][Math]::Round($span) }
            }
            $detail = Join-StoryDetail @($b.Message, $b.ErrorText)
        }
        $lines.Add((New-StoryLineObject -Kind Event -Server $b.Server -TimeUtc ([datetime]$b.TimeUtc) -LastTimeUtc ([datetime]$b.LastTimeUtc) `
                    -TimeServerLocal $b.TimeServerLocal -Category $b.Category -Text $text -Detail $detail -RowId $b.RowId -Count $b.Count))
        $shown++
        $previous = $b
    }
    [PSCustomObject]@{ Lines = $lines.ToArray(); MoreCount = [Math]::Max(0, $built.Count - $shown) }
}

function Format-TimelineStoryText {
    <#
        The story as ticket lines: one per Event line ('AD-01 2026-11-18 17:49 (server local):
        Disk I/O had to be retried (3 in 3 min)'), no gap or detail lines, so N lines means N
        happenings. Ends with how many more flagged events there were when the story was cut.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Story)
    foreach ($l in @($Story.Lines | Where-Object { $_.Kind -eq 'Event' })) {
        '{0} {1:yyyy-MM-dd HH:mm} (server local): {2}' -f $l.Server, ([datetime]$l.TimeServerLocal), $l.Text
    }
    if ($Story.MoreCount -gt 0) {
        $noun = if ($Story.MoreCount -eq 1) { 'flagged event' } else { 'flagged events' }
        '... and {0} more {1} (see the report)' -f $Story.MoreCount, $noun
    }
}

function ConvertTo-TimelineStoryHtml {
    <# The story as an HTML list for the report. Every piece of text is HTML-encoded. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Story)
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<h2>What happened</h2>')
    $lines = @($Story.Lines)
    if ($lines.Count -eq 0) {
        [void]$sb.Append("<p class=""meta"">Nothing the tool recognises happened in these events - check the errors in the table.</p>")
        return $sb.ToString()
    }
    [void]$sb.Append('<ul class="story">')
    foreach ($l in $lines) {
        if ($l.Kind -eq 'Gap') { [void]$sb.AppendFormat('<li class="gap">{0}</li>', (& $e $l.Text)); continue }
        [void]$sb.AppendFormat('<li><span class="when">{0:yyyy-MM-dd HH:mm}</span> <b>{1}</b> {2}', ([datetime]$l.TimeServerLocal), (& $e $l.Server), (& $e $l.Text))
        if ($l.Detail) { [void]$sb.AppendFormat('<br><span class="meta">{0}</span>', (& $e $l.Detail)) }
        [void]$sb.Append('</li>')
    }
    [void]$sb.Append('</ul>')
    if ($Story.MoreCount -gt 0) {
        [void]$sb.AppendFormat('<p class="meta">... and {0:N0} more flagged events - see the table below.</p>', $Story.MoreCount)
    }
    $sb.ToString()
}

# One symbol and colour per flag category, shared by the story tab, the picture strip and
# the report. Anything without its own (a restart, a category added later) is a grey circle,
# so new flags still show up. Glyphs are built from code points to keep this file ASCII.
$script:TimelineCategoryShapes = @{
    Disk = 'Triangle'; LowMemory = 'Triangle'
    AppCrash = 'Cross'; ServiceCrash = 'Cross'; Bugcheck = 'Cross'
    Update = 'Square'; TimeJump = 'Diamond'
}
$script:TimelineShapeStyles = @{
    Triangle = @{ Color = '#E0B43A'; Glyph = [string][char]0x25B2 }
    Cross    = @{ Color = '#E06C5A'; Glyph = [string][char]0x2716 }
    Square   = @{ Color = '#5DADE2'; Glyph = [string][char]0x25A0 }
    Diamond  = @{ Color = '#B48EDB'; Glyph = [string][char]0x25C6 }
    Circle   = @{ Color = '#8B94A3'; Glyph = [string][char]0x25CF }
}

function Get-TimelineCategoryStyle {
    <# Shape ('Triangle'|'Cross'|'Square'|'Diamond'|'Circle'), Color ('#RRGGBB') and Glyph for a flag category. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Category)
    $shape = $script:TimelineCategoryShapes[$Category]
    if (-not $shape) { $shape = 'Circle' }
    $st = $script:TimelineShapeStyles[$shape]
    [PSCustomObject]@{ Shape = $shape; Color = $st.Color; Glyph = $st.Glyph }
}

$script:StripMarkMergePx = 4
$script:StripDotPx = 6
$script:StripTickSteps = @(1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440)

function Get-TimelineStripModel {
    <#
        The picture strip's layout: one lane per server (in -Servers order), X from 0 to
        -Width across StartUtc..EndUtc.
        - Marks: flagged rows the story counts, symbol and colour by category; marks of one
          shape closer than 4 px merge, with the count in the tooltip.
        - Dots: unflagged Error/Critical rows, one per 6 px slice, stronger with more errors.
        - DownBars: the quiet gap before an unexpected restart (last event, then the restart).
        - Ticks and AxisIsUtc: local time when every server shares a UTC offset, else UTC.
        One pass, no function call for ordinary rows: 40,000 rows must take well under 100 ms
        on the window thread (the window froze once from doing too much there).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [string[]]$Servers,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc,
        [Parameter(Mandatory)][double]$Width,
        # All rows in UTC order (the store's), when -Rows holds only the flagged and error
        # ones: the quiet gap before a restart is measured from any event, not just those.
        [object[]]$ContextRows
    )
    if ($null -eq $Rows) { $Rows = @() }
    $lanes = New-Object System.Collections.Generic.List[object]
    $laneOf = @{}
    foreach ($s in @($Servers | Where-Object { $_ })) {
        if ($laneOf.ContainsKey($s)) { continue }
        $laneOf[$s] = $lanes.Count
        $lanes.Add([PSCustomObject]@{ Server = $s; Index = $lanes.Count })
    }
    $startTicks = $StartUtc.Ticks
    $endTicks = $EndUtc.Ticks
    $span = [Math]::Max([long]1, [long]($endTicks - $startTicks))
    $scale = $Width / $span
    $restartGapTicks = [TimeSpan]::FromMinutes($script:StoryRestartMinutes).Ticks
    $roles = $script:StoryRestartRoles
    $kinds = $script:SummaryKindByLabel

    $markList = New-Object System.Collections.Generic.List[object]
    $markAt = @{}
    $dotList = New-Object System.Collections.Generic.List[object]
    $dotAt = @{}
    $bars = New-Object System.Collections.Generic.List[object]
    $groups = @{}

    $closeGroup = {
        param($g)
        if (-not $g -or $g.Role -notin @('Unexpected', 'Bugcheck') -or $null -eq $g.PlainBefore) { return }
        $mins = [int][Math]::Round(($g.Start - $g.PlainBefore) / 600000000.0)
        if ($mins -lt 1) { return }
        $how = if ($g.Role -eq 'Bugcheck') { 'restarted after a blue screen' } else { 'restarted without a clean shutdown' }
        $bars.Add([PSCustomObject]@{
                Lane = $g.Lane; X1 = [Math]::Max(0.0, ($g.PlainBefore - $startTicks) * $scale); X2 = ($g.Start - $startTicks) * $scale
                Text = ('no events for about {0} min, then {1}' -f $mins, $how)
            })
    }

    # Locals, not $script: lookups, inside the loop.
    $dotPx = $script:StripDotPx
    $mergePx = $script:StripMarkMergePx
    $shapeOf = $script:TimelineCategoryShapes
    # foreach with a counter: measurably faster than for ($k...) $Rows[$k] on 5.1.
    $k = -1
    foreach ($r in $Rows) {
        $k++
        $flag = $r.Flag
        if (-not $flag) {
            $level = $r.Level
            if ($level -ne 1 -and $level -ne 2) { continue }
        }
        $t = $r.TimeUtc.Ticks
        if ($t -lt $startTicks -or $t -gt $endTicks) { continue }
        $lane = $laneOf[$r.Server]
        if ($null -eq $lane) { continue }
        $x = ($t - $startTicks) * $scale

        if (-not $flag) {
            $slice = [int][Math]::Floor($x / $dotPx)
            $key = $lane * 1000000 + $slice
            $d = $dotAt[$key]
            if ($d) { $d.Count++ }
            else {
                $d = @{ Lane = $lane; X = $slice * $dotPx + $dotPx / 2; Count = 1; Server = $r.Server; Local = $r.TimeServerLocal }
                $dotAt[$key] = $d; $dotList.Add($d)
            }
            continue
        }

        $role = $roles[$flag]
        if ($role) {
            $g = $groups[$lane]
            if ($g -and ($t - $g.Last) -le $restartGapTicks) {
                $g.Last = $t
                if ($script:StoryRoleRank[$role] -gt $script:StoryRoleRank[$g.Role]) { $g.Role = $role }
            }
            else {
                & $closeGroup $g
                # The last event on this server that isn't part of a restart: when it went quiet.
                $before = $null
                $look = $Rows; $from = $k - 1
                if ($ContextRows) {
                    # Binary search for the first row at or after this one, then walk back.
                    $look = $ContextRows; $lo = 0; $hi = $ContextRows.Count
                    while ($lo -lt $hi) { $mid = [int](($lo + $hi) / 2 - 0.5); if ($ContextRows[$mid].TimeUtc.Ticks -lt $t) { $lo = $mid + 1 } else { $hi = $mid } }
                    $from = $lo - 1
                }
                for ($j = $from; $j -ge 0; $j--) {
                    $p = $look[$j]
                    if ($p.Server -eq $r.Server -and -not ($p.Flag -and $roles[$p.Flag])) { $before = $p.TimeUtc.Ticks; break }
                }
                $groups[$lane] = @{ Lane = $lane; Start = $t; Last = $t; Role = $role; PlainBefore = $before }
            }
        }
        if (-not $kinds.ContainsKey($flag)) { continue }
        # Same rule as Get-TimelineCategoryStyle, inline: a call per flagged row cost ~0.1 ms.
        $shape = $shapeOf[[string]$r.FlagCategory]
        if (-not $shape) { $shape = 'Circle' }
        $key = [string]$lane + '|' + $shape + '|' + [int][Math]::Floor($x / $mergePx)
        $m = $markAt[$key]
        if ($m) { $m.Count++; continue }
        # Only a new mark pays for its text.
        $m = @{ Lane = $lane; X = $x; Shape = $shape; Row = $r; Count = 1; Label = $flag }
        $markAt[$key] = $m; $markList.Add($m)
    }
    foreach ($g in $groups.Values) { & $closeGroup $g }

    # The loop's own tables are the output: building 800 new objects with their tooltip text
    # cost more than the loop. Tooltips are made on demand (Get-TimelineStripToolTip).
    $styles = $script:TimelineShapeStyles
    foreach ($m in $markList) {
        $r = $m.Row
        $m.Color = $styles[$m.Shape].Color
        $m.RowId = [string]$r.Server + '|' + [string]$r.Log + '|' + [string]$r.RecordId
    }
    foreach ($d in $dotList) { $d.Opacity = [Math]::Round(0.35 + 0.65 * [Math]::Min(1.0, ($d.Count - 1) / 19.0), 2) }
    $marks = $markList.ToArray()
    $dots = $dotList.ToArray()

    # The axis: local time when every server shares an offset (read from its rows), else UTC.
    $offsets = New-Object 'System.Collections.Generic.HashSet[int]'
    $seen = @{}
    $sample = if ($ContextRows) { $ContextRows } else { $Rows }
    $limit = [Math]::Min($sample.Count, 5000)
    for ($k = 0; $k -lt $limit -and $seen.Count -lt $lanes.Count; $k++) {
        $r = $sample[$k]
        if ($seen.ContainsKey($r.Server) -or -not $laneOf.ContainsKey($r.Server)) { continue }
        $seen[$r.Server] = $true
        [void]$offsets.Add([int][Math]::Round(([datetime]$r.TimeServerLocal - [datetime]$r.TimeUtc).TotalMinutes))
    }
    $axisUtc = $offsets.Count -gt 1
    $offset = if ($offsets.Count -eq 1) { @($offsets)[0] } else { 0 }
    $spanMinutes = $span / 600000000.0
    $step = $script:StripTickSteps[-1]
    foreach ($candidate in $script:StripTickSteps) { if ($spanMinutes / $candidate -le 8) { $step = $candidate; break } }
    $shownStart = $StartUtc.AddMinutes($offset)
    $shownEnd = $EndUtc.AddMinutes($offset)
    $format = if ($spanMinutes -gt 1440) { 'MM-dd HH:mm' } else { 'HH:mm' }
    $tick = $shownStart.Date.AddMinutes([Math]::Ceiling(($shownStart - $shownStart.Date).TotalMinutes / $step) * $step)
    $ticks = New-Object System.Collections.Generic.List[object]
    while ($tick -le $shownEnd) {
        $ticks.Add([PSCustomObject]@{ X = ($tick - $shownStart).Ticks * $scale; Label = $tick.ToString($format) })
        $tick = $tick.AddMinutes($step)
    }

    [PSCustomObject]@{
        Lanes = $lanes.ToArray(); Marks = [object[]]$marks; Dots = [object[]]$dots; DownBars = $bars.ToArray()
        Ticks = $ticks.ToArray(); AxisIsUtc = $axisUtc; AxisOffsetMinutes = $offset
    }
}

function Get-TimelineStoreStripModel {
    <#
        The picture for the window: Get-TimelineStripModel over the store's flagged and error
        rows (Store.Notable) that pass the event list's filters, with every row as context.
        Walking only those rows keeps a 40,000-row search well under 100 ms.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][hashtable]$Filter,
        [string[]]$Servers,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc,
        [Parameter(Mandatory)][double]$Width
    )
    $rows = @(Select-TimelineRows -Rows $Store.Notable.ToArray() -Filter $Filter)
    Get-TimelineStripModel -Rows $rows -Servers $Servers -StartUtc $StartUtc -EndUtc $EndUtc -Width $Width -ContextRows $Store.Rows.ToArray()
}

function Get-TimelineStripToolTip {
    <#
        The hover text for one mark or dot from Get-TimelineStripModel, made only when shown:
        a mark says what it was, where and when, and its source and ID ("5 x ..." when several
        sat on the same spot); a dot says how many errors, on which server, around when.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Item)
    if ($Item.Row) {
        $r = $Item.Row
        $label = if ($Item.Count -gt 1) { '{0} x {1}' -f $Item.Count, $Item.Label } else { $Item.Label }
        return ('{0}{1}{2} {3:yyyy-MM-dd HH:mm:ss} (server local){1}{4} {5}' -f $label, [Environment]::NewLine, $r.Server, [datetime]$r.TimeServerLocal, $r.Provider, $r.EventId)
    }
    $noun = if ($Item.Count -eq 1) { 'error' } else { 'errors' }
    '{0} {1} on {2} around {3:HH:mm} (server local)' -f $Item.Count, $noun, $Item.Server, [datetime]$Item.Local
}

function Get-TimelineStripWindow {
    <#
        The time the picture covers: from the earliest server's window start to the latest
        one's end, in UTC (each server's window is its own local time, so servers in different
        time zones cover different UTC stretches). Servers not reached yet count with offset 0.
        -NowUtc fixes a "last N minutes" search to when it started.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Window, $Status, [Nullable[datetime]]$NowUtc)
    $start = $null; $end = $null
    $states = @(if ($Status) { $Status.Values } else { $null })
    foreach ($st in $states) {
        $offset = if ($st) { [int]$st.UtcOffsetMinutes } else { 0 }
        $w = ConvertTo-UtcWindow -Window $Window -UtcOffsetMinutes $offset -NowUtc $NowUtc
        if ($null -eq $start -or $w.StartUtc -lt $start) { $start = $w.StartUtc }
        if ($null -eq $end -or $w.EndUtc -gt $end) { $end = $w.EndUtc }
    }
    [PSCustomObject]@{ StartUtc = $start; EndUtc = $end }
}

function ConvertTo-TimelineStripSvg {
    <#
        The picture for the HTML report: the same lanes, symbols, error dots and down bars as
        the window, as inline SVG with a <title> on each for the hover text. No script, so the
        report stays self-contained. Every piece of text is HTML-encoded. Colours for lines
        and labels come from the report's CSS variables, so light mode works.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][double]$Width)
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $n = { param([double]$v) $v.ToString('0.#', $inv) }
    $label = 118; $axis = 14; $lane = 22; $legendPx = 22
    $lanes = @($Model.Lanes)
    $plotH = $axis + [Math]::Max(1, $lanes.Count) * $lane + 6
    $w = $label + $Width + 16
    $h = $plotH + $legendPx
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('<svg class="strip" viewBox="0 0 {0} {1}" width="100%" role="img" aria-label="Timeline of the flagged events on each server" font-family="Segoe UI, sans-serif" font-size="11">', (& $n $w), (& $n $h))
    foreach ($t in @($Model.Ticks)) {
        $x = & $n ($label + $t.X)
        [void]$sb.AppendFormat('<line x1="{0}" x2="{0}" y1="{1}" y2="{2}" stroke="var(--line)"/>', $x, ($axis - 2), ($plotH - 4))
        [void]$sb.AppendFormat('<text x="{0}" y="10" fill="var(--muted)" font-size="10" text-anchor="middle">{1}</text>', $x, (& $e $t.Label))
    }
    foreach ($l in $lanes) {
        $y = $axis + $l.Index * $lane + $lane / 2
        $name = [string]$l.Server
        $short = if ($name -match '^\d{1,3}(\.\d{1,3}){3}$') { $name } else { ($name -split '\.')[0] }
        [void]$sb.AppendFormat('<text x="4" y="{0}" fill="var(--text)"><title>{1}</title>{2}</text>', (& $n ($y + 4)), (& $e $name), (& $e $short))
        [void]$sb.AppendFormat('<line x1="{0}" x2="{1}" y1="{2}" y2="{2}" stroke="var(--line)"/>', $label, (& $n ($label + $Width)), (& $n $y))
    }
    foreach ($b in @($Model.DownBars)) {
        $y = $axis + $b.Lane * $lane + $lane / 2 - 6
        [void]$sb.AppendFormat('<rect x="{0}" y="{1}" width="{2}" height="12" rx="2" fill="#2A2F3A" stroke="#4A5160"><title>{3}</title></rect>',
            (& $n ($label + $b.X1)), (& $n $y), (& $n ([Math]::Max(2, $b.X2 - $b.X1))), (& $e $b.Text))
    }
    foreach ($d in @($Model.Dots)) {
        [void]$sb.AppendFormat('<circle cx="{0}" cy="{1}" r="2.5" fill="#E06C5A" opacity="{2}"><title>{3}</title></circle>',
            (& $n ($label + $d.X)), (& $n ($axis + $d.Lane * $lane + $lane / 2)), (& $n $d.Opacity), (& $e (Get-TimelineStripToolTip -Item $d)))
    }
    foreach ($m in @($Model.Marks)) {
        $cx = $label + $m.X; $cy = $axis + $m.Lane * $lane + $lane / 2
        $tip = '<title>{0}</title>' -f (& $e (Get-TimelineStripToolTip -Item $m))
        $c = $m.Color
        $shape = switch ($m.Shape) {
            'Triangle' { '<polygon points="{0},{1} {2},{3} {4},{3}" fill="{5}">{6}</polygon>' -f (& $n $cx), (& $n ($cy - 5)), (& $n ($cx + 5)), (& $n ($cy + 4)), (& $n ($cx - 5)), $c, $tip }
            'Diamond' { '<polygon points="{0},{1} {2},{3} {0},{4} {5},{3}" fill="{6}">{7}</polygon>' -f (& $n $cx), (& $n ($cy - 5)), (& $n ($cx + 5)), (& $n $cy), (& $n ($cy + 5)), (& $n ($cx - 5)), $c, $tip }
            'Square' { '<rect x="{0}" y="{1}" width="9" height="9" rx="1.5" fill="{2}">{3}</rect>' -f (& $n ($cx - 4.5)), (& $n ($cy - 4.5)), $c, $tip }
            'Cross' { '<path d="M{0},{1} L{2},{3} M{2},{1} L{0},{3}" stroke="{4}" stroke-width="2.6" stroke-linecap="round" fill="none">{5}</path>' -f (& $n ($cx - 4.5)), (& $n ($cy - 4.5)), (& $n ($cx + 4.5)), (& $n ($cy + 4.5)), $c, $tip }
            default { '<circle cx="{0}" cy="{1}" r="4" fill="{2}">{3}</circle>' -f (& $n $cx), (& $n $cy), $c, $tip }
        }
        [void]$sb.Append($shape)
    }
    # The legend, under the lanes.
    $x = $label
    $ly = $plotH + 14
    foreach ($part in @(@('Disk', 'disk or low memory'), @('AppCrash', 'crash'), @('Update', 'update'), @('TimeJump', 'time change'), @('Restart', 'restart or other'))) {
        $st = Get-TimelineCategoryStyle -Category $part[0]
        [void]$sb.AppendFormat('<text x="{0}" y="{1}"><tspan fill="{2}">{3}</tspan><tspan fill="var(--muted)"> {4}</tspan></text>', (& $n $x), (& $n $ly), $st.Color, (& $e $st.Glyph), (& $e $part[1]))
        $x += 18 + 6.2 * $part[1].Length + 14
    }
    $axisText = if ($Model.AxisIsUtc) { 'times in UTC (the servers are in different time zones)' } else { 'server local time' }
    [void]$sb.AppendFormat('<text x="{0}" y="{1}"><tspan fill="#E06C5A">&#8226;</tspan><tspan fill="var(--muted)"> errors &#183; {2}</tspan></text>', (& $n $x), (& $n $ly), (& $e $axisText))
    [void]$sb.Append('</svg>')
    $sb.ToString()
}
