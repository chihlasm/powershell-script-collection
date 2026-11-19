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
