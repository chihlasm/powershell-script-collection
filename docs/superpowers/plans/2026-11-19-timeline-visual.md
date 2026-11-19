# Server Event Timeline: seeing what happened - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a plain-English "What happened" story (window tab, ticket note, HTML report). Then
add a lanes picture of the flagged events (a window strip and an SVG in the HTML report), with
a drag-to-narrow time filter.

**Architecture:**
- All logic goes in a new pure file, `ServerEventTimeline.Story.ps1`, dot-sourced by Core the
  way `ServerEventTimeline.ServerList.ps1` is. It builds the story lines, the strip's marks and
  the SVG.
- The window only draws what those functions return.
- Part 1 is Tasks 1-3 and can ship on its own. Part 2 is Tasks 4-7.

**Tech Stack:** Windows PowerShell 5.1 and WPF (XAML in `Start-ServerEventTimeline.ps1`), Pester
5 under pwsh.

**Spec:** `docs/superpowers/specs/2026-11-19-timeline-visual-design.md`

## Global Constraints

- PowerShell 5.1 floor for this tool. Use UTF-8 with BOM for any file holding a non-ASCII
  character, such as ✖ or ▲.
- Pure logic stays out of the window and is tested without one. Test the window off-screen
  (STA-gated tests, as in `Tests/ServerEventTimeline.Gui.Tests.ps1`). Agents never launch the GUI
  or touch real servers, the clipboard or settings.
- Only flagged events are used. The story leaves out flags with no summary kind (clean
  shutdown 6006/Kernel-General 13 on their own, WER 1001 crash report), and so does the picture.
- Thresholds:

  | Setting | Value |
  | --- | --- |
  | Repeat fold | same flag, same server, within 10 min of the previous one |
  | Restart pairing | within 5 min |
  | "Errors before" window | 5 min |
  | Gap line | 10 min or more |
  | Story limit | 60 lines |
  | Ticket limit | 15 story lines |

- Copy:
  - "Search to see the important events here, in order."
  - "Nothing the tool recognises happened in this window - check the errors in the list."
  - "... and N more flagged events - filter the list to see them".
- Symbols:

  | Category | Symbol |
  | --- | --- |
  | Disk, LowMemory | amber triangle `#E0B43A` |
  | AppCrash, ServiceCrash, Bugcheck | red ✖ `#E06C5A` |
  | Update | blue square `#5DADE2` |
  | TimeJump | purple diamond `#B48EDB` |
  | Restart and any unknown category | grey circle `#8B94A3` |

- Strip size: about 110 px for up to 4 lanes, plus 22 px per extra lane, scrolling past 6.
- Strip redraw: on search finish, on a filter change, on resize after a 200 ms pause, and at most
  every 2 s while results arrive.
- Performance: 40,000 rows must build the strip's marks in under 100 ms, checked under
  Windows PowerShell 5.1.
- A new Microsoft fact gets a Learn citation in code and in `.NOTES` REFERENCES.
- Conventional commits ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A search with no flagged events, or no rows at all.** The tab shows the right empty text,
   the strip draws lanes with no marks, and the report and note don't throw. Covered by Task 1
   (empty) and Task 5 (no marks).
2. **A one-row result on Windows PowerShell 5.1.** A single PSCustomObject has no `.Count`, the
   trap that bit this tool before. Every story and strip function returns arrays wrapped in `@()`.
   Covered by Task 1 (single flagged row) and Task 5 (single row).
3. **Servers in different time zones.** Lanes align on UTC, the axis is labelled UTC with
   "(UTC)", and story times stay server-local. Covered by Task 5.
4. **A restart with no "started" event in the window** (the search ends mid-outage). The line
   stays "Restarted without a clean shutdown" with no "back up at". Covered by Task 1.
5. **A story line whose row the current filters hide.** A click clears the filters and still
   selects the row. Covered by Task 3.

---

### Task 1: The story model

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.Story.ps1`
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1` (dot-source the new file after
  ServerList; add a REFERENCES line)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Story.Tests.ps1` (dot-source Core)

**Interfaces:**
- Produces:
  - `Get-TimelineRowId -Row <row>` returns `[string]` `'Server|Log|RecordId'`.
  - `Get-TimelineStory -Rows <object[]> [-MaxLines 60]` returns
    `[PSCustomObject]@{ Lines = [object[]]; MoreCount = [int] }`.
  - Each line is a PSCustomObject:
    - `Kind`: 'Event' or 'Gap'
    - `Server`
    - `TimeUtc`
    - `TimeServerLocal`
    - `Category` (the row's FlagCategory)
    - `Text`
    - `Detail`
    - `RowId` (the line's first row)
    - `Count`
  - Gap lines carry only `Kind`, `Text` (for example '25 minutes later') and `TimeUtc`.
  - `Format-TimelineGap -Minutes <double>` returns `[string]`: '10 minutes later',
    '1 hour later', '3 hours later' or '2 days later'.

- [ ] **Step 1: Check the restart facts on Microsoft Learn**

Read https://learn.microsoft.com/troubleshoot/windows-client/performance/event-id-41-restart and
https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs.

Confirm two things:
- 41 and 6008 are written when the system starts again, not at the moment it went down.
- 1074 is written when a restart or shutdown is requested.

Put the citation in a comment over the restart folding code and in Core's `.NOTES`
REFERENCES. If Learn contradicts the spec's wording, ledger a ruling and reword. The wording
must not claim a time Windows didn't record.

- [ ] **Step 2: Write the failing tests** in `Story.Tests.ps1`. Build the rows with a local
`New-TestRow` helper that sets Server, Log, TimeUtc, TimeServerLocal, Level, Flag, FlagCategory,
Provider, EventId, MessageFirstLine and RecordId. Use real flag labels from
`$script:FlagCatalog`.

  - `It 'returns no lines and MoreCount 0 for no rows'`
  - `It 'returns no lines when nothing is flagged'`
  - `It 'returns one line for one flagged row'`: `@($s.Lines).Count | Should -Be 1`, `Text` is
    the flag label, and `Detail` is the MessageFirstLine.
  - `It 'leaves out the WER crash report and a lone clean shutdown'`: rows with WER 1001
    (Application) and EventLog 6006 only give 0 lines.
  - `It 'folds the same flag on one server within 10 minutes'`:
    - Three Disk 153 rows at 17:49, 17:50:30 and 17:52 give 1 line with `Count` 3.
    - The text ends with ' (3 in 3 min)'.
    - A fourth row at 18:05 starts a new line.
  - `It 'does not fold across servers'`
  - `It 'folds an unexpected restart and the start into one line'`:
    - 41 at 18:04:00, 6008 at 18:04:01, 6005 at 18:04:02 and Kernel-General 12 at 18:03:58
      give 1 line.
    - The text is 'Restarted without a clean shutdown - back up at 18:04'.
    - The last unflagged row on that server at 17:58:03 adds the detail
      '(no events for about 6 min before that)'.
  - `It 'keeps the restart line without "back up at" when no start event is in the window'`
  - `It 'folds a requested restart'`: 1074 followed by 6006, then 6005 within 5 min, gives
    'Restarted on request - back up at <HH:mm>'.
  - `It 'counts unrecognised errors in the 5 minutes before a crash'`: seven Level 2 unflagged
    rows on AD-01 between 17:53 and 17:56, then an Application Error 1000 at 17:57, give a detail
    containing '(7 errors in the 5 minutes before)'.
  - `It 'puts a gap line between lines 10 minutes or more apart'`: lines at 17:00 and 17:25 give
    the middle line Kind 'Gap', Text '25 minutes later'. Lines 9 minutes apart give no gap.
  - `It 'orders lines by UTC across servers and shows server-local time'`
  - `It 'stops at MaxLines and reports the rest'`: 70 separate flagged events with
    `-MaxLines 60` give 60 Event lines and MoreCount 10.
  - `It 'Get-TimelineRowId names one row'`: 'AD-01|System|4242'.
  - `It 'Format-TimelineGap words the gap'`: test 10, 60, 180 and 2880 minutes.

- [ ] **Step 3: Run the tests and watch them fail**

Run: `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests\ServerEventTimeline.Story.Tests.ps1`

Expected: FAIL, because `Get-TimelineStory` is not recognised.

- [ ] **Step 4: Implement the functions in `ServerEventTimeline.Story.ps1`**

  - Walk the rows once in UTC order. Keep per server the last unflagged row and a short queue
    of unflagged Error/Critical rows from the last 5 minutes.
  - Use `$script:SummaryKindByLabel` to drop flags with no summary kind.
  - Wrap every returned collection in `@()`.

- [ ] **Step 5: Run the tests and watch them pass**, then run the tool's whole folder:
`-Path .\Server-EventTimeline\Tests`.

Expected: all pass.

- [ ] **Step 6: Commit**: `feat: Server-EventTimeline builds a plain-English story of the flagged events`

### Task 2: The story in the ticket note and the HTML report

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1`: `New-TimelineTicketNote`
  (the flagged-rows loop near its end) and `ConvertTo-TimelineHtml`.
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Story.Tests.ps1` and the existing
  ticket-note tests. Find them with `grep -rn "New-TimelineTicketNote" Server-EventTimeline/Tests`.

**Interfaces:**
- Consumes: `Get-TimelineStory` from Task 1.
- Produces: `Format-TimelineStoryText -Story <story> [-MaxLines]` returns `[string[]]`, one line
  per Event line: `'{Server} {yyyy-MM-dd HH:mm} (server local): {Text}'`. It includes no gap
  lines and no detail. When lines are cut, it ends with `'... and N more flagged events (see the report)'`.

- [ ] **Step 1: Write the failing tests**
  - `It 'the ticket note lists story lines instead of raw flagged rows'`: three Disk 153 rows give
    one note line containing '(3 in 3 min)', and no line contains 'Disk 153'.
  - `It 'the ticket note keeps 15 story lines and says how many more'`
  - `It 'the HTML report has a What happened section after What was found'`: the index of
    '<h2>What happened</h2>' is greater than the index of '<h2>What was found</h2>'.
  - `It 'the HTML story is built from the rows the report was given'`: pass only AD-03's rows,
    and the section has no 'AD-01'.
  - `It 'the HTML story encodes text'`: a MessageFirstLine of `<script>` appears as `&lt;script&gt;`.
  - Update any existing assertion on the old `'... - provider ID'` line format to the new
    format, and ledger it as a ruling: the spec replaces those lines.

- [ ] **Step 2: Run the tests and watch them fail**

Run: `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests`

Expected: the new tests fail.

- [ ] **Step 3: Implement `Format-TimelineStoryText` in Story.ps1**

  - Use it in `New-TimelineTicketNote`, built from all rows with `-MaxLines $MaxEventLines`.
  - In `ConvertTo-TimelineHtml`, add the section: a `<ul>` of time, server, text and muted
    detail, plus gap lines as muted `<li>`. Build it from `$Rows`.
  - -NoGui picks both up unchanged.

- [ ] **Step 4: Run the tests and watch them pass**: the folder suite, including the -NoGui
tests in Gui.Tests.

Expected: all pass.

- [ ] **Step 5: Commit**: `feat: Server-EventTimeline ticket note and report tell what happened, in order`

### Task 3: The "What happened" tab in the window

**Files:**
- Modify: `Server-EventTimeline/Start-ServerEventTimeline.ps1`:
  - XAML around `DetailText` (line ~624);
  - `Update-View`/`Update-Summary`;
  - `Start-Search`;
  - a new click handler.
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: `Get-TimelineStory`, `Get-TimelineRowId`, `Format-TimelineStoryText`, and the
  existing `Copy-TimelineRows` pattern for a clipboard call that never throws.
- Produces the named controls:
  - `DetailTabs` (TabControl), holding the `DetailText` tab ("Event details") and the
    "What happened" tab;
  - `StoryList` (ItemsControl or ListBox of story lines);
  - `StoryEmptyText` (TextBlock);
  - `CopyStoryButton` ("Copy for ticket").
- Produces the window function `Show-StoryRow -RowId <string>`.

- [ ] **Step 1: Write the failing tests** (off-screen, STA-gated like the existing layout tests)
  - `It 'has the two detail tabs, the story list and Copy for ticket'`
  - `It 'shows the waiting text before any search'`: StoryEmptyText is 'Search to see the
    important events here, in order.'
  - `It 'shows the nothing-recognised text when no row is flagged'`
  - `It 'fills the story from the rows when a search finishes'`: drive through the same seam the
    existing tests use to load rows into the store.
  - `It 'selects and scrolls to the clicked line''s row, clearing a filter that hides it'`:
    - Set EventKey to another event and the Level filter to Errors, so the target
      Information row is hidden.
    - Call `Show-StoryRow`.
    - EventKey is '' and Level is All.
    - The grid's SelectedItem has that RowId.
  - `It 'Copy for ticket says so instead of failing when the clipboard is busy'`: use a mocked
    clipboard setter, like the Copy selected rows test.

- [ ] **Step 2: Run the tests and watch them fail**: Gui.Tests.

Expected: the new tests fail because the controls are missing.

- [ ] **Step 3: Implement the tab**

  - Wrap `DetailText` in a TabControl in the same grid row.
  - Each story line is a Button in the `CardButton` style, so hover and press states come free.
    It shows the symbol (TextBlock coloured by Category), the time, a server chip, the text and
    a muted detail. Gap lines are muted text.
  - Refresh the story in `Update-Summary`. It already runs only when the row count or server
    state changed, so the story inherits the "every few seconds while arriving" behaviour.
  - Reset it in `Start-Search`.
  - Clicking a line calls `Show-StoryRow`:
    1. If `Select-TimelineRows` on the current filter excludes the row, clear the Level,
       Server, Log, FlaggedOnly and Text filters and the Hidden list and EventKey, then
       `Update-View`.
    2. Turn off "collapse repeats" if it hides the row.
    3. Select the row and `ScrollIntoView`.

- [ ] **Step 4: Run the tests and watch them pass**: the folder suite.

Expected: all pass.

- [ ] **Step 5: Render it off-screen and look**

Add story lines to `render.ps1` in the scratchpad, render at 1288×830 and look at the PNG. Fix
any clipping.

- [ ] **Step 6: Commit**: `feat: Server-EventTimeline "What happened" tab`

*(Part 1 is complete here and can be merged on its own.)*

### Task 4: The time-range filter

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1`: `Test-RowMatchesFilter`,
  `Select-TimelineRows`.
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Produces: filter keys `FromUtc` and `ToUtc` ([datetime], UTC, or `$null` for no limit). A row
  passes when `FromUtc <= TimeUtc < ToUtc`. Add them to the doc comment beside the other keys.

- [ ] **Step 1: Write the failing tests**
  - `It 'keeps rows inside FromUtc to ToUtc, the end not included'`: test both functions on the
    same rows.
  - `It 'ignores a missing FromUtc or ToUtc'`
  - `It 'Select-TimelineRows and Test-RowMatchesFilter agree on the time range'`: compare the
    counts over a mixed set.

- [ ] **Step 2: Run the tests and watch them fail**: Core.Tests.

Expected: the range tests fail.

- [ ] **Step 3: Implement the range in both functions**

Compare `([datetime]$r.TimeUtc).Ticks` with prepared tick values inside the inline loop. Add the
range to the early "no filter" return condition.

- [ ] **Step 4: Run the tests and watch them pass**: the folder suite.

Expected: all pass.

- [ ] **Step 5: Commit**: `feat: Server-EventTimeline filters by a time range`

### Task 5: The strip model

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Story.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Story.Tests.ps1`

**Interfaces:**
- Consumes: the Task 1 story rules (which flags count, restart pairing) and `Get-TimelineRowId`.
- Produces: `Get-TimelineStripModel -Rows <object[]> -Servers <string[]> -StartUtc <datetime>
  -EndUtc <datetime> -Width <double>`, which returns a PSCustomObject:
  - `Lanes` = @(@{ Server; Index })
  - `Marks` = @(@{ Lane; X; Shape ('Triangle'|'Cross'|'Square'|'Diamond'|'Circle'); Color;
    ToolTip; RowId })
  - `Dots` = @(@{ Lane; X; Count; Opacity }), one per slice of about 6 px with at least one
    unflagged Error/Critical row. Opacity runs from 0.35 at 1 to 1.0 at 20 or more.
  - `DownBars` = @(@{ Lane; X1; X2; Text })
  - `Ticks` = @(@{ X; Label })
  - `AxisIsUtc` = [bool]

  X runs from 0 to Width across StartUtc..EndUtc. Rows outside are dropped. Lanes follow the
  `-Servers` order.

- [ ] **Step 1: Write the failing tests**
  - `It 'gives each server a lane, in the order given'`
  - `It 'draws a mark only for flagged rows the story counts'`: WER 1001 gives no mark.
  - `It 'picks the symbol and colour by category, grey for anything unknown'`: a row with
    FlagCategory 'Lockout' gets Shape 'Circle' and Color '#8B94A3'.
  - `It 'puts errors into slices about 6 px wide, one dot per slice, with the count'`: 300 Level 2
    rows within one 6 px slice give 1 dot with Count 300 and Opacity 1.0.
  - `It 'draws a down bar from the last event before an unexpected restart to the start'`
  - `It 'labels the axis in local time when every server shares an offset, in UTC when they differ'`:
    two servers with TimeServerLocal−TimeUtc of −300 and −300 min give AxisIsUtc $false; −300
    and 0 give $true. Read the offset from the rows.
  - `It 'works for one row and for no rows'`: Marks and Dots are empty arrays, not $null, and
    Lanes are still there.
  - `It 'builds 40,000 rows in under 100 ms'`:
    - Use 4 servers, 1% flagged, 10% errors, and width 900.
    - Time the call under pwsh.
    - Also time it in a child `powershell.exe -NoProfile -Command` that dot-sources Core and
      prints the milliseconds (`-Skip` when powershell.exe isn't present).
    - Both must be under 100.

- [ ] **Step 2: Run the tests and watch them fail**: Story.Tests.

Expected: FAIL, because `Get-TimelineStripModel` is not recognised.

- [ ] **Step 3: Implement `Get-TimelineStripModel`**

Make one pass over the rows. Use a lane lookup hashtable and a hashtable keyed by `lane*10000 + slice`
for the dots, and avoid any function call per row. That keeps it inside the 100 ms budget.

- [ ] **Step 4: Run the tests and watch them pass**: the folder suite.

Expected: all pass, including the timing.

- [ ] **Step 5: Commit**: `feat: Server-EventTimeline lays out a picture of the flagged events`

### Task 6: The strip in the window

**Files:**
- Modify: `Server-EventTimeline/Start-ServerEventTimeline.ps1`:
  - XAML: a new row between the filters (Row 0) and EventGrid in the right-hand grid; shift
    the later rows;
  - a `TimeRangeChip` in the filter bar;
  - `Get-CurrentFilter` (FromUtc and ToUtc);
  - `Update-View`;
  - the heartbeat;
  - the ShowAll handler, which also clears the range.
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1`: `Read-TimelineSettings` and
  `Save-TimelineSettings` gain `ShowPicture` ([bool], default `$true`, kept when not given).
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1` and Core.Tests (settings).

**Interfaces:**
- Consumes: `Get-TimelineStripModel` (Task 5), the FromUtc/ToUtc filter keys (Task 4) and
  `Show-StoryRow` (Task 3, reused for a mark click).
- Produces:
  - controls `StripBorder`, `StripScroll`, `StripCanvas`, `HidePictureToggle`,
    `TimeRangeChip`, `ClearRangeButton`;
  - window functions `Update-Strip [-Force]` and `Set-TimeRange -FromUtc -ToUtc` (both `$null`
    clears it).

- [ ] **Step 1: Write the failing tests** (off-screen, STA-gated)
  - `It 'has the picture strip between the filters and the event list'`: check the Grid.Row values.
  - `It 'is about 110 px for 4 servers and stops growing past 6 lanes'`: the height for 4, 6
    and 10 servers. 10 doesn't exceed the 6-lane height, and the ScrollViewer scrolls.
  - `It 'draws one shape per mark and dot, and none for unflagged information rows'`: count the
    Canvas children against the model.
  - `It 'follows the Level filter'`: Errors hides the Update mark.
  - `It 'clicking a mark selects its row'`
  - `It 'Set-TimeRange narrows the list and shows the chip; the chip''s button clears it'`
  - `It 'Show everything again clears the time range too'`
  - `It 'Hide picture folds the strip and is remembered'`: settings under `$TestDrive`, never
    the real path.
  - `It 'does not redraw more than once in 2 seconds while results arrive'`: count Update-Strip
    rebuilds across several heartbeats with rows arriving.
  - Core: `It 'remembers ShowPicture and keeps it when other settings are saved'`

- [ ] **Step 2: Run the tests and watch them fail**: Gui.Tests and Core.Tests.

Expected: the new tests fail.

- [ ] **Step 3: Implement the strip**

  - Draw the model on the Canvas with WPF shapes. Each mark's ToolTip is the model's text, and
    MouseLeftButtonUp calls `Show-StoryRow`.
  - Drag on the Canvas draws a translucent selection Rectangle. On release, a drag wider than
    6 px calls `Set-TimeRange` with the X range mapped back to UTC. Double-click calls
    `Set-TimeRange $null $null`.
  - When a range is set, the model is built with that range, so the axis zooms.
  - `Update-Strip` runs:
    - from `Update-View` (finish, filter change), skipped unless `-Force` or 2 s have passed
      since the last draw while the search runs;
    - on `SizeChanged` through a 200 ms DispatcherTimer.
  - Every handler stays under `Register-TimelineErrorGuard`.

- [ ] **Step 4: Run the tests and watch them pass**: the folder suite.

Expected: all pass.

- [ ] **Step 5: Render off-screen at 1288×830 with 4 servers and at 1920×1080 with 8, and look**

Add marks to `render.ps1` in the scratchpad. The event list must keep most of the height.

- [ ] **Step 6: Commit**: `feat: Server-EventTimeline picture strip above the event list`

### Task 7: The picture in the HTML report, help and README

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Story.ps1` (new function) and
  `ServerEventTimeline.Core.ps1` (`ConvertTo-TimelineHtml`).
- Modify: `Server-EventTimeline/README.md` and the help block in `Start-ServerEventTimeline.ps1`.
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Story.Tests.ps1`

**Interfaces:**
- Consumes: `Get-TimelineStripModel`.
- Produces: `ConvertTo-TimelineStripSvg -Model <model>` returns `[string]`, an inline `<svg>`
  with a `<title>` child per mark and dot. `ConvertTo-TimelineHtml` takes the servers from
  `$Context.Servers` and the window from `$Context.StartUtc`/`EndUtc` (add them to both callers'
  contexts if they are missing). It inserts the SVG under a "Timeline" heading before
  "What happened".

- [ ] **Step 1: Write the failing tests**
  - `It 'the report has one SVG with a title on every mark'`: the count of `<title>` equals
    Marks + Dots.
  - `It 'the SVG encodes every piece of text'`: a server named `a<b` appears as `a&lt;b`.
  - `It 'the report still has no script'`: no `<script` in the output.
  - `It 'a report with no rows still renders'`

- [ ] **Step 2: Run the tests and watch them fail**: Story.Tests.

Expected: the new tests fail.

- [ ] **Step 3: Implement `ConvertTo-TimelineStripSvg` and the insertion**

Use the same shapes and colours as the window. Add a legend row. Text uses `var(--muted)` so
light mode works.

- [ ] **Step 4: Update the README and help**

Describe the "What happened" tab, the picture strip (hover, click, drag, double-click, Hide
picture) and the report sections, in plain English.

- [ ] **Step 5: Run the folder suite and the gates, and watch them pass**

Run:
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`
- `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests`
- `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Tests` (ScriptEncoding, GuiOwnProcess)

Expected: all pass. A new dot-sourced file must not trip `Tests/GuiOwnProcess.Tests.ps1`; if it
does, extend that test's dot-sourced-file rule.

- [ ] **Step 6: Commit**: `feat: Server-EventTimeline report shows the timeline picture` and `docs: Server-EventTimeline picture and story in help and README`
