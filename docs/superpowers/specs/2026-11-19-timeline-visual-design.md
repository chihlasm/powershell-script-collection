# Server Event Timeline: seeing what happened

Date: 2026-11-19. Owner: Michael. Tool: `Server-EventTimeline/`. Follows the sidebar layout
(`2026-11-18-timeline-sidebar-layout-design.md`).

## Why

The tool is called a timeline, but the window and the HTML report both show a list sorted by
time. To see "AD-01's disk started complaining, then an app crashed, then it restarted" you
have to read row by row and keep the times in your head, across several servers. Michael saw
two mockups (`.superpowers/brainstorm/1308-1795103870/content/timeline-visual.html`) and found
both useful. He asked which one is more likely to break the window and then chose to build both:
the plain-English list first, because it is small and safe, then the picture.

## Goals

- A tech sees the order of the important events, across all servers, without reading every row.
- The same story reaches the ticket and the HTML report, so whoever reads them sees it too.
- Nothing here makes the window freeze or vanish. It has frozen once already this week, from
  too much work while results arrived.

## Non-goals

- New event IDs. Both parts use the events the tool already flags (`$script:FlagCatalog`). The
  "what are you troubleshooting?" topics idea (lockouts and so on) is a separate change. The
  picture should take any flagged event, so new topics show up in it for free.
- Changing the event list, or the -NoGui console lines. Part 2 adds one filter, the time range.
- Guessing causes. The story says what happened and when, never "the disk caused the crash".

## Anti-goals

- A picture that draws one shape per event. That would bring back the freeze at 40,000 events.
- A story that hides events. It summarises the flagged ones; the list still shows everything.

## Approaches

1. **Picture only: lanes above the event list.** It shows "this came before that" at a glance,
   across servers. It's the riskier one: drawing, hover, click and zoom code on the window thread.
2. **Plain-English list only: a "What happened" tab.** Small, safe, and pasteable into a
   ticket, but it's text, so order across servers is slower to take in.
3. **Both, the list first (chosen).** The list is built from an "important events in order"
   model that the picture reuses, so the second part costs less. If the picture runs into
   trouble, the list has already shipped.

## Design

### Part 1: "What happened" (build first)

**The model.** A new pure function in `ServerEventTimeline.Core.ps1` turns the rows into story
lines. Each line has the server, the server-local time of its first event, a category (for the
symbol), the text, a muted detail, and the identity of its first row so a click can find it.
The identity is Server + Log + RecordId, not `Get-TimelineEventKey`, which names a kind of
event (`Provider|Id`) rather than one row.

- Only flagged rows count. A flag with no summary kind is left out: clean shutdowns, and the
  crash report (WER 1001) that follows every app crash and would double each one. The kinds come
  from `$script:SummaryKinds`.
- **Repeats fold.** The same flag on the same server within 10 minutes of the previous one makes
  one line with a count, for example "Disk I/O had to be retried (3 in 3 min)".
- **A restart is one line.** An unexpected-restart flag (Kernel-Power 41, EventLog 6008) and the
  "Windows started" flags (6005, Kernel-General 12) on that server within 5 minutes become a
  single line: "Restarted without a clean shutdown - back up at 18:04". A clean restart
  folds the same way: "Restart or shutdown requested" (1074) and its shutdown/start events
  become "Restarted on request - back up at 18:04". When the server's last
  event before the restart is known, add "(no events for about 6 min before that)". It's an
  estimate from the gap, and the wording says so.
  - Check on Microsoft Learn when 41 and 6008 are written (at the next start, not at the moment
    of the crash) and cite it. The wording must not claim a time Windows didn't record.
- **Context for crashes.** On app-crash, service-failure, blue-screen and unexpected-restart
  lines, count the unflagged Error and Critical rows on that server in the 5 minutes before,
  for example "(7 errors in the 5 minutes before)". These are errors the tool doesn't recognise,
  shown as a count so they stay visible.
- **Gaps.** When 10 minutes or more pass between two lines, put a muted line between them, such
  as "25 minutes later" or "3 hours later".
- **Order and limit.** Lines go in UTC order, with the server's local time shown. The list stops
  at 60 lines and ends with "... and N more flagged events - filter the list to see them".
- The line text is the existing flag label. The detail is the first line of the event's
  message, trimmed. Nothing is parsed out of message text, because it is localised.

**In the window.** The detail pane (`DetailText`) becomes two tabs:
- **Event details** is today's pane, unchanged.
- **What happened** shows the story lines with the symbol, time, a server chip and the text, with
  the detail in muted type.
- The tab tells the story of the whole search and ignores the filters.
- Clicking a line selects and scrolls to its first event in the list. If a filter hides that
  event (including "Show only this event" and the time range from Part 2), the filters are
  cleared first. A **Copy for ticket** button copies the story as plain text.
- The tab fills in when a search finishes, and every few seconds while results arrive. Before
  any results it says "Search to see the important events here, in order."
- With nothing flagged it says "Nothing the tool recognises happened in this window - check the
  errors in the list."

**In the ticket and the report.**
- `New-TimelineTicketNote` uses the story lines for its event lines, replacing today's raw
  "server time: label - provider ID" lines.
  - It keeps the 15-line limit, counting story lines only.
  - Each line is the server, time and text, with no detail line and no gap lines, so 15
    lines still means 15 happenings.
  - The note is built from all rows, as it is today.
- `ConvertTo-TimelineHtml` gains a "What happened" section after "What was found". It is built
  from the same rows the report contains, so an export of a filtered list tells the story of
  what was exported.
- -NoGui calls the same two functions, so its ticket note and report gain the story too. Its
  console lines stay as they are.

### Part 2: the picture (build second)

**Where.** A strip between the filter bar and the event list, in a new row of the right-hand
grid. It is about 110 px tall for up to 4 servers, and each extra lane adds 22 px. Past 6 lanes
the strip scrolls rather than growing, so the event list keeps its room. A small "Hide picture"
toggle folds it, and the choice is remembered in the settings.

**What it draws.**
- One lane per server. The time axis covers the search window.
- Flagged events get a symbol by flag category (`FlagCategory` on the row), in the mockup's
  shapes and colours:

  | Category | Symbol |
  | --- | --- |
  | Disk, LowMemory | amber triangle |
  | AppCrash, ServiceCrash, Bugcheck | red ✖ |
  | Update | blue square |
  | TimeJump (time changes and time sync problems) | purple diamond |
  | Restart: requested, clean shutdown or Windows started | grey circle |

  - Any category added later without its own symbol gets the grey circle, so new flags
    (from the topics idea, for example) still appear.
  - Flags the story leaves out, such as the WER 1001 crash report, are also left out of the
    picture.
- An unexpected restart draws a grey "down" bar across the quiet gap, labelled as in the story.
- Ordinary Error and Critical rows are grouped into time slices about 6 px wide, one small dot
  per slice. The dot gets stronger with more errors, and its hover text gives the count.
- A legend sits under the lanes.
- The strip follows the Level, Server, Log and text filters, so it always pictures what the
  list shows. With Level set to Errors, flagged Information events such as updates and starts
  disappear from it too.

**Aligning the times.** Lanes line up on UTC, so servers in different time zones line up
correctly. If every server has the same UTC offset, label the axis in that local time. If they
differ, label it in UTC and add "(UTC)" to the axis.

**Using it.**
- Hovering over a symbol shows the flag, server, time, source and ID.
- Clicking a symbol selects and scrolls to that event, the same as a story line.
- Dragging across the strip narrows the list to that stretch of time. It shows as a removable
  "17:52 - 17:58 ×" chip in the filter bar. Double-clicking the strip, or the chip's ×, goes back
  to the whole window.
  - The range is a real filter, like the others. It goes into `Test-RowMatchesFilter` and
    `Select-TimelineRows`, so CSV and HTML export and Copy see the same rows the list shows.
  - The strip's axis zooms to the range.
  - The "What happened" tab doesn't narrow; it always covers the whole search.

**Staying safe.**
- The shapes come from a pure function in Core: rows, width and filters in, a list of marks out.
  Only flagged events and the grouped dots become shapes, so there are never more than a few
  hundred.
- Redraw when a search finishes, when a filter changes, on resize (after a 200 ms pause), and at
  most every 2 s while results arrive.
- A test with 40,000 rows fails if building the marks takes 100 ms or more under Windows
  PowerShell 5.1. This follows the heartbeat test in `EngineRun.Tests.ps1`.
- All hover, click and drag code runs under the existing error guard
  (`Register-TimelineErrorGuard`).

**In the HTML report.** The same lanes as inline SVG, with a `<title>` on each symbol for the
hover text. There's no script, so the report stays self-contained.

## Constraints

- PowerShell 5.1 floor for this tool. Pure logic stays in Core and is testable without a window.
  Test the window off-screen, the way the sidebar was tested; agents don't launch the GUI.
- Any new Microsoft fact (when 41 and 6008 are written, for example) gets checked on Microsoft
  Learn and cited in code and in `.NOTES` REFERENCES.
- Keep the existing colours (Accent `#5DADE2`, Warn `#E0B43A`) and dark-first styling. The
  report keeps its light-mode colours.
- Update the README and help.

## Left to the builder

- Exact symbol sizes, spacing and the hover box styling.
- Story wording beyond the examples above, kept in plain English.
- How the "every few seconds while results arrive" refresh hooks into the existing heartbeat.

## My calls (Michael can overrule)

- The main reader is the tech working the ticket. The report version should also make sense to
  a client, but it isn't polished for presentation. Michael hasn't said which matters more.
- The story replaces the raw event lines in the ticket note instead of being added alongside.
- The 10-minute repeat fold, the 5-minute restart pairing, the 10-minute gap line and the
  60-line limit.
- The window's tab tells the story of the whole search, while the strip and the exported report
  follow the filters.
- The -NoGui ticket note and report gain the story, because they share the functions.
- The symbol for each flag category, including grey for restarts and anything new.
- The drag-selected range is a real filter that exports and Copy respect.
