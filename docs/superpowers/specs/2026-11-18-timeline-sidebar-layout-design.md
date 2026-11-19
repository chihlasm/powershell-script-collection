# Server Event Timeline: sidebar layout

Date: 2026-11-18. Owner: Michael. Tool: `Server-EventTimeline/`. Follows the server list
design (`2026-11-18-timeline-server-list-design.md`).

## Why

With four servers in the new list, the inputs card, the per-server status lines, the "what
was found" strip and the fixed 170 px detail pane left the event list one row tall in an
830 px window. Michael compared two mockups and picked the left sidebar: "significantly
simpler to read and understand and gives more options for UX real estate".

## Approaches

1. **Tidy the current layout.** Fold the inputs into one line after Search, merge status and
   findings, add a resizable detail pane. Familiar and the least work.
2. **Left sidebar (chosen).** All inputs in a column on the left; results fill the right.
   The server list can grow without touching the events.
3. **Two screens, set-up then results.** Each is simple, but going back and forth is clumsy.

## Design

**Left sidebar** (column 300 px wide, draggable from 260 to 520 px):
- Top to bottom: Which servers? (the server list), When?, Which logs? with More options,
  then Search and Cancel, then input errors.
- Below that, an **EACH SERVER** block with one card per server.
  - Line 1 is the state: ✓ done, … reading, ✗ couldn't reach, plus the event count and how
    the server was reached.
  - Line 2 is what was found, wrapped.
  - Clicking a card filters the event list to that server; clicking it again shows all
    servers.
  - The yellow incomplete-logs banner, the time-zone note and the "Security log not read"
    hint sit under the cards.
- The sidebar scrolls vertically when the window is short.
- A « button collapses it to a 28 px strip; » brings it back.

**Right side:**
- The filter bar, then the event list (it gets all the remaining height), a drag handle,
  then the detail pane (starts at 120 px, at least 60 px).
- A bottom bar holds Export CSV, Export HTML report, Copy selected rows, Copy summary for
  ticket, and the status message.
- The save folder goes on the row below that.

Unchanged: every control's behaviour, the menus, the right-click menu and the -NoGui mode.
The separate status list (Consolas lines) goes; its lines are folded into the server cards.
The per-server lines are still written to the log file.

## Left to the builder

- The exact glyphs and colours on the cards (✓ in Accent, ✗ and "with gaps" in Warn).
- How the When? inputs wrap to fit about 280 px.
