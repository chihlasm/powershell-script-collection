# Server-EventTimeline: read the important events first

Date: 2026-11-20 · Status: draft for approval · Tool: `Server-EventTimeline/`

## Why

Run against three of a 50+ server estate, the tool reported "stopped at 5,000 events" on
Application and GroupPolicy/Operational, and "didn't answer within 60 s" on SMBServer and
TaskScheduler. Today each log is **one** read: every level, **oldest first**, stopped at the cap
(`ServerEventTimeline.Engine.ps1`, `$script:LogQueryScript`, `Oldest = $true`). That has two
consequences:

1. When a log hits the cap, what is dropped is the **end** of the window, which is usually the
   part nearest the problem.
2. Routine Information events (Group Policy, Task Scheduler chatter) use up the cap, and a
   timeout loses the **whole** log, errors included.

Michael wants the important data (errors, warnings, and the events the tool recognises) read
completely on every server, so a run across many servers can be trusted. When something has to
be cut, it should be the oldest routine events.

## Goals

- For every log read, Critical, Error and Warning events and the recognised events
  (`$script:FlagCatalog`) come back in full, up to the per-log cap, **newest first**.
- Routine events (everything else) still appear in the grid as they do today (option A agreed
  in conversation). They fill the room left under the per-log cap, newest first.
- A slow or failed routine read never loses the important events of that log.
- The status, banner, cards, ticket note and reports say plainly what was cut, and treat "older
  routine events trimmed" as less serious than "important events missing".

## Non-goals

- No count-only / volume summary of the routine events that weren't read (option B, declined).
- No "include routine events" checkbox (option C, declined).
- No change to how servers are reached (WinRM, then RPC), to the grid's level filter, or to
  repeat grouping.
- No new recognised events beyond the Security rule below.

## Anti-goals

- A run that looks complete while important events were dropped. Any loss of important events
  must still mark the server "with gaps" and block "ruled out" in the ticket note.
- Duplicated rows. An event returned by the important read must not come back in the routine
  read.
- Raising the PowerShell floor of the code that runs on the target servers. The query script
  stays 3.0-safe. `SuppressHashFilter` only appears in the PowerShell 7 `Get-WinEvent` docs, so it
  must not be used in it.

## Facts this rests on (verified on Microsoft Learn, 2026-11-20)

- `Get-WinEvent` returns events newest to oldest by default; `-Oldest` reverses it.
  https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
- FilterHashtable keys `Level` (Critical 1, Error 2, Warning 3, Informational 4, Verbose 5,
  LogAlways 0), `Id` and `Keywords` (AuditFailure = 4503599627370496 = 0x10000000000000), and
  an array of hashtables is a union.
  https://learn.microsoft.com/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable
- Security audit events are written at **Level 0** and the outcome is in Keywords. Event 4625's
  XML shows `<Level>0</Level>` and `<Keywords>0x8010000000000000</Keywords>`.
  https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625

## Approaches considered

1. **Two reads per log, in sequence (chosen).** The important read runs first (cap = per-log
   cap). When it finishes, the routine read for that log is queued with
   `budget = max(Cap - importantCount, 0)`. This keeps "N events per log" meaning what it says,
   the important events always win, and a slow routine read can't lose them.
2. Two reads per log in parallel, each with its own cap. Slightly faster, but a log can return
   2× the cap and the routine events don't just "fill the rest". Rejected.
3. One read, ranked afterwards. Windows can only filter or order a log by time on its side, so
   everything would still have to be read first, and one timeout would still lose it all.
   Rejected.

## Design

### What counts as important

| Log | Important read | Routine read |
|---|---|---|
| Any log except Security | Level 1, 2, 3 **or** an event ID the FlagCatalog lists for that log (for logs outside the catalog, levels only) | Everything else in the window |
| Security | Keywords = AuditFailure **or** event 4740 (account locked out, written as an audit success) **or** Level 1, 2, 3 | Everything else in the window |

- Matching the recognised IDs by ID only (not provider) on the server is fine: an occasional
  extra event from another provider with the same ID is harmless. Flags are still assigned by
  `Get-EventFlag` with provider matching, as today.
- 4740 is added because the tool's own Security hint is about sign-in and lockout problems, and
  a lockout is not an audit failure. Verified: 4740's XML shows `<Level>0</Level>` and
  `<Keywords>0x8020000000000000</Keywords>` (audit success), so an AuditFailure filter alone
  would miss it.
  https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740

### Reads and order

- Both reads drop `-Oldest` (newest first) and ask for `budget + 1` events to detect "more
  than budget", as today.
- When a probe completes, one **important** task per log is queued (same place as today's log
  tasks). When an important task completes as `Read` or `Capped`, that log's **routine** task
  is appended to the end of the pending queue, so on a busy run routine reads naturally go
  after the important reads already waiting.
- *(My call, from the review.)* When the important read `TimedOut` or `Failed`, the routine
  read is **not** run. Its outcome is `NotRead` with reason "errors and warnings weren't read,
  so routine events weren't either". A second read would double the wait on the slow logs
  that caused this change, couldn't succeed after access denied, and would fill the grid with
  routine rows for a log whose errors are missing.
- If the routine budget is 0, no routine read runs. The log's routine outcome is `Trimmed` with
  reason "no room left after N important events".
- The routine read must exclude what the important read returned. It's the builder's call
  whether to do that with `-FilterXml` `<Suppress>` on the target or by skipping matching
  events in the query script **before** touching `.Message` (the slow part). Either way the
  budget counts routine events only, and the script stays PowerShell 3.0-safe.
- The per-server total (`ServerTotalCap`, default 50,000) applies to **routine events only**.
  Important events are never dropped to make room. When the total is reached, the remaining
  routine reads for that server are not run (outcome `Trimmed`, reason names the total) and
  running ones are stopped, as today.
- The timeout applies to each read separately.
- Cancel marks both parts of unfinished logs `Cancelled`.
- *(My call, from the review.)* On cancel, a server whose important reads have **all**
  finished (none pending or running) becomes `Done` (or `DoneWithGaps` by the usual rule), not
  `Cancelled`. Its unfinished routine reads are `Cancelled` and shown as a quiet card note
  ("routine events cancelled in N logs"). The note must not be written to `$st.Reason`, which
  blocks "ruled out". So a tech who stops waiting during the slow routine reads at the end of
  a 50-server run keeps every verdict that is already complete. Servers with important reads
  still unfinished are `Cancelled` as today. The card keeps showing "reading" until the
  routine reads end; only cancel moves it to Done early.

### Status model

Keep **one entry per log** in `$st.Logs`. The existing `Outcome`, `Count` and `Reason` describe
the **important** read, so every existing consumer that checks `Outcome -ne 'Read'` for gaps
(banner, ticket note, `Test-TimelineServerComplete`, -NoGui exit code, report details, workbook)
keeps meaning "important events missing". Add `RoutineOutcome` (`Pending`, `Read`, `Trimmed`,
`TimedOut`, `Failed`, `Cancelled`, `NotRead`), `RoutineCount` and `RoutineReason`. `EventCount`
on the server is the sum of both.

Server state:
- `DoneWithGaps` only when an **important** read is not `Read` (or skipped as today).
- Routine trimmed, timed out or failed leaves the server `Done`. The card adds a quiet note,
  e.g. "older routine events trimmed in 2 logs" (or "routine events not read in 1 log" for
  timeout/failure). These notes aren't warnings.

### Wording

| Situation | Where | Text (plain English) |
|---|---|---|
| Important capped | banner (yellow), ticket note "not checked" | `AD-03 Application: more than 5,000 errors and warnings - kept the newest 5,000; narrow the window or raise the cap` |
| Important timed out / failed | banner, ticket note | as today, but "errors and warnings not read - …" |
| Routine trimmed | server card note, report/workbook details; **not** banner, **not** ticket note | `Application: kept the newest 3,200 routine events; older ones in the window weren't read` |
| Routine timed out / failed | same as trimmed | `TaskScheduler: routine events not read (didn't answer within 60 s); errors and warnings were read` |

The cap box keeps its meaning (events per log). Update its tooltip, the `-Cap`/`-TotalCap`
help and the README: "errors, warnings and recognised events are read first; routine events
fill the rest, newest first. The server total limits routine events only."

### Ticket note

A server can still be "ruled out" when its important reads were all `Read`, even if routine
events were trimmed or not read, because recognised events are in the important read.

## Constraints

- Code that runs on target servers: PowerShell 3.0-safe (root `CLAUDE.md`; `Tests/PSVersionFloor.Tests.ps1`).
- Row conversion stays in the task's runspace (`RowConverterTask`), never the UI thread.
- Tests use fakes only (squad rules): extend the engine fakes with the read part. Never query a
  real event log.
- Add citations next to the query code and to the script's `.NOTES` REFERENCES.
- Run `Build-TestZip.ps1` after merge + push (team practice).

## Tests the builder must add

- Query script: important filter for a catalog log (levels + recognised IDs), a non-catalog log
  (levels only), Security (AuditFailure + 4740); no `Oldest`; routine read excludes important
  events and its budget counts routine only.
- Engine: routine task queued only after the important task completes; budget = cap − important
  count; budget 0 → `Trimmed` without a read; important `TimedOut`/`Failed` → no routine read,
  routine `NotRead`; cancel after all important reads finished → server `Done`, routine
  `Cancelled`, `Reason` empty; cancel with an important read unfinished → server `Cancelled`; server total trims routine only and never
  important; important timeout → `DoneWithGaps`; routine timeout/trim → `Done` with a note;
  cancel marks both parts.
- Regression: a capped log keeps the **newest** events (the old behaviour kept the oldest).
- Banner/ticket note/`Test-TimelineServerComplete`: routine-only trimming doesn't add a gap or
  block "ruled out"; important capping does.

## Left to the builder

- `-FilterXml` Suppress vs. client-side skip for the routine read (constraints above).
- Exact card-note and status-line strings within the wording table's intent.
- How the report/workbook list routine outcomes (one extra detail line per log is enough).
