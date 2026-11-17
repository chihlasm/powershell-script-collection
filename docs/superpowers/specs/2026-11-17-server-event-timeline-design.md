# Server Event Timeline: design

Date: 2026-11-17. Owner: Michael (leaving 2026-11-20; the tool must be finished, documented,
and maintainable by the team without him).

## Intent

"What happened to this server around 3am?" Today a tech opens Event Viewer on each server, one
log at a time, filters by time, and pieces the story together by hand. Problems often cross
servers (the app server broke because SQL01 or a DC hiccupped), and Event Viewer cannot show
several servers on one timeline at all.

This tool takes **several servers and a time window** and shows **every event from the chosen
logs, merged into one timeline**, with known-important events flagged so the eye finds them
first. In Michael's words: not every event is relevant to what happened, but *information is the
key to understanding a problem*. The tool's job is to put the evidence in front of the tech,
quickly and completely, not to decide for them.

Users: helpdesk techs mid-ticket and senior engineers doing incident analysis (see root
`CLAUDE.md` Design Context and `squad/SQUAD.md`).

## Goals

- Pick several servers and a time window, and see all their events on one merged timeline
  within seconds to a minute.
- Flag known-important events with a plain-English label; never hide anything by default.
- Narrow fast when noisy: level, log, server, source, and a text search.
- Full event detail one click away.
- Get the evidence into a ticket: CSV, HTML report, copy rows as text.
- **The window never freezes**, whatever the servers do (unreachable, slow, huge logs).

## Non-goals

- No verdict or root-cause engine ("the cause was X"). Flags label events; they do not judge.
- No changes to any server. Read-only. `Changes anything? No`.
- No live tailing / monitoring.
- No collection of `.evtx` files (other tools do this).
- Not a SIEM: no saved cases, no history, no database.

## Anti-goals (failure even if it technically works)

- The window shows "Not Responding" or a cancel that doesn't stop the work.
- A capped or failed query looks like a complete, quiet log ("no events" when really "couldn't
  read" or "stopped at 5,000"). Every server/log reports its real outcome.
- One unreachable server stops or delays the others.
- A wrong event-ID meaning (an uncited, recalled-from-memory label) that sends a tech down the
  wrong path.

## Constraints

- PowerShell + WPF, Windows PowerShell 5.1 floor (`#Requires -Version 5.1`; WPF GUI on admin
  workstations, per root `CLAUDE.md`). Must also work under PowerShell 7 on Windows.
- Self-contained folder; no modules beyond built-in Windows ones.
- Runs on a workstation, queries servers remotely. Never assumes it runs on the target.
- Repo conventions: comment-based help with REFERENCES, `-LoadFunctionsOnly`, logic separated
  from UI, Pester 5 tests with everything external mocked, UTF-8 with BOM if any non-ASCII,
  `@()` before `.Count`, `[PASS]/[WARN]/[FAIL]/[INFO]` console lines.
- Every event-ID meaning and log/channel name verified on Microsoft Learn and cited.
- Timing: aimed at Friday 2026-11-20, but Michael said full scope matters more than the date;
  build everything in this doc rather than cutting. Build in this order anyway, so the tool is
  usable at each step: core timeline + status + cancel + filters + CSV/copy, then flags, then
  operational logs and Security, then HTML report, Run as, Pick from AD, All logs.

## Approaches considered

| | Approach | Trade-off |
|---|---|---|
| **A (chosen)** | **PowerShell + WPF + background runspaces** | Matches the repo and the ServiceDesk-Toolkit bundle; the team can maintain it after Michael leaves; reuses the runspace + `DispatcherTimer` pattern already working in `PortMonitor/PortMonitor.ps1` and `FolderPermissionManager/FolderPermissionManager-GUI.ps1`. Runspace code is fiddly. |
| B | C# WPF app | Most robust, but needs a build step, a compiled `.exe` is often blocked on client servers, and it would be the only non-PowerShell tool, with nobody to maintain it. |
| C | Browser UI over local `HttpListener` | Easy to keep responsive, but the collection has been moving GUIs to WPF, and it brings port/firewall prompts. |

Michael picked A. Freezing is a question of where the work runs, not the language; A solves it
with the design under "Staying responsive".

## What Michael decided

- Broad incident view: **all events in the window**, important ones flagged, nothing hidden by
  default.
- **Several servers merged** on one timeline (Server column).
- **Logs = option B**: System + Application + a hand-picked set of ~10 operational logs as
  checkboxes (all ticked by default). **Security is an opt-in checkbox.** An **"All logs"**
  checkbox for when stuck.
- **PowerShell + WPF + runspaces** (approach A).
- "Run as" credential: kept, but tucked away (he is unsure how often it's needed).
- **Times shown and entered in each server's local time**, with a UTC column.
- **Full scope over the Friday date.**

## The design

### Folder

`Server-EventTimeline/`
- `Start-ServerEventTimeline.ps1`: the WPF window (thin). `-LoadFunctionsOnly` supported.
- `ServerEventTimeline.Core.ps1`: pure logic, dot-sourced by the GUI and by tests: building
  query filters, the flag catalog, normalising events into rows, merging/sorting, filtering,
  export rendering (CSV/HTML/text), time-window maths.
- `README.md`, `Tests/*.Tests.ps1`.
- Added to the root `README.md` index and to `ServiceDesk-Toolkit` (labelled *Changes anything?
  No*). The bundle builder (`ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`) is itself 5.1 and
  works from a `$manifest` list, so this is one manifest entry plus the README row.

### The window (sketch)

```
 Servers: [APP01, SQL01, DC01          ] [Pick from AD...]       More options >
 When:  (o) Around [2026-11-17 03:00] +/- [15 min v]   ( ) From [...] To [...]
        [Last hour] [Last 24 hours]
 Logs:  [x] System [x] Application [x] Task Scheduler [x] Windows Update ...
        [ ] Security (slow on DCs/file servers)   [ ] All logs (slow)
                                                        [ Search ]  [ Cancel ]
 APP01  done - 1,240 events   SQL01  querying...   DC01  couldn't reach: WinRM refused
 ! APP01 System: stopped at 5,000 events - narrow the window or raise the cap
 Filter: [Errors+ v] [All servers v] [All logs v] [search text............]
 Time (server local)  Server Level   Flag            Source              Message
 03:02:11             APP01  Error   Disk error      disk                The device ...
 03:02:14             SQL01  Error   Service crash   Service Control...  The SQL Serv...
 ----------------------------------------------------------------------------------
 Detail of selected row: full message, event ID, log, source, record ID, user, machine
 [Export CSV] [Export HTML report] [Copy selected rows]
```

Dark by default with the blue accent; follow the existing WPF GUIs' look.

### Inputs

- **Servers:** free text (comma/space/newline separated), plus **Pick from AD**: domain
  controllers (`Get-ADDomainController -Filter *`) and a computer name search, if the
  ActiveDirectory module loads (runtime `Import-Module` in try/catch; the button is disabled with
  a tooltip if not). Duplicates removed, case-insensitive.
- **Time window:** default **Around [time] +/- [15 min]** (choices 5/15/30/60 min, 2/6 h);
  switch to **From/To**; quick buttons *Last hour*, *Last 24 hours*. Times entered are
  **server local time** (Michael's decision: it matches the client's "it broke at 3am" and what
  Event Viewer shows on the server). Each server's window is converted to UTC using that
  server's own UTC offset, read in the remote call; so "03:00" means 03:00 on each server.
  *Last hour* / *Last 24 hours* are relative to now and need no conversion.
- **Logs:** System and Application, plus the operational set below, as checkboxes ticked by
  default; Security opt-in; All logs opt-in.
- **More options (collapsed):** per-log event cap (default 5,000), per-server timeout (default
  60 s), **Run as** credential (`Get-Credential`, passed to the remote call).

#### The operational log set (starting list; builder verifies each channel name on Learn)

Task Scheduler, Windows Update client, Group Policy, Remote Desktop session manager and
connection manager, SMB client and SMB server, Windows Time, Failover Clustering, Hyper-V VMMS.
A channel that doesn't exist or is disabled on a server is **skipped and reported** in that
server's status detail ("Task Scheduler log is turned off on APP01"), never an error that stops
the server. Note that the Task Scheduler operational log is disabled by default on many servers;
say so plainly when that's why it's empty.

### Querying

- One background runspace per server (a `RunspacePool`, max ~8 at once), so servers run in
  parallel.
- **Pre-check:** a TCP connect with a 2-second timeout to WinRM (5985). If WinRM is unreachable,
  try RPC (135) for the fallback. Neither reachable → "couldn't reach" immediately, no hang.
- **Primary transport:** `Invoke-Command -ComputerName` running `Get-WinEvent -FilterHashtable`
  on the server (filtering happens server-side; only matching events cross the wire), returning
  plain projected objects, not raw `EventLogRecord`s. **Fallback** when WinRM is closed:
  `Get-WinEvent -ComputerName` (remote event log over RPC).
- **One query per log** (a missing channel in a multi-log filter errors the whole call), with
  `StartTime`/`EndTime` and `-MaxEvents` = cap + 1 so "capped" can be detected exactly.
- "No events found" from `Get-WinEvent` is an empty result, not an error.
- **Timeout is per log, not per server** (builder's call, from the review): each log query gets
  the timeout (default 60 s). A log that exceeds it is marked "timed out" and the server moves on
  to its next log; completed logs are kept. A whole-server timeout would routinely kill exactly
  the busy DCs and file servers people care about.
- **"All logs" has a per-server total cap** of 50,000 events (adjustable in More options) on top
  of the per-log cap, to bound memory; hitting it is reported like any other cap.
- **When to fall back to RPC** (builder's call): only on *connection-level* WinRM failures:
  port 5985 closed, WinRM transport errors, Kerberos/SPN failures, a target given by IP or
  outside the domain that TrustedHosts rejects. **Access denied is reported, not retried** over
  RPC (it would almost certainly be denied there too, and retrying doubles the wait). Each
  outcome names the transport used ("via remote event log (WinRM unavailable)").
- **Cancel and the RPC path** (builder's call): `PowerShell.Stop()` does not reliably interrupt a
  blocking `Get-WinEvent -ComputerName` call. Cancel marks the server "cancelled" at once, the
  UI stops waiting and discards its results, and the runspace is disposed when the call returns.
  A background RPC call may run on briefly; this is accepted (killable out-of-process queries
  are out of scope) and noted in the README. The WinRM path stops properly.
- **Run as:** `-Credential` on both transports when set.
- **"All logs":** list the server's channels with records (`Get-WinEvent -ListLog *` filtered to
  `RecordCount -gt 0`), then query each (same cap per log).

### Staying responsive (the anti-goal)

- The UI thread only draws. All querying happens in the runspace pool.
- Results flow through a thread-safe queue; a `DispatcherTimer` (~250 ms) drains it and adds
  rows **in batches**, so the window updates as each server finishes.
- The grid uses WPF row virtualization (don't turn on grouping, which disables it) so 20,000+
  rows scroll smoothly. Filtering is done on an in-memory list / `ICollectionView`, not by
  re-querying.
- **Cancel** stops every running runspace (`PowerShell.Stop()`/`BeginStop`) and marks unfinished
  servers "cancelled" immediately (see the RPC note under Querying). The window must stay usable
  while it does so.
- Closing the window mid-query cleans up the pool.

### Each server's status

Shown live as a status strip/list: *waiting / querying / done (N events) / done with gaps /
couldn't reach: reason / timed out / cancelled*. Reasons in plain English ("access denied: check
you're an admin on DC01 or use Run as", "WinRM and remote event log both unreachable"). Capped
logs get a yellow banner naming server + log. These outcomes also appear in the HTML report.

### Rows and flags

Each row: **time in that server's local time** (column header "Time (server local)", Michael's
decision), a **UTC** column, server, log, level, flag (blank for most), source/provider, event
ID, message (first line in the grid, full in the detail pane), record ID, user, machine.

The merged sort is always on UTC, so the order is correct. When the queried servers have
different UTC offsets from each other, show a one-line note above the grid ("APP01 and LON-SQL01
are in different time zones: compare the UTC column across them"). CSV and HTML carry both
columns.

**Flag catalog:** keyed on **log + provider + event ID** (the same ID means different things from
different providers, as `Entra-DeviceActivityTimeline` learned). Categories and starting
candidates, each to be verified on Microsoft Learn and cited next to the entry:

- Restart/shutdown: User32 1074 (who/why), Kernel-Power 41, EventLog 6008, Kernel-General 12/13,
  EventLog 6005/6006. Copy the verified entries and REFERENCES from
  `Entra-DeviceActivityTimeline/Get-DeviceActivityTimeline.ps1`.
- Service crashes: Service Control Manager 7031, 7034, 7023/7024 (failed), 7000/7009 (didn't
  start/timeout).
- Disk/storage: disk 7, 11, 51, 153; Ntfs 55, 98, 137; volmgr 161; storport/stornvme resets.
- Updates: WindowsUpdateClient 19/20/43, Servicing / TrustedInstaller installs.
- App crashes/hangs: Application Error 1000, Application Hang 1002, Windows Error Reporting 1001.
- Bugcheck: BugCheck 1001 in System.
- Time jumps: Kernel-General 1, Time-Service warnings.
- Resource exhaustion: Resource-Exhaustion-Detector 2004 (low memory).

The builder trims anything that can't be confirmed on Learn rather than shipping an uncited
label. Flagged rows get a coloured flag cell and a "Flagged only" filter option.

### Filters

Level (All / Warnings+ / Errors+ / Critical), Server, Log, Flagged only, and a text box matching
message, source, and event ID. Counts update ("Showing 312 of 18,450"). Default view: all
levels, so nothing is hidden by default.

### Output

- **Export CSV** of the visible (filtered) rows, `Export-Csv -NoTypeInformation -Encoding UTF8`,
  both local and UTC time columns.
- **Export HTML report**: header with window (local + UTC), servers, logs chosen, per-server
  outcome (including failures and caps), filters in effect, then the rows. Self-contained,
  HTML-encoded messages.
- **Copy selected rows** as plain text lines for a ticket note.
- Default output folder: `-OutputPath`, default `Reports` beside the script; filenames
  `ServerEventTimeline_yyyy-MM-dd_HHmmss.*`. Also write a `.log` of status lines.

### Testing

Pester 5, everything external mocked (`Invoke-Command`, `Get-WinEvent`, the port check,
AD cmdlets with throwing stubs, file writes in `$TestDrive`); never targets `$env:COMPUTERNAME`.
Cover: time-window maths (around/from-to, UTC), per-log query building, capped detection,
missing/disabled channels, unreachable/denied/timeout outcomes, flag lookup by provider+ID,
merge/sort across servers, filters, CSV/HTML/text rendering (including HTML encoding), and
that the core never touches the UI. Verify real cmdlet parameter names via `Get-Command`
(per `squad/SQUAD.md`). A smoke-test start mode that builds the window without querying
(matching SQ-029's convention) if cheap. Run `Tests\Test-ScriptParse.ps1` and
`Tests\Invoke-AllTests.ps1` as the gate.

## Calls made without Michael (check these)

- Per-log timeout (60 s) rather than per-server; 50,000-event per-server cap for "All logs".
- RPC fallback only on connection-level WinRM failures; access denied is reported, not retried.
- Cancel on the RPC path abandons the call rather than killing it (README notes this).
- Default cap 5,000 per log; default window +/- 15 min; max ~8 servers queried at once.
- One query per log; missing/disabled channels reported, not errors.
- Flags never filter; default view shows all levels.

## Left to the builder

- Exact WPF layout, colours, and control choices within the sketch and the repo's existing look.
- Runspace plumbing details (copy the working pattern from PortMonitor/FolderPermissionManager).
- Which flags survive Learn verification.
- Exact operational channel names (verify each; drop any that can't be confirmed).
- Max parallel servers and the polling interval.
