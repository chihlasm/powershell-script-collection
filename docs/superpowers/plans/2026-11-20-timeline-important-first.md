# Timeline: Important Events First, Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each log is read in two parts: first the important events (errors, warnings, recognised events), newest first, then routine events newest first into the room left. So the evidence is complete and cuts only ever drop the oldest routine events.

**Architecture:** The remote query script gains a `Part` (Important or Routine) and a per-log importance rule computed in Core. The engine queues one Important task per log after the probe, and queues the Routine task with budget `Cap - importantCount` only when the Important task ends `Read`/`Capped`. The per-log status entry keeps `Outcome`/`Count`/`Reason` for the important part (so every existing gap check keeps working) and adds `RoutineOutcome`/`RoutineCount`/`RoutineReason`.

**Tech Stack:** Windows PowerShell 5.1 (GUI and engine), with the code that runs on target servers kept PowerShell 3.0-safe. Pester 5 under `pwsh`.

**Spec:** `docs/superpowers/specs/2026-11-20-timeline-important-first-design.md`

## Global Constraints

- `$script:LogQueryScript` runs on target servers: PowerShell 3.0-safe. No `SuppressHashFilter`, no `::new()`, no `.Where()`/`.ForEach()`.
- No real event log reads, no real servers: Get-WinEvent / Invoke-Command are mocked, and engine tests use fake probe/log scripts.
- Cite Microsoft Learn next to the query code and in `.NOTES` REFERENCES (URLs are in the spec, "Facts this rests on").
- AuditFailure keyword = `4503599627370496` (0x10000000000000). Lockout event = `4740`.
- Row conversion stays in the task runspace (`RowConverterTask`), never the UI thread.
- Files containing non-ASCII must be saved as UTF-8 with BOM (`Tests/ScriptEncoding.Tests.ps1`).
- Wrap filtered results in `@()` before `.Count`.
- Consumers must tolerate status `Logs` entries **without** the Routine fields (old fakes, saved contexts): check `$l.PSObject.Properties['RoutineOutcome']`.
- Gates: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1` and `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1` (run from the repo root).

## Review Focus

1. **A recognised Information event in both reads** (for example 6005 in System): it must appear once, not twice. Test in Task 1.
2. **More than 20 recognised IDs for one log.** Windows rejects a FilterHashtable with too many IDs ("The specified query is invalid"). System has about 22 unique IDs in `$script:FlagCatalog`, so IDs go in chunks of at most 20 per query. Test in Task 1.
3. **A log where every important query finds nothing** (each call throws NoMatchingEventsFound): the result is `Read` with 0 events, and the routine read still runs with the full budget. Test in Tasks 1 and 2.
4. **Security log without admin rights**: the important read `Failed` (access denied), no routine read runs, and the card shows one failure, not two. Test in Task 2.
5. **Cancel mid-run on many servers**: a server whose important reads are done keeps its verdict (`Done`, empty `Reason`). Test in Task 2.

---

### Task 1: The importance rule and the two-part log read

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1` (new function after `Get-EventFlag`, ~line 263)
- Modify: `Server-EventTimeline/ServerEventTimeline.Engine.ps1:15-25` (REFERENCES), `:31-68` (`$script:LogQueryScript`), `:211-262` (`Invoke-LogQuery`)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`, `Server-EventTimeline/Tests/ServerEventTimeline.Engine.Tests.ps1`
- Also commit: the spec and this plan.

**Interfaces:**
- Produces: `Get-TimelineImportantRule -LogName <string>` → `[PSCustomObject]@{ Ids = [int[]]; AuditFailure = [bool] }`. Levels 1, 2, 3 are always important, so they aren't returned.
  - Security: `Ids = @(4740)`, `AuditFailure = $true`.
  - A log in `$script:FlagCatalog`: the unique sorted IDs of its entries, `AuditFailure = $false`.
  - Any other log: `Ids = @()`, `AuditFailure = $false`.
- Produces: `Invoke-LogQuery ... -Part <'Important'|'Routine'> (default 'Important')`. `-Cap` is the budget for this part. It returns the same object as today (`Outcome` Read/Capped/Failed, `Count`, `Events`, `Reason`) and is called by Task 2.
- Produces: `$script:LogQueryScript` param order: `$LogName, $StartTicks, $EndTicks, $MaxEvents, $ComputerName, $Credential, $Part, [int[]]$ImportantIds, [bool]$AuditFailure`. The new arguments go at the end because WinRM passes them by position.

- [ ] **Step 1: Branch and commit the docs**

```bash
git checkout -b feat/important-first
git add docs/superpowers/specs/2026-11-20-timeline-important-first-design.md docs/superpowers/plans/2026-11-20-timeline-important-first.md
git commit -m "docs: Server-EventTimeline important-first design and plan"
```

- [ ] **Step 2: Write failing tests**

Core.Tests, new `Describe 'Get-TimelineImportantRule'`:
- `Security` → `Ids` equals `@(4740)`, `AuditFailure` is `$true`.
- `System` → `Ids` contains 6005, 1074, 41, 19 and 1. No duplicates (`@($r.Ids).Count -eq @($r.Ids | Select-Object -Unique).Count`). `AuditFailure` is `$false`.
- `Microsoft-Windows-SMBServer/Operational` → `@($r.Ids).Count -eq 0`.

Engine.Tests, under `Describe 'Invoke-LogQuery'`. Extend `New-RawEvent` with `-Level` (default 4), `-RecordId` (default 1) and `-Keywords` (default 0), and set `Keywords` on the object.
- Rename `'asks for one more than the cap, oldest first, ...'` to `'reads newest first (regression: oldest first dropped the end of the window)'`. Assert `-not $Oldest`.
- `'important read asks for levels 1-3 and the recognised IDs in chunks of at most 20'`. Mock Get-WinEvent returning `@()`. Call `-Part Important -LogName System`. Assert one call with `$FilterHashtable[0].Level` equal to `1,2,3`. Assert every call carrying `Id` has `@($FilterHashtable[0].Id).Count -le 20`. Assert the union of all `Id` values equals `(Get-TimelineImportantRule System).Ids`.
- `'important read for Security asks for audit failures and 4740'`. Assert a call with `$FilterHashtable[0].Keywords -eq 4503599627370496` and a call with `Id` containing 4740.
- `'important read merges the queries newest first, without duplicates, and caps'`. Mock returns RecordIds 5, 3 for the level query and 5, 4 for the ID query (by parameter filter). `-Cap 2` → `Outcome 'Capped'`, Events RecordIds `5, 4`.
- `'routine read skips important events before the budget'` (non-Security). Mock returns RecordIds 9 (Id 6005, Level 4), 8 (Id 7036), 7 (Id 7036), 6 (Id 7036). `-Part Routine -Cap 2` → Events RecordIds `8, 7`, `Outcome 'Capped'`. Assert `$FilterHashtable[0].Level` equals `0,4,5`.
- `'routine read of Security skips audit failures, 4740 and levels 1-3'`. Events: Keywords `0x8010000000000000` (skip), Id 4740 (skip), Id 4624 with Keywords `0x8020000000000000` (keep) → 1 event.
- `'no matching events in every important query is an empty Read'`.

- [ ] **Step 3: Run them and confirm they fail**

Run: `pwsh -NoProfile -Command "Invoke-Pester -Path .\Server-EventTimeline\Tests\ServerEventTimeline.Engine.Tests.ps1,.\Server-EventTimeline\Tests\ServerEventTimeline.Core.Tests.ps1 -Output Detailed"`
Expected: the new tests FAIL (`Get-TimelineImportantRule` not found, `$Oldest` still set).

- [ ] **Step 4: Implement `Get-TimelineImportantRule` in Core**

Derive the IDs from `$script:FlagCatalog` (filter by `Log`, select `Id`, unique, sorted). Comment that 4740 is a Level 0 audit *success* and cite the event-4740 page.

- [ ] **Step 5: Implement the two-part read in `$script:LogQueryScript` and `Invoke-LogQuery`**

- Drop `Oldest`. Get-WinEvent returns newest first by default (cite the Get-WinEvent page).
- **Important:** run separate `Get-WinEvent -FilterHashtable` calls, each with `MaxEvents = $MaxEvents` and the same LogName/StartTime/EndTime keys as today:
  - `Level = 1,2,3`
  - one call per chunk of at most 20 `$ImportantIds`
  - when `$AuditFailure`, one call with `Keywords = 4503599627370496`

  Each call catches NoMatchingEventsFound on its own. Merge the results, drop duplicate `RecordId`s, sort by `RecordId` descending (newest first within one log), and keep the first `$MaxEvents`.
- **Routine:** a single call with `Level = 0,4,5` for non-Security logs, and no Level key for Security, without `MaxEvents`. Pipe it through a `Where-Object` that drops important events, then `Select-Object -First $MaxEvents` (since PowerShell 3.0 this stops the upstream read early). For non-Security, an event is important when its `Id` is in `$ImportantIds`. For Security, an event is important when `($_.Keywords -band 4503599627370496) -ne 0`, its `Id` is in `$ImportantIds`, or its `Level` is 1–3.
  - Touch `.Message` only in the projection, after the filter: formatting messages is the slow part.
- `Invoke-LogQuery` gets the rule from `Get-TimelineImportantRule -LogName $LogName` and passes `$Part, $rule.Ids, $rule.AuditFailure` after the existing arguments (also in the WinRM `ArgumentList`).
- Capped reasons:
  - Important: `'more than {0:N0} errors and warnings - kept the newest {0:N0}' -f $Cap`
  - Routine: `'kept the newest {0:N0} routine events; older ones in the window weren''t read' -f $Cap`
- Add the Learn citations (spec, "Facts this rests on") next to the code and to the REFERENCES block. Remove `-Oldest` from the REFERENCES line.

- [ ] **Step 6: Run the tests and confirm they pass**

Same command as Step 3. Expected: PASS, including the unchanged existing `Invoke-LogQuery` tests.

- [ ] **Step 7: Commit**

```bash
git add Server-EventTimeline/ServerEventTimeline.Core.ps1 Server-EventTimeline/ServerEventTimeline.Engine.ps1 Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1 Server-EventTimeline/Tests/ServerEventTimeline.Engine.Tests.ps1
git commit -m "feat: Server-EventTimeline reads important events first, newest first"
```

---

### Task 2: Engine schedules important then routine reads

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Engine.ps1:348-352` (`DefaultLogTask`), `:354-403` (`Start-TimelineEngine` status objects), `:431-439` (`Set-TimelineLogOutcome`), `:449-472` (`Complete-TimelineProbe`), `:474-510` (`Complete-TimelineLog`), `:512-579` (`Update-TimelineEngine`), `:581-599` (`Stop-TimelineEngine`)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.EngineRun.Tests.ps1`, plus every fake `LogScript` in `Server-EventTimeline/Tests/*.Tests.ps1` (for example `ServerEventTimeline.Gui.Tests.ps1:~290`)

**Interfaces:**
- Consumes: `Invoke-LogQuery -Part` (Task 1).
- Produces:
  - Log scripts (default and fakes) take `param($EnginePath, $Server, $Transport, $LogName, $StartUtc, $EndUtc, $Cap, $Credential, $Part)`.
  - Status per server gains `RoutineEventCount` (int). `EventCount` stays the total of both parts.
  - Each `Logs` entry: `Log, Outcome, Count, Reason` (important part) plus `RoutineOutcome` (`Pending|Read|Trimmed|TimedOut|Failed|Cancelled|NotRead`), `RoutineCount`, `RoutineReason`.
  - `Set-TimelineLogOutcome -Status -Log -Outcome [-Count] [-Reason] [-Part 'Important'|'Routine' = 'Important']`. A new entry starts with `RoutineOutcome 'Pending'`, except Skipped logs, which get `RoutineOutcome 'Skipped'`.
  - Tasks carry `Part` (`$task.Part`).

- [ ] **Step 1: Update the existing fakes**

Add `$Part` as the last parameter of every fake log script in the test files. In `$script:TwoEventLog` (EngineRun.Tests), return its two Level 4 events only when `$Part -eq 'Routine'` and an empty `Read` for Important, so existing counts stay the same.

- [ ] **Step 2: Write failing tests**

Add to `EngineRun.Tests`, new `Describe 'Timeline engine: important first'`. Each fake records calls to a synchronized list passed in through the closure, or returns events that encode `$Part`/`$Cap`.
- `'reads important first, then routine with the room left'`. The Important fake returns 3 Level 2 events. With `-Cap 5`, the Routine fake receives `$Cap -eq 2`. The log ends `Outcome 'Read'`, `Count 3`, `RoutineOutcome 'Read'`, `RoutineCount 2`. Server `EventCount 5`, state `Done`.
- `'no routine read when important events fill the cap'`. Important returns `Capped` with 5 events at `-Cap 5`. No Routine call happens. `RoutineOutcome 'Trimmed'`, `RoutineReason` like `'*no room left after 5 important events*'`. State `DoneWithGaps`, because the important part is Capped.
- `'no routine read after the important read times out'`. The Important fake sleeps 10 s with `-TimeoutSec 1`. `Outcome 'TimedOut'`, `Reason` like `'errors and warnings not read*'`, `RoutineOutcome 'NotRead'`, `RoutineReason` like `'*errors and warnings weren''t read*'`. No Routine call.
- `'no routine read after the important read fails'` (access denied). Same assertions with `Outcome 'Failed'`.
- `'a routine timeout leaves the server Done'`. The Routine fake sleeps → `RoutineOutcome 'TimedOut'`, state `Done`, `$st.Reason` empty.
- `'the server total trims routine events only'`. `-ServerTotalCap 3`, two logs, each with 2 important and 2 routine events, `-MaxConcurrency 1`. All 4 important rows are kept (`Count` 2 each, `Outcome 'Read'`), and routine is trimmed to 3 in total across both logs: at least one log has `RoutineOutcome 'Trimmed'` with reason like `'*3 event total*'`. State `Done`.
- `'cancel after the important reads keeps the server Done'`. Important returns at once, Routine sleeps 30 s. Wait until a Routine task is running, then call `Stop-TimelineEngine`. State `Done`, `RoutineOutcome 'Cancelled'`, `Reason` empty.
- `'cancel with an important read still running marks the server Cancelled'` (the existing 'cancels at once' test stays as is with Part-aware fakes).

Rewrite the two existing total-cap tests (`'stops reading a server at the total cap…'`, `'marks a log cut short by the server total cap as Capped…'`) to the new rule: the trimming lands on `RoutineOutcome`, the important `Outcome` stays `Read`, and the state is `Done`. Make the fakes in `'times out a slow log…'` and `'a stopped task that is still running…'` sleep for `$Part -eq 'Important'` only, and keep their assertions.

- [ ] **Step 3: Run them and confirm they fail**

Run: `pwsh -NoProfile -Command "Invoke-Pester -Path .\Server-EventTimeline\Tests\ServerEventTimeline.EngineRun.Tests.ps1 -Output Detailed"`
Expected: the new and rewritten tests FAIL.

- [ ] **Step 4: Implement the scheduling**

- `Complete-TimelineProbe` queues tasks with `Part = 'Important'` and `Cap = $Engine.Cap`.
- Add `Request-TimelineRoutineRead -Engine -Task -ImportantResult`:
  - Important `Read`/`Capped` → `budget = [Math]::Min($Engine.Cap - $count, $Engine.ServerTotalCap - $st.RoutineEventCount)`.
    - `budget -le 0` → `RoutineOutcome 'Trimmed'`. The reason is `'no room left after {0:N0} important events'` when the per-log room is the limit, otherwise the existing total-cap text `'stopped at the {0:N0} event total for this server'`.
    - Otherwise append a Routine task (same parameters, `Part 'Routine'`, `Cap = budget`) to the end of `Pending`.
  - Important `TimedOut`/`Failed` → `RoutineOutcome 'NotRead'`, `RoutineReason "errors and warnings weren't read, so routine events weren't either"`.

  Call it from `Complete-TimelineLog` (important part) and from the timeout and failure branches of `Update-TimelineEngine` for Important tasks.
- `Complete-TimelineLog`:
  - Important part: add every row. No total-cap trimming.
  - Routine part: today's total-cap logic, applied to `RoutineEventCount`. A routine result that comes back `Capped` maps to `RoutineOutcome 'Trimmed'` with its reason. When the server total is reached, stop and mark only the pending/running **Routine** tasks of that server as `Trimmed`.
- Important timeout reason: `"errors and warnings not read: didn't answer within {0} s"`. Routine timeout reason: `"routine events not read (didn't answer within {0} s); errors and warnings were read"`.
- The busy count in `Update-TimelineEngine` already covers both parts. Gaps stay `Outcome -notin Read, Skipped`.
- `Stop-TimelineEngine`: a server in `Querying` with no pending/running Important task and no log whose `Outcome` is still `Pending` goes to `Done`/`DoneWithGaps` by the usual rule. Its unfinished routine parts become `Cancelled`. Every other `Waiting`/`Querying` server is `Cancelled` as today. Never write to `$st.Reason` for routine cancels.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `pwsh -NoProfile -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests`
Expected: all Server-EventTimeline tests PASS.

- [ ] **Step 6: Commit**

```bash
git add Server-EventTimeline/ServerEventTimeline.Engine.ps1 Server-EventTimeline/Tests
git commit -m "feat: Server-EventTimeline engine reads routine events into the room left"
```

---

### Task 3: Say what was cut, in the cards, reports, help and README

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1:990-1018` (`Get-TimelineServerCards`), `:451-457` (HTML report details)
- Modify: `Server-EventTimeline/ServerEventTimeline.Workbook.ps1:406` (workbook details)
- Modify: `Server-EventTimeline/Start-ServerEventTimeline.ps1:117-124` (help for `-Cap`/`-TotalCap`), `:565-570` (CapBox/TotalCapBox tooltips), `:1932-1934` (log lines)
- Modify: `Server-EventTimeline/README.md:~170` and `:292`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`, `Server-EventTimeline/Tests/ServerEventTimeline.Workbook.Tests.ps1`

**Interfaces:**
- Consumes: the `Logs` entry fields from Task 2.
- Produces: `Get-TimelineRoutineNote -Status <server status>` → `[string]` (empty when nothing was cut), used by the cards.

- [ ] **Step 1: Write failing tests**

- `Get-TimelineRoutineNote`:
  - 2 logs `Trimmed` → `'older routine events trimmed in 2 logs'`.
  - 1 log `TimedOut` → `'routine events not read in 1 log'`.
  - 1 `Cancelled` → `'routine events cancelled in 1 log'`.
  - Mixed → the parts joined with `'; '`, in that order.
  - Entries without `RoutineOutcome` → `''`.
- `Get-TimelineServerCards`: a `Done` server with 1 trimmed log has `Warn` `$false`, and its `Findings` end with `'(older routine events trimmed in 1 log)'`.
- `Get-TimelineBannerText`: a status whose only cut is routine `Trimmed` → `''`.
- `New-TimelineTicketNote`: a `Done` server, no flags or errors, with routine `Trimmed` is still ruled out (no `NotChecked` item for it).
- HTML report and workbook details: a log with `RoutineOutcome 'Trimmed'` adds the line `'System (routine events): Trimmed kept the newest 3,200 routine events; older ones in the window weren''t read'`.

- [ ] **Step 2: Run them and confirm they fail**

Run: `pwsh -NoProfile -Command "Invoke-Pester -Path .\Server-EventTimeline\Tests\ServerEventTimeline.Core.Tests.ps1,.\Server-EventTimeline\Tests\ServerEventTimeline.Workbook.Tests.ps1 -Output Detailed"`
Expected: the new tests FAIL.

- [ ] **Step 3: Implement**

- Add `Get-TimelineRoutineNote`. In `Get-TimelineServerCards`, append `" ($note)"` to `Findings`, or use the note as `Findings` when there are none. Don't change `Warn`.
- Report, workbook and GUI log lines: one extra line per log where `RoutineOutcome -notin 'Read','Pending','Skipped'`, formatted `'{0} (routine events): {1} {2}'`.
- Text:
  - CapBox tooltip: `Most events read per log. Errors, warnings and recognised events are read first; routine events fill the rest, newest first.`
  - TotalCapBox tooltip: `A safety limit for routine events across all logs on one server. Errors, warnings and recognised events are never dropped for it.`
  - Mirror both in the `-Cap`/`-TotalCap` help and in the README parameter table.
- README "stopped at…" bullet: replace it with the two new texts (important capped → narrow the window or raise the cap; routine trimmed → older routine events only, the errors are complete).

- [ ] **Step 4: Run the tests and confirm they pass**

Same command as Step 2. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Server-EventTimeline
git commit -m "feat: Server-EventTimeline says when only routine events were trimmed"
```

---

### Task 4: Full gates

- [ ] **Step 1: Parse gate**

Run: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`
Expected: no parse failures.

- [ ] **Step 2: Full test gate**

Run: `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1`
Expected: 0 failed, including `Tests/PSVersionFloor.Tests.ps1` and `Tests/ScriptEncoding.Tests.ps1`.

- [ ] **Step 3: Fix anything red, commit, and hand back for merge.** After merge and push, run `Server-EventTimeline\Build-TestZip.ps1` (team practice).
