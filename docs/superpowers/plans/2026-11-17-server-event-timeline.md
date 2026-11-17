# Server Event Timeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A WPF tool that queries several servers' event logs for a time window and shows every event on one merged, filterable timeline, with known-important events flagged, without ever freezing.

**Architecture:** Three files. `ServerEventTimeline.Core.ps1` holds pure logic (time windows, log set, flag catalog, row shaping, filters, exports, error classification). `ServerEventTimeline.Engine.ps1` holds the remote scriptblocks and a runspace-pool engine that the UI polls from a `DispatcherTimer`. `Start-ServerEventTimeline.ps1` is the thin WPF window. The unit of background work is one **(server, log)** task, preceded by one **probe** task per server, so per-log timeouts and per-server isolation fall out of the task model.

**Tech Stack:** Windows PowerShell 5.1 / PowerShell 7 on Windows, WPF (PresentationFramework), `Invoke-Command` (WinRM) with `Get-WinEvent -ComputerName` (RPC) fallback, Pester 5.

**Spec:** `docs/superpowers/specs/2026-11-17-server-event-timeline-design.md`

## Global Constraints

- Folder `Server-EventTimeline/`; self-contained; no modules beyond built-in Windows ones (ActiveDirectory optional, runtime `Import-Module` in try/catch).
- `#Requires -Version 5.1` on all three scripts; no `#Requires -Modules`.
- Read-only: nothing writes to any server. Never target `$env:COMPUTERNAME` in tests.
- Every event-ID meaning and channel name verified on Microsoft Learn, cited next to the code, and listed in `.NOTES` REFERENCES. Drop anything that can't be verified.
- Keep files pure ASCII (build icons/marks from `[char]` code points); otherwise UTF-8 with BOM.
- `@()` before every `.Count` on a filtered result.
- Comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES` with REFERENCES) on the entry script; `-LoadFunctionsOnly` and `-SmokeTest` switches; `-OutputPath` default `Reports` beside the script.
- Filenames `ServerEventTimeline_yyyy-MM-dd_HHmmss.*`; log timestamps `yyyy-MM-dd HH:mm:ss`; console lines `[PASS]`/`[WARN]`/`[FAIL]`/`[INFO]` Green/Yellow/Red/Cyan.
- Defaults: window +/- 15 min (choices 5, 15, 30, 60 min, 2 h, 6 h); per-log cap 5,000; per-log timeout 60 s; "All logs" per-server total cap 50,000; pool max 8; timer 250 ms; port-check timeout 2 s.
- Times shown and entered in **each server's local time**, with a UTC column; merged sort on UTC.
- Flags label, never filter. Default view: all levels.
- Tests: Pester 5 under pwsh; mock `Invoke-Command`, `Get-WinEvent`, `Get-CimInstance`, the port check, AD cmdlets (throwing stubs, `ADPS_LoadDefaultDrive=0`); files in `$TestDrive`. WPF tests skip unless the thread is STA (pattern: `FolderPermissionManager/Tests/FolderPermissionManager-App.Tests.ps1`).
- Gate: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1` and `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1`.
- Commits: `feat:`/`docs:`/`fix:` prefix, ending `Co-Authored-By:` naming the model doing the work.

## Review Focus

1. **RPC-path messages are blank.** `Get-WinEvent -ComputerName` renders message text with the *workstation's* provider DLLs, so SQL/Veeam/role events often have `Message = $null`. Expect a placeholder naming the event, never an empty cell or a crash. (Test in Task 2.)
2. **Localized servers.** `LevelDisplayName` is localized; level filters and colours must use the numeric `Level` (1 Critical, 2 Error, 3 Warning, 0/4 Information, 5 Verbose). (Test in Task 2.)
3. **Server name input mess**: FQDNs, trailing commas, blank lines, duplicates differing in case, an IP address. Expect a clean de-duplicated list; IP targets are allowed (WinRM may reject them via TrustedHosts → falls back to RPC). (Test in Task 1.)
4. **A window crossing a DST change or the user typing an invalid date.** Invalid input disables Search with a plain message; DST is handled by taking the offset at the window start from the server (accepted approximation, noted in README). (Test in Task 1.)
5. **HTML report with hostile message text** (`<script>`, `&`, quotes in event messages). Expect encoded output. (Test in Task 3.)

---

### Task 1: Core: inputs, time windows, log set

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.Core.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Produces:
  - `ConvertTo-ServerList -Text [string] -> [string[]]`: split on comma/semicolon/whitespace/newline, trim, drop empties, de-duplicate case-insensitively keeping first spelling.
  - `New-TimelineWindow -Mode ('Around'|'Range'|'Relative') [-At [datetime]] [-PlusMinusMinutes [int]] [-From [datetime]] [-To [datetime]] [-LastMinutes [int]] -> [PSCustomObject]@{ Mode; StartLocal; EndLocal; LastMinutes }` (`StartLocal`/`EndLocal` are server-local wall-clock, `DateTimeKind.Unspecified`). Throws `ArgumentException` with plain text when `From >= To` or values missing.
  - `ConvertTo-UtcWindow -Window -UtcOffsetMinutes [int] [-NowUtc [datetime]] -> @{ StartUtc; EndUtc }`: Around/Range subtract the offset; Relative uses `NowUtc.AddMinutes(-LastMinutes)` to `NowUtc`.
  - `Get-TimelineLogCatalog -> [PSCustomObject[]]@{ Name; Label; Default [bool]; Group ('Core'|'Operational'|'Security') }`: System, Application, the operational set (Task Scheduler, Windows Update client, Group Policy, RDS LocalSessionManager, RDS RemoteConnectionManager, SMB client, SMB server, Windows Time, Failover Clustering, Hyper-V VMMS), Security (`Default = $false`). Each `Name` is a verified channel name with a Learn citation comment.

- [ ] **Step 1: Write failing tests**
  - `ConvertTo-ServerList 'app01, APP01;sql01.contoso.local`n`n 10.0.0.5,'` → `@('app01','sql01.contoso.local','10.0.0.5')`.
  - `New-TimelineWindow -Mode Around -At '2026-11-17 03:00' -PlusMinusMinutes 15` → StartLocal `02:45`, EndLocal `03:15`.
  - `New-TimelineWindow -Mode Range -From '2026-11-17 04:00' -To '2026-11-17 03:00'` throws, message contains `From must be before To`.
  - `New-TimelineWindow -Mode Around` with no `-At` throws a plain message (Review Focus 4); `-Mode Range` across the 2026-11-01 US DST change still returns the typed wall-clock values unchanged.
  - `ConvertTo-UtcWindow` with offset `-300` turns `02:45` local into `07:45` UTC; Relative 60 with `NowUtc 12:00Z` → `11:00Z..12:00Z`.
  - `Get-TimelineLogCatalog`: contains `System` and `Application` with `Default $true`; `Security` has `Default $false`; 12 or fewer operational entries; no duplicate `Name`.
- [ ] **Step 2: Run** `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests` → FAIL (functions not defined).
- [ ] **Step 3: Implement** the four functions. Verify each channel name on Learn first (record the URL beside each entry); drop any that can't be confirmed and adjust the test count.
- [ ] **Step 4: Run** the same command → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline core inputs, time windows and log set`.

### Task 2: Core: flag catalog and rows

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Consumes: none.
- Produces:
  - `$script:FlagCatalog`: array of `@{ Log; Provider; Id; Category; Label }`, keyed on log + provider + id. Categories: `Restart`, `ServiceCrash`, `Disk`, `Update`, `AppCrash`, `Bugcheck`, `TimeJump`, `LowMemory`. Starting candidates are in the spec's "Flag catalog"; copy verified restart entries and their REFERENCES from `Entra-DeviceActivityTimeline/Get-DeviceActivityTimeline.ps1` (`$script:ActivityMap`). Every entry carries a Learn URL comment; drop unverifiable ones.
  - `Get-EventFlag -Log -Provider -Id -> $null | @{ Category; Label }`
  - `ConvertTo-TimelineRow -Server [string] -Event [PSCustomObject] -UtcOffsetMinutes [int] -> [PSCustomObject]` where `-Event` is the projected remote shape `@{ TimeCreatedUtc; Id; ProviderName; Level; LogName; Message; RecordId; UserSid; MachineName }`. Output properties: `Server, Log, TimeUtc, TimeServerLocal, Level, LevelName, FlagCategory, Flag, Provider, EventId, Message, MessageFirstLine, RecordId, User, Machine`.
  - `Merge-TimelineRows -Rows [object[]] -> [object[]]` sorted by `TimeUtc`, then `Server`, then `RecordId`.

- [ ] **Step 1: Write failing tests**
  - `Get-EventFlag -Log System -Provider User32 -Id 1074` → Category `Restart`; `-Provider 'Some-Other' -Id 1074` → `$null` (provider matters).
  - `Get-EventFlag -Log System -Provider 'Service Control Manager' -Id 7031` → `ServiceCrash`; `Application`/`Application Error`/`1000` → `AppCrash` (only if verified; otherwise test the entries that survived).
  - Row with `Level 2` → `LevelName 'Error'`; `Level 0` and `4` → `'Information'`; `Level 1` → `'Critical'` (Review Focus 2).
  - Row with `Message $null`, provider `MSSQLSERVER`, id `17883` → `Message` = `(No message text: the event's provider isn't installed on this workstation. Event 17883 from MSSQLSERVER.)`, `MessageFirstLine` same (Review Focus 1).
  - Multi-line message → `MessageFirstLine` is the first non-empty line.
  - `TimeServerLocal` = `TimeUtc` + offset; `Merge-TimelineRows` orders two servers' rows by UTC.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Do the Learn verification for each catalog entry before writing it.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline flag catalog and timeline rows`.

### Task 3: Core: filters, exports, failure classification

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Core.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Consumes: row shape from Task 2.
- Produces:
  - `Test-RowMatchesFilter -Row -Filter @{ MinLevel ('All'|'Warning'|'Error'|'Critical'); Server ('*'|name); Log ('*'|name); FlaggedOnly [bool]; Text [string] } -> [bool]`: Warning+ means Level in 1,2,3; Error+ 1,2; Critical 1. Text matches message, provider, or event ID, case-insensitive, literal (not regex).
  - `ConvertTo-TimelineText -Rows -> [string]`: one line per row `yyyy-MM-dd HH:mm:ss (server local) | SERVER | Level | Provider | ID | first line`.
  - `Export-TimelineCsv -Rows -Path` (`Export-Csv -NoTypeInformation -Encoding UTF8`; columns include `TimeServerLocal` and `TimeUtc`).
  - `ConvertTo-TimelineHtml -Rows -Context @{ WindowText; Servers; Logs; ServerOutcomes; FiltersText; GeneratedAt } -> [string]`: self-contained HTML, all text through `[System.Net.WebUtility]::HtmlEncode`, outcomes section lists failures, caps, timeouts, skipped logs. Dark-first styling with blue accent.
  - `Get-RemoteFailureKind -ErrorRecord -> 'AccessDenied'|'Connection'|'Other'`: `AccessDenied` for access-denied remoting/RPC errors (HRESULT 0x80070005 / FullyQualifiedErrorId containing `AccessDenied`); `Connection` for WinRM transport, Kerberos/SPN, TrustedHosts and unreachable errors (`PSRemotingTransportException` other than access denied, RPC server unavailable 0x800706BA); else `Other`. Cite the docs consulted.
  - `Get-FailureText -Kind -Server -> [string]`, plain English, e.g. AccessDenied: `Access denied on DC01: check you're an admin there, or use Run as.`

- [ ] **Step 1: Write failing tests**: each `MinLevel` boundary; `Text '7031'` matches by ID; `Text '[x'` doesn't throw (literal); `FlaggedOnly` excludes rows with blank `Flag`; CSV round-trips both time columns in `$TestDrive`; HTML for a message `<script>alert(1)</script> & "q"` contains `&lt;script&gt;` and no `<script>` (Review Focus 5); HTML lists a capped log and an unreachable server; `Get-RemoteFailureKind` on constructed ErrorRecords: access-denied remoting error → `AccessDenied`, transport error with "WinRM cannot complete the operation" → `Connection`, `UnauthorizedAccessException` → `AccessDenied`, generic `RuntimeException` → `Other`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline filters, exports and failure classification`.

### Task 4: Engine: probe and per-log remote queries

**Files:**
- Create: `Server-EventTimeline/ServerEventTimeline.Engine.ps1` (dot-sources Core)
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Engine.Tests.ps1`

**Interfaces:**
- Consumes: `ConvertTo-UtcWindow`, `Get-RemoteFailureKind`, `Get-FailureText`.
- Produces:
  - `Test-TcpPortQuick -ComputerName -Port -TimeoutMs 2000 -> [bool]` (`System.Net.Sockets.TcpClient.BeginConnect` + wait handle).
  - `Invoke-ServerProbe -ComputerName [-Credential] -WindowStartLocal [datetime] -> [PSCustomObject]@{ Server; Reachable [bool]; Transport ('WinRM'|'RPC'|''); UtcOffsetMinutes; TimeZoneId; Channels (@{ Name; IsEnabled; RecordCount }); FailureKind; Reason }`. Order: port 5985 open → `Invoke-Command` returning `[TimeZoneInfo]::Local` offset at `WindowStartLocal` and `Get-WinEvent -ListLog *` (`-ErrorAction SilentlyContinue`) projected to Name/IsEnabled/RecordCount. On `Connection` failure or port closed → port 135 open → RPC: `Get-WinEvent -ListLog * -ComputerName` and `Get-CimInstance Win32_OperatingSystem` over a DCOM `CimSession` (`New-CimSessionOption -Protocol Dcom`) for `CurrentTimeZone` (current offset; README notes the DST approximation). `AccessDenied` → not reachable, no fallback. Neither port → `Reason 'WinRM and remote event log are both unreachable from here.'`
  - `Invoke-LogQuery -ComputerName -Transport -LogName -StartUtc -EndUtc -Cap [int] [-Credential] -> [PSCustomObject]@{ Server; Log; Outcome ('Read'|'Capped'|'Failed'); Count; Events (projected shape from Task 2); Reason }`. `Get-WinEvent -FilterHashtable @{ LogName; StartTime; EndTime } -MaxEvents ($Cap + 1)`; run inside `Invoke-Command` for WinRM, with `-ComputerName` for RPC. Projection happens on the server (WinRM) so only plain objects cross the wire; `TimeCreatedUtc` = `TimeCreated.ToUniversalTime()`. The "No events were found" error is an empty `Read`, not `Failed` (match on the error id `NoMatchingEventsFound`; verify). More than `Cap` → trim to `Cap`, `Capped`.
  - `Get-LogPlan -Probe -Catalog -SelectedNames [string[]] -AllLogs [bool] -> @{ Query [string[]]; Skipped (@{ Log; Reason }) }`: a selected log missing from `Channels` → skipped `"<Label> log doesn't exist on <server>"`; present but disabled → `"<Label> log is turned off on <server>"` (Task Scheduler gets the extra note that it is off by default). `AllLogs` adds every channel with `RecordCount -gt 0`.

- [ ] **Step 1: Write failing tests** (mock `Test-TcpPortQuick`, `Invoke-Command`, `Get-WinEvent`, `Get-CimInstance`, `New-CimSession`; servers named `srv-fake-01` etc.):
  - 5985 open + Invoke-Command ok → Transport `WinRM`, offset passed through.
  - 5985 closed, 135 open → Transport `RPC`; `Invoke-Command` never called.
  - Invoke-Command throws Connection-kind → falls back to RPC.
  - Invoke-Command throws AccessDenied → `Reachable $false`, `FailureKind 'AccessDenied'`, `Get-WinEvent -ComputerName` never called.
  - Both ports closed → unreachable with the exact reason text.
  - `Invoke-LogQuery` with Cap 3 and 4 mocked events → `Capped`, Count 3; with NoMatchingEventsFound error → `Read`, Count 0; with other error → `Failed` and plain reason.
  - `Get-LogPlan` skips a missing and a disabled channel with the right text; `AllLogs` adds only channels with records; no duplicates when a channel is both selected and in AllLogs.
  - Parameter-name guard: for `Get-WinEvent`, `Invoke-Command`, `Get-CimInstance`, `New-CimSession`, `New-CimSessionOption`, assert via `Get-Command` that every parameter name used exists on the real cmdlet.
- [ ] **Step 2: Run** `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\Server-EventTimeline\Tests` → FAIL.
- [ ] **Step 3: Implement.** Verify `Get-WinEvent` FilterHashtable keys, `-MaxEvents`, and the no-events error id on Learn; cite.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline probe and per-log remote queries`.

### Task 5: Engine: runspace pool, polling, timeouts, cancel

**Files:**
- Modify: `Server-EventTimeline/ServerEventTimeline.Engine.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Engine.Tests.ps1`

**Interfaces:**
- Consumes: Task 4 functions; `ConvertTo-TimelineRow`.
- Produces:
  - `Start-TimelineEngine -Servers [string[]] -Window -SelectedLogs [string[]] [-AllLogs] [-Cap 5000] [-ServerTotalCap 50000] [-TimeoutSec 60] [-MaxConcurrency 8] [-Credential] [-ProbeScript [scriptblock]] [-LogScript [scriptblock]] -> $engine`. `ProbeScript`/`LogScript` default to scriptblocks that dot-source Core+Engine inside the runspace (via the pool's `InitialSessionState` startup scripts) and call `Invoke-ServerProbe`/`Invoke-LogQuery`; tests inject fakes.
  - `Update-TimelineEngine -Engine -> [PSCustomObject]@{ NewRows [object[]]; StatusChanged [bool]; Finished [bool] }`: called from the UI timer. Harvests completed handles (`IsCompleted` → `EndInvoke`), starts log tasks for each probed server (window via `ConvertTo-UtcWindow` with that server's offset), stops tasks past `TimeoutSec` (`BeginStop`, outcome `TimedOut`), enforces `ServerTotalCap` (remaining tasks for that server → `NotRead`, reason `stopped at the 50,000-event total for this server`), converts events to rows.
  - `$engine.Status`: ordered dictionary server → `@{ Server; State ('Waiting'|'Querying'|'Done'|'DoneWithGaps'|'Unreachable'|'Cancelled'); Transport; Reason; EventCount; UtcOffsetMinutes; Logs (list of @{ Log; Outcome ('Read'|'Capped'|'TimedOut'|'Skipped'|'Failed'|'Cancelled'|'NotRead'); Count; Reason }) }`. `DoneWithGaps` when any log is not `Read`.
  - `Stop-TimelineEngine -Engine`: marks all unfinished servers/logs `Cancelled` immediately, `BeginStop`s every running task, never blocks; disposes the pool once handles complete (on later `Update-TimelineEngine` calls or via `Close-TimelineEngine`).
  - `Close-TimelineEngine -Engine`: for window close; stop and dispose without waiting on RPC calls.

- [ ] **Step 1: Write failing tests** using a real pool with injected fake scriptblocks (no network):
  - Two servers, fake probe + fake log returning 2 events each → polling until `Finished` gives 4 rows ordered by UTC, both servers `Done`.
  - One probe unreachable → that server `Unreachable` with reason; the other still `Done`.
  - Fake log script that sleeps 10 s with `TimeoutSec 1` → log `TimedOut`, server `DoneWithGaps`, other logs on that server still `Read`, total wall time under 5 s.
  - `Stop-TimelineEngine` while a fake sleeps 30 s → returns in under 1 s; statuses `Cancelled`; next `Update-TimelineEngine` reports `Finished`.
  - `ServerTotalCap 3` with fake logs returning 2 events each across 3 logs → rows for that server ≤ 4 (the in-flight batch may land), remaining logs `NotRead`.
  - Capped outcome from fake log surfaces in `Status.Logs`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Follow the pool setup in `PortMonitor/PortMonitor.ps1` (around `CreateRunspacePool`, line ~1266). Polling handles replaces the spec's queue: same effect (UI thread only drains finished work), simpler to test.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline background engine with timeouts and cancel`.

### Task 6: The window

**Files:**
- Create: `Server-EventTimeline/Start-ServerEventTimeline.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1`

**Interfaces:**
- Consumes: everything above.
- Produces: script params `[string[]]$ComputerName`, `[string]$OutputPath`, `[switch]$SmokeTest`, `[switch]$LoadFunctionsOnly`. Functions `New-TimelineWindowXaml -> [string]`, `Show-ServerEventTimeline`.

Layout per the spec's sketch: servers box, Around/From-To with presets, log checkboxes from `Get-TimelineLogCatalog` (Security unticked, "All logs" unticked, both labelled "(slow)"), collapsed **More options** (cap, timeout, Run as placeholder wired in Task 7), Search/Cancel, per-server status list, yellow cap/timeout banner, time-zone note (shown when servers' `UtcOffsetMinutes` differ), filter row (level, server, log, flagged only, text, "Showing N of M"), virtualized `DataGrid` (no grouping) with columns Time (server local), UTC, Server, Level, Flag, Source, ID, Message; detail pane for the selected row; Export CSV / Export HTML report / Copy selected rows. Dark by default, blue accent, following FolderPermissionManager's WPF look. Rows go into a `List` behind an `ICollectionView`; filter via the view's `Filter` predicate calling `Test-RowMatchesFilter`; add rows in batches per timer tick and `Refresh()` once per tick. Search disabled with a plain message while inputs are invalid. Status lines also go to `<OutputPath>\ServerEventTimeline_<stamp>.log` and the console.

- [ ] **Step 1: Write failing tests**
  - Help block has all sections, `.PARAMETER SmokeTest`, an `.EXAMPLE` with `-SmokeTest`, and a REFERENCES block.
  - `-LoadFunctionsOnly` defines `Show-ServerEventTimeline` and opens nothing.
  - (STA only) `New-TimelineWindowXaml` loads with `XamlReader`; named controls exist: `ServersBox, AroundRadio, RangeRadio, AtBox, PlusMinusCombo, FromBox, ToBox, LastHourButton, Last24Button, LogPanel, SecurityCheck, AllLogsCheck, CapBox, TimeoutBox, RunAsButton, PickFromAdButton, SearchButton, CancelButton, StatusList, BannerText, TimeZoneNote, LevelFilter, ServerFilter, LogFilter, FlaggedOnlyCheck, FilterText, CountText, EventGrid, DetailText, ExportCsvButton, ExportHtmlButton, CopyButton`.
  - (STA only) `EventGrid` has `EnableRowVirtualization` true and no `GroupDescriptions`.
  - Smoke test: `Tests\Invoke-SmokeTest.ps1 -ScriptPath Server-EventTimeline\Start-ServerEventTimeline.ps1` builds the window and exits 0 without querying anything (follow SQ-029 / PortMonitor's `-SmokeTest`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the Server-EventTimeline tests and the smoke test under `powershell.exe -STA` → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline WPF window`.

### Task 7: Run as, Pick from AD, All logs in the UI

**Files:**
- Modify: `Server-EventTimeline/Start-ServerEventTimeline.ps1`, `Server-EventTimeline/ServerEventTimeline.Core.ps1`
- Test: `Server-EventTimeline/Tests/ServerEventTimeline.Gui.Tests.ps1`, `ServerEventTimeline.Core.Tests.ps1`

**Interfaces:**
- Produces: `Get-AdServerCandidates -Kind ('DomainControllers'|'Search') [-SearchText] -> [string[]]` in Core (runtime `Import-Module ActiveDirectory` in try/catch; returns host names; throws a plain-English error if the module is missing). The UI disables `PickFromAdButton` with a tooltip when the module isn't available. Run as: `Get-Credential` stored in the window state and passed to `Start-TimelineEngine -Credential`; button text shows the user name with a clear (x) link. All logs: the checkbox passes `-AllLogs`; banner wording for the 50,000 total.

- [ ] **Step 1: Write failing tests**: with throwing `Import-Module` mock, `Get-AdServerCandidates` throws text containing `ActiveDirectory module`; with stub `Get-ADDomainController` returning two DCs → their `HostName`s; with stub `Get-ADComputer` → names matching the search (verify `-Filter`/`-LDAPFilter` param names via `Get-Command` where RSAT exists; skip otherwise); engine receives the credential object passed in (mock `Start-TimelineEngine`, assert `-Credential`).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat: Server-EventTimeline Run as, Pick from AD and All logs`.

### Task 8: Docs, indexes, toolkit, full gate

**Files:**
- Create: `Server-EventTimeline/README.md`
- Modify: root `README.md` (index), `ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1` (`$manifest` entry `@{ Source = 'Server-EventTimeline'; Destination = 'Server-EventTimeline' }`), `ServiceDesk-Toolkit/README.md` (row: "Something happened on these servers around a time - what?" → Server-EventTimeline, *Changes anything? No*).

README covers: what it answers, how to start it, what each log choice means and that Security/All logs are slow, server-local times + UTC column, the two transports and what they need (WinRM 5985, or remote event log over RPC 135 + dynamic ports with the "Remote Event Log Management" firewall rule), blank messages on the RPC path and why, caps/timeouts and how to read the banners, the Cancel-on-RPC note, the DST approximation, exports, and REFERENCES.

- [ ] **Step 1:** Write the README and index/toolkit entries.
- [ ] **Step 2: Run** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1` → no parse errors.
- [ ] **Step 3: Run** `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1` → all green (includes `PSVersionFloor`, `ScriptEncoding`, ServiceDesk-Toolkit tests).
- [ ] **Step 4: Commit** `docs: Server-EventTimeline README, index and ServiceDesk-Toolkit entry`.
