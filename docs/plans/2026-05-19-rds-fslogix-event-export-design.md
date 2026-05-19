# RDS / FSLogix Event Export — Design

**Date:** 2026-05-19
**Status:** Approved, ready for implementation
**Folder:** `RDS-FSLogix-EventExport/` (new)

## Purpose

Standalone PowerShell script that runs locally on an RDS / Citrix session host and exports RDS- and FSLogix-related Windows event log entries for a user-specified timeframe. Output is CSV (for filtering in Excel) plus a self-contained HTML report (for sharing).

Fits the existing script-collection pattern: one folder, one main `.ps1`, one `README.md`, no external dependencies beyond built-in Windows event log cmdlets.

## Parameters

```powershell
-StartTime <DateTime>     # explicit window; mutually exclusive with -LastHours/-LastDays
-EndTime   <DateTime>     # defaults to (Get-Date) when -StartTime is provided alone
-LastHours <int>          # shortcut: events in the last N hours
-LastDays  <int>          # shortcut: events in the last N days
-OutputPath <string>      # defaults to current directory
-IncludeSecurity [switch] # opt-in; pulls 4624/4625/4634/4647 filtered to LogonType 7/10
-Level <int[]>            # defaults to 1,2,3 (Critical, Error, Warning)
```

**Validation rules:**
- If both `-StartTime` and `-LastHours`/`-LastDays` are supplied, throw.
- If neither is supplied, default to the last 24 hours.
- `-EndTime` without `-StartTime` is invalid.
- `-Level` accepts any subset of `1..5`.

## Logs collected

Events are gathered into four logical categories so the HTML can section them. Every log is queried with `Get-WinEvent -FilterHashtable` (server-side filtered, fast). Each call is wrapped in its own try/catch — a missing or locked log emits `[INFO]` or `[WARN]` and the script continues.

### 1. RDS

Every `Microsoft-Windows-TerminalServices-*/Operational` log present on the box, enumerated dynamically:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-TerminalServices-*' |
    Where-Object { $_.RecordCount -gt 0 -or $_.IsEnabled }
```

Typical logs (depending on role):
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
- `Microsoft-Windows-TerminalServices-SessionBroker/Operational`
- `Microsoft-Windows-TerminalServices-SessionBroker-Client/Operational`
- `Microsoft-Windows-TerminalServices-Gateway/Operational`
- `Microsoft-Windows-TerminalServices-Licensing/Operational`
- `Microsoft-Windows-TerminalServices-PnPDevices/Operational`
- `Microsoft-Windows-TerminalServices-Printers/Operational`
- `Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational`
- `Microsoft-Windows-TerminalServices-RDPClient/Operational`

### 2. FSLogix

- `Microsoft-FSLogix-Apps/Operational`
- `Microsoft-FSLogix-Apps/Admin`
- `Microsoft-FSLogix-CloudCache/Operational` (if present)

### 3. System / Application (provider-filtered)

`System` and `Application` logs, filtered by `ProviderName` to only RDS/FSLogix-relevant sources. Catches service crashes and GPO-driven failures that the operational logs miss.

Providers:
- `TermService`, `TermDD`, `RemoteDesktopServices`
- `Microsoft-Windows-TerminalServices-*` (wildcard match handled in PowerShell after retrieval, since `FilterHashtable` doesn't support provider wildcards)
- `frxsvc`, `frxccd`, `frxdrv`, `frxdrvvt`

Implementation: query with a `ProviderName` array of the literal names, then post-filter the wildcard `Microsoft-Windows-TerminalServices-*` providers as a separate pass.

### 4. Security (opt-in via `-IncludeSecurity`)

`Security` log, EventID `4624, 4625, 4634, 4647`, filtered after retrieval to `LogonType` 7 (unlock) and 10 (RemoteInteractive). Requires admin; if access is denied, emit `[WARN] Security log requires elevation — skipping` and continue.

## Output

Two files written to `-OutputPath`, both timestamped:

**CSV** — `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.csv`
Flat row per event with columns:
`TimeCreated, Category, LogName, Id, Level, LevelDisplayName, ProviderName, MachineName, UserId, Message`

Exported via `Export-Csv -NoTypeInformation -Encoding UTF8`.

**HTML** — `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.html`
Single self-contained file, no external CSS or JS. Dark theme matching the project's design language (bold, trustworthy, capable — VS Code / Windows Admin Center with personality, not generic admin-dashboard gray).

Structure:
- **Header** — computer name, time window, generated-at timestamp, total event count.
- **Summary band** — count by category, count by severity (color-coded chips).
- **One collapsible section per category** (RDS / FSLogix / System+App / Security). Each section has a sortable table; long Message values are truncated with click-to-expand. Tiny inline `<script>` handles sort and expand — no external libraries.
- **Empty state** — if total events is 0, the HTML still renders with a clear "No events in the specified window" message (no half-broken page).

Severity color mapping in HTML:
- Critical / Error → red (matches `[FAIL]`)
- Warning → amber (matches `[WARN]`)
- Information → blue (matches `[INFO]`)
- Verbose → muted gray

## Console output

Per the project's dual-output convention:
- `[INFO]` (Cyan) when starting collection on a log.
- `[PASS]` (Green) with event count on successful collection.
- `[WARN]` (Yellow) when a log is missing, empty, or access-denied.
- `[FAIL]` (Red) on unexpected errors.

Timestamp format: `yyyy-MM-dd HH:mm:ss` for log lines, `yyyy-MM-dd_HHmmss` for filenames.

## Error handling

- Each log queried in its own try/catch — one failure does not halt the run.
- `Get-WinEvent` throws when a log has zero matching events; catch this specific case (`Exception.GetType().Name -eq 'Exception'` with message `No events were found`) and treat as success-with-zero.
- Missing logs (`-ListLog` returns nothing) are skipped silently with an `[INFO]`.
- Access-denied on Security log → `[WARN]` and skip.
- Output directory not writable → fail fast at the top of the script with a clear message before any collection runs.

## Edge cases

- Host without the Gateway / Broker role → those logs aren't present; dynamic enumeration handles this.
- Zero events across all categories → HTML still emits with empty-state messaging; CSV is written with header row only.
- Very large windows (e.g. `-LastDays 30` on a busy broker) → no artificial cap, but document in `.NOTES` that runtime scales with event volume and recommend narrowing the window for routine triage.
- Time zone — all timestamps in output are local time, matching what an admin sees in Event Viewer. CSV column header is `TimeCreated` (not `TimeCreatedUtc`) to make this clear.

## File layout

```
RDS-FSLogix-EventExport/
├── Export-RDSFSLogixEvents.ps1
└── README.md
```

`#Requires -Version 5.1` at the top. `#Requires -RunAsAdministrator` only if `-IncludeSecurity` is the dominant case — instead, runtime-check for elevation and emit the warning, so non-admin runs still produce RDS/FSLogix output.

## Manual test plan

1. **Quiet box, narrow window** — `-LastHours 1` on an idle host. Confirm the empty-state HTML renders cleanly and the CSV has only the header row.
2. **Busy window** — `-LastDays 7` on an active broker. Open the HTML in a browser and confirm: total count in the header matches the CSV row count, each category section opens/closes, sortable columns work, severity colors are correct.
3. **Non-admin run** — open a non-elevated PowerShell, run with `-IncludeSecurity`. Confirm `[WARN]` about Security log appears and RDS/FSLogix sections still populate.
4. **Host missing Gateway log** — run on a session host without the Gateway role. Confirm `[INFO]` skip messages for absent logs, no errors, output still produced.
5. **Conflicting parameters** — run with both `-StartTime` and `-LastHours`. Confirm immediate, clear error before any collection starts.
6. **Output path** — run with `-OutputPath` pointing to a read-only directory. Confirm fail-fast with a clear message.
