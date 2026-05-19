# RDS-FSLogix-EventExport

Local-only PowerShell script that exports RDS- and FSLogix-related Windows event log entries for a user-specified time window to CSV plus a self-contained HTML report.

Designed to be dropped onto an RDS session host or Citrix VDA and run with no setup.

## Requirements
- Windows PowerShell 5.1 or later (PowerShell 7+ also works).
- Run locally on the host whose events you want to collect.
- Administrator elevation required only if you pass `-IncludeSecurity`. Non-admin runs still produce RDS + FSLogix output.

## Usage

```powershell
# Last 4 hours of errors and warnings, output to current directory
.\Export-RDSFSLogixEvents.ps1 -LastHours 4

# Explicit window with RDP logon events, output to C:\Logs
.\Export-RDSFSLogixEvents.ps1 -StartTime '2026-05-18 08:00' -EndTime '2026-05-18 17:00' -IncludeSecurity -OutputPath C:\Logs

# Last day including Information-level entries
.\Export-RDSFSLogixEvents.ps1 -LastDays 1 -Level 1,2,3,4
```

## Output

Two files, both timestamped:

- `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.csv` — flat per-event rows for Excel filtering.
- `RDS-FSLogix-Events_<ComputerName>_<yyyy-MM-dd_HHmmss>.html` — single self-contained HTML report with category sections, sortable tables, severity color-coding.

## What it collects

| Category | Source |
|---|---|
| RDS | All `Microsoft-Windows-TerminalServices-*/Operational` logs present on the host |
| FSLogix | `Microsoft-FSLogix-Apps/Operational`, `Microsoft-FSLogix-Apps/Admin`, `Microsoft-FSLogix-CloudCache/Operational` |
| System / Application | Filtered to providers: TermService, TermDD, RemoteDesktopServices, Microsoft-Windows-TerminalServices-*, frxsvc, frxccd, frxdrv, frxdrvvt |
| Security (opt-in) | 4624 / 4625 / 4634 / 4647 filtered to LogonType 7 (unlock) and 10 (RemoteInteractive) |

Default severity: 1 (Critical), 2 (Error), 3 (Warning). Override with `-Level`.

## Notes
- Time stamps in output are local time, matching Event Viewer.
- One missing or locked log does not halt the run; it logs a `[WARN]` and continues.
- A zero-event window still produces both files (HTML shows an empty state, CSV has the header only).
