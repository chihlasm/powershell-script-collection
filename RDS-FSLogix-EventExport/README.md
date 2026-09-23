# RDS-FSLogix-EventExport

PowerShell script that exports RDS- and FSLogix-related Windows event log entries for a user-specified time window to CSV plus a self-contained HTML report.

Runs against the local machine by default, or against **one or many remote hosts** with `-ComputerName`. Designed to be dropped onto an RDS session host or Citrix VDA and run with no setup, or driven from a technician's workstation across a whole pool.

## Requirements
- Windows PowerShell 5.1 or later (PowerShell 7+ also works).
- For remote hosts: administrative rights on the target and the **Remote Event Log Management** firewall rule enabled there. `Get-WinEvent` reaches remote machines over RPC rather than PowerShell remoting, so this works where WinRM is switched off.
- Administrator elevation required only if you pass `-IncludeSecurity`. Non-admin runs still produce RDS + FSLogix output. (The elevation check applies to local runs; for a remote host the query is attempted and an access denial is reported honestly.)

## Usage

```powershell
# Last 4 hours of errors and warnings, output to current directory
.\Export-RDSFSLogixEvents.ps1 -LastHours 4

# Explicit window with RDP logon events, output to C:\Logs
.\Export-RDSFSLogixEvents.ps1 -StartTime '2026-05-18 08:00' -EndTime '2026-05-18 17:00' -IncludeSecurity -OutputPath C:\Logs

# Last day including Information-level entries
.\Export-RDSFSLogixEvents.ps1 -LastDays 1 -Level 1,2,3,4

# Sweep three session hosts into one combined report
.\Export-RDSFSLogixEvents.ps1 -ComputerName CTXVDA01, CTXVDA02, CTXVDA03 -LastHours 8

# Sweep a whole pool with explicit credentials
.\Export-RDSFSLogixEvents.ps1 -ComputerName (Get-Content .\pool-hosts.txt) `
    -LastDays 2 -Credential (Get-Credential) -OutputPath \\fileserver\Triage
```

## Output

Two files, both timestamped. A single-host run is named after that host; a multi-host sweep is named `<N>-hosts`, because stamping one machine's name on a file covering twelve of them would be misleading.

- `RDS-FSLogix-Events_<tag>_<yyyy-MM-dd_HHmmss>.csv` — flat per-event rows for Excel filtering. The `MachineName` column identifies which host each event came from.
- `RDS-FSLogix-Events_<tag>_<yyyy-MM-dd_HHmmss>.html` — single self-contained HTML report covering every host, with category sections, sortable tables, severity color-coding.

## What it collects

| Category | Source |
|---|---|
| RDS | All `Microsoft-Windows-TerminalServices-*/Operational` logs present on the host |
| FSLogix | `Microsoft-FSLogix-Apps/Operational`, `Microsoft-FSLogix-Apps/Admin`, `Microsoft-FSLogix-CloudCache/Operational` |
| System / Application | Filtered to providers: TermService, TermDD, RemoteDesktopServices, Microsoft-Windows-TerminalServices-*, frxsvc, frxccd, frxdrv, frxdrvvt |
| Security (opt-in) | 4624 / 4625 / 4634 / 4647 filtered to LogonType 7 (unlock) and 10 (RemoteInteractive) |

Default severity: 1 (Critical), 2 (Error), 3 (Warning). Override with `-Level`.

## Notes
- Time stamps in output are local time **of the host that logged the event**, matching Event Viewer. On a pool spanning time zones, prefer `-LastHours` / `-LastDays` over an explicit `-StartTime`.
- One missing or locked log does not halt the run; it logs a `[WARN]` and continues.
- One unreachable *host* does not halt a sweep either — it is reported and the remaining hosts are still collected.
- A zero-event window still produces both files (HTML shows an empty state, CSV has the header only).

## Tests

```powershell
Invoke-Pester -Path .\Tests
```

30 tests, including regression guards for the remote-targeting defect this script previously had: it accepted a computer name for the report header while every query silently ran against the local machine.

## Related

For a combined **performance and event** view across a fleet, with per-machine verdicts, see [`Citrix-FSLogix-HealthCollector`](../Citrix-FSLogix-HealthCollector/).
