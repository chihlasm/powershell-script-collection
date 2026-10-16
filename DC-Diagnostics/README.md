# DC-Diagnostics

Read-only health snapshot of a single domain controller, built to line a DC's behavior up against a Hyper-V host crash or other outage window. Produces one text report with a findings summary at the top.

## Local-only by design

Run `Get-DCDiagnostics.ps1` **on the domain controller you are checking**. It runs `dcdiag`, `repadmin`, `w32tm` and `fsutil`, reads the local event logs and the local NTDS registry parameters, so it has no `-ComputerName` parameter. To check several DCs, run it on each one (for example `Invoke-Command -ComputerName DC01 -FilePath .\Get-DCDiagnostics.ps1`). It warns (and records a finding) if the computer is not a domain controller or the session is not elevated.

## Requirements

- Windows PowerShell 3.0 or later (`#Requires -Version 3.0`; works as shipped on Server 2012 / 2012 R2)
- Elevated prompt (dcdiag and the Directory Service log need admin rights)
- Optional: ActiveDirectory module (without it the FSMO section falls back to `netdom query fsmo`)

## Usage

```powershell
.\Get-DCDiagnostics.ps1
.\Get-DCDiagnostics.ps1 -DaysBack 210 -IncidentDates '2025-12-05','2026-06-20'
.\Get-DCDiagnostics.ps1 -OutputPath D:\Reports
```

| Parameter | Default | Description |
|---|---|---|
| `-DaysBack` | `30` | Event log lookback window (1-3650 days) |
| `-IncidentDates` | none | Dates (`yyyy-MM-dd`); pulls a +/- 24 hour window from the System, Directory Service, DNS Server and DFS Replication logs for each |
| `-OutputPath` | Current directory | Report directory (created if missing) |

Output: `<COMPUTERNAME>_DCDiagnostics_<yyyy-MM-dd_HHmmss>.log` (UTF-8).

## What it collects

- OS, last boot, uptime
- FSMO role holders and DC inventory (flags a single-DC domain)
- `dcdiag /v` (flags "failed test" lines)
- `repadmin /showrepl` and `/replsummary` (flags rows with a non-zero failure count or a delta in days)
- `w32tm` status and source (flags the local CMOS / free-running clock)
- Secure channel test
- Reboot and shutdown history from the System log: 1074, 6005, 6006, 6008 and Kernel-Power 41 (6008 and 41 are flagged as unexpected shutdowns)
- Error/Warning events from the Directory Service, DNS Server and DFS Replication logs
- NTDS database and log volume free space and dirty bit
- Optional incident-date correlation

## Event IDs

| ID | Source | Meaning |
|---|---|---|
| 1074 | User32 | A process or user initiated a shutdown or restart |
| 6005 / 6006 | EventLog | Event log service started / stopped (boot and clean-shutdown markers; not verified on Learn) |
| 6008 | EventLog | The previous system shutdown was unexpected |
| 41 | Kernel-Power | The system rebooted without cleanly shutting down first |
| 2213 | DFSR | Replication paused after a dirty database shutdown |
| 4614 / 4604 | DFSR | SYSVOL waiting for initial replication / SYSVOL initialized |

References are in the script's `.NOTES`.

## Tests

```powershell
Invoke-Pester .\DC-Diagnostics\Tests
```

`Compatibility.Tests.ps1` guards the PowerShell 3.0 floor (no `::new()`, classes, `.Where()`, 5.x-only cmdlets, `#Requires -Modules`), the current-directory output default, the local-only design, and the `repadmin /replsummary` parser.
