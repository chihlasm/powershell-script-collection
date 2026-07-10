# MSP Troubleshooting Workbench

Portable, browser-based troubleshooting case workbench for MSP Windows support. Create a case per ticket, run read-only diagnostic checks against servers and desktops, capture notes, and generate ready-to-paste ticket notes.

## Quick Start

```powershell
# Preferred: double-click or run the launcher
.\MSPWorkbench.exe

# Or run the entry point directly (elevate when checks need admin rights)
.\Start-MSPTroubleshootingWorkbench.ps1
```

The workbench opens at `http://localhost:8275/` (change with `-Port`). All data stays local: cases in `cases\`, exports in `exports\`, logs in `logs\`. Use `-OutputPath` to point data at another folder. Stop the server with Ctrl+C.

`MSPWorkbench.exe` is a small launcher for the PowerShell entry point. If a compiler is not available, use `Start-MSPTroubleshootingWorkbench.ps1` directly.

## Workflow

1. **Create a case** — client, ticket number, issue type, plus optional user/device/path/address context.
2. **Run checks** — pick a check, fill in its inputs (prefilled from the case), run it. Results, evidence, and recommended next steps land on the case.
3. **Add notes** — record anything you observed or did manually.
4. **Generate Notes** — builds structured ticket notes (Issue / Actions Taken / Findings / Evidence / Likely Cause / Next Steps / Customer-Facing Summary). Copy to clipboard and paste into your PSA.
5. **Export Evidence** — writes `ticket-notes.md`, `report.html`, and `evidence.json` to `exports\<CaseId>\`.

## Checks

Checks are standalone scripts in `checks\` declared in `checks\manifest.json` (`checkId`, `name`, `category`, `script`, `description`, `readOnly`, `inputs`, `timeoutSeconds`). All bundled checks are read-only.

| Check | Inputs | Timeout |
| --- | --- | --- |
| Network Quick Check (`network.quick`) | address, port | 60s |
| AD Lockout Diagnostics (`ad.lockout`) | user, days back, domain controller(s) | 240s |
| Citrix/FSLogix Triage (`citrix.fslogix.triage`) | device, user | 180s |

`timeoutSeconds` (1–3600, default 60) bounds how long the server waits for a check. It must exceed any timeout the check applies to its own child processes — `ad.lockout` uses 240 because its diagnostics script gives its child 120 seconds and still needs headroom to import modules and write its report.

The server stamps `InputsUsed` onto each stored result, so generated notes record which inputs a check actually ran with.

### Network Quick Check

`network.quick` runs from this workstation: ping, DNS resolution, TCP port reachability, and the local default route.

### AD Lockout Diagnostics

`ad.lockout` wraps `..\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1` and returns the shared workbench check result fields. It accepts:

- `affectedUser`: SamAccountName, UPN, or distinguished name to investigate.
- `daysBack`: 1-90 days of Security event logs to search.
- `domainController`: optional DC name or names to query instead of auto-discovery.

The wrapper writes the underlying HTML report to `output\checks\ad.lockout\<timestamp>` under the workbench folder and includes the report path in `RawOutput.ReportPath` and the evidence list when the diagnostic completes.

Local preflight checks return `Status = "Warn"` instead of crashing when the diagnostics script is missing or the RSAT `ActiveDirectory` module cannot load. A real AD run still requires a domain-connected workstation or server, RSAT Active Directory tools, and permissions to read domain controller Security logs.

### Citrix/FSLogix Triage

`citrix.fslogix.triage` runs read-only profile triage against an affected Citrix, RDS, or Windows session host. It accepts:

- `affectedDevice`: server or workstation to inspect. The standalone script defaults to the local computer, but API/manifest runs should pass this value.
- `affectedUser`: optional user name for context and simple profile path token replacement.

The check collects server reachability, FSLogix service status, FSLogix profile registry settings, recent FSLogix events, recent Terminal Services events, fixed disk free space, and configured `VHDLocations` or `CCDLocations` path reachability. Remote service, event, CIM, and profile path queries use the affected device; registry reads use a remote HKLM base key. If remote registry, event logs, CIM, or PowerShell remoting are blocked, the check records Warn evidence and continues.

Profile path reachability is tested from the affected host context with `Invoke-Command -ComputerName affectedDevice` for remote targets. When the affected device is explicitly local, the check uses local `Test-Path` and labels the evidence as local target context. Local development runs do not require an actual Citrix host; final validation should be performed against a real Citrix/RDS host with FSLogix installed and permissions to read the target event logs, registry, and configured profile paths.

### Adding a check

Drop a script into `checks\` that returns the shared result object (`CheckId, Name, Category, Status [Pass|Warn|Fail], Summary, Evidence[], RecommendedNextSteps[], RawOutput, StartedAt, FinishedAt, Error`) and add a manifest entry. Keep checks read-only.

## Portability

Copy the whole repository, not just this folder — `ad.lockout` calls `..\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1` relative to the repo root. If the diagnostics script is missing, the check degrades to a Warn result instead of failing.

To rebuild `MSPWorkbench.exe` on a workstation with a .NET Framework C# compiler:

```powershell
.\launcher\build.ps1
```

## Security

The server listens on localhost only. POST endpoints require a per-session token that the server injects into the served page and expects back in an `X-Workbench-Token` header, so other websites open in your browser cannot drive the API. No authentication beyond that — do not expose the port off-machine.

## Tests

```powershell
Get-ChildItem .\tests\*.Tests.ps1 | ForEach-Object { powershell -NoProfile -File $_.FullName }
```

`Workbench.Api.Tests.ps1` boots a real server on a random port and exercises the full case lifecycle over HTTP, including the token gate.

`Start-MSPTroubleshootingWorkbench.ps1 -LibraryMode` defines every function and resolves `-OutputPath`, then returns without starting the listener. Unit tests dot-source it that way.

Test scripts pin `$env:PSModulePath` to the shipped Windows module path. A broken module elsewhere on `PSModulePath` that exports cmdlets by wildcard can shadow built-ins such as `Write-Host` and make otherwise-passing tests fail.
