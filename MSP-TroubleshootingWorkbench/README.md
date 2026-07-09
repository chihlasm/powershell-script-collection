# MSP Troubleshooting Workbench

Portable local troubleshooting case workbench for MSP Windows infrastructure support.

## Quick Start

Run from an elevated PowerShell session when checks require admin rights:

```powershell
.\Start-MSPTroubleshootingWorkbench.ps1
```

## Checks

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
