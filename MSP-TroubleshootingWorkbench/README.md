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
