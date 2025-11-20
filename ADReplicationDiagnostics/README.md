# Diagnose-AD-DFS-Replication.ps1

## Description

This PowerShell script provides comprehensive diagnostics for Active Directory replication and DFS/DFSR issues across multiple domain controllers.

## Features

- AD replication status checking
- DFS/DFSR service health monitoring
- Replication backlog analysis
- Namespace and target verification
- Colored output for easy issue identification
- Support for specifying specific domain controllers or auto-detection
- Optional logging to file with timestamps and execution details

## Requirements

- Windows PowerShell 5.1 or later
- ActiveDirectory module (available on domain controllers or RSAT installed)
- DFSReplication module (available on domain controllers or RSAT installed)
- Domain admin privileges
- Run as administrator

## Usage

### Basic usage (auto-detect all domain controllers):

```powershell
.\Diagnose-AD-DFS-Replication.ps1
```

### Specify specific domain controllers:

```powershell
.\Diagnose-AD-DFS-Replication.ps1 -DomainControllers "DC1", "DC2", "DC3"
```

### Enable logging to file:

```powershell
.\Diagnose-AD-DFS-Replication.ps1 -LogFile "C:\Logs\AD-DFS-Diagnostic.log"
```

### Combined usage:

```powershell
.\Diagnose-AD-DFS-Replication.ps1 -DomainControllers "DC1", "DC2", "DC3" -LogFile "C:\Logs\AD-DFS-Diagnostic.log"
```

## Output

The script provides:

- List of detected domain controllers
- AD replication failures and status
- DFS/DFSR service status
- Replication group information
- Backlog analysis
- Namespace and target details
- Summary of issues found

When logging is enabled, a detailed log file is created with:
- Execution start time and parameters
- All console output with timestamps
- Execution duration and issue count
- Complete diagnostic history

## Notes

- The script gracefully handles missing modules and permissions
- All operations are read-only and safe to run in production
- Requires network connectivity to all domain controllers
- Best run from a domain controller or management server with RSAT

## Troubleshooting

If you encounter permission errors, ensure you're running as a domain admin.

If modules are not found, install RSAT or run from a domain controller.

For DFS/DFSR issues, check service status and network connectivity first.

## Log File Format

When logging is enabled, the log file contains:

```
AD/DFS Replication Diagnostic Log
Started: 2025-11-06 12:20:00
Computer: WORKSTATION01
User: DOMAIN\Administrator
Parameters: DomainControllers= LogFile=C:\Logs\AD-DFS-Diagnostic.log
================================================================================

2025-11-06 12:20:01 [Cyan] Logging enabled. Output will be saved to: C:\Logs\AD-DFS-Diagnostic.log
2025-11-06 12:20:01 [Green] Auto-detected 3 domain controllers:
2025-11-06 12:20:01 [Cyan]   DC1.domain.com
...
================================================================================
Diagnostic completed: 2025-11-06 12:21:15
Duration: 74.23 seconds
Total issues found: 0
Log saved to: C:\Logs\AD-DFS-Diagnostic.log
================================================================================
