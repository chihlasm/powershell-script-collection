# Diagnose-AD-DFS-Replication.ps1

Read-only diagnostics for Active Directory replication and DFS Replication (DFSR) / DFS Namespaces (DFSN) across domain controllers.

## What it checks

1. **AD replication** (kept short; `AD-Audit\Invoke-ADAudit.ps1` gives the full picture) - current replication failures (`Get-ADReplicationFailure -Target`) and per-partner last success (`Get-ADReplicationPartnerMetadata`). A partner with consecutive failures, no success, or no success within `-StaleHours` is reported as stale.
2. **DFSR service** on every DC, queried remotely with `Get-CimInstance Win32_Service -ComputerName`.
3. **DFS Replication** - `Get-DfsReplicationGroup -IncludeSysvol`, `Get-DfsrMember`, `Get-DfsrConnection`, `Get-DfsReplicatedFolder`, and `Get-DfsrBacklog` for every enabled connection and replicated folder. `Get-DfsrBacklog` only returns 100 files; the script reads the true count from its verbose stream.
4. **DFS Namespaces** - `Get-DfsnRoot -Domain`, `Get-DfsnRootTarget`, `Get-DfsnFolder`, `Get-DfsnFolderTarget`.

Every server is queried in its own try/catch, so one unreachable DC does not stop the run. Output uses `[PASS]` / `[WARN]` / `[FAIL]` / `[INFO]` prefixes.

## Requirements

- Windows PowerShell 3.0 or later (`#Requires -Version 3.0`)
- ActiveDirectory module (imported at run time; the script exits with RSAT instructions if it is missing)
- Optional: DFSR and DFSN modules (the "DFS Management Tools" RSAT feature, or a DC/file server with the DFS roles). If a module is missing, that half is skipped with a warning.
- A domain admin (or equivalent read access to the DFS configuration and remote CIM/WMI access to the DCs)

The module names are `DFSR` and `DFSN`. Earlier versions of this script called `Get-DfsReplicationGroupMember`, `Get-DfsReplicationGroupConnection`, `Get-DfsReplicationBacklog`, `Get-DfsNamespace` and `Get-DfsReplicationTarget`, none of which exist, and `Get-Service -ComputerName`, which is gone in PowerShell 6+.

## Usage

```powershell
.\Diagnose-AD-DFS-Replication.ps1
.\Diagnose-AD-DFS-Replication.ps1 -DomainControllers DC1, DC2 -OutputPath C:\Logs
.\Diagnose-AD-DFS-Replication.ps1 -StaleHours 48 -BacklogWarningThreshold 100
```

| Parameter | Default | Description |
|---|---|---|
| `-DomainControllers` | all DCs in the domain | DC names to check |
| `-OutputPath` (alias `-LogFile`) | current directory | Output directory; a value with a file extension is used as the log file path |
| `-StaleHours` | `24` | Hours without a successful replication before a partnership is "Stale" |
| `-BacklogWarningThreshold` | `1` | Backlog file count that is reported as a problem |
| `-LoadFunctionsOnly` | off | Define functions and return (used by tests) |

## Output

Written to `-OutputPath`, named with a `yyyy-MM-dd_HHmmss` timestamp:

- `AD-DFS-Replication_<timestamp>.log` - everything shown on screen
- `AD-DFS-Replication_<timestamp>-ADReplication.csv` - partner status
- `AD-DFS-Replication_<timestamp>-DfsrBacklog.csv` - backlog per connection and folder

Standalone (non-domain) namespaces are not enumerated; only domain-based namespaces of the current domain.

## Tests

```powershell
Invoke-Pester .\ADReplicationDiagnostics\Tests
```

The tests mock every AD, DFSR and DFSN cmdlet, assert the correct cmdlet names and parameters are called, assert the old non-existent names are never called, and cover the missing-module and unreachable-DC paths.

References are listed in the script's `.NOTES`.
