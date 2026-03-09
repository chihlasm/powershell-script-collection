# Audit-DHCPFailover.ps1

Audits DHCP failover health across all authorized DHCP servers in an Active Directory domain. Produces a color-coded console report and a timestamped text file with actionable findings.

## Requirements

- **PowerShell** 5.1 or 7.x
- **RSAT DHCP Server tools** (DhcpServer module)
- **Domain-joined machine** with permissions to query AD and read DHCP server configuration
- Can be run from a domain controller or any management workstation with RSAT installed

### Installing RSAT DHCP Tools

```powershell
# Windows Server
Install-WindowsFeature RSAT-DHCP

# Windows 10/11 workstation
Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0
```

## Usage

```powershell
# Run from current directory (report saved to current directory)
.\Audit-DHCPFailover.ps1

# Specify output directory
.\Audit-DHCPFailover.ps1 -OutputPath "C:\Reports"
```

### Parameters

| Parameter    | Type   | Default           | Description                          |
|------------- |--------|-------------------|--------------------------------------|
| `-OutputPath`| String | Current directory  | Directory where the report file is saved |

## What It Checks

### 1. DHCP Server Discovery
Queries Active Directory via `Get-DhcpServerInDC` to find all authorized DHCP servers. No server names are hardcoded.

### 2. Failover Relationship Status
For each failover relationship, reports:
- Partner server names
- Mode (LoadBalance or HotStandby)
- State (Normal, CommunicationInterrupted, PartnerDown, etc.)
- Load balance percentage split
- Maximum Client Lead Time (MCLT)
- Auto state transition and state switchover interval
- Whether a shared secret is configured

Flags any relationship not in `Normal` state.

### 3. Scope Coverage Audit
Cross-references scopes from all servers and identifies:
- **FAIL** — Scopes that exist on only one server and are not in failover (unprotected)
- **WARN** — Scopes on multiple servers but not in a failover relationship
- **PASS** — Scopes protected by a failover relationship

### 4. Lease Utilization
Displays a per-server table with total addresses, in-use, free, and percentage utilized for every scope. Flags any scope at or above **80% utilization**.

### 5. Scope Option Consistency
Compares scope-level DHCP options (DNS servers, default gateway, lease duration, etc.) between both servers for failover-paired scopes. Flags any mismatches in option presence or values.

### 6. Exclusion Range Comparison
Compares exclusion ranges between both servers for paired scopes. Detects:
- Mismatched exclusion ranges
- Split-scope style exclusions (complementary non-overlapping exclusions on each server instead of proper failover)

### 7. Reservation Sync Check
Compares DHCP reservations by IP address and MAC (ClientId) between both servers for paired scopes. Lists any reservations that:
- Exist on one server but not the other
- Have mismatched MAC addresses

## Output

### Console
Color-coded output using `[PASS]`, `[WARN]`, and `[FAIL]` prefixes:
- **Green** — Healthy / expected state
- **Yellow** — Warning, review recommended
- **Red** — Failure, action required
- **Cyan** — Informational

### Report File
A plain-text `.txt` file saved to the output directory with a timestamp in the filename:
```
DHCPFailoverAudit_2026-03-09_143022.txt
```

The report begins with a summary:
```
  DHCP Servers Discovered  : 2
  DHCP Servers Reachable   : 2
  Failover Relationships   : 1
  Total Unique Scopes      : 12
  Scopes Protected (FO)    : 10
  Scopes UNPROTECTED       : 2
  Warnings                 : 3
  Failures                 : 2

[FAIL] OVERALL HEALTH: ACTION REQUIRED — 2 failure(s) and 3 warning(s) found.
```

## Error Handling

- Each server connection is wrapped in `try/catch` — if one DC is unreachable, the script continues with the other
- Per-scope data collection failures are silently handled so a single bad scope doesn't halt the audit
- If no DHCP servers are found or none are reachable, the script exits early with a clear error message

## Example Workflow

```powershell
# Run the audit
.\Audit-DHCPFailover.ps1 -OutputPath "C:\DHCPAudits"

# Review the report
Get-Content "C:\DHCPAudits\DHCPFailoverAudit_2026-03-09_143022.txt"

# If unprotected scopes are found, add them to failover:
Add-DhcpServerv4Failover -ComputerName "DC01" -Name "DC01-DC02-FO" -ScopeId 10.1.5.0

# If reservations are out of sync, replicate:
Invoke-DhcpServerv4FailoverReplication -ComputerName "DC01" -Name "DC01-DC02-FO" -Force
```
