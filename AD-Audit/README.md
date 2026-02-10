# AD-Audit

Comprehensive Active Directory audit tool that checks users, groups, computers, security, replication, password policies, privileged access, infrastructure health, and OU structure. Outputs HTML reports and CSV files.

## Requirements

- Windows PowerShell 5.1+
- **ActiveDirectory** RSAT module (`Install-WindowsFeature RSAT-AD-PowerShell` on servers, or install RSAT via Settings > Optional Features on workstations)
- Domain-joined machine or valid domain credentials
- Optional: **DnsServer** module for stale DNS record checks

## Quick Start

```powershell
# Run full audit with defaults (HTML + CSV, opens report in browser)
.\Invoke-ADAudit.ps1

# Run with GUI
.\Show-ADAuditGUI.ps1
```

## Command-Line Usage

```powershell
# Full audit to a specific folder
.\Invoke-ADAudit.ps1 -OutputPath "C:\Reports"

# Audit a remote domain with alternate credentials
.\Invoke-ADAudit.ps1 -Domain "contoso.com" -Credential (Get-Credential)

# Change stale threshold to 60 days, HTML only
.\Invoke-ADAudit.ps1 -DaysInactive 60 -ExportFormat HTML

# Run only specific sections
.\Invoke-ADAudit.ps1 -IncludeSection Users, Security, PrivilegedAccess

# Capture results for further processing
$results = .\Invoke-ADAudit.ps1 -SkipBrowserOpen
$results.Users.StaleUsers | Export-Csv stale.csv -NoTypeInformation
```

## GUI Usage

Run `Show-ADAuditGUI.ps1` to open a WinForms launcher with:

- **Parameters panel** - output path (with folder browser), domain, days inactive, export format
- **Section checkboxes** - select which audits to run (Select All / Deselect All)
- **Log output** - real-time scrolling log while the audit runs in the background

The GUI calls `Invoke-ADAudit.ps1` internally. The UI stays responsive during the audit.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | Script directory | Where reports are saved |
| `-ExportFormat` | `Both` | `HTML`, `CSV`, or `Both` |
| `-Domain` | Current domain | Target domain FQDN |
| `-Credential` | Current user | PSCredential for remote domain |
| `-DaysInactive` | `90` | Days without logon = stale |
| `-SkipBrowserOpen` | `$false` | Don't auto-open HTML report |
| `-IncludeSection` | `All` | Array of section names (see below) |
| `-LogCallback` | None | Scriptblock for log capture (used by GUI) |

### Section Names

`DomainOverview`, `DomainControllers`, `Users`, `Groups`, `Computers`, `PasswordPolicy`, `PrivilegedAccess`, `Security`, `Infrastructure`, `OUStructure`

## Audit Sections

### Domain Overview
Forest/domain info, functional levels, FSMO role holders, domain trusts, AD sites and subnets.

### Domain Controllers
All DCs with OS version, site, Global Catalog and RODC status, FSMO roles held, and replication status. Lists replication failures with partner, failure count, and error details.

### User Accounts
- Enabled/disabled counts
- Stale users (no logon in X days)
- Password never expires
- Password not required
- Never logged on
- Locked out accounts
- Accounts with SID history

### Group Analysis
- Empty groups and large groups (50+ members)
- Privileged group membership (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators)
- Nested group warnings (groups inside privileged groups)

### Computer Accounts
- Enabled/disabled counts
- Stale computers (no logon in X days)
- OS distribution breakdown
- Unsupported OS detection (Server 2003-2012, Windows XP/Vista/7/8)

### Password Policy
- Default domain password policy settings
- NIST 800-63B compliance checks (minimum length, expiration, reversible encryption)
- Fine-grained password policies with precedence and scope

### Privileged Access
- AdminSDHolder protected accounts
- Kerberos delegation: unconstrained (non-DC), constrained, and Resource-Based Constrained Delegation (RBCD)
- Kerberoastable admin accounts (Domain Admins with SPNs)
- AS-REP Roastable accounts (no Kerberos pre-authentication required)

### Security Findings
- Accounts with reversible encryption enabled
- Accounts restricted to DES-only Kerberos
- LAPS deployment status (Legacy LAPS and Windows LAPS reported separately)
- Stale DNS records (if DnsServer module is available)

### Infrastructure Health
- Tombstone lifetime
- AD Recycle Bin status
- Schema version (mapped to Windows Server version)
- Sysvol replication method (DFSR vs legacy FRS)
- Trust health: selective authentication, SID filtering, TGT delegation

### OU Structure
- Total OUs and maximum nesting depth
- Empty OUs (no child objects)
- OUs without GPO links

## Output

**HTML report** - styled report with summary metrics, table of contents, collapsible sections, color-coded severity, and back-to-top navigation. File named `AD-Audit-YYYY-MM-DD-HHmmss.html`.

**CSV files** - one CSV per audit sub-category (e.g., `AD-Audit-...-Users-Stale.csv`, `AD-Audit-...-Security-Findings.csv`). Only generated for sections that have data.

**Pipeline output** - the script returns a hashtable of all audit results for further processing in PowerShell.

## Files

| File | Description |
|---|---|
| `Invoke-ADAudit.ps1` | Main audit script (CLI) |
| `Show-ADAuditGUI.ps1` | WinForms GUI launcher |
