# Find-PrivilegedAccessPaths

Tools for investigating and auditing privileged access in Active Directory. Includes two scripts: one for single-user investigation and one for domain-wide auditing.

## Scripts

### Find-PrivilegedAccessPaths.ps1

Traces all paths through which a specific user may be flagged as privileged or admin. Use this when a user appears on a Privileged Account Report and you need to find out **why**.

Checks performed:
- Direct membership in built-in admin groups (Domain Admins, Enterprise Admins, etc.)
- Nested (indirect) group membership
- AdminCount attribute = 1 (set by AdminSDHolder, often orphaned)
- AdminSDHolder protection status
- SID History carrying admin SIDs from old domains
- Delegated permissions on OUs
- User Rights Assignments via GPO
- Service accounts running under the user's identity
- primaryGroupID mismatches

```powershell
.\Find-PrivilegedAccessPaths.ps1 -Username "jsmith"

.\Find-PrivilegedAccessPaths.ps1 -Username "jsmith" -ExportPath "C:\Reports\jsmith-priv-audit.csv"
```

### Get-DomainPrivilegedAccess.ps1

Domain-wide privileged access audit — finds every user with any form of admin access and explains how they got it. Outputs a color-coded console report and exports to CSV.

```powershell
.\Get-DomainPrivilegedAccess.ps1

.\Get-DomainPrivilegedAccess.ps1 -ExportPath "C:\Reports\priv-audit.csv" -IncludeDisabled
```

## Parameters

### Find-PrivilegedAccessPaths.ps1

| Parameter | Required | Description |
|-----------|----------|-------------|
| `Username` | Yes | sAMAccountName of the user to investigate |
| `ExportPath` | No | CSV export file path |

### Get-DomainPrivilegedAccess.ps1

| Parameter | Required | Description |
|-----------|----------|-------------|
| `ExportPath` | No | CSV export path. Defaults to Desktop. |
| `IncludeDisabled` | No | Include disabled accounts in the audit |

## Requirements

- ActiveDirectory PowerShell module (RSAT)
- Domain Admin or equivalent read access
