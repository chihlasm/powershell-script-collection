# AD-GroupPolicy-DriveMaps

Audits all drive mappings configured via Group Policy Preferences across the domain.

## Quick Start

```powershell
# Basic audit — all drive maps with conflict/duplicate detection and path validation
.\Audit-GPDriveMaps.ps1

# Show which drives a specific user would get (GPO precedence simulation)
.\Audit-GPDriveMaps.ps1 -TargetUser "jsmith" -TargetComputer "WS01"

# Fast audit (skip network path checks)
.\Audit-GPDriveMaps.ps1 -SkipPathValidation -SkipBrowserOpen
```

## Features

- **Drive map extraction** — Finds every GP Preferences drive mapping across all GPOs
- **Item-level targeting** — Parses ILT filters (groups, users, OUs, IPs, etc.) for each mapping
- **UNC path validation** — Tests each share path for network reachability
- **Conflict detection** — Same drive letter mapped to different paths across GPOs. Delete-action items are excluded from the competing-path comparison (so the "delete-for-everyone + create-for-a-group" restrict-to-department pattern is not misreported as a conflict), and item-level targeting is checked to separate real conflicts from targeting-resolved ones
- **Reachability-aware classification** — When every target share for a drive letter is unreachable, the finding is labeled *all endpoints unreachable* (a dead-endpoint problem) rather than a targeting conflict — different root cause, different fix
- **Stale-host detection** — Flags any UNC server that is unreachable anywhere in the export and is still referenced by a drive mapping, regardless of drive letter (catches the case where one letter was migrated off a dead server but another still points at it)
- **Group-membership overlap check** (`-CheckGroupOverlap`) — Verifies that ILT security groups sharing a drive letter are actually mutually exclusive by resolving real AD membership, and flags any user in 2+ competing groups
- **Duplicate detection** — Same UNC path in multiple GPOs
- **GPO precedence simulation** — Shows the winning GPO per drive letter for a specific user/computer
- **Loopback processing awareness** — Detects User Group Policy Loopback Processing (Merge/Replace) on the target computer's OU chain and factors computer-linked GPOs into the precedence simulation accordingly — critical for Citrix/RDS environments where loopback is common
- **HTML + CSV reports** — Professional report matching the `AD-GroupPolicy-Audit` style

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-OutputPath` | Report output directory | Script directory |
| `-ExportFormat` | HTML, CSV, or Both | Both |
| `-Domain` | Target a specific domain | Current domain |
| `-Credential` | Credentials for domain access | Current user |
| `-TargetUser` | SamAccountName for precedence simulation | *(none)* |
| `-TargetComputer` | Computer name for precedence simulation | *(none)* |
| `-SkipBrowserOpen` | Don't auto-open the HTML report | `$false` |
| `-SkipPathValidation` | Skip UNC path reachability checks | `$false` |
| `-CheckGroupOverlap` | Resolve AD group membership and flag users in 2+ groups mapping the same drive letter | `$false` |

## Requirements

- PowerShell 5.1+
- RSAT: `GroupPolicy` and `ActiveDirectory` modules
- Domain-joined machine (or `-Domain` / `-Credential` for remote access)

## Output Files

| File | Contents |
|------|----------|
| `DriveMap-Audit-*.html` | Full HTML report with all sections |
| `*-AllMappings.csv` | Every drive mapping with ILT and GPO link info |
| `*-Conflicts.csv` | Drive letter conflicts |
| `*-Duplicates.csv` | Duplicate share paths |
| `*-PathValidation.csv` | UNC path reachability results |
| `*-StaleHosts.csv` | Unreachable servers still referenced by any drive mapping |
| `*-GroupOverlap.csv` | Users in 2+ groups mapping the same letter (when `-CheckGroupOverlap` used) |
| `*-EffectiveMaps.csv` | Winning GPO per drive letter (when `-TargetUser` used) |
