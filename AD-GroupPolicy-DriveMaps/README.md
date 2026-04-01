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
- **Conflict detection** — Same drive letter mapped to different paths across GPOs
- **Duplicate detection** — Same UNC path in multiple GPOs
- **GPO precedence simulation** — Shows the winning GPO per drive letter for a specific user/computer
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
| `*-EffectiveMaps.csv` | Winning GPO per drive letter (when `-TargetUser` used) |
