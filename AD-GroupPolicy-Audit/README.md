# AD Group Policy Audit Tool

Audits all GPOs in an Active Directory domain and generates reports covering duplicates, conflicts, optimization opportunities, security issues, and FSLogix configuration.

## Requirements

- Windows PowerShell 5.1+
- RSAT modules: `GroupPolicy`, `ActiveDirectory`
- Domain read permissions for GPO settings and permissions

## Quick Start

```powershell
# Full audit with defaults (HTML + CSV output, opens report in browser)
.\Audit-ADGroupPolicy.ps1

# Output to a specific folder, HTML only
.\Audit-ADGroupPolicy.ps1 -OutputPath "C:\Reports" -ExportFormat HTML

# Audit a specific domain without FSLogix checks
.\Audit-ADGroupPolicy.ps1 -Domain "contoso.com" -IncludeFSLogix $false

# Suppress auto-opening the browser
.\Audit-ADGroupPolicy.ps1 -SkipBrowserOpen
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | string | Script directory | Where reports are saved |
| `-IncludeFSLogix` | bool | `$true` | Run FSLogix-specific analysis |
| `-ExportFormat` | string | `Both` | `HTML`, `CSV`, or `Both` |
| `-ExportXML` | bool | `$true` | Export individual GPO XML files |
| `-Domain` | string | Current domain | Target domain to audit |
| `-Credential` | PSCredential | None | Credential for cross-domain auth |
| `-SkipBrowserOpen` | switch | Off | Don't open HTML report in browser |

## What It Checks

| Category | What It Finds |
|----------|---------------|
| **Duplicates** | Exact-match GPOs (SHA256 hash) and similar-named GPOs |
| **Overlaps** | Registry settings configured in multiple GPOs (conflicts vs. redundancies) |
| **Optimizations** | Empty GPOs, unlinked GPOs, stale GPOs (>1 year), disabled sections with no settings |
| **Security** | Non-standard edit permissions, sensitive GPOs applying to all Authenticated Users |
| **Security Filtering** | GPOs with no Apply permission (won't apply to anyone) |
| **Drive Maps** | Same share mapped in multiple GPOs, same drive letter pointing to different shares |
| **Printers** | Same printer deployed by multiple GPOs, conflicting default printer settings |
| **FSLogix** | Profile/ODFC/Cloud Cache settings from both Admin Templates and GP Preferences registry items, conflicts, mixed-source warnings |
| **Links** | Full link inventory with enforcement and ordering details |

## Output Files

All files are saved to `-OutputPath` with a timestamped name like `GPO-Audit-2025-01-15-143022`:

```
OutputPath/
  GPO-Audit-2025-01-15-143022.html          # Main HTML report
  GPO-Audit-2025-01-15-143022-Duplicates.csv
  GPO-Audit-2025-01-15-143022-Overlaps.csv
  GPO-Audit-2025-01-15-143022-DriveMaps.csv
  GPO-Audit-2025-01-15-143022-Printers.csv
  GPO-Audit-2025-01-15-143022-Optimizations.csv
  GPO-Audit-2025-01-15-143022-Security.csv
  GPO-Audit-2025-01-15-143022-NoSecurityFiltering.csv
  GPO-Audit-2025-01-15-143022-Links.csv
  GPO-Audit-2025-01-15-143022-FSLogix.csv
  GPO-Audit-2025-01-15-143022-FSLogix-Conflicts.csv
  GPO-Audit-2025-01-15-143022-XMLExport.csv
  GPO-XML-Export/                            # Individual GPO XML files
    GPO-Inventory.xml                        # Combined metadata
    PolicyName-{GUID}.xml                    # One per GPO
```

CSV files are only created when findings exist for that category.

## Performance Notes

The script caches every GPO's XML report in memory on the first pass, then reuses the cache across all analysis functions. This avoids redundant `Get-GPOReport` calls and significantly reduces runtime in environments with many GPOs.
