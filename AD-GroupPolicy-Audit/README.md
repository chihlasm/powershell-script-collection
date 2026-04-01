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
| **FSLogix** | Profile Container, ODFC, Cloud Cache, and App Masking settings from both ADMX Admin Templates and GP Preferences registry items; conflicting values across GPOs; best-practice recommendations (VolumeType, redirections.xml, VHDLocations/CCDLocations overlap, missing critical settings); mixed-source warnings |
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

## FSLogix Audit Details

The FSLogix audit detects settings delivered via two different mechanisms:

- **ADMX Admin Templates** (`Computer Configuration > Administrative Templates > FSLogix`) write to `HKLM\SOFTWARE\Policies\FSLogix\*`. The script parses the ADMX category path from the GPO XML report and maps it to the underlying registry location.
- **GP Preferences Registry Items** (`Computer Configuration > Preferences > Windows Settings > Registry`) write directly to `HKLM\SOFTWARE\FSLogix\*`. These are detected by matching the registry key path.

When both methods are used in the same environment, the script flags it as a consistency warning because `Policies\` paths take precedence and GP Preferences registry items are not removed when their GPO is unlinked.

Best-practice checks include:

| Setting | Recommendation |
|---------|---------------|
| `Enabled` | Must be set to 1 for Profile Containers to activate |
| `VolumeType` | Use VHDX over VHD (larger size limit, better corruption resilience) |
| `DeleteLocalProfileWhenVHDShouldApply` | Set to 1 to prevent stale local profile conflicts |
| `FlipFlopProfileDirectoryName` | Set to 1 for human-readable folder names (username_SID) |
| `PreventLoginWithTempProfile` | Set to 1 to prevent silent data loss from temp profiles |
| `PreventLoginWithFailure` | 0 for most environments (fallback to local), 1 for strict VDI |
| `RedirXMLSourceFolder` | Configure redirections.xml to exclude temp/cache folders |
| `VHDLocations` + `CCDLocations` | Never set both; CCDLocations silently overrides VHDLocations |

## Performance Notes

The script caches every GPO's XML report in memory on the first pass, then reuses the cache across all analysis functions. This avoids redundant `Get-GPOReport` calls and significantly reduces runtime in environments with many GPOs.
