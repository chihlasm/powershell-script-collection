# Drive Storage Report

Generates a dark-themed HTML report showing local drive totals, free space, and per-folder sizes up to a configurable depth. Designed to be copied to a target server and run locally.

## Requirements

- Windows Server / Windows 10+
- PowerShell 5.1 or later
- No external modules

## Usage

```powershell
.\Get-DriveStorageReport.ps1
```

Opens the report in your default browser when finished.

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Drive` | all fixed drives | Limit scan to specific drive letters, e.g. `-Drive C,D`. Accepts `C`, `C:`, or `C:\`. |
| `-Depth` | `3` | How many folder levels to break out individually. Subfolders beyond this roll up into their depth-N ancestor. |
| `-MinSizeMB` | `100` | Folders below this size are aggregated into a Misc row at their depth level. |
| `-OutputPath` | current dir | Where the HTML file is written. Created if missing. |
| `-NoOpen` | off | Skip auto-launching the HTML file. |

## Examples

Scan every fixed drive with defaults:

```powershell
.\Get-DriveStorageReport.ps1
```

Scan only C:, two levels deep, hide anything under 500 MB:

```powershell
.\Get-DriveStorageReport.ps1 -Drive C -Depth 2 -MinSizeMB 500
```

Write the report to a network share without opening it:

```powershell
.\Get-DriveStorageReport.ps1 -OutputPath '\\fileserver\reports\storage' -NoOpen
```

## Output

A single self-contained HTML file named `DriveStorageReport_<HOSTNAME>_<yyyy-MM-dd_HHmmss>.html` containing:

- One drive summary card per fixed drive — total size, used, free, utilization bar (green below 75 %, amber 75–90 %, red above 90 %).
- Per-drive folder breakdown up to the configured depth, sorted largest first.
- **Misc.** rows aggregating folders below the threshold so totals always balance.
- Collapsible **Unreadable folders** section listing anything that threw access denied.

## Notes

- **Run elevated** for deepest coverage. Without admin, more system folders land in the Unreadable section and contribute 0 bytes to totals.
- Reparse points, junctions, and symlinks are skipped to avoid loops and double-counting.
- Large drives with millions of small files can take several minutes to scan. The console prints per-drive progress and final elapsed time.
