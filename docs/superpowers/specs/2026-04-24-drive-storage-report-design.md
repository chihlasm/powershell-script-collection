# Drive Storage Report — Design

**Date:** 2026-04-24
**Author:** Michael Chihlas (with Claude)
**Status:** Approved for implementation planning

## Purpose

A standalone PowerShell script that inventories storage on a local Windows machine and produces a single self-contained HTML report covering:

1. Each fixed drive's total size, used, free, and utilization percentage.
2. Folder sizes up to 3 levels deep on each drive, sorted largest first.

Intended to run locally on servers where an admin needs a quick, readable picture of where storage is going.

## Scope

- **In scope:** Local fixed drives (`DriveType=3`). Single-machine execution.
- **Out of scope:** Remote targeting (`-ComputerName`), multi-server fan-out, CSV/JSON export, file-count or last-modified metrics, owner lookup, scheduled execution, email delivery.

## Folder & File Layout

New top-level folder following the repo's one-tool-per-folder convention:

```
Drive-Storage-Report/
├── Get-DriveStorageReport.ps1
└── README.md
```

No shared modules. No external dependencies beyond built-in Windows PowerShell 5.1 and CIM.

## Parameters

```powershell
[CmdletBinding()]
param(
    [string[]]$Drive,
    [ValidateRange(1,10)]
    [int]$Depth = 3,
    [ValidateRange(0,100000)]
    [int]$MinSizeMB = 100,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$NoOpen
)
```

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-Drive` | (all fixed) | Optional filter. Accepts drive letters (e.g. `C`, `C:`, `C:\`). Invalid letters are warned and skipped. |
| `-Depth` | `3` | Folder levels to break out individually in the report. Beyond this depth, subfolder sizes roll up into their depth-3 ancestor. |
| `-MinSizeMB` | `100` | Folders below this size are aggregated into a single `Misc.` row at their depth level. |
| `-OutputPath` | current dir | Where the HTML file is written. Created if missing. |
| `-NoOpen` | off | Skip auto-launch of the HTML after generation. |

Script header requirements:
- `#Requires -Version 5.1`
- Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE` (3+), `.NOTES`.
- No `#Requires -RunAsAdministrator`. Admin not strictly required, but noted in `.NOTES` that running without admin causes more access-denied folders to fall into the Unreadable bucket.

## Data Collection

### Drive enumeration

`Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"` to enumerate local fixed drives. For each drive, capture:

- `DeviceID` (e.g. `C:`)
- `VolumeName` (label)
- `Size` (total bytes)
- `FreeSpace` (free bytes)
- Derived: `UsedBytes = Size - FreeSpace`, `UsedPct = UsedBytes / Size`

If `-Drive` is supplied, filter to matching `DeviceID` values (normalized to `<letter>:`).

### Folder traversal

Single recursive walk per drive. Bottom-up aggregation so each folder is scanned exactly once.

**Pseudo-code:**

```
function Walk-Folder(path, currentDepth):
    direct = sum of file.Length for files directly in path
             (Get-ChildItem -File -Force, caught for access denied)
    total = direct
    subRecords = []

    for each subfolder of path (Get-ChildItem -Directory -Force):
        try:
            childTotal, childRecords = Walk-Folder(subfolder.FullName, currentDepth + 1)
            total += childTotal
            subRecords += childRecords
        catch [UnauthorizedAccessException | IOException]:
            UnreadablePaths += subfolder.FullName

    if currentDepth <= MaxDepth:
        emit { Path=path, Depth=currentDepth, SizeBytes=total }

    return (total, subRecords + self-if-emitted)
```

- Errors on individual files/folders are swallowed locally; enumeration continues.
- Reparse points (junctions, symlinks) are skipped to avoid loops and double-counting — check `FileAttributes.ReparsePoint`.
- Drive root is depth 0 and is tracked as the drive total (not emitted as a folder row — drive card shows it).

### Misc. bucket

After the walk, for each parent folder (including the drive root), inspect its direct children:

- Partition children into "kept" (SizeBytes >= MinSizeMB threshold in bytes) and "rolled-up" (below threshold).
- If rolled-up count > 0, emit a synthetic record:
  - `Path = "<parent>\(Misc. — N folders)"`
  - `Depth = childDepth`
  - `SizeBytes = sum of rolled-up sizes`
  - Flag: `IsMisc = true`
- Keep and rolled-up sizes always sum to the parent's child-total, so totals balance.
- The `Misc.` row renders as the last child under its parent in the HTML table, at the child's depth. It exists only where `rolled-up count > 0`.

### Unreadable folders

A flat list of paths that threw access-denied or IO errors during enumeration. Rendered in its own collapsed section at the bottom of the report. These folders contribute 0 bytes to totals (their real size is unknown). This is acknowledged in the report footer.

## HTML Report

### File output

- Filename: `DriveStorageReport_<HOSTNAME>_<yyyy-MM-dd_HHmmss>.html`
- Location: `-OutputPath`
- Single file, fully self-contained (inline CSS, no external fonts, no JS required for core viewing; lightweight inline JS only for the expand/collapse on the Unreadable section).
- UTF-8 encoding.

### Layout

1. **Header strip**
   - Report title: "Drive Storage Report"
   - Hostname, scan start timestamp, total scan duration
   - Total drives scanned · total bytes across drives

2. **Drive summary cards** — CSS grid, responsive
   - One card per drive
   - Card contents:
     - Drive letter (large) · volume label (smaller, muted)
     - `<used> used of <total>` in human-readable units
     - Progress bar, width = UsedPct
       - Color: green (< 75%), amber (75–90%), red (>= 90%)
     - `<free> free` beneath the bar

3. **Per-drive folder sections** — one per drive, in order C: → Z:
   - Section header: `C:\ — 456 GB used`
   - Flat table, sorted by size descending within each parent, columns:
     - **Folder** — indented by `(depth - 1) * 16px` so hierarchy reads visually. Monospace font for the path segment. Only the leaf folder name is shown (not full path) once inside its parent; depth-1 rows show the full path like `C:\Users`.
     - **Size** — human-readable, right-aligned
     - **Bar** — horizontal bar, width relative to the drive's used bytes. Subtle; for scannability, not precision.
   - `Misc.` rows rendered with a muted style and italic label.

4. **Unreadable folders section** (bottom, collapsed by default)
   - Summary: `⚠ 12 folders could not be read (access denied)`
   - Click to expand: plain list of paths in monospace.
   - Collapsed via `<details>/<summary>` — no custom JS needed.

5. **Footer**
   - Generated by `Get-DriveStorageReport.ps1` · hostname · timestamp
   - Note: "Unreadable folders contribute 0 bytes to totals. Run elevated for deeper coverage."

### Styling

Follows project design principles (bold, trustworthy, capable; dark default; VS Code / Windows Admin Center feel).

- **Background:** `#1a1a1a`
- **Surface:** `#242424` (cards, table rows on hover)
- **Border:** `#333`
- **Text primary:** `#e8e8e8`
- **Text muted:** `#8a8a8a`
- **Accent blue:** `#5dade2` (bars, links, headings)
- **Status colors (progress bars):** green `#27ae60`, amber `#f39c12`, red `#e74c3c`
- **Fonts:**
  - Sans: `-apple-system, "Segoe UI", Roboto, sans-serif` for UI chrome
  - Mono: `"Cascadia Code", "Consolas", monospace` for paths and sizes

Size formatter helper: bytes → `B`, `KB`, `MB`, `GB`, `TB` with 1 decimal place above MB, whole numbers below.

## Execution Flow & Console Output

Uses the repo's dual-output logging convention (console with color-coded status prefixes). No log file is written for this tool — the HTML is the artifact.

```
[INFO]  2026-04-24 10:14:02  Drive Storage Report starting on SERVER01
[INFO]  2026-04-24 10:14:02  Scanning 2 fixed drives
[INFO]  2026-04-24 10:14:02  Scanning C:\ ...
   (Write-Progress: top-level folder currently walking, running byte total)
[PASS]  2026-04-24 10:16:47  C:\ complete — 456 GB across 8,421 folders (2m 45s)
[INFO]  2026-04-24 10:16:47  Scanning D:\ ...
[PASS]  2026-04-24 10:18:12  D:\ complete — 1.2 TB across 14,302 folders (1m 25s)
[INFO]  2026-04-24 10:18:12  Writing report: C:\Reports\DriveStorageReport_SERVER01_2026-04-24_101412.html
[PASS]  2026-04-24 10:18:12  Report generated (4m 10s total)
```

- `Write-Progress` is cleared when each drive finishes.
- On success, print the HTML path and `Start-Process $path` unless `-NoOpen` is set.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| No fixed drives found | `Write-Error`, exit with non-zero code |
| `-Drive` filter matches nothing | `Write-Warning`, exit 0 (nothing to do) |
| `-OutputPath` doesn't exist | `New-Item -ItemType Directory -Force`; if creation fails, `Write-Error` and exit |
| A drive query fails entirely (offline / removable disappeared) | `[WARN]` line, `continue` to next drive |
| Access denied on a folder | Add to Unreadable list, continue |
| Access denied on a file | Silent — that file isn't counted; parent folder tally is `-ErrorAction SilentlyContinue` for file enumeration |
| Reparse points / symlinks | Skipped by attribute check, not an error |
| HTML write fails | `Write-Error`, exit non-zero |

## README.md (for the new tool folder)

Should cover:
- One-paragraph overview
- Requirements (Windows, PowerShell 5.1+)
- Parameters table
- 3 usage examples:
  - Scan all drives with defaults
  - `-Drive C -Depth 2 -MinSizeMB 500`
  - `-OutputPath \\fileserver\reports\storage -NoOpen`
- Note on running elevated for best coverage
- Sample screenshot placeholder (can be added later)

## Non-Goals / Explicit YAGNI

- No file-count, last-modified, or owner reporting (deferred — simplest useful version first).
- No CSV export (can be added later if requested).
- No trending / comparison across runs (each report is a point-in-time snapshot).
- No email delivery.
- No remote execution — user explicitly wants to run locally on each target server.
- No scheduled-task integration.
- No interactive tree UI (static indented table is sufficient for this pass).

## Success Criteria

1. Running `.\Get-DriveStorageReport.ps1` on a typical file server produces a single HTML file in under 10 minutes for drives with ~1 TB of data and fewer than 200k folders.
2. The HTML opens in Edge/Chrome and is readable without horizontal scroll on 1080p.
3. Drive totals, per-folder totals, and the Misc. bucket always sum correctly (no phantom bytes, no missing bytes relative to scanned folders).
4. Access-denied folders don't halt the scan; they appear in the Unreadable section.
5. All folders with size ≥ `MinSizeMB` at depths 1 through `Depth` appear as individual rows, sorted largest first within each parent.
