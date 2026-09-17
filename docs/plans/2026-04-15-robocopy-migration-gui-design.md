# RobocopyMigration-GUI Design

## Overview

A single-file, browser-based robocopy migration tool for server-to-server file migrations. Forked from FolderPermissionManager-GUI's architecture (PowerShell HTTP listener + embedded HTML/CSS/JS). Preserves timestamps, permissions, and attributes via robocopy.

## File Structure

```
RobocopyMigration/
├── RobocopyMigration-GUI.ps1   # Entire tool (HTTP listener + HTML/CSS/JS)
└── README.md
```

## Architecture

Same pattern as FolderPermissionManager-GUI:

1. PowerShell `System.Net.HttpListener` on configurable port (default 8272)
2. `GET /` serves full HTML/CSS/JS frontend as single response
3. API endpoints handle backend logic (validation, robocopy execution, job management)
4. Frontend communicates via `fetch()` to API routes
5. Browser opens automatically on launch (`-NoBrowserOpen` switch to suppress)

### Parameters

```powershell
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8272,
    [switch]$NoBrowserOpen
)
```

## UI Layout

Single-page layout with three zones:

### 1. Header Bar
Tool name ("Robocopy Migration"), dark background, minimal.

### 2. Job Builder Panel (top half)
- **Source path** — text input + Browse button (folder picker modal, same tree pattern as FolderPermissionManager)
- **Destination path** — same
- **Preset selector** — dropdown with three modes:
  - "Full Migration" — timestamps, permissions, attributes, all subdirectories
  - "Data Only" — files and timestamps, no permissions
  - "Mirror" — exact copy, deletes extras at destination (with destructive warning badge)
- **Advanced section** — collapsed by default, expandable:
  - Retry count and wait time
  - Bandwidth throttle (`/IPG:`)
  - Exclude files/folders patterns
  - Log file output path
  - Multi-threaded copy toggle (`/MT:` with thread count)
- **Action buttons:** "Preview" (dry run with `/L`) and "Add to Queue" (or "Start Now" if queue empty), side by side

### 3. Job Queue & Log Panel (bottom half)
- **Queue table** — columns: #, Source, Destination, Preset, Status (Pending/Running/Complete/Failed/Cancelled), Actions (cancel/remove)
- **Execution controls:** "Run Queue" button, sequential/parallel toggle (bandwidth warning on parallel), "Clear Completed"
- **Log drawer** — clicking a job row expands inline log panel with live robocopy output and running stats

## API Endpoints

| Method | Route | Purpose |
|--------|-------|---------|
| `GET` | `/` | Serve HTML/CSS/JS frontend |
| `GET` | `/api/browse?path=` | List drives or folder contents for picker |
| `POST` | `/api/validate` | Check source exists, destination writable, return counts |
| `POST` | `/api/preview` | Robocopy with `/L`, return what would be copied |
| `POST` | `/api/job/add` | Add job to queue (source, dest, preset, overrides) |
| `GET` | `/api/job/list` | Return all jobs with status |
| `POST` | `/api/job/start` | Start queue execution (sequential or parallel mode) |
| `POST` | `/api/job/cancel/{id}` | Kill running job's robocopy process |
| `DELETE` | `/api/job/{id}` | Remove job from queue |
| `GET` | `/api/job/{id}/log` | Poll for live log output and stats |

Job lifecycle: Added (pending) → Running → Complete/Failed/Cancelled. Each job gets a GUID. Running jobs store `System.Diagnostics.Process` handle for cancellation.

## Robocopy Presets

### Full Migration (default)
```
robocopy <src> <dst> /S /E /COPY:DATSOU /DCOPY:DAT /R:3 /W:5 /NP /NDL /TEE /V /BYTES
```
All files, subdirectories (including empty), preserves Data, Attributes, Timestamps, Security (NTFS ACLs), Owner, aUditing.

### Data Only
```
robocopy <src> <dst> /S /E /COPY:DAT /DCOPY:DAT /R:3 /W:5 /NP /NDL /TEE /V /BYTES
```
Same structure, no permissions/owner/auditing.

### Mirror
```
robocopy <src> <dst> /MIR /COPY:DATSOU /DCOPY:DAT /R:3 /W:5 /NP /NDL /TEE /V /BYTES
```
Exact replica — deletes destination files not present at source. UI shows red warning.

### Common Flags
- `/NP` — no per-file progress percentage (cleaner log)
- `/NDL` — don't log directory names separately
- `/V` — verbose file listing for live log
- `/BYTES` — sizes in bytes for stat parsing
- `/TEE` — output to console and log simultaneously
- `/R:3 /W:5` — retry 3 times, wait 5 seconds (overridable)

### Advanced Overrides
Layer on top of selected preset:
- Retry/wait → replaces `/R:` and `/W:` values
- Bandwidth throttle → adds `/IPG:<ms>`
- Multi-threaded → adds `/MT:<n>` (default 8 when enabled)
- Exclude files → adds `/XF <pattern>...`
- Exclude dirs → adds `/XD <pattern>...`
- Log to file → adds `/LOG:<path>`

## Live Log & Stats

Backend captures robocopy stdout line-by-line. Frontend polls `/api/job/{id}/log` every ~1 second.

### Stats Object
```json
{
  "filesCopied": 142,
  "filesSkipped": 3,
  "filesFailed": 1,
  "bytesCopied": 52428800,
  "elapsedSeconds": 34,
  "currentFile": "\\\\OldServer\\Share\\Reports\\Q4-2025.xlsx",
  "status": "running"
}
```

Parsed via regex on each stdout line as it arrives. No pre-scan needed.

### Frontend Display
- Stats bar: `142 copied · 3 skipped · 1 failed · 50 MB · 0:34 elapsed`
- Scrollable monospace log panel (auto-scrolls, pauses if user scrolls up)

### Exit Code Mapping
- `0-3` → Complete (success)
- `4-7` → Complete with warnings
- `8+` → Failed
- Process killed → Cancelled

## Design System
Matches FolderPermissionManager: dark theme, blue accent (#5dade2 range), bold modern tooling aesthetic. Plain English labels, icons paired with text, density with breathing room.
