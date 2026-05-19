# DiskSpd Diagnostic Tool — Design

**Date:** 2026-05-19
**Status:** Approved design, ready for implementation plan
**Folder:** `DiskSpdDiagnostic/`

## Purpose

On-demand storage triage tool that uses Microsoft's `diskspd.exe` to produce authoritative IOPS, throughput, and latency numbers for physical and virtual disks — both locally on the machine running the tool and across the network (UNC shares and remote VDAs targeting file servers). Built for the moment a user reports "this is slow" and the operator needs to prove or disprove a storage bottleneck quickly.

Complements (does not replace) `CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1`, which already does lightweight I/O sampling. This tool is the deeper benchmark you reach for when the consolidated diagnostic flags a storage concern.

## Scope

### In scope
- Three targeting modes:
  1. Local disk on the machine running the tool
  2. SMB/UNC share from the machine running the tool
  3. Run diskspd ON a remote VDA, targeting a path from that VDA (typically a FileServer share — measures the exact path a real user session experiences)
- Preset workload profiles with override fields (dual-audience design)
- WPF GUI as primary form factor; optional `-NoUI` headless mode for scheduling
- Live in-GUI results view + saved HTML report
- Bundled `diskspd.exe` (x64, Microsoft-signed)
- Preflight checks + mandatory cleanup + business-hours warning

### Out of scope
- Scheduled baselining / trending across runs (separate tool if desired later)
- Comparative side-by-side runs in a single invocation
- Continuous monitoring or alerting
- Cross-platform support — Windows + PowerShell 5.1 only
- A separate exposed module API (Approach A — everything in one .ps1)

## Folder layout

```
DiskSpdDiagnostic/
├── Invoke-DiskSpdDiagnostic.ps1     # WPF UI + engine, single file
├── diskspd.exe                       # Bundled, x64, Microsoft-signed
├── diskspd-LICENSE.txt               # MIT license from upstream release
├── ReportTemplate.html               # HTML report skeleton with CSS inline
└── README.md                         # Usage, parameters, screenshots
```

Single-file script matches the existing project convention (every other tool is self-contained in its own folder with a `.ps1` and `README.md`).

## Script entry points

```powershell
# GUI mode (default)
.\Invoke-DiskSpdDiagnostic.ps1

# Headless mode for scheduling / CI
.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' `
    -Profile FSLogixLike -OutputPath C:\Reports
```

`[CmdletBinding()]` parameters:
- `-Target <string>` — path or UNC; required for `-NoUI`
- `-ComputerName <string>` — optional; if set, runs diskspd on that VDA
- `-Profile <string>` — `FSLogixLike | SequentialRead | MixedUserLoad | QuickSanity | Custom`
- `-BlockSize`, `-Threads`, `-QueueDepth`, `-WriteRatioPercent`, `-DurationSeconds`, `-TestFileSizeMB` — override fields (required when `-Profile Custom`)
- `-NoUI <switch>` — skip the WPF window
- `-OutputPath <string>` — report destination (defaults to `Documents\DiskSpdReports`)
- `-Force <switch>` — bypass business-hours confirmation

## WPF UI

Single window, ~900×650, dark default (matches CLAUDE.md design context).

**Zone 1 — Target selector (top, ~120px)**
Three radio buttons:
- Local disk on this machine → path textbox + Browse button
- Network path from this machine → UNC textbox
- Run on remote VDA, target a path → VDA name textbox + target path textbox

Inactive fields gray out. "Test connection" link beside each runs preflight only.

**Zone 2 — Workload profile + overrides (middle, ~180px)**
Dropdown:
- **FSLogix-like** — 4K random, 70/30 R/W, 4 threads, QD 8, 30s
- **Sequential read** — 64K sequential read, 1 thread, QD 4, 30s
- **Mixed user load** — 8K random, 80/20 R/W, 2 threads, QD 4, 60s
- **Quick sanity** — 64K random, 100% read, 1 thread, QD 2, 10s
- **Custom** — enables all override fields

"Advanced" expander reveals overrides (block size, threads, queue depth, R/W mix %, duration, test file size). Preset selection pre-fills the overrides so the operator sees what they're getting.

**Zone 3 — Run controls + live results (bottom, ~350px)**
- "Run Test" button (primary action, blue accent #5dade2)
- "Cancel" (disabled until running)
- Status line: `Idle / Preflight / Running diskspd (Xs remaining) / Parsing / Done`
- Progress bar tied to elapsed/total duration
- Results grid: Metric / Value rows for IOPS, Avg Latency, P95 Latency, P99 Latency, MB/s read, MB/s write, CPU%, test file path
- "Save Report" enabled after a successful run

Color convention follows project standard: Green `[PASS]`, Yellow `[WARN]`, Red `[FAIL]` dots beside threshold-breaching rows.

## Engine functions

All defined in `Invoke-DiskSpdDiagnostic.ps1`.

### `Test-DiskSpdPreflight`
- Verifies `diskspd.exe` is next to the script and Authenticode-signed by Microsoft
- Confirms target path reachable + writable (1-byte probe file)
- Confirms free space at target ≥ test file size × 1.2
- For remote mode: `Test-WSMan`, and confirms ability to copy diskspd to `\\<vda>\C$\Windows\Temp\`
- Business-hours check (Mon–Fri 7am–6pm local) returns a warning flag the UI surfaces as a modal; `-Force` skips
- Returns `[PSCustomObject]@{ Pass; Warnings; Errors }`

### `Invoke-DiskSpdLocal`
- Builds argv from profile + overrides
- Runs `diskspd.exe -Rxml … <testfile>` via `Start-Process -NoNewWindow -PassThru -RedirectStandardOutput`
- `-Rxml` produces structured XML output (much more reliable than text parsing)
- Runs in a background runspace so the UI stays responsive and Cancel works

### `Invoke-DiskSpdRemote`
For VDA-targeted runs:
- Copies bundled `diskspd.exe` to `\\<vda>\C$\Windows\Temp\diskspd.exe` (skipped if SHA-256 matches existing copy)
- `Invoke-Command -ComputerName <vda>` runs diskspd against the target path, captures XML as string, returns it
- `finally{}` cleanup deletes both the test file and the copied binary

### `ConvertFrom-DiskSpdXml`
Parses the XML into a flat `[PSCustomObject]`: `IOPS`, `AvgLatencyMs`, `Latency95Ms`, `Latency99Ms`, `ReadMBps`, `WriteMBps`, `CpuPercent`, `TestFilePath`, `Duration`, `ProfileName`, plus the raw XML for the report.

### `Get-DiskSpdHealthAssessment`
Applies thresholds from `CitrixVDADiagnostics/README.md`:
- Network read <25 MB/s on 1GbE = CRIT, 25–50 = WARN, >50 = OK
- Local read <50 MB/s = CRIT, 50–100 = WARN, >100 = OK
- Read latency >20ms = CRIT, 10–20 = WARN, <10 = OK
- Write latency >20ms = CRIT, 10–20 = WARN, <10 = OK
Returns per-metric status the UI uses to color rows and the report uses to summarize.

### `Export-DiskSpdHtmlReport`
Loads `ReportTemplate.html`, fills placeholders (`{{TARGET}}`, `{{PROFILE}}`, `{{RESULTS_TABLE}}`, `{{HEALTH_BADGES}}`, `{{RAW_XML}}`), writes to disk. Styled to match the existing CitrixVDA-Consolidated HTML reports.

## Data flow

```
User clicks Run
   ↓
Test-DiskSpdPreflight  →  errors? show modal, abort
   ↓                       warnings? show modal, Continue/Cancel
Business-hours check   →  modal if applicable, -Force skips
   ↓
Invoke-DiskSpdLocal | Invoke-DiskSpdRemote   (in background runspace)
   ↓
ConvertFrom-DiskSpdXml
   ↓
Get-DiskSpdHealthAssessment
   ↓
UI updates results grid + status
   ↓
User clicks Save Report  →  Export-DiskSpdHtmlReport
   ↓
finally{}: cleanup test file + remote diskspd.exe, log result
```

## Error handling

| Failure mode | Behavior |
|---|---|
| Preflight error | Modal with message, no run |
| Business-hours warning | Modal Continue/Cancel; `-Force` skips |
| diskspd nonzero exit | Parse stderr, red status in UI, no report generated |
| XML parse failure | Fall back to parsing diskspd's human text output, mark report as "partial parse" |
| Remote connection drop mid-test | Cancel local job, surface error, attempt cleanup via fresh remote session |
| Cleanup failure | UI shows red "Cleanup failed — manual removal needed: `<path>`" |

## Safety guardrails

Per user selection:
- **Preflight** — verifies path, free space, signed binary, remote reachability before any I/O
- **Cleanup** — `try{…}finally{}` around every test-file and binary-copy operation; runs even on Cancel/Ctrl+C; UI confirms cleanup success or surfaces the path needing manual removal
- **Business-hours warning** — modal between 7am–6pm Mon–Fri; `-Force` to skip

Deliberately *not* included (operator opted out):
- Read-only-by-default (operator wants writes available without ceremony)
- Test file size cap (operator wants full control)

## Conventions adhered to

From `CLAUDE.md`:
- `[CmdletBinding()]` with typed `param()`, `[ValidateSet()]` on `-Profile`, `[Parameter(Mandatory)]` where appropriate
- `-OutputPath` for file output
- Comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- Runtime `Import-Module` with try/catch — but this script needs only `PresentationFramework` (in-box) for WPF, no RSAT modules
- `#Requires -Version 5.1`, `#Requires -RunAsAdministrator`
- Try/catch around remote calls so one unreachable VDA doesn't halt the run
- `[PASS]/[WARN]/[FAIL]` color prefixes in console output for `-NoUI` mode
- Timestamps: `yyyy-MM-dd HH:mm:ss` for logs, `yyyy-MM-dd_HHmmss` for filenames
- `[PSCustomObject]` for structured data
- `-ComputerName` for all remote queries
- Folder structure: own folder with `.ps1` + `README.md`

## Open questions / deferrals

None blocking. Items to revisit after first ship:
- Trending across runs (if useful, separate tool that reads the HTML reports' embedded raw XML)
- A side-by-side comparison mode (local vs. remote in a single window)
- Optional `-Profile FioCompat` mapping to FIO defaults for cross-tool comparison

## Next step

Hand off to `writing-plans` skill to produce an implementation plan.
