# Citrix VDA Fleet Resource Report — Design

**Date:** 2026-08-19
**Status:** Approved design, ready for implementation plan
**Folder:** `Get-CitrixVDAResources/`

## Purpose

Fleet-wide resource inventory for Citrix VDAs. Discovers every VDA from the Delivery
Controller, collects CPU / memory / disk / uptime per machine over CIM, and produces two
artifacts:

1. **CSV** — one row per VDA, the internal record.
2. **Self-contained HTML report** — for stakeholders who only care about hardware
   resources and performance at a glance.

Complements `CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1` rather than replacing it.
That tool goes deep on one machine; this one goes wide across all of them. It answers
"which VDAs in this environment are under pressure?" — the question you ask before you
know which machine to run the consolidated diagnostic against.

## Scope

### In scope
- Broker-based discovery with optional delivery-group / catalog scoping
- Per-VDA resource collection over CIM sessions (WinRM)
- Broker state per machine (registration, maintenance mode, load index, session count)
- Tunable warn/critical thresholds
- CSV export + self-contained HTML report with embedded SVG charts
- Sequential collection, PowerShell 5.1 compatible
- Pester unit tests for the pure logic

### Out of scope
- FSLogix profile/storage detail — covered by `CitrixVDADiagnostics/Monitor-CitrixFSLogixStorage.ps1`
- Top-process detail per machine — covered by `CitrixVDA-Consolidated.ps1`
- Trending or comparison across runs (each run is a point-in-time snapshot)
- Parallel collection (see Non-Goals — deliberately deferred)
- Remediation of any kind — this tool only reports
- Email delivery / scheduled-task integration

## Folder layout

```
Get-CitrixVDAResources/
├── Get-CitrixVDAResources.ps1        # Everything: discovery, collection, reporting
├── README.md
└── Tests/
    └── Get-CitrixVDAResources.Tests.ps1
```

Single self-contained `.ps1`, matching the repo's flat one-tool-per-folder pattern.

## Architecture

Four stages, each isolated behind its own function so they can be tested independently:

```
Discover (broker)  →  Collect (CIM, per machine)  →  Analyze (thresholds)  →  Report (CSV + HTML)
   Get-VDAInventory      Get-VDAResourceSnapshot       Get-ResourceStatus       Export + New-VDAHtmlReport
```

| Function | Responsibility | Depends on |
|---|---|---|
| `Get-VDAInventory` | Query broker, return machine list with broker state | Citrix Broker SDK |
| `Get-VDAResourceSnapshot` | One machine in, one flat PSCustomObject out | CIM / WinRM |
| `Get-ResourceStatus` | Value + thresholds → `PASS`/`WARN`/`FAIL` | Nothing (pure) |
| `New-VDAHtmlReport` | Result set → HTML string | Nothing (pure) |
| `Write-StatusLine` | Console output with color + prefix | Nothing |

`Get-VDAResourceSnapshot` takes exactly one machine. The sequential `foreach` over the
inventory is the only place that would change if parallelism is added later.

`Get-ResourceStatus` and `New-VDAHtmlReport` are pure functions — no CIM, no broker, no
filesystem — which is what makes the test suite possible without a live Citrix site.

## Verified Facts

Per CLAUDE.md, documented facts were checked against vendor documentation rather than
recalled. Each gets a citation comment next to the code it justifies.

### MaxRecordCount silently truncates at 250

**This is the most consequential finding of the design phase.** Citrix Broker cmdlets
return only the first **250** records when `-MaxRecordCount` is not specified. The cmdlet
emits a warning and continues — it does not error.

On a fleet larger than 250 VDAs, a naive `Get-BrokerMachine` call under-reports and the
resulting report *looks complete*. This is exactly the failure mode CLAUDE.md warns about:
a confident, plausible, wrong answer rather than an error.

Mitigations, both required:
1. Pass `-MaxRecordCount` explicitly (default `[int]::MaxValue`).
2. Report discovered-vs-collected counts in console, CSV summary, and HTML, so a partial
   run is always visible.

Source: <https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2511/Broker/about_Broker_Filtering.html>

### Get-BrokerMachine properties

Confirmed present: `DNSName`, `RegistrationState`, `InMaintenanceMode`, `LoadIndex`,
`SessionCount`, `PowerState`, `OSType`, `CatalogName`, `DesktopGroupName`.

`RegistrationState` values: `Unregistered`, `Initializing`, `Registered`, `AgentError`.

Filtering parameters: `-DesktopGroupName`, `-CatalogName`, `-MachineName`.
Controller address: `-AdminAddress` (common to all Broker cmdlets).

Source: <https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2407/Broker/Get-BrokerMachine.html>

### Open item for implementation

`Win32_PerfFormattedData_PerfOS_Processor` field names (`PercentProcessorTime`, `Name`
for the `_Total` instance) must be verified against Microsoft documentation during
implementation and cited inline. Do not write these from memory.

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-DeliveryController` | string | `localhost` | Passed to `-AdminAddress` |
| `-DesktopGroupName` | string | — | Scope to one delivery group |
| `-CatalogName` | string | — | Scope to one catalog |
| `-MachineName` | string[] | — | Explicit machines; bypasses broker filtering |
| `-Credential` | PSCredential | — | For CIM where current context lacks rights |
| `-CpuWarnPercent` | int (1-100) | 80 | CPU warn threshold |
| `-CpuCriticalPercent` | int (1-100) | 90 | CPU critical threshold |
| `-MemoryWarnPercent` | int (1-100) | 80 | Memory warn threshold |
| `-MemoryCriticalPercent` | int (1-100) | 90 | Memory critical threshold |
| `-DiskWarnPercent` | int (1-100) | 80 | Disk-used warn threshold |
| `-DiskCriticalPercent` | int (1-100) | 90 | Disk-used critical threshold |
| `-MaxRecordCount` | int | `[int]::MaxValue` | Broker record cap — see Verified Facts |
| `-ConnectionTimeoutSeconds` | int | 15 | Per-machine CIM timeout |
| `-IncludeUnregistered` | switch | off | Include non-`Registered` machines in collection |
| `-OutputPath` | string | `.` | Where CSV + HTML are written |
| `-NoOpen` | switch | off | Suppress opening the HTML when finished |
| `-LoadFunctionsOnly` | switch | off | Dot-source for Pester without executing |

`-LoadFunctionsOnly` follows the idiom established in
`AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`.

Per CLAUDE.md, the Citrix SDK is loaded via runtime `Add-PSSnapin` / `Import-Module` in
try/catch — never `#Requires -Modules`. The existing fallback chain in
`Get-CitrixSessions/Get-CitrixSessions.ps1` (PSSnapin first, then Import-Module) is the
pattern to copy.

## Data Flow

Discovery returns one object per VDA carrying broker state. Collection enriches each with
resource metrics. Every row that comes out of discovery appears in both outputs — an
unreachable machine is a row with `CollectionStatus = 'Unreachable'` and null metrics,
never a missing row. Silence is never mistaken for health.

### Output row schema

| Field | Source |
|---|---|
| `MachineName`, `DnsName` | Broker |
| `CatalogName`, `DeliveryGroup` | Broker |
| `RegistrationState`, `InMaintenanceMode` | Broker |
| `LoadIndex`, `SessionCount`, `PowerState` | Broker |
| `CpuPercent` | CIM perf data |
| `MemoryTotalGB`, `MemoryUsedGB`, `MemoryFreeGB`, `MemoryUsedPercent` | `Win32_OperatingSystem` |
| `DiskSummary` (per-drive `C: 45/120GB (37%)`) | `Win32_LogicalDisk`, fixed disks only |
| `MaxDiskUsedPercent` | Computed — worst drive, drives the status |
| `UptimeDays` | `Win32_OperatingSystem.LastBootUpTime` |
| `CollectionStatus` | `Success` / `Unreachable` / `Skipped` |
| `ErrorMessage` | Exception message when not `Success` |
| `OverallStatus` | Worst of CPU / memory / disk status |

## Error Handling

| Condition | Behavior |
|---|---|
| Citrix SDK not loadable | `Write-Error`, exit non-zero — cannot discover without it |
| Broker query fails | `Write-Error`, exit non-zero |
| Broker returns zero machines | `Write-Warning`, exit 0 (nothing to do) |
| Broker warns of truncation | `[WARN]` line naming the cap; surfaced in HTML |
| CIM session fails for a machine | `[WARN]`, row with `Unreachable`, `continue` |
| A single CIM query fails mid-machine | That field is null, other fields still collected |
| Machine unregistered, `-IncludeUnregistered` off | Row with `Skipped`, no connection attempted |
| Machine powered off | Row with `Skipped` — expected, not an error |
| `-OutputPath` missing | `New-Item -ItemType Directory -Force`; error and exit if that fails |
| CSV or HTML write fails | `Write-Error`, exit non-zero |

Every remote call is individually wrapped, `Remove-CimSession` in `finally`. One
unreachable VDA never halts the run.

## Console Output

Repo dual-output convention — color-coded prefixes, `yyyy-MM-dd HH:mm:ss` timestamps:

```
[INFO]  2026-08-19 10:14:02  Connecting to Delivery Controller: DDC01
[INFO]  2026-08-19 10:14:03  Discovered 48 VDAs (delivery group: All)
[INFO]  2026-08-19 10:14:03  Collecting resources (sequential)...
   (Write-Progress: current machine, N of 48)
[PASS]  2026-08-19 10:14:09  VDA-0001   CPU 12%  MEM 41%  DISK 55%  up 6d
[WARN]  2026-08-19 10:14:15  VDA-0007   CPU 88%  MEM 79%  DISK 61%  up 41d
[FAIL]  2026-08-19 10:14:21  VDA-0012   CPU 71%  MEM 94%  DISK 91%  up 118d
[WARN]  2026-08-19 10:14:36  VDA-0019   Unreachable — WinRM connection timed out
[INFO]  2026-08-19 10:16:44  Collected 46 of 48 (2 unreachable)
[PASS]  2026-08-19 10:16:44  CSV:  C:\Reports\CitrixVDAResources_2026-08-19_101402.csv
[PASS]  2026-08-19 10:16:44  HTML: C:\Reports\CitrixVDAResources_2026-08-19_101402.html
```

`Write-Progress` cleared when collection finishes. HTML opened via `Start-Process` unless
`-NoOpen`.

## HTML Report

Single self-contained file — inline CSS, inline SVG, no external requests — so it survives
being emailed. Dark theme per the CLAUDE.md design direction (bold modern tooling, strong
typographic hierarchy, blue accent; not dashboard gray soup).

Structure, top to bottom:

1. **Header** — environment name, delivery-group scope, timestamp, VDA count.
2. **Fleet summary band** — total VDAs, reachable, healthy / warning / critical counts,
   fleet-average CPU and memory. Any truncation or unreachable count stated plainly here.
3. **Charts** — inline SVG horizontal bars for CPU, memory, and worst-disk per VDA, sorted
   worst-first so the machines that matter are at the top. Threshold lines drawn at warn
   and critical.
4. **Full table** — every VDA including unreachable ones, color-coded by status, with
   broker state alongside resource numbers.

Design principles applied from CLAUDE.md: plain-English labels ("Memory in use", not
"MemUtil%"), machine names always visible as data, status communicated by both color and
text label (never color alone).

## Testing

Pester, mirroring `AD-LockoutDiagnostics/Tests/`. Script dot-sourced with
`-LoadFunctionsOnly`; broker and CIM mocked. No live Citrix site required.

| Target | Cases |
|---|---|
| `Get-ResourceStatus` | Below warn → `PASS`; at warn boundary → `WARN`; at critical boundary → `FAIL`; null input → no crash |
| Row construction | Unreachable machine still produces a row with `ErrorMessage`; skipped machine marked `Skipped` |
| `New-VDAHtmlReport` | Fixed result set produces valid HTML containing every machine name; unreachable rows present; no unescaped `<`/`&` from machine names |
| CSV shape | Column set stable; one row per discovered VDA including failures |
| Truncation | Warning surfaced when broker reports more records than returned |

Boundary values are tested explicitly (exactly 80, exactly 90) since off-by-one in
threshold comparison silently misclassifies machines.

## Non-Goals / Explicit YAGNI

- **No parallelism in this pass.** Sequential is correct to ~50 VDAs and guaranteed to run
  on stock PS 5.1. Collection is isolated behind one function so a runspace pool can be
  added later without reshaping the script.
- No historical trending or run-over-run comparison.
- No alerting, email, or webhook delivery.
- No remediation actions — reporting only.
- No FSLogix or process-level detail (existing tools cover these).
- No `ImportExcel` or any other external module dependency.

## Success Criteria

1. Running against a live site with no parameters discovers every VDA and produces both
   files without manual input.
2. A fleet larger than 250 VDAs is reported **completely** — the `MaxRecordCount` default
   does not silently truncate.
3. An unreachable or powered-off VDA appears as a row with a clear status; the run
   completes.
4. Every documented Citrix/Microsoft fact in the script carries a citation comment, and
   `.NOTES` carries a `REFERENCES` block.
5. The HTML opens in Edge/Chrome, is readable without horizontal scroll at 1080p, and a
   non-technical reader can identify the machines needing attention within seconds.
6. Pester suite passes with no live Citrix dependency.
