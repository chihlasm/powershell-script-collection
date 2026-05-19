# DiskSpd Diagnostic

On-demand storage triage. Wraps Microsoft's `diskspd.exe` with a WPF GUI and an optional headless mode for scheduling. Built for the moment a user reports "this is slow" and you need authoritative IOPS / throughput / latency numbers fast.

Complements `..\CitrixVDADiagnostics\CitrixVDA-Consolidated.ps1` — that tool samples I/O lightly; this one benchmarks deeply.

## Quick start

GUI:

```powershell
.\Invoke-DiskSpdDiagnostic.ps1
```

Headless (schedulable, no window):

```powershell
.\Invoke-DiskSpdDiagnostic.ps1 -NoUI -Target '\\FileServer01\FSLogix' -Workload FSLogixLike -Force
```

## What this measures

Each test asks `diskspd.exe` to hammer a scratch file for a fixed duration and reports back the actual I/O the storage subsystem can sustain. You get:

- **IOPS** — input/output operations per second (higher is better)
- **MB/s read / write** — throughput (higher is better)
- **Avg / P95 / P99 latency** — how long each I/O took (lower is better; P95/P99 are the slow-tail outliers that real users feel)
- **CPU %** — how much CPU the test pinned during the run
- **OK / WARN / CRIT badges** — each metric color-coded against the threshold table (see below)
- **A self-documenting HTML report** that includes the workload description, the threshold guide, and the raw diskspd XML output as an appendix

## Three targeting modes

The GUI's Target zone (or the equivalent CLI parameters) supports:

| Mode | Where diskspd runs | What it measures | When to use |
|---|---|---|---|
| **Local disk on this machine** | This machine | This machine's local disk subsystem | Sanity-checking your own workstation; testing a VDA's local C: |
| **Network path from this machine** | This machine | Network + remote storage end-to-end | "Is this share fast enough?" tests from a workstation |
| **Run on remote VDA, target a path** | A remote VDA via PSRemoting | The exact path a real user session experiences | The FSLogix triage scenario — `VDA01` writing to `\\FileServer\Profiles` |

The third mode requires WinRM on the VDA and the admin share (`\\<vda>\C$`) reachable from where you run the tool.

## Workload presets

The Preset dropdown picks the I/O pattern. Each preset has a one-line description in the GUI under the dropdown, and the same description appears at the top of the saved report.

| Preset | Block | Pattern | R/W | Threads | QD | Duration | Best for |
|---|---|---|---|---|---|---|---|
| **FSLogixLike**    | 4K  | random     | 70/30 | 4 | 8 | 30s | FSLogix profile container I/O simulation |
| **SequentialRead** | 64K | sequential | 100/0 | 1 | 4 | 30s | Boot/login throughput, large file copies, image deployment |
| **MixedUserLoad**  | 8K  | random     | 80/20 | 2 | 4 | 60s | General "is this drive fast enough?" mixed workload |
| **QuickSanity**    | 64K | random     | 100/0 | 1 | 2 | 10s | Fast smoke test; confirm a drive is reachable and sane |
| **Custom**         | (operator supplies all 6 fields) |

Any preset's settings can be overridden in the **Advanced overrides** expander (GUI) or via the matching CLI parameters.

## CLI parameters (for `-NoUI` / scheduling)

| Parameter | Notes |
|---|---|
| `-Target` | Path or UNC. Required when `-NoUI` is set. |
| `-ComputerName` | Optional. If set, diskspd runs on this remote VDA instead of locally. |
| `-Workload` | One of `FSLogixLike, SequentialRead, MixedUserLoad, QuickSanity, Custom`. Default `FSLogixLike`. |
| `-BlockSize`, `-Threads`, `-QueueDepth`, `-WriteRatioPercent`, `-DurationSeconds`, `-TestFileSizeMB` | Override individual settings on top of the preset. Required when `-Workload Custom`. |
| `-NoUI` | Run headless (console-only). |
| `-OutputPath` | Where the HTML report is written. Defaults to the script folder. |
| `-Force` | Skip the business-hours warning. |

## Safety guardrails

- **Preflight** runs before every test: verifies `diskspd.exe` is present and Microsoft-signed; checks the target path is reachable and writable; confirms enough free space; for remote runs, verifies WinRM and the admin share. The GUI surfaces errors as a blocking MessageBox and warnings as Continue/Cancel.
- **Cleanup** runs in `finally{}` blocks regardless of success/failure: the diskspd test data file is removed, stdout/stderr temp files are removed, and for remote runs the deposited `diskspd.exe` is removed too (only if this invocation copied it, so the SHA-256 cache survives between runs).
- **Business-hours warning** fires if you start a test Mon–Fri between 7am and 6pm local time. `-Force` skips it.

## Health thresholds

Reports color each metric against these bands. The same thresholds are documented inline in every saved report, in a `How to read these numbers` card.

| Metric | Transport | OK | WARN | CRIT |
|---|---|---|---|---|
| Read MB/s   | Local   | > 100 | 50–100 | < 50 |
| Read MB/s   | Network | > 50  | 25–50  | < 25 |
| Write MB/s  | Local   | > 100 | 50–100 | < 50 |
| Write MB/s  | Network | > 40  | 20–40  | < 20 |
| Latency     | Local   | < 10ms | 10–20ms | > 20ms |
| Latency     | Network | < 20ms | 20–50ms | > 50ms |

Latency thresholds apply to avg, P95, and P99. Source of truth: `..\CitrixVDADiagnostics\README.md`.

## Reports

After a successful run, click **Save Report** in the GUI to open a Save As dialog. The default filename matches the source file (e.g., `diskspd_C__Users_..._...html`). After save, the report opens in your default browser. The session remembers the last folder you saved to.

In headless mode, the report is written to `-OutputPath` (default: the script folder) and the path is returned by `Invoke-DiskSpdHeadless`.

Each report contains:

1. **Header** — target, workload, timestamp
2. **What this test measured** — plain-English workload description
3. **Results table** — IOPS, MB/s, latency percentiles, CPU %, with status badges
4. **Health Assessment** — quick badge summary
5. **How to read these numbers** — metric definitions + threshold table
6. **Raw diskspd XML output** — collapsed by default, contains the full diskspd response for deep dives

## Requirements

- Windows Server 2016+ / Windows 10+
- PowerShell 5.1
- Administrator (for performance counter access and remote PSSession)
- For remote mode: WinRM enabled on the VDA, admin share (`C$`) reachable
- `diskspd.exe` v2.2 is bundled (Microsoft GitHub release, MIT-licensed; signature verified Microsoft-signed at preflight)

## Tests

```powershell
# One-time setup if not present:
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser

# Fast unit-only sweep (no diskspd runs):
Invoke-Pester -Path .\Tests -ExcludeTag Integration

# Full suite including integration tests that actually run diskspd against $env:TEMP:
Invoke-Pester -Path .\Tests
```

Unit tests: 66 (parser, settings merge, threshold classification, preflight, etc.)
Integration tests: 7 (real diskspd subprocess + end-to-end orchestrator pipeline)
Total: 73, runtime ~50 seconds when integration tests are included.

Remote-mode (`Invoke-DiskSpdRemote`) has no automated tests — exercising it requires a real second machine. Manual smoke when first pointing at a new VDA target.

## Troubleshooting

**"diskspd.exe not found"** — the bundled binary is missing from this folder. Re-clone the repo or download the binary from https://github.com/microsoft/diskspd/releases/v2.2.

**"Insufficient free space"** — the workload's `TestFileSizeMB` × 1.2 doesn't fit on the target. Switch to QuickSanity (256 MB) or override `-TestFileSizeMB` to something smaller.

**"Test-WSMan failed" in remote mode** — the VDA's WinRM listener isn't reachable. From the machine running the tool, try `Test-WSMan -ComputerName <vda>`. If that fails, fix WinRM before retrying.

**"Target not writable"** — the operator's account doesn't have write permission on the target path. Required for the 1-byte preflight probe AND the actual diskspd test file.

**The GUI's "green progress bar just sat there"** — that was the pre-fix indeterminate animation. It's now a real progress bar that counts up to your test's expected duration plus ~6s of diskspd warmup overhead. If it stalls, check the PowerShell console for an error (WPF runspace failures often surface there rather than in the window).

**Reports landed in an unexpected folder** — the default `-OutputPath` is the script folder, but the GUI's Save Report button opens a Save As dialog so each report can land wherever you choose. The session remembers your last-used folder for subsequent saves.

## Files

- `Invoke-DiskSpdDiagnostic.ps1` — the script (WPF UI + engine + headless dispatch)
- `diskspd.exe` — bundled benchmark binary
- `diskspd-LICENSE.txt` — upstream EULA
- `ReportTemplate.html` — HTML report skeleton
- `Tests\DiskSpdDiagnostic.Tests.ps1` — Pester 5 test suite
- `Tests\sample-diskspd-output.xml` — fixture for the XML parser
