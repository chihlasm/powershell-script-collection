# Robocopy Migration GUI: Native WPF Rewrite (Design)

**Date:** 2026-10-09
**Status:** Approved, implementation authorized
**Folder:** `RobocopyMigration/`

## 1. The problem

The current `RobocopyMigration-GUI.ps1` is a PowerShell `HttpListener` server with an HTML front end.
In the field it is slow, freezes, and is awkward to start and stop. The causes are in the backend:

- A single thread serves HTTP **and** monitors jobs. Any slow request stalls everything.
- Preview runs a synchronous `robocopy /L`, which blocks the server for minutes on large shares.
- The folder browser enumerates every child folder a second time to compute "has children".
- `/V` output goes into an unbounded in-memory list. Every line is regex-matched in PowerShell, and the
  browser re-renders the entire log every second.
- Closing the console kills every running robocopy.

## 2. Goals

- A native WPF window: launch it, close it. No port, no browser, no Ctrl+C.
- It stays responsive during multi-hour, million-file migrations.
- **Running copies survive the window closing.** Reopening the tool reattaches to them.
- Queued jobs that have not started wait until the GUI is reopened. There is no hidden runner.
- It replaces the web version in place (same file name). Git history keeps the old one.
- All existing features stay: 4 presets, advanced options, preview, queue (one at a time / all at
  once), stop, mapped-drive resolution, dark/light theme, default `Logs\` folder.
- New features:
  - % progress bar and time left (from the preview totals)
  - Open log / Open destination buttons
  - Plain-English finished-job summary with the robocopy summary table and the failed-files list
  - "Run again as Incremental"
  - "Add & Start"

## 3. Constraints

- A single self-contained `.ps1` file. PowerShell 5.1. No shipped DLLs. `Add-Type` C# is allowed.
- The file is pure ASCII (5.1 misreads non-ASCII scripts), so icons in the XAML are entity-encoded.
- Elevation is checked at runtime, not with `#Requires -RunAsAdministrator`. That way Pester can
  dot-source the script with `-LoadFunctionsOnly` without elevation.

## 4. Layout: "B, queue first"

- **Title bar:** `+ New Job`, the queue mode toggle, and the theme toggle.
- **Left:** the queue as cards (status pill, % bar), plus "Clear finished".
- **Right:** detail for the selected job.
  - **While running:** paths, % bar, stats (files copied, size done of total, failed, time left), the
    last 500 log lines, and Open log / Open destination / Stop.
  - **When finished:** the verdict banner, the summary table (Dirs/Files/Bytes x
    Total/Copied/Skipped/Mismatch/Failed/Extras), the failed files, and Open log / Open destination /
    Run again as Incremental.
- **New Job:** a slide-in panel with plain-English labels, advanced options collapsed, a cancellable
  preview, and Add to Queue / Add & Start.
- **Browse:** a WPF tree dialog that loads folders lazily on a background thread. It lists local
  drives, mapped drives and recently used UNC roots.

## 5. Components (regions of the one script)

| Unit | Responsibility |
|---|---|
| `RoboLogTailer` (C#) | Incrementally reads a UTF-16 `/UNILOG` file from a byte offset. Keeps running counters, a 500-line ring buffer, failed files (max 1000), and the parsed summary table. |
| `Build-RobocopyArgs` | preset + options -> argument list. Pure. |
| `Get-RoboExitInfo` | exit code (+ summary) -> status and plain-English verdict. Pure. |
| Job store | Loads/saves `State\jobs.json`. Writes to a temp file, then renames. A corrupt file is moved to `.bad`. |
| Job runner | **Start:** per-job `.cmd` wrapper (robocopy, then exit code to `<id>.exit`), launched hidden and detached; records PID + process start time. **Stop:** `taskkill /T /F`. **Reattach.** **Finish.** |
| Background workers | A `RunspacePool` (max 3) for preview and folder listing. Returns plain data only. |
| UI | XAML, theme brush dictionaries, and one 500 ms `DispatcherTimer` that does all polling. |

## 6. Job lifecycle

`Waiting -> Running -> Done | Warnings | Problems | Failed`, plus `Stopped` and `Interrupted`.

| Status | Exit code | Meaning |
|---|---|---|
| Done | 0-3 | Copy finished successfully |
| Warnings | 4-7 | Mismatched files |
| Problems | 8-15 | "Finished with problems": some files failed after all retries |
| Failed | >= 16 | Robocopy could not run the copy |
| Stopped | - | Stop button |
| Interrupted | - | Process gone and no exit file (for example, a reboot) |

- **Wrapper:** each job runs as a hidden, detached `powershell.exe -EncodedCommand`. It runs
  robocopy and writes `$LASTEXITCODE` to `<id>.exit`. EncodedCommand is UTF-16, so Unicode paths
  survive, unlike a `.cmd` file read in the OEM code page. Stop kills the wrapper tree.

- **Reattach on open:**
  - PID alive and start time matches -> Running (shown as "Reattached")
  - exit file present -> finish the job
  - otherwise -> Interrupted
- **Closing with jobs running:** prompt Keep running / Stop all / Cancel.
- **Single instance:** a named mutex. A second launch shows a message and exits.
- **One-at-a-time mode:** the timer starts the next Waiting job when none are running. The queue
  continues after a job fails.

## 7. Verified facts (see the script's REFERENCES)

- Exit codes per Microsoft Learn:
  - 0, 1, 2, 3, 5, 6, 7 are documented as combinations of copied (1), extras (2) and mismatched (4)
  - >= 8 means at least one failure
  - 16 is not documented on Learn. Observed locally: a missing source directory returns 16 and writes no
    summary table.
- `/MT` cannot be used with `/IPG` (Learn). The current tool allowed both. Now the UI and the
  argument builder enforce it, with a regression test.
- `/UNILOG` writes UTF-16LE with a BOM (observed).
- With `/V`, file lines are written **before** the copy attempt, and each retry re-logs the line.
  `ERROR: RETRY LIMIT EXCEEDED.` marks the final failure, so live counters reverse the pending file.
- The `modified` class is skipped by default (Learn remarks: "These files aren't copied by default").
- Progress = (copied + skipped bytes) / preview total bytes. The summary shows
  Total = Copied + Skipped + Failed bytes.

## 8. Error handling

- Source or destination unreachable -> that job fails with a reason; the queue continues.
- Log locked or not created yet -> retry on the next tick.
- Corrupt `jobs.json` -> `.bad` plus a warning banner.
- Preview failure -> message in the panel; the job can still be added without a %.
- Any exception during a tick -> caught per job, logged to `State\gui-errors.log`, shown as a warning.
- C# compile or WPF load failure -> a message box, then exit.

## 9. Testing

- **Pester 5 (`Tests\RobocopyMigration-GUI.Tests.ps1`):**
  - ASCII-only file and clean parse
  - Build-RobocopyArgs (each preset, the options, `/MT` with `/IPG`, quoting)
  - the exit-code translator
  - the tailer (split appends, a split UTF-16 code unit, the ring cap, retry reversal, summary parsing,
    no-summary)
  - job store round-trip and corruption handling
  - reattach decision table
- **End-to-end:** a real job on temp folders through the runner; stopping a job kills robocopy too.
- **Manual checklist in the README:** themes, Browse on UNC and mapped drives, close + reattach, a
  100k-file run.
