# Robocopy Migration GUI

A Windows desktop tool for server-to-server file migrations using robocopy. You plan jobs, preview how much will be copied, run them one at a time or all at once, and watch progress live. When each job finishes, you get a plain-English summary of the result.

Each copy runs as its own background process. **Closing the window doesn't stop copies that are already running.** Reopen the tool and it picks them up again.

## Prerequisites

- Windows Server 2012 R2+ or Windows 10+
- Windows PowerShell 5.1 (PowerShell 7 also works)
- Administrator rights, needed to copy NTFS permissions and owners and for backup mode. If you start the tool without them, it asks for elevation through a UAC prompt.
- Robocopy (included with Windows)

Nothing to install. It's a single `.ps1` file.

## Usage

```powershell
.\RobocopyMigration-GUI.ps1
```

You can also right-click the file and choose **Run with PowerShell**. The tool asks for elevation, opens its window and hides its own console. Close the window to exit.

1. Click **+ New Job** (or press Ctrl+N).
2. Pick **Copy from** and **Copy to**. **Browse** loads folders in the background, so a slow server won't freeze the window.
3. Choose a **Type of copy** (see below). Open **Advanced options** if you need them.
4. Click **Preview** (optional, but recommended). It counts files and size without copying, which gives the job a % bar and a time-left estimate.
5. Click **Add & Start**, or **Add to Queue** to start it later with **Start queue**.

## Types of copy

| Type | What it copies | Robocopy flags | Use when |
|------|----------------|----------------|----------|
| **Full Migration** | Files, folders, timestamps, NTFS permissions, owners | `/E /COPY:DATSO /DCOPY:DAT` | Moving a share to a new server and you need an exact replica |
| **Incremental** | Only new or updated files, with permissions | `/E /COPY:DATSO /DCOPY:DAT /XO /XX` | A second pass after a full copy, or topping up overnight changes |
| **Data Only** | Files, folders, timestamps | `/E /COPY:DAT /DCOPY:DAT` | The destination has its own permission setup |
| **Mirror** | Everything, and **deletes** destination files that aren't in the source | `/MIR /COPY:DATSO /DCOPY:DAT` | Keeping the destination in sync. You're asked to confirm. |

Every job also uses `/V /BYTES /NP /NDL /UNILOG:<log>` plus the retry settings.

## Advanced options

| Option | Default | Notes |
|--------|---------|-------|
| Retries per file | 3 | `/R` |
| Wait between retries | 5 sec | `/W` |
| Copy several files at once | Off (8 threads when on) | `/MT`. Much faster for many small files. |
| Slow down | 0 ms | `/IPG`. Robocopy doesn't allow this together with `/MT`, so it's turned off while threads are on. |
| Files this account can't open | Skip them | **Retry in backup mode** = `/ZB`, **Always backup mode** = `/B` |
| Skip files matching / folders named | - | `/XF` / `/XD`, space-separated |
| Save log to | `Logs\` next to the script | A folder, or a full path ending in `.log` |

## Queue

- **One at a time** starts the next waiting job when the current one finishes. **All at once** starts every waiting job together.
- Waiting jobs don't start until you click **Start queue** (or **Add & Start**). When you reopen the tool, the queue is paused.
- A failed job doesn't block the queue, because robocopy failures are usually per file.

## When a job finishes

The job is marked with one of these, based on robocopy's exit code:

| Status | Exit code | Meaning |
|--------|-----------|---------|
| Done | 0-3 | Copied successfully (or nothing needed copying) |
| Check | 4-7 | Mismatched files or folders. See the log. |
| Finished with problems | 8-15 | Some files failed after all retries (usually "access denied" or a file in use) |
| Failed | 16+ | Robocopy couldn't run the copy (usually the source or destination couldn't be reached) |
| Stopped | - | You clicked Stop |
| Interrupted | - | The copy process ended without reporting a result (for example, the server rebooted) |

The detail pane shows robocopy's summary table, the files that couldn't be copied, and the options **Open log**, **Open destination** and **Run again as Incremental**. Incremental skips everything already copied, so it's the fast way to retry failures or finish a stopped job.

## Files the tool creates

```
RobocopyMigration\
  RobocopyMigration-GUI.ps1
  Logs\    robocopy logs (UTF-16, open with Notepad)
  State\   jobs.json, per-job exit-code files, settings.json, gui-errors.log
```

Delete `State\` to start with an empty job list. The logs are never deleted automatically.

## Tests

```powershell
Invoke-Pester .\Tests
```

The tests need Pester 5 or later. They don't need admin rights. They cover the robocopy arguments, the exit-code meanings, log parsing, the job file, reattach logic, and real end-to-end runs. Those end-to-end runs include stopping a copy and a copy that keeps going after the process that started it exits.

### Manual checks before release

- Dark/light toggle. Browse on a UNC path and on a mapped drive.
- Close the window while a copy is running, choose **Yes** (keep running), then reopen. The job should show **Reattached** and keep updating.
- Run a copy with 100k+ files. The window should stay responsive and memory should stay flat.
