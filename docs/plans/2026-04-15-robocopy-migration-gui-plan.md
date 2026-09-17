# RobocopyMigration-GUI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a browser-based robocopy migration tool for server-to-server file migrations with job queue, presets, preview, and live log output.

**Architecture:** Single-file PowerShell script (forked from FolderPermissionManager-GUI.ps1 pattern) — HTTP listener + embedded HTML/CSS/JS. Three presets for common migration scenarios, collapsible advanced options, job queue with sequential/parallel execution, live log polling.

**Tech Stack:** PowerShell 5.1, System.Net.HttpListener, vanilla HTML/CSS/JS, robocopy.exe

---

### Task 1: Scaffold — HTTP listener, helpers, route dispatcher, empty HTML shell

**Files:**
- Create: `RobocopyMigration/RobocopyMigration-GUI.ps1`

Create the script skeleton with:
- Comment-based help block (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator`
- `[CmdletBinding()] param()` with `$Port = 8272` and `[switch]$NoBrowserOpen`
- Drive mapping cache (copy verbatim from FolderPermissionManager-GUI.ps1 lines 48-69)
- Helper functions: `Send-Json`, `Send-Html`, `Read-RequestBody`, `Resolve-MappedDrive` (copy from FolderPermissionManager-GUI.ps1 lines 74-122)
- Empty `Invoke-Route` function with just `GET /` → `Send-Html` and a default 404
- Minimal `$script:htmlContent` here-string: just a `<!DOCTYPE html>` page with the title "Robocopy Migration" and the CSS `:root` variables from FolderPermissionManager (lines 1033-1060)
- HTTP listener startup + main request loop (copy from FolderPermissionManager-GUI.ps1 lines 2208-2243, changing the port and tool name)

**Step 1: Create the file with the full scaffold**

Write `RobocopyMigration/RobocopyMigration-GUI.ps1` with all the above. The HTML body should just say `<h1>Robocopy Migration</h1>` for now.

**Step 2: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): scaffold HTTP listener and empty HTML shell"
```

---

### Task 2: Browse API — drive listing and folder tree

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1`

Add the folder browsing backend that the folder picker modal will use.

**Step 1: Add `Get-Drives` function**

Copy from FolderPermissionManager-GUI.ps1 lines 124-163. Returns array of drive objects with name, root, label, usedGB, freeGB, isMapped, uncPath.

**Step 2: Add `Get-Children` function**

Copy from FolderPermissionManager-GUI.ps1 lines 165-208. Takes `?path=` query param, returns child folders with name, fullName, hasChildren.

**Step 3: Wire routes in `Invoke-Route`**

Add to the switch:
```powershell
'^GET /api/drives$'     { Get-Drives $response }
'^GET /api/children$'   { Get-Children $request $response }
```

**Step 4: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add browse API for drives and folder tree"
```

---

### Task 3: Validate and Preview API endpoints

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1`

**Step 1: Add `Invoke-Validate` function**

POST endpoint. Reads JSON body with `source` and `destination` fields. Checks:
- Source exists (`Test-Path -PathType Container`)
- Destination parent is writable (try creating a temp file, delete it)
- Returns `{ valid: true/false, sourceExists: bool, destWritable: bool, error: string|null }`

**Step 2: Add `Invoke-Preview` function**

POST endpoint. Reads JSON body with `source`, `destination`, `preset` (full/dataonly/mirror), and optional overrides. Runs robocopy with `/L` flag to list what would be copied. Parse the summary output for dirs, files, bytes counts — same parsing pattern as `Get-RobocopyPreview` in FolderPermissionManager (lines 934-974) but accepting POST body instead of query params, and building the robocopy args based on preset.

Return:
```json
{
  "dirs": 42,
  "files": 1337,
  "bytes": 52428800,
  "sizeDisplay": "50 MB",
  "rawSummary": "..."
}
```

**Step 3: Wire routes**

```powershell
'^POST /api/validate$'  { Invoke-Validate $request $response }
'^POST /api/preview$'   { Invoke-Preview $request $response }
```

**Step 4: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add validate and preview API endpoints"
```

---

### Task 4: Job queue backend — add, list, cancel, remove, start

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1`

This is the core backend. Jobs are stored in a `$script:jobs` ordered dictionary keyed by GUID.

**Step 1: Add job state management**

At script scope, add:
```powershell
$script:jobs = [ordered]@{}
$script:jobLogBuffers = @{}
$script:jobProcesses = @{}
$script:jobStats = @{}
```

Each job object:
```powershell
@{
    id          = [guid]::NewGuid().ToString()
    source      = $source
    destination = $destination
    preset      = $preset        # 'full', 'dataonly', 'mirror'
    overrides   = $overrides     # hashtable of advanced options
    status      = 'pending'      # pending, running, complete, warning, failed, cancelled
    exitCode    = $null
    exitMeaning = $null
    createdAt   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    startedAt   = $null
    finishedAt  = $null
}
```

**Step 2: Add `Invoke-AddJob` function (POST /api/job/add)**

Reads JSON body, builds job object, adds to `$script:jobs`. Returns the job object.

**Step 3: Add `Get-JobList` function (GET /api/job/list)**

Returns `@($script:jobs.Values)` as JSON array.

**Step 4: Add `Invoke-CancelJob` function (POST /api/job/cancel/{id})**

Extract job ID from URL path. If job is running and process exists in `$script:jobProcesses`, kill it. Set status to `cancelled`.

**Step 5: Add `Remove-Job` function (DELETE /api/job/{id})**

Extract job ID from URL path. Remove from `$script:jobs`, `$script:jobLogBuffers`, `$script:jobProcesses`, `$script:jobStats`. Cannot remove a running job.

**Step 6: Add `Get-JobLog` function (GET /api/job/{id}/log)**

Returns the current log buffer and stats for a job:
```json
{
  "lines": ["line1", "line2", ...],
  "stats": { "filesCopied": 0, "filesSkipped": 0, "filesFailed": 0, "bytesCopied": 0, "elapsedSeconds": 0, "currentFile": "", "status": "running" },
  "fromIndex": 0
}
```
Accept `?from=N` query param so the frontend can request only new lines since last poll.

**Step 7: Add `Invoke-StartQueue` function (POST /api/job/start)**

Reads JSON body with `mode` field (`sequential` or `parallel`). This is the execution engine:

For **sequential mode**: iterate pending jobs in order. For each job:
1. Set status to `running`, record `startedAt`
2. Build robocopy argument list based on preset + overrides (use the flag mapping from the design doc)
3. Start robocopy as a `System.Diagnostics.Process` with `RedirectStandardOutput = $true`
4. Store process handle in `$script:jobProcesses[$id]`
5. Read stdout line-by-line in a loop, appending to `$script:jobLogBuffers[$id]` and parsing stats
6. On completion, set status based on exit code, record `finishedAt`
7. Process the main request loop between line reads so the UI stays responsive (call `$listener.GetContextAsync()` with short timeout)

For **parallel mode**: start all pending jobs simultaneously using the same process setup, but don't wait for each to finish before starting the next.

**Important:** The robocopy stat parsing regex patterns (applied to each stdout line):
- File copy line: matches `New File` or `Newer` or similar robocopy status tags → increment filesCopied
- Bytes: parse the size field from the file line → accumulate bytesCopied
- Skip line: matches `same` or `skip` → increment filesSkipped
- Error line: matches `ERROR` → increment filesFailed
- Current file: capture the filename from the most recent line

**Step 8: Wire all routes**

```powershell
'^POST /api/job/add$'         { Invoke-AddJob $request $response }
'^GET /api/job/list$'         { Get-JobList $response }
'^POST /api/job/start$'       { Invoke-StartQueue $request $response }
'^POST /api/job/cancel/(.+)$' { Invoke-CancelJob $request $response $Matches[1] }
'^DELETE /api/job/(.+)$'      { Remove-Job $request $response $Matches[1] }
'^GET /api/job/(.+)/log$'     { Get-JobLog $request $response $Matches[1] }
```

Note: The regex route dispatcher needs to capture the job ID from the URL. Update `Invoke-Route` so the switch block captures `$Matches` and passes it to the handlers.

**Step 9: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add job queue backend with start, cancel, log polling"
```

---

### Task 5: Frontend — HTML structure, CSS, and layout

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1` (the `$script:htmlContent` here-string)

Replace the placeholder HTML with the full frontend. This task covers structure and styling only — no JavaScript behavior yet.

**Step 1: Write the HTML structure**

Inside `$script:htmlContent`, build:

```html
<!-- Header bar -->
<div class="topbar">
  <h1>Robocopy Migration</h1>
  <div class="topbar-actions">
    <button id="themeToggle" class="btn-icon" title="Toggle theme">Theme</button>
  </div>
</div>

<!-- Job Builder panel -->
<div class="builder-panel">
  <div class="builder-row">
    <label>Source</label>
    <input type="text" id="sourcePath" placeholder="\\\\Server\\Share or C:\\Folder" />
    <button id="sourceBtn" class="btn-secondary">Browse</button>
  </div>
  <div class="builder-row">
    <label>Destination</label>
    <input type="text" id="destPath" placeholder="\\\\Server\\Share or C:\\Folder" />
    <button id="destBtn" class="btn-secondary">Browse</button>
  </div>
  <div class="builder-row">
    <label>Preset</label>
    <select id="presetSelect">
      <option value="full">Full Migration (timestamps + permissions + attributes)</option>
      <option value="dataonly">Data Only (no permissions)</option>
      <option value="mirror">Mirror (exact copy — deletes extras at destination)</option>
    </select>
    <span id="mirrorWarning" class="warning-badge" style="display:none;">Destructive</span>
  </div>

  <!-- Advanced section (collapsed) -->
  <details id="advancedSection">
    <summary>Advanced Options</summary>
    <div class="advanced-grid">
      <label>Retries</label><input type="number" id="retries" value="3" min="0" max="99" />
      <label>Wait (seconds)</label><input type="number" id="waitTime" value="5" min="0" max="300" />
      <label>Bandwidth throttle (ms)</label><input type="number" id="ipg" value="0" min="0" placeholder="0 = no limit" />
      <label>Multi-threaded</label>
      <div><input type="checkbox" id="mtEnabled" /><input type="number" id="mtCount" value="8" min="1" max="128" disabled /></div>
      <label>Exclude files</label><input type="text" id="excludeFiles" placeholder="*.tmp *.log" />
      <label>Exclude folders</label><input type="text" id="excludeDirs" placeholder="Temp .git" />
      <label>Log file path</label><input type="text" id="logFilePath" placeholder="Optional — e.g. C:\\Logs\\migration.log" />
    </div>
  </details>

  <!-- Action buttons -->
  <div class="builder-actions">
    <button id="previewBtn" class="btn-secondary">Preview</button>
    <button id="addJobBtn" class="btn-primary">Add to Queue</button>
  </div>
</div>

<!-- Preview results (hidden until triggered) -->
<div id="previewResults" class="preview-panel" style="display:none;">
  <h3>Preview Results</h3>
  <div id="previewContent"></div>
</div>

<!-- Job Queue panel -->
<div class="queue-panel">
  <div class="queue-header">
    <h2>Job Queue</h2>
    <div class="queue-controls">
      <select id="execMode">
        <option value="sequential">Run sequentially</option>
        <option value="parallel">Run in parallel</option>
      </select>
      <button id="runQueueBtn" class="btn-primary" disabled>Run Queue</button>
      <button id="clearDoneBtn" class="btn-secondary">Clear Completed</button>
    </div>
  </div>
  <div id="parallelWarning" class="warning-banner" style="display:none;">
    Parallel mode runs all jobs simultaneously — this may saturate network bandwidth.
  </div>
  <table class="queue-table">
    <thead>
      <tr><th>#</th><th>Source</th><th>Destination</th><th>Preset</th><th>Status</th><th>Actions</th></tr>
    </thead>
    <tbody id="queueBody"></tbody>
  </table>
</div>

<!-- Folder picker modal -->
<div id="folderModal" class="modal" style="display:none;">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Select Folder</h3>
      <button class="btn-icon modal-close">&times;</button>
    </div>
    <div class="modal-body">
      <div id="folderTree" class="tree-container"></div>
    </div>
    <div class="modal-footer">
      <span id="selectedPath" class="selected-path">No folder selected</span>
      <button id="folderSelectBtn" class="btn-primary" disabled>Select</button>
    </div>
  </div>
</div>
```

**Step 2: Write the CSS**

Use the FolderPermissionManager CSS variables (`:root` dark/light themes) as the base. Add new styles specific to this tool:

- `.builder-panel` — card-style panel with padding, background `var(--bg-card)`, border
- `.builder-row` — flex row with label (fixed width), input (flex grow), button
- `.builder-actions` — flex row, right-aligned, gap between buttons
- `.advanced-grid` — 2-column CSS grid for the advanced options
- `.preview-panel` — collapsible results card
- `.queue-panel` — card for the job queue section
- `.queue-table` — full-width table, striped rows, monospace for paths
- `.queue-header` — flex row with title left, controls right
- `.warning-badge` — small red pill badge for "Destructive" on mirror preset
- `.warning-banner` — yellow background banner for parallel mode warning
- `.modal` — full-screen overlay with centered white card
- `.btn-primary`, `.btn-secondary`, `.btn-icon` — button styles matching FolderPermissionManager
- `.job-log` — monospace scrollable panel for inline log expansion under a job row
- `.stats-bar` — flex row of stat chips (files copied, skipped, failed, size, elapsed)
- Status badges: `.status-pending` (gray), `.status-running` (blue pulse), `.status-complete` (green), `.status-warning` (yellow), `.status-failed` (red), `.status-cancelled` (gray strikethrough)

**Step 3: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add frontend HTML structure and CSS"
```

---

### Task 6: Frontend — JavaScript: folder picker, presets, form behavior

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1` (the `<script>` section in `$script:htmlContent`)

**Step 1: Theme toggle**

Same pattern as FolderPermissionManager — toggle `body.light` class, persist to `localStorage`.

**Step 2: Folder picker modal**

Wire Browse buttons to open the modal. On open:
1. Fetch `GET /api/drives` → render drive list as tree roots
2. Clicking a drive/folder fetches `GET /api/children?path=...` → renders child nodes
3. Clicking a folder selects it, shows full path in `#selectedPath`
4. "Select" button closes modal and populates the source or destination input

Track which input (source/dest) triggered the modal via a variable.

**Step 3: Preset selector behavior**

- When "mirror" is selected, show the `#mirrorWarning` badge
- Hide it for other presets

**Step 4: Advanced section behavior**

- Multi-threaded checkbox enables/disables the thread count input
- Parallel execution mode shows/hides the `#parallelWarning` banner

**Step 5: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add folder picker, preset, and form JS behavior"
```

---

### Task 7: Frontend — JavaScript: preview, add job, queue management

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1` (the `<script>` section)

**Step 1: Preview button**

Click handler:
1. Validate source and dest are filled
2. `POST /api/preview` with `{ source, destination, preset, overrides }`
3. Show `#previewResults` panel with: file count, folder count, total size, raw summary in a collapsible `<details>`

**Step 2: Add to Queue button**

Click handler:
1. Validate source and dest
2. Collect preset and advanced overrides into an object
3. `POST /api/job/add` with the job spec
4. On success, refresh the queue table
5. Clear the form (or don't — user may want to add similar jobs)
6. Enable the "Run Queue" button if there are pending jobs

**Step 3: Queue table rendering**

Write a `renderQueue()` function:
1. `GET /api/job/list` → render rows in `#queueBody`
2. Each row shows: index, source (truncated with tooltip), destination (truncated), preset label, status badge, action buttons
3. Action buttons: "Cancel" (for running jobs), "Remove" (for pending/completed/failed)
4. Clicking a row toggles the inline log panel below it

**Step 4: Run Queue button**

Click handler:
1. Read `#execMode` value
2. `POST /api/job/start` with `{ mode: 'sequential'|'parallel' }`
3. Start polling the queue every 1 second via `setInterval` calling `renderQueue()`
4. Stop polling when no jobs are `running`

**Step 5: Clear Completed button**

Delete all jobs with status `complete`, `warning`, `failed`, or `cancelled` via `DELETE /api/job/{id}` for each.

**Step 6: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add preview, job queue, and queue execution JS"
```

---

### Task 8: Frontend — JavaScript: live log panel and stats

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1` (the `<script>` section)

**Step 1: Log panel expansion**

When a job row is clicked:
1. Toggle a `<tr class="job-log-row">` below the clicked row
2. Inside it: a `.stats-bar` div and a `.job-log` pre/code block
3. Start polling `GET /api/job/{id}/log?from=N` every 1 second
4. Append new log lines to the code block
5. Update the stats bar: `142 copied · 3 skipped · 1 failed · 50 MB · 0:34 elapsed`
6. Auto-scroll to bottom unless user has scrolled up (track with a `userScrolled` flag set on `scroll` event)

**Step 2: Stop polling when job finishes**

When `status` is no longer `running`, stop the per-job log interval and show the final stats + exit code meaning.

**Step 3: Format helpers**

- `formatBytes(n)` — returns human-readable size (KB/MB/GB)
- `formatDuration(seconds)` — returns `M:SS` or `H:MM:SS`
- `truncatePath(path, maxLen)` — shortens long UNC paths with `...` in the middle

**Step 4: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): add live log panel with stats and auto-scroll"
```

---

### Task 9: Backend refinement — async job execution

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1`

The initial `Invoke-StartQueue` from Task 4 runs robocopy synchronously which blocks the HTTP listener. This task fixes that by running robocopy in background jobs/runspaces so the server stays responsive.

**Step 1: Refactor job execution to use `System.Diagnostics.Process` with async output**

Instead of blocking on `WaitForExit()`, use:
```powershell
$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo.FileName = 'robocopy.exe'
$proc.StartInfo.Arguments = $argString
$proc.StartInfo.UseShellExecute = $false
$proc.StartInfo.RedirectStandardOutput = $true
$proc.StartInfo.RedirectStandardError = $true
$proc.StartInfo.CreateNoWindow = $true
$proc.EnableRaisingEvents = $true

# Register async output handler
$proc.add_OutputDataReceived({
    param($sender, $e)
    if ($e.Data) {
        $jobId = $sender.StartInfo.Environment['JOB_ID']
        $script:jobLogBuffers[$jobId].Add($e.Data)
        # Parse stats from line
    }
})

$proc.Start()
$proc.BeginOutputReadLine()
```

Store the process in `$script:jobProcesses[$id]`.

**Step 2: Update the main request loop to check for completed processes**

In the `while ($script:running)` loop, after handling each request, check all running job processes:
```powershell
foreach ($id in @($script:jobProcesses.Keys)) {
    $proc = $script:jobProcesses[$id]
    if ($proc.HasExited) {
        # Finalize job: set status based on exit code, record finishedAt
        # Start next pending job if in sequential mode
    }
}
```

**Step 3: Sequential mode — start next job when current finishes**

Add a `$script:queueMode` variable. When a job finishes and mode is `sequential`, find the next `pending` job and start it.

**Step 4: Commit**

```bash
git add RobocopyMigration/RobocopyMigration-GUI.ps1
git commit -m "feat(robocopy-migration): async job execution with non-blocking HTTP server"
```

---

### Task 10: Polish, edge cases, and README

**Files:**
- Modify: `RobocopyMigration/RobocopyMigration-GUI.ps1`
- Create: `RobocopyMigration/README.md`

**Step 1: Edge case handling**

- UNC path validation — accept `\\server\share` format, handle backslash escaping in JSON
- Empty queue — disable "Run Queue" when no pending jobs
- Already running — disable "Run Queue" while jobs are executing
- Mirror preset confirmation — show a confirm dialog before adding a mirror job to queue
- Long paths — handle paths > 260 chars by adding `\\?\` prefix to robocopy args
- Destination creation — robocopy creates the destination automatically, but validate the parent path is reachable

**Step 2: Console logging**

Add Write-Host status messages to the PowerShell console matching the repo logging pattern:
- `[INFO]` (Cyan) — server start, job added, job started
- `[PASS]` (Green) — job completed successfully
- `[WARN]` (Yellow) — job completed with warnings
- `[FAIL]` (Red) — job failed

**Step 3: Write README.md**

Follow the repo's README pattern. Include:
- What it does (one paragraph)
- Prerequisites (PowerShell 5.1, admin rights, robocopy)
- Usage examples
- Screenshot placeholder
- Preset descriptions
- Advanced options reference

**Step 4: Commit**

```bash
git add RobocopyMigration/
git commit -m "feat(robocopy-migration): polish edge cases, console logging, and README"
```

---

### Task 11: Manual QA — launch and test

**Step 1: Launch the tool**

```powershell
.\RobocopyMigration\RobocopyMigration-GUI.ps1
```

Verify browser opens to `http://localhost:8272/`.

**Step 2: Test folder picker**

Click Browse on source and destination. Navigate drives and folders. Verify UNC paths work if a network share is available.

**Step 3: Test preview**

Set source to a small test folder, destination to a temp location. Click Preview. Verify file count and size display.

**Step 4: Test job queue**

Add 2-3 jobs with different presets. Verify they appear in the queue table with correct info.

**Step 5: Test execution**

Run the queue in sequential mode. Verify:
- Jobs transition through pending → running → complete
- Live log shows robocopy output
- Stats bar updates
- Exit code is interpreted correctly

**Step 6: Test cancel**

Start a large copy job, then cancel it. Verify the process is killed and status shows cancelled.

**Step 7: Test mirror warning**

Select the Mirror preset. Verify the destructive warning badge appears.

**Step 8: Test parallel mode**

Add 2 jobs, switch to parallel, run. Verify both start simultaneously.

**Step 9: Fix any issues found during QA**

Commit fixes as needed.
