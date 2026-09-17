# MSP Troubleshooting Workbench Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the correctness bugs and close the UI gaps that keep the MSP Troubleshooting Workbench from being usable end-to-end: run any check from the browser with its real inputs, see results/evidence/notes in a case workspace, copy generated ticket notes, and harden timeouts + localhost API security.

**Architecture:** The workbench is a single PowerShell 5.1 HTTP server (`Start-MSPTroubleshootingWorkbench.ps1`, `System.Net.HttpListener`) serving one static page (`app/index.html`, vanilla JS) and a JSON API. Checks are standalone `.ps1` scripts declared in `checks/manifest.json`, executed via `Start-Job`. All changes stay inside this architecture — no frameworks, no external dependencies.

**Tech Stack:** PowerShell 5.1 (Windows built-ins only), vanilla HTML/CSS/JS, plain-PowerShell test scripts (repo has no Pester dependency — tests use the existing `Assert-True` pattern in `MSP-TroubleshootingWorkbench/tests/`).

## Global Constraints

- `#Requires -Version 5.1` — everything must run on Windows PowerShell 5.1 (no PS7-only syntax: no `??`, no ternary, no `ForEach-Object -Parallel`).
- No external dependencies (no Pester requirement, no npm, no CDN scripts). UI must stay a single self-contained `index.html`.
- Follow repo conventions in `CLAUDE.md`: comment-based help on scripts, `[CmdletBinding()]`, dual console/file logging with `[PASS]/[WARN]/[FAIL]/[INFO]` prefixes, timestamps `yyyy-MM-dd HH:mm:ss`.
- UI copy is plain English for a mixed helpdesk/sysadmin audience ("User" not "SamAccountName", "Days back" not "DaysBack"). Dark default with the existing `#5dade2` accent; keep existing CSS variables.
- Commit prefix convention: `feat:`, `fix:`, `docs:`, `test:`. End commit messages with `Co-Authored-By:` line per repo convention.
- The server is single-threaded; do not introduce runspace pools or background request handling in this plan (out of scope — noted in Future Work).
- All paths below are relative to the repo root `powershell-script-collection/`.

## Context for the implementer (read first)

- The server script defines ~40 functions at the top, then falls into a blocking `while` loop around `$listener.GetContext()` (line ~1098). `$OutputPath` is a script-scope variable that functions like `Get-CasePath` read directly.
- A check result is a `PSCustomObject` with fields: `CheckId, Name, Category, Status (Pass|Warn|Fail), Summary, Evidence (array of {Name,Status,Detail}), RecommendedNextSteps (string[]), RawOutput, StartedAt, FinishedAt, Error`.
- Cases are JSON files `cases/CASE-yyyyMMdd-HHmmss.json` with fields `CaseId, ClientName, TicketNumber, IssueType, AffectedUser, AffectedDevice, TargetPath, TargetAddress, CreatedAt, UpdatedAt, Checks[], Notes[], GeneratedSummary`.
- Existing tests (`tests/Task*.Tests.ps1`) are plain scripts with a local `Assert-True` helper that throw on failure. New tests follow the same pattern. Run any test with `powershell -NoProfile -File <path>`.

---

### Task 1: Library mode so tests can load server functions

The server script currently starts the HTTP listener on load, so nothing in it can be unit-tested. Add a `-LibraryMode` switch that defines all functions and resolves `$OutputPath`, then returns before touching the listener. This unblocks every behavioral test in later tasks.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1` (param block ~line 27, and the top of the runtime section ~line 1049)
- Test: `MSP-TroubleshootingWorkbench/tests/Workbench.LibraryMode.Tests.ps1` (create)

**Interfaces:**
- Produces: dot-sourcing `. $serverPath -LibraryMode -OutputPath <dir>` loads all server functions into the caller's scope with `$OutputPath` resolved, and does NOT start a listener. All later test files rely on exactly this invocation.

- [ ] **Step 1: Write the failing test**

Create `MSP-TroubleshootingWorkbench/tests/Workbench.LibraryMode.Tests.ps1`:

```powershell
#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-libmode-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    # Dot-source in library mode: must define functions and must NOT block or listen.
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    Assert-True -Condition ($null -ne (Get-Command Test-WorkbenchCaseId -ErrorAction SilentlyContinue)) -Message "Test-WorkbenchCaseId is defined after library-mode load."
    Assert-True -Condition ($null -ne (Get-Command New-TicketNotesMarkdown -ErrorAction SilentlyContinue)) -Message "New-TicketNotesMarkdown is defined after library-mode load."
    Assert-True -Condition ($null -ne (Get-Command Invoke-WorkbenchCheck -ErrorAction SilentlyContinue)) -Message "Invoke-WorkbenchCheck is defined after library-mode load."
    Assert-True -Condition ($OutputPath -eq $tempRoot) -Message "OutputPath resolves to the requested folder in library mode."
    Assert-True -Condition (Test-WorkbenchCaseId -CaseId "CASE-20260101-120000") -Message "Case id validation accepts a well-formed id."
    Assert-True -Condition (-not (Test-WorkbenchCaseId -CaseId "..\evil")) -Message "Case id validation rejects traversal input."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Library mode tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Library mode tests completed." -ForegroundColor Green
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.LibraryMode.Tests.ps1"`
Expected: FAIL — the script either errors on the unknown `-LibraryMode` parameter, or (worse) starts the listener and blocks. Ctrl+C if it blocks.

- [ ] **Step 3: Add the LibraryMode switch**

In `Start-MSPTroubleshootingWorkbench.ps1`, add to the `param()` block after `[switch]$NoBrowserOpen`:

```powershell
    [switch]$NoBrowserOpen,

    [switch]$LibraryMode
```

Then find the runtime section that begins:

```powershell
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$OutputPath = $resolvedOutputPath
```

Immediately AFTER those two lines (so `$OutputPath` is resolved for library consumers, but before `$appPath`/listener setup), insert:

```powershell
if ($LibraryMode) {
    return
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.LibraryMode.Tests.ps1"`
Expected: all `[PASS]`, exits promptly (no listener).

- [ ] **Step 5: Verify the server still starts normally**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1" -Port 8299 -NoBrowserOpen` in one terminal; in another run `powershell -NoProfile -Command "(Invoke-WebRequest -UseBasicParsing http://localhost:8299/api/status).StatusCode"`.
Expected: `200`. Stop the server with Ctrl+C (note: current code may need one extra request to unblock — fixed in Task 7).

- [ ] **Step 6: Commit**

```bash
git add MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1 MSP-TroubleshootingWorkbench/tests/Workbench.LibraryMode.Tests.ps1
git commit -m "test: add LibraryMode switch so workbench functions are testable"
```

---

### Task 2: Per-check timeouts from the manifest

Bug: `Invoke-WorkbenchCheck` defaults to a 60-second job timeout, but the AD Lockout wrapper gives its child diagnostics process 120 seconds — the server kills real AD runs before they can finish. Move timeout ownership to the manifest.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/checks/manifest.json`
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1` (`Get-CheckCatalog` ~line 406, `Invoke-WorkbenchCheck` ~line 706)
- Test: `MSP-TroubleshootingWorkbench/tests/Workbench.CheckTimeout.Tests.ps1` (create)

**Interfaces:**
- Consumes: `-LibraryMode` loading from Task 1.
- Produces: catalog entries gain an `int` property `TimeoutSeconds` (default 60, validated 1–3600). `Invoke-WorkbenchCheck -TimeoutSeconds` becomes optional: `0` (new default) means "use the check's manifest value". `GET /api/checks` includes `TimeoutSeconds` in its `Select-Object`. Task 5's UI reads nothing new; Task 8's README documents the field.

- [ ] **Step 1: Write the failing test**

Create `MSP-TroubleshootingWorkbench/tests/Workbench.CheckTimeout.Tests.ps1`:

```powershell
#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-timeout-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    $catalog = @(Get-CheckCatalog)
    Assert-True -Condition ($catalog.Count -ge 3) -Message "Catalog loads at least three checks."

    foreach ($check in $catalog) {
        Assert-True -Condition ($check.PSObject.Properties.Name -contains "TimeoutSeconds") -Message ("Check '{0}' exposes TimeoutSeconds." -f $check.CheckId)
        Assert-True -Condition ($check.TimeoutSeconds -ge 1 -and $check.TimeoutSeconds -le 3600) -Message ("Check '{0}' TimeoutSeconds is within 1-3600." -f $check.CheckId)
    }

    $adCheck = @($catalog | Where-Object { $_.CheckId -eq "ad.lockout" })[0]
    Assert-True -Condition ($adCheck.TimeoutSeconds -gt 120) -Message "ad.lockout timeout exceeds its 120s child-process timeout."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Check timeout tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Check timeout tests completed." -ForegroundColor Green
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.CheckTimeout.Tests.ps1"`
Expected: FAIL — "exposes TimeoutSeconds" assertions fail.

- [ ] **Step 3: Add timeoutSeconds to the manifest**

In `MSP-TroubleshootingWorkbench/checks/manifest.json`, add a `timeoutSeconds` field to each check (after `readOnly`):

- `network.quick`: `"timeoutSeconds": 60,`
- `ad.lockout`: `"timeoutSeconds": 240,` (child process gets 120s; wrapper needs headroom for module import + report write)
- `citrix.fslogix.triage`: `"timeoutSeconds": 180,`

- [ ] **Step 4: Parse and validate in Get-CheckCatalog**

In `Get-CheckCatalog`, inside the `foreach ($check in @($manifest.checks))` loop, after the script-path validation and before `$catalog +=`, add:

```powershell
        $timeoutSeconds = 60
        if ($check.PSObject.Properties.Name -contains "timeoutSeconds" -and $null -ne $check.timeoutSeconds) {
            $timeoutSeconds = 0
            if (-not [int]::TryParse([string]$check.timeoutSeconds, [ref]$timeoutSeconds)) {
                throw "Check manifest entry 'timeoutSeconds' must be a number."
            }

            if ($timeoutSeconds -lt 1 -or $timeoutSeconds -gt 3600) {
                throw "Check manifest entry 'timeoutSeconds' must be between 1 and 3600."
            }
        }
```

And add to the `[PSCustomObject]` emitted into `$catalog`:

```powershell
            TimeoutSeconds = $timeoutSeconds
```

- [ ] **Step 5: Use the manifest timeout in Invoke-WorkbenchCheck**

Change the parameter (remove the `ValidateRange`, since 0 is now the sentinel):

```powershell
        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 0
```

After `$selectedCheck = $check[0]`, add:

```powershell
    if ($TimeoutSeconds -le 0) {
        $TimeoutSeconds = [int]$selectedCheck.TimeoutSeconds
    }
```

- [ ] **Step 6: Expose TimeoutSeconds on GET /api/checks**

In the `/api/checks` route handler, extend the `Select-Object`:

```powershell
$checks = @(Get-CheckCatalog | Select-Object CheckId, Name, Category, Script, Description, ReadOnly, Inputs, TimeoutSeconds)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.CheckTimeout.Tests.ps1"`
Expected: all `[PASS]`.
Also run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.LibraryMode.Tests.ps1"` — still `[PASS]`.

- [ ] **Step 8: Commit**

```bash
git add MSP-TroubleshootingWorkbench/checks/manifest.json MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1 MSP-TroubleshootingWorkbench/tests/Workbench.CheckTimeout.Tests.ps1
git commit -m "fix: per-check timeouts from manifest so AD lockout runs are not killed at 60s"
```

---

### Task 3: Record check inputs and rewrite ticket-notes generation

The generated notes are the product's core value and currently have three defects: blank case fields render as dangling labels ("Target path:"), "Actions Taken" doesn't say what inputs each check ran with, and "Likely Cause" circularly restates the check summary. Fix all three.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1` (`Invoke-WorkbenchCheck` ~line 706, `New-TicketNotesMarkdown` ~line 800)
- Test: `MSP-TroubleshootingWorkbench/tests/Workbench.TicketNotes.Tests.ps1` (create)

**Interfaces:**
- Consumes: `-LibraryMode` loading from Task 1.
- Produces: every check result stored on a case gains `InputsUsed` (PSCustomObject of the parameters actually passed, e.g. `@{ TargetAddress = "srv01"; Port = 443 }`). `New-TicketNotesMarkdown -Case <case>` returns markdown where: blank Issue fields are omitted; each Actions Taken bullet is `Ran <Name> (<friendly input list>) at <FinishedAt>`; Likely Cause bullets quote the failing/warning Evidence `Detail` text per check.

- [ ] **Step 1: Write the failing test**

Create `MSP-TroubleshootingWorkbench/tests/Workbench.TicketNotes.Tests.ps1`:

```powershell
#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-notes-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    . $serverPath -LibraryMode -OutputPath $tempRoot -NoBrowserOpen

    $case = [PSCustomObject]@{
        CaseId           = "CASE-20260101-120000"
        ClientName       = "Contoso"
        TicketNumber     = "10545"
        IssueType        = "Network"
        AffectedUser     = "jdoe"
        AffectedDevice   = ""
        TargetPath       = ""
        TargetAddress    = "srv01"
        CreatedAt        = "2026-01-01 12:00:00"
        UpdatedAt        = "2026-01-01 12:05:00"
        Checks           = @(
            [PSCustomObject]@{
                CheckId              = "network.quick"
                Name                 = "Network Quick Check"
                Category             = "Network"
                Status               = "Fail"
                Summary              = "Network quick check found a blocking issue for srv01."
                Evidence             = @(
                    [PSCustomObject]@{ Name = "Ping"; Status = "Pass"; Detail = "Target responded to ICMP echo." },
                    [PSCustomObject]@{ Name = "TCP port"; Status = "Fail"; Detail = "TCP port 445 is not reachable." }
                )
                RecommendedNextSteps = @("Check local routing, firewall policy, and service listener state for the target.")
                InputsUsed           = [PSCustomObject]@{ TargetAddress = "srv01"; Port = 445 }
                StartedAt            = "2026-01-01 12:01:00"
                FinishedAt           = "2026-01-01 12:01:10"
                Error                = ""
            }
        )
        Notes            = @()
        GeneratedSummary = ""
    }

    $markdown = New-TicketNotesMarkdown -Case $case

    Assert-True -Condition ($markdown -notmatch '- Target path:\s*$') -Message "Blank Target path is omitted from Issue section."
    Assert-True -Condition ($markdown -notmatch '- Affected device:\s*$') -Message "Blank Affected device is omitted from Issue section."
    Assert-True -Condition ($markdown -match '- Target address: srv01') -Message "Non-blank Target address is included."
    Assert-True -Condition ($markdown -match 'Ran Network Quick Check \(') -Message "Actions Taken bullet includes an input list."
    Assert-True -Condition ($markdown -match 'target: srv01') -Message "Actions Taken names the target address input."
    Assert-True -Condition ($markdown -match 'port: 445') -Message "Actions Taken names the port input."
    Assert-True -Condition ($markdown -match 'Likely Cause:') -Message "Likely Cause section exists."
    Assert-True -Condition ($markdown -match 'Network Quick Check: TCP port 445 is not reachable\.') -Message "Likely Cause quotes the failing evidence detail."
    Assert-True -Condition ($markdown -notmatch 'Likely related to: Network quick check found a blocking issue') -Message "Likely Cause no longer restates the check summary."
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("Ticket notes tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Ticket notes tests completed." -ForegroundColor Green
```

- [ ] **Step 2: Run test to verify it fails**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.TicketNotes.Tests.ps1"`
Expected: FAIL — blank-field, input-list, and likely-cause assertions fail against the current generator.

- [ ] **Step 3: Stamp InputsUsed onto check results in Invoke-WorkbenchCheck**

In `Invoke-WorkbenchCheck`, add a helper application right before each `return`. The cleanest way: define this small helper next to `New-WorkbenchCheckFailureResult`:

```powershell
function Add-WorkbenchCheckInputsUsed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [hashtable]$Parameters
    )

    $inputsUsed = ConvertTo-WorkbenchPlainValue -Value $Parameters
    if ($Result.PSObject.Properties.Name -contains "InputsUsed") {
        $Result.InputsUsed = $inputsUsed
    }
    else {
        Add-Member -InputObject $Result -MemberType NoteProperty -Name "InputsUsed" -Value $inputsUsed
    }

    return $Result
}
```

Then in `Invoke-WorkbenchCheck`, wrap every return of a result object:
- timeout path: `return (Add-WorkbenchCheckInputsUsed -Result (New-WorkbenchCheckFailureResult ...) -Parameters $invokeParams)`
- catch path: same wrapping
- null-result path: same wrapping
- success path: `return (Add-WorkbenchCheckInputsUsed -Result (ConvertTo-WorkbenchPlainValue -Value $result) -Parameters $invokeParams)`

Note: `ConvertTo-WorkbenchPlainValue` on an empty hashtable returns a `[string]` (its zero-property fallback). Guard in the helper: if `$Parameters.Count -eq 0`, set `$inputsUsed = $null` and skip adding the member. Add this at the top of the helper:

```powershell
    if ($Parameters.Count -eq 0) {
        return $Result
    }
```

- [ ] **Step 4: Rewrite New-TicketNotesMarkdown**

Replace the function body sections as follows (full replacement of the function, keeping the existing `Add-TicketNotesLine`/`Add-TicketNotesBullet` helpers):

```powershell
function Get-WorkbenchInputDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ParameterName
    )

    switch ($ParameterName.ToLowerInvariant()) {
        "targetaddress"    { return "target" }
        "port"             { return "port" }
        "affecteduser"     { return "user" }
        "affecteddevice"   { return "device" }
        "daysback"         { return "days back" }
        "domaincontroller" { return "domain controller" }
        default            { return $ParameterName.ToLowerInvariant() }
    }
}

function Get-WorkbenchCheckInputsText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Check
    )

    if ($null -eq $Check -or -not ($Check.PSObject.Properties.Name -contains "InputsUsed") -or $null -eq $Check.InputsUsed) {
        return ""
    }

    $parts = @()
    foreach ($property in @($Check.InputsUsed.PSObject.Properties)) {
        $valueText = ""
        if ($property.Value -is [System.Collections.IEnumerable] -and -not ($property.Value -is [string])) {
            $valueText = (@($property.Value) -join ", ")
        }
        else {
            $valueText = [string]$property.Value
        }

        if (-not [string]::IsNullOrWhiteSpace($valueText)) {
            $parts += ("{0}: {1}" -f (Get-WorkbenchInputDisplayName -ParameterName $property.Name), $valueText)
        }
    }

    return ($parts -join ", ")
}

function New-TicketNotesMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Case
    )

    $builder = New-Object System.Text.StringBuilder
    $checks = @()
    $notes = @()

    if ($Case.PSObject.Properties.Name -contains "Checks" -and $null -ne $Case.Checks) {
        $checks = @($Case.Checks)
    }

    if ($Case.PSObject.Properties.Name -contains "Notes" -and $null -ne $Case.Notes) {
        $notes = @($Case.Notes)
    }

    Add-TicketNotesLine -Builder $builder -Line "Issue:"
    Add-TicketNotesBullet -Builder $builder -Text ("Client: {0}" -f $Case.ClientName)
    Add-TicketNotesBullet -Builder $builder -Text ("Ticket: {0}" -f $Case.TicketNumber)
    Add-TicketNotesBullet -Builder $builder -Text ("Issue type: {0}" -f $Case.IssueType)

    $optionalFields = @(
        @{ Label = "Affected user"; Value = [string]$Case.AffectedUser },
        @{ Label = "Affected device"; Value = [string]$Case.AffectedDevice },
        @{ Label = "Target path"; Value = [string]$Case.TargetPath },
        @{ Label = "Target address"; Value = [string]$Case.TargetAddress }
    )

    foreach ($field in $optionalFields) {
        if (-not [string]::IsNullOrWhiteSpace($field.Value)) {
            Add-TicketNotesBullet -Builder $builder -Text ("{0}: {1}" -f $field.Label, $field.Value)
        }
    }

    if ($notes.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text ("Reported detail: {0}" -f [string]$notes[0].Text)
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Actions Taken:"
    if ($checks.Count -gt 0) {
        foreach ($check in $checks) {
            $action = "Ran {0}" -f $check.Name
            $inputsText = Get-WorkbenchCheckInputsText -Check $check
            if (-not [string]::IsNullOrWhiteSpace($inputsText)) {
                $action = "{0} ({1})" -f $action, $inputsText
            }

            $finishedAt = ""
            if ($check.PSObject.Properties.Name -contains "FinishedAt") {
                $finishedAt = [string]$check.FinishedAt
            }

            if (-not [string]::IsNullOrWhiteSpace($finishedAt)) {
                $action = "$action at $finishedAt"
            }

            Add-TicketNotesBullet -Builder $builder -Text $action
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "No automated checks have been run yet."
    }

    foreach ($note in $notes) {
        $noteLine = [string]$note.Text
        if ($note.PSObject.Properties.Name -contains "CreatedAt" -and -not [string]::IsNullOrWhiteSpace([string]$note.CreatedAt)) {
            $noteLine = "{0}: {1}" -f $note.CreatedAt, $note.Text
        }

        Add-TicketNotesBullet -Builder $builder -Text $noteLine
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Findings:"
    if ($checks.Count -gt 0) {
        foreach ($check in $checks) {
            Add-TicketNotesBullet -Builder $builder -Text ("{0} [{1}]: {2}" -f $check.Name, $check.Status, $check.Summary)
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "Findings are pending additional checks."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Evidence:"
    $evidenceCount = 0
    foreach ($check in $checks) {
        if ($check.PSObject.Properties.Name -contains "Evidence" -and $null -ne $check.Evidence) {
            foreach ($evidence in @($check.Evidence)) {
                $evidenceCount++
                Add-TicketNotesBullet -Builder $builder -Text ("{0} - {1}: {2}" -f $evidence.Name, $evidence.Status, $evidence.Detail)
            }
        }
    }

    if ($evidenceCount -eq 0) {
        Add-TicketNotesBullet -Builder $builder -Text "No evidence has been captured yet."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Likely Cause:"
    $problemChecks = @($checks | Where-Object { ([string]$_.Status) -in @("Warn", "Fail") })
    $likelyCauseCount = 0
    foreach ($problemCheck in $problemChecks) {
        $problemEvidence = @()
        if ($problemCheck.PSObject.Properties.Name -contains "Evidence" -and $null -ne $problemCheck.Evidence) {
            $problemEvidence = @($problemCheck.Evidence | Where-Object { ([string]$_.Status) -eq "Fail" })
            if ($problemEvidence.Count -eq 0) {
                $problemEvidence = @($problemCheck.Evidence | Where-Object { ([string]$_.Status) -eq "Warn" })
            }
        }

        if ($problemEvidence.Count -gt 0) {
            foreach ($evidence in $problemEvidence) {
                $likelyCauseCount++
                Add-TicketNotesBullet -Builder $builder -Text ("{0}: {1}" -f $problemCheck.Name, $evidence.Detail)
            }
        }
        else {
            $likelyCauseCount++
            Add-TicketNotesBullet -Builder $builder -Text ("{0}: {1}" -f $problemCheck.Name, $problemCheck.Summary)
        }
    }

    if ($likelyCauseCount -eq 0) {
        if ($checks.Count -gt 0) {
            Add-TicketNotesBullet -Builder $builder -Text "No failing automated check has identified a likely cause yet."
        }
        else {
            Add-TicketNotesBullet -Builder $builder -Text "Likely cause is pending diagnostic evidence."
        }
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Next Steps:"
    $nextSteps = @()
    foreach ($check in $checks) {
        if ($check.PSObject.Properties.Name -contains "RecommendedNextSteps" -and $null -ne $check.RecommendedNextSteps) {
            $nextSteps += @($check.RecommendedNextSteps)
        }
    }

    $nextSteps = @($nextSteps | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($nextSteps.Count -gt 0) {
        foreach ($step in $nextSteps) {
            Add-TicketNotesBullet -Builder $builder -Text ([string]$step)
        }
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text "Run the relevant troubleshooting checks and document the result."
    }
    Add-TicketNotesLine -Builder $builder

    Add-TicketNotesLine -Builder $builder -Line "Customer-Facing Summary:"
    if ($problemChecks.Count -gt 0) {
        $customerNextAction = "continue troubleshooting with the captured evidence."
        if ($nextSteps.Count -gt 0) {
            $customerNextAction = [string]$nextSteps[0]
        }

        Add-TicketNotesBullet -Builder $builder -Text ("We reviewed the reported {0} issue and found evidence requiring follow-up. Next action: {1}" -f $Case.IssueType, $customerNextAction)
    }
    elseif ($checks.Count -gt 0) {
        Add-TicketNotesBullet -Builder $builder -Text ("We reviewed the reported {0} issue and the completed checks did not identify a current failure." -f $Case.IssueType)
    }
    else {
        Add-TicketNotesBullet -Builder $builder -Text ("We opened the {0} troubleshooting case and are gathering diagnostic evidence." -f $Case.IssueType)
    }

    return $builder.ToString().TrimEnd()
}
```

Place `Get-WorkbenchInputDisplayName` and `Get-WorkbenchCheckInputsText` immediately before `New-TicketNotesMarkdown` in the file.

- [ ] **Step 5: Run tests to verify they pass**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.TicketNotes.Tests.ps1"`
Expected: all `[PASS]`.
Also re-run the Task 1 and Task 2 test files — still `[PASS]`.

- [ ] **Step 6: Commit**

```bash
git add MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1 MSP-TroubleshootingWorkbench/tests/Workbench.TicketNotes.Tests.ps1
git commit -m "feat: record check inputs and generate evidence-based ticket notes"
```

---

### Task 4: Session token to block cross-site POSTs

Any webpage open in the tech's browser can currently fire `fetch("http://localhost:8275/api/...", {method:"POST", mode:"no-cors", body:"{...}"})` and the server will execute it (it never checks Content-Type or origin). Fix: the server generates a per-session token, injects it into the served page, and rejects POSTs without the matching `X-Workbench-Token` header. Cross-origin pages cannot set custom headers without a CORS preflight, which the server never approves.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1` (runtime section + POST routing)
- Modify: `MSP-TroubleshootingWorkbench/app/index.html` (token meta tag + fetch headers)
- Test: `MSP-TroubleshootingWorkbench/tests/Workbench.Api.Tests.ps1` covers this in Task 8 (integration). This task adds a source-level test consistent with the existing repo pattern.

**Interfaces:**
- Consumes: nothing new.
- Produces: `$script:WorkbenchToken` (32-hex-char string); served HTML contains `<meta name="workbench-token" content="<token>">`; every POST endpoint returns HTTP 403 `{"error":"Missing or invalid workbench token."}` when the `X-Workbench-Token` header doesn't match. Task 5/6 UI code MUST send the token via the shared `postJson()` helper defined here. Task 8's integration test scrapes the token from `GET /`.

- [ ] **Step 1: Generate the token and inject it into the page**

In the runtime section of `Start-MSPTroubleshootingWorkbench.ps1`, after `$logPath = ...` add:

```powershell
$script:WorkbenchToken = [guid]::NewGuid().ToString("N")
```

In the `GET /` route handler, change the HTML serving to inject the token:

```powershell
            if ($method -ieq "GET" -and $path -eq "/") {
                if (Test-Path -LiteralPath $indexPath) {
                    $html = Get-Content -LiteralPath $indexPath -Raw
                    $html = $html.Replace("__WORKBENCH_TOKEN__", $script:WorkbenchToken)
                    Send-Html -Context $context -Html $html
                }
                else {
                    Send-Text -Context $context -Text "Workbench UI not found." -StatusCode 404
                }
            }
```

- [ ] **Step 2: Enforce the token on all POSTs**

Immediately after `$method = $request.HttpMethod` and the request log line, add a single gate (before the big if/elseif chain):

```powershell
            if ($method -ieq "POST" -and ([string]$request.Headers["X-Workbench-Token"]) -ne $script:WorkbenchToken) {
                Send-JsonError -Context $context -Message "Missing or invalid workbench token. Reload the page and try again." -StatusCode 403
                continue
            }
```

Note: `continue` is valid here because the routing runs inside the `while` loop; it skips the rest of the iteration after the response is sent.

- [ ] **Step 3: Add the token to the UI**

In `app/index.html` `<head>`, after the viewport meta tag, add:

```html
  <meta name="workbench-token" content="__WORKBENCH_TOKEN__">
```

At the top of the `<script>` block, add a shared helper and use it everywhere a POST happens:

```javascript
    const workbenchToken = document.querySelector('meta[name="workbench-token"]').content;

    async function postJson(url, body) {
      return fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Workbench-Token": workbenchToken
        },
        body: JSON.stringify(body === undefined ? {} : body)
      });
    }
```

Replace the three existing `fetch(..., {method: "POST", ...})` calls:
- in `createCase`: `const response = await postJson("/api/cases", body);`
- in `runCheck`: `const response = await postJson("/api/cases/" + encodeURIComponent(caseId) + "/checks/" + encodeURIComponent(checkId) + "/run", body);`
- in `postCaseAction`: `const response = await postJson("/api/cases/" + encodeURIComponent(caseId) + "/" + action);`

- [ ] **Step 4: Add a source-level regression test**

Create `MSP-TroubleshootingWorkbench/tests/Workbench.Token.Tests.ps1`:

```powershell
#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverSource = Get-Content -LiteralPath (Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1") -Raw
$uiSource = Get-Content -LiteralPath (Join-Path $repoRoot "MSP-TroubleshootingWorkbench\app\index.html") -Raw

Assert-True -Condition ($serverSource -match 'X-Workbench-Token') -Message "Server checks the X-Workbench-Token header."
Assert-True -Condition ($serverSource -match '__WORKBENCH_TOKEN__') -Message "Server injects the session token into the page."
Assert-True -Condition ($uiSource -match 'workbench-token') -Message "UI page carries the token meta tag."
Assert-True -Condition ($uiSource -match 'X-Workbench-Token') -Message "UI sends the token header on POSTs."
Assert-True -Condition (-not ($uiSource -match 'method:\s*"POST"[\s\S]{0,200}headers:\s*\{\s*"Content-Type":\s*"application/json"\s*\}')) -Message "No POST fetch remains without the token header."

if ($script:Failures.Count -gt 0) {
    throw ("Token tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] Token tests completed." -ForegroundColor Green
```

- [ ] **Step 5: Run test and manually verify**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.Token.Tests.ps1"` — expected all `[PASS]`.
Manual check: start the server (`-Port 8299 -NoBrowserOpen`), then:
`powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -Method Post -Uri http://localhost:8299/api/cases -Body '{}' } catch { $_.Exception.Response.StatusCode.value__ }"`
Expected: `403`. Then open `http://localhost:8299/` in a browser and create a case through the form — expected: succeeds.

- [ ] **Step 6: Commit**

```bash
git add MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1 MSP-TroubleshootingWorkbench/app/index.html MSP-TroubleshootingWorkbench/tests/Workbench.Token.Tests.ps1
git commit -m "fix: require per-session token on POST endpoints to block cross-site requests"
```

---

### Task 5: Check picker with dynamic inputs in the UI

Bug: the UI always runs `checkCatalog[0]` — two of three checks are unreachable from the browser, and only address/port inputs exist. Replace the check form with a check `<select>` plus input fields generated from each check's manifest `inputs`, prefilled from the selected case.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/app/index.html` (check form markup + `loadChecks`/`runCheck` JS)
- Test: manual browser verification (steps below) + integration coverage in Task 8

**Interfaces:**
- Consumes: `GET /api/checks` (each entry: `CheckId, Name, Category, Description, Inputs[]`), `postJson()` from Task 4.
- Produces: a `<select id="check-select">` and a `<div id="check-inputs">` of generated fields; `window.selectedCase` (set in Task 6, may be null) used for prefill; `renderCheckInputs()` function Task 6 calls when a case is selected. Input name → field metadata mapping `CHECK_INPUT_FIELDS` (exact keys: `targetAddress`, `port`, `affectedUser`, `affectedDevice`, `daysBack`, `domainController`).

- [ ] **Step 1: Replace the check form markup**

In `app/index.html`, replace the existing `<form id="check-form" class="check-panel">...</form>` block with:

```html
      <form id="check-form" class="check-panel">
        <div class="field">
          <label for="check-select">Check to run</label>
          <select id="check-select" name="checkId" required></select>
        </div>
        <div id="check-inputs" class="check-inputs"></div>
        <div class="form-actions">
          <button type="submit" id="run-check-button">Run check</button>
          <p id="check-form-message" class="form-message" aria-live="polite"></p>
        </div>
      </form>
```

Remove the now-duplicated `<p id="check-form-message">` that sat below the workspace actions (the message element now lives inside the form). Keep the `workspace-actions` div — Task 6 rewires it.

Replace the `.check-panel` CSS rule with:

```css
    .check-panel {
      display: grid;
      gap: 12px;
    }

    .check-inputs {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    @media (max-width: 760px) {
      .check-inputs {
        grid-template-columns: 1fr;
      }
    }
```

(Fold the media-query addition into the existing `@media (max-width: 760px)` block rather than creating a second one.)

- [ ] **Step 2: Add the field metadata map and rendering logic**

In the `<script>` block, add near the top (after `let checkCatalog = [];`):

```javascript
    let selectedCase = null;

    const CHECK_INPUT_FIELDS = {
      targetAddress: { label: "Address (host or IP)", type: "text", placeholder: "e.g. SRV01 or 10.0.0.5", caseField: "TargetAddress" },
      port: { label: "Port", type: "number", placeholder: "e.g. 443", min: 1, max: 65535, caseField: null },
      affectedUser: { label: "User", type: "text", placeholder: "e.g. jdoe", caseField: "AffectedUser" },
      affectedDevice: { label: "Device", type: "text", placeholder: "e.g. RDSH01", caseField: "AffectedDevice" },
      daysBack: { label: "Days back", type: "number", placeholder: "e.g. 7", min: 1, max: 90, caseField: null },
      domainController: { label: "Domain controller (optional)", type: "text", placeholder: "e.g. DC01, DC02", caseField: null }
    };

    function renderCheckInputs() {
      const container = document.getElementById("check-inputs");
      container.innerHTML = "";

      const checkId = document.getElementById("check-select").value;
      const check = checkCatalog.find((entry) => entry.CheckId === checkId);
      if (!check) {
        return;
      }

      (check.Inputs || []).forEach((inputName) => {
        const meta = CHECK_INPUT_FIELDS[inputName] || { label: inputName, type: "text", placeholder: "", caseField: null };
        const field = document.createElement("div");
        field.className = "field";

        const label = document.createElement("label");
        label.setAttribute("for", "check-input-" + inputName);
        label.textContent = meta.label;

        const input = document.createElement("input");
        input.id = "check-input-" + inputName;
        input.name = inputName;
        input.type = meta.type;
        input.autocomplete = "off";
        if (meta.placeholder) { input.placeholder = meta.placeholder; }
        if (meta.min !== undefined) { input.min = meta.min; }
        if (meta.max !== undefined) { input.max = meta.max; }
        if (selectedCase && meta.caseField && selectedCase[meta.caseField]) {
          input.value = selectedCase[meta.caseField];
        }

        field.append(label, input);
        container.appendChild(field);
      });
    }
```

- [ ] **Step 3: Populate the select in loadChecks**

At the end of the `try` block in `loadChecks()` (after the catalog list rendering loop), add:

```javascript
        const select = document.getElementById("check-select");
        select.innerHTML = "";
        checkCatalog.forEach((check) => {
          const option = document.createElement("option");
          option.value = check.CheckId;
          option.textContent = check.Name + " — " + (check.Description || check.Category || "");
          select.appendChild(option);
        });
        renderCheckInputs();
```

And register the change handler with the other listeners at the bottom of the script:

```javascript
    document.getElementById("check-select").addEventListener("change", renderCheckInputs);
```

- [ ] **Step 4: Rewrite runCheck to use the selected check and dynamic inputs**

Replace the body-building part of `runCheck` (everything from `const formData = ...` through `delete body.port`) with:

```javascript
      const checkId = document.getElementById("check-select").value;
      const caseId = selectedCase ? selectedCase.CaseId : "";
      const body = {};

      document.querySelectorAll("#check-inputs input").forEach((input) => {
        if (input.value.trim() !== "") {
          body[input.name] = input.value.trim();
        }
      });

      if (!caseId) {
        message.className = "form-message error";
        message.textContent = "Select a case first, or create one above.";
        return;
      }
```

(The `message` element lookup stays where it is; move the guard after it. The POST call itself becomes `const response = await postJson(...)` per Task 4.)

`selectedCase` is set by Task 6's case selection; until Task 6 lands, temporarily keep it working by setting `selectedCase = workbenchCase` inside the existing case-item click handler in `loadCases()` (replace the two lines that set `check-case-id` / `check-target-address` values, since those inputs no longer exist — **this is required or the page throws on click**). Also delete the two lines in `createCase` that set `check-case-id` / `check-target-address`, replacing them with `selectedCase = data;`.

- [ ] **Step 5: Manual verification**

Start the server: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1" -Port 8299`
In the browser:
1. The check dropdown lists all three checks.
2. Selecting "AD Lockout Diagnostics" shows User / Days back / Domain controller fields; "Network Quick Check" shows Address / Port.
3. Create a case with a user and device; click it in the case list; select the Citrix check — Device and User prefill from the case.
4. Run "Network Quick Check" with address `localhost`, port `8299` — message shows `Pass: ...`.
5. Run it with port `9` — message shows `Fail: ...` (connection refused is expected evidence).

- [ ] **Step 6: Commit**

```bash
git add MSP-TroubleshootingWorkbench/app/index.html
git commit -m "feat: check picker with per-check dynamic inputs in workbench UI"
```

---

### Task 6: Case workspace — results, evidence, notes, and copyable ticket notes

The UI never shows what a check found, has no way to add notes, and never displays the generated ticket notes. Add a case workspace section: clicking a case loads its detail; the workspace shows check history with evidence, a notes list with an add-note form, and the generated notes in a `<pre>` with a Copy button.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/app/index.html`
- Test: manual browser verification + integration coverage in Task 8

**Interfaces:**
- Consumes: `GET /api/cases/{id}`, `POST /api/cases/{id}/notes` (body `{"note": "..."}`), `POST /api/cases/{id}/generate-notes` (returns `{caseId, markdown, case}`), `POST /api/cases/{id}/export` (returns `{CaseId, MarkdownPath, ReportPath, EvidencePath}`), `postJson()` from Task 4, `selectedCase` + `renderCheckInputs()` from Task 5.
- Produces: `selectCase(caseId)` async function; `renderWorkspace()`; workspace DOM ids `workspace-section`, `workspace-title`, `workspace-checks`, `workspace-notes`, `note-text`, `add-note-button`, `generated-notes`, `copy-notes-button`.

- [ ] **Step 1: Add workspace markup**

In `app/index.html`, insert a new section between the Cases section and the Checks section:

```html
    <section id="workspace-section" aria-labelledby="workspace-title" hidden>
      <h2 id="workspace-title">Case workspace</h2>
      <dl id="workspace-meta"></dl>

      <h3 class="workspace-subtitle">Check results</h3>
      <p id="workspace-checks-empty" class="empty">No checks have been run for this case yet.</p>
      <ul id="workspace-checks" class="check-list"></ul>

      <h3 class="workspace-subtitle">Notes</h3>
      <p id="workspace-notes-empty" class="empty">No notes yet.</p>
      <ul id="workspace-notes" class="note-list"></ul>
      <div class="note-form">
        <input id="note-text" placeholder="Add a note about what you observed or did..." autocomplete="off">
        <button type="button" id="add-note-button">Add note</button>
      </div>

      <h3 class="workspace-subtitle">Ticket notes</h3>
      <pre id="generated-notes" class="generated-notes" hidden></pre>
      <div class="workspace-actions" aria-label="Case workspace actions">
        <button type="button" id="generate-notes-button">Generate Notes</button>
        <button type="button" id="copy-notes-button" hidden>Copy to clipboard</button>
        <button type="button" id="export-evidence-button">Export Evidence</button>
        <p id="workspace-action-message" class="form-message" aria-live="polite"></p>
      </div>
    </section>
```

Delete the old `workspace-actions` div from the Checks section (the buttons move here). Add CSS:

```css
    .workspace-subtitle {
      margin: 18px 0 8px;
      font-size: 0.95rem;
      font-weight: 650;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .note-list {
      display: grid;
      gap: 6px;
      margin: 0 0 10px;
      padding: 0;
      list-style: none;
    }

    .note-form {
      display: flex;
      gap: 10px;
    }

    .note-form input {
      flex: 1;
    }

    .generated-notes {
      white-space: pre-wrap;
      background: var(--field-bg);
      border: 1px solid var(--panel-border);
      border-radius: 4px;
      padding: 14px;
      margin: 0 0 12px;
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.85rem;
    }

    .status-pill {
      display: inline-block;
      min-width: 44px;
      padding: 1px 8px;
      border-radius: 3px;
      font-size: 0.78rem;
      font-weight: 700;
      text-align: center;
    }

    .status-pass { background: #1f4d2e; color: #9be3ae; }
    .status-warn { background: #4d3f1f; color: #e3cf9b; }
    .status-fail { background: #4d1f1f; color: #e39b9b; }

    .evidence-list {
      margin: 6px 0 0;
      padding-left: 18px;
      color: var(--muted);
      font-size: 0.88rem;
    }
```

- [ ] **Step 2: Add selectCase and renderWorkspace**

Add to the script:

```javascript
    async function selectCase(caseId) {
      const message = document.getElementById("workspace-action-message");
      try {
        const response = await fetch("/api/cases/" + encodeURIComponent(caseId));
        if (!response.ok) {
          throw new Error("Could not load case " + caseId);
        }

        selectedCase = await response.json();
        renderWorkspace();
        renderCheckInputs();
      }
      catch (error) {
        message.className = "form-message error";
        message.textContent = error.message;
      }
    }

    function statusPill(status) {
      const pill = document.createElement("span");
      const value = (status || "").toLowerCase();
      pill.className = "status-pill status-" + (["pass", "warn", "fail"].includes(value) ? value : "warn");
      pill.textContent = status || "?";
      return pill;
    }

    function renderWorkspace() {
      const section = document.getElementById("workspace-section");
      if (!selectedCase) {
        section.hidden = true;
        return;
      }

      section.hidden = false;
      document.getElementById("workspace-title").textContent = "Case workspace — " + selectedCase.CaseId;

      const meta = document.getElementById("workspace-meta");
      meta.innerHTML = "";
      [
        ["Client", selectedCase.ClientName],
        ["Ticket", selectedCase.TicketNumber],
        ["Issue type", selectedCase.IssueType],
        ["User", selectedCase.AffectedUser],
        ["Device", selectedCase.AffectedDevice]
      ].forEach(([label, value]) => {
        if (!value) { return; }
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = value;
        meta.append(dt, dd);
      });

      const checks = selectedCase.Checks || [];
      const checksList = document.getElementById("workspace-checks");
      document.getElementById("workspace-checks-empty").hidden = checks.length > 0;
      checksList.innerHTML = "";
      checks.forEach((check) => {
        const item = document.createElement("li");
        item.className = "check-item";

        const header = document.createElement("div");
        const name = document.createElement("span");
        name.className = "check-name";
        name.textContent = check.Name || check.CheckId;
        header.append(name, document.createTextNode(" "), statusPill(check.Status));

        const summary = document.createElement("div");
        summary.className = "case-meta";
        summary.textContent = (check.Summary || "") + (check.FinishedAt ? " (" + check.FinishedAt + ")" : "");

        const evidenceList = document.createElement("ul");
        evidenceList.className = "evidence-list";
        (check.Evidence || []).forEach((evidence) => {
          const evidenceItem = document.createElement("li");
          evidenceItem.textContent = evidence.Name + " [" + evidence.Status + "]: " + evidence.Detail;
          evidenceList.appendChild(evidenceItem);
        });

        item.append(header, summary, evidenceList);
        checksList.appendChild(item);
      });

      const notes = selectedCase.Notes || [];
      const notesList = document.getElementById("workspace-notes");
      document.getElementById("workspace-notes-empty").hidden = notes.length > 0;
      notesList.innerHTML = "";
      notes.forEach((note) => {
        const item = document.createElement("li");
        item.className = "case-meta";
        item.textContent = (note.CreatedAt ? note.CreatedAt + " — " : "") + note.Text;
        notesList.appendChild(item);
      });

      const generated = document.getElementById("generated-notes");
      const copyButton = document.getElementById("copy-notes-button");
      if (selectedCase.GeneratedSummary) {
        generated.textContent = selectedCase.GeneratedSummary;
        generated.hidden = false;
        copyButton.hidden = false;
      }
      else {
        generated.hidden = true;
        copyButton.hidden = true;
      }
    }
```

- [ ] **Step 3: Wire notes, generate, copy, export**

Add:

```javascript
    async function addNote() {
      const input = document.getElementById("note-text");
      const message = document.getElementById("workspace-action-message");
      if (!selectedCase || input.value.trim() === "") {
        return;
      }

      try {
        const response = await postJson("/api/cases/" + encodeURIComponent(selectedCase.CaseId) + "/notes", { note: input.value.trim() });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || "Adding the note failed");
        }

        input.value = "";
        selectedCase = data;
        renderWorkspace();
      }
      catch (error) {
        message.className = "form-message error";
        message.textContent = error.message;
      }
    }

    async function copyGeneratedNotes() {
      const message = document.getElementById("workspace-action-message");
      const text = document.getElementById("generated-notes").textContent;
      try {
        await navigator.clipboard.writeText(text);
        message.className = "form-message";
        message.textContent = "Ticket notes copied to clipboard.";
      }
      catch (error) {
        message.className = "form-message error";
        message.textContent = "Copy failed — select the text and copy manually.";
      }
    }
```

Update `postCaseAction` to use `selectedCase` instead of the removed `check-case-id` input, and to refresh the workspace:

```javascript
    async function postCaseAction(action, buttonId, pendingText, successText) {
      if (!selectedCase) { return; }
      const caseId = selectedCase.CaseId;
      const button = document.getElementById(buttonId);
      const message = document.getElementById("workspace-action-message");

      button.disabled = true;
      message.className = "form-message";
      message.textContent = pendingText;

      try {
        const response = await postJson("/api/cases/" + encodeURIComponent(caseId) + "/" + action);
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || successText + " failed");
        }

        if (action === "export") {
          message.textContent = successText + ": " + (data.MarkdownPath || data.markdownPath || "");
        }
        else {
          message.textContent = successText + ".";
        }

        await selectCase(caseId);
      }
      catch (error) {
        message.className = "form-message error";
        message.textContent = error.message;
      }
      finally {
        button.disabled = false;
      }
    }
```

Update the case-item click handler in `loadCases()` to `selectCase(workbenchCase.CaseId)`, the `createCase` success path to `await selectCase(data.CaseId)`, and the `runCheck` success path to `await selectCase(caseId)` (so new results appear immediately). Register listeners:

```javascript
    document.getElementById("add-note-button").addEventListener("click", addNote);
    document.getElementById("copy-notes-button").addEventListener("click", copyGeneratedNotes);
    document.getElementById("note-text").addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); addNote(); }
    });
```

- [ ] **Step 4: Manual verification**

Start the server on port 8299 and in the browser:
1. Create a case → workspace appears with case meta.
2. Run a Network Quick Check against `localhost:8299` → check result with evidence bullets appears in the workspace without a manual refresh.
3. Add a note ("User reports slow logins") → it appears with a timestamp.
4. Click Generate Notes → ticket notes render in the pre block; Copy to clipboard works (paste into Notepad to confirm).
5. Click Export Evidence → message shows the ticket-notes.md path; open the file and confirm it matches the on-screen notes.
6. Reload the page and click the case in the list → workspace restores with all history.

- [ ] **Step 5: Commit**

```bash
git add MSP-TroubleshootingWorkbench/app/index.html
git commit -m "feat: case workspace with check results, notes, and copyable ticket notes"
```

---

### Task 7: Responsive shutdown (non-blocking accept loop)

`$listener.GetContext()` blocks forever, so Ctrl+C only takes effect after one more request arrives, and the console handler resorts to calling `Stop()` from the handler thread. Replace with `GetContextAsync()` polled in short waits.

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1` (main `while` loop)
- Test: manual verification (blocking-accept behavior can't be asserted from source), plus keep all prior test files green.

**Interfaces:**
- Consumes: nothing new.
- Produces: no API change; Ctrl+C stops the server within ~1 second even with no traffic.

- [ ] **Step 1: Replace the blocking accept**

In the main loop, replace:

```powershell
            $context = $listener.GetContext()
```

with:

```powershell
            $contextTask = $listener.GetContextAsync()
            while (-not $contextTask.AsyncWaitHandle.WaitOne(250)) {
                if ($script:StopRequested) {
                    break
                }
            }

            if ($script:StopRequested) {
                break
            }

            $context = $contextTask.GetAwaiter().GetResult()
```

And simplify the cancel handler — it no longer needs to stop the listener from the handler thread:

```powershell
$cancelHandler = [ConsoleCancelEventHandler]{
    param($Sender, $EventArgs)

    $EventArgs.Cancel = $true
    $script:StopRequested = $true
}
```

(Keep `$script:WorkbenchListener = $listener` removal optional; if removed, also remove the assignment. The `finally` block already stops and closes the listener.)

- [ ] **Step 2: Manual verification**

1. Start the server with `-Port 8299 -NoBrowserOpen`. Press Ctrl+C with zero requests made. Expected: "MSP Troubleshooting Workbench stopped." within ~1 second.
2. Start again, load the UI, run a check, then Ctrl+C. Expected: clean stop, no unhandled exception spew.
3. Confirm `logs/` shows the stop line.

- [ ] **Step 3: Run all existing tests**

Run each file in `MSP-TroubleshootingWorkbench/tests/` with `powershell -NoProfile -File <path>`. Expected: all pass. (Note: `Task4`–`Task9` regression tests assert on source patterns; if any fail because this task changed a matched pattern, update that regression test's pattern to match the new code — the *behavior* they guard is unchanged.)

- [ ] **Step 4: Commit**

```bash
git add MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1
git commit -m "fix: non-blocking accept loop so Ctrl+C stops the workbench immediately"
```

---

### Task 8: End-to-end API integration test + README rewrite

The existing tests only regex the source. Add one integration test that boots the real server on a random port, exercises the full case lifecycle over HTTP (including the token), and shuts it down. Then rewrite the README to document what actually exists.

**Files:**
- Test: `MSP-TroubleshootingWorkbench/tests/Workbench.Api.Tests.ps1` (create)
- Modify: `MSP-TroubleshootingWorkbench/README.md`

**Interfaces:**
- Consumes: everything shipped in Tasks 1–7.
- Produces: a repeatable smoke test future changes must keep green.

- [ ] **Step 1: Write the integration test**

Create `MSP-TroubleshootingWorkbench/tests/Workbench.Api.Tests.ps1`:

```powershell
#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:Failures = @()

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        $script:Failures += $Message
        Write-Host "[FAIL] $Message" -ForegroundColor Red
    }
    else {
        Write-Host "[PASS] $Message" -ForegroundColor Green
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$serverPath = Join-Path $repoRoot "MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1"
$tempRoot = Join-Path $env:TEMP ("wb-api-{0}" -f ([guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$port = Get-Random -Minimum 20000 -Maximum 40000
$baseUrl = "http://localhost:$port"
$serverProcess = $null

try {
    $serverProcess = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$serverPath`"", "-Port", $port, "-OutputPath", "`"$tempRoot`"", "-NoBrowserOpen") `
        -PassThru -WindowStyle Hidden

    # Wait up to 20s for the server to answer.
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            $status = Invoke-RestMethod -Uri "$baseUrl/api/status" -TimeoutSec 2
            if ($status.appName) { $ready = $true; break }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    Assert-True -Condition $ready -Message "Server answers /api/status."
    if (-not $ready) { throw "Server never became ready; aborting." }

    # Scrape the session token from the served page.
    $page = (Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/").Content
    $tokenMatch = [regex]::Match($page, 'name="workbench-token" content="([0-9a-f]{32})"')
    Assert-True -Condition $tokenMatch.Success -Message "Served page contains an injected session token."
    $token = $tokenMatch.Groups[1].Value
    $headers = @{ "X-Workbench-Token" = $token }

    # POST without the token is rejected.
    $blockedStatus = 0
    try {
        Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases" -Body '{"clientName":"X","ticketNumber":"1","issueType":"Network"}' -ContentType "application/json" | Out-Null
    }
    catch {
        $blockedStatus = [int]$_.Exception.Response.StatusCode
    }
    Assert-True -Condition ($blockedStatus -eq 403) -Message "POST without token returns 403."

    # Full lifecycle with the token.
    $caseBody = '{"clientName":"Contoso","ticketNumber":"10545","issueType":"Network","affectedUser":"jdoe","affectedDevice":"","targetPath":"","targetAddress":"localhost"}'
    $case = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases" -Body $caseBody -ContentType "application/json" -Headers $headers
    Assert-True -Condition ($case.CaseId -match '^CASE-\d{8}-\d{6}$') -Message "Case creation returns a well-formed case id."

    $checks = @(Invoke-RestMethod -Uri "$baseUrl/api/checks")
    Assert-True -Condition ($checks.Count -ge 3) -Message "Check catalog lists at least three checks."
    Assert-True -Condition ($null -ne ($checks | Where-Object { $_.CheckId -eq "ad.lockout" })) -Message "Catalog includes ad.lockout."

    $runBody = ('{{"targetAddress":"localhost","port":"{0}"}}' -f $port)
    $updatedCase = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/checks/network.quick/run" -Body $runBody -ContentType "application/json" -Headers $headers -TimeoutSec 120
    $lastCheck = @($updatedCase.Checks)[-1]
    Assert-True -Condition ($lastCheck.CheckId -eq "network.quick") -Message "Check run is recorded on the case."
    Assert-True -Condition ($null -ne $lastCheck.InputsUsed) -Message "Check result records the inputs used."
    Assert-True -Condition ([string]$lastCheck.InputsUsed.TargetAddress -eq "localhost") -Message "InputsUsed captures the target address."

    $noteCase = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/notes" -Body '{"note":"User reports slow logins."}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition (@($noteCase.Notes).Count -eq 1) -Message "Note is stored on the case."

    $notes = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/generate-notes" -Body '{}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition ($notes.markdown -match 'Ran Network Quick Check \(') -Message "Generated notes include the check inputs."
    Assert-True -Condition ($notes.markdown -notmatch '- Target path:\s*$') -Message "Generated notes omit blank case fields."

    $export = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/cases/$($case.CaseId)/export" -Body '{}' -ContentType "application/json" -Headers $headers
    Assert-True -Condition (Test-Path -LiteralPath $export.MarkdownPath) -Message "Export writes ticket-notes.md."
    Assert-True -Condition (Test-Path -LiteralPath $export.ReportPath) -Message "Export writes report.html."
    Assert-True -Condition (Test-Path -LiteralPath $export.EvidencePath) -Message "Export writes evidence.json."
}
finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
    throw ("API integration tests failed: {0}" -f ($script:Failures -join "; "))
}

Write-Host "[PASS] API integration tests completed." -ForegroundColor Green
```

- [ ] **Step 2: Run the integration test**

Run: `powershell -NoProfile -File "MSP-TroubleshootingWorkbench\tests\Workbench.Api.Tests.ps1"`
Expected: all `[PASS]`. If the 403 assertion fails, Task 4's gate isn't wired; if `InputsUsed` fails, Task 3's stamping isn't wired.

- [ ] **Step 3: Rewrite the README**

Replace `MSP-TroubleshootingWorkbench/README.md` with:

```markdown
# MSP Troubleshooting Workbench

Portable, browser-based troubleshooting case workbench for MSP Windows support. Create a case per ticket, run read-only diagnostic checks against servers and desktops, capture notes, and generate ready-to-paste ticket notes.

## Quick Start

```powershell
# Preferred: double-click or run the launcher
.\MSPWorkbench.exe

# Or run the entry point directly (elevate when checks need admin rights)
.\Start-MSPTroubleshootingWorkbench.ps1
```

The workbench opens at `http://localhost:8275/` (change with `-Port`). All data stays local: cases in `cases\`, exports in `exports\`, logs in `logs\`. Use `-OutputPath` to point data at another folder. Stop the server with Ctrl+C.

## Workflow

1. **Create a case** — client, ticket number, issue type, plus optional user/device/path/address context.
2. **Run checks** — pick a check, fill in its inputs (prefilled from the case), run it. Results, evidence, and recommended next steps land on the case.
3. **Add notes** — record anything you observed or did manually.
4. **Generate Notes** — builds structured ticket notes (Issue / Actions Taken / Findings / Evidence / Likely Cause / Next Steps / Customer-Facing Summary). Copy to clipboard and paste into your PSA.
5. **Export Evidence** — writes `ticket-notes.md`, `report.html`, and `evidence.json` to `exports\<CaseId>\`.

## Checks

Checks are standalone scripts in `checks\` declared in `checks\manifest.json` (`checkId`, `name`, `category`, `script`, `description`, `readOnly`, `inputs`, `timeoutSeconds`). All bundled checks are read-only.

| Check | Inputs | Notes |
|---|---|---|
| Network Quick Check (`network.quick`) | address, port | Ping, DNS, TCP port, default route. Runs from this workstation. |
| AD Lockout Diagnostics (`ad.lockout`) | user, days back, domain controller(s) | Wraps `..\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1`. Needs RSAT AD module, domain connectivity, and rights to read DC Security logs. HTML report path is included in the evidence. |
| Citrix/FSLogix Triage (`citrix.fslogix.triage`) | device, user | Service state, FSLogix registry, recent FSLogix/TS events, disk space, profile path reachability on the target host. Blocked remote access degrades to Warn evidence. |

### Adding a check

Drop a script into `checks\` that returns the shared result object (`CheckId, Name, Category, Status [Pass|Warn|Fail], Summary, Evidence[], RecommendedNextSteps[], RawOutput, StartedAt, FinishedAt, Error`) and add a manifest entry. Keep checks read-only.

## Portability

Copy the whole repository, not just this folder — `ad.lockout` calls `..\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1` relative to the repo root. If the diagnostics script is missing, the check degrades to a Warn result instead of failing.

To rebuild `MSPWorkbench.exe` on a workstation with a .NET Framework C# compiler:

```powershell
.\launcher\build.ps1
```

## Security

The server listens on localhost only. POST endpoints require a per-session token injected into the served page, so other websites open in your browser cannot drive the API. No authentication beyond that — do not expose the port off-machine.

## Tests

```powershell
Get-ChildItem .\tests\*.Tests.ps1 | ForEach-Object { powershell -NoProfile -File $_.FullName }
```

`Workbench.Api.Tests.ps1` boots a real server on a random port and exercises the full case lifecycle.
```

- [ ] **Step 4: Run every test file one last time**

Run: `powershell -NoProfile -Command "Get-ChildItem 'MSP-TroubleshootingWorkbench\tests\*.Tests.ps1' | ForEach-Object { Write-Host ('=== ' + $_.Name); powershell -NoProfile -File $_.FullName; if ($LASTEXITCODE -ne 0) { throw $_.Name } }"`
Expected: every file passes.

- [ ] **Step 5: Commit**

```bash
git add MSP-TroubleshootingWorkbench/tests/Workbench.Api.Tests.ps1 MSP-TroubleshootingWorkbench/README.md
git commit -m "test: end-to-end API lifecycle test; docs: rewrite workbench README"
```

---

## Future Work (explicitly out of scope for this plan)

Documented so the implementer doesn't scope-creep into them:

- **Async check execution** — the server is single-threaded; a long check freezes the UI until it finishes. The right fix is a run-queue (POST returns a run id, UI polls) or a runspace-pool listener. Sizeable change; do it as its own plan.
- **Case management** — archive/delete cases, search/filter the case list, log rotation for `logs/`.
- **network.quick severity tuning** — a closed TCP port always yields overall `Fail` even when the port was a default (443) nobody asked about; consider making the port test optional or downgrading to Warn when the port input was not user-supplied.
- **PSA integration** — pushing generated notes directly to ConnectWise/Autotask instead of clipboard.
- **Vendoring `AD-LockoutDiagnostics`** into the workbench folder for true single-folder portability.
- **Replacing the Task4–Task9 source-regex tests** with behavioral equivalents now that LibraryMode + the API harness exist.
