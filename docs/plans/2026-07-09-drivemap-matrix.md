# Drive Map Matrix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an interactive Group x Drive-Letter matrix (expandable to AD users) to the GPO drive-map audit report, rendered as a self-contained, JSON-driven, vanilla-JS HTML section with color-coded cells that surface unreachable targets and group overlaps.

**Architecture:** A new pure PowerShell function `Build-DriveMapMatrix` pivots the already-extracted `$AllDriveMaps` (plus existing `PathValidation` and resolved AD membership) into a structured object. That object is serialized to JSON, embedded in the existing HTML report inside a new `<script>` block, and rendered client-side by inline vanilla JS (sort/filter/search/expand). No new GPO parsing, no external libraries, no build step.

**Tech Stack:** Windows PowerShell 5.1, Pester (existing repo test convention), `ConvertTo-Json`, inline HTML/CSS/JS. ASCII-only source (PS 5.1 reads BOM-less .ps1 as ANSI).

**Reference:** Design doc `docs/plans/2026-07-09-drivemap-matrix-design.md`. Target script `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1`.

---

## Task 0: Make the script testable (`-LoadFunctionsOnly` guard)

Mirrors the repo convention in `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`
(switch param + guarded invocation) so Pester can dot-source the script and call
functions without running the full audit.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (param block ~line 90-95; tail ~line 1998)
- Create: `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`

**Step 1: Add the switch parameter**

In the `param()` block, after `[switch]$CheckGroupOverlap`:

```powershell
    [Parameter()]
    [switch]$CheckGroupOverlap,

    [Parameter()]
    [switch]$LoadFunctionsOnly
)
```

**Step 2: Guard the invocation**

Replace the tail:

```powershell
# Run the audit
if (-not $LoadFunctionsOnly) {
    $results = Start-DriveMapAudit
}
#endregion
```

**Step 3: Write the smoke test**

Create `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Audit-GPDriveMaps.ps1" -LoadFunctionsOnly
}

Describe 'Script loads functions only' {
    It 'exposes Build-DriveMapMatrix once implemented' -Skip {
        Get-Command Build-DriveMapMatrix | Should -Not -BeNullOrEmpty
    }
    It 'does not run the audit on dot-source' {
        # If the guard failed, dot-sourcing would have thrown (no domain here).
        $true | Should -BeTrue
    }
}
```

**Step 4: Run and verify it passes**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: PASS (1 skipped). Dot-source must not throw.

**Step 5: Commit**

```bash
git add AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1 AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1
git commit -m "test: add -LoadFunctionsOnly guard so drive-map functions are testable"
```

---

## Task 1: `Build-DriveMapMatrix` - group pivot (no status yet)

Pure function that pivots `$AllDriveMaps` into groups x letters. Start with structure
and cell paths; status colors come in Task 2.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (new function in a new
  `#region Matrix` after the conflict/stale-host region, ~line 815)
- Test: `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`

**Step 1: Write the failing test**

```powershell
Describe 'Build-DriveMapMatrix - group pivot' {
    BeforeAll {
        function New-M { param($GPO,$Action,$Letter,$Path,$Groups)
            $ilt = @($Groups | ForEach-Object { [PSCustomObject]@{ Type='FilterGroup'; Not=$false; Bool='AND'; Detail="Group IS '$_'" } })
            $an = switch ($Action) { 'C'{'Create'} 'D'{'Delete'} default{$Action} }
            [PSCustomObject]@{ GPOName=$GPO; ActionName=$an; DriveLetter=$Letter; UNCPath=$Path
                ILTSummary='x'; ILTFilters=$ilt; Configuration='User' } }
    }
    It 'pivots one group/one letter into a cell' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        $m.letters | Should -Contain 'M'
        ($m.groups | Where-Object name -eq 'Fire').cells.M[0].path | Should -Be '\\srv\fire'
    }
    It 'puts no-ILT mappings under the (all users) row' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'S' '\\srv\scratch' @()))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq '(all users)').cells.S[0].path | Should -Be '\\srv\scratch'
    }
}
```

**Step 2: Run to verify it fails**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: FAIL - "The term 'Build-DriveMapMatrix' is not recognized".

**Step 3: Implement the pivot**

Add to a new `#region Matrix`:

```powershell
#region Matrix
function Build-DriveMapMatrix {
    param(
        [System.Collections.Generic.List[object]]$DriveMaps,
        [array]$PathValidation = @(),
        [array]$GroupOverlap = @()
    )

    # Column axis: distinct real drive letters, sorted.
    $letters = @($DriveMaps | Where-Object {
        $_.DriveLetter -and $_.DriveLetter.Trim() -ne '' -and $_.DriveLetter -ne 'NOCHANGE'
    } | Select-Object -ExpandProperty DriveLetter -Unique | Sort-Object)

    # Extract positive (non-NOT) ILT group names from a mapping; empty => (all users).
    $groupsForMap = {
        param($m)
        $g = @($m.ILTFilters | Where-Object { $_.Type -eq 'FilterGroup' -and -not $_.Not } |
            ForEach-Object { if ($_.Detail -match "'(.+)'") { $Matches[1] } }) | Where-Object { $_ }
        if ($g.Count -eq 0) { @('(all users)') } else { $g }
    }

    # rowName -> ( letter -> list of cell entries )
    $rows = @{}
    foreach ($map in $DriveMaps) {
        if (-not $map.DriveLetter -or $map.DriveLetter.Trim() -eq '' -or $map.DriveLetter -eq 'NOCHANGE') { continue }
        foreach ($gName in (& $groupsForMap $map)) {
            if (-not $rows.ContainsKey($gName)) { $rows[$gName] = @{} }
            $letter = $map.DriveLetter
            if (-not $rows[$gName].ContainsKey($letter)) {
                $rows[$gName][$letter] = [System.Collections.Generic.List[object]]::new()
            }
            $rows[$gName][$letter].Add([PSCustomObject]@{
                path   = $map.UNCPath
                gpo    = $map.GPOName
                action = $map.ActionName
                status = 'ok'   # refined in Task 2
            })
        }
    }

    $groupObjs = foreach ($name in ($rows.Keys | Sort-Object)) {
        [PSCustomObject]@{
            name  = $name
            cells = $rows[$name]
        }
    }

    return [PSCustomObject]@{
        letters     = $letters
        groups      = @($groupObjs)
        hasUserData = $false
    }
}
#endregion
```

**Step 4: Run to verify it passes**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: PASS (remove `-Skip` from the Task-0 command test).

**Step 5: Commit**

```bash
git add AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1 AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1
git commit -m "feat: add Build-DriveMapMatrix group/letter pivot"
```

---

## Task 2: Cell status computation

Color status per cell from data already computed: unreachable (path failed validation),
overlap (letter shared across groups OR same group has 2+ paths for the letter),
remove (Delete action), else ok.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (`Build-DriveMapMatrix`)
- Test: `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`

**Step 1: Write the failing tests**

```powershell
Describe 'Build-DriveMapMatrix - cell status' {
    It 'marks a cell unreachable when its path failed validation' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'O' '\\dead\o' @('Grp')))
        $pv = @([PSCustomObject]@{ UNCPath='\\dead\o'; Reachable=$false })
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation $pv -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'Grp').cells.O[0].status | Should -Be 'unreachable'
    }
    It 'marks a cell remove for Delete actions' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'D' 'M' '\\srv\x' @('Grp')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'Grp').cells.M[0].status | Should -Be 'remove'
    }
    It 'marks overlap when a group has 2 paths for one letter' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'Z' '\\a\z' @('Staff')))
        $maps.Add((New-M 'G2' 'C' 'Z' '\\b\z' @('Staff')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        $cellz = ($m.groups | Where-Object name -eq 'Staff').cells.Z
        $cellz.Count | Should -Be 2
        ($cellz | Where-Object { $_.status -eq 'overlap' }).Count | Should -Be 2
    }
    It 'marks overlap when two different groups share a letter' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'Z' '\\a\z' @('HR')))
        $maps.Add((New-M 'G2' 'C' 'Z' '\\b\z' @('Finance')))
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()
        ($m.groups | Where-Object name -eq 'HR').cells.Z[0].status | Should -Be 'overlap'
        ($m.groups | Where-Object name -eq 'Finance').cells.Z[0].status | Should -Be 'overlap'
    }
}
```

**Step 2: Run to verify they fail**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: FAIL (statuses currently hard-coded to 'ok').

**Step 3: Implement status logic**

Before building `$rows`, precompute:
- A path->reachable lookup from `$PathValidation` (case-insensitive), matching the
  `Find-DriveMapConflicts` pattern.
- The set of letters that are "shared" - letters whose **distinct competing (non-Delete)
  UNC paths** number > 1 across ALL groups (this covers both cross-group and same-group
  multi-path).

Then set each entry's `status`:
```powershell
$status = if ($entry.action -eq 'Delete') { 'remove' }
          elseif ($reachableByPath.ContainsKey($path.ToLower()) -and -not $reachableByPath[$path.ToLower()]) { 'unreachable' }
          elseif ($sharedLetters.Contains($letter)) { 'overlap' }
          else { 'ok' }
```
Compute `$sharedLetters` as: group all non-Delete maps by `DriveLetter`, keep letters
with >1 distinct `UNCPath`.

**Step 4: Run to verify they pass**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: PASS (all).

**Step 5: Commit**

```bash
git commit -am "feat: compute matrix cell status (unreachable/overlap/remove/ok)"
```

---

## Task 3: User rows from resolved AD membership

Attach `users` to each group row when membership is available, and set `hasUserData`.
Reuse the cached membership resolution from `Find-GroupMembershipOverlap`.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (extract a shared
  `Resolve-GroupMembersCached` helper used by both overlap and matrix; add optional
  `-GroupMembers` hashtable param to `Build-DriveMapMatrix`)
- Test: `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`

**Step 1: Write the failing test** (inject a fake membership map - no live AD)

```powershell
Describe 'Build-DriveMapMatrix - user rows' {
    It 'attaches members and sets hasUserData when membership provided' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        $members = @{ 'Fire' = @('jsmith','adoe') }
        $m = Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @() -GroupMembers $members
        $m.hasUserData | Should -BeTrue
        ($m.groups | Where-Object name -eq 'Fire').users | Should -Contain 'jsmith'
    }
    It 'leaves hasUserData false when no membership provided' {
        $maps = [System.Collections.Generic.List[object]]::new()
        $maps.Add((New-M 'G1' 'C' 'M' '\\srv\fire' @('Fire')))
        (Build-DriveMapMatrix -DriveMaps $maps -PathValidation @() -GroupOverlap @()).hasUserData | Should -BeFalse
    }
}
```

**Step 2: Run to verify it fails.** Expected: FAIL (no `-GroupMembers` param).

**Step 3: Implement** - add `[hashtable]$GroupMembers = @{}` param; when non-empty,
set `hasUserData=$true` and attach `users = @($GroupMembers[$name])` per group row (empty
array if the row is `(all users)` or has no entry).

**Step 4: Run to verify it passes.** Expected: PASS.

**Step 5: Commit** `git commit -am "feat: add user rows to matrix from resolved AD membership"`

---

## Task 4: JSON embedding + HTML section + TOC entry

Wire the matrix into the report: call `Build-DriveMapMatrix` in the main flow, serialize
to JSON, embed in a new `<div class="section" id="matrix">`, add TOC link.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (main flow ~line 1810;
  `Export-HTMLReport` TOC ~line 1505 and section insertion before `#allmappings`)

**Step 1** (manual verification task - no unit test; verified in Task 6 render test):

Main flow, after stale-host/overlap computation:
```powershell
$matrixMembers = if ($CheckGroupOverlap) { $script:__groupMemberCache } else { @{} }
$auditResults.Matrix = Build-DriveMapMatrix -DriveMaps $auditResults.AllDriveMaps `
    -PathValidation @($auditResults.PathValidation) -GroupOverlap @($auditResults.GroupOverlap) `
    -GroupMembers $matrixMembers
```
(Refactor `Find-GroupMembershipOverlap` to store its member cache in
`$script:__groupMemberCache` so the matrix reuses it - single AD resolution.)

Add to `$auditResults` initializer: `Matrix = $null`.

**Step 2:** In `Export-HTMLReport`, add TOC entry:
```powershell
<li><a href="#matrix">Who Gets What (Matrix)</a></li>
```

**Step 3:** Insert the section before `#allmappings`. The JSON goes in a script tag:
```powershell
"<div class='section' id='matrix'>
    <h2>Who Gets What - Drive Map Matrix</h2>
    <div id='matrix-toolbar'></div>
    <div id='matrix-grid'></div>
    <script id='matrix-data' type='application/json'>$(($AuditResults.Matrix | ConvertTo-Json -Depth 8 -Compress))</script>
</div>"
```
Note: `ConvertTo-Json` output is placed inside a `type="application/json"` script block
(not executed), so `<`/`&` in UNC paths are safe; the JS reads it via
`JSON.parse(document.getElementById('matrix-data').textContent)`.

**Step 4:** Verify the report still generates without error using a mock (Task 6 covers
the render). For now:

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: PASS (existing tests unaffected).

**Step 5: Commit** `git commit -am "feat: embed matrix JSON and add matrix report section"`

---

## Task 5: Inline vanilla-JS renderer (sort/filter/search/expand/view toggle)

Add the client-side script that reads the JSON and renders the interactive grid.

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (`Export-HTMLReport` - add
  a `<style>` block for matrix classes and a `<script>` renderer before `</body>`)

**Step 1-3:** Implement (no PS unit test - validated by the render harness in Task 6).
The JS must:
- `JSON.parse` the embedded data.
- Render a table: sticky first column (name) + sticky header row (letters).
- Cell = short share name (last path segment), `title`=full path; stacked entries for
  multi-path cells; class per status (`m-ok`,`m-unreachable`,`m-overlap`,`m-remove`).
- Toolbar: text search (filter rows by name), letter checkboxes (show/hide columns),
  "Problems only" toggle, Groups/Users view toggle (disabled when `!hasUserData`, with
  note), per-row expander to show member users.
- Column-header click sorts by that letter's worst status (problems first); name-header
  click sorts alphabetically.
- User view caps initial render at 500 rows with "N more - refine with search" notice.

CSS classes (add near existing badges): `.m-ok{background:#eafaf1}` green,
`.m-unreachable{background:#fdf2f2;color:#c0392b}` red, `.m-overlap{background:#fef5e7}`
amber, `.m-remove{background:#f4f6f6;color:#7f8c8d}` grey. Reuse `position: sticky`.

**Step 4:** Manual smoke: generate a report from a fixture (Task 6) and open it.

**Step 5: Commit** `git commit -am "feat: add interactive vanilla-JS matrix renderer"`

---

## Task 6: End-to-end render fixture test

Prove the whole path produces valid, self-contained HTML from a realistic fixture,
without a live domain.

**Files:**
- Test: `AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`

**Step 1: Write the test** - build a fixture `$auditResults` with a few groups/letters
(including an overlap on Z: and an unreachable O:), call `Export-HTMLReport` to a temp
file, then assert:

```powershell
Describe 'Matrix renders into self-contained HTML' {
    It 'embeds parseable JSON and references no external hosts' {
        # ...build fixture $auditResults incl. .Matrix from Build-DriveMapMatrix...
        $out = Join-Path $TestDrive 'r.html'
        Export-HTMLReport -AuditResults $auditResults -OutputFile $out
        $html = Get-Content $out -Raw
        $html | Should -Match 'id=.matrix-data.'
        $html | Should -Not -Match 'https?://(?!www\.w3\.org)'   # no external hosts except doctype ns
        # extract JSON and ensure it parses
        $json = [regex]::Match($html, "(?s)matrix-data[^>]*>(.*?)</script>").Groups[1].Value
        { $json | ConvertFrom-Json } | Should -Not -Throw
    }
}
```

**Step 2: Run to verify it fails** (if any wiring is off). **Step 3:** Fix wiring.
**Step 4: Run to verify it passes.**

Run: `Invoke-Pester -Path AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1`
Expected: PASS (all describes).

**Step 5: Commit** `git commit -am "test: end-to-end matrix render into self-contained HTML"`

---

## Task 7: ASCII + parse validation, README, CSV companion

**Files:**
- Modify: `AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1` (CSV export ~line 1780),
  `AD-GroupPolicy-DriveMaps/README.md`

**Step 1:** Add `*-Matrix.csv` export (rows=groups, cols=letters, cell=joined paths or
blank) in `Export-CSVReports`.

**Step 2:** ASCII check:
Run: `perl -ne '$n+=()=/[^\x00-\x7F]/g;END{print "$n\n"}' AD-GroupPolicy-DriveMaps/Audit-GPDriveMaps.ps1`
Expected: `0`. Fix any non-ASCII (em dashes/arrows) introduced.

**Step 3:** Full parse check:
Run PowerShell `[Parser]::ParseFile(...)` on the script.
Expected: `CLEAN`.

**Step 4:** Update README: add "Who Gets What (Matrix)" to Features and `*-Matrix.csv` to
Output Files.

**Step 5: Commit** `git commit -am "docs: document drive-map matrix; add Matrix CSV; ascii/parse verified"`

---

## Definition of Done

- `Invoke-Pester AD-GroupPolicy-DriveMaps/Tests/Audit-GPDriveMaps.Tests.ps1` all green.
- Script is ASCII-only and parses clean.
- Report opens in a browser and shows an interactive matrix; group view works with no AD
  data, user view/expand works when `-CheckGroupOverlap` was used.
- No external hosts referenced (self-contained).
- README updated.
