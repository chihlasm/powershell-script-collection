# FolderPermissionManager GUI v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add file-level ACL inspection and batch file operations to FolderPermissionManager-GUI.ps1, and rewrite the frontend around a context-aware 2-panel layout.

**Architecture:** The PowerShell HTTP backend is extended with five new API endpoint functions inserted before the route dispatcher, and the route dispatcher switch gains five new cases. The embedded HTML/JS here-string (lines 755–2527) is replaced wholesale with a rewritten frontend that implements the context-aware layout — folder ACL section stacked above a file list with checkboxes, sticky batch action bar, and inline ACL expansion per file. All existing backend functions are untouched.

**Tech Stack:** PowerShell 5.1, .NET `System.Security.AccessControl`, `System.Net.HttpListener`, vanilla HTML/CSS/JS (no frameworks — matches existing code), `takeown.exe`, `icacls.exe`, `robocopy.exe`

---

## File Map

| File | Change |
| --- | --- |
| `FolderPermissionManager/FolderPermissionManager-GUI.ps1` | Add 5 backend functions (~lines 668–711), add 5 route cases (~lines 724–736), replace HTML here-string (~lines 755–2527) |

One file. All changes are additive on the backend; the frontend is a full rewrite of the here-string block.

---

## Task 1: Add `Get-FileAcl` endpoint function

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — insert after line 552 (after `Invoke-ExportReport` ends), before the `Invoke-Robocopy` function

- [ ] **Step 1: Insert `Get-FileAcl` function**

Insert the following block immediately after the closing `}` of `Invoke-ExportReport` (around line 552) and before `function Invoke-Robocopy`:

```powershell
function Get-FileAcl {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $filePath = Resolve-MappedDrive $Request.QueryString['path']
    if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    try {
        $acl = Get-Acl -Path $filePath -ErrorAction Stop
        $entries = @($acl.Access | ForEach-Object {
            [PSCustomObject]@{
                identity         = $_.IdentityReference.ToString()
                rights           = $_.FileSystemRights.ToString()
                type             = $_.AccessControlType.ToString()
                isInherited      = $_.IsInherited
                inheritanceFlags = $_.InheritanceFlags.ToString()
                propagationFlags = $_.PropagationFlags.ToString()
            }
        })
        $result = [PSCustomObject]@{
            path                    = $filePath
            owner                   = $acl.Owner
            areAccessRulesProtected = $acl.AreAccessRulesProtected
            entries                 = $entries
        }
        Send-Json $Response $result
    }
    catch [System.UnauthorizedAccessException] {
        $Response.StatusCode = 403
        Send-Json $Response @{ error = "Access denied to '$filePath'. Try taking ownership first." }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to read ACL: $($_.Exception.Message)" }
    }
}
```

- [ ] **Step 2: Verify the script still parses**

```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output (empty `$errors`).

- [ ] **Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): add Get-FileAcl endpoint function"
```

---

## Task 2: Add `Invoke-AddFileAce` and `Invoke-RemoveFileAce` endpoint functions

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — insert after `Get-FileAcl`

- [ ] **Step 1: Insert `Invoke-AddFileAce` function**

Insert immediately after the closing `}` of `Get-FileAcl`:

```powershell
function Invoke-AddFileAce {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body     = Read-RequestBody $Request
    $paths    = @($body.paths)
    $identity = $body.identity
    $rights   = $body.rights
    $type     = $body.type

    if (-not $paths -or $paths.Count -eq 0 -or -not $identity -or -not $rights) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing required fields: paths, identity, rights" }
        return
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($rawPath in $paths) {
        $filePath = Resolve-MappedDrive $rawPath
        if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) {
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = 'Path not found or not a file' })
            continue
        }
        try {
            $acl        = Get-Acl -Path $filePath -ErrorAction Stop
            $accessType = if ($type -eq 'Deny') { [System.Security.AccessControl.AccessControlType]::Deny } else { [System.Security.AccessControl.AccessControlType]::Allow }
            $fileRights = [System.Security.AccessControl.FileSystemRights]$rights
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
            $propagation = [System.Security.AccessControl.PropagationFlags]::None
            $account    = [System.Security.Principal.NTAccount]::new($identity)
            $rule       = [System.Security.AccessControl.FileSystemAccessRule]::new($account, $fileRights, $inheritance, $propagation, $accessType)
            $acl.AddAccessRule($rule)
            Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'success'; message = "Added $type $rights for $identity" })
        }
        catch {
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}
```

Note: files use `InheritanceFlags::None` and `PropagationFlags::None` — inheritance flags only apply to containers (folders), not leaf files.

- [ ] **Step 2: Insert `Invoke-RemoveFileAce` function**

Insert immediately after the closing `}` of `Invoke-AddFileAce`:

```powershell
function Invoke-RemoveFileAce {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body     = Read-RequestBody $Request
    $paths    = @($body.paths)
    $identity = $body.identity
    $rights   = $body.rights
    $type     = $body.type

    if (-not $paths -or $paths.Count -eq 0 -or -not $identity -or -not $rights) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing required fields: paths, identity, rights" }
        return
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($rawPath in $paths) {
        $filePath = Resolve-MappedDrive $rawPath
        if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) {
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = 'Path not found or not a file' })
            continue
        }
        try {
            $acl        = Get-Acl -Path $filePath -ErrorAction Stop
            $accessType = if ($type -eq 'Deny') { [System.Security.AccessControl.AccessControlType]::Deny } else { [System.Security.AccessControl.AccessControlType]::Allow }
            $fileRights = [System.Security.AccessControl.FileSystemRights]$rights
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
            $propagation = [System.Security.AccessControl.PropagationFlags]::None
            $account    = [System.Security.Principal.NTAccount]::new($identity)
            $rule       = [System.Security.AccessControl.FileSystemAccessRule]::new($account, $fileRights, $inheritance, $propagation, $accessType)
            $acl.RemoveAccessRuleAll($rule)
            Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'success'; message = "Removed $type $rights for $identity" })
        }
        catch {
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}
```

- [ ] **Step 3: Verify the script still parses**

```powershell
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): add Invoke-AddFileAce and Invoke-RemoveFileAce endpoint functions"
```

---

## Task 3: Add `Invoke-TakeFileOwnership` endpoint function

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — insert after `Invoke-RemoveFileAce`

- [ ] **Step 1: Insert `Invoke-TakeFileOwnership` function**

Insert immediately after the closing `}` of `Invoke-RemoveFileAce`:

```powershell
function Invoke-TakeFileOwnership {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body  = Read-RequestBody $Request
    $paths = @($body.paths)

    if (-not $paths -or $paths.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing required field: paths" }
        return
    }

    # Resolve the current identity once — $env:USERNAME is unreliable under SYSTEM/service accounts
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $ownerAccount    = [System.Security.Principal.NTAccount]::new($currentIdentity)

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($rawPath in $paths) {
        $filePath = Resolve-MappedDrive $rawPath
        if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) {
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = 'Path not found or not a file' })
            continue
        }
        try {
            # takeown forces OS-level ownership grant (uses SE_TAKE_OWNERSHIP privilege)
            $takeownOutput = takeown /F $filePath /A /D Y 2>&1
            # Then set owner via .NET ACL API — same pattern as folder ownership in Invoke-TakeOwnership
            $acl = Get-Acl -Path $filePath -ErrorAction Stop
            $acl.SetOwner($ownerAccount)
            Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'success'; message = "Ownership taken by $currentIdentity" })
        }
        catch {
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}
```

- [ ] **Step 2: Verify the script still parses**

```powershell
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): add Invoke-TakeFileOwnership endpoint function"
```

---

## Task 4: Add `Invoke-RobocopyFiles` endpoint function

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — insert after `Invoke-TakeFileOwnership`, before the route dispatcher

- [ ] **Step 1: Insert `Invoke-RobocopyFiles` function**

Insert immediately after the closing `}` of `Invoke-TakeFileOwnership`:

```powershell
function Invoke-RobocopyFiles {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body       = Read-RequestBody $Request
    $sourceDir  = Resolve-MappedDrive $body.sourceDir
    $destDir    = Resolve-MappedDrive $body.destDir
    $files      = @($body.files)
    $extraFlags = $body.extraFlags

    # Explicit rejection — empty files[] must never fall through to a full directory copy
    if (-not $files -or $files.Count -eq 0) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "files[] must not be empty" }
        return
    }

    if (-not $sourceDir -or -not (Test-Path $sourceDir -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing sourceDir" }
        return
    }

    if (-not $destDir) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing destDir" }
        return
    }

    # Validate each file exists as a leaf before invoking robocopy
    $invalidFiles = $files | Where-Object { -not (Test-Path (Join-Path $sourceDir $_) -PathType Leaf) }
    if ($invalidFiles) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Files not found in sourceDir: $($invalidFiles -join ', ')" }
        return
    }

    # Build robocopy args
    # /COPY:DATSO = Data, Attributes, Timestamps, Security (ACLs), Owner info
    # /COPY:U (auditing) is intentionally excluded — requires SeSecurityPrivilege (Backup Operator+)
    # which is not guaranteed in standard MSP environments and causes silent partial failures.
    # /SECFIX is required for file copies — without it robocopy skips ACL copying on unchanged files
    $roboArgs = [System.Collections.Generic.List[string]]::new()
    $roboArgs.Add("`"$sourceDir`"")
    $roboArgs.Add("`"$destDir`"")
    foreach ($f in $files) { $roboArgs.Add("`"$f`"") }
    $roboArgs.Add('/COPY:DATSO')
    $roboArgs.Add('/SECFIX')
    $roboArgs.Add('/ZB')
    $roboArgs.Add('/NP')
    $roboArgs.Add('/R:3')
    $roboArgs.Add('/W:5')
    if ($extraFlags) { $roboArgs.Add($extraFlags) }

    $cmdLine = "robocopy $($roboArgs -join ' ')"

    try {
        $output   = robocopy $sourceDir $destDir $files /COPY:DATSO /SECFIX /ZB /NP /R:3 /W:5 2>&1
        $exitCode = $LASTEXITCODE
        $success  = $exitCode -lt 8

        $message = switch ($exitCode) {
            0  { 'No files copied — source and destination are identical' }
            1  { 'Files copied successfully' }
            2  { 'Extra files detected in destination' }
            3  { 'Files copied + extra files detected' }
            4  { 'Mismatched files detected' }
            5  { 'Files copied + mismatched files' }
            6  { 'Extra and mismatched files detected' }
            7  { 'Files copied + extra + mismatched' }
            8  { 'Some files could not be copied (errors occurred)' }
            16 { 'Fatal error — no files were copied' }
            default { "Exit code $exitCode" }
        }

        if (-not $success) { $Response.StatusCode = 500 }
        Send-Json $Response @{
            success  = $success
            exitCode = $exitCode
            message  = $message
            command  = $cmdLine
            output   = ($output | Out-String).Trim()
        }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Robocopy failed: $($_.Exception.Message)"; command = $cmdLine }
    }
}
```

- [ ] **Step 2: Verify the script still parses**

```powershell
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): add Invoke-RobocopyFiles endpoint function"
```

---

## Task 5: Wire new endpoints into the route dispatcher

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — the `switch` block inside `Invoke-Route` (~line 724)

- [ ] **Step 1: Add five new route cases to the dispatcher**

In the `switch -Regex` block inside `Invoke-Route`, add the five new cases after the existing `'^GET /api/robocopy-preview$'` line and before the `default` case:

```powershell
'^GET /api/file-acl$'                { Get-FileAcl $request $response }
'^POST /api/file-acl/add$'           { Invoke-AddFileAce $request $response }
'^POST /api/file-acl/remove$'        { Invoke-RemoveFileAce $request $response }
'^POST /api/file-acl/take-ownership$' { Invoke-TakeFileOwnership $request $response }
'^POST /api/robocopy-files$'         { Invoke-RobocopyFiles $request $response }
```

The dispatcher block should now look like:

```powershell
switch -Regex ("$method $path") {
    '^GET /$'                              { Send-Html $response }
    '^GET /api/drives$'                    { Get-Drives $response }
    '^GET /api/children$'                  { Get-Children $request $response }
    '^GET /api/files$'                     { Get-Files $request $response }
    '^GET /api/acl$'                       { Get-FolderAcl $request $response }
    '^POST /api/take-ownership$'           { Invoke-TakeOwnership $request $response }
    '^POST /api/replicate$'                { Invoke-ReplicatePermissions $request $response }
    '^POST /api/add-ace$'                  { Invoke-AddAce $request $response }
    '^POST /api/remove-ace$'               { Invoke-RemoveAce $request $response }
    '^GET /api/export$'                    { Invoke-ExportReport $request $response }
    '^POST /api/robocopy$'                 { Invoke-Robocopy $request $response }
    '^GET /api/robocopy-preview$'          { Get-RobocopyPreview $request $response }
    '^GET /api/file-acl$'                  { Get-FileAcl $request $response }
    '^POST /api/file-acl/add$'             { Invoke-AddFileAce $request $response }
    '^POST /api/file-acl/remove$'          { Invoke-RemoveFileAce $request $response }
    '^POST /api/file-acl/take-ownership$'  { Invoke-TakeFileOwnership $request $response }
    '^POST /api/robocopy-files$'           { Invoke-RobocopyFiles $request $response }
    '^GET /api/shutdown$'                  {
        Send-Json $response @{ status = 'shutting down' }
        $script:running = $false
    }
    default {
        $response.StatusCode = 404
        Send-Json $response @{ error = 'Not found' }
    }
}
```

- [ ] **Step 2: Verify the script still parses**

```powershell
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 3: Smoke-test the backend manually**

Start the server in a separate PowerShell window:
```powershell
.\FolderPermissionManager\FolderPermissionManager-GUI.ps1 -NoBrowserOpen
```

In another window, test that new routes respond (not 404):
```powershell
# Should return 400 (missing path), not 404
Invoke-RestMethod 'http://localhost:8271/api/file-acl' -ErrorAction SilentlyContinue
# Should return 400 (missing fields), not 404
Invoke-RestMethod 'http://localhost:8271/api/file-acl/add' -Method Post -ContentType 'application/json' -Body '{}' -ErrorAction SilentlyContinue
```

Expected: both return `{ error: "..." }` with status 400, not 404.

- [ ] **Step 4: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): wire new file ACL and robocopy-files routes into dispatcher"
```

---

## Task 6: Rewrite the frontend HTML/JS — layout skeleton and folder ACL section

**Context:** The entire `$script:htmlContent = @"..."@` here-string (lines ~755–2527) is replaced. This task writes the skeleton + folder ACL section. Tasks 7–9 build on it incrementally. Work in a scratch copy if desired, then paste the final result.

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` — replace the `$script:htmlContent` here-string

- [ ] **Step 1: Replace the here-string with the new frontend skeleton + folder ACL section**

Replace everything from `$script:htmlContent = @"` through the closing `"@` (lines ~755–2527) with the following. This establishes the 2-panel layout, drive/folder tree (left panel), and folder ACL section (right panel top) — identical behavior to v1 but in the new structure:

```powershell
$script:htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Folder Permission Manager</title>
<style>
:root {
    --bg: #1a1d23;
    --bg-card: #23272e;
    --bg-hover: #2a2f38;
    --bg-input: #1e2229;
    --text: #e0e0e0;
    --text-muted: #8b95a5;
    --accent: #5dade2;
    --accent-hover: #4a9bd4;
    --border: #333a45;
    --success: #2ecc71;
    --warning: #f39c12;
    --danger: #e74c3c;
    --danger-hover: #c0392b;
    --shadow: rgba(0,0,0,0.3);
}
body.light {
    --bg: #f5f5f5;
    --bg-card: #ffffff;
    --bg-hover: #e8ecf0;
    --bg-input: #ffffff;
    --text: #2c3e50;
    --text-muted: #7f8c8d;
    --accent: #3498db;
    --accent-hover: #2980b9;
    --border: #dce1e8;
    --shadow: rgba(0,0,0,0.1);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

/* Top nav */
.topbar { display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; background: var(--bg-card); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.topbar h1 { font-size: 14px; font-weight: 600; color: var(--accent); }
.topbar-actions { display: flex; gap: 8px; align-items: center; }

/* Tab bar */
.tabbar { display: flex; background: var(--bg-card); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.tab { padding: 8px 16px; font-size: 13px; cursor: pointer; border-bottom: 2px solid transparent; color: var(--text-muted); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Main layout */
.main { display: flex; flex: 1; overflow: hidden; }

/* Left panel — folder tree */
.panel-left { width: 280px; min-width: 200px; border-right: 1px solid var(--border); display: flex; flex-direction: column; overflow: hidden; background: var(--bg-card); }
.panel-left-header { padding: 10px 12px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.tree-container { flex: 1; overflow-y: auto; padding: 4px 0; }

/* Tree nodes */
.tree-node { padding: 5px 8px 5px 0; cursor: pointer; font-size: 13px; display: flex; align-items: center; gap: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; border-radius: 4px; margin: 1px 4px; }
.tree-node:hover { background: var(--bg-hover); }
.tree-node.selected { background: var(--accent); color: #fff; }
.tree-node .toggle { width: 16px; text-align: center; flex-shrink: 0; font-size: 10px; color: var(--text-muted); }
.tree-node.selected .toggle { color: rgba(255,255,255,0.7); }
.tree-children { padding-left: 16px; }

/* Right panel */
.panel-right { flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }

/* Tab content panes */
.tab-pane { display: none; flex: 1; flex-direction: column; overflow: hidden; }
.tab-pane.active { display: flex; }

/* Permissions pane — stacked: folder ACL top, files section below */
#pane-permissions { flex-direction: column; }
.pane-section { padding: 14px 16px; border-bottom: 1px solid var(--border); }
.pane-section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.pane-section-title { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

/* Folder ACL section */
#folder-acl-section { flex-shrink: 0; }
.owner-row { font-size: 12px; margin-bottom: 10px; color: var(--text-muted); }
.owner-row span { color: var(--text); font-weight: 500; }
.acl-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.acl-table th { text-align: left; padding: 4px 8px; color: var(--text-muted); font-weight: 500; border-bottom: 1px solid var(--border); }
.acl-table td { padding: 5px 8px; border-bottom: 1px solid var(--border); }
.acl-table tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; }
.badge-allow { background: rgba(46,204,113,0.15); color: var(--success); }
.badge-deny  { background: rgba(231,76,60,0.15); color: var(--danger); }
.badge-inherited { background: rgba(139,149,165,0.15); color: var(--text-muted); }
.folder-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }

/* Buttons */
.btn { padding: 5px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; transition: background 0.15s; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-danger  { background: var(--danger); color: #fff; }
.btn-danger:hover  { background: var(--danger-hover); }
.btn-secondary { background: var(--bg-hover); color: var(--text); border: 1px solid var(--border); }
.btn-secondary:hover { background: var(--border); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }

/* Status bar */
.status-bar { padding: 6px 16px; font-size: 12px; background: var(--bg-card); border-top: 1px solid var(--border); flex-shrink: 0; min-height: 30px; }
.status-bar.success { color: var(--success); }
.status-bar.error   { color: var(--danger); }
.status-bar.info    { color: var(--accent); }
.status-bar.warning { color: var(--warning); }

/* Modal overlay */
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 100; align-items: center; justify-content: center; }
.modal-overlay.open { display: flex; }
.modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; min-width: 360px; max-width: 520px; width: 90%; }
.modal h3 { font-size: 14px; font-weight: 600; margin-bottom: 14px; }
.form-row { margin-bottom: 10px; }
.form-row label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
.form-row input, .form-row select { width: 100%; padding: 6px 8px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-size: 13px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }

/* Placeholder state */
.placeholder-msg { display: flex; align-items: center; justify-content: center; flex: 1; color: var(--text-muted); font-size: 13px; }

/* Files section */
#files-section { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
.files-list-header { display: grid; grid-template-columns: 24px 1fr 80px 140px 24px; align-items: center; gap: 6px; padding: 6px 16px; background: var(--bg-card); border-bottom: 1px solid var(--border); font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; flex-shrink: 0; }
.files-list { flex: 1; overflow-y: auto; }
.file-row { display: grid; grid-template-columns: 24px 1fr 80px 140px 24px; align-items: center; gap: 6px; padding: 5px 16px; font-size: 12px; border-bottom: 1px solid var(--border); cursor: default; }
.file-row:hover { background: var(--bg-hover); }
.file-row.checked { background: rgba(93,173,226,0.08); }
.file-row input[type=checkbox] { cursor: pointer; }
.file-row .file-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.file-row .file-size { color: var(--text-muted); text-align: right; }
.file-row .file-date { color: var(--text-muted); }
.expand-btn { background: none; border: none; cursor: pointer; color: var(--text-muted); padding: 0 2px; font-size: 11px; }
.expand-btn:hover { color: var(--accent); }

/* Inline file ACL */
.file-acl-row { background: var(--bg-input); padding: 8px 16px 8px 44px; border-bottom: 1px solid var(--border); font-size: 11px; }
.file-acl-row .acl-entry { display: flex; gap: 8px; align-items: center; padding: 2px 0; }

/* Sticky action bar */
.action-bar { display: none; padding: 8px 16px; background: var(--bg-card); border-top: 2px solid var(--accent); flex-shrink: 0; }
.action-bar.visible { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.action-bar .selection-count { font-size: 12px; font-weight: 600; color: var(--accent); margin-right: 4px; }
.acl-diff-warning { width: 100%; padding: 4px 8px; background: rgba(243,156,18,0.15); border: 1px solid var(--warning); border-radius: 4px; color: var(--warning); font-size: 11px; margin-top: 4px; }

/* Robocopy pane */
#pane-robocopy { padding: 16px; overflow-y: auto; }
.mode-toggle { display: flex; gap: 0; margin-bottom: 16px; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; width: fit-content; }
.mode-toggle button { padding: 6px 16px; border: none; cursor: pointer; font-size: 12px; background: var(--bg-input); color: var(--text-muted); }
.mode-toggle button.active { background: var(--accent); color: #fff; }
.robo-form { display: flex; flex-direction: column; gap: 10px; max-width: 600px; }
.robo-form label { font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 3px; }
.robo-form input, .robo-form select { padding: 6px 8px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-size: 13px; width: 100%; }
.robo-output { margin-top: 14px; font-family: monospace; font-size: 11px; background: var(--bg-input); border: 1px solid var(--border); border-radius: 4px; padding: 10px; white-space: pre-wrap; max-height: 300px; overflow-y: auto; color: var(--text-muted); }
.robo-file-list { border: 1px solid var(--border); border-radius: 4px; max-height: 180px; overflow-y: auto; background: var(--bg-input); }
.robo-file-item { display: flex; align-items: center; gap: 6px; padding: 4px 8px; font-size: 12px; border-bottom: 1px solid var(--border); }
.robo-file-item:last-child { border-bottom: none; }
.robo-file-item input[type=checkbox] { cursor: pointer; }
</style>
</head>
<body>

<div class="topbar">
  <h1>Folder Permission Manager</h1>
  <div class="topbar-actions">
    <button class="btn btn-secondary" onclick="toggleTheme()" id="btnTheme">Light</button>
    <button class="btn btn-danger" onclick="shutdown()">Shutdown</button>
  </div>
</div>

<div class="tabbar">
  <div class="tab active" data-tab="permissions" onclick="switchTab('permissions')">Permissions</div>
  <div class="tab" data-tab="robocopy" onclick="switchTab('robocopy')">Robocopy</div>
</div>

<div class="main">
  <!-- Left panel: folder tree -->
  <div class="panel-left">
    <div class="panel-left-header">Folders</div>
    <div class="tree-container" id="treeContainer"></div>
  </div>

  <!-- Right panel -->
  <div class="panel-right">

    <!-- Permissions tab pane -->
    <div class="tab-pane active" id="pane-permissions">

      <div id="no-folder-msg" class="placeholder-msg">Select a folder to view permissions</div>

      <!-- Folder ACL section -->
      <div id="folder-acl-section" class="pane-section" style="display:none;">
        <div class="pane-section-header">
          <span class="pane-section-title" id="folderAclTitle">Folder Permissions</span>
          <span class="owner-row">Owner: <span id="folderOwner">—</span></span>
        </div>
        <table class="acl-table">
          <thead><tr><th>Identity</th><th>Rights</th><th>Type</th><th>Inherited</th></tr></thead>
          <tbody id="folderAclBody"></tbody>
        </table>
        <div class="folder-actions">
          <button class="btn btn-primary" onclick="showAddAceModal('folder')">Add ACE</button>
          <button class="btn btn-secondary" onclick="showRemoveAceModal('folder')">Remove ACE</button>
          <button class="btn btn-secondary" onclick="takeOwnership(false)">Take Ownership</button>
          <button class="btn btn-secondary" onclick="takeOwnership(true)">Take Ownership (Recursive)</button>
          <button class="btn btn-secondary" onclick="showReplicateModal()">Replicate Permissions</button>
          <button class="btn btn-secondary" id="btnExport" onclick="exportReport()">Export CSV</button>
        </div>
      </div>

      <!-- Files section -->
      <div id="files-section" style="display:none;">
        <div class="files-list-header">
          <input type="checkbox" id="selectAllFiles" onchange="toggleSelectAll(this.checked)" title="Select all">
          <span>Name</span>
          <span style="text-align:right">Size</span>
          <span>Modified</span>
          <span></span>
        </div>
        <div class="files-list" id="filesList"></div>
        <!-- Sticky batch action bar -->
        <div class="action-bar" id="actionBar">
          <span class="selection-count" id="selectionCount">0 selected</span>
          <button class="btn btn-primary" onclick="showAddAceModal('files')">Add ACE</button>
          <button class="btn btn-secondary" onclick="showRemoveAceModal('files')">Remove ACE</button>
          <button class="btn btn-secondary" onclick="takeFileOwnership()">Take Ownership</button>
          <button class="btn btn-secondary" onclick="showCopyFilesModal()">Copy to...</button>
          <div class="acl-diff-warning" id="aclDiffWarning" style="display:none;">
            ACLs differ across selected files — this operation applies uniformly
          </div>
        </div>
      </div>

    </div><!-- /pane-permissions -->

    <!-- Robocopy tab pane -->
    <div class="tab-pane" id="pane-robocopy">
      <div class="mode-toggle">
        <button class="active" id="roboModeFolderBtn" onclick="setRoboMode('folder')">Folder copy</button>
        <button id="roboModeFileBtn" onclick="setRoboMode('file')">File copy</button>
      </div>

      <!-- Folder copy mode -->
      <div id="roboFolderForm" class="robo-form">
        <div><label>Source folder</label><input type="text" id="roboSrc" placeholder="\\server\share\source"></div>
        <div><label>Destination folder</label><input type="text" id="roboDst" placeholder="\\server\share\dest"></div>
        <div>
          <label>Mode</label>
          <select id="roboMode">
            <option value="copy">Copy (/E — all subdirs including empty)</option>
            <option value="mirror">Mirror (/MIR — deletes files not in source)</option>
          </select>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
          <div><label>Threads (/MT)</label><input type="number" id="roboThreads" value="8" min="1" max="128"></div>
          <div><label>Retries (/R)</label><input type="number" id="roboRetries" value="3" min="0"></div>
          <div><label>Wait (/W sec)</label><input type="number" id="roboWait" value="5" min="0"></div>
        </div>
        <div><label>Extra flags (optional)</label><input type="text" id="roboExtra" placeholder="/XF *.tmp /XD .git"></div>
        <div><label>Log file path (optional)</label><input type="text" id="roboLog" placeholder="Leave empty to skip"></div>
        <div style="display:flex;gap:8px;">
          <button class="btn btn-secondary" id="btnRoboPreview" onclick="roboPreview()">Preview</button>
          <button class="btn btn-primary" id="btnRobocopy" onclick="runRobocopy()">Run Robocopy</button>
        </div>
      </div>

      <!-- File copy mode -->
      <div id="roboFileForm" class="robo-form" style="display:none;">
        <div style="display:flex;gap:8px;align-items:flex-end;">
          <div style="flex:1;"><label>Source folder</label><input type="text" id="roboFileSrc" placeholder="\\server\share\source" oninput="loadRoboFileList()"></div>
          <button class="btn btn-secondary" style="margin-bottom:0;" onclick="loadRoboFileList()">Load files</button>
        </div>
        <div><label>Select files to copy</label><div class="robo-file-list" id="roboFileList"><span style="padding:8px;color:var(--text-muted);font-size:12px;display:block;">Enter a source folder above</span></div></div>
        <div><label>Destination folder</label><input type="text" id="roboFileDst" placeholder="\\server\share\dest"></div>
        <div><label>Extra flags (optional)</label><input type="text" id="roboFileExtra" placeholder="/XO"></div>
        <div>
          <button class="btn btn-primary" id="btnRobocopyFiles" onclick="runRobocopyFiles()">Copy Selected Files</button>
        </div>
      </div>

      <div class="robo-output" id="roboOutput" style="display:none;"></div>
    </div><!-- /pane-robocopy -->

    <div class="status-bar" id="statusBar">Ready</div>

  </div><!-- /panel-right -->
</div><!-- /main -->

<!-- Add ACE modal -->
<div class="modal-overlay" id="addAceModal">
  <div class="modal">
    <h3 id="addAceModalTitle">Add Permission Entry</h3>
    <div class="form-row"><label>Identity (user or group)</label><input type="text" id="addAceIdentity" placeholder="DOMAIN\User or DOMAIN\Group"></div>
    <div class="form-row">
      <label>Rights</label>
      <select id="addAceRights">
        <option value="FullControl">Full Control</option>
        <option value="Modify">Modify</option>
        <option value="ReadAndExecute">Read & Execute</option>
        <option value="Read">Read</option>
        <option value="Write">Write</option>
      </select>
    </div>
    <div class="form-row">
      <label>Type</label>
      <select id="addAceType">
        <option value="Allow">Allow</option>
        <option value="Deny">Deny</option>
      </select>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('addAceModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitAddAce()">Add</button>
    </div>
  </div>
</div>

<!-- Remove ACE modal -->
<div class="modal-overlay" id="removeAceModal">
  <div class="modal">
    <h3 id="removeAceModalTitle">Remove Permission Entry</h3>
    <div class="form-row">
      <label>Identity</label>
      <select id="removeAceIdentity"></select>
    </div>
    <div class="form-row">
      <label>Rights</label>
      <select id="removeAceRights">
        <option value="FullControl">Full Control</option>
        <option value="Modify">Modify</option>
        <option value="ReadAndExecute">Read & Execute</option>
        <option value="Read">Read</option>
        <option value="Write">Write</option>
      </select>
    </div>
    <div class="form-row">
      <label>Type</label>
      <select id="removeAceType">
        <option value="Allow">Allow</option>
        <option value="Deny">Deny</option>
      </select>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('removeAceModal')">Cancel</button>
      <button class="btn btn-danger" onclick="submitRemoveAce()">Remove</button>
    </div>
  </div>
</div>

<!-- Replicate modal -->
<div class="modal-overlay" id="replicateModal">
  <div class="modal">
    <h3>Replicate Permissions</h3>
    <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Copy permissions from the selected folder to target paths (one per line).</p>
    <div class="form-row"><label>Target paths</label><textarea id="replicateTargets" rows="5" style="width:100%;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 8px;font-size:12px;resize:vertical;" placeholder="C:\Shares\FolderA&#10;C:\Shares\FolderB"></textarea></div>
    <div class="form-row"><label><input type="checkbox" id="replicateRecursive"> Apply recursively</label></div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('replicateModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitReplicate()">Replicate</button>
    </div>
  </div>
</div>

<!-- Copy files modal -->
<div class="modal-overlay" id="copyFilesModal">
  <div class="modal">
    <h3>Copy Selected Files</h3>
    <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Files will be copied with ACL preservation (/COPY:DATSO /SECFIX).</p>
    <div class="form-row"><label>Destination folder</label><input type="text" id="copyFilesDest" placeholder="\\server\share\dest"></div>
    <div class="form-row"><label>Extra robocopy flags (optional)</label><input type="text" id="copyFilesExtra" placeholder="/XO"></div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('copyFilesModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitCopyFiles()">Copy</button>
    </div>
  </div>
</div>

<script>
(function() {
'use strict';

// --- State ---
var currentFolder  = null;   // currently selected folder path
var currentFiles   = [];     // array of file objects for current folder
var checkedFiles   = new Set(); // paths of checked files
var addAceTarget   = 'folder'; // 'folder' or 'files'
var removeAceTarget = 'folder';
var fileAclCache   = {};     // path -> acl object, for inline expand + diff check

// --- Utilities ---
function setStatus(msg, type) {
    var el = document.getElementById('statusBar');
    el.textContent = msg;
    el.className = 'status-bar ' + (type || '');
}

function api(url, opts) {
    return fetch(url, opts).then(function(r) {
        return r.json().then(function(d) {
            if (!r.ok) throw new Error(d.error || r.statusText);
            return d;
        });
    });
}

function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function openModal(id)  { document.getElementById(id).classList.add('open'); }

function toggleTheme() {
    document.body.classList.toggle('light');
    document.getElementById('btnTheme').textContent = document.body.classList.contains('light') ? 'Dark' : 'Light';
    localStorage.setItem('fpm-theme', document.body.classList.contains('light') ? 'light' : 'dark');
}
function initTheme() {
    if (localStorage.getItem('fpm-theme') === 'light') { document.body.classList.add('light'); document.getElementById('btnTheme').textContent = 'Dark'; }
}

function switchTab(name) {
    document.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === name); });
    document.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.toggle('active', p.id === 'pane-' + name); });
}

function shutdown() {
    if (!confirm('Stop the Folder Permission Manager server?')) return;
    fetch('/api/shutdown').catch(function(){});
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#8b95a5;font-family:sans-serif;">Server stopped. You may close this tab.</div>';
}

// --- Folder Tree ---
function loadDrives() {
    setStatus('Loading drives...', 'info');
    api('/api/drives').then(function(drives) {
        var container = document.getElementById('treeContainer');
        container.innerHTML = '';
        drives.forEach(function(d) {
            var node = makeTreeNode(d.label || d.name, d.root, 0, true);
            container.appendChild(node);
        });
        setStatus('Ready');
    }).catch(function(e) { setStatus('Failed to load drives: ' + e.message, 'error'); });
}

function makeTreeNode(label, path, depth, hasChildren) {
    var wrapper = document.createElement('div');
    var node = document.createElement('div');
    node.className = 'tree-node';
    node.style.paddingLeft = (8 + depth * 16) + 'px';
    node.dataset.path = path;

    var toggle = document.createElement('span');
    toggle.className = 'toggle';
    toggle.textContent = hasChildren ? '▶' : ' ';

    var name = document.createElement('span');
    name.textContent = label;

    node.appendChild(toggle);
    node.appendChild(name);
    wrapper.appendChild(node);

    var childContainer = document.createElement('div');
    childContainer.className = 'tree-children';
    childContainer.style.display = 'none';
    wrapper.appendChild(childContainer);

    var expanded = false;

    node.addEventListener('click', function() {
        selectFolder(path);
        if (hasChildren) {
            expanded = !expanded;
            toggle.textContent = expanded ? '▼' : '▶';
            childContainer.style.display = expanded ? 'block' : 'none';
            if (expanded && childContainer.children.length === 0) {
                loadChildren(path, depth + 1, childContainer);
            }
        }
    });

    return wrapper;
}

function loadChildren(path, depth, container) {
    api('/api/children?path=' + encodeURIComponent(path)).then(function(children) {
        container.innerHTML = '';
        children.forEach(function(c) {
            container.appendChild(makeTreeNode(c.name, c.path, depth, c.hasChildren));
        });
    }).catch(function(e) { setStatus('Error loading children: ' + e.message, 'error'); });
}

function selectFolder(path) {
    // Update selection highlight
    document.querySelectorAll('.tree-node').forEach(function(n) {
        n.classList.toggle('selected', n.dataset.path === path);
    });
    currentFolder = path;
    checkedFiles.clear();
    fileAclCache = {};
    loadFolderAcl(path);
    loadFiles(path);
}

// --- Folder ACL ---
function loadFolderAcl(path) {
    document.getElementById('no-folder-msg').style.display = 'none';
    document.getElementById('folder-acl-section').style.display = 'block';
    document.getElementById('files-section').style.display = 'flex';
    document.getElementById('folderAclTitle').textContent = path.split('\\').pop() || path;

    api('/api/acl?path=' + encodeURIComponent(path)).then(function(data) {
        document.getElementById('folderOwner').textContent = data.owner || '—';
        var tbody = document.getElementById('folderAclBody');
        tbody.innerHTML = '';
        (data.entries || []).forEach(function(e) {
            var tr = document.createElement('tr');
            tr.innerHTML =
                '<td>' + e.identity + '</td>' +
                '<td>' + e.rights + '</td>' +
                '<td><span class="badge badge-' + e.type.toLowerCase() + '">' + e.type + '</span></td>' +
                '<td>' + (e.isInherited ? '<span class="badge badge-inherited">Yes</span>' : '') + '</td>';
            tbody.appendChild(tr);
        });
    }).catch(function(e) { setStatus('Failed to load ACL: ' + e.message, 'error'); });
}

// --- Files list ---
function loadFiles(path) {
    var list = document.getElementById('filesList');
    list.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:12px;">Loading...</div>';
    api('/api/files?path=' + encodeURIComponent(path)).then(function(files) {
        currentFiles = files;
        renderFilesList();
    }).catch(function(e) {
        list.innerHTML = '<div style="padding:12px;color:var(--danger);font-size:12px;">Failed to load files: ' + e.message + '</div>';
    });
}

function renderFilesList() {
    var list = document.getElementById('filesList');
    list.innerHTML = '';
    if (!currentFiles || currentFiles.length === 0) {
        list.innerHTML = '<div style="padding:12px;color:var(--text-muted);font-size:12px;">No files in this folder</div>';
        updateActionBar();
        return;
    }
    currentFiles.forEach(function(f) {
        var row = document.createElement('div');
        row.className = 'file-row' + (checkedFiles.has(f.path) ? ' checked' : '');
        row.dataset.path = f.path;

        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = checkedFiles.has(f.path);
        cb.addEventListener('change', function() { toggleFileCheck(f.path, cb.checked, row); });

        var nameEl = document.createElement('span');
        nameEl.className = 'file-name';
        nameEl.textContent = f.name;
        nameEl.title = f.name;

        var sizeEl = document.createElement('span');
        sizeEl.className = 'file-size';
        sizeEl.textContent = f.sizeDisplay;

        var dateEl = document.createElement('span');
        dateEl.className = 'file-date';
        dateEl.textContent = f.lastModified;

        var expandBtn = document.createElement('button');
        expandBtn.className = 'expand-btn';
        expandBtn.textContent = '▶';
        expandBtn.title = 'Show ACL';
        expandBtn.addEventListener('click', function(e) { e.stopPropagation(); toggleFileAcl(f.path, row, expandBtn); });

        row.appendChild(cb);
        row.appendChild(nameEl);
        row.appendChild(sizeEl);
        row.appendChild(dateEl);
        row.appendChild(expandBtn);
        list.appendChild(row);
    });
    updateActionBar();
}

function toggleFileCheck(path, checked, row) {
    if (checked) { checkedFiles.add(path); } else { checkedFiles.delete(path); }
    row.classList.toggle('checked', checked);
    document.getElementById('selectAllFiles').checked = checkedFiles.size === currentFiles.length && currentFiles.length > 0;
    updateActionBar();
}

function toggleSelectAll(checked) {
    checkedFiles.clear();
    if (checked) { currentFiles.forEach(function(f) { checkedFiles.add(f.path); }); }
    renderFilesList();
    document.getElementById('selectAllFiles').checked = checked;
}

function updateActionBar() {
    var bar = document.getElementById('actionBar');
    var count = checkedFiles.size;
    document.getElementById('selectionCount').textContent = count + ' file' + (count === 1 ? '' : 's') + ' selected';
    bar.classList.toggle('visible', count > 0);
    // ACL diff check — only when 2+ files are checked and we have their ACLs cached
    checkAclDiff();
}

// --- Inline file ACL expand ---
function toggleFileAcl(path, row, btn) {
    // If already expanded, collapse
    var existing = row.nextSibling;
    if (existing && existing.classList && existing.classList.contains('file-acl-row')) {
        existing.remove();
        btn.textContent = '▶';
        return;
    }
    btn.textContent = '▼';
    btn.disabled = true;
    setStatus('Loading file ACL...', 'info');

    api('/api/file-acl?path=' + encodeURIComponent(path)).then(function(data) {
        fileAclCache[path] = data;
        var aclRow = document.createElement('div');
        aclRow.className = 'file-acl-row';
        var html = '<strong style="font-size:11px;color:var(--text-muted);">Owner: ' + (data.owner || '—') + '</strong>';
        (data.entries || []).forEach(function(e) {
            html += '<div class="acl-entry"><span class="badge badge-' + e.type.toLowerCase() + '">' + e.type + '</span>' +
                    '<span>' + e.identity + '</span><span style="color:var(--text-muted);">' + e.rights + '</span>' +
                    (e.isInherited ? '<span class="badge badge-inherited">inherited</span>' : '') + '</div>';
        });
        aclRow.innerHTML = html;
        row.insertAdjacentElement('afterend', aclRow);
        setStatus('Ready');
        checkAclDiff();
    }).catch(function(e) {
        btn.textContent = '▶';
        setStatus('Failed to load file ACL: ' + e.message, 'error');
    }).finally(function() { btn.disabled = false; });
}

function checkAclDiff() {
    var warning = document.getElementById('aclDiffWarning');
    if (checkedFiles.size < 2) { warning.style.display = 'none'; return; }
    var checkedCached = Array.from(checkedFiles).filter(function(p) { return fileAclCache[p]; });
    if (checkedCached.length < 2) { warning.style.display = 'none'; return; }
    var first = JSON.stringify((fileAclCache[checkedCached[0]].entries || []).map(function(e) { return e.identity + e.rights + e.type; }).sort());
    var differs = checkedCached.slice(1).some(function(p) {
        return JSON.stringify((fileAclCache[p].entries || []).map(function(e) { return e.identity + e.rights + e.type; }).sort()) !== first;
    });
    warning.style.display = differs ? 'block' : 'none';
}

// --- Folder ACL operations ---
function showAddAceModal(target) {
    addAceTarget = target;
    document.getElementById('addAceModalTitle').textContent = target === 'files' ? 'Add Permission to Selected Files' : 'Add Permission Entry';
    document.getElementById('addAceIdentity').value = '';
    openModal('addAceModal');
}

function submitAddAce() {
    var identity = document.getElementById('addAceIdentity').value.trim();
    var rights   = document.getElementById('addAceRights').value;
    var type     = document.getElementById('addAceType').value;
    if (!identity) { setStatus('Identity is required', 'error'); return; }
    closeModal('addAceModal');

    if (addAceTarget === 'files') {
        var paths = Array.from(checkedFiles);
        setStatus('Adding ACE to ' + paths.length + ' file(s)...', 'info');
        api('/api/file-acl/add', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ paths: paths, identity: identity, rights: rights, type: type }) })
            .then(function(r) {
                var failed = (r.results || []).filter(function(x) { return x.status === 'error'; });
                if (failed.length) { setStatus(failed.length + ' file(s) failed. First error: ' + failed[0].message, 'error'); }
                else { setStatus('ACE added to ' + paths.length + ' file(s)', 'success'); }
            }).catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
    } else {
        setStatus('Adding ACE...', 'info');
        api('/api/add-ace', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ path: currentFolder, identity: identity, rights: rights, type: type }) })
            .then(function() { setStatus('ACE added', 'success'); loadFolderAcl(currentFolder); })
            .catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
    }
}

function showRemoveAceModal(target) {
    removeAceTarget = target;
    document.getElementById('removeAceModalTitle').textContent = target === 'files' ? 'Remove Permission from Selected Files' : 'Remove Permission Entry';
    var select = document.getElementById('removeAceIdentity');
    select.innerHTML = '';

    if (target === 'files') {
        // Populate from cached ACLs of checked files — combined unique identities
        var identities = new Set();
        Array.from(checkedFiles).forEach(function(p) {
            if (fileAclCache[p]) {
                (fileAclCache[p].entries || []).forEach(function(e) { identities.add(e.identity); });
            }
        });
        if (identities.size === 0) { setStatus('Expand file ACLs first to load identities', 'warning'); return; }
        identities.forEach(function(id) { var o = document.createElement('option'); o.value = id; o.textContent = id; select.appendChild(o); });
    } else {
        // Populate from current folder ACL table
        var rows = document.querySelectorAll('#folderAclBody tr');
        var seen = new Set();
        rows.forEach(function(r) {
            var id = r.cells[0] && r.cells[0].textContent;
            if (id && !seen.has(id)) { seen.add(id); var o = document.createElement('option'); o.value = id; o.textContent = id; select.appendChild(o); }
        });
    }
    openModal('removeAceModal');
}

function submitRemoveAce() {
    var identity = document.getElementById('removeAceIdentity').value;
    var rights   = document.getElementById('removeAceRights').value;
    var type     = document.getElementById('removeAceType').value;
    closeModal('removeAceModal');

    if (removeAceTarget === 'files') {
        var paths = Array.from(checkedFiles);
        setStatus('Removing ACE from ' + paths.length + ' file(s)...', 'info');
        api('/api/file-acl/remove', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ paths: paths, identity: identity, rights: rights, type: type }) })
            .then(function(r) {
                var failed = (r.results || []).filter(function(x) { return x.status === 'error'; });
                if (failed.length) { setStatus(failed.length + ' file(s) failed. First error: ' + failed[0].message, 'error'); }
                else { setStatus('ACE removed from ' + paths.length + ' file(s)', 'success'); }
            }).catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
    } else {
        setStatus('Removing ACE...', 'info');
        api('/api/remove-ace', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ path: currentFolder, identity: identity, rights: rights, type: type }) })
            .then(function() { setStatus('ACE removed', 'success'); loadFolderAcl(currentFolder); })
            .catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
    }
}

function takeOwnership(recursive) {
    if (!currentFolder) return;
    var msg = recursive ? 'Take ownership RECURSIVELY on all files and subfolders in ' + currentFolder + '? This may take a while.' : 'Take ownership of ' + currentFolder + '?';
    if (!confirm(msg)) return;
    setStatus('Taking ownership...', 'info');
    api('/api/take-ownership', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ path: currentFolder, recursive: recursive }) })
        .then(function(r) { setStatus(r.message || 'Ownership taken', 'success'); loadFolderAcl(currentFolder); })
        .catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
}

function showReplicateModal() {
    document.getElementById('replicateTargets').value = '';
    document.getElementById('replicateRecursive').checked = false;
    openModal('replicateModal');
}

function submitReplicate() {
    var raw = document.getElementById('replicateTargets').value;
    var targets = raw.split('\n').map(function(s) { return s.trim(); }).filter(Boolean);
    if (!targets.length) { setStatus('Enter at least one target path', 'error'); return; }
    closeModal('replicateModal');
    setStatus('Replicating permissions...', 'info');
    api('/api/replicate', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ sourcePath: currentFolder, targetPaths: targets, recursive: document.getElementById('replicateRecursive').checked }) })
        .then(function(r) {
            var failed = (r.results || []).filter(function(x) { return x.status === 'error'; });
            if (failed.length) { setStatus(failed.length + ' target(s) failed. First: ' + failed[0].message, 'error'); }
            else { setStatus('Permissions replicated to ' + targets.length + ' target(s)', 'success'); }
        }).catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
}

function exportReport() {
    if (!currentFolder) return;
    window.location.href = '/api/export?path=' + encodeURIComponent(currentFolder);
}

// --- File ownership ---
function takeFileOwnership() {
    var paths = Array.from(checkedFiles);
    if (!paths.length) return;
    if (!confirm('Take ownership of ' + paths.length + ' file(s)?')) return;
    setStatus('Taking ownership of ' + paths.length + ' file(s)...', 'info');
    api('/api/file-acl/take-ownership', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ paths: paths }) })
        .then(function(r) {
            var failed = (r.results || []).filter(function(x) { return x.status === 'error'; });
            if (failed.length) { setStatus(failed.length + ' file(s) failed. First: ' + failed[0].message, 'error'); }
            else { setStatus('Ownership taken on ' + paths.length + ' file(s)', 'success'); }
        }).catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
}

// --- Copy files modal ---
function showCopyFilesModal() {
    document.getElementById('copyFilesDest').value = '';
    document.getElementById('copyFilesExtra').value = '';
    openModal('copyFilesModal');
}

function submitCopyFiles() {
    var dest  = document.getElementById('copyFilesDest').value.trim();
    var extra = document.getElementById('copyFilesExtra').value.trim();
    var paths = Array.from(checkedFiles);
    if (!dest) { setStatus('Destination folder is required', 'error'); return; }
    if (!paths.length) { setStatus('No files selected', 'error'); return; }
    closeModal('copyFilesModal');
    // Filenames only — robocopy-files expects sourceDir + filenames
    var filenames = paths.map(function(p) { return p.split('\\').pop(); });
    setStatus('Copying ' + filenames.length + ' file(s)...', 'info');
    api('/api/robocopy-files', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ sourceDir: currentFolder, destDir: dest, files: filenames, extraFlags: extra || null }) })
        .then(function(r) {
            setStatus((r.success ? 'Copy complete: ' : 'Copy finished with errors: ') + r.message, r.success ? 'success' : 'error');
        }).catch(function(e) { setStatus('Failed: ' + e.message, 'error'); });
}

// --- Robocopy tab ---
function setRoboMode(mode) {
    document.getElementById('roboFolderForm').style.display = mode === 'folder' ? 'flex' : 'none';
    document.getElementById('roboFileForm').style.display  = mode === 'file'   ? 'flex' : 'none';
    document.getElementById('roboModeFolderBtn').classList.toggle('active', mode === 'folder');
    document.getElementById('roboModeFileBtn').classList.toggle('active', mode === 'file');
    document.getElementById('roboOutput').style.display = 'none';
}

function loadRoboFileList() {
    var src = document.getElementById('roboFileSrc').value.trim();
    var list = document.getElementById('roboFileList');
    if (!src) { list.innerHTML = '<span style="padding:8px;color:var(--text-muted);font-size:12px;display:block;">Enter a source folder above</span>'; return; }
    list.innerHTML = '<span style="padding:8px;color:var(--text-muted);font-size:12px;display:block;">Loading...</span>';
    api('/api/files?path=' + encodeURIComponent(src)).then(function(files) {
        list.innerHTML = '';
        if (!files || files.length === 0) { list.innerHTML = '<span style="padding:8px;color:var(--text-muted);font-size:12px;display:block;">No files found</span>'; return; }
        files.forEach(function(f) {
            var item = document.createElement('div');
            item.className = 'robo-file-item';
            var cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = f.name; cb.id = 'rfl-' + f.name;
            var lbl = document.createElement('label'); lbl.htmlFor = 'rfl-' + f.name; lbl.style.fontSize = '12px'; lbl.style.cursor = 'pointer';
            lbl.textContent = f.name + ' (' + f.sizeDisplay + ')';
            item.appendChild(cb); item.appendChild(lbl);
            list.appendChild(item);
        });
    }).catch(function(e) { list.innerHTML = '<span style="padding:8px;color:var(--danger);font-size:12px;display:block;">Error: ' + e.message + '</span>'; });
}

function runRobocopy() {
    var src     = document.getElementById('roboSrc').value.trim();
    var dst     = document.getElementById('roboDst').value.trim();
    var mode    = document.getElementById('roboMode').value;
    var threads = parseInt(document.getElementById('roboThreads').value) || 8;
    var retries = parseInt(document.getElementById('roboRetries').value) || 3;
    var wait    = parseInt(document.getElementById('roboWait').value) || 5;
    var extra   = document.getElementById('roboExtra').value.trim();
    var log     = document.getElementById('roboLog').value.trim();
    if (!src || !dst) { setStatus('Source and destination are required', 'error'); return; }
    document.getElementById('btnRobocopy').disabled = true;
    document.getElementById('btnRoboPreview').disabled = true;
    setStatus('Running robocopy...', 'info');
    api('/api/robocopy', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ source: src, destination: dst, mode: mode, threads: threads, retries: retries, waitTime: wait, extraFlags: extra || null, logFile: log || null }) })
        .then(function(r) {
            showRoboOutput(r);
            setStatus((r.success ? 'Robocopy complete: ' : 'Robocopy error: ') + r.message, r.success ? 'success' : 'error');
        })
        .catch(function(e) { setStatus('Robocopy failed: ' + e.message, 'error'); })
        .finally(function() { document.getElementById('btnRobocopy').disabled = false; document.getElementById('btnRoboPreview').disabled = false; });
}

function roboPreview() {
    var src = document.getElementById('roboSrc').value.trim();
    var dst = document.getElementById('roboDst').value.trim();
    if (!src) { setStatus('Source folder is required for preview', 'error'); return; }
    document.getElementById('btnRoboPreview').disabled = true;
    setStatus('Running preview...', 'info');
    api('/api/robocopy-preview?source=' + encodeURIComponent(src) + '&destination=' + encodeURIComponent(dst))
        .then(function(r) {
            var out = document.getElementById('roboOutput');
            out.style.display = 'block';
            out.textContent = 'Preview: ' + r.dirs + ' dirs, ' + r.files + ' files, ' + r.sizeDisplay + '\n\n' + (r.rawSummary || '');
            setStatus('Preview complete', 'success');
        })
        .catch(function(e) { setStatus('Preview failed: ' + e.message, 'error'); })
        .finally(function() { document.getElementById('btnRoboPreview').disabled = false; });
}

function runRobocopyFiles() {
    var src   = document.getElementById('roboFileSrc').value.trim();
    var dst   = document.getElementById('roboFileDst').value.trim();
    var extra = document.getElementById('roboFileExtra').value.trim();
    if (!src || !dst) { setStatus('Source and destination are required', 'error'); return; }
    var checked = Array.from(document.querySelectorAll('#roboFileList input[type=checkbox]:checked')).map(function(cb) { return cb.value; });
    if (!checked.length) { setStatus('Select at least one file to copy', 'error'); return; }
    document.getElementById('btnRobocopyFiles').disabled = true;
    setStatus('Copying ' + checked.length + ' file(s)...', 'info');
    api('/api/robocopy-files', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ sourceDir: src, destDir: dst, files: checked, extraFlags: extra || null }) })
        .then(function(r) {
            showRoboOutput(r);
            setStatus((r.success ? 'Copy complete: ' : 'Copy error: ') + r.message, r.success ? 'success' : 'error');
        })
        .catch(function(e) { setStatus('Copy failed: ' + e.message, 'error'); })
        .finally(function() { document.getElementById('btnRobocopyFiles').disabled = false; });
}

function showRoboOutput(r) {
    var out = document.getElementById('roboOutput');
    out.style.display = 'block';
    out.textContent = 'Command: ' + r.command + '\nExit code: ' + r.exitCode + ' — ' + r.message + '\n\n' + (r.output || '');
}

// --- Init ---
initTheme();
loadDrives();
})();
</script>
</body>
</html>
"@
```

- [ ] **Step 2: Verify the script still parses**

```powershell
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    ".\FolderPermissionManager\FolderPermissionManager-GUI.ps1",
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 3: Smoke-test end-to-end in the browser**

Start the server:
```powershell
.\FolderPermissionManager\FolderPermissionManager-GUI.ps1
```

Verify:
- Page loads without JS errors in browser console
- Drive list populates in left panel
- Clicking a drive/folder loads its folder ACL (owner + ACE table visible)
- Folders pane shows files section below the ACL section
- Light/Dark theme toggle works
- Permissions tab and Robocopy tab switch correctly
- Robocopy tab shows Folder copy / File copy mode toggle

- [ ] **Step 4: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): rewrite frontend with context-aware 2-panel layout and file section"
```

---

## Task 7: Verify file ACL inline expand and batch action bar

- [ ] **Step 1: Test file ACL inline expand**

With the server running, navigate to a folder that has files. Click the `▶` expand button on a file row.

Expected:
- Inline ACL row appears below the file row showing owner and ACE entries
- Button changes to `▼`
- Clicking `▼` again collapses the row
- Status bar shows "Loading file ACL..." then "Ready"

- [ ] **Step 2: Test batch action bar**

Check one or more files using the checkboxes.

Expected:
- Sticky action bar slides into view at the bottom of the files section
- Shows "X file(s) selected" count
- Buttons visible: Add ACE, Remove ACE, Take Ownership, Copy to...
- "Select all" checkbox in header selects/deselects all files
- Unchecking all files hides the action bar

- [ ] **Step 3: Test ACL diff advisory**

Expand the ACL for two files that have different permissions (or temporarily assign different ACEs to two test files). Check both files.

Expected:
- Yellow advisory banner appears: "ACLs differ across selected files — this operation applies uniformly"
- Banner is absent when ACLs match or fewer than 2 files are checked

- [ ] **Step 4: Test Add ACE to files**

Check one or more test files. Click "Add ACE" in the action bar. Enter a valid identity (e.g. `Everyone`), select `Read`, `Allow`. Click Add.

Expected:
- Status bar shows "Adding ACE to X file(s)..." then "ACE added to X file(s)"
- Expanding the file ACL inline shows the new entry

- [ ] **Step 5: Test Remove ACE from files**

With files checked and their ACLs expanded, click "Remove ACE". Verify the identity dropdown is populated. Select an identity and click Remove.

Expected:
- Status bar shows success
- Expanding the file ACL inline confirms the entry is gone

- [ ] **Step 6: Test Take Ownership on files**

Check one or more files. Click "Take Ownership". Confirm the prompt.

Expected:
- Status bar shows success with the resolved identity name (e.g. "Ownership taken by DOMAIN\Admin")
- No CMD-style `%USERNAME%` in the message

- [ ] **Step 7: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "test(fpm): verify file ACL inline expand, batch action bar, and ownership flow"
```

---

## Task 8: Verify Copy to... and Robocopy File copy mode

- [ ] **Step 1: Test Copy to... modal from action bar**

Check one or more files. Click "Copy to...". Enter a writable destination folder path. Click Copy.

Expected:
- Status bar shows "Copying X file(s)..." then result message
- Files appear in the destination folder
- ACLs on the copied files match the originals (verify with the tool: navigate to destination, expand file ACL)

- [ ] **Step 2: Verify empty files[] is rejected**

```powershell
Invoke-RestMethod 'http://localhost:8271/api/robocopy-files' -Method Post -ContentType 'application/json' -Body '{"sourceDir":"C:\\Windows","destDir":"C:\\Temp","files":[]}' -ErrorAction SilentlyContinue
```

Expected: 400 response with `{ error: "files[] must not be empty" }`.

- [ ] **Step 3: Test Robocopy tab — File copy mode**

Switch to the Robocopy tab. Click "File copy". Enter a source folder path and click "Load files".

Expected:
- File list populates with checkboxes and size info
- Checking files and clicking "Copy Selected Files" runs the copy
- Output panel shows the robocopy command, exit code, and summary

- [ ] **Step 4: Verify Robocopy tab — Folder copy mode unchanged**

Switch to "Folder copy" mode. Verify existing source/destination/mode/threads/retries/wait/log/extra fields are present and "Run Robocopy" and "Preview" still work.

Expected: behavior identical to v1.

- [ ] **Step 5: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "test(fpm): verify Copy to, robocopy-files endpoint, and robocopy tab file mode"
```

---

## Task 9: Final regression check — all existing operations

- [ ] **Step 1: Verify folder ACL section**

Navigate to several folders. Verify owner, ACE table, inherited badges all display correctly. Confirm inherited ACEs show the "Yes" badge and explicit ACEs show nothing.

- [ ] **Step 2: Verify Add/Remove ACE on folder**

Add an ACE to a test folder (e.g. `Everyone` / Read / Allow). Confirm it appears in the ACL table. Remove it. Confirm it disappears.

- [ ] **Step 3: Verify Take Ownership (folder, both modes)**

Test non-recursive and recursive take ownership on a test folder. Confirm success message and ACL owner field updates.

- [ ] **Step 4: Verify Replicate Permissions**

Open the Replicate modal. Enter a target folder path. Submit. Confirm success status.

- [ ] **Step 5: Verify CSV Export**

Click "Export CSV". Confirm a `.csv` file downloads containing the permission entries for the selected folder and its subfolders.

- [ ] **Step 6: Verify mapped drive handling**

If mapped drives are available, navigate into one and confirm ACL operations work (no path resolution errors).

- [ ] **Step 7: Final commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat(fpm): v2 complete — file ACL operations, batch action bar, context-aware layout"
```

---

## Self-Review Notes

- **InheritanceFlags for files:** `Invoke-AddFileAce` and `Invoke-RemoveFileAce` correctly use `InheritanceFlags::None` / `PropagationFlags::None` — inheritance flags only apply to directory ACEs, not file ACEs. This differs from the folder `Invoke-AddAce` which uses `ContainerInherit, ObjectInherit`.
- **`/COPY:DATSO` vs `/COPY:DATSOU`:** `U` (auditing) dropped intentionally — requires `SeSecurityPrivilege`. Comment in `Invoke-RobocopyFiles` documents this decision.
- **`WindowsIdentity::GetCurrent().Name`** used in `Invoke-TakeFileOwnership` instead of `$env:USERNAME` — reliable under SYSTEM/service accounts.
- **Empty `files[]` guard** in `Invoke-RobocopyFiles` returns 400 before any robocopy invocation.
- **`-PathType Leaf` validation** present in all five new backend functions.
- **Remove ACE identity picker for files:** requires at least one file's ACL to be expanded/cached before the modal populates — the UI tells the user "Expand file ACLs first" if none are cached. This is the simplest correct behavior; a future improvement could auto-fetch all ACLs on selection.
