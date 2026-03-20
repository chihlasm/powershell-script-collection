# Folder Permission Manager GUI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a browser-based GUI for managing NTFS folder permissions across local drives and network shares.

**Architecture:** Single PowerShell script hosts an HTTP listener on `localhost:8271`. The embedded HTML/CSS/JS frontend makes fetch() calls to REST-style API endpoints. The PowerShell backend handles all filesystem operations (Get-Acl, Set-Acl, icacls). Sidebar has a folder tree browser; main panel has tabbed views for permissions, children, and actions.

**Tech Stack:** PowerShell 5.1, System.Net.HttpListener, vanilla HTML/CSS/JS (no frameworks), same CSS variable theme system as GPO audit report.

---

### Task 1: PowerShell HTTP Listener Skeleton

**Files:**
- Create: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

**Step 1: Create script with help block, parameters, and HTTP listener**

Write the script skeleton: comment-based help, `#Requires -Version 5.1`, `#Requires -RunAsAdministrator`, `[CmdletBinding()]` param block with `-Port` (default 8271) and `-NoBrowserOpen` switch. Set up `System.Net.HttpListener` on `http://localhost:$Port/`, add a request loop that dispatches to a route handler function, and a shutdown endpoint. Include `Start-Process` to open the browser on launch.

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Folder Permission Manager — Browser-based GUI for NTFS permissions.

.DESCRIPTION
    Starts a local web server and opens a browser-based interface for:
    - Browsing local drives and network shares
    - Viewing folder ownership and ACL entries
    - Taking ownership (single or recursive)
    - Adding/removing permission entries
    - Replicating parent permissions to child folders
    - Exporting permissions reports to CSV

.PARAMETER Port
    TCP port for the local web server. Default: 8271

.PARAMETER NoBrowserOpen
    Do not automatically open the browser on launch.

.EXAMPLE
    .\FolderPermissionManager-GUI.ps1

.EXAMPLE
    .\FolderPermissionManager-GUI.ps1 -Port 9090 -NoBrowserOpen

.NOTES
    Must run as Administrator for ownership operations.
    Press Ctrl+C in the PowerShell window to stop the server.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1024, 65535)]
    [int]$Port = 8271,

    [Parameter()]
    [switch]$NoBrowserOpen
)

$ErrorActionPreference = 'Continue'
$baseUrl = "http://localhost:$Port/"

# Start HTTP listener
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($baseUrl)
try {
    $listener.Start()
    Write-Host "[INFO] Folder Permission Manager running at $baseUrl" -ForegroundColor Cyan
    Write-Host "[INFO] Press Ctrl+C to stop." -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to start HTTP listener on port $Port. Is it already in use? Error: $_"
    exit 1
}

if (-not $NoBrowserOpen) {
    Start-Process $baseUrl
}

# Route handler
function Invoke-Route {
    param(
        [System.Net.HttpListenerContext]$Context
    )

    $request = $Context.Request
    $response = $Context.Response
    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod

    try {
        switch -Regex ("$method $path") {
            '^GET /$'                    { Send-Html $response }
            '^GET /api/drives$'          { Get-Drives $response }
            '^GET /api/children$'        { Get-Children $request $response }
            '^GET /api/acl$'             { Get-FolderAcl $request $response }
            '^POST /api/take-ownership$' { Invoke-TakeOwnership $request $response }
            '^POST /api/replicate$'      { Invoke-ReplicatePermissions $request $response }
            '^POST /api/add-ace$'        { Invoke-AddAce $request $response }
            '^POST /api/remove-ace$'     { Invoke-RemoveAce $request $response }
            '^GET /api/export$'          { Invoke-ExportReport $request $response }
            '^GET /api/shutdown$'        {
                Send-Json $response @{ status = 'shutting down' }
                $script:running = $false
            }
            default {
                $response.StatusCode = 404
                Send-Json $response @{ error = 'Not found' }
            }
        }
    }
    catch {
        $response.StatusCode = 500
        Send-Json $response @{ error = $_.Exception.Message }
    }
}

# JSON helper
function Send-Json {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [object]$Data
    )
    $json = $Data | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.ContentType = 'application/json; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

# HTML helper
function Send-Html {
    param([System.Net.HttpListenerResponse]$Response)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($script:htmlContent)
    $Response.ContentType = 'text/html; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

# Main loop
$script:running = $true
try {
    while ($script:running) {
        $contextTask = $listener.GetContextAsync()
        while (-not $contextTask.IsCompleted) {
            Start-Sleep -Milliseconds 100
        }
        $context = $contextTask.Result
        Invoke-Route -Context $context
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host "[INFO] Server stopped." -ForegroundColor Yellow
}
```

**Step 2: Verify the script parses without errors**

Run: `powershell -NoProfile -Command "& { $null = [scriptblock]::Create((Get-Content 'FolderPermissionManager/FolderPermissionManager-GUI.ps1' -Raw)) }"`
Expected: No output (clean parse)

**Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add HTTP listener skeleton for FolderPermissionManager GUI"
```

---

### Task 2: API Endpoints — Drives and Folder Browsing

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

**Step 1: Implement Get-Drives endpoint**

Returns all available drive letters (fixed + network) plus any mapped network drives. Insert before the main loop.

```powershell
function Get-Drives {
    param([System.Net.HttpListenerResponse]$Response)

    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root } | ForEach-Object {
        $usedGB = [math]::Round($_.Used / 1GB, 1)
        $freeGB = [math]::Round($_.Free / 1GB, 1)
        [PSCustomObject]@{
            name     = $_.Name
            root     = $_.Root
            label    = if ($_.Description) { $_.Description } else { $_.Name }
            usedGB   = $usedGB
            freeGB   = $freeGB
            provider = 'FileSystem'
        }
    }
    Send-Json $Response @($drives)
}
```

**Step 2: Implement Get-Children endpoint**

Returns immediate child folders for a given path (lazy-loading). Query param: `?path=C:\`.

```powershell
function Get-Children {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    $children = @(Get-ChildItem -Path $folderPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $hasChildren = $false
        try {
            $hasChildren = @(Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1).Count -gt 0
        } catch {}

        [PSCustomObject]@{
            name        = $_.Name
            path        = $_.FullName
            hasChildren = $hasChildren
        }
    })
    Send-Json $Response $children
}
```

**Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add drives and folder browsing API endpoints"
```

---

### Task 3: API Endpoints — ACL Read, Ownership, Permissions

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

**Step 1: Implement Get-FolderAcl endpoint**

Returns owner, inheritance status, and all ACL entries for a folder. Query param: `?path=C:\folder`.

```powershell
function Get-FolderAcl {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    try {
        $acl = Get-Acl -Path $folderPath -ErrorAction Stop
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
            path                      = $folderPath
            owner                     = $acl.Owner
            areAccessRulesProtected   = $acl.AreAccessRulesProtected
            entries                   = $entries
        }
        Send-Json $Response $result
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to read ACL: $($_.Exception.Message)" }
    }
}
```

**Step 2: Implement Invoke-TakeOwnership endpoint**

POST body JSON: `{ "path": "C:\\folder", "recursive": true }`. Uses icacls for recursive, Set-Acl for single.

```powershell
function Invoke-TakeOwnership {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $folderPath = $body.path
    $recursive = $body.recursive -eq $true

    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path" }
        return
    }

    try {
        if ($recursive) {
            $output = icacls $folderPath /setowner $env:USERNAME /T /C /Q 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "icacls failed: $output"
            }
            Send-Json $Response @{ status = 'success'; message = "Ownership taken recursively on $folderPath" }
        }
        else {
            $acl = Get-Acl -Path $folderPath
            $owner = [System.Security.Principal.NTAccount]::new($env:USERDOMAIN, $env:USERNAME)
            $acl.SetOwner($owner)
            Set-Acl -Path $folderPath -AclObject $acl -ErrorAction Stop
            Send-Json $Response @{ status = 'success'; message = "Ownership taken on $folderPath" }
        }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Take ownership failed: $($_.Exception.Message)" }
    }
}

# Helper to read JSON POST body
function Read-RequestBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $json = $reader.ReadToEnd()
    $reader.Close()
    return $json | ConvertFrom-Json
}
```

**Step 3: Implement Invoke-ReplicatePermissions endpoint**

POST body: `{ "sourcePath": "C:\\parent", "targetPaths": ["C:\\parent\\child1", "C:\\parent\\child2"] }`.

```powershell
function Invoke-ReplicatePermissions {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $sourcePath = $body.sourcePath
    $targetPaths = @($body.targetPaths)

    if (-not $sourcePath -or -not (Test-Path $sourcePath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid source path" }
        return
    }

    $sourceAcl = Get-Acl -Path $sourcePath -ErrorAction Stop
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $targetPaths) {
        try {
            if (-not (Test-Path $target -PathType Container)) {
                $results.Add([PSCustomObject]@{ path = $target; status = 'skipped'; message = 'Path not found' })
                continue
            }
            $targetAcl = Get-Acl -Path $target
            foreach ($rule in $sourceAcl.Access) {
                $exists = $targetAcl.Access | Where-Object {
                    $_.IdentityReference -eq $rule.IdentityReference -and
                    $_.FileSystemRights -eq $rule.FileSystemRights -and
                    $_.AccessControlType -eq $rule.AccessControlType -and
                    $_.InheritanceFlags -eq $rule.InheritanceFlags -and
                    $_.PropagationFlags -eq $rule.PropagationFlags
                }
                if (-not $exists) {
                    $targetAcl.AddAccessRule($rule)
                }
            }
            Set-Acl -Path $target -AclObject $targetAcl -ErrorAction Stop
            $results.Add([PSCustomObject]@{ path = $target; status = 'success'; message = 'Permissions replicated' })
        }
        catch {
            $results.Add([PSCustomObject]@{ path = $target; status = 'error'; message = $_.Exception.Message })
        }
    }

    Send-Json $Response @{ status = 'complete'; results = @($results) }
}
```

**Step 4: Implement Invoke-AddAce and Invoke-RemoveAce endpoints**

POST body for add: `{ "path": "...", "identity": "DOMAIN\\User", "rights": "Modify", "type": "Allow" }`
POST body for remove: `{ "path": "...", "identity": "DOMAIN\\User", "rights": "Modify", "type": "Allow" }`

```powershell
function Invoke-AddAce {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $folderPath = $body.path
    $identity = $body.identity
    $rights = $body.rights
    $type = $body.type

    if (-not $folderPath -or -not $identity -or -not $rights) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing required fields: path, identity, rights" }
        return
    }

    try {
        $acl = Get-Acl -Path $folderPath -ErrorAction Stop
        $accessType = if ($type -eq 'Deny') { [System.Security.AccessControl.AccessControlType]::Deny } else { [System.Security.AccessControl.AccessControlType]::Allow }
        $fileRights = [System.Security.AccessControl.FileSystemRights]$rights
        $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $account = [System.Security.Principal.NTAccount]::new($identity)

        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($account, $fileRights, $inheritance, $propagation, $accessType)
        $acl.AddAccessRule($rule)
        Set-Acl -Path $folderPath -AclObject $acl -ErrorAction Stop

        Send-Json $Response @{ status = 'success'; message = "Added $type $rights for $identity" }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to add ACE: $($_.Exception.Message)" }
    }
}

function Invoke-RemoveAce {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $folderPath = $body.path
    $identity = $body.identity
    $rights = $body.rights
    $type = $body.type

    if (-not $folderPath -or -not $identity -or -not $rights) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing required fields: path, identity, rights" }
        return
    }

    try {
        $acl = Get-Acl -Path $folderPath -ErrorAction Stop
        $accessType = if ($type -eq 'Deny') { [System.Security.AccessControl.AccessControlType]::Deny } else { [System.Security.AccessControl.AccessControlType]::Allow }
        $fileRights = [System.Security.AccessControl.FileSystemRights]$rights
        $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $account = [System.Security.Principal.NTAccount]::new($identity)

        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($account, $fileRights, $inheritance, $propagation, $accessType)
        $acl.RemoveAccessRuleAll($rule)
        Set-Acl -Path $folderPath -AclObject $acl -ErrorAction Stop

        Send-Json $Response @{ status = 'success'; message = "Removed $type $rights for $identity" }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to remove ACE: $($_.Exception.Message)" }
    }
}
```

**Step 5: Implement Invoke-ExportReport endpoint**

Query param: `?path=C:\folder`. Recursively collects ACLs and returns CSV content.

```powershell
function Invoke-ExportReport {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $folders = @($folderPath) + @(Get-ChildItem -Path $folderPath -Recurse -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

    foreach ($folder in $folders) {
        try {
            $acl = Get-Acl -Path $folder -ErrorAction Stop
            foreach ($entry in $acl.Access) {
                $rows.Add([PSCustomObject]@{
                    Path             = $folder
                    Owner            = $acl.Owner
                    Identity         = $entry.IdentityReference.ToString()
                    Rights           = $entry.FileSystemRights.ToString()
                    AccessType       = $entry.AccessControlType.ToString()
                    IsInherited      = $entry.IsInherited
                    InheritanceFlags = $entry.InheritanceFlags.ToString()
                })
            }
        }
        catch {
            $rows.Add([PSCustomObject]@{
                Path = $folder; Owner = 'ERROR'; Identity = ''; Rights = ''
                AccessType = ''; IsInherited = ''; InheritanceFlags = $_.Exception.Message
            })
        }
    }

    $csv = ($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($csv)
    $Response.ContentType = 'text/csv; charset=utf-8'
    $safeName = ($folderPath -replace '[\\/:*?"<>|]', '_')
    $Response.Headers.Add('Content-Disposition', "attachment; filename=Permissions-$safeName.csv")
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}
```

**Step 6: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add ACL, ownership, replicate, add/remove ACE, and export endpoints"
```

---

### Task 4: HTML/CSS Frontend — Layout and Theme

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

**Step 1: Add the embedded HTML as a here-string variable**

Insert `$script:htmlContent = @"..."@` before the main loop. This contains the full HTML page with:
- CSS variables matching the GPO audit dark/light theme
- Layout: fixed sidebar (280px) with drive picker + folder tree, main content area with toolbar + tab panels
- Confirmation modal overlay
- Status bar at bottom

The HTML should include the complete CSS and the structural HTML elements. JavaScript will be added in subsequent tasks.

Key CSS additions beyond the GPO audit base:
- `.tree-item` — folder tree nodes with indent levels, expand/collapse toggle
- `.tab-bar` / `.tab-btn` / `.tab-panel` — tab switching for Overview/ACL/Children
- `.toolbar` — action buttons row
- `.modal-overlay` / `.modal` — confirmation dialogs
- `.status-bar` — fixed bottom bar for operation feedback
- `.acl-table` — styled permission entries table
- `.badge-allow` / `.badge-deny` — green/red access type badges

**Step 2: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add embedded HTML/CSS frontend with sidebar layout and theme"
```

---

### Task 5: JavaScript — Folder Tree and Drive Browsing

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` (inside the HTML here-string `<script>` block)

**Step 1: Implement drive loading and tree rendering**

On page load, fetch `/api/drives` and render drive buttons in the sidebar. When a drive is clicked, fetch `/api/children?path=C:\` and render the folder tree. Each tree node is clickable to expand (lazy-loads children) or select (loads ACL in main panel).

Key functions:
- `loadDrives()` — fetches drives, renders drive picker
- `loadChildren(path, parentElement)` — fetches children, appends tree nodes
- `toggleTreeNode(element, path)` — expand/collapse tree nodes
- `selectFolder(path)` — sets the active folder, triggers ACL load
- `setStatus(message, type)` — updates the status bar

**Step 2: Implement path bar**

Add a text input at the top of the main panel that shows the current path and allows direct path entry (press Enter to navigate).

**Step 3: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add folder tree browsing and drive picker JavaScript"
```

---

### Task 6: JavaScript — ACL Display Tabs (Overview, ACL Entries, Children)

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` (inside `<script>`)

**Step 1: Implement tab switching**

Wire up tab buttons to show/hide tab panels. Three tabs: Overview, ACL Entries, Children.

**Step 2: Implement Overview tab**

When a folder is selected, fetch `/api/acl?path=...` and display:
- Owner (with "Take Ownership" button inline)
- Inheritance status (protected or inheriting)
- Summary counts: N allow rules, N deny rules, N inherited

**Step 3: Implement ACL Entries tab**

Render a table of all access entries from the ACL response:
- Columns: Identity, Rights, Type (Allow/Deny badge), Inherited, Applies To
- Each non-inherited row gets a "Remove" button
- "Add Permission" button at top

**Step 4: Implement Children tab**

Fetch `/api/children?path=...` and render a table of child folders with:
- Checkbox column for bulk selection
- Folder name, owner (fetched per-child via individual `/api/acl` calls, loaded lazily)
- "Select All" checkbox in header
- "Replicate Permissions" button that sends selected paths to `/api/replicate`

**Step 5: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add Overview, ACL Entries, and Children tab panels"
```

---

### Task 7: JavaScript — Action Modals and Operations

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1` (inside `<script>`)

**Step 1: Implement confirmation modal system**

Generic `showModal(title, bodyHtml, onConfirm)` function that displays a centered modal with title, body content, Cancel and Confirm buttons. Clicking outside or Cancel closes it.

**Step 2: Implement Take Ownership action**

Button in toolbar and in Overview tab. Shows modal with "Take ownership of [path]?" and a "Recursive" checkbox. On confirm, POST to `/api/take-ownership`.

**Step 3: Implement Add Permission modal**

"Add Permission" button opens a modal with:
- Identity text input (e.g. `DOMAIN\GroupName`)
- Rights dropdown: FullControl, Modify, ReadAndExecute, Read, Write
- Type: Allow / Deny radio buttons
On confirm, POST to `/api/add-ace`.

**Step 4: Implement Remove Permission action**

"Remove" button on each non-inherited ACL row. Shows confirmation modal. On confirm, POST to `/api/remove-ace`.

**Step 5: Implement Replicate Permissions action**

Button in Children tab and toolbar. Shows modal listing selected child folders. On confirm, POST to `/api/replicate` with source as current folder and selected children as targets.

**Step 6: Implement Export Report action**

Button in toolbar. Triggers a download by navigating to `/api/export?path=...` (browser handles CSV download).

**Step 7: Implement theme toggle**

Button in sidebar footer. Toggles `body.light` class, saves to localStorage.

**Step 8: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add action modals, theme toggle, and all permission operations"
```

---

### Task 8: Status Bar, Error Handling, Polish

**Files:**
- Modify: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`

**Step 1: Wire up status bar to all operations**

Every API call should update the status bar: "Loading..." on start, "Done" on success (green), error message on failure (red). Auto-clear after 5 seconds.

**Step 2: Add loading states**

Disable action buttons during API calls. Show a subtle spinner or "Working..." text in the status bar.

**Step 3: Handle edge cases**

- Access denied errors shown in status bar, not as alerts
- Empty folders show "No subfolders" message
- Network paths that are slow to respond get a timeout message
- Refresh button in toolbar to reload current folder

**Step 4: Commit**

```bash
git add FolderPermissionManager/FolderPermissionManager-GUI.ps1
git commit -m "feat: add status bar feedback, loading states, and error handling"
```

---

### Task 9: README Update

**Files:**
- Modify: `FolderPermissionManager/README.md`

**Step 1: Update README to document both scripts**

Add documentation for the new GUI script: what it does, how to launch, screenshots description, available actions, and that it requires Administrator.

**Step 2: Commit and push**

```bash
git add FolderPermissionManager/README.md
git commit -m "docs: update FolderPermissionManager README with GUI documentation"
```

---

## Summary

| Task | Description | Key Output |
|------|-------------|------------|
| 1 | HTTP listener skeleton | Working server that accepts requests |
| 2 | Drives + folder browsing API | `/api/drives`, `/api/children` |
| 3 | ACL + ownership + permissions API | `/api/acl`, `/api/take-ownership`, `/api/replicate`, `/api/add-ace`, `/api/remove-ace`, `/api/export` |
| 4 | HTML/CSS frontend layout | Sidebar + main panel + theme |
| 5 | JS folder tree browsing | Drive picker, lazy tree, path bar |
| 6 | JS ACL display tabs | Overview, ACL Entries, Children tabs |
| 7 | JS action modals | Take ownership, add/remove ACE, replicate, export |
| 8 | Polish | Status bar, loading states, error handling |
| 9 | README | Documentation |
