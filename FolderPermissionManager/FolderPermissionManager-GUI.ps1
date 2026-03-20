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

# --- Helper Functions ---

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

# Helper to read JSON POST body
function Read-RequestBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $json = $reader.ReadToEnd()
    $reader.Close()
    return $json | ConvertFrom-Json
}

# --- API Endpoint Functions ---

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

# --- Route Dispatcher ---

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

# --- Placeholder HTML Content ---

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
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--bg);
    color: var(--text);
    overflow: hidden;
}
.layout {
    display: flex;
    min-height: 100vh;
}

/* Sidebar */
.sidebar {
    width: 280px;
    min-width: 280px;
    background: var(--bg-card);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    height: 100vh;
    position: fixed;
    left: 0;
    top: 0;
    z-index: 10;
}
.sidebar-header {
    padding: 20px 16px 12px;
    border-bottom: 1px solid var(--border);
}
.sidebar-header h1 {
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
}
.sidebar-section {
    padding: 12px 16px 8px;
}
.sidebar-section-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 8px;
}
.drive-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.drive-btn {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    transition: all 0.15s;
}
.drive-btn:hover { background: var(--bg-hover); border-color: var(--accent); }
.drive-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

/* Tree */
.tree-container {
    flex: 1;
    overflow-y: auto;
    padding: 4px 0;
}
.tree-node {
    user-select: none;
}
.tree-node-row {
    display: flex;
    align-items: center;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 13px;
    white-space: nowrap;
    transition: background 0.1s;
}
.tree-node-row:hover { background: var(--bg-hover); }
.tree-node-row.active { background: var(--accent); color: #fff; }
.tree-arrow {
    width: 18px;
    text-align: center;
    font-size: 10px;
    color: var(--text-muted);
    flex-shrink: 0;
    cursor: pointer;
}
.tree-arrow.empty { visibility: hidden; }
.tree-icon { margin-right: 6px; font-size: 14px; flex-shrink: 0; }
.tree-label { overflow: hidden; text-overflow: ellipsis; }
.tree-children { display: none; }
.tree-children.expanded { display: block; }

/* Sidebar footer */
.sidebar-footer {
    padding: 12px 16px;
    border-top: 1px solid var(--border);
}
.theme-toggle {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    width: 100%;
    transition: all 0.15s;
}
.theme-toggle:hover { background: var(--bg-hover); }

/* Main Content */
.main {
    margin-left: 280px;
    flex: 1;
    display: flex;
    flex-direction: column;
    height: 100vh;
}
.path-bar {
    display: flex;
    align-items: center;
    padding: 10px 16px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    gap: 8px;
}
.path-bar label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.path-input {
    flex: 1;
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 12px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
}
.path-input:focus { outline: none; border-color: var(--accent); }

/* Toolbar */
.toolbar {
    display: flex;
    align-items: center;
    padding: 8px 16px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    gap: 8px;
    flex-wrap: wrap;
}
.toolbar-btn {
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 14px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    transition: all 0.15s;
    white-space: nowrap;
}
.toolbar-btn:hover:not(:disabled) { background: var(--bg-hover); border-color: var(--accent); color: var(--accent); }
.toolbar-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.toolbar-btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
.toolbar-btn.primary:hover:not(:disabled) { background: var(--accent-hover); }
.toolbar-btn.danger { border-color: var(--danger); color: var(--danger); }
.toolbar-btn.danger:hover:not(:disabled) { background: var(--danger); color: #fff; }

/* Tabs */
.tab-bar {
    display: flex;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
    padding: 0 16px;
}
.tab-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    padding: 10px 20px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Tab panels */
.tab-content {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
}
.tab-panel { display: none; }
.tab-panel.active { display: block; }

/* Overview panel */
.overview-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 12px;
}
.overview-card h3 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 8px;
}
.overview-card .value {
    font-size: 15px;
    color: var(--text);
    word-break: break-all;
}
.overview-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}
.overview-row .overview-card { flex: 1; min-width: 180px; }
.stat-number {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
}

/* ACL Table */
.acl-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.acl-table th {
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-card);
    border-bottom: 2px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    position: sticky;
    top: 0;
}
.acl-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    word-break: break-word;
    max-width: 300px;
}
.acl-table tr:hover td { background: var(--bg-hover); }
.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}
.badge-allow { background: rgba(46,204,113,0.15); color: var(--success); }
.badge-deny { background: rgba(231,76,60,0.15); color: var(--danger); }
.badge-inherited { background: rgba(93,173,226,0.1); color: var(--accent); font-size: 10px; }
.badge-explicit { background: rgba(243,156,18,0.15); color: var(--warning); font-size: 10px; }
.remove-btn {
    background: none;
    border: 1px solid var(--danger);
    color: var(--danger);
    padding: 3px 8px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
    font-family: inherit;
}
.remove-btn:hover { background: var(--danger); color: #fff; }

/* Children table */
.children-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
.children-table th {
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-card);
    border-bottom: 2px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
}
.children-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
}
.children-table tr:hover td { background: var(--bg-hover); }

/* Modal */
.modal-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}
.modal {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    min-width: 400px;
    max-width: 560px;
    max-height: 80vh;
    overflow-y: auto;
    box-shadow: 0 8px 32px var(--shadow);
}
.modal h2 {
    font-size: 16px;
    margin-bottom: 16px;
    color: var(--accent);
}
.modal p { font-size: 13px; margin-bottom: 12px; color: var(--text-muted); }
.modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 20px;
}
.modal-actions button {
    padding: 8px 20px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
    font-family: inherit;
    border: 1px solid var(--border);
}
.btn-cancel { background: var(--bg); color: var(--text); }
.btn-cancel:hover { background: var(--bg-hover); }
.btn-confirm { background: var(--accent); color: #fff; border-color: var(--accent); }
.btn-confirm:hover { background: var(--accent-hover); }
.btn-danger-confirm { background: var(--danger); color: #fff; border-color: var(--danger); }
.btn-danger-confirm:hover { background: var(--danger-hover); }

/* Form elements inside modals */
.form-group {
    margin-bottom: 14px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}
.form-group input[type='text'],
.form-group select {
    width: 100%;
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 13px;
    font-family: inherit;
}
.form-group input:focus,
.form-group select:focus { outline: none; border-color: var(--accent); }
.radio-group {
    display: flex;
    gap: 16px;
    align-items: center;
    padding-top: 4px;
}
.radio-group label {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-transform: none;
    font-weight: normal;
    cursor: pointer;
}
.checkbox-group {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 8px;
}
.checkbox-group label {
    text-transform: none;
    font-weight: normal;
    cursor: pointer;
}
.target-list {
    max-height: 150px;
    overflow-y: auto;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px;
    font-size: 12px;
    margin-top: 8px;
}
.target-list div {
    padding: 2px 0;
    color: var(--text-muted);
}

/* Status bar */
.status-bar {
    background: var(--bg-card);
    border-top: 1px solid var(--border);
    padding: 6px 16px;
    font-size: 12px;
    color: var(--text-muted);
    min-height: 32px;
    display: flex;
    align-items: center;
}
.status-bar.info { color: var(--accent); }
.status-bar.success { color: var(--success); }
.status-bar.error { color: var(--danger); }
.status-bar.working { color: var(--warning); }

/* Empty state */
.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-muted);
}
.empty-state .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.4; }
.empty-state p { font-size: 14px; }

/* Scrollbar */
::-webkit-scrollbar { width: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
</style>
</head>
<body>
<div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-header">
            <h1>Folder Permissions</h1>
        </div>
        <div class="sidebar-section">
            <div class="sidebar-section-title">Drives</div>
            <div class="drive-list" id="driveList"></div>
        </div>
        <div class="sidebar-section" style="flex:0 0 auto;">
            <div class="sidebar-section-title">Folder Tree</div>
        </div>
        <div class="tree-container" id="treeContainer"></div>
        <div class="sidebar-footer">
            <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">Toggle Theme</button>
        </div>
    </aside>

    <!-- Main -->
    <main class="main">
        <div class="path-bar">
            <label>Path</label>
            <input type="text" class="path-input" id="pathInput" placeholder="Select a folder or type a path and press Enter" />
        </div>
        <div class="toolbar">
            <button class="toolbar-btn" id="btnOwnership" onclick="showTakeOwnershipModal()" disabled>Take Ownership</button>
            <button class="toolbar-btn primary" id="btnAddPerm" onclick="showAddPermissionModal()" disabled>Add Permission</button>
            <button class="toolbar-btn" id="btnReplicate" onclick="showReplicateModal()" disabled>Replicate Permissions</button>
            <button class="toolbar-btn" id="btnExport" onclick="exportCsv()" disabled>Export CSV</button>
            <button class="toolbar-btn" id="btnRefresh" onclick="refreshCurrent()" disabled>Refresh</button>
        </div>
        <div class="tab-bar">
            <button class="tab-btn active" onclick="switchTab('overview')">Overview</button>
            <button class="tab-btn" onclick="switchTab('acl')">ACL Entries</button>
            <button class="tab-btn" onclick="switchTab('children')">Children</button>
        </div>
        <div class="tab-content">
            <div class="tab-panel active" id="panel-overview">
                <div class="empty-state" id="overviewEmpty">
                    <div class="icon">&#128193;</div>
                    <p>Select a folder from the sidebar to view its permissions.</p>
                </div>
                <div id="overviewContent" style="display:none;"></div>
            </div>
            <div class="tab-panel" id="panel-acl">
                <div class="empty-state" id="aclEmpty">
                    <div class="icon">&#128274;</div>
                    <p>Select a folder to view its ACL entries.</p>
                </div>
                <div id="aclContent" style="display:none;"></div>
            </div>
            <div class="tab-panel" id="panel-children">
                <div class="empty-state" id="childrenEmpty">
                    <div class="icon">&#128194;</div>
                    <p>Select a folder to view its subfolders.</p>
                </div>
                <div id="childrenContent" style="display:none;"></div>
            </div>
        </div>
        <div class="status-bar" id="statusBar">Ready</div>
    </main>
</div>

<script>
(function() {
    var currentPath = '';
    var currentAcl = null;
    var childrenData = [];
    var statusTimer = null;

    // --- Theme ---
    function initTheme() {
        var saved = localStorage.getItem('fpm-theme');
        if (saved === 'light') {
            document.body.classList.add('light');
        }
        updateThemeButton();
    }
    function updateThemeButton() {
        var btn = document.getElementById('themeToggle');
        var isLight = document.body.classList.contains('light');
        btn.textContent = isLight ? 'Switch to Dark Theme' : 'Switch to Light Theme';
    }
    window.toggleTheme = function() {
        document.body.classList.toggle('light');
        var isLight = document.body.classList.contains('light');
        localStorage.setItem('fpm-theme', isLight ? 'light' : 'dark');
        updateThemeButton();
    };

    // --- Status Bar ---
    function setStatus(message, type) {
        var bar = document.getElementById('statusBar');
        bar.textContent = message;
        bar.className = 'status-bar';
        if (type) bar.classList.add(type);
        if (statusTimer) clearTimeout(statusTimer);
        if (type !== 'error') {
            statusTimer = setTimeout(function() {
                bar.textContent = 'Ready';
                bar.className = 'status-bar';
            }, 5000);
        }
    }
    window.setStatus = setStatus;

    // --- API Helpers ---
    function apiGet(url) {
        setStatus('Working...', 'working');
        return fetch(url).then(function(r) {
            if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Request failed'); });
            return r.json();
        });
    }
    function apiPost(url, data) {
        setStatus('Working...', 'working');
        return fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        }).then(function(r) {
            if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'Request failed'); });
            return r.json();
        });
    }

    // --- Modal System ---
    function showModal(title, bodyHtml, confirmText, onConfirm, isDanger) {
        closeModal();
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.id = 'modalOverlay';
        overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };

        var confirmClass = isDanger ? 'btn-danger-confirm' : 'btn-confirm';
        overlay.innerHTML = '<div class="modal">' +
            '<h2>' + escHtml(title) + '</h2>' +
            '<div id="modalBody">' + bodyHtml + '</div>' +
            '<div class="modal-actions">' +
            '<button class="btn-cancel" onclick="closeModal()">Cancel</button>' +
            '<button class="' + confirmClass + '" id="modalConfirmBtn">' + escHtml(confirmText) + '</button>' +
            '</div></div>';
        document.body.appendChild(overlay);
        document.getElementById('modalConfirmBtn').onclick = function() {
            onConfirm();
        };
    }
    window.showModal = showModal;
    function closeModal() {
        var el = document.getElementById('modalOverlay');
        if (el) el.remove();
    }
    window.closeModal = closeModal;

    function escHtml(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    // --- Drives ---
    function loadDrives() {
        apiGet('/api/drives').then(function(drives) {
            var container = document.getElementById('driveList');
            container.innerHTML = '';
            drives.forEach(function(d) {
                var btn = document.createElement('button');
                btn.className = 'drive-btn';
                btn.textContent = d.name + ': ' + d.label;
                btn.title = d.root + ' (' + d.freeGB + ' GB free)';
                btn.onclick = function() { selectDrive(d.root, btn); };
                container.appendChild(btn);
            });
            setStatus('Drives loaded', 'info');
        }).catch(function(err) {
            setStatus('Failed to load drives: ' + err.message, 'error');
        });
    }

    function selectDrive(root, btnEl) {
        var btns = document.querySelectorAll('.drive-btn');
        btns.forEach(function(b) { b.classList.remove('active'); });
        if (btnEl) btnEl.classList.add('active');
        document.getElementById('treeContainer').innerHTML = '';
        loadChildren(root, document.getElementById('treeContainer'), 0);
    }

    // --- Tree ---
    function loadChildren(path, parentEl, level) {
        apiGet('/api/children?path=' + encodeURIComponent(path)).then(function(children) {
            children.forEach(function(child) {
                var node = document.createElement('div');
                node.className = 'tree-node';

                var row = document.createElement('div');
                row.className = 'tree-node-row';
                row.style.paddingLeft = (8 + level * 16) + 'px';

                var arrow = document.createElement('span');
                arrow.className = 'tree-arrow' + (child.hasChildren ? '' : ' empty');
                arrow.textContent = child.hasChildren ? '\u25B6' : '';

                var icon = document.createElement('span');
                icon.className = 'tree-icon';
                icon.textContent = '\uD83D\uDCC1';

                var label = document.createElement('span');
                label.className = 'tree-label';
                label.textContent = child.name;

                row.appendChild(arrow);
                row.appendChild(icon);
                row.appendChild(label);
                node.appendChild(row);

                var childrenContainer = document.createElement('div');
                childrenContainer.className = 'tree-children';
                node.appendChild(childrenContainer);

                var loaded = false;

                function toggleExpand(e) {
                    if (e) e.stopPropagation();
                    if (!child.hasChildren) return;
                    var isExpanded = childrenContainer.classList.contains('expanded');
                    if (isExpanded) {
                        childrenContainer.classList.remove('expanded');
                        arrow.textContent = '\u25B6';
                    } else {
                        childrenContainer.classList.add('expanded');
                        arrow.textContent = '\u25BC';
                        if (!loaded) {
                            loaded = true;
                            loadChildren(child.path, childrenContainer, level + 1);
                        }
                    }
                }

                arrow.onclick = toggleExpand;
                row.onclick = function() { selectFolder(child.path); };
                row.ondblclick = toggleExpand;

                parentEl.appendChild(node);
            });
            if (children.length === 0 && level === 0) {
                setStatus('No subfolders found', 'info');
            }
        }).catch(function(err) {
            setStatus('Failed to load children: ' + err.message, 'error');
        });
    }

    function selectFolder(path) {
        currentPath = path;
        document.getElementById('pathInput').value = path;

        // highlight active tree row
        var rows = document.querySelectorAll('.tree-node-row');
        rows.forEach(function(r) { r.classList.remove('active'); });
        // find matching row by checking label text against path
        rows.forEach(function(r) {
            var lbl = r.querySelector('.tree-label');
            // match by the folder name being the last segment of the path
            var parts = path.replace(/[\\/]+/g, '/').replace(/\/$/, '').split('/');
            var folderName = parts[parts.length - 1];
            if (lbl && lbl.textContent === folderName) {
                r.classList.add('active');
            }
        });

        // enable toolbar
        document.getElementById('btnOwnership').disabled = false;
        document.getElementById('btnAddPerm').disabled = false;
        document.getElementById('btnReplicate').disabled = false;
        document.getElementById('btnExport').disabled = false;
        document.getElementById('btnRefresh').disabled = false;

        loadAcl(path);
        loadChildrenTab(path);
    }
    window.selectFolder = selectFolder;

    // --- Path input ---
    document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('pathInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                var p = this.value.trim();
                if (p) selectFolder(p);
            }
        });
    });

    // --- ACL Loading ---
    function loadAcl(path) {
        apiGet('/api/acl?path=' + encodeURIComponent(path)).then(function(data) {
            currentAcl = data;
            renderOverview(data);
            renderAclTable(data);
            setStatus('Loaded permissions for ' + path, 'success');
        }).catch(function(err) {
            setStatus('Failed to load ACL: ' + err.message, 'error');
        });
    }

    // --- Overview Tab ---
    function renderOverview(data) {
        var el = document.getElementById('overviewContent');
        document.getElementById('overviewEmpty').style.display = 'none';
        el.style.display = 'block';

        var allowCount = 0, denyCount = 0, inheritedCount = 0;
        data.entries.forEach(function(e) {
            if (e.type === 'Allow') allowCount++;
            else denyCount++;
            if (e.isInherited) inheritedCount++;
        });

        var inheritText = data.areAccessRulesProtected ? 'Protected (explicit only)' : 'Inheriting from parent';

        el.innerHTML =
            '<div class="overview-card">' +
                '<h3>Owner</h3>' +
                '<div class="value">' + escHtml(data.owner) +
                ' <button class="toolbar-btn" style="margin-left:12px;padding:3px 10px;font-size:11px;" onclick="showTakeOwnershipModal()">Take Ownership</button></div>' +
            '</div>' +
            '<div class="overview-card">' +
                '<h3>Inheritance</h3>' +
                '<div class="value">' + escHtml(inheritText) + '</div>' +
            '</div>' +
            '<div class="overview-row">' +
                '<div class="overview-card"><h3>Allow Rules</h3><div class="stat-number">' + allowCount + '</div></div>' +
                '<div class="overview-card"><h3>Deny Rules</h3><div class="stat-number" style="color:var(--danger)">' + denyCount + '</div></div>' +
                '<div class="overview-card"><h3>Inherited</h3><div class="stat-number" style="color:var(--text-muted)">' + inheritedCount + '</div></div>' +
            '</div>';
    }

    // --- ACL Table ---
    function renderAclTable(data) {
        var el = document.getElementById('aclContent');
        document.getElementById('aclEmpty').style.display = 'none';
        el.style.display = 'block';

        var html = '<table class="acl-table"><thead><tr>' +
            '<th>Identity</th><th>Rights</th><th>Type</th><th>Inherited</th><th>Applies To</th><th></th>' +
            '</tr></thead><tbody>';

        data.entries.forEach(function(entry, idx) {
            var typeBadge = entry.type === 'Allow'
                ? '<span class="badge badge-allow">Allow</span>'
                : '<span class="badge badge-deny">Deny</span>';
            var inheritBadge = entry.isInherited
                ? '<span class="badge badge-inherited">Inherited</span>'
                : '<span class="badge badge-explicit">Explicit</span>';

            var appliesTo = entry.inheritanceFlags || 'This folder only';

            var removeCell = '';
            if (!entry.isInherited) {
                removeCell = '<button class="remove-btn" onclick="showRemoveModal(' + idx + ')">Remove</button>';
            }

            html += '<tr>' +
                '<td>' + escHtml(entry.identity) + '</td>' +
                '<td>' + escHtml(entry.rights) + '</td>' +
                '<td>' + typeBadge + '</td>' +
                '<td>' + inheritBadge + '</td>' +
                '<td>' + escHtml(appliesTo) + '</td>' +
                '<td>' + removeCell + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        el.innerHTML = html;
    }

    // --- Children Tab ---
    function loadChildrenTab(path) {
        apiGet('/api/children?path=' + encodeURIComponent(path)).then(function(children) {
            childrenData = children;
            renderChildrenTable(children);
        }).catch(function(err) {
            setStatus('Failed to load children: ' + err.message, 'error');
        });
    }

    function renderChildrenTable(children) {
        var el = document.getElementById('childrenContent');
        if (children.length === 0) {
            document.getElementById('childrenEmpty').style.display = 'block';
            document.getElementById('childrenEmpty').querySelector('p').textContent = 'No subfolders found.';
            el.style.display = 'none';
            return;
        }
        document.getElementById('childrenEmpty').style.display = 'none';
        el.style.display = 'block';

        var html = '<div style="margin-bottom:10px;"><button class="toolbar-btn primary" onclick="replicateSelected()">Replicate Permissions to Selected</button></div>' +
            '<table class="children-table"><thead><tr>' +
            '<th><input type="checkbox" id="selectAllChildren" onchange="toggleSelectAllChildren(this)" /></th>' +
            '<th>Name</th><th>Owner</th>' +
            '</tr></thead><tbody>';

        children.forEach(function(child, idx) {
            html += '<tr>' +
                '<td><input type="checkbox" class="child-check" data-path="' + escHtml(child.path) + '" /></td>' +
                '<td>' + escHtml(child.name) + '</td>' +
                '<td id="child-owner-' + idx + '"><span class="badge badge-inherited" style="cursor:pointer" onclick="loadChildOwner(' + idx + ',\'' + escHtml(child.path).replace(/'/g, "\\'") + '\')">Load</span></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        el.innerHTML = html;
    }

    window.toggleSelectAllChildren = function(el) {
        var checks = document.querySelectorAll('.child-check');
        checks.forEach(function(c) { c.checked = el.checked; });
    };

    window.loadChildOwner = function(idx, path) {
        var cell = document.getElementById('child-owner-' + idx);
        cell.textContent = 'Loading...';
        apiGet('/api/acl?path=' + encodeURIComponent(path)).then(function(data) {
            cell.textContent = data.owner;
        }).catch(function() {
            cell.textContent = 'Error';
        });
    };

    // --- Tab Switching ---
    window.switchTab = function(tabName) {
        var btns = document.querySelectorAll('.tab-btn');
        btns.forEach(function(b, i) {
            var names = ['overview', 'acl', 'children'];
            if (names[i] === tabName) b.classList.add('active');
            else b.classList.remove('active');
        });
        var panels = document.querySelectorAll('.tab-panel');
        panels.forEach(function(p) {
            if (p.id === 'panel-' + tabName) p.classList.add('active');
            else p.classList.remove('active');
        });
    };

    // --- Action Modals ---
    window.showTakeOwnershipModal = function() {
        if (!currentPath) return;
        var body = '<p>Take ownership of:</p>' +
            '<p style="color:var(--text);word-break:break-all;font-weight:600;">' + escHtml(currentPath) + '</p>' +
            '<div class="checkbox-group">' +
            '<input type="checkbox" id="ownerRecursive" />' +
            '<label for="ownerRecursive">Recursive (include all subfolders)</label>' +
            '</div>';
        showModal('Take Ownership', body, 'Take Ownership', function() {
            var recursive = document.getElementById('ownerRecursive').checked;
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/take-ownership', { path: currentPath, recursive: recursive }).then(function(data) {
                closeModal();
                setStatus(data.message, 'success');
                loadAcl(currentPath);
            }).catch(function(err) {
                closeModal();
                setStatus('Take ownership failed: ' + err.message, 'error');
            });
        }, false);
    };

    window.showAddPermissionModal = function() {
        if (!currentPath) return;
        var body = '<div class="form-group">' +
            '<label>Identity (e.g. DOMAIN\\User or Everyone)</label>' +
            '<input type="text" id="aceIdentity" />' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Rights</label>' +
            '<select id="aceRights">' +
            '<option value="FullControl">Full Control</option>' +
            '<option value="Modify">Modify</option>' +
            '<option value="ReadAndExecute" selected>Read &amp; Execute</option>' +
            '<option value="Read">Read</option>' +
            '<option value="Write">Write</option>' +
            '</select>' +
            '</div>' +
            '<div class="form-group">' +
            '<label>Type</label>' +
            '<div class="radio-group">' +
            '<label><input type="radio" name="aceType" value="Allow" checked /> Allow</label>' +
            '<label><input type="radio" name="aceType" value="Deny" /> Deny</label>' +
            '</div>' +
            '</div>';
        showModal('Add Permission', body, 'Add Permission', function() {
            var identity = document.getElementById('aceIdentity').value.trim();
            if (!identity) { setStatus('Identity is required', 'error'); return; }
            var rights = document.getElementById('aceRights').value;
            var typeRadio = document.querySelector('input[name="aceType"]:checked');
            var type = typeRadio ? typeRadio.value : 'Allow';
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/add-ace', { path: currentPath, identity: identity, rights: rights, type: type }).then(function(data) {
                closeModal();
                setStatus(data.message, 'success');
                loadAcl(currentPath);
            }).catch(function(err) {
                closeModal();
                setStatus('Add permission failed: ' + err.message, 'error');
            });
        }, false);
    };

    window.showRemoveModal = function(idx) {
        if (!currentAcl || !currentAcl.entries[idx]) return;
        var entry = currentAcl.entries[idx];
        var body = '<p>Remove the following permission?</p>' +
            '<p style="color:var(--text)"><strong>' + escHtml(entry.identity) + '</strong></p>' +
            '<p>' + escHtml(entry.type) + ': ' + escHtml(entry.rights) + '</p>' +
            '<p style="color:var(--text);word-break:break-all;">' + escHtml(currentPath) + '</p>';
        showModal('Remove Permission', body, 'Remove', function() {
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/remove-ace', {
                path: currentPath,
                identity: entry.identity,
                rights: entry.rights,
                type: entry.type
            }).then(function(data) {
                closeModal();
                setStatus(data.message, 'success');
                loadAcl(currentPath);
            }).catch(function(err) {
                closeModal();
                setStatus('Remove failed: ' + err.message, 'error');
            });
        }, true);
    };

    window.showReplicateModal = function() {
        if (!currentPath) return;
        var checks = document.querySelectorAll('.child-check:checked');
        var targets = [];
        checks.forEach(function(c) { targets.push(c.getAttribute('data-path')); });
        if (targets.length === 0) {
            setStatus('Select subfolders in the Children tab first', 'error');
            switchTab('children');
            return;
        }
        var listHtml = '<div class="target-list">';
        targets.forEach(function(t) { listHtml += '<div>' + escHtml(t) + '</div>'; });
        listHtml += '</div>';

        var body = '<p>Copy permissions from:</p>' +
            '<p style="color:var(--text);font-weight:600;word-break:break-all;">' + escHtml(currentPath) + '</p>' +
            '<p>To ' + targets.length + ' selected folder(s):</p>' +
            listHtml;
        showModal('Replicate Permissions', body, 'Replicate', function() {
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/replicate', { sourcePath: currentPath, targetPaths: targets }).then(function(data) {
                closeModal();
                var successes = 0;
                var errors = 0;
                if (data.results) {
                    data.results.forEach(function(r) {
                        if (r.status === 'success') successes++;
                        else errors++;
                    });
                }
                setStatus('Replication complete: ' + successes + ' succeeded, ' + errors + ' failed', errors > 0 ? 'error' : 'success');
            }).catch(function(err) {
                closeModal();
                setStatus('Replication failed: ' + err.message, 'error');
            });
        }, false);
    };

    window.replicateSelected = function() {
        window.showReplicateModal();
    };

    // --- Export ---
    window.exportCsv = function() {
        if (!currentPath) return;
        window.location.href = '/api/export?path=' + encodeURIComponent(currentPath);
        setStatus('Export started for ' + currentPath, 'info');
    };

    // --- Refresh ---
    window.refreshCurrent = function() {
        if (!currentPath) return;
        loadAcl(currentPath);
        loadChildrenTab(currentPath);
    };

    // --- Init ---
    initTheme();
    loadDrives();
})();
</script>
</body>
</html>
"@

# --- Start HTTP Listener ---

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

# --- Main Request Loop ---

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
