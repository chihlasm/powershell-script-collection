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

# Cache mapped network drives from the user session via WMI
# Elevated processes can't see drive mappings, so we grab them here
$script:driveMappings = @{}
try {
    Get-WmiObject -Class Win32_MappedLogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        $script:driveMappings[$_.DeviceID.TrimEnd(':').ToUpper()] = $_.ProviderName
    }
    # Also try net use as a fallback
    $netUse = net use 2>$null | Where-Object { $_ -match '^\s*(OK|Disconnected|Unavailable)\s+([A-Z]:)\s+(\\\\[^\s]+)' }
    foreach ($line in $netUse) {
        if ($line -match '^\s*(?:OK|Disconnected|Unavailable)\s+([A-Z]:)\s+(\\\\[^\s]+)') {
            $letter = $Matches[1].TrimEnd(':').ToUpper()
            if (-not $script:driveMappings.ContainsKey($letter)) {
                $script:driveMappings[$letter] = $Matches[2]
            }
        }
    }
    if ($script:driveMappings.Count -gt 0) {
        Write-Host "[INFO] Found $($script:driveMappings.Count) mapped drive(s): $(($script:driveMappings.GetEnumerator() | ForEach-Object { "$($_.Key): -> $($_.Value)" }) -join ', ')" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "[WARN] Could not enumerate mapped drives: $_" -ForegroundColor Yellow
}

# --- Helper Functions ---

# JSON helper
function Send-Json {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [object]$Data
    )
    if ($null -eq $Data) { $Data = @() }
    $json = $Data | ConvertTo-Json -Depth 10 -Compress
    if ([string]::IsNullOrEmpty($json)) { $json = '[]' }
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

function Resolve-MappedDrive {
    # Elevated sessions can't see mapped drives from the standard user session.
    # Query WMI for all mapped network drives so we can resolve letter -> UNC path.
    param([string]$Path)
    if ($Path -match '^([A-Za-z]):\\') {
        $letter = $Matches[1]
        $mapping = $script:driveMappings[$letter.ToUpper()]
        if ($mapping) {
            return $Path -replace "^$letter`:\\", "$mapping\"
        }
    }
    return $Path
}

function Get-Drives {
    param([System.Net.HttpListenerResponse]$Response)

    # Get local filesystem drives
    $drives = [System.Collections.Generic.List[object]]::new()
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root } | ForEach-Object {
        $usedGB = [math]::Round($_.Used / 1GB, 1)
        $freeGB = [math]::Round($_.Free / 1GB, 1)
        $drives.Add([PSCustomObject]@{
            name     = $_.Name
            root     = $_.Root
            label    = if ($_.Description) { $_.Description } else { $_.Name }
            usedGB   = $usedGB
            freeGB   = $freeGB
            provider = 'FileSystem'
            isMapped = $false
        })
    }

    # Also include mapped drives from the non-elevated user session via WMI
    # These won't show in Get-PSDrive when running elevated
    foreach ($letter in $script:driveMappings.Keys) {
        $existing = $drives | Where-Object { $_.name -eq $letter }
        if (-not $existing) {
            $unc = $script:driveMappings[$letter]
            $drives.Add([PSCustomObject]@{
                name     = $letter
                root     = "$letter`:\"
                label    = "$letter ($unc)"
                usedGB   = 0
                freeGB   = 0
                provider = 'FileSystem'
                isMapped = $true
                uncPath  = $unc
            })
        }
    }

    Send-Json $Response @($drives)
}

function Get-Children {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = Resolve-MappedDrive $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    try {
        $items = Get-ChildItem -Path $folderPath -Directory -Force -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $Response.StatusCode = 403
        Send-Json $Response @{ error = "Access denied to '$folderPath'. Try taking ownership first." }
        return
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to list '$folderPath': $($_.Exception.Message)" }
        return
    }

    $children = @($items | ForEach-Object {
        $hasChildren = $false
        try {
            $hasChildren = @(Get-ChildItem -Path $_.FullName -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 1).Count -gt 0
        } catch {}

        [PSCustomObject]@{
            name        = $_.Name
            path        = $_.FullName
            hasChildren = $hasChildren
        }
    })
    if ($null -eq $children) { $children = @() }
    Send-Json $Response $children
}

function Get-Files {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = Resolve-MappedDrive $Request.QueryString['path']
    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path parameter" }
        return
    }

    try {
        $items = Get-ChildItem -Path $folderPath -File -Force -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $Response.StatusCode = 403
        Send-Json $Response @{ error = "Access denied to '$folderPath'. Try taking ownership first." }
        return
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Failed to list files: $($_.Exception.Message)" }
        return
    }

    $files = @($items | ForEach-Object {
        $sizeDisplay = if ($_.Length -gt 1GB) { "$([math]::Round($_.Length / 1GB, 2)) GB" }
                       elseif ($_.Length -gt 1MB) { "$([math]::Round($_.Length / 1MB, 1)) MB" }
                       elseif ($_.Length -gt 1KB) { "$([math]::Round($_.Length / 1KB, 1)) KB" }
                       else { "$($_.Length) B" }
        [PSCustomObject]@{
            name         = $_.Name
            path         = $_.FullName
            extension    = $_.Extension
            size         = $_.Length
            sizeDisplay  = $sizeDisplay
            lastModified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            created      = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
            isReadOnly   = $_.IsReadOnly
            attributes   = $_.Attributes.ToString()
        }
    })
    if ($null -eq $files) { $files = @() }
    Send-Json $Response $files
}

function Get-FolderAcl {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $folderPath = Resolve-MappedDrive $Request.QueryString['path']
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
    $folderPath = Resolve-MappedDrive $body.path
    $recursive = $body.recursive -eq $true

    if (-not $folderPath -or -not (Test-Path $folderPath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing path" }
        return
    }

    try {
        if ($recursive) {
            # takeown first to force ownership on folders and files (uses SE_TAKE_OWNERSHIP privilege)
            $takeownOutput = takeown /F $folderPath /R /A /D Y 2>&1
            # Then set the current user as owner via icacls on all files and folders
            $icaclsOutput = icacls $folderPath /setowner $env:USERNAME /T /C /Q 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "icacls failed: $icaclsOutput"
            }
            Send-Json $Response @{ status = 'success'; message = "Ownership taken recursively on all folders and files in $folderPath" }
        }
        else {
            # takeown on just this folder and its immediate files
            $takeownOutput = takeown /F $folderPath /A /D Y 2>&1
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
    $sourcePath = Resolve-MappedDrive $body.sourcePath
    $targetPaths = @($body.targetPaths | ForEach-Object { Resolve-MappedDrive $_ })
    $recursive = $body.recursive -eq $true

    if (-not $sourcePath -or -not (Test-Path $sourcePath -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid source path" }
        return
    }

    $sourceAcl = Get-Acl -Path $sourcePath -ErrorAction Stop
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $targetPaths) {
        try {
            if (-not (Test-Path $target)) {
                $results.Add([PSCustomObject]@{ path = $target; status = 'skipped'; message = 'Path not found' })
                continue
            }

            if ($recursive) {
                # Use icacls to reset inheritance and apply parent ACLs to all files and subfolders
                # /reset re-enables inheritance and pushes inheritable ACEs from parent down to all children
                $output = icacls $target /reset /T /C /Q 2>&1
                if ($LASTEXITCODE -ge 2) {
                    $results.Add([PSCustomObject]@{ path = $target; status = 'warning'; message = "icacls /reset completed with exit code $LASTEXITCODE" })
                } else {
                    # Now apply source ACL rules via icacls /grant for each non-inherited rule
                    $grantErrors = 0
                    foreach ($rule in $sourceAcl.Access) {
                        if ($rule.IsInherited) { continue }
                        $identity = $rule.IdentityReference.ToString()
                        $perm = switch -Wildcard ($rule.FileSystemRights.ToString()) {
                            '*FullControl*'      { 'F' }
                            '*Modify*'           { 'M' }
                            '*ReadAndExecute*'   { 'RX' }
                            '*Read*'             { 'R' }
                            '*Write*'            { 'W' }
                            default              { 'R' }
                        }
                        $inheritFlag = '(OI)(CI)'  # Apply to this folder, subfolders, and files
                        if ($rule.AccessControlType -eq 'Allow') {
                            $icaclsOut = icacls $target /grant "${identity}:${inheritFlag}${perm}" /T /C /Q 2>&1
                        } else {
                            $icaclsOut = icacls $target /deny "${identity}:${inheritFlag}${perm}" /T /C /Q 2>&1
                        }
                        if ($LASTEXITCODE -ge 2) { $grantErrors++ }
                    }
                    if ($grantErrors -gt 0) {
                        $results.Add([PSCustomObject]@{ path = $target; status = 'warning'; message = "Replicated recursively with $grantErrors permission errors" })
                    } else {
                        $results.Add([PSCustomObject]@{ path = $target; status = 'success'; message = 'Permissions replicated to all subfolders and files' })
                    }
                }
            }
            else {
                # Non-recursive: apply to this single item only
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
    $folderPath = Resolve-MappedDrive $body.path
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
    $folderPath = Resolve-MappedDrive $body.path
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

    $folderPath = Resolve-MappedDrive $Request.QueryString['path']
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
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}

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
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}

function Invoke-Robocopy {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $body = Read-RequestBody $Request
    $source = Resolve-MappedDrive $body.source
    $destination = Resolve-MappedDrive $body.destination
    $mode = $body.mode          # 'copy' or 'mirror'
    $threads = $body.threads    # /MT:N
    $retries = $body.retries    # /R:N
    $waitTime = $body.waitTime  # /W:N
    $logFile = $body.logFile    # log path — defaults to destination folder if true/empty
    $extraFlags = $body.extraFlags  # optional raw flags string

    if (-not $source -or -not (Test-Path $source -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid or missing source path" }
        return
    }

    if (-not $destination) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Missing destination path" }
        return
    }

    # Build robocopy arguments
    # /COPY:DATSOU = Data, Attributes, Timestamps, Security (ACLs), Owner, aUditing
    # /DCOPY:DAT   = Directory Data, Attributes, Timestamps
    $roboArgs = [System.Collections.Generic.List[string]]::new()
    $roboArgs.Add("`"$source`"")
    $roboArgs.Add("`"$destination`"")

    if ($mode -eq 'mirror') {
        $roboArgs.Add('/MIR')
    } else {
        $roboArgs.Add('/E')
    }

    $roboArgs.Add('/COPY:DATSOU')
    $roboArgs.Add('/DCOPY:DAT')
    $roboArgs.Add('/ZB')
    $roboArgs.Add('/NP')
    $roboArgs.Add('/ETA')
    $roboArgs.Add('/R:' + $(if ($retries) { $retries } else { 3 }))
    $roboArgs.Add('/W:' + $(if ($waitTime) { $waitTime } else { 5 }))

    if ($threads -and $threads -gt 0) {
        $roboArgs.Add("/MT:$threads")
    } else {
        $roboArgs.Add('/MT:8')
    }

    if ($logFile) {
        $roboArgs.Add("/LOG:`"$logFile`"")
        $roboArgs.Add('/TEE')
    }

    if ($extraFlags) {
        $extraFlags -split '\s+' | Where-Object { $_ } | ForEach-Object { $roboArgs.Add($_) }
    }

    $argString = $roboArgs -join ' '
    $cmdLine = "robocopy $argString"

    try {
        # Create destination if it doesn't exist
        if (-not (Test-Path $destination -PathType Container)) {
            New-Item -Path $destination -ItemType Directory -Force | Out-Null
        }

        # If logFile path was provided, ensure its parent directory exists
        if ($logFile) {
            $logDir = Split-Path -Path $logFile -Parent
            if ($logDir -and -not (Test-Path $logDir -PathType Container)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
        }

        $output = cmd /c $cmdLine 2>&1
        $exitCode = $LASTEXITCODE

        # Robocopy exit codes: 0-7 = success (bitmask), 8+ = errors
        $success = $exitCode -lt 8
        $summary = @{
            status   = if ($success) { 'success' } else { 'error' }
            exitCode = $exitCode
            exitMeaning = switch ($exitCode) {
                0 { 'No files copied — source and destination are synchronized' }
                1 { 'Files copied successfully' }
                2 { 'Extra files or directories detected in destination' }
                3 { 'Files copied + extra files in destination' }
                4 { 'Mismatched files or directories detected' }
                5 { 'Files copied + mismatched files detected' }
                6 { 'Extra and mismatched files detected' }
                7 { 'Files copied + extra + mismatched' }
                8 { 'Some files or directories could not be copied (errors occurred)' }
                16 { 'Fatal error — no files were copied' }
                default { "Exit code $exitCode" }
            }
            command  = $cmdLine
            output   = ($output | Out-String).Trim()
        }

        if (-not $success) { $Response.StatusCode = 500 }
        Send-Json $Response $summary
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Robocopy failed: $($_.Exception.Message)"; command = $cmdLine }
    }
}

function Get-RobocopyPreview {
    param(
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )

    $source = Resolve-MappedDrive $Request.QueryString['source']
    $destination = Resolve-MappedDrive $Request.QueryString['destination']

    if (-not $source -or -not (Test-Path $source -PathType Container)) {
        $Response.StatusCode = 400
        Send-Json $Response @{ error = "Invalid source path" }
        return
    }

    try {
        # /L = List only (no copy), /E = include subdirs, /BYTES = show sizes in bytes
        $output = robocopy $source $(if ($destination) { $destination } else { 'NUL' }) /L /E /BYTES /NP /NFL /NDL 2>&1
        $summary = ($output | Out-String).Trim()

        # Parse the summary lines
        $dirs = 0; $files = 0; $bytes = 0
        if ($summary -match 'Dirs\s*:\s*(\d+)') { $dirs = [int]$Matches[1] }
        if ($summary -match 'Files\s*:\s*(\d+)') { $files = [int]$Matches[1] }
        if ($summary -match 'Bytes\s*:\s*(\d+)') { $bytes = [long]$Matches[1] }

        Send-Json $Response @{
            dirs  = $dirs
            files = $files
            bytes = $bytes
            sizeDisplay = if ($bytes -gt 1GB) { "$([math]::Round($bytes / 1GB, 2)) GB" }
                          elseif ($bytes -gt 1MB) { "$([math]::Round($bytes / 1MB, 1)) MB" }
                          else { "$([math]::Round($bytes / 1KB, 0)) KB" }
            rawSummary = $summary
        }
    }
    catch {
        $Response.StatusCode = 500
        Send-Json $Response @{ error = "Preview failed: $($_.Exception.Message)" }
    }
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
            '^GET /api/files$'           { Get-Files $request $response }
            '^GET /api/acl$'             { Get-FolderAcl $request $response }
            '^POST /api/take-ownership$' { Invoke-TakeOwnership $request $response }
            '^POST /api/replicate$'      { Invoke-ReplicatePermissions $request $response }
            '^POST /api/add-ace$'        { Invoke-AddAce $request $response }
            '^POST /api/remove-ace$'     { Invoke-RemoveAce $request $response }
            '^GET /api/export$'          { Invoke-ExportReport $request $response }
            '^POST /api/robocopy$'       { Invoke-Robocopy $request $response }
            '^GET /api/robocopy-preview$' { Get-RobocopyPreview $request $response }
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

/* Action Buttons */
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

/* Breadcrumbs */
.breadcrumbs {
    display: flex;
    align-items: center;
    flex: 1;
    flex-wrap: wrap;
    gap: 2px;
    font-size: 13px;
    min-height: 32px;
}
.breadcrumbs a {
    color: var(--accent);
    text-decoration: none;
    padding: 4px 6px;
    border-radius: 3px;
    cursor: pointer;
    white-space: nowrap;
}
.breadcrumbs a:hover { background: var(--bg-hover); text-decoration: underline; }
.breadcrumbs .sep { color: var(--text-muted); font-size: 11px; padding: 0 2px; user-select: none; }
.breadcrumbs .current { color: var(--text); font-weight: 600; padding: 4px 6px; }
.path-edit-btn {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 4px 8px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    flex-shrink: 0;
}
.path-edit-btn:hover { background: var(--bg-hover); color: var(--text); border-color: var(--accent); }
.path-refresh-btn {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 4px 8px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-family: inherit;
    flex-shrink: 0;
}
.path-refresh-btn:hover { background: var(--bg-hover); color: var(--accent); border-color: var(--accent); }

/* Permissions tab header */
.perm-header {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 12px;
}
.perm-header .owner-section {
    display: flex;
    align-items: center;
    gap: 8px;
    flex: 1;
    min-width: 200px;
}
.perm-header .owner-section .owner-label {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
}
.perm-header .owner-section .owner-value {
    font-size: 14px;
    color: var(--text);
    font-weight: 500;
}
.perm-quick-stats {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 12px;
}
.perm-stat {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 14px;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 6px;
}
.perm-stat .num { font-weight: 700; font-size: 16px; }
.perm-stat.allow .num { color: var(--success); }
.perm-stat.deny .num { color: var(--danger); }
.perm-stat.inherited .num { color: var(--text-muted); }
.perm-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 14px;
}
.section-divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 20px 0;
}
.section-heading {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-bottom: 10px;
}

/* Context Menu */
.context-menu {
    position: fixed;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 4px 0;
    min-width: 220px;
    box-shadow: 0 8px 24px var(--shadow);
    z-index: 2000;
    display: none;
}
.context-menu .ctx-item {
    display: block;
    width: 100%;
    text-align: left;
    background: none;
    border: none;
    color: var(--text);
    padding: 8px 16px;
    font-size: 13px;
    font-family: inherit;
    cursor: pointer;
    white-space: nowrap;
}
.context-menu .ctx-item:hover { background: var(--bg-hover); color: var(--accent); }
.context-menu .ctx-sep {
    border-top: 1px solid var(--border);
    margin: 4px 0;
}

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

    <!-- Context Menu -->
    <div class="context-menu" id="contextMenu">
        <button class="ctx-item" onclick="ctxTakeOwnership(false)">Take Ownership</button>
        <button class="ctx-item" onclick="ctxTakeOwnership(true)">Take Ownership (Recursive)</button>
        <div class="ctx-sep"></div>
        <button class="ctx-item" onclick="ctxReplicateHere()">Replicate Permissions Here</button>
        <div class="ctx-sep"></div>
        <button class="ctx-item" onclick="ctxCopyPath()">Copy Path</button>
        <div class="ctx-sep"></div>
        <button class="ctx-item" onclick="ctxOpenInTab('permissions')">Open in Permissions Tab</button>
        <button class="ctx-item" onclick="ctxOpenInTab('contents')">Open in Contents Tab</button>
    </div>

    <!-- Main -->
    <main class="main">
        <div class="path-bar">
            <label>Path</label>
            <div class="breadcrumbs" id="breadcrumbs">
                <span style="color:var(--text-muted);">Select a folder from the sidebar</span>
            </div>
            <input type="text" class="path-input" id="pathInput" placeholder="Type a path and press Enter" style="display:none;" />
            <button class="path-edit-btn" id="pathEditBtn" onclick="togglePathEdit()" title="Edit path manually">&#9998;</button>
            <button class="path-refresh-btn" id="pathRefreshBtn" onclick="refreshCurrent()" title="Refresh" style="display:none;">&#8635;</button>
        </div>
        <div class="tab-bar">
            <button class="tab-btn active" data-tab="permissions" onclick="switchTab('permissions')">Permissions</button>
            <button class="tab-btn" data-tab="contents" onclick="switchTab('contents')">Contents</button>
            <button class="tab-btn" data-tab="robocopy" onclick="switchTab('robocopy')">Robocopy</button>
        </div>
        <div class="tab-content">
            <div class="tab-panel active" id="panel-permissions">
                <div class="empty-state" id="permissionsEmpty">
                    <div class="icon">&#128274;</div>
                    <p>Select a folder from the sidebar to view its permissions.</p>
                </div>
                <div id="permissionsContent" style="display:none;"></div>
            </div>
            <div class="tab-panel" id="panel-contents">
                <div class="empty-state" id="contentsEmpty">
                    <div class="icon">&#128194;</div>
                    <p>Select a folder to view its contents.</p>
                </div>
                <div id="contentsContent" style="display:none;"></div>
            </div>
            <div class="tab-panel" id="panel-robocopy">
                <h3 style="color:var(--text-heading); margin-top:0;">Robocopy</h3>
                <p style="color:var(--text-muted); font-size:13px; margin-bottom:16px;">Copy or move folder contents with full fidelity - preserves permissions, timestamps, ownership, and attributes.</p>

                <!-- Step 1: Source -->
                <div style="background:var(--bg-hover); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:12px;">
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                        <span style="background:var(--accent); color:#fff; border-radius:50%; width:24px; height:24px; display:inline-flex; align-items:center; justify-content:center; font-size:13px; font-weight:700;">1</span>
                        <strong style="color:var(--text-heading);">Source - Where to copy FROM</strong>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <input type="text" id="roboSource" style="flex:1; padding:10px 14px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; font-size:14px;" placeholder="Click a folder in the sidebar, or type a path..." readonly>
                        <button class="toolbar-btn" onclick="useCurrentPathAsSource()" title="Use the folder selected in the sidebar" style="padding:10px 14px; white-space:nowrap;">Use Selected Folder</button>
                        <button class="toolbar-btn" onclick="document.getElementById('roboSource').readOnly=false;document.getElementById('roboSource').focus();" title="Type a path manually" style="padding:10px 14px;">Edit</button>
                    </div>
                </div>

                <!-- Step 2: Destination -->
                <div style="background:var(--bg-hover); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:12px;">
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                        <span style="background:var(--accent); color:#fff; border-radius:50%; width:24px; height:24px; display:inline-flex; align-items:center; justify-content:center; font-size:13px; font-weight:700;">2</span>
                        <strong style="color:var(--text-heading);">Destination - Where to copy TO</strong>
                    </div>
                    <input type="text" id="roboDest" style="width:100%; padding:10px 14px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:6px; font-size:14px; box-sizing:border-box;" placeholder="Type or paste the destination path, e.g. \\server\share\folder or D:\Backups\Data">
                    <p style="color:var(--text-muted); font-size:11px; margin:6px 0 0 0;">The folder will be created automatically if it does not exist.</p>
                </div>

                <!-- Step 3: What to do -->
                <div style="background:var(--bg-hover); border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:12px;">
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:12px;">
                        <span style="background:var(--accent); color:#fff; border-radius:50%; width:24px; height:24px; display:inline-flex; align-items:center; justify-content:center; font-size:13px; font-weight:700;">3</span>
                        <strong style="color:var(--text-heading);">What should happen?</strong>
                    </div>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        <label style="display:flex; align-items:start; gap:10px; padding:10px 14px; background:var(--bg-card); border:2px solid var(--border); border-radius:6px; cursor:pointer;" onclick="document.getElementById('roboModeCopy').checked=true; this.style.borderColor='var(--accent)';">
                            <input type="radio" name="roboMode" id="roboModeCopy" value="copy" checked style="margin-top:2px;">
                            <div>
                                <strong style="color:var(--text-heading);">Copy</strong>
                                <p style="color:var(--text-muted); font-size:12px; margin:2px 0 0 0;">Copy all files and folders to the destination. Existing files in the destination are kept.</p>
                            </div>
                        </label>
                        <label style="display:flex; align-items:start; gap:10px; padding:10px 14px; background:var(--bg-card); border:2px solid var(--border); border-radius:6px; cursor:pointer;" onclick="document.getElementById('roboModeMirror').checked=true; this.style.borderColor='#e74c3c';">
                            <input type="radio" name="roboMode" id="roboModeMirror" value="mirror" style="margin-top:2px;">
                            <div>
                                <strong style="color:#e74c3c;">Mirror (Exact Sync)</strong>
                                <p style="color:var(--text-muted); font-size:12px; margin:2px 0 0 0;">Make the destination an exact copy of the source. <strong style="color:#e74c3c;">Files in the destination that are NOT in the source will be DELETED.</strong></p>
                            </div>
                        </label>
                    </div>
                </div>

                <!-- Step 4: Go -->
                <div style="display:flex; gap:12px; margin-bottom:12px; align-items:center;">
                    <button class="toolbar-btn" id="btnRoboPreview" onclick="robocopyPreview()" style="padding:10px 20px;">Preview First (see what will be copied)</button>
                    <button class="toolbar-btn" id="btnRobocopy" onclick="robocopyRun()" style="padding:10px 20px; background:var(--accent); color:#fff; font-weight:600;">Start Copy</button>
                </div>

                <!-- Preview result -->
                <div id="roboPreviewBox" style="display:none; background:var(--bg-card); border:1px solid var(--accent); border-radius:8px; padding:16px; margin-bottom:12px;">
                    <strong style="color:var(--text-heading);">Preview - What will be copied</strong>
                    <div id="roboPreviewContent" style="margin-top:8px; font-size:13px;"></div>
                </div>

                <!-- Advanced options (collapsed) -->
                <div style="margin-bottom:12px;">
                    <button onclick="var el=document.getElementById('roboAdvanced'); el.style.display = el.style.display==='none'?'block':'none'; this.textContent = el.style.display==='none'?'Show Advanced Options':'Hide Advanced Options';" style="background:none; border:none; color:var(--accent); cursor:pointer; font-size:13px; padding:0;">Show Advanced Options</button>
                    <div id="roboAdvanced" style="display:none; margin-top:10px; background:var(--bg-hover); border:1px solid var(--border); border-radius:8px; padding:16px;">
                        <div style="display:flex; gap:24px; flex-wrap:wrap; margin-bottom:12px;">
                            <div>
                                <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Parallel Threads</label>
                                <input type="number" id="roboThreads" value="8" min="1" max="128" style="width:70px; padding:8px 12px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:4px; font-size:13px;">
                                <span style="color:var(--text-muted); font-size:11px;"> (default 8)</span>
                            </div>
                            <div>
                                <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Retry Count</label>
                                <input type="number" id="roboRetries" value="3" min="0" max="99" style="width:70px; padding:8px 12px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:4px; font-size:13px;">
                                <span style="color:var(--text-muted); font-size:11px;"> per failed file</span>
                            </div>
                            <div>
                                <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Wait Between Retries</label>
                                <input type="number" id="roboWait" value="5" min="0" max="60" style="width:70px; padding:8px 12px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:4px; font-size:13px;">
                                <span style="color:var(--text-muted); font-size:11px;"> seconds</span>
                            </div>
                        </div>
                        <div style="margin-bottom:12px;">
                            <div class="checkbox-group" style="margin-bottom:6px;">
                                <input type="checkbox" id="roboLogEnabled" checked onchange="updateRoboLogPath()">
                                <label for="roboLogEnabled">Save log file to destination folder</label>
                            </div>
                            <input type="text" id="roboLog" style="width:100%; max-width:500px; padding:8px 12px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:4px; font-size:13px; box-sizing:border-box;" placeholder="Auto-generated from destination path">
                            <p style="color:var(--text-muted); font-size:11px; margin:4px 0 0 0;">Log file is saved inside the destination folder. Edit the path to save elsewhere.</p>
                        </div>
                        <div>
                            <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Exclude (folders or files)</label>
                            <input type="text" id="roboExtra" style="width:100%; max-width:500px; padding:8px 12px; background:var(--bg-card); color:var(--text); border:1px solid var(--border); border-radius:4px; font-size:13px; box-sizing:border-box;" placeholder="e.g.  /XD Temp Logs  /XF *.tmp *.log">
                            <p style="color:var(--text-muted); font-size:11px; margin:4px 0 0 0;">/XD = exclude directories, /XF = exclude files. Separate multiple with spaces.</p>
                        </div>
                    </div>
                </div>

                <!-- Output -->
                <div id="roboOutputBox" style="display:none; background:var(--bg-card); border:1px solid var(--border); border-radius:8px; padding:16px; max-height:400px; overflow-y:auto;">
                    <strong style="color:var(--text-heading);">Output</strong>
                    <pre id="roboOutputContent" style="margin-top:8px; font-size:12px; color:var(--text); white-space:pre-wrap; word-break:break-all;"></pre>
                </div>
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
    var contextMenuPath = '';

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

    // --- Breadcrumbs ---
    function renderBreadcrumbs(path) {
        var container = document.getElementById('breadcrumbs');
        if (!path) {
            container.innerHTML = '<span style="color:var(--text-muted);">Select a folder from the sidebar</span>';
            return;
        }
        var normalized = path.replace(/\//g, '\\');
        var parts = normalized.split('\\').filter(function(p) { return p.length > 0; });
        var html = '';
        for (var i = 0; i < parts.length; i++) {
            var segment = parts[i];
            // Build the path up to this segment
            var partialPath = parts.slice(0, i + 1).join('\\');
            // For drive root like C:, add trailing backslash
            if (i === 0 && segment.indexOf(':') >= 0) {
                partialPath = partialPath + '\\';
            }
            if (i > 0) {
                html += '<span class="sep">&#9656;</span>';
            }
            if (i === parts.length - 1) {
                html += '<span class="current">' + escHtml(segment) + '</span>';
            } else {
                html += '<a onclick="selectFolder(\'' + escHtml(partialPath).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '\')">' + escHtml(segment) + '</a>';
            }
        }
        container.innerHTML = html;
    }

    window.togglePathEdit = function() {
        var input = document.getElementById('pathInput');
        var breadcrumbs = document.getElementById('breadcrumbs');
        var editBtn = document.getElementById('pathEditBtn');
        if (input.style.display === 'none') {
            input.style.display = 'block';
            breadcrumbs.style.display = 'none';
            input.value = currentPath;
            input.focus();
            editBtn.innerHTML = '&#10003;';
            editBtn.title = 'Back to breadcrumbs';
        } else {
            input.style.display = 'none';
            breadcrumbs.style.display = 'flex';
            editBtn.innerHTML = '&#9998;';
            editBtn.title = 'Edit path manually';
        }
    };

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
        loadTreeChildren(root, document.getElementById('treeContainer'), 0);
    }

    // --- Tree ---
    function loadTreeChildren(path, parentEl, level) {
        apiGet('/api/children?path=' + encodeURIComponent(path)).then(function(children) {
            children.forEach(function(child) {
                var node = document.createElement('div');
                node.className = 'tree-node';

                var row = document.createElement('div');
                row.className = 'tree-node-row';
                row.style.paddingLeft = (8 + level * 16) + 'px';
                row.setAttribute('data-path', child.path);

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
                            loadTreeChildren(child.path, childrenContainer, level + 1);
                        }
                    }
                }

                arrow.onclick = toggleExpand;
                row.onclick = function() { selectFolder(child.path); };
                row.ondblclick = toggleExpand;

                // Right-click context menu
                row.addEventListener('contextmenu', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    showContextMenu(e.clientX, e.clientY, child.path);
                });

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
        renderBreadcrumbs(path);
        document.getElementById('pathRefreshBtn').style.display = 'inline-block';

        // Make sure breadcrumbs are visible (not edit mode)
        document.getElementById('pathInput').style.display = 'none';
        document.getElementById('breadcrumbs').style.display = 'flex';
        document.getElementById('pathEditBtn').innerHTML = '&#9998;';
        document.getElementById('pathEditBtn').title = 'Edit path manually';

        // highlight active tree row
        var rows = document.querySelectorAll('.tree-node-row');
        rows.forEach(function(r) { r.classList.remove('active'); });
        rows.forEach(function(r) {
            var lbl = r.querySelector('.tree-label');
            var parts = path.replace(/[\\/]+/g, '/').replace(/\/$/, '').split('/');
            var folderName = parts[parts.length - 1];
            if (lbl && lbl.textContent === folderName) {
                r.classList.add('active');
            }
        });

        loadAcl(path);
        loadChildrenTab(path);
        loadFilesTab(path);
    }
    window.selectFolder = selectFolder;

    // --- Path input ---
    document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('pathInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                var p = this.value.trim();
                if (p) {
                    selectFolder(p);
                }
            }
        });
    });

    // --- ACL Loading ---
    function loadAcl(path) {
        apiGet('/api/acl?path=' + encodeURIComponent(path)).then(function(data) {
            currentAcl = data;
            renderPermissionsTab(data);
            setStatus('Loaded permissions for ' + path, 'success');
        }).catch(function(err) {
            setStatus('Failed to load ACL: ' + err.message, 'error');
        });
    }

    // --- Permissions Tab (combined Overview + ACL) ---
    function renderPermissionsTab(data) {
        var el = document.getElementById('permissionsContent');
        document.getElementById('permissionsEmpty').style.display = 'none';
        el.style.display = 'block';

        var allowCount = 0, denyCount = 0, inheritedCount = 0;
        data.entries.forEach(function(e) {
            if (e.type === 'Allow') allowCount++;
            else denyCount++;
            if (e.isInherited) inheritedCount++;
        });

        var inheritText = data.areAccessRulesProtected ? 'Protected (explicit only)' : 'Inheriting from parent';

        // Header with owner, inheritance, stats
        var html = '<div class="perm-header">' +
            '<div class="owner-section">' +
                '<span class="owner-label">Owner:</span> ' +
                '<span class="owner-value">' + escHtml(data.owner) + '</span>' +
                ' <button class="toolbar-btn" style="padding:3px 10px;font-size:11px;" onclick="showTakeOwnershipModal()">Take Ownership</button>' +
            '</div>' +
            '<span style="font-size:12px; color:var(--text-muted);">' + escHtml(inheritText) + '</span>' +
            '<a href="/api/export?path=' + encodeURIComponent(currentPath) + '" style="font-size:12px; color:var(--accent); text-decoration:none; margin-left:auto; white-space:nowrap;" title="Export all permissions to CSV">Export CSV</a>' +
            '</div>';

        // Quick stats
        html += '<div class="perm-quick-stats">' +
            '<div class="perm-stat allow"><span class="num">' + allowCount + '</span> allow</div>' +
            '<div class="perm-stat deny"><span class="num">' + denyCount + '</span> deny</div>' +
            '<div class="perm-stat inherited"><span class="num">' + inheritedCount + '</span> inherited</div>' +
            '</div>';

        // Add Permission button
        html += '<div class="perm-actions">' +
            '<button class="toolbar-btn primary" onclick="showAddPermissionModal()">Add Permission</button>' +
            '</div>';

        // ACL table
        html += renderAclTableHtml(data);

        el.innerHTML = html;
    }

    // --- ACL Table (returns HTML string) ---
    function renderAclTableHtml(data) {
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
        return html;
    }

    // Keep renderAclTable for backwards compat (calls into permissionsTab)
    function renderAclTable(data) {
        renderPermissionsTab(data);
    }

    // Keep renderOverview for backwards compat
    function renderOverview(data) {
        renderPermissionsTab(data);
    }

    // --- Children Tab ---
    function loadChildrenTab(path) {
        apiGet('/api/children?path=' + encodeURIComponent(path)).then(function(children) {
            childrenData = children;
            renderContentsTab(children, null);
            // Also load files for the contents tab
        }).catch(function(err) {
            setStatus('Failed to load children: ' + err.message, 'error');
        });
    }

    // --- Files Tab ---
    function loadFilesTab(path) {
        apiGet('/api/files?path=' + encodeURIComponent(path)).then(function(files) {
            renderContentsTab(null, files);
        }).catch(function(err) {
            setStatus('Failed to load files: ' + err.message, 'error');
        });
    }

    // Store latest data for combined rendering
    var latestChildren = null;
    var latestFiles = null;

    function renderContentsTab(children, files) {
        if (children !== null) latestChildren = children;
        if (files !== null) latestFiles = files;

        var el = document.getElementById('contentsContent');
        var emptyEl = document.getElementById('contentsEmpty');

        var hasChildren = latestChildren && latestChildren.length > 0;
        var hasFiles = latestFiles && latestFiles.length > 0;

        if (!hasChildren && !hasFiles && latestChildren !== null && latestFiles !== null) {
            emptyEl.style.display = 'block';
            emptyEl.querySelector('p').textContent = 'This folder is empty.';
            el.style.display = 'none';
            return;
        }

        // Show content if we have at least some data
        if (hasChildren || hasFiles) {
            emptyEl.style.display = 'none';
            el.style.display = 'block';
        }

        var html = '';

        // Replicate button at top
        html += '<div style="margin-bottom:14px;"><button class="toolbar-btn primary" onclick="replicateSelected()">Replicate Permissions to Selected</button></div>';

        // Subfolders section
        html += '<div class="section-heading">Subfolders</div>';
        if (hasChildren) {
            html += renderChildrenTableHtml(latestChildren);
        } else if (latestChildren !== null) {
            html += '<p style="color:var(--text-muted); font-size:13px; margin-bottom:8px;">No subfolders found.</p>';
        } else {
            html += '<p style="color:var(--text-muted); font-size:13px; margin-bottom:8px;">Loading...</p>';
        }

        // Divider
        html += '<hr class="section-divider">';

        // Files section
        html += '<div class="section-heading">Files</div>';
        if (hasFiles) {
            html += renderFilesTableHtml(latestFiles);
        } else if (latestFiles !== null) {
            html += '<p style="color:var(--text-muted); font-size:13px;">No files in this folder.</p>';
        } else {
            html += '<p style="color:var(--text-muted); font-size:13px;">Loading...</p>';
        }

        el.innerHTML = html;
    }

    function renderChildrenTableHtml(children) {
        var html = '<table class="children-table"><thead><tr>' +
            '<th><input type="checkbox" id="selectAllChildren" onchange="toggleSelectAllChildren(this)" /></th>' +
            '<th>Name</th><th>Owner</th>' +
            '</tr></thead><tbody>';

        children.forEach(function(child, idx) {
            html += '<tr>' +
                '<td><input type="checkbox" class="child-check" data-path="' + escHtml(child.path) + '" /></td>' +
                '<td>' + escHtml(child.name) + '</td>' +
                '<td id="child-owner-' + idx + '"><span class="badge badge-inherited" style="cursor:pointer" onclick="loadChildOwner(' + idx + ',\'' + escHtml(child.path).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '\')">Load</span></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        return html;
    }

    // Keep renderChildrenTable for backwards compat
    function renderChildrenTable(children) {
        renderContentsTab(children, null);
    }

    function renderFilesTableHtml(files) {
        var totalSize = 0;
        files.forEach(function(f) { totalSize += f.size || 0; });
        var totalDisplay = totalSize > 1073741824 ? (totalSize / 1073741824).toFixed(2) + ' GB'
            : totalSize > 1048576 ? (totalSize / 1048576).toFixed(1) + ' MB'
            : totalSize > 1024 ? (totalSize / 1024).toFixed(1) + ' KB'
            : totalSize + ' B';

        var html = '<p style="color:var(--text-muted); font-size:13px; margin-bottom:8px;">' +
            '<strong>' + files.length + '</strong> files, <strong>' + totalDisplay + '</strong> total</p>' +
            '<table class="children-table"><thead><tr>' +
            '<th style="cursor:pointer" onclick="sortFilesTable(0)">Name &#x25B2;&#x25BC;</th>' +
            '<th style="cursor:pointer; width:100px;" onclick="sortFilesTable(1)">Size &#x25B2;&#x25BC;</th>' +
            '<th style="cursor:pointer; width:160px;" onclick="sortFilesTable(2)">Modified &#x25B2;&#x25BC;</th>' +
            '<th style="width:80px;">Attributes</th>' +
            '</tr></thead><tbody>';

        files.forEach(function(f) {
            var attrBadges = '';
            if (f.isReadOnly) attrBadges += '<span class="badge badge-deny" style="font-size:10px; padding:1px 5px;">RO</span> ';
            if (f.attributes && f.attributes.indexOf('Hidden') >= 0) attrBadges += '<span class="badge badge-inherited" style="font-size:10px; padding:1px 5px;">H</span> ';
            if (f.attributes && f.attributes.indexOf('System') >= 0) attrBadges += '<span class="badge badge-inherited" style="font-size:10px; padding:1px 5px;">S</span> ';

            html += '<tr>' +
                '<td style="word-break:break-all;">' + escHtml(f.name) + '</td>' +
                '<td style="text-align:right; white-space:nowrap;">' + escHtml(f.sizeDisplay) + '</td>' +
                '<td style="white-space:nowrap;">' + escHtml(f.lastModified) + '</td>' +
                '<td>' + (attrBadges || '-') + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        return html;
    }

    // Keep renderFilesTable for backwards compat
    function renderFilesTable(files) {
        renderContentsTab(null, files);
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

    var filesData = [];
    var filesSortCol = -1;
    var filesSortAsc = true;
    window.sortFilesTable = function(col) {
        filesSortAsc = (filesSortCol === col) ? !filesSortAsc : true;
        filesSortCol = col;
        apiGet('/api/files?path=' + encodeURIComponent(currentPath)).then(function(files) {
            files.sort(function(a, b) {
                var va, vb;
                if (col === 0) { va = a.name.toLowerCase(); vb = b.name.toLowerCase(); return filesSortAsc ? va.localeCompare(vb) : vb.localeCompare(va); }
                if (col === 1) { return filesSortAsc ? a.size - b.size : b.size - a.size; }
                if (col === 2) { va = a.lastModified; vb = b.lastModified; return filesSortAsc ? va.localeCompare(vb) : vb.localeCompare(va); }
                return 0;
            });
            latestFiles = files;
            renderContentsTab(null, files);
        });
    };

    // --- Tab Switching ---
    window.switchTab = function(tabName) {
        var btns = document.querySelectorAll('.tab-btn');
        btns.forEach(function(b) {
            if (b.getAttribute('data-tab') === tabName) b.classList.add('active');
            else b.classList.remove('active');
        });
        var panels = document.querySelectorAll('.tab-panel');
        panels.forEach(function(p) {
            if (p.id === 'panel-' + tabName) p.classList.add('active');
            else p.classList.remove('active');
        });
        // Auto-fill robocopy source when switching to robocopy tab
        if (tabName === 'robocopy' && currentPath) {
            var roboSrc = document.getElementById('roboSource');
            if (roboSrc && !roboSrc.value.trim()) {
                roboSrc.value = currentPath;
            }
        }
    };

    // --- Context Menu ---
    function showContextMenu(x, y, path) {
        contextMenuPath = path;
        var menu = document.getElementById('contextMenu');
        menu.style.display = 'block';
        menu.style.left = x + 'px';
        menu.style.top = y + 'px';
        // Keep menu in viewport
        var rect = menu.getBoundingClientRect();
        if (rect.right > window.innerWidth) {
            menu.style.left = (x - rect.width) + 'px';
        }
        if (rect.bottom > window.innerHeight) {
            menu.style.top = (y - rect.height) + 'px';
        }
    }

    function hideContextMenu() {
        document.getElementById('contextMenu').style.display = 'none';
        contextMenuPath = '';
    }

    document.addEventListener('click', function() { hideContextMenu(); });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') hideContextMenu();
    });

    window.ctxTakeOwnership = function(recursive) {
        var path = contextMenuPath;
        hideContextMenu();
        if (!path) return;
        var body = '<p>Take ownership of:</p>' +
            '<p style="color:var(--text);word-break:break-all;font-weight:600;">' + escHtml(path) + '</p>' +
            (recursive ? '<p style="color:var(--warning);">This will be applied recursively to all subfolders and files.</p>' : '');
        showModal('Take Ownership', body, 'Take Ownership', function() {
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/take-ownership', { path: path, recursive: recursive }).then(function(data) {
                closeModal();
                setStatus(data.message, 'success');
                if (path === currentPath) loadAcl(currentPath);
            }).catch(function(err) {
                closeModal();
                setStatus('Take ownership failed: ' + err.message, 'error');
            });
        }, false);
    };

    window.ctxReplicateHere = function() {
        var targetPath = contextMenuPath;
        hideContextMenu();
        if (!currentPath || !targetPath) {
            setStatus('Select a source folder first (click it in the tree), then right-click the target', 'error');
            return;
        }
        var body = '<p>Copy permissions from:</p>' +
            '<p style="color:var(--text);font-weight:600;word-break:break-all;">' + escHtml(currentPath) + '</p>' +
            '<p>To:</p>' +
            '<p style="color:var(--text);font-weight:600;word-break:break-all;">' + escHtml(targetPath) + '</p>' +
            '<div class="checkbox-group" style="margin-top:12px;">' +
            '<input type="checkbox" id="ctxReplicateRecursive" checked />' +
            '<label for="ctxReplicateRecursive">Recursive (apply to all subfolders and files)</label>' +
            '</div>';
        showModal('Replicate Permissions', body, 'Replicate', function() {
            var recursive = document.getElementById('ctxReplicateRecursive').checked;
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            apiPost('/api/replicate', { sourcePath: currentPath, targetPaths: [targetPath], recursive: recursive }).then(function(data) {
                closeModal();
                var msg = 'Replication complete';
                if (data.results && data.results.length > 0) {
                    msg = data.results[0].message || msg;
                }
                setStatus(msg, 'success');
            }).catch(function(err) {
                closeModal();
                setStatus('Replication failed: ' + err.message, 'error');
            });
        }, false);
    };

    window.ctxCopyPath = function() {
        var path = contextMenuPath;
        hideContextMenu();
        if (!path) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(path).then(function() {
                setStatus('Path copied: ' + path, 'success');
            }).catch(function() {
                fallbackCopy(path);
            });
        } else {
            fallbackCopy(path);
        }
    };

    function fallbackCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); setStatus('Path copied: ' + text, 'success'); }
        catch(e) { setStatus('Could not copy path', 'error'); }
        document.body.removeChild(ta);
    }

    window.ctxOpenInTab = function(tabName) {
        var path = contextMenuPath;
        hideContextMenu();
        if (!path) return;
        selectFolder(path);
        switchTab(tabName);
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

        var body = '<p>Copy permissions from:</p>' +
            '<p style="color:var(--text);font-weight:600;word-break:break-all;">' + escHtml(currentPath) + '</p>';

        if (targets.length > 0) {
            var listHtml = '<div class="target-list">';
            targets.forEach(function(t) { listHtml += '<div>' + escHtml(t) + '</div>'; });
            listHtml += '</div>';
            body += '<p>To ' + targets.length + ' selected folder(s):</p>' + listHtml;
        } else {
            body += '<p>To: <strong>all contents of this folder</strong></p>';
            targets = [currentPath];
        }

        body += '<div class="checkbox-group" style="margin-top:12px;">' +
            '<input type="checkbox" id="replicateRecursive" checked />' +
            '<label for="replicateRecursive">Recursive (apply to all subfolders and files)</label>' +
            '</div>' +
            '<p style="color:var(--text-muted); font-size:12px; margin-top:8px;">When recursive, permissions are pushed to every file and subfolder underneath each target using icacls /T.</p>';

        showModal('Replicate Permissions', body, 'Replicate', function() {
            var recursive = document.getElementById('replicateRecursive').checked;
            var btn = document.getElementById('modalConfirmBtn');
            btn.disabled = true;
            btn.textContent = 'Working...';
            setStatus('Replicating permissions' + (recursive ? ' recursively' : '') + '...', 'working');
            apiPost('/api/replicate', { sourcePath: currentPath, targetPaths: targets, recursive: recursive }).then(function(data) {
                closeModal();
                var successes = 0;
                var warnings = 0;
                var errors = 0;
                if (data.results) {
                    data.results.forEach(function(r) {
                        if (r.status === 'success') successes++;
                        else if (r.status === 'warning') warnings++;
                        else errors++;
                    });
                }
                var msg = 'Replication complete: ' + successes + ' succeeded';
                if (warnings > 0) msg += ', ' + warnings + ' warnings';
                if (errors > 0) msg += ', ' + errors + ' failed';
                setStatus(msg, errors > 0 ? 'error' : (warnings > 0 ? 'info' : 'success'));
                refreshCurrent();
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
        latestChildren = null;
        latestFiles = null;
        loadAcl(currentPath);
        loadChildrenTab(currentPath);
        loadFilesTab(currentPath);
    };

    // --- Robocopy ---
    window.useCurrentPathAsSource = function() {
        document.getElementById('roboSource').value = currentPath || '';
    };

    window.updateRoboLogPath = function() {
        var dest = document.getElementById('roboDest').value.trim();
        var enabled = document.getElementById('roboLogEnabled').checked;
        var logInput = document.getElementById('roboLog');
        if (!enabled) {
            logInput.value = '';
            logInput.disabled = true;
            return;
        }
        logInput.disabled = false;
        if (dest) {
            var sep = dest.indexOf('/') >= 0 ? '/' : '\\';
            var now = new Date();
            var ts = now.getFullYear() + '-' +
                String(now.getMonth() + 1).padStart(2, '0') + '-' +
                String(now.getDate()).padStart(2, '0') + '_' +
                String(now.getHours()).padStart(2, '0') +
                String(now.getMinutes()).padStart(2, '0') +
                String(now.getSeconds()).padStart(2, '0');
            logInput.value = dest.replace(/[\\\/]+`$/, '') + sep + 'robocopy-log_' + ts + '.txt';
        }
    };

    // Auto-update log path when destination changes
    document.getElementById('roboDest').addEventListener('input', function() {
        if (document.getElementById('roboLogEnabled').checked) {
            updateRoboLogPath();
        }
    });

    window.robocopyPreview = function() {
        var source = document.getElementById('roboSource').value.trim();
        var dest = document.getElementById('roboDest').value.trim();
        if (!source) { setStatus('Enter a source path', 'error'); return; }

        setStatus('Running preview...', 'working');
        var url = '/api/robocopy-preview?source=' + encodeURIComponent(source);
        if (dest) url += '&destination=' + encodeURIComponent(dest);

        apiGet(url).then(function(data) {
            var box = document.getElementById('roboPreviewBox');
            var content = document.getElementById('roboPreviewContent');
            box.style.display = 'block';
            content.innerHTML =
                '<div style="display:flex; gap:24px; margin-bottom:8px;">' +
                '<span><strong>' + data.dirs + '</strong> directories</span>' +
                '<span><strong>' + data.files + '</strong> files</span>' +
                '<span><strong>' + data.sizeDisplay + '</strong> total</span>' +
                '</div>';
            setStatus('Preview complete', 'success');
        }).catch(function(err) {
            setStatus('Preview failed: ' + err.message, 'error');
        });
    };

    window.robocopyRun = function() {
        var source = document.getElementById('roboSource').value.trim();
        var dest = document.getElementById('roboDest').value.trim();
        if (!source || !dest) { setStatus('Enter both source and destination paths', 'error'); return; }

        var modeRadio = document.querySelector('input[name="roboMode"]:checked');
        var mode = modeRadio ? modeRadio.value : 'copy';
        var modeLabel = mode === 'mirror' ? 'MIRROR (will delete extras in destination)' : 'COPY';

        showModal('Run Robocopy', '<p><strong>Mode:</strong> ' + modeLabel + '</p>' +
            '<p><strong>From:</strong> ' + source + '</p>' +
            '<p><strong>To:</strong> ' + dest + '</p>' +
            (mode === 'mirror' ? '<p style="color:#e74c3c;"><strong>Warning:</strong> Mirror mode will delete files in the destination that do not exist in the source.</p>' : '') +
            '<p>This copies all files with permissions, timestamps, and ownership.</p>',
            'Run', function() {
                closeModal();
                setStatus('Robocopy running... this may take a while', 'working');
                document.getElementById('btnRobocopy').disabled = true;
                document.getElementById('btnRoboPreview').disabled = true;

                var payload = {
                    source: source,
                    destination: dest,
                    mode: mode,
                    threads: parseInt(document.getElementById('roboThreads').value) || 8,
                    retries: parseInt(document.getElementById('roboRetries').value) || 3,
                    waitTime: parseInt(document.getElementById('roboWait').value) || 5,
                    logFile: (document.getElementById('roboLogEnabled').checked ? document.getElementById('roboLog').value.trim() : null) || null,
                    extraFlags: document.getElementById('roboExtra').value.trim() || null
                };

                apiPost('/api/robocopy', payload).then(function(data) {
                    var outBox = document.getElementById('roboOutputBox');
                    var outContent = document.getElementById('roboOutputContent');
                    outBox.style.display = 'block';
                    outContent.textContent = 'Command: ' + data.command + '\n\nExit Code: ' + data.exitCode + ' (' + data.exitMeaning + ')\n\n' + (data.output || '');

                    if (data.status === 'success') {
                        setStatus('Robocopy completed -- ' + data.exitMeaning, 'success');
                    } else {
                        setStatus('Robocopy error -- ' + data.exitMeaning, 'error');
                    }
                }).catch(function(err) {
                    setStatus('Robocopy failed: ' + err.message, 'error');
                }).finally(function() {
                    document.getElementById('btnRobocopy').disabled = false;
                    document.getElementById('btnRoboPreview').disabled = false;
                });
            }
        );
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
