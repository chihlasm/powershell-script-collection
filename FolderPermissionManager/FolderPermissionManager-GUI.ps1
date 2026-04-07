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
            $null = takeown /F $filePath /A /D Y 2>&1
            # Then set owner via .NET ACL API — same pattern as folder ownership in Invoke-TakeOwnership
            $acl = Get-Acl -Path $filePath -ErrorAction Stop
            $acl.SetOwner($ownerAccount)
            Set-Acl -Path $filePath -AclObject $acl -ErrorAction Stop
            $results.Add([PSCustomObject]@{ path = $filePath; status = 'success'; message = "Ownership taken by $currentIdentity" })
        }
        catch {
            $results.Add([PSCustomObject]@{ path = $rawPath; status = 'error'; message = $_.Exception.Message })
        }
    }
    Send-Json $Response @{ status = 'complete'; results = @($results) }
}

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
        $output   = cmd /c $cmdLine 2>&1
        $exitCode = $LASTEXITCODE
        $success  = $exitCode -lt 8

        $summary = @{
            status   = if ($success) { 'success' } else { 'error' }
            exitCode = $exitCode
            exitMeaning = switch ($exitCode) {
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
            '^GET /api/file-acl$'                  { Get-FileAcl $request $response }
            '^POST /api/file-acl/add$'             { Invoke-AddFileAce $request $response }
            '^POST /api/file-acl/remove$'          { Invoke-RemoveFileAce $request $response }
            '^POST /api/file-acl/take-ownership$'  { Invoke-TakeFileOwnership $request $response }
            '^POST /api/robocopy-files$'           { Invoke-RobocopyFiles $request $response }
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

/* Icons */
.btn svg, .btn-icon svg { vertical-align: middle; margin-right: 4px; flex-shrink: 0; }
.btn-icon { display: inline-flex; align-items: center; gap: 4px; }
.btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
.btn-ghost:hover { background: rgba(231,76,60,0.1); color: var(--danger); border-color: var(--danger); }
.tree-node .node-icon { flex-shrink: 0; color: var(--text-muted); }
.tree-node.selected .node-icon { color: rgba(255,255,255,0.8); }
.file-icon { color: var(--text-muted); flex-shrink: 0; }

/* Path context header */
.path-header { padding: 8px 16px; background: var(--bg-card); border-bottom: 1px solid var(--border); font-size: 12px; color: var(--text-muted); flex-shrink: 0; display: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.path-header .path-drive { color: var(--accent); font-weight: 600; }
.path-header .path-rest { color: var(--text); }
</style>
</head>
<body>

<div class="topbar">
  <h1>Folder Permission Manager</h1>
  <div class="topbar-actions">
    <button class="btn btn-secondary btn-icon" onclick="toggleTheme()" id="btnTheme" title="Switch to light mode">
      <svg id="iconTheme" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      <span id="btnThemeLabel">Light</span>
    </button>
    <button class="btn btn-ghost btn-icon" onclick="shutdown()" title="Stop the server">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
      Shut Down
    </button>
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

      <div id="path-header" class="path-header"></div>

      <div id="no-folder-msg" class="placeholder-msg">
        <div style="text-align:center;">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--border);display:block;margin:0 auto 10px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
          <div>Choose a folder from the left panel to view and manage its permissions.</div>
        </div>
      </div>

      <!-- Folder ACL section -->
      <div id="folder-acl-section" class="pane-section" style="display:none;">
        <div class="pane-section-header">
          <span class="pane-section-title" id="folderAclTitle">Folder Permissions</span>
          <span class="owner-row">Owner: <span id="folderOwner">—</span></span>
        </div>
        <table class="acl-table">
          <thead><tr><th>User or Group</th><th>Permission Level</th><th>Type</th><th>Inherited</th></tr></thead>
          <tbody id="folderAclBody"></tbody>
        </table>
        <div class="folder-actions">
          <button class="btn btn-primary btn-icon" onclick="showAddAceModal('folder')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Add Permission</button>
          <button class="btn btn-secondary btn-icon" onclick="showRemoveAceModal('folder')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"/></svg>Remove Permission</button>
          <button class="btn btn-secondary btn-icon" onclick="takeOwnership(false)"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Take Ownership</button>
          <button class="btn btn-secondary btn-icon" onclick="takeOwnership(true)"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Take Ownership (All Files Too)</button>
          <button class="btn btn-secondary btn-icon" onclick="showReplicateModal()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy Permissions To...</button>
          <button class="btn btn-secondary btn-icon" id="btnExport" onclick="exportReport()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Export CSV</button>
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
          <button class="btn btn-primary btn-icon" onclick="showAddAceModal('files')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>Add Permission</button>
          <button class="btn btn-secondary btn-icon" onclick="showRemoveAceModal('files')"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="5" y1="12" x2="19" y2="12"/></svg>Remove Permission</button>
          <button class="btn btn-secondary btn-icon" onclick="takeFileOwnership()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Take Ownership</button>
          <button class="btn btn-secondary btn-icon" onclick="showCopyFilesModal()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy to...</button>
          <div class="acl-diff-warning" id="aclDiffWarning" style="display:none;">
            Selected files have different permissions — this operation applies uniformly to all
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
          <button class="btn btn-secondary btn-icon" id="btnRoboPreview" onclick="roboPreview()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>Preview</button>
          <button class="btn btn-primary btn-icon" id="btnRobocopy" onclick="runRobocopy()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>Run Robocopy</button>
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
          <button class="btn btn-primary btn-icon" id="btnRobocopyFiles" onclick="runRobocopyFiles()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>Copy Selected Files</button>
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
    <h3 id="addAceModalTitle">Add Permission</h3>
    <div class="form-row"><label>User or Group</label><input type="text" id="addAceIdentity" placeholder="DOMAIN\User or DOMAIN\Group"></div>
    <div class="form-row">
      <label>Permission Level</label>
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
    <h3 id="removeAceModalTitle">Remove Permission</h3>
    <div class="form-row">
      <label>User or Group</label>
      <select id="removeAceIdentity"></select>
    </div>
    <div class="form-row">
      <label>Permission Level</label>
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
    <h3>Copy Permissions To...</h3>
    <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">Copies the current folder's permissions to each destination path you list below (one per line).</p>
    <div class="form-row"><label>Target paths</label><textarea id="replicateTargets" rows="5" style="width:100%;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 8px;font-size:12px;resize:vertical;" placeholder="C:\Shares\FolderA&#10;C:\Shares\FolderB"></textarea></div>
    <div class="form-row"><label><input type="checkbox" id="replicateRecursive"> Apply recursively</label></div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('replicateModal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitReplicate()">Copy Permissions</button>
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

function updateThemeButton(isLight) {
    var lbl = document.getElementById('btnThemeLabel');
    var icon = document.getElementById('iconTheme');
    var btn = document.getElementById('btnTheme');
    if (lbl) lbl.textContent = isLight ? 'Dark' : 'Light';
    if (btn) btn.title = isLight ? 'Switch to dark mode' : 'Switch to light mode';
    if (icon) {
        if (isLight) {
            // Moon icon for switching to dark
            icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
        } else {
            // Sun icon for switching to light
            icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
        }
    }
}
function toggleTheme() {
    document.body.classList.toggle('light');
    var isLight = document.body.classList.contains('light');
    updateThemeButton(isLight);
    localStorage.setItem('fpm-theme', isLight ? 'light' : 'dark');
}
function initTheme() {
    if (localStorage.getItem('fpm-theme') === 'light') { document.body.classList.add('light'); updateThemeButton(true); }
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
    // Update path header
    var ph = document.getElementById('path-header');
    if (ph) {
        var drive = path.match(/^[A-Za-z]:[\\\/]/);
        if (drive) {
            ph.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span class="path-drive">' + drive[0].replace(/\\/g, '/') + '</span><span class="path-rest">' + path.substring(drive[0].length).replace(/\\/g, ' \u203a ') + '</span>';
        } else {
            ph.textContent = path;
        }
        ph.style.display = 'block';
    }
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
                '<td>' + (e.isInherited ? '<span class="badge badge-inherited" title="This permission was inherited from a parent folder">Inherited</span>' : '') + '</td>';
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
                    (e.isInherited ? '<span class="badge badge-inherited" title="This permission was inherited from a parent folder">Inherited</span>' : '') + '</div>';
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
        if (identities.size === 0) { setStatus('Expand a file\'s permissions first (click ▶) to load available users and groups', 'warning'); return; }
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
    var msg = recursive
        ? 'This will change ownership on ALL files and subfolders under:\n\n' + currentFolder + '\n\nThis cannot be undone. Continue?'
        : 'Take ownership of:\n\n' + currentFolder + '?';
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
            var ok = r.exitCode === 0 || r.exitCode === 1;
            setStatus((ok ? 'Copy complete: ' : 'Copy finished with warnings/errors: ') + (r.exitMeaning || r.status || ''), ok ? 'success' : 'warning');
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
            var ok = r.exitCode === 0 || r.exitCode === 1;
            setStatus((ok ? 'Robocopy complete: ' : 'Robocopy finished with warnings/errors: ') + (r.exitMeaning || r.status || ''), ok ? 'success' : 'warning');
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
            var ok = r.exitCode === 0 || r.exitCode === 1;
            setStatus((ok ? 'Copy complete: ' : 'Copy finished with warnings/errors: ') + (r.exitMeaning || r.status || ''), ok ? 'success' : 'warning');
        })
        .catch(function(e) { setStatus('Copy failed: ' + e.message, 'error'); })
        .finally(function() { document.getElementById('btnRobocopyFiles').disabled = false; });
}

function showRoboOutput(r) {
    var out = document.getElementById('roboOutput');
    out.style.display = 'block';
    out.textContent = 'Command: ' + r.command + '\nExit code: ' + r.exitCode + ' — ' + (r.exitMeaning || r.status || '') + '\n\n' + (r.output || '');
}

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
