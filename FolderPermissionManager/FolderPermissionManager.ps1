param(
    [string]$Path
)

# Check if path is provided
if (-not $Path) {
    $Path = Read-Host "Enter the path to the top-level folder"
}

# Validate path
if (-not (Test-Path $Path -PathType Container)) {
    Write-Error "The specified path does not exist or is not a directory."
    exit
}

# Function to take ownership of sub-folders
function Take-Ownership {
    param([string]$FolderPath)
    Write-Host "Taking ownership of sub-folders in $FolderPath..."
    # Use icacls to take ownership recursively
    icacls $FolderPath /setowner $env:USERNAME /T /C /Q
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to take ownership. Ensure you are running as Administrator."
    } else {
        Write-Host "Ownership taken successfully."
    }
}

# Take ownership
Take-Ownership -FolderPath $Path

# Get ACL of top-level folder
$topAcl = Get-Acl $Path

# Display permissions on top-level folder
Write-Host "`nPermissions on top-level folder ($Path):"
Write-Host "Owner: $($topAcl.Owner)"
Write-Host "Access Rules:"
$topAcl.Access | Format-Table -AutoSize

# Get all sub-folders (skip inaccessible ones)
$subFolders = Get-ChildItem $Path -Recurse -Directory -ErrorAction SilentlyContinue

# Display permissions on sub-folders
Write-Host "`nSub-folders and their owners:"
foreach ($folder in $subFolders) {
    try {
        $folderAcl = Get-Acl $folder.FullName -ErrorAction Stop
        Write-Host "$($folder.FullName) - Owner: $($folderAcl.Owner)"
    } catch {
        Write-Warning "Cannot access $($folder.FullName): $($_.Exception.Message)"
    }
}

# Ask for confirmation to replicate permissions
$confirm = Read-Host "`nDo you want to replicate the permissions from the top-level folder to all sub-folders? (y/n)"
if ($confirm -eq 'y' -or $confirm -eq 'Y') {
    Write-Host "Replicating permissions..."
    foreach ($folder in $subFolders) {
        try {
            $subAcl = Get-Acl $folder.FullName
            # Add access rules from top-level ACL if they don't already exist
            foreach ($rule in $topAcl.Access) {
                $exists = $subAcl.Access | Where-Object {
                    $_.IdentityReference -eq $rule.IdentityReference -and
                    $_.FileSystemRights -eq $rule.FileSystemRights -and
                    $_.AccessControlType -eq $rule.AccessControlType -and
                    $_.InheritanceFlags -eq $rule.InheritanceFlags -and
                    $_.PropagationFlags -eq $rule.PropagationFlags
                }
                if (-not $exists) {
                    $subAcl.AddAccessRule($rule)
                }
            }
            Set-Acl -Path $folder.FullName -AclObject $subAcl
            Write-Host "Permissions added to $($folder.FullName)"
        } catch {
            Write-Warning "Failed to add permissions to $($folder.FullName): $($_.Exception.Message)"
        }
    }
    Write-Host "Replication complete."
} else {
    Write-Host "Replication cancelled."
}
