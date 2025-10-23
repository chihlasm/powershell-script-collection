<#
.SYNOPSIS
    Backs up Microsoft Edge bookmarks
.DESCRIPTION
    Copies Edge's Bookmarks file for backup and restoration
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\EdgeBookmarks.bak)
#>

param (
    [string]$OutputPath = ".\EdgeBookmarks.bak",
    [string]$ProfilePath
)

Write-Host "Backing up Edge bookmarks..."

try {
    # Determine Edge bookmarks location
    if ($ProfilePath) {
        # Use mounted profile path
        $edgeBookmarksPath = Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
    } else {
        # Use current user's default location
        $edgeBookmarksPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"
    }

    if (Test-Path $edgeBookmarksPath) {
        # Create backup directory if it doesn't exist
        $backupDir = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        # Copy the bookmarks file
        Copy-Item -Path $edgeBookmarksPath -Destination $OutputPath -Force

        if (Test-Path $OutputPath) {
            Write-Host "Edge bookmarks backed up successfully to: $OutputPath"
            Write-Host "Backup size: $((Get-Item $OutputPath).Length) bytes"
        } else {
            Write-Warning "Failed to create backup file"
        }
    } else {
        Write-Warning "Edge bookmarks file not found at: $edgeBookmarksPath"
        Write-Warning "Edge may not be installed or no profile created yet"
    }
}
catch {
    Write-Error "Error backing up Edge bookmarks: $($_.Exception.Message)"
}
