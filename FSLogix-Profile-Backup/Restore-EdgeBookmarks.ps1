<#
.SYNOPSIS
    Restores Edge bookmarks from backup
.DESCRIPTION
    Copies Edge bookmarks file to the current user's Edge profile
.PARAMETER BackupPath
    Path to the backup bookmarks file
.EXAMPLE
    .\Restore-EdgeBookmarks.ps1 -BackupPath "C:\Backup\EdgeBookmarks.bak"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath
)

Write-Host "Restoring Edge bookmarks..."

try {
    if (-not (Test-Path $BackupPath)) {
        throw "Backup file not found: $BackupPath"
    }

    # Target Edge bookmarks location
    $edgeBookmarksPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"

    # Ensure Edge profile directory exists
    $edgeDir = Split-Path -Path $edgeBookmarksPath -Parent
    if (-not (Test-Path $edgeDir)) {
        New-Item -ItemType Directory -Path $edgeDir -Force | Out-Null
        Write-Host "Created Edge profile directory: $edgeDir"
    }

    # Check if Edge is running
    $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
    if ($edgeProcesses) {
        Write-Warning "Edge is currently running. Please close Edge for proper restoration."
        Write-Host "Continuing with restoration - changes will take effect after Edge restart."
    }

    Write-Host "Copying bookmarks to: $edgeBookmarksPath"

    # Create backup of existing bookmarks if they exist
    if (Test-Path $edgeBookmarksPath) {
        $backupExisting = "$edgeBookmarksPath.pre-restore"
        Copy-Item -Path $edgeBookmarksPath -Destination $backupExisting -Force
        Write-Host "Existing bookmarks backed up to: $backupExisting"
    }

    # Copy the backup file
    Copy-Item -Path $BackupPath -Destination $edgeBookmarksPath -Force

    if (Test-Path $edgeBookmarksPath) {
        $backupInfo = Get-Item $BackupPath
        $fileSize = [math]::Round($backupInfo.Length / 1KB, 2)
        Write-Host "Edge bookmarks restored successfully." -ForegroundColor Green
        Write-Host "Restored bookmarks file size: ${fileSize}KB"
        Write-Host "Please restart Edge to see the changes."
    } else {
        throw "Failed to restore Edge bookmarks - file not created"
    }
}
catch {
    Write-Error "Error restoring Edge bookmarks: $($_.Exception.Message)"
    throw
}
