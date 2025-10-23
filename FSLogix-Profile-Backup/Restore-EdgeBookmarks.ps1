<#
.SYNOPSIS
    Restores Edge bookmarks from backup
.DESCRIPTION
    Copies Edge bookmarks file to the current user's Edge profile
.PARAMETER BackupPath
    Path to the backup bookmarks file
#>

param (
    [string]$BackupPath
)

Write-Host "Restoring Edge bookmarks..."

try {
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup file not found: $BackupPath"
        return
    }

    # Target Edge bookmarks location
    $edgeBookmarksPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"

    # Ensure Edge profile directory exists
    $edgeDir = Split-Path -Path $edgeBookmarksPath -Parent
    if (-not (Test-Path $edgeDir)) {
        New-Item -ItemType Directory -Path $edgeDir -Force | Out-Null
    }

    Write-Host "Copying bookmarks to: $edgeBookmarksPath"

    # Check if Edge is running
    $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
    if ($edgeProcesses) {
        Write-Warning "Edge is currently running. Please close Edge for proper restoration."
        Write-Host "Continuing with restoration - changes will take effect after Edge restart."
    }

    # Copy the backup file
    Copy-Item -Path $BackupPath -Destination $edgeBookmarksPath -Force

    if (Test-Path $edgeBookmarksPath) {
        Write-Host "Edge bookmarks restored successfully."
        Write-Host "Please restart Edge to see the changes."

        $backupInfo = Get-Item $BackupPath
        $fileSize = [math]::Round($backupInfo.Length / 1KB, 2)
        Write-Host "Restored bookmarks file size: ${fileSize}KB"
    } else {
        Write-Error "Failed to restore Edge bookmarks."
    }
}
catch {
    Write-Error "Error restoring Edge bookmarks: $($_.Exception.Message)"
}
