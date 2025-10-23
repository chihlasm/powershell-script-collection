<#
.SYNOPSIS
    Restores Chrome bookmarks from backup
.DESCRIPTION
    Copies Chrome bookmarks file to the current user's Chrome profile
.PARAMETER BackupPath
    Path to the backup bookmarks file
#>

param (
    [string]$BackupPath
)

Write-Host "Restoring Chrome bookmarks..."

try {
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup file not found: $BackupPath"
        return
    }

    # Target Chrome bookmarks location
    $chromeBookmarksPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"

    # Ensure Chrome profile directory exists
    $chromeDir = Split-Path -Path $chromeBookmarksPath -Parent
    if (-not (Test-Path $chromeDir)) {
        New-Item -ItemType Directory -Path $chromeDir -Force | Out-Null
    }

    Write-Host "Copying bookmarks to: $chromeBookmarksPath"

    # Check if Chrome is running
    $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
    if ($chromeProcesses) {
        Write-Warning "Chrome is currently running. Please close Chrome for proper restoration."
        Write-Host "Continuing with restoration - changes will take effect after Chrome restart."
    }

    # Copy the backup file
    Copy-Item -Path $BackupPath -Destination $chromeBookmarksPath -Force

    if (Test-Path $chromeBookmarksPath) {
        Write-Host "Chrome bookmarks restored successfully."
        Write-Host "Please restart Chrome to see the changes."

        $backupInfo = Get-Item $BackupPath
        $fileSize = [math]::Round($backupInfo.Length / 1KB, 2)
        Write-Host "Restored bookmarks file size: ${fileSize}KB"
    } else {
        Write-Error "Failed to restore Chrome bookmarks."
    }
}
catch {
    Write-Error "Error restoring Chrome bookmarks: $($_.Exception.Message)"
}
