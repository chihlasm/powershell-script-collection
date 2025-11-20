<#
.SYNOPSIS
    Restores Chrome bookmarks from backup
.DESCRIPTION
    Copies Chrome bookmarks file to the current user's Chrome profile
.PARAMETER BackupPath
    Path to the backup bookmarks file
.EXAMPLE
    .\Restore-ChromeBookmarks.ps1 -BackupPath "C:\Backup\ChromeBookmarks.bak"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath
)

Write-Host "Restoring Chrome bookmarks..."

try {
    if (-not (Test-Path $BackupPath)) {
        throw "Backup file not found: $BackupPath"
    }

    # Target Chrome bookmarks location
    $chromeBookmarksPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"

    # Ensure Chrome profile directory exists
    $chromeDir = Split-Path -Path $chromeBookmarksPath -Parent
    if (-not (Test-Path $chromeDir)) {
        New-Item -ItemType Directory -Path $chromeDir -Force | Out-Null
        Write-Host "Created Chrome profile directory: $chromeDir"
    }

    # Check if Chrome is running
    $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
    if ($chromeProcesses) {
        Write-Warning "Chrome is currently running. Please close Chrome for proper restoration."
        Write-Host "Continuing with restoration - changes will take effect after Chrome restart."
    }

    Write-Host "Copying bookmarks to: $chromeBookmarksPath"

    # Create backup of existing bookmarks if they exist
    if (Test-Path $chromeBookmarksPath) {
        $backupExisting = "$chromeBookmarksPath.pre-restore"
        Copy-Item -Path $chromeBookmarksPath -Destination $backupExisting -Force
        Write-Host "Existing bookmarks backed up to: $backupExisting"
    }

    # Copy the backup file
    Copy-Item -Path $BackupPath -Destination $chromeBookmarksPath -Force

    if (Test-Path $chromeBookmarksPath) {
        $backupInfo = Get-Item $BackupPath
        $fileSize = [math]::Round($backupInfo.Length / 1KB, 2)
        Write-Host "Chrome bookmarks restored successfully." -ForegroundColor Green
        Write-Host "Restored bookmarks file size: ${fileSize}KB"
        Write-Host "Please restart Chrome to see the changes."
    } else {
        throw "Failed to restore Chrome bookmarks - file not created"
    }
}
catch {
    Write-Error "Error restoring Chrome bookmarks: $($_.Exception.Message)"
    throw
}
