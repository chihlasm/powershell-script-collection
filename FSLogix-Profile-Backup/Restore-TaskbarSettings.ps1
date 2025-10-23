<#
.SYNOPSIS
    Restores Windows Taskbar shortcuts and settings
.DESCRIPTION
    Imports registry keys containing taskbar settings from backup
.PARAMETER BackupPath
    Path to the backup registry file
#>

param (
    [string]$BackupPath
)

Write-Host "Restoring taskbar settings..."

try {
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup file not found: $BackupPath"
        return
    }

    Write-Host "Importing registry file: $BackupPath"

    # Import the registry file
    $regCommand = "reg import `"$BackupPath`""
    $result = cmd /c $regCommand 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Taskbar settings restored successfully."
        Write-Host "Note: Changes may require logoff/logon or Explorer restart to take effect."
        Write-Host "You may need to unpin/re-pin items for changes to be fully visible."
    } else {
        Write-Warning "Registry import completed with warnings. Some settings may not have been restored."
        Write-Host "Warnings: $result"
    }
}
catch {
    Write-Error "Error restoring taskbar settings: $($_.Exception.Message)"
}
