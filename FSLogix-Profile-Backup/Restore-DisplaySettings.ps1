<#
.SYNOPSIS
    Restores Windows display and scaling settings
.DESCRIPTION
    Imports registry keys containing display settings from backup
.PARAMETER BackupPath
    Path to the backup registry file
#>

param (
    [string]$BackupPath
)

Write-Host "Restoring display settings..."

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
        Write-Host "Display settings restored successfully."
        Write-Host "Note: Some changes may require logoff/logon or system restart to take full effect."
    } else {
        Write-Warning "Registry import completed with warnings. Some settings may not have been restored."
        Write-Host "Warnings: $result"
    }
}
catch {
    Write-Error "Error restoring display settings: $($_.Exception.Message)"
}
