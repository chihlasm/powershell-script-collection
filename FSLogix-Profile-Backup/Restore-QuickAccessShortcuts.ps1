<#
.SYNOPSIS
    Restores Windows Explorer Quick Access shortcuts
.DESCRIPTION
    Imports registry keys containing Quick Access shortcuts from backup
.PARAMETER BackupPath
    Path to the backup registry file
#>

param (
    [string]$BackupPath
)

Write-Host "Restoring Quick Access shortcuts..."

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
        Write-Host "Quick Access shortcuts restored successfully."
        Write-Host "Note: Changes may require Explorer restart or logoff/logon to take effect."
    } else {
        Write-Error "Failed to import registry file. Error: $result"
    }
}
catch {
    Write-Error "Error restoring Quick Access shortcuts: $($_.Exception.Message)"
}
