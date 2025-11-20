<#
.SYNOPSIS
    Restores Windows display and scaling settings
.DESCRIPTION
    Imports registry keys containing display settings from backup
.PARAMETER BackupPath
    Path to the backup registry file
.EXAMPLE
    .\Restore-DisplaySettings.ps1 -BackupPath "C:\Backup\DisplaySettingsBackup.reg"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath
)

Write-Host "Restoring display settings..."

try {
    if (-not (Test-Path $BackupPath)) {
        throw "Backup file not found: $BackupPath"
    }

    Write-Host "Importing registry file: $BackupPath"

    # Use Start-Process for better control
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "import", "`"$BackupPath`"" -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "Display settings restored successfully." -ForegroundColor Green
        Write-Host "Note: Some changes may require logoff/logon or system restart to take full effect."
    } else {
        throw "Registry import failed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Error "Error restoring display settings: $($_.Exception.Message)"
    throw
}
