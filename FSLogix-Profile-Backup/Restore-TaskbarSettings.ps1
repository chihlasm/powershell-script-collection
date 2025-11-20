<#
.SYNOPSIS
    Restores Windows Taskbar shortcuts and settings
.DESCRIPTION
    Imports registry keys containing taskbar settings from backup
.PARAMETER BackupPath
    Path to the backup registry file
.EXAMPLE
    .\Restore-TaskbarSettings.ps1 -BackupPath "C:\Backup\TaskbarSettingsBackup.reg"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath
)

Write-Host "Restoring taskbar settings..."

try {
    if (-not (Test-Path $BackupPath)) {
        throw "Backup file not found: $BackupPath"
    }

    Write-Host "Importing registry file: $BackupPath"

    # Use Start-Process for better control
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "import", "`"$BackupPath`"" -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "Taskbar settings restored successfully." -ForegroundColor Green
        Write-Host "Note: Changes may require logoff/logon or Explorer restart to take effect."
        Write-Host "You may need to unpin/re-pin items for changes to be fully visible."
    } else {
        throw "Registry import failed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Error "Error restoring taskbar settings: $($_.Exception.Message)"
    throw
}
