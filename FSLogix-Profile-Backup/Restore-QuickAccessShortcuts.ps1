<#
.SYNOPSIS
    Restores Windows Explorer Quick Access shortcuts
.DESCRIPTION
    Imports registry keys containing Quick Access shortcuts from backup
.PARAMETER BackupPath
    Path to the backup registry file
.EXAMPLE
    .\Restore-QuickAccessShortcuts.ps1 -BackupPath "C:\Backup\QuickAccessBackup.reg"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath
)

Write-Host "Restoring Quick Access shortcuts..."

try {
    if (-not (Test-Path $BackupPath)) {
        throw "Backup file not found: $BackupPath"
    }

    Write-Host "Importing registry file: $BackupPath"

    # Use Start-Process for better control
    $process = Start-Process -FilePath "reg.exe" -ArgumentList "import", "`"$BackupPath`"" -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Host "Quick Access shortcuts restored successfully." -ForegroundColor Green
        Write-Host "Note: Changes may require Explorer restart or logoff/logon to take effect."
    } else {
        throw "Registry import failed with exit code: $($process.ExitCode)"
    }
}
catch {
    Write-Error "Error restoring Quick Access shortcuts: $($_.Exception.Message)"
    throw
}
