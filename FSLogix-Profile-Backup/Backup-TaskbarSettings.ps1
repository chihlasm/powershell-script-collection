<#
.SYNOPSIS
    Backs up Windows Taskbar shortcuts and settings
.DESCRIPTION
    Exports registry keys containing taskbar settings and pinned items for backup and restoration
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\TaskbarSettingsBackup.reg)
#>

param (
    [string]$OutputPath = ".\TaskbarSettingsBackup.reg",
    [string]$ProfilePath
)

Write-Host "Backing up Taskbar shortcuts and settings..."

if ($ProfilePath) {
    Write-Warning "ProfilePath parameter not applicable for registry-based backups. Exporting current user's registry."
}

try {
    # Create backup directory if it doesn't exist
    $backupDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }

    # Temporary file to combine exports
    $tempFile = [System.IO.Path]::GetTempFileName()

    # Export taskbar-related registry keys
    $regPaths = @(
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TaskBand",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TaskBar"
    )

    $exportCount = 0
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $regCommand = "reg export `"$regPath`" `"$tempFile`" /y"
            Invoke-Expression $regCommand
            if (Test-Path $tempFile) {
                # Append to output file
                if (Test-Path $OutputPath) {
                    Get-Content $tempFile | Add-Content $OutputPath
                } else {
                    Copy-Item $tempFile $OutputPath -Force
                }
                Remove-Item $tempFile -Force
                $exportCount++
            }
        } else {
            Write-Warning "Registry path not found: $regPath"
        }
    }

    if (Test-Path $OutputPath) {
        Write-Host "Taskbar settings backed up successfully to: $OutputPath"
        Write-Host "Backup size: $((Get-Item $OutputPath).Length) bytes"
    } else {
        Write-Warning "Failed to create backup file"
    }
}
catch {
    Write-Error "Error backing up taskbar settings: $($_.Exception.Message)"
}
finally {
    # Clean up temp file if it still exists
    if (Test-Path $tempFile) {
        Remove-Item $tempFile -Force
    }
}
