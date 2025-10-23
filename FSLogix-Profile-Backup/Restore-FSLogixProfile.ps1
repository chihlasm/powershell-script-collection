<#
.SYNOPSIS
    Main script to restore FSLogix profile settings from backup
.DESCRIPTION
    Runs all restore scripts to import backed up user settings into current profile
.PARAMETER BackupPath
    Path to the backup directory containing the files to restore
.PARAMETER SkipRegistry
    Skip registry-based restorations (useful when restoring to different system)
.PARAMETER SkipBrowser
    Skip browser-related restorations (bookmarks, passwords)
#>

param (
    [string]$BackupPath = ".\FSLogixBackups",
    [switch]$SkipRegistry,
    [switch]$SkipBrowser
)

Write-Host "Starting FSLogix Profile Restore..."
Write-Host "Backup source: $BackupPath"

# Find the most recent backup if BackupPath is a directory
if (Test-Path $BackupPath) {
    $backupItem = Get-Item $BackupPath
    if ($backupItem.PSIsContainer) {
        # It's a directory, find the most recent backup
        $latestBackup = Get-ChildItem $BackupPath -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latestBackup) {
            $BackupPath = $latestBackup.FullName
            Write-Host "Using most recent backup: $BackupPath"
        } else {
            Write-Error "No backup directories found in: $BackupPath"
            exit 1
        }
    }
} else {
    Write-Error "Backup path not found: $BackupPath"
    exit 1
}

try {
    # Run restore scripts
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

    # Restore Quick Access shortcuts
    if (-not $SkipRegistry) {
        Write-Host "`n=== Restoring Quick Access Shortcuts ==="
        $scriptPath = Join-Path $scriptDir "Restore-QuickAccessShortcuts.ps1"
        $inputPath = Join-Path $BackupPath "QuickAccessBackup.reg"
        if (Test-Path $scriptPath) {
            if (Test-Path $inputPath) {
                & $scriptPath -BackupPath $inputPath
            } else {
                Write-Warning "Quick Access backup file not found: $inputPath"
            }
        } else {
            Write-Warning "Quick Access restore script not found: $scriptPath"
        }
    }

    # Restore Chrome bookmarks
    if (-not $SkipBrowser) {
        Write-Host "`n=== Restoring Chrome Bookmarks ==="
        $scriptPath = Join-Path $scriptDir "Restore-ChromeBookmarks.ps1"
        $inputPath = Join-Path $BackupPath "ChromeBookmarks.bak"
        if (Test-Path $scriptPath) {
            if (Test-Path $inputPath) {
                & $scriptPath -BackupPath $inputPath
            } else {
                Write-Warning "Chrome bookmarks backup file not found: $inputPath"
            }
        } else {
            Write-Warning "Chrome bookmarks restore script not found: $scriptPath"
        }
    }

    # Restore Edge bookmarks
    if (-not $SkipBrowser) {
        Write-Host "`n=== Restoring Edge Bookmarks ==="
        $scriptPath = Join-Path $scriptDir "Restore-EdgeBookmarks.ps1"
        $inputPath = Join-Path $BackupPath "EdgeBookmarks.bak"
        if (Test-Path $scriptPath) {
            if (Test-Path $inputPath) {
                & $scriptPath -BackupPath $inputPath
            } else {
                Write-Warning "Edge bookmarks backup file not found: $inputPath"
            }
        } else {
            Write-Warning "Edge bookmarks restore script not found: $scriptPath"
        }
    }

    # Restore display settings
    if (-not $SkipRegistry) {
        Write-Host "`n=== Restoring Display Settings ==="
        $scriptPath = Join-Path $scriptDir "Restore-DisplaySettings.ps1"
        $inputPath = Join-Path $BackupPath "DisplaySettingsBackup.reg"
        if (Test-Path $scriptPath) {
            if (Test-Path $inputPath) {
                & $scriptPath -BackupPath $inputPath
            } else {
                Write-Warning "Display settings backup file not found: $inputPath"
            }
        } else {
            Write-Warning "Display settings restore script not found: $scriptPath"
        }
    }

    # Restore taskbar settings
    if (-not $SkipRegistry) {
        Write-Host "`n=== Restoring Taskbar Settings ==="
        $scriptPath = Join-Path $scriptDir "Restore-TaskbarSettings.ps1"
        $inputPath = Join-Path $BackupPath "TaskbarSettingsBackup.reg"
        if (Test-Path $scriptPath) {
            if (Test-Path $inputPath) {
                & $scriptPath -BackupPath $inputPath
            } else {
                Write-Warning "Taskbar settings backup file not found: $inputPath"
            }
        } else {
            Write-Warning "Taskbar settings restore script not found: $scriptPath"
        }
    }

    # Restore browser passwords instructions
    if (-not $SkipBrowser) {
        Write-Host "`n=== Browser Password Restoration ==="
        $passwordDir = Join-Path $BackupPath "BrowserPasswords"
        if (Test-Path $passwordDir) {
            $instructionFile = Join-Path $passwordDir "PasswordBackupInstructions.txt"
            if (Test-Path $instructionFile) {
                Write-Host "Browser password restoration instructions are available in: $instructionFile"
                Write-Host "Please follow the manual steps in the file to restore passwords."
            }
        } else {
            Write-Warning "Browser password backup directory not found: $passwordDir"
        }
    }

    Write-Host "`n========== RESTORATION COMPLETED =========="
    Write-Host "Some changes may require logging off and back on to take effect."
    Write-Host "Browser bookmarks may require browser restart."

}
catch {
    Write-Error "Error during restoration process: $($_.Exception.Message)"
}
