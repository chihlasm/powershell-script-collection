<#
.SYNOPSIS
    Main script to restore FSLogix profile settings from backup
.DESCRIPTION
    Runs all restore scripts to import backed up user settings into current profile.
    Validates backup integrity and provides detailed status reporting.
.PARAMETER BackupPath
    Path to the backup directory containing the files to restore
.PARAMETER SkipRegistry
    Skip registry-based restorations (useful when restoring to different system)
.PARAMETER SkipBrowser
    Skip browser-related restorations (bookmarks, passwords)
.PARAMETER Force
    Skip confirmation prompts and restore even if checksums don't match
.EXAMPLE
    .\Restore-FSLogixProfile.ps1
    Restores from the most recent backup in the default location
.EXAMPLE
    .\Restore-FSLogixProfile.ps1 -BackupPath "D:\Backups\Backup_20241115_120000"
    Restores from a specific backup directory
.EXAMPLE
    .\Restore-FSLogixProfile.ps1 -SkipRegistry
    Restores only browser bookmarks, skipping registry settings
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = ".\FSLogixBackups",

    [Parameter(Mandatory = $false)]
    [switch]$SkipRegistry,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBrowser,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Script-level variables for tracking
$script:RestoreResults = @{}
$script:LogPath = $null

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Write to console with appropriate color
    switch ($Level) {
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }

    # Write to log file if available
    if ($script:LogPath) {
        $logMessage | Out-File -FilePath $script:LogPath -Append -Encoding UTF8
    }
}

function Test-BackupIntegrity {
    param(
        [string]$BackupDir,
        [hashtable]$ManifestResults
    )

    $integrityOk = $true

    foreach ($item in $ManifestResults.GetEnumerator()) {
        if ($item.Value.Checksum -and $item.Value.Output) {
            $filePath = $item.Value.Output
            if (Test-Path $filePath) {
                $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
                if ($currentHash -ne $item.Value.Checksum) {
                    Write-Log "Checksum mismatch for $($item.Key): expected $($item.Value.Checksum), got $currentHash" -Level Warning
                    $integrityOk = $false
                }
            }
        }
    }

    return $integrityOk
}

#endregion

Write-Host ""
Write-Log "========== FSLogix Profile Restore Started ==========" -Level Info
Write-Log "Backup source: $BackupPath" -Level Info

# Find the backup directory
if (Test-Path $BackupPath) {
    $backupItem = Get-Item $BackupPath
    if ($backupItem.PSIsContainer) {
        # Check if this is a backup directory itself (contains manifest)
        $manifestCheck = Join-Path $BackupPath "BACKUP_MANIFEST.json"
        if (-not (Test-Path $manifestCheck)) {
            # It's a parent directory, find the most recent backup
            $latestBackup = Get-ChildItem $BackupPath -Directory |
                Where-Object { $_.Name -match '^Backup_\d{8}_\d{6}$' } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            if ($latestBackup) {
                $BackupPath = $latestBackup.FullName
                Write-Log "Using most recent backup: $BackupPath" -Level Info
            } else {
                Write-Log "No backup directories found in: $BackupPath" -Level Error
                exit 1
            }
        }
    }
} else {
    Write-Log "Backup path not found: $BackupPath" -Level Error
    exit 1
}

# Initialize log file in backup directory
$script:LogPath = Join-Path $BackupPath "restore.log"

# Load and validate manifest
$manifestPath = Join-Path $BackupPath "BACKUP_MANIFEST.json"
$manifest = $null

if (Test-Path $manifestPath) {
    try {
        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
        Write-Log "Backup manifest loaded successfully" -Level Info
        Write-Log "Backup created: $($manifest.BackupInfo.Date)" -Level Info
        Write-Log "Created by: $($manifest.BackupInfo.CreatedBy) on $($manifest.BackupInfo.ComputerName)" -Level Info

        # Check integrity if manifest has checksums
        if ($manifest.Results -and -not $Force) {
            $resultsHash = @{}
            foreach ($prop in $manifest.Results.PSObject.Properties) {
                $resultsHash[$prop.Name] = $prop.Value
            }

            $integrityOk = Test-BackupIntegrity -BackupDir $BackupPath -ManifestResults $resultsHash
            if (-not $integrityOk) {
                Write-Log "Backup integrity check failed. Use -Force to restore anyway." -Level Warning
                $continue = Read-Host "Continue with restore? (Y/N)"
                if ($continue -ne 'Y' -and $continue -ne 'y') {
                    Write-Log "Restore cancelled by user" -Level Info
                    exit 0
                }
            }
        }
    }
    catch {
        Write-Log "Failed to load manifest: $($_.Exception.Message)" -Level Warning
        Write-Log "Continuing without manifest validation..." -Level Warning
    }
} else {
    Write-Log "No manifest found. Continuing without validation..." -Level Warning
}

try {
    # Get script directory
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

    # Define restore operations
    $restoreOperations = @(
        @{
            Name = "Quick Access Shortcuts"
            Script = "Restore-QuickAccessShortcuts.ps1"
            Input = "QuickAccessBackup.reg"
            Type = "Registry"
            Skip = $SkipRegistry
        },
        @{
            Name = "Chrome Bookmarks"
            Script = "Restore-ChromeBookmarks.ps1"
            Input = "ChromeBookmarks.bak"
            Type = "Browser"
            Skip = $SkipBrowser
        },
        @{
            Name = "Edge Bookmarks"
            Script = "Restore-EdgeBookmarks.ps1"
            Input = "EdgeBookmarks.bak"
            Type = "Browser"
            Skip = $SkipBrowser
        },
        @{
            Name = "Display Settings"
            Script = "Restore-DisplaySettings.ps1"
            Input = "DisplaySettingsBackup.reg"
            Type = "Registry"
            Skip = $SkipRegistry
        },
        @{
            Name = "Taskbar Settings"
            Script = "Restore-TaskbarSettings.ps1"
            Input = "TaskbarSettingsBackup.reg"
            Type = "Registry"
            Skip = $SkipRegistry
        }
    )

    # Execute restore operations
    foreach ($operation in $restoreOperations) {
        if ($operation.Skip) {
            Write-Log "Skipping $($operation.Name) (excluded by parameter)" -Level Info
            $script:RestoreResults[$operation.Name] = @{
                Status = "Skipped"
                Reason = "Excluded by parameter"
            }
            continue
        }

        Write-Log "=== Restoring $($operation.Name) ===" -Level Info

        $scriptPath = Join-Path $scriptDir $operation.Script
        $inputPath = Join-Path $BackupPath $operation.Input

        if (-not (Test-Path $scriptPath)) {
            Write-Log "$($operation.Name) restore script not found: $scriptPath" -Level Warning
            $script:RestoreResults[$operation.Name] = @{
                Status = "Failed"
                Error = "Restore script not found"
            }
            continue
        }

        if (-not (Test-Path $inputPath)) {
            # Check for multi-profile backups (Edge/Chrome)
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($operation.Input)
            $extension = [System.IO.Path]::GetExtension($operation.Input)
            $multiProfileFiles = Get-ChildItem $BackupPath -Filter "$baseName-*$extension" -ErrorAction SilentlyContinue

            if ($multiProfileFiles) {
                Write-Log "Found multi-profile backup files for $($operation.Name)" -Level Info
                # For now, restore the Default profile if it exists
                $defaultFile = $multiProfileFiles | Where-Object { $_.Name -match "Default" } | Select-Object -First 1
                if ($defaultFile) {
                    $inputPath = $defaultFile.FullName
                } else {
                    $inputPath = $multiProfileFiles[0].FullName
                }
                Write-Log "Using: $inputPath" -Level Info
            } else {
                Write-Log "$($operation.Name) backup file not found: $inputPath" -Level Warning
                $script:RestoreResults[$operation.Name] = @{
                    Status = "Skipped"
                    Reason = "Backup file not found"
                }
                continue
            }
        }

        try {
            & $scriptPath -BackupPath $inputPath

            $script:RestoreResults[$operation.Name] = @{
                Status = "Success"
                Input = $inputPath
            }
            Write-Log "$($operation.Name) restored successfully" -Level Success
        }
        catch {
            $script:RestoreResults[$operation.Name] = @{
                Status = "Failed"
                Error = $_.Exception.Message
            }
            Write-Log "Failed to restore $($operation.Name): $($_.Exception.Message)" -Level Error
        }
    }

    # Browser passwords instructions
    if (-not $SkipBrowser) {
        Write-Log "=== Browser Password Restoration ===" -Level Info
        $passwordDir = Join-Path $BackupPath "BrowserPasswords"
        if (Test-Path $passwordDir) {
            $instructionFile = Join-Path $passwordDir "PasswordBackupInstructions.txt"
            if (Test-Path $instructionFile) {
                Write-Log "Browser password restoration instructions available at: $instructionFile" -Level Info
                Write-Log "Please follow the manual steps in the file to restore passwords." -Level Warning
            }
        } else {
            Write-Log "No browser password backup found" -Level Info
        }
    }

    # Summary
    $successCount = ($script:RestoreResults.Values | Where-Object { $_.Status -eq "Success" }).Count
    $failedCount = ($script:RestoreResults.Values | Where-Object { $_.Status -eq "Failed" }).Count
    $skippedCount = ($script:RestoreResults.Values | Where-Object { $_.Status -eq "Skipped" }).Count

    Write-Log "" -Level Info
    Write-Log "========== RESTORATION COMPLETED ==========" -Level Success
    Write-Log "Results: $successCount succeeded, $failedCount failed, $skippedCount skipped" -Level Info
    Write-Log "" -Level Info
    Write-Log "Post-restoration steps:" -Level Info
    Write-Log "- Registry changes may require logoff/logon to take effect" -Level Info
    Write-Log "- Browser bookmarks require browser restart" -Level Info
    Write-Log "- Taskbar items may need to be unpinned and re-pinned" -Level Info

    # Save restore results
    $restoreManifest = @{
        RestoreInfo = @{
            Date = (Get-Date).ToString("o")
            RestoredBy = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            SourceBackup = $BackupPath
        }
        Results = $script:RestoreResults
    }

    $restoreManifestPath = Join-Path $BackupPath "RESTORE_MANIFEST.json"
    $restoreManifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $restoreManifestPath -Encoding UTF8
    Write-Log "Restore manifest saved to: $restoreManifestPath" -Level Info
}
catch {
    Write-Log "Error during restoration process: $($_.Exception.Message)" -Level Error
    throw
}
