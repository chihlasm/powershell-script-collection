<#
.SYNOPSIS
    Main script to backup FSLogix profile settings
.DESCRIPTION
    Runs all backup scripts to create a comprehensive backup of user settings
.PARAMETER BackupPath
    Root path where backups will be stored (default: current directory + 'FSLogixBackups')
.PARAMETER CreateZip
    Whether to create a ZIP archive of the backup (default: true)
.PARAMETER FSLogixProfile
    Path to FSLogix VHD/VHDX file to mount for offline backup
.PARAMETER MountProfile
    Switch to enable mounting of FSLogix profile (requires -FSLogixProfile)
#>

[CmdletBinding(SupportsShouldProcess = $false)]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = ".\FSLogixBackups",

    [Parameter(Mandatory = $false)]
    [bool]$CreateZip = $true,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FSLogixProfile,

    [Parameter(Mandatory = $false)]
    [switch]$MountProfile
)

# Ensure we're running as administrator for some operations
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script may require administrator privileges for some operations."
    Write-Warning "Consider running as administrator if you encounter access issues."
}

# Create timestamped backup directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $BackupPath "Backup_$timestamp"

Write-Host "Starting FSLogix Profile Backup..."
Write-Host "Backup directory: $backupDir"
Write-Host "Create ZIP archive: $CreateZip"
if ($MountProfile) {
    Write-Host "FSLogix profile mounting enabled"
    if (-not $FSLogixProfile) {
        Write-Error "FSLogix profile path must be specified when using -MountProfile"
        exit 1
    }
    Write-Host "Profile to mount: $FSLogixProfile"
}

try {
    # Mount FSLogix profile if requested
    $mountedProfile = $null
    $mountedDriveLetter = $null

    if ($MountProfile -and $FSLogixProfile) {
        Write-Host "`n=== Mounting FSLogix Profile ==="
        try {
            if (-not (Test-Path $FSLogixProfile)) {
                throw "FSLogix profile file not found: $FSLogixProfile"
            }

            # Mount the VHD/VHDX file
            $mountResult = Mount-DiskImage -ImagePath $FSLogixProfile -PassThru
            Write-Host "Disk image mounted successfully"

            # Find the mounted drive letter
            $disk = Get-Disk | Where-Object { $_.Location -eq $FSLogixProfile }
            $partition = Get-Partition | Where-Object { $_.DiskNumber -eq $disk.Number }
            $mountedDriveLetter = ($partition | Get-Volume).DriveLetter

            if ($mountedDriveLetter) {
                $mountedProfile = "$mountedDriveLetter`:"
                Write-Host "FSLogix profile mounted at: $mountedProfile"

                # Verify it's an FSLogix profile structure
                $fslogixTestPath = Join-Path $mountedProfile "Profile"
                if (Test-Path $fslogixTestPath) {
                    $mountedProfile = Join-Path $mountedProfile "Profile"
                    Write-Host "FSLogix profile structure detected. Using path: $mountedProfile"
                }
            } else {
                throw "Unable to determine mounted drive letter"
            }
        }
        catch {
            Write-Error "Failed to mount FSLogix profile: $($_.Exception.Message)"
            exit 1
        }
    }

    # Create backup directory
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }

    # Define backup operations with progress tracking
    $backupOperations = @(
        @{
            Name = "Quick Access Shortcuts"
            Script = "Backup-QuickAccessShortcuts.ps1"
            Output = "QuickAccessBackup.reg"
        },
        @{
            Name = "Chrome Bookmarks"
            Script = "Backup-ChromeBookmarks.ps1"
            Output = "ChromeBookmarks.bak"
        },
        @{
            Name = "Edge Bookmarks"
            Script = "Backup-EdgeBookmarks.ps1"
            Output = "EdgeBookmarks.bak"
        },
        @{
            Name = "Display Settings"
            Script = "Backup-DisplaySettings.ps1"
            Output = "DisplaySettingsBackup.reg"
        },
        @{
            Name = "Taskbar Settings"
            Script = "Backup-TaskbarSettings.ps1"
            Output = "TaskbarSettingsBackup.reg"
        },
        @{
            Name = "Browser Password Instructions"
            Script = "Backup-BrowserPasswords.ps1"
            Output = "BrowserPasswords"
        }
    )

    # Run individual backup scripts with progress
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

    Write-Progress -Activity "Backing up FSLogix Profile" -Status "Preparing backup operations..." -PercentComplete 0

    for ($i = 0; $i -lt $backupOperations.Count; $i++) {
        $operation = $backupOperations[$i]
        $percentComplete = [math]::Round(($i / $backupOperations.Count) * 100)

        Write-Progress -Activity "Backing up FSLogix Profile" -Status "Backing up $($operation.Name)..." -PercentComplete $percentComplete

        $scriptPath = Join-Path $scriptDir $operation.Script
        $outputPath = Join-Path $backupDir $operation.Output

        Write-Verbose "Starting backup: $($operation.Name)"
        Write-Host "`n=== Backing up $($operation.Name) ==="

        if (Test-Path $scriptPath) {
            try {
                $params = @{ OutputPath = $outputPath }
                if ($mountedProfile -and $operation.Script -notlike "*BrowserPasswords*") {
                    $params.ProfilePath = $mountedProfile
                }

                & $scriptPath @params
                Write-Verbose "Successfully completed backup: $($operation.Name)"
            }
            catch {
                Write-Warning "Error backing up $($operation.Name): $($_.Exception.Message)"
            }
        } else {
            Write-Warning "$($operation.Name) backup script not found: $scriptPath"
        }
    }

    Write-Progress -Activity "Backing up FSLogix Profile" -Completed

    # Create ZIP archive if requested
    if ($CreateZip) {
        Write-Host "`n=== Creating ZIP Archive ==="
        $zipPath = "$backupDir.zip"

        try {
            if (Test-Path $zipPath) {
                Remove-Item $zipPath -Force
            }

            # Use PowerShell's Compress-Archive
            Compress-Archive -Path $backupDir -DestinationPath $zipPath -CompressionLevel Optimal
            Write-Host "ZIP archive created: $zipPath"

            # Calculate and display backup size
            $backupSize = (Get-ChildItem $backupDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
            $zipSize = (Get-Item $zipPath).Length / 1MB
            Write-Host "Backup directory size: $([math]::Round($backupSize, 2)) MB"
            Write-Host "ZIP archive size: $([math]::Round($zipSize, 2)) MB"
        }
        catch {
            Write-Warning "Failed to create ZIP archive: $($_.Exception.Message)"
            Write-Host "Backup files are available at: $backupDir"
        }
    }

    # Create backup manifest
    $manifestPath = Join-Path $backupDir "BACKUP_MANIFEST.txt"
    $manifest = @"
FSLogix Profile Backup Manifest
===============================

Backup Date: $(Get-Date)
Backup Timestamp: $timestamp
Created By: $env:USERNAME
Computer Name: $env:COMPUTERNAME

Included Backups:
-----------------
- Windows Explorer Quick Access Shortcuts
- Chrome Bookmarks
- Edge Bookmarks
- Display and Scaling Settings
- Taskbar Shortcuts and Settings
- Browser Password Export Instructions

IMPORTANT NOTES:
- Browser passwords require manual export using browser interface
- Registry backups (.reg files) can be restored by double-clicking
- Browser bookmarks can be restored by copying files back to original locations
- Test restoration on a test system first
- Some settings may not restore correctly across different hardware/OS versions

For restoration instructions, see the README file in the scripts directory.
"@

    $manifest | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-Host "`nBackup manifest created at: $manifestPath"

    Write-Host "`n========== BACKUP COMPLETED =========="
    Write-Host "Backup location: $backupDir"
    if ($CreateZip) {
        Write-Host "ZIP archive: $zipPath"
    }
    Write-Host "`nRemember to manually export browser passwords as instructed in the password backup folder."

}
catch {
    Write-Error "Error during backup process: $($_.Exception.Message)"
    Write-Host "Partial backup may exist at: $backupDir"
}
finally {
    # Unmount FSLogix profile if it was mounted
    if ($mountedProfile -and $FSLogixProfile) {
        Write-Host "`n=== Unmounting FSLogix Profile ==="
        try {
            $disk = Get-Disk | Where-Object { $_.Location -eq $FSLogixProfile }
            if ($disk) {
                Dismount-DiskImage -ImagePath $FSLogixProfile
                Write-Host "FSLogix profile unmounted successfully"
            }
        }
        catch {
            Write-Warning "Failed to unmount FSLogix profile: $($_.Exception.Message)"
        }
    }
}
