<#
.SYNOPSIS
    Main script to backup FSLogix profile settings
.DESCRIPTION
    Runs all backup scripts to create a comprehensive backup of user settings.
    Supports both online (current user) and offline (mounted VHD) backup modes.
.PARAMETER BackupPath
    Root path where backups will be stored (default: current directory + 'FSLogixBackups')
.PARAMETER CreateZip
    Whether to create a ZIP archive of the backup (default: true)
.PARAMETER FSLogixProfile
    Path to FSLogix VHD/VHDX file to mount for offline backup
.PARAMETER MountProfile
    Switch to enable mounting of FSLogix profile (requires -FSLogixProfile)
.EXAMPLE
    .\Backup-FSLogixProfile.ps1
    Creates a backup of the current user's profile settings
.EXAMPLE
    .\Backup-FSLogixProfile.ps1 -BackupPath "D:\Backups" -CreateZip
    Creates a backup in a custom location with ZIP archive
.EXAMPLE
    .\Backup-FSLogixProfile.ps1 -MountProfile -FSLogixProfile "\\server\share\user_profile.vhdx"
    Mounts an FSLogix profile and backs up settings from it
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupPath = ".\FSLogixBackups",

    [Parameter(Mandatory = $false)]
    [switch]$CreateZip,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and -not ($_ -match '\.(vhd|vhdx)$')) {
            throw "FSLogixProfile must be a .vhd or .vhdx file"
        }
        return $true
    })]
    [string]$FSLogixProfile,

    [Parameter(Mandatory = $false)]
    [switch]$MountProfile
)

# Script-level variables for tracking
$script:BackupResults = @{}
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

function Test-DiskSpace {
    param(
        [string]$Path,
        [int]$RequiredMB = 100
    )

    try {
        $drive = (Resolve-Path $Path -ErrorAction SilentlyContinue | Split-Path -Qualifier) -replace ':', ''
        if (-not $drive) {
            $drive = (Get-Location).Drive.Name
        }

        $freeSpace = (Get-PSDrive $drive).Free / 1MB
        if ($freeSpace -lt $RequiredMB) {
            Write-Log "Insufficient disk space. Required: ${RequiredMB}MB, Available: $([math]::Round($freeSpace, 2))MB" -Level Error
            return $false
        }
        return $true
    }
    catch {
        Write-Log "Could not check disk space: $($_.Exception.Message)" -Level Warning
        return $true  # Continue anyway
    }
}

function Get-FileChecksum {
    param([string]$FilePath)

    if (Test-Path $FilePath) {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    }
    return $null
}

function Test-LockFile {
    param([string]$LockPath)

    if (Test-Path $LockPath) {
        $lockContent = Get-Content $LockPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($lockContent) {
            $lockTime = [datetime]::Parse($lockContent.StartTime)
            $elapsed = (Get-Date) - $lockTime

            # If lock is older than 1 hour, consider it stale
            if ($elapsed.TotalHours -gt 1) {
                Write-Log "Removing stale lock file (created $([math]::Round($elapsed.TotalMinutes)) minutes ago)" -Level Warning
                Remove-Item $LockPath -Force
                return $false
            }

            Write-Log "Another backup is in progress (started at $($lockContent.StartTime) by $($lockContent.User))" -Level Error
            return $true
        }
    }
    return $false
}

function New-LockFile {
    param([string]$LockPath)

    $lockContent = @{
        StartTime = (Get-Date).ToString("o")
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
        ProcessId = $PID
    } | ConvertTo-Json

    $lockContent | Out-File -FilePath $LockPath -Encoding UTF8
}

#endregion

#region Main Script

# Check administrator privileges and offer credential-based elevation
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$adminCredentials = $null
$useCredentialElevation = $false

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "Administrator privileges may be required for some registry operations." -ForegroundColor Yellow
    $elevateChoice = Read-Host "Do you want to provide admin credentials to run privileged operations? (Y/N)"

    if ($elevateChoice -eq 'Y' -or $elevateChoice -eq 'y') {
        $adminCredentials = Get-Credential -Message "Enter administrator credentials for privileged operations"
        if ($adminCredentials) {
            $useCredentialElevation = $true
            Write-Host "Will run privileged operations with provided credentials." -ForegroundColor Green
        } else {
            Write-Warning "No credentials provided. Some operations may fail."
        }
    } else {
        Write-Host "Running without additional privileges. Some operations may fail." -ForegroundColor Yellow
    }
}

# Validate MountProfile requirements
if ($MountProfile -and -not $FSLogixProfile) {
    Write-Error "FSLogix profile path must be specified when using -MountProfile"
    exit 1
}

if ($MountProfile -and $FSLogixProfile -and -not (Test-Path $FSLogixProfile)) {
    Write-Error "FSLogix profile file not found: $FSLogixProfile"
    exit 1
}

# Resolve and validate backup path
try {
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    $BackupPath = (Resolve-Path $BackupPath).Path
}
catch {
    Write-Error "Cannot create or access backup path: $BackupPath - $($_.Exception.Message)"
    exit 1
}

# Check for concurrent execution
$lockFile = Join-Path $BackupPath ".backup.lock"
if (Test-LockFile -LockPath $lockFile) {
    exit 1
}

# Check disk space
if (-not (Test-DiskSpace -Path $BackupPath -RequiredMB 100)) {
    exit 1
}

# Create timestamped backup directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $BackupPath "Backup_$timestamp"

try {
    # Create lock file
    New-LockFile -LockPath $lockFile

    # Create backup directory
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    # Initialize log file
    $script:LogPath = Join-Path $backupDir "backup.log"

    Write-Log "========== FSLogix Profile Backup Started ==========" -Level Info
    Write-Log "Backup directory: $backupDir" -Level Info
    Write-Log "Create ZIP archive: $CreateZip" -Level Info
    Write-Log "Running as administrator: $isAdmin" -Level Info

    if ($MountProfile) {
        Write-Log "FSLogix profile mounting enabled" -Level Info
        Write-Log "Profile to mount: $FSLogixProfile" -Level Info
    }

    # Mount FSLogix profile if requested
    $mountedProfile = $null
    $mountedDriveLetter = $null

    if ($MountProfile -and $FSLogixProfile) {
        Write-Log "=== Mounting FSLogix Profile ===" -Level Info
        try {
            # Mount the VHD/VHDX file
            $mountResult = Mount-DiskImage -ImagePath $FSLogixProfile -PassThru -ErrorAction Stop
            Write-Log "Disk image mounted successfully" -Level Success

            # Wait briefly for the mount to complete
            Start-Sleep -Milliseconds 500

            # Find the mounted drive letter
            $diskImage = Get-DiskImage -ImagePath $FSLogixProfile
            $disk = Get-Disk | Where-Object { $_.Number -eq $diskImage.Number }

            if ($disk) {
                $partition = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter }
                $mountedDriveLetter = $partition.DriveLetter
            }

            if ($mountedDriveLetter) {
                $mountedProfile = "${mountedDriveLetter}:"
                Write-Log "FSLogix profile mounted at: $mountedProfile" -Level Success

                # Check for FSLogix profile structure variants
                $profilePaths = @(
                    (Join-Path $mountedProfile "Profile"),
                    (Join-Path $mountedProfile "UVHD-Profile"),
                    $mountedProfile
                )

                foreach ($testPath in $profilePaths) {
                    $ntUserPath = Join-Path $testPath "NTUSER.DAT"
                    if (Test-Path $ntUserPath) {
                        $mountedProfile = $testPath
                        Write-Log "FSLogix profile structure detected. Using path: $mountedProfile" -Level Success
                        break
                    }
                }
            } else {
                throw "Unable to determine mounted drive letter"
            }
        }
        catch {
            Write-Log "Failed to mount FSLogix profile: $($_.Exception.Message)" -Level Error
            throw
        }
    }

    # Define backup operations with progress tracking
    $backupOperations = @(
        @{
            Name = "Quick Access Shortcuts"
            Script = "Backup-QuickAccessShortcuts.ps1"
            Output = "QuickAccessBackup.reg"
            Type = "Registry"
        },
        @{
            Name = "Chrome Bookmarks"
            Script = "Backup-ChromeBookmarks.ps1"
            Output = "ChromeBookmarks.bak"
            Type = "File"
        },
        @{
            Name = "Edge Bookmarks"
            Script = "Backup-EdgeBookmarks.ps1"
            Output = "EdgeBookmarks.bak"
            Type = "File"
        },
        @{
            Name = "Display Settings"
            Script = "Backup-DisplaySettings.ps1"
            Output = "DisplaySettingsBackup.reg"
            Type = "Registry"
        },
        @{
            Name = "Taskbar Settings"
            Script = "Backup-TaskbarSettings.ps1"
            Output = "TaskbarSettingsBackup.reg"
            Type = "Registry"
        },
        @{
            Name = "Browser Password Instructions"
            Script = "Backup-BrowserPasswords.ps1"
            Output = "BrowserPasswords"
            Type = "Instructions"
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

        Write-Log "=== Backing up $($operation.Name) ===" -Level Info

        if (Test-Path $scriptPath) {
            try {
                $params = @{ OutputPath = $outputPath }

                # Pass ProfilePath for file-based backups when mounting
                if ($mountedProfile -and $operation.Type -eq "File") {
                    $params.ProfilePath = $mountedProfile
                }

                # For registry backups with mounted profile, pass the NTUSER.DAT path
                if ($mountedProfile -and $operation.Type -eq "Registry") {
                    $ntUserPath = Join-Path $mountedProfile "NTUSER.DAT"
                    if (Test-Path $ntUserPath) {
                        $params.NTUserPath = $ntUserPath
                    }
                }

                # Check if this is a registry-based script that may need elevation
                $privilegedScripts = @("Backup-QuickAccessShortcuts.ps1", "Backup-DisplaySettings.ps1", "Backup-TaskbarSettings.ps1")
                $isPrivileged = $privilegedScripts -contains $operation.Script

                if ($useCredentialElevation -and $isPrivileged -and $adminCredentials) {
                    Write-Log "Running $($operation.Script) with admin credentials" -Level Info
                    try {
                        # Build the argument string
                        $argString = "& '$scriptPath'"
                        foreach ($param in $params.GetEnumerator()) {
                            $argString += " -$($param.Key) '$($param.Value)'"
                        }

                        # Run script with admin credentials
                        $scriptBlock = [scriptblock]::Create($argString)
                        Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $adminCredentials -ScriptBlock $scriptBlock -ErrorAction Stop

                        $script:BackupResults[$operation.Name] = @{
                            Status = "Success"
                            Output = $outputPath
                            Elevated = $true
                        }
                    }
                    catch {
                        Write-Log "Elevated execution failed for $($operation.Name): $($_.Exception.Message)" -Level Warning
                        Write-Log "Falling back to regular execution..." -Level Info
                        & $scriptPath @params

                        $script:BackupResults[$operation.Name] = @{
                            Status = "Success"
                            Output = $outputPath
                            Elevated = $false
                        }
                    }
                } else {
                    # Run script normally
                    & $scriptPath @params

                    $script:BackupResults[$operation.Name] = @{
                        Status = "Success"
                        Output = $outputPath
                        Elevated = $false
                    }
                }

                # Verify backup was created and calculate checksum
                if ($operation.Type -ne "Instructions") {
                    if (Test-Path $outputPath) {
                        $checksum = Get-FileChecksum -FilePath $outputPath
                        $script:BackupResults[$operation.Name].Checksum = $checksum
                        $script:BackupResults[$operation.Name].Size = (Get-Item $outputPath).Length
                        Write-Log "$($operation.Name) backed up successfully" -Level Success
                    } else {
                        $script:BackupResults[$operation.Name].Status = "Warning"
                        $script:BackupResults[$operation.Name].Message = "Output file not created"
                        Write-Log "$($operation.Name) - output file not created" -Level Warning
                    }
                } else {
                    Write-Log "$($operation.Name) completed" -Level Success
                }
            }
            catch {
                $script:BackupResults[$operation.Name] = @{
                    Status = "Failed"
                    Error = $_.Exception.Message
                }
                Write-Log "Error backing up $($operation.Name): $($_.Exception.Message)" -Level Error
            }
        } else {
            $script:BackupResults[$operation.Name] = @{
                Status = "Skipped"
                Message = "Script not found"
            }
            Write-Log "$($operation.Name) backup script not found: $scriptPath" -Level Warning
        }
    }

    Write-Progress -Activity "Backing up FSLogix Profile" -Completed

    # Create backup manifest with actual results
    $manifestPath = Join-Path $backupDir "BACKUP_MANIFEST.json"
    $manifest = @{
        BackupInfo = @{
            Timestamp = $timestamp
            Date = (Get-Date).ToString("o")
            CreatedBy = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            IsAdmin = $isAdmin
            MountedProfile = if ($mountedProfile) { $FSLogixProfile } else { $null }
        }
        Results = $script:BackupResults
        Notes = @(
            "Browser passwords require manual export using browser interface",
            "Registry backups (.reg files) can be restored by double-clicking",
            "Browser bookmarks can be restored by copying files back to original locations",
            "Test restoration on a test system first",
            "Some settings may not restore correctly across different hardware/OS versions"
        )
    }

    $manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-Log "Backup manifest created at: $manifestPath" -Level Info

    # Also create human-readable manifest
    $readableManifestPath = Join-Path $backupDir "BACKUP_MANIFEST.txt"
    $manifestLines = @()
    $manifestLines += "FSLogix Profile Backup Manifest"
    $manifestLines += "==============================="
    $manifestLines += ""
    $manifestLines += "Backup Date: $(Get-Date)"
    $manifestLines += "Backup Timestamp: $timestamp"
    $manifestLines += "Created By: $env:USERNAME"
    $manifestLines += "Computer Name: $env:COMPUTERNAME"
    $manifestLines += "Administrator: $isAdmin"
    if ($mountedProfile) {
        $manifestLines += "Source Profile: $FSLogixProfile"
    }
    $manifestLines += ""
    $manifestLines += "Backup Results:"
    $manifestLines += "---------------"

    foreach ($result in $script:BackupResults.GetEnumerator()) {
        $status = $result.Value.Status
        $icon = switch ($status) {
            "Success" { "[OK]" }
            "Warning" { "[!]" }
            "Failed"  { "[X]" }
            "Skipped" { "[-]" }
            default   { "[?]" }
        }
        $manifestLines += "$icon $($result.Key): $status"
        if ($result.Value.Size) {
            $manifestLines += "    Size: $($result.Value.Size) bytes"
        }
        if ($result.Value.Checksum) {
            $manifestLines += "    SHA256: $($result.Value.Checksum)"
        }
        if ($result.Value.Message) {
            $manifestLines += "    Note: $($result.Value.Message)"
        }
        if ($result.Value.Error) {
            $manifestLines += "    Error: $($result.Value.Error)"
        }
    }

    $manifestLines += ""
    $manifestLines += "IMPORTANT NOTES:"
    $manifestLines += "- Browser passwords require manual export using browser interface"
    $manifestLines += "- Registry backups (.reg files) can be restored by double-clicking"
    $manifestLines += "- Browser bookmarks can be restored by copying files back to original locations"
    $manifestLines += "- Test restoration on a test system first"
    $manifestLines += "- Some settings may not restore correctly across different hardware/OS versions"
    $manifestLines += ""
    $manifestLines += "For restoration, use: Restore-FSLogixProfile.ps1 -BackupPath `"$backupDir`""

    $manifestLines -join "`n" | Out-File -FilePath $readableManifestPath -Encoding UTF8

    # Create ZIP archive if requested
    if ($CreateZip) {
        Write-Log "=== Creating ZIP Archive ===" -Level Info
        $zipPath = "$backupDir.zip"

        try {
            if (Test-Path $zipPath) {
                Remove-Item $zipPath -Force
            }

            # Use PowerShell's Compress-Archive
            Compress-Archive -Path $backupDir -DestinationPath $zipPath -CompressionLevel Optimal
            Write-Log "ZIP archive created: $zipPath" -Level Success

            # Calculate and display backup size
            $backupSize = (Get-ChildItem $backupDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
            $zipSize = (Get-Item $zipPath).Length / 1MB
            Write-Log "Backup directory size: $([math]::Round($backupSize, 2)) MB" -Level Info
            Write-Log "ZIP archive size: $([math]::Round($zipSize, 2)) MB" -Level Info
        }
        catch {
            Write-Log "Failed to create ZIP archive: $($_.Exception.Message)" -Level Error
            Write-Log "Backup files are available at: $backupDir" -Level Info
        }
    }

    # Summary
    $successCount = ($script:BackupResults.Values | Where-Object { $_.Status -eq "Success" }).Count
    $warningCount = ($script:BackupResults.Values | Where-Object { $_.Status -eq "Warning" }).Count
    $failedCount = ($script:BackupResults.Values | Where-Object { $_.Status -eq "Failed" }).Count

    Write-Log "" -Level Info
    Write-Log "========== BACKUP COMPLETED ==========" -Level Success
    Write-Log "Location: $backupDir" -Level Info
    if ($CreateZip) {
        Write-Log "ZIP archive: $zipPath" -Level Info
    }
    Write-Log "Results: $successCount succeeded, $warningCount warnings, $failedCount failed" -Level Info
    Write-Log "" -Level Info
    Write-Log "Remember to manually export browser passwords as instructed in the BrowserPasswords folder." -Level Warning
}
catch {
    Write-Log "Error during backup process: $($_.Exception.Message)" -Level Error
    Write-Host "Partial backup may exist at: $backupDir"
    throw
}
finally {
    # Unmount FSLogix profile if it was mounted
    if ($FSLogixProfile -and $MountProfile) {
        Write-Log "=== Unmounting FSLogix Profile ===" -Level Info
        try {
            $diskImage = Get-DiskImage -ImagePath $FSLogixProfile -ErrorAction SilentlyContinue
            if ($diskImage -and $diskImage.Attached) {
                Dismount-DiskImage -ImagePath $FSLogixProfile -ErrorAction Stop
                Write-Log "FSLogix profile unmounted successfully" -Level Success
            }
        }
        catch {
            Write-Log "Failed to unmount FSLogix profile: $($_.Exception.Message)" -Level Warning
        }
    }

    # Remove lock file
    if (Test-Path $lockFile) {
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    }
}

#endregion
