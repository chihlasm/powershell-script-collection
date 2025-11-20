<#
.SYNOPSIS
    Comprehensive storage cleanup script for Citrix VDA servers with FSLogix.

.DESCRIPTION
    This script safely reclaims storage space on Citrix VDA servers by cleaning:
    - FSLogix ghost/orphaned profiles
    - Windows temp files and caches
    - User temp directories
    - Windows Update cleanup
    - IIS logs (if present)
    - Citrix-specific caches
    - Old Windows profiles
    - Browser caches
    - Font cache
    - Recycle bins

.PARAMETER WhatIf
    Shows what would be deleted without actually deleting.

.PARAMETER LogPath
    Path for the cleanup log file. Defaults to C:\Logs\StorageCleanup.

.PARAMETER DaysOld
    Age threshold in days for temp file cleanup. Default is 7 days.

.PARAMETER SkipFSLogixCleanup
    Skip FSLogix ghost profile cleanup.

.EXAMPLE
    .\Cleanup-CitrixVDAStorage.ps1

.EXAMPLE
    .\Cleanup-CitrixVDAStorage.ps1 -WhatIf

.EXAMPLE
    .\Cleanup-CitrixVDAStorage.ps1 -DaysOld 14 -LogPath "D:\Logs"

.NOTES
    Author: Generated for Citrix VDA Storage Cleanup
    Requires: Run as Administrator
    Warning: Always test in non-production first
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$LogPath = "C:\Logs\StorageCleanup",
    [int]$DaysOld = 7,
    [switch]$SkipFSLogixCleanup
)

#Requires -RunAsAdministrator

# Initialize variables
$script:TotalSpaceReclaimed = 0
$script:ErrorCount = 0
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogPath "StorageCleanup_$Timestamp.log"

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    switch ($Level) {
        'ERROR'   { Write-Host $LogMessage -ForegroundColor Red }
        'WARNING' { Write-Host $LogMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $LogMessage -ForegroundColor Green }
        default   { Write-Host $LogMessage }
    }

    Add-Content -Path $LogFile -Value $LogMessage
}

function Get-FolderSize {
    param([string]$Path)

    if (Test-Path $Path) {
        try {
            $Size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            return [math]::Round($Size / 1MB, 2)
        }
        catch {
            return 0
        }
    }
    return 0
}

function Remove-ItemSafely {
    param(
        [string]$Path,
        [switch]$Recurse
    )

    if (Test-Path $Path) {
        try {
            $SizeBefore = Get-FolderSize -Path $Path

            if ($PSCmdlet.ShouldProcess($Path, "Delete")) {
                if ($Recurse) {
                    Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                }
                else {
                    Remove-Item -Path $Path -Force -ErrorAction Stop
                }
                $script:TotalSpaceReclaimed += $SizeBefore
                Write-Log "Removed: $Path (${SizeBefore}MB)" -Level SUCCESS
            }
            else {
                Write-Log "Would remove: $Path (${SizeBefore}MB)" -Level INFO
            }
        }
        catch {
            Write-Log "Failed to remove $Path`: $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
}

function Get-ActiveUserSessions {
    # Get currently logged in users to avoid cleaning their profiles
    try {
        $Sessions = query user 2>$null | Select-Object -Skip 1
        $ActiveUsers = @()

        foreach ($Session in $Sessions) {
            if ($Session -match '^\s*(\S+)') {
                $ActiveUsers += $Matches[1]
            }
        }

        return $ActiveUsers
    }
    catch {
        return @()
    }
}

function Get-FSLogixGhostProfiles {
    Write-Log "Scanning for FSLogix ghost profiles..." -Level INFO

    $GhostProfiles = @()
    $ActiveUsers = Get-ActiveUserSessions
    $ProfilesPath = "C:\Users"

    # Get all user profile folders
    $UserFolders = Get-ChildItem -Path $ProfilesPath -Directory -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }

    foreach ($Folder in $UserFolders) {
        $ProfilePath = $Folder.FullName
        $Username = $Folder.Name

        # Skip active users
        if ($ActiveUsers -contains $Username) {
            Write-Log "Skipping active user: $Username" -Level INFO
            continue
        }

        # Check for FSLogix indicators
        $IsFSLogixProfile = $false
        $IsGhost = $false

        # FSLogix local profile markers
        $FSLogixMarkers = @(
            (Join-Path $ProfilePath "AppData\Local\FSLogix"),
            (Join-Path $ProfilePath ".fslogix")
        )

        foreach ($Marker in $FSLogixMarkers) {
            if (Test-Path $Marker) {
                $IsFSLogixProfile = $true
                break
            }
        }

        # Check if profile is orphaned (no corresponding user in AD or local)
        if ($IsFSLogixProfile) {
            try {
                $UserExists = $false

                # Check local users
                $LocalUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
                if ($LocalUser) {
                    $UserExists = $true
                }

                # Check AD users (if domain joined)
                if (-not $UserExists) {
                    try {
                        $ADUser = ([adsisearcher]"(samaccountname=$Username)").FindOne()
                        if ($ADUser) {
                            $UserExists = $true
                        }
                    }
                    catch {
                        # Not domain joined or AD not available
                    }
                }

                # Check registry for profile
                $ProfileList = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue
                $RegisteredProfile = $false

                foreach ($Profile in $ProfileList) {
                    $ProfileImagePath = (Get-ItemProperty $Profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
                    if ($ProfileImagePath -eq $ProfilePath) {
                        $RegisteredProfile = $true
                        break
                    }
                }

                # Profile is ghost if it's an FSLogix profile and either user doesn't exist or not registered
                if (-not $RegisteredProfile -or -not $UserExists) {
                    $IsGhost = $true
                }

                # Also check for profiles that haven't been accessed in a long time
                $LastAccess = (Get-Item $ProfilePath -ErrorAction SilentlyContinue).LastAccessTime
                if ($LastAccess -lt (Get-Date).AddDays(-30)) {
                    $IsGhost = $true
                }
            }
            catch {
                Write-Log "Error checking profile $Username`: $($_.Exception.Message)" -Level WARNING
            }
        }

        if ($IsGhost) {
            $Size = Get-FolderSize -Path $ProfilePath
            $GhostProfiles += [PSCustomObject]@{
                Path = $ProfilePath
                Username = $Username
                SizeMB = $Size
                LastAccess = (Get-Item $ProfilePath -ErrorAction SilentlyContinue).LastAccessTime
            }
        }
    }

    return $GhostProfiles
}

function Clear-FSLogixGhostProfiles {
    if ($SkipFSLogixCleanup) {
        Write-Log "Skipping FSLogix ghost profile cleanup (disabled by parameter)" -Level INFO
        return
    }

    Write-Log "=== FSLogix Ghost Profile Cleanup ===" -Level INFO

    $GhostProfiles = Get-FSLogixGhostProfiles

    if ($GhostProfiles.Count -eq 0) {
        Write-Log "No FSLogix ghost profiles found" -Level INFO
        return
    }

    Write-Log "Found $($GhostProfiles.Count) ghost profile(s)" -Level WARNING

    foreach ($Profile in $GhostProfiles) {
        Write-Log "Ghost profile: $($Profile.Username) - $($Profile.SizeMB)MB - Last Access: $($Profile.LastAccess)" -Level INFO
        Remove-ItemSafely -Path $Profile.Path -Recurse
    }
}

function Clear-WindowsTempFiles {
    Write-Log "=== Windows Temp Files Cleanup ===" -Level INFO

    $TempLocations = @(
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Logs\CBS",
        "$env:SystemRoot\SoftwareDistribution\Download",
        "$env:SystemRoot\Prefetch",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue",
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
    )

    foreach ($Location in $TempLocations) {
        if (Test-Path $Location) {
            $Files = Get-ChildItem -Path $Location -Recurse -Force -ErrorAction SilentlyContinue |
                     Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-$DaysOld) }

            foreach ($File in $Files) {
                Remove-ItemSafely -Path $File.FullName
            }
        }
    }
}

function Clear-UserTempDirectories {
    Write-Log "=== User Temp Directories Cleanup ===" -Level INFO

    $ActiveUsers = Get-ActiveUserSessions
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }

    foreach ($Profile in $UserProfiles) {
        # Skip active user sessions
        if ($ActiveUsers -contains $Profile.Name) {
            Write-Log "Skipping active user temp: $($Profile.Name)" -Level INFO
            continue
        }

        $TempPaths = @(
            (Join-Path $Profile.FullName "AppData\Local\Temp"),
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Windows\INetCache"),
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Windows\Temporary Internet Files"),
            (Join-Path $Profile.FullName "AppData\Local\CrashDumps"),
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Terminal Server Client\Cache")
        )

        foreach ($TempPath in $TempPaths) {
            if (Test-Path $TempPath) {
                $Files = Get-ChildItem -Path $TempPath -Recurse -Force -ErrorAction SilentlyContinue |
                         Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-$DaysOld) }

                foreach ($File in $Files) {
                    Remove-ItemSafely -Path $File.FullName
                }
            }
        }
    }
}

function Clear-BrowserCaches {
    Write-Log "=== Browser Cache Cleanup ===" -Level INFO

    $ActiveUsers = Get-ActiveUserSessions
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }

    foreach ($Profile in $UserProfiles) {
        if ($ActiveUsers -contains $Profile.Name) {
            continue
        }

        $BrowserCaches = @(
            # Chrome
            (Join-Path $Profile.FullName "AppData\Local\Google\Chrome\User Data\Default\Cache"),
            (Join-Path $Profile.FullName "AppData\Local\Google\Chrome\User Data\Default\Code Cache"),
            (Join-Path $Profile.FullName "AppData\Local\Google\Chrome\User Data\Default\GPUCache"),
            # Edge
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Cache"),
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\Code Cache"),
            (Join-Path $Profile.FullName "AppData\Local\Microsoft\Edge\User Data\Default\GPUCache"),
            # Firefox
            (Join-Path $Profile.FullName "AppData\Local\Mozilla\Firefox\Profiles\*\cache2")
        )

        foreach ($CachePath in $BrowserCaches) {
            $ExpandedPaths = Resolve-Path $CachePath -ErrorAction SilentlyContinue
            foreach ($Path in $ExpandedPaths) {
                if (Test-Path $Path) {
                    $Files = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                             Where-Object { -not $_.PSIsContainer }

                    foreach ($File in $Files) {
                        Remove-ItemSafely -Path $File.FullName
                    }
                }
            }
        }
    }
}

function Clear-CitrixCaches {
    Write-Log "=== Citrix Cache Cleanup ===" -Level INFO

    $CitrixLocations = @(
        "C:\ProgramData\Citrix\GroupPolicy\History",
        "C:\ProgramData\Citrix\MachineIdentityServiceAgent\Logs",
        "C:\ProgramData\CitrixCseCache"
    )

    # Per-user Citrix caches
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' }

    foreach ($Profile in $UserProfiles) {
        $CitrixLocations += Join-Path $Profile.FullName "AppData\Local\Citrix\SelfService\Icons"
        $CitrixLocations += Join-Path $Profile.FullName "AppData\Local\Citrix\SelfService\Cache"
    }

    foreach ($Location in $CitrixLocations) {
        if (Test-Path $Location) {
            $Files = Get-ChildItem -Path $Location -Recurse -Force -ErrorAction SilentlyContinue |
                     Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-$DaysOld) }

            foreach ($File in $Files) {
                Remove-ItemSafely -Path $File.FullName
            }
        }
    }
}

function Clear-WindowsUpdateCleanup {
    Write-Log "=== Windows Update Cleanup ===" -Level INFO

    # Run Disk Cleanup for Windows Update files
    if ($PSCmdlet.ShouldProcess("Windows Update Cleanup", "Run Disk Cleanup")) {
        try {
            # Set up cleanup flags in registry
            $VolumeCachesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

            $CleanupKeys = @(
                "Update Cleanup",
                "Windows Update Cleanup",
                "Temporary Setup Files",
                "Previous Installations",
                "Service Pack Cleanup"
            )

            foreach ($Key in $CleanupKeys) {
                $KeyPath = Join-Path $VolumeCachesPath $Key
                if (Test-Path $KeyPath) {
                    Set-ItemProperty -Path $KeyPath -Name StateFlags0001 -Value 2 -ErrorAction SilentlyContinue
                }
            }

            # Run cleanmgr
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction SilentlyContinue
            Write-Log "Windows Update cleanup completed" -Level SUCCESS
        }
        catch {
            Write-Log "Windows Update cleanup failed: $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
}

function Clear-IISLogs {
    Write-Log "=== IIS Logs Cleanup ===" -Level INFO

    $IISLogPath = "C:\inetpub\logs\LogFiles"

    if (Test-Path $IISLogPath) {
        $LogFiles = Get-ChildItem -Path $IISLogPath -Recurse -Include "*.log" -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$DaysOld) }

        foreach ($LogFile in $LogFiles) {
            Remove-ItemSafely -Path $LogFile.FullName
        }
    }
    else {
        Write-Log "IIS logs directory not found (IIS may not be installed)" -Level INFO
    }
}

function Clear-EventLogs {
    Write-Log "=== Event Log Cleanup ===" -Level INFO

    if ($PSCmdlet.ShouldProcess("Event Logs", "Clear old entries")) {
        try {
            # Clear logs that are commonly large and less critical
            $LogsToClear = @(
                "Microsoft-Windows-TWinUI/Operational",
                "Microsoft-Windows-AppxDeploymentServer/Operational"
            )

            foreach ($LogName in $LogsToClear) {
                try {
                    wevtutil cl $LogName 2>$null
                    Write-Log "Cleared event log: $LogName" -Level SUCCESS
                }
                catch {
                    # Log may not exist, skip
                }
            }
        }
        catch {
            Write-Log "Event log cleanup failed: $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
}

function Clear-FontCache {
    Write-Log "=== Font Cache Cleanup ===" -Level INFO

    $FontCachePath = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\FontCache"

    if (Test-Path $FontCachePath) {
        $CacheFiles = Get-ChildItem -Path $FontCachePath -Force -ErrorAction SilentlyContinue |
                      Where-Object { -not $_.PSIsContainer }

        foreach ($File in $CacheFiles) {
            Remove-ItemSafely -Path $File.FullName
        }
    }
}

function Clear-RecycleBins {
    Write-Log "=== Recycle Bin Cleanup ===" -Level INFO

    if ($PSCmdlet.ShouldProcess("All Recycle Bins", "Empty")) {
        try {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
            Write-Log "Recycle bins cleared" -Level SUCCESS
        }
        catch {
            Write-Log "Recycle bin cleanup failed: $($_.Exception.Message)" -Level ERROR
            $script:ErrorCount++
        }
    }
}

function Clear-OldWindowsInstallations {
    Write-Log "=== Old Windows Installations Cleanup ===" -Level INFO

    $OldWindowsLocations = @(
        "C:\Windows.old",
        "C:\$Windows.~BT",
        "C:\$Windows.~WS"
    )

    foreach ($Location in $OldWindowsLocations) {
        if (Test-Path $Location) {
            Remove-ItemSafely -Path $Location -Recurse
        }
    }
}

function Clear-MSICache {
    Write-Log "=== MSI Installer Cache Cleanup ===" -Level INFO

    $MSICachePath = "$env:SystemRoot\Installer\$PatchCache$"

    if (Test-Path $MSICachePath) {
        $OldFiles = Get-ChildItem -Path $MSICachePath -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-90) }

        foreach ($File in $OldFiles) {
            Remove-ItemSafely -Path $File.FullName
        }
    }
}

function Clear-MemoryDumps {
    Write-Log "=== Memory Dump Cleanup ===" -Level INFO

    $DumpLocations = @(
        "$env:SystemRoot\MEMORY.DMP",
        "$env:SystemRoot\Minidump"
    )

    foreach ($Location in $DumpLocations) {
        if (Test-Path $Location) {
            if ((Get-Item $Location -ErrorAction SilentlyContinue).PSIsContainer) {
                $DumpFiles = Get-ChildItem -Path $Location -Force -ErrorAction SilentlyContinue
                foreach ($Dump in $DumpFiles) {
                    Remove-ItemSafely -Path $Dump.FullName
                }
            }
            else {
                Remove-ItemSafely -Path $Location
            }
        }
    }
}

function Get-DiskSpaceReport {
    Write-Log "=== Disk Space Report ===" -Level INFO

    $Drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,
        @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}},
        @{Name="FreeSpaceGB";Expression={[math]::Round($_.FreeSpace/1GB,2)}},
        @{Name="PercentFree";Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}

    foreach ($Drive in $Drives) {
        Write-Log "$($Drive.DeviceID) - Total: $($Drive.SizeGB)GB, Free: $($Drive.FreeSpaceGB)GB ($($Drive.PercentFree)%)" -Level INFO
    }
}

# Main execution
Write-Log "========================================" -Level INFO
Write-Log "Citrix VDA Storage Cleanup Script Started" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Parameters: DaysOld=$DaysOld, WhatIf=$WhatIfPreference" -Level INFO

# Get initial disk space
Write-Log "Initial Disk Space:" -Level INFO
Get-DiskSpaceReport

# Run all cleanup functions
Clear-FSLogixGhostProfiles
Clear-WindowsTempFiles
Clear-UserTempDirectories
Clear-BrowserCaches
Clear-CitrixCaches
Clear-IISLogs
Clear-EventLogs
Clear-FontCache
Clear-MemoryDumps
Clear-OldWindowsInstallations
Clear-MSICache
Clear-RecycleBins
Clear-WindowsUpdateCleanup

# Final report
Write-Log "========================================" -Level INFO
Write-Log "Cleanup Complete" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Total Space Reclaimed: $($script:TotalSpaceReclaimed)MB" -Level SUCCESS
Write-Log "Errors Encountered: $script:ErrorCount" -Level $(if ($script:ErrorCount -gt 0) { 'WARNING' } else { 'INFO' })

Write-Log "Final Disk Space:" -Level INFO
Get-DiskSpaceReport

Write-Log "Log file saved to: $LogFile" -Level INFO
