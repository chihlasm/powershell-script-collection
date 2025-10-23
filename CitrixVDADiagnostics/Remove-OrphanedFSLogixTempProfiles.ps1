# Remove-OrphanedFSLogixTempProfiles.ps1
# Removes temporary user profiles that were created for FSLogix failures when users are no longer logged in

param(
    [switch]$WhatIf,
    [switch]$Force,
    [switch]$Verbose,
    [string]$LogPath = ""
)

# Function to get active user sessions
function Get-ActiveUserSessions {
    try {
        # Get active sessions using query session
        $sessions = query session 2>$null | Where-Object { $_ -match '\sActive\s' } | ForEach-Object {
            $parts = $_ -split '\s+'
            [PSCustomObject]@{
                UserName = $parts[1]
                SessionName = $parts[0]
                State = 'Active'
            }
        }

        # Also check for disconnected sessions that might still be using profiles
        $disconnectedSessions = query session 2>$null | Where-Object { $_ -match '\sDisc\s' } | ForEach-Object {
            $parts = $_ -split '\s+'
            [PSCustomObject]@{
                UserName = $parts[1]
                SessionName = $parts[0]
                State = 'Disconnected'
            }
        }

        # Combine active and disconnected sessions
        $allSessions = $sessions + $disconnectedSessions

        if ($Verbose) {
            Write-Host "Found $($allSessions.Count) active/disconnected sessions:" -ForegroundColor Yellow
            $allSessions | ForEach-Object { Write-Host "  - $($_.UserName) ($($_.State))" }
            Write-Host ""
        }

        return $allSessions
    }
    catch {
        Write-Warning "Could not retrieve active sessions: $_"
        return @()
    }
}

# Function to get user profiles from registry
function Get-UserProfiles {
    try {
        $profiles = @()
        $profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

        if (Test-Path $profileListKey) {
            $profileKeys = Get-ChildItem $profileListKey -ErrorAction SilentlyContinue

            foreach ($profileKey in $profileKeys) {
                $sid = $profileKey.PSChildName

                # Skip system profiles (S-1-5-18, S-1-5-19, S-1-5-20)
                if ($sid -match '^S-1-5-(18|19|20)$') { continue }

                try {
                    $profileData = Get-ItemProperty -Path $profileKey.PSPath -ErrorAction SilentlyContinue

                    if ($profileData) {
                        $isTempProfile = $false
                        $flags = $profileData.Flags

                        if ($flags -ne $null) {
                            # Check TempProfile bit (0x00000001) or special flags for temp profiles
                            $isTempProfile = ($flags -band 0x00000001) -ne 0
                        }

                        # Also check ProfileImagePath for temp profile patterns
                        $profilePath = $profileData.ProfileImagePath
                        if ($profilePath -and ($profilePath -match 'TEMP|\\TEMP\\' -or $profilePath -notmatch '^C:\\Users\\[^\\]+$')) {
                            $isTempProfile = $true
                        }

                        $userName = $null
                        try {
                            $userName = ([System.Security.Principal.SecurityIdentifier]::new($sid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
                        }
                        catch {
                            $userName = "SID-$sid"
                        }

                        $profiles += [PSCustomObject]@{
                            SID = $sid
                            UserName = $userName
                            ProfilePath = $profilePath
                            RegistryPath = $profileKey.PSPath
                            IsTempProfile = $isTempProfile
                            Flags = $flags
                        }
                    }
                }
                catch {
                    Write-Warning "Could not read profile data for SID $sid`: $_"
                }
            }
        }

        return $profiles
    }
    catch {
        Write-Warning "Could not retrieve user profiles: $_"
        return @()
    }
}

# Function to check if user folder exists in C:\Users
function Test-UserFolderExists {
    param([string]$UserName)

    $userFolder = Join-Path $env:USERPROFILE\.. $UserName
    return Test-Path $userFolder
}

# Function to get NTUser.dat modification time as profile last access
function Get-ProfileLastAccess {
    param([string]$ProfilePath)

    if ($ProfilePath -and (Test-Path $ProfilePath)) {
        $ntuserPath = Join-Path $ProfilePath "NTUSER.DAT"
        if (Test-Path $ntuserPath) {
            return (Get-Item $ntuserPath).LastWriteTime
        }
    }

    return $null
}

# Function to safely remove a temporary profile
function Remove-TempProfile {
    param(
        [PSCustomObject]$Profile,
        [switch]$WhatIf,
        [switch]$Verbose
    )

    $userName = $Profile.UserName
    $profilePath = $Profile.ProfilePath

    Write-Host "Processing temporary profile for user: $userName" -ForegroundColor Cyan

    # Remove registry entry
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would remove registry key: $($Profile.RegistryPath)" -ForegroundColor Yellow
    } else {
        try {
            Remove-Item -Path $Profile.RegistryPath -Recurse -Force
            Write-Host "  Removed registry key: $($Profile.RegistryPath)" -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed to remove registry key $($Profile.RegistryPath): $_"
        }
    }

    # Remove user folder if it exists
    if ($profilePath -and (Test-Path $profilePath)) {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would remove user folder: $profilePath" -ForegroundColor Yellow
        } else {
            try {
                # Add recursive and force to ensure complete removal
                Remove-Item -Path $profilePath -Recurse -Force
                Write-Host "  Removed user folder: $profilePath" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to remove user folder $profilePath`: $_"
            }
        }
    } else {
        Write-Host "  User folder not found: $profilePath" -ForegroundColor Blue
    }
}

# Function to log cleanup actions
function Write-LogEntry {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    if ($LogPath) {
        try {
            $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
        }
        catch {
            Write-Warning "Could not write to log file $LogPath`: $_"
        }
    }

    # Also output to console based on level
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { if ($Verbose) { Write-Host $logEntry -ForegroundColor White } }
        default { Write-Host $logEntry }
    }
}

# Function to check FSLogix service status
function Get-FSLogixServiceStatus {
    $services = @('FSLogix Apps Services', 'frxsrv')

    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            return @{
                Name = $svc.Name
                Status = $svc.Status
                Running = ($svc.Status -eq 'Running')
            }
        }
    }

    return @{
        Name = "Not Found"
        Status = "Not Installed"
        Running = $false
    }
}

# Function to check FSLogix logs for recent temp profile events
function Get-FSLogixTempProfileEvents {
    param([int]$LastHours = 24)

    try {
        $fslogixLogPath = "$env:ProgramData\FSLogix\Logs"
        if (Test-Path $fslogixLogPath) {
            $logFiles = Get-ChildItem -Path $fslogixLogPath -Filter "*.log" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-$LastHours) }

            $tempProfileEvents = @()

            foreach ($logFile in $logFiles) {
                $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
                $tempEvents = $content | Where-Object { $_ -match 'temp.*profile|temporary.*profile|fallback.*profile' -or
                                                     $_ -match 'LoadProfile failed|Profile load error' }

                if ($tempEvents) {
                    $tempProfileEvents += [PSCustomObject]@{
                        LogFile = $logFile.Name
                        Events = $tempEvents.Count
                        LastEntry = ($tempEvents | Select-Object -Last 1)
                    }
                }
            }

            return $tempProfileEvents
        }
    }
    catch {
        Write-Warning "Could not check FSLogix logs: $_"
    }

    return @()
}

# Main function
function Remove-OrphanedFSLogixTempProfiles {
    Write-LogEntry "=== FSLogix Temporary Profile Cleanup ==="

    # Check FSLogix service status
    $fslogixStatus = Get-FSLogixServiceStatus
    Write-LogEntry "FSLogix Service Status: $($fslogixStatus.Status)"
    if (-not $fslogixStatus.Running) {
        Write-LogEntry "FSLogix service is not running. Temp profile cleanup may not be necessary." "WARNING"
    }

    # Check for recent FSLogix temp profile events
    $tempEvents = Get-FSLogixTempProfileEvents
    if ($tempEvents) {
        Write-LogEntry "Recent FSLogix temp profile events found:"
        $tempEvents | ForEach-Object {
            Write-LogEntry "  $($_.LogFile): $($_.Events) events"
        }
    }

    # Get active sessions
    $activeSessions = Get-ActiveUserSessions
    $activeUserNames = $activeSessions | Select-Object -ExpandProperty UserName -Unique

    # Get all user profiles
    $userProfiles = Get-UserProfiles

    if (-not $userProfiles) {
        Write-LogEntry "No user profiles found in registry." "WARNING"
        return
    }

    Write-LogEntry "Found $($userProfiles.Count) user profiles in registry."

    # Find temporary profiles that belong to users not currently logged in
    $orphanedTempProfiles = @()

    foreach ($profile in $userProfiles) {
        # Only process temporary profiles
        if ($profile.IsTempProfile) {
            $isUserActive = $activeUserNames -contains $profile.UserName
            $folderExists = Test-UserFolderExists -Profile $profile.ProfilePath

            if (-not $isUserActive) {
                $lastAccess = Get-ProfileLastAccess -Profile $profile.ProfilePath
                $age = if ($lastAccess) { (Get-Date) - $lastAccess } else { $null }

                $orphanedTempProfiles += $profile | Add-Member -MemberType NoteProperty -Name 'LastAccess' -Value $lastAccess -PassThru |
                                          Add-Member -MemberType NoteProperty -Name 'Age' -Value $age -PassThru |
                                          Add-Member -MemberType NoteProperty -Name 'FolderExists' -Value $folderExists -PassThru
            }
        }
    }

    Write-LogEntry "Found $($orphanedTempProfiles.Count) orphaned temporary profiles."

    if ($orphanedTempProfiles.Count -eq 0) {
        Write-LogEntry "No orphaned temporary profiles to clean up."
        return
    }

    # Display orphaned profiles
    Write-Host "`nOrphaned Temporary Profiles Found:" -ForegroundColor Yellow
    Write-Host ("=" * 80)

    $orphanedTempProfiles | ForEach-Object {
        $ageString = if ($_.Age) { "{0:dd} days {0:hh}:{0:mm} hours old" -f $_.Age } else { "Unknown age" }
        Write-Host "User: $($_.UserName)" -ForegroundColor Red
        Write-Host "  SID: $($_.SID)"
        Write-Host "  Profile Path: $($_.ProfilePath)"
        Write-Host "  Age: $ageString"
        Write-Host "  Folder Exists: $($_.FolderExists)"
        Write-Host ""
    }

    # Ask for confirmation unless -Force is specified
    if (-not $Force -and -not $WhatIf) {
        $response = Read-Host "Remove $($orphanedTempProfiles.Count) orphaned temporary profiles? (Y/N)"
        if ($response -notmatch '^Y(es)?$') {
            Write-LogEntry "Cleanup cancelled by user."
            return
        }
    }

    # Remove orphaned profiles
    $removedCount = 0
    foreach ($profile in $orphanedTempProfiles) {
        try {
            Remove-TempProfile -Profile $profile -WhatIf:$WhatIf -Verbose:$Verbose
            $removedCount++
            Write-LogEntry "Successfully processed temp profile for user: $($profile.UserName)"
        }
        catch {
            Write-LogEntry "Failed to process temp profile for user $($profile.UserName): $_" "ERROR"
        }
    }

    if ($WhatIf) {
        Write-LogEntry "[WHATIF] Would have processed $removedCount orphaned temporary profiles."
    } else {
        Write-LogEntry "Successfully processed $removedCount orphaned temporary profiles."
    }

    Write-LogEntry "=== Cleanup Complete ==="
}

# Execute the cleanup
Remove-OrphanedFSLogixTempProfiles
