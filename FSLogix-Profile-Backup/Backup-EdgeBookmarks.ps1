<#
.SYNOPSIS
    Backs up Microsoft Edge bookmarks
.DESCRIPTION
    Copies Edge's Bookmarks file for backup and restoration.
    Supports multiple Edge profiles and mounted FSLogix profiles.
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\EdgeBookmarks.bak)
.PARAMETER ProfilePath
    Path to mounted profile or Edge user data directory
.PARAMETER ProfileName
    Specific Edge profile name to backup (default: Default, or all profiles if not specified)
.EXAMPLE
    .\Backup-EdgeBookmarks.ps1
    Backs up Edge bookmarks from all profiles found
.EXAMPLE
    .\Backup-EdgeBookmarks.ps1 -ProfileName "Profile 1" -OutputPath "C:\Backup\EdgeBookmarks.bak"
    Backs up bookmarks from a specific Edge profile
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\EdgeBookmarks.bak",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName
)

Write-Verbose "Starting Edge bookmarks backup..."

try {
    # Determine Edge bookmarks location
    $edgeUserDataPath = if ($ProfilePath) {
        # Use mounted profile path or custom path
        Join-Path $ProfilePath "AppData\Local\Microsoft\Edge\User Data"
    } else {
        # Use current user's default location
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    }

    Write-Verbose "Edge user data path: $edgeUserDataPath"

    if (-not (Test-Path $edgeUserDataPath)) {
        Write-Warning "Edge user data directory not found: $edgeUserDataPath"
        Write-Warning "Edge may not be installed or no profiles exist"
        return
    }

    # Check if Edge is running (for current user backup)
    if (-not $ProfilePath) {
        $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
        if ($edgeProcesses) {
            Write-Warning "Edge is currently running. Bookmarks file may be locked."
            Write-Warning "For best results, close Edge before backing up."
        }
    }

    # Resolve output path
    $OutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $backupDir = Split-Path -Path $OutputPath -Parent

    # Create backup directory if it doesn't exist
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Write-Verbose "Created backup directory: $backupDir"
    }

    # Determine profiles to backup
    $profilesToBackup = @()
    if ($ProfileName) {
        # Backup specific profile
        $profilesToBackup = @($ProfileName)
        Write-Verbose "Backing up specific profile: $ProfileName"
    } else {
        # Find all Edge profiles
        $foundProfiles = Get-ChildItem $edgeUserDataPath -Directory -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match '^(Default|Profile \d+)$'
        } | Select-Object -ExpandProperty Name

        if ($foundProfiles) {
            $profilesToBackup = $foundProfiles
            Write-Verbose "Found profiles: $($profilesToBackup -join ', ')"
        } else {
            # Fallback to Default if no profiles found
            $profilesToBackup = @('Default')
            Write-Verbose "No profiles found, using default: Default"
        }
    }

    $backupCount = 0
    $totalSize = 0

    foreach ($profile in $profilesToBackup) {
        $bookmarksPath = Join-Path $edgeUserDataPath "$profile\Bookmarks"
        Write-Verbose "Checking profile '$profile': $bookmarksPath"

        if (Test-Path $bookmarksPath) {
            $profileOutputPath = if ($ProfileName -or $profilesToBackup.Count -eq 1) {
                # Single profile - use original output path
                $OutputPath
            } else {
                # Multiple profiles - create separate files
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
                $extension = [System.IO.Path]::GetExtension($OutputPath)
                Join-Path $backupDir "$baseName-$profile$extension"
            }

            Write-Verbose "Copying from: $bookmarksPath to: $profileOutputPath"

            try {
                # Try Copy-Item first (simpler)
                Copy-Item -Path $bookmarksPath -Destination $profileOutputPath -Force -ErrorAction Stop

                if (Test-Path $profileOutputPath) {
                    $fileSize = (Get-Item $profileOutputPath).Length
                    $totalSize += $fileSize
                    $backupCount++
                    Write-Verbose "Successfully backed up profile '$profile' ($fileSize bytes)"
                } else {
                    Write-Warning "Failed to create backup file for profile '$profile'"
                }
            }
            catch {
                Write-Warning "Error copying bookmarks for profile '$profile': $($_.Exception.Message)"

                # If the file is locked, try reading and writing content
                try {
                    Write-Verbose "Attempting alternative copy method..."
                    $content = [System.IO.File]::ReadAllText($bookmarksPath)
                    [System.IO.File]::WriteAllText($profileOutputPath, $content)

                    if (Test-Path $profileOutputPath) {
                        $fileSize = (Get-Item $profileOutputPath).Length
                        $totalSize += $fileSize
                        $backupCount++
                        Write-Verbose "Successfully backed up profile '$profile' using alternative method ($fileSize bytes)"
                    }
                }
                catch {
                    Write-Warning "Failed to backup profile '$profile': $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "Bookmarks file not found for profile '$profile'"
        }
    }

    if ($backupCount -gt 0) {
        Write-Host "Edge bookmarks backed up successfully ($backupCount profile(s)) to: $backupDir"
        Write-Host "Total backup size: $totalSize bytes"

        if ($profilesToBackup.Count -gt 1 -and -not $ProfileName) {
            Write-Host "Individual files created for each profile"
        }
    } else {
        Write-Warning "No Edge bookmarks were backed up"
    }
}
catch {
    Write-Error "Error backing up Edge bookmarks: $($_.Exception.Message)"
}
