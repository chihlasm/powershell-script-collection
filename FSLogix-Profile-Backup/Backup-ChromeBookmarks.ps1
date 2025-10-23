<#
.SYNOPSIS
    Backs up Chrome bookmarks
.DESCRIPTION
    Copies Chrome's Bookmarks file for backup and restoration
.PARAMETER OutputPath
    Path where to save the backup file (default: current directory\ChromeBookmarks.bak)
.PARAMETER ProfilePath
    Path to mounted profile or Chrome user data directory
.PARAMETER ProfileName
    Specific Chrome profile name to backup (default: Default, or all profiles if not specified)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\ChromeBookmarks.bak",

    [Parameter(Mandatory = $false)]
    [string]$ProfilePath,

    [Parameter(Mandatory = $false)]
    [string]$ProfileName
)

Write-Verbose "Starting Chrome bookmarks backup..."

try {
    # Determine Chrome bookmarks location
    $chromeUserDataPath = if ($ProfilePath) {
        # Use mounted profile path or custom path
        Join-Path $ProfilePath "AppData\Local\Google\Chrome\User Data"
    } else {
        # Use current user's default location
        "$env:LOCALAPPDATA\Google\Chrome\User Data"
    }

    Write-Verbose "Chrome user data path: $chromeUserDataPath"

    if (-not (Test-Path $chromeUserDataPath)) {
        Write-Warning "Chrome user data directory not found: $chromeUserDataPath"
        Write-Warning "Chrome may not be installed or no profiles exist"
        return
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
        # Find all Chrome profiles
        $foundProfiles = Get-ChildItem $chromeUserDataPath -Directory | Where-Object {
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
        $bookmarksPath = Join-Path $chromeUserDataPath "$profile\Bookmarks"
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
            Copy-Item -Path $bookmarksPath -Destination $profileOutputPath -Force

            if (Test-Path $profileOutputPath) {
                $fileSize = (Get-Item $profileOutputPath).Length
                $totalSize += $fileSize
                $backupCount++
                Write-Verbose "Successfully backed up profile '$profile' ($fileSize bytes)"
            } else {
                Write-Warning "Failed to create backup file for profile '$profile'"
            }
        } else {
            Write-Verbose "Bookmarks file not found for profile '$profile'"
        }
    }

    if ($backupCount -gt 0) {
        Write-Host "Chrome bookmarks backed up successfully ($backupCount profile(s)) to: $backupDir"
        Write-Host "Total backup size: $totalSize bytes"

        if ($profilesToBackup.Count -gt 1 -and -not $ProfileName) {
            Write-Host "Individual files created for each profile"
        }
    } else {
        Write-Warning "No Chrome bookmarks were backed up"
    }
}
catch {
    Write-Error "Error backing up Chrome bookmarks: $($_.Exception.Message)"
}
