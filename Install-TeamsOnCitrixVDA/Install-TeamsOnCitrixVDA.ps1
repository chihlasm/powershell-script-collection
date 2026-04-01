#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs Microsoft Teams on a Citrix VDA or RDS Terminal Server.
    Removes old Teams and new Teams if present, ensures prerequisites are met, and performs clean installation.

.DESCRIPTION
    This script performs the following actions:
    1. Checks for and removes old Microsoft Teams (classic) if installed
    2. Checks for and removes new Microsoft Teams (MSIX) if installed
    3. Verifies and installs prerequisites (WebView2, .NET Framework)
    4. Downloads the latest Microsoft Teams MSIX package
    5. Installs Microsoft Teams for the target environment

    Two deployment modes are supported:
    - CitrixVDA: Uses Add-AppxPackage; Teams auto-detects the VDA and provisions machine-wide
    - RDS: Uses Add-AppxProvisionedPackage for machine-wide provisioning on standard
      Remote Desktop Services terminal servers without Citrix

.PARAMETER DeploymentType
    Target environment for the installation. Must be either 'CitrixVDA' or 'RDS'.
    - CitrixVDA: Standard Citrix Virtual Delivery Agent servers
    - RDS: Windows Remote Desktop Services terminal servers (no Citrix)

.PARAMETER TeamsDownloadUrl
    URL to download Teams MSIX. If not specified, uses the official Microsoft URL.
    Ignored if TeamsMsixPath is specified.

.PARAMETER TeamsMsixPath
    Path to a local or network share MSIX file. If specified, the script will use this
    file instead of downloading from the internet. Supports UNC paths (e.g., \\server\share\teams.msix)
    and local paths (e.g., C:\Installers\teams.msix).

.PARAMETER Force
    Reinstalls Teams even if it is already installed. Removes the existing installation
    first, then performs a fresh install. Without this switch, the script exits early
    if Teams is already detected.

.PARAMETER WebView2Url
    URL to download WebView2 runtime. If not specified, uses the official Microsoft URL.

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA -Force
    Reinstalls Teams on a Citrix VDA even if it is already installed.

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS -TeamsMsixPath "\\fileserver\software\Teams_x64.msix"

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA -TeamsDownloadUrl "https://custom.url/teams.msix"

.NOTES
    On Citrix VDA, Teams detects the VDA environment via registry keys and auto-provisions
    machine-wide. On RDS, the script uses Add-AppxProvisionedPackage to achieve the same result.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateSet('CitrixVDA', 'RDS')]
    [string]$DeploymentType,

    [string]$TeamsDownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2196106",
    [string]$TeamsMsixPath,
    [string]$WebView2Url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
    [switch]$Force
)

# Function to write log messages
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Function to check if old Teams is installed (current user)
function Test-OldTeamsInstalled {
    $teamsPath = "$env:LOCALAPPDATA\Microsoft\Teams"
    if (Test-Path $teamsPath) {
        Write-Log "Old Teams installation detected at $teamsPath"
        return $true
    }
    Write-Log "Old Teams not detected for current user"
    return $false
}

# Function to check if old Teams is installed in any user profile
function Test-OldTeamsInstalledAllUsers {
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    $found = $false
    foreach ($profile in $userProfiles) {
        $teamsPath = Join-Path $profile.FullName "AppData\Local\Microsoft\Teams"
        if (Test-Path $teamsPath) {
            Write-Log "Old Teams installation detected in profile: $($profile.Name)"
            $found = $true
        }
    }

    if (-not $found) {
        Write-Log "Old Teams not detected in any user profile"
    }
    return $found
}

# Function to remove old Teams (current user only)
function Remove-OldTeams {
    Write-Log "Attempting to uninstall old Teams for current user..."
    $teamsPath = "$env:LOCALAPPDATA\Microsoft\Teams"

    if (Test-Path "$teamsPath\Update.exe") {
        try {
            Start-Process -FilePath "$teamsPath\Update.exe" -ArgumentList "--uninstall /s" -Wait -NoNewWindow
            Write-Log "Old Teams uninstall initiated"
            Start-Sleep -Seconds 10
            if (Test-Path $teamsPath) {
                Remove-Item -Path $teamsPath -Recurse -Force
                Write-Log "Old Teams directory removed"
            }
        }
        catch {
            Write-Log "Error uninstalling old Teams: $_"
            throw
        }
    }
    else {
        Write-Log "Old Teams Update.exe not found, removing directory manually"
        if (Test-Path $teamsPath) {
            Remove-Item -Path $teamsPath -Recurse -Force
            Write-Log "Old Teams directory removed"
        }
    }
}

# Function to remove old Teams from all user profiles
function Remove-OldTeamsAllUsers {
    Write-Log "Attempting to remove old Teams from all user profiles..."
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($profile in $userProfiles) {
        $teamsPath = Join-Path $profile.FullName "AppData\Local\Microsoft\Teams"
        if (Test-Path $teamsPath) {
            try {
                # Try uninstaller first
                $updateExe = Join-Path $teamsPath "Update.exe"
                if (Test-Path $updateExe) {
                    Start-Process -FilePath $updateExe -ArgumentList "--uninstall /s" -Wait -NoNewWindow
                    Write-Log "Old Teams uninstall initiated for profile: $($profile.Name)"
                    Start-Sleep -Seconds 10
                }
                # Remove directory regardless
                if (Test-Path $teamsPath) {
                    Remove-Item -Path $teamsPath -Recurse -Force
                    Write-Log "Old Teams directory removed for profile: $($profile.Name)"
                }
            }
            catch {
                Write-Log "[WARN] Failed to remove old Teams for profile $($profile.Name): $_"
                continue
            }
        }
    }
}

# Function to check if new Teams is installed
function Test-NewTeamsInstalled {
    if ($DeploymentType -eq 'RDS') {
        $teamsPackage = Get-AppxPackage -AllUsers -Name "*Teams*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*Teams*" }
    }
    else {
        $teamsPackage = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*Teams*" }
    }

    if ($teamsPackage) {
        Write-Log "New Teams installation detected: $($teamsPackage.Name)"
        return $true
    }
    Write-Log "New Teams not detected"
    return $false
}

# Function to remove new Teams
function Remove-NewTeams {
    Write-Log "Attempting to uninstall new Teams..."
    try {
        if ($DeploymentType -eq 'RDS') {
            $teamsPackage = Get-AppxPackage -AllUsers -Name "*Teams*" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*Teams*" }
            if ($teamsPackage) {
                # Remove provisioned package so new users don't get it
                $provisionedPkg = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*Teams*" }
                if ($provisionedPkg) {
                    Remove-AppxProvisionedPackage -Online -PackageName $provisionedPkg.PackageName
                    Write-Log "Provisioned Teams package removed"
                }
                # Remove for all existing users
                $teamsPackage | Remove-AppxPackage -AllUsers
                Write-Log "New Teams uninstalled for all users"
            }
            else {
                Write-Log "New Teams package not found for removal"
            }
        }
        else {
            $teamsPackage = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like "*Teams*" }
            if ($teamsPackage) {
                Remove-AppxPackage -Package $teamsPackage.PackageFullName
                Write-Log "New Teams uninstalled successfully"
            }
            else {
                Write-Log "New Teams package not found for removal"
            }
        }
    }
    catch {
        Write-Log "Error uninstalling new Teams: $_"
        throw
    }
}

# Function to check .NET Framework version
function Test-DotNetVersion {
    $dotNetVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue
    if ($dotNetVersion) {
        $release = $dotNetVersion.Release
        if ($release -ge 394802) {
            Write-Log ".NET Framework version is sufficient (Release: $release)"
            return $true
        }
        else {
            Write-Log ".NET Framework version is too old (Release: $release). Version 4.6.2 or later required."
            return $false
        }
    }
    else {
        Write-Log ".NET Framework 4.5 or later not detected"
        return $false
    }
}

# Function to install WebView2
function Install-WebView2 {
    Write-Log "Installing Microsoft Edge WebView2 runtime..."
    $installerPath = "$env:TEMP\MicrosoftEdgeWebview2Setup.exe"

    try {
        # Switch to install mode on RDS so registry mappings work for all users
        if ($DeploymentType -eq 'RDS') {
            Write-Log "Switching to install mode for RDS..."
            & change user /install 2>$null
        }

        Invoke-WebRequest -Uri $WebView2Url -OutFile $installerPath
        Write-Log "WebView2 installer downloaded to $installerPath"

        $process = Start-Process -FilePath $installerPath -ArgumentList "/silent /install" -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Log "WebView2 installation completed successfully"
        }
        else {
            throw "WebView2 installation failed with exit code $($process.ExitCode)"
        }
    }
    catch {
        Write-Log "Error installing WebView2: $_"
        throw
    }
    finally {
        # Switch back to execute mode on RDS
        if ($DeploymentType -eq 'RDS') {
            & change user /execute 2>$null
            Write-Log "Switched back to execute mode"
        }
        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force
        }
    }
}

# Function to check if WebView2 is installed
function Test-WebView2Installed {
    $webView2Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    if (Test-Path $webView2Path) {
        Write-Log "WebView2 is already installed"
        return $true
    }
    Write-Log "WebView2 not detected"
    return $false
}

# Function to download Teams installer
function Get-TeamsInstaller {
    param ([string]$Url, [string]$OutputPath)

    Write-Log "Downloading Teams installer from $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath
        Write-Log "Teams installer downloaded to $OutputPath"
    }
    catch {
        Write-Log "Error downloading Teams installer: $_"
        throw
    }
}

# Function to install Teams on Citrix VDA
function Install-TeamsCitrixVDA {
    param ([string]$MsixPath)

    Write-Log "Installing Microsoft Teams for Citrix VDA..."
    try {
        Add-AppxPackage -Path $MsixPath
        Write-Log "Teams installation completed successfully (Citrix VDA - auto-provisions via VDA detection)"
    }
    catch {
        Write-Log "Error installing Teams: $_"
        throw
    }
}

# Function to install Teams on RDS terminal server
function Install-TeamsRDS {
    param ([string]$MsixPath)

    Write-Log "Installing Microsoft Teams for RDS (machine-wide provisioning)..."
    try {
        Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -SkipLicense
        Write-Log "Teams provisioned successfully for all users (RDS)"
    }
    catch {
        Write-Log "Error provisioning Teams: $_"
        throw
    }
}

# Main script execution
try {
    Write-Log "Starting Teams installation script - Deployment Type: $DeploymentType"

    # Check if new Teams is already installed
    $teamsAlreadyInstalled = Test-NewTeamsInstalled
    if ($teamsAlreadyInstalled -and -not $Force) {
        Write-Log "Teams is already installed. Use -Force to remove and reinstall."
        Write-Log "Exiting — no changes made."
        return
    }

    if ($teamsAlreadyInstalled -and $Force) {
        Write-Log "-Force specified. Removing existing Teams installation before reinstalling..."
    }

    # Check and remove old Teams
    if ($DeploymentType -eq 'RDS') {
        if (Test-OldTeamsInstalledAllUsers) {
            Remove-OldTeamsAllUsers
        }
    }
    else {
        if (Test-OldTeamsInstalled) {
            Remove-OldTeams
        }
    }

    # Check and remove new Teams
    if ($teamsAlreadyInstalled) {
        Remove-NewTeams
    }

    # Check prerequisites
    Write-Log "Checking prerequisites..."

    # Check .NET Framework
    if (-not (Test-DotNetVersion)) {
        Write-Log "[WARN] .NET Framework version may be insufficient. Please ensure .NET Framework 4.6.2 or later is installed."
    }

    # Check and install WebView2
    if (-not (Test-WebView2Installed)) {
        Install-WebView2
    }

    # Determine MSIX source and install Teams
    if ($TeamsMsixPath) {
        Write-Log "Using provided MSIX path: $TeamsMsixPath"

        if (-not (Test-Path $TeamsMsixPath)) {
            throw "Teams MSIX file not found at: $TeamsMsixPath"
        }

        if ($TeamsMsixPath -notmatch '\.msix$') {
            Write-Log "[WARN] File does not have .msix extension. Proceeding anyway..."
        }

        if ($DeploymentType -eq 'CitrixVDA') {
            Install-TeamsCitrixVDA -MsixPath $TeamsMsixPath
        }
        else {
            Install-TeamsRDS -MsixPath $TeamsMsixPath
        }
    }
    else {
        $downloadedMsixPath = "$env:TEMP\Teams_x64.msix"
        Get-TeamsInstaller -Url $TeamsDownloadUrl -OutputPath $downloadedMsixPath

        if ($DeploymentType -eq 'CitrixVDA') {
            Install-TeamsCitrixVDA -MsixPath $downloadedMsixPath
        }
        else {
            Install-TeamsRDS -MsixPath $downloadedMsixPath
        }

        # Clean up downloaded file
        if (Test-Path $downloadedMsixPath) {
            Remove-Item -Path $downloadedMsixPath -Force
        }
    }

    Write-Log "Teams installation script completed successfully for $DeploymentType"
}
catch {
    Write-Log "[FAIL] Script failed with error: $_"
    exit 1
}
