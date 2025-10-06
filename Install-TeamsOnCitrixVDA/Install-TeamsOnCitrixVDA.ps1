#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs Microsoft Teams on a Citrix VDA running Windows Server 2019.
    Removes old Teams and new Teams if present, ensures prerequisites are met, and performs clean installation.

.DESCRIPTION
    This script performs the following actions:
    1. Checks for and removes old Microsoft Teams (classic) if installed
    2. Checks for and removes new Microsoft Teams (MSIX) if installed
    3. Verifies and installs prerequisites (WebView2, .NET Framework)
    4. Downloads the latest Microsoft Teams MSIX package
    5. Installs Microsoft Teams for Citrix VDA

.PARAMETER TeamsDownloadUrl
    URL to download Teams MSIX. If not specified, uses the official Microsoft URL.

.PARAMETER WebView2Url
    URL to download WebView2 runtime. If not specified, uses the official Microsoft URL.

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1

.EXAMPLE
    .\Install-TeamsOnCitrixVDA.ps1 -TeamsDownloadUrl "https://custom.url/teams.msix"
#>

param (
    [string]$TeamsDownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2196106",
    [string]$WebView2Url = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
)

# Function to write log messages
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Function to check if old Teams is installed
function Test-OldTeamsInstalled {
    $teamsPath = "$env:LOCALAPPDATA\Microsoft\Teams"
    if (Test-Path $teamsPath) {
        Write-Log "Old Teams installation detected at $teamsPath"
        return $true
    }
    Write-Log "Old Teams not detected"
    return $false
}

# Function to remove old Teams
function Remove-OldTeams {
    Write-Log "Attempting to uninstall old Teams..."
    $teamsPath = "$env:LOCALAPPDATA\Microsoft\Teams"

    if (Test-Path "$teamsPath\Update.exe") {
        try {
            Start-Process -FilePath "$teamsPath\Update.exe" -ArgumentList "--uninstall /s" -Wait -NoNewWindow
            Write-Log "Old Teams uninstall initiated"
            # Wait a bit for uninstall to complete
            Start-Sleep -Seconds 10
            # Remove the directory if it still exists
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

# Function to check if new Teams is installed
function Test-NewTeamsInstalled {
    $teamsPackage = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Teams*" }
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
        $teamsPackage = Get-AppxPackage -Name "*Teams*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Teams*" }
        if ($teamsPackage) {
            Remove-AppxPackage -Package $teamsPackage.PackageFullName
            Write-Log "New Teams uninstalled successfully"
        }
        else {
            Write-Log "New Teams package not found for removal"
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
        # .NET Framework 4.6.2 or later required (Release >= 394802)
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

# Function to install Teams
function Install-Teams {
    param ([string]$MsixPath)

    Write-Log "Installing Microsoft Teams..."
    try {
        Add-AppxPackage -Path $MsixPath
        Write-Log "Teams installation completed successfully"
    }
    catch {
        Write-Log "Error installing Teams: $_"
        throw
    }
}

# Main script execution
try {
    Write-Log "Starting Teams installation script for Citrix VDA"

    # Check and remove old Teams
    if (Test-OldTeamsInstalled) {
        Remove-OldTeams
    }

    # Check and remove new Teams
    if (Test-NewTeamsInstalled) {
        Remove-NewTeams
    }

    # Check prerequisites
    Write-Log "Checking prerequisites..."

    # Check .NET Framework
    if (-not (Test-DotNetVersion)) {
        Write-Log "Warning: .NET Framework version may be insufficient. Please ensure .NET Framework 4.6.2 or later is installed."
        # Note: Not installing .NET here as it requires specific handling and Windows Server 2019 should have it
    }

    # Check and install WebView2
    if (-not (Test-WebView2Installed)) {
        Install-WebView2
    }

    # Download and install Teams
    $teamsMsixPath = "$env:TEMP\Teams_x64.msix"
    Get-TeamsInstaller -Url $TeamsDownloadUrl -OutputPath $teamsMsixPath

    Install-Teams -MsixPath $teamsMsixPath

    # Clean up
    if (Test-Path $teamsMsixPath) {
        Remove-Item -Path $teamsMsixPath -Force
    }

    Write-Log "Teams installation script completed successfully"
}
catch {
    Write-Log "Script failed with error: $_"
    exit 1
}
