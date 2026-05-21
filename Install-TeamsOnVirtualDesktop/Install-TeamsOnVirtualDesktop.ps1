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
    [ValidateSet('CitrixVDA', 'RDS', 'AVD')]
    [string]$DeploymentType,

    [string]$TeamsDownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2196106",
    [string]$TeamsBootstrapperUrl = "https://go.microsoft.com/fwlink/?linkid=2243204",
    [string]$WebRTCRedirectorUrl = "https://aka.ms/msrdcwebrtcsvc/msi",
    [switch]$SkipWebRTCRedirector,
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
            $errMsg = $_.Exception.Message
            Write-Log "Error uninstalling old Teams: $errMsg"
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
                $errMsg = $_.Exception.Message
                Write-Log "[WARN] Failed to remove old Teams for profile $($profile.Name): $errMsg"
                continue
            }
        }
    }
}

# Function to remove per-machine classic Teams MSI (Teams Machine-Wide Installer)
function Remove-OldTeamsPerMachine {
    # Detect via uninstall registry hive — NOT Win32_Product (triggers MSI
    # self-repair on every installed product, slow and disruptive).
    $teamsMsiCode = '{731F6BAA-A986-45A4-8936-7C3AAAAA760B}'
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$teamsMsiCode",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$teamsMsiCode"
    )
    $found = $uninstallKeys | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) {
        Write-Log "Per-machine classic Teams MSI not detected"
        return
    }
    Write-Log "Per-machine classic Teams MSI detected, uninstalling..."
    try {
        $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                              -ArgumentList "/x", $teamsMsiCode, "/qn", "/norestart" `
                              -Wait -PassThru -NoNewWindow
        # 0 = success, 1605 = product not installed (race),
        # 3010 = success/reboot queued, 1641 = success/reboot initiated
        if ($proc.ExitCode -in @(0, 1605, 3010, 1641)) {
            Write-Log "Per-machine classic Teams MSI uninstall completed (exit $($proc.ExitCode))"
        }
        else {
            Write-Log "[WARN] msiexec /x for classic Teams MSI returned $($proc.ExitCode); continuing"
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Log "[WARN] Could not launch msiexec to remove per-machine Teams MSI: $errMsg; continuing"
    }
}

# Function to check if new Teams is installed
function Test-NewTeamsInstalled {
    if ($DeploymentType -in @('RDS', 'AVD')) {
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
        if ($DeploymentType -in @('RDS', 'AVD')) {
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
        $errMsg = $_.Exception.Message
        Write-Log "Error uninstalling new Teams: $errMsg"
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
        # Switch to install mode on RDS/AVD so registry mappings work for all users
        if ($DeploymentType -in @('RDS', 'AVD')) {
            Write-Log "Switching to install mode for multi-session ($DeploymentType)..."
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
        $errMsg = $_.Exception.Message
        Write-Log "Error installing WebView2: $errMsg"
        throw
    }
    finally {
        # Switch back to execute mode on RDS/AVD
        if ($DeploymentType -in @('RDS', 'AVD')) {
            & change user /execute 2>$null
            Write-Log "Switched back to execute mode ($DeploymentType)"
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
        $errMsg = $_.Exception.Message
        Write-Log "Error downloading Teams installer: $errMsg"
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
        $errMsg = $_.Exception.Message
        Write-Log "Error installing Teams: $errMsg"
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
        $errMsg = $_.Exception.Message
        Write-Log "Error provisioning Teams: $errMsg"
        throw
    }
}

# Function to install Teams on AVD (Azure Virtual Desktop)
function Install-TeamsAVD {
    param ([string]$MsixPath)

    $osBuild = [System.Environment]::OSVersion.Version.Build

    if ($osBuild -ge 19041) {
        # Win10 20H1+, Win11, Server 2022+ — Microsoft-recommended path
        Write-Log "Installing Microsoft Teams for AVD via teamsbootstrapper.exe (build $osBuild)..."
        $bootstrapperPath = "$env:TEMP\teamsbootstrapper.exe"
        try {
            # Suppress progress bar — under PS 5.1 it can slow downloads 10-50x
            $prevProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $TeamsBootstrapperUrl -OutFile $bootstrapperPath
            $ProgressPreference = $prevProgress
            Write-Log "teamsbootstrapper.exe downloaded to $bootstrapperPath"

            $proc = Start-Process -FilePath $bootstrapperPath `
                                  -ArgumentList "-p", "-o", $MsixPath `
                                  -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                throw "teamsbootstrapper.exe failed with exit code $($proc.ExitCode). See C:\WINDOWS\Temp\teamsprovision.log.* for details."
            }
            Write-Log "Teams provisioned successfully via teamsbootstrapper.exe (AVD)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log "Error provisioning Teams via bootstrapper: $errMsg"
            throw
        }
        finally {
            if ($prevProgress) { $ProgressPreference = $prevProgress }
            if (Test-Path $bootstrapperPath) {
                Remove-Item -Path $bootstrapperPath -Force
            }
        }
    }
    else {
        # Server 2019 (build 17763) — DISM-equivalent is the only supported method.
        # In the main script, Task 8's OS gate already throws on build < 19041 for AVD
        # mode; this branch is reached only if Install-TeamsAVD is called directly,
        # bypassing the main gate. Keeping it self-contained documents intent.
        Write-Log "Installing Microsoft Teams for AVD via Add-AppxProvisionedPackage (build $osBuild — Server 2019 fallback)..."
        try {
            Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -SkipLicense
            Write-Log "Teams provisioned successfully for all users (AVD on Server 2019)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log "Error provisioning Teams: $errMsg"
            throw
        }
    }
}

# Function to install / upgrade the AVD WebRTC Redirector
function Install-WebRTCRedirector {
    # Check existing version via uninstall registry first (idempotent re-runs)
    $rtcMsiCode = '{FB41EDB3-4138-4240-AC09-B5A184E8F8E4}'
    $existingPath = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$rtcMsiCode",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$rtcMsiCode"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($existingPath) {
        $existingVersion = (Get-ItemProperty $existingPath).DisplayVersion
        Write-Log "WebRTC Redirector $existingVersion already installed; uninstalling before upgrade..."
        $unProc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                                -ArgumentList "/x", $rtcMsiCode, "/qn", "/norestart" `
                                -Wait -PassThru -NoNewWindow
        if ($unProc.ExitCode -notin @(0, 1605, 3010, 1641)) {
            Write-Log "[WARN] msiexec /x for WebRTC Redirector returned $($unProc.ExitCode); proceeding with install anyway"
        }
    }

    $installerPath = "$env:TEMP\MsRdcWebRTCSvc_x64.msi"
    $prevProgress = $ProgressPreference
    try {
        # Suppress progress bar — under PS 5.1 it can slow downloads 10-50x
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $WebRTCRedirectorUrl -OutFile $installerPath
        $ProgressPreference = $prevProgress
        Write-Log "WebRTC Redirector MSI downloaded to $installerPath"

        $proc = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                              -ArgumentList "/i", $installerPath, "/qn", "/norestart" `
                              -Wait -PassThru -NoNewWindow
        # 0 = success, 3010 = success/reboot queued, 1641 = success/reboot initiated
        if ($proc.ExitCode -in @(0, 3010, 1641)) {
            Write-Log "WebRTC Redirector installed (exit $($proc.ExitCode))"
        }
        else {
            throw "WebRTC Redirector install failed with exit code $($proc.ExitCode)"
        }
    }
    finally {
        if ($prevProgress) { $ProgressPreference = $prevProgress }
        if (Test-Path $installerPath) { Remove-Item $installerPath -Force }
    }
}

# Main script execution
try {
    # Ensure TLS 1.2 is available for HTTPS downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    Write-Log "Starting Teams installation script - Deployment Type: $DeploymentType"

    # AVD mode is intended for image-build VMs. Warn loudly if it's being
    # run anywhere else so a live-host operator has a chance to abort.
    if ($DeploymentType -eq 'AVD') {
        Write-Log "[WARN] AVD mode provisions Teams machine-wide. This is intended for use inside a"
        Write-Log "[WARN] golden-image VM before sysprep/sealing. Running on a live AVD session host"
        Write-Log "[WARN] will affect all users on this host. Continuing in 5 seconds -- Ctrl+C to abort."
        Start-Sleep -Seconds 5
    }

    # OS gate is mode-aware:
    #  - CitrixVDA / RDS: build 17763+ (Server 2019)
    #  - AVD: build 19041+ (Win10 20H1, Win11, Server 2022+) per Microsoft Learn
    #    https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy
    $osBuild = [System.Environment]::OSVersion.Version.Build
    if ($DeploymentType -eq 'AVD') {
        if ($osBuild -lt 19041) {
            throw "AVD deployment requires Windows 10 build 19041 (20H1) or later, Windows 11, or Server 2022+. This system is build $osBuild."
        }
    }
    else {
        if ($osBuild -lt 17763) {
            throw "New Teams requires Windows Server 2019 or later (build 17763+). This system is build $osBuild. Install Teams Classic (MSI) instead."
        }
    }

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
    if ($DeploymentType -in @('RDS', 'AVD')) {
        if (Test-OldTeamsInstalledAllUsers) {
            Remove-OldTeamsAllUsers
        }
        # Also clean the per-machine classic Teams MSI if present
        Remove-OldTeamsPerMachine
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

        switch ($DeploymentType) {
            'CitrixVDA' { Install-TeamsCitrixVDA -MsixPath $TeamsMsixPath }
            'RDS'       { Install-TeamsRDS -MsixPath $TeamsMsixPath }
            'AVD'       { Install-TeamsAVD -MsixPath $TeamsMsixPath }
        }
    }
    else {
        $downloadedMsixPath = "$env:TEMP\Teams_x64.msix"
        Get-TeamsInstaller -Url $TeamsDownloadUrl -OutputPath $downloadedMsixPath

        switch ($DeploymentType) {
            'CitrixVDA' { Install-TeamsCitrixVDA -MsixPath $downloadedMsixPath }
            'RDS'       { Install-TeamsRDS -MsixPath $downloadedMsixPath }
            'AVD'       { Install-TeamsAVD -MsixPath $downloadedMsixPath }
        }

        # Clean up downloaded file
        if (Test-Path $downloadedMsixPath) {
            Remove-Item -Path $downloadedMsixPath -Force
        }
    }

    # AVD media optimization requires this registry key. Per Microsoft Learn,
    # without it Teams installs but won't enable AV redirection on AVD.
    # NOTE: WebRTC-based optimization is deprecated — End of Support 2026-10-01,
    # End of Availability 2027-04-01 — but the key remains required until then.
    if ($DeploymentType -eq 'AVD') {
        # IsWVDEnvironment — non-fatal on failure (Teams install already succeeded)
        try {
            $teamsRegPath = "HKLM:\SOFTWARE\Microsoft\Teams"
            if (-not (Test-Path $teamsRegPath)) {
                New-Item -Path $teamsRegPath -Force | Out-Null
            }
            New-ItemProperty -Path $teamsRegPath -Name "IsWVDEnvironment" `
                             -Value 1 -PropertyType DWORD -Force | Out-Null
            Write-Log "Set HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1 (enables AVD media optimization)"
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Log "[WARN] Could not set IsWVDEnvironment registry key: $errMsg"
            Write-Log "[WARN] Teams is installed; set HKLM\SOFTWARE\Microsoft\Teams\IsWVDEnvironment = 1 (DWORD) manually."
        }

        # WebRTC Redirector — non-fatal on failure (Teams install already succeeded)
        if ($SkipWebRTCRedirector) {
            Write-Log "Skipping WebRTC Redirector install (-SkipWebRTCRedirector)"
        }
        else {
            Write-Log "Installing AVD WebRTC Redirector..."
            try {
                Install-WebRTCRedirector
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Log "[WARN] WebRTC Redirector install failed: $errMsg"
                Write-Log "[WARN] Teams + IsWVDEnvironment are configured; install the redirector manually or rerun."
            }
        }
    }

    Write-Log "Teams installation script completed successfully for $DeploymentType"
}
catch {
    $errMsg = $_.Exception.Message
    Write-Log "[FAIL] Script failed with error: $errMsg"
    exit 1
}