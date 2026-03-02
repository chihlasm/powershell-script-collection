#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs an MSI file from a specified URL.

.DESCRIPTION
    This script downloads an MSI installer from a URL and installs it silently
    using msiexec with standard quiet/passive flags.

.NOTES
    Modify the $DownloadUrl variable to point to your desired MSI file.
#>

# ============================================================================
# CONFIGURATION - Modify these values as needed
# ============================================================================

$DownloadUrl = "https://aetherdl.blob.core.windows.net/download/PulseSecure.x64.msi"
$InstallerName = "PulseSecure.msi"

# ============================================================================
# SCRIPT LOGIC - No modifications needed below this line
# ============================================================================

$TempPath = Join-Path -Path $env:TEMP -ChildPath $InstallerName

try {
    Write-Host "Downloading installer from: $DownloadUrl" -ForegroundColor Cyan

    # Download the MSI file
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath -UseBasicParsing -ErrorAction Stop

    Write-Host "Download complete. Starting installation..." -ForegroundColor Cyan

    # Install silently with logging
    $LogPath = Join-Path -Path $env:TEMP -ChildPath "msi_install.log"
    $Arguments = @(
        "/i"
        "`"$TempPath`""
        "/qn"           # Quiet, no UI
        "/norestart"    # Suppress reboot
        "/l*v"          # Verbose logging
        "`"$LogPath`""
    )

    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru

    if ($Process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully." -ForegroundColor Green
    }
    elseif ($Process.ExitCode -eq 3010) {
        Write-Host "Installation completed successfully. A reboot is required." -ForegroundColor Yellow
    }
    else {
        Write-Host "Installation failed with exit code: $($Process.ExitCode)" -ForegroundColor Red
        Write-Host "Check log file at: $LogPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    # Clean up downloaded file
    if (Test-Path -Path $TempPath) {
        Remove-Item -Path $TempPath -Force -ErrorAction SilentlyContinue
    }
}
