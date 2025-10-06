# Install-TeamsOnCitrixVDA

**Description**: A PowerShell script that downloads and installs Microsoft Teams on a Citrix Virtual Desktop Agent (VDA) running Windows Server 2019. The script performs a clean installation by removing any existing Teams versions, ensuring prerequisites are met, and installing the latest Teams MSIX package optimized for Citrix environments.

## Features

- **Clean Installation**: Automatically detects and removes old Microsoft Teams (classic) and new Microsoft Teams (MSIX) installations before proceeding.
- **Prerequisite Verification**: Checks and installs required components including Microsoft Edge WebView2 runtime and verifies .NET Framework version.
- **Automated Download**: Downloads the latest Microsoft Teams MSIX package from the official Microsoft source (or custom URL if specified).
- **Citrix VDA Optimized**: Specifically designed for Citrix Virtual Desktop Agent environments on Windows Server 2019.
- **Comprehensive Logging**: Provides detailed logging throughout the installation process for troubleshooting.
- **Error Handling**: Robust error handling with cleanup of temporary files and clear error messages.

## Prerequisites

- Windows Server 2019
- PowerShell 5.1 or later
- Administrator privileges (script requires -RunAsAdministrator)
- Internet access for downloading Teams and WebView2
- Citrix Virtual Desktop Agent installed

## Parameters

- `-TeamsDownloadUrl <string>` (Optional): Custom URL to download the Teams MSIX package. Default uses the official Microsoft URL (https://go.microsoft.com/fwlink/?linkid=2196106).
- `-WebView2Url <string>` (Optional): Custom URL to download the Microsoft Edge WebView2 runtime. Default uses the official Microsoft URL (https://go.microsoft.com/fwlink/p/?LinkId=2124703).

## Usage Examples

### Basic Installation
```powershell
.\Install-TeamsOnCitrixVDA.ps1
```

### Custom Download URLs
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -TeamsDownloadUrl "https://custom.url/teams.msix" -WebView2Url "https://custom.url/webview2.exe"
```

### Scheduled Installation
Use Windows Task Scheduler to run the script with appropriate parameters:
- Action: Start a program
- Program/script: `powershell.exe`
- Arguments: `-ExecutionPolicy Bypass -File "C:\Path\To\Install-TeamsOnCitrixVDA.ps1"`

## Script Actions

The script performs the following steps in order:

1. **Initialization**: Logs the start of the installation process
2. **Old Teams Removal**: Detects and uninstalls classic Microsoft Teams if present
3. **New Teams Removal**: Detects and removes any existing MSIX Teams installation
4. **Prerequisite Check**:
   - Verifies .NET Framework 4.6.2 or later
   - Checks for Microsoft Edge WebView2 runtime installation
   - Installs WebView2 if not present
5. **Download**: Downloads the latest Teams MSIX package to a temporary location
6. **Installation**: Installs Microsoft Teams using Add-AppxPackage
7. **Cleanup**: Removes temporary installation files
8. **Completion**: Logs successful installation

## Requirements Verification

### .NET Framework
- Minimum version: 4.6.2 (Release 394802 or higher)
- The script checks the registry for the installed version
- Warning displayed if version is insufficient (though Windows Server 2019 typically includes compatible versions)

### WebView2 Runtime
- Automatically downloaded and installed if not detected
- Registry check: `HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

## Error Handling

- All operations include try-catch blocks with detailed error logging
- Temporary files are cleaned up even if installation fails
- Script exits with error code 1 on failure
- Comprehensive logging to console with timestamps

## Security Considerations

- Requires administrator privileges for installation
- Downloads from official Microsoft URLs by default
- No persistent changes to system configuration beyond Teams installation
- Safe for production Citrix VDA environments

## Troubleshooting

### Common Issues

1. **WebView2 Installation Fails**
   - Ensure internet connectivity
   - Check firewall settings for Microsoft download URLs
   - Verify administrator privileges

2. **Teams Installation Fails**
   - Confirm Citrix VDA is properly installed
   - Check Windows Server 2019 compatibility
   - Review PowerShell execution policy

3. **Old Teams Won't Uninstall**
   - Manual removal may be required
   - Check for running Teams processes
   - Use Task Manager to force close Teams

### Logs
All actions are logged to the console with timestamps. For automated deployments, redirect output to a log file:
```powershell
.\Install-TeamsOnCitrixVDA.ps1 > installation.log 2>&1
```

## Compatibility

- **Operating System**: Windows Server 2019
- **Citrix**: Virtual Desktop Agent (VDA)
- **PowerShell**: Version 5.1+
- **Teams**: Latest MSIX version for Citrix

## Notes

- Designed specifically for Citrix VDA environments
- Automatically handles both classic and MSIX Teams versions
- No user interaction required - fully automated
- Safe to run multiple times (idempotent)
- Test in a non-production environment first
- Requires internet access for downloads
- Temporary files stored in %TEMP% and automatically cleaned up
