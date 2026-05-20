# Install-TeamsOnCitrixVDA

**Description**: A PowerShell script that downloads and installs Microsoft Teams on a Citrix VDA or RDS Terminal Server. The script performs a clean installation by removing any existing Teams versions, ensuring prerequisites are met, and installing the latest Teams MSIX package using the appropriate method for each environment.

## Features

- **Dual Deployment Modes**: Supports both Citrix VDA and RDS Terminal Server environments via the `-DeploymentType` parameter.
- **Clean Installation**: Automatically detects and removes old Microsoft Teams (classic) and new Microsoft Teams (MSIX) installations before proceeding.
- **Machine-Wide Provisioning (RDS)**: Uses `Add-AppxProvisionedPackage` on RDS to ensure all current and future users receive Teams.
- **All-User Cleanup (RDS)**: Scans every user profile for old Teams installations instead of only the current user.
- **Prerequisite Verification**: Checks and installs required components including Microsoft Edge WebView2 runtime and verifies .NET Framework version.
- **Automated Download**: Downloads the latest Microsoft Teams MSIX package from the official Microsoft source, or accepts a local/network path.
- **Comprehensive Logging**: Provides detailed timestamped logging throughout the installation process.
- **Error Handling**: Robust error handling with cleanup of temporary files and clear error messages.

## Prerequisites

- Windows Server 2019 or later
- PowerShell 5.1 or later
- Administrator privileges (script requires -RunAsAdministrator)
- Internet access for downloading Teams and WebView2 (unless using `-TeamsMsixPath`)
- Citrix Virtual Desktop Agent installed (for CitrixVDA mode)
- Remote Desktop Services role installed (for RDS mode)

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-DeploymentType` | Yes | Target environment: `CitrixVDA` or `RDS` |
| `-TeamsDownloadUrl` | No | Custom URL for the Teams MSIX package. Ignored if `-TeamsMsixPath` is specified. Default: official Microsoft URL |
| `-TeamsMsixPath` | No | Local or UNC path to a Teams MSIX file. Skips download when provided |
| `-WebView2Url` | No | Custom URL for the WebView2 runtime installer. Default: official Microsoft URL |
| `-Force` | No | Reinstalls Teams even if already installed. Without this, the script exits early if Teams is detected |

## Usage Examples

### Citrix VDA Installation
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA
```

### RDS Terminal Server Installation
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS
```

### Reinstall (Force)
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA -Force
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS -Force
```

### Using a Local or Network MSIX File
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS -TeamsMsixPath "\\fileserver\software\Teams_x64.msix"
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType CitrixVDA -TeamsMsixPath "C:\Installers\Teams_x64.msix"
```

### Scheduled Installation
Use Windows Task Scheduler to run the script with appropriate parameters:
- Action: Start a program
- Program/script: `powershell.exe`
- Arguments: `-ExecutionPolicy Bypass -File "C:\Path\To\Install-TeamsOnCitrixVDA.ps1" -DeploymentType RDS`

## How It Works

### CitrixVDA Mode

1. Checks and removes old Teams for the current user
2. Checks and removes new Teams (MSIX) for the current user
3. Verifies prerequisites (WebView2, .NET Framework)
4. Installs Teams via `Add-AppxPackage` — Teams auto-detects the Citrix VDA environment via registry keys and provisions machine-wide

### RDS Mode

1. Scans all user profiles under `C:\Users` and removes old Teams from each
2. Checks and removes new Teams for all users (`-AllUsers`), including the provisioned package
3. Verifies prerequisites; installs WebView2 in RDS install mode (`change user /install`)
4. Installs Teams via `Add-AppxProvisionedPackage -Online -SkipLicense` for machine-wide provisioning

## Requirements Verification

### .NET Framework
- Minimum version: 4.6.2 (Release 394802 or higher)
- The script checks the registry for the installed version
- Warning displayed if version is insufficient (Windows Server 2019+ typically includes compatible versions)

### WebView2 Runtime
- Automatically downloaded and installed if not detected
- Registry check: `HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
- On RDS, installed in install mode so registry mappings apply to all users

## Error Handling

- All operations include try/catch blocks with detailed error logging
- RDS all-user cleanup uses `continue` so one locked profile doesn't halt the script
- Temporary files are cleaned up even if installation fails
- Script exits with error code 1 on failure
- Comprehensive logging to console with timestamps

## Troubleshooting

### Common Issues

1. **WebView2 Installation Fails**
   - Ensure internet connectivity
   - Check firewall settings for Microsoft download URLs
   - Verify administrator privileges

2. **Teams Installation Fails**
   - CitrixVDA: Confirm Citrix VDA is properly installed and VDA registry keys exist
   - RDS: Confirm the Remote Desktop Services role is installed
   - Review PowerShell execution policy

3. **Old Teams Won't Uninstall (RDS)**
   - Check for active user sessions with Teams running
   - Use `query user` to identify logged-in users
   - Log off users or force close Teams processes before running the script

4. **Provisioned Package Removal Fails**
   - Ensure no users are actively running Teams
   - Run `Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*Teams*" }` to verify state

### Logs
All actions are logged to the console with timestamps. For automated deployments, redirect output to a log file:
```powershell
.\Install-TeamsOnCitrixVDA.ps1 -DeploymentType RDS > installation.log 2>&1
```

## Compatibility

- **Operating System**: Windows Server 2019 or later
- **Citrix**: Virtual Desktop Agent (VDA)
- **RDS**: Windows Remote Desktop Services
- **PowerShell**: Version 5.1+
- **Teams**: Latest MSIX version

## Notes

- The `-DeploymentType` parameter is mandatory — you must specify the target environment
- On Citrix VDA, Teams detects the VDA via `HKLM:\SOFTWARE\Citrix\PortICA` and auto-provisions machine-wide
- On RDS, `Add-AppxProvisionedPackage` ensures both existing and newly created user profiles receive Teams
- Safe to run multiple times (idempotent)
- Test in a non-production environment first
- Temporary files stored in %TEMP% and automatically cleaned up
