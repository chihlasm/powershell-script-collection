# Migrate-AdobeProducts

**Description**: A comprehensive PowerShell script that uninstalls Adobe Acrobat products from a Citrix Virtual Desktop Agent (VDA) environment and installs a replacement Adobe Acrobat package from a network share. The script performs comprehensive detection, clean uninstallation using MSI methods, thorough cleanup of remaining Acrobat files and registry entries, and seamless replacement package installation for Adobe Acrobat product migration. Creative Cloud and other non-Acrobat Adobe products are preserved.

## Features

- **Selective Adobe Acrobat Removal**: Detects and uninstalls ONLY Adobe Acrobat products (preserves Creative Cloud, Photoshop, etc.)
- **Comprehensive Detection**: Uses both WMI and registry queries to detect Adobe Acrobat product installations
- **Multiple Uninstall Methods**: Supports MSI uninstallation and registry-based uninstall commands for Adobe Acrobat products
- **Process Management**: Detects and optionally stops running Adobe Acrobat processes
- **Thorough Cleanup**: Removes Adobe Acrobat installation directories, user data, and registry entries while preserving other Adobe products
- **Citrix VDA Optimized**: Designed for Citrix Virtual Desktop Agent environments with proper error handling
- **Comprehensive Logging**: Provides detailed logging throughout the entire process
- **Force Option**: Allows forced uninstallation even when Adobe Acrobat processes are running
- **Replacement Package Installation**: Seamlessly installs Adobe Acrobat packages configured in Adobe Admin Console from network shares
- **Adobe Admin Console Integration**: Supports Acrobat packages created and configured through Adobe's enterprise deployment tools
- **Direct Download Support**: Downloads Adobe Acrobat installers directly from Adobe's enterprise download URLs
- **Silent Installation**: Automatically configures silent installation with Protected Mode disabled for Citrix compatibility
- **Automatic Extraction**: Handles ZIP file downloads and extraction, or direct EXE downloads for enterprise installer packages

## Prerequisites

- Windows Server (2016, 2019, or 2022)
- PowerShell 5.1 or later
- Administrator privileges (script requires -RunAsAdministrator)
- Citrix Virtual Desktop Agent installed
- Network access to replacement package location (if using -InstallPackage)

## Parameters

- `-Force` (Optional): Forces uninstallation by stopping any running Adobe processes automatically. Without this parameter, the script will exit if Adobe applications are currently running.
- `-InstallPackage <string>` (Optional): Full path to the replacement Adobe installation package (MSI or EXE) located on a network share. The package should be created and configured through Adobe Admin Console for enterprise deployment.
- `-DownloadUrl <string>` (Optional): Direct download URL for Adobe Acrobat enterprise installer (ZIP or EXE file). The script will automatically download, extract (if ZIP), and install the package.
- `-PackageArgs <string>` (Optional): Installation arguments for the replacement package.

## Usage Examples

### Standard Migration (removes all Adobe products and installs replacement)
```powershell
.\Migrate-AdobeProducts.ps1 -InstallPackage "\\server\share\AdobePackage.msi"
```

### Forced Migration (stops running processes)
```powershell
.\Migrate-AdobeProducts.ps1 -Force -InstallPackage "\\server\share\AdobePackage.msi"
```

### Custom Installation Arguments
```powershell
.\Migrate-AdobeProducts.ps1 -InstallPackage "\\server\share\AdobeSetup.exe" -PackageArgs "/s /v/qn"
```

### Direct Download Installation (downloads from Adobe enterprise URLs)
```powershell
.\Migrate-AdobeProducts.ps1 -DownloadUrl "https://ardownload3.adobe.com/pub/adobe/acrobat/win/AcrobatDC/misc/CustWiz2200320310_en_US_DC.exe" -Force
```

### Download with Custom Arguments
```powershell
.\Migrate-AdobeProducts.ps1 -DownloadUrl "https://ardownload3.adobe.com/pub/adobe/acrobat/win/AcrobatDC/misc/CustWiz2200320310_en_US_DC.exe" -PackageArgs "/s /v`"bDisableProtectedModeAtStartup=1 DISABLE_AUTO_UPDATES=1 /qn`"" -Force
```

### Scheduled Deployment
Use Windows Task Scheduler to run the script with appropriate parameters:
- Action: Start a program
- Program/script: `powershell.exe`
- Arguments: `-ExecutionPolicy Bypass -File "C:\Path\To\Migrate-AdobeProducts.ps1" -Force -InstallPackage "\\server\share\AdobePackage.msi"`

### Citrix Director Integration
For Citrix environments, you can integrate this script with Citrix Director or Citrix Studio:
1. Copy the script to a network share accessible by all VDAs
2. Create a scheduled task or use Citrix PowerShell SDK to execute remotely
3. Monitor execution through Citrix Director
4. Use Citrix policies to deploy the replacement package

## Script Actions

The script performs the following steps in order:

1. **Initialization**: Logs the start of the process
2. **Download Handling** (if -DownloadUrl specified): Downloads Adobe Acrobat installer (ZIP or EXE), extracts ZIP if needed, and locates the installer
3. **Detection**: Searches for Adobe Acrobat products using WMI and registry queries (preserves other Adobe products)
4. **Process Check**: Verifies if any Adobe Acrobat processes are running
5. **Process Termination** (if -Force specified): Stops all Adobe Acrobat-related processes
6. **Uninstallation**: Attempts MSI uninstallation for all detected Adobe Acrobat products
7. **Fallback Methods**: Uses registry uninstall strings if MSI uninstallation fails
8. **Cleanup**: Removes remaining Adobe Acrobat files and registry entries (preserves other Adobe products)
9. **Verification**: Confirms successful uninstallation of Adobe Acrobat products
10. **Package Installation** (if specified): Installs the replacement Adobe Acrobat package
11. **Completion**: Logs successful completion

## Detection Methods

### WMI Query
- Searches `Win32_Product` class for all products with "Adobe" in the name
- Excludes Adobe Refresh Manager to avoid conflicts
- Provides product codes for MSI uninstallation

### Registry Query
- Checks both `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and `HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- Uses DisplayName to identify all Adobe product installations
- Extracts UninstallString for alternative uninstallation methods

## Uninstall Methods

### MSI Uninstallation
- Uses `msiexec.exe /x {ProductCode} /quiet /norestart /l*v "logfile.log"`
- Creates timestamped log files in `%TEMP%\Adobe_Uninstall_YYYYMMDD_HHMMSS.log`
- Handles exit codes 0 (success) and 3010 (success, reboot required)

### Registry-Based Uninstallation
- Parses UninstallString from registry entries
- Supports both MSI and setup.exe based Adobe uninstallers
- Uses silent uninstallation flags where available

## Cleanup Operations

### File System Cleanup
Removes all Adobe directories from:
- `%ProgramFiles%\Adobe\*`
- `%ProgramFiles(x86)%\Adobe\*`
- `%APPDATA%\Adobe\*`
- `%LOCALAPPDATA%\Adobe\*`
- `%ALLUSERSPROFILE%\Adobe\*`

### Registry Cleanup
Removes all Adobe registry keys from:
- `HKCU:\Software\Adobe\*`
- `HKLM:\SOFTWARE\Adobe\*`
- `HKLM:\SOFTWARE\WOW6432Node\Adobe\*`

## Replacement Package Installation

### Adobe Admin Console Packages
- Supports packages created through Adobe Admin Console
- Handles both MSI and EXE package formats
- Configurable installation arguments for different deployment scenarios

### Network Share Deployment
- Accesses packages from UNC paths (`\\server\share\package.msi`)
- Supports authenticated network access
- Validates package existence before installation

### Installation Methods
- **MSI Packages**: Uses `msiexec.exe /i "package.msi" /quiet /norestart /l*v "logfile.log"`
- **EXE Packages**: Runs executable with specified arguments
- Creates timestamped installation logs in `%TEMP%`

## Error Handling

- All operations include try-catch blocks with detailed error logging
- Script exits with appropriate error codes (0=success, 1=failure)
- Comprehensive logging to console with timestamps
- Graceful handling of partial uninstallations and installation failures

## Citrix VDA Considerations

### Server Mode Management
- **Automatic Install Mode**: When Citrix VDA is detected, the script automatically sets the server to install mode before package installation
- **Automatic Execute Mode**: After successful installation, the server is automatically returned to execute mode
- **Fallback Handling**: If Citrix commands fail, the script logs warnings and continues with installation
- **Manual Override**: For environments where automatic mode switching is not desired, manually set server modes before/after running the script

### Multi-Session Environment
- Script runs in system context, affecting all sessions
- Handles both machine-level and user-level Adobe installations
- Safe for concurrent user sessions during maintenance windows

### Roaming Profiles
- Cleans up user profile data that may roam with Citrix profiles
- Removes both local and roaming Adobe application data

### Citrix Integration
- Compatible with Citrix Virtual Apps and Desktops
- Can be deployed through Citrix Studio policies and actions
- Suitable for automated maintenance windows and scheduled deployments
- Supports Citrix PowerShell cmdlets and changemode.exe

## Adobe Admin Console Integration

### Package Creation
1. Create packages in Adobe Admin Console
2. Configure licensing and deployment options
3. Export packages to network shares accessible by Citrix VDAs

### Deployment Workflow
1. Run uninstallation script with -Force parameter
2. Script automatically installs replacement package
3. Citrix policies can manage package updates and licensing

### Supported Package Types
- Adobe Acrobat packages (Standard, Pro)
- Creative Cloud packages
- Custom enterprise packages
- Both MSI and EXE installers

## Security Considerations

- Requires administrator privileges for complete uninstallation and installation
- No external dependencies or downloads required (packages must be pre-staged)
- Safe for production Citrix VDA environments
- No persistent changes to system configuration beyond Adobe product management

## Troubleshooting

### Common Issues

1. **"No Adobe products detected"**
   - Verify Adobe products are actually installed
   - Check if products are installed under different names
   - Run script with elevated privileges

2. **"Adobe processes are running"**
   - Close all Adobe applications manually
   - Use `-Force` parameter to stop processes automatically
   - Schedule during maintenance windows when users are not active

3. **"Uninstallation failed"**
   - Check the log files in `%TEMP%\Adobe_Uninstall_*.log`
   - Verify administrator privileges
   - Some Adobe products may require manual uninstallation

4. **"Package installation failed"**
   - Verify network path accessibility
   - Check package file permissions
   - Validate installation arguments for the specific package
   - Review installation logs in `%TEMP%\Adobe_Install_*.log`

5. **"Cleanup warnings"**
   - Some files/registry entries may be in use by system processes
   - Reboot may be required for complete cleanup
   - Warnings are logged but don't prevent script completion

### Logs
All actions are logged to the console with timestamps. For automated deployments, redirect output to a log file:
```powershell
.\Migrate-AdobeProducts.ps1 > adobe_migration.log 2>&1
```

Individual uninstallation and installation operations create detailed logs in `%TEMP%` with timestamps.

## Compatibility

- **Operating System**: Windows Server 2016, 2019, 2022
- **Citrix**: Virtual Desktop Agent (VDA) 7.x, 1912 LTSR, 2203 LTSR, 2305+
- **PowerShell**: Version 5.1+
- **Adobe Products**: Adobe Acrobat products only (preserves Creative Cloud, Photoshop, etc.)
- **Package Types**: MSI and EXE installers from Adobe Admin Console

## Notes

- Designed specifically for Citrix VDA environments and enterprise Adobe deployments
- Automatically detects and handles all Adobe product versions and editions
- Idempotent - safe to run multiple times
- No user interaction required - fully automated
- Test in a non-production environment first
- Requires administrator privileges
- May require system reboot for complete cleanup in some cases
- Supports seamless migration from legacy to modern Adobe products
