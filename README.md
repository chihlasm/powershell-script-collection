# powershell-script-collection
Collection of useful PowerShell scripts for automation and system administration tasks.

## Scripts

### DeleteOldFolders.ps1

**Description**: This PowerShell script recursively searches for and deletes folders ending with '.old' that are older than a specified number of days. It's designed for automated cleanup of temporary, backup, or obsolete folders to free up disk space.

**Parameters**:
- `-DrivePath <string>` (Required): The root directory path to scan for old folders (e.g., "C:\Temp").
- `-DaysOld <int>` (Optional, default: 14): The age threshold in days for folders to be considered for deletion.
- `-WhatIf` (Optional): Switch to simulate the deletion process without actually deleting folders.
- `-SkipConfirmation` (Optional): Switch to skip the confirmation prompt before deletion.
- `-LogFile <string>` (Optional): Path to a log file where all actions and results are recorded.

**Usage Examples**:
- Basic one-time cleanup: `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30`
- Simulation mode (safe to test): `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30 -WhatIf`
- Automated with logging: `.\DeleteOldFolders.ps1 -DrivePath "C:\Backups" -DaysOld 90 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`
- Scheduled task setup: Use Windows Task Scheduler to run the script daily with parameters like `-DrivePath "C:\Temp" -DaysOld 7 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`

**Notes**:
- The script determines folder age using the older of LastWriteTime or CreationTime.
- Supports long file paths and handles access-denied directories gracefully.
- Always use `-WhatIf` first to preview what would be deleted.
- Requires appropriate permissions to delete folders in the specified path.

### FileCopyMoveGUI.ps1

**Description**: This PowerShell script provides a graphical user interface (GUI) for performing file and folder copy or move operations with Robocopy-like features. It allows users to select source and destination directories, choose between copy and move operations, and configure options such as recursive copying, mirroring, and file exclusions.

**Parameters**:
- None (interactive GUI application)

**Usage Examples**:
- Run the script: `.\FileCopyMoveGUI.ps1`
- Select source folder using the Browse button
- Select destination folder using the Browse button
- Choose operation type (Copy or Move)
- Configure options as needed (Recursive, Mirror, Exclusions)
- Click Start to begin the operation
- Monitor progress and view logs in the interface

**Notes**:
- Requires Windows Forms assemblies (included in the script)
- Uses robocopy.exe for the actual file operations
- Supports recursive copying, mirroring, and file exclusions
- Provides real-time progress tracking and error logging
- Cancel button allows stopping the operation mid-process
- Requires appropriate permissions for source and destination paths

## CitrixVDADiagnostics

**Description**: A comprehensive diagnostic tool for Citrix Virtual Desktop Agent (VDA) servers, specifically designed to monitor performance issues related to FSlogix user profiles. The tool analyzes disk queue length, storage space utilization, CPU and RAM usage per user, Windows update status, FSlogix version, and I/O performance, providing actionable recommendations for optimizing Citrix environments.

**Parameters**:
- `-ServerName <string>` (Optional, default: local computer): Target server for diagnostics.
- `-Verbose` (Optional): Switch to show detailed session information and critical update counts.

**Usage Examples**:
- Basic local diagnostics: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1`
- Remote server analysis: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1 -ServerName "CitrixServer01"`
- Verbose output: `.\CitrixVDADiagnostics\CitrixVDADiagnostics.ps1 -Verbose`
- Scheduled monitoring: Use Windows Task Scheduler to run daily with logging redirection

**Features**:
- **Citrix Session Monitoring**: Detects active user sessions using Citrix cmdlets or fallback methods
- **FSlogix Integration**: Automatically detects FSlogix version and analyzes profile VHD storage locations
- **Windows Update Monitoring**: Checks for pending Windows updates and critical security patches
- **Disk Performance Analysis**: Measures disk queue length for storage drives hosting user profiles
- **Storage Capacity Monitoring**: Tracks disk space usage with configurable thresholds
- **I/O Performance Diagnostics**: Measures read/write performance and latency for both local and network storage
- **Resource Usage Tracking**: Monitors CPU and RAM usage with per-user calculations
- **Automated Recommendations**: Provides actionable insights for performance optimization
- **Color-coded Alerts**: Visual indicators for OK/WARNING/CRITICAL status levels

**Thresholds**:
- Disk Queue Length: OK (< 2.0), WARNING (2.0-5.0), CRITICAL (> 5.0)
- Storage Usage: OK (< 80%), WARNING (80-90%), CRITICAL (> 90%)
- CPU per User: WARNING (> 80%), CRITICAL (> 100%)
- Memory per User: WARNING (> 1GB), CRITICAL (> 2GB)
- I/O Performance: Read/Write < 50 MB/s (Red), 50-100 MB/s (Yellow), > 100 MB/s (Green)
- I/O Latency: > 20ms (Red), 10-20ms (Yellow), < 10ms (Green)
- Windows Updates: > 10 pending (Red), 5-10 pending (Yellow), < 5 pending (Green)

**Notes**:
- Designed specifically for Citrix VDA servers with FSlogix
- Includes fallback methods for environments without Citrix PowerShell SDK
- Requires administrative privileges for performance counter access
- Compatible with Windows Server 2016+ and PowerShell 5.1+
- Can be run locally or against remote servers
- I/O testing for UNC paths creates temporary test files (1MB) that are automatically cleaned up
- Output can be redirected to log files for automated monitoring
- Windows Update checking requires Windows Update service access

### CloudSignInMgr.ps1 (Block 365 Sign-in)

**Description**: A PowerShell GUI application for managing Microsoft 365 cloud sign-in access for Active Directory users. This tool allows administrators to selectively block or allow cloud sign-in for users while maintaining their local Active Directory authentication. It works in conjunction with Azure AD Connect synchronization rules by setting the `msDS-cloudExtensionAttribute10` attribute to "BlockCloudSignIn" to disable cloud access.

**Parameters**:
- None (interactive GUI application)

**Usage Examples**:
- Run the script: `.\Block 365 Sign-in\CloudSignInMgr.ps1`
- Search and select users from the grid
- Use "Block Cloud Sign-In" to disable Microsoft 365 access
- Use "Unblock Cloud Sign-In" to restore Microsoft 365 access
- Optionally trigger Azure AD Connect synchronization to apply changes immediately

**Features**:
- **User Search and Selection**: Search users by name or username with real-time filtering
- **Bulk Operations**: Select multiple users for batch blocking/unblocking operations
- **Visual Status Display**: Shows current cloud sign-in status (Allowed/Blocked) for each user
- **Confirmation Prompts**: Safety confirmations before making changes
- **Sync Integration**: Optional Azure AD Connect synchronization trigger after changes
- **Error Handling**: Comprehensive error reporting for failed operations

**Prerequisites**:
- Active Directory PowerShell module
- Domain Administrator or equivalent permissions
- Azure AD Connect installed (for synchronization)
- Windows Forms assemblies (included in script)

**Notes**:
- Changes take effect after Azure AD Connect synchronization cycle
- Local Active Directory sign-in remains unaffected
- Requires appropriate AD permissions to modify user attributes
- Compatible with Windows Server 2016+ and PowerShell 5.1+
- Synchronization rule configuration required (see script folder README for details)

## LocalAdminManager

**Description**: A PowerShell script for managing the local Administrators group on Windows computers by adding or removing domain users and groups.

**Parameters**:
- `-Action <string>` (Required): Action to perform ('Add' or 'Remove').
- `-Member <string>` (Required): Domain user or group in 'DOMAIN\Username' format.
- `-ComputerName <string>` (Optional): Target computer name (defaults to localhost).

**Usage Examples**:
- Add user locally: `.\LocalAdminManager\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"`
- Remove group remotely: `.\LocalAdminManager\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\DomainAdmins" -ComputerName "RemotePC01"`

**Notes**:
- Requires administrator privileges.
- Supports local and remote computer management.
- Domain users/groups must exist in Active Directory.

# SMB Diagnostic & Drive Mapping Script

**Description:**  
This PowerShell script diagnoses SMB connectivity, detects protocol versions, tests access, lists files, and maps network drives between Windows clients (Windows 7–11) and Windows Servers (2008–2022).

## Features

- ✅ Test TCP connectivity to SMB port 445
- ✅ Check active SMB sessions
- ✅ Detect SMB protocol version (SMB1/2/3)
- ✅ Test folder access and permissions
- ✅ List files and folders in the target share
- ✅ Map network drives safely
- ✅ Color-coded output:
  - **Green** = Pass
  - **Yellow** = Warning
  - **Red** = Fail/Error

## Requirements

- PowerShell 3.0+
- Windows clients: Windows 7 – 11
- Windows servers: Server 2008 – 2022
- Network access to the SMB share (TCP 445)
- Permissions to access the target share

> SMB dialect detection requires Windows 8 / Server 2012+. Legacy servers fallback to `net use`.

## Installation & Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/chihlasm/powershell-script-collection.git
   cd powershell-script-collection
**Configure the script (SMB_Diagnostic.ps1) by editing the variables:**

$ServerIP   = "xxx.xxx.xxx.xxx"   # Replace with your SMB server IP
$ShareName  = "folder"            # Replace with your share name
$DriveLetter = "Z"                # Desired local drive letter


**Run the script in PowerShell:**

powershell.exe -ExecutionPolicy Bypass -File .\SMB_Diagnostic.ps1


**The script performs the following steps:**

Step 1: Test TCP connectivity to SMB port 445 
Step 2: Check existing SMB sessions on the client and server
Step 3: Detect SMB protocol version (SMB1/2/3)
Step 4: Test folder access and permissions
Step 5: List files and folders in the share
Step 6: Map network drive to the chosen letter

**Example Output**
=== Step 1: Test TCP connectivity on port 445 ===
[PASS] TCP connection to SMB port 445 successful.

=== Step 2: Check existing SMB sessions ===
[INFO] Active SMB sessions found:
ServerName    ShareName UserName  Dialect
----------    --------- --------  -------
192.168.1.10  Share1    DOMAIN\User  3.1.1

=== Step 3: Detect SMB protocol version ===
[PASS] SMB2/3 in use — modern protocol, Explorer should work.

=== Step 4: Test folder access ===
[PASS] Access to \\192.168.1.10\Share1 successful.

=== Step 5: List files/folders ===
[PASS] Files/folders in \\192.168.1.10\Share1:
Name           Length LastWriteTime
----           ------ -------------
File1.txt      1024   9/23/2025 8:45 AM
Folder1        0      9/22/2025 3:12 PM

=== Step 6: Map network drive Z: ===
[PASS] Mapped \\192.168.1.10\Share1 to drive Z:

=== Diagnostic Complete ===

Notes

SMB1 detected → Consider enabling SMB2/3 on the server to prevent Explorer hangs.

Admin rights not required for diagnostics; may be required for persistent drives.

Fully safe for internal networks; changes are limited to the mapped share.

## FolderPermissionManager

**Description**: A PowerShell script for managing permissions on folders and their sub-folders. It allows taking ownership of sub-folders, reviewing current permissions, and replicating permissions from the top-level folder to all sub-folders.

**Parameters**:
- `-Path <string>` (Optional): The path to the top-level folder. If not provided, the script will prompt for it.

**Usage Examples**:
- Run with path: `.\FolderPermissionManager\FolderPermissionManager.ps1 -Path "C:\SharedFolder"`
- Run without path (prompts): `.\FolderPermissionManager\FolderPermissionManager.ps1`

**Notes**:
- Requires administrative privileges to modify ownership and permissions.
- Run the script from an elevated PowerShell session.
- Taking ownership uses `icacls` and may fail without proper permissions.
- Replicating permissions adds the top-level folder's access rules to sub-folders without removing existing permissions (ownership is taken at the beginning).
- Test on a small folder first to understand the behavior.

## HideFromGal

**Description**: A collection of PowerShell scripts for managing user visibility in the Exchange Online Global Address List (GAL) using Entra Connect synchronization rules. Provides both one-time setup and ongoing management capabilities for hiding users from GAL.

**Scripts**:
- **HideFromGal-RuleBuilder.ps1**: Creates a custom Entra Connect synchronization rule that maps the `msDS-cloudExtensionAttribute1` AD attribute to `msExchHideFromAddressLists` in Exchange Online.
- **HideFromGAL.ps1**: GUI-based tool for managing GAL visibility by setting/clearing the `msDS-cloudExtensionAttribute1` attribute on AD user accounts.

**Prerequisites**:
- Entra Connect server with Azure AD Connect installed and ADSync module available
- Domain-joined administrative workstation with Active Directory module
- Domain Admin or equivalent permissions for AD modifications
- Administrative access to Entra Connect server for rule creation

**Usage**:
1. **Setup (One-time)**: Run `HideFromGal-RuleBuilder.ps1` on the Entra Connect server to create the synchronization rule.
2. **Management (Ongoing)**: Run `HideFromGAL.ps1` on a domain workstation to hide/unhide users from GAL.

**Features**:
- Automatic domain detection and connector lookup
- GUI with search, bulk selection, and confirmation prompts
- Manual synchronization triggering
- Comprehensive logging to `C:\Temp\`
- Error handling and user-friendly messages

**Notes**:
- Run rule builder only once per Entra Connect server/domain
- GUI tool supports search, select all/deselect all, and bulk operations
- Changes take effect after Entra Connect synchronization cycle
- Uses cloud extension attribute that doesn't conflict with on-premises AD
- Test in non-production environment first
