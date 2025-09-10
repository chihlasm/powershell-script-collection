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
