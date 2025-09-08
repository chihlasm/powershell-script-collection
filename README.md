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
