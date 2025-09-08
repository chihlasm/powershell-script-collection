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
