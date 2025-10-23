# DeleteOldFolders.ps1

**Description**: A comprehensive PowerShell script that recursively searches for and deletes folders ending with '.old' that are older than a specified number of days. This utility is designed for automated cleanup of temporary, backup, or obsolete directories to reclaim disk space while maintaining safety through various protection mechanisms.

**Parameters**:
- `-DrivePath <string>` (Required): The root directory path to scan for old folders (e.g., "C:\Temp", "\\Server\Share").
- `-DaysOld <int>` (Optional, default: 14): The age threshold in days - folders older than this will be considered for deletion.
- `-WhatIf <switch>` (Optional): Switch to simulate the deletion process without actually removing any folders.
- `-SkipConfirmation <switch>` (Optional): Switch to skip the confirmation prompt before performing deletions.
- `-LogFile <string>` (Optional): Path to a log file where all actions, results, and errors are recorded.

**Usage Examples**:
- Basic one-time cleanup: `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30`
- Simulation mode for testing: `.\DeleteOldFolders.ps1 -DrivePath "C:\Temp" -DaysOld 30 -WhatIf`
- Automated with logging: `.\DeleteOldFolders.ps1 -DrivePath "C:\Backups" -DaysOld 90 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`
- Windows Task Scheduler: Configure as daily task with `-DrivePath "C:\Temp" -DaysOld 7 -LogFile "C:\Logs\cleanup.log" -SkipConfirmation`

**Features**:
- **Recursive Folder Enumeration**: Uses .NET Directory.EnumerateDirectories for better performance and long path support
- **Age Calculation**: Determines folder age using the older of LastWriteTime or CreationTime for conservative deletion
- **Safety Checks**: Prevents deletion of folders that can't be analyzed or lack proper timestamps
- **Comprehensive Logging**: All operations logged with timestamps when LogFile parameter is specified
- **Error Handling**: Gracefully handles access-denied directories and other filesystem errors
- **Interactive Confirmation**: Prompts for user confirmation unless SkipConfirmation is used
- **WhatIf Support**: Preview mode shows what would be deleted without making changes
- **Long Path Support**: Uses .NET Directory.Delete method for paths longer than 260 characters

**Requirements**:
- Windows PowerShell 3.0 or higher
- Appropriate permissions to delete folders in the target paths
- Network access for UNC paths (\\server\share)
- Read/write permissions for log file location (if used)

**Notes**:
- Only deletes folders ending with '.old' extension (case-sensitive)
- Determines folder age conservatively (uses older of Creation or Modification time)
- Continues processing even if some directories cannot be accessed
- Uses .NET methods for better long path handling and performance
- Always test with -WhatIf first to understand what will be deleted
- Can be safely used in production with proper logging and testing
- No dependencies on third-party modules required
- Compatible with Windows file servers and NAS devices
