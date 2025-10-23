# FileCopyMoveGUI.ps1

**Description**: A user-friendly PowerShell script that provides a graphical user interface (GUI) for performing advanced file and folder copy or move operations with Robocopy-like features. The interface allows users to select source and destination directories, configure mirroring options, set exclusions, and monitor progress in real-time.

**Parameters**:
- None (interactive Windows Forms GUI - no command-line parameters)

**GUI Features**:
- **Browse Buttons**: Folder browser dialogs for selecting source and destination paths
- **Operation Selection**: Radio buttons to choose between Copy and Move operations
- **Recursive Option**: Checkbox to include subdirectories (enabled by default)
- **Mirror Mode**: Checkbox to delete extra files in destination not present in source
- **Exclude Patterns**: Text field for specifying file/folder exclusion patterns (semicolon-separated)
- **Progress Tracking**: Visual progress bar and real-time log display
- **Cancel Support**: Button to cancel operations mid-execution
- **Error Handling**: Comprehensive error reporting with temporary file cleanup

**Usage Examples**:
- Launch GUI: `.\FileCopyMoveGUI.ps1`
- Copy operation with default settings: Select source folder, destination folder, ensure "Copy" is selected, click Start
- Mirror backup: Select "Recursive", check "Mirror", set exclusions like "*.tmp;*.log", click Start
- Clean move operation: Select "Move", enable recursive, exclude system files, click Start

**Advanced Options**:
- **Exclusion Patterns**: Use wildcards like "*.tmp", "*.log", "temp_*" separated by semicolons
- **Robocopy Integration**: Leverages robocopy.exe for efficient large-file transfers
- **Mirror Mode**: Synchronizes destination with source, removing files not in source (destructive)
- **Work-Around Support**: No Job Header/Summary output (NJH/NJS) for clean progress monitoring

**Requirements**:
- **Operating System**: Windows 7 / Server 2008 R2 or higher
- **PowerShell Version**: Windows PowerShell 3.0 or higher (.NET Framework 4.5+)
- **Administrative Privileges**: Not required but recommended for system directories
- **Robocopy**: Built into Windows (automatically available)
- **Windows Forms**: Included in all supported Windows versions

**Supported Operations**:
- **File Copy**: Standard recursive copying with directory creation
- **File Move**: Atomic move operation preserving file attributes
- **Selective Copy/Move**: Exclude specific files/folders with patterns
- **Directory Mirroring**: Synchronize destination structure with source (including deletions)
- **Large File Handling**: Automatic handling of files larger than 2GB
- **Permission Preservation**: Maintains file ownership and security permissions where possible

**Progress and Monitoring**:
- **Real-Time Progress Bar**: Visual feedback on operation progress
- **Detailed Log Output**: Complete robocopy output displayed in scrollable text box
- **Error Reporting**: Temporary file redirection for clean error capture
- **Operation Cancellation**: Graceful stopping of background robocopy processes
- **Success/Failure Feedback**: Clear status messages and error details

**Safety Features**:
- **Temporary Files Management**: Automatic cleanup of temp files on completion/termination
- **Error Boundary Handling**: Continues processing despite individual file failures
- **Confirmation Prompts**: Should not be used without pre-flight validation
- **Read-Only Safety**: No modifications made to source files during preview operations

**Performance Considerations**:
- **Large File Optimization**: Uses robocopy's multi-threaded transfer for large files
- **Network Optimization**: Automatic adjustment for network copy operations
- **Memory Efficiency**: Minimal RAM usage through pipelined robocopy integration
- **Cancellation Responsiveness**: Immediate termination capability without data corruption

**Common Use Cases**:
- **Backup Operations**: Periodic file backup with mirror mode enabled
- **Content Migration**: Moving large amounts of data between locations
- **Folder Synchronization**: Keeping multiple locations in sync
- **Archival Processes**: Moving old files to slower storage with selective exclusions
- **Deployment Scripts**: Automated copy/move operations for software deployment

**Notes**:
- **Confirmation Dialogs**: Will prompt for confirmation before operations that cannot be undone
- **Temporary Storage**: Uses system temp directory for log redirection
- **Process Management**: Background robocopy execution with clean termination
- **Compatible Filesystems**: NTFS, SMB shares, local and network drives
- **Cross-Volume Operations**: Supports operations across different disks/partitions
- **Security Context**: Runs under user security context (elevate for system areas)
- **No Dependencies**: Relies only on built-in Windows components
- **Localization**: Inherits robocopy output in the system locale
- **Audit Trail**: Save operation logs for compliance and troubleshooting
- **Scalability**: Suitable for operations from KB to TB scale transfers
