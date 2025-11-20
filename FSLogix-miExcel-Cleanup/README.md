# FSLogix miExcel Cleanup Script

This PowerShell script removes miExcel add-in installations from FSLogix user profiles in virtual desktop environments.

## Overview

When miExcel needs to be uninstalled or removed from user profiles, this script automates the cleanup process across all FSLogix VHD/VHDX profile containers. The script:

- Mounts each user profile VHDX file read-write
- Removes miExcel files from standard locations
- Cleans miExcel registry entries from the user hive
- Unmounts and compacts the VHDX files to reclaim space

## Quick Start

1. Update the configuration variables in the script:

   ```powershell
   $ProfileShare   = "\\FILESERVER\FSLogixProfiles"  # Path to FSLogix profile share
   $MountBase      = "C:\FSLogixMount"               # Local mount directory
   $LogFile        = "C:\Temp\miExcel-Cleanup.log"   # Log file location
   ```

2. Run the script with administrator privileges:

   ```powershell
   .\Remove-miExcelFromFSLogixProfiles.ps1
   ```

3. Monitor the log file for progress and any errors.

## What Gets Removed

### Files and Folders

The script removes miExcel-related files from these standard Excel add-in locations within each profile:

**Standard Excel Add-in Locations:**
- `%APPDATA%\Microsoft\AddIns\miExcel*` (Excel add-in files - .xla, .xlam, .dll)
- `%APPDATA%\Microsoft\Excel\XLSTART\miExcel*` (Excel startup files)

**Application Data:**
- `%APPDATA%\miExcel` (Roaming profile data and settings)
- `%LOCALAPPDATA%\miExcel` (Local profile data and temp files)
- `%USERPROFILE%\Documents\miExcel` (User documents and templates)

**Additional Common Locations:**
- `%APPDATA%\Roaming\Microsoft\AddIns\miExcel*` (Alternative add-ins location)
- `%LOCALAPPDATA%\Microsoft\Office\miExcel*` (Office-specific local data)

### Registry Entries

The script loads each profile's `NTUSER.DAT` registry hive and removes standard Excel add-in registry keys:

**Excel Add-in Registration:**
- `HKU\FSLogixTemp\Software\Microsoft\Office\Excel\Addins\miExcel*` (COM add-in registration)
- `HKU\FSLogixTemp\Software\Microsoft\Office\16.0\Excel\Addins\miExcel*` (Version-specific registration)

**Application Settings:**
- `HKU\FSLogixTemp\Software\miExcel` (miExcel software settings and preferences)
- `HKU\FSLogixTemp\Software\Microsoft\Office\Excel\Options` (Excel options containing miExcel references)

**Additional Registry Locations:**
- `HKU\FSLogixTemp\Software\Classes\CLSID\{miExcel-CLSID}` (COM class registration)
- `HKU\FSLogixTemp\Software\Microsoft\Office\Excel\Recent Files` (Recent files containing miExcel)

## Script Components

### Configuration Section

```powershell
$ProfileShare   = "\\FILESERVER\FSLogixProfiles"  # UNC path to profile share
$MountBase      = "C:\FSLogixMount"               # Local directory for mounting
$LogFile        = "C:\Temp\miExcel-Cleanup.log"   # Log file path
```

### Functions

**`Log($msg)`**

- Writes timestamped messages to the log file
- All operations are logged for auditing and troubleshooting

**`Clean-UserVHDX($VHDPath)`**

- Main cleanup function that processes individual VHDX files
- Handles mounting, cleanup, unmounting, and compaction
- Includes error handling and logging

### Main Execution

The script automatically discovers all `Profile_*.vhdx` files in the profile share and processes them sequentially.

## Requirements

- Windows Server with Hyper-V role (for VHD mounting) or Windows 10/11 Pro/Enterprise
- Administrator privileges
- Access to FSLogix profile share
- PowerShell 5.1 or later
- Sufficient disk space for mounting VHDX files

## Usage Examples

### Basic Usage

```powershell
# Run with default configuration
.\Remove-miExcelFromFSLogixProfiles.ps1
```

### Custom Configuration

Edit the script variables before running:

```powershell
$ProfileShare = "\\MyServer\Profiles$"
$MountBase = "D:\Mount"
$LogFile = "C:\Logs\miExcel-cleanup.log"
```

### Processing Specific Profiles

To process only specific VHDX files, modify the main section:

```powershell
# Instead of automatic discovery
$vhds = Get-ChildItem "$ProfileShare\Profile_User123.vhdx"

# Or filter by date/modified time
$vhds = Get-ChildItem "$ProfileShare\*.vhdx" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-30)
}
```

## Log File Output

The script creates a detailed log file showing:

```
2025-11-04 21:53:33 === miExcel FSLogix Cleanup Started ===
2025-11-04 21:53:33 Processing user123 -> \\FILESERVER\FSLogixProfiles\Profile_user123.vhdx
2025-11-04 21:53:34   Mounted as F:
2025-11-04 21:53:34     Deleted: F:\AppData\Roaming\miExcel
2025-11-04 21:53:34     Deleted registry: HKU\FSLogixTemp\Software\miExcel
2025-11-04 21:53:35   Unmounted
2025-11-04 21:53:40   Compacted VHDX
2025-11-04 21:53:40 === Cleanup Completed ===
```

## Safety Features

- **Read-Write Mounting**: Profiles are mounted read-write to allow modifications
- **Error Handling**: Failed operations are logged but don't stop processing other profiles
- **Automatic Unmounting**: VHDX files are always unmounted, even after errors
- **Registry Safety**: Uses temporary hive name (`HKU\FSLogixTemp`) to avoid conflicts
- **Compaction**: Automatically compacts VHDX files to reclaim deleted space

## Troubleshooting

### Mount Failed

**Error**: "Failed to get drive letter"

**Solutions**:
- Ensure Hyper-V role is installed (`Install-WindowsFeature -Name Hyper-V`)
- Check available drive letters
- Verify VHDX file is not corrupted
- Run as Administrator

### Registry Load Failed

**Error**: Registry operations fail

**Solutions**:
- Verify `NTUSER.DAT` exists in the profile
- Check file permissions on the profile share
- Ensure no other processes have the registry hive loaded

### Access Denied

**Error**: Cannot access profile share or VHDX files

**Solutions**:
- Run PowerShell as Administrator
- Verify network connectivity to profile share
- Check NTFS permissions on the share
- Ensure account has read/write access to profiles

### Disk Space Issues

**Error**: Insufficient space for mounting/compaction

**Solutions**:
- Clear space on the mount drive (`$MountBase`)
- Process profiles in smaller batches
- Skip compaction if space is critical (comment out `Optimize-VHD`)

## Performance Considerations

- **Mounting Overhead**: Each VHDX mount/unmount takes 5-15 seconds
- **Compaction Time**: VHDX optimization can take several minutes for large profiles
- **Network Latency**: Remote profile shares may slow down the process
- **Concurrent Access**: Ensure no users are actively using profiles during cleanup

## Best Practices

1. **Test First**: Run on a single test profile before processing all profiles
2. **Backup Profiles**: Create backups of important profiles before cleanup
3. **Monitor Logs**: Review log files for errors or unexpected deletions
4. **Schedule Wisely**: Run during maintenance windows when users are offline
5. **Verify Results**: Spot-check cleaned profiles to ensure miExcel is removed

## Security Considerations

- Requires domain administrator or equivalent privileges
- Access to user profile data should be logged and audited
- Store log files securely as they contain user information
- Delete log files after verification and retention period

## Related Scripts

- **FSLogix Profile Backup**: Backup user settings before profile operations
- **Citrix VDA Diagnostics**: Monitor FSLogix storage and profile health
- **Remove Orphaned FSLogix Temp Profiles**: Clean up temporary profile artifacts

## License

This script is provided as-is for operational use in virtual desktop environments. Test thoroughly in your environment before production deployment.
