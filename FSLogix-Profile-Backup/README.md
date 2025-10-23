# FSLogix Profile Backup Scripts

This collection of PowerShell scripts helps backup and restore important personal settings when rebuilding FSLogix user profiles in virtual desktop environments.

## Overview

When FSLogix profiles need to be rebuilt or migrated, important user customizations are often lost. This collection of scripts backs up:

- Windows Explorer Quick Access shortcuts
- Google Chrome bookmarks
- Microsoft Edge bookmarks
- Display and scaling settings
- Taskbar shortcuts and settings
- Browser auto-fill password export instructions

## Quick Start

1. Run the main backup script:

   ```powershell
   .\Backup-FSLogixProfile.ps1
   ```

2. Follow the browser password export instructions manually (if needed).

3. The backup will be saved in a timestamped folder and optionally as a ZIP archive.

## Scripts Included

### Main Orchestration Script

**`Backup-FSLogixProfile.ps1`**

- Main script that runs all individual backups
- Creates timestamped backup directories
- Generates ZIP archives
- Creates backup manifests
- **Optionally mounts FSLogix VHD/VHDX profiles for offline backup**
- Automatically unmounts profiles after backup completion

### Individual Backup Scripts

**`Backup-QuickAccessShortcuts.ps1`**

- Backs up Windows Explorer Quick Access shortcuts
- Exports registry key: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Quick Access`
- Output: `.reg` file for easy restoration

**`Backup-ChromeBookmarks.ps1`**

- Backs up Google Chrome bookmarks
- Copies bookmarks from Chrome's default profile
- Output: Backup copy of bookmarks file

**`Backup-EdgeBookmarks.ps1`**

- Backs up Microsoft Edge bookmarks
- Copies bookmarks from Edge's default profile
- Output: Backup copy of bookmarks file

**`Backup-DisplaySettings.ps1`**

- Backs up display and scaling settings
- Exports multiple registry keys:
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Display`
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Dpi`
  - `HKCU:\Control Panel\Desktop*`
- Output: Combined `.reg` file

**`Backup-TaskbarSettings.ps1`**

- Backs up taskbar shortcuts and settings
- Exports registry keys for taskbar configuration and pinned items
- Output: Combined `.reg` file

**`Backup-BrowserPasswords.ps1`**

- Provides instructions for browser password export
- Cannot automatically export passwords due to security restrictions
- Opens browser settings pages for manual export

### Main Restore Orchestration Script

**`Restore-FSLogixProfile.ps1`**

- Main script that runs all individual restorations
- Automatically finds the most recent backup
- Supports selective restoration (skip registry/browser)
- Provides status and next steps guidance

### Individual Restore Scripts

**`Restore-QuickAccessShortcuts.ps1`**

- Restores Windows Explorer Quick Access shortcuts from .reg file
- Imports registry keys to HKCU

**`Restore-ChromeBookmarks.ps1`**

- Restores Google Chrome bookmarks from backup file
- Copies bookmarks to Chrome profile directory
- Detects if Chrome is running

**`Restore-EdgeBookmarks.ps1`**

- Restores Microsoft Edge bookmarks from backup file
- Copies bookmarks to Edge profile directory
- Detects if Edge is running

**`Restore-DisplaySettings.ps1`**

- Restores display and scaling settings from .reg file
- Imports registry keys for display configuration

**`Restore-TaskbarSettings.ps1`**

- Restores taskbar shortcuts and settings from .reg file
- Imports registry keys for taskbar configuration

## Usage

### Running Backups

#### Full Backup (Recommended)

```powershell
# Run from this directory
.\Backup-FSLogixProfile.ps1

# Or specify custom backup location
.\Backup-FSLogixProfile.ps1 -BackupPath "C:\Backup\Profiles"
```

#### Individual Backups

```powershell
# Backup only Quick Access shortcuts
.\Backup-QuickAccessShortcuts.ps1 -OutputPath "C:\Backup\quickaccess.reg"

# Backup only Chrome bookmarks
.\Backup-ChromeBookmarks.ps1 -OutputPath "C:\Backup\chrome_bookmarks.bak"
```

#### FSLogix Profile Mounting (Offline Backup)

```powershell
# Mount and backup from FSLogix VHD/VHDX file
.\Backup-FSLogixProfile.ps1 -MountProfile -FSLogixProfile "C:\FSLogixProfiles\User123.vhd"

# Specify both profile path and backup location
.\Backup-FSLogixProfile.ps1 -MountProfile -FSLogixProfile "\\Server\Share\UserProfiles\User123.vhdx" -BackupPath "C:\Backups"
```

### Restoring Backups

#### Full Automated Restore (Recommended)

After logging into the new user profile, run the restore script:

```powershell
# Restore from most recent backup
.\Restore-FSLogixProfile.ps1

# Restore from specific backup
.\Restore-FSLogixProfile.ps1 -BackupPath "C:\Backups\Backup_20251023_144130"

# Skip certain types of restorations if needed
.\Restore-FSLogixProfile.ps1 -SkipRegistry  # Skip display/taskbar/registry settings
.\Restore-FSLogixProfile.ps1 -SkipBrowser   # Skip bookmarks and passwords
```

#### Manual Restoration Options

##### Registry Files (.reg)

**Option 1: Automated Script**

```powershell
# Restore specific registry settings
.\Restore-QuickAccessShortcuts.ps1 -BackupPath "C:\Backup\QuickAccessBackup.reg"
.\Restore-DisplaySettings.ps1 -BackupPath "C:\Backup\DisplaySettingsBackup.reg"
.\Restore-TaskbarSettings.ps1 -BackupPath "C:\Backup\TaskbarSettingsBackup.reg"
```

**Option 2: Manual Double-Click**

1. Double-click the `.reg` file
2. Click "Yes" when prompted to merge with registry
3. Log off and back on for changes to take effect

##### Browser Bookmarks

**Option 1: Automated Script**

```powershell
# Restore browser bookmarks
.\Restore-ChromeBookmarks.ps1 -BackupPath "C:\Backup\ChromeBookmarks.bak"
.\Restore-EdgeBookmarks.ps1 -BackupPath "C:\Backup\EdgeBookmarks.bak"
```

**Option 2: Manual Copy**

1. Close Chrome/Edge
2. Copy the backup file over the original:
   - Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Bookmarks`
   - Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks`
3. Restart browser

##### Browser Passwords

1. Open Chrome/Edge settings (chrome://settings/passwords or edge://settings/passwords)
2. Look for "Import" option
3. Select the exported CSV file from the backup
4. Follow prompts to complete import

## Parameters

### Backup-FSLogixProfile.ps1

- `-BackupPath`: Root directory for backups (default: ".\FSLogixBackups")
- `-CreateZip`: Create ZIP archive (default: true)
- `-FSLogixProfile`: Path to FSLogix VHD/VHDX file to mount for offline backup
- `-MountProfile`: Switch to enable mounting of FSLogix profile (requires -FSLogixProfile)

### Individual Scripts

- `-OutputPath`: Path for output file (varies by script)

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges recommended
- Google Chrome and/or Microsoft Edge installed (for browser backups)

## Limitations

### Browser Passwords

Due to security restrictions, browser passwords cannot be automatically exported. The script provides instructions for manual export through the browser interface.

### Profile-Specific Locations

Scripts assume default browser profile locations. For non-default profiles, you may need to modify the scripts.

### Cross-Machine Compatibility

Some settings (especially display settings) may not restore correctly on different hardware configurations.

## Security Considerations

- Registry exports contain system configuration data
- Browser password exports contain sensitive information
- Store backups securely and delete when no longer needed
- Test restoration procedures on non-production systems first

## Troubleshooting

### Registry Export Failed

- Run PowerShell as Administrator
- Some registry keys may not exist on all systems

### Browser Not Found

- Ensure Chrome/Edge is installed
- Check installation paths in the scripts

### ZIP Creation Failed

- Ensure PowerShell has write permissions to the backup location
- Check available disk space

## Contributing

To add additional backup items:

1. Create a new script following the existing pattern
2. Add the script call to `Backup-FSLogixProfile.ps1`
3. Update this README with documentation
4. Test thoroughly before production use

## License

These scripts are provided as-is for educational and operational use. Test in your environment before deploying in production.
