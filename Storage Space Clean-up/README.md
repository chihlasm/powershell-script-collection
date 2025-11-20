# Citrix VDA Storage Cleanup

A comprehensive PowerShell script for reclaiming storage space on Citrix VDA servers with FSLogix profile containers.

## Overview

This script safely removes temporary files, caches, and orphaned FSLogix ghost profiles from Citrix VDA servers. It targets common storage consumers while protecting active user sessions and critical system files.

## Features

- **FSLogix Ghost Profile Detection** - Identifies and removes orphaned profiles not registered in the system or Active Directory
- **Multi-location Cleanup** - Cleans Windows temp, user caches, browser data, Citrix caches, and more
- **Active Session Protection** - Automatically skips currently logged-in users
- **WhatIf Support** - Preview all deletions before executing
- **Detailed Logging** - Complete audit trail of all actions
- **Disk Space Reporting** - Before and after space comparison

## Requirements

- Windows Server with Citrix VDA
- PowerShell 5.1 or later
- Administrator privileges
- FSLogix (optional, for ghost profile cleanup)

## Installation

1. Copy `Cleanup-CitrixVDAStorage.ps1` to your scripts directory
2. Ensure execution policy allows running scripts:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Preview Mode (Recommended First Run)

```powershell
.\Cleanup-CitrixVDAStorage.ps1 -WhatIf
```

### Standard Cleanup

```powershell
.\Cleanup-CitrixVDAStorage.ps1
```

### Custom Age Threshold

Clean files older than 3 days instead of the default 7:

```powershell
.\Cleanup-CitrixVDAStorage.ps1 -DaysOld 3
```

### Custom Log Location

```powershell
.\Cleanup-CitrixVDAStorage.ps1 -LogPath "D:\Logs\Cleanup"
```

### Skip FSLogix Cleanup

If you only want to clean temp files without touching profiles:

```powershell
.\Cleanup-CitrixVDAStorage.ps1 -SkipFSLogixCleanup
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-WhatIf` | Switch | False | Preview deletions without removing files |
| `-LogPath` | String | `C:\Logs\StorageCleanup` | Directory for log files |
| `-DaysOld` | Int | 7 | Age threshold in days for temp file cleanup |
| `-SkipFSLogixCleanup` | Switch | False | Skip ghost profile detection and removal |

## What Gets Cleaned

### FSLogix Ghost Profiles
- Profiles not registered in Windows profile list
- Profiles with no corresponding AD or local user
- Profiles not accessed in 30+ days

### Windows System
- `C:\Windows\Temp`
- `C:\Windows\Logs\CBS`
- `C:\Windows\SoftwareDistribution\Download`
- `C:\Windows\Prefetch`
- Windows Error Reporting files
- Memory dumps (MEMORY.DMP, Minidump)
- Old Windows installations (Windows.old)

### User Profiles
- AppData\Local\Temp
- Internet cache files
- Crash dumps
- Terminal Server Client cache

### Browser Caches
- Google Chrome (Cache, Code Cache, GPUCache)
- Microsoft Edge (Cache, Code Cache, GPUCache)
- Mozilla Firefox (cache2)

### Citrix-Specific
- GroupPolicy History
- Machine Identity Service logs
- CSE Cache
- Self-Service icons and cache

### Other
- IIS logs (if present)
- Event logs (non-critical)
- Font cache
- MSI installer patch cache (90+ days old)
- All recycle bins

## Safety Features

1. **Administrator Required** - Script will not run without elevation
2. **Active Session Detection** - Uses `query user` to identify logged-in users
3. **Age-Based Filtering** - Only removes files older than specified threshold
4. **WhatIf Support** - Full preview capability before any deletion
5. **Error Handling** - Continues on errors, logs all failures
6. **Audit Logging** - Timestamped log of all operations

## Log Output

Logs are saved to `C:\Logs\StorageCleanup\StorageCleanup_YYYYMMDD_HHMMSS.log`

Example log entries:
```
[2025-01-15 10:30:45] [INFO] Citrix VDA Storage Cleanup Script Started
[2025-01-15 10:30:46] [INFO] C: - Total: 100GB, Free: 15GB (15%)
[2025-01-15 10:30:47] [SUCCESS] Removed: C:\Users\OldUser (2500MB)
[2025-01-15 10:35:12] [SUCCESS] Total Space Reclaimed: 8500MB
```

## Scheduling

To run weekly via Task Scheduler:

```powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"C:\Scripts\Cleanup-CitrixVDAStorage.ps1`""

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "Citrix VDA Storage Cleanup" `
    -Action $Action -Trigger $Trigger -Principal $Principal
```

## Troubleshooting

### Script won't run
- Verify you're running as Administrator
- Check execution policy: `Get-ExecutionPolicy`

### Ghost profiles not detected
- Ensure FSLogix is installed on the VDA
- Verify profiles have FSLogix markers in AppData\Local\FSLogix

### Files not being deleted
- Check the `-DaysOld` parameter value
- Verify files aren't locked by running processes
- Review log file for specific errors

### Active users being cleaned
- The script queries active sessions via `query user`
- Ensure Remote Desktop Services are running

## Best Practices

1. **Always run with `-WhatIf` first** on new servers
2. **Schedule during maintenance windows** when user sessions are minimal
3. **Monitor disk space trends** to adjust `-DaysOld` parameter
4. **Review logs regularly** for recurring errors
5. **Test in non-production** before deploying to production VDAs

## License

This script is provided as-is for use in managing Citrix VDA environments.
