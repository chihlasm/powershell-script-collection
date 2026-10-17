# Folder Permission Manager

Tools for managing NTFS folder permissions, ownership, and ACLs. Includes a command-line script and a browser-based GUI.

## Scripts

### FolderPermissionManager-GUI.ps1 (Web GUI)

A browser-based interface for managing folder permissions across local drives and network shares. Runs a local web server and opens an interactive dashboard.

**Features:**
- Browse all local drives and network shares in a folder tree
- View ownership, inheritance status, and full ACL entries for any folder
- Take ownership (single folder or recursive)
- Add and remove permission entries (identity, rights, allow/deny)
- Replicate parent permissions to selected child folders
- Export permissions report as CSV
- Dark/light theme toggle

**Usage:**

```powershell
# Launch with defaults (opens browser automatically)
.\FolderPermissionManager-GUI.ps1

# Custom port, don't auto-open browser
.\FolderPermissionManager-GUI.ps1 -Port 9090 -NoBrowserOpen
```

Press Ctrl+C in the PowerShell window to stop the server.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Port` | `8271` | TCP port for the local web server (1024-65535) |
| `-NoBrowserOpen` | — | Don't automatically open the browser on launch |
| `-LogFolder` | `Logs` next to the script | Where permission backups and the change log go (see below) |

### Changes are backed up and logged

Before the GUI changes the permissions of a folder or of selected files, it saves the
current permissions. **If it cannot save them, it changes nothing** and the status bar says
why. This covers:

- Add permission and Remove permission (folder, or selected files)
- Take ownership of this folder only, or of selected files
- Copy permissions to other folders, when "apply recursively" is not ticked

The two "all subfolders and files" options (take ownership recursively, copy permissions
recursively) are **not backed up or logged yet**.

After each change the status bar says what was done and where it was logged, for example
`Added Allow Modify for CONTOSO\HR-Staff on \\FS01\Data\HR. Backed up to ...\Backups\2026-10-17_142233_AddPermission.csv and logged to ...\Changes_2026-10-17.csv.`
The console shows the log folder at startup.

| File | What is in it |
|------|---------------|
| `Logs\Changes_<yyyy-MM-dd>.csv` | One row per folder or file changed: `Time`, `Technician`, `Computer`, `Action`, `Target`, `ItemType`, `Detail`, `OldValue`, `NewValue`, `Result`, `Error`, `BackupFile`. `OldValue` and `NewValue` are the permissions before and after, as SDDL text. |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_<Action>.csv` | The permissions as they were just before one action: `Path`, `ItemType`, `Sddl`. |

`Result` is one of `Done`, `Failed`, `Skipped (not found)` or `Skipped (WhatIf)`. A `Failed`
row whose `NewValue` differs from its `OldValue` was **partly changed** (for example, takeown
gave the folder to Administrators but the owner could not then be set to you); the status bar
says so and points at the backup. Each row is written as soon as that item is done, so a batch
that is interrupted still leaves a log of what it changed.

`Could not read` means the tool could not read the item's permissions before the change. Add
permission, Remove permission and Copy permissions then refuse that item and change nothing.
Take ownership still goes ahead (it exists for folders you are locked out of), so that item
cannot be restored from the backup, and the status bar says so.

Remove permission removes **every** Allow (or Deny) entry the account has on the item, whatever
rights you picked, as it always has; the status bar says "Removed all Allow permissions for ...
(asked: Modify)". Inherited entries are not touched.

Text that Excel would run as a formula (starting with `=`, `+`, `-`, `@`, a tab or a carriage
return, such as a mistyped target `=1+1`) is written to both CSV files with a leading `'`. The
restore steps below remove it again.

The log folder is `Logs` next to the script, not the current directory (which is
`C:\Windows\System32` when PowerShell runs as administrator). If the script is on a network
share, a mapped drive or any drive that is not a local fixed disk, or that folder is
read-only, `%LOCALAPPDATA%\FolderPermissionManager\Logs` on this computer is used instead and
the console says so with `[WARN]`. A `-LogFolder` you pass is always used as given; if it is on
the network the console warns, because every change is refused while it cannot be written. If
no local folder can be found at all, the tool stops with `[FAIL]` and asks for `-LogFolder`.

Logs and backups hold client paths, account names and SIDs: they stay on the machine that ran
the tool and are never deleted automatically. **They get the permissions of the folder they
are in**: the tool does not lock them down. Keep the tool in a folder only administrators can
read (or pass a `-LogFolder` that is), and do not copy it to a shared folder on a server that
other users can open.

### Undo a change

There is no Undo button. To put back the permissions of one folder or file, open the backup
CSV named in the change log's `BackupFile` column and run, as administrator:

```powershell
$backup = 'C:\Tools\FolderPermissionManager\Logs\Backups\2026-10-17_142233_AddPermission.csv'
foreach ($row in Import-Csv -LiteralPath $backup) {
    # A path that looked like an Excel formula was saved with a leading ' (see above).
    $path = if ($row.Path -match "^'[=+\-@\t\r]") { $row.Path.Substring(1) } else { $row.Path }
    if ($row.Sddl -eq 'Could not read') { Write-Warning "No backup for $path"; continue }
    $acl = Get-Acl -LiteralPath $path
    $acl.SetSecurityDescriptorSddlForm($row.Sddl)   # owner, group and permissions as they were
    Set-Acl -LiteralPath $path -AclObject $acl

    # Check: read the item again and compare it with the backup.
    $now = Get-Acl -LiteralPath $path
    $saved = Get-Acl -LiteralPath $path
    $saved.SetSecurityDescriptorSddlForm($row.Sddl)
    if ($now.Sddl -ne $row.Sddl -or $now.Owner -ne $saved.Owner) {
        Write-Warning "$path does not match the backup. Owner now: $($now.Owner); in the backup: $($saved.Owner)."
    } else {
        Write-Host "[PASS] $path restored" -ForegroundColor Green
    }
}
```

Remove the rows for items you do not want to restore first. Use `-LiteralPath`, not `-Path`:
folder names with `[` or `]` are otherwise read as wildcards. Run this in an elevated
PowerShell window: changing permissions with `Set-Acl` needs the right to change them, and
setting the owner back to another account needs the "Restore files and directories" right
(`SeRestorePrivilege`), which administrators have only when the window is elevated. Without it,
`Set-Acl` fails with "The security identifier is not allowed to be the owner of this object"
and the check above warns. A warning can also mean Windows changed the inherited part of the
permissions (for example, the parent folder changed since the backup); compare the two SDDL
strings to see what differs.

References:
[Get-Acl](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl),
[Set-Acl](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/set-acl),
[SetSecurityDescriptorSddlForm](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.setsecuritydescriptorsddlform),
[SeRestorePrivilege sets any owner](https://learn.microsoft.com/windows/win32/secauthz/privilege-constants),
[RemoveAccessRuleAll](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.removeaccessruleall).

### FolderPermissionManager.ps1 (CLI)

Command-line script that takes ownership of subfolders, reviews permissions, and optionally replicates parent ACLs to all children.

```powershell
.\FolderPermissionManager.ps1 -Path "C:\SharedFolder"
```

If no path is provided, the script will prompt for it.

## Requirements

- PowerShell 5.1+ for the GUI
- Run as Administrator (required for ownership and permission operations)
- Keep `FolderPermissions.Core.ps1` in the same folder as the GUI: it holds the backup,
  logging and change logic
