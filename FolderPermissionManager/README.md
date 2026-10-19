# Folder Permission Manager

Tools for managing NTFS folder permissions, ownership, and ACLs. Includes a Windows app, a
command-line script, and the older browser-based GUI.

## Scripts

### FolderPermissionManager-GUI.ps1 (Windows app)

A normal Windows window (WPF) for looking at folder and file permissions on local drives,
mapped drives and network shares. Nothing listens on the network, and slow work (opening a
folder on a busy share, reading permissions, the export) runs in the background, so the
window never freezes.

**View only in this version.** The buttons that change permissions (Add Permission, Remove
Permission, Take Ownership, Copy Permissions To...) are shown but switched off; the window
says so. Until they are switched on, make changes with the browser version,
`FolderPermissionManager-WebGUI.ps1` (below). Changes anything? **No.**

**How to start it:** right-click `FolderPermissionManager-GUI.ps1` and choose **Run with
PowerShell**, or run it from a PowerShell window:

```powershell
# Open the window (asks for administrator rights first if needed)
.\FolderPermissionManager-GUI.ps1

# Keep backups and the change log in the ticket folder
.\FolderPermissionManager-GUI.ps1 -LogFolder 'D:\Tickets\12345\PermissionChanges'

# Dry run: the window says "Dry run (WhatIf): nothing will be changed"
.\FolderPermissionManager-GUI.ps1 -WhatIf
```

- **Administrator rights.** Started without them, it asks Windows for them (the UAC prompt)
  and opens again elevated. If you choose No, it says why it needs them and closes. Mapped
  drives are passed on to the elevated window, because an elevated window usually cannot see
  your mapped drives ([Microsoft Learn](https://learn.microsoft.com/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)).
- **One window per log folder.** A second copy that would use the same log folder is refused
  with "Folder Permission Manager is already open (possibly in another session on this
  computer). Use that window, or close it first." Two windows must never write to the same
  change log at once. A copy started with a different `-LogFolder` can run alongside.
- **Where changes are logged.** The bar under the title says "Changes are backed up and logged
  to `<folder>`", with any warning about that folder (for example when it is on a network
  share), and **Open log folder** opens it. The folder is chosen exactly as in the browser
  version (see "Changes are backed up and logged" below).

**What you see:**
- The full path of the selected folder at the top, at all times, and the real location
  (`\\server\share\...`) behind a mapped drive letter. Both can be selected and copied.
- A folder tree of the local and mapped drives; type a path such as `\\fs01\Data` in the box
  above it and press Enter to open a share that is not mapped. Folders open in the background;
  a folder with no subfolders loses its expander. A folder you cannot open shows the next step,
  for example "Access denied to '`<path>`'. Take ownership (this folder only) first, then use
  Add Permission to give yourself access."
- **Folder permissions:** who owns the folder, whether it gets the permissions of the folder
  above it, and each entry: User or Group, Permission Level, Allow/Deny (Deny in red), Inherited.
- **Files:** name, size and modified time. Tick one or several files (or click, Ctrl+click,
  Shift+click, **Select all** or Ctrl+A) to see who owns each one and who has access to it on
  the right (the first 20 selected). When the selected files' permissions differ, it says
  "Selected files have different permissions — this operation applies uniformly to all".
- A busy line with a progress bar and the elapsed time while anything loads, and a status line
  whose text can be selected and copied.
- **Export to CSV...** saves the permissions of the selected folder and all its subfolders to a
  CSV file you choose (`Path`, `Owner`, `Identity`, `Rights`, `AccessType`, `IsInherited`,
  `InheritanceFlags`; a folder that could not be read gets a row with `Owner` = `ERROR` and the
  reason). Hidden and system subfolders are included. It runs in the background and can be
  stopped. Text that Excel would run as a formula gets a leading `'`, as in the change log.
  The Save dialog starts in your Documents folder when that is on this computer's own disk and
  not in OneDrive; otherwise in `%LOCALAPPDATA%\FolderPermissionManager\Exports`. If you pick a
  network share, a mapped, network or removable drive, or a OneDrive folder, the status line
  warns and names the location, and the tool asks before it writes there.
- **Dark or light:** the button at the top right ("Switch to light" / "Switch to dark")
  switches; the choice is remembered in `%LOCALAPPDATA%\FolderPermissionManager\settings.json`.
  Unexpected errors are written to `gui-errors.log` in the same folder.
- **F5** or **Refresh** reads the current folder again.

**Client data in what it saves.** The export CSV holds the folder paths, owners and account
names of the client's whole folder tree. `gui-errors.log` holds the raw text of unexpected
errors, which can name client folders and accounts; it is trimmed to its last 1 MB each time
the app starts. A saved file inherits the permissions (ACL) of the folder it is saved in, so
anyone who can read that folder can read it. Save the export locally (not in OneDrive or on a
share), attach it to the ticket, then delete the local copy. The status line and the path
boxes show raw paths and error text: they are not ticket-note-safe, and anything you copy from
them goes into Windows clipboard history and, in a Remote Desktop (RDP) session, to the other
computer's clipboard. Even in this view-only version and with `-WhatIf`, starting the app
creates the `Logs` folder next to the script (when that is a local fixed disk) and writes and
deletes a small probe file there, to check that backups could be saved.

To copy files with their permissions, use [RobocopyMigration](../RobocopyMigration/): the
Windows app has no Robocopy tab and no "Copy Files To...".

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-LogFolder` | `Logs` next to the script | Where permission backups and the change log go (see below) |
| `-WhatIf` | | Dry run: the window says nothing will be changed |
| `-DriveMap` | | Used by the tool itself when it opens again as administrator; leave it out |

Requires Windows PowerShell 5.1 (or PowerShell 7 on Windows). Keep
`FolderPermissions.Core.ps1` in the same folder.

### FolderPermissionManager-WebGUI.ps1 (browser version, kept until the Windows app is lab-tested)

The browser version of the tool, until now `FolderPermissionManager-GUI.ps1`. It is kept only
until the Windows app above has been lab-tested and can make changes, then it is removed. Use
it to make changes in the meantime.

A browser-based interface for managing folder permissions across local drives and network shares. Runs a local web server and opens an interactive dashboard.

**Features:**
- Browse all local drives and network shares in a folder tree
- View ownership, inheritance status, and full ACL entries for any folder
- Take ownership (single folder or recursive)
- Add and remove permission entries (identity, rights, allow/deny)
- Copy a folder's own permissions to other folders (adds only, nothing is removed)
- Export permissions report as CSV
- Dark/light theme toggle

**Usage:**

```powershell
# Launch with defaults (opens browser automatically)
.\FolderPermissionManager-WebGUI.ps1

# Custom port, don't auto-open browser
.\FolderPermissionManager-WebGUI.ps1 -Port 9090 -NoBrowserOpen
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
- Copy permissions to other folders
- Take ownership of a folder **and all its subfolders and files**: the current owner of every
  item is saved first (see the owner snapshot below)

### Copy Permissions To...

**Copy only adds.** It takes the permissions set directly on the current folder and adds them
to each folder you list. Nothing already on a target folder is removed.

- Only the current folder's **own** permissions are copied. Permissions it only inherits from
  its parent are not, so later changes higher up the share still reach the target. If the
  folder has no permissions of its own, nothing changes and the status bar says
  `Nothing to copy: <folder> has no permissions of its own. All of its permissions come from <parent>. Open a folder that has its own permissions, or use Add Permission.`
- Each permission arrives exactly as it is: the same person or group, the same level of access
  (Read & execute stays Read & execute; special combinations stay as they are), Allow or Deny,
  and the same "applies to" setting.
- A target that already has every one of those permissions is not changed
  (`Skipped (nothing to copy)`, "Already has these permissions; nothing changed."). The status
  bar shows this as information, not as a problem. For a target inside the current folder, a
  permission it already inherits from the current folder counts as already there: it is not
  added again as the target's own, so removing it from the current folder later still removes
  it everywhere below.
- If the current folder has a Deny permission of its own, the dialog says so before you copy:
  a Deny is copied too and blocks access even where another permission allows it.
- Each target folder is changed once. **Subfolders and files under it that inherit permissions
  get the new ones automatically**, as they would in Explorer.
- A target that is a file is refused: "<path> is a file. Copy permissions copies to folders only."
- Folder names with `[` or `]` (such as `HR [old]`) work, here and everywhere else in the tool.

**Known limitation: subfolders that block inheritance are not changed.** A subfolder under a
target with inheritance turned off (often on purpose, such as `HR\Confidential`) keeps exactly
the permissions it had. Windows only passes inheritable permissions to children that inherit
([SetNamedSecurityInfo](https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow),
[SE_DACL_PROTECTED](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-control)).
Add the permission to such a subfolder yourself if it needs it. The status bar says this after
every copy.

The older "Apply recursively" option is gone. It reset every custom permission below the target
and could turn Read & execute into a broken command.

After each change the status bar says what was done and where it was logged, for example
`Added Allow Modify for CONTOSO\HR-Staff on \\FS01\Data\HR. Backed up to ...\Backups\2026-10-17_142233_AddPermission.csv and logged to ...\Changes_2026-10-17.csv.`
The console shows the log folder at startup.

| File | What is in it |
|------|---------------|
| `Logs\Changes_<yyyy-MM-dd>.csv` | One row per folder or file changed: `Time`, `Technician`, `Computer`, `Action`, `Target`, `ItemType`, `Detail`, `OldValue`, `NewValue`, `Result`, `Error`, `BackupFile`. `OldValue` and `NewValue` are the permissions before and after, as SDDL text. |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_<Action>.csv` | The permissions as they were just before one action: `Path`, `ItemType`, `Sddl`. |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv` (whole folder) | The owner snapshot written before taking ownership of a folder and everything under it: `Path`, `ItemType`, `Owner`, `OwnerSid`, one row for the folder and every subfolder and file under it (hidden ones too). |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_NotOpened.txt` (whole folder) | Written after taking ownership when some folders could not be opened: all of them, one path per line, for the escalation. Not a backup: their permissions were not changed. |

`Result` is one of `Done`, `Partly done`, `Failed`, `Skipped (not found)`, `Skipped (nothing to copy)` or `Skipped (WhatIf)`. A `Failed`
row whose `NewValue` differs from its `OldValue` was **partly changed** (for example, takeown
gave the folder to Administrators but the owner could not then be set to you); the status bar
says so and points at the backup. Each row is written as soon as that item is done, so a batch
that is interrupted still leaves a log of what it changed.

Taking ownership of a whole folder writes its one row when it ends. **A `..._TakeOwnership.csv`
in `Backups` with no row in the change log whose `BackupFile` names it means that run was
interrupted** (window closed, server restarted) after the owners were saved: some owners may
have changed. The snapshot still holds the owners from before, so the restore steps below work
for it. (The command-line script says this before it starts.)

Taking ownership of a whole folder logs **one row for the folder** (`ItemType` = `Folder tree`):
`OldValue` is `Saved in <owner snapshot>`. It runs `takeown /F <folder> /R /A /D N` (gives every
item to Administrators, so locked-out items can be opened, and skips folders it cannot open) and then
`icacls <folder> /setowner <DOMAIN\you> /T /C /Q` (makes you the owner); `Detail` ends with the
two commands exactly as run. A relative path or a trailing backslash is turned into one full
path first, and that path is used for the snapshot, both tools and the log.

Afterwards the tool **reads the owner of every item in the snapshot again**, and that decides
the result: `Done` when you own every item, `Partly done` when you own some (or when no owner
could be read back at all, so nothing is known: `NewValue` is `Not checked`), `Failed` when you
own none. A tool that reports errors (exit code not 0) also keeps the result from looking
better than the tools say. `NewValue` says what the owners are now: `Owner: <you>`,
`Owner: <you> on 3 of 5 items`, `Owner: Administrators (icacls failed)` (takeown worked, icacls
did not) or `Owner unchanged`. `Error` says how many items you do not own and adds the tools'
own messages, for example `Successfully processed 3 files; Failed processing 2 files`.

Items under a folder the tool could not open are not in the snapshot, so their owners cannot
be put back from it. The result is then `Partly done`, never `Done`, even when you own
everything that could be opened.

**A folder that cannot be opened is skipped and left alone.** For a folder the account has no
"List folder" and "Read" permission on, `takeown /R /A /D N` skips the folder instead of taking
it ([takeown](https://learn.microsoft.com/windows-server/administration/windows-commands/takeown):
answering `Y` instead would take it and replace its permissions with permission granting only
you full control, so the tool never does that; taking ownership of a single item passes no `/D`
at all, because the page says it must be used with `/R`). Its permissions are not changed, so
there is nothing extra to back up. `icacls /setowner /T` may still change the owner of the
skipped folder itself (Microsoft's documentation does not say), so its owner is read back too.
The result is `Partly done`, and the status bar (or the console, with `[WARN]`) gives the next
step: `Escalate: 1 folder(s) could not be opened, so they were left alone.` (or, when its owner
was changed: `its owner was changed, but its permissions were not`), the first three folders,
the `..._NotOpened.txt` file that lists all of them, and `Ask a senior engineer to take
ownership of them with an account that can open them.` The console also prints every such
folder on its own line, and the change log's `Detail` names the first 20. The console `[WARN]`
line before the change and the GUI's confirm dialog say that such folders are skipped.

**The root of a drive and the Windows folders are refused.** Taking ownership of a whole drive
root (`C:\`, `D:\`), or of anything in `%SystemRoot%` (`C:\Windows`), `%ProgramFiles%`,
`%ProgramFiles(x86)%` or `%ProgramData%` (the folders themselves too), would change the owner
of Windows and program files and is very hard to undo, so the tool stops before saving or
changing anything and says why. The same goes for the 64-bit Program Files folder seen from a
32-bit PowerShell (`%ProgramW6432%`); for those folders spelt another way (`\\?\C:\Windows`,
`C:\Windows.`, a short name such as `C:\PROGRA~1`) or reached through a junction or symbolic
link; and for another server's administrative shares: `ADMIN$`, a drive share such as
`\\fs01\D$`, and `Windows`, `Program Files`, `Program Files (x86)` and `ProgramData` on one
(`\\fs01\C$\Windows`); and for the domain controller and print server shares `SYSVOL`,
`NETLOGON` and `PRINT$` (`\\dc01\SYSVOL\contoso.com\Policies`), which hold Group Policy, logon
scripts and printer drivers for every computer that uses them. The root of an ordinary share
(`\\fs01\share`, or a hidden one such as `\\fs01\Users$`) is allowed. A folder that is, or is
inside, a junction or symbolic link is refused when the tool cannot see where it leads: on a
share the server follows its own junctions, so the tool only sees the path you typed. A path
with a short name (`~1`) is refused when Windows cannot tell its full name. The GUI has no
way around this; the command-line script takes `-AllowSystemFolder` for the rare case where it
is really needed.

Junctions and symbolic links inside the folder are listed in the snapshot but not gone into,
because they can point outside the folder. Microsoft's documentation does not say whether
`takeown /R` and `icacls /T` go into them, and `icacls` changes what a symbolic link points to
unless `/L` is given ([icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls)),
so each one is checked like the folder itself. **A junction or symbolic link inside the folder
that leads into one of the folders above, or somewhere the tool cannot check, refuses the whole
folder**: the result is `Failed`, names the link, and nothing is changed. The command-line
script says so before asking anything; the GUI finds out while saving the owner snapshot, and
keeps that snapshot (the change log row names it, and nothing needs to be put back from it).
Take ownership of the folders beside the link instead. Other links do not stop the change, but
a folder containing any is never reported as a plain success: the result says how many there
are and names them. Check them, and what they point to, after the change. Deduplicated files
and OneDrive placeholders are not links and are changed like any other item.

`Could not read` means the tool could not read the item's permissions (or, in an owner
snapshot, its owner) before the change. Add permission, Remove permission and Copy permissions
then refuse that item and change nothing. Take ownership still goes ahead, for one item or a
whole folder (it exists for folders you are locked out of), so that item cannot be restored
from the backup, and the status bar says how many there were.

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

`Logs\` holds client paths, account names and SIDs:
keep it with the ticket and delete it when the ticket is closed.
The logs and backups stay on the machine that ran the tool and are never deleted
automatically. **They get the permissions of the folder they
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

A Copy permissions backup can also hold rows for folders that turned out to need no change:
they already had the permissions by the time of the change, and the change log shows them as
`Skipped (nothing to copy)`. The tool did not change those folders: leave their rows out when
you restore, or a later change to them made by someone else would be undone.

Remove the rows for items you do not want to restore first. Use `-LiteralPath`, not `-Path`:
folder names with `[` or `]` are otherwise read as wildcards. Run this in an elevated
PowerShell window: changing permissions with `Set-Acl` needs the right to change them, and
setting the owner back to another account needs the "Restore files and directories" right
(`SeRestorePrivilege`), which administrators have only when the window is elevated. Without it,
`Set-Acl` fails with "The security identifier is not allowed to be the owner of this object"
and the check above warns. A warning can also mean Windows changed the inherited part of the
permissions (for example, the parent folder changed since the backup); compare the two SDDL
strings to see what differs.

#### Put owners back after taking ownership of a whole folder

The owner snapshot (`..._TakeOwnership.csv`, named in the log's `BackupFile` column) holds
every item's owner. Run, in an elevated PowerShell window:

```powershell
$snapshot = 'C:\Tools\FolderPermissionManager\Logs\Backups\2026-10-17_142233_TakeOwnership.csv'
foreach ($row in Import-Csv -LiteralPath $snapshot) {
    try {
        $path = if ($row.Path -match "^'[=+\-@\t\r]") { $row.Path.Substring(1) } else { $row.Path }
        if (-not $row.OwnerSid) { Write-Warning "No saved owner for $path ($($row.Owner))"; continue }

        # A SID is given to icacls with a leading * ; /C carries on after an error.
        $out = & icacls.exe $path /setowner "*$($row.OwnerSid)" /C 2>&1
        $set = if ($LASTEXITCODE -eq 0) { 'owner set' } else { "icacls reported a problem (exit code $LASTEXITCODE): $out" }
    } catch {
        Write-Warning "Could not restore the owner of $($row.Path): $($_.Exception.Message)"
        continue
    }

    # Check, on its own: read the owner again and compare it with the snapshot. A check that
    # fails does not mean the restore failed, so both results are shown.
    try {
        $now = (Get-Acl -LiteralPath $path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Warning "${path}: $set; could not verify: $($_.Exception.Message)"
        continue
    }
    if ($now -ne $row.OwnerSid) {
        Write-Warning "${path}: $set; but it is owned by $now, not $($row.Owner) ($($row.OwnerSid))."
    } else {
        Write-Host "[PASS] ${path}: $set and verified" -ForegroundColor Green
    }
}
```

The restore uses the saved SID, not the name, so it also works for an owner whose account
name has changed. One item that fails is reported and the rest carry on. Setting another
account as the owner needs the "Restore files and directories" right (`SeRestorePrivilege`),
which administrators have in an elevated window. Rows with `Could not read` have no saved owner
and are skipped with a warning.

Taking ownership of a whole folder does not change any permissions, and folders it could not
open were skipped, so putting the owners back is all there is to undo.

Alternative, if `icacls` is not available: replace the `icacls` line with
`$acl = Get-Acl -LiteralPath $path; $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $row.OwnerSid)); Set-Acl -LiteralPath $path -AclObject $acl`.
It is **not verified** that `Set-Acl` turns on `SeRestorePrivilege` for you, so it may fail with
"The security identifier is not allowed to be the owner of this object"; the check line then
warns.

References:
[Get-Acl](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-acl),
[Set-Acl](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/set-acl),
[SetSecurityDescriptorSddlForm](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.setsecuritydescriptorsddlform),
[SeRestorePrivilege sets any owner](https://learn.microsoft.com/windows/win32/secauthz/privilege-constants),
[RemoveAccessRuleAll](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.filesystemsecurity.removeaccessruleall),
[GetOwner](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.objectsecurity.getowner),
[takeown](https://learn.microsoft.com/windows-server/administration/windows-commands/takeown),
[icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls).
Microsoft Learn documents neither `icacls` exit codes nor its closing
`Successfully processed ...` line (which is translated on non-English Windows), so the tool
decides the result by reading the owners back and only shows the tools' output.

### FolderPermissionManager.ps1 (CLI)

For servers without a browser. It takes ownership of a folder and everything under it, then
shows the permissions and the owner of each subfolder. **It asks before taking ownership**, and
the change is backed up and logged exactly as in the GUI (owner snapshot first, same
`Changes_<yyyy-MM-dd>.csv`). Changes anything? **Yes**: owners. It does not change permissions.

To give someone access: add it on the folder they need. Adding it on a folder gives them
everything inside it that inherits, so adding it on a share or home-folder root gives them
everything below. Subfolders that block inheritance (inheritance turned off, often locked down
on purpose) do not get it, nor do the folders inside them; the script names them after the
owner list. An explicit Deny on a subfolder still wins. Add it with Add Permission in the
browser version (`FolderPermissionManager-WebGUI.ps1`) or on Explorer's Security tab (Properties > Security > Edit > Add). Without a browser:

```powershell
icacls "D:\Shares\HR\Finance" /grant "DOMAIN\user:(OI)(CI)RX"
```

`(OI)(CI)` lets the files and subfolders inherit it and `RX` is read and execute; use M only
if they must change or delete files (`(OI)(CI)M`, Modify). The script prints the same command
with a placeholder under your folder, not the folder itself. Do not add /T: it writes the
permission onto every subfolder and file, including the ones that block inheritance
([icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls)).

```powershell
# Dry run: shows what would change; nothing is changed, backed up or logged
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -WhatIf

# Asks before taking ownership
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR'

# No questions; backups and log in the ticket folder
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -Force -LogFolder 'C:\Tickets\12345'
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Path` | asks | The top folder |
| `-LogFolder` | `Logs` next to the script | Where backups and the change log go (same rules as the GUI) |
| `-Force` | — | Do not ask before taking ownership (needed, or `-WhatIf`, on a host that cannot ask) |
| `-AllowSystemFolder` | — | Take ownership even of a drive root or a folder in `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` or `%ProgramData%`, on `SYSVOL`, `NETLOGON` or `PRINT$`, or with a junction or symbolic link inside that leads into one, which is refused otherwise (see above) |
| `-WhatIf` | — | Show what would be changed and change nothing |

Before taking ownership it prints what will change with `[WARN]` (how many items: the folder is
counted first, read only, and `-WhatIf` shows the count too), then asks `Continue? (y/N)`.
Answer `y` to go ahead; anything else (including Enter) leaves the owners alone. Declining
ownership, or ownership failing, still shows the permissions. Run it in an elevated window: it
stops with `[FAIL]` otherwise (except with `-WhatIf`). See "Undo a change" above to put owners
back.

A remote console (Enter-PSSession, or psexec) is asked like a local one. A host that cannot
ask (a scheduled task, or PowerShell started with `-NonInteractive`) needs `-Force` or
`-WhatIf`. Started with `-NonInteractive`, the script stops with `[FAIL] Run with -Force, or
-WhatIf for a dry run; this host cannot ask.` and exit code `1` before anything is counted,
saved or changed. Any other host whose question fails stops at the question with `[FAIL]
This host cannot ask; run with -Force, or -WhatIf for a dry run. Nothing was changed.` and exit
code `1`; the log folder is only set up after you answer `y`. With `-Force` but no `-Path` it
stops the same way and asks for `-Path`.

After the owner list the script names the subfolders that block inheritance. A subfolder whose
permissions it cannot read is counted as "could not be checked" (it may block inheritance too),
so check those by hand.

A drive root or a Windows folder is refused straight away, before any question, with one
`[FAIL]` line that names the folder and `-AllowSystemFolder`, and exit code `1`. Nothing is
counted, saved or changed. A junction or symbolic link inside the folder that leads into one is
refused the same way once the folder has been counted, before any question: the `[FAIL]` line
names the link, and nothing is saved or changed.

The script exits with `1` when taking ownership `Failed`, was only `Partly done` or could not be
checked everywhere (folders it could not open, owners it could not read back, or junctions and
symbolic links in the folder), or when the folder, the log folder or the host could not be
used; and `0` otherwise, including `-WhatIf` and a declined question.

The owners of the subfolders are shown for the folders counted before taking ownership:
junctions and symbolic links are not gone into, and folders that could not be opened are named
in the `[WARN]` instead. The heading says how many it leaves out, for example
`Subfolders and their owners (12, not counting 1 that could not be opened and 2 junctions or
symbolic links, listed above):`. If taking ownership is interrupted, see the note on
interrupted runs above.

## Requirements

- PowerShell 5.1+ for the Windows app and the browser version; PowerShell 3.0+ for the
  command-line script (Windows Server 2012 and later)
- Run as Administrator (required for ownership and permission operations; the Windows app asks
  for it itself)
- Keep `FolderPermissions.Core.ps1` in the same folder as the scripts: it holds the backup,
  logging and change logic
