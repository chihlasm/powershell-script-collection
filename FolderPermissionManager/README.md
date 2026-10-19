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
- Take ownership of a folder **and all its subfolders and files**: the current owner of every
  item is saved first (see the owner snapshot below)

Copying permissions with "apply recursively" ticked is **not backed up or logged yet**.

After each change the status bar says what was done and where it was logged, for example
`Added Allow Modify for CONTOSO\HR-Staff on \\FS01\Data\HR. Backed up to ...\Backups\2026-10-17_142233_AddPermission.csv and logged to ...\Changes_2026-10-17.csv.`
The console shows the log folder at startup.

| File | What is in it |
|------|---------------|
| `Logs\Changes_<yyyy-MM-dd>.csv` | One row per folder or file changed: `Time`, `Technician`, `Computer`, `Action`, `Target`, `ItemType`, `Detail`, `OldValue`, `NewValue`, `Result`, `Error`, `BackupFile`. `OldValue` and `NewValue` are the permissions before and after, as SDDL text. |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_<Action>.csv` | The permissions as they were just before one action: `Path`, `ItemType`, `Sddl`. |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_TakeOwnership.csv` (whole folder) | The owner snapshot written before taking ownership of a folder and everything under it: `Path`, `ItemType`, `Owner`, `OwnerSid`, one row for the folder and every subfolder and file under it (hidden ones too). |
| `Logs\Backups\<yyyy-MM-dd_HHmmss>_NotOpened.txt` (whole folder) | Written after taking ownership when some folders could not be opened: all of them, one path per line, for the escalation. Not a backup: their permissions were not changed. |

`Result` is one of `Done`, `Partly done`, `Failed`, `Skipped (not found)` or `Skipped (WhatIf)`. A `Failed`
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
share the server follows its own junctions, so the tool only sees the path you typed. A folder
on a network path is also looked up in DFS (see "Refused" below). A path
with a short name (`~1`) is refused when Windows cannot tell its full name. The GUI has no
way around this; the command-line script takes `-AllowSystemFolder` for the rare case where it
is really needed.

Junctions and symbolic links inside the folder are listed in the snapshot but not gone into,
because they can point outside the folder. Microsoft's documentation does not say whether
`takeown /R` and `icacls /T` go into them, and `icacls` changes what a symbolic link points to
unless `/L` is given ([icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls)),
so each one is checked like the folder itself. Messages say what was found: a `junction`, a
`symbolic link`, a `DFS link`, or an `other redirect (reparse point 0x........)`.

**Refused:** a junction or symbolic link inside the folder (or any other link: a DFS link, or a
reparse point the tool does not recognise) that leads into one of the folders above, or
somewhere the tool cannot check, refuses the whole folder. "Cannot check" includes a link whose
destination Windows will not tell, or tells as the link's own path, which is what happens on a
share where the server follows the link itself. **DFS targets are looked up**: for a DFS link
on a network path, and for a chosen folder on a network path (`\\contoso.com\dfs\HR`), the tool
asks the DFS client on this computer where the path really is (`NetDfsGetClientInfo`, built
into Windows) and checks every target; a target such as `\\dc01\NETLOGON`, or a lookup that
fails, refuses the folder. The result is `Failed`, names the link, and nothing is changed. The
command-line script says so before asking anything; the GUI finds out while saving the owner
snapshot, and keeps that snapshot (the change log row names it, and nothing needs to be put back
from it). Take ownership of the folders beside the link instead, or ask a senior engineer. The
command-line script offers `-AllowSystemFolder` only when the destination is a protected folder,
not when it could not be found out.

**Allowed:** a link that leads to an ordinary place, even outside the folder (a DFS target such
as `\\fs02\Apps$`), does not stop the change, but a folder containing any link is never
reported as a plain success: the result says how many there are and names them. Check them, and
what they point to, after the change. A short list of storage features count as plain items and
are changed like any other: deduplicated files, compressed (WOF) files, OneDrive and other cloud
placeholders, and legacy HSM and single-instance storage files. Every other kind of reparse
point, DFS links and anything the tool does not recognise included, is treated as a link and
checked as above.

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

For servers without a browser. It takes ownership of a folder and everything under it, shows
the permissions and the owner of each subfolder, and then copies the top folder's permissions to
every subfolder (entries a subfolder lacks are added; nothing is removed). **It asks before
taking ownership and again before copying**, and every change is backed up and logged exactly
as in the GUI (owner snapshot before taking ownership, SDDL backup before copying, same
`Changes_<yyyy-MM-dd>.csv`). Changes anything? **Yes**: owners and permissions.

```powershell
# Dry run: shows what would change; nothing is changed, backed up or logged
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -WhatIf

# Asks before each step
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR'

# No questions; backups and log in the ticket folder
.\FolderPermissionManager.ps1 -Path 'D:\Shares\HR' -Force -LogFolder 'C:\Tickets\12345'
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Path` | asks | The top folder |
| `-LogFolder` | `Logs` next to the script | Where backups and the change log go (same rules as the GUI) |
| `-Force` | — | Do not ask before taking ownership or copying permissions |
| `-AllowSystemFolder` | — | Take ownership even of a drive root or a folder in `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` or `%ProgramData%`, on `SYSVOL`, `NETLOGON` or `PRINT$`, or with a junction or symbolic link inside that leads into one, which is refused otherwise (see above) |
| `-WhatIf` | — | Show what would be changed and change nothing |

Before each step it prints what will change with `[WARN]` (for ownership, how many items:
the folder is counted first, read only, and `-WhatIf` shows the count too), then asks
`Continue? (y/N)`. Answer `y` to go ahead; anything else (including Enter) skips that step.
Declining ownership, or ownership failing, still shows the permissions and offers the copy: it
does not depend on ownership. Run it in an elevated window: it stops with `[FAIL]` otherwise
(except with `-WhatIf`). See "Undo a change" above to put owners or permissions back.

A drive root or a Windows folder is refused straight away, before any question, with one
`[FAIL]` line that names the folder and `-AllowSystemFolder`, and exit code `1`. Nothing is
counted, saved or changed. A junction or symbolic link inside the folder that leads into one is
refused the same way once the folder has been counted, before any question: the `[FAIL]` line
names the link, and nothing is saved or changed. When the folder or a link is refused because
where it leads could not be found out, the `[FAIL]` line does not offer `-AllowSystemFolder`; it
says to take ownership of the folders beside the link instead, or to ask a senior engineer.

The script exits with `1` when a step `Failed` or was only `Partly done`, when taking ownership
could not be checked everywhere (folders it could not open, owners it could not read back, or
junctions and symbolic links in the folder), or when the folder or the log folder could not be
used; and `0` otherwise, including `-WhatIf` and declined steps.

The copy step lists the subfolders the same way as the owner snapshot: it does not go into
junctions or symbolic links and skips them (they can point outside the folder), and it skips
folders it cannot open; both are named in the console. If taking ownership is interrupted, see
the note on interrupted runs above.

## Requirements

- PowerShell 5.1+ for the GUI; PowerShell 3.0+ for the command-line script (Windows Server 2012
  and later)
- Run as Administrator (required for ownership and permission operations)
- Keep `FolderPermissions.Core.ps1` in the same folder as both scripts: it holds the backup,
  logging and change logic
