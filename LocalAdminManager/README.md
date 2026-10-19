# Local Admin Manager

Adds or removes a domain user or group in the local Administrators group of a Windows
computer, locally or remotely, and writes every attempt to a change log with the member list
before and after.

**Changes anything? Yes.** It changes who is a local administrator on the target computer.

## Features

- Add or remove one domain user or group in the local Administrators group
- Works on this computer, or on a remote computer through PowerShell remoting (WinRM)
- Finds the group by its fixed SID (`S-1-5-32-544`), so it also works on non-English Windows
  where the group is called, for example, "Administratoren"
- Shows what will change and asks before changing anything; `-WhatIf` for a dry run,
  `-Force` for batch files
- Logs every attempt (done, no change, failed) with who, when, from where, on which computer,
  and the member list before and after
- Exit code 1 when the change failed, so batch files can detect it

## Requirements

- Windows PowerShell 3.0 or later (Windows Server 2012 and later as shipped)
- An elevated PowerShell prompt (Run as administrator)
- Your account must be a local administrator on the target computer
- Remote computers: PowerShell remoting (WinRM) enabled on the target
  (`Enable-PSRemoting` on the target, or the usual Group Policy setting)
- Domain-joined computer (for domain users and groups)

## Usage

```powershell
.\LocalAdminManager.ps1 -Action <Add|Remove> -Member "DOMAIN\Name" [-ComputerName "PC01"] [-LogFolder <folder>] [-Force] [-WhatIf]
```

### Parameters

- **Action**: Required. `Add` or `Remove`.
- **Member**: Required. The domain user or group as `DOMAIN\Username` or `DOMAIN\GroupName`.
  A name without a domain means a local account on the target computer. A SID
  (`S-1-5-21-...`) also works: that is how you remove a deleted account that the group only
  shows as its SID. A user principal name (`jsmith@contoso.com`) is refused; use
  `DOMAIN\Name`.
- **ComputerName**: Optional. The computer to change. Defaults to this computer.
- **LogFolder**: Optional. Where the change log goes. Defaults to the `Logs` folder next to
  the script. When the script runs from a share, a mapped network drive or a removable disk,
  the default is `%LOCALAPPDATA%\LocalAdminManager\Logs` on this computer instead, with a
  `[WARN]` line saying so. A `-LogFolder` on a network drive is used, with a `[WARN]`.
- **Force**: Optional. Make the change without the confirmation prompt.
- **WhatIf**: Optional. Show the current member count and what would change, and change
  nothing. A dry run writes no log; its last line is an `[INFO] Dry run: ...` line, never
  "Logged to". It exits 1 if the computer could not be read.

### What you see

```
[WARN] This will add CONTOSO\JSmith to the local administrators group (Administrators) on PC01 (currently 4 members).
Confirm ... [Y] Yes  [N] No ...
[PASS] Added CONTOSO\JSmith to Administrators on PC01. Logged to C:\Tools\LocalAdminManager\Logs\Changes_2026-10-17.csv
```

The member is matched by its SID, as the target computer resolves the name, so
`contoso\jsmith` and `CONTOSO\JSmith` are the same member. If the person is already a member
(Add) or not a member (Remove), nothing changes and the result says "No change". A Remove of
a name the computer cannot find, and that is not in the group under that name, is `Failed`
rather than "No change": check the spelling, or give the SID. If the change fails, the
`[FAIL]` line gives the reason and the script exits with code 1. After the change the group
is read again; if the change does not show there, the result is `Failed` ("change not
visible after re-read").

### Examples

Add a domain user on this computer:

```powershell
.\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\JohnDoe"
```

Remove a domain group on a remote computer:

```powershell
.\LocalAdminManager.ps1 -Action Remove -Member "CONTOSO\TempAdmins" -ComputerName "RemotePC01"
```

Dry run on a remote computer:

```powershell
.\LocalAdminManager.ps1 -Action Add -Member "CONTOSO\ITSupport" -ComputerName "RemotePC01" -WhatIf
```

### Batch operations

Batch files need `-Force`, because there is nobody to answer the prompt. Without it, a
`-NonInteractive` session cannot show the prompt: the result is `Failed` ("confirmation not
possible in a non-interactive session; use -Force"), it is logged, and the exit code is 1.

```batch
REM Add two users on PC01
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Add -Member "CONTOSO\User1" -ComputerName PC01 -Force
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Add -Member "CONTOSO\User2" -ComputerName PC01 -Force

REM Remove a group, and stop if it failed
powershell.exe -ExecutionPolicy Bypass -File "LocalAdminManager.ps1" -Action Remove -Member "CONTOSO\TempAdmins" -ComputerName PC01 -Force
if errorlevel 1 echo Removal failed - see the [FAIL] line above
```

## Change log

Every attempt is one row in `Logs\Changes_<yyyy-MM-dd>.csv` next to the script (or in
`-LogFolder`, or in `%LOCALAPPDATA%\LocalAdminManager\Logs` when the script runs from a
network or removable location). Runs on the same day go into the same file. A dry run
(`-WhatIf`) writes nothing. Columns:

| Column | Meaning |
|---|---|
| Time | When it ran (`yyyy-MM-dd HH:mm:ss`) |
| Technician | Who ran it (`DOMAIN\user`) |
| Computer | The machine the tool ran on |
| Action | `Add administrator` or `Remove administrator` |
| Target | The changed computer and group, e.g. `PC01\Administrators` |
| ItemType | `Local group` |
| Detail | The member added or removed |
| OldValue | Members before, sorted, separated by `; ` |
| NewValue | Members after, read again from the computer |
| Result | `Done`, `No change (already a member)`, `No change (not a member)`, `Failed`, `Skipped (not confirmed)` |
| Error | The reason, when something failed |
| BackupFile | Empty (kept so all change tools write the same columns) |

A member whose account was deleted shows as its SID. To undo a change by hand, compare
OldValue and NewValue and run the opposite action. A value that starts with `=`, `+`, `-` or
`@` is written with a leading `'`, so Excel shows it as text instead of running it as a
formula.

**The log holds client account names.** It is client data: attach it to the ticket if
needed, and do not copy it into shared folders or source control (`LocalAdminManager/Logs/`
is gitignored). Logs are never deleted automatically, and they inherit the permissions of
the folder they are in: keep the tool in a folder only administrators can read.

Before any change, the tool opens today's log file for writing. If that fails (folder
read-only, disk full, file open in Excel), the tool changes nothing, shows a `[FAIL]` line
naming the folder, and exits 1. Pick another folder with `-LogFolder`.

If the log write fails only after the change was made, the `[FAIL]` line says the change
**was** made but not logged, the Target, Detail, OldValue, NewValue and Result are shown on
screen, the row is saved to `%TEMP%\LocalAdminManager_Changes_<yyyy-MM-dd>.csv`, and the
script exits 1. Copy that row into the change log or the ticket.

## How it works

The group is read and changed through the ADSI WinNT provider. On this computer that runs
in-process; on a remote computer the same code runs there through `Invoke-Command`
(WinRM). The member list is read again after the change, so the log shows what the computer
actually holds.

Earlier versions used `Add-LocalGroupMember` / `Remove-LocalGroupMember` with
`-ComputerName`. Those cmdlets have no `-ComputerName` parameter, so every run failed while
the script still printed "Operation completed."

## Troubleshooting

- **Access is denied**: run from an elevated prompt, and make sure your account is a local
  administrator on the target.
- **Connecting to remote server ... failed / WinRM cannot complete the operation**: WinRM is
  not enabled or is blocked by the firewall on the target. Enable PowerShell remoting there,
  or run the tool on the target itself.
- **The specified account name is not valid / member not found**: check the spelling and the
  `DOMAIN\Name` format, and that the account exists in Active Directory. To remove a deleted
  account, give its SID as it appears in the member list.
- **Cannot write the change log**: the log folder is read-only or on a full disk. Use
  `-LogFolder` to point to a folder you can write to.

## Security considerations

- Only grant local administrator access when necessary and for the shortest time needed.
- Review the change log and remove access that is no longer needed.
- For many computers, prefer Group Policy (Restricted Groups or Local Users and Groups
  preferences) over one-off changes.
