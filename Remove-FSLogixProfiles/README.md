# Remove-FSLogixProfiles

Archives or deletes FSLogix profile container folders for users who have left. It checks every folder first, and anything that fails a check is skipped and left alone.

**Changes anything?** Yes, in `Archive` and `Delete` modes. The default `Report` mode is read-only.

## Before you start

- Get the list of folders to remove: a CSV with a `FolderName` column, or folder names passed with `-FolderName`. A folder name looks like `S-1-5-21-...-1105_jsmith` (or `jsmith_S-1-5-21-...` if the client uses `FlipFlopProfileDirectoryName`).
- Run it from a machine that can reach the profile share with delete rights, and that has the **ActiveDirectory** module (RSAT) and access to the profiles' domain.
- Windows PowerShell 3.0 or later. Admin rights on the machine are not needed, but rights on the share are.

## What it checks

A folder is **skipped**, never removed, if any of these fail:

| Check | Why |
|---|---|
| The folder sits directly under `-ProfileShare` | Stops nested or `..\` paths from reaching anything else |
| The name contains a domain account SID (`S-1-5-21-...`) | Only real FSLogix user folders qualify |
| No `.vhd` / `.vhdx` in it is open | A container attached to a session is held open. If the file can't be opened exclusively, the user is (or may be) signed in |
| The SID belongs to this domain | Looked up in the wrong domain, every account would look deleted |
| The AD account is not enabled | Enabled users keep their profile. Disabled or deleted accounts are OK to remove |
| *(optional)* Nothing was written in the last `-MinDaysInactive` days | Extra protection against recently used profiles |

If the AD check can't run (module missing, DC unreachable), `Archive` and `Delete` stop before changing anything. `Report` carries on with a warning. Use `-SkipADCheck` only when you know the accounts are gone.

## How to use it

Work through the modes in order:

```powershell
# 1. Report: see what would happen. Nothing changes.
.\Remove-FSLogixProfiles.ps1 -ProfileShare \\fileserver\profiles -TargetCsv .\RemovalTargets.csv

# 2. Archive: move eligible folders to \\fileserver\profiles\_Archive_<date>. Reversible.
.\Remove-FSLogixProfiles.ps1 -ProfileShare \\fileserver\profiles -TargetCsv .\RemovalTargets.csv -Mode Archive

# 3. Later, once nobody has missed anything, delete the archive folder by hand,
#    or delete straight from the share:
.\Remove-FSLogixProfiles.ps1 -ProfileShare \\fileserver\profiles -TargetCsv .\RemovalTargets.csv -Mode Delete -WhatIf
.\Remove-FSLogixProfiles.ps1 -ProfileShare \\fileserver\profiles -TargetCsv .\RemovalTargets.csv -Mode Delete
```

`Archive` and `Delete` ask before each folder. Add `-Force` to skip the prompts. The safety checks still run.

One user:

```powershell
.\Remove-FSLogixProfiles.ps1 -ProfileShare Z:\ -FolderName 'S-1-5-21-1111111111-2222222222-3333333333-1105_jsmith' -Mode Archive
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-ProfileShare` | *(required)* | FSLogix share root, UNC or mapped drive |
| `-TargetCsv` | | CSV with a `FolderName` column (folder name or full path under the share) |
| `-FolderName` | | One or more folder names, instead of a CSV |
| `-Mode` | `Report` | `Report`, `Archive`, or `Delete` |
| `-ArchivePath` | `<share>\_Archive_<yyyy-MM-dd>` | Where Archive moves folders. Keep it on the same share so the move is an instant rename, not a copy |
| `-MinDaysInactive` | `0` (off) | Skip folders with any file written within this many days |
| `-SkipADCheck` | off | Don't check AD. Enabled accounts are then **not** protected |
| `-Server` | this computer's domain | DC or domain name for the AD check |
| `-OutputPath` | current directory | Folder for the CSV log |
| `-Force` | off | Don't prompt before each move or delete |
| `-WhatIf` | | Show what would happen without changing anything |

## Output

Each folder gets a color-coded line in the console, followed by a per-status total in GB. Every run, including `-WhatIf`, writes `FSLogixRemoval_<Mode>_<yyyy-MM-dd_HHmmss>.csv` to `-OutputPath`. Attach it to the ticket.

| Status | Meaning |
|---|---|
| `Eligible` | Passed every check (Report mode) |
| `Archived` / `Deleted` | Moved or deleted |
| `WhatIf` | Would have been moved or deleted |
| `Skipped` | Failed a check. `Reason` says which one |
| `NotFound` | No such folder under the share |
| `Failed` | The move or delete itself errored. **Check the folder by hand**, it may be partly gone |

## Tests

```powershell
pwsh -File ..\Tests\Invoke-AllTests.ps1 -Path .\Tests
```

The tests use a fake share under Pester's `$TestDrive` and a mocked AD. They never touch a real share or domain.
