# Citrix-FSLogix-Triage

**"My profile didn't load" / "I got a temporary profile" / "I was logged straight back out."**

Point it at the Citrix, RDS or AVD session host the user signs in to. The first line answers
the question:

```
FSLogix check for CTXVDA01 (user jdoe):  PROBLEMS FOUND
======================================================================
Problems:
  [FAIL] Service frxsvc: FSLogix Apps Services is Stopped (start type Auto).
         What to do: FSLogix cannot load profiles while this service is stopped. Escalate ...
Looks fine:
  [PASS] FSLogix profiles switched on: FSLogix profile containers are enabled (Enabled = 1).
  ...
```

It is **read-only**: it reads services, registry, event logs and disk space and changes nothing.

## Quick start

```powershell
# The server jdoe signs in to
.\Invoke-CitrixFSLogixTriage.ps1 -ComputerName CTXVDA01 -UserName jdoe

# Same, plus a text report (paste into the ticket) and a CSV
.\Invoke-CitrixFSLogixTriage.ps1 -ComputerName CTXVDA01 -UserName jdoe -OutputPath C:\Temp

# Run it on the session host itself
.\Invoke-CitrixFSLogixTriage.ps1
```

Run as an account that is a local administrator on the session host.

## What it checks

| Check | Problem when | Warning when |
|---|---|---|
| Server answers a ping | | No reply (some servers block ping) |
| FSLogix services `frxsvc` and `frxccds` | A service is installed but not running | Not installed, or the service list can't be read |
| Profiles switched on | `Enabled` is not 1 in `HKLM\SOFTWARE\FSLogix\Profiles`, or the key is missing | Registry can't be read |
| Profile storage setting | Both `VHDLocations` and `CCDLocations` set, neither set, or a Cloud Cache entry is misspelled (`type=SMB` instead of `type=smb`) | FSLogix values found under `HKLM\SOFTWARE\Policies\FSLogix\Profiles`, which FSLogix does not document for profile settings |
| Recent events (FSLogix Apps Operational/Admin, Remote Desktop session logs) | Error events in the lookback window (default 24 h) | Warning events, a log that is missing, or a log that can't be read |
| Free disk space on the server | Under 5 GB, or under 10% and under 20 GB | Under 10 GB, or under 15% and under 40 GB |
| Profile share reachable | Unreachable when run on the server itself | Not confirmed from the server when run remotely (see below) |

**A check that could not run is a warning, never a pass.** If the tool can't read something,
it says so.

### Why "share not confirmed" is only a warning from your PC

When you check a server remotely, Windows will not pass your sign-in on from that server to the
file server (the "double hop"). So the share test run *on* the server can fail even when the
share is fine. The tool also tests the share from your PC and tells you which case you're in.
To be sure, sign in to the server and run the tool there.

## Parameters

| Parameter | Meaning |
|---|---|
| `-ComputerName` | Session host to check. Default: this computer. Alias `-AffectedDevice`. |
| `-UserName` | Optional. Fills `%username%` in the profile path before testing it. Alias `-AffectedUser`. |
| `-EventLookbackHours` | Hours of events to read. Default 24, maximum 168. |
| `-OutputPath` | Folder for `FSLogixTriage_<computer>_<timestamp>.txt` and `.csv`. Omit for console only. |
| `-TicketNumber` | Put the reports and the ticket note in `Ticket_<number>` (see Ticket note). |
| `-NoClipboard` | Do not copy the ticket note to the clipboard. |
| `-FullDetail` | Keep IP addresses and share paths in the ticket note. |
| `-PassThru` | Return the result object instead of setting an exit code (for other scripts). |
| `-Quiet` | No console output and no clipboard. Use with `-PassThru` or `-OutputPath`. |

**Exit codes** (without `-PassThru`): 0 = looks healthy, 1 = warnings, 2 = problems found,
3 = a `-TicketNumber` that does not fit.

## Ticket note

Every run ends with a short note on the clipboard, ready to paste into the ticket:

```
[Ticket note] Citrix-FSLogix-Triage: FSLogix check for CTXVDA01 (user jdoe):  PROBLEMS FOUND

Checked:
- FSLogix on CTXVDA01 for user jdoe, checked from WS-114 over the network: services, profile settings, event logs (last 24 hours), disk space and the profile share.
- PROBLEM: FSLogix Apps Services is Stopped (start type Auto).
Ruled out:
- FSLogix profile containers are enabled (Enabled = 1).
- Disk C: 120 GB free of 200 GB (60 percent).
Could not check:
- [share path removed] could not be confirmed from CTXVDA01. It CAN be reached from your PC.
Next step:
- Start with the first problem listed; it is the most likely cause.
- ...

Computer: CTXVDA01 | Ran by: CONTOSO\jtech on WS-114 | 2026-10-17 09:30:12 (UTC+01:00) | Changed anything: No
Evidence: FSLogixTriage_CTXVDA01_2026-10-17_093012.txt, FSLogixTriage_CTXVDA01_2026-10-17_093012.csv
```

- **Ruled out** only lists checks that really ran. Anything the tool could not read (ping, services, registry, event logs, disks), a profile share it could not confirm from the server (the double hop below; the line says whether it worked from your PC), and a Cloud Cache location it does not test are listed under **Could not check**. In the report they stay warnings, as before.
- The FSLogix settings block and Cloud Cache entries (their connection strings) never go into the note. They stay in the text report, with secrets redacted. A misspelled Cloud Cache entry is reported by which part is wrong, never by repeating the entry, so a typo such as a missing comma cannot carry a storage key into the report, the note or the clipboard. As a last check, any note line that still looks like a connection string, account key or SAS token is replaced.
- **Where the files go:**
  - `-TicketNumber 482113`: the text report, the CSV and `Note_<date>_<time>_Citrix-FSLogix-Triage.txt` go into `Ticket_482113` under `-OutputPath`, or under `%USERPROFILE%\Documents\TicketNotes` when `-OutputPath` is not given. A ticket number that does not fit (letters, digits, `-` or `_`, up to 32 characters) is refused with a `[FAIL]` line and exit code 3, before anything is checked.
  - `-OutputPath` alone: the note is saved next to the reports.
  - Neither: no files. The note goes to the clipboard, or is printed on the console if the clipboard is not available (for example on a server with no desktop).
- IP addresses and share paths are replaced by `[IP removed]` / `[share path removed]`, so the note is safe to paste. Add `-FullDetail` to keep them. Evidence shows file names only.
- The note never changes the verdict or the exit code.
- Ran several tools on the same ticket? `..\TicketNote\Join-TicketNotes.ps1 -TicketNumber 482113` joins their notes into one.
- **The clipboard is not private.** On Windows PowerShell 5.0 and later the note is copied with `Set-Clipboard`, so it can land in clipboard history (Win+V) and the cloud clipboard (synced to the user's other devices, if turned on). On 3.0 and 4.0 the note is marked to stay out of both. In a Remote Desktop session the clipboard is shared with the PC you connected from (RDP clipboard redirection). The note names the server and the user, so add `-NoClipboard` when that matters; the note file is still saved when a folder is in play.
- The note is built by `CaseKit.ps1` in this folder. Keep it next to the script. Without it the check still runs, with no note, and `-TicketNumber` is ignored (the warning says so).

## Requirements

- PowerShell 3.0 or later (Server 2012 and up), Windows PowerShell 5.1 or PowerShell 7.
- On the session host: ping, WinRM (for CIM and `Invoke-Command`), the Remote Registry service,
  and remote Event Log access.
- No modules to install.

## What it does not check

The user's own container file (size, locks, corruption), the FSLogix text logs, and Citrix broker
state. Use these next:

- `Parse-FSLogixLogs`: reads the FSLogix profile logs for load times and errors
- `RDS-FSLogix-EventExport`: every RDS and FSLogix event for a time window, as a report
- `FSLogix-ProfileDiskRepair`: scan and repair a user's VHDX
- `Citrix-FSLogix-HealthCollector`: performance and events across the whole farm

## For other tools

`-PassThru -Quiet` returns an object with `CheckId` (`citrix.fslogix.triage`), `Status`
(`Pass`/`Warn`/`Fail`), `Summary`, `Evidence` (Name, Status, Detail, Action, NotChecked),
`RecommendedNextSteps`, `RawOutput`, `StartedAt`, `FinishedAt`, `Error` and `TicketNote` (the note
object; `$null` when `CaseKit.ps1` is missing). Secrets in Cloud
Cache settings (Azure connection strings, keys, tokens) are redacted. Apart from `NotChecked` and
`TicketNote`, this is the same shape the old `MSP-TroubleshootingWorkbench` check returned.

## Tests

```powershell
Invoke-Pester .\Citrix-FSLogix-Triage\Tests
```

All remote calls are mocked. The tests cover the documented FSLogix rules, plus regressions for
the bugs fixed when this left the workbench (see below).

## History

This was the `citrix.fslogix.triage` check of `MSP-TroubleshootingWorkbench`, which now lives in
its own repository. Changes made when it became a standalone tool:

- Added plain-English console output with a "What to do" per finding, `-OutputPath`, and exit codes.
- Services are read through `Win32_Service`. `Get-Service -ComputerName` does not exist in
  PowerShell 7.
- Only `HKLM\SOFTWARE\FSLogix\Profiles` is treated as the effective setting. The old check let
  `HKLM\SOFTWARE\Policies\FSLogix\Profiles` override it, which FSLogix does not document.
- New checks from the FSLogix reference: `VHDLocations` and `CCDLocations` must not both be
  set, and Cloud Cache entries are case sensitive.
- A missing FSLogix event log is now reported as "missing", not as a permissions problem.
- A remote share test that fails is checked again from your PC, so the double hop does not
  read as an outage.
- Requires only PowerShell 3.0.
