# Network-QuickCheck

**"I can't reach the server" / "the app won't connect" / "my mapped drive won't connect."**

Run it **on the computer that has the problem** and name the server and port it can't reach.
The first line answers the question:

```
Can PC-0423 reach FILESRV01 on port 445?  YES, WITH WARNINGS
======================================================================
Warnings:
  [WARN] Ping: FILESRV01 did not answer a ping.
         What to do: Many servers block ping on purpose. If the port test passes, ignore this.
Looks fine:
  [PASS] Name lookup (DNS): FILESRV01 resolves to 10.0.0.5.
  [PASS] Port 445 (file shares (SMB)): Connected to 10.0.0.5:445 from 10.0.0.20:51234.
  [PASS] Default gateway: Gateway 10.0.0.1 on Ethernet.
```

It is **read-only**.

## Quick start

```powershell
# Mapped drive won't connect
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress FILESRV01 -Port 445

# Remote Desktop gateway: two ports at once, with a report for the ticket
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress rds.contoso.com -Port 443,3389 -OutputPath C:\Temp

# An IP address works too (the DNS step is skipped)
.\Invoke-NetworkQuickCheck.ps1 -TargetAddress 10.0.0.5 -Port 3389
```

## What it checks

1. **Name lookup (DNS).** Does the name turn into an address? Skipped for an IP address.
2. **Ping.** A missed ping is only a warning; many servers block it.
3. **Each TCP port.** Does the port accept a connection within 3 seconds? This is the result
   that matters.
4. **Default gateway.** Does this computer have a way off its own subnet?

The answer is **YES** when every port connects, **PARTLY** when some do, and **NO** when none do.

### Common ports

| Port | Used by |
|---|---|
| 445 | File shares / mapped drives (SMB) |
| 3389 | Remote Desktop |
| 443 / 80 | Websites, most cloud apps, RD Gateway |
| 1494 / 2598 | Citrix ICA / session reliability |
| 389 / 636 / 3268 | LDAP / LDAPS / Global Catalog |
| 88 | Kerberos |
| 53 | DNS |
| 1433 | SQL Server |
| 5985 / 5986 | WinRM |

## Parameters

| Parameter | Meaning |
|---|---|
| `-TargetAddress` | Host name, FQDN or IP address. Required. Aliases `-ComputerName`, `-Target`. |
| `-Port` | One or more TCP ports. Default 443. |
| `-TimeoutMilliseconds` | Wait per port before calling it closed. Default 3000. |
| `-OutputPath` | Folder for `NetworkQuickCheck_<target>_<timestamp>.txt` and `.csv`. Omit for console only. |
| `-TicketNumber` | Put the reports and the ticket note in `Ticket_<number>` (see Ticket note). |
| `-NoClipboard` | Do not copy the ticket note to the clipboard. |
| `-FullDetail` | Keep IP addresses and share paths in the ticket note. |
| `-PassThru` | Return the result object instead of setting an exit code (for other scripts). |
| `-Quiet` | No console output and no clipboard. Use with `-PassThru` or `-OutputPath`. |

**Exit codes** (without `-PassThru`): 0 = reachable, 1 = reachable with warnings, 2 = cannot reach
(or no target given), 3 = a `-TicketNumber` that does not fit.

## Ticket note

Every run ends with a short note on the clipboard, ready to paste into the ticket:

```
[Ticket note] Network-QuickCheck: Can PC-0423 reach FILESRV01 on port 445? YES, WITH WARNINGS

Checked:
- Tested from PC-0423 to FILESRV01 on TCP port 445.
- WARNING: Ping: FILESRV01 did not answer a ping.
Ruled out:
- Name lookup (DNS): FILESRV01 resolves to [IP removed].
- Port 445 (file shares (SMB)): Connected to [IP removed] from [IP removed].
- Default gateway: Gateway [IP removed] on Ethernet.
Could not check:
- (none)
Next step:
- Confirm the server name and port are right for the application.
- Run the same check from a computer that works; if it passes there, the problem is this computer or its network.

Computer: PC-0423 | Ran by: CONTOSO\jtech on PC-0423 | 2026-10-17 09:30:12 (UTC+01:00) | Changed anything: No
Evidence: NetworkQuickCheck_FILESRV01_2026-10-17_093012.txt, NetworkQuickCheck_FILESRV01_2026-10-17_093012.csv
```

- **Ruled out** only lists checks that really ran. A ping that could not run at all, or a routing table that could not be read, is listed under **Could not check**. So is the default gateway on Windows versions without `Get-NetRoute` (before Windows 8 / Server 2012).
- For an IP address there is no name lookup, so it is in neither list; the first line says no lookup was needed.
- **Where the files go:**
  - `-TicketNumber 482113`: the text report, the CSV and `Note_<date>_<time>_Network-QuickCheck.txt` go into `Ticket_482113` under `-OutputPath`, or under `%USERPROFILE%\Documents\TicketNotes` when `-OutputPath` is not given. A ticket number that does not fit (letters, digits, `-` or `_`, up to 32 characters) is refused with a `[FAIL]` line and exit code 3, before anything is checked.
  - `-OutputPath` alone: the note is saved next to the reports.
  - Neither: no files. The note goes to the clipboard, or is printed on the console if the clipboard is not available (for example on a server with no desktop).
- IP addresses and share paths are replaced by `[IP removed]` / `[share path removed]`, so the note is safe to paste. Add `-FullDetail` to keep them. Evidence shows file names only.
- The note never changes the answer or the exit code.
- Ran several tools on the same ticket? `..\TicketNote\Join-TicketNotes.ps1 -TicketNumber 482113` joins their notes into one.
- **The clipboard is not private.** On Windows PowerShell 5.0 and later the note is copied with `Set-Clipboard`, so it can land in clipboard history (Win+V) and the cloud clipboard (synced to the user's other devices, if turned on). On 3.0 and 4.0 the note is marked to stay out of both. In a Remote Desktop session the clipboard is shared with the PC you connected from (RDP clipboard redirection). The note names the server you tested, so add `-NoClipboard` when that matters; the note file is still saved when a folder is in play.
- The note is built by `CaseKit.ps1` in this folder. Keep it next to the script. Without it the check still runs, with no note, and `-TicketNumber` is ignored (the warning says so).

## Requirements

PowerShell 3.0 or later. Nothing to install. On Windows 8 / Server 2012 and later it uses
`Resolve-DnsName` and `Get-NetRoute`; on older systems it falls back to the .NET resolver and
skips the gateway check.

## What it does not check

UDP ports, the firewall on the far end, share or NTFS permissions, or whether the service
behind the port is healthy. A port that connects only tells you something is listening.

For an interactive menu of more network tools (traceroute, Wi-Fi details, certificate check),
see `Network-Troubleshooting-Palette`.

## For other tools

`-PassThru -Quiet` returns an object with `CheckId` (`network.quick`), `Status`, `Answer`
(`YES` / `YES, WITH WARNINGS` / `PARTLY` / `NO`), `Summary`, `Evidence` (Name, Status,
Detail, Action, NotChecked), `RecommendedNextSteps`, `RawOutput`, `StartedAt`, `FinishedAt`, `Error`
and `TicketNote` (the note object; `$null` when `CaseKit.ps1` is missing).
Apart from the new `Answer`, `NotChecked` and `TicketNote` fields, this is the same shape the old `MSP-TroubleshootingWorkbench`
check returned.

## Tests

```powershell
Invoke-Pester .\Network-QuickCheck\Tests
```

## History

This was the `network.quick` check of `MSP-TroubleshootingWorkbench`, which now lives in its own
repository. Changes made when it became a standalone tool:

- Added plain-English console output, `-OutputPath`, exit codes, and several ports per run.
- `-TargetAddress` is required. The old check quietly tested `localhost` when none was given.
- An IP address no longer gives a misleading DNS warning.
- Ports are tested with a 3-second TCP connect instead of `Test-NetConnection`, which waits
  about 20 seconds on a closed port and does not exist on Server 2012.
- Requires only PowerShell 3.0.
