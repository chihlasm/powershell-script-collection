# Server Event Timeline

**What happened on these servers around 3am?** Pick one or more servers and a time, and get
every event from their logs on **one timeline**, sorted by time, with the important ones
flagged. It replaces opening Event Viewer on each server, one log at a time, and lining the
times up by hand. It also shows several servers side by side, which Event Viewer can't do.

Read-only: it changes nothing on any server.

```powershell
.\Start-ServerEventTimeline.ps1
.\Start-ServerEventTimeline.ps1 -ComputerName APP01, SQL01, DC01
```

Run it from your admin workstation. Your account needs to be able to read the servers' event
logs (local admin, or a member of **Event Log Readers**, on each server).

## How to use it

1. **Which servers?** The list starts with **this computer** already filled in. Type more
   names (commas, spaces or new lines all work), press **This computer** to add it back, or
   use **Pick from AD...** to add every domain controller or find servers by part of their
   name. Workstations work too: any Windows machine you can reach.
2. **When?** "Around 2026-11-17 03:00 +/- 15 min" is the usual start. You can switch to
   **From ... to ...**, or press **Last hour** / **Last 24 hours** to search right away.
   **The time is each server's local time**: "03:00" means 03:00 on each server, which is
   what the client says and what Event Viewer on the server shows.
3. **Which logs?** Click the logs box to open the list. It's grouped as **Everyday**
   (System, Application), **Extra detail** (the useful extra logs below) and **Slow**
   (Security, All logs with events). Everyday and extra detail are ticked by default;
   **All**, **None** and **Default** buttons reset the list quickly. The closed box sums
   up the choice, e.g. *System, Application + 8 more*.
4. Press **Search**. Each server is read in the background. Rows appear as servers finish,
   and you can scroll and filter while it works. **Cancel** stops at once and keeps what was
   read.
5. Narrow it down: level (Warnings and worse, Errors and worse...), server, log, **Flagged
   only**, or search the message, source or event ID.
6. Click a row to see everything about the event. Then **Export CSV**, **Export HTML report**,
   or **Copy selected rows** to paste into the ticket.
7. **Save reports to:** shows where exports go. Type a folder or press **Browse...** (for
   example the ticket's folder). The folder is remembered for next time, per user, in
   `%APPDATA%\ServerEventTimeline\settings.json`. **Open folder** shows it in File Explorer.
   `-OutputPath` on the command line overrides it for that run.

## The logs

| Checkbox | Log | Notes |
|---|---|---|
| System | System | Restarts, services, disks, drivers, updates |
| Application | Application | App crashes and hangs, SQL, backup software |
| Task Scheduler | Microsoft-Windows-TaskScheduler/Operational | **Off by default on most servers**; the tool says so if it is |
| Group Policy | Microsoft-Windows-GroupPolicy/Operational | Policy processing |
| Remote Desktop sessions / connections | TerminalServices-LocalSessionManager / RemoteConnectionManager Operational | Who signed in over RDP, disconnects |
| File share client / server (SMB) | SMBClient / SMBServer Operational | Slow or failing file shares (SMB server 1020 = slow storage) |
| Windows Time | Microsoft-Windows-Time-Service/Operational | Time sync |
| Failover Clustering | Microsoft-Windows-FailoverClustering/Operational | Cluster nodes only |
| Security | Security | Off by default: huge on DCs and file servers |
| All logs with events | every log with records | Off by default: can be 100+ logs |

A log a server doesn't have, or has turned off, is skipped and named in the report, never
shown as an error. The Windows Update client and Hyper-V VMMS logs are left out because
Microsoft's documentation didn't confirm their exact names. Windows Update installs still
appear in the System log (event 19, flagged).

## What gets flagged

Flags are labels, so they never hide anything. Every flag is checked against Microsoft's
documentation (sources are in `ServerEventTimeline.Core.ps1`):

- **Restarts:** restart/shutdown requested (1074, with who and why), restarted without a
  clean shutdown (Kernel-Power 41), previous shutdown unexpected (6008), Windows started or
  shut down (6005, 6006, Kernel-General 12/13)
- **Blue screens:** WER-SystemErrorReporting 1001
- **Services:** crashed (7031, 7034), stopped with an error (7024), failed to start (7000),
  timed out (7011)
- **Disks:** disk errors (51, 153), controller error (11) and storage reset (129) from the
  storage driver, NTFS corruption (55, 98)
- **Updates:** Windows Update installed an update (19)
- **Apps:** Application Error 1000, Windows Error Reporting 1001, Application Hang 1002
- **Time:** system time changed (Kernel-General 1), no time source (Time-Service 129, 134)
- **Memory:** Windows ran low on memory (Resource-Exhaustion-Detector 2004)

## Reading the results

Each server shows one line:

- **done - 1,240 events (via WinRM)**: everything asked for was read.
- **done with gaps**: at least one log is incomplete. A **yellow banner** names it:
  - *stopped at 5,000 events - narrow the window or raise the cap*: there was more.
    The first 5,000 of the window are shown. Raise the limit under **More options**.
  - *didn't answer within 60 s*: that log was too slow. The other logs on that server
    still show.
  - *not read - stopped at the 50,000 event total for this server*: "All logs" hit its
    safety limit.
- **couldn't reach - why**, for example *Access denied on DC01: check you're an admin
  there, or use Run as*, or *WinRM and remote event log are both unreachable from here*.

A short log is never presented as a quiet one: an incomplete log is always named.

**Times:** the first column is each server's local time, and the UTC column sits beside it.
The order is always by real (UTC) time. If you mix servers in different time zones, a note
tells you to compare the UTC column.

## How it reaches servers

0. **This computer** (by its name, its FQDN, `localhost`, `.` or `127.0.0.1`) is read
   **directly** from its own logs: no WinRM, no firewall rules, no network. Its status line
   says *(this computer, read directly)*. Run as doesn't apply to it. Reading its
   **Security** log needs the tool started **as administrator**; without that, the Security
   log says so and the other logs read normally.
1. **WinRM** (TCP 5985): the query runs on the server and only matching events come back.
   This is the normal route on Windows Server 2012 and later.
2. If WinRM can't connect, it uses the **remote event log** over RPC (TCP 135 plus dynamic
   ports, firewall rule group *Remote Event Log Management*). With this route the message
   text is built on **your** workstation, so events from software that isn't installed there
   (SQL Server, backup agents...) show *"No message text: the event's provider isn't
   installed on this workstation"*. The event ID and source are still correct.
3. **Access denied** is reported straight away, not retried the other way.

A dead server is spotted in about 2 seconds (port check), so it never holds up the others.
Up to 8 servers are read at once.

**Run as:** under **More options**, **Run as another account...** reads the servers with a
different account (for example another domain's admin). Cancel the prompt to go back to your
own account.

## Known limits

- **Cancel on the remote-event-log route:** the window stops waiting at once, but a query
  already running over RPC can carry on in the background for a short while until the server
  answers. WinRM queries stop properly.
- **Daylight saving on the remote-event-log route:** the server's UTC offset is read as it is
  *now*. A window on the other side of a daylight-saving change can be an hour out. The WinRM
  route uses the offset at the window's start, so it is exact.
- **Big windows:** 50,000 rows are fine, but filtering then takes about a second.

## Files

- `Start-ServerEventTimeline.ps1`: the window (run this)
- `ServerEventTimeline.Core.ps1`: logic: times, logs, flags, filters, exports
- `ServerEventTimeline.Engine.ps1`: reading servers in the background
- The save folder (default `Reports\` beside the script; see step 7): exports and an activity log,
  `ServerEventTimeline_yyyy-MM-dd_HHmmss.*`. These contain client data: don't commit or
  sync them.

Keep the three `.ps1` files together. Needs Windows PowerShell 5.1 or PowerShell 7 on
Windows. Pick from AD needs the RSAT Active Directory tools (optional).

## Smoke test

```powershell
powershell.exe -NoProfile -STA -File .\Start-ServerEventTimeline.ps1 -SmokeTest
```

Opens the window off-screen, checks it built, prints `[PASS]` and closes (exit code 0). It
queries no server and writes no file.

## Tests

```powershell
pwsh -File ..\Tests\Invoke-AllTests.ps1 -Path .\Tests
```

Every remote call is mocked. The engine tests use a real background pool with fake
servers.

## References

- Get-WinEvent: https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent
- Unexpected reboots and their events: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
- Disk and NTFS errors: https://learn.microsoft.com/troubleshoot/windows-server/backup-and-storage/troubleshoot-data-corruption-and-disk-errors
- RPC server unavailable (0x6BA) and its ports: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/status-code-0x6ba-rpc-server-unavailable
- Full per-event citations are in `ServerEventTimeline.Core.ps1` and `ServerEventTimeline.Engine.ps1`.
