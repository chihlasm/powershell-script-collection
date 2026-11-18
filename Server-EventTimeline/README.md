# Server Event Timeline

**What happened on these servers around 3am?** Pick one or more servers and a time, and get
every event from their logs on **one timeline**, sorted by time, with the important ones
flagged. It replaces opening Event Viewer on each server, one log at a time, and lining the
times up by hand. It also shows several servers side by side, which Event Viewer can't do.

Read-only: it changes nothing on any server.

```powershell
.\Start-ServerEventTimeline.ps1
.\Start-ServerEventTimeline.ps1 -ComputerName APP01, SQL01, DC01

# No window (RMM scripts, scheduled runs): CSV + HTML report, and a ticket note
.\Start-ServerEventTimeline.ps1 -NoGui -ComputerName APP01, SQL01 -At '2026-11-17 03:00' -TicketNumber 482113
```

Run it from your admin workstation. Your account needs to be able to read the servers' event
logs (local admin, or a member of **Event Log Readers**, on each server).

## How to use it

1. **Which servers?** The list starts with **this computer** already filled in. Type more
   names (commas, spaces or new lines all work), press **This computer** to add it back, or
   use **Pick from AD...** to add every domain controller or find servers by part of their
   name. **Recent** lists the last 8 server lists you searched (for example one client's
   servers), so you don't retype them. Workstations work too: any Windows machine you can reach.
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
5. Read **What was found** above the list: one line per server, for example
   *APP01: 1 unexpected restart, 3 service failures, 1 update installed* or
   *SQL01: nothing flagged in 1,240 events*. It counts every event read, whatever the filters.
6. Narrow it down: level (Warnings and worse, Errors and worse...), server, log, **Flagged
   only**, or search the message, source or event ID. **Collapse repeats** shows the same
   routine event on the same server once, as *[240x, last at 03:14:22] ...*; click it to see
   every time it happened. Flagged events are never collapsed.
7. **Right-click a row:**
   - **Search all servers around this event (+/- 5 min)**: what happened just before and
     after it, everywhere. The time is that server's local time.
   - **Show only this event**: the same source and event ID on every server.
   - **Hide events from this source**: for chatty sources such as Task Scheduler. What's
     hidden is named next to the filters; **Show everything again** brings it back.
   - **Show only this server**.
8. Click a row to see everything about the event. Then **Export CSV**, **Export HTML report**
   (with *What was found* at the top), or **Copy selected rows** to paste into the ticket.
   Exports always contain every filtered event, even when repeats are collapsed.
9. **Ticket note...** asks for the ticket number and writes the four-part ticket note
   (found, ruled out, couldn't check, next steps) and the HTML report into
   `Documents\TicketNotes\Ticket_<number>`, then copies the note. That's the folder the quick
   checks use, so [TicketNote](../TicketNote/)'s `Join-TicketNotes.ps1` merges them into one
   note. A server is only *ruled out* when every log was read in full and nothing was flagged.
10. **Save reports to:** shows where exports go. Type a folder or press **Browse...** (for
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
    safety limit. Raise it under **More options** (*Stop each server at ... events in total*).
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

**Security log:** an account that isn't allowed to read a server's Security log can't see it
in that server's list of logs either. The tool reads it anyway when you tick Security, so you
get *Access denied* (the real reason) rather than *doesn't exist*.

A dead server is spotted in about 4 seconds (a 2-second port check for WinRM, then one for
the remote event log), so it never holds up the others. Up to 8 servers are read at once.

**Run as:** under **More options**, **Run as another account...** reads the servers with a
different account (for example another domain's admin). Cancel the prompt to go back to your
own account.

## Known limits

- **Cancel on the remote-event-log route:** the window stops waiting at once, but a query
  already running over RPC can carry on in the background for a short while until the server
  answers. WinRM queries stop properly.
- **Daylight saving:** one UTC offset is used per server for the whole window. On the WinRM
  route (and for this computer) it is the offset at the window's **start**; on the
  remote-event-log route it is the offset **now**. So a window that crosses a daylight-saving
  change, or a remote-event-log search on the other side of one, can be up to an hour out for
  part of the window. The UTC column is always right: compare that when in doubt.
- **Search around this event** uses that row's server-local time on every server, so it is
  greyed out when the servers are in different time zones (the blue note says so): search by
  a From/To range instead.
- **Selecting many rows:** after a refresh, up to 200 selected rows are put back exactly;
  with more (Ctrl+A), the rows still listed stay selected but nothing new is re-added.
- **Big windows:** 50,000 rows are fine, but filtering then takes about a second.

## Without the window (-NoGui)

For RMM scripts, scheduled tasks or a quick look from a console. It uses the same background
reading, prints how each server went and *What was found*, and writes the CSV, the HTML report
and a log.

```powershell
# Around a time (each server's local time), +/- 30 minutes
.\Start-ServerEventTimeline.ps1 -NoGui -ComputerName APP01, SQL01 -At '2026-11-17 03:00' -PlusMinusMinutes 30 -OutputPath D:\Reports

# A range, extra logs, with a ticket note (Documents\TicketNotes\Ticket_482113)
.\Start-ServerEventTimeline.ps1 -NoGui -ComputerName DC01 -From '2026-11-17 02:00' -To '2026-11-17 04:00' -LogName System, 'Group Policy' -IncludeSecurity -TicketNumber 482113

# The last two hours on this computer
.\Start-ServerEventTimeline.ps1 -NoGui -LastMinutes 120
```

| Option | What it does |
|---|---|
| `-ComputerName` | Servers to read. Default: this computer. |
| `-At` + `-PlusMinusMinutes` | Around a time (default +/- 15 min). |
| `-From` + `-To` | A range. |
| `-LastMinutes` | The last N minutes (default 60), when no time is given. |
| `-LogName` | Logs by checkbox label (`System`, `Task Scheduler`, `Group Policy`...) or log name. Default: the window's default logs. |
| `-IncludeSecurity`, `-AllLogs` | Same as the window's Slow options. |
| `-Cap`, `-TotalCap`, `-TimeoutSec` | Per log, per server and per log time limits (defaults 5000, 50000, 60). |
| `-Credential` | Read the servers as another account. |
| `-TicketNumber` | Write the ticket note, CSV and report into `<-OutputPath or Documents\TicketNotes>\Ticket_<number>`, and copy the note (`-NoClipboard` to skip that). |
| `-OutputPath` | Where the files go (without `-TicketNumber`, default `Reports\` beside the script). |

Exit codes: `0` every log was read in full, `1` a server or log couldn't be read in full
(the output says which), `2` couldn't run (a time it couldn't read, a bad ticket number, or a
folder it couldn't create).

## Files

- `Start-ServerEventTimeline.ps1`: the window and the -NoGui mode (run this)
- `ServerEventTimeline.Core.ps1`: logic: times, logs, flags, summary, filters, exports, ticket note
- `ServerEventTimeline.Engine.ps1`: reading servers in the background
- `CaseKit.ps1`: the shared ticket-note kit (an identical copy of `TicketNote\CaseKit.ps1`)
- The save folder (default `Reports\` beside the script; see step 7): exports and an activity log,
  `ServerEventTimeline_yyyy-MM-dd_HHmmss.*`. These contain client data: don't commit or
  sync them.

Keep the four `.ps1` files together. Recent server lists and the save folder are remembered
per user in `%APPDATA%\ServerEventTimeline\settings.json`. Needs Windows PowerShell 5.1 or PowerShell 7 on
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
