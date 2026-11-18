# Port Monitor

Keeps checking whether servers answer on their TCP ports and logs every time one goes up or
down. Use it in a window on your workstation, or in the console on a server or from an RMM
tool.

- **No installs, no admin rights, no modules.** One script. Runs on Windows PowerShell 3.0–5.1
  and PowerShell 7 (Windows).
- **Tells you why, not just "failed":**

  | Status | What it means |
  |---|---|
  | **Open** | The port accepted a connection. Latency is shown. |
  | **Refused** | The server answered, but nothing is listening on that port (service stopped, wrong port). |
  | **Timeout** | No answer in time. A firewall is dropping the traffic, or the host is off. |
  | **DNS Failure** | The name could not be resolved. Check the spelling, or the DNS server. |
  | **Error** | Anything else, such as "network unreachable". The **Details** column says what. |

- **Tells you when a connection is bad, not just down:** optional packet-loss measuring (see
  [below](#packet-loss-up-but-bad)).

## How to run it

```powershell
# Window, using the default target list (%APPDATA%\PortMonitor\targets.json)
.\PortMonitor.ps1

# Window, using one client's target list (changes are saved back to that file)
.\PortMonitor.ps1 -ConfigPath '\\fileserver\it\clients\contoso-ports.json'

# Console on a server: live table, Ctrl+C to stop
.\PortMonitor.ps1 -NoGui -ConfigPath C:\Temp\targets.json

# One pass for an RMM check or a scheduled task
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PortMonitor.ps1 -Once -ConfigPath C:\Temp\targets.json

# Uptime and outage report for the last 30 days, saved in C:\Temp
.\PortMonitor.ps1 -Report -Days 30 -OutputPath C:\Temp
```

Started from a PowerShell prompt, the window opens in a PowerShell process of its own and the
prompt is free again straight away. A window opened inside a PowerShell session that had been
open for hours (VS Code, Windows Terminal) could crash that whole session.

In the window: **Add** a target, then click **Start**. Double-click a row to change it.
Untick **Enabled** on a row to pause that target. Click a row to see its full details in the
panel under the list.

### Adding a whole server at once

In **Add**, pick **What is it?** to add every usual port for that kind of server in one go.
Each port becomes its own row, labelled like `Contoso DC01 - LDAP`. Untick any port you don't
need. Ports that are already in the list for that host are skipped.

| What is it? | Ports added |
|---|---|
| Domain controller | 53 DNS, 88 Kerberos, 135 RPC, 389 LDAP, 445 SMB, 464 Kerberos password change, 636 LDAP SSL, 3268/3269 Global Catalog |
| File server | 445 SMB |
| Remote Desktop server | 3389 RDP, 443 HTTPS (RD Gateway / RD Web) |
| SQL Server | 1433 (default instance; named instances use their own port, so change it after adding) |
| Exchange server | 443 HTTPS, 25 SMTP, 587 SMTP submission |
| Web server | 80 HTTP, 443 HTTPS |
| Network printer | 9100 RAW printing, 515 LPD |
| Remote management (WinRM) | 5985 HTTP, 5986 HTTPS |

The ports come from Microsoft's documentation: [Windows service ports](https://learn.microsoft.com/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements),
[Exchange ports](https://learn.microsoft.com/exchange/plan-and-deploy/deployment-ref/network-ports),
and [Standard TCP/IP printer port](https://learn.microsoft.com/troubleshoot/windows-server/printing/standard-port-monitor-for-tcpip).

### Ignoring one-off blips

A single dropped connection on a busy link no longer counts as an outage. A target that was
**Open** is only reported down after **2 failed checks in a row**, and back up after **1 good
check**. While a change is being confirmed, the row keeps its old status and **Details** shows
something like `Confirming: Timeout (1 of 2 in a row)`. Nothing is logged or notified until the
change is confirmed.

You can change both numbers per target in **Add**/**Edit** (**Report down after** / **Report back
up after**, 1–10). Set **Report down after** to 1 to hear about every single failure. The very
first check is always reported straight away, and Fails / Uptime % still count every check.

### Packet loss: "up, but bad"

A port check only asks "does it answer?". **Lost packets usually stay hidden**: TCP sends a lost
packet again, so the port still shows **Open**, just a little slower. A line losing 5% of its
packets makes calls choppy and RDP sluggish while every port stays green.

To measure loss, tick **Measure packet loss** in **Add**/**Edit**. After each port check, Port
Monitor pings the same address a few times (**Pings per check**, default 10) and shows:

| Column | What it shows |
|---|---|
| **Loss %** | Share of this check's pings that got no answer. Turns **amber** when the host is losing packets. Says *no reply* when ping is blocked. |
| **Jitter** | How uneven the answers were: the average change between one ping's time and the next. High jitter hurts calls even without loss. |

- **When it warns:** when the loss reaches **Warn when this % is lost** (default 5%) for
  **Report down after** checks in a row (default 2), and when it's back below the line for
  **Report back up after** checks. You get a notification, a line in the log, and the tray
  icon turns **amber**.
- **Ping blocked?** Many firewalls drop pings. If no ping is answered while the port is open,
  Port Monitor says *no reply* and reports nothing. That isn't loss, it just can't be measured
  for that host. In that case, use the slow-answer hint below.
- **Presets ping once per host:** with **What is it?**, only the first port measures loss.
  Loss is the same whichever port you look at.
- **Slow answers, for every target:** a port that normally answers in 2 ms and suddenly takes
  over a second usually lost a packet that had to be sent again. **Details** says so
  (`Slow answer: 1100 ms (usually 2 ms), often a lost packet that had to be resent`). It's a
  hint only, and isn't logged or notified, because a single resend is normal on any network.
- **Not a full line test:** 10 pings every 30 seconds will spot loss that keeps happening, not
  a single dropped packet. For a one-off look at *where* packets are lost, run
  `pathping <host>`.

### Uptime and outage report

Click **Report** and pick **Last 24 hours**, **Last 7 days** or **Last 30 days**. Port Monitor
reads its logs, writes an HTML page to `Logs\Reports`, and opens it. The page has a one-line
verdict at the top ("2 of 14 targets had outages: 3 in total, 47 min of downtime. Longest: …"),
each target's uptime %, and every outage with when it went down, when it came back, and how long
it lasted. If any host had periods of high packet loss, they get their own table, and the verdict
mentions them. It's ready to attach to a ticket.

The log only records changes, so the report counts any time Port Monitor wasn't running as the
last state it saw. Outages that were cut short by a restart are marked as such.

### Keyboard and look

| Key | Does |
|---|---|
| Insert | Add |
| Delete | Remove the selected row |
| Enter or F2 | Edit the selected row |
| F5 | Start / Stop |

**Light mode / Dark mode** (top right) switches the look. Port Monitor remembers the look, the
window's size and position, and how the list is sorted. If the monitor it was on has since been
unplugged, it opens in the middle of the screen instead.

## Running in the background

Click **Run in Background** in the window, or start it with `-Tray`. The window goes away and
checking carries on. A round icon in the notification area (near the clock) shows how things
stand:

| Icon | Meaning |
|---|---|
| Green | Every target is open |
| Amber | Every port answers, but a host is losing packets |
| Red | At least one target is not answering. Hover over the icon to see which. |
| Blue | Checking (results not in yet) |
| Grey | Stopped, or nothing to check |

- **A Windows notification appears whenever a target changes**: it goes down, comes back up,
  fails its very first check, starts losing packets, or stops losing them. Several changes at once are combined into one notification.
  Click the notification to open the window. No notification is shown while you're looking at
  the window, and none is shown for targets that are simply open when monitoring starts.
- **Click the icon** to open the window. **Closing the window** hides it again, and checking
  continues. To quit, right-click the icon and choose **Exit Port Monitor**.
- **Right-click the icon** to: Open, Stop/Start monitoring, Open log folder,
  **Start when I sign in**, or Exit.
- **The first time it runs in the background, it offers to start at sign-in.** If you say Yes, it
  adds `Port Monitor.lnk` to your Startup folder (`shell:startup`). No admin rights are needed.
  The shortcut runs the script from where it is at that moment, so if you move the script,
  turn the option off and on again. You're only asked once; after that, use the menu item.
- **Only one copy runs per user.** Starting Port Monitor again, whether from the shortcut, a
  double-click or `-Tray`, opens the copy that is already running instead of starting a second
  one. That way changes are never logged twice. Other users signed in to the same RDS server
  each get their own copy.

Windows decides how notifications look and whether they appear. Do Not Disturb / Focus can
hide them, and they show up as coming from "Windows PowerShell".

To try it out, **Import** `targets.example.json`. It has a public DNS server, a public web
host, and a closed local port that should show **Refused**.

## Parameters

| Parameter | What it does |
|---|---|
| `-ConfigPath <file>` | The target list to load. Default `%APPDATA%\PortMonitor\targets.json`. A missing file means an empty list. |
| `-LogPath <folder>` | Where the daily CSV logs go. Default `%APPDATA%\PortMonitor\Logs`. |
| `-Tray` | Starts in the background: no window, a notification area icon, checking starts at once, and a notification for every change. This is what the "Start when I sign in" shortcut runs. |
| `-Report` | Writes the uptime and outage report (HTML) from the logs and exits. Checks nothing. Use with `-Days` (1–366, default 7) and `-OutputPath` (default: the current folder). |
| `-NoGui` | Console mode: the same checks in a loop. You get a coloured table in a console window, or one `[PASS]`/`[FAIL]` line per change when the output is redirected (RMM). Stop with Ctrl+C. |
| `-Once` | Console, one pass: checks every enabled target once and exits. **Exit code 0** = all open, **1** = at least one is not open, or is losing packets above its warning level, **2** = nothing to check. |
| `-SmokeTest` | Opens the window off-screen, checks that it works, closes it, and prints `[PASS]`/`[FAIL]`. Reads and writes nothing. Run it with a time limit: `Tests\Invoke-SmokeTest.ps1 -ScriptPath PortMonitor\PortMonitor.ps1`. |

## Files

| File | What it is |
|---|---|
| `%APPDATA%\PortMonitor\targets.json` | The target list. The window saves it after every Add, Edit, Remove or Enabled change. Console mode never writes it. |
| `%APPDATA%\PortMonitor\Logs\PortMonitor_yyyyMMdd.csv` | One file per day, **state changes only**. Columns: `Timestamp, Label, Host, Port, PreviousStatus, NewStatus, LatencyMs`. |
| `%APPDATA%\PortMonitor\Logs\PortMonitor_Loss_yyyyMMdd.csv` | Only for targets that measure packet loss: one file per day, **changes only** (`OK`, `High loss`, `No replies`). Columns: `Timestamp, Label, Host, Port, PreviousStatus, NewStatus, LossPercent, JitterMs, AvgMs, Sent, Received`. |
| `%APPDATA%\PortMonitor\settings.json` | Your look (dark/light), window size and position, sort order, and whether you were already asked about starting at sign-in. |
| `%APPDATA%\PortMonitor\Logs\Reports\PortMonitor_Report_*.html` | Reports made with the **Report** button. |
| `<Startup folder>\Port Monitor.lnk` | Only if you choose **Start when I sign in**. Removing the tick deletes it. |
| `<targets file>.bak-yyyy-MM-dd_HHmmss` | Made only if a target list could not be fully read (bad JSON or invalid entries). The original is kept here before the first save replaces it. |

Each target in the JSON looks like this. Everything after `Port` is optional (defaults: 30,
3000, true, 2, 1, false, 10, 5). Lists saved by older versions load fine.

```json
[
  { "Label": "DC01 LDAP", "Host": "dc01.example.local", "Port": 389, "IntervalSec": 30, "TimeoutMs": 3000, "Enabled": true,
    "FailAfter": 2, "RecoverAfter": 1, "MeasureLoss": true, "LossPings": 10, "LossAlertPercent": 5 }
]
```

Limits: port 1–65535, interval at least 1 second, timeout 100–30000 ms, FailAfter and
RecoverAfter 1–10, LossPings 1–50, LossAlertPercent 1–100. The host cannot be blank.

The first result for each target is logged too, with `PreviousStatus` set to `Not checked`.
That way the log shows what state monitoring started in. If the CSV is open in Excel, the
write fails. The window says so in its status bar, and the console prints a `[WARN]`.

## Scripts downloaded to a client machine

Windows marks files from the internet or email as blocked. To run the script:

```powershell
Unblock-File -Path .\PortMonitor.ps1
```

If the execution policy still stops it ("running scripts is disabled on this system"), run it
for this one process only. This changes no machine setting:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PortMonitor.ps1
```

## Good to know

- **Use a timeout of 2500 ms or more.** Windows retries a connection that was refused, so a
  closed port takes about 2.1 seconds to show as **Refused**. With a shorter timeout, a
  closed port shows as **Timeout** instead. The default is 3000 ms.
- `TimeoutMs` applies to the DNS lookup and, separately, to the connection. One check can take
  up to twice the timeout. Latency is the connection time only.
- When a name resolves to several addresses, the first IPv4 address is checked. The
  **Details** column shows which address was used.
- Fails and Uptime % count every check since the target started being monitored in this
  session. They reset when you restart the tool, or when you change a target's host or port.
- Every column fits at the default window size. In a narrower window the list scrolls
  sideways. Text too long for its column ends in "…".
- **Click a row to read its full details** in the panel under the list. You can select and
  copy the text from there, for example into a ticket.
- Up to 16 checks run at the same time in the background, so the window never freezes.
- With packet loss on, each check takes longer: the pings are 200 ms apart, and each waits up
  to the timeout (at most 2 s) for an answer. 10 pings take about 2 seconds when all answer.
  Pings go to the address the port check used, and need no admin rights.
- The window needs an STA thread (WPF). If it is started from an MTA host, it relaunches
  itself with `-STA` and the same parameters.
- Pressing Ctrl+C in the console that started the window closes it cleanly, including in
  background mode.

## Tests

```powershell
pwsh -File Tests\Invoke-AllTests.ps1 -Path .\PortMonitor\Tests                      # unit tests (no network)
Invoke-Pester .\PortMonitor\Tests -TagFilter Integration                             # loopback ports and pings, child 5.1/7 processes, smoke
```
