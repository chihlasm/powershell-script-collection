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
```

In the window: **Add** a target, then click **Start**. Double-click a row to change it.
Untick **Enabled** on a row to pause that target. Hover over a row to see the full details.

## Running in the background

Click **Run in Background** in the window, or start it with `-Tray`. The window goes away and
checking carries on. A round icon in the notification area (near the clock) shows how things
stand:

| Icon | Meaning |
|---|---|
| Green | Every target is open |
| Red | At least one target is not answering. Hover over the icon to see which. |
| Blue | Checking (results not in yet) |
| Grey | Stopped, or nothing to check |

- **A Windows notification appears whenever a target changes**: it goes down, comes back up,
  or fails its very first check. Several changes at once are combined into one notification.
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
| `-NoGui` | Console mode: the same checks in a loop. You get a coloured table in a console window, or one `[PASS]`/`[FAIL]` line per change when the output is redirected (RMM). Stop with Ctrl+C. |
| `-Once` | Console, one pass: checks every enabled target once and exits. **Exit code 0** = all open, **1** = at least one is not, **2** = nothing to check. |
| `-SmokeTest` | Opens the window off-screen, checks that it works, closes it, and prints `[PASS]`/`[FAIL]`. Reads and writes nothing. Run it with a time limit: `Tests\Invoke-SmokeTest.ps1 -ScriptPath PortMonitor\PortMonitor.ps1`. |

## Files

| File | What it is |
|---|---|
| `%APPDATA%\PortMonitor\targets.json` | The target list. The window saves it after every Add, Edit, Remove or Enabled change. Console mode never writes it. |
| `%APPDATA%\PortMonitor\Logs\PortMonitor_yyyyMMdd.csv` | One file per day, **state changes only**. Columns: `Timestamp, Label, Host, Port, PreviousStatus, NewStatus, LatencyMs`. |
| `%APPDATA%\PortMonitor\settings.json` | Remembers that you were already asked about starting at sign-in. |
| `<Startup folder>\Port Monitor.lnk` | Only if you choose **Start when I sign in**. Removing the tick deletes it. |
| `<targets file>.bak-yyyy-MM-dd_HHmmss` | Made only if a target list could not be fully read (bad JSON or invalid entries). The original is kept here before the first save replaces it. |

Each target in the JSON looks like this. `IntervalSec`, `TimeoutMs` and `Enabled` are optional
(defaults: 30, 3000, true).

```json
[
  { "Label": "DC01 LDAP", "Host": "dc01.example.local", "Port": 389, "IntervalSec": 30, "TimeoutMs": 3000, "Enabled": true }
]
```

Limits: port 1–65535, interval at least 1 second, timeout 100–30000 ms. The host cannot be blank.

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
- Fail Count and Uptime % count every check since the target started being monitored in this
  session. They reset when you restart the tool, or when you change a target's host or port.
- Up to 16 checks run at the same time in the background, so the window never freezes.
- The window needs an STA thread (WPF). If it is started from an MTA host, it relaunches
  itself with `-STA` and the same parameters.
- Pressing Ctrl+C in the console that started the window closes it cleanly, including in
  background mode.

## Tests

```powershell
pwsh -File Tests\Invoke-AllTests.ps1 -Path .\PortMonitor\Tests                      # unit tests (no network)
Invoke-Pester .\PortMonitor\Tests -TagFilter Integration                             # loopback, child 5.1/7 processes, smoke
```
