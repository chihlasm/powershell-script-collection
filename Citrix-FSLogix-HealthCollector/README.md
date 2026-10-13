# Citrix / FSLogix Health Collector

**Which Citrix or RDS server is the problem?**

Point this at your Citrix / RDS servers, and the file servers that hold the FSLogix profiles.
It checks each one and gives every machine a simple verdict: **Healthy**, **Needs attention**,
**Serious problems**, or **Could not reach**. It says why in plain English, and the report
opens in your browser.

It only looks. **It never changes anything** on the servers.

---

## Step 1: Open PowerShell the right way

1. Click **Start** and type `PowerShell`.
2. Right-click **Windows PowerShell** and choose **Run as administrator**.
3. Go to this folder:

   ```powershell
   cd C:\Tools\ServiceDesk-Toolkit\Citrix-FSLogix-HealthCollector
   ```

   (Change the path if you saved the toolkit somewhere else.)

---

## Step 2: Pick ONE command

### A. "Check these servers" (works everywhere, no Citrix needed)

Type the server names, separated by commas:

```powershell
.\Get-CitrixFSLogixHealth.ps1 -ComputerName CTXVDA01, CTXVDA02, FS01
```

**Start here if you're not sure.** It works for Citrix, RDS, file servers, anything Windows.

### B. "Check every Citrix server" (run on a Citrix Delivery Controller)

```powershell
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01
```

It asks Citrix for the full list of servers, so you don't have to type them. Put your
Delivery Controller's name in place of `DDC01`.

To include the FSLogix file servers too, since Citrix doesn't know about them:

```powershell
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01 -AdditionalComputerName FS01, FS02
```

### C. "The problem was a while ago"

By default it looks at the **last 24 hours** of errors. To look further back:

```powershell
.\Get-CitrixFSLogixHealth.ps1 -ComputerName CTXVDA01 -LastDays 3
```

---

## Step 3: Wait

**It checks one server at a time, for about 30 seconds each**, plus time to read the logs. It
tells you roughly how long when it starts.

| Servers | Roughly |
|---|---|
| 1 | under a minute |
| 10 | 5 to 10 minutes |
| 50 | 25 minutes or more |

In a hurry? Add `-SampleSeconds 0` to skip the 30-second watch on each server. That roughly
halves the time. It's less accurate: it can miss a server that spikes on and off. Reading
the error logs still takes a little while per server.

---

## Step 4: Read the report

The report opens in your browser by itself. Worst machines are at the top.

### What the verdicts mean

| You see | It means | Do this |
|---|---|---|
| 🟢 **Healthy** | Nothing wrong found. | Nothing. Move on. |
| 🟡 **Attention** / Needs attention | Something is running high, or a handful of errors. | Read **What we found**. Keep an eye on it. |
| 🔴 **Serious** / Serious problems | Overloaded, nearly full, or lots of errors. | **This is probably your problem.** Read **What we found** and escalate with the report. |
| ⚪ **No contact** / Could not reach | The tool couldn't get any information from it. | Is the server on? See [If something goes wrong](#if-something-goes-wrong). |

The CSV and the PowerShell window use the technical names for the same four verdicts:
`Healthy`, `Degraded`, `Critical`, `Unreachable`.

### The columns

| Column | What it shows |
|---|---|
| **Processor / Memory / Disk** | How busy or full it is. The bar is the average. The little tick shows the highest point. **Disk** is the fullest drive. |
| **Users** | People logged on (Citrix servers only). |
| **Up (d)** | Days since the last restart. |
| **Crit / Err / Warn** | How many critical, error and warning events in the time window. |
| **Most frequent problem** | The error that happened most, e.g. `Microsoft-FSLogix-Apps (ID 26) x14` means that error happened 14 times. |
| **What we found** | **Read this first.** A plain-English explanation of the verdict. |

A `--` in a bar means **"couldn't measure this"**. It does **not** mean zero.

Further down, **Most common problems across the fleet** lists errors that happen on many
servers. When the same error shows up on every server, the cause is usually something they
share, like the file server or the network, rather than one bad machine.

### When it turns red

| Colour | Processor | Memory | Disk |
|---|---|---|---|
| 🟡 Yellow | 80% | 80% | 80% full |
| 🔴 Red | 90% | 90% | 90% full |

**Events:** 5 or more errors turns it yellow. 25 or more errors, or **any** critical event,
turns it red.

---

## If something goes wrong

| You see | What to do |
|---|---|
| `running scripts is disabled` or `not digitally signed` | Run `Get-ChildItem -Recurse \| Unblock-File` in the folder, then try again. |
| `The Citrix Broker SDK is not available` | You used command **B** on a machine without Citrix Studio. Use command **A** and type the server names instead. |
| A server says **No contact** | Check it's switched on and you can ping it. You need to be an admin on it. |
| `no performance data (WinRM and DCOM both refused)` | Remote management is blocked on that server. Event logs may still work, and the report will say so. |
| `event logs could not be read` | The **Remote Event Log Management** firewall rule is off on that server, or you're not an admin there. |
| **What we found** says `the real event counts are HIGHER than shown` | That server logged so many errors it hit the limit. Re-run with a shorter window, e.g. `-LastHours 4`. |
| **What we found** says `Could not read: ...` | Those numbers couldn't be measured. Everything else on that row is still correct. |

---

## Where the files go

Into the folder you ran it from, unless you add `-OutputPath C:\Reports`.

| File | What it's for |
|---|---|
| `CitrixFSLogixHealth_<date>.html` | **The report.** Attach this to the ticket. It's a single file that works offline. |
| `..._Hosts.csv` | One row per server, for Excel. |
| `..._Events.csv` | Every error and warning found (only written if there were any). |
| `..._Samples.csv` | Every individual reading. This is the proof behind the averages. |

---

## All options

You won't normally need these.

| Option | What it does | Default |
|---|---|---|
| `-ComputerName` | The servers to check. | — |
| `-DeliveryController` | Citrix controller to get the server list from. | `localhost` |
| `-AdditionalComputerName` | Extra servers to add to a Citrix sweep (e.g. file servers). | — |
| `-DesktopGroupName` / `-CatalogName` | Only check one Citrix delivery group or catalog. | All |
| `-IncludeUnregistered` | Also try Citrix servers that aren't registered (usually switched off). | Off |
| `-LastHours` / `-LastDays` | How far back to look for errors. | 24 hours |
| `-StartTime` / `-EndTime` | An exact time range instead. | — |
| `-SampleSeconds` | How long to watch each server. `0` = one quick reading. | 30 |
| `-SkipEvents` | Only check performance. Faster. | Off |
| `-SkipPerformance` | Only check the error logs. | Off |
| `-OutputPath` | Folder for the report. | Current folder |
| `-NoOpen` | Don't open the report when finished. | Off |
| `-Credential` | Use a different admin account for the servers. | You |
| `-CpuWarnPercent`, `-MemoryCriticalPercent`, etc. | Change when things turn yellow or red. | 80 / 90 |
| `-DegradedErrorCount` / `-CriticalErrorCount` | Errors needed to turn yellow / red. | 5 / 25 |
| `-MaxEventsPerLog` | The most events read from each log. | 2000 |
| `-PassThru` | Also output the results as objects, for other scripts. | Off |

Run `Get-Help .\Get-CitrixFSLogixHealth.ps1 -Full` for every option in detail.

---

## For maintainers

### How it works

- **Performance is sampled, not a snapshot.** It takes a reading every 5 seconds for
  `-SampleSeconds` and reports the average and the peak, so a server that spikes to 100% every
  few minutes isn't caught looking idle. The verdict uses the **average**. The peak is shown
  alongside it.
- **Memory "in use"** is total minus `Win32_OperatingSystem.FreePhysicalMemory`. On a live
  test that value tracked the *Available* counter (9.72 GB), not the free-and-zero list
  (0.19 GB), so standby cache isn't counted as used. That matches Task Manager.
- **Processor queue is normalised per logical processor.** A queue of 4 is severe on 2 vCPUs
  and nothing on 32. Microsoft's own published thresholds disagree with each other. See
  `Get-QueueStatus` for all three sources and why the defaults are 2 / 5 per CPU.
- **Event channels are discovered, not guessed.** Citrix doesn't publish its Event Viewer
  channel names, and a wrong guess returns zero rows while looking healthy. Channels are
  therefore matched by pattern (`*Citrix*`, `Microsoft-FSLogix-*`, TerminalServices, SMB
  client/server, User Profile Service) against what each server actually has. `System` and
  `Application` are narrowed to the storage, SMB, profile and session providers.
- **Two transports, tracked separately.**
  - Performance uses CIM: WinRM first, falling back to DCOM.
  - Events use `Get-WinEvent` over RPC. That's not PowerShell remoting, so it works where
    WinRM is off.
  - A server can answer one and refuse the other, and the report says which.

### Verdict rules

- **Could not reach (`Unreachable`)** means no usable evidence at all. That covers both
  collections failing, and one failing while the other was skipped with `-SkipPerformance` or
  `-SkipEvents`. A server is **never** called Healthy on zero evidence.
- **Coverage notes** ("Could not read: processor queue", "Event history was not checked",
  "real counts are HIGHER than shown") are listed after the findings. The "No problems found"
  line only claims what was actually checked.
- **An `UNKNOWN` metric** never counts as healthy or as a problem. In the report it's a `--`,
  never an empty bar.
- **Thresholds are inclusive**: exactly 80% is yellow. A warn threshold set above its critical
  threshold is rejected at startup.

### Using it from another script

```powershell
$health = .\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02 -NoOpen -PassThru
$health | Where-Object Verdict -ne 'Healthy' | Format-Table ComputerName, Verdict, Reasons
```

`-PassThru` is required for pipeline output. Without it, an interactive run ends on the summary
instead of scrolling 37 fields per server past it. The MSP Troubleshooting Workbench's
`citrix.fslogix.health` check passes `-PassThru`.

### Tests

```powershell
Invoke-Pester -Path .\Tests
```

There are 106 tests. They cover:

- threshold boundaries and per-CPU queue normalisation
- sample aggregation when some reads fail
- time windows and target de-duplication
- verdict logic, including the "never Healthy on no evidence" and event-limit regressions
- HTML escaping and channel patterns
- the pure-ASCII file rule, which Windows PowerShell 5.1 needs to parse the file

The suite runs anywhere, with no Citrix or servers needed.

### References

The full list is in the script's `.NOTES`. The key ones:

- [Get-WinEvent](https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent): one computer per call, RPC rather than remoting, and wildcard `-ListLog`
- [FilterHashtable levels](https://learn.microsoft.com/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable): 1 Critical, 2 Error, 3 Warning, 4 Information
- [Win32_OperatingSystem](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem): memory values are in kilobytes
- [Win32_LogicalDisk](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-logicaldisk): DriveType 3 is a local disk, and sizes are in bytes
- [Win32_PerfFormattedData_PerfOS_System](https://learn.microsoft.com/previous-versions/aa394272(v=vs.85)): ProcessorQueueLength is the last observed value, not an average
- [FSLogix event logs](https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics)
- [Citrix event logs](https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/monitor/event-logs.html)

### Related tools

- `Get-CitrixVDAResources`: faster fleet-wide CPU, memory and disk from the broker
- `Get-RAM-Usage`: which *user* is using the memory on one server
- `RDS-FSLogix-EventExport`: full event export for a time window
- `MSP-TroubleshootingWorkbench`: runs this as the `citrix.fslogix.health` check
