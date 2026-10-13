# Citrix-PerfTriage

One command for "the Citrix servers are slow". It runs this repository's Citrix, FSLogix, storage and Hyper-V tools against the same servers and the same time window, then produces a single summary that says what to look at first.

Built for the common MSP situation where you have admin rights on the session hosts but **not** on the Hyper-V cluster underneath them. Where the Hyper-V hosts refuse you, it builds a hand-off package for whoever does have access, instead of failing.

## What it runs

| # | Step | Tool | What it tells you |
|---|---|---|---|
| 1 | Server health | [Citrix-FSLogix-HealthCollector](../Citrix-FSLogix-HealthCollector/) | Sampled CPU, memory, disk and queue, plus Citrix / RDS / FSLogix events - one verdict per server |
| 2 | FSLogix settings | *(built in)* | Where the profile share and FSLogix logs are, read from each server's registry |
| 3 | FSLogix logs | [Parse-FSLogixLogs](../Parse-FSLogixLogs/) | Slow profile loads, re-attach loops, containers filling up, logged errors |
| 4 | Storage events | [Get-FSLogixStorageEvents](../Get-FSLogixStorageEvents/) | SMB, disk and profile events - **lined up against each profile re-attach from step 3** so the trigger stands out |
| 5 | RDS events | [RDS-FSLogix-EventExport](../RDS-FSLogix-EventExport/) | Full event export for the record |
| 6 | Profile share speed | [DiskSpdDiagnostic](../DiskSpdDiagnostic/) | Measured operations/second and response time from a session host to the profile share |
| 7 | Hyper-V hosts | [HyperV-Host-Diagnostics](../HyperV-Host-Diagnostics/) + [Hyper-V-Inventory](../Hyper-V-Inventory/) | Host disk health, CSV redirected mode, Hyper-V event errors, unexpected host reboots, VM CPU/memory configuration, vCPU oversubscription |

Each tool runs in its own Windows PowerShell 5.1 process with its own output folder and a time limit, so one tool failing, hanging or calling `exit` never stops the rest.

## What you see while it runs

Servers are discovered first, then checked **one tool run per server, four servers at a time** (`-ThrottleLimit`), so you always know what is being checked where:

```
[INFO] 15 session host(s) to check in delivery group 'Shared Desktop':
[INFO]          CTXVDA01  CTXVDA02  CTXVDA03  CTXVDA04  CTXVDA05
[INFO]          ...
[WARN] Not registered with Citrix (checked anyway): CTXVDA07 (Unregistered)

[INFO] Plan - 4 server(s) at a time, roughly 12 minute(s):
[INFO]    1. Server health        15 server(s) - 60 s sampling + events
[INFO]    ...

[INFO] Step 1 of 7: Server health - 15 server(s), 4 at a time, 60 s of sampling each
[PASS]    [ 1/15] CTXVDA01  Healthy - CPU 34%, memory 61%  (1:12)
[WARN]    [ 3/15] CTXVDA03  Degraded - Memory is running high  (1:15)
[FAIL]    [ 7/15] CTXVDA07  Unreachable - Could not be contacted  (0:40)
[INFO]       still running: CTXVDA09 (2:05), CTXVDA10 (2:01)
[WARN] Leaving out of the remaining steps (unreachable): CTXVDA07
```

A progress bar at the top shows which servers are running right now. A server found unreachable in step 1 is left out of the later steps rather than timing out in each one. Unregistered session hosts are checked anyway, since an unregistered server may be the problem, and powered-off ones are listed but skipped. The time in the plan is a rough estimate.

## Running it on a client server - use a kit

The script runs other tools from this repository, so it needs their folders next to it. Don't copy the `.ps1` on its own - build a kit instead:

```powershell
# 1. On your workstation, from the repository root
.\Citrix-PerfTriage\Invoke-CitrixPerfTriage.ps1 -CreateKit C:\Temp\CitrixPerfTriageKit.zip
```

2. Copy the zip to the client server (the Delivery Controller is ideal) and extract it.
3. In an **elevated** Windows PowerShell, inside the extracted folder:

```powershell
# On a Delivery Controller - no names needed, it finds the session hosts itself
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CitrixPerfTriage.ps1 -OutputPath C:\Temp

# Narrow it to the delivery group with the complaints
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-CitrixPerfTriage.ps1 -DesktopGroupName 'Shared Desktop' -OutputPath C:\Temp
```

The kit is about 300 KB: the script, the seven tool folders (without their test suites), and a `README-FIRST.txt` with these steps. If tools are missing, the script says which and how to fix it rather than running half the checks. `-ToolRoot` points it at tool folders kept somewhere else.

When run on a Delivery Controller with no `-ComputerName` or `-DeliveryController`, it detects the Citrix Broker Service and discovers the session hosts from the local Controller.

## Usage

```powershell
# Session hosts and the cluster they run on - the usual case
.\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01, CTXVDA02 -HyperVCluster HVCLUSTER01

# Discover the session hosts from Citrix and look back three days
.\Invoke-CitrixPerfTriage.ps1 -DeliveryController DDC01 -DesktopGroupName 'Shared Desktop' -LookbackHours 72

# A colleague with Hyper-V rights types their credential at your desk
.\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01 -HyperVHost HV01 -HyperVCredential (Get-Credential)

# Business hours: no load on the profile share, no Hyper-V
.\Invoke-CitrixPerfTriage.ps1 -ComputerName CTXVDA01 -SkipStorageBenchmark -SkipHyperV
```

Run it from an **elevated** console - the profile share speed test needs it. Without elevation that one step is skipped and everything else still runs.

## Key parameters

| Parameter | Default | Notes |
|---|---|---|
| `-ComputerName` / `-DeliveryController` | - | Session hosts, or a Delivery Controller to discover them from (needs the Citrix Broker SDK) |
| `-HyperVHost` / `-HyperVCluster` | - | Leave both out to skip Hyper-V. A cluster's nodes are discovered automatically |
| `-VMName` | session host names | Only needed when the Hyper-V VM names differ from the computer names |
| `-LookbackHours` | 24 | Event log and FSLogix log window |
| `-HyperVDaysBack` | 7 | Hyper-V host event window - host storage problems often start before users notice |
| `-SampleSeconds` | 60 | Performance sampling per session host |
| `-ProfileSharePath` | from FSLogix settings | Override the share the speed test targets |
| `-BenchmarkWorkload` | FSLogixLike | 4K random, 30% writes, 30 s, 1 GB test file |
| `-SkipStorageBenchmark`, `-SkipHyperV` | off | Leave a step out |
| `-Credential` | current user | For the session hosts; passed to every tool that accepts one |
| `-HyperVCredential` | current user | For the Hyper-V hosts |
| `-ThrottleLimit` | 4 | Servers checked at the same time in each step |
| `-StepTimeoutSeconds` | 1800 | Time limit for one tool run (one server, one step) |
| `-CreateKit` | - | Build a portable folder or `.zip` instead of running a triage |
| `-ToolRoot` | - | Where the tool folders are, if not next to the script |
| `-PassThru` | off | Also return the result object (for scripting) |

## The verdict

The summary gives one overall result: **Critical**, **Warning**, **Healthy**, or **Incomplete**. Healthy is only given when the checks actually ran and none failed. If nothing ran, or nothing was flagged but a step failed, the result is Incomplete, not Healthy. Problems that were found are always reported, even if other steps failed.

## The profile share speed test

Runs every time unless `-SkipStorageBenchmark` is given. It writes a **1 GB test file** to the profile share and puts real load on it for about 30 seconds, then deletes the file. Users on that share may notice slower logons while it runs. It also copies `diskspd.exe` to `C:\Windows\Temp` on the session host it runs from, and removes it afterwards.

The share is taken from `VHDLocations` on the session hosts (or the SMB entries in `CCDLocations` for Cloud Cache). Both the REG_SZ (semicolon-separated) and REG_MULTI_SZ forms are read.

## When you can't get into Hyper-V

For each Hyper-V host, the script works out *why* it can't check it:

| State | Meaning |
|---|---|
| `NoRemoting` | Remote PowerShell refused you - you are not an admin on the host |
| `NoHyperVRights` | Remote PowerShell works, but Hyper-V refused to list the VMs |
| `Unreachable` | WinRM could not reach the host from your workstation |
| `ClusterLookup` | The cluster's node list could not be read |

Any blocked host gets a **hand-off package** in `7-HyperV\HyperV-Handoff\`:

- `README-HyperV-Team.txt` - who is asking and why, which hosts, what to run, and a plain statement that nothing is changed
- `Collect-HyperVEvidence.ps1` - one command that runs both Hyper-V scripts for your VMs and zips the results
- `Get-HyperVHostDiagnostics.ps1`, `Get-HyperVInfrastructureInventory.ps1` - the read-only scripts it runs

Send the folder to the Hyper-V administrators. They run one command and send back a zip.

## Output

Everything lands in `CitrixPerfTriage_<yyyy-MM-dd_HHmmss>\` under `-OutputPath`:

```
Summary.html              - start here: what to look at first, one row per server, what ran, links
Servers.csv               - per-server verdict, CPU, memory, disk, sessions, issue count
Findings.csv              - every finding, one row each
Steps.csv                 - each step's result and report path
Triage.log                - the console output, timestamped
0-Discovery\              - the Delivery Controller query (when discovering)
1-ServerHealth\<server>\  - health collector HTML + CSVs
2-FSLogixSettings\        - FSLogixSettings.csv
3-FSLogixLogs\<server>\   - parsed FSLogix log CSVs
4-StorageEvents\<server>\ - Events.csv, Summary.csv
5-RdsEvents\<server>\     - RDS/FSLogix event HTML + CSV
6-StorageSpeed\           - DiskSpd HTML report
7-HyperV\                 - host diagnostic logs, Inventory\, HyperV-Handoff\
```

Each tool run's folder also holds `console.log` (the tool's full console output) for when something fails.

Keep `-OutputPath` short (for example `C:\Temp`). Some tools nest long file names under their folder, and Windows PowerShell 5.1 cannot create paths over 260 characters. The script warns when the path is long.

## Requirements

- Windows PowerShell 5.1 on your workstation. The tools always run under `powershell.exe` 5.1, even if you start the orchestrator from PowerShell 7, because the Citrix Broker SDK snap-ins only load in 5.1.
- The sibling tool folders from this repository, next to this folder. A missing tool skips its step with a warning.
- On the session hosts: admin rights, WinRM, the Remote Event Log Management firewall rule, and the `C$` admin share (to read FSLogix logs).
- FSLogix settings are read over WinRM, falling back to the Remote Registry service.

## What it changes

Nothing on the session hosts or Hyper-V hosts, except:

- the speed test's temporary 1 GB file on the profile share and `diskspd.exe` in the session host's `C:\Windows\Temp` (both removed afterwards), and
- the Hyper-V host check's log, written to a temporary folder on the host and deleted once read.

## Tests

```powershell
Invoke-Pester .\Tests\Invoke-CitrixPerfTriage.Tests.ps1
```

65 tests (Pester 5 syntax), covering the FSLogix registry value parsing, the admin-share path mapping, the Hyper-V flag and DiskSpd result parsing, the hand-off package, HTML encoding, the overall verdict (including a regression guard: a run where nothing executed must be Incomplete, never Healthy), name-list splitting (a regression guard for `-File` passing `VDA01,VDA02` as one string), tool discovery, the kit, the tool runner (typed parameters in, objects out, `exit` codes, thrown errors, time limits, credential file cleanup), and the batch runner (result order, running in parallel, one failure not stopping the rest).

## References

- FSLogix log location, `LogDir`, `LogFileKeepingPeriod` (default 2 days): <https://learn.microsoft.com/fslogix/reference-configuration-settings#log-settings>
- FSLogix text logs: <https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics#text-based-log-files>
- `VHDLocations` / `CCDLocations` value formats: <https://learn.microsoft.com/fslogix/troubleshooting-old-temp-local-profiles#incorrect-settings-in-vhdlocations-or-ccdlocations>
