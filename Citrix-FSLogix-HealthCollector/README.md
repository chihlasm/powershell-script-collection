# Citrix / FSLogix Health Collector

One command that produces a client-ready picture of a Citrix, RDS, and FSLogix estate: **sampled performance metrics** and **critical / error / warning events**, collected in a single pass and rolled up to one verdict per machine.

Built to be run from a technician's workstation during an engagement. Read-only throughout — it queries performance counters and event logs, and never writes to or clears them.

---

## Why this exists

The collection already had most of the pieces, spread across four scripts, and none of them crossed the performance/event line:

| Existing script | What it does | What it does not do |
| --- | --- | --- |
| `Get-CitrixVDAResources` | Fleet-wide CPU/memory/disk from the broker | No events. Single instantaneous reading. |
| `Get-FSLogixStorageEvents` | Multi-host SMB / FSLogix event correlation | No performance. No Citrix channels. |
| `Export-RDSFSLogixEvents` | Severity-filtered RDS / FSLogix events | Was local-only (now fixed). No performance. |
| `Monitor-CitrixFSLogixStorage` | Storage capacity on VDAs and file servers | Capacity only. |

This script is the orchestrator across both halves. It reuses the proven broker discovery and CIM patterns from `Get-CitrixVDAResources` rather than reinventing them.

---

## Quick start

```powershell
# Every VDA in the site, 30s of sampling, last 24 hours of errors and warnings
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01

# No Citrix anywhere - just name the servers
.\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02, FS01

# The whole VDA fleet PLUS the FSLogix file servers, three days of history
.\Get-CitrixFSLogixHealth.ps1 -DeliveryController DDC01 `
    -AdditionalComputerName FS01, FS02 -LastDays 3 -OutputPath C:\Reports\Contoso

# Fast triage sweep - no sampling delay, last two hours, no browser popup
.\Get-CitrixFSLogixHealth.ps1 -ComputerName (Get-Content .\hosts.txt) `
    -SampleSeconds 0 -LastHours 2 -NoOpen
```

---

## Two ways to choose targets

**Broker discovery (default).** Asks a Delivery Controller for every VDA. Use `-DesktopGroupName` or `-CatalogName` to narrow it, and `-AdditionalComputerName` to append machines the broker does not know about — most usefully the FSLogix file servers, which are never VDAs and so never appear in a broker query.

**Explicit list.** `-ComputerName` takes any set of Windows servers. No Citrix SDK, no Delivery Controller, no broker involvement. Use this on RDS-only estates, on file servers, or anywhere the Citrix SDK is not installed.

Broker-discovered machines that are not `Registered` are skipped by default (they are usually powered off, and sweeping them burns the full connection timeout). Pass `-IncludeUnregistered` to collect them anyway. **Explicitly named servers are never filtered this way** — you asked for them by name.

---

## Performance is sampled, not snapshot

A single counter read is close to meaningless on a session host. A VDA pinned at 100% for forty seconds every few minutes reads as idle if you catch it between spikes.

`-SampleSeconds` (default 30) takes repeated readings and reports **average and peak**, so a spike cannot hide behind a calm average and a calm average is not mistaken for a spike. `-SampleIntervalSeconds` (default 5) controls the spacing.

This matters most for processor queue length, which Microsoft documents explicitly as *"the last observed value only; it is not an average"*.

Set `-SampleSeconds 0` for a single instantaneous read when speed matters more than accuracy. The report says so in plain text when you do, so nobody mistakes a snapshot for a sampled run.

### Processor queue is normalized per logical processor

Microsoft's own published thresholds for processor queue length disagree with each other:

- The [WMI class page](https://learn.microsoft.com/en-us/previous-versions/aa394272(v=vs.85)) says a sustained queue over **2** indicates congestion, with no normalization.
- The [Exchange counter guidance](https://learn.microsoft.com/exchange/exchange-2013-performance-counters-exchange-2013-help#processor-and-process-counters) says it "shouldn't be greater than **5 per processor**".
- The [PAL guide](https://learn.microsoft.com/biztalk/technical-guides/using-the-performance-analysis-of-logs-pal-tool#processor-queue-length-analysis) says to **divide by the processor count**, and treats a queue exceeding the processor count as a bottleneck.

All three agree on the mechanism: there is **one system-wide queue**, regardless of processor count. So a raw threshold is meaningless across a mixed fleet — a queue of 4 is severe on a 2-vCPU host and unremarkable on a 32-vCPU one. This script divides by `NumberOfLogicalProcessors` and applies per-processor thresholds (`-QueueWarnPerCpu` 2, `-QueueCriticalPerCpu` 5).

---

## Events are discovered, not guessed

Citrix publishes its event catalogs by service but **does not publish the literal Event Viewer channel names**, and those names have differed between product versions.

Hardcoding a guessed channel name is the worst possible failure here: the query succeeds, returns zero rows, and the report shows a clean bill of health for a broken VDA. So Citrix channels are matched **by pattern against what each target actually has**, using `Get-WinEvent -ListLog`, and whatever is found gets queried.

FSLogix channel names *are* documented, so those patterns are anchored rather than open-ended.

| Area | How it is found |
| --- | --- |
| FSLogix | `Microsoft-FSLogix-*` ([documented](https://learn.microsoft.com/fslogix/troubleshooting-events-logs-diagnostics)) |
| Citrix | `*Citrix*` — discovered at runtime |
| RDS | `Microsoft-Windows-TerminalServices-*`, `Microsoft-Windows-RemoteDesktopServices*` |
| Storage | `Microsoft-Windows-SMBClient/*`, `Microsoft-Windows-SMBServer/*` |
| Profile | `Microsoft-Windows-User Profile Service/*` |

The noisy `System` and `Application` logs are never pulled wholesale. They are narrowed to the providers that actually explain Citrix and FSLogix failures — storage stack, SMB redirector, profile service, session stack — and those provider names are resolved against each host first, because an unmatched literal provider makes `Get-WinEvent` throw.

Severity defaults to `-Level 1,2,3` (Critical, Error, Warning). Pass `1..4` to include Information.

---

## Two transports, tracked separately

| Data | Transport | Needs |
| --- | --- | --- |
| Performance | CIM — WinRM, falling back to **DCOM** | WinRM or legacy WMI/DCOM, admin on target |
| Events | `Get-WinEvent` over **RPC** (not PowerShell remoting) | Remote Event Log Management firewall rule, admin on target |

A host can answer one and refuse the other. Both are reported independently, and a machine is only called **Unreachable** when *both* fail — so a WinRM-blocked server still yields its full event history instead of vanishing from the report.

---

## Verdicts

| Verdict | Meaning |
| --- | --- |
| **Healthy** | Resource use and event history both within thresholds |
| **Degraded** | A metric at its warning threshold, or `-DegradedErrorCount` (5) or more error events |
| **Critical** | A metric at its critical threshold, any critical-level event, or `-CriticalErrorCount` (25) or more error events |
| **Unreachable** | Neither performance nor events could be collected |

Every verdict carries plain-English reasons — *"Processor is overloaded — averaged 94% during the sample, peaking at 100%"* — because a verdict with no explanation just moves the investigation rather than advancing it.

A metric that could not be collected returns `UNKNOWN` and never counts as healthy. In the HTML it renders as a dash, never an empty bar, since an empty bar reads as "zero percent".

---

## Output

Four files, timestamped `yyyy-MM-dd_HHmmss`:

| File | Contents |
| --- | --- |
| `..._Hosts.csv` | One row per machine: verdict, reasons, every metric, event counts |
| `..._Events.csv` | Every collected event, flat |
| `..._Samples.csv` | **Raw per-sample readings** — what makes a performance claim auditable afterwards |
| `....html` | Self-contained dark report: fleet tiles, per-machine table, fleet-wide top problems |

The HTML has no external stylesheets, fonts, or scripts, so it survives being emailed to a client and opened offline. All event text is HTML-escaped.

The script also returns the host rows to the pipeline:

```powershell
$health = .\Get-CitrixFSLogixHealth.ps1 -ComputerName RDS01, RDS02 -NoOpen
$health | Where-Object Verdict -ne 'Healthy' | Format-Table ComputerName, Verdict, Reasons
```

---

## Key parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-DeliveryController` | `localhost` | Broker to query for the VDA list |
| `-AdditionalComputerName` | — | Append non-VDA servers to a broker sweep |
| `-ComputerName` | — | Explicit server list; bypasses Citrix entirely |
| `-SampleSeconds` | `30` | Sampling window per machine; `0` for one reading |
| `-SampleIntervalSeconds` | `5` | Spacing between readings |
| `-LastHours` / `-LastDays` | 24 hours | Event window (or `-StartTime` / `-EndTime`) |
| `-Level` | `1,2,3` | Critical, Error, Warning |
| `-QueueWarnPerCpu` / `-QueueCriticalPerCpu` | `2` / `5` | Per-processor queue thresholds |
| `-DegradedErrorCount` / `-CriticalErrorCount` | `5` / `25` | Error counts that drive the verdict |
| `-SkipEvents` / `-SkipPerformance` | off | Collect only one half |
| `-NoOpen` | off | Do not launch the browser |

Thresholds are validated at startup — a warn threshold above its critical threshold is rejected rather than silently making the critical band unreachable.

---

## Requirements

- Windows PowerShell 5.1 (runs on session hosts as-is)
- Broker discovery needs the Citrix Broker SDK — loaded at runtime with a clear fallback message, not `#Requires`
- Administrative rights on the targets
- Time windows are interpreted in **each target's local time**, which is how `Get-WinEvent` filters. On a fleet spanning time zones, prefer `-LastHours` / `-LastDays` over an explicit `-StartTime`.

---

## Tests

```powershell
Invoke-Pester -Path .\Tests
```

93 tests covering threshold boundaries, the per-CPU queue normalization, sample aggregation with failed reads, time-window resolution, target de-duplication, verdict logic, HTML escaping, and the channel patterns. The suite deliberately avoids mocking Windows-only CIM cmdlets, so it runs anywhere.

---

## Related

- `Get-CitrixVDAResources` — deeper broker-side VDA detail
- `Get-FSLogixStorageEvents` — SMB correlation against known re-attach timestamps
- `Parse-FSLogixLogs` — FSLogix's own text logs; finds re-attach loops
- `CitrixVDADiagnostics\CitrixVDA-Consolidated` — deep single-machine diagnostics
- `MSP-TroubleshootingWorkbench` — runs this as the `citrix.fslogix.health` check
