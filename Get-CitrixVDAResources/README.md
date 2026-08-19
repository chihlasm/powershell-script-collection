# Get-CitrixVDAResources

Fleet-wide resource report for Citrix VDAs. Discovers every VDA registered with a Delivery
Controller, collects CPU, memory, disk, and uptime from each one, and produces a CSV for
the record plus a self-contained HTML report for stakeholders.

Machines that cannot be contacted still appear in both outputs with a clear status, so an
unreachable VDA is never mistaken for a healthy one.

Complements [`CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1`](../CitrixVDADiagnostics/),
which goes deep on a single machine. This script goes wide across the fleet — run it first
to find the machine worth investigating.

## Requirements

- Windows PowerShell 5.1
- Citrix Broker SDK (present on a Delivery Controller, or install Citrix Studio / the
  Citrix PowerShell SDK)
- WinRM reachable on the target VDAs
- An account with Citrix read rights and CIM access to the VDAs

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-DeliveryController` | `localhost` | Delivery Controller to query |
| `-DesktopGroupName` | — | Limit to one delivery group |
| `-CatalogName` | — | Limit to one machine catalog |
| `-MachineName` | — | Explicit machine names; bypasses group/catalog filters |
| `-Credential` | — | Credentials for the CIM connections |
| `-CpuWarnPercent` | `80` | CPU warning threshold |
| `-CpuCriticalPercent` | `90` | CPU critical threshold |
| `-MemoryWarnPercent` | `80` | Memory warning threshold |
| `-MemoryCriticalPercent` | `90` | Memory critical threshold |
| `-DiskWarnPercent` | `80` | Disk warning threshold |
| `-DiskCriticalPercent` | `90` | Disk critical threshold |
| `-MaxRecordCount` | no practical limit | Broker record cap — see note below |
| `-ConnectionTimeoutSeconds` | `15` | Per-machine CIM timeout |
| `-IncludeUnregistered` | off | Also try to collect from unregistered machines |
| `-OutputPath` | current directory | Where the CSV and HTML are written |
| `-NoOpen` | off | Do not open the HTML when finished |

## Examples

Report on every VDA in the site:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01
```

Limit to one delivery group and write to a share:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -DesktopGroupName "Finance Desktops" -OutputPath \\fileserver\reports
```

Lower the CPU warning threshold for a busy environment, without opening the report:

```powershell
.\Get-CitrixVDAResources.ps1 -DeliveryController DDC01 -CpuWarnPercent 70 -NoOpen
```

## Output

Two files, both named `CitrixVDAResources_<yyyy-MM-dd_HHmmss>`:

- **`.csv`** — one row per VDA with all 23 fields (broker state, every resource metric,
  per-metric status, collection status, and any error message).
- **`.html`** — a dark-themed standalone page: a fleet summary band, then every machine
  sorted worst-first with inline bars for CPU, memory, and disk. No external resources, so
  it can be emailed as a single file.

The console shows a colour-coded line per machine as it goes, plus a discovered-vs-collected
tally at the end.

## Notes

**On fleet size.** Citrix Broker cmdlets return only the first 250 records unless
`-MaxRecordCount` is supplied — they warn rather than error, so a naive query on a large
site silently under-reports while still looking complete. This script always passes the
parameter explicitly and prints how many machines it discovered against how many it
collected, so a partial run is visible.
([Citrix SDK reference](https://developer-docs.citrix.com/en-us/citrix-virtual-apps-desktops-sdk/2511/Broker/about_Broker_Filtering.html))

**On collection time.** Collection is sequential, roughly a second or two per machine.
A 50-VDA site takes about a minute. Very large fleets will take proportionally longer.

**On unreachable machines.** Powered-off and unregistered machines are skipped without a
connection attempt (that is expected, not a fault, and they show as neutral notes).
Machines that should be reachable but are not appear as `Unreachable` in red with the
underlying error.

**On thresholds.** They are inclusive: a machine at exactly 80% is a warning, and exactly
90% is critical. A machine's overall status is the worst of its CPU, memory, and disk
statuses — but each metric bar keeps its own true colour, so a machine can show a green CPU
bar on a red row when only its memory is the problem.

## Testing

```powershell
Invoke-Pester .\Tests\Get-CitrixVDAResources.Tests.ps1
```

43 tests covering threshold boundaries, broker discovery, the KB-vs-bytes unit conversions,
per-machine CIM failure isolation, row assembly, and HTML generation. The suite mocks the
broker and CIM layers, so it runs anywhere — no Citrix site required.
