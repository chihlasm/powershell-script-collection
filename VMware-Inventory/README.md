# Get-VMwareInfrastructureInventory.ps1

Inventories VMware infrastructure — ESXi hosts, the VMs running on them, their power state and allocated resources, datastore capacity, and snapshots — across one or more vCenter Servers and/or standalone ESXi hosts. Exports a set of timestamped CSVs plus a single JSON blob, and computes capacity rollups intended for a vCIO or architect to interpret.

**This script reports; it does not advise.** It applies no thresholds and renders no verdicts. Every computed ratio is published alongside the raw inputs it came from, so the reader can audit the arithmetic and draw their own conclusions about what the numbers mean for a given client.

**Read-only.** Nothing is powered on or off, no snapshot is consolidated, no host enters or leaves maintenance mode.

## Requirements

- **PowerShell 5.1** (see [Why Windows PowerShell 5.1](#why-windows-powershell-51) — it runs on 7.x with two caveats)
- **PowerCLI** (`VMware.PowerCLI`) — the script detects its absence and tells you how to install it
- **Network access** to each target on TCP 443
- A vSphere account with **read-only** rights on each target. To get snapshot sizes it additionally needs the **Datastore → Browse datastore** privilege (see [Snapshot sizes](#snapshot-sizes))

### Installing PowerCLI

```powershell
# Current user — no administrator rights required
Install-Module VMware.PowerCLI -Scope CurrentUser
```

Or let the script do it:

```powershell
.\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01 -InstallPowerCLI
```

For air-gapped machines, see Broadcom's [offline install procedure](https://techdocs.broadcom.com/us/en/vmware-cis/vcf/power-cli/latest/powercli/installing-vmware-vsphere-powercli/install-powercli-offline.html).

The script sets two PowerCLI options at startup so a first run doesn't stall on a prompt:

- **Invalid certificates are ignored** for the session only — standalone ESXi hosts ship with self-signed certificates and would otherwise refuse the connection. Your persisted preference is not modified.
- **CEIP participation** is defaulted to off, once, only if you have never answered the prompt. This must be set at User scope because Broadcom does not permit Session scope for it.

## Usage

```powershell
# A single vCenter — inventories everything it manages
.\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01.contoso.local

# Two standalone ESXi hosts sharing a credential
.\Get-VMwareInfrastructureInventory.ps1 -Server 192.168.10.21,192.168.10.22 -Credential (Get-Credential root)

# Targets from a file, output somewhere specific
.\Get-VMwareInfrastructureInventory.ps1 -HostListFile .\client-hosts.txt -OutputPath C:\Reports

# Mixed: a vCenter plus a standalone host that isn't in it
.\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01.contoso.local,esxi-dmz01.contoso.local

# Fast pass, no snapshot enumeration
.\Get-VMwareInfrastructureInventory.ps1 -Server vcenter01 -SkipSnapshots
```

### Parameters

| Parameter          | Type         | Default                          | Description |
|--------------------|--------------|----------------------------------|-------------|
| `-Server`          | String[]     | —                                | One or more vCenter Servers or standalone ESXi hosts. NetBIOS, FQDN, or IP. |
| `-HostListFile`    | String       | —                                | Newline-delimited file of additional targets. Combined with `-Server`. |
| `-Credential`      | PSCredential | *(credential store, then prompt)* | Applied to every target in the run. |
| `-OutputPath`      | String       | `.\VMwareInventory_<timestamp>`  | Folder for the export set. |
| `-SkipSnapshots`   | Switch       | Off                              | Skips snapshot collection — the slowest phase of a large run. |
| `-InstallPowerCLI` | Switch       | Off                              | Installs PowerCLI for the current user if missing, then proceeds. |

### Host list file format

Blank lines and `#` comments are ignored, so decommissioned hosts can be commented out rather than deleted:

```text
# Contoso — production cluster
vcenter01.contoso.local

# DMZ standalone hosts (not in vCenter)
192.168.50.11
192.168.50.12

# esxi-old01.contoso.local   decommissioned 2026-03
```

Targets from `-Server` and the file are merged and de-duplicated case-insensitively, so naming the same host in both places will not double-count it.

## Credentials

`-Credential` applies to every target in the run. That is the simple case, and it is the right one when a single vCenter covers the whole estate.

When you **omit** `-Credential`, PowerCLI consults its own credential store before prompting. This is the practical answer for a client with several standalone hosts that do not share a password, and for scheduled/unattended runs. Populate it once per host, from Windows PowerShell 5.1:

```powershell
New-VICredentialStoreItem -Host esxi01.contoso.local -User root -Password '<password>'
New-VICredentialStoreItem -Host esxi02.contoso.local -User root -Password '<password>'
```

Entries land in `%APPDATA%\VMware\credstore\vicredentials.xml` under the profile of the user who created them. Inspect with `Get-VICredentialStoreItem`, remove with `Remove-VICredentialStoreItem`.

> **Unverified:** Broadcom does not publish the `about_server_authentication` help topic on the web, so the exact precedence between the credential store, explicit credentials, and integrated authentication is not documented online. Confirm on your own machine with `Get-Help about_server_authentication`.

## Output

| File | Contents |
|------|----------|
| `Hosts.csv` | Per ESXi host: connection/power state, maintenance mode, vendor, model, serial, BIOS, ESXi version+build, CPU model, sockets/cores/threads, CPU and memory capacity and live usage, uptime, boot time, cluster |
| `VirtualMachines.csv` | Per VM: power state, host, cluster, folder, resource pool, vCPU, cores-per-socket, memory, provisioned vs used disk, datastores, guest OS (configured and running), hostname, IPs, VMware Tools version and status, hardware version, creation date, notes |
| `Datastores.csv` | Per datastore: type, state, availability, capacity/used/free, uncommitted, total provisioned, provisioned:capacity ratio, overcommit flag, snapshot consumption |
| `Snapshots.csv` | Per snapshot: VM, name, description, creation date, **age in days**, size (GB and MB), current flag, parent, child count |
| `Clusters.csv` | vCenter only: HA and DRS configuration, EVC mode, host count, aggregate CPU and memory |
| `HostCapacityRollup.csv` | Per host: VM counts, physical cores vs vCPU allocated, physical memory vs memory allocated, and the derived ratios |
| `Summary.csv` | Per target: totals and environment-wide ratios |
| `ConnectionLog.csv` | Per target: connected or not, product line, version, build, and the error if it failed |
| `FullInventory.json` | Everything above in one structure, for diffing between runs |

### The rollups

Three derived figures, each published next to its inputs:

**vCPU per physical core** — total vCPU allocated divided by physical cores. Reported twice: over **powered-on VMs only** (the live contention picture) and over **all VMs** (the capacity-planning picture, i.e. what happens if everything is powered on). A powered-off VM reserves no CPU, so counting it in the live figure would overstate contention.

**Memory overcommit** — allocated guest memory divided by physical host memory. Same powered-on/all split, same reasoning. Above 1.0 means more memory is allocated than the host physically has.

**Provisioned vs capacity (thin overallocation)** — total provisioned storage divided by datastore capacity. Above 1.0 means thin-provisioned disks could, if fully written, exceed the datastore.

The provisioned figure deserves a note, because it is the easiest number in vSphere to compute wrongly. The API field `Summary.Uncommitted` is *not* total provisioned space — it is the **additional** space thin disks could still consume beyond what is already written, in **bytes**, and it is valid only when the datastore is accessible. Total provisioned is therefore `used + uncommitted`, and a datastore is overcommitted when that exceeds capacity. Reading `Uncommitted` as "provisioned" overstates provisioning by everything already written — a plausible, confidently wrong number in a client report.

## Things to know

### Snapshot sizes

vSphere populates a snapshot's size only when the querying account holds the **Datastore → Browse datastore** privilege. Without it, PowerCLI emits a warning and the size comes back empty. A read-only service account will therefore produce a snapshot report that looks like *no snapshot consumption at all* rather than an error.

The script detects this: sizeless snapshots are marked in `Snapshots.csv`'s `CollectionNote`, and the console warns you how many were affected. If you see that warning, the snapshot totals are understated — grant the privilege and re-run.

### VMs spanning multiple datastores

A VM with disks on several datastores cannot have its snapshot size split between them without walking each disk individually. Such a VM's snapshot size is attributed to **every** datastore it touches, and both the console and the affected `CollectionNote` fields say so. This over-attributes rather than under-attributes: a visible, explicable overstatement beats a full datastore with no explanation for why.

### Hardware version

Reported as `HardwareVersion`, a string (e.g. `vmx-21`). PowerCLI also exposes a `Version` property, but it is an enum capped at `v18` — any VM on newer hardware reports `Unknown` there — and PowerCLI 13.3 deprecates it in favour of the string. The script reads only the string.

### VMware Tools

`ToolsRunningStatus` and `ToolsVersionStatus` come from the current API fields. The older `toolsStatus` field has been deprecated since vSphere API 4.0 and is deliberately not read.

### Deprecated properties

Verified by reflection against `VMware.VimAutomation.Core 13.3.0.24145081`, these carry `[Obsolete]` and emit a console warning on every read, so the script avoids them: `Datastore.Accessible` (uses `State` instead), `Snapshot.Quiesced`, `Snapshot.Parent` (uses `ParentSnapshot`), `VMGuest.GuestId` (the script reads `VirtualMachine.GuestId`, which is not deprecated), and `Cluster.DrsMode` (uses `DrsAutomationLevel`). `VirtualMachine.Version` is warned about by the cmdlet layer rather than by the type.

### Standalone ESXi vs vCenter

The script branches on the connection's `ProductLine` (`vpx` = vCenter, `embeddedEsx` = standalone ESXi). Cluster collection is attempted only against vCenter, since clusters cannot exist on a standalone host.

> **Verify on first standalone run:** Broadcom does not document whether `Get-Cluster` against a standalone ESXi host returns an empty result or raises an error. The script does not depend on either — the call is both branch-guarded and wrapped in try/catch — but this is worth confirming the first time you point it at a real standalone host.

### Why Windows PowerShell 5.1

The script targets Windows PowerShell 5.1 and declares `#Requires -Version 5.1`. It runs under PowerShell 7.x, but two PowerCLI features are unavailable there:

- `Connect-VIServer -SaveCredentials` is *"not supported on the Core edition of PowerShell"*, so the credential store cannot be populated from PS 7.
- `InvalidCertificateAction` supports only `Fail` and `Ignore` on PowerShell Core; `Warn` and `Prompt` are Windows PowerShell only. The script uses `Ignore`, which is valid on both.

### Resilience

- One unreachable target does not end the run — the failure is recorded in `ConnectionLog.csv` and the next target is attempted.
- One host, VM, or datastore that fails to collect fully is still emitted as a row, with the reason in its `CollectionNote` column prefixed `PARTIAL:`. Nothing is ever silently dropped from a count.
- Every connection is made with `-NotDefault`, so an existing interactive PowerCLI session is not hijacked, and every target is disconnected when its collection finishes.

## What this does not cover

- **SAN / NAS arrays** — no VMware agent; inventory them from their own management plane and cross-reference by datastore/LUN.
- **Virtual networking** — vSwitches, port groups, and VLANs are not collected. Distributed switches would need `VMware.VimAutomation.Vds`.
- **Performance history** — this is a point-in-time inventory. Live CPU and memory usage are captured as a single sample; for trending, use vRealize/Aria Operations or repeated runs diffed via `FullInventory.json`.
- **Guest-level detail** — installed software, patch level, and disk free space inside the guest come from the guest OS, not vSphere.
