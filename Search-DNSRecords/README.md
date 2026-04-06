# Search-DNSRecords-GUI.ps1

Browser-based DNS record audit tool for searching, detecting stale records, and comparing DNS zones across domain controllers. Launches a local web server with a dark-themed UI for interactive DNS exploration and reporting.

## Requirements

- **PowerShell** 5.1 or later
- **RSAT DNS Server tools** (DnsServer module)
- **ActiveDirectory module** (optional) — enables AD orphan detection in stale mode
- **Domain-joined machine** with permissions to read DNS zones on target domain controllers

### Installing RSAT DNS Tools

```powershell
# Windows Server
Install-WindowsFeature RSAT-DNS-Server

# Windows 10/11 workstation
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0

# ActiveDirectory module (optional, for stale record AD orphan detection)
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11 workstation
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Usage

```powershell
# Launch with default settings (opens browser to http://localhost:8080)
.\Search-DNSRecords-GUI.ps1

# Custom port and stale threshold
.\Search-DNSRecords-GUI.ps1 -Port 9090 -StaleThresholdDays 60

# Save exports to a specific directory, don't auto-open browser
.\Search-DNSRecords-GUI.ps1 -OutputPath "C:\Reports" -NoBrowserOpen
```

### Parameters

| Parameter              | Type   | Default          | Description                                          |
|------------------------|--------|------------------|------------------------------------------------------|
| `-Port`                | Int    | 8080             | TCP port for the local web server (1024-65535)       |
| `-StaleThresholdDays`  | Int    | 90               | Age in days after which a record is considered stale |
| `-OutputPath`          | String | Current directory | Directory where exported CSV and HTML files are saved|
| `-NoBrowserOpen`       | Switch | False            | Do not automatically open the browser on launch      |

## Modes

### 1. Search Mode

Find DNS records by name, IP address, record type, or age across selected zones.

- **Pattern matching**: Wildcard (default) or regex
- **Record type filter**: A, AAAA, CNAME, MX, PTR, SRV, TXT, NS, or all types
- **Age filter**: Only show records older than N days
- Results displayed in a sortable, filterable table

### 2. Stale Record Detection

Scan selected zones and flag records that may be stale. Three detection methods, each individually toggleable:

| Method | What it catches |
|--------|----------------|
| **Age-based** | Records with a timestamp older than the threshold (default 90 days) |
| **Static records** | Records with a zero timestamp that are never scavenged |
| **AD orphan** | A records whose hostname has no matching Active Directory computer object |

Each flagged record shows one or more staleness reason tags. The AD orphan check requires the ActiveDirectory module — if unavailable, that checkbox is disabled in the UI and the tool gracefully skips it.

### 3. DC Comparison

Compare DNS zones between two domain controllers to find replication issues:

- **Missing records** — present on one DC but not the other
- **Mismatched records** — same record name and type exists on both but with different data
- Color-coded results: records unique to each DC are flagged, mismatches highlighted

## GUI Overview

The browser-based interface includes:

- **DC input** with zone auto-discovery — enter a DC name and click "Load Zones"
- **Zone picker** — checkboxes for each zone, forward zones pre-checked, with Select All/Deselect All buttons
- **Mode tabs** — switch between Search, Stale, and Compare modes
- **Results table** — sortable columns, text filter, row count
- **Export buttons** — download results as CSV or standalone HTML report

## Export Formats

- **CSV**: One row per record, saved to OutputPath and also downloaded via browser. Compatible with Excel and other tools.
- **HTML**: Standalone dark-themed report with built-in filtering and sorting. Suitable for emailing or archiving.

## Notes

- All DNS queries use the `-ComputerName` parameter — the script does not need to run on a domain controller
- The AD orphan check pre-fetches all computer objects for performance, so the first stale scan may take a few seconds on large domains
- Press Ctrl+C in the PowerShell window to stop the web server
- The tool filters out Forwarder zones and TrustAnchors from the zone picker automatically
