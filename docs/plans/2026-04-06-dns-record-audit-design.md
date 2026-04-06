# DNS Record Audit & Search Tool — Design

**Date:** 2026-04-06
**Status:** Approved
**Folder:** `Search-DNSRecords/`

## Purpose

A browser-based PowerShell tool for searching, auditing, and comparing DNS records across domain controllers. Targets MSP/enterprise environments where stale DNS records accumulate after server decommissions, IP changes, and failed scavenging.

## Core Modes

### 1. Search Mode

Find DNS records by name, IP, record type, or age across user-selected zones.

- Supports wildcard and regex matching
- Filter by record type (A, AAAA, CNAME, MX, PTR, SRV, TXT, NS)
- Filter by age (records older than N days)
- Results displayed in a filterable, sortable table

### 2. Stale Record Detection

Scan selected zones and flag records as stale using three detection methods:

| Method | Description |
|--------|-------------|
| **Age-based** | Record timestamp older than configurable threshold (default 90 days) |
| **Static record** | Zero timestamp — never scavenged, often the most stale |
| **AD orphan** | A record with no matching AD computer object (disabled or deleted) |

Each flagged record gets a staleness reason tag explaining why it was flagged. Multiple reasons can apply to the same record.

### 3. DC Comparison

Select two DCs, pick overlapping zones, and get a full diff:

- **Missing records** — present on DC1 but absent on DC2, and vice versa
- **Mismatched records** — same record name exists on both but differs in IP, TTL, or timestamp
- Summary counts and a color-coded diff table (green = match, yellow = mismatch, red = missing)

## Architecture

Single self-contained PowerShell script (`Search-DNSRecords-GUI.ps1`) using the HTTP Listener pattern established in `FolderPermissionManager-GUI.ps1`.

```
Browser (localhost:8080)
  |
  |-- HTML/CSS/JS frontend (embedded in script)
  |     |-- Zone picker (checkbox list, forward zones pre-checked)
  |     |-- Mode selector (Search / Stale / Compare)
  |     |-- Parameters panel (mode-specific options)
  |     |-- Results table (sortable, filterable, color-coded)
  |     |-- Export bar (CSV + HTML buttons)
  |
  |-- REST API (PowerShell HttpListener)
        |-- GET  /api/zones?dc=<name>     — list zones for picker
        |-- POST /api/search              — search by pattern/type/age
        |-- POST /api/stale               — run stale detection
        |-- POST /api/compare             — compare two DCs
        |-- GET  /api/export/csv          — download CSV
        |-- GET  /api/export/html         — download standalone HTML report
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Port` | int | 8080 | HTTP listener port |
| `-StaleThresholdDays` | int | 90 | Age threshold for stale detection |
| `-OutputPath` | string | `.` (current dir) | Directory for exported files |

## GUI Layout

- **Top bar**: Target DC input field(s), mode selector tabs (Search / Stale / Compare)
- **Zone picker**: Checkbox list auto-populated from target DC. Forward lookup zones pre-checked, reverse zones unchecked by default.
- **Parameters panel**: Changes based on selected mode:
  - Search: pattern input, record type dropdown, age filter
  - Stale: threshold slider/input, checkboxes for which detection methods to use
  - Compare: second DC input field
- **Results table**: Sortable columns, text filter, color-coded status column
- **Export bar**: "Export CSV" and "Export HTML" buttons

## PowerShell Dependencies

| Module | Purpose | Load pattern |
|--------|---------|-------------|
| `DnsServer` | All DNS queries (`Get-DnsServerZone`, `Get-DnsServerResourceRecord`) | `Import-Module` with try/catch |
| `ActiveDirectory` | AD computer cross-reference for stale detection | `Import-Module` with try/catch; stale mode degrades gracefully if unavailable (skips AD orphan check) |

## Key Implementation Details

- All DNS queries use `-ComputerName` parameter — never assumes script runs on the DC
- Zone discovery via `Get-DnsServerZone -ComputerName`
- AD computer lookup via `Get-ADComputer -Filter "Name -eq '$hostname'"` with individual try/catch per record
- Comparison mode queries both DCs for the same zone, then diffs in-memory using hashtable lookups
- Large zone handling: results streamed to the API response in batches, frontend renders progressively
- Timestamp = 0 means static record (set once, never scavenged)

## Error Handling

- DC connection errors caught per-DC with friendly status in the GUI
- Zone-level errors reported per-zone in the results (not script-halting)
- Module unavailability detected at startup with clear messages about what functionality is degraded
- Individual record query failures logged and skipped (one bad record doesn't stop the scan)

## Export Formats

- **CSV**: One row per record match, columns for zone, name, type, data, TTL, timestamp, age, staleness reason, DC source. Uses `Export-Csv -NoTypeInformation -Encoding UTF8`.
- **HTML**: Standalone file with embedded CSS/JS, same filterable table as the GUI, suitable for emailing or archiving. Follows the pattern from the GPO audit report.

## Folder Structure

```
Search-DNSRecords/
  Search-DNSRecords-GUI.ps1
  README.md
```
