# Get-RAM-Usage

Breaks down RAM usage by user and process on Citrix VDA / multi-session servers.
Uses **Private Working Set** (matches Task Manager's "Memory" column).

## Quick Start

```powershell
# Local server — console output + interactive HTML report
.\Get-RAMUsage.ps1

# Multiple VDAs
.\Get-RAMUsage.ps1 -ComputerName CTXVDA01, CTXVDA02

# Export CSV alongside the HTML
.\Get-RAMUsage.ps1 -ExportCSV ".\ram.csv"

# Quiet mode (no browser pop-up)
.\Get-RAMUsage.ps1 -SkipBrowserOpen
```

## Features

- **Private Working Set** — matches Task Manager, no double-counted shared memory
- **Interactive HTML report** — dark-themed, auto-opens in browser
  - Click any user row to expand their full process list
  - Search and sort processes within each user
  - Sort user table by any column (RAM, CPU, process count, etc.)
  - Toggle system accounts on/off
  - Expand All / Collapse All buttons
- **Memory utilization cards** — per-server with color-coded bars
- **Console summary** — ranked user list with visual memory bar
- **Multi-server** — query multiple VDAs in one run
- **CSV export** — full detail for every process

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ComputerName` | Server(s) to query | Local machine |
| `-Credential` | Credentials for remote access | Current user |
| `-Top` | Max processes per user in console (0 = all) | 15 |
| `-ExportCSV` | CSV output file path | *(none)* |
| `-ExportHTML` | HTML output file path | Script directory |
| `-SkipBrowserOpen` | Don't auto-open the HTML report | `$false` |
| `-IncludeSystemProcesses` | Show SYSTEM/LOCAL SERVICE in console detail | `$false` |

## Requirements

- PowerShell 5.1+
- **Run as Administrator** (`Get-Process -IncludeUserName` requires elevation)
- For remote servers: WinRM / PowerShell Remoting enabled
