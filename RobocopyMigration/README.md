# Robocopy Migration GUI

Browser-based tool for server-to-server file migrations using robocopy. Starts a local web server with a clean, dark-themed interface for configuring migration jobs, previewing what will be copied, and monitoring live progress — all without touching the command line.

## Prerequisites

- Windows Server 2012 R2+ or Windows 10+
- PowerShell 5.1
- Run as Administrator (required for permission-preserving copies)
- Robocopy (included with Windows)

## Usage

```powershell
# Launch with default settings (opens browser automatically)
.\RobocopyMigration-GUI.ps1

# Use a custom port
.\RobocopyMigration-GUI.ps1 -Port 9090

# Launch without opening browser
.\RobocopyMigration-GUI.ps1 -NoBrowserOpen
```

## Migration Presets

| Preset | What it copies | Robocopy flags | Use when |
|--------|---------------|----------------|----------|
| **Full Migration** | Files, folders, timestamps, NTFS permissions, ownership | `/S /E /COPY:DATSO /DCOPY:DAT` | Migrating a file share to a new server and need an exact replica |
| **Incremental** | Only new or updated files, with permissions | `/S /E /COPY:DATSO /DCOPY:DAT /XO /XX` | Second pass after a full migration, or topping up overnight changes. Skips older files and ignores extras at destination |
| **Data Only** | Files, folders, timestamps | `/S /E /COPY:DAT /DCOPY:DAT` | Destination has different permission structure, or you just need the data |
| **Mirror** | Everything + deletes extras at destination | `/MIR /COPY:DATSO /DCOPY:DAT` | Keeping destination in sync with source -- **deletes files at destination not present at source** |

## Advanced Options

| Option | Default | Description |
|--------|---------|-------------|
| Retries | 3 | Number of times to retry a failed file copy |
| Wait time | 5 sec | Seconds to wait between retries |
| Inter-packet gap | 0 (unlimited) | Milliseconds between packets — increase to throttle bandwidth |
| Multi-threaded | Off | Enable multi-threaded copying with configurable thread count (default 8) |
| Exclude files | — | Space-separated patterns (e.g., `*.tmp *.log`) |
| Exclude folders | — | Space-separated folder names (e.g., `Temp .git`) |
| Log file | — | Path to save a robocopy log file |

## Features

- **Preview before you copy** — See file count, folder count, and total size before starting
- **Job queue** — Add multiple migration jobs and run them sequentially or in parallel
- **Live progress** — Click any running job to see real-time log output and stats
- **Cancel jobs** — Stop a running migration at any time
- **Mapped drive support** — Detects network drives visible to the current session, even under elevation
- **Dark/light theme** — Toggle in the top-right corner
