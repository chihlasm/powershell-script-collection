# FSLogix VHDX Health Scan + Repair

Automated health scanning and repair tool for FSLogix Profile Container VHDX files in RDS/AVD environments. Detects active user sessions, skips in-use disks, scans offline VHDXs for filesystem corruption, repairs unhealthy volumes, and generates detailed reports.

## Download

One-liner to download to `C:\Scripts\FSLogix-ProfileDiskRepair` on any Windows machine:

```powershell
$dest = 'C:\Scripts\FSLogix-ProfileDiskRepair'
New-Item -Path $dest -ItemType Directory -Force | Out-Null
$base = 'https://raw.githubusercontent.com/chihlasm/powershell-script-collection/main/FSLogix-ProfileDiskRepair'
@('FSLogix-Repair.ps1', 'FSLogix-RepairMenu.ps1') | ForEach-Object {
    Invoke-WebRequest -Uri "$base/$_" -OutFile (Join-Path $dest $_) -UseBasicParsing
}
Write-Host "Downloaded to $dest" -ForegroundColor Green
```

Or clone the full repo:

```powershell
git clone https://github.com/chihlasm/powershell-script-collection.git
cd powershell-script-collection\FSLogix-ProfileDiskRepair
```

## Contents

| File | Purpose |
|------|---------|
| `FSLogix-Repair.ps1` | Core scan and repair engine (CLI, scriptable) |
| `FSLogix-RepairMenu.ps1` | Interactive TUI menu wrapping the repair script |

## Requirements

- **PowerShell 5.1** or later (ships with Windows Server 2016+)
- **Run as Administrator** (required for disk mounting and volume repair)
- **Storage module** (`Mount-DiskImage`, `Get-Volume`, `Repair-Volume`) -- ships with all Windows Server 2012+ and Windows 8+ installs. No Hyper-V role or tools required. Works inside VMs.
- Network access to the FSLogix profile share and RDS session hosts
- The target VHDXs must not be actively mounted by another process

## Quick Start

### Interactive mode (recommended for first use)

```powershell
.\FSLogix-RepairMenu.ps1
```

On first launch, the menu walks you through configuring your profile share path, session host names, and output directory. Settings are saved to `FSLogix-RepairMenu.config.json` alongside the script.

### Command-line mode

```powershell
.\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' -SessionHosts 'TS1','TS2'
```

---

## FSLogix-Repair.ps1 Reference

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ProfileShare` | String | *(required)* | UNC path to the FSLogix Profile Containers folder |
| `-SessionHosts` | String[] | *(required)* | RDS session host names to query for active sessions |
| `-OutputPath` | String | Current directory | Where CSV, HTML, and transcript files are saved |
| `-MountTimeoutSeconds` | Int | `15` | Max seconds to wait for a volume after mounting a VHDX |
| `-ThrottleLimit` | Int | `4` | Number of VHDXs to process concurrently (1-32) |
| `-MaxRetries` | Int | `2` | Retry attempts for failed repairs (0-10) |
| `-HtmlReport` | Switch | Off | Generate a styled HTML report alongside the CSV |
| `-SmtpServer` | String | *(none)* | SMTP server for email notifications |
| `-EmailTo` | String[] | *(none)* | Recipient address(es) for the completion email |
| `-EmailFrom` | String | *(none)* | Sender address for the completion email |
| `-Force` | Switch | Off | Skip the confirmation prompt before starting repairs |

### Examples

**Basic scan and repair:**

```powershell
.\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' `
    -SessionHosts 'TS1','TS2'
```

**Full-featured run with HTML report and email:**

```powershell
.\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' `
    -SessionHosts 'TS1','TS2','TS3' `
    -OutputPath 'C:\Reports' `
    -ThrottleLimit 6 `
    -MaxRetries 3 `
    -HtmlReport `
    -SmtpServer 'mail.contoso.com' `
    -EmailTo 'admin@contoso.com' `
    -EmailFrom 'noreply@contoso.com' `
    -Force
```

**Dry run (no actual repairs):**

```powershell
.\FSLogix-Repair.ps1 -ProfileShare '\\fs01\Profiles\Profile Containers' `
    -SessionHosts 'TS1' -WhatIf
```

### Output Files

Each run produces up to three files in the output directory:

| File | Always | Description |
|------|--------|-------------|
| `VHDX_ScanRepair_<timestamp>.csv` | Yes | Structured report with per-VHDX results |
| `VHDX_ScanRepair_<timestamp>.transcript.log` | Yes | Full console transcript for audit |
| `VHDX_ScanRepair_<timestamp>.html` | `-HtmlReport` only | Color-coded HTML with summary cards |

### CSV Columns

| Column | Description |
|--------|-------------|
| `VHDX` | Filename of the VHDX |
| `Owner` | Username extracted from the FSLogix folder name |
| `SizeMB` | Actual file size on disk (MB) |
| `MaxSizeMB` | Maximum provisioned VHDX size (MB) |
| `FragmentPct` | Filesystem fragmentation percentage |
| `HealthBefore` | Volume health status before any repair |
| `RepairResult` | Repair-Volume output or `NoActionNeeded` |
| `HealthAfter` | Volume health status after repair |
| `RetryCount` | Number of retry attempts needed (0 = first try) |
| `Status` | Final status: `HEALTHY`, `REPAIRED`, `REPAIR FAILED`, `SKIPPED`, or `ERROR` |
| `Error` | Error message if applicable |

### How It Works

1. **Pre-flight checks** -- Validates the Hyper-V module, output path writability, profile share access, session host connectivity, and email parameter consistency.
2. **Collect active sessions** -- Queries each session host with `query session` using dynamic column parsing. Usernames with active or disconnected sessions are collected.
3. **Enumerate VHDXs** -- Recursively finds all `.vhdx` files on the profile share.
4. **Parallel scan and repair** -- VHDXs are distributed across a runspace pool (controlled by `-ThrottleLimit`). Each worker:
   - Skips VHDXs belonging to active users
   - Mounts the VHDX and waits for the volume (with timeout)
   - Checks the volume health status
   - If unhealthy, runs `Repair-Volume -OfflineScanAndFix` with retry logic
   - Captures disk size, max size, and fragmentation metrics
   - Dismounts the VHDX cleanly (with best-effort dismount on failure)
5. **Report generation** -- Exports CSV (always), HTML (if `-HtmlReport`), and transcript log. Sends email if SMTP parameters are provided.

---

## FSLogix-RepairMenu.ps1 Reference

### Menu Options

| Option | Name | Description |
|--------|------|-------------|
| **1** | Quick Scan | Runs the repair script with `-WhatIf` so no disks are modified. Shows health status for all VHDXs. |
| **2** | Scan + Repair | Full scan and repair run. Requires typing `YES` to confirm. |
| **3** | View Last Report | Finds the most recent CSV report in the output directory and displays it as a formatted, color-coded table. |
| **4** | Session Host Status | Queries all configured session hosts and displays active/disconnected sessions in a table. |
| **5** | Disk Space Analysis | Lists all VHDXs sorted by size (largest first) with color-coded thresholds: green (< 4 GB), yellow (4-10 GB), red (> 10 GB). Shows top consumers. |
| **6** | Settings | Configure profile share, session hosts, output path, and mount timeout. Changes are saved to the JSON config file. |
| **7** | Help | Displays usage instructions. |
| **Q** | Quit | Exits the menu. |

### Configuration File

On first run, the TUI prompts for required values and saves them to `FSLogix-RepairMenu.config.json`:

```json
{
    "ProfileShare": "\\\\fs01\\Profiles\\Profile Containers",
    "SessionHosts": ["TS1", "TS2"],
    "OutputPath": "C:\\Reports",
    "MountTimeoutSeconds": 15
}
```

Edit this file manually or use menu option **6** to update settings.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-ConfigPath` | String | `FSLogix-RepairMenu.config.json` (same directory) | Path to the JSON configuration file |

---

## Scheduling

To run unattended on a schedule (e.g., weekly during a maintenance window), create a scheduled task:

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @"
-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\FSLogix-Repair.ps1" `
    -ProfileShare '\\fs01\Profiles\Profile Containers' `
    -SessionHosts 'TS1','TS2' `
    -OutputPath 'C:\Reports' `
    -HtmlReport `
    -SmtpServer 'mail.contoso.com' `
    -EmailTo 'admin@contoso.com' `
    -EmailFrom 'noreply@contoso.com' `
    -Force
"@

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At '02:00AM'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

Register-ScheduledTask -TaskName 'FSLogix VHDX Health Scan' `
    -Action $action -Trigger $trigger -Principal $principal
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Missing cmdlets: Mount-DiskImage...` | Storage module not available | Should not happen on Server 2012+/Win8+. Check with `Get-Module -ListAvailable Storage` |
| `Volume not available after N seconds` | Slow storage or locked VHDX | Increase `-MountTimeoutSeconds` or verify no other process has the VHDX open |
| Session host shows `[WARN] Unreachable` | Host is offline or firewalled | Verify the host is online and WinRM/RPC ports are open |
| `Profile share is not writable` warning | Share permissions are read-only for the service account | Grant the account write access, or ignore the warning (scanning still works) |
| All VHDXs show `SKIPPED - User Active` | All users are logged in | Run during a maintenance window or when users are logged off |
| `REPAIR FAILED` after retries | Severe filesystem corruption | Mount the VHDX manually and run `chkdsk /f` or restore from backup |
