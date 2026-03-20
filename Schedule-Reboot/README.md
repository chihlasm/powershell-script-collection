# Schedule-Reboot

Creates a one-time Windows scheduled task to reboot a server at a specified date and time. The task runs as SYSTEM, triggers a graceful `shutdown /r`, and auto-deletes after execution.

## Usage

```powershell
# Schedule a reboot for a specific date/time
.\Schedule-Reboot.ps1 -RebootDate "2026-03-15 02:00"

# With custom grace period and reason
.\Schedule-Reboot.ps1 -RebootDate "Saturday 3AM" -GracePeriod 120 -Reason "Monthly patching"

# Skip confirmation prompt
.\Schedule-Reboot.ps1 -RebootDate "2026-04-01 23:00" -TaskName "April-Reboot" -Force
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `RebootDate` | Yes | — | Date and time to reboot (any valid DateTime format) |
| `TaskName` | No | `Scheduled-Reboot` | Name for the scheduled task |
| `Reason` | No | `Planned maintenance reboot` | Reason string logged in the shutdown event |
| `GracePeriod` | No | `60` | Seconds to wait before forcing reboot (0–600) |
| `NoAutoDelete` | No | — | Keep the task after execution; also runs if server was offline at scheduled time |
| `Force` | No | — | Skip the confirmation prompt |

## Behavior

- By default, the task auto-deletes 1 hour after the scheduled time
- With `-NoAutoDelete`, the task persists and uses `StartWhenAvailable` to run if missed
- Warns and prompts if a task with the same name already exists

## Requirements

- PowerShell 5.1+
- Run as Administrator
