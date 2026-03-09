#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a scheduled task to reboot the local server at a specified date and time.

.DESCRIPTION
    Creates a one-time Windows scheduled task that reboots the server at the specified
    date and time. The task runs as SYSTEM, triggers a graceful shutdown /r, and
    automatically deletes itself after execution. Useful for scheduling maintenance
    reboots during off-hours via RMM or manual execution.

.PARAMETER RebootDate
    The date and time to reboot in a standard DateTime format.
    Examples: "2026-03-15 02:00", "03/15/2026 2:00 AM", "Saturday 2AM"

.PARAMETER TaskName
    Optional name for the scheduled task. Default: "Scheduled-Reboot"

.PARAMETER Reason
    Optional reason string logged in the shutdown event. Default: "Planned maintenance reboot"

.PARAMETER GracePeriod
    Seconds to wait before forcing reboot, giving users time to save work. Default: 60

.PARAMETER NoAutoDelete
    Do not set an end boundary or auto-delete the task. The task will persist in Task
    Scheduler after execution and will still run if the server was offline at the
    scheduled time (via StartWhenAvailable). Without this flag, the task auto-deletes
    1 hour after the scheduled time and won't execute if missed by more than 1 hour.

.PARAMETER Force
    Skip the confirmation prompt.

.EXAMPLE
    .\Schedule-Reboot.ps1 -RebootDate "2026-03-15 02:00"
    Schedules a reboot for March 15, 2026 at 2:00 AM with default settings.

.EXAMPLE
    .\Schedule-Reboot.ps1 -RebootDate "Saturday 3AM" -GracePeriod 120 -Reason "Monthly patching"
    Schedules a reboot for the next Saturday at 3 AM with a 2-minute grace period.

.EXAMPLE
    .\Schedule-Reboot.ps1 -RebootDate "2026-04-01 23:00" -TaskName "April-Reboot" -Force
    Schedules a reboot without confirmation prompt using a custom task name.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Date and time to reboot (e.g. '2026-03-15 02:00')")]
    [DateTime]$RebootDate,

    [Parameter()]
    [string]$TaskName = "Scheduled-Reboot",

    [Parameter()]
    [string]$Reason = "Planned maintenance reboot",

    [Parameter()]
    [ValidateRange(0, 600)]
    [int]$GracePeriod = 60,

    [Parameter()]
    [switch]$NoAutoDelete,

    [Parameter()]
    [switch]$Force
)

# --- Validate the reboot date is in the future ---
if ($RebootDate -le (Get-Date)) {
    Write-Error "RebootDate must be in the future. You specified: $RebootDate"
    exit 1
}

# --- Check for existing task with the same name ---
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Warning "A scheduled task named '$TaskName' already exists."
    if (-not $Force) {
        $response = Read-Host "Overwrite it? (Y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-Host "Aborted. No changes made."
            exit 0
        }
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed existing task '$TaskName'."
}

# --- Confirm with the user ---
if (-not $Force) {
    Write-Host ""
    Write-Host "Server:       $env:COMPUTERNAME"
    Write-Host "Reboot at:    $($RebootDate.ToString('yyyy-MM-dd hh:mm tt'))"
    Write-Host "Grace period: $GracePeriod seconds"
    Write-Host "Auto-delete:  $(if ($NoAutoDelete) { 'No' } else { 'Yes (1 hour after scheduled time)' })"
    Write-Host "Reason:       $Reason"
    Write-Host ""
    $confirm = Read-Host "Proceed? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Aborted. No changes made."
        exit 0
    }
}

# --- Build and register the scheduled task ---
$action = New-ScheduledTaskAction -Execute "shutdown.exe" `
    -Argument "/r /t $GracePeriod /d p:0:0 /c `"$Reason`""

$trigger = New-ScheduledTaskTrigger -Once -At $RebootDate

$settingsParams = @{
    AllowStartIfOnBatteries    = $true
    DontStopIfGoingOnBatteries = $true
    StartWhenAvailable         = $true
}

if (-not $NoAutoDelete) {
    $settingsParams['DeleteExpiredTaskAfter'] = New-TimeSpan -Hours 1
    $trigger.EndBoundary = $RebootDate.AddHours(1).ToString('s')
}

$settings = New-ScheduledTaskSettingsSet @settingsParams

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "One-time reboot: $Reason" `
        -ErrorAction Stop | Out-Null

    Write-Host ""
    Write-Host "Scheduled task '$TaskName' created successfully." -ForegroundColor Green
    Write-Host "  Server:    $env:COMPUTERNAME"
    Write-Host "  Reboot at: $($RebootDate.ToString('yyyy-MM-dd hh:mm tt'))"
    Write-Host "  Grace:     $GracePeriod seconds"
    Write-Host ""
    Write-Host "To cancel: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
} catch {
    Write-Error "Failed to create scheduled task: $_"
    exit 1
}
