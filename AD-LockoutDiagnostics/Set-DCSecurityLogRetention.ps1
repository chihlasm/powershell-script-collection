#Requires -Version 5.1
<#
.SYNOPSIS
    Reports and optionally increases the Security event log size on domain controllers.
.DESCRIPTION
    Lockout reports can only look back as far as the Security log is retained. When the
    log wraps every few days, a "60 day" report silently returns only those few days of
    data.

    This script measures the current retention on every domain controller, calculates the
    log size needed to hold a target number of days, and - only when -Apply is supplied -
    increases the maximum log size to match.

    IMPORTANT, read before using -Apply:

      * This CHANGES DOMAIN CONTROLLER CONFIGURATION. Run the default read-only report
        first and review the numbers.
      * It CANNOT recover events that have already been overwritten. After enlarging the
        log you must wait for new history to accumulate before a longer report window
        returns real data.
      * If Security log size is managed by Group Policy (Computer Configuration >
        Policies > Windows Settings > Security Settings > Event Log), that GPO will
        revert this change at the next refresh. The script detects the likely presence of
        such a policy and warns. In a GPO-managed domain, change the GPO instead.
      * Enlarging the log consumes disk on the DC's system drive. The script reports free
        space and refuses to apply a change that would leave less than -MinFreeSpaceGB.
      * The log is NOT cleared. Increasing MaximumSizeInBytes is non-destructive to the
        events already present.
.PARAMETER TargetDays
    How many days of Security log history you want to retain. 1-365, default 90.
.PARAMETER DomainController
    Optional. One or more DC names to check instead of auto-discovering all DCs.
.PARAMETER Apply
    Actually increase the log size. Without this switch the script only reports.
    Supports -WhatIf and -Confirm.
.PARAMETER MinFreeSpaceGB
    Refuse to apply a change that would leave less than this much free space on the DC's
    log volume. Default 10 GB.
.PARAMETER MaxSizeGB
    Safety ceiling on the size this script will set, in GB. Default 4 GB. A calculated
    requirement above this is reported but clamped.
.PARAMETER OutputPath
    Folder for the CSV report. Defaults to a "Reports" folder beside this script.
.EXAMPLE
    .\Set-DCSecurityLogRetention.ps1
    Read-only. Reports current retention on every DC and what 90 days would require.
.EXAMPLE
    .\Set-DCSecurityLogRetention.ps1 -TargetDays 60
    Read-only sizing report for a 60-day target.
.EXAMPLE
    .\Set-DCSecurityLogRetention.ps1 -TargetDays 60 -Apply -WhatIf
    Shows exactly what would change, without changing anything.
.EXAMPLE
    .\Set-DCSecurityLogRetention.ps1 -TargetDays 60 -Apply
    Increases the Security log on each DC to hold roughly 60 days. Prompts per DC.
.NOTES
    Requires RSAT ActiveDirectory module, remote registry/WinRM access to the DCs, and
    administrative rights on them. Run the read-only report first.

    Companion tools: Get-ADLockoutHistory.ps1, Diagnose-ADAccountLockout.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateRange(1, 365)]
    [int]$TargetDays = 90,

    [string[]]$DomainController,

    [switch]$Apply,

    [ValidateRange(0, 1000)]
    [int]$MinFreeSpaceGB = 10,

    [ValidateRange(1, 64)]
    [int]$MaxSizeGB = 4,

    [string]$OutputPath,

    # Internal: dot-source the functions without running the orchestration body.
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Get-RequiredLogSize {
    # Pure sizing math, kept separate so it is unit-testable without a domain.
    # Given how much log is currently consumed over a known number of days, work out the
    # size needed to cover TargetDays, plus a headroom factor for activity spikes
    # (audit policy changes, incidents, patch days all raise the daily rate).
    param(
        [Parameter(Mandatory)][double]$CurrentSizeBytes,
        [Parameter(Mandatory)][double]$CurrentDays,
        [Parameter(Mandatory)][int]$TargetDays,
        [double]$HeadroomFactor = 1.25,
        [int]$MaxSizeGB = 4
    )

    $result = [PSCustomObject]@{
        BytesPerDay      = $null
        RequiredBytes    = $null
        RequiredMB       = $null
        ClampedToMax     = $false
        Calculable       = $false
        Note             = ''
    }

    # Guard against a divide-by-zero and against a log so fresh the rate is meaningless.
    if ($CurrentDays -le 0.1) {
        $result.Note = 'Current history is too short (< 0.1 day) to estimate a daily rate reliably.'
        return $result
    }
    if ($CurrentSizeBytes -le 0) {
        $result.Note = 'Current log size reported as zero; cannot estimate a daily rate.'
        return $result
    }

    $perDay = $CurrentSizeBytes / $CurrentDays
    $needed = $perDay * $TargetDays * $HeadroomFactor

    # Windows requires the Security log size to be a multiple of 64 KB.
    $chunk  = 64KB
    $needed = [math]::Ceiling($needed / $chunk) * $chunk

    # The documented maximum is 4194240 KB, which is 64 KB SHORT of a literal 4 GB
    # (4194304 KB). Requesting a full 4 GB therefore exceeds the permitted range, so the
    # ceiling is capped at the documented value and then floored to a 64 KB boundary.
    # https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc778402(v=ws.10)
    $absoluteMax = 4194240KB
    $ceiling = [double]$MaxSizeGB * 1GB
    if ($ceiling -gt $absoluteMax) { $ceiling = [double]$absoluteMax }
    if ($needed -gt $ceiling) {
        $result.ClampedToMax = $true
        $result.Note = ("Calculated requirement ({0} MB) exceeds the -MaxSizeGB ceiling of {1} GB; clamped. Consider log forwarding/SIEM for this retention target." -f [math]::Round($needed/1MB,0), $MaxSizeGB)
        $needed = [math]::Floor($ceiling / $chunk) * $chunk
    }

    # Documented floor is 1024 KB (1 MB). A tiny calculated value would otherwise be
    # rejected by Windows as out of range.
    if ($needed -lt 1MB) { $needed = 1MB }

    $result.BytesPerDay   = $perDay
    $result.RequiredBytes = $needed
    $result.RequiredMB    = [math]::Round($needed / 1MB, 0)
    $result.Calculable    = $true
    return $result
}

function Get-DCLogStatus {
    # Collects current Security log state and retention for one DC. Every remote call is
    # wrapped so one unreachable DC never halts the sweep.
    param(
        [Parameter(Mandatory)][string]$DcName,
        [Parameter(Mandatory)][int]$TargetDays,
        [int]$MaxSizeGB = 4
    )

    $row = [PSCustomObject]@{
        DC                = $DcName
        Reachable         = $false
        CurrentMaxMB      = $null
        CurrentUsedMB     = $null
        OldestEvent       = $null
        RetentionDays     = $null
        LogMode           = $null
        BytesPerDayMB     = $null
        RequiredMB        = $null
        MeetsTarget       = $false
        FreeSpaceGB       = $null
        GpoManaged        = $null
        Note              = ''
    }

    try {
        $log = Get-WinEvent -ListLog Security -ComputerName $DcName -ErrorAction Stop
    } catch {
        $row.Note = "Could not read Security log configuration: $($_.Exception.Message)"
        return $row
    }

    $row.Reachable     = $true
    $row.CurrentMaxMB  = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
    $row.CurrentUsedMB = [math]::Round($log.FileSize / 1MB, 0)
    $row.LogMode       = [string]$log.LogMode

    try {
        $oldest = Get-WinEvent -ComputerName $DcName -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($oldest) {
            $row.OldestEvent   = $oldest.TimeCreated
            $row.RetentionDays = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 2)
        }
    } catch {
        $row.Note = "Could not read the oldest Security event: $($_.Exception.Message)"
    }

    if ($null -ne $row.RetentionDays) {
        $sizing = Get-RequiredLogSize -CurrentSizeBytes $log.FileSize -CurrentDays $row.RetentionDays `
            -TargetDays $TargetDays -MaxSizeGB $MaxSizeGB
        if ($sizing.Calculable) {
            $row.BytesPerDayMB = [math]::Round($sizing.BytesPerDay / 1MB, 1)
            $row.RequiredMB    = $sizing.RequiredMB
            $row.MeetsTarget   = ($row.RetentionDays -ge $TargetDays)
            if ($sizing.Note) { $row.Note = ($row.Note, $sizing.Note | Where-Object { $_ }) -join ' ' }
        } elseif ($sizing.Note) {
            $row.Note = ($row.Note, $sizing.Note | Where-Object { $_ }) -join ' '
        }
    }

    # Free space on the volume holding the log file, so we never fill a DC's system drive.
    try {
        $logPath = [System.Environment]::ExpandEnvironmentVariables($log.LogFilePath)
        $driveLetter = if ($logPath -match '^([A-Za-z]):') { $Matches[1] } else { 'C' }
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $DcName `
            -Filter "DeviceID='${driveLetter}:'" -ErrorAction Stop
        if ($disk) { $row.FreeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 1) }
    } catch {
        $row.Note = ($row.Note, "Could not read free disk space: $($_.Exception.Message)" | Where-Object { $_ }) -join ' '
    }

    # Detect a GPO-enforced log size. When this policy key is present, the effective size
    # is controlled by Group Policy and any local change is reverted at the next refresh.
    try {
        $gpo = Invoke-Command -ComputerName $DcName -ErrorAction Stop -ScriptBlock {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            if (Test-Path $key) { (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).MaxSize } else { $null }
        }
        $row.GpoManaged = ($null -ne $gpo)
        if ($row.GpoManaged) {
            $row.Note = ($row.Note, ("Security log size is set by Group Policy (MaxSize={0} KB). Change the GPO instead; a local change will be reverted." -f [math]::Round($gpo/1KB,0)) | Where-Object { $_ }) -join ' '
        }
    } catch {
        # Remoting may be unavailable; not fatal, but we cannot rule out GPO management.
        $row.GpoManaged = $null
        $row.Note = ($row.Note, 'Could not check for a Group Policy log-size setting (remoting unavailable); verify manually before applying.' | Where-Object { $_ }) -join ' '
    }

    return $row
}

function Set-DCLogSize {
    # Applies the new maximum size. Isolated so the orchestration body stays readable and
    # so ShouldProcess wraps exactly one well-defined action.
    param(
        [Parameter(Mandatory)][string]$DcName,
        [Parameter(Mandatory)][long]$NewSizeBytes
    )
    # The *-EventLog cmdlets (including Limit-EventLog) were REMOVED in PowerShell 7 -
    # they rely on APIs that are not supported on .NET Core. Calling it there fails with
    # "not recognized", so prefer it only on Windows PowerShell 5.1 and fall back to
    # wevtutil (present on every Windows Server) everywhere else.
    # https://learn.microsoft.com/powershell/scripting/whats-new/differences-from-windows-powershell
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.management/limit-eventlog
    $useLimitEventLog = ($PSVersionTable.PSEdition -ne 'Core') -and
                        (Get-Command -Name 'Limit-EventLog' -ErrorAction SilentlyContinue)

    if ($useLimitEventLog) {
        Limit-EventLog -LogName Security -ComputerName $DcName -MaximumSize $NewSizeBytes -ErrorAction Stop
        return
    }

    # wevtutil sets the same value and, like Limit-EventLog, does not clear the log.
    # /ms: takes bytes. Run it on the DC so no remote-registry rights are needed beyond
    # the WinRM session this script already requires elsewhere.
    Invoke-Command -ComputerName $DcName -ErrorAction Stop -ArgumentList $NewSizeBytes -ScriptBlock {
        param([long]$Bytes)
        $output = & wevtutil.exe sl Security /ms:$Bytes 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "wevtutil sl Security /ms:$Bytes failed with exit code ${LASTEXITCODE}: $output"
        }
    }
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

Write-Status INFO "Security log retention check - target: $TargetDays day(s)."

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load the ActiveDirectory module (RSAT). $($_.Exception.Message)"
    exit 1
}

if ($DomainController) {
    $dcs = @($DomainController)
} else {
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName)
    } catch {
        Write-Status FAIL "Could not enumerate domain controllers. $($_.Exception.Message)"
        exit 1
    }
}
Write-Status INFO "Checking $($dcs.Count) domain controller(s): $($dcs -join ', ')"

$results = foreach ($dc in $dcs) {
    Write-Status INFO "Querying $dc ..."
    Get-DCLogStatus -DcName $dc -TargetDays $TargetDays -MaxSizeGB $MaxSizeGB
}
$results = @($results)

Write-Host ''
$results | Format-Table -AutoSize -Property DC, CurrentMaxMB, RetentionDays, BytesPerDayMB, RequiredMB, FreeSpaceGB, MeetsTarget |
    Out-String | Write-Host

foreach ($r in $results | Where-Object { $_.Note }) {
    Write-Status WARN "$($r.DC): $($r.Note)"
}

$short = @($results | Where-Object { $_.Reachable -and -not $_.MeetsTarget -and $null -ne $_.RequiredMB })
if ($short.Count -eq 0) {
    Write-Status PASS "Every reachable DC already retains at least $TargetDays day(s)."
} else {
    Write-Status WARN "$($short.Count) DC(s) retain less than $TargetDays day(s)."
    Write-Host ''
    Write-Status INFO 'Already-overwritten events CANNOT be recovered. Enlarging the log only'
    Write-Status INFO 'affects history collected from this point forward.'
}

# --- Apply ---
if ($Apply -and $short.Count -gt 0) {
    Write-Host ''
    Write-Status WARN 'APPLY MODE: this will change Security log configuration on domain controllers.'

    foreach ($r in $short) {
        if ($r.GpoManaged -eq $true) {
            Write-Status WARN "$($r.DC): skipped - size is enforced by Group Policy. Update the GPO instead."
            continue
        }
        if ($null -ne $r.FreeSpaceGB) {
            $growthGB = [math]::Round((($r.RequiredMB - $r.CurrentMaxMB) / 1024), 2)
            if ($growthGB -gt 0 -and ($r.FreeSpaceGB - $growthGB) -lt $MinFreeSpaceGB) {
                Write-Status WARN ("{0}: skipped - growing by {1} GB would leave under {2} GB free (currently {3} GB)." -f $r.DC, $growthGB, $MinFreeSpaceGB, $r.FreeSpaceGB)
                continue
            }
        } else {
            Write-Status WARN "$($r.DC): free space unknown; skipping to avoid filling the system drive. Re-run with connectivity to this DC or set the size manually."
            continue
        }
        if ($r.RequiredMB -le $r.CurrentMaxMB) {
            Write-Status INFO "$($r.DC): current maximum ($($r.CurrentMaxMB) MB) already meets the calculated requirement ($($r.RequiredMB) MB); the log may simply need time to fill."
            continue
        }

        $target = [long]($r.RequiredMB * 1MB)
        $action = "Increase Security log maximum from $($r.CurrentMaxMB) MB to $($r.RequiredMB) MB"
        if ($PSCmdlet.ShouldProcess($r.DC, $action)) {
            try {
                Set-DCLogSize -DcName $r.DC -NewSizeBytes $target
                Write-Status PASS "$($r.DC): Security log maximum set to $($r.RequiredMB) MB."
            } catch {
                Write-Status FAIL "$($r.DC): could not set log size. $($_.Exception.Message)"
            }
        }
    }

    Write-Host ''
    Write-Status INFO "Allow $TargetDays day(s) for history to accumulate before expecting a full-window report."
} elseif ($short.Count -gt 0) {
    Write-Host ''
    Write-Status INFO 'Read-only report. Re-run with -Apply to increase the log size, or -Apply -WhatIf to preview.'
}

# --- CSV report ---
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"
        exit 1
    }
}
$stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$csvPath = Join-Path $OutputPath "DCSecurityLogRetention_$stamp.csv"
try {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Status PASS "Report written: $csvPath"
} catch {
    Write-Status FAIL "Could not write CSV: $($_.Exception.Message)"
}
