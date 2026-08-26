#Requires -Version 5.1

<#
.SYNOPSIS
    Live view of bad-password activity across every domain controller.
.DESCRIPTION
    The rest of this toolkit is retrospective: it reads what already happened. This is the
    one tool for watching a lockout AS IT HAPPENS - the thing to leave running on a second
    monitor while a user retries, or while you work through which device is at fault.

    It polls badPwdCount on every domain controller and reports each increase the moment
    it appears, with how close the account now is to locking out.

    WHY IT POLLS DIRECTORY ATTRIBUTES RATHER THAN EVENT LOGS

    Two reasons, and the second is what makes this worth having:

      1. IT WORKS WHEN AUDITING IS OFF. badPwdCount is a directory attribute, not a log
         entry. If failure auditing is disabled - the condition that makes every other
         report in this toolkit return empty - this still sees the attempts.

      2. IT IS CHEAP AND BOUNDED. One LDAP read per account per DC per poll. Reading event
         logs on a busy DC is what made the correlation pass in
         Export-ADAuthSourceEvidence.ps1 unusable; nothing here touches an event log.

    TWO FACTS ABOUT badPwdCount THAT SHAPE EVERYTHING HERE

      NOT REPLICATED. Each DC maintains its own counter, reflecting only the attempts it
      personally handled. Watching one DC sees a fraction of the activity, so every DC is
      polled and their counters tracked separately. This is also why the tool can tell you
      WHICH DC is receiving the bad passwords, which narrows the search to a site.

      RESETS ON SUCCESS. The counter resets on a DC when the user successfully
      authenticates against that DC. A falling counter therefore means the user just got
      in - not that the problem resolved itself. Reported as a reset, never as negative
      activity.
      https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount

    READ-ONLY. Reads directory attributes and changes nothing.
.PARAMETER Identity
    One or more accounts to watch (sAMAccountName). Omit to watch every account that is
    currently locked out or carrying a non-zero bad-password count, refreshed each poll -
    useful when you do not yet know who is affected.
.PARAMETER IntervalSeconds
    Seconds between polls. Default 15. Values below 5 are raised to 5: a tighter loop
    against every DC is the one way this tool could put load on a domain controller.
.PARAMETER DomainController
    Optional. One or more DCs to poll instead of auto-discovering all of them.
.PARAMETER DurationMinutes
    Stop automatically after this long. Default 0 (run until Ctrl+C).
.PARAMETER LogPath
    Optional CSV file to append every observed change to, so a watch left running
    overnight leaves evidence rather than just scrollback.
.PARAMETER Threshold
    Lockout threshold to measure against. Read from the domain policy when not supplied.
.EXAMPLE
    .\Watch-ADLockoutActivity.ps1
    Watch every account with bad-password activity, polling all DCs every 15 seconds.
.EXAMPLE
    .\Watch-ADLockoutActivity.ps1 -Identity jdoe
    Watch one account while they retry.
.EXAMPLE
    .\Watch-ADLockoutActivity.ps1 -Identity jdoe,asmith -IntervalSeconds 5 -LogPath .\watch.csv
    Watch two accounts closely and record every change.
.EXAMPLE
    .\Watch-ADLockoutActivity.ps1 -DurationMinutes 30
    Run for half an hour, then stop.
.NOTES
    Run on a DC or an admin workstation with RSAT. Requires permission to read user
    attributes on each domain controller. No event log access needed, so this works where
    the event-log tools cannot.

    Companion tools:
      Export-ADAuthSourceEvidence.ps1  Which DEVICE is sending the bad passwords.
      Get-LockoutCause.ps1             What to fix once the device is known.
      Test-ADAuditPolicy.ps1           Whether the event-log tools can see anything.

    REFERENCES
      badPwdCount - not replicated, resets on successful logon to that DC
        https://learn.microsoft.com/windows/win32/adschema/a-badpwdcount
      badPasswordTime
        https://learn.microsoft.com/windows/win32/adschema/a-badpasswordtime
      Get-ADUser -Server, -Properties
        https://learn.microsoft.com/powershell/module/activedirectory/get-aduser
      Account lockout threshold
        https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/account-lockout-threshold

    Verified against Microsoft Learn on 2026-08-20.
#>
[CmdletBinding()]
param(
    [string[]]$Identity,

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 15,

    [string[]]$DomainController,

    [ValidateRange(0, 1440)]
    [int]$DurationMinutes = 0,

    [string]$LogPath,

    [ValidateRange(0, 999)]
    [int]$Threshold = -1,

    [switch]$LoadFunctionsOnly
)

$ErrorActionPreference = 'Stop'

# A poll tighter than this against every DC in the domain is load without benefit - bad
# password attempts do not arrive faster than a few per second even under a spray.
$script:MinIntervalSeconds = 5

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level = 'INFO'
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Test-WatchInterval {
    <#
    .SYNOPSIS
        Enforces the minimum poll interval.
    .DESCRIPTION
        The floor is applied in code rather than documented as advice, because the failure
        mode - a one-second loop querying every DC in a large domain - lands on production
        domain controllers rather than on the person who typed it.
    #>
    param([Parameter(Mandatory)][int]$Seconds)

    if ($Seconds -lt $script:MinIntervalSeconds) {
        return [PSCustomObject]@{
            Allowed  = $false
            Adjusted = $script:MinIntervalSeconds
            Message  = "Interval $Seconds s is below the $($script:MinIntervalSeconds) s minimum and has been raised - polling every DC faster than this adds load without seeing more."
        }
    }
    return [PSCustomObject]@{ Allowed = $true; Adjusted = $Seconds; Message = '' }
}

function Get-CounterDelta {
    <#
    .SYNOPSIS
        Compares this poll's counters against the previous one.
    .DESCRIPTION
        The subtle part of the whole script, because badPwdCount does not behave like a
        monotonic counter:

          * It RESETS to a low value when the user successfully authenticates against that
            DC. Naive subtraction yields a negative "delta" that reads as the problem
            resolving itself, when it actually means the user just logged in successfully.
            Reported as a reset, with the new value as the delta since those attempts are
            genuinely new.

          * It is PER-DC and does not replicate, so state is keyed DC|Account. Keying on
            the account alone would let one DC's reading overwrite another's and silently
            lose activity.

        First sighting counts the whole value, because an account already at 8 when the
        watch starts is news, not a steady state.
    #>
    param(
        [hashtable]$Previous = @{},
        [object[]]$Current = @()
    )

    $changes  = New-Object System.Collections.Generic.List[object]
    $lockouts = New-Object System.Collections.Generic.List[object]
    $newState = @{}
    $total    = 0

    foreach ($row in @($Current)) {
        $key = "$($row.DC)|$($row.Account)"
        $now = [int]$row.BadPwdCount
        $newState[$key] = $now

        if ($row.LockedOut) {
            $lockouts.Add([PSCustomObject]@{
                Account = $row.Account
                DC      = $row.DC
                Count   = $now
                Time    = Get-Date
            })
        }

        $hadPrevious = $Previous.ContainsKey($key)
        $before      = if ($hadPrevious) { [int]$Previous[$key] } else { 0 }

        if (-not $hadPrevious) {
            if ($now -gt 0) {
                $changes.Add([PSCustomObject]@{
                    Account = $row.Account; DC = $row.DC; Delta = $now; NewValue = $now
                    WasReset = $false; FirstSight = $true
                    LockedOut = [bool]$row.LockedOut
                    BadPasswordTime = $row.BadPasswordTime
                    Note = 'first reading'
                    Time = Get-Date
                })
                $total += $now
            }
            continue
        }

        if ($now -gt $before) {
            $delta = $now - $before
            $changes.Add([PSCustomObject]@{
                Account = $row.Account; DC = $row.DC; Delta = $delta; NewValue = $now
                WasReset = $false; FirstSight = $false
                LockedOut = [bool]$row.LockedOut
                BadPasswordTime = $row.BadPasswordTime
                Note = ''
                Time = Get-Date
            })
            $total += $delta
        }
        elseif ($now -lt $before -and $now -gt 0) {
            # Counter fell but is not zero: it reset on a successful logon and has since
            # taken new bad attempts. Those attempts are real and new.
            $changes.Add([PSCustomObject]@{
                Account = $row.Account; DC = $row.DC; Delta = $now; NewValue = $now
                WasReset = $true; FirstSight = $false
                LockedOut = [bool]$row.LockedOut
                BadPasswordTime = $row.BadPasswordTime
                Note = 'counter reset - successful logon on this DC, then new failures'
                Time = Get-Date
            })
            $total += $now
        }
        # $now -lt $before and $now -eq 0: a clean reset with no new attempts. Nothing to
        # report - the user simply authenticated successfully.
    }

    # ToArray() rather than @($changes): in PowerShell 5.1, wrapping a
    # System.Collections.Generic.List[object] in @() inside a [PSCustomObject]@{} literal
    # throws "Argument types do not match". Materializing the array first avoids it.
    return [PSCustomObject]@{
        Changes    = $changes.ToArray()
        Lockouts   = $lockouts.ToArray()
        NewState   = $newState
        TotalDelta = $total
    }
}

function Get-WatchSeverity {
    <#
    .SYNOPSIS
        Rates how urgent one reading is.
    .DESCRIPTION
        Scaled against the lockout threshold rather than the raw count, because 8 of 10 is
        about to lock and 8 of 50 is not. A threshold of 0 means lockout is disabled, so
        nothing can be urgent - and guards the division.
    #>
    param(
        [Parameter(Mandatory)][int]$NewValue,
        [Parameter(Mandatory)][int]$Threshold,
        [bool]$LockedOut = $false
    )

    if ($LockedOut) { return 'Critical' }
    if ($Threshold -le 0) { return 'Info' }

    $ratio = $NewValue / $Threshold
    if ($ratio -ge 0.8) { return 'Critical' }
    if ($ratio -ge 0.4) { return 'Warning' }
    return 'Info'
}

function Format-WatchLine {
    <#
    .SYNOPSIS
        Renders one change as a single console line.
    .DESCRIPTION
        Built for glanceability. During a live incident the number that matters is how
        many attempts remain before the account locks, so the count is always shown
        against the threshold rather than on its own.
    #>
    param(
        [Parameter(Mandatory)][object]$Change,
        [int]$Threshold = 0
    )

    $stamp = (Get-Date).ToString('HH:mm:ss')
    $count = if ($Threshold -gt 0) { "$($Change.NewValue)/$Threshold" } else { "$($Change.NewValue)" }

    $line = "{0}  {1,-20} {2,-18} +{3,-3} ({4})" -f `
        $stamp, $Change.Account, $Change.DC, $Change.Delta, $count

    if ($Change.WasReset)   { $line += '  [counter reset - successful logon, then new failures]' }
    elseif ($Change.FirstSight) { $line += '  [first reading]' }
    if ($Change.LockedOut)  { $line += '  *** LOCKED OUT ***' }

    return $line
}

function Get-WatchTarget {
    <#
    .SYNOPSIS
        Reads the current counters for the accounts being watched, from one DC.
    .DESCRIPTION
        With -Identity, reads exactly those accounts. Without it, searches for accounts
        that are locked out or carrying a non-zero bad-password count, so a watch started
        before anyone reports a problem still finds the activity.

        Wrapped per DC by the caller so an unreachable DC costs only its own readings.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string[]]$Accounts
    )

    $props = @('badPwdCount', 'badPasswordTime', 'lockoutTime', 'LockedOut', 'SamAccountName')
    $out = New-Object System.Collections.Generic.List[object]

    if ($Accounts -and $Accounts.Count -gt 0) {
        foreach ($a in $Accounts) {
            try {
                $u = Get-ADUser -Identity $a -Server $ComputerName -Properties $props -ErrorAction Stop
                $out.Add([PSCustomObject]@{
                    DC              = $ComputerName
                    Account         = $u.SamAccountName
                    BadPwdCount     = [int]$u.badPwdCount
                    LockedOut       = [bool]$u.LockedOut
                    BadPasswordTime = if ($u.badPasswordTime -and $u.badPasswordTime -gt 0) { [datetime]::FromFileTime($u.badPasswordTime) } else { $null }
                })
            } catch {
                Write-Verbose "$ComputerName / ${a}: $($_.Exception.Message)"
            }
        }
        return $out
    }

    # No -Identity: find anyone currently showing activity. badPwdCount is not indexed, so
    # this is a filtered read rather than a targeted one - acceptable at a 15-second
    # cadence, and the reason -Identity is preferred when the account is known.
    try {
        $users = @(Get-ADUser -Filter 'badPwdCount -gt 0 -or lockoutTime -gt 0' `
                              -Server $ComputerName -Properties $props -ErrorAction Stop)
        foreach ($u in $users) {
            $out.Add([PSCustomObject]@{
                DC              = $ComputerName
                Account         = $u.SamAccountName
                BadPwdCount     = [int]$u.badPwdCount
                LockedOut       = [bool]$u.LockedOut
                BadPasswordTime = if ($u.badPasswordTime -and $u.badPasswordTime -gt 0) { [datetime]::FromFileTime($u.badPasswordTime) } else { $null }
            })
        }
    } catch {
        throw
    }

    return $out
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status "ActiveDirectory module unavailable: $($_.Exception.Message)" 'FAIL'
    exit 1
}

# --- Interval floor ----------------------------------------------------------
$intervalCheck = Test-WatchInterval -Seconds $IntervalSeconds
if (-not $intervalCheck.Allowed) { Write-Status $intervalCheck.Message 'WARN' }
$interval = $intervalCheck.Adjusted

# --- Domain controllers ------------------------------------------------------
$dcs = @()
if ($DomainController -and $DomainController.Count -gt 0) {
    $dcs = $DomainController
} else {
    try {
        $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName | Sort-Object)
    } catch {
        Write-Status "Could not enumerate domain controllers: $($_.Exception.Message)" 'FAIL'
        Write-Status "Supply -DomainController explicitly to continue." 'INFO'
        exit 1
    }
}
if ($dcs.Count -eq 0) { Write-Status 'No domain controllers to poll.' 'FAIL'; exit 1 }

# --- Lockout threshold -------------------------------------------------------
if ($Threshold -lt 0) {
    try {
        $Threshold = [int](Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).LockoutThreshold
    } catch {
        $Threshold = 0
        Write-Status "Could not read the domain lockout threshold - counts will be shown without it." 'WARN'
    }
}

Write-Host ''
Write-Status 'AD lockout activity watch' 'INFO'
Write-Status "DCs      : $($dcs.Count) ($($dcs -join ', '))" 'INFO'
Write-Status "Accounts : $(if ($Identity) { $Identity -join ', ' } else { 'any account with bad-password activity' })" 'INFO'
Write-Status "Interval : every $interval second(s)" 'INFO'
if ($Threshold -gt 0) {
    Write-Status "Threshold: $Threshold bad attempts before lockout" 'INFO'
} else {
    Write-Status "Threshold: lockout is disabled in this domain (threshold 0) - accounts will not lock" 'WARN'
}
if ($DurationMinutes -gt 0) { Write-Status "Duration : stopping after $DurationMinutes minute(s)" 'INFO' }
if ($LogPath) { Write-Status "Log      : $LogPath" 'INFO' }

Write-Host ''
Write-Host 'Watching. Press Ctrl+C to stop.' -ForegroundColor White
Write-Host ('-' * 96) -ForegroundColor DarkGray
Write-Host ("{0,-9} {1,-20} {2,-18} {3,-4} {4}" -f 'TIME', 'ACCOUNT', 'DC', 'NEW', 'COUNT') -ForegroundColor DarkGray
Write-Host ('-' * 96) -ForegroundColor DarkGray

$state       = @{}
$pollCount   = 0
$totalSeen   = 0
$deadUntil   = @{}   # DCs that failed, and when to retry them
$startedAt   = Get-Date
$logRows     = New-Object System.Collections.Generic.List[object]

try {
    while ($true) {

        if ($DurationMinutes -gt 0 -and ((Get-Date) - $startedAt).TotalMinutes -ge $DurationMinutes) {
            Write-Host ''
            Write-Status "Duration reached ($DurationMinutes minute(s))." 'INFO'
            break
        }

        $pollCount++
        $current = New-Object System.Collections.Generic.List[object]

        foreach ($dc in $dcs) {
            # A DC that just failed is skipped for a few polls rather than retried every
            # cycle - otherwise one dead DC fills the screen with the same error.
            if ($deadUntil.ContainsKey($dc) -and (Get-Date) -lt $deadUntil[$dc]) { continue }

            try {
                foreach ($r in @(Get-WatchTarget -ComputerName $dc -Accounts $Identity)) {
                    $current.Add($r)
                }
                if ($deadUntil.ContainsKey($dc)) {
                    $deadUntil.Remove($dc)
                    Write-Status "$dc is responding again." 'PASS'
                }
            } catch {
                if (-not $deadUntil.ContainsKey($dc)) {
                    Write-Status "$dc unreachable: $($_.Exception.Message)" 'WARN'
                }
                $deadUntil[$dc] = (Get-Date).AddSeconds([math]::Max(60, $interval * 4))
            }
        }

        $delta = Get-CounterDelta -Previous $state -Current $current
        $state = $delta.NewState

        foreach ($c in $delta.Changes) {
            # The first poll establishes a baseline. Printing every pre-existing counter
            # as if it just happened would bury the real-time activity that follows.
            if ($pollCount -eq 1) { continue }

            $totalSeen += $c.Delta
            $severity = Get-WatchSeverity -NewValue $c.NewValue -Threshold $Threshold -LockedOut $c.LockedOut
            $color = @{ Critical='Red'; Warning='Yellow'; Info='Gray' }[$severity]
            Write-Host (Format-WatchLine -Change $c -Threshold $Threshold) -ForegroundColor $color

            if ($LogPath) {
                $logRows.Add([PSCustomObject]@{
                    Time            = $c.Time.ToString('yyyy-MM-dd HH:mm:ss')
                    Account         = $c.Account
                    DC              = $c.DC
                    Delta           = $c.Delta
                    BadPwdCount     = $c.NewValue
                    Threshold       = $Threshold
                    Severity        = $severity
                    LockedOut       = $c.LockedOut
                    WasReset        = $c.WasReset
                    BadPasswordTime = $c.BadPasswordTime
                    Note            = $c.Note
                })
            }
        }

        if ($pollCount -eq 1) {
            $baseline = @($delta.Changes).Count
            if ($baseline -gt 0) {
                Write-Status "Baseline: $baseline account/DC counter(s) already non-zero. Reporting changes from here." 'INFO'
            } else {
                Write-Status 'Baseline: no bad-password activity anywhere. Watching for new attempts.' 'PASS'
            }
            Write-Host ''
        }

        Start-Sleep -Seconds $interval
    }
} finally {
    # Runs on Ctrl+C too, so an interrupted watch still reports and still writes its log.
    Write-Host ''
    Write-Host ('-' * 96) -ForegroundColor DarkGray
    Write-Status "Stopped after $pollCount poll(s) over $([math]::Round(((Get-Date) - $startedAt).TotalMinutes, 1)) minute(s)." 'INFO'
    Write-Status "$totalSeen bad-password attempt(s) observed." 'INFO'

    if ($LogPath -and $logRows.Count -gt 0) {
        try {
            $dir = Split-Path -Parent $LogPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            @($logRows) | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
            Write-Status "$($logRows.Count) change(s) written to $LogPath" 'PASS'
        } catch {
            Write-Status "Could not write log: $($_.Exception.Message)" 'WARN'
        }
    }

    if ($totalSeen -gt 0) {
        Write-Host ''
        Write-Status 'Next step: identify the device behind these attempts.' 'INFO'
        Write-Host '       .\Export-ADAuthSourceEvidence.ps1 -DaysBack 1' -ForegroundColor Gray
        Write-Host '       .\Get-LockoutCause.ps1 -SourcesCsv .\Reports\AuthSources_<timestamp>.csv' -ForegroundColor Gray
    }
    Write-Host ''
}
