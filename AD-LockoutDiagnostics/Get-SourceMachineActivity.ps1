# 3.0 so this runs on Server 2012 (PS 3.0) / 2012 R2 (PS 4.0) as shipped; Tests\PSVersionFloor.Tests.ps1 guards it.
#Requires -Version 3.0

<#
.SYNOPSIS
    Shows when a source machine was on, asleep, locked and unlocked, and lines that up
    against the failed sign-ins that came from it.

.DESCRIPTION
    The rest of the toolkit reads domain controllers, which record THAT a machine sent a bad
    password. They cannot say what the machine was doing at the time. This reads the
    machine's own logs - startup, shutdown, sleep, wake, lock and unlock - and answers the
    questions the DC evidence cannot:

      - Do the failures start right after it wakes, boots or unlocks?
        Then something on it replays a saved password when it resumes - typically a mapped
        drive reconnecting or a saved credential. That confirms the culprit.

      - Do the failures continue while it was shut down or asleep?
        Then it is probably NOT the source, even though the reports name it: something else
        is using its address or name (a second device, a VM, a DHCP address that moved).

      - Do the failures happen while it was locked?
        Then a background process is sending them, not the user typing.

    Read-only. Each machine is queried in its own try/catch; an unreachable machine is
    reported as such and the run continues.

    WHAT IT CANNOT SEE
      Lock and unlock (4800/4801) are only written when "Audit Other Logon/Logoff Events"
      is set to Success on that machine. When none are found the report says so rather than
      treating the silence as "never locked". Startup, shutdown, sleep and wake are always
      written to the System log.

      Modern Standby laptops (events 506/507) can keep the network connected while they look
      asleep, so failures during Modern Standby are reported separately and are NOT taken as
      evidence that the machine was off.

.PARAMETER ComputerName
    One or more computers to read. Use this to run it by hand against a machine you choose.

.PARAMETER SourcesCsv
    An AuthSources_*.csv from Export-ADAuthSourceEvidence.ps1. The top -Top sources that
    resolved to a domain-joined workstation are read. Servers and domain controllers are
    skipped: they have their own owners and their activity is not one user's.

.PARAMETER AuthEventsCsv
    An AuthEvents_*.csv from Export-ADAuthSourceEvidence.ps1. Supplies the failure times to
    line up against. Without it the report is a timeline only.

.PARAMETER Top
    How many workstations to read from -SourcesCsv. Default 3.

.PARAMETER DaysBack
    How far back to read each machine's logs. Default 7.

.PARAMETER WindowMinutes
    How soon after a wake, startup or unlock a failure counts as "right after". Default 5.

.PARAMETER OutputPath
    Folder for the HTML and CSV output. Defaults to an "Account Lockout Diagnostics" folder
    beside this script, the same place the investigation writes.

.PARAMETER LoadFunctionsOnly
    Internal: dot-source the functions without running, for tests.

.EXAMPLE
    .\Get-SourceMachineActivity.ps1 -ComputerName CON-LT-0142
    Timeline of one machine for the last 7 days.

.EXAMPLE
    .\Get-SourceMachineActivity.ps1 -ComputerName CON-LT-0142 -AuthEventsCsv .\AuthEvents_2026-10-14_093130.csv
    The same, lined up against the failures that machine sent.

.EXAMPLE
    .\Get-SourceMachineActivity.ps1 -SourcesCsv .\AuthSources_2026-10-14_093130.csv -AuthEventsCsv .\AuthEvents_2026-10-14_093130.csv
    What Invoke-ADLockoutInvestigation.ps1 runs as step 8: the top 3 workstation sources.

.NOTES
    Requires remote Event Log access to each machine (the "Remote Event Log Management"
    firewall rule). Reading the Security log for lock/unlock needs administrator rights on
    that machine; the System log usually does not.

    REFERENCES
      4800/4801/4802/4803 and the subcategory that writes them (Audit Other Logon/Logoff):
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4800
        https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-logonlogoff-events
      Kernel-General 12/13, User32 1074, Kernel-Power 41, EventLog 6008:
        https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
      Kernel-Power 42 (entering sleep), 107 (resumed from sleep), 506/507 (Modern Standby):
        https://learn.microsoft.com/defender-endpoint/troubleshoot-mdav-scan-issues
      Modern Standby keeps networking available while the screen is off:
        https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [string]$SourcesCsv,

    [string]$AuthEventsCsv,

    [ValidateRange(1, 20)]
    [int]$Top = 3,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [ValidateRange(1, 60)]
    [int]$WindowMinutes = 5,

    [string]$OutputPath,

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

# Provider + event ID -> what happened. Keyed on BOTH, because the same ID means different
# things from different providers (System log event 12 is not always Kernel-General).
# Sources are listed in the REFERENCES block above.
$script:ActivityMap = @(
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-General'; Id=12;   Kind='Startup';           Label='Windows started' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-General'; Id=13;   Kind='Shutdown';          Label='Windows shut down' }
    @{ Log='System';   Provider='User32';                           Id=1074; Kind='ShutdownRequest';   Label='Restart or shutdown requested' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';   Id=41;   Kind='UnexpectedRestart'; Label='Restarted after a crash or power loss' }
    @{ Log='System';   Provider='EventLog';                         Id=6008; Kind='UnexpectedRestart'; Label='Previous shutdown was unexpected' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';   Id=42;   Kind='Sleep';             Label='Went to sleep' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';   Id=107;  Kind='Wake';              Label='Woke from sleep' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';   Id=506;  Kind='StandbyEnter';      Label='Entered Modern Standby (network can stay on)' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';   Id=507;  Kind='StandbyExit';       Label='Left Modern Standby' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4800; Kind='Lock';           Label='Locked' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4801; Kind='Unlock';         Label='Unlocked' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4802; Kind='ScreenSaverOn';  Label='Screen saver started' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4803; Kind='ScreenSaverOff'; Label='Screen saver dismissed' }
)

# The points after which a saved password is typically replayed.
$script:ResumeKinds = @('Wake', 'StandbyExit', 'Startup', 'UnexpectedRestart', 'Unlock')

function ConvertTo-ShortName {
    # Event logs spell one machine several ways: CON-LT-0142, \\CON-LT-0142,
    # con-lt-0142.contoso.com, CON-LT-0142$. Compare on the bare upper-case short name.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim().TrimStart('\') -replace '\$$', ''
    if ($n -match '^\d{1,3}(\.\d{1,3}){3}$') { return $n }
    return ($n -split '\.')[0].ToUpperInvariant()
}

function ConvertTo-EventTime {
    # CSV round-trips write DateTime in the current culture, so parse that first; a file
    # made on a machine with another culture falls back to the invariant form.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $out = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::None, [ref]$out)) { return $out }
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$out)) { return $out }
    return $null
}

function ConvertFrom-ActivityEvent {
    # Classifies one event. Pure, so the mapping is testable without a remote machine.
    # Returns $null for an event this tool does not track.
    param(
        [string]$LogName,
        [string]$ProviderName,
        [int]$EventId,
        [datetime]$Time,
        [string]$Message,
        [string]$UserName
    )

    $rule = $script:ActivityMap | Where-Object {
        $_.Id -eq $EventId -and $_.Log -eq $LogName -and $_.Provider -eq $ProviderName
    } | Select-Object -First 1
    if (-not $rule) { return $null }

    # First line of the rendered message is enough context for a timeline row (1074 names
    # the process and user; 42 names the sleep reason) without dumping the whole event.
    $detail = ''
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        $detail = (($Message -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
        if ($detail.Length -gt 220) { $detail = $detail.Substring(0, 217) + '...' }
    }
    if ($UserName) { $detail = if ($detail) { "$UserName - $detail" } else { $UserName } }

    [PSCustomObject]@{
        Time    = $Time
        Kind    = $rule.Kind
        Label   = $rule.Label
        EventId = $EventId
        Detail  = $detail
    }
}

function Get-ActivityInterval {
    # Turns the ordered events into periods: Off, Asleep, Standby, Locked. Open-ended
    # periods (a sleep with no wake in the data) are left out rather than guessed at.
    param([object[]]$Events)

    $intervals = New-Object System.Collections.ArrayList
    $resume    = New-Object System.Collections.ArrayList
    $open = @{ Off = $null; Asleep = $null; Standby = $null; Locked = $null }

    foreach ($e in @($Events | Where-Object { $_ } | Sort-Object Time)) {
        $t = [datetime]$e.Time
        switch ($e.Kind) {
            'Shutdown' {
                if ($open.Locked) { $null = $intervals.Add([PSCustomObject]@{ Kind='Locked'; Start=$open.Locked; End=$t }); $open.Locked = $null }
                $open.Off = $t
            }
            { $_ -in @('Startup', 'UnexpectedRestart') } {
                if ($open.Off)    { $null = $intervals.Add([PSCustomObject]@{ Kind='Off';    Start=$open.Off;    End=$t }); $open.Off = $null }
                # Hibernate ends in a boot rather than a wake.
                if ($open.Asleep) { $null = $intervals.Add([PSCustomObject]@{ Kind='Asleep'; Start=$open.Asleep; End=$t }); $open.Asleep = $null }
                $open.Standby = $null; $open.Locked = $null
            }
            'Sleep'        { $open.Asleep = $t }
            'Wake'         { if ($open.Asleep)  { $null = $intervals.Add([PSCustomObject]@{ Kind='Asleep';  Start=$open.Asleep;  End=$t }); $open.Asleep = $null } }
            'StandbyEnter' { $open.Standby = $t }
            'StandbyExit'  { if ($open.Standby) { $null = $intervals.Add([PSCustomObject]@{ Kind='Standby'; Start=$open.Standby; End=$t }); $open.Standby = $null } }
            'Lock'         { $open.Locked = $t }
            'Unlock'       { if ($open.Locked)  { $null = $intervals.Add([PSCustomObject]@{ Kind='Locked';  Start=$open.Locked;  End=$t }); $open.Locked = $null } }
        }
        if ($e.Kind -in $script:ResumeKinds) {
            $null = $resume.Add([PSCustomObject]@{ Kind = $e.Kind; Time = $t })
        }
    }

    [PSCustomObject]@{ Intervals = @($intervals); ResumePoints = @($resume) }
}

function Get-FailureState {
    # What the machine was doing at one failure time. Order matters: being shut down or
    # asleep outranks everything, then "right after resuming", then the softer states.
    param(
        [datetime]$Time,
        [object[]]$Intervals,
        [object[]]$ResumePoints,
        [Nullable[datetime]]$CoverageStart,
        [int]$WindowMinutes = 5
    )

    if ($CoverageStart -and $Time -lt $CoverageStart) { return [PSCustomObject]@{ State='BeforeCoverage'; ResumeKind='' } }

    foreach ($k in @('Off', 'Asleep')) {
        foreach ($i in @($Intervals | Where-Object { $_.Kind -eq $k })) {
            if ($Time -ge $i.Start -and $Time -lt $i.End) { return [PSCustomObject]@{ State = "While$k"; ResumeKind = '' } }
        }
    }

    # When several resume points fall inside the window - a wake, then the user unlocking
    # seconds later - credit the power transition. That is when Windows reconnects mapped
    # drives and services retry; the unlock is just the user arriving.
    $window = [timespan]::FromMinutes($WindowMinutes)
    $priority = @{ Startup=0; UnexpectedRestart=0; Wake=1; StandbyExit=1; Unlock=2 }
    $recent = @($ResumePoints | Where-Object { $_.Time -le $Time -and ($Time - $_.Time) -le $window } |
                Sort-Object @{ Expression = { $priority[$_.Kind] } }, @{ Expression = 'Time'; Descending = $true } |
                Select-Object -First 1)
    if ($recent.Count -gt 0) { return [PSCustomObject]@{ State='AfterResume'; ResumeKind=$recent[0].Kind } }

    foreach ($pair in @(@{ K='Standby'; S='InStandby' }, @{ K='Locked'; S='WhileLocked' })) {
        foreach ($i in @($Intervals | Where-Object { $_.Kind -eq $pair.K })) {
            if ($Time -ge $i.Start -and $Time -lt $i.End) { return [PSCustomObject]@{ State=$pair.S; ResumeKind='' } }
        }
    }
    return [PSCustomObject]@{ State='Awake'; ResumeKind='' }
}

function Measure-FailureState {
    # Counts the failure states for one machine. Pure.
    param(
        [object[]]$FailureTimes,
        [object[]]$Events,
        [Nullable[datetime]]$CoverageStart,
        [int]$WindowMinutes = 5
    )

    $periods = Get-ActivityInterval -Events $Events
    $counts = [ordered]@{ Total=0; BeforeCoverage=0; WhileOff=0; WhileAsleep=0; AfterResume=0; InStandby=0; WhileLocked=0; Awake=0 }
    $resumeKinds = @{}
    foreach ($ft in @($FailureTimes | Where-Object { $_ })) {
        $s = Get-FailureState -Time ([datetime]$ft) -Intervals $periods.Intervals -ResumePoints $periods.ResumePoints `
                              -CoverageStart $CoverageStart -WindowMinutes $WindowMinutes
        $counts.Total++
        $counts[$s.State]++
        if ($s.ResumeKind) { $resumeKinds[$s.ResumeKind] = 1 + [int]$resumeKinds[$s.ResumeKind] }
    }
    $counts['ResumeKinds'] = $resumeKinds
    return [PSCustomObject]$counts
}

function Format-ResumeKinds {
    # "waking (5), starting (2)" - which resume points the failures followed.
    param([hashtable]$Kinds)
    $words = @{ Wake='waking from sleep'; StandbyExit='leaving Modern Standby'; Startup='starting up'; UnexpectedRestart='restarting'; Unlock='being unlocked' }
    $parts = foreach ($k in ($Kinds.Keys | Sort-Object { -1 * $Kinds[$_] })) { "$($words[$k]) ($($Kinds[$k]))" }
    return ($parts -join ', ')
}

function Get-ActivityVerdict {
    # One plain-English reading per machine. Pure.
    param(
        [string]$Computer,
        [object]$Counts,
        [bool]$HasFailureData,
        [bool]$Reachable = $true,
        [string]$UnreachableReason = '',
        [int]$WindowMinutes = 5
    )

    if (-not $Reachable) {
        return [PSCustomObject]@{ Class='unknown'; Key='Unreachable'
            Line = "$Computer could not be reached."
            Next = "$UnreachableReason If failures are still arriving while it cannot be reached, it is probably not the source." }
    }
    if (-not $HasFailureData) {
        return [PSCustomObject]@{ Class='unknown'; Key='TimelineOnly'
            Line = "Timeline of $Computer."
            Next = 'No failure times were supplied to compare against. Pass -AuthEventsCsv to line them up.' }
    }

    $covered = [int]$Counts.Total - [int]$Counts.BeforeCoverage
    if ($covered -le 0) {
        return [PSCustomObject]@{ Class='unknown'; Key='NoOverlap'
            Line = "$Computer's logs do not reach back to the failures."
            Next = 'Its System log has already overwritten that period, so its activity at the time cannot be checked.' }
    }

    $offAsleep = [int]$Counts.WhileOff + [int]$Counts.WhileAsleep
    if ($offAsleep -ge [math]::Max(3, [math]::Ceiling($covered * 0.5))) {
        return [PSCustomObject]@{ Class='warn'; Key='WhileOff'
            Line = "$Computer was shut down or asleep for $offAsleep of $covered failures."
            Next = 'A machine that is off cannot send passwords, so it is probably NOT the source - something else is using its address or name: a second device, a virtual machine, or a DHCP address that moved. Check the Which Device tab and the DHCP lease times before clearing anything on it.' }
    }

    $after = [int]$Counts.AfterResume
    if ($after -ge [math]::Max(2, [math]::Ceiling($covered * 0.3))) {
        return [PSCustomObject]@{ Class='bad'; Key='AfterResume'
            Line = "$after of $covered failures came within $WindowMinutes minutes of $Computer $(Format-ResumeKinds -Kinds $Counts.ResumeKinds)."
            Next = 'Something on it replays a saved password whenever it resumes - typically a mapped drive reconnecting or a saved credential. On that machine check net use and cmdkey /list, and have the user sign out and back in after clearing them.' }
    }

    if ([int]$Counts.WhileLocked -ge [math]::Ceiling($covered * 0.5)) {
        return [PSCustomObject]@{ Class='bad'; Key='WhileLocked'
            Line = "$($Counts.WhileLocked) of $covered failures happened while $Computer was locked."
            Next = 'Nobody was typing, so a background process sent them: a service, scheduled task, mapped drive, or an app signed in as the user.' }
    }

    $standbyNote = if ([int]$Counts.InStandby -gt 0) { " $($Counts.InStandby) were during Modern Standby, when the network can stay on." } else { '' }
    return [PSCustomObject]@{ Class='ok'; Key='Awake'
        Line = "$Computer was on and awake for the failures."
        Next = "No sleep, wake or lock pattern stands out.$standbyNote The other tabs remain the best guide to the cause." }
}

function Select-TimelineTarget {
    # The machines worth reading: top workstations by failure count. Servers and DCs are
    # left out - their activity is not one user's, and they have their own owners.
    param([object[]]$Sources, [int]$Top = 3)

    $seen = @{}
    $out = foreach ($s in @($Sources | Where-Object { $_.DeviceClass -eq 'DomainJoinedWorkstation' -and $_.ResolvedName } |
                             Sort-Object { [int]$_.FailureCount } -Descending)) {
        $key = ConvertTo-ShortName -Name $s.ResolvedName
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [PSCustomObject]@{ Computer = $s.ResolvedName; SourceIp = $s.SourceIp; Accounts = $s.Accounts; FailureCount = [int]$s.FailureCount }
    }
    return @($out | Select-Object -First $Top)
}

function Get-FailureTimesForComputer {
    # Failure times from an AuthEvents CSV that belong to one machine, matched on its
    # resolved name, the name the event carried, or its address.
    param([object[]]$AuthEvents, [string]$Computer, [string]$SourceIp)

    $short = ConvertTo-ShortName -Name $Computer
    $times = foreach ($e in @($AuthEvents)) {
        if ("$($e.IsFailure)" -notmatch '^(True|1)$') { continue }
        $match = ((ConvertTo-ShortName -Name $e.ResolvedName) -eq $short) -or
                 ((ConvertTo-ShortName -Name $e.SourceHost) -eq $short) -or
                 ($SourceIp -and $e.SourceIp -eq $SourceIp)
        if ($match) { ConvertTo-EventTime -Value $e.Time }
    }
    return @($times | Where-Object { $_ } | Sort-Object)
}

function Get-RemoteErrorText {
    # Turns the usual remote event log errors into what is actually wrong.
    param([string]$Message)
    if ($Message -match 'RPC server is unavailable|0x800706BA|network path was not found|No such host|cannot find the computer') {
        return 'The machine did not answer (switched off, off the network, or the Remote Event Log Management firewall rule is closed).'
    }
    if ($Message -match 'Access is denied|0x80070005|Unauthorized') {
        return 'Access denied - reading this log needs administrator rights on that machine.'
    }
    return $Message
}

function Get-MachineActivity {
    # Reads one machine. The only function here that touches the network.
    param([Parameter(Mandatory)][string]$Computer, [Parameter(Mandatory)][datetime]$StartTime)

    $result = [PSCustomObject]@{
        Computer = $Computer; Reachable = $true; UnreachableReason = ''
        Events = @(); CoverageStart = $null; Notes = @()
    }

    $systemIds = @($script:ActivityMap | Where-Object { $_.Log -eq 'System' } | ForEach-Object { $_.Id } | Select-Object -Unique)
    $rows = New-Object System.Collections.ArrayList

    try {
        $sys = @(Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='System'; Id=$systemIds; StartTime=$StartTime } -ErrorAction Stop)
        foreach ($ev in $sys) {
            $r = ConvertFrom-ActivityEvent -LogName 'System' -ProviderName $ev.ProviderName -EventId $ev.Id -Time $ev.TimeCreated -Message $ev.Message
            if ($r) { $null = $rows.Add($r) }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $why = Get-RemoteErrorText -Message $_.Exception.Message
            if ($why -match 'did not answer') {
                $result.Reachable = $false; $result.UnreachableReason = $why
                return $result
            }
            $result.Notes += "System log could not be read: $why"
        }
    }

    # How far back the System log really reaches - the same coverage question the DC
    # reports ask, because an empty period may just be an overwritten one.
    try {
        $oldest = Get-WinEvent -ComputerName $Computer -LogName System -Oldest -MaxEvents 1 -ErrorAction Stop
        if ($oldest) { $result.CoverageStart = $oldest.TimeCreated }
    } catch { }

    try {
        $sec = @(Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; Id=@(4800,4801,4802,4803); StartTime=$StartTime } -ErrorAction Stop)
        foreach ($ev in $sec) {
            $user = ''
            try {
                $x = [xml]$ev.ToXml()
                $d = @{}
                foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
                # 4800/4801 fields per Microsoft Learn: TargetDomainName, TargetUserName.
                if ($d['TargetUserName']) { $user = "$($d['TargetDomainName'])\$($d['TargetUserName'])" }
            } catch { }
            $r = ConvertFrom-ActivityEvent -LogName 'Security' -ProviderName $ev.ProviderName -EventId $ev.Id -Time $ev.TimeCreated -UserName $user
            if ($r) { $null = $rows.Add($r) }
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            $result.Notes += 'No lock or unlock events were found. "Audit Other Logon/Logoff Events" is probably not enabled on this machine, so lock and unlock could not be checked.'
        } else {
            $result.Notes += "Lock and unlock were not read: $(Get-RemoteErrorText -Message $_.Exception.Message)"
        }
    }

    $result.Events = @($rows | Sort-Object Time)
    return $result
}

function New-TimelineRow {
    # Merges machine events and failures into one list, collapsing each run of failures
    # between two machine events into a single row - 80 identical failure lines bury the
    # wake event that explains them.
    param(
        [object[]]$Events,
        [object[]]$FailureTimes,
        [object[]]$Intervals,
        [object[]]$ResumePoints,
        [Nullable[datetime]]$CoverageStart,
        [int]$WindowMinutes = 5
    )

    $stateWords = @{ BeforeCoverage='before this log starts'; WhileOff='while it was shut down'; WhileAsleep='while it was asleep'
                     AfterResume='right after it resumed'; InStandby='during Modern Standby'; WhileLocked='while it was locked'; Awake='while it was on' }

    $merged = @()
    foreach ($e in @($Events)) { $merged += [PSCustomObject]@{ Time=[datetime]$e.Time; IsFailure=$false; Item=$e } }
    foreach ($f in @($FailureTimes)) {
        $s = Get-FailureState -Time ([datetime]$f) -Intervals $Intervals -ResumePoints $ResumePoints -CoverageStart $CoverageStart -WindowMinutes $WindowMinutes
        $merged += [PSCustomObject]@{ Time=[datetime]$f; IsFailure=$true; Item=$s }
    }

    $rows = New-Object System.Collections.ArrayList
    $run = $null
    foreach ($m in @($merged | Sort-Object Time)) {
        if ($m.IsFailure) {
            if ($run -and $run.State -eq $m.Item.State) {
                $run.Count++; $run.Last = $m.Time
            } else {
                if ($run) { $null = $rows.Add($run) }
                $run = [PSCustomObject]@{ Time=$m.Time; Last=$m.Time; IsFailure=$true; Count=1; State=$m.Item.State; Label=''; Detail='' }
            }
        } else {
            if ($run) { $null = $rows.Add($run); $run = $null }
            $null = $rows.Add([PSCustomObject]@{ Time=$m.Time; Last=$m.Time; IsFailure=$false; Count=0; State=$m.Item.Kind; Label=$m.Item.Label; Detail=$m.Item.Detail })
        }
    }
    if ($run) { $null = $rows.Add($run) }

    foreach ($r in $rows) {
        if ($r.IsFailure) {
            $span = if ($r.Count -gt 1) { " ($($r.Time.ToString('HH:mm'))-$($r.Last.ToString('HH:mm')))" } else { '' }
            $r.Label = "$($r.Count) failed sign-in$(if ($r.Count -ne 1) { 's' }) $($stateWords[$r.State])$span"
        }
    }
    return @($rows)
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Import-ReferenceDataFile {
    # Import-PowerShellDataFile is PowerShell 5.0+. On 3.0/4.0 (Server 2012 / 2012 R2) it
    # is missing; Import-LocalizedData reads the same file the same way (restricted
    # language, no code executed) and exists on every version.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/import-localizeddata
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (Get-Command -Name Import-PowerShellDataFile -ErrorAction SilentlyContinue) {
        return Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
    }
    $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    Import-LocalizedData -BaseDirectory (Split-Path -Parent $full) -FileName (Split-Path -Leaf $full) -ErrorAction Stop
}

function Get-ReportCss {
    # The shared stylesheet, so this page matches the toolkit and styles correctly inside
    # the combined report. A minimal fallback keeps it readable standalone.
    $p = Join-Path $PSScriptRoot 'LockoutReference.psd1'
    if (Test-Path -LiteralPath $p) {
        try { $ref = Import-ReferenceDataFile -Path $p -ErrorAction Stop; if ($ref.ReportCss) { return $ref.ReportCss } } catch { }
    }
    return @'
  body { background:#15181c; color:#e8eaed; font-family:'Segoe UI',system-ui,sans-serif; margin:0 auto; padding:32px; max-width:1100px; line-height:1.55; }
  .verdict { border-left:5px solid #6d7885; padding:4px 0 4px 20px; margin-bottom:26px; }
  .verdict.bad { border-left-color:#e2686a; } .verdict.warn { border-left-color:#e0a458; } .verdict.ok { border-left-color:#5fc98a; }
  .card { background:#1d2126; border:1px solid #333a44; border-radius:8px; padding:18px; margin-bottom:14px; }
  table { width:100%; border-collapse:collapse; font-size:13px; } th,td { text-align:left; padding:6px 10px; border-bottom:1px solid #333a44; }
'@
}

function New-SourceActivityHtml {
    # Renders every machine read. Pure: takes the collected results.
    param(
        [object[]]$Machines,
        [int]$DaysBack,
        [int]$WindowMinutes = 5,
        [string]$GeneratedOn
    )

    $ms = @($Machines)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine('<title>Device Timeline</title>')
    $null = $sb.AppendLine("<style>$(Get-ReportCss)</style></head><body>")
    $null = $sb.AppendLine('<div class="top"><h1>Device Timeline</h1><div class="facts">')
    $null = $sb.AppendLine("<span>Last <b>$DaysBack days</b></span><span><b>$(ConvertTo-HtmlSafe $GeneratedOn)</b></span></div></div>")

    if ($ms.Count -eq 0) {
        $null = $sb.AppendLine('<div class="verdict unknown"><div class="label">What this means</div><p class="line">No source machines to check.</p>')
        $null = $sb.AppendLine('<p class="next">None of the sources resolved to a domain-joined workstation, so there was no machine whose own logs could be read.</p></div>')
        $null = $sb.AppendLine('</body></html>')
        return $sb.ToString()
    }

    # The headline is the most telling machine: a replay on resume confirms a culprit, and
    # "off while failing" overturns one - both outrank a quiet result.
    $rank = @{ AfterResume=0; WhileOff=1; WhileLocked=2; Awake=3; NoOverlap=4; TimelineOnly=5; Unreachable=6 }
    $lead = @($ms | Sort-Object { $rank[$_.Verdict.Key] }, { -1 * [int]$_.Counts.Total })[0]
    $null = $sb.AppendLine("<div class=`"verdict $($lead.Verdict.Class)`"><div class=`"label`">What this means</div>")
    $null = $sb.AppendLine("<p class=`"line`">$(ConvertTo-HtmlSafe $lead.Verdict.Line)</p>")
    $null = $sb.AppendLine("<p class=`"next`">$(ConvertTo-HtmlSafe $lead.Verdict.Next)</p></div>")

    foreach ($m in $ms) {
        $null = $sb.AppendLine("<div class=`"card $(if ($m.Verdict.Class -eq 'bad') { 'bad' } elseif ($m.Verdict.Class -eq 'ok') { 'ok' })`">")
        $null = $sb.AppendLine("<div class=`"card-head`"><span class=`"card-name`">$(ConvertTo-HtmlSafe $m.Computer)</span>")
        $tag = switch ($m.Verdict.Key) {
            'AfterResume' { '<span class="tag bad">fails on resume</span>' }
            'WhileOff'    { '<span class="tag warn">failing while off</span>' }
            'WhileLocked' { '<span class="tag bad">fails while locked</span>' }
            'Unreachable' { '<span class="tag warn">not reachable</span>' }
            default       { '' }
        }
        $null = $sb.AppendLine("$tag</div>")
        $null = $sb.AppendLine("<p><b>$(ConvertTo-HtmlSafe $m.Verdict.Line)</b> $(ConvertTo-HtmlSafe $m.Verdict.Next)</p>")

        if ($m.Reachable -and $m.HasFailureData) {
            $c = $m.Counts
            $null = $sb.AppendLine('<div class="stats">')
            foreach ($pair in @(
                @{ N=$c.Total; K='Failures'; C='' }
                @{ N=$c.AfterResume; K="Within $WindowMinutes min of resuming"; C=$(if ($c.AfterResume) { 'bad' } else { '' }) }
                @{ N=([int]$c.WhileOff + [int]$c.WhileAsleep); K='While off or asleep'; C='' }
                @{ N=$c.WhileLocked; K='While locked'; C='' }
            )) {
                $null = $sb.AppendLine("<div class=`"stat`"><div class=`"n $($pair.C)`">$($pair.N)</div><div class=`"k`">$(ConvertTo-HtmlSafe $pair.K)</div></div>")
            }
            $null = $sb.AppendLine('</div>')
        }

        foreach ($n in @($m.Notes)) { $null = $sb.AppendLine("<p class=`"note`">$(ConvertTo-HtmlSafe $n)</p>") }
        if ($m.CoverageStart) {
            $null = $sb.AppendLine("<p class=`"card-meta`">This machine's System log reaches back to $(ConvertTo-HtmlSafe ([datetime]$m.CoverageStart).ToString('yyyy-MM-dd HH:mm')).</p>")
        }

        $rows = @($m.Timeline)
        if ($rows.Count -gt 0) {
            $null = $sb.AppendLine("<details$(if ($m -eq $lead) { ' open' })><summary>Timeline ($($rows.Count))</summary><div class=`"tablewrap`"><table>")
            # Fixed column widths: the shared table style lets a long Detail squeeze the
            # timestamp into three wrapped lines.
            $null = $sb.AppendLine('<tr><th style="width:150px;white-space:nowrap">Time</th><th style="width:36%">What happened</th><th>Detail</th></tr>')
            foreach ($r in $rows) {
                $cls = if ($r.IsFailure -and $r.State -eq 'AfterResume') { ' class="bad"' } elseif ($r.IsFailure) { ' class="warn"' } else { '' }
                $label = if ($r.IsFailure) { "<b>$(ConvertTo-HtmlSafe $r.Label)</b>" } else { ConvertTo-HtmlSafe $r.Label }
                $null = $sb.AppendLine("<tr$cls><td style=`"white-space:nowrap`">$(ConvertTo-HtmlSafe $r.Time.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$label</td><td>$(ConvertTo-HtmlSafe $r.Detail)</td></tr>")
            }
            $null = $sb.AppendLine('</table></div></details>')
        }
        $null = $sb.AppendLine('</div>')
    }

    $null = $sb.AppendLine('<footer>Startup, shutdown, sleep and wake come from each machine''s System log. Lock and unlock (4800/4801) are only recorded when "Audit Other Logon/Logoff Events" is enabled on that machine. During Modern Standby the network can stay connected, so failures then do not prove the machine was idle.</footer>')
    $null = $sb.AppendLine('</body></html>')
    return $sb.ToString()
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $scriptRoot 'Account Lockout Diagnostics' }
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
    catch { Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"; exit 1 }
}

Write-Host ''
Write-Status INFO "Device timeline - last $DaysBack day(s)."

# --- Which machines ---
$targets = @()
if ($ComputerName) {
    $targets = @($ComputerName | Where-Object { $_ } | ForEach-Object { [PSCustomObject]@{ Computer=$_; SourceIp=''; Accounts=''; FailureCount=0 } })
} elseif ($SourcesCsv) {
    try {
        $targets = @(Select-TimelineTarget -Sources @(Import-Csv -LiteralPath $SourcesCsv -ErrorAction Stop) -Top $Top)
    } catch {
        Write-Status FAIL "Could not read ${SourcesCsv}: $($_.Exception.Message)"; exit 1
    }
    if ($targets.Count -eq 0) { Write-Status WARN 'No source resolved to a domain-joined workstation - nothing to read.' }
} else {
    Write-Status FAIL 'Supply -ComputerName, or -SourcesCsv from Export-ADAuthSourceEvidence.ps1.'
    exit 1
}

$authEvents = @()
if ($AuthEventsCsv) {
    try { $authEvents = @(Import-Csv -LiteralPath $AuthEventsCsv -ErrorAction Stop) }
    catch { Write-Status WARN "Could not read ${AuthEventsCsv}: $($_.Exception.Message) - timeline only." }
}

$startTime = (Get-Date).AddDays(-$DaysBack)
$machines = foreach ($t in $targets) {
    Write-Status INFO "Reading $($t.Computer) ..."
    $a = Get-MachineActivity -Computer $t.Computer -StartTime $startTime
    $failures = if ($authEvents.Count -gt 0) { @(Get-FailureTimesForComputer -AuthEvents $authEvents -Computer $t.Computer -SourceIp $t.SourceIp) } else { @() }
    $hasData = $authEvents.Count -gt 0
    $counts = Measure-FailureState -FailureTimes $failures -Events $a.Events -CoverageStart $a.CoverageStart -WindowMinutes $WindowMinutes
    $verdict = Get-ActivityVerdict -Computer $t.Computer -Counts $counts -HasFailureData $hasData -Reachable $a.Reachable `
                                   -UnreachableReason $a.UnreachableReason -WindowMinutes $WindowMinutes
    $periods = Get-ActivityInterval -Events $a.Events
    $timeline = if ($a.Reachable) {
        New-TimelineRow -Events $a.Events -FailureTimes $failures -Intervals $periods.Intervals -ResumePoints $periods.ResumePoints `
                        -CoverageStart $a.CoverageStart -WindowMinutes $WindowMinutes
    } else { @() }

    if (-not $a.Reachable) { Write-Status WARN "$($t.Computer): $($a.UnreachableReason)" }
    else {
        $level = switch ($verdict.Class) { 'bad' { 'FAIL' } 'warn' { 'WARN' } default { 'PASS' } }
        Write-Status $level "$($t.Computer): $($verdict.Line)"
        foreach ($n in $a.Notes) { Write-Status INFO "$($t.Computer): $n" }
    }

    [PSCustomObject]@{
        Computer = $t.Computer; Reachable = $a.Reachable; HasFailureData = $hasData
        Counts = $counts; Verdict = $verdict; Notes = @($a.Notes); CoverageStart = $a.CoverageStart
        Events = $a.Events; Timeline = @($timeline)
    }
}
$machines = @($machines)

# --- Output ---
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$timelineCsv = Join-Path $OutputPath "SourceActivity_$stamp.csv"
$summaryCsv  = Join-Path $OutputPath "SourceActivitySummary_$stamp.csv"
$htmlPath    = Join-Path $OutputPath "SourceActivity_$stamp.html"

try {
    @($machines | ForEach-Object {
        $m = $_
        $m.Timeline | ForEach-Object {
            [PSCustomObject]@{ Computer=$m.Computer; Time=$_.Time; LastTime=$_.Last; IsFailure=$_.IsFailure; Count=$_.Count; State=$_.State; WhatHappened=$_.Label; Detail=$_.Detail }
        }
    }) | Export-Csv -Path $timelineCsv -NoTypeInformation -Encoding UTF8
    @($machines | ForEach-Object {
        [PSCustomObject]@{
            Computer = $_.Computer; Reachable = $_.Reachable; Verdict = $_.Verdict.Line; Next = $_.Verdict.Next; Reading = $_.Verdict.Key
            Failures = $_.Counts.Total; AfterResume = $_.Counts.AfterResume
            WhileOffOrAsleep = ([int]$_.Counts.WhileOff + [int]$_.Counts.WhileAsleep); WhileLocked = $_.Counts.WhileLocked
            InStandby = $_.Counts.InStandby; Notes = ($_.Notes -join ' ')
        }
    }) | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
    Write-Status PASS "CSV written: $timelineCsv"
} catch {
    Write-Status FAIL "Could not write CSV: $($_.Exception.Message)"
}

try {
    $html = New-SourceActivityHtml -Machines $machines -DaysBack $DaysBack -WindowMinutes $WindowMinutes -GeneratedOn (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Status PASS "HTML report written: $htmlPath"
} catch {
    Write-Status FAIL "Could not write HTML report: $($_.Exception.Message)"
}
