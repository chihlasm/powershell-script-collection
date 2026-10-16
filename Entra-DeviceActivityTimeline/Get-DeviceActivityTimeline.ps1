# Entra join only exists on Windows 10/11, which ship Windows PowerShell 5.1, so 5.1 is the
# real floor of every machine this targets. Compress-Archive (5.0) packages the output.
#Requires -Version 5.1

<#
.SYNOPSIS
    Shows when one Windows device was started, shut down, asleep, awake, locked, unlocked
    and signed in to - read from the device's own logs, with no Active Directory needed.

.DESCRIPTION
    Built for Microsoft Entra joined (and Intune managed) devices, where the usual approach -
    reading event logs remotely with domain credentials - is not available. It runs ON the
    device, by whatever route you have: an RMM or remote-support session, Defender Live
    Response, an Intune platform script, or an Intune Remediation run on demand.

    It reads:
      System log    startup, shutdown, restart requests, crashes, sleep, wake, Modern Standby
      Security log  lock / unlock (4800/4801), screen saver (4802/4803), remote-session
                    connect / disconnect (4778/4779), sign-in (4624), sign-out (4647)

    and writes a day-by-day summary (first and last sign of use each day), a full timeline,
    and a description of the device (join type, tenant, Intune agent, time zone, how far the
    logs reach back). Everything is packaged into one zip so it can be collected in one step.

    LOCK AND UNLOCK NEED AN AUDIT SETTING THAT IS OFF BY DEFAULT
      4800/4801 are only written when "Audit Other Logon/Logoff Events" is set to Success.
      Intune's default for that setting is Off. The report checks the setting and says
      plainly whether lock/unlock data can exist, instead of letting an empty table look like
      "never locked". Unlocks are still recovered from the sign-in record (4624 type 7),
      which "Audit Logon" writes by default; locks cannot be recovered that way.

      -EnableLockAuditing turns the setting on locally so recording starts now. It only
      records from that moment forward - it cannot fill in the past.

    Read-only unless -EnableLockAuditing is given.

.PARAMETER DaysBack
    How many days back to read. Default 30. Ignored when -Start is given.

.PARAMETER Start
    Read from this date/time instead of -DaysBack.

.PARAMETER End
    Read up to this date/time. Default: now.

.PARAMETER UserName
    Only show user events (sign-in, lock, unlock, sign-out) whose account contains this
    text - for example a UPN such as jdoe@contoso.com, or just jdoe - or whose SID equals it.
    Machine events (startup, shutdown, sleep, wake) are always shown.

.PARAMETER OutputPath
    Folder for the report. Default: a "Reports" folder beside this script - not the current
    directory, which is System32 when run as SYSTEM. Through Intune or Live Response the
    script itself runs from a temporary working folder that is cleaned up, so pass an explicit
    path there (for example -OutputPath C:\Temp\DeviceActivity) that you can collect from.

.PARAMETER NoZip
    Leave the HTML and CSV files loose instead of also packaging them into a zip.

.PARAMETER IntuneSummary
    Print only a compact summary (under Intune's 2,048-character output limit) instead of
    the usual console lines, so the answer appears in the Intune admin center's Remediation
    output column. The full report is still written to -OutputPath.

.PARAMETER EnableLockAuditing
    Turn on "Audit Other Logon/Logoff Events" (Success) on this device with auditpol, so lock
    and unlock are recorded from now on. Needs administrator rights. Prefer the Intune
    setting for anything permanent - see README.md. Supports -WhatIf.

.PARAMETER IncludeRawLogs
    Also export the full System and Security logs (.evtx, with wevtutil) into the package,
    so someone else can check the report against the original events - and so the evidence
    survives the logs overwriting themselves. Adds roughly the logs' size (20 MB each by
    default) to the zip.

.PARAMETER LoadFunctionsOnly
    Internal: dot-source the functions without running, for tests.

.EXAMPLE
    .\Get-DeviceActivityTimeline.ps1
    The last 30 days on this device, all users. Run from an elevated prompt.

.EXAMPLE
    .\Get-DeviceActivityTimeline.ps1 -UserName jdoe@contoso.com -Start 2026-10-01 -End 2026-10-14
    One user's sign-in, lock and unlock events for two weeks, alongside the device's power events.

.EXAMPLE
    .\Get-DeviceActivityTimeline.ps1 -IntuneSummary
    As an Intune Remediation detection script: the day-by-day summary shows up in the
    Remediation's output column; the full zip stays on the device for collection.

.EXAMPLE
    .\Get-DeviceActivityTimeline.ps1 -EnableLockAuditing -DaysBack 1
    Start recording lock/unlock now, and confirm the setting took.

.NOTES
    Run elevated (or as SYSTEM). Without administrator rights the Security log cannot be read,
    so sign-in, lock and unlock are missing; the System log events are still reported.

    Times are the device's local time. The report records its time zone and every CSV row also
    carries the UTC time, so a device in another time zone cannot be misread.

    The script is pure ASCII on purpose: Intune Remediations with signature checking require
    UTF-8 without a BOM, and Windows PowerShell needs a BOM for any non-ASCII script. ASCII
    satisfies both. Tests\Get-DeviceActivityTimeline.Tests.ps1 guards it.

    REFERENCES
      Lock/unlock/screen saver and the subcategory that writes them (default Off in Intune):
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4800
        https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-logonlogoff-events
        https://learn.microsoft.com/windows/client-management/mdm/policy-csp-audit#accountlogonlogoff_auditotherlogonlogoffevents
      Remote session reconnect/disconnect (also Fast User Switching):
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4778
      Sign-in, logon types (7 = Unlock), fields; user-initiated sign-out:
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
        https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4647
      Subcategory GUID (Audit_Logon_Others) and auditpol syntax:
        https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
        https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-set
      Kernel-General 12/13, User32 1074, Kernel-Power 41, EventLog 6008:
        https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
      Kernel-Power 42 / 107 / 506 / 507, Modern Standby keeps networking available:
        https://learn.microsoft.com/defender-endpoint/troubleshoot-mdav-scan-issues
        https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby
      Join state from dsregcmd /status:
        https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd
      Entra user/group SIDs begin S-1-12-1:
        https://learn.microsoft.com/surface-hub/surface-hub-2s-nonglobal-admin
      Intune Management Extension install path:
        https://learn.microsoft.com/intune/device-management/tools/management-extension-windows
      Resume record sleep types (SYSTEM_POWER_STATE) and Fast Startup vs. hibernate resume:
        https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-system_power_state
        https://learn.microsoft.com/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation
      Exporting logs (wevtutil epl):
        https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil
      Remediations: 2,048-character output limit, UTF-8 without BOM when signature-checked:
        https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [datetime]$Start,

    [datetime]$End,

    [string]$UserName,

    [string]$OutputPath,

    [switch]$NoZip,

    [switch]$IncludeRawLogs,

    [switch]$IntuneSummary,

    [switch]$EnableLockAuditing,

    [switch]$LoadFunctionsOnly
)

$script:Quiet = $false

function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    if ($script:Quiet) { return }
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

# Provider + event ID -> what happened. Keyed on BOTH, because the same ID means different
# things from different providers (System log event 12 is not always Kernel-General).
# Copied from AD-LockoutDiagnostics\Get-SourceMachineActivity.ps1 (folders here are
# self-contained); sources are in the REFERENCES block above.
$script:ActivityMap = @(
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-General';    Id=12;   Kind='Startup';           Label='Windows started' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-General';    Id=13;   Kind='Shutdown';          Label='Windows shut down' }
    @{ Log='System';   Provider='User32';                              Id=1074; Kind='ShutdownRequest';   Label='Restart or shutdown requested' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';      Id=41;   Kind='UnexpectedRestart'; Label='Restarted after a crash or power loss' }
    @{ Log='System';   Provider='EventLog';                            Id=6008; Kind='UnexpectedRestart'; Label='Previous shutdown was unexpected' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';      Id=42;   Kind='Sleep';             Label='Went to sleep' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';      Id=107;  Kind='Wake';              Label='Woke from sleep' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';      Id=506;  Kind='StandbyEnter';      Label='Entered Modern Standby (network can stay on)' }
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-Power';      Id=507;  Kind='StandbyExit';       Label='Left Modern Standby' }
    # Written on every system time change; only jumps of minutes or more are kept. Needed
    # to recover real wake times - see Repair-ResumeTime.
    @{ Log='System';   Provider='Microsoft-Windows-Kernel-General';    Id=1;    Kind='ClockChange';       Label='System clock changed' }
    # "Returned from a low power state": real sleep/wake times, sleep type and wake source.
    # Consumed by Repair-ResumeTime; never shown as its own row.
    @{ Log='System';   Provider='Microsoft-Windows-Power-Troubleshooter'; Id=1; Kind='ResumeRecord';      Label='Resume record' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4800; Kind='Lock';              Label='Locked' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4801; Kind='Unlock';            Label='Unlocked' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4802; Kind='ScreenSaverOn';     Label='Screen saver started' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4803; Kind='ScreenSaverOff';    Label='Screen saver dismissed' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4778; Kind='SessionConnect';    Label='Session reconnected' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4779; Kind='SessionDisconnect'; Label='Session disconnected' }
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4647; Kind='SignOut';           Label='Signed out' }
    # 4624 is classified by logon type - see $script:LogonTypeMap.
    @{ Log='Security'; Provider='Microsoft-Windows-Security-Auditing'; Id=4624; Kind='';                  Label='' }
)

# 4624 logon types that mean a person at (or remoting into) this device. Network (3),
# batch (4), service (5) and the rest are machine plumbing and are left out.
# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
$script:LogonTypeMap = @{
    '2'  = @{ Kind='SignIn';       Label='Signed in';                     Detail='At the device' }
    '11' = @{ Kind='SignIn';       Label='Signed in';                     Detail='Checked against credentials saved on the device (normal for Entra and laptop sign-ins)' }
    '10' = @{ Kind='RemoteSignIn'; Label='Signed in over Remote Desktop'; Detail='' }
    '12' = @{ Kind='RemoteSignIn'; Label='Signed in over Remote Desktop'; Detail='With saved credentials' }
    '7'  = @{ Kind='Unlock';       Label='Unlocked';                      Detail='From the sign-in record (4624 type 7)' }
    '13' = @{ Kind='Unlock';       Label='Unlocked';                      Detail='From the sign-in record (4624 type 13)' }
}

# Only real people: local/AD accounts (S-1-5-21-...) and Entra accounts (S-1-12-1-...).
# This drops SYSTEM, LOCAL/NETWORK SERVICE, and the per-session Window Manager (DWM-n) and
# Font Driver Host (UMFD-n) accounts that sign in alongside every interactive session.
$script:PersonSidPattern = '^S-1-(5-21|12-1)-'

# Zero-width and bidirectional marks (U+200B-200F, 202A-202E, 2066-2069) that rendered event
# messages wrap around dates. Built from code points so this file stays pure ASCII - a
# literal mark here is decoded as ANSI by Windows PowerShell and breaks the regex.
$script:InvisibleMarks = '[{0}-{1}{2}-{3}{4}-{5}]' -f [char]0x200B, [char]0x200F, [char]0x202A, [char]0x202E, [char]0x2066, [char]0x2069

# Kinds that show someone starting to use the device, and ones that show them stopping.
$script:StartKinds = @('Startup', 'UnexpectedRestart', 'Wake', 'StandbyExit', 'Unlock', 'SignIn', 'RemoteSignIn', 'SessionConnect', 'ScreenSaverOff')
$script:StopKinds  = @('Shutdown', 'Sleep', 'StandbyEnter', 'Lock', 'SignOut', 'SessionDisconnect', 'ScreenSaverOn')

# Audit_Logon_Others - "Audit Other Logon/Logoff Events". GUIDs are locale-independent;
# the display name is translated.
# https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
$script:OtherLogonLogoffGuid = '{0CCE921C-69AE-11D9-BED3-505054503030}'

$script:IntuneOutputLimit = 2048

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Join-AccountName {
    param([string]$Domain, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    if ([string]::IsNullOrWhiteSpace($Domain) -or $Domain -eq '-') { return $Name }
    return "$Domain\$Name"
}

function ConvertFrom-EventDataXml {
    # EventData <Data Name="x">value</Data> -> hashtable.
    param([string]$Xml)
    $d = @{}
    if ([string]::IsNullOrWhiteSpace($Xml)) { return $d }
    try {
        $x = [xml]$Xml
        foreach ($n in @($x.Event.EventData.Data)) { if ($n -and $n.Name) { $d[$n.Name] = [string]$n.'#text' } }
    } catch { }
    return $d
}

function ConvertFrom-ActivityEvent {
    # Classifies one event. Pure, so the mapping is testable without real logs.
    # Returns $null for an event this tool does not track.
    param(
        [string]$LogName,
        [string]$ProviderName,
        [int]$EventId,
        [datetime]$Time,
        [string]$Message,
        [hashtable]$Data
    )
    if (-not $Data) { $Data = @{} }

    $rule = $script:ActivityMap | Where-Object {
        $_.Id -eq $EventId -and $_.Log -eq $LogName -and $_.Provider -eq $ProviderName
    } | Select-Object -First 1
    if (-not $rule) { return $null }

    $kind = $rule.Kind; $label = $rule.Label; $source = "$LogName $EventId"
    $user = ''; $sid = ''; $detail = ''; $clockFrom = $null; $clockTo = $null
    $resumeType = ''; $wakeSource = ''

    if ($kind -eq 'ResumeRecord') {
        # Power-Troubleshooter 1 is written once the device is running again, so its
        # SleepTime/WakeTime (UTC) are real even when other resume events carry the stopped
        # clock. Target/EffectiveState are SYSTEM_POWER_STATE values (5 = hibernate S4,
        # 6 = shutdown S5, 2-4 = sleep S1-S3); target shutdown + effective hibernate is a Fast
        # Startup, per Microsoft's driver guidance.
        #   https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-system_power_state
        #   https://learn.microsoft.com/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation
        $inv = [Globalization.CultureInfo]::InvariantCulture
        try {
            $clockFrom = [datetime]::Parse([string]$Data['SleepTime'], $inv, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
            $clockTo   = [datetime]::Parse([string]$Data['WakeTime'], $inv, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
        } catch { return $null }
        $target = 0; $effective = 0
        [void][int]::TryParse([string]$Data['TargetState'], [ref]$target)
        [void][int]::TryParse([string]$Data['EffectiveState'], [ref]$effective)
        $resumeType = if ($target -eq 6 -and $effective -eq 5) { 'FastStartup' } elseif ($effective -eq 5) { 'Hibernate' } else { 'Sleep' }
        $wakeSource = [string]$Data['WakeSourceText']
        if (-not $wakeSource -and $Message -match 'Wake Source:\s*(.+)') { $wakeSource = $Matches[1] }
        $wakeSource = ($wakeSource -replace $script:InvisibleMarks, '').Trim()
        if ($wakeSource -match '^Unknown$') { $wakeSource = '' }
        $Message = ''
        $source = 'System 1 (Power-Troubleshooter)'
    }

    if ($kind -eq 'ClockChange') {
        # OldTime/NewTime are UTC in EventData. Small corrections (time sync nudging the
        # clock) are noise; only a jump of minutes says something about the device.
        $inv = [Globalization.CultureInfo]::InvariantCulture
        try {
            $clockFrom = [datetime]::Parse([string]$Data['OldTime'], $inv, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
            $clockTo   = [datetime]::Parse([string]$Data['NewTime'], $inv, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
        } catch { return $null }
        if ([math]::Abs(($clockTo - $clockFrom).TotalMinutes) -lt 2) { return $null }
        $detail = "Clock moved from $($clockFrom.ToString('yyyy-MM-dd HH:mm:ss')) to $($clockTo.ToString('yyyy-MM-dd HH:mm:ss'))"
        $Message = ''
        $source = 'System 1 (Kernel-General)'
    }

    if ($LogName -eq 'Security') {
        if ($EventId -eq 4778 -or $EventId -eq 4779) {
            # 4778/4779 carry AccountName/AccountDomain and no SID.
            $user = Join-AccountName -Domain $Data['AccountDomain'] -Name $Data['AccountName']
            $session = [string]$Data['SessionName']
            $client  = [string]$Data['ClientName']
            $address = [string]$Data['ClientAddress']
            $detail = if ($session -match '^Console$') { 'At the device (switched user)' }
                      elseif ($client -and $client -ne 'Unknown') { "Remote session from $client ($address)" }
                      else { "Session $session" }
        } else {
            $sid = [string]$Data['TargetUserSid']
            if ($sid -notmatch $script:PersonSidPattern) { return $null }
            $user = Join-AccountName -Domain $Data['TargetDomainName'] -Name $Data['TargetUserName']
            if ($EventId -eq 4624) {
                $lt = [string]$Data['LogonType']
                $map = $script:LogonTypeMap[$lt]
                if (-not $map) { return $null }
                $kind = $map.Kind; $label = $map.Label; $detail = $map.Detail
                $source = "Security 4624 type $lt"
            }
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($Message)) {
        # First line of the rendered message is enough context for a timeline row (1074
        # names the process and user; 42 names the sleep reason).
        $detail = (($Message -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
        # Rendered messages wrap dates in invisible left-to-right marks (U+200E etc.), which
        # end up in the CSV and break searching it.
        $detail = ($detail -replace $script:InvisibleMarks, '').Trim()
        if ($detail.Length -gt 220) { $detail = $detail.Substring(0, 217) + '...' }
    }

    [PSCustomObject]@{
        Time    = $Time
        Kind    = $kind
        Label   = $label
        EventId = $EventId
        Source  = $source
        User    = $user
        UserSid = $sid
        Detail  = $detail
        ClockFrom = $clockFrom
        ClockTo   = $clockTo
        ResumeType = $resumeType
        WakeSource = $wakeSource
    }
}

function Repair-ResumeTime {
    # Recovers real wake and start times after a long sleep, hibernation or Fast Startup.
    # Pure.
    #
    # While a device is down its clock stops. On resume Windows writes "resumed from sleep"
    # (Kernel-Power 107) BEFORE it resets the clock from the hardware clock, so 107 is stamped
    # with the moment it went down - seconds after the sleep event - and the timeline shows a
    # device that woke at once and then sat on, silent, for days. Two later events carry the
    # real time:
    #   1. Power-Troubleshooter 1 (the resume record): SleepTime/WakeTime, written after the
    #      resume. Used first.
    #   2. Kernel-General 1 (the clock reset): OldTime = the stopped clock, NewTime = real.
    #      Fallback when there is no resume record; Microsoft documents event 1 on every time
    #      change, so the match is strict: a forward jump whose OldTime falls within
    #      -MaxGapMinutes after the device went down (sleep, standby or shutdown).
    #      https://learn.microsoft.com/troubleshoot/windows-server/active-directory/w32time-event-142-time-service-stopped-advertising
    #      https://learn.microsoft.com/windows/win32/sysinfo/system-time
    # The ordering itself was observed on Windows 11 laptops, not documented.
    #
    # Each recovered resume becomes a row at the real time (or, when an accurate resume row
    # already exists there, adds its detail to that row). Rows stamped with the stopped clock
    # are kept but relabelled so they no longer count. Unmatched clock jumps stay as
    # "System clock changed"; resume records are never shown as rows of their own.
    param([object[]]$Events, [int]$MaxGapMinutes = 10)

    $list = @($Events | Where-Object { $_ } | Sort-Object Time)
    $stale = @{}; $used = @{}; $enrich = @{}
    $added = New-Object System.Collections.ArrayList
    $resumeKinds = @('Wake', 'StandbyExit', 'Startup')

    # Resume-type rows AFTER the sleep/shutdown event and well before the real resume time are
    # the ones Windows stamped with the stopped clock. Rows before that event are genuine - a
    # laptop typically leaves Modern Standby just before it hibernates.
    $markStale = {
        param([datetime]$Down, [datetime]$Up)
        $from = $null
        foreach ($e in $list) {
            $t = [datetime]$e.Time
            if ($t -gt $Down.AddMinutes($MaxGapMinutes)) { break }
            if ($t -ge $Down.AddMinutes(-1) -and $e.Kind -in @('Sleep', 'Shutdown')) { $from = $t; break }
        }
        if (-not $from) { $from = $Down }
        $first = $null
        for ($i = 0; $i -lt $list.Count; $i++) {
            $t = [datetime]$list[$i].Time
            if ($t -le $from) { continue }
            if ($t -gt $Down.AddMinutes($MaxGapMinutes) -or $t -ge $Up.AddSeconds(-60)) { break }
            if ($list[$i].Kind -in $resumeKinds) { $stale[$i] = $true; if (-not $first) { $first = $t } }
        }
        return $first
    }
    # An accurate resume row already at the real time, if Windows wrote one.
    $findRow = {
        param([datetime]$Up)
        for ($i = 0; $i -lt $list.Count; $i++) {
            if (-not $stale.ContainsKey($i) -and $list[$i].Kind -in $resumeKinds -and
                [math]::Abs(([datetime]$list[$i].Time - $Up).TotalSeconds) -le 120) { return $i }
        }
        return -1
    }
    $staleNote = { param($at) if ($at) { " Windows logged it at $(([datetime]$at).ToString('yyyy-MM-dd HH:mm:ss')), before its clock caught up." } else { '' } }

    # 1. Resume records.
    $recovered = @()
    for ($c = 0; $c -lt $list.Count; $c++) {
        $r = $list[$c]
        if ($r.Kind -ne 'ResumeRecord') { continue }
        $used[$c] = $true
        if (-not $r.ClockFrom -or -not $r.ClockTo) { continue }
        $down = [datetime]$r.ClockFrom; $up = [datetime]$r.ClockTo
        $recovered += $up
        $how = switch ($r.ResumeType) { 'FastStartup' { 'a Fast Startup shutdown' } 'Hibernate' { 'hibernation' } default { 'sleep' } }
        $why = if ($r.WakeSource) { " Wake source: $($r.WakeSource)." } else { '' }
        $staleAt = & $markStale $down $up
        $isStart = $r.ResumeType -eq 'FastStartup'
        $kind  = if ($isStart) { 'Startup' } else { 'Wake' }
        $label = if ($isStart) { 'Windows started (Fast Startup)' } elseif ($r.ResumeType -eq 'Hibernate') { 'Woke from hibernation' } else { 'Woke from sleep' }
        $idx = & $findRow $up
        if ($idx -ge 0) {
            # An accurate row is already there (often "Left Modern Standby" right after a
            # hibernate resume); give it the resume record's more precise meaning.
            $enrich[$idx] = @{ Kind = $kind; Label = $label; Note = "Resumed from $how.$why" }
            continue
        }
        $null = $added.Add([PSCustomObject]@{
            Time = $up; EventId = 1; Source = 'System 1 (Power-Troubleshooter)'; User = ''; UserSid = ''
            Kind  = $kind
            Label = $label
            Detail = "Down since $($down.ToString('yyyy-MM-dd HH:mm:ss')); resumed from $how.$why$(& $staleNote $staleAt)"
            ClockFrom = $down; ClockTo = $up; ResumeType = $r.ResumeType; WakeSource = $r.WakeSource
        })
    }

    # 2. Clock resets with no resume record for the same resume.
    for ($c = 0; $c -lt $list.Count; $c++) {
        $jump = $list[$c]
        if ($jump.Kind -ne 'ClockChange' -or -not $jump.ClockFrom -or -not $jump.ClockTo) { continue }
        $old = [datetime]$jump.ClockFrom; $new = [datetime]$jump.ClockTo
        if (($new - $old).TotalMinutes -lt 2) { continue }
        if (@($recovered | Where-Object { [math]::Abs(($_ - $new).TotalSeconds) -le 120 }).Count -gt 0) { $used[$c] = $true; continue }

        $downIdx = -1
        for ($i = 0; $i -lt $list.Count; $i++) {
            $t = [datetime]$list[$i].Time
            if ($t -gt $old) { break }
            if ($list[$i].Kind -in @('Sleep', 'StandbyEnter', 'Shutdown') -and ($old - $t).TotalMinutes -le $MaxGapMinutes) { $downIdx = $i }
        }
        if ($downIdx -lt 0) { continue }

        $down = [datetime]$list[$downIdx].Time
        $wasOff = $list[$downIdx].Kind -eq 'Shutdown'
        $staleAt = & $markStale $down $new
        $used[$c] = $true
        if ((& $findRow $new) -ge 0) { continue }
        $null = $added.Add([PSCustomObject]@{
            Time = $new; EventId = 1; Source = 'System 1 (clock reset)'; User = ''; UserSid = ''
            Kind  = $(if ($wasOff) { 'Startup' } else { 'Wake' })
            Label = $(if ($wasOff) { 'Windows started' } else { 'Woke from sleep' })
            Detail = "$(if ($wasOff) { 'Off' } else { 'Asleep or hibernated' }) since $($down.ToString('yyyy-MM-dd HH:mm:ss')); real time recovered from the clock reset.$(& $staleNote $staleAt)"
            ClockFrom = $old; ClockTo = $new; ResumeType = ''; WakeSource = ''
        })
    }

    $out = for ($i = 0; $i -lt $list.Count; $i++) {
        if ($used.ContainsKey($i)) { continue }
        $e = $list[$i]
        if ($stale.ContainsKey($i)) {
            $e = $e.PSObject.Copy()
            $e.Label = if ($e.Kind -eq 'Startup') { 'Start logged with the clock still at the time it shut down' } else { 'Resume logged with the clock still at the time it went to sleep' }
            $e.Kind = 'ResumeLogged'
        } elseif ($enrich.ContainsKey($i)) {
            $e = $e.PSObject.Copy()
            # A Windows-started row keeps its kind; a standby/wake row takes the record's.
            if ($e.Kind -ne 'Startup') { $e.Kind = $enrich[$i].Kind; $e.Label = $enrich[$i].Label }
            $e.Detail = (@($e.Detail, $enrich[$i].Note) | Where-Object { $_ }) -join ' - '
        }
        $e
    }
    return @(@($out) + @($added) | Sort-Object Time)
}

function Merge-ActivityEvent {
    # Collapses the records Windows writes several of for one action. Pure.
    #
    #  1. The same record twice within 2 seconds (an administrator's sign-in is written for
    #     both the elevated and the standard token).
    #  2. A 4624 sign-in followed within -PairSeconds by a 4624 unlock for the same account
    #     is one unlock. On Windows 11 Entra-joined devices an unlock writes type 11 and then
    #     type 7 about two seconds apart - observed on real devices, not documented, so it is
    #     limited to that tight window.
    #  3. A 4624-derived unlock within -PairSeconds of a real 4801 unlock is the same unlock;
    #     4801 is the authoritative record and is kept.
    param([object[]]$Events, [int]$PairSeconds = 10)

    $sorted = @($Events | Where-Object { $_ } | Sort-Object Time)
    $kept = New-Object System.Collections.ArrayList
    $lastSeen = @{}
    foreach ($e in $sorted) {
        $key = "$($e.Kind)|$($e.Source)|$($e.UserSid)|$($e.User)"
        if ($lastSeen.ContainsKey($key) -and ([datetime]$e.Time - [datetime]$lastSeen[$key]).TotalSeconds -le 2) { continue }
        $lastSeen[$key] = $e.Time
        $null = $kept.Add($e)
    }

    $list = @($kept)
    $drop = @{}
    for ($i = 0; $i -lt $list.Count; $i++) {
        $e = $list[$i]
        if ($e.EventId -ne 4624) { continue }
        $t = [datetime]$e.Time
        # The list is sorted, so only neighbours inside the window can match.
        for ($j = $i - 1; $j -ge 0 -and ($t - [datetime]$list[$j].Time).TotalSeconds -le $PairSeconds; $j--) {
            $o = $list[$j]
            if ($e.Kind -eq 'Unlock' -and $o.EventId -eq 4801 -and $o.UserSid -eq $e.UserSid) { $drop[$i] = $true }
        }
        for ($j = $i + 1; $j -lt $list.Count -and ([datetime]$list[$j].Time - $t).TotalSeconds -le $PairSeconds; $j++) {
            $o = $list[$j]
            if ($o.UserSid -ne $e.UserSid) { continue }
            if ($e.Kind -eq 'SignIn' -and $o.EventId -eq 4624 -and $o.Kind -eq 'Unlock') { $drop[$i] = $true }
            if ($e.Kind -eq 'Unlock' -and $o.EventId -eq 4801) { $drop[$i] = $true }
        }
    }

    $out = for ($i = 0; $i -lt $list.Count; $i++) { if (-not $drop.ContainsKey($i)) { $list[$i] } }
    return @($out)
}

function Test-UserMatch {
    # Whether an event belongs to -UserName. Machine-wide events (no account) always match.
    param([object]$Item, [string]$UserName)
    if ([string]::IsNullOrWhiteSpace($UserName)) { return $true }
    if (-not $Item.User -and -not $Item.UserSid) { return $true }
    if ($Item.UserSid -and $Item.UserSid -eq $UserName.Trim()) { return $true }
    return ([string]$Item.User).IndexOf($UserName.Trim(), [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Get-DailySummary {
    # One row per day: when use started and stopped, and how often each thing happened. Pure.
    # Days before the logs begin are left out rather than shown as "no activity".
    param(
        [object[]]$Events,
        [datetime]$From,
        [datetime]$To,
        [Nullable[datetime]]$CoverageStart
    )

    # Events before -From only set the starting state below; they are not counted.
    $byDay = @{}
    foreach ($e in @($Events | Where-Object { $_ -and [datetime]$_.Time -ge $From -and [datetime]$_.Time -le $To })) {
        $k = ([datetime]$e.Time).ToString('yyyy-MM-dd')
        if (-not $byDay.ContainsKey($k)) { $byDay[$k] = New-Object System.Collections.ArrayList }
        $null = $byDay[$k].Add($e)
    }

    $first = $From.Date
    if ($CoverageStart -and ([datetime]$CoverageStart).Date -gt $first) { $first = ([datetime]$CoverageStart).Date }
    $inv = [Globalization.CultureInfo]::InvariantCulture

    # The power state each kind leaves the device in, so a day with no events can say what
    # the device was doing ("asleep all day") instead of a bare "no events".
    $powerState = @{ Shutdown='Off'; Startup='On'; UnexpectedRestart='On'; Sleep='Asleep'; Wake='On'; StandbyEnter='Standby'; StandbyExit='On' }
    $allDayText = @{
        Off     = 'Off all day'
        Asleep  = 'Asleep all day'
        Standby = 'In Modern Standby all day (screen off; network may be on)'
        On      = 'On, but nothing changed state (no sleep, lock or sign-in recorded)'
    }
    $state = ''; $stateSince = $null
    foreach ($e in @($Events | Where-Object { $_ -and ([datetime]$_.Time) -lt $From -and $powerState.ContainsKey($_.Kind) } | Sort-Object Time)) {
        $state = $powerState[$e.Kind]; $stateSince = [datetime]$e.Time
    }

    $rows = for ($d = $first; $d -le $To.Date; $d = $d.AddDays(1)) {
        $k = $d.ToString('yyyy-MM-dd')
        $evs = @()
        if ($byDay.ContainsKey($k)) { $evs = @($byDay[$k] | Sort-Object Time) }

        $allDay = ''
        if ($evs.Count -eq 0) {
            $allDay = if ($state) { $allDayText[$state] } else { 'No events recorded' }
            if ($state -and $stateSince -and $state -ne 'On') { $allDay += " (since $($stateSince.ToString('yyyy-MM-dd HH:mm')))" }
        }
        foreach ($e in $evs) { if ($powerState.ContainsKey($e.Kind)) { $state = $powerState[$e.Kind]; $stateSince = [datetime]$e.Time } }
        $starts = @($evs | Where-Object { $_.Kind -in $script:StartKinds })
        $any    = @($evs | Where-Object { $_.Kind -in ($script:StartKinds + $script:StopKinds) })
        $f = $starts | Select-Object -First 1
        $l = $any | Select-Object -Last 1
        $count = { param($kinds) @($evs | Where-Object { $_.Kind -in $kinds }).Count }

        [PSCustomObject]@{
            Date          = $k
            Day           = $d.ToString('ddd', $inv)
            FirstActivity = if ($f) { ([datetime]$f.Time).ToString('HH:mm') } else { '' }
            FirstWhat     = if ($f) { $f.Label } else { '' }
            LastActivity  = if ($l) { ([datetime]$l.Time).ToString('HH:mm') } else { '' }
            LastWhat      = if ($l) { $l.Label } else { '' }
            Startups      = & $count @('Startup', 'UnexpectedRestart')
            Shutdowns     = & $count @('Shutdown')
            Sleeps        = & $count @('Sleep', 'StandbyEnter')
            Wakes         = & $count @('Wake', 'StandbyExit')
            Locks         = & $count @('Lock')
            Unlocks       = & $count @('Unlock')
            SignIns       = & $count @('SignIn', 'RemoteSignIn')
            SignOuts      = & $count @('SignOut')
            Events        = $evs.Count
            AllDay        = $allDay
        }
    }
    return @($rows)
}

function ConvertFrom-AuditPolCsv {
    # Parses `auditpol /get /r` CSV into GUID -> setting rows. Matches on GUID because the
    # subcategory display name is localized. Same approach as Test-ADAuditPolicy.ps1.
    param([AllowEmptyString()][string]$CsvText)
    $rows = @()
    if ([string]::IsNullOrWhiteSpace($CsvText)) { return $rows }
    try { $parsed = @($CsvText | ConvertFrom-Csv) } catch { return $rows }
    foreach ($p in $parsed) {
        $names = @($p.PSObject.Properties.Name)
        $guidProp = $names | Where-Object { $_ -match 'GUID' } | Select-Object -First 1
        $setProp  = $names | Where-Object { $_ -match 'Inclusion' } | Select-Object -First 1
        if (-not $guidProp -or -not $setProp) { continue }
        $rows += [PSCustomObject]@{ Guid = ([string]$p.$guidProp).Trim(); Setting = ([string]$p.$setProp).Trim() }
    }
    return $rows
}

function Resolve-AuditSetting {
    # auditpol's "Inclusion Setting" -> On / Off / Unknown for SUCCESS auditing. auditpol
    # prints English words on English Windows; anything else is reported as Unknown rather
    # than guessed at, and the presence of real 4800/4801 events decides instead.
    param([AllowEmptyString()][string]$Setting)
    $s = ([string]$Setting).Trim()
    $state = switch -Regex ($s) {
        '^$'                       { 'Unknown'; break }
        '^No Auditing$'            { 'Off'; break }
        '^Success( and Failure)?$' { 'On'; break }
        '^Failure$'                { 'Off'; break }
        default                    { 'Unknown' }
    }
    [PSCustomObject]@{ State = $state; Setting = $s }
}

function Get-LockAuditSetting {
    # Reads the effective local setting with auditpol (needs administrator rights).
    $exe = Resolve-SystemExe -Name 'auditpol.exe'
    try {
        $text = & $exe /get "/subcategory:$($script:OtherLogonLogoffGuid)" /r 2>&1 | Out-String
    } catch {
        return [PSCustomObject]@{ State = 'Unknown'; Setting = "auditpol failed: $($_.Exception.Message)" }
    }
    $row = @(ConvertFrom-AuditPolCsv -CsvText $text | Where-Object { $_.Guid -eq $script:OtherLogonLogoffGuid }) | Select-Object -First 1
    if (-not $row) { return [PSCustomObject]@{ State = 'Unknown'; Setting = ($text.Trim() -split "`r?`n")[0] } }
    return Resolve-AuditSetting -Setting $row.Setting
}

function Get-LockAuditReadiness {
    # Plain-English answer to "can this report show lock and unlock?". Pure.
    param(
        [string]$State,
        [int]$LockEventCount,
        [bool]$SecurityReadable
    )
    if (-not $SecurityReadable) {
        return [PSCustomObject]@{ Class='warn'; Key='NoSecurityLog'
            Line = 'The Security log could not be read, so sign-in, lock and unlock are missing.'
            Next = 'Run the script elevated or as SYSTEM. Startup, shutdown, sleep and wake below are complete.' }
    }
    if ($LockEventCount -gt 0) {
        $tail = if ($State -eq 'Off') { ' The setting now reads Off, so locks after it was turned off will be missing.' } else { '' }
        return [PSCustomObject]@{ Class='ok'; Key='Recording'
            Line = 'Lock and unlock are being recorded on this device.'
            Next = "Found $LockEventCount lock/unlock/screen-saver events in this period.$tail" }
    }
    switch ($State) {
        'On' {
            return [PSCustomObject]@{ Class='warn'; Key='OnButEmpty'
                Line = 'Lock and unlock recording is on, but none were recorded in this period.'
                Next = 'Either it was turned on recently or the screen was never locked. Lock the screen (Windows+L), unlock, and run this again to confirm it is working.' }
        }
        'Off' {
            return [PSCustomObject]@{ Class='bad'; Key='Off'
                Line = 'Lock and unlock are NOT recorded on this device - "Audit Other Logon/Logoff Events" is off (the Intune default).'
                Next = 'Unlocks below come from the sign-in record (4624 type 7), which is recorded by default. Locks cannot be recovered for the past. Turn the setting on in Intune (see README) to record them from now on.' }
        }
        default {
            return [PSCustomObject]@{ Class='warn'; Key='Unknown'
                Line = 'Could not confirm whether lock and unlock are recorded, and none were found.'
                Next = 'Treat missing locks as unknown, not as "never locked". Unlocks below come from the sign-in record (4624 type 7).' }
        }
    }
}

function ConvertFrom-DsregcmdStatus {
    # "    AzureAdJoined : YES" lines -> hashtable. The first occurrence of a key wins: later
    # sections (user state, other workplace tenants) reuse some names.
    param([AllowEmptyString()][string]$Text)
    $h = @{}
    foreach ($line in ([string]$Text -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z][A-Za-z ]*?)\s*:\s*(.*?)\s*$') {
            if (-not $h.ContainsKey($Matches[1])) { $h[$Matches[1]] = $Matches[2] }
        }
    }
    return $h
}

function Resolve-JoinType {
    # Per the dsregcmd device-state table:
    # https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd
    param([hashtable]$Status)
    $yes = { param($k) ([string]$Status[$k]) -eq 'YES' }
    if ((& $yes 'AzureAdJoined') -and (& $yes 'DomainJoined')) { return 'Microsoft Entra hybrid joined' }
    if (& $yes 'AzureAdJoined')    { return 'Microsoft Entra joined' }
    if (& $yes 'EnterpriseJoined') { return 'On-premises DRS joined' }
    if (& $yes 'DomainJoined')     { return 'Domain joined (not Entra)' }
    if (& $yes 'WorkplaceJoined')  { return 'Microsoft Entra registered only (not joined)' }
    if ($Status.Count -eq 0)       { return 'Unknown (dsregcmd gave no output)' }
    return 'Not joined to Entra or a domain'
}

function Resolve-SystemExe {
    # A 32-bit PowerShell host (an Intune script with "Run in 64-bit" off) is redirected to
    # SysWOW64, which may not have the tool. Sysnative reaches the real System32.
    param([string]$Name)
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $p = Join-Path $env:windir "Sysnative\$Name"
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return (Join-Path $env:windir "System32\$Name")
}

function Get-DeviceIdentity {
    $status = @{}
    try { $status = ConvertFrom-DsregcmdStatus -Text (& (Resolve-SystemExe -Name 'dsregcmd.exe') /status 2>$null | Out-String) } catch { }

    $os = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    $tz = [TimeZoneInfo]::Local
    $offset = $tz.GetUtcOffset((Get-Date))
    $sign = if ($offset -lt [timespan]::Zero) { '-' } else { '+' }

    # Presence of the agent shows Intune has deployed scripts or apps here. The MDM URL alone
    # does not prove enrollment - dsregcmd shows it whenever the tenant has auto-enrollment.
    $ime = Test-Path -LiteralPath (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension')

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        JoinType     = Resolve-JoinType -Status $status
        TenantName   = [string]$status['TenantName']
        TenantId     = [string]$status['TenantId']
        DeviceId     = [string]$status['DeviceId']
        MdmUrl       = [string]$status['MdmUrl']
        IntuneAgent  = $ime
        OS           = if ($os) { "$($os.Caption) $($os.Version)" } else { '' }
        LastBoot     = if ($os) { $os.LastBootUpTime } else { $null }
        TimeZone     = $tz.Id
        UtcOffset    = ('UTC{0}{1:hh\:mm}' -f $sign, $offset)
    }
}

function New-SecurityQueryXml {
    # Security log query. Filtering the logon type inside the query matters: service and
    # network logons (types 3/5) outnumber interactive ones by hundreds to one, and fetching
    # and parsing them all is what makes a month's read slow. Pure.
    param([datetime]$StartTime, [datetime]$EndTime)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $s = $StartTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $inv)
    $e = $EndTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $inv)
    $time = "TimeCreated[@SystemTime&gt;='$s' and @SystemTime&lt;='$e']"
    $types = (@($script:LogonTypeMap.Keys | Sort-Object { [int]$_ }) | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
    $others = (@(4647, 4778, 4779, 4800, 4801, 4802, 4803) | ForEach-Object { "EventID=$_" }) -join ' or '
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624) and $time]] and *[EventData[$types]]</Select>
    <Select Path="Security">*[System[($others) and $time]]</Select>
  </Query>
</QueryList>
"@
}

function Get-LogCoverage {
    # How far a log really reaches back, and its size - an empty week may just be overwritten.
    param([string]$LogName)
    $r = [PSCustomObject]@{ LogName = $LogName; Oldest = $null; MaxSizeMB = $null }
    try { $r.Oldest = (Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { }
    try { $r.MaxSizeMB = [math]::Round((Get-WinEvent -ListLog $LogName -ErrorAction Stop).MaximumSizeInBytes / 1MB) } catch { }
    return $r
}

function Read-ActivityEvent {
    # The only function that reads the event logs. The System log is read -LookbackDays
    # further back than asked: the sleep that a wake in the range belongs to - and so the
    # state the device was in when the range starts - is often earlier. The caller trims the
    # result back to the requested range.
    param([datetime]$StartTime, [datetime]$EndTime, [int]$LookbackDays = 14)

    $result = [PSCustomObject]@{ Events = @(); SystemReadable = $true; SecurityReadable = $true; Notes = @() }
    $rows = New-Object System.Collections.ArrayList
    $systemIds = @($script:ActivityMap | Where-Object { $_.Log -eq 'System' } | ForEach-Object { $_.Id } | Select-Object -Unique)

    try {
        foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=$systemIds; StartTime=$StartTime.AddDays(-$LookbackDays); EndTime=$EndTime } -ErrorAction Stop)) {
            # Only the clock-change and resume-record events (both ID 1) need their fields.
            $data = if ($ev.Id -eq 1) { ConvertFrom-EventDataXml -Xml $ev.ToXml() } else { @{} }
            $r = ConvertFrom-ActivityEvent -LogName 'System' -ProviderName $ev.ProviderName -EventId $ev.Id -Time $ev.TimeCreated -Message $ev.Message -Data $data
            if ($r) { $null = $rows.Add($r) }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $result.SystemReadable = $false
            $result.Notes += "System log could not be read: $($_.Exception.Message)"
        }
    }

    try {
        foreach ($ev in @(Get-WinEvent -FilterXml ([xml](New-SecurityQueryXml -StartTime $StartTime -EndTime $EndTime)) -ErrorAction Stop)) {
            $r = ConvertFrom-ActivityEvent -LogName 'Security' -ProviderName $ev.ProviderName -EventId $ev.Id -Time $ev.TimeCreated -Data (ConvertFrom-EventDataXml -Xml $ev.ToXml())
            if ($r) { $null = $rows.Add($r) }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            $result.SecurityReadable = $false
            $why = if ($_.Exception.Message -match 'unauthorized|Access is denied|0x80070005') { 'access denied - run elevated or as SYSTEM' } else { $_.Exception.Message }
            $result.Notes += "Security log could not be read: $why"
        }
    }

    $result.Events = @($rows)
    return $result
}

function Format-IntuneSummary {
    # The whole answer in under Intune's 2,048-character output limit: one header, then one
    # line per day, newest first, trimmed from the oldest end if it does not fit. Pure.
    param([object]$Report, [int]$MaxLength = $script:IntuneOutputLimit)

    $d = $Report.Device
    $who = if ($Report.UserName) { " user=$($Report.UserName)" } else { '' }
    $head = New-Object System.Collections.ArrayList
    $null = $head.Add("$($d.ComputerName) | $($d.JoinType) | $($d.UtcOffset) | $($Report.From.ToString('yyyy-MM-dd'))..$($Report.To.ToString('yyyy-MM-dd'))$who")
    $lockWord = switch ($Report.Audit.Key) { 'Recording' { 'recorded' } 'Off' { 'NOT recorded (audit off)' } 'OnButEmpty' { 'on, none yet' } 'NoSecurityLog' { 'Security log unreadable' } default { 'unknown' } }
    $cov = @()
    foreach ($c in @($Report.Coverage)) { if ($c.Oldest) { $cov += "$($c.LogName) from $(([datetime]$c.Oldest).ToString('yyyy-MM-dd'))" } }
    $null = $head.Add("Lock/unlock: $lockWord | $($cov -join ' | ')")
    $null = $head.Add('Day            first-last   up sd sl wk lk ul in')

    $tail = "Full report: $($Report.OutputHint)"
    $lines = foreach ($r in @($Report.Daily | Sort-Object Date -Descending)) {
        if ($r.Events -eq 0) {
            $short = switch -Regex ($r.AllDay) { '^Off' { 'off all day' } '^Asleep' { 'asleep all day' } '^In Modern' { 'standby all day' } '^On' { 'on, no changes' } default { 'no events' } }
            '{0} {1} {2}' -f $r.Date, $r.Day, $short
            continue
        }
        $span = '{0,5}-{1,-5}' -f $r.FirstActivity, $r.LastActivity
        '{0} {1} {2}  {3,2} {4,2} {5,2} {6,2} {7,2} {8,2} {9,2}' -f $r.Date, $r.Day, $span, $r.Startups, $r.Shutdowns, $r.Sleeps, $r.Wakes, $r.Locks, $r.Unlocks, $r.SignIns
    }
    $lines = @($lines)

    $out = New-Object System.Collections.ArrayList
    foreach ($h in $head) { $null = $out.Add($h) }
    $budget = $MaxLength - (($head -join "`n").Length + $tail.Length + 40)
    $used = 0; $shown = 0
    foreach ($l in $lines) {
        if ($used + $l.Length + 1 -gt $budget) { break }
        $null = $out.Add($l); $used += $l.Length + 1; $shown++
    }
    if ($shown -lt $lines.Count) { $null = $out.Add("(+$($lines.Count - $shown) older days in the full report)") }
    $null = $out.Add($tail)
    $text = $out -join "`n"
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) }
    return $text
}

function Get-ReportCss {
    return @'
:root { --bg:#14171b; --panel:#1c2026; --line:#2f3640; --text:#e6e8eb; --muted:#9aa4b0; --accent:#5dade2;
        --ok:#5fc98a; --warn:#e0a458; --bad:#e2686a; --row:#191d22; }
@media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) { --bg:#f5f6f8; --panel:#ffffff; --line:#d8dde3; --text:#1b1f24;
        --muted:#5a6470; --accent:#1f78b4; --ok:#1e8a4c; --warn:#a96410; --bad:#c0392b; --row:#f0f2f5; } }
:root[data-theme="light"] { --bg:#f5f6f8; --panel:#ffffff; --line:#d8dde3; --text:#1b1f24; --muted:#5a6470; --accent:#1f78b4;
        --ok:#1e8a4c; --warn:#a96410; --bad:#c0392b; --row:#f0f2f5; }
* { box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; margin:0 auto; padding:28px 16px; max-width:1180px; line-height:1.5; }
h1 { font-size:26px; margin:0; letter-spacing:-0.01em; } h2 { font-size:17px; margin:28px 0 10px; }
.top { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:flex-end; gap:12px; border-bottom:2px solid var(--accent); padding-bottom:12px; margin-bottom:22px; }
.facts { color:var(--muted); font-size:13px; display:flex; flex-wrap:wrap; gap:6px 18px; } .facts b { color:var(--text); }
.verdict { border-left:5px solid var(--muted); background:var(--panel); padding:12px 18px; margin-bottom:20px; border-radius:0 6px 6px 0; }
.verdict.ok { border-left-color:var(--ok); } .verdict.warn { border-left-color:var(--warn); } .verdict.bad { border-left-color:var(--bad); }
.verdict .line { font-weight:600; font-size:16px; margin:0 0 4px; } .verdict .next { margin:0; color:var(--muted); }
.grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:10px; }
.cell { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:10px 12px; }
.cell .k { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.04em; } .cell .v { font-weight:600; word-break:break-word; }
.tablewrap { overflow-x:auto; border:1px solid var(--line); border-radius:6px; }
table { width:100%; border-collapse:collapse; font-size:13px; background:var(--panel); }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; position:sticky; top:0; background:var(--panel); }
td.n { text-align:right; font-variant-numeric:tabular-nums; } td.t { white-space:nowrap; font-variant-numeric:tabular-nums; }
tr.empty td { color:var(--muted); } tr:hover td { background:var(--row); }
tr.k-Lock td:nth-child(2), tr.k-Shutdown td:nth-child(2), tr.k-Sleep td:nth-child(2), tr.k-SignOut td:nth-child(2) { color:var(--warn); }
tr.k-Unlock td:nth-child(2), tr.k-Startup td:nth-child(2), tr.k-Wake td:nth-child(2), tr.k-SignIn td:nth-child(2) { color:var(--ok); }
tr.k-UnexpectedRestart td:nth-child(2) { color:var(--bad); }
details { background:var(--panel); border:1px solid var(--line); border-radius:6px; margin-bottom:8px; }
summary { cursor:pointer; padding:8px 12px; font-weight:600; } summary:hover { color:var(--accent); }
details .tablewrap { border:0; border-top:1px solid var(--line); border-radius:0; }
.note { color:var(--muted); font-size:13px; }
.toggle { background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:6px; padding:5px 10px; cursor:pointer; font:inherit; font-size:12px; }
.toggle:hover { border-color:var(--accent); }
footer { color:var(--muted); font-size:12px; margin-top:28px; border-top:1px solid var(--line); padding-top:12px; }
'@
}

function New-ActivityHtml {
    # Renders the report. Pure: takes the assembled report object.
    param([object]$Report)

    $d = $Report.Device
    $sb = New-Object System.Text.StringBuilder
    $add = { param($s) $null = $sb.AppendLine($s) }

    & $add '<!DOCTYPE html>'
    & $add '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add "<title>Device Activity - $(ConvertTo-HtmlSafe $d.ComputerName)</title>"
    & $add "<style>$(Get-ReportCss)</style></head><body>"
    & $add "<div class=`"top`"><div><h1>Device Activity - $(ConvertTo-HtmlSafe $d.ComputerName)</h1><div class=`"facts`">"
    & $add "<span><b>$(ConvertTo-HtmlSafe $Report.From.ToString('yyyy-MM-dd HH:mm'))</b> to <b>$(ConvertTo-HtmlSafe $Report.To.ToString('yyyy-MM-dd HH:mm'))</b></span>"
    & $add "<span>Times are <b>$(ConvertTo-HtmlSafe $d.UtcOffset)</b> ($(ConvertTo-HtmlSafe $d.TimeZone))</span>"
    $who = if ($Report.UserName) { ConvertTo-HtmlSafe $Report.UserName } else { 'all users' }
    & $add "<span>User events: <b>$who</b></span><span>Generated <b>$(ConvertTo-HtmlSafe $Report.GeneratedOn)</b></span></div></div>"
    & $add '<button class="toggle" type="button" onclick="var r=document.documentElement;r.dataset.theme=(r.dataset.theme===''light''?''dark'':''light'')">Light / dark</button></div>'

    $a = $Report.Audit
    & $add "<div class=`"verdict $($a.Class)`"><p class=`"line`">$(ConvertTo-HtmlSafe $a.Line)</p><p class=`"next`">$(ConvertTo-HtmlSafe $a.Next)</p></div>"

    & $add '<h2>About this device</h2><div class="grid">'
    $cells = @(
        @{ K='How it is joined'; V=$d.JoinType }
        @{ K='Tenant'; V=$(if ($d.TenantName) { $d.TenantName } else { '-' }) }
        @{ K='Intune agent installed'; V=$(if ($d.IntuneAgent) { 'Yes' } else { 'No' }) }
        @{ K='Windows'; V=$d.OS }
        @{ K='Last started'; V=$(if ($d.LastBoot) { ([datetime]$d.LastBoot).ToString('yyyy-MM-dd HH:mm') } else { '-' }) }
    )
    foreach ($c in @($Report.Coverage)) {
        $v = if ($c.Oldest) { "Back to $(([datetime]$c.Oldest).ToString('yyyy-MM-dd HH:mm'))" } else { 'Could not read' }
        if ($c.MaxSizeMB) { $v += " ($($c.MaxSizeMB) MB max)" }
        $cells += @{ K="$($c.LogName) log reaches"; V=$v }
    }
    foreach ($c in $cells) { & $add "<div class=`"cell`"><div class=`"k`">$(ConvertTo-HtmlSafe $c.K)</div><div class=`"v`">$(ConvertTo-HtmlSafe $c.V)</div></div>" }
    & $add '</div>'
    foreach ($n in @($Report.Notes)) { & $add "<p class=`"note`">$(ConvertTo-HtmlSafe $n)</p>" }

    & $add '<h2>Day by day</h2><div class="tablewrap"><table>'
    & $add '<tr><th>Date</th><th>First sign of use</th><th>Last sign of use</th><th class="n">Started</th><th class="n">Shut down</th><th class="n">Went to sleep</th><th class="n">Woke</th><th class="n">Locked</th><th class="n">Unlocked</th><th class="n">Signed in</th></tr>'
    foreach ($r in @($Report.Daily | Sort-Object Date -Descending)) {
        if ($r.Events -eq 0) {
            & $add "<tr class=`"empty`"><td class=`"t`">$($r.Date) $($r.Day)</td><td colspan=`"9`">$(ConvertTo-HtmlSafe $r.AllDay)</td></tr>"
            continue
        }
        $f = if ($r.FirstActivity) { "<b>$($r.FirstActivity)</b> $(ConvertTo-HtmlSafe $r.FirstWhat)" } else { '-' }
        $l = if ($r.LastActivity)  { "<b>$($r.LastActivity)</b> $(ConvertTo-HtmlSafe $r.LastWhat)" } else { '-' }
        & $add "<tr><td class=`"t`">$($r.Date) $($r.Day)</td><td>$f</td><td>$l</td><td class=`"n`">$($r.Startups)</td><td class=`"n`">$($r.Shutdowns)</td><td class=`"n`">$($r.Sleeps)</td><td class=`"n`">$($r.Wakes)</td><td class=`"n`">$($r.Locks)</td><td class=`"n`">$($r.Unlocks)</td><td class=`"n`">$($r.SignIns)</td></tr>"
    }
    & $add '</table></div>'
    & $add '<p class="note">"Went to sleep" and "Woke" include Modern Standby, which on many laptops starts whenever the screen turns off - the network can stay connected during it.</p>'

    & $add '<h2>Full timeline</h2>'
    $groups = @($Report.Events | Group-Object { ([datetime]$_.Time).ToString('yyyy-MM-dd') } | Sort-Object Name -Descending)
    if ($groups.Count -eq 0) { & $add '<p class="note">No events in this period.</p>' }
    $firstGroup = $true
    foreach ($g in $groups) {
        $open = if ($firstGroup) { ' open' } else { '' }
        $firstGroup = $false
        & $add "<details$open><summary>$($g.Name) $(([datetime]$g.Name).ToString('dddd', [Globalization.CultureInfo]::InvariantCulture)) ($($g.Count))</summary><div class=`"tablewrap`"><table>"
        & $add '<tr><th style="width:90px">Time</th><th style="width:30%">What happened</th><th style="width:22%">Account</th><th>Detail</th><th style="width:150px">Source</th></tr>'
        foreach ($e in @($g.Group | Sort-Object Time)) {
            & $add "<tr class=`"k-$($e.Kind)`"><td class=`"t`">$(([datetime]$e.Time).ToString('HH:mm:ss'))</td><td>$(ConvertTo-HtmlSafe $e.Label)</td><td>$(ConvertTo-HtmlSafe $e.User)</td><td>$(ConvertTo-HtmlSafe $e.Detail)</td><td class=`"t`">$(ConvertTo-HtmlSafe $e.Source)</td></tr>"
        }
        & $add '</table></div></details>'
    }

    & $add '<footer>Read from this device''s own System and Security logs. This shows when the device was started, used, locked and put to sleep - not what anyone was doing on it, and not whether someone was at the desk while it sat unlocked. Lock and unlock (4800/4801) are only recorded when "Audit Other Logon/Logoff Events" is enabled. A day with no rows means nothing changed state that day, not necessarily that the device was off.</footer>'
    & $add '</body></html>'
    return $sb.ToString()
}

if ($LoadFunctionsOnly) { return }

# =============================================================================
# Main
# =============================================================================

$script:Quiet = [bool]$IntuneSummary

$to = if ($PSBoundParameters.ContainsKey('End')) { $End } else { Get-Date }
$from = if ($PSBoundParameters.ContainsKey('Start')) { $Start } else { $to.AddDays(-$DaysBack) }
if ($from -ge $to) { Write-Status FAIL "-Start ($from) must be before -End ($to)."; exit 1 }

# -WhatIf is for the one change this script can make. Decide it here, then turn WhatIf off:
# otherwise it flows into New-Item / Export-Csv and a preview run produces no report.
$applyLockAuditing = $EnableLockAuditing -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable "Audit Other Logon/Logoff Events" (Success)')
$WhatIfPreference = $false

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
    catch { Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"; exit 1 }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $script:Quiet) { Write-Host '' }
Write-Status INFO "Device activity for $env:COMPUTERNAME, $($from.ToString('yyyy-MM-dd HH:mm')) to $($to.ToString('yyyy-MM-dd HH:mm'))."
if (-not $isAdmin) { Write-Status WARN 'Not running elevated: the Security log (sign-in, lock, unlock) will not be readable.' }

$device = Get-DeviceIdentity
Write-Status INFO "$($device.JoinType)$(if ($device.TenantName) { " - $($device.TenantName)" }). Intune agent: $(if ($device.IntuneAgent) { 'installed' } else { 'not found' })."

if ($applyLockAuditing) {
    if (-not $isAdmin) {
        Write-Status FAIL '-EnableLockAuditing needs administrator rights; skipped.'
    } else {
        $out = & (Resolve-SystemExe -Name 'auditpol.exe') /set "/subcategory:$($script:OtherLogonLogoffGuid)" /success:enable 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Status PASS 'Lock and unlock recording turned on. It records from now on; earlier locks cannot be recovered.'
            Write-Status INFO 'If Intune or Group Policy manages audit policy here, it can turn this back off - set it in Intune to make it stick.'
        } else {
            Write-Status FAIL "auditpol could not change the setting: $($out.Trim())"
        }
    }
}

$auditSetting = if ($isAdmin) { Get-LockAuditSetting } else { [PSCustomObject]@{ State='Unknown'; Setting='not elevated' } }

Write-Status INFO 'Reading the System and Security logs ...'
$read = Read-ActivityEvent -StartTime $from -EndTime $to
$coverage = @((Get-LogCoverage -LogName 'System'), (Get-LogCoverage -LogName 'Security'))

$allEvents = @(Repair-ResumeTime -Events (Merge-ActivityEvent -Events $read.Events) | Where-Object { Test-UserMatch -Item $_ -UserName $UserName })
$events = @($allEvents | Where-Object { [datetime]$_.Time -ge $from -and [datetime]$_.Time -le $to })
$lockCount = @($events | Where-Object { $_.EventId -in @(4800, 4801, 4802, 4803) }).Count
$audit = Get-LockAuditReadiness -State $auditSetting.State -LockEventCount $lockCount -SecurityReadable $read.SecurityReadable

# Daily rows start where the System log does: before that, "no events" means "no log".
$systemCoverage = ($coverage | Where-Object { $_.LogName -eq 'System' }).Oldest
$daily = Get-DailySummary -Events $allEvents -From $from -To $to -CoverageStart $systemCoverage

$notes = @($read.Notes)
if ($systemCoverage -and $systemCoverage -gt $from) {
    $notes += "The System log only reaches back to $(([datetime]$systemCoverage).ToString('yyyy-MM-dd HH:mm')); earlier days cannot be shown."
}
$securityCoverage = ($coverage | Where-Object { $_.LogName -eq 'Security' }).Oldest
if ($read.SecurityReadable -and $securityCoverage -and $securityCoverage -gt $from) {
    $notes += "The Security log only reaches back to $(([datetime]$securityCoverage).ToString('yyyy-MM-dd HH:mm')); sign-in, lock and unlock before that are gone."
}

# --- Output ---
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$base = "DeviceActivity_$($env:COMPUTERNAME)_$stamp"
$htmlPath     = Join-Path $OutputPath "$base.html"
$timelineCsv  = Join-Path $OutputPath "${base}_Timeline.csv"
$dailyCsv     = Join-Path $OutputPath "${base}_Daily.csv"
$summaryPath  = Join-Path $OutputPath "${base}_Summary.txt"
$zipPath      = Join-Path $OutputPath "$base.zip"

$report = [PSCustomObject]@{
    Device = $device; From = $from; To = $to; UserName = $UserName; Audit = $audit
    Coverage = $coverage; Daily = $daily; Events = $events; Notes = $notes
    GeneratedOn = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    OutputHint = $(if ($NoZip) { $htmlPath } else { $zipPath })
}

$written = @()
try {
    $events | ForEach-Object {
        [PSCustomObject]@{
            Time = ([datetime]$_.Time).ToString('yyyy-MM-dd HH:mm:ss'); TimeUtc = ([datetime]$_.Time).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            WhatHappened = $_.Label; Kind = $_.Kind; Account = $_.User; AccountSid = $_.UserSid; Detail = $_.Detail; Source = $_.Source
        }
    } | Export-Csv -Path $timelineCsv -NoTypeInformation -Encoding UTF8
    $daily | Export-Csv -Path $dailyCsv -NoTypeInformation -Encoding UTF8
    $written += $timelineCsv, $dailyCsv
    Write-Status PASS "CSV written: $timelineCsv"
} catch {
    Write-Status FAIL "Could not write CSV: $($_.Exception.Message)"
}

try {
    [System.IO.File]::WriteAllText($htmlPath, (New-ActivityHtml -Report $report), (New-Object System.Text.UTF8Encoding($false)))
    $written += $htmlPath
    Write-Status PASS "HTML report written: $htmlPath"
} catch {
    Write-Status FAIL "Could not write HTML report: $($_.Exception.Message)"
}

if ($IncludeRawLogs) {
    # The original logs, so the report can be checked against them and outlives the logs
    # overwriting themselves. wevtutil epl copies the whole log without needing to parse it.
    # https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil
    $logNames = @('System')
    if ($read.SecurityReadable) { $logNames += 'Security' }
    foreach ($log in $logNames) {
        $evtx = Join-Path $OutputPath "${base}_$log.evtx"
        $out = & (Resolve-SystemExe -Name 'wevtutil.exe') epl $log $evtx /ow:true 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $evtx)) {
            $written += $evtx
            Write-Status PASS "$log log exported: $evtx"
        } else {
            Write-Status WARN "Could not export the $log log: $($out.Trim())"
        }
    }
}

# Leave room for the SHA-256 line appended to the Intune output below.
$summaryText = Format-IntuneSummary -Report $report -MaxLength ($script:IntuneOutputLimit - 80)
$deviceLines = @(
    "Join type:   $($device.JoinType)", "Tenant:      $($device.TenantName) $($device.TenantId)", "Device ID:   $($device.DeviceId)",
    "MDM URL:     $($device.MdmUrl)", "Intune agent: $(if ($device.IntuneAgent) { 'installed' } else { 'not found' })",
    "Windows:     $($device.OS)", "Time zone:   $($device.TimeZone) ($($device.UtcOffset))",
    "Audit Other Logon/Logoff (auditpol): $($auditSetting.State) [$($auditSetting.Setting)]",
    "Lock/unlock: $($audit.Line) $($audit.Next)"
)
try {
    [System.IO.File]::WriteAllText($summaryPath, ($summaryText + "`r`n`r`n" + ($deviceLines -join "`r`n") + "`r`n" + (($notes | ForEach-Object { "Note: $_" }) -join "`r`n")), (New-Object System.Text.UTF8Encoding($false)))
    $written += $summaryPath
} catch { }

$zipped = $false
if (-not $NoZip -and $written.Count -gt 0) {
    try {
        Compress-Archive -LiteralPath $written -DestinationPath $zipPath -Force -ErrorAction Stop
        $zipped = $true
        Write-Status PASS "Everything in one file: $zipPath"
    } catch {
        Write-Status WARN "Could not create the zip ($($_.Exception.Message)); the files are in $OutputPath."
    }
}

# SHA-256 of what was handed over, beside it in sha256sum format, so a copy filed with HR or
# legal can be shown to be unchanged since it left the device.
$zipHash = ''
try {
    $targets = if ($zipped) { @($zipPath) } else { @($written) }
    $lines = foreach ($f in $targets) { '{0}  {1}' -f (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant(), (Split-Path -Leaf $f) }
    $hashPath = if ($zipped) { "$zipPath.sha256" } else { Join-Path $OutputPath "${base}_SHA256.txt" }
    [System.IO.File]::WriteAllText($hashPath, (($lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    if ($zipped) {
        $zipHash = ($lines -split '\s+')[0]
        Write-Status PASS "SHA-256 of the zip: $zipHash (saved to $hashPath)"
    } else {
        Write-Status PASS "SHA-256 of each file saved to $hashPath"
    }
} catch {
    Write-Status WARN "Could not compute the SHA-256: $($_.Exception.Message)"
}

$level = switch ($audit.Class) { 'ok' { 'PASS' } 'bad' { 'FAIL' } default { 'WARN' } }
Write-Status $level $audit.Line
foreach ($n in $notes) { Write-Status INFO $n }
$active = @($daily | Where-Object { $_.Events -gt 0 }).Count
Write-Status INFO "$($events.Count) events across $active day(s) with activity."

if ($IntuneSummary) {
    if ($zipHash) { $summaryText += "`nSHA256 $zipHash" }
    Write-Output $summaryText
}
