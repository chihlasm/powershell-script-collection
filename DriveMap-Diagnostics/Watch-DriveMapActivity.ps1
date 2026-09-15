#Requires -Version 5.1

<#
.SYNOPSIS
    Watches a mapped drive letter and captures the moment it disappears, with
    surrounding context, so an intermittent fault can be diagnosed from the
    transition itself rather than from a post-hoc snapshot.

.DESCRIPTION
    This is the WATCHER in the drive-map diagnostics toolkit. Every other tool
    in this toolkit answers "what is the state of this machine right now?" -
    which is exactly the question that CANNOT diagnose an intermittent fault,
    because a snapshot taken after the drive reappears (or before it vanishes
    again) proves nothing. The transition itself - the instant a drive that was
    present becomes absent - is the single most diagnostic artifact available,
    and it exists for only one polling interval before it is gone.

    This script polls the drive letter's live presence every -IntervalSeconds
    and, on every transition (Appeared or Disappeared), captures the
    surrounding context in one pass:
      - Registry-vs-live mount comparison (Compare-MountState, matching
        Export-DriveMapEvidence.ps1's Task 1 registry paths)
      - Group Policy Preferences events (Application log,
        'Group Policy Drive Maps' source) in the surrounding window
      - Group Policy Operational events (a SEPARATE channel - CSE processing,
        not individual preference items) in the surrounding window
      - Recent process-creation (4688) events referencing the drive letter,
        WHERE that audit subcategory is enabled - and an explicit statement
        when it is NOT, because silence from a disabled audit policy is
        indistinguishable from silence meaning "no process touched it"
      - Current network connection profile
      - The last Group Policy refresh time (gpsvc's own record of when
        background processing last ran)

    THE DESIGN POINT: timing discriminates causes that look identical in any
    snapshot.
      - Within 5 minutes of logon              -> implicates a logon script
      - Within 2 minutes of a GP background
        refresh (~90 minutes, by default)      -> implicates policy processing
      - Following sleep/resume or a network
        change, matching neither window        -> implicates reconnect/
                                                   persistence (Unexplained,
                                                   but with next steps)
      - Alternating disappearance/reappearance
        pattern across logons                  -> implicates Fast Logon
                                                   Optimization's every-other-
                                                   logon mechanism (see
                                                   Test-DriveMapLoggingReadiness.ps1's
                                                   Get-EveryOtherLogonRisk)

    Get-DisappearanceTiming checks the logon window FIRST, so a background
    refresh that happens to coincide with logon is still attributed to logon -
    the more specific, more actionable explanation. 'Unexplained' is a REAL
    finding, not a failure to classify: it always carries an Implication naming
    exactly what would narrow it further (turn on process-creation auditing;
    check whether the disappearance follows sleep/resume or a network change).
    An unresolved result must never render as a blank in the timeline.

    Every poll and every context-capture read is wrapped in its own try/catch.
    A watch that dies at hour 3 of an 8-hour run has lost the entire run's
    evidence, so no single unreachable share, denied registry key, or missing
    event log may ever abort the loop.

.PARAMETER DriveLetter
    The drive letter to watch (e.g. "X"). Required.

.PARAMETER IntervalSeconds
    How often to poll the drive letter's live presence, in seconds. Defaults
    to 30. Shorter intervals catch the transition more precisely but increase
    log volume and CPU/event-log query load.

.PARAMETER DurationHours
    How many hours to run before stopping on its own. Defaults to 8 (a work
    shift). A watch intended to run indefinitely via -Install should still set
    this to bound each individual run the scheduled task performs.

.PARAMETER OutputPath
    Folder the timeline file (and, when written, the scheduled-task
    registration log) is written under. Defaults to a "Reports" folder beside
    this script.

.PARAMETER Install
    Switch. Registers a Scheduled Task that runs this script at user logon so
    the watch is running the next time the fault occurs, rather than only
    while a technician has a console open. Does not start a watch itself when
    supplied; run again without -Install to watch interactively.

.PARAMETER LoadFunctionsOnly
    Internal. Dot-sources the functions below without running the
    orchestration body, so Pester can test them directly. Must remain the
    last parameter.

.EXAMPLE
    .\Watch-DriveMapActivity.ps1 -DriveLetter X -IntervalSeconds 30 -DurationHours 8

    Polls the X: drive every 30 seconds for up to 8 hours, appending a
    timestamped timeline entry to .\Reports on every transition, with full
    surrounding context captured at that moment.

.EXAMPLE
    .\Watch-DriveMapActivity.ps1 -DriveLetter S -Install

    Registers a Scheduled Task that starts the watcher at logon, so the next
    occurrence of the fault is captured even if no technician is present when
    it happens.

.NOTES
    Files this script writes are UTF-8 WITH a byte-order mark, written via
    [System.IO.File]::WriteAllText with a UTF8Encoding(true) instance (or the
    corresponding byte-append path for the timeline), because PowerShell 7's
    -Encoding UTF8 omits the BOM while Windows PowerShell 5.1's does not. The
    timeline file is APPENDED to across the life of a long-running watch; the
    BOM is written only once, on file creation, never re-written mid-file.

    Companion tools in this toolkit: Test-DriveMapLoggingReadiness.ps1,
    Export-DriveMapEvidence.ps1.

    REFERENCES
      Event 4688 (process creation), its Subcategory (Audit Process Creation),
      and the Process Command Line field / "Include command line in process
      creation events" policy (command line is empty unless that separate
      policy is also enabled):
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
      Audit Process Creation policy path (Computer Configuration > Policies >
      Windows Settings > Security Settings > Advanced Audit Configuration >
      Detailed Tracking > Audit Process Creation), default Not Configured, and
      the separate "Include command line in process creation events" policy
      under Administrative Templates\System\Audit Process Creation (also
      default Not Configured):
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
      auditpol /get /subcategory syntax and report (/r, CSV) format used to
      determine whether the Process Creation subcategory is currently audited
      on this machine:
        https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get
      GPP preference-item events (Application log, 'Group Policy Drive Maps'
      source) and GP Operational events (Microsoft-Windows-GroupPolicy/
      Operational, a separate channel) are documented in DriveMapReference.psd1
      (Task 1 of this toolkit) and consumed here unchanged; see that file's own
      REFERENCES/inline citations for their sources.
      HKCU\Network stores persistent (reconnect-at-logon) mapped drives - see
      DriveMapReference.psd1 and Export-DriveMapEvidence.ps1's own NOTE ON
      VERIFICATION: the per-subkey value schema (RemotePath/ProviderName/
      ConnectionType/UserName) is not documented on any found Microsoft Learn
      page, only the key's purpose; this script reads it the same defensive
      way Export-DriveMapEvidence.ps1 does, with no -Name filter.
      Get-NetConnectionProfile / NetworkCategory describes whether the network
      is Public/Private/DomainAuthenticated:
        https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile
      Register-ScheduledTask, New-ScheduledTaskTrigger -AtLogOn, and
      New-ScheduledTaskAction parameters used by -Install:
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask
        https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger
      gpsvc records the last Group Policy processing time under
      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History -
      this script's research found no Microsoft Learn page documenting that
      History key's schema, so -LastGpRefresh is treated as best-effort/
      CouldNotCollect rather than asserted as an authoritative read; see the
      Get-LastGroupPolicyRefreshTime function below for exactly what is (and
      is not) claimed about it.
#>
[CmdletBinding()]
param(
    # Not [Parameter(Mandatory)]: -LoadFunctionsOnly must be callable with no
    # other arguments (Pester dot-sources the script that way to load just the
    # functions), so presence is validated in the orchestration body instead,
    # after the LoadFunctionsOnly early-return.
    [ValidatePattern('^[A-Za-z]$')]
    [string]$DriveLetter,

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 30,

    [ValidateRange(1, 168)]
    [int]$DurationHours = 8,

    [string]$OutputPath,

    [switch]$Install,

    # Internal: dot-source the functions without running the orchestration body.
    [switch]$LoadFunctionsOnly
)

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function New-CollectionResult {
    # The three-state contract. A collector that cannot express "I could not look"
    # will silently report a blind machine as a clean one.
    param(
        [Parameter(Mandatory)][ValidateSet('Found','EmptyButValid','CouldNotCollect')][string]$State,
        [object]$Data,
        [string]$Reason
    )
    if ($State -eq 'CouldNotCollect' -and [string]::IsNullOrWhiteSpace($Reason)) {
        throw "A CouldNotCollect result must carry a Reason."
    }
    [PSCustomObject]@{ State = $State; Data = $Data; Reason = $Reason }
}

function Get-TransitionType {
    <#
    .SYNOPSIS
        Classifies a poll-to-poll change in a drive letter's live presence.
    #>
    param(
        [Parameter(Mandatory)][bool]$Previous,
        [Parameter(Mandatory)][bool]$Current
    )
    if ($Previous -and -not $Current) { return 'Disappeared' }
    if (-not $Previous -and $Current) { return 'Appeared' }
    return 'NoChange'
}

function Get-DisappearanceTiming {
    <#
    .SYNOPSIS
        Classifies WHEN a disappearance happened relative to logon and the last
        Group Policy background refresh - the single fact a post-hoc snapshot
        can never recover.

    .DESCRIPTION
        Classification rules, checked in this order (logon FIRST, so a refresh
        that coincides with logon is still attributed to the more specific,
        more actionable explanation):
          1. Within 5 minutes of LogonTime      -> 'AtLogon'
          2. Within 2 minutes of LastGpRefresh
             (only when LastGpRefresh is supplied) -> 'AtGroupPolicyRefresh'
          3. Otherwise                          -> 'Unexplained'

        'Unexplained' is a real, actionable finding - not a failure to
        classify - so it always carries an Implication naming exactly what
        would narrow it further: enabling process-creation (4688) auditing,
        and checking whether the disappearance follows sleep/resume or a
        network change. A caller must never render an unresolved result as a
        blank line.
    #>
    param(
        [Parameter(Mandatory)][datetime]$TransitionTime,
        [Parameter(Mandatory)][datetime]$LogonTime,
        # Deliberately untyped (not [datetime] or [Nullable[datetime]]): a typed nullable
        # parameter here round-trips through PowerShell's argument binder as a boxed
        # object whose subtraction operator PowerShell cannot resolve ("Cannot find an
        # overload for op_Subtraction and the argument count: 2"), confirmed by direct
        # test failure. Accepting [object] and casting explicitly below is the reliable
        # pattern for an optional datetime parameter that must also accept $null.
        [AllowNull()][object]$LastGpRefresh
    )

    $minutesSinceLogon = [Math]::Round(($TransitionTime - $LogonTime).TotalMinutes, 2)

    if ([Math]::Abs($minutesSinceLogon) -le 5) {
        return [PSCustomObject]@{
            Pattern           = 'AtLogon'
            MinutesSinceLogon = $minutesSinceLogon
            Implication       = "The drive vanished within $([Math]::Abs($minutesSinceLogon)) minute(s) of logon. This implicates a LOGON SCRIPT, scheduled task, or Run-key entry running AFTER the drive was mapped (Microsoft's own scenario guide documents exactly this pattern - a healthy Group Policy Preferences trace followed by an unrelated logon script deleting the drive). Check logon scripts, Run/RunOnce keys, and Startup items for a reference to this letter (Export-DriveMapEvidence.ps1 already searches these)."
        }
    }

    if ($null -ne $LastGpRefresh) {
        $lastGpRefreshDate = [datetime]$LastGpRefresh
        $minutesSinceRefresh = [Math]::Abs(($TransitionTime - $lastGpRefreshDate).TotalMinutes)
        if ($minutesSinceRefresh -le 2) {
            return [PSCustomObject]@{
                Pattern           = 'AtGroupPolicyRefresh'
                MinutesSinceLogon = $minutesSinceLogon
                Implication       = "The drive vanished within $([Math]::Round($minutesSinceRefresh, 2)) minute(s) of a Group Policy background refresh. This implicates POLICY PROCESSING - check GP Operational events (4001/4016/5016/5017/5312/7016) and GPP preference-item events for a failure or a competing GPO reapplying a conflicting drive map during this refresh cycle."
            }
        }
    }

    return [PSCustomObject]@{
        Pattern           = 'Unexplained'
        MinutesSinceLogon = $minutesSinceLogon
        Implication       = "The disappearance matches neither the logon window nor a Group Policy refresh window - it does not yet have a cause. To narrow it: (1) enable process-creation (4688) auditing via the 'Audit Process Creation' subcategory so the next occurrence captures which process ran 'net use /delete' or equivalent; (2) check whether this disappearance follows a sleep/resume cycle or a network change (SSID switch, VPN connect/disconnect, cable unplug) - both are common causes of a reconnect/persistence failure that neither logon nor policy timing would explain."
    }
}

function Format-TimelineEntry {
    <#
    .SYNOPSIS
        Formats one timeline entry as a single line, prefixed with the
        repository's log timestamp convention (yyyy-MM-dd HH:mm:ss).
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$Entry
    )
    $timestamp = Get-Date -Date $Entry.Timestamp -Format 'yyyy-MM-dd HH:mm:ss'
    "{0} [{1}] Drive {2}: - {3}" -f $timestamp, $Entry.Transition, $Entry.DriveLetter, $Entry.Detail
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
    throw "-DriveLetter is required (a single letter, e.g. 'X')."
}

function Test-IsLocalComputer {
    param([string]$Name)
    $Name -eq $env:COMPUTERNAME -or $Name -eq 'localhost' -or $Name -eq '.'
}

# Files must be UTF-8 WITH BOM on both PowerShell 5.1 and 7. PowerShell 7's
# -Encoding UTF8 omits the BOM; Windows PowerShell 5.1's does not. Writing bytes
# directly with an explicit BOM makes behavior identical and deterministic on
# both (same approach as Export-DriveMapEvidence.ps1 in this toolkit).
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
function Write-Utf8BomFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8Bom)
}

# Timeline writes are APPENDS across a long-running loop. The BOM must be
# written exactly once, at file creation - re-writing it on every append would
# corrupt the file with an EF BB BF sequence buried mid-content. Track file
# existence to append the BOM-less bytes on every write after the first.
function Add-Utf8BomFileLine {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Line)
    $text = $Line + [Environment]::NewLine
    if (-not (Test-Path -LiteralPath $Path)) {
        # First write: WriteAllText with a BOM-emitting encoding writes the
        # BOM once, at the very start of the file.
        [System.IO.File]::WriteAllText($Path, $text, $script:Utf8Bom)
    } else {
        # Subsequent writes: append raw UTF-8 bytes with NO encoder preamble,
        # so the BOM already at byte 0 is never duplicated or re-written.
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($text)
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
        try {
            $stream.Write($bytes, 0, $bytes.Length)
        } finally {
            $stream.Dispose()
        }
    }
}

function Test-DriveLetterLive {
    <#
    .SYNOPSIS
        Returns $true if the drive letter currently has a live network mount
        in this process's token context, $false otherwise. Never throws - an
        unreadable state is treated as "not present" for polling purposes, but
        is also logged as a WARN so a run of read failures is visible.
    #>
    param([Parameter(Mandatory)][string]$DriveLetter)
    try {
        $conn = Get-CimInstance -ClassName Win32_NetworkConnection -Filter "LocalName='${DriveLetter}:'" -ErrorAction Stop
        return [bool]$conn
    } catch {
        Write-Status WARN "Could not query live mount state for ${DriveLetter}: $($_.Exception.Message)"
        return $false
    }
}

function Get-PersistentMountSnapshot {
    param([Parameter(Mandatory)][string]$RegistryPath, [Parameter(Mandatory)][string]$DriveLetter)
    try {
        $subPath = Join-Path $RegistryPath $DriveLetter
        if (-not (Test-Path -LiteralPath $subPath)) {
            return New-CollectionResult -State 'EmptyButValid' -Data @()
        }
        $props = Get-ItemProperty -LiteralPath $subPath -ErrorAction Stop
        $record = [PSCustomObject]@{
            DriveLetter    = $DriveLetter
            RemotePath     = $props.RemotePath
            ProviderName   = $props.ProviderName
            ConnectionType = $props.ConnectionType
            UserName       = $props.UserName
        }
        New-CollectionResult -State 'Found' -Data $record
    } catch {
        New-CollectionResult -State 'CouldNotCollect' -Reason "Could not read HKCU:\Network\${DriveLetter}: $($_.Exception.Message)"
    }
}

function Get-ProcessCreationAuditState {
    <#
    .SYNOPSIS
        Reports whether the 'Process Creation' audit subcategory is currently
        enabled, using auditpol /get - the supported, documented way to query
        subcategory-level audit policy.
        https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get

    .DESCRIPTION
        auditpol has no -ComputerName equivalent; it only reports local policy.
        Remote checks must run it via Invoke-Command instead. This function
        NEVER returns a silent "not enabled" for an unreadable state - an
        auditpol failure is CouldNotCollect, distinct from a confirmed-disabled
        subcategory, because the two must never be presented the same way to a
        reader relying on this to interpret an empty 4688 capture.
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    $scriptBlock = {
        $csv = auditpol /get /subcategory:"Process Creation" /r 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol exited with code $LASTEXITCODE`: $csv"
        }
        $parsed = $csv | ConvertFrom-Csv
        if (-not $parsed) { throw 'auditpol produced no parsable output.' }
        $parsed[0]
    }
    try {
        $row = if (Test-IsLocalComputer -Name $ComputerName) {
            & $scriptBlock
        } else {
            Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock $scriptBlock
        }
        # auditpol /r's inclusion-setting column is literally named "Inclusion Setting"
        # per its documented report format; values include 'Success', 'Success and Failure',
        # 'Failure', and 'No Auditing'.
        # https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get
        $setting = $row.'Inclusion Setting'
        $enabled = $setting -and $setting -ne 'No Auditing'
        New-CollectionResult -State 'Found' -Data ([PSCustomObject]@{ Enabled = $enabled; Setting = $setting })
    } catch {
        New-CollectionResult -State 'CouldNotCollect' -Reason "Could not determine Process Creation audit state on ${ComputerName}: $($_.Exception.Message)"
    }
}

function Get-RecentProcessCreationEvents {
    <#
    .SYNOPSIS
        Captures recent 4688 (process creation) Security-log events whose
        command line or new-process name references the watched drive letter,
        within a time window around a transition. Only called after confirming
        the Process Creation subcategory is enabled - see Get-ProcessCreationAuditState.
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][datetime]$WindowStart,
        [Parameter(Mandatory)][datetime]$WindowEnd
    )
    try {
        $filter = @{ LogName = 'Security'; Id = 4688; StartTime = $WindowStart; EndTime = $WindowEnd }
        $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
        $letterPattern = [regex]::Escape("${DriveLetter}:")
        $rows = @($events | Where-Object { $_.Message -match $letterPattern } | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                Message     = $_.Message
            }
        })
        if ($rows.Count -eq 0) {
            New-CollectionResult -State 'EmptyButValid' -Data @()
        } else {
            New-CollectionResult -State 'Found' -Data $rows
        }
    } catch [Exception] {
        if ($_.Exception.Message -match 'No events were found') {
            return New-CollectionResult -State 'EmptyButValid' -Data @()
        }
        New-CollectionResult -State 'CouldNotCollect' -Reason "Could not query 4688 events on ${ComputerName}: $($_.Exception.Message)"
    }
}

function Get-WindowedEvents {
    <#
    .SYNOPSIS
        Generic helper: captures events from a named log within a time window,
        for the GPP and GP Operational capture steps, each wrapped so a
        failure on one log never blocks the other.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$LogName,
        [string]$ProviderName,
        [Parameter(Mandatory)][datetime]$WindowStart,
        [Parameter(Mandatory)][datetime]$WindowEnd
    )
    try {
        $filter = @{ LogName = $LogName; StartTime = $WindowStart; EndTime = $WindowEnd }
        if ($ProviderName) { $filter['ProviderName'] = $ProviderName }
        $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop
        $rows = @($events | ForEach-Object {
            [PSCustomObject]@{ TimeCreated = $_.TimeCreated; Id = $_.Id; Message = $_.Message }
        })
        if ($rows.Count -eq 0) {
            New-CollectionResult -State 'EmptyButValid' -Data @()
        } else {
            New-CollectionResult -State 'Found' -Data $rows
        }
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return New-CollectionResult -State 'EmptyButValid' -Data @()
        }
        New-CollectionResult -State 'CouldNotCollect' -Reason "Could not query '$LogName' on ${ComputerName}: $($_.Exception.Message)"
    }
}

function Get-LastGroupPolicyRefreshTime {
    <#
    .SYNOPSIS
        Best-effort lookup of the last Group Policy background refresh time,
        used only to feed Get-DisappearanceTiming's AtGroupPolicyRefresh check.

    .DESCRIPTION
        This toolkit's research found no learn.microsoft.com page documenting
        the schema of HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group
        Policy\History (or an equivalent supported API) as an authoritative,
        timestamped "last background refresh" value. Per this toolkit's
        verification rule, that is NOT presented here as a verified Microsoft
        fact. Instead, this function falls back to the most recent
        DOCUMENTED GP Operational event that marks the end of a processing
        cycle (5016, "CSE processing completed successfully" -
        DriveMapReference.psd1, itself sourced from
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
        within the lookback window, and reports CouldNotCollect - never a
        guessed or silently-null timestamp - when no such event exists in that
        window. A caller must treat a CouldNotCollect result exactly like "no
        LastGpRefresh available", never like "refresh did not happen".
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$GpOperationalLogName,
        [Parameter(Mandatory)][datetime]$LookbackStart
    )
    try {
        $filter = @{ LogName = $GpOperationalLogName; Id = 5016; StartTime = $LookbackStart }
        $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $filter -ErrorAction Stop |
            Sort-Object TimeCreated -Descending
        if (-not $events) {
            return New-CollectionResult -State 'EmptyButValid' -Data $null
        }
        New-CollectionResult -State 'Found' -Data ($events | Select-Object -First 1).TimeCreated
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return New-CollectionResult -State 'EmptyButValid' -Data $null
        }
        New-CollectionResult -State 'CouldNotCollect' -Reason "Could not determine last Group Policy refresh time on ${ComputerName}: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# -Install: register a Scheduled Task so the watch is running the next time
# the fault occurs, rather than only while a technician has a console open.
# https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask
# https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger
# ---------------------------------------------------------------------------
if ($Install) {
    try {
        Import-Module ScheduledTasks -ErrorAction Stop
    } catch {
        Write-Status FAIL "The ScheduledTasks module is not available: $($_.Exception.Message)"
        exit 1
    }

    $scriptPath = $MyInvocation.MyCommand.Path
    $taskName   = "DriveMapWatcher_$DriveLetter"
    $arguments  = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DriveLetter $DriveLetter -IntervalSeconds $IntervalSeconds -DurationHours $DurationHours"
    if ($OutputPath) { $arguments += " -OutputPath `"$OutputPath`"" }

    try {
        $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Drive-map diagnostics watcher for ${DriveLetter}: (drivemap-diagnostics toolkit)" -Force -ErrorAction Stop | Out-Null
        Write-Status PASS "Scheduled task '$taskName' registered - the watcher will start at the next logon."
    } catch {
        Write-Status FAIL "Could not register scheduled task '$taskName': $($_.Exception.Message)"
        exit 1
    }
    return
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
Write-Status INFO "Starting drive-map watcher for ${DriveLetter}: (poll every ${IntervalSeconds}s, for up to $DurationHours hour(s))."

$refPath = Join-Path $PSScriptRoot 'DriveMapReference.psd1'
try {
    $ref = Import-PowerShellDataFile -Path $refPath -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load DriveMapReference.psd1: $($_.Exception.Message)"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $scriptRoot 'Reports'
}
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    }
} catch {
    Write-Status FAIL "Could not create output folder ${OutputPath}: $($_.Exception.Message)"
    exit 1
}

$stamp        = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$timelinePath = Join-Path $OutputPath "DriveMapWatch_${DriveLetter}_$stamp.log"
Write-Status INFO "Timeline file: $timelinePath"

$computerName = $env:COMPUTERNAME

# Logon time for the current session, used by Get-DisappearanceTiming. Falls
# back to process start time if the logon time cannot be determined, which is
# reported explicitly rather than silently assumed.
try {
    $logonTime = (Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop |
        Where-Object { $_.LogonType -in 2, 10, 11 } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1).StartTime
    if (-not $logonTime) { throw 'No interactive/RemoteInteractive/CachedInteractive logon session was found.' }
} catch {
    Write-Status WARN "Could not determine logon time via Win32_LogonSession ($($_.Exception.Message)); falling back to this process's start time, which understates time-since-logon."
    $logonTime = (Get-Process -Id $PID).StartTime
}
Write-Status INFO "Using logon time: $(Get-Date -Date $logonTime -Format 'yyyy-MM-dd HH:mm:ss')"

# Process-creation audit state is checked ONCE up front (not on every
# transition) - it changes rarely, and a per-transition auditpol call would
# add avoidable failure surface to the hot path of the loop.
$auditState = Get-ProcessCreationAuditState -ComputerName $computerName
if ($auditState.State -eq 'Found' -and $auditState.Data.Enabled) {
    Write-Status PASS "Process Creation auditing is enabled (Inclusion Setting: $($auditState.Data.Setting)). 4688 events referencing ${DriveLetter}: will be captured on each transition."
} elseif ($auditState.State -eq 'Found') {
    Write-Status WARN "Process Creation auditing is NOT enabled (Inclusion Setting: $($auditState.Data.Setting)). No process-creation events can be captured for this run - an empty 4688 capture in the timeline means 'not audited', NOT 'no process touched the drive'. Enable it via Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking > Audit Process Creation to capture this evidence on a future run."
} else {
    Write-Status WARN "Could not determine whether Process Creation auditing is enabled: $($auditState.Reason) Any 4688 capture in the timeline is UNRELIABLE until this is confirmed manually (auditpol /get /subcategory:'Process Creation')."
}

# ---------------------------------------------------------------------------
# Context capture on a transition. Every read here is independently wrapped -
# see the individual functions above - so a failure on any single source
# never blocks the others or aborts the loop.
# ---------------------------------------------------------------------------
function Get-TransitionContext {
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][hashtable]$Reference,
        [Parameter(Mandatory)][datetime]$Now,
        [Parameter(Mandatory)][PSCustomObject]$AuditState
    )
    $windowStart = $Now.AddMinutes(-15)
    $windowEnd   = $Now.AddMinutes(1)

    $lines = New-Object System.Collections.Generic.List[string]

    $persistent = Get-PersistentMountSnapshot -RegistryPath $Reference.RegistryPaths.PersistentMounts -DriveLetter $DriveLetter
    switch ($persistent.State) {
        'Found'           { $lines.Add("Persistent mount (HKCU:\Network\$DriveLetter): RemotePath=$($persistent.Data.RemotePath)") }
        'EmptyButValid'   { $lines.Add("Persistent mount (HKCU:\Network\$DriveLetter): none registered.") }
        'CouldNotCollect' { $lines.Add("Persistent mount: could not read - $($persistent.Reason)") }
    }

    $gpp = Get-WindowedEvents -ComputerName $ComputerName -LogName $Reference.GppLogName -ProviderName $Reference.GppLogSource -WindowStart $windowStart -WindowEnd $windowEnd
    switch ($gpp.State) {
        'Found'           { $lines.Add("GPP events in window: $($gpp.Data.Count) (see IDs $((@($gpp.Data | ForEach-Object { $_.Id }) | Sort-Object -Unique) -join ','))") }
        'EmptyButValid'   { $lines.Add('GPP events in window: none.') }
        'CouldNotCollect' { $lines.Add("GPP events: could not read - $($gpp.Reason)") }
    }

    $gpOperational = Get-WindowedEvents -ComputerName $ComputerName -LogName $Reference.GpOperationalLogName -WindowStart $windowStart -WindowEnd $windowEnd
    switch ($gpOperational.State) {
        'Found'           { $lines.Add("GP Operational events in window: $($gpOperational.Data.Count) (see IDs $((@($gpOperational.Data | ForEach-Object { $_.Id }) | Sort-Object -Unique) -join ','))") }
        'EmptyButValid'   { $lines.Add('GP Operational events in window: none.') }
        'CouldNotCollect' { $lines.Add("GP Operational events: could not read - $($gpOperational.Reason)") }
    }

    if ($AuditState.State -eq 'Found' -and $AuditState.Data.Enabled) {
        $proc = Get-RecentProcessCreationEvents -ComputerName $ComputerName -DriveLetter $DriveLetter -WindowStart $windowStart -WindowEnd $windowEnd
        switch ($proc.State) {
            'Found'           { $lines.Add("4688 events referencing ${DriveLetter}: $($proc.Data.Count) found in window.") }
            'EmptyButValid'   { $lines.Add("4688 events referencing ${DriveLetter}: none in window (auditing IS enabled, so this is a confirmed absence).") }
            'CouldNotCollect' { $lines.Add("4688 events: could not read - $($proc.Reason)") }
        }
    } else {
        $lines.Add('4688 process-creation events: NOT CAPTURED - Process Creation auditing is not confirmed enabled on this machine. An empty result here would NOT mean "no process touched the drive."')
    }

    try {
        $netProfile = Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" }
        $lines.Add("Network profile: $($netProfile -join '; ')")
    } catch {
        $lines.Add("Network profile: could not read - $($_.Exception.Message)")
    }

    $lines -join ' | '
}

# ---------------------------------------------------------------------------
# Poll loop. Every iteration is defensive: a single bad poll or a single
# failed context capture must never abort a long-running watch.
# ---------------------------------------------------------------------------
$endTime = (Get-Date).AddHours($DurationHours)
$previousState = Test-DriveLetterLive -DriveLetter $DriveLetter
Write-Status INFO "Initial state: ${DriveLetter}: is $(if ($previousState) { 'present' } else { 'absent' })."

$transitionCount = 0
while ((Get-Date) -lt $endTime) {
    try {
        Start-Sleep -Seconds $IntervalSeconds
    } catch {
        Write-Status WARN "Sleep interrupted: $($_.Exception.Message)"
    }

    try {
        $now = Get-Date
        $currentState = Test-DriveLetterLive -DriveLetter $DriveLetter
        $transition = Get-TransitionType -Previous $previousState -Current $currentState

        if ($transition -ne 'NoChange') {
            $transitionCount++
            Write-Status $(if ($transition -eq 'Disappeared') { 'FAIL' } else { 'PASS' }) "Transition detected: ${DriveLetter}: $transition at $(Get-Date -Date $now -Format 'yyyy-MM-dd HH:mm:ss')."

            $lastGpRefreshResult = Get-LastGroupPolicyRefreshTime -ComputerName $computerName -GpOperationalLogName $ref.GpOperationalLogName -LookbackStart $now.AddHours(-3)
            $lastGpRefresh = if ($lastGpRefreshResult.State -eq 'Found') { $lastGpRefreshResult.Data } else { $null }

            $detail = Get-TransitionContext -DriveLetter $DriveLetter -ComputerName $computerName -Reference $ref -Now $now -AuditState $auditState

            if ($transition -eq 'Disappeared') {
                try {
                    $timing = Get-DisappearanceTiming -TransitionTime $now -LogonTime $logonTime -LastGpRefresh $lastGpRefresh
                    $detail = "Pattern=$($timing.Pattern) (MinutesSinceLogon=$($timing.MinutesSinceLogon)); Implication: $($timing.Implication) || $detail"
                } catch {
                    Write-Status WARN "Could not classify disappearance timing: $($_.Exception.Message)"
                    $detail = "Pattern=CouldNotClassify; Implication: timing classification failed ($($_.Exception.Message)). || $detail"
                }
            }

            try {
                $entry = [PSCustomObject]@{
                    Timestamp   = $now
                    Transition  = $transition
                    DriveLetter = $DriveLetter
                    Detail      = $detail
                }
                $line = Format-TimelineEntry -Entry $entry
                Add-Utf8BomFileLine -Path $timelinePath -Line $line
            } catch {
                Write-Status FAIL "Could not write timeline entry (transition itself is NOT lost - it was: $transition at $now): $($_.Exception.Message)"
            }
        }

        $previousState = $currentState
    } catch {
        Write-Status WARN "Poll iteration failed, continuing: $($_.Exception.Message)"
    }
}

Write-Status PASS "Watch complete. $transitionCount transition(s) recorded. Timeline: $timelinePath"
