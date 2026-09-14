#Requires -Version 5.1

<#
.SYNOPSIS
    Checks whether this machine can produce trustworthy evidence for a drive-map
    investigation before any evidence is collected.

.DESCRIPTION
    Group Policy Preferences (GPP) informational events - the events a drive-map
    investigation depends on - are only written to the Application log when the
    "Logging and tracing" policy is enabled. It is OFF by default. Without this check,
    an empty evidence report and a perfectly healthy machine look identical: both produce
    no events, for opposite reasons.

    This script is the GATE. Run it before Get-DriveMapEvidence.ps1 or any other
    collector in this toolkit. It answers three questions that determine whether an
    empty result can be trusted:

      1. Is GPP logging enabled, so preference-item events are written at all?
      2. Is GPP tracing enabled, so trace files exist to read?
      3. Does the Application log retain events far enough back to cover the fault?

    If any of these is "no", collecting now produces a report that CANNOT be
    distinguished from a healthy machine. The script says so explicitly rather than
    printing a clean-looking empty summary.

    It also reports on two configuration conditions that are themselves among the most
    common root causes of an intermittently-missing mapped drive, so this script
    frequently resolves the investigation outright without further collection:

      * Fast Logon Optimization + a Replace-mode drive map without "Always wait for the
        network at computer startup and logon" - the Drive Maps client-side extension
        (CSE) only applies during synchronous Group Policy processing, so the map can
        apply on only every OTHER logon. See Get-EveryOtherLogonRisk.
      * EnableLinkedConnections not set to 1 under UAC - drive mappings are per-session
        symbolic links, so a drive genuinely does not appear in an elevated session
        unless this is set. See Get-SplitTokenRisk.

    The registry value name(s) that the "Logging and tracing" ADMX policy actually
    writes are not documented on any Microsoft Learn page this script's research could
    find - only the GPO UI path and its effect are documented. Rather than guess at a
    value name and silently read or write nothing while reporting success, this script
    reports that state as CouldNotCollect with an explicit reason, and corroborates it
    with a documented, indirect signal instead: the presence and freshness of GPP trace
    files at their documented default location. This script is READ-ONLY: with
    -EnableLogging it prints step-by-step Group Policy instructions for turning logging
    on and reproducing the fault, but it does not perform an unverified registry write.

.PARAMETER ComputerName
    The computer to check. Defaults to the local computer. Remote registry and event log
    reads are used so this can be run against a user's machine from an admin workstation.

.PARAMETER DriveLetter
    Optional. The drive letter reported missing (e.g. "X"), included in the report for
    context. Does not change what is collected.

.PARAMETER FaultAgeHours
    How many hours ago the drive was last known to be missing. Used to judge whether the
    Application log's retention reaches back far enough to have captured it. Defaults to
    24.

.PARAMETER EnableLogging
    Switch. The underlying registry value name(s) for the GPP "Logging and tracing"
    policy are not documented by Microsoft, so this script does not perform an
    unverified registry write. When supplied, it instead prints step-by-step Group
    Policy instructions for turning logging on and reproducing the fault so real
    evidence can be captured on the next occurrence. Without this switch (or with it)
    the script changes nothing on the target - it is always read-only.

.PARAMETER OutputPath
    Folder for the readiness report. Defaults to a "Reports" folder beside this script.

.PARAMETER LoadFunctionsOnly
    Internal. Dot-sources the functions below without running the orchestration body, so
    Pester can test them directly. Must remain the last parameter.

.EXAMPLE
    .\Test-DriveMapLoggingReadiness.ps1 -DriveLetter X

    Checks the local machine's logging readiness for an investigation into a missing
    X: drive, using the default 24-hour fault-age assumption.

.EXAMPLE
    .\Test-DriveMapLoggingReadiness.ps1 -ComputerName WKS042 -DriveLetter S -FaultAgeHours 72 -EnableLogging

    Checks WKS042 and prints step-by-step Group Policy instructions for enabling GPP
    logging and reproducing the fault, so the NEXT occurrence can be captured.

.NOTES
    Always read-only, including with -EnableLogging - the underlying registry value
    name(s) for GPP "Logging and tracing" are not documented by Microsoft, so this
    script never attempts to write them; it prints Group Policy instructions instead.
    Every registry and event-log read is wrapped in its own try/catch so one unreadable
    value cannot abort the run - a value that cannot be read is reported as
    CouldNotCollect, never silently treated as absent or disabled.

    Companion tools in this toolkit: Get-DriveMapEvidence.ps1, Get-DriveMapGpoTimeline.ps1,
    Get-DriveMapVerdict.ps1, New-DriveMapHtmlReport.ps1.

    REFERENCES
      GPP informational events are only logged when "Logging and tracing" is enabled;
      events are written to the Application log. This page documents the GPO path but
      not the underlying registry value name, which is why this script reports that
      state as CouldNotCollect rather than reading a guessed value:
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
      Drive Maps CSE / NoBackgroundPolicy and the every-other-logon mechanism with Fast
      Logon Optimization:
        https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
      Drive Maps CSE registration path (Windows NT\CurrentVersion\Winlogon\GPExtensions),
      NoBackgroundPolicy semantics, and confirmation that the Drive Maps preference
      extension requires synchronous processing and is NOT called during background
      processing:
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581924(v=ws.11)
        https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj573586(v=ws.11)
      EnableLinkedConnections and UAC split-token mapped-drive visibility:
        https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
      ConsentPromptBehaviorAdmin registry value and data meanings (1 and 3 = prompt for
      credentials; 0, 2, 4, 5 = prompt for consent or no prompt):
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4
      GPP trace file default location (%COMMONAPPDATA%\GroupPolicy\Preference\Trace,
      where %COMMONAPPDATA% is a variable recognized only by the Preference CSEs and
      expands to %SYSTEMDRIVE%\ProgramData on Vista/Server 2008 and later). Used only as
      CORROBORATING evidence for tracing state, never as proof - the location can be
      changed by policy:
        https://learn.microsoft.com/en-us/archive/blogs/askds/enabling-group-policy-preferences-debug-logging-using-the-rsat
#>
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,

    [string]$DriveLetter,

    [int]$FaultAgeHours = 24,

    [switch]$EnableLogging,

    [string]$OutputPath,

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

function Test-BlindCondition {
    param(
        [Parameter(Mandatory)][bool]$GppLoggingEnabled,
        [Parameter(Mandatory)][bool]$TracingEnabled,
        [Parameter(Mandatory)][timespan]$OldestEventAge,
        [Parameter(Mandatory)][timespan]$FaultAge
    )
    $reasons = New-Object System.Collections.Generic.List[string]

    # GPP informational events are only written when the Logging and tracing policy is
    # enabled - it is off by default, so silence proves nothing.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
    if (-not $GppLoggingEnabled) {
        $reasons.Add('Group Policy Preferences logging is disabled - no preference-item events were ever recorded.')
    }
    if (-not $TracingEnabled) {
        $reasons.Add('Group Policy Preferences tracing is disabled - no trace files exist to read.')
    }
    if ($OldestEventAge -lt $FaultAge) {
        # NOTE: wording deliberately includes "reach back" verbatim (not "reaches back")
        # because the regression test matches 'retention|reach back' literally.
        $reasons.Add(("The Application log's retention does not reach back far enough - it only reaches back {0:N1} hours, but the fault is {1:N1} hours old, so the evidence has already rolled off." -f $OldestEventAge.TotalHours, $FaultAge.TotalHours))
    }

    [PSCustomObject]@{
        IsBlind      = ($reasons.Count -gt 0)
        BlindReasons = $reasons.ToArray()
    }
}

function Get-EveryOtherLogonRisk {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][bool]$FastLogonOptimization,
        [Parameter(Mandatory)][bool]$AlwaysWaitForNetwork
    )
    # The Drive Maps CSE sets NoBackgroundPolicy=1 (never called on background refresh)
    # and only applies preference items when Group Policy processes SYNCHRONOUSLY. Fast
    # Logon Optimization makes logon asynchronous, so the CSE declines to apply, requests
    # synchronous processing for the NEXT logon, and applies only then - the drive maps
    # every other logon.
    # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
    $atRisk = $FastLogonOptimization -and (-not $AlwaysWaitForNetwork)

    $explanation = if ($atRisk) {
        "Fast Logon Optimization makes logon processing asynchronous. The Drive Maps extension only applies settings during synchronous processing and is never called during background refresh, so with the '$Action' action the drive can map on only every other logon. This looks exactly like a drive that randomly disappears."
    } else {
        "Group Policy is configured to process synchronously at logon, so the Drive Maps extension is called every logon."
    }

    # Microsoft explicitly does NOT recommend setting NoBackgroundPolicy to 0, and notes
    # it does not reliably guarantee application. Never offer it as a remediation.
    $remediations = if ($atRisk) {
        @(
            "Enable 'Always wait for the network at computer startup and logon' (Computer Configuration\Policies\Administrative Templates\System\Logon). This forces synchronous foreground processing every logon.",
            "Or change the drive map to the Create action with Reconnect enabled, so the mapping persists between sessions."
        )
    } else { @() }

    [PSCustomObject]@{ AtRisk = $atRisk; Explanation = $explanation; Remediations = $remediations }
}

function Get-SplitTokenRisk {
    param(
        [object]$EnableLinkedConnections,
        [Parameter(Mandatory)][bool]$UacPromptsForCredentials
    )
    # With UAC enabled the system creates two linked logon sessions. Drive mappings are
    # symbolic link (DosDevices) objects that are per-session and not shared, so a drive
    # mapped in the filtered token is genuinely absent from the elevated one.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
    $isSet  = ($null -ne $EnableLinkedConnections -and [int]$EnableLinkedConnections -eq 1)
    $atRisk = -not $isSet

    $explanation = if ($atRisk) {
        "EnableLinkedConnections is not set to 1. With UAC enabled, drives mapped in the standard-user session are not visible to elevated processes. A drive reported as missing only from an administrative command prompt is a visibility artifact, not a mapping failure."
    } else {
        "EnableLinkedConnections is set to 1, so mapped drives are written to both linked logon sessions."
    }

    if ($UacPromptsForCredentials) {
        # Documented caveat: prompting for credentials creates an additional session in
        # which previously created symbolic links are unavailable.
        $explanation += " Note: UAC is configured to prompt for credentials, which creates an additional logon session where previously created drive mappings are unavailable - EnableLinkedConnections does not fully resolve this configuration."
    }

    $remediations = if ($atRisk) {
        @("Set EnableLinkedConnections (DWORD) to 1 under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, then restart.")
    } else { @() }

    [PSCustomObject]@{ AtRisk = $atRisk; Explanation = $explanation; Remediations = $remediations }
}

function Test-TraceEvidenceCoversFault {
    # Trace-file existence alone is not evidence tracing is CURRENTLY on - a file left
    # over from a prior configuration can sit in the default folder indefinitely. The
    # same "does the evidence reach back to the fault?" reasoning already applied to
    # Application log retention (see Test-BlindCondition) must also apply here: a trace
    # file older than the fault cannot contain evidence of it, so it cannot corroborate
    # that tracing was on when the fault occurred.
    param(
        [Parameter(Mandatory)][timespan]$TraceAge,
        [Parameter(Mandatory)][timespan]$FaultAge
    )
    $TraceAge -le $FaultAge
}

if ($LoadFunctionsOnly) { return }

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

Write-Status INFO "Checking drive-map logging readiness on $ComputerName ..."
if ($DriveLetter) { Write-Status INFO "Reported missing drive: $DriveLetter`:" }

$refPath = Join-Path $PSScriptRoot 'DriveMapReference.psd1'
try {
    $ref = Import-PowerShellDataFile -Path $refPath -ErrorAction Stop
} catch {
    Write-Status FAIL "Could not load DriveMapReference.psd1: $($_.Exception.Message)"
    exit 1
}

$faultAge = [timespan]::FromHours($FaultAgeHours)

# ---------------------------------------------------------------------------
# Helper: read one registry value on $ComputerName, wrapped so a single failure
# (unreachable machine, missing key, missing value, access denied) never aborts the run.
# ---------------------------------------------------------------------------
function Read-RemoteRegistryValue {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq 'localhost' -or $ComputerName -eq '.') {
            if (-not (Test-Path -LiteralPath $Path)) {
                return New-CollectionResult -State 'CouldNotCollect' -Reason "Registry key '$Path' does not exist on $ComputerName."
            }
            $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return New-CollectionResult -State 'Found' -Data $item.$Name
        } else {
            $value = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
                param($p, $n)
                if (-not (Test-Path -LiteralPath $p)) { return $null }
                (Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction SilentlyContinue).$n
            } -ArgumentList $Path, $Name
            if ($null -eq $value) {
                return New-CollectionResult -State 'CouldNotCollect' -Reason "Value '$Name' was not found under '$Path' on $ComputerName."
            }
            return New-CollectionResult -State 'Found' -Data $value
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "Value '$Name' was not found under '$Path' on $ComputerName."
    } catch {
        return New-CollectionResult -State 'CouldNotCollect' -Reason "Could not read '$Name' under '$Path' on ${ComputerName}: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 1. GPP Logging state.
#
# Microsoft documents that this ADMX-backed policy (Computer Configuration\Policies\
# Administrative Templates\System\Group Policy\Logging and tracing) must be enabled for
# GPP informational events to be written at all, and gives the GPO path, but does NOT
# document the underlying registry value name(s) it writes on any currently reachable
# Microsoft Learn page.
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
#
# Per this toolkit's own rule (never assert a fact that cannot be cited), this script
# does not guess at that value name. It reports GPP logging state as CouldNotCollect
# with an explicit instruction to confirm manually, rather than reading an unverified
# value and risking a false PASS or false FAIL - exactly the confident-plausible-wrong-
# answer failure this toolkit exists to prevent. Tracing state gets a separate,
# corroborated (not guessed) treatment immediately below.
# ---------------------------------------------------------------------------
$gppLoggingResult = New-CollectionResult -State 'CouldNotCollect' `
    -Reason "The registry value names written by the Logging and tracing policy are not documented by Microsoft, so this cannot be read reliably. Confirm via 'gpresult /h' or the Group Policy editor at Computer Configuration\Policies\Administrative Templates\System\Group Policy\Logging and tracing on $ComputerName."

Write-Status WARN $gppLoggingResult.Reason

# For the blind-condition calculation, an unverifiable read is never treated as
# "confirmed enabled" - the CouldNotCollect contract requires erring toward telling the
# operator to verify, never toward a silent, unearned PASS.
$gppLoggingEnabled = $false

# ---------------------------------------------------------------------------
# Tracing corroboration: Microsoft does NOT document the registry value name for the
# tracing policy, but it DOES document where trace files land by default -
# %COMMONAPPDATA%\GroupPolicy\Preference\Trace, where %COMMONAPPDATA% is a variable
# recognized only by the Preference CSEs and expands to %SYSTEMDRIVE%\ProgramData on
# Windows Vista/Server 2008 and later (%SYSTEMDRIVE%\Documents and Settings\All
# Users\Application Data on XP/2003).
# https://learn.microsoft.com/en-us/archive/blogs/askds/enabling-group-policy-preferences-debug-logging-using-the-rsat
#
# This is used ONLY as corroborating evidence, never as proof: the policy allows
# relocating the trace path, so an empty folder does not prove tracing is off, and a
# populated one does not prove the CURRENT policy has tracing on (files could be stale
# from a prior configuration). Both directions are reported with that caveat attached -
# this must never collapse into a definitive "tracing is disabled" or "enabled".
# ---------------------------------------------------------------------------
$traceFolder = if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq 'localhost' -or $ComputerName -eq '.') {
    Join-Path $env:ProgramData 'GroupPolicy\Preference\Trace'
} else {
    "\\$ComputerName\C$\ProgramData\GroupPolicy\Preference\Trace"
}

$tracingEnabled = $false
try {
    if (Test-Path -LiteralPath $traceFolder) {
        $traceFiles = @(Get-ChildItem -LiteralPath $traceFolder -File -ErrorAction Stop)
        if ($traceFiles.Count -gt 0) {
            $newest = $traceFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $traceAge = (Get-Date) - $newest.LastWriteTime
            if (Test-TraceEvidenceCoversFault -TraceAge $traceAge -FaultAge $faultAge) {
                $tracingEnabled = $true
                Write-Status INFO ("Trace files exist at the default location ({0}); newest was modified {1:N1} hours ago, which covers the reported {2:N1}-hour-old fault. This is CORROBORATING evidence that tracing is on, drawn from the files' existence - not a read of the policy itself, and the path may have been relocated by policy." -f $traceFolder, $traceAge.TotalHours, $faultAge.TotalHours)
            } else {
                Write-Status WARN ("Trace files exist at the default location ({0}), but the newest was modified {1:N1} hours ago - older than the reported {2:N1}-hour-old fault. These files predate the fault, so they cannot contain evidence of it; tracing may have been on at some point but does not appear to have run since. This is indirect evidence only - the trace path may have been relocated by policy." -f $traceFolder, $traceAge.TotalHours, $faultAge.TotalHours)
            }
        } else {
            Write-Status WARN "The default trace folder ($traceFolder) exists but is empty. This is indirect evidence that tracing is probably OFF, but the trace path may have been customized by policy - this is not definitive."
        }
    } else {
        Write-Status WARN "No trace folder found at the default location ($traceFolder). This is indirect evidence that tracing is probably OFF, but the trace path may have been customized by policy - this is not definitive."
    }
} catch {
    Write-Status WARN "Could not check the default trace folder ($traceFolder) on ${ComputerName}: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 2. Application log retention - does it reach back far enough to cover the fault?
# ---------------------------------------------------------------------------
$oldestEventAge = $null
$logRetentionResult = $null
try {
    $log = Get-WinEvent -ListLog $ref.GppLogName -ComputerName $ComputerName -ErrorAction Stop
    try {
        $oldest = Get-WinEvent -ComputerName $ComputerName -LogName $ref.GppLogName -Oldest -MaxEvents 1 -ErrorAction Stop
        $oldestEventAge = (Get-Date) - $oldest.TimeCreated
        $logRetentionResult = New-CollectionResult -State 'Found' -Data $oldestEventAge
        Write-Status PASS ("Application log on {0} reaches back {1:N1} hours." -f $ComputerName, $oldestEventAge.TotalHours)
    } catch {
        $logRetentionResult = New-CollectionResult -State 'CouldNotCollect' -Reason "Could not read the oldest event in the $($ref.GppLogName) log on ${ComputerName}: $($_.Exception.Message)"
        Write-Status WARN $logRetentionResult.Reason
    }
} catch {
    $logRetentionResult = New-CollectionResult -State 'CouldNotCollect' -Reason "Could not list the $($ref.GppLogName) log on ${ComputerName}: $($_.Exception.Message)"
    Write-Status FAIL $logRetentionResult.Reason
}

# If retention could not be determined, treat it as NOT covering the fault (blind),
# rather than assuming it does - the same CouldNotCollect-never-becomes-clean rule.
if ($null -eq $oldestEventAge) {
    $oldestEventAge = [timespan]::Zero
}

# ---------------------------------------------------------------------------
# 3. Blind-condition assessment - can a collection right now be trusted?
# ---------------------------------------------------------------------------
$blind = Test-BlindCondition -GppLoggingEnabled $gppLoggingEnabled -TracingEnabled $tracingEnabled `
            -OldestEventAge $oldestEventAge -FaultAge $faultAge

Write-Host ''
if ($blind.IsBlind) {
    Write-Status FAIL 'This machine CANNOT currently produce trustworthy drive-map evidence.'
    foreach ($reason in $blind.BlindReasons) { Write-Status FAIL "  - $reason" }
    Write-Status WARN 'Collecting now would produce an EMPTY report that looks identical to a healthy machine. Do not treat an empty result as "no problem" until this is resolved.'
} else {
    Write-Status PASS 'Logging is enabled and the Application log covers the reported fault window. Evidence collection can be trusted.'
}

# ---------------------------------------------------------------------------
# 4. EnableLinkedConnections - split-token / elevated-session visibility risk.
# ---------------------------------------------------------------------------
$elcPath = $ref.RegistryPaths.EnableLinkedConnections
$elcResult = Read-RemoteRegistryValue -ComputerName $ComputerName -Path $elcPath -Name 'EnableLinkedConnections'
$elcValue = if ($elcResult.State -eq 'Found') { $elcResult.Data } else { $null }
if ($elcResult.State -eq 'Found') {
    Write-Status INFO "EnableLinkedConnections = $elcValue"
} else {
    Write-Status WARN "EnableLinkedConnections could not be read: $($elcResult.Reason)"
}

# UAC prompt-for-credentials state. ConsentPromptBehaviorAdmin values 1 and 3 mean
# "prompt for credentials"; 0, 2, 4, and 5 mean "prompt for consent" (Permit/Deny) or no
# prompt at all - only 1/3 create the additional logon session this caveat is about.
# Key: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System, Value: ConsentPromptBehaviorAdmin, Type: REG_DWORD
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4
# Read defensively; treated as CouldNotCollect -> not-prompting for the split-token
# explanation below, since this is a secondary caveat rather than the headline finding.
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacResult = Read-RemoteRegistryValue -ComputerName $ComputerName -Path $uacPath -Name 'ConsentPromptBehaviorAdmin'
$uacPromptsForCredentials = ($uacResult.State -eq 'Found' -and [int]$uacResult.Data -in @(1, 3))
if ($uacResult.State -ne 'Found') {
    Write-Status WARN "ConsentPromptBehaviorAdmin could not be read: $($uacResult.Reason)"
}

$splitTokenRisk = Get-SplitTokenRisk -EnableLinkedConnections $elcValue -UacPromptsForCredentials $uacPromptsForCredentials
if ($splitTokenRisk.AtRisk) {
    Write-Status WARN $splitTokenRisk.Explanation
    foreach ($r in $splitTokenRisk.Remediations) { Write-Status WARN "  Fix: $r" }
} else {
    Write-Status PASS $splitTokenRisk.Explanation
}

# ---------------------------------------------------------------------------
# 5. Drive Maps CSE NoBackgroundPolicy + Fast Logon Optimization / Always-wait risk.
#
# Microsoft documents the CSE registration key's Default, DLLName and EventSources
# values but NOT NoBackgroundPolicy. A missing value must be CouldNotCollect, never
# "risk absent" or 0 - see DriveMapReference.psd1 and Ruling 4 in the design ledger.
# ---------------------------------------------------------------------------
$csePath = $ref.RegistryPaths.DriveMapsCse
$cseResult = Read-RemoteRegistryValue -ComputerName $ComputerName -Path $csePath -Name 'NoBackgroundPolicy'
if ($cseResult.State -eq 'Found') {
    Write-Status INFO "Drive Maps CSE NoBackgroundPolicy = $($cseResult.Data) (documented behavior: 1 = never called on background refresh)."
} else {
    Write-Status WARN "Drive Maps CSE NoBackgroundPolicy could not be determined: $($cseResult.Reason) This is NOT documented by Microsoft as an absent-means-0 value - treat the every-other-logon risk below as unconfirmed either way, not as ruled out."
}

# Fast Logon Optimization / "Always wait for the network at computer startup and logon"
# are documented by Microsoft only as GPO policy settings (Computer Configuration >
# Policies > Administrative Templates > System > Logon), and this script's research did
# not find a Microsoft Learn page documenting the underlying registry value name(s) for
# either one. Per this toolkit's rule against asserting unverified facts, this script
# does not guess at those value names or read them. It falls back to the DOCUMENTED
# client default confirmed above (Fast Logon Optimization is on by default for domain
# and workgroup members since Windows XP), and reports that assumption explicitly rather
# than presenting a guessed registry read as a real measurement.
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj573586(v=ws.11)
Write-Status WARN "Fast Logon Optimization and 'Always wait for the network at computer startup and logon' are not documented with a specific registry value name on any reachable Microsoft Learn page, so this script cannot read them directly. Confirm the effective setting with 'gpresult /h report.html' or rsop.msc on $ComputerName."
$fastLogonOptimization = $true
$alwaysWaitForNetwork  = $false

$driveMapAction = 'Replace'
$everyOtherLogonRisk = Get-EveryOtherLogonRisk -Action $driveMapAction -FastLogonOptimization $fastLogonOptimization -AlwaysWaitForNetwork $alwaysWaitForNetwork
if ($everyOtherLogonRisk.AtRisk) {
    Write-Status WARN $everyOtherLogonRisk.Explanation
    foreach ($r in $everyOtherLogonRisk.Remediations) { Write-Status WARN "  Fix: $r" }
} else {
    Write-Status PASS $everyOtherLogonRisk.Explanation
}

# ---------------------------------------------------------------------------
# -EnableLogging: turn on GPP logging/tracing so the NEXT fault occurrence is captured.
#
# Because the underlying registry value name for "Logging and tracing" is not
# documented on any reachable Microsoft Learn page (see section 1 above), this script
# does not attempt an unverified registry write for it either. Setting an undocumented
# value with a guessed name/data risks silently doing nothing while claiming success -
# the same confident-plausible-wrong-answer failure this toolkit exists to prevent.
# Direct the operator to the supported, documented path instead: the Group Policy
# Management Console policy itself.
# ---------------------------------------------------------------------------
if ($EnableLogging) {
    Write-Host ''
    Write-Status INFO 'Enabling GPP logging was requested.'
    Write-Status WARN 'The registry value(s) behind "Logging and tracing" are not documented by Microsoft, so this script will not attempt an unverified registry write.'
    Write-Status INFO 'Enable it via Group Policy instead, then reproduce the fault:'
    Write-Status INFO '  1. Edit the GPO applying the drive map: Computer Configuration > Policies > Administrative Templates > System > Group Policy > Logging and tracing.'
    Write-Status INFO "  2. Enable it for the 'Group Policy Drive Maps' area (and any other CSEs of interest)."
    Write-Status INFO "  3. Run gpupdate /force on $ComputerName, then log off and back on twice (Replace-mode maps under Fast Logon Optimization only apply every other logon)."
    Write-Status INFO "  4. Reproduce the fault, then re-run this readiness check and, once it reports PASS, run the evidence collector."
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
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

$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$reportPath = Join-Path $OutputPath "DriveMapLoggingReadiness_$stamp.txt"

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add("Drive Map Logging Readiness Report")
$reportLines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$reportLines.Add("Computer: $ComputerName")
if ($DriveLetter) { $reportLines.Add("Reported missing drive: ${DriveLetter}:") }
$reportLines.Add("Fault age assumption: $FaultAgeHours hour(s)")
$reportLines.Add('')
$reportLines.Add('--- Blind-condition assessment ---')
if ($blind.IsBlind) {
    $reportLines.Add('BLIND: evidence collected now cannot be trusted.')
    foreach ($reason in $blind.BlindReasons) { $reportLines.Add("  - $reason") }
} else {
    $reportLines.Add('NOT BLIND: logging is enabled and retention covers the fault window.')
}
$reportLines.Add('')
$reportLines.Add('--- GPP logging state ---')
$reportLines.Add($gppLoggingResult.Reason)
$reportLines.Add('')
$reportLines.Add('--- GPP tracing state (corroborating evidence only, not proof) ---')
$reportLines.Add("Default trace folder: $traceFolder")
$reportLines.Add("Tracing evidently on (files present): $tracingEnabled")
$reportLines.Add('This is drawn from trace-file presence/freshness at the DOCUMENTED DEFAULT location, not a read of the tracing policy itself. The trace path can be relocated by policy, so an empty/missing folder does not prove tracing is off, and a populated one does not prove the CURRENT policy has tracing on.')
$reportLines.Add('')
$reportLines.Add('--- Application log retention ---')
$reportLines.Add("State: $($logRetentionResult.State)")
if ($logRetentionResult.State -eq 'Found') {
    $reportLines.Add(("Oldest retained event: {0:N1} hours ago" -f $oldestEventAge.TotalHours))
} else {
    $reportLines.Add($logRetentionResult.Reason)
}
$reportLines.Add('')
$reportLines.Add('--- Split-token / elevated-session visibility (EnableLinkedConnections) ---')
$reportLines.Add("AtRisk: $($splitTokenRisk.AtRisk)")
$reportLines.Add($splitTokenRisk.Explanation)
foreach ($r in $splitTokenRisk.Remediations) { $reportLines.Add("  Fix: $r") }
$reportLines.Add('')
$reportLines.Add('--- Every-other-logon risk (Fast Logon Optimization / Replace mode) ---')
$reportLines.Add("AtRisk: $($everyOtherLogonRisk.AtRisk)")
$reportLines.Add($everyOtherLogonRisk.Explanation)
foreach ($r in $everyOtherLogonRisk.Remediations) { $reportLines.Add("  Fix: $r") }
$reportLines.Add('')
$reportLines.Add('--- Drive Maps CSE NoBackgroundPolicy ---')
$reportLines.Add("State: $($cseResult.State)")
if ($cseResult.State -eq 'Found') {
    $reportLines.Add("NoBackgroundPolicy = $($cseResult.Data)")
} else {
    $reportLines.Add($cseResult.Reason)
}

try {
    # Files must be UTF-8 WITH BOM. Windows PowerShell 5.1's -Encoding UTF8 writes a BOM,
    # but PowerShell 7's -Encoding UTF8 does NOT (confirmed by byte-level inspection in
    # this session: 'D','r','i' with no EF BB BF preamble) - 'utf8BOM' is required there
    # instead. Write bytes directly with an explicit BOM so behavior is identical on
    # both, rather than relying on a version-dependent cmdlet alias.
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $reportText = ($reportLines -join [Environment]::NewLine) + [Environment]::NewLine
    [System.IO.File]::WriteAllText($reportPath, $reportText, $utf8Bom)
    Write-Host ''
    Write-Status PASS "Readiness report written: $reportPath"
} catch {
    Write-Status FAIL "Could not write readiness report: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Machine-readable companion (JSON), alongside the human-readable .txt above.
#
# This gate computes several signals that Invoke-DriveMapInvestigation.ps1's
# ranked-cause verdict logic needs (EnableLinkedConnections, Fast Logon
# Optimization, "Always wait for the network", NoBackgroundPolicy, GPP
# logging/tracing state, the blind-condition result) but previously exposed
# them only as console text and prose inside the .txt report - unreadable by
# another script without fragile text-scraping. Without this file, the two
# ranked-cause rules that depend on these signals (every-other-logon,
# split-token visibility) could never fire on a real run, silently disabling
# this toolkit's two highest-value, most-documented conclusions (spec section
# 6; sections 3.3 and 3.4).
#
# Every value is written as a three-state record - { State; Value; Reason } -
# using this script's own New-CollectionResult shape, so the
# Found/EmptyButValid/CouldNotCollect distinction survives into JSON exactly
# as it exists in memory. A value this script could not determine (for
# example GppLoggingEnabled and TracingEnabled, which per the ruling above are
# NEVER read from an undocumented registry value) must serialize as
# CouldNotCollect with its Reason preserved, not as a bare $false - collapsing
# that here would let a downstream consumer treat "could not determine" as a
# confirmed negative, precisely the failure the three-state contract exists to
# prevent.
$jsonPath = Join-Path $OutputPath "DriveMapLoggingReadiness_$stamp.json"
try {
    $readinessData = [ordered]@{
        GeneratedAt   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ComputerName  = $ComputerName
        DriveLetter   = $DriveLetter

        EnableLinkedConnections = [ordered]@{
            State  = $elcResult.State
            Value  = if ($elcResult.State -eq 'Found') { $elcValue } else { $null }
            Reason = $elcResult.Reason
        }

        # Not read from the registry - see the citation above this section: no Microsoft
        # Learn page documents a value name for either Fast Logon Optimization or "Always
        # wait for the network", so this script falls back to the documented CLIENT DEFAULT
        # (Fast Logon Optimization on, "Always wait" off) rather than guessing a registry
        # read. That fallback is itself not a confirmed measurement of THIS machine's
        # effective policy, so it is recorded as CouldNotCollect with an explicit reason,
        # never as Found - a downstream consumer must not treat this as verified.
        FastLogonOptimization = [ordered]@{
            State  = 'CouldNotCollect'
            Value  = $null
            Reason = "Not read from the registry - no Microsoft Learn page documents the underlying value name. The documented CLIENT DEFAULT (enabled) is $fastLogonOptimization but is NOT a measurement of this machine; confirm with 'gpresult /h' or rsop.msc on $ComputerName."
        }
        AlwaysWaitForNetwork = [ordered]@{
            State  = 'CouldNotCollect'
            Value  = $null
            Reason = "Not read from the registry - no Microsoft Learn page documents the underlying value name. The documented CLIENT DEFAULT (disabled) is $alwaysWaitForNetwork but is NOT a measurement of this machine; confirm with 'gpresult /h' or rsop.msc on $ComputerName."
        }

        NoBackgroundPolicy = [ordered]@{
            State  = $cseResult.State
            Value  = if ($cseResult.State -eq 'Found') { $cseResult.Data } else { $null }
            Reason = $cseResult.Reason
        }

        # Per Ruling 6: the registry value name(s) behind the GPP "Logging and tracing"
        # policy are not documented anywhere on learn.microsoft.com. This gate never guesses
        # at them, so GppLoggingEnabled is unconditionally CouldNotCollect - preserved
        # faithfully here, not flattened to a bare $false.
        GppLoggingEnabled = [ordered]@{
            State  = 'CouldNotCollect'
            Value  = $null
            Reason = $gppLoggingResult.Reason
        }

        # Tracing state is corroborated (not proven) via trace-file presence/freshness at
        # the documented default location - see the orchestration section above. It is a
        # real (if indirect) measurement, so it IS reported as Found, with its boolean
        # value and the same corroboration caveat carried in Reason.
        TracingEnabled = [ordered]@{
            State  = 'Found'
            Value  = $tracingEnabled
            Reason = "Corroborating evidence only (trace-file presence/freshness at $traceFolder), not a direct read of the tracing policy - the trace path can be relocated by policy."
        }

        BlindCondition = [ordered]@{
            IsBlind      = $blind.IsBlind
            BlindReasons = @($blind.BlindReasons)
        }
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $readinessJson = $readinessData | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($jsonPath, $readinessJson, $utf8Bom)
    Write-Status PASS "Machine-readable readiness data written: $jsonPath"
} catch {
    Write-Status FAIL "Could not write machine-readable readiness JSON: $($_.Exception.Message)"
}
