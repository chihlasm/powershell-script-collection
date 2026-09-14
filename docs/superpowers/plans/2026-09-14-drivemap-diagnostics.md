# Drive Map Diagnostics Toolkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a five-script PowerShell toolkit that diagnoses why a user's mapped drive intermittently disappears, naming the specific mechanism and configuration object responsible.

**Architecture:** Endpoint collectors (gate, snapshot, watcher) produce a portable evidence bundle; an operator-side orchestrator correlates that bundle with domain-side Group Policy data from two existing scripts it reuses unmodified, then emits one combined HTML case report. Every interpretation step is a pure function so it tests without a domain, and every collector distinguishes "looked and found nothing" from "could not look."

**Tech Stack:** Windows PowerShell 5.1 (target runtime; authored to run on 5.1 and 7.x), Pester 5.7.1, RSAT `GroupPolicy` and `ActiveDirectory` modules (imported at runtime in try/catch, never via `#Requires -Modules`).

**Spec:** `docs/superpowers/specs/2026-09-14-drivemap-diagnostics-design.md`

## Global Constraints

These apply to every task. Copied from the spec §8 and the repository CLAUDE.md.

- `#Requires -Version 5.1` at the top of every script. Never `#Requires -Modules`.
- `[CmdletBinding()]` with a typed `param()` block on every script.
- Every script that writes files takes `-OutputPath` (string), defaulting to the script's own directory.
- Every script takes `-LoadFunctionsOnly` ([switch]) as its **last** parameter. All functions are defined above the line `if ($LoadFunctionsOnly) { return }`, and all orchestration below it. This is what makes the script dot-sourceable by Pester. Follow `AD-LockoutDiagnostics\Test-ADAuditPolicy.ps1:553` exactly.
- Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER` (one per parameter), `.EXAMPLE`, `.NOTES`. The `.NOTES` block ends with a `REFERENCES` section listing every Microsoft Learn URL the script relies on.
- Console output uses `Write-Status` with prefixes `[PASS]` (Green), `[WARN]` (Yellow), `[FAIL]` (Red), `[INFO]` (Cyan).
- Timestamps: `yyyy-MM-dd HH:mm:ss` in logs, `yyyy-MM-dd_HHmmss` in filenames.
- Structured data is `[PSCustomObject]@{}`; CSV export uses `Export-Csv -NoTypeInformation -Encoding UTF8`.
- Every remote query passes `-ComputerName`. Every per-target call is individually wrapped in try/catch so one unreachable machine cannot abort a run, and the failure is recorded and surfaced — never silently dropped.
- **Any documented Microsoft fact (event ID, registry path, status code, cmdlet behavior) must be verified against learn.microsoft.com before being written into code, and cited in a comment next to the code it justifies.** Do not write these from memory. Use WebFetch against learn.microsoft.com. The facts already verified are in spec §3 with their URLs — reuse those citations; verify anything new.
- Files are UTF-8 with BOM (match the existing scripts). Use the Write and Edit tools, never shell redirection or `sed`, which corrupt the BOM.

### The three-state rule (spec §2)

Every collector returns a `[PSCustomObject]` with a `State` property that is exactly one of:

- `'Found'` — looked, got data (`Data` populated)
- `'EmptyButValid'` — looked, nothing was there (`Data` empty; this is a real result)
- `'CouldNotCollect'` — could not look (`Reason` populated; asserts nothing)

A collector that returns a bare `@()` for both "nothing there" and "access denied" has destroyed the distinction the entire toolkit exists to preserve. This is enforced by tests in every collector task.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `DriveMap-Diagnostics/DriveMapReference.psd1` | Shared data: event IDs, registry paths, verdict definitions. Pure data, no logic. |
| `DriveMap-Diagnostics/Test-DriveMapLoggingReadiness.ps1` | Gate: blind-condition checks + config root causes. `-EnableLogging` repairs. |
| `DriveMap-Diagnostics/Export-DriveMapEvidence.ps1` | Endpoint snapshot → portable bundle |
| `DriveMap-Diagnostics/Watch-DriveMapActivity.ps1` | Catches the disappearance transition |
| `DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1` | Orchestrator: gate → endpoint → domain → correlate → case folder |
| `DriveMap-Diagnostics/New-DriveMapCaseReport.ps1` | Combined tabbed HTML report |
| `DriveMap-Diagnostics/README.md` | Usage, including a PS Remoting setup section |
| `DriveMap-Diagnostics/Tests/*.Tests.ps1` | One Pester file per script |

Reused unmodified (never edited by this plan):
- `AD-GroupPolicy-DriveMaps\Audit-GPDriveMaps.ps1`
- `Search-SYSVOLScripts\Search-SYSVOLScripts.ps1`

### Running tests

From the `DriveMap-Diagnostics` folder:

```powershell
Invoke-Pester -Path .\Tests\<Name>.Tests.ps1 -Output Detailed
```

Confirmed working against Pester 5.7.1 on this machine.

---

## Task 1: Reference data module

Builds the shared fact table every other script reads. Doing this first means the verified
Microsoft constants live in exactly one place, and the regression tests that protect them
are written before any consumer exists.

**Files:**
- Create: `DriveMap-Diagnostics/DriveMapReference.psd1`
- Test: `DriveMap-Diagnostics/Tests/DriveMapReference.Tests.ps1`

**Interfaces:**
- Consumes: nothing
- Produces: a `.psd1` loaded via `Import-PowerShellDataFile`, returning a hashtable with keys `GppEvents` (hashtable: int ID → hashtable with `Severity`, `Meaning`, `Category`), `GpOperationalEvents` (int ID → string), `RegistryPaths` (string → string), `GppLogSource` (string), `GppLogName` (string).

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/DriveMapReference.Tests.ps1`:

```powershell
BeforeAll {
    $script:Ref = Import-PowerShellDataFile -Path "$PSScriptRoot\..\DriveMapReference.psd1"
}

Describe 'GPP event reference (verified against Microsoft Learn)' {
    # GPP preference-item events are written to the APPLICATION log under source
    # 'Group Policy Drive Maps' - NOT to Microsoft-Windows-GroupPolicy/Operational.
    # Conflating the two streams means querying the wrong log and finding nothing,
    # which is indistinguishable from a healthy machine.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events

    It 'reads GPP preference events from the Application log' {
        $script:Ref.GppLogName | Should -Be 'Application'
    }

    It 'uses the documented Drive Maps event source' {
        $script:Ref.GppLogSource | Should -Be 'Group Policy Drive Maps'
    }

    It 'maps 4098 to a general item failure, not a targeting failure' {
        $script:Ref.GppEvents[4098].Category | Should -Be 'ItemFailed'
    }

    # 4105/4106/8212 mean the GPO did not apply TO THIS USER (targeting), which is a
    # different root cause and a different fix from 4098 (the item tried and errored).
    # Merging them hides which of the two is happening.
    It 'classifies 4105, 4106 and 8212 as targeting failures' {
        foreach ($id in 4105, 4106, 8212) {
            $script:Ref.GppEvents[$id].Category | Should -Be 'TargetingFailed'
        }
    }

    It 'records 4096 as a successful apply and 4101 as a successful removal' {
        $script:Ref.GppEvents[4096].Category | Should -Be 'Applied'
        $script:Ref.GppEvents[4101].Category | Should -Be 'Removed'
    }

    It 'records 8194 as a CSE-level failure' {
        $script:Ref.GppEvents[8194].Category | Should -Be 'CseFailed'
    }
}

Describe 'Registry path reference (verified against Microsoft Learn)' {
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
    It 'uses the documented EnableLinkedConnections policy key' {
        $script:Ref.RegistryPaths.EnableLinkedConnections |
            Should -Be 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    }

    It 'points persistent mount lookups at HKCU\Network' {
        $script:Ref.RegistryPaths.PersistentMounts | Should -Be 'HKCU:\Network'
    }
}

Describe 'Group Policy operational event reference' {
    It 'includes the CSE start and completion events' {
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 4016
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 5016
        $script:Ref.GpOperationalEvents.Keys | Should -Contain 7016
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\DriveMapReference.Tests.ps1 -Output Detailed`
Expected: FAIL — `DriveMapReference.psd1` does not exist, so `Import-PowerShellDataFile` throws in `BeforeAll`.

- [ ] **Step 3: Write the reference file**

Create `DriveMap-Diagnostics/DriveMapReference.psd1`. Every entry below traces to spec §3;
keep the citation comments — they are the regression guard's other half.

```powershell
@{
    # Group Policy Preferences events are written to the Application log. Informational
    # events are ONLY logged when the 'Logging and tracing' policy is enabled, so an
    # empty Application log means "not recorded", never "no failures".
    # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
    GppLogName   = 'Application'
    GppLogSource = 'Group Policy Drive Maps'

    GppEvents = @{
        4096 = @{ Severity = 'Success'; Category = 'Applied';         Meaning = 'Preference item applied successfully' }
        4098 = @{ Severity = 'Warning'; Category = 'ItemFailed';      Meaning = 'Item did not apply - failed with an error code' }
        4101 = @{ Severity = 'Success'; Category = 'Removed';         Meaning = 'Preference item was successfully removed' }
        4105 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because a targeting item failed' }
        4106 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because its targeting item failed' }
        8194 = @{ Severity = 'Warning'; Category = 'CseFailed';       Meaning = 'Client-side extension could not process settings for the GPO' }
        8212 = @{ Severity = 'Warning'; Category = 'TargetingFailed'; Meaning = 'Did not apply because a targeting item failed' }
    }

    # The Group Policy engine's own CSE-processing events, in a DIFFERENT channel:
    # Microsoft-Windows-GroupPolicy/Operational. These say whether the Drive Maps CSE
    # ran at all; the GppEvents above say whether an individual drive item applied.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
    GpOperationalLogName = 'Microsoft-Windows-GroupPolicy/Operational'
    GpOperationalEvents = @{
        4001 = 'Group Policy processing started'
        4016 = 'CSE processing started'
        5016 = 'CSE processing completed successfully'
        5017 = 'Organizational unit resolved'
        5312 = 'List of applicable GPOs'
        7016 = 'CSE processing completed with an error'
    }

    RegistryPaths = @{
        # Persistent (reconnect-at-logon) mounts. A letter present here but absent from
        # the live mount list means reconnect is failing - a different root cause from
        # policy failing to apply.
        PersistentMounts = 'HKCU:\Network'

        # Historical mount points - what the user has had mapped previously.
        MountPoints2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'

        # With UAC on, logon creates two linked sessions and drive mappings are
        # per-session symbolic links. EnableLinkedConnections=1 writes them to both.
        # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command
        EnableLinkedConnections = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

        # GPP logging and tracing policy.
        # https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events
        GppTracing = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Group Policy'

        # Drive Maps CSE registration. NoBackgroundPolicy=1 means the CSE is never
        # called during background refresh - half of the every-other-logon mechanism.
        # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon
        DriveMapsCse = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\{5794DAFD-BE60-433f-88A2-1A31939AC01F}'
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\DriveMapReference.Tests.ps1 -Output Detailed`
Expected: PASS, 11 tests.

- [ ] **Step 5: Verify the Drive Maps CSE GUID before committing**

The CSE GUID in `DriveMapsCse` is the one constant above that was not verified during
spec research. Confirm it against Microsoft documentation (search learn.microsoft.com for
the Drive Maps client-side extension GUID). If it differs, correct it and add a test
asserting the verified value with the source URL in a comment. If it cannot be confirmed
from Microsoft documentation, remove the `DriveMapsCse` entry and have Task 2 read
`NoBackgroundPolicy` by enumerating CSE keys and matching on the display name instead —
do not ship an unverified GUID.

- [ ] **Step 6: Commit**

```bash
git add DriveMap-Diagnostics/DriveMapReference.psd1 DriveMap-Diagnostics/Tests/DriveMapReference.Tests.ps1
git commit -m "feat: add Drive Map Diagnostics reference data

Event IDs, registry paths and channel names verified against Microsoft
Learn, with regression tests carrying the source URLs.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: The gate — Test-DriveMapLoggingReadiness.ps1

The most important script in the toolkit and the one that most often solves the case
outright, because the configuration facts it reports (§3.3, §3.4) are themselves the two
most common root causes.

**Files:**
- Create: `DriveMap-Diagnostics/Test-DriveMapLoggingReadiness.ps1`
- Test: `DriveMap-Diagnostics/Tests/Test-DriveMapLoggingReadiness.Tests.ps1`

**Interfaces:**
- Consumes: `DriveMapReference.psd1` (Task 1)
- Produces:
  - `Write-Status -Level <string> -Message <string>` — console writer reused by later tasks
  - `New-CollectionResult -State <string> -Data <object> -Reason <string>` → `[PSCustomObject]` with `State`, `Data`, `Reason`
  - `Test-BlindCondition -GppLoggingEnabled <bool> -TracingEnabled <bool> -OldestEventAge <timespan> -FaultAge <timespan>` → `[PSCustomObject]` with `IsBlind` (bool), `BlindReasons` (string[])
  - `Get-EveryOtherLogonRisk -Action <string> -FastLogonOptimization <bool> -AlwaysWaitForNetwork <bool>` → `[PSCustomObject]` with `AtRisk` (bool), `Explanation` (string), `Remediations` (string[])
  - `Get-SplitTokenRisk -EnableLinkedConnections <object> -UacPromptsForCredentials <bool>` → `[PSCustomObject]` with `AtRisk` (bool), `Explanation` (string), `Remediations` (string[])
  - Script parameters: `-ComputerName <string>`, `-DriveLetter <string>`, `-FaultAgeHours <int>`, `-EnableLogging <switch>`, `-OutputPath <string>`, `-LoadFunctionsOnly <switch>`

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/Test-DriveMapLoggingReadiness.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Test-DriveMapLoggingReadiness.ps1" -LoadFunctionsOnly
}

Describe 'New-CollectionResult' {
    # The distinction this toolkit exists to preserve: "looked and found nothing" and
    # "could not look" produce identical empty data but opposite conclusions.
    It 'distinguishes EmptyButValid from CouldNotCollect' {
        $empty  = New-CollectionResult -State 'EmptyButValid' -Data @()
        $failed = New-CollectionResult -State 'CouldNotCollect' -Reason 'Access denied'

        $empty.State  | Should -Be 'EmptyButValid'
        $failed.State | Should -Be 'CouldNotCollect'
        $failed.Reason | Should -Be 'Access denied'
    }

    It 'rejects a state outside the three permitted values' {
        { New-CollectionResult -State 'Maybe' -Data @() } | Should -Throw
    }

    It 'requires a reason when it could not collect' {
        { New-CollectionResult -State 'CouldNotCollect' } | Should -Throw
    }
}

Describe 'Test-BlindCondition' {
    It 'reports blind when GPP logging is disabled' {
        $r = Test-BlindCondition -GppLoggingEnabled $false -TracingEnabled $false `
                -OldestEventAge ([timespan]::FromDays(30)) -FaultAge ([timespan]::FromHours(2))
        $r.IsBlind | Should -BeTrue
        ($r.BlindReasons -join ' ') | Should -Match 'logging'
    }

    # A log that only reaches back 6 hours cannot evidence a fault from yesterday. The
    # query returns empty and looks exactly like a clean machine.
    It 'reports blind when the log does not reach back to the fault' {
        $r = Test-BlindCondition -GppLoggingEnabled $true -TracingEnabled $true `
                -OldestEventAge ([timespan]::FromHours(6)) -FaultAge ([timespan]::FromHours(48))
        $r.IsBlind | Should -BeTrue
        ($r.BlindReasons -join ' ') | Should -Match 'retention|reach back'
    }

    It 'is not blind when logging is on and the log covers the fault' {
        $r = Test-BlindCondition -GppLoggingEnabled $true -TracingEnabled $true `
                -OldestEventAge ([timespan]::FromDays(14)) -FaultAge ([timespan]::FromHours(6))
        $r.IsBlind | Should -BeFalse
        $r.BlindReasons | Should -BeNullOrEmpty
    }

    It 'names every blind condition, not just the first' {
        $r = Test-BlindCondition -GppLoggingEnabled $false -TracingEnabled $false `
                -OldestEventAge ([timespan]::FromHours(1)) -FaultAge ([timespan]::FromDays(3))
        $r.BlindReasons.Count | Should -BeGreaterThan 1
    }
}

Describe 'Get-EveryOtherLogonRisk (verified against Microsoft Learn)' {
    # The Drive Maps CSE has NoBackgroundPolicy=1 and only applies items when Group
    # Policy runs synchronously. With Fast Logon Optimization on (the client default),
    # logon is asynchronous, so Replace-mode maps apply every OTHER logon. This presents
    # exactly as "the drive keeps disappearing" with no configuration change.
    # https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon

    It 'flags Replace + Fast Logon Optimization without always-wait as at risk' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        $r.AtRisk | Should -BeTrue
    }

    It 'clears the risk when always-wait-for-network is enabled' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $true
        $r.AtRisk | Should -BeFalse
    }

    It 'recommends always-wait and Create+Reconnect' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        ($r.Remediations -join ' ') | Should -Match 'wait for the network'
        ($r.Remediations -join ' ') | Should -Match 'Reconnect'
    }

    # Microsoft explicitly advises against setting NoBackgroundPolicy=0, and notes it
    # does not reliably work. The toolkit must never suggest it.
    It 'never recommends setting NoBackgroundPolicy to 0' {
        $r = Get-EveryOtherLogonRisk -Action 'Replace' -FastLogonOptimization $true -AlwaysWaitForNetwork $false
        ($r.Remediations -join ' ') | Should -Not -Match 'NoBackgroundPolicy'
    }
}

Describe 'Get-SplitTokenRisk (verified against Microsoft Learn)' {
    # With UAC on, logon creates two linked sessions; drive mappings are per-session
    # symbolic links. A drive "missing" only when elevated was never missing - it is a
    # visibility artifact, and diagnosing it as a GPO problem wastes the investigation.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command

    It 'flags risk when EnableLinkedConnections is absent' {
        (Get-SplitTokenRisk -EnableLinkedConnections $null -UacPromptsForCredentials $false).AtRisk | Should -BeTrue
    }

    It 'flags risk when EnableLinkedConnections is 0' {
        (Get-SplitTokenRisk -EnableLinkedConnections 0 -UacPromptsForCredentials $false).AtRisk | Should -BeTrue
    }

    It 'clears the risk when EnableLinkedConnections is 1' {
        (Get-SplitTokenRisk -EnableLinkedConnections 1 -UacPromptsForCredentials $false).AtRisk | Should -BeFalse
    }

    # Documented caveat: with UAC set to prompt for credentials a THIRD session is
    # created, and previously created symbolic links are unavailable in it - so
    # EnableLinkedConnections=1 does not fully resolve that configuration.
    It 'still warns when UAC prompts for credentials even with the value set' {
        $r = Get-SplitTokenRisk -EnableLinkedConnections 1 -UacPromptsForCredentials $true
        $r.Explanation | Should -Match 'prompt'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\Test-DriveMapLoggingReadiness.Tests.ps1 -Output Detailed`
Expected: FAIL — the script does not exist, so dot-sourcing in `BeforeAll` throws.

- [ ] **Step 3: Write the script**

Create `DriveMap-Diagnostics/Test-DriveMapLoggingReadiness.ps1` with full comment-based
help (per Global Constraints), then the functions below, then `if ($LoadFunctionsOnly) { return }`,
then orchestration.

Pure functions (these are what the tests above exercise):

```powershell
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
        $reasons.Add(("The Application log only reaches back {0:N1} hours, but the fault is {1:N1} hours old - the evidence has already rolled off." -f $OldestEventAge.TotalHours, $FaultAge.TotalHours))
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
```

Below `if ($LoadFunctionsOnly) { return }`, write the orchestration: read the registry
values named in `DriveMapReference.psd1` (each read in its own try/catch returning a
`New-CollectionResult`), query the Application log's oldest retained event, call the pure
functions above, print results via `Write-Status`, and write a readiness report to
`-OutputPath`. When `-EnableLogging` is passed, set the GPP logging and tracing policy
values and print reproduce-the-fault instructions. When the gate is blind, print the
remediation and state clearly that collecting now would produce an empty report that
cannot be distinguished from a healthy machine.

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\Test-DriveMapLoggingReadiness.Tests.ps1 -Output Detailed`
Expected: PASS, 16 tests.

- [ ] **Step 5: Verify the script runs end to end**

Run: `.\Test-DriveMapLoggingReadiness.ps1 -DriveLetter X -WhatIf`
Expected: completes without error, prints a readiness summary. It is fine and expected for
some checks to report `CouldNotCollect` on a non-domain-joined machine — confirm they say
so explicitly rather than reporting a clean result.

- [ ] **Step 6: Commit**

```bash
git add DriveMap-Diagnostics/Test-DriveMapLoggingReadiness.ps1 DriveMap-Diagnostics/Tests/Test-DriveMapLoggingReadiness.Tests.ps1
git commit -m "feat: add drive map logging readiness gate

Checks the three blind conditions (GPP logging off, tracing off, log
already rolled) before any collection, and reports the two most common
configuration root causes: the Fast Logon Optimization every-other-logon
mechanism and EnableLinkedConnections split-token visibility.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Evidence collector — Export-DriveMapEvidence.ps1

**Files:**
- Create: `DriveMap-Diagnostics/Export-DriveMapEvidence.ps1`
- Test: `DriveMap-Diagnostics/Tests/Export-DriveMapEvidence.Tests.ps1`

**Interfaces:**
- Consumes: `DriveMapReference.psd1` (Task 1); re-declares `Write-Status` and `New-CollectionResult` with identical signatures to Task 2 (each script is standalone — the repo has no shared modules, per CLAUDE.md)
- Produces:
  - `Get-PersistentMountRecord -RegistryData <hashtable>` → `[PSCustomObject]` with `DriveLetter`, `RemotePath`, `ProviderName`, `ConnectionType`, `UserName`
  - `Compare-MountState -PersistentMounts <object[]> -LiveMounts <object[]>` → `[PSCustomObject][]` each with `DriveLetter`, `InRegistry` (bool), `InLiveMounts` (bool), `Finding` (string: `'Consistent'`, `'ReconnectFailing'`, `'TransientMount'`)
  - `Select-DriveLetterReference -Text <string> -DriveLetter <string>` → `[PSCustomObject][]` each with `LineNumber`, `Line`, `Operation` (string: `'Delete'`, `'Map'`, `'Reference'`)
  - `New-EvidenceManifest -Results <hashtable>` → `[PSCustomObject]` with `Collected` (string[]), `Empty` (string[]), `Failed` (string[])
  - Script parameters: `-DriveLetter <string>`, `-ComputerName <string>`, `-OutputPath <string>`, `-LoadFunctionsOnly <switch>`

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/Export-DriveMapEvidence.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Export-DriveMapEvidence.ps1" -LoadFunctionsOnly
}

Describe 'Compare-MountState' {
    # A letter recorded in HKCU\Network but absent from the live mount list means the
    # persistent mount exists and reconnect is FAILING - the share was unreachable at
    # logon. That is a different root cause, and a different fix, from Group Policy
    # failing to apply. Collapsing them sends the technician to the wrong place.
    It 'identifies a failing reconnect when the mount is in the registry but not live' {
        $result = Compare-MountState `
            -PersistentMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' }) `
            -LiveMounts @()
        $row = $result | Where-Object { $_.DriveLetter -eq 'X' }
        $row.Finding | Should -Be 'ReconnectFailing'
    }

    It 'identifies a transient mount when live but not persisted' {
        $result = Compare-MountState `
            -PersistentMounts @() `
            -LiveMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' })
        ($result | Where-Object { $_.DriveLetter -eq 'X' }).Finding | Should -Be 'TransientMount'
    }

    It 'reports consistent when present in both' {
        $result = Compare-MountState `
            -PersistentMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' }) `
            -LiveMounts @([PSCustomObject]@{ DriveLetter = 'X'; RemotePath = '\\srv\share' })
        ($result | Where-Object { $_.DriveLetter -eq 'X' }).Finding | Should -Be 'Consistent'
    }

    It 'returns nothing when both sides are empty' {
        Compare-MountState -PersistentMounts @() -LiveMounts @() | Should -BeNullOrEmpty
    }
}

Describe 'Select-DriveLetterReference' {
    # Microsoft's own scenario guide documents the case this catches: every Group Policy
    # event healthy, GPP trace showing the drive mapped successfully, and the drive still
    # gone - because a logon script in an unrelated GPO ran 'net use z: /delete'.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected

    It 'classifies net use /delete as a Delete operation' {
        $r = Select-DriveLetterReference -Text "net use x: /delete" -DriveLetter 'X'
        $r.Operation | Should -Be 'Delete'
    }

    It 'classifies a mapping command as a Map operation' {
        $r = Select-DriveLetterReference -Text "net use x: \\server\share /persistent:yes" -DriveLetter 'X'
        $r.Operation | Should -Be 'Map'
    }

    It 'is case insensitive about the drive letter' {
        (Select-DriveLetterReference -Text "NET USE X: /DELETE" -DriveLetter 'x').Operation | Should -Be 'Delete'
    }

    It 'reports the line number of each match' {
        $text = "rem header`r`nnet use x: /delete`r`nexit"
        (Select-DriveLetterReference -Text $text -DriveLetter 'X').LineNumber | Should -Be 2
    }

    It 'does not match a different drive letter' {
        Select-DriveLetterReference -Text "net use z: /delete" -DriveLetter 'X' | Should -BeNullOrEmpty
    }

    It 'matches PowerShell Remove-PSDrive as a Delete operation' {
        (Select-DriveLetterReference -Text "Remove-PSDrive -Name X" -DriveLetter 'X').Operation | Should -Be 'Delete'
    }
}

Describe 'New-EvidenceManifest' {
    # The manifest is what makes a bundle collected by someone else interpretable without
    # asking them what they ran. An item that could not be collected must never be
    # silently absent - absence would read as "nothing was there".
    It 'separates collected, empty and failed collectors' {
        $manifest = New-EvidenceManifest -Results @{
            PersistentMounts = [PSCustomObject]@{ State = 'Found';           Data = @(1) }
            GppEvents        = [PSCustomObject]@{ State = 'EmptyButValid';   Data = @() }
            TraceFiles       = [PSCustomObject]@{ State = 'CouldNotCollect'; Reason = 'Tracing disabled' }
        }
        $manifest.Collected | Should -Contain 'PersistentMounts'
        $manifest.Empty     | Should -Contain 'GppEvents'
        $manifest.Failed    | Should -Contain 'TraceFiles'
    }

    It 'records the reason a collector could not run' {
        $manifest = New-EvidenceManifest -Results @{
            TraceFiles = [PSCustomObject]@{ State = 'CouldNotCollect'; Reason = 'Tracing disabled' }
        }
        ($manifest.Failed -join ' ') | Should -Match 'Tracing disabled'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\Export-DriveMapEvidence.Tests.ps1 -Output Detailed`
Expected: FAIL — script does not exist.

- [ ] **Step 3: Write the script**

Create `DriveMap-Diagnostics/Export-DriveMapEvidence.ps1` with full comment-based help,
the pure functions whose contracts the tests above pin down, then
`if ($LoadFunctionsOnly) { return }`, then orchestration.

`Select-DriveLetterReference` must recognise, case-insensitively: `net use <letter>: /delete`
and `/d` → `Delete`; `Remove-PSDrive` naming the letter → `Delete`; `net use <letter>: \\...`
and `New-PSDrive` naming the letter → `Map`; any other mention of `<letter>:` → `Reference`.
Return one row per matching line with its 1-based line number.

`Compare-MountState` takes the union of drive letters from both inputs and emits one row
per letter with the `Finding` values the tests pin down.

Orchestration collects, each in its own try/catch producing a `New-CollectionResult`:
`HKCU\Network`, `MountPoints2`, live mounts **in both token contexts** (spec §3.4 — collecting
from one context only produces a confidently wrong answer), GPP events from the Application
log filtered to source `Group Policy Drive Maps`, GP Operational events, GPP trace files, GPO
logon scripts under `\User\Scripts\Logon\`, the AD `scriptPath` attribute, scheduled tasks,
Run/RunOnce keys, the Startup folder, DFS and Offline Files state, and network profile.
Each text-bearing source is passed through `Select-DriveLetterReference`. Write everything to
a timestamped folder under `-OutputPath`, write `manifest.json` from `New-EvidenceManifest`,
and zip it.

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\Export-DriveMapEvidence.Tests.ps1 -Output Detailed`
Expected: PASS, 13 tests.

- [ ] **Step 5: Verify against real output**

Run: `.\Export-DriveMapEvidence.ps1 -DriveLetter X -OutputPath $env:TEMP`
Open the resulting `manifest.json` and confirm every collector appears in exactly one of
`Collected` / `Empty` / `Failed`, and that no CSV column contains the literal text
`System.Object[]` (a real bug in the lockout toolkit's history — flatten arrays before export).

- [ ] **Step 6: Commit**

```bash
git add DriveMap-Diagnostics/Export-DriveMapEvidence.ps1 DriveMap-Diagnostics/Tests/Export-DriveMapEvidence.Tests.ps1
git commit -m "feat: add drive map evidence collector

Collects endpoint evidence into a portable, self-describing bundle:
persistent mounts, live mounts in both token contexts, GPP and Group
Policy events, trace files, and every logon script, scheduled task and
startup item that references the drive letter.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Watcher — Watch-DriveMapActivity.ps1

**Files:**
- Create: `DriveMap-Diagnostics/Watch-DriveMapActivity.ps1`
- Test: `DriveMap-Diagnostics/Tests/Watch-DriveMapActivity.Tests.ps1`

**Interfaces:**
- Consumes: `DriveMapReference.psd1` (Task 1); re-declares `Write-Status`
- Produces:
  - `Get-TransitionType -Previous <bool> -Current <bool>` → string (`'Disappeared'`, `'Appeared'`, `'NoChange'`)
  - `Get-DisappearanceTiming -TransitionTime <datetime> -LogonTime <datetime> -LastGpRefresh <nullable[datetime]>` → `[PSCustomObject]` with `Pattern` (string: `'AtLogon'`, `'AtGroupPolicyRefresh'`, `'Unexplained'`), `MinutesSinceLogon` (double), `Implication` (string)
  - `Format-TimelineEntry -Entry <PSCustomObject>` → string (one line, `yyyy-MM-dd HH:mm:ss` prefix)
  - Script parameters: `-DriveLetter <string>`, `-IntervalSeconds <int>`, `-DurationHours <int>`, `-OutputPath <string>`, `-Install <switch>`, `-LoadFunctionsOnly <switch>`

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/Watch-DriveMapActivity.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Watch-DriveMapActivity.ps1" -LoadFunctionsOnly
}

Describe 'Get-TransitionType' {
    It 'detects a disappearance' {
        Get-TransitionType -Previous $true -Current $false | Should -Be 'Disappeared'
    }
    It 'detects an appearance' {
        Get-TransitionType -Previous $false -Current $true | Should -Be 'Appeared'
    }
    It 'reports no change when the state is stable' {
        Get-TransitionType -Previous $true -Current $true   | Should -Be 'NoChange'
        Get-TransitionType -Previous $false -Current $false | Should -Be 'NoChange'
    }
}

Describe 'Get-DisappearanceTiming' {
    # Timing is what discriminates causes that look identical in a snapshot. A drive that
    # vanishes within minutes of logon implicates a logon script; one that vanishes at a
    # background refresh implicates policy processing. Same symptom, different fix.
    $logon = [datetime]'2026-09-14 08:00:00'

    It 'attributes a disappearance within minutes of logon to logon processing' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 08:02:00') `
                -LogonTime $logon -LastGpRefresh $null
        $r.Pattern | Should -Be 'AtLogon'
        $r.Implication | Should -Match 'logon script|logon'
    }

    It 'attributes a disappearance coinciding with a policy refresh to Group Policy' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 09:31:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:30')
        $r.Pattern | Should -Be 'AtGroupPolicyRefresh'
    }

    It 'reports unexplained when it matches neither' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 11:47:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:00')
        $r.Pattern | Should -Be 'Unexplained'
    }

    It 'reports minutes since logon' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 08:30:00') `
                -LogonTime $logon -LastGpRefresh $null
        $r.MinutesSinceLogon | Should -Be 30
    }

    # An 'Unexplained' pattern is a real finding that narrows the search, not a failure
    # to classify. It must carry an implication the reader can act on.
    It 'gives an actionable implication even when unexplained' {
        $r = Get-DisappearanceTiming -TransitionTime ([datetime]'2026-09-14 11:47:00') `
                -LogonTime $logon -LastGpRefresh ([datetime]'2026-09-14 09:30:00')
        $r.Implication | Should -Not -BeNullOrEmpty
    }
}

Describe 'Format-TimelineEntry' {
    It 'formats with the repository timestamp convention' {
        $line = Format-TimelineEntry -Entry ([PSCustomObject]@{
            Timestamp  = [datetime]'2026-09-14 08:02:15'
            Transition = 'Disappeared'
            DriveLetter = 'X'
            Detail     = 'was \\srv\share'
        })
        $line | Should -Match '^2026-09-14 08:02:15'
        $line | Should -Match 'Disappeared'
        $line | Should -Match 'X'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\Watch-DriveMapActivity.Tests.ps1 -Output Detailed`
Expected: FAIL — script does not exist.

- [ ] **Step 3: Write the script**

Create `DriveMap-Diagnostics/Watch-DriveMapActivity.ps1`.

`Get-DisappearanceTiming` classification rules: within 5 minutes of logon → `AtLogon`;
within 2 minutes of `LastGpRefresh` (when supplied) → `AtGroupPolicyRefresh`; otherwise
`Unexplained`. Check the logon window first so a refresh that coincides with logon is
attributed to logon. Each pattern carries an `Implication` naming what to examine next;
`Unexplained` says which evidence would narrow it (process-creation auditing, and whether
the disappearance follows sleep/resume or a network change).

Orchestration polls the drive letter every `-IntervalSeconds`, and on a transition captures
the registry-versus-live comparison, GPP and GP Operational events in the surrounding
window, recent 4688 process-creation events referencing the letter where that auditing is
enabled (and says so explicitly when it is not, rather than silently capturing nothing),
network state, and the last Group Policy refresh time. Appends via `Format-TimelineEntry`
to a timeline file under `-OutputPath`. `-Install` registers a scheduled task; `-DurationHours`
bounds the run.

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\Watch-DriveMapActivity.Tests.ps1 -Output Detailed`
Expected: PASS, 10 tests.

- [ ] **Step 5: Verify it catches a real transition**

```powershell
# In one window:
.\Watch-DriveMapActivity.ps1 -DriveLetter T -IntervalSeconds 5 -OutputPath $env:TEMP
# In another, create then remove a mapping to a local share and confirm the timeline
# records both transitions with correct timestamps.
```

- [ ] **Step 6: Commit**

```bash
git add DriveMap-Diagnostics/Watch-DriveMapActivity.ps1 DriveMap-Diagnostics/Tests/Watch-DriveMapActivity.Tests.ps1
git commit -m "feat: add drive map activity watcher

Polls the drive letter and captures the moment it disappears with the
surrounding context, classifying the timing as logon, policy refresh or
unexplained - the discriminator a post-hoc snapshot cannot provide.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Correlation and verdicts — Invoke-DriveMapInvestigation.ps1

The orchestrator, and the home of the ranked-cause logic from spec §6.

**Files:**
- Create: `DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1`
- Test: `DriveMap-Diagnostics/Tests/Invoke-DriveMapInvestigation.Tests.ps1`

**Interfaces:**
- Consumes: `DriveMapReference.psd1`; runs Tasks 2–4 as child processes; runs `Audit-GPDriveMaps.ps1` and `Search-SYSVOLScripts.ps1` as child processes
- Produces:
  - `Resolve-CompanionScript -FileName <string> -ScriptRoot <string>` → string path or `$null`
  - `Invoke-Step -Name <string> -ScriptPath <string> -Arguments <hashtable> -CaseFolder <string>` → `[PSCustomObject]` with `Step`, `Script`, `Ran`, `ExitCode`, `Error`
  - `Get-DriveMapVerdict -Evidence <PSCustomObject>` → `[PSCustomObject][]` each with `Cause`, `Confidence` (`'High'`/`'Medium'`/`'Low'`), `Evidence` (string[]), `Remediation` (string[]), ordered most-confident first
  - `New-CaseSummary -DriveLetter <string> -Identity <string> -Verdicts <object[]> -Steps <object[]> -CaseFolder <string> -GeneratedOn <string>` → string
  - Script parameters: `-Identity <string>`, `-ComputerName <string>`, `-DriveLetter <string>`, `-EvidencePath <string>`, `-OutputPath <string>`, `-Force <switch>`, `-LoadFunctionsOnly <switch>`

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/Invoke-DriveMapInvestigation.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Invoke-DriveMapInvestigation.ps1" -LoadFunctionsOnly
}

Describe 'Get-DriveMapVerdict' {
    # Microsoft's documented scenario: every Group Policy event green, GPP trace showing
    # the drive mapped successfully, and the drive still gone - because a logon script in
    # an unrelated GPO deleted it afterwards. A report that stops at CSE success events
    # reports SUCCESS on a broken machine.
    # https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected
    It 'identifies a logon script deleting what Group Policy created' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied        = $true
            DrivePresent      = $false
            ScriptDeletions   = @([PSCustomObject]@{ Source = 'DomainWideSettings'; Line = 'net use x: /delete' })
            InRegistry        = $false
            InLiveMounts      = $false
            TargetingFailures = @()
            Action            = 'Replace'
            FastLogonOptimization  = $false
            AlwaysWaitForNetwork   = $true
            ElevatedVisible   = $true
            UnelevatedVisible = $true
            EnableLinkedConnections = 1
        })
        $v[0].Cause | Should -Match 'script'
        $v[0].Confidence | Should -Be 'High'
        ($v[0].Evidence -join ' ') | Should -Match 'DomainWideSettings'
    }

    It 'identifies the every-other-logon mechanism' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'every other logon'
    }

    It 'identifies a failing reconnect' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'reconnect'
    }

    # This is a visibility artifact, NOT a disappearing drive. Reporting it as a Group
    # Policy problem sends the technician to audit a GPO for a drive that was never gone.
    It 'identifies split-token visibility and does not call it a disappearance' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $true; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $true; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $true; EnableLinkedConnections = 0
        })
        $v[0].Cause | Should -Match 'elevated|visibility'
        ($v[0].Remediation -join ' ') | Should -Match 'EnableLinkedConnections'
    }

    It 'identifies item-level targeting failures' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false
            TargetingFailures = @([PSCustomObject]@{ EventId = 4105; Gpo = 'Map-X-Drive' })
            Action = 'Replace'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Cause -join ' ') | Should -Match 'targeting'
    }

    # An unresolved case is a finding with a next step, never a blank page.
    It 'returns an explicit no-cause-identified verdict when nothing matches' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $true; ScriptDeletions = @()
            InRegistry = $true; InLiveMounts = $true; TargetingFailures = @()
            Action = 'Create'; FastLogonOptimization = $false; AlwaysWaitForNetwork = $true
            ElevatedVisible = $true; UnelevatedVisible = $true; EnableLinkedConnections = 1
        })
        $v | Should -Not -BeNullOrEmpty
        $v[0].Cause | Should -Match 'No cause identified'
        $v[0].Remediation | Should -Not -BeNullOrEmpty
    }

    It 'orders verdicts most-confident first' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $true; DrivePresent = $false
            ScriptDeletions = @([PSCustomObject]@{ Source = 'GPO-A'; Line = 'net use x: /delete' })
            InRegistry = $true; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        $v.Count | Should -BeGreaterThan 1
        $v[0].Confidence | Should -Be 'High'
    }

    # Microsoft explicitly advises against NoBackgroundPolicy=0 and it does not reliably
    # work. It must never appear in a remediation.
    It 'never recommends NoBackgroundPolicy=0 in any verdict' {
        $v = Get-DriveMapVerdict -Evidence ([PSCustomObject]@{
            GppApplied = $false; DrivePresent = $false; ScriptDeletions = @()
            InRegistry = $false; InLiveMounts = $false; TargetingFailures = @()
            Action = 'Replace'; FastLogonOptimization = $true; AlwaysWaitForNetwork = $false
            ElevatedVisible = $false; UnelevatedVisible = $false; EnableLinkedConnections = 1
        })
        ($v.Remediation -join ' ') | Should -Not -Match 'NoBackgroundPolicy'
    }
}

Describe 'Resolve-CompanionScript' {
    It 'returns null when the companion is absent' {
        Resolve-CompanionScript -FileName 'Nope-DoesNotExist.ps1' -ScriptRoot $TestDrive | Should -BeNullOrEmpty
    }

    It 'finds a companion sitting beside the script' {
        New-Item -Path (Join-Path $TestDrive 'Audit-GPDriveMaps.ps1') -ItemType File -Force | Out-Null
        Resolve-CompanionScript -FileName 'Audit-GPDriveMaps.ps1' -ScriptRoot $TestDrive | Should -Not -BeNullOrEmpty
    }
}

Describe 'New-CaseSummary' {
    It 'names the top verdict in the summary text' {
        $summary = New-CaseSummary -DriveLetter 'X' -Identity 'jsmith' `
            -Verdicts @([PSCustomObject]@{
                Cause = 'A logon script deletes the drive after Group Policy maps it'
                Confidence = 'High'; Evidence = @('GPO: DomainWideSettings'); Remediation = @('Remove the script')
            }) `
            -Steps @() -CaseFolder 'C:\Cases\X' -GeneratedOn '2026-09-14 10:00:00'
        $summary | Should -Match 'logon script'
        $summary | Should -Match 'jsmith'
        $summary | Should -Match 'X'
    }

    It 'states plainly when a step could not run' {
        $summary = New-CaseSummary -DriveLetter 'X' -Identity 'jsmith' -Verdicts @() `
            -Steps @([PSCustomObject]@{ Step = 'Domain drive maps'; Ran = $false; Error = 'Script not found' }) `
            -CaseFolder 'C:\Cases\X' -GeneratedOn '2026-09-14 10:00:00'
        $summary | Should -Match 'Script not found'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\Invoke-DriveMapInvestigation.Tests.ps1 -Output Detailed`
Expected: FAIL — script does not exist.

- [ ] **Step 3: Write the script**

Create `DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1`.

Copy `Resolve-CompanionScript` and `Invoke-Step` from
`AD-LockoutDiagnostics\Invoke-ADLockoutInvestigation.ps1:218-290`, adjusting the candidate
paths to `AD-GroupPolicy-DriveMaps` and `Search-SYSVOLScripts`. Keep the quoting logic
intact — it exists so a path containing an apostrophe cannot break out of the child command.

`Get-DriveMapVerdict` implements spec §6's table. Evaluate every rule (a machine can have
more than one problem), assign confidence, sort most-confident first, and when no rule
matches return the explicit `'No cause identified'` verdict listing what was ruled out and
what to collect next. Never emit an empty array.

Orchestration: run the gate; unless `-Force`, stop when blind and say which condition is
blind. Then collect endpoint evidence (over remoting, or from `-EvidencePath` when a bundle
was collected by hand), run `Audit-GPDriveMaps.ps1 -TargetUser -TargetComputer` and
`Search-SYSVOLScripts.ps1 -SearchPattern` for the drive letter, assemble the evidence
object, call `Get-DriveMapVerdict`, write `SUMMARY.txt`, and invoke Task 6's report script.

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\Invoke-DriveMapInvestigation.Tests.ps1 -Output Detailed`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1 DriveMap-Diagnostics/Tests/Invoke-DriveMapInvestigation.Tests.ps1
git commit -m "feat: add drive map investigation orchestrator

Sequences the gate, endpoint collection and the two existing domain-side
scripts, then maps the combined evidence to ranked causes. Reuses
Audit-GPDriveMaps.ps1 and Search-SYSVOLScripts.ps1 unmodified.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Case report — New-DriveMapCaseReport.ps1

**Files:**
- Create: `DriveMap-Diagnostics/New-DriveMapCaseReport.ps1`
- Test: `DriveMap-Diagnostics/Tests/New-DriveMapCaseReport.Tests.ps1`

**Interfaces:**
- Consumes: the case folder and verdict objects produced by Task 5
- Produces:
  - `ConvertTo-SafeHtml -Text <string>` → string with `&`, `<`, `>`, `"` escaped
  - `New-ReportTab -Title <string> -Content <string> -Index <int>` → string (HTML fragment)
  - `New-CollectionStateBadge -State <string>` → string (HTML span; distinct rendering for each of the three states)
  - `New-DriveMapHtmlReport -Verdicts <object[]> -Sections <hashtable> -DriveLetter <string> -Identity <string> -GeneratedOn <string>` → string (complete HTML document)
  - Script parameters: `-CaseFolder <string>`, `-OutputPath <string>`, `-SkipBrowserOpen <switch>`, `-LoadFunctionsOnly <switch>`

- [ ] **Step 1: Write the failing test**

Create `DriveMap-Diagnostics/Tests/New-DriveMapCaseReport.Tests.ps1`:

```powershell
BeforeAll {
    . "$PSScriptRoot\..\New-DriveMapCaseReport.ps1" -LoadFunctionsOnly
}

Describe 'ConvertTo-SafeHtml' {
    # UNC paths and script lines land in the report verbatim. An unescaped angle bracket
    # from a script line would break the document.
    It 'escapes HTML metacharacters' {
        ConvertTo-SafeHtml -Text '<script>' | Should -Be '&lt;script&gt;'
        ConvertTo-SafeHtml -Text 'a & b'    | Should -Be 'a &amp; b'
    }
    It 'escapes ampersands before angle brackets so entities are not double-escaped' {
        ConvertTo-SafeHtml -Text '<a & b>' | Should -Be '&lt;a &amp; b&gt;'
    }
    It 'passes a UNC path through unchanged' {
        ConvertTo-SafeHtml -Text '\\server\share' | Should -Be '\\server\share'
    }
    It 'returns empty string for null input' {
        ConvertTo-SafeHtml -Text $null | Should -Be ''
    }
}

Describe 'New-CollectionStateBadge' {
    # The three states must remain visually distinct all the way into the report. If
    # "could not look" renders the same as "nothing found", the whole design is defeated
    # at the last step.
    It 'renders the three states distinguishably' {
        $found   = New-CollectionStateBadge -State 'Found'
        $empty   = New-CollectionStateBadge -State 'EmptyButValid'
        $blind   = New-CollectionStateBadge -State 'CouldNotCollect'

        $found | Should -Not -Be $empty
        $empty | Should -Not -Be $blind
        $found | Should -Not -Be $blind
    }

    It 'makes clear that CouldNotCollect is not a clean result' {
        New-CollectionStateBadge -State 'CouldNotCollect' | Should -Match 'not|could'
    }
}

Describe 'New-DriveMapHtmlReport' {
    It 'produces a complete HTML document' {
        $html = New-DriveMapHtmlReport -Verdicts @() -Sections @{} -DriveLetter 'X' `
                    -Identity 'jsmith' -GeneratedOn '2026-09-14 10:00:00'
        $html | Should -Match '(?i)<!DOCTYPE html>'
        $html | Should -Match '(?i)</html>'
    }

    It 'shows the drive letter and account in the header' {
        $html = New-DriveMapHtmlReport -Verdicts @() -Sections @{} -DriveLetter 'X' `
                    -Identity 'jsmith' -GeneratedOn '2026-09-14 10:00:00'
        $html | Should -Match 'X'
        $html | Should -Match 'jsmith'
    }

    # Confidence is a visible tag, never a buried field - a guess must never read as fact.
    It 'renders the confidence of every verdict' {
        $html = New-DriveMapHtmlReport -DriveLetter 'X' -Identity 'jsmith' `
                    -GeneratedOn '2026-09-14 10:00:00' -Sections @{} `
                    -Verdicts @([PSCustomObject]@{
                        Cause = 'A logon script deletes the drive'; Confidence = 'High'
                        Evidence = @('GPO: DomainWideSettings'); Remediation = @('Remove the script')
                    })
        $html | Should -Match 'High'
        $html | Should -Match 'logon script'
    }

    It 'escapes verdict text rather than emitting it raw' {
        $html = New-DriveMapHtmlReport -DriveLetter 'X' -Identity 'jsmith' `
                    -GeneratedOn '2026-09-14 10:00:00' -Sections @{} `
                    -Verdicts @([PSCustomObject]@{
                        Cause = 'Bad <script>alert(1)</script>'; Confidence = 'Low'
                        Evidence = @(); Remediation = @()
                    })
        $html | Should -Not -Match '<script>alert'
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `Invoke-Pester -Path .\Tests\New-DriveMapCaseReport.Tests.ps1 -Output Detailed`
Expected: FAIL — script does not exist.

- [ ] **Step 3: Write the script**

Create `DriveMap-Diagnostics/New-DriveMapCaseReport.ps1`.

`ConvertTo-SafeHtml` must replace `&` first, then `<`, `>`, `"`, or entities get
double-escaped. Tabs are ordered by the five questions from spec §1, with findings on
screen at open. Style follows `Audit-GPDriveMaps.ps1`'s existing report for visual
consistency; per CLAUDE.md design context, dark default with the blue accent, plain-English
labels, density with breathing room. Group repeated evidence — "this letter disappeared 14
times, all within 3 minutes of logon" is the finding, not 14 near-identical rows.

- [ ] **Step 4: Run test to verify it passes**

Run: `Invoke-Pester -Path .\Tests\New-DriveMapCaseReport.Tests.ps1 -Output Detailed`
Expected: PASS, 12 tests.

- [ ] **Step 5: Verify the report renders**

Generate a report from a case folder produced in Task 5, open it in a browser, and confirm:
tabs switch correctly, findings are visible without scrolling, and a `CouldNotCollect`
section is visually distinct from an empty one.

- [ ] **Step 6: Commit**

```bash
git add DriveMap-Diagnostics/New-DriveMapCaseReport.ps1 DriveMap-Diagnostics/Tests/New-DriveMapCaseReport.Tests.ps1
git commit -m "feat: add drive map case report

One combined tabbed HTML report ordered by the five investigation
questions, with confidence shown as a visible tag and the three
collection states rendered distinguishably.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: README and full-suite verification

**Files:**
- Create: `DriveMap-Diagnostics/README.md`
- Modify: `README.md` (repository root — add the new folder to its tool list, matching the existing entry format)

- [ ] **Step 1: Run the full test suite**

Run: `Invoke-Pester -Path .\Tests\ -Output Detailed`
Expected: PASS, roughly 74 tests across six files. Fix any failure before continuing —
do not write the README against a failing suite.

- [ ] **Step 2: Write the toolkit README**

Create `DriveMap-Diagnostics/README.md` following `AD-LockoutDiagnostics/README.md`'s
shape: a "Start here" section, the individual tools table, a parameters table per script,
requirements, and output files.

It must include:

- **Start here:** `.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X`
- **Why the gate exists**, in the README's own words: GPP logging is off by default, so an
  empty report and a healthy machine are indistinguishable without checking first.
- **An "If the drive disappears on some logons but not others" section** pointing at the
  every-other-logon mechanism (spec §3.3) as the first thing to check, with the
  `Test-DriveMapLoggingReadiness.ps1` command that reports it.
- **A "Setting up PS Remoting" section**, since the operator has stated they will likely
  need it. Cover: `Enable-PSRemoting -Force` on the target; `Test-WSMan -ComputerName <name>`
  to verify; the TrustedHosts requirement for non-domain-joined targets
  (`Set-Item WSMan:\localhost\Client\TrustedHosts`); the firewall rule; and that the whole
  section is optional because `Export-DriveMapEvidence.ps1` can be run locally and the
  bundle handed back via `-EvidencePath`. **Verify each cmdlet and its behavior against
  learn.microsoft.com before writing this section** — do not write remoting setup steps
  from memory.
- **A REFERENCES section** listing the five Microsoft Learn URLs from spec §3.

- [ ] **Step 3: Add the toolkit to the repository README**

Add a `DriveMap-Diagnostics` row to the root `README.md` tool list, matching the format of
the surrounding entries.

- [ ] **Step 4: Commit**

```bash
git add DriveMap-Diagnostics/README.md README.md
git commit -m "docs: add Drive Map Diagnostics README

Includes a PS Remoting setup section and a first-thing-to-check pointer
for drives that disappear on alternating logons.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: §2 three-state rule → Task 2 Step 1
and Task 3's manifest tests; §2.1 self-repairing gate → Task 2 `-EnableLogging`; §3.1 GPP
events → Task 1; §3.2 Replace semantics → Task 2 `Get-EveryOtherLogonRisk`; §3.3
every-other-logon → Tasks 2, 5, 7; §3.4 split-token → Tasks 2, 3, 5; §3.5 script-deletes-drive
→ Tasks 3, 5; §4 architecture → Tasks 2–6; §5 evidence → Tasks 2–4; §6 verdicts → Task 5;
§6.1 traps → tests in Tasks 2 and 5 (including explicit "never recommends NoBackgroundPolicy"
guards); §7 output → Task 6; §8 conventions → Global Constraints; §9 testing → every task;
§10 out-of-scope → no task touches the two reused scripts.

**Placeholder scan.** No TBD/TODO. Every code step carries real code. No "similar to Task N".

**Type consistency.** `New-CollectionResult` returns the same `State`/`Data`/`Reason` shape
in Tasks 2 and 3, consumed by `New-EvidenceManifest` (Task 3) and `New-CollectionStateBadge`
(Task 6). `Get-DriveMapVerdict`'s output (`Cause`/`Confidence`/`Evidence`/`Remediation`) is
consumed with those exact property names by `New-CaseSummary` (Task 5) and
`New-DriveMapHtmlReport` (Task 6). `Write-Status` has one signature throughout.

**One deliberate deviation from DRY, called out so no one "fixes" it:** `Write-Status` and
`New-CollectionResult` are re-declared in each script rather than shared through a module.
This matches CLAUDE.md — "no shared modules… keep scripts flat and self-contained" — because
these scripts are deployed individually to target machines and must run standing alone. The
duplication is the deployment model, not an oversight.
