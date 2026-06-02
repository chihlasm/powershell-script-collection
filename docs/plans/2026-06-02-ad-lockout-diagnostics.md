# AD Account Lockout Diagnostics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `Diagnose-ADAccountLockout.ps1`, a single-user lockout investigator that traces the source of repeated account lockouts and outputs a dark-themed HTML report.

**Architecture:** One self-contained `.ps1` script in a new `AD-LockoutDiagnostics/` folder. Pure-logic helpers (event-XML parsing, verdict ranking) are written as standalone functions so they can be Pester-tested without a live domain; the domain-bound functions (AD queries, `Get-WinEvent` against DCs) are manually verified against a real domain. Output is a self-contained HTML file.

**Tech Stack:** PowerShell 5.1, ActiveDirectory RSAT module, `Get-WinEvent` (event IDs 4740/4625/4771/4724), Pester 5 (for the pure-logic tests only — already used by `DiskSpdDiagnostic`).

**Testing note:** This repo has no test framework for most scripts. Domain-bound logic is verified manually on a DC/admin box. Only the pure parsing/verdict helpers get Pester tests (no domain needed). Each task ends with a concrete verification step and a commit.

---

## Reference: Event IDs

| ID | Log | Meaning | Key fields |
|----|-----|---------|-----------|
| 4740 | Security (PDC authoritative) | Account locked out | TargetUserName, **TargetDomainName**, **CallerComputerName** |
| 4625 | Security (per DC) | Failed logon | TargetUserName, IpAddress, WorkstationName, LogonType, SubStatus |
| 4771 | Security (per DC) | Kerberos pre-auth failed | TargetUserName, IpAddress (Client Address), Status (0x18 = bad pw) |
| 4724 | Security (per DC) | Password reset attempt | TargetUserName, SubjectUserName (who did it) |

---

## Task 1: Scaffold folder, help block, param block

**Files:**
- Create: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Create the file with `#Requires -Version 5.1`, full comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER` for each, two `.EXAMPLE`s, `.NOTES`), and the `[CmdletBinding()]` param block:

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses why an Active Directory account keeps locking out and traces the source.
.DESCRIPTION
    Investigates repeated account lockouts (often mistaken for forced password resets).
    Reads account state and effective lockout policy (including any Fine-Grained
    Password Policy) from the PDC emulator, builds a lockout timeline from event 4740,
    traces bad-password sources via 4625/4771 across all DCs, flags admin resets (4724),
    and writes a ranked-verdict HTML report.
.PARAMETER Identity
    SamAccountName, UPN, or DN of the user to investigate.
.PARAMETER OutputPath
    Folder where the HTML report is written. Defaults to the current directory.
.PARAMETER DaysBack
    How many days of Security event logs to search. 1-90, default 7.
.PARAMETER DomainController
    Optional. One or more DC names to query instead of auto-discovering all DCs.
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe
.EXAMPLE
    .\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath C:\Reports
.NOTES
    Run on a DC or admin box with RSAT. Requires permission to read DC Security logs.
    Hybrid/Entra lockouts are out of scope (lockouts originate on-prem).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Identity,

    [string]$OutputPath = (Get-Location).Path,

    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [string[]]$DomainController
)
```

**Step 2: Verify** the file parses:
Run: `powershell -NoProfile -Command "[scriptblock]::Create((Get-Content -Raw '.\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1')) | Out-Null; 'OK'"`
Expected: `OK`

**Step 3: Commit**
```bash
git add AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1
git commit -m "feat: scaffold Diagnose-ADAccountLockout with help and params"
```

---

## Task 2: Console logging helper + module import

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add a `Write-Status` helper (dual console pattern per repo convention) and the AD module import in try/catch:

```powershell
function Write-Status {
    param(
        [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Level,
        [string]$Message
    )
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Status FAIL "ActiveDirectory module not found. Install RSAT and retry."
    exit 1
}
```

**Step 2: Verify** parse again (same command as Task 1 Step 2). On a domain box, run the script with a bogus identity to confirm the import path runs without crashing before AD lookups.

**Step 3: Commit**
```bash
git commit -am "feat: add Write-Status helper and AD module import"
```

---

## Task 3: Resolve user + locate PDC emulator

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add resolution logic. Find the PDC first (authoritative for 4740 and for current counters), then resolve the user against it:

```powershell
try {
    $pdc = (Get-ADDomain -ErrorAction Stop).PDCEmulator
    Write-Status INFO "PDC emulator: $pdc"
} catch {
    Write-Status FAIL "Could not contact the domain. $($_.Exception.Message)"
    exit 1
}

$props = @('LockedOut','badPwdCount','lockoutTime','pwdLastSet',
           'LastBadPasswordAttempt','whenChanged','msDS-User-Account-Control-Computed')
try {
    $user = Get-ADUser -Identity $Identity -Server $pdc -Properties $props -ErrorAction Stop
    Write-Status PASS "Resolved user: $($user.SamAccountName) ($($user.DistinguishedName))"
} catch {
    Write-Status FAIL "Could not resolve identity '$Identity'. $($_.Exception.Message)"
    exit 1
}
```

**Step 2: Verify** on a domain box: run `-Identity <real user>` → PASS line with DN; run `-Identity nosuchuser123` → FAIL and exit.

**Step 3: Commit**
```bash
git commit -am "feat: resolve user against PDC emulator"
```

---

## Task 4: Effective lockout policy (FGPP-aware)

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add `Get-EffectiveLockoutPolicy` — try resultant (FGPP) first, fall back to default domain policy. Return a `[PSCustomObject]` with `Source`, `LockoutThreshold`, `LockoutObservationWindow`, `LockoutDuration`:

```powershell
function Get-EffectiveLockoutPolicy {
    param($User, $Server)
    try {
        $fgpp = Get-ADUserResultantPasswordPolicy -Identity $User -Server $Server -ErrorAction Stop
        if ($fgpp) {
            return [PSCustomObject]@{
                Source                  = "Fine-Grained ($($fgpp.Name))"
                LockoutThreshold        = $fgpp.LockoutThreshold
                LockoutObservationWindow= $fgpp.LockoutObservationWindow
                LockoutDuration         = $fgpp.LockoutDuration
            }
        }
    } catch { }
    $d = Get-ADDefaultDomainPasswordPolicy -Server $Server
    [PSCustomObject]@{
        Source                  = 'Default Domain Policy'
        LockoutThreshold        = $d.LockoutThreshold
        LockoutObservationWindow= $d.LockoutObservationWindow
        LockoutDuration         = $d.LockoutDuration
    }
}
$policy = Get-EffectiveLockoutPolicy -User $user -Server $pdc
Write-Status INFO "Lockout policy ($($policy.Source)): threshold=$($policy.LockoutThreshold)"
```

**Step 2: Verify** on a domain box: confirm threshold matches `Get-ADDefaultDomainPasswordPolicy`; if the user has an FGPP, confirm Source names it.

**Step 3: Commit**
```bash
git commit -am "feat: add FGPP-aware effective lockout policy lookup"
```

---

## Task 5: Pure-logic helper — parse a 4740 event (Pester-tested)

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`
- Create: `AD-LockoutDiagnostics/Tests/Diagnose-ADAccountLockout.Tests.ps1`

**Why a helper:** parsing `Get-WinEvent` XML is pure string logic — testable without a domain. Factor it out.

**Step 1: Write the failing test** (`Tests/Diagnose-ADAccountLockout.Tests.ps1`):

```powershell
BeforeAll {
    . "$PSScriptRoot\..\Diagnose-ADAccountLockout.ps1" -Identity '__pester__' -WhatIf 4>$null 3>$null 2>$null
}
# NOTE: dot-sourcing must NOT execute the body. See Task 11 (guard with a -LoadFunctionsOnly switch).

Describe 'ConvertFrom-LockoutEvent' {
    It 'extracts TargetUserName and CallerComputerName from event XML' {
        $xml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><TimeCreated SystemTime="2026-06-01T13:05:00.000Z"/></System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="CallerComputerName">LAPTOP-7</Data>
  </EventData>
</Event>
'@
        $row = ConvertFrom-LockoutEvent -EventXml $xml -DcName 'DC01'
        $row.User           | Should -Be 'jdoe'
        $row.CallerComputer | Should -Be 'LAPTOP-7'
        $row.DC             | Should -Be 'DC01'
    }
}
```

**Step 2: Run, expect fail:**
Run: `Invoke-Pester .\AD-LockoutDiagnostics\Tests\ -Output Detailed`
Expected: FAIL — `ConvertFrom-LockoutEvent` not defined.

**Step 3: Implement** in the script (place above the body, after `Write-Status`):

```powershell
function ConvertFrom-LockoutEvent {
    param([string]$EventXml, [string]$DcName)
    $x = [xml]$EventXml
    $d = @{}
    foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
    [PSCustomObject]@{
        Time           = [datetime]$x.Event.System.TimeCreated.SystemTime
        User           = $d['TargetUserName']
        Domain         = $d['TargetDomainName']
        CallerComputer = $d['CallerComputerName']
        DC             = $DcName
    }
}
```

**Step 4: Run, expect pass** (same Pester command).

**Step 5: Commit**
```bash
git add AD-LockoutDiagnostics/
git commit -m "feat: add ConvertFrom-LockoutEvent parser with Pester test"
```

---

## Task 6: Pure-logic helper — parse 4625/4771 source events (Pester-tested)

**Files:**
- Modify: script + test file

**Step 1: Write failing tests** for `ConvertFrom-BadLogonEvent` covering both a 4625 (WorkstationName + IpAddress + LogonType) and a 4771 (Client Address `IpAddress`, Status). Assert `SourceHost`, `SourceIp`, `LogonType`, `EventId`.

**Step 2: Run, expect fail.**

**Step 3: Implement** `ConvertFrom-BadLogonEvent` — same XML-walk pattern, mapping the differing field names per event ID (4625 → `IpAddress`/`WorkstationName`/`LogonType`; 4771 → `IpAddress`/`Status`). Normalize `IpAddress` of `-` or `::1` to `(local)`.

**Step 4: Run, expect pass.**

**Step 5: Commit**
```bash
git commit -am "feat: add ConvertFrom-BadLogonEvent parser with Pester tests"
```

---

## Task 7: Pure-logic helper — verdict ranking (Pester-tested)

**Files:**
- Modify: script + test file

**Step 1: Write failing tests** for `Get-LockoutVerdict` given arrays of parsed rows + the policy object. Assert ranked string output for:
- One caller computer dominates 4740s → "stale cached credential on <host>".
- `LockoutThreshold` ≤ 3 → includes "aggressive lockout policy" note.
- No events at all → includes "no on-prem evidence … consider hybrid/Entra".

```powershell
Describe 'Get-LockoutVerdict' {
    It 'fingers the dominant caller computer' {
        $lockouts = @(
            [PSCustomObject]@{CallerComputer='LAPTOP-7'},
            [PSCustomObject]@{CallerComputer='LAPTOP-7'},
            [PSCustomObject]@{CallerComputer='PHONE-1'}
        )
        $v = Get-LockoutVerdict -Lockouts $lockouts -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'LAPTOP-7'
    }
    It 'flags aggressive policy' {
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=3})
        ($v -join ' ') | Should -Match 'aggressive'
    }
    It 'notes no evidence' {
        $v = Get-LockoutVerdict -Lockouts @() -BadLogons @() -Policy ([PSCustomObject]@{LockoutThreshold=5})
        ($v -join ' ') | Should -Match 'no on-prem'
    }
}
```

**Step 2: Run, expect fail.**

**Step 3: Implement** `Get-LockoutVerdict` returning an ordered string array of findings (group lockouts by CallerComputer, take the top; check threshold; handle empty).

**Step 4: Run, expect pass.**

**Step 5: Commit**
```bash
git commit -am "feat: add Get-LockoutVerdict ranking with Pester tests"
```

---

## Task 8: Query 4740 on the PDC

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add `Get-LockoutEvents` — `Get-WinEvent -ComputerName $pdc` with a FilterHashtable (`LogName='Security'; Id=4740; StartTime=(Get-Date).AddDays(-$DaysBack)`), in try/catch. For each event, call `ConvertFrom-LockoutEvent` on `$_.ToXml()` and keep rows where `User` matches `$user.SamAccountName` (case-insensitive). "No events" (`Get-WinEvent` throws "No events were found") → `[WARN]`, return `@()`.

**Step 2: Verify** on a domain box against a user known to have locked out: confirm rows with timestamps + caller computers; confirm a clean user yields a graceful WARN.

**Step 3: Commit**
```bash
git commit -am "feat: query 4740 lockout events on PDC"
```

---

## Task 9: Query 4625/4771 + 4724 across all DCs

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add DC discovery and per-DC querying:

```powershell
$dcs = if ($DomainController) { $DomainController }
       else { (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName) }

$badLogons = @(); $resets = @()
foreach ($dc in $dcs) {
    try {
        $filter = @{ LogName='Security'; Id=4625,4771,4724;
                     StartTime=(Get-Date).AddDays(-$DaysBack) }
        $events = Get-WinEvent -ComputerName $dc -FilterHashtable $filter -ErrorAction Stop
        # split by Id; parse 4625/4771 via ConvertFrom-BadLogonEvent, filter to user;
        # parse 4724 (TargetUserName + SubjectUserName) into $resets
        Write-Status PASS "$dc: queried Security log"
    } catch {
        Write-Status WARN "$dc: $($_.Exception.Message)"
        continue
    }
}
```

Filter every parsed row to `$user.SamAccountName`. One unreachable DC must not halt the run (`continue`).

**Step 2: Verify** on a multi-DC domain: confirm each DC logs PASS or WARN; confirm bad-logon rows carry source host/IP/logon type; confirm a `-DomainController DC01` override queries only that DC.

**Step 3: Commit**
```bash
git commit -am "feat: query 4625/4771/4724 across all DCs with per-DC error handling"
```

---

## Task 10: HTML report writer

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add `Write-LockoutReport` building a self-contained dark-themed HTML string (inline CSS, blue `#5dade2` accent per repo design context). Sections in order: **Verdict** (from `Get-LockoutVerdict`), **Account State**, **Effective Policy**, **Lockout Timeline (4740)**, **Bad-Password Sources (4625/4771)**, **Admin Resets (4724)**. Use `ConvertTo-Html -Fragment` for the tables, wrap in the themed shell. Filename: `ADLockout_<sam>_yyyy-MM-dd_HHmmss.html` in `$OutputPath`. `Set-Content -Encoding UTF8`. Print the full path with `[PASS]`. Create `$OutputPath` if missing.

**Step 2: Verify** on a domain box: open the produced HTML — verdict at top, all six sections render, dark theme, path printed to console.

**Step 3: Commit**
```bash
git commit -am "feat: add dark-themed HTML lockout report writer"
```

---

## Task 11: Wire the orchestration body + dot-source guard

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

**Step 1:** Add a guard so the test file can dot-source the functions without executing the body. Add a hidden switch to the param block:

```powershell
[switch]$LoadFunctionsOnly
```
and wrap the orchestration (Tasks 3,4,8,9,10 calls) in:
```powershell
if (-not $LoadFunctionsOnly) {
    # resolve user, policy, lockouts, badLogons, resets, verdict, write report
}
```
Update the test `BeforeAll` to `. $script -Identity '__x__' -LoadFunctionsOnly`.

**Step 2:** Order the body: resolve → policy → 4740 → all-DC 4625/4771/4724 → verdict → report. End with a console echo of the verdict lines and the report path.

**Step 3: Verify** end-to-end on a domain box against the real problem user; re-run Pester to confirm dot-sourcing still loads functions only.
Run: `Invoke-Pester .\AD-LockoutDiagnostics\Tests\ -Output Detailed` → all pass.

**Step 4: Commit**
```bash
git commit -am "feat: wire orchestration body with dot-source guard for tests"
```

---

## Task 12: README

**Files:**
- Create: `AD-LockoutDiagnostics/README.md`

**Step 1:** Write README: purpose (lockout investigation, not password expiry), the stale-credential explanation, prerequisites (RSAT, DC Security-log read rights, run on DC/admin box), parameter table, two usage examples, "How to read the report" (verdict + caller computer = the machine to clean), and the event-ID reference table. Note hybrid/Entra is out of scope with a pointer to the future enhancement.

**Step 2: Verify** links/paths correct; examples match actual params.

**Step 3: Commit**
```bash
git add AD-LockoutDiagnostics/README.md
git commit -m "docs: add README for AD lockout diagnostics tool"
```

---

## Done criteria

- `Invoke-Pester .\AD-LockoutDiagnostics\Tests\` → all pass (parser + verdict helpers).
- Manual run on a DC/admin box against the problem user produces an HTML report with a verdict naming the likely source machine.
- One unreachable DC produces a WARN and the run completes.
- A clean (never-locked) user produces graceful WARNs and a "no on-prem evidence" verdict.
