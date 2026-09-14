# Drive Map Diagnostics Toolkit — Design

**Date:** 2026-09-14
**Status:** Approved for planning
**Folder:** `DriveMap-Diagnostics/`

## 1. The problem

A user's mapped drive (typically `X:`) disappears intermittently. The cause could be
Group Policy Preferences, a logon script, a manual persistent mount, a scheduled task, or
an interaction between them. The drive is present often enough that a snapshot taken after
the fact frequently catches a healthy machine.

The goal is to name the **mechanism** that removes or fails to create the drive, and the
**specific configuration object** behind it (which GPO, which script, which registry value).

The investigation answers five questions in order:

| # | Question | Evidence |
|---|----------|----------|
| 1 | **Can we trust this data?** | GPP logging/tracing state, Application log retention |
| 2 | **What should the user get?** | GPP drive maps + precedence (existing `Audit-GPDriveMaps.ps1`) |
| 3 | **What do they actually have?** | Endpoint registry, live mounts in both token contexts |
| 4 | **Who else is touching this letter?** | Logon scripts, scheduled tasks, startup items |
| 5 | **Why does it vanish?** | Ranked causes mapped to remediation |

## 2. The central design constraint

> **An empty report and a healthy machine look identical.**

Inherited from the AD Lockout toolkit brief, and sharper here because Group Policy
Preferences logging is **off by default**. Microsoft states plainly: *"Informational events
are only logged when the relevant Group Policy settings are enabled."*

Three independent blind conditions exist, each individually fatal to the investigation:

1. **GPP logging/tracing disabled** — no preference-item events were ever written
2. **Application log already rolled** — the fault predates log retention
3. **No GPP trace files** — a separate setting from event logging, with its own path

A run with all three blind produces a confident-looking report stating "no drive map
failures found." The gate detects and names which of the three is blind, and stops.
`-Force` collects anyway to document the gap on a ticket.

**Every collector must distinguish three states**, and they must remain distinct all the
way into the report:

- `Found` — looked, got data
- `EmptyButValid` — looked, nothing was there (a real, informative result)
- `CouldNotCollect(reason)` — could not look; asserts nothing

In PowerShell this is a `[PSCustomObject]` with a `State` property, never a bare array
whose emptiness is ambiguous. A collector that returns `@()` for both "nothing there" and
"access denied" has destroyed the distinction before the report can render it.

### 2.1 This gate can repair itself

Unlike the lockout toolkit's gate (audit policy on a DC, which the operator may not own),
this gate's remediation is a registry write on an endpoint the operator already administers.
So the gate offers `-EnableLogging`, which enables GPP logging and tracing and instructs the
operator to reproduce the fault.

This reframes the first run of an intermittent investigation from "diagnose now" to "start
recording." That is usually the correct first action and should be stated as such in the
console output, not buried.

## 3. Verified Microsoft facts

These shaped the architecture and were confirmed before this spec was written. Each is
cited in code next to the logic it justifies, per CLAUDE.md.

### 3.1 GPP events live in the Application log, not GroupPolicy/Operational

Two distinct evidence streams that are easy to conflate:

| Stream | Channel | What it tells you |
|--------|---------|-------------------|
| GP engine CSE processing | `Microsoft-Windows-GroupPolicy/Operational` | Whether the Drive Maps CSE ran at all (4016 start / 5016 success / 7016 error, 4001 policy start, 5312 applicable GPO list) |
| GPP preference items | **Application**, source `Group Policy Drive Maps` | Whether an individual drive item applied |

Preference-item event IDs:

| ID | Severity | Meaning |
|----|----------|---------|
| 4096 | Success | Preference item applied successfully |
| 4098 | Warning | Item did not apply — failed with an error code |
| 4101 | Success | Item successfully **removed** |
| 4105 | Warning | Did not apply because **a targeting item failed** |
| 4106 | Warning | Did not apply because **its targeting item failed** |
| 8194 | Warning | CSE could not process settings for a GPO |
| 8212 | Warning | Did not apply because a targeting item failed |

4105/4106/8212 are the item-level-targeting failures. They mean something different from
4098: the GPO was not applied *to this user*, versus the GPO tried and errored. These map to
different remediations and must never be merged.

Logging policy path:
`Computer Configuration\Policies\Administrative Templates\System\Group Policy\Logging and tracing`

Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events>

### 3.2 Replace mode deletes and recreates on every application

`Replace` performs a delete then a create — it is not an idempotent no-op. Under a slow or
unavailable network at the moment of refresh, the delete succeeds and the create fails,
leaving the user with no drive where they previously had one.

`Update` modifies only the settings defined in the preference item and does not delete
first. Notably, Update **cannot** change Location, Reconnect, or "Connect as" — those
require Replace.

Source: Drive Maps extension documentation (Server 2012 R2), confirmed 2026-09-14.

### 3.3 The every-other-logon mechanism — highest-value finding

The Drive Maps CSE:

- has `NoBackgroundPolicy = 1`, so it is **never called during background refresh**
- **only applies items when Group Policy processes synchronously**

With Fast Logon Optimization enabled (the default on client OS), logon processing is
asynchronous. The CSE therefore declines to apply, requests synchronous processing for the
*next* logon, and applies only then. Result: **the drive maps every other logon.**

This presents exactly as "the drive keeps disappearing" with no configuration change, and
is invisible to any check that only inspects the GPO. Remediations, in order of preference:

1. Enable **"Always wait for the network at computer startup and logon"**
   (`Computer Configuration\Policies\Administrative Templates\System\Logon`) — guarantees
   synchronous foreground processing every logon
2. Use **Create action + Reconnect** so the mount persists between sessions
3. Setting `NoBackgroundPolicy = 0` is **explicitly not recommended** by Microsoft and does
   not actually guarantee application — the toolkit must not suggest it

Source: <https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon>

### 3.4 Split-token / EnableLinkedConnections

With UAC enabled, logon creates **two linked logon sessions** (elevated and filtered).
Drive mappings are symbolic link objects (DosDevices) that are **per-logon-session and not
shared**. A drive mapped in one context is genuinely absent from the other.

Fix: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
`EnableLinkedConnections` (DWORD) = `1`.

Caveat to encode: when UAC is set to **Prompt for credentials**, a third logon session is
created and previously established symbolic links are unavailable in it — so
`EnableLinkedConnections = 1` does not fully resolve that configuration.

**This is a visibility artifact, not a disappearing drive.** Diagnosing it as a GPO problem
sends the technician to audit Group Policy for a drive that was never missing. This is why
the collector must enumerate mounts in **both token contexts** — collecting from only one
produces a confidently wrong answer.

Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command>

### 3.5 "GPO applied successfully" does not mean the drive is present

Microsoft's own scenario guide documents a case matching this investigation: every Group
Policy event healthy (4001, 5017, 5312, 4016 all green), GPP trace showing
`Completed class <Drive> - Z:` and the success event — and the drive still absent, because a
logon script in an *unrelated* GPO ran `net use z: /delete` afterwards.

The process chain was `GPScript.exe` → `cmd.exe` → `net.exe`, running a `.bat` from a
different GPO's `\User\Scripts\Logon\` folder.

Consequence for design: **a report that stops at CSE success events reports success on a
broken machine.** Question 4 ("who else is touching this letter?") is not optional
enrichment — it is the step that solves Microsoft's own documented example.

Source: <https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected>

## 4. Architecture

Five new scripts, flat in `DriveMap-Diagnostics/`, plus `Tests/`. Two existing scripts are
**reused unmodified** via the lockout toolkit's `Resolve-CompanionScript` pattern (located
beside the script or in a sibling folder; skipped with an explicit note if absent).

| Script | Runs on | Role |
|--------|---------|------|
| `Test-DriveMapLoggingReadiness.ps1` | endpoint | **Gate.** Blind-condition check + config root causes. `-EnableLogging` repairs. |
| `Export-DriveMapEvidence.ps1` | endpoint | Snapshot → portable evidence bundle |
| `Watch-DriveMapActivity.ps1` | endpoint | Catches the disappearance transition |
| `Invoke-DriveMapInvestigation.ps1` | operator workstation | Orchestrator; case folder + `SUMMARY.txt` |
| `New-DriveMapCaseReport.ps1` | operator workstation | Combined tabbed HTML report |

Reused:

- `AD-GroupPolicy-DriveMaps\Audit-GPDriveMaps.ps1` — question 2, invoked with
  `-TargetUser` / `-TargetComputer` for precedence simulation (already loopback-aware)
- `Search-SYSVOLScripts\Search-SYSVOLScripts.ps1` — question 4, searching SYSVOL for the
  drive letter

Endpoint collection works **either** over PS Remoting **or** by running the collector
locally and handing back the bundle. Neither path is privileged; the orchestrator accepts a
pre-collected bundle via `-EvidencePath`.

### 4.1 Why endpoint and domain collection stay separate

They require different rights, may run on different machines, and fail independently. A
single script would make an unreachable endpoint abort the domain-side collection that
would still have been useful. Each is separately runnable and separately testable.

## 5. Evidence collected

### 5.1 `Test-DriveMapLoggingReadiness.ps1`

Read-only by default. Reports both blind conditions and configuration root causes — this
script alone frequently solves the case.

- GPP logging and tracing enabled? Trace file path and current size
- Application log: max size, retention mode, oldest retained event (can we see far enough back?)
- `Microsoft-Windows-GroupPolicy/Operational` enabled and retention
- Fast Logon Optimization state; "Always wait for the network at computer startup and logon"
- `EnableLinkedConnections` value
- Drive Maps CSE `NoBackgroundPolicy` value
- Whether 4688 process-creation auditing is on (determines watcher fidelity)

`-EnableLogging` sets GPP logging + tracing, then prints reproduce-the-fault instructions.

### 5.2 `Export-DriveMapEvidence.ps1`

| Evidence | Diagnostic value |
|----------|------------------|
| `HKCU\Network\<letter>` (`RemotePath`, `ProviderName`, `ConnectionType`, `UserName`) | The persistent-mount record. Present here but absent from live mounts = **reconnect failing**, a different root cause from policy failing |
| Live mounts, **both elevated and filtered token** | Difference between contexts = split-token (§3.4) |
| `MountPoints2` | Historical mounts — what was there previously |
| GPP events (Application, source `Group Policy Drive Maps`) | Per-item apply/remove/targeting outcomes (§3.1) |
| GP Operational 4001/4016/5016/7016/5312 | Whether the CSE ran; sync vs async; applicable GPO list |
| GPP trace files | `Starting class <Drive>` / `Completed class <Drive>` per-item detail |
| Logon scripts: GPO `\User\Scripts\Logon\`, AD `scriptPath` | §3.5 — the documented culprit |
| Scheduled tasks, Run/RunOnce keys, Startup folder | Non-GPO mechanisms touching the letter |
| DFS referral state, Offline Files state | Intermittent path resolution |
| Network profile, connection type, VPN presence | Logon-time network timing |

Output: timestamped folder + zip. Self-describing — includes a manifest recording what was
collected, what was empty, and what could not be read, so a bundle collected by someone else
is interpretable without asking them what they ran.

### 5.3 `Watch-DriveMapActivity.ps1`

Polls the target letter every `-IntervalSeconds` (default 15). On a state transition,
captures:

- Timestamp and direction (present → absent, or absent → present)
- Registry state vs. live mount state at that moment
- GPP and GP Operational events in the surrounding window
- Recent process creations referencing the letter (4688 where available; best-effort otherwise)
- Whether a Group Policy refresh had just run
- Network/VPN state

Appends to a timeline file. Foreground, or `-Install` to register a scheduled task;
`-DurationHours` bounds the run.

**Design rationale:** the *timing* of disappearance discriminates causes that look identical
in a snapshot — at logon implicates a script; ~90 minutes in implicates background refresh;
after sleep/reconnect implicates persistence; alternating across logons implicates §3.3.

## 6. Correlation and ranked causes

Every verdict is a pure function over collected evidence, testable without a domain.

| Evidence pattern | Verdict | Remediation |
|------------------|---------|-------------|
| GPP applied OK + drive absent + `net use /delete` found in a logon script | **Script deletes what GPO created** (§3.5) | Name the GPO and script; remove/unlink/deny |
| Replace + FLO on + "always wait" off + alternating pattern | **Every-other-logon CSE behavior** (§3.3) | Enable "always wait"; or Create+Reconnect |
| In `HKCU\Network` but not in live mounts | **Reconnect failing** — path unreachable at logon | Check share/DFS availability at logon time |
| Present unelevated, absent elevated, `EnableLinkedConnections` ≠ 1 | **Split-token visibility** (§3.4) | Set `EnableLinkedConnections = 1`; note the Prompt-for-credentials caveat |
| 4105 / 4106 / 8212 present | **Item-level targeting failed** | Resolve group membership; cross-reference `-CheckGroupOverlap` |
| Multiple GPOs, same letter, different paths | **Conflict** | Defer to `Audit-GPDriveMaps.ps1` findings |
| Everything clean, drive still vanishes | **No cause identified** | State what was ruled out and what to collect next |

The last row is a required output, not a fallback. An unresolved case is a finding with a
next step; it must never render as a blank page.

### 6.1 Traps to encode

1. **CSE success ≠ drive present** (§3.5). Never conclude "working" from GP events alone.
2. **Absence of GPP events ≠ absence of failures** (§2). Logging is off by default, so this
   is `CouldNotCollect`, never `EmptyButValid`.
3. **Split-token is not a disappearance** (§3.4). Misreporting it sends a technician to
   audit Group Policy for a drive that was never missing.
4. **`NoBackgroundPolicy = 0` must never be recommended** (§3.3) — Microsoft explicitly
   advises against it and it does not reliably work.

## 7. Output design

Following the lockout toolkit's §9, which was driven by a real complaint ("which file do I
open first?"):

- **One combined tabbed HTML report**, tabs ordered by the five questions, findings on
  screen at open
- CSV alongside for pivoting — but every collector must also appear in the HTML, or its
  evidence effectively disappears
- Group repeated evidence: "this letter disappeared 14 times, all within 3 minutes of
  logon" is the finding; 14 near-identical rows is noise
- **Confidence is a visible tag, never a buried field.** Never show a guess as a fact.
- Plain-English labels for a mixed helpdesk/sysadmin audience, per CLAUDE.md design
  context — but every conclusion names the evidence behind it so an expert can audit it

## 8. Script conventions

Per CLAUDE.md:

- `[CmdletBinding()]`, typed `param()`, validation attributes
- `-OutputPath` on every script producing file output
- Runtime `Import-Module` in try/catch — **not** `#Requires -Modules`
- `#Requires -Version 5.1`; `-RunAsAdministrator` where genuinely needed
- Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`
- `.NOTES` carries a `REFERENCES` block listing every Microsoft page consulted
- Status prefixes `[PASS]`/`[WARN]`/`[FAIL]`/`[INFO]`; dual console + file output
- Per-target try/catch — one unreachable machine must not abort the run, and a skipped
  target must be surfaced, never silently dropped
- `-ComputerName` on every remote query

## 9. Testing

Pester tests in `Tests/`, one file per script, matching the lockout toolkit.

- **Pure functions for every interpretation step** — verdict selection, ranking, state
  classification, formatting — tested without a domain
- **Fixtures from documented event XML shapes and real registry exports**, never from
  memory. The lockout toolkit's 4740 bug survived because a hand-written fixture agreed
  with the wrong code.
- **Regression tests encoding each documented fact in §3**, with the source URL in a
  comment, so a wrong version cannot silently return
- Explicit tests that each collector returns distinguishable `EmptyButValid` vs
  `CouldNotCollect` — the failure mode this entire design exists to prevent

## 10. Out of scope

- Modifying `Audit-GPDriveMaps.ps1` or `Search-SYSVOLScripts.ps1` — reused as-is
- Remediation beyond enabling logging. The toolkit diagnoses and recommends; it does not
  change GPOs, edit logon scripts, or remap drives.
- Non-Windows clients, and drive letters mapped by third-party agents (Citrix, VPN clients)
  beyond recording their presence as a candidate mechanism
