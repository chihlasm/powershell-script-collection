# Drive Map Diagnostics

## Start here

```powershell
.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X
```

Runs the whole investigation in order — checks whether the machine can even produce
trustworthy evidence, collects it, checks the Group Policy side, searches for anything else
that touches the drive letter, and writes a ranked, plain-English verdict into one timestamped
case folder with a `SUMMARY.txt` and (if `New-DriveMapCaseReport.ps1` is present) a tabbed HTML
report you can open in a browser and attach to a ticket.

If you already have an evidence bundle collected by hand (see **Setting up PS Remoting**
below for why you might), point the investigation at it instead of collecting again:

```powershell
.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X `
    -EvidencePath 'D:\Cases\12345\DriveMapEvidence_WS01_2026-09-14_090000'
```

## Why the gate exists

Group Policy Preferences (GPP) — the feature behind "Drive Maps" in a GPO — only writes its
own success/failure events when a policy called "Logging and tracing" is turned on, and that
policy is **off by default**. That means an empty evidence report and a perfectly healthy
machine look identical: both produce no GPP events, for completely opposite reasons.

`Test-DriveMapLoggingReadiness.ps1` is the gate `Invoke-DriveMapInvestigation.ps1` runs first,
and it exists to close that gap. It checks whether GPP logging is on, whether GPP tracing is
on, and whether the Application log actually reaches back far enough to cover when the drive
went missing. If any of those come back "no," it refuses to hand you a clean-looking empty
result — it tells you the machine is **BLIND** and says exactly which condition caused it:

```
[FAIL] Group Policy Preferences logging is disabled - no preference-item events were ever recorded.
[WARN] This machine CANNOT currently produce trustworthy drive-map evidence.
[INFO] Re-run with -Force to collect anyway and document the gap, or see -EnableLogging.
```

Pass `-Force` to `Invoke-DriveMapInvestigation.ps1` to continue past a BLIND result anyway —
useful when you need *something* today and will follow up once logging is enabled. The verdict
logic does not need special-casing for this: a blind machine simply produces more
"could not collect" results, and every part of this toolkit already renders "could not look"
differently from "looked and found nothing."

## If the drive disappears on some logons but not others

**Check this first.** It is the single most common cause of an "intermittent" mapped drive and
it has nothing to do with permissions or network connectivity — but it is also the one cause
this toolkit **cannot** confirm for you automatically. See the subsection below before
trusting any "no cause identified" result.

The Group Policy Drive Maps client-side extension (the code that actually applies a drive-map
preference item) has `NoBackgroundPolicy=1` — Microsoft's own documentation for this extension
confirms it is **never invoked during a background Group Policy refresh**, only during
processing at logon. Separately, that same extension only applies preference items during
*synchronous* logon processing. Windows client machines have **Fast Logon Optimization**
enabled by default, which makes the first Group Policy pass at logon *asynchronous* — so on
that first pass the extension declines to run and instead asks Group Policy to run it
synchronously on the **next** logon. The practical effect: a **Replace**-mode drive map can
end up applying only on every *other* logon, with no configuration change and no error
anywhere in the logs.

### This toolkit cannot confirm this condition automatically — you must check it by hand

This is the one high-value finding the automated verdict engine **structurally cannot make**,
so read this before relying on `Invoke-DriveMapInvestigation.ps1`'s conclusion.

Microsoft documents Fast Logon Optimization and "Always wait for the network at computer
startup and logon" only as **Group Policy settings** (`Computer Configuration\Policies\
Administrative Templates\System\Logon`). No reachable Microsoft Learn page documents the
underlying **registry value names** those policies write. Per this toolkit's rule against
asserting unverified facts, nothing here guesses at them — so both signals are reported as
`CouldNotCollect`, never as confirmed booleans.

The verdict engine's every-other-logon rule requires both as confirmed `$true`/`$false` and
correctly refuses to fire on an unknown. The practical consequence:

> **`Invoke-DriveMapInvestigation.ps1` will never name this cause, even when it is the
> cause.** A "No cause identified" verdict does **not** mean this condition was ruled out —
> it means it was never measured. The verdict output says so in its own "what to check next"
> list, with this check listed first.

**Where the toolkit does surface it:** the readiness gate flags the risk based on the
*documented client default* (Fast Logon Optimization on, "Always wait" off), clearly labeled
as a default rather than a measurement of your machine:

```powershell
.\Test-DriveMapLoggingReadiness.ps1 -ComputerName WS01 -DriveLetter X
```

Look for the **`EVERY-OTHER-LOGON RISK`** section in the `.txt` report it writes (the same
finding is printed to the console in a banner). That section states the risk, says plainly
that it could not be confirmed automatically, and gives the remediation.

**How to actually confirm it** — run one of these against the affected machine and read the
effective setting for "Always wait for the network at computer startup and logon":

```powershell
gpresult /h report.html    # then open report.html
# or
rsop.msc
```

**Remediation** (either one resolves it):
- Enable **"Always wait for the network at computer startup and logon"**
  (`Computer Configuration\Policies\Administrative Templates\System\Logon`). This forces every
  logon to process Group Policy synchronously, so the extension never declines.
- Change the drive map's action from **Replace** to **Create**, and enable **Reconnect**. A
  reconnecting Create-mode mapping persists between logons instead of depending on the
  extension re-applying it every single time.

**Do not set `NoBackgroundPolicy` to `0`.** It is tempting because it looks like the obvious
switch to flip, but Microsoft's own guidance explicitly advises against changing it and
documents that doing so does not reliably make the extension run in the background anyway.
Nothing in this toolkit will ever recommend it — `Get-DriveMapVerdict` (inside
`Invoke-DriveMapInvestigation.ps1`) has a regression test that fails the build if any verdict
ever suggests it.

Source: [Group Policy troubleshooting: Drive Maps preference extension (Replace mode) only maps the drive every other logon](https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon)

## Citrix / RDS environments

**Run the endpoint scripts (`Export-DriveMapEvidence.ps1`, `Test-DriveMapLoggingReadiness.ps1`)
on the VDA the user actually landed on — not the endpoint device the user is physically
sitting at, and not a domain controller.** This is not a hypothetical mistake: on a real case,
the first run of this toolkit went against a domain controller, which has neither the user's
session, the user's live mounts, nor the user's GPP processing history — every endpoint
collector came back empty for reasons that had nothing to do with the drive-mapping problem.
`Get-CitrixSessions.ps1` (in this repository) finds which VDA a given user is actually on:

```powershell
.\Get-CitrixSessions\Get-CitrixSessions.ps1 -VdaMachineName "DOMAIN\jsmith"
```

Then point `-ComputerName` at that VDA (or run the endpoint scripts locally on it):

```powershell
.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName VDA07 -DriveLetter X
```

**Loopback processing is standard for Citrix/RDS session hosts, and this toolkit accounts for
it.** User Group Policy Loopback Processing makes a *computer*-linked GPO's *User*-scope
settings apply to whoever logs on to that computer — which is exactly why a VDA's effective
drive mapping can come from a GPO that is not linked anywhere near the user's own OU.
`Audit-GPDriveMaps.ps1` (reused unmodified by this toolkit) already detects loopback mode
(Merge/Replace) on the VDA's computer OU chain and folds it into its precedence simulation;
`Invoke-DriveMapInvestigation.ps1` now reads that result back out of
`*-EffectiveMaps.csv`'s `Reason` column and surfaces it as a lead callout on the case report's
"What should the user get?" tab whenever it applies, specifically so a Citrix precedence
result is not misread as an unexplained anomaly. If you are reading `Audit-GPDriveMaps.ps1`'s
own report directly instead, look for `LoopbackMode` in its precedence section and a `Reason`
of the form `"Applied via loopback (Merge) from GPO linked to computer OU '...'"` in its
effective-maps table.

**Two Citrix-specific mechanisms are checked directly by `Export-DriveMapEvidence.ps1` and are
otherwise invisible to every Group-Policy-side collector in this toolkit:**

- **Citrix Workspace Environment Management (WEM).** WEM maps drives through its own
  console-configured actions, applied by its own agent — entirely outside Group Policy, so a
  WEM-mapped drive produces no GPP events, no GPO to audit, and nothing for
  `Audit-GPDriveMaps.ps1` to find. `Export-DriveMapEvidence.ps1` checks for the
  **Citrix WEM Agent Host Service** (formerly **Norskale Agent Host Service**) by exact service
  name and reports a three-state result: `Found` names the service and its status, and a
  confirmed-absent result (`EmptyButValid`) closes the question rather than leaving WEM an open
  suspicion. If it is present, treat it as a first-class suspect alongside Group Policy, not an
  afterthought.
- **Citrix Client Drive Mapping (CDM).** CDM redirects the *endpoint device's* own drives into
  the session as a virtual channel — not a network mapping at all, so neither Group Policy nor
  a logon script can be its root cause. Citrix does not document any registry, WMI, or other
  queryable signal that lets a script running inside the session confirm whether one *specific*
  drive letter is CDM-mapped, so `Export-DriveMapEvidence.ps1` does not guess at one: it reports
  the session's raw `SESSIONNAME` value and whether the Citrix VDA registration registry key
  (`HKLM\Software\Citrix\VirtualDesktopAgent`) is present, both as corroborating context, and
  says plainly that per-letter CDM confirmation has to be done by hand — via Citrix Connection
  Center on the endpoint device, or the VDA's own client drive list.

**Non-persistent VDAs would destroy trace evidence at logoff — this is a caveat for this
environment, not a blocker, since it is running persistent VDAs.** GPP trace files, the
Application log's GPP preference-item events, and any registry state this toolkit reads all
live on the VDA itself. On a non-persistent VDA, all of that resets to the base image at
logoff, so any evidence not collected *during the affected session* is gone before a technician
can log in and run `Export-DriveMapEvidence.ps1`. If a persistent-VDA assumption ever changes,
collect evidence live (`Watch-DriveMapActivity.ps1`) or immediately upon reproducing the fault,
rather than after the user logs off.

## The tools

| Script                                  | Role                    | Answers                                                          |
|------------------------------------------|-------------------------|-------------------------------------------------------------------|
| `Invoke-DriveMapInvestigation.ps1`        | **Orchestrator**        | Runs everything below in order; gates on logging readiness; writes the ranked verdict |
| `Test-DriveMapLoggingReadiness.ps1`       | Prerequisite check      | Can this machine's evidence even be trusted? Also flags the every-other-logon and split-token risks directly |
| `Export-DriveMapEvidence.ps1`            | Endpoint collector      | What does the machine actually have — live mounts, registry mounts, GPP events, logon scripts, scheduled tasks, startup items? |
| `Watch-DriveMapActivity.ps1`             | Live watcher            | Catches the drive disappearing *as it happens*, with full context at that instant |
| `New-DriveMapCaseReport.ps1`             | Report                  | Turns a case folder into one tabbed HTML report a technician can read start to finish |
| `DriveMapReference.psd1`                 | Shared data             | Documented event IDs, registry paths, and CSE behavior every other script reads from |

> **If an investigation comes back with no clear cause, do not assume the drive is fine.**
> `Get-DriveMapVerdict` always returns at least a "no cause identified" result naming what was
> ruled out and exactly what evidence to collect next — treat that the same way you'd treat
> `Test-ADAuditPolicy.ps1` coming back "not logging" in `AD-LockoutDiagnostics`: it is telling
> you the investigation is incomplete, not that the problem does not exist.

---

## Invoke-DriveMapInvestigation.ps1

The orchestrator, and the only script in this toolkit that reaches a **verdict** rather than
just collecting evidence. It runs, in order: the readiness gate, endpoint evidence collection
(or accepts a bundle you already collected), the GPO-side audit (`Audit-GPDriveMaps.ps1`,
reused from `AD-GroupPolicy-DriveMaps`), a SYSVOL logon-script search for the drive letter
(`Search-SYSVOLScripts.ps1`), and then flattens everything into one evidence object and runs
every ranked-cause rule against it. More than one rule can match — a machine can have more
than one problem — so every case folder lists every match, most-confident first, not just the
top one.

**Parameters:**

| Parameter        | Type   | Default                     | Description |
|------------------|--------|------------------------------|--------------|
| `-Identity`      | String | *(none)*                     | The user (SamAccountName) whose mapping is under investigation |
| `-ComputerName`  | String | Local computer               | The affected machine |
| `-DriveLetter`   | String | *(none)*                     | The drive letter reported missing (e.g. `X`) |
| `-EvidencePath`  | String | *(collects live instead)*    | Path to a bundle already produced by `Export-DriveMapEvidence.ps1` — skips live collection |
| `-OutputPath`    | String | `.\Cases`                    | Folder under which a timestamped case folder is created |
| `-Force`         | Switch | Off                          | Continue past a BLIND readiness result instead of stopping |

**Output** (one timestamped folder per run, under `-OutputPath`):
- `SUMMARY.txt` — plain-text case summary: the verdict(s), and which steps ran
- `Verdicts.json` — the same verdicts, machine-readable, for the HTML report
- `Evidence.json` — the flattened evidence object every verdict was built from, also for the
  HTML report — this is what lets the report show "what should the user get" / "what do they
  actually have" / "who else is touching this letter" with real data instead of "not
  established"
- `ReadinessGate.log`, plus the readiness gate's own `.txt`/`.json` report
- Whatever `Export-DriveMapEvidence.ps1`, `Audit-GPDriveMaps.ps1`, and
  `Search-SYSVOLScripts.ps1` each wrote
- `DriveMapInvestigationReport.html`, if `New-DriveMapCaseReport.ps1` is present alongside this
  script

## Test-DriveMapLoggingReadiness.ps1

The gate. Read-only — it never changes anything on the target, including with `-EnableLogging`
(see below). Answers three questions before anything else runs:

1. Is GPP logging on, so preference-item events are written at all?
2. Is GPP tracing on, so trace files exist to corroborate?
3. Does the Application log actually reach back far enough to cover when the fault happened?

It also directly reports two configuration risks that are themselves common root causes,
independent of the gate result — see **If the drive disappears on some logons but not
others** above for the first one, and the split-token note under **Known limitations** for the
second.

**Parameters:**

| Parameter         | Type   | Default          | Description |
|-------------------|--------|-------------------|--------------|
| `-ComputerName`   | String | Local computer     | The machine to check |
| `-DriveLetter`    | String | *(none)*           | Included in the report for context only |
| `-FaultAgeHours`  | Int    | 24                 | How many hours ago the drive was last known missing — used to judge log retention |
| `-EnableLogging`  | Switch | Off                | Prints step-by-step Group Policy instructions for turning GPP logging/tracing on. The underlying registry value name Microsoft's "Logging and tracing" policy actually writes is not documented anywhere, so this script will not guess at it and write it — it tells you the GPO path instead |
| `-OutputPath`     | String | `.\Reports`        | Folder for the readiness report |

**Output:** `DriveMapLoggingReadiness_<timestamp>.txt` (human-readable) and a matching `.json`
(machine-readable — this is what `Invoke-DriveMapInvestigation.ps1` reads to pull
`FastLogonOptimization` / `AlwaysWaitForNetwork` / `EnableLinkedConnections` into the verdict).

## Export-DriveMapEvidence.ps1

The endpoint collector. Gathers everything a drive-map investigation needs into one portable,
timestamped, zipped folder: persistent (reconnect-at-logon) mounts from `HKCU:\Network`, live
mounts, GPP and Group Policy operational events, and — because Microsoft's own troubleshooting
guide documents a case where a logon script in an *unrelated* GPO deleted a drive that Group
Policy had already mapped successfully — every logon script, scheduled task, Run key, and
startup item that references the drive letter at all.

Every individual source is collected in its own `try`/`catch`, so one denied registry key or
unreachable log can never blank out the rest of the bundle — a failed source is recorded as
"could not collect" with a specific reason, never silently dropped.

**Parameters:**

| Parameter        | Type   | Default        | Description |
|------------------|--------|-----------------|--------------|
| `-DriveLetter`   | String | *(none)*        | The drive letter to filter for and search for references to |
| `-ComputerName`  | String | Local computer  | The machine to collect from |
| `-OutputPath`    | String | `.\Reports`     | Folder under which a timestamped, zipped bundle is created |

**Output:** `DriveMapEvidence_<computer>_<timestamp>\` containing `manifest.json` (which
sources were Found / confirmed Empty / could not be collected, and why) plus one CSV per
collected source, and a matching `.zip` of the same folder for easy handoff.

## Watch-DriveMapActivity.ps1

The watcher. Every other tool in this toolkit answers "what is true right now?" — which
cannot diagnose an *intermittent* fault, because a snapshot taken after the drive reappears
proves nothing. This script polls the drive letter's live presence and, the moment it
transitions (appears or disappears), captures full context at that exact instant: the
registry-vs-live comparison, GPP and Group Policy operational events, process-creation (4688)
events referencing the letter (when that audit subcategory is on), the current network
profile, and the last Group Policy refresh time.

It also classifies *when* the transition happened, because timing tells causes apart that
look identical in a snapshot: within 5 minutes of logon points at a logon script; within 2
minutes of a background Group Policy refresh points at policy processing; anything else gets
an honest "Unexplained" with a concrete next step, never a blank line in the timeline.

**Parameters:**

| Parameter           | Type   | Default        | Description |
|----------------------|--------|-----------------|--------------|
| `-DriveLetter`       | String | *(required)*    | The drive letter to watch |
| `-IntervalSeconds`   | Int    | 30              | How often to poll |
| `-DurationHours`     | Int    | 8                | How long to run before stopping on its own |
| `-OutputPath`        | String | `.\Reports`     | Folder the timeline file is written under |
| `-Install`           | Switch | Off             | Registers a Scheduled Task that starts the watcher at the user's next logon, instead of watching interactively now |

**Output:** `DriveMapWatch_<letter>_<timestamp>.log`, appended to on every transition for the
life of the run.

## New-DriveMapCaseReport.ps1

The report. Turns a case folder into one self-contained, tabbed HTML file with no external
dependencies (no CDN, no separate stylesheet) so it can be attached to a ticket and opened on
a machine with no internet access. Five tabs, in a fixed order that mirrors how you'd actually
work the case: **Can we trust this data?** → **What should the user get?** → **What do they
actually have?** → **Who else is touching this letter?** → **Why does it vanish?** Every
"could not collect" result renders visually distinct from a confirmed-empty one everywhere in
the report — color, icon, *and* label text, so the distinction survives being read in
grayscale or by screen reader.

**Parameters:**

| Parameter          | Type   | Default                          | Description |
|---------------------|--------|-----------------------------------|--------------|
| `-CaseFolder`       | String | Most recent `.\Cases\DriveMapCase_*` | The case folder to render |
| `-OutputPath`       | String | The case folder itself            | Where to write the report |
| `-SkipBrowserOpen`  | Switch | Off                               | Do not open the report automatically after writing it |

**Output:** `DriveMapInvestigationReport.html` in `-OutputPath`.

This script is independently runnable against an older case folder that predates
`Evidence.json` (or one supplied without it) — tabs 2 through 4 simply fall back to "not
established" text for the fields that file would have supplied, the same way they do for any
other collector that could not run.

## DriveMapReference.psd1

Not a script — the shared, documented data every other script in this toolkit reads from
rather than hardcoding: GPP preference-item event IDs and what each one means, the Group
Policy operational event IDs, and the registry paths for persistent mounts, MountPoints2,
`EnableLinkedConnections`, GPP tracing, and the Drive Maps client-side extension's own
registration key.

---

## Setting up PS Remoting

**This entire section is optional.** `Export-DriveMapEvidence.ps1` and
`Test-DriveMapLoggingReadiness.ps1` can both be run **locally**, by anyone, directly on the
affected machine — no remoting setup required. Hand the resulting evidence folder back (email
it, copy it to a share, whatever is convenient) and feed it to the investigation with
`-EvidencePath`:

```powershell
.\Invoke-DriveMapInvestigation.ps1 -Identity jsmith -ComputerName WS01 -DriveLetter X `
    -EvidencePath 'D:\Cases\12345\DriveMapEvidence_WS01_2026-09-14_090000'
```

Set up remoting only if you'd rather run the investigation *against* a machine from your own
workstation, without asking the user to run anything themselves. This toolkit uses standard
PowerShell Remoting (WinRM) via `-ComputerName` — the same mechanism as `Invoke-Command`, not
a custom transport — so the setup is exactly what any PowerShell remoting task needs.

**1. Enable remoting on the target machine** (run elevated, on the target):

```powershell
Enable-PSRemoting -Force
```

This starts the WinRM service, sets it to start automatically, creates a listener, and opens
the corresponding Windows Firewall exception for you — you do not need to touch the firewall
by hand for a normal domain-joined target.
([Microsoft Learn: Enable-PSRemoting](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting))

Domain controllers and most managed servers already have this enabled by default; workstations
usually do not.

**2. Verify it from your own workstation:**

```powershell
Test-WSMan -ComputerName WS01
```

A response back means the WinRM service is running and reachable. Note that without
`-Authentication`, the request is sent anonymously and the OS-version fields in the response
come back blank (`OS: 0.0.0`) — that is expected and does not mean anything is wrong.
([Microsoft Learn: Test-WSMan](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman))

**3. Non-domain-joined or workgroup target: add it to TrustedHosts.**

Kerberos authentication (the default for domain-joined remoting) does not work against a
workgroup computer or a bare IP address, so WinRM falls back to NTLM — and NTLM over WinRM
requires either HTTPS or that the target be explicitly trusted on your client:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'WS01' -Concatenate
```

(`-Concatenate` adds to the existing list instead of replacing it; use a comma-separated list
or a wildcard like `*.contoso.com` for multiple targets.) You will also need to pass
`-Credential` explicitly on every remote command against a workgroup machine, even when
connecting as yourself.

**This setting is not narrow: it affects every user of your computer, not just your own
session** — Microsoft's own documentation calls this out explicitly as a caution. Add specific
machine names rather than a broad wildcard, and only for as long as you need it.
([Microsoft Learn: about_Remote_Troubleshooting — TrustedHosts](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting))

**4. Firewall.** `Enable-PSRemoting` already creates the WinRM firewall exception for private
and domain networks. If the target machine's network profile is **Public** — an unusual case
for a managed workstation, but possible for a laptop off the corporate network — the default
exception is restricted to the local subnet only; there is no reason to widen it further for
this toolkit's purposes, since you would normally be reaching the machine from the same
network anyway.

If none of this is worth setting up for a one-off case, go back to the top of this section:
collect locally and hand back the bundle.

---

## Known limitations

- **The most common cause of all — the every-other-logon mechanism — can never be reported as
  an automated verdict.** Microsoft documents Fast Logon Optimization and "Always wait for the
  network at computer startup and logon" only as Group Policy settings, never with the registry
  value names they write, so this toolkit reports both as "could not collect" rather than
  guessing. The verdict engine's rule for this cause requires both as confirmed booleans and
  correctly declines to fire on an unknown — meaning **"No cause identified" never rules this
  out.** `Test-DriveMapLoggingReadiness.ps1` flags the risk from the documented client default
  in its `.txt` report's `EVERY-OTHER-LOGON RISK` section, and the verdict output lists this
  check first under "what to check next". Confirm it by hand with `gpresult /h report.html` or
  `rsop.msc`. See [If the drive disappears on some logons but not
  others](#if-the-drive-disappears-on-some-logons-but-not-others).

- **GPP logging/tracing state is often reported as "could not determine," not "off."** The
  registry value name(s) that the "Logging and tracing" Group Policy setting actually writes
  are not documented anywhere on Microsoft Learn — only the GPO path and its effect are. Rather
  than guess at a value name and risk silently reading (or writing) the wrong thing while
  reporting success, this toolkit reports that specific state honestly as unknown and
  corroborates it *only* with an indirect, secondary signal: whether GPP trace files exist and
  are fresh at their documented default location,
  `%COMMONAPPDATA%\GroupPolicy\Preference\Trace`. Trace file presence is evidence, not proof —
  the location itself can be changed by policy.

- **A single run cannot collect live mounts from both UAC token contexts.** With UAC on, logon
  creates two linked sessions (standard and elevated), and mapped drives are per-session
  symbolic links — genuinely not shared between them. A drive missing from only the elevated
  session is a **visibility artifact**, not an actual disappearance, and this toolkit is
  careful to word it that way rather than sending you to audit a GPO for a drive that was never
  missing. But one running process only holds one token, so `Export-DriveMapEvidence.ps1`
  cannot inspect the *other* context out-of-process in the same run — it records whichever
  context it is actually running in, and reports the other one as "could not collect" with an
  explicit reason rather than guessing. **If split-token visibility is a live suspect for your
  case, run the collector twice** — once from a normal prompt, once elevated — and hand both
  bundles to the investigation, or compare them by hand.

---

## Requirements

- PowerShell 5.1 or later
- RSAT **GroupPolicy** and **ActiveDirectory** modules, for the domain-side steps
  (`Audit-GPDriveMaps.ps1`, `Search-SYSVOLScripts.ps1`) that `Invoke-DriveMapInvestigation.ps1`
  calls
- Local administrator rights on the target machine for the elevated-context checks in
  `Export-DriveMapEvidence.ps1` and for `Watch-DriveMapActivity.ps1 -Install`
- PowerShell Remoting (WinRM) enabled on the target if you are collecting evidence remotely —
  see **Setting up PS Remoting** above; not required if evidence is collected locally and
  handed back via `-EvidencePath`

## REFERENCES

Microsoft Learn pages this toolkit's code and this README rely on:

- [Group Policy Preferences events are only logged when "Logging and tracing" is enabled](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/information-group-policy-preferences-events)
- [Drive Maps preference extension (Replace mode) only maps the drive every other logon](https://learn.microsoft.com/en-us/archive/technet-wiki/12221.group-policy-troubleshooting-drive-maps-preference-extension-replace-mode-only-maps-the-drive-every-other-logon)
- [Drive Maps CSE registration, NoBackgroundPolicy, and synchronous-only processing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581924(v=ws.11))
- ["Always wait for the network at computer startup and logon"](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj573586(v=ws.11))
- [Mapped drives not available from an elevated command prompt (UAC split-token, EnableLinkedConnections)](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)
- [Scenario guide: a GPO-mapped drive doesn't apply as expected (unrelated logon script deleting a healthy GPP mapping)](https://learn.microsoft.com/en-us/troubleshoot/windows-client/group-policy/scenario-guide-gpo-to-map-network-drive-doesn-t-apply-as-expected)
- [Replace vs. Update vs. Create action semantics for Drive Maps preference items](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581924(v=ws.11))
- [GPP trace file default location (%COMMONAPPDATA%\GroupPolicy\Preference\Trace)](https://learn.microsoft.com/en-us/archive/blogs/askds/enabling-group-policy-preferences-debug-logging-using-the-rsat)
- [ConsentPromptBehaviorAdmin values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)
- [Event 4688 (process creation) and the Process Command Line field](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Command-line process auditing / Audit Process Creation policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [auditpol /get syntax and report format](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get)
- [Remove-PSDrive disconnects mapped network drives since PowerShell 3.0](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-psdrive)
- [New-PSDrive -Persist](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive)
- [net use syntax](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11))
- [scriptPath Active Directory user attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-scriptpath)
- [Run/RunOnce registry key locations](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Get-ScheduledTask / -CimSession for remote targeting](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)
- [Register-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask) / [New-ScheduledTaskTrigger](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger)
- [Win32_OfflineFilesCache WMI class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/offlinefiles/win32-offlinefilescache)
- [Get-NetConnectionProfile / NetworkCategory](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile)
- [MountPoints2 and disconnected mapped network drives](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/mapped-network-drive-disconnected)
- [Enable-PSRemoting](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting) (PS Remoting setup, verified for this README)
- [Test-WSMan](https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman) (PS Remoting setup, verified for this README)
- [about_Remote_Troubleshooting — TrustedHosts, firewall, and workgroup remoting](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting) (PS Remoting setup, verified for this README)

## Tests

Pure-logic functions (the three-state evidence contract, verdict ranking, HTML rendering, the
readiness gate's risk checks) have Pester tests that run without a domain or a live machine:

```powershell
Invoke-Pester -Path .\Tests\ -Output Detailed
```

Everything that touches a real registry, event log, or remote machine is verified by running
the scripts themselves.
