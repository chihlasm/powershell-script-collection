# Entra Device Activity Timeline

When was this laptop on, asleep, locked and unlocked? For **one Windows device that is
Microsoft Entra joined** (and usually Intune managed), where there is no domain to query from
and no remote event log access.

```powershell
.\Get-DeviceActivityTimeline.ps1                                  # last 30 days, all users
.\Get-DeviceActivityTimeline.ps1 -UserName jdoe@contoso.com -Start 2026-10-01 -End 2026-10-14
```

It runs **on the device** and reads that device's own System and Security logs:

| What | Where it comes from |
|---|---|
| Started, shut down, restart requested, crashed | System log - Kernel-General 12/13, User32 1074, Kernel-Power 41, EventLog 6008 |
| Went to sleep, woke, hibernated, Modern Standby | System log - Kernel-Power 42/107/506/507, plus the resume record (Power-Troubleshooter 1) and clock reset (Kernel-General 1) for real wake times - see below |
| Locked, unlocked, screen saver | Security log - 4800/4801/4802/4803 (*only if auditing is on*) |
| Signed in, unlocked (fallback), signed out | Security log - 4624 types 2/7/10/11/13, 4647 |
| Remote / switched-user session | Security log - 4778/4779 |

You get one zip in a `Reports` folder beside the script (or wherever `-OutputPath` points) containing:

- **HTML report**: a day-by-day table (first and last sign of use, counts), then the full timeline grouped by day, a description of the device (join type, tenant, Intune agent, Windows build, time zone, and how far each log reaches back), and a plain answer to "can this show lock/unlock?"
- **`_Daily.csv` / `_Timeline.csv`**: the same data for Excel. Every row has both local time and UTC.
- **`_Summary.txt`**: the short version, to paste into a ticket.
- **`_System.evtx` / `_Security.evtx`** (only with `-IncludeRawLogs`): the original logs, so
  someone else can check the report against them.

Beside the zip, **`<name>.zip.sha256`** holds the zip's SHA-256 (`sha256sum` format), and the
console prints it too. If the report is filed with HR or legal, that hash shows the copy is the
one that left the device: `Get-FileHash <zip> -Algorithm SHA256` must give the same value.

## Read this first: lock and unlock are probably not being recorded

4800 (locked) and 4801 (unlocked) are only written when **Audit Other Logon/Logoff Events**
is set to Success. **Intune's default for that setting is Off**
([Policy CSP - Audit](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-audit#accountlogonlogoff_auditotherlogonlogoffevents)),
so on a typical Intune laptop there is no lock history to find. The report checks the setting
and says so at the top instead of showing an empty table that reads like "never locked".

What you can still get without it:

- **Unlocks**: yes. Each unlock also writes a sign-in record (4624 type 7), and "Audit Logon"
  is on by default. These rows are marked *From the sign-in record (4624 type 7)*.
- **Locks**: no. Nothing records them when the setting is off, and the past cannot be recovered.
- **Startup, shutdown, sleep, wake**: always, from the System log.

### Turn it on for the future (Intune)

Intune admin center > **Devices** > **Configuration** > **Create** > Windows 10 and later >
**Settings catalog**. Search **Other Logon Logoff**, pick *Account Logon Logoff Audit Other
Logon Logoff Events*, and set it to **Success**. Assign it to the device or user group.

CSP, if you prefer a custom OMA-URI:
`./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditOtherLogonLogoffEvents` = `1`

To start recording on one device right now, without waiting for policy:

```powershell
.\Get-DeviceActivityTimeline.ps1 -EnableLockAuditing -DaysBack 1
```

That runs `auditpol /set` for the subcategory GUID `{0CCE921C-69AE-11D9-BED3-505054503030}`
([auditing constants](https://learn.microsoft.com/windows/win32/secauthz/auditing-constants)).
Lock the screen once (Windows+L), unlock it, and run the script again: the banner should now
say *being recorded*. Intune remains the durable fix, because a later policy refresh can
overwrite a local change.

### Keep the evidence longer

The Security log defaults to 20 MB and overwrites itself. On a busy laptop that can be only
two or three weeks. The report shows exactly how far back each log reaches. To keep more, use
the Settings catalog: *Event Log Service > Security > Specify the maximum log file size (KB)*
([`EventLogService/SpecifyMaximumFileSizeSecurityLog`](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-eventlogservice#specifymaximumfilesizesecuritylog)).
196608 KB (192 MB) is the size Microsoft's security baselines use.

When the evidence matters, run with `-IncludeRawLogs` as early as you can. It exports both
logs into the zip with `wevtutil epl`
([wevtutil](https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil)),
which adds about 20 MB per log at default sizes. On the test laptop, one night of update
reboots cut the Security log's reach from 18 days to under 2 hours. A copy taken before that
would have kept it all.

## Getting it onto the device

The script needs administrator rights or SYSTEM. Without them the Security log cannot be read,
and the report says so.

**Remote session (ScreenConnect, RMM, Quick Assist with elevation).** Copy the script over and
run it from an elevated PowerShell. Open the HTML from the `Reports` folder next to the script.

**Defender for Endpoint Live Response.** Upload `Get-DeviceActivityTimeline.ps1` to the library
(unsigned scripts must be allowed in *Settings > Endpoints > Advanced features*), then:

```
run Get-DeviceActivityTimeline.ps1 -parameters "-DaysBack 30 -OutputPath C:\Temp\DeviceActivity"
dir C:\Temp\DeviceActivity
getfile "C:\Temp\DeviceActivity\DeviceActivity_<NAME>_<STAMP>.zip"
```

Always pass `-OutputPath` here. Live Response runs library scripts from its own working
folder, so a `Reports` folder beside the script would be somewhere you can't easily find and
that may be cleaned up. Live Response forbids `; & | ! $` inside `-parameters`; paths and UPNs
are fine ([Live Response](https://learn.microsoft.com/defender-endpoint/live-response)).

**Intune Remediation, run on demand.** Add the script as the *detection* script of a
Remediation package (no remediation script), with *Run this script using the logged-on
credentials* = No and *Run script in 64-bit PowerShell* = Yes. Then go to the device >
**...** > **Run remediation**. Remediations cannot pass parameters, so to get the answer back
in the portal, edit the copy you upload so summary mode and a fixed output folder are the
defaults (Intune runs the script from a temporary cache folder, so the default `Reports`
folder beside it would not survive):

```powershell
    [string]$OutputPath = 'C:\Temp\DeviceActivity',
    ...
    [switch]$IntuneSummary = $true,
```

The day-by-day summary then appears in the Remediation's *pre-remediation detection output*
column, which Microsoft caps at 2,048 characters; the script trims the oldest days to fit. The
full zip stays on the device for collection by one of the routes above. Remediations require
Windows Enterprise E3/E5 (or equivalent) licensing
([Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)).

**Intune platform script.** Works without the Remediations licence, but output does not come
back to the portal. Platform scripts can't take parameters either, so make the same
`$OutputPath` edit and collect the zip from there afterwards.

## Reading the day-by-day table

```
2026-10-12 Mon   02:14 Woke from sleep        14:02 Went to sleep    ...  4 unlocked
2026-10-11 Sun   Asleep all day (since 2026-09-28 07:29)
2026-09-26 Sat   On, but nothing changed state (no sleep, lock or sign-in recorded)
```

- **First / last sign of use**: the earliest start-type event (startup, wake, unlock, sign-in)
  and the latest event of any kind that day.
- **Days with no events** say what state the device was left in: *off*, *asleep*, *in Modern
  Standby*, or *on, but nothing changed*. A device left unlocked and awake all day records
  nothing, especially when lock auditing is off.
- **Went to sleep / Woke** include Modern Standby, which on many laptops starts whenever the
  screen turns off. The network can stay connected during it
  ([Modern Standby](https://learn.microsoft.com/windows-hardware/design/device-experiences/modern-standby)).

### Why some rows say "Resume logged with the clock still at the time it went to sleep"

While a laptop sleeps or hibernates its clock stops. On resume, Windows writes *resumed from
sleep* (Kernel-Power 107) **before** it resets the clock from the hardware clock, so that
event is stamped with the moment the laptop went to sleep, a few seconds after the sleep
event. Taken at face value, a laptop that hibernated for two weeks looks like it woke at once
and then sat on, silent, for two weeks.

Two later events carry the real time, and the report uses them in this order:

1. **The resume record** (Power-Troubleshooter event 1). It is written once the device is
   running again and holds the real sleep and wake times, plus the sleep type:
   - sleep or hibernation;
   - Fast Startup, which Microsoft describes as target state *shutdown* with effective state
     *hibernate*
     ([SYSTEM_POWER_STATE](https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-system_power_state),
     [Fast Startup vs. hibernate](https://learn.microsoft.com/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation)).

   This is where rows like *Woke from hibernation* come from. The record also names a wake
   source (power button, lid, timer) when Windows knows it. On the test laptop it was
   "Unknown" for every hibernate resume, so the report leaves an unknown source out rather
   than printing it.
2. **The clock reset** (Kernel-General event 1, old and new time). This is the fallback when
   there is no resume record. It is only used when the jump starts within 10 minutes of a
   sleep or shutdown.

Either way, the original 107 row is kept but relabelled, and is not counted as a wake. A
genuine *Left Modern Standby* from just before the device hibernated is left alone. Clock jumps
that do not belong to a resume are shown as *System clock changed*, which is itself worth
knowing.

The stopped-clock ordering was observed on Windows 11 Entra-joined laptops, not documented by
Microsoft. That is why the matching is strict and covered by tests built from a real laptop's
sequence.

### Fast Startup: one thing to check on a real device

With Fast Startup on (the Windows default), **Shut down** from the Start menu is really a
partial hibernate. **Restart** is always a full boot
([Fast Startup](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/fast-startup-causes-system-hibernation-shutdown-fail)).
The report handles a Fast Startup boot the same way as a hibernate resume. However, the test
laptop is never shut down from the Start menu, so this path has only been tested with
synthetic data. To confirm it on a device:

1. **Start > Power > Shut down**. Wait a few minutes, then power on.
2. Run the script with `-DaysBack 1`.
3. Check that the timeline shows *Windows shut down*, then *Windows started (Fast Startup)*
   (or *Windows started*) at the time you pressed the power button.

If the start shows a few seconds after the shutdown instead, send the timeline CSV back.

## What this cannot tell you

- **What the person was doing.** This is device state, not activity monitoring. An unlocked,
  awake laptop looks the same whether someone is at it or not.
- **Anything before the logs begin.** The report shows where each log starts. Earlier days are
  left out rather than shown as "no activity".
- **Locks, while auditing is off.** See above.

Requests like this are often HR- or legal-driven. Confirm the request is authorised before
pulling one person's activity, and attach the HTML or zip as produced rather than a re-typed
summary. The report records the device's time zone, the UTC offset and the log coverage, which
is what makes it defensible.

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-DaysBack` | 30 | Days to read (1-365). Ignored with `-Start`. |
| `-Start` / `-End` | now-30d / now | Explicit window. |
| `-UserName` | all | Filter user events by account text (UPN or name) or SID. Machine events are always kept. |
| `-OutputPath` | `Reports` beside the script | Output folder. Set it explicitly for Live Response and Intune runs, which execute from temporary folders. |
| `-NoZip` | off | Leave the files loose. |
| `-IncludeRawLogs` | off | Also export the System and Security logs (.evtx) into the zip. |
| `-IntuneSummary` | off | Print only the 2,048-character summary (for Remediation output), ending with the zip's SHA-256. |
| `-EnableLockAuditing` | off | Turn on Audit Other Logon/Logoff Events locally. Supports `-WhatIf`. |

## Requirements

- Windows 10/11 with Windows PowerShell 5.1 (every Entra-joinable Windows has it), or PowerShell 7.
- Administrator or SYSTEM for the Security log and `auditpol`.
- No modules and no network access.

The script is pure ASCII, so it works both as a Windows PowerShell script (which needs a BOM
for any non-ASCII file) and as a signature-checked Intune Remediation (which rejects a BOM).

## Tests

```powershell
Invoke-Pester .\Entra-DeviceActivityTimeline\Tests -Output Detailed
```

Pure tests, needing no event logs: event mapping, merging of duplicate sign-in records, the
wake-time recovery (using a real sequence from a laptop), the daily states, auditpol and
dsregcmd parsing, the 2,048-character limit, HTML escaping, and the ASCII-only guard.

## Related

[AD-LockoutDiagnostics](../AD-LockoutDiagnostics/) has the domain-joined version of this
timeline (`Get-SourceMachineActivity.ps1`). It reads the same events remotely and lines them
up against failed sign-ins.
