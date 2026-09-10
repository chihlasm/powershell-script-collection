# AD Lockout Diagnostics

## Start here

```powershell
.\Start-LockoutWorkbench.ps1
```

Scans the domain, shows you who is actually locking out, and lets you pick one:

```
  Accounts locking out (last 7 day(s))

  [ 1]  jdoe                      14 lockouts    12 min ago   LAPTOP-7  << LOCKED NOW
  [ 2]  asmith                     6 lockouts     5 hr ago    SQLSRV02
  [ 3]  svc_backup                 4 lockouts     2 days ago  5 different sources

  Enter a number, or type an account name.  [R] rescan   [Q] quit
```

Pick a number, answer one optional question about Entra Connect, and it runs the full
investigation. This exists because the toolkit used to require an account name before it
would tell you anything - and at the start of a ticket, the account name is often exactly
what you do not have.

If you already know the account, skip the menu:

```powershell
.\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe
```

Either route runs the tools below in the right order, **stops if the DCs are not logging lockout events**, and drops everything into a single timestamped case folder with a `SUMMARY.txt` you can attach to a ticket.

When you name an account, the combined report marks it throughout — the domain-wide steps still report on every account, because one account locking out means something different when forty others are too, but you can now see at a glance which rows are yours.

The gate is the point. An empty lockout report and a clean domain look identical — unless something checks whether the events were ever being written. This does that first, and refuses to hand you confident-looking empty reports.

```
[FAIL] Account lockout events (4740) are not being recorded.
       DC02: User Account Management is 'No Auditing'
[WARN] STOPPING before event-log collection.
[INFO] Re-run with -Force to collect anyway and document the gap.
```

Add `-MultiForest` when a second forest may be involved, or when auditing is off — that step polls per-DC bad-password counters, which are directory attributes and still work with auditing fully disabled.

Add `-EntraConnectServer` when the account is synced to Microsoft Entra ID:

```powershell
.\Invoke-ADLockoutInvestigation.ps1 -Identity jdoe -EntraConnectServer AADCONNECT01
```

This collects sync-server evidence during step 4 — ADSync and Pass-through Authentication agent service state, Password Hash Sync health, and PTA agent events. Without it the investigation examines on-premises evidence only, and a lockout driven by a sync server or a PTA agent looks like a lockout with no identifiable source. The console says so explicitly when hybrid evidence is not collected, so a hybrid-blind run cannot be mistaken for a clean one.

There is no auto-discovery for this: the Entra Connect server is not marked as such in AD, and guessing wrong would query an unrelated machine and report its silence as a healthy sync.

**Before the first real hybrid investigation, run the readiness check once:**

```powershell
.\Test-EntraConnectReadiness.ps1 -EntraConnectServer AADCONNECT01
```

Read-only, takes seconds. It confirms the hybrid checks can actually read what they assume — that the `Directory Synchronization` event provider is registered, that the PTA log channel exists under the expected name, and that this account can read both remotely. Every one of those assumptions fails the same way (an empty result), and an empty result is indistinguishable from a healthy quiet server. Run it again after any Entra Connect upgrade.

---

The individual tools remain runnable on their own when you already know what you want.

| Script                              | Scope                  | Answers                                        |
|-------------------------------------|------------------------|------------------------------------------------|
| `Start-LockoutWorkbench.ps1`        | **Menu**               | Scan first, then pick an account. Start here.  |
| `Invoke-ADLockoutInvestigation.ps1` | **Orchestrator**       | Runs the rest in order; gates on audit policy  |
| `Test-ADAuditPolicy.ps1`            | Prerequisite check     | Are the DCs even *logging* lockout events?     |
| `Get-ADLockoutHistory.ps1`          | Domain-wide triage     | *Who* is locking out, and how often?           |
| `Diagnose-ADAccountLockout.ps1`     | Per-account deep dive  | *Why* this account, and from *what machine*?   |
| `Invoke-ADLockoutForensics.ps1`     | Multi-forest forensics | *Which DC / forest* is receiving the attempts? |
| `Set-DCSecurityLogRetention.ps1`    | DC log sizing          | *How far back* can these reports actually see? |
| `Test-EntraConnectReadiness.ps1`    | Hybrid preflight       | Can the hybrid checks *read* what they assume? |
| `Export-ADAuthSourceEvidence.ps1`   | Device identity        | *What is* the machine behind that source IP?   |
| `LockoutReference.psd1`             | Shared data            | Documented event IDs, status codes, audit GUIDs|

> **If a lockout report comes back empty, run `Test-ADAuditPolicy.ps1` before concluding
> anything.** An empty report has two indistinguishable causes: no lockouts occurred, or
> the DCs were never configured to log them. If failure auditing is off, no lockout report
> can find 4625/4771 evidence regardless of the search window or log retention.

**Typical workflow** — triage first, then deep-dive the worst offenders:

```powershell
.\Get-ADLockoutHistory.ps1 -DaysBack 30                 # 1. who is locking out?
.\Diagnose-ADAccountLockout.ps1 -Identity svc_backup    # 2. why is the worst one locking?
```

Both write into a shared `Reports\` folder beside the scripts, so a case's triage report and its per-account follow-ups stay together:

```
AD-LockoutDiagnostics\Reports\
  ADLockoutHistory_2026-08-12_141530.html    (domain-wide triage)
  ADLockoutHistory_2026-08-12_141530.csv
  ADLockout_jdoe_2026-08-12_141602.html      (per-account deep dive)
```

---

## Test-ADAuditPolicy.ps1

Verifies that the domain controllers are actually configured to log the events every other tool in this folder depends on. **Run this first when a lockout report comes back empty.**

A lockout report can only find what the DCs record. If failure auditing is disabled, the investigation returns empty no matter how far back it searches — because the events were never written. That failure mode is invisible from the report itself: "no evidence found" and "no evidence recorded" look identical.

### What it checks

| Subcategory                     | Event      | Needs   | Without it you lose                                 |
|---------------------------------|------------|---------|-----------------------------------------------------|
| User Account Management         | 4740, 4724 | Success | **The lockout timeline itself**, and admin resets   |
| Logon                           | 4625       | Failure | Failed-logon source host / IP / logon type          |
| Kerberos Authentication Service | 4771       | Failure | Kerberos pre-auth failures                          |
| Account Lockout                 | 4625       | Failure | Logons against an account that is already locked    |

> **Watch the names here.** Event **4740 — the lockout itself — comes from *Audit User
> Account Management*, not from the similarly-named *Audit Account Lockout*.** That
> subcategory logs 4625 for logons against an account that is *already* locked, and has no
> Success events at all. Checking the wrong one will declare a blind DC healthy.
> ([Microsoft Learn](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-account-lockout))

Plus two things that silently defeat a correct-looking configuration:

- **Legacy vs Advanced audit policy conflict.** If `SCENoApplyLegacyAuditPolicy` is not enabled, legacy settings can override Advanced Audit Policy — so `auditpol` may report the right values while the effective policy differs.
- **Security log retention**, because correct auditing plus a log that wraps in days still yields an empty long-window report.

### Usage

```powershell
# Check every discovered DC
.\Test-ADAuditPolicy.ps1

# Check specific DCs
.\Test-ADAuditPolicy.ps1 -DomainController DC01,DC02
```

Requires PowerShell remoting (WinRM) to the DCs — `auditpol` reports *effective local* policy, so it must run on each DC rather than via a remote registry read.

### Reading the result

- **Any subcategory not logging** → lockout reports are structurally blind for that event. Fix the policy before drawing conclusions from an empty report.
- **All subcategories logging** → an empty lockout report is *meaningful*. The events genuinely did not occur on-prem, which points at a cloud-side origin (Entra sign-in logs, Smart Lockout, PTA) rather than a collection gap.

### Fixing it

This script **reports only**. Audit policy belongs in Group Policy on the Domain Controllers OU — a local `auditpol` change is reverted at the next GPO refresh:

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration`

- **Account Management → Audit User Account Management** → Success — produces **4740 (the lockout)** and 4724. Set this one first; without it no lockout is ever recorded.
- **Logon/Logoff → Audit Logon** → Success *and* Failure
- **Account Logon → Audit Kerberos Authentication Service** → Success *and* Failure
- **Logon/Logoff → Audit Account Lockout** → Failure — this subcategory has no Success events, so enabling Success achieves nothing
- **Local Policies → Security Options →** "Force audit policy subcategory settings to override audit policy category settings" → **Enabled**

Then `gpupdate /force` on the DCs and re-run the check.

---

## Get-ADLockoutHistory.ps1

Reports **every** account lockout across the domain over a time window, ranked by frequency. Queries event **4740** once on the PDC emulator, aggregates per account, and names the caller computer(s) that submitted the bad password.

This is triage, not a deep dive — it answers "is this one stale service account or a widespread problem?" in seconds. It deliberately does **not** trace 4625/4771 across all DCs; that is `Diagnose-ADAccountLockout.ps1`'s job, and doing it for every account over 30 days would be slow on a real domain.

### Usage

```powershell
# Last 30 days, HTML + CSV into .\Reports\
.\Get-ADLockoutHistory.ps1

# Wider window, and only accounts that locked out 5+ times
.\Get-ADLockoutHistory.ps1 -DaysBack 60 -MinLockouts 5

# Target a specific DC, CSV only, custom folder
.\Get-ADLockoutHistory.ps1 -DomainController DC01 -Format Csv -OutputPath C:\Reports
```

### Parameters

| Parameter           | Type     | Default                | Description                                         |
|---------------------|----------|------------------------|-----------------------------------------------------|
| `-DaysBack`         | Int      | 30                     | Days of Security log to search (1–90)               |
| `-OutputPath`       | String   | `.\Reports`            | Output folder beside the script, created if missing |
| `-DomainController` | String[] | *(auto: PDC emulator)* | DC(s) to query; the first that answers is used      |
| `-MinLockouts`      | Int      | 1                      | Only report accounts at or above this count         |
| `-Format`           | String   | `Both`                 | `Html`, `Csv`, or `Both`                            |

### Output

- **HTML** — coverage banner, summary stats, accounts ranked by lockout count, then the full raw timeline.
- **CSV** — one row per lockout event (`Time, User, Domain, CallerComputer, DC`) for pivoting in Excel.

The console prints the top 10 offenders and ends with a ready-to-run `Diagnose-ADAccountLockout.ps1` command for the worst account.

### Log retention coverage

The Security log wraps. If it does not reach back the full `-DaysBack` window, the script says so on the console **and** puts an `INCOMPLETE COVERAGE` banner at the top of the HTML report:

> Security log on DC01 only reaches back 11.4 day(s); 30 day(s) were requested. Older lockouts have already been overwritten and are NOT in this report.

This matters because a 30-day report backed by 11 days of log otherwise looks like a quiet month. Check headroom with:

```powershell
Get-WinEvent -ListLog Security -ComputerName (Get-ADDomain).PDCEmulator |
    Select-Object FileSize, MaximumSizeInBytes, RecordCount
```

### Notes on the data

- **Machine accounts** (ending in `$`) are included and flagged in an `IsComputer` column — they lock out for different reasons (duplicate SPNs, broken secure channel) than user accounts.
- A blank `CallerComputerName` renders as `(not recorded)` rather than an empty cell — it means the submitting host could not be resolved, which is itself a clue.
- If the PDC emulator is unreachable the script falls back to other DCs and **warns** that 4740 coverage may be partial.

---

## Invoke-ADLockoutForensics.ps1

Multi-forest lockout forensics. Use this when the single-forest tools come back empty, or when a single Entra tenant is fed by more than one on-premises forest (account forest + resource forest joined by email matching).

### Why it finds things the other tools cannot

`badPwdCount`, `badPasswordTime`, and `lockoutTime` are **non-replicated** attributes — every DC keeps its own copy reflecting only the authentications it personally handled. Querying "the domain" returns whichever DC you happened to bind to, which is why single-DC results are inconsistent.

This script polls those counters on **every DC in every forest**, which pinpoints the DC receiving the bad passwords **even when auditing is completely disabled**. It reads directory attributes, not event logs, so it still produces evidence where every event-based tool returns nothing.

It also finds the same person's account in each forest via `mail`/`proxyAddresses` — mirroring how Entra Connect joins identities — and compares `pwdLastSet` side by side. Two accounts with two independently-managed passwords behind one cloud login is a classic lockout engine that single-forest tooling cannot see.

### Usage

```powershell
# Fast survey: forests, audit policy, log health. Run this first.
.\Invoke-ADLockoutForensics.ps1 -SkipEventCollection

# Full investigation, auto-discovering trusted forests
.\Invoke-ADLockoutForensics.ps1 -Identity janelle.mccall -DaysBack 7

# Explicit forests with a credential for one the current user cannot read
$es = Get-Credential 'CORP-ES\svc-audit'
.\Invoke-ADLockoutForensics.ps1 -Identity janelle.mccall `
    -Forest 'corp.example.com','CORP-ES.EXAMPLE.COM' `
    -ForestCredential @{ 'CORP-ES.EXAMPLE.COM' = $es } -DaysBack 14
```

### Parameters

| Parameter             | Type      | Default            | Description                                              |
|-----------------------|-----------|--------------------|----------------------------------------------------------|
| `-Identity`           | String    | *(survey mode)*    | sAMAccountName, UPN, or email; omit for a health survey  |
| `-Forest`             | String[]  | *(auto via trusts)*| Forest FQDNs to interrogate                              |
| `-ForestCredential`   | Hashtable | *(current context)*| Per-forest credentials, keyed by forest FQDN             |
| `-DaysBack`           | Int       | 7                  | Event log search window (1–365)                          |
| `-OutputFolder`       | String    | `.\Reports`        | Output folder beside the script, created if missing      |
| `-SkipEventCollection`| Switch    | *(off)*            | Skip Security log queries; fast triage in under a minute |

### Relationship to the other tools

Overlaps deliberately with `Test-ADAuditPolicy.ps1` (same audit subcategory GUIDs, so the two agree) and `Set-DCSecurityLogRetention.ps1` (log health). The single-forest tools are faster and simpler for everyday work; reach for this one when the environment is multi-forest or the simple tools return nothing.

A one-way trust may block reads into the far forest. A trust makes a credential *presentable*, it does not grant rights — supply `-ForestCredential` when the far forest returns access errors.

---

## Set-DCSecurityLogRetention.ps1

Measures how far back each DC's Security log actually reaches, calculates the log size needed to hold a target number of days, and can increase it.

**Use this when a lockout report returns far less history than you asked for** — e.g. requesting 60 days but getting 4.6. That is the Security log wrapping, not an absence of lockouts.

### Two things to understand first

1. **Already-overwritten events cannot be recovered.** Enlarging the log only affects history collected *from that point forward*. After applying a change you must wait for the window to accumulate.
2. **This changes domain controller configuration.** The script is read-only unless you pass `-Apply`, and `-Apply` supports `-WhatIf`.

### Usage

```powershell
# Read-only: what do the DCs retain now, and what would 60 days require?
.\Set-DCSecurityLogRetention.ps1 -TargetDays 60

# Preview the exact changes without making them
.\Set-DCSecurityLogRetention.ps1 -TargetDays 60 -Apply -WhatIf

# Apply (prompts per DC)
.\Set-DCSecurityLogRetention.ps1 -TargetDays 60 -Apply
```

### Parameters

| Parameter           | Type     | Default           | Description                                              |
|---------------------|----------|-------------------|----------------------------------------------------------|
| `-TargetDays`       | Int      | 90                | Days of history you want retained (1–365)                |
| `-DomainController` | String[] | *(all DCs)*       | Specific DCs to check instead of auto-discovery          |
| `-Apply`            | Switch   | *(off)*           | Actually change the log size; supports `-WhatIf`         |
| `-MinFreeSpaceGB`   | Int      | 10                | Refuse a change leaving less free space than this        |
| `-MaxSizeGB`        | Int      | 4                 | Safety ceiling on the size this script will set          |
| `-OutputPath`       | String   | `.\Reports`       | Folder for the CSV report                                |

### How the sizing works

It measures the current bytes-per-day rate from what the log holds now, multiplies by `-TargetDays`, and adds **25% headroom** for activity spikes (audit policy changes, incidents, patch days). The result is rounded up to a 64 KB boundary, as Windows requires.

Worked example matching a 4.6-day retention in a 128 MB log:

```
128 MB / 4.6 days      = ~27.8 MB/day
27.8 * 60 * 1.25       = ~2,087 MB  -> set the log to ~2 GB for 60 days
```

### Built-in safety checks

- **Group Policy detection** — if log size is set by GPO, a local change is reverted at the next refresh. The script detects this and **skips** the DC, telling you to change the GPO instead.
- **Free space guard** — refuses to apply a change that would leave less than `-MinFreeSpaceGB` on the log's volume, and skips any DC whose free space it could not read.
- **Size ceiling** — clamps at `-MaxSizeGB` and suggests log forwarding/SIEM when the calculated need exceeds it.
- **Non-destructive** — increasing the maximum size does not clear the log.

### Where this should really be set

For a domain, the durable fix is **Group Policy**, not a per-DC change:

`Computer Configuration → Policies → Windows Settings → Security Settings → Event Log → Maximum security log size`

Apply it to the Domain Controllers OU. Use this script to *calculate the number* and verify the result; use the GPO to *enforce* it. For retention beyond a few weeks, forward events to a SIEM or use Windows Event Forwarding rather than growing local logs indefinitely.

---

## Diagnose-ADAccountLockout.ps1

Investigates why an Active Directory account keeps locking out and traces the **source** of the bad authentications. Produces a color-coded console summary and a self-contained dark-themed HTML report suitable for attaching to a ticket.

> **This is a lockout investigator, not a password-expiry checker.** When a user reports being "forced to reset their password" far more often than the policy allows, the cause is almost always repeated **account lockouts** — the user (or helpdesk) resets the password each time the account locks, which *feels* like constant forced resets. The real culprit is usually a **stale cached credential**: a phone with an old Exchange password, a mapped drive, a disconnected RDP session, a service or scheduled task running as the user, or a saved Windows credential on a workstation. This tool finds the machine that credential lives on.
>
> For domain password-policy *settings* (not lockouts), see [`PasswordPolicyAuditor`](../PasswordPolicyAuditor).

### Requirements

- **PowerShell** 5.1 or 7.x
- **RSAT Active Directory tools** (ActiveDirectory module)
- **Domain-joined machine** — run from a domain controller or a management workstation with RSAT
- Permission to **read the Security event log** on the domain controllers (the script reads 4740/4625/4771/4724 events remotely via `Get-WinEvent`)
- For optional Entra Connect diagnostics: permission to query services via CIM and read Application / PTA agent event logs on the Entra Connect server

#### Installing RSAT AD Tools

```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11 workstation
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

### Usage

```powershell
# Investigate a user, report saved to .\Reports\ beside the script
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe

# Search further back and write the report elsewhere
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath "C:\Reports"

# Limit the event-log search to specific DCs instead of auto-discovering all of them
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DomainController DC01,DC02

# Include hybrid authentication diagnostics for a synced user
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -EntraConnectServer AADCONNECT01 -HybridAuthMode Auto

# If you already know the tenant uses Pass-through Authentication
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -EntraConnectServer AADCONNECT01 -HybridAuthMode PTA
```

#### Parameters

| Parameter             | Type     | Default            | Description                                                            |
|-----------------------|----------|--------------------|------------------------------------------------------------------------|
| `-Identity`           | String   | *(required)*       | SamAccountName, UPN, or DN of the user to investigate                  |
| `-OutputPath`         | String   | `.\Reports`        | Output folder beside the script, created if missing                    |
| `-DaysBack`           | Int      | 7                  | How many days of Security event logs to search (1–90)                  |
| `-DomainController`   | String[] | *(auto-discover)*  | One or more DCs to query instead of all discovered DCs                 |
| `-EntraConnectServer` | String   | *(not run)*        | Entra Connect / sync server to query for hybrid-auth evidence          |
| `-HybridAuthMode`     | String   | `Auto`             | Expected hybrid auth mode: `Auto`, `PHS`, `PTA`, or `Unknown`          |

### What It Does

### 1. Account state (from the PDC emulator)
Reads the user's current `LockedOut` flag, `badPwdCount`, `LastBadPasswordAttempt`, `pwdLastSet`, and `lockoutTime` from the PDC emulator — the authoritative source for these counters.

### 2. Effective lockout policy (FGPP-aware)
Resolves the policy that *actually* applies to the user via `Get-ADUserResultantPasswordPolicy`, falling back to the default domain policy. A **Fine-Grained Password Policy** with an aggressively low `LockoutThreshold` (e.g. 3) is itself a common cause and is called out.

### 3. Lockout timeline — Event 4740 (PDC)
Queries event **4740** (account locked out) on the PDC emulator, which reliably receives these events domain-wide. Each event names the **Caller Computer** — the machine that submitted the bad password. This is the primary evidence.

### 4. Bad-password source tracing — Events 4625 / 4771 (all DCs)
Queries every discovered DC (or those named in `-DomainController`) for failed-logon (**4625**) and Kerberos pre-auth failure (**4771**) events, extracting the **source host / IP** and **logon type** so you can tell a mapped drive (type 3) from an RDP session (type 10) from a service (type 5). Each DC is queried in its own `try/catch` so one unreachable DC doesn't halt the run.

### 5. Admin / helpdesk resets — Event 4724 (all DCs)
Queries event **4724** to show whether someone keeps manually resetting the password — which explains the "forced to reset" perception and distinguishes human resets from automated lockouts.

### 6. Verdict
A ranked **"Likely Cause"** appears at the top of the report:
- Repeated lockouts from one caller computer → stale cached credential on that machine.
- A varied / external set of sources → possible credential compromise.
- A very low lockout threshold → policy too aggressive.
- No on-prem evidence → consider widening `-DaysBack`; for PHS-synced users, check Entra sign-in logs, Smart Lockout, SSPR, and password sync health.
- PTA evidence on the Entra Connect / Authentication Agent server → correlate Entra cloud sign-ins with on-prem 4740/4625/4771 timestamps, because PTA validates cloud sign-ins against on-prem AD.

### 7. Entra Connect / hybrid auth diagnostics (optional)

When `-EntraConnectServer` is supplied, the report adds an **Entra Connect / Hybrid Auth Diagnostics** section:

- `ADSync`, `AzureADConnectAuthenticationAgent`, and updater service status.
- Password Hash Sync Application log events across the full documented table (`601`–`668`), including the heartbeat `654` and connectivity errors `0`, `611`, `652`, `655`.
- PTA Authentication Agent Admin log events from `Microsoft-AzureADConnect-AuthenticationAgent/Admin`.
- Notes when expected heartbeat/events are missing or the sync server cannot be queried.

All remote failures are captured as diagnostic notes rather than thrown, so the AD lockout investigation continues even if the sync server is unreachable.

#### The heartbeat is judged against three hours, not the search window

Event `654` is logged **every 30 minutes** while the sync channel is active and no password changes are pending, and Microsoft's own troubleshooting task looks for one **within the past three hours**.

This matters more than it sounds. An earlier version of this check searched the whole `-DaysBack` window and only reported a problem when the *entire* window held no `654` — so on the default 7-day search, password hash sync could have died yesterday and still be reported healthy. Freshness is now measured against the documented three-hour window regardless of how far back events were gathered, and the report states how old the newest heartbeat actually is.

#### Connectivity errors are called out separately

Events `0`, `611`, `652` and `655` are documented together as indicating a connectivity problem between Entra Connect and Active Directory, with the affected forest named in the event message.

These get their own finding because they invert the usual conclusion: a sync server that *cannot reach a DC* is **not** the source of the bad passwords, but from the cloud side it looks identical to a broken account. The remediation is the connector account's `Replicate Directory Changes` / `Replicate Directory Changes All` rights and DC reachability — not anything to do with the user.

Sources for the above:
[PHS troubleshooting](https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization) ·
[PTA troubleshooting](https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication)

### Report output

#### Console

Color-coded `[PASS]` (green) / `[WARN]` (yellow) / `[FAIL]` (red) / `[INFO]` (cyan) progress, ending with the verdict and the report path.

#### HTML report

A self-contained, dark-themed `.html` file written to `-OutputPath`, which defaults to the shared `Reports\` folder beside the script:
```
AD-LockoutDiagnostics\Reports\ADLockout_jdoe_2026-08-12_141602.html
```
Sections: **Likely Cause → Account State → Effective Lockout Policy → Lockout Timeline (4740) → Bad-Password Sources (4625/4771) → Admin Resets (4724) → Entra Connect / Hybrid Auth Diagnostics**.

### How to Read the Report

1. Start at **Likely Cause** — it names the machine to investigate first.
2. Confirm it in the **Lockout Timeline**: a single Caller Computer appearing repeatedly is the smoking gun.
3. Cross-check **Bad-Password Sources** for the logon type — that tells you *what kind* of stale credential it is (mapped drive, RDP, service, phone).
4. Go to that machine and clear the stale credential: Credential Manager, mapped-drive reconnect with old creds, a service/scheduled task running as the user, or a mobile device with a cached password.

## Event ID Reference

| ID   | Log (best source)       | Meaning                  | Key fields                                               |
|------|-------------------------|--------------------------|----------------------------------------------------------|
| 4740 | Security — PDC emulator | Account locked out       | TargetUserName, **CallerComputerName**                   |
| 4625 | Security — per DC       | Failed logon             | TargetUserName, IpAddress, WorkstationName, LogonType    |
| 4771 | Security — per DC       | Kerberos pre-auth failed | TargetUserName, IpAddress (`Status 0x18` = bad password) |
| 4724 | Security — per DC       | Password reset attempt   | TargetUserName, SubjectUserName (who did it)             |

## Error Handling

Both scripts follow the same conventions:

- The ActiveDirectory module import and the initial domain contact each fail with a clear `[FAIL]` message and a non-zero exit code.
- An unresolvable `-Identity` exits early (`Diagnose-ADAccountLockout.ps1`).
- Each DC is queried in its own `try/catch`; an unreachable DC logs a `[WARN]` and the run continues.
- "No events found" is treated as a normal result (a `[WARN]`/`[INFO]`), not an error.

## Scope

These tools cover **on-prem AD lockouts**, where the bad authentications actually lock the account. For hybrid-synced users, `Diagnose-ADAccountLockout.ps1` can add Entra Connect server-side evidence when you provide `-EntraConnectServer`. Neither script calls Microsoft Graph or reads cloud sign-in logs directly; the report tells you when to correlate the AD evidence with Entra sign-in logs, Smart Lockout, SSPR, PHS health, or PTA agent logs.

## Tests

Pure-logic helpers (event-XML parsing, verdict ranking, lockout aggregation, and HTML rendering) have Pester tests that run without a domain:

```powershell
Invoke-Pester .\AD-LockoutDiagnostics\Tests\ -Output Detailed
```

The domain-bound functions (AD queries, event-log reads) are verified by running the scripts against a real domain.
