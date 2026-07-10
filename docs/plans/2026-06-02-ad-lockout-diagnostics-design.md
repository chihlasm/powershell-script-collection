# AD Account Lockout Diagnostics — Design

**Date:** 2026-06-02
**Author:** Michael Chihlas
**Status:** Approved (pending implementation)

## Problem

A user reports being "forced to reset their password" far more often than the
domain password policy should require. Investigation reframed the symptom: this
is **repeated account lockouts**, not password expiry. The user (or helpdesk)
resets the password each time the account locks, creating the perception of
constant forced resets.

The actual task is a **lockout investigation**: find where the bad
authentications originate. The usual culprit is a *stale cached credential* — a
phone with an old Exchange password, a mapped drive, a disconnected RDP session,
a service or scheduled task running as the user, or a saved Windows credential
on a workstation.

## Goal

Given a username, determine why the account keeps locking and identify the
source machine(s)/IP(s) of the bad authentications, then produce an HTML report
suitable for attaching to a ticket. Built user-focused but parameterized so it
works for any user.

## Non-Goals (YAGNI)

- **Entra ID / Graph integration.** Accounts are hybrid-synced, but AD lockouts
  originate on-prem (the on-prem DCs lock the account). Entra smart lockout is a
  separate mechanism that does not force AD password resets. Graph checks are a
  documented *future enhancement*, not in v1. If on-prem evidence comes up empty,
  the report will flag the hybrid angle as a next step.
- Remediation (clearing stale creds, killing sessions). Diagnosis only.
- Auditing all users at once. Single `-Identity` per run.

## Script

`AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1` (+ `README.md`)

### Parameters

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| `-Identity` | string (Mandatory) | — | SamAccountName / UPN / DN of the user |
| `-OutputPath` | string | current dir | Where the HTML report is written |
| `-DaysBack` | int (ValidateRange 1–90) | 7 | How far back to search event logs |
| `-DomainController` | string[] | — | Override DC auto-discovery |

`[CmdletBinding()]`, comment-based help, `#Requires -Version 5.1`.
`Import-Module ActiveDirectory` inside try/catch (not `#Requires -Modules`).

## Data Flow

1. **Account state** — `Get-ADUser -Server <PDC> -Properties LockedOut,
   badPwdCount, lockoutTime, pwdLastSet, LastBadPasswordAttempt,
   msDS-User-Account-Control-Computed`. Report current lock state and counters.

2. **Effective password/lockout policy** — `Get-ADUserResultantPasswordPolicy`
   first (catches a Fine-Grained Password Policy with an aggressive
   `LockoutThreshold`/`LockoutDuration`, which is itself a root cause); fall back
   to `Get-ADDefaultDomainPasswordPolicy`. Report `LockoutThreshold`,
   `LockoutObservationWindow`, `LockoutDuration`.

3. **Lockout timeline (Event 4740)** — query the **PDC emulator** Security log
   (authoritative for 4740). Each event yields timestamp + **Caller Computer
   Name** — the primary evidence.

4. **Bad-password source tracing (4625 / 4771)** — query **all DCs**
   (auto-discovered via `Get-ADDomainController -Filter *`, or `-DomainController`
   override) for failed logon (4625) and Kerberos pre-auth failure (4771) for the
   user. Extract source workstation/IP and logon type so a mapped drive can be
   told apart from RDP, a service, or a phone. Each DC in its own try/catch.

5. **Admin/helpdesk resets (Event 4724)** — query all DCs to see if someone keeps
   manually resetting the password (explains the "forced to reset" perception and
   distinguishes human resets from automated lockouts).

6. **Verdict** — ranked "Likely cause" at the top of the report:
   - Repeated lockouts from one caller computer → stale cached credential there.
   - Broad/varied sources or external IPs → possible credential compromise.
   - FGPP/domain `LockoutThreshold` very low (e.g. 3) → policy too aggressive.
   - No on-prem events found → note hybrid/Entra as the next avenue.

## Output

- **Console** during the run: color-coded `[PASS]` (green) / `[WARN]` (yellow) /
  `[FAIL]` (red) / `[INFO]` (cyan) per repo convention.
- **HTML report** to `-OutputPath`, filename
  `ADLockout_<sam>_yyyy-MM-dd_HHmmss.html`. Self-contained (inline CSS, dark
  theme matching repo aesthetic). Sections: Verdict → Account State → Effective
  Policy → Lockout Timeline (4740) → Bad-Password Sources (4625/4771) → Admin
  Resets (4724).

## Error Handling

- AD module import in try/catch with a clear "install RSAT" message.
- Per-DC try/catch; an unreachable DC logs a `[WARN]` and the run continues.
- `Get-WinEvent` FilterHashtable wrapped per-DC; "no events found" is a normal
  result, not an error.
- `-Identity` not resolvable → `[FAIL]` and exit early.

## Conventions

Discovery over hardcoding (`Get-ADDomainController -Filter *`), `-ComputerName`/
`-Server` on every remote query, `[PSCustomObject]` for structured rows,
timestamps `yyyy-MM-dd HH:mm:ss` (logs) / `yyyy-MM-dd_HHmmss` (filenames).

## Future Enhancements

- Entra ID sign-in log / SSPR check via Microsoft Graph for hybrid accounts.
- Optional CSV export of the raw event rows alongside the HTML.
