# Diagnose-ADAccountLockout.ps1

Investigates why an Active Directory account keeps locking out and traces the **source** of the bad authentications. Produces a color-coded console summary and a self-contained dark-themed HTML report suitable for attaching to a ticket.

> **This is a lockout investigator, not a password-expiry checker.** When a user reports being "forced to reset their password" far more often than the policy allows, the cause is almost always repeated **account lockouts** — the user (or helpdesk) resets the password each time the account locks, which *feels* like constant forced resets. The real culprit is usually a **stale cached credential**: a phone with an old Exchange password, a mapped drive, a disconnected RDP session, a service or scheduled task running as the user, or a saved Windows credential on a workstation. This tool finds the machine that credential lives on.
>
> For domain password-policy *settings* (not lockouts), see [`PasswordPolicyAuditor`](../PasswordPolicyAuditor).

## Requirements

- **PowerShell** 5.1 or 7.x
- **RSAT Active Directory tools** (ActiveDirectory module)
- **Domain-joined machine** — run from a domain controller or a management workstation with RSAT
- Permission to **read the Security event log** on the domain controllers (the script reads 4740/4625/4771/4724 events remotely via `Get-WinEvent`)

### Installing RSAT AD Tools

```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11 workstation
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Usage

```powershell
# Investigate a user, report saved to the current directory
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe

# Search further back and write the report elsewhere
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DaysBack 14 -OutputPath "C:\Reports"

# Limit the event-log search to specific DCs instead of auto-discovering all of them
.\Diagnose-ADAccountLockout.ps1 -Identity jdoe -DomainController DC01,DC02
```

### Parameters

| Parameter           | Type     | Default            | Description |
|---------------------|----------|--------------------|-------------|
| `-Identity`         | String   | *(required)*       | SamAccountName, UPN, or DN of the user to investigate |
| `-OutputPath`       | String   | Current directory  | Folder where the HTML report is written (created if missing) |
| `-DaysBack`         | Int      | 7                  | How many days of Security event logs to search (1–90) |
| `-DomainController` | String[] | *(auto-discover)*  | One or more DCs to query instead of all discovered DCs |

## What It Does

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
- No on-prem evidence → consider widening `-DaysBack` or investigating hybrid/Entra sign-in logs (see *Scope* below).

## Output

### Console
Color-coded `[PASS]` (green) / `[WARN]` (yellow) / `[FAIL]` (red) / `[INFO]` (cyan) progress, ending with the verdict and the report path.

### HTML report
A self-contained, dark-themed `.html` file written to `-OutputPath`:
```
ADLockout_jdoe_2026-06-02_093059.html
```
Sections: **Likely Cause → Account State → Effective Lockout Policy → Lockout Timeline (4740) → Bad-Password Sources (4625/4771) → Admin Resets (4724)**.

## How to Read the Report

1. Start at **Likely Cause** — it names the machine to investigate first.
2. Confirm it in the **Lockout Timeline**: a single Caller Computer appearing repeatedly is the smoking gun.
3. Cross-check **Bad-Password Sources** for the logon type — that tells you *what kind* of stale credential it is (mapped drive, RDP, service, phone).
4. Go to that machine and clear the stale credential: Credential Manager, mapped-drive reconnect with old creds, a service/scheduled task running as the user, or a mobile device with a cached password.

## Event ID Reference

| ID   | Log (best source)            | Meaning                       | Key fields |
|------|------------------------------|-------------------------------|------------|
| 4740 | Security — PDC emulator       | Account locked out            | TargetUserName, **CallerComputerName** |
| 4625 | Security — per DC             | Failed logon                  | TargetUserName, IpAddress, WorkstationName, LogonType |
| 4771 | Security — per DC             | Kerberos pre-auth failed      | TargetUserName, IpAddress (`Status 0x18` = bad password) |
| 4724 | Security — per DC             | Password reset attempt        | TargetUserName, SubjectUserName (who did it) |

## Error Handling

- The ActiveDirectory module import and the initial domain contact each fail with a clear `[FAIL]` message and a non-zero exit code.
- An unresolvable `-Identity` exits early.
- Each DC is queried in its own `try/catch`; an unreachable DC logs a `[WARN]` and the run continues.
- "No events found" is treated as a normal result (a `[WARN]`/`[INFO]`), not an error.

## Scope

This tool covers **on-prem AD lockouts**, where the bad authentications actually lock the account. If accounts are hybrid-synced to Entra ID and the on-prem evidence comes up empty, the report flags that as the next avenue — Entra smart lockout and SSPR are a separate mechanism and a possible future enhancement (Microsoft Graph), out of scope here.

## Tests

Pure-logic helpers (event-XML parsing and verdict ranking) have Pester tests that run without a domain:

```powershell
Invoke-Pester .\AD-LockoutDiagnostics\Tests\ -Output Detailed
```

The domain-bound functions (AD queries, event-log reads) are verified by running the script against a real domain.
