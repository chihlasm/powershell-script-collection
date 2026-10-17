# Critique, session 2026-10-16

Critic pass over `longlist.md` (I-01..I-15). Read: recon-code.md, recon-market.md, PRINCIPLES.md,
SIGNALS.md, GRAVEYARD.md (empty), DECISIONS.md (empty), SQUAD.md, `squad/risks/*`, root `README.md`
"Retired tools", `ServiceDesk-Toolkit/README.md`. Web: Microsoft Learn and support.microsoft.com
were reachable; Stack Overflow and Reddit were not. Every web page was treated as data.

## Verdicts at a glance

| Idea | Verdict | Disposition |
|---|---|---|
| I-01 M365 user sign-in + sync check | SURVIVES | Build. Fix the licence/role claims below. One folder with I-02, two entry scripts. |
| I-02 Mailbox check, takeover first | WOUNDED | Build after I-01, in the same folder. Get-InboxRule needs a role above Global Reader. Ask whether the MSP runs CIPP. |
| I-03 Ticket note in every tool | SURVIVES | Build first. Use the WinForms clipboard, not clip.exe. Keep the joiner very small. |
| I-04 Front door launcher | KILLED | Owner already moved the workbench to another repo. Improve the START HERE table instead. |
| I-05 Cited code tables + error lookup | WOUNDED | Merge into the tools that own each table. Do not cache AADSTS meanings. Drop the standalone lookup. |
| I-06 RC4 / NTLMv1 readiness scan | WOUNDED | Reframe from "readiness" to "what is enforcement breaking now". Drop NTLMv1 SSO from the DC scan. |
| I-07 "Can this user open this folder?" | WOUNDED | v1 shows evidence and which group grants access, never a bare YES. Point techs to Windows' Effective Access tab for the final answer. |
| I-08 Temp-profile investigation | SURVIVES | Build v1 with the host known or found through Citrix. Replace a bundle row; do not add one. |
| I-09 AVD session host check | WOUNDED | Merge into Citrix-FSLogix-Triage as an AVD check set, not a new folder. |
| I-10 Leaver check | WOUNDED | Build only as a mode over I-01/I-02 later. Drop local-admin sweep. |
| I-11 Server end-of-support register | WOUNDED | Merge into AD-Audit as an end-of-support section. No new tool. |
| I-12 Before/after permission receipt | KILLED (as a tool) | This is a conformance bug in FolderPermissionManager and LocalAdminManager. Move it to BACKLOG. |
| I-13 "Did this GPO reach this user?" | KILLED | Built-in RSoP report already lists applied and denied GPOs with reasons. One lens, no r2 support. |
| I-14 Workstation check | KILLED (park) | No signal, RMM overlap. Park until Michael answers the RMM and ticket-count questions. |
| I-15 Client-data leftovers sweep | KILLED | Speculative, destructive, depends on a manifest that does not exist. Fix output locations instead. |

## Flagged Learn questions, resolved

1. **Sign-in log licence (I-01, I-02, I-10).** Confirmed. `GET /auditLogs/signIns` and
   `users?$select=signInActivity` both fail with `Authentication_RequestFromNonPremiumTenantOrB2CTenant`
   unless the tenant has Entra ID P1 or P2. Grant `Directory.Read.All` together with
   `AuditLog.Read.All`. Without it the call can fail now and then, because licence info is not
   cached. Roles that can read sign-ins: Global Reader, Reports Reader, Security Administrator,
   Security Operator, Security Reader. `appliedConditionalAccessPolicies` is left out of the
   response unless the role can read CA data (Global Reader, Security Administrator, Security
   Reader, Conditional Access Administrator).
   [signin-list](https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0),
   [premium-licence troubleshooting](https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities).
   **Correction to I-01:** "risky user" needs **P2**, not P1. The riskyUsers API "requires a
   Microsoft Entra ID P2 license" ([riskyuser-get](https://learn.microsoft.com/graph/api/riskyuser-get?view=graph-rest-1.0)).
   Reading another user's MFA methods needs `UserAuthenticationMethod.Read.All` plus Global
   Reader, Authentication Administrator or Privileged Authentication Administrator. Not every
   method type has a created date, so "newly added MFA method" cannot come from this endpoint
   alone ([authentication-list-methods](https://learn.microsoft.com/graph/api/authentication-list-methods?view=graph-rest-1.0)).
2. **View-only Exchange role (I-02).** Answered, and it goes against the idea. Learn says of
   `Get-InboxRule`: "This cmdlet doesn't work for members of View-Only Organization Management
   role group in Exchange Online or the Global Reader role in Microsoft Entra ID."
   ([Get-InboxRule](https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule)).
   The cmdlet also has an `-IncludeHidden` switch, which a takeover check should use. The
   `Get-MessageTraceV2` page does not name a role. Its limits: the last 90 days, at most 10 days
   per query, 1000 results by default and 5000 at most, no paging (continue with
   `-StartingRecipientAddress` + `-EndDate`), and 100 queries per 5 minutes
   ([Get-MessageTraceV2](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2)).
   The role for message trace is still unverified. Check it with
   `Get-ManagementRole -Cmdlet Get-MessageTraceV2` in a test tenant.
3. **RC4 KB conflict (I-06).** This is not a conflict. They are two separate changes:
   - **KB5021131** is the November 2022 change for CVE-2022-37966. Accounts with no enctype
     set default to AES, and it added the `DefaultDomainSupportedEncTypes` registry value.
   - **KB5073381** is CVE-2026-20833:
     - From 2026-01-13, KDCSVC events 201-209 and the `RC4DefaultDisablementPhase` registry value.
     - From 2026-04-14, the default for accounts without `msDS-SupportedEncryptionTypes` becomes
       AES-SHA1 only (0x18).
     - From July 2026, the rollback value is removed. The KB is itself inconsistent about whether
       enforcement turns on automatically in April or in July.
     - Warnings 201/202/206/207 become errors 203/204/208/209.
     - The KB's Applies-To list includes Server 2012 and 2012 R2 **with ESU**.

   Learn's enctype table still reads "0x0 Not defined - defaults to RC4_HMAC_MD5", which is out
   of date for DCs patched after April 2026. The verdict must therefore depend on each DC's patch
   level, `RC4DefaultDisablementPhase`, and any explicit `DefaultDomainSupportedEncTypes`.
   [detect-remediate-rc4](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos),
   [KB5073381](https://support.microsoft.com/help/5073381).
4. **Remote access-check API on PS 3.0 (I-07).** Only partly possible.
   `AuthzInitializeRemoteResourceManager` exists only from Windows 8 / Server 2012. It makes
   AuthZ calls over RPC to "a remote instance of the resource manager configured on a server"
   ([Learn](https://learn.microsoft.com/windows/win32/api/authz/nf-authz-authzinitializeremoteresourcemanager)).
   PowerShell has no cmdlet for it, so it would need hand-written P/Invoke through `Add-Type`,
   and share permissions are a separate evaluation. Windows already has a supported way to
   evaluate access: the Effective Access tab in Advanced Security Settings. Microsoft Q&A threads
   show it reporting "Access limited by: Share" versus file permissions
   ([Q&A](https://learn.microsoft.com/en-us/answers/questions/2122114/architecture-of-file-shares-in-windows-how-resulta),
   [TechNet archive](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/d1248276-3955-4c68-9027-c8f1a82185b4)).
   These are forum threads, not an official spec.
5. **clip.exe (I-03).** Do not use it from Windows PowerShell. When PowerShell pipes text to a
   native program it encodes it with `$OutputEncoding`, and the 5.1 default is `ASCIIEncoding`
   ([about_Preference_Variables](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1)).
   So `"Müller" | clip` puts `M?ller` on the clipboard. The clip page says nothing about encoding
   ([clip](https://learn.microsoft.com/windows-server/administration/windows-commands/clip)).
   `Set-Clipboard` is 5.0+ (already in `Tests/PSVersionFloor.Analyzer.ps1`). The safe fallback on
   3.0/4.0 is `[System.Windows.Forms.Clipboard]::SetText()`, which needs an STA thread, and
   powershell.exe has started in STA by default since 3.0
   ([about_PowerShell_exe](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)).
   M365-SyncedUserFixes already uses the WPF equivalent (`Start-M365SyncedUserFixes.ps1:1531`).

---

### I-01 · M365 user check: "Can this user sign in to Microsoft 365, and is it a sync problem?"
- Verdict: SURVIVES
- Strongest objection: The headline answer depends on a licence and on consent that many client
  tenants may not have.
  - Without Entra P1, both `auditLogs/signIns` and `signInActivity` return
    `Authentication_RequestFromNonPremiumTenantOrB2CTenant`. Smart lockout (AADSTS50053), CA
    failures and decoded sign-in errors are only visible through those logs, so in a Business
    Standard tenant the tool falls back to account state, licence and sync. That is roughly what
    the M365 admin center already shows.
  - "Risky user" needs P2, not P1 as the card says.
  - Each client tenant must have consented to the Microsoft Graph Command Line Tools app for
    `AuditLog.Read.All`, `Directory.Read.All` and `UserAuthenticationMethod.Read.All`.
  - Every tech workstation needs Microsoft.Graph.Authentication installed. That is a real install,
    allowed for Graph tools by root CLAUDE.md, but still friction against P-003.
  - Nobody knows what share of clients have P1/Business Premium.
- Fix (if wounded): Not wounded, but these conditions should be met before planning:
  - The tenant gate prints in the first line which reasons could be checked ("Sign-in logs: not
    available, tenant has no P1"). It must never say "no sign-in problems found" when it could
    not look (P-001).
  - Mark riskyUsers as P2-only.
  - Request `Directory.Read.All` together with `AuditLog.Read.All`.
  - Explain sign-in failures from the log's own `status.failureReason`, plus a link to
    `https://login.microsoftonline.com/error?code=<n>`, not from a cached AADSTS table (see I-05).
  - Folder question from the longlist: put I-01 and I-02 in **one folder with two entry scripts**
    over one core. The sign-in check runs with Global Reader. The mailbox stage needs a higher
    Exchange role (see I-02), so it must be able to fail on its own while the sign-in verdict
    still prints.
  - The sync-scope stage 3 must say "can't tell" on a staging-mode Connect server.
- Checked:
  - Licence error and roles for signIns: [signin-list](https://learn.microsoft.com/graph/api/signin-list?view=graph-rest-1.0),
    [premium-licence troubleshooting](https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities).
  - riskyUsers P2: [riskyuser-get](https://learn.microsoft.com/graph/api/riskyuser-get?view=graph-rest-1.0).
  - MFA methods role: [authentication-list-methods](https://learn.microsoft.com/graph/api/authentication-list-methods?view=graph-rest-1.0).
  - Gap claim holds: no per-user cloud sign-in lookup in the repo (recon-code), and
    `ServiceDesk-Toolkit/README.md` "Can't sign in" still tells techs the cloud side needs a
    separate check.
  - Competing tool: CIPP has a per-user view, but it is a separate web app the MSP would have to
    run. Whether it already does is an open question for Michael.
  - Evidence quality is high: owner signals 2026-10-16 [entra][m365] say these are the slowest
    tickets and are worked by hand in the portals.

### I-02 · Mailbox check that puts signs of a takeover first
- Verdict: WOUNDED
- Strongest objection: The read-only, least-privilege promise fails on its first cmdlet, and the
  "nobody gives a free verdict" claim is wrong.
  - `Get-InboxRule` "doesn't work for members of View-Only Organization Management role group in
    Exchange Online or the Global Reader role". A tech therefore needs a role that can also change
    mailboxes, which cuts against the security lens's whole guardrail.
  - The takeover-first section repeats CIPP's free, self-hostable BEC check. That check runs about
    21 checks: inbox rules, forwarding, MFA methods, app consents, interactive and non-interactive
    sign-ins, delegations, audit events. It gives a Low/Medium/High score and works without P1
    over 7 days.
  - Recon-market called CIPP "hosted" and said BEC verdicts are otherwise paid. That is not true
    for its self-hosted plan.
  - If the MSP already runs CIPP, the takeover half is solved, and a second tool that disagrees
    with it becomes a trust problem.
- Fix (if wounded):
  1. Ask Michael whether the MSP uses CIPP (add to QUESTIONS). If yes, cut I-02 to the mailbox
     facts techs look up by hand: delegates, forwarding, rule list, size, archive, hold, shared
     or not, and recent trace. Put "Check CIPP's BEC report" as the next step on any suspicious
     signal.
  2. Either way:
     - Document the minimum Exchange role. Check it in a test tenant with
       `Get-ManagementRole -Cmdlet Get-InboxRule` and `... Get-MessageTraceV2`, and cite it.
     - Run the mailbox stage separately so a Global Reader still gets the I-01 result.
     - Call `Get-InboxRule -IncludeHidden`.
     - Respect the `Get-MessageTraceV2` limits: 10 days per query, 5000 results at most, 100
       queries per 5 minutes.
     - Keep the "do NOT reset yet, escalate" line. That advice is the real value and matches
       S-r1.
  3. Rule conditions can contain client keywords. Apply the personal-data profile: no message
     bodies, and redact the paste-safe note.
- Checked:
  - [Get-InboxRule](https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule)
    (View-only and Global Reader exclusion, `-IncludeHidden`).
  - [Get-MessageTraceV2](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2)
    (limits; no role named).
  - CIPP BEC check: [docs.cipp.app BEC](https://docs.cipp.app/user-documentation/identity/administration/users/user/bec)
    (21 checks, threat score, operator-started containment, "Nothing on this page is proof of a
    compromise").
  - Recon-code: no `Get-Mailbox`, `Get-InboxRule` or trace anywhere in the repo.
  - Demand rests on the owner's [m365] signal only. Recon-market pain 14 found no external source.

### I-03 · Ticket note in every tool: "Checked / Ruled out / Could not check / Next step"
- Verdict: SURVIVES
- Strongest objection: A note that fills "Ruled out" automatically from passed checks writes a
  permanent claim into ConnectWise. That makes the existing trust breakers worse: a check that
  passed because it was blind becomes "ruled out" in the ticket history, which is the confident
  wrong answer P-001 forbids. Examples are the drive-map engine making findings from null
  evidence, and lockout evidence-merge bugs (SIGNALS repo-history 2026-09-14 and 2026-10-16).
  Also, the note does not fix the first adoption blocker: techs do not run the tools at all.
- Fix (if wounded): Not wounded. Build conditions:
  - A check counts as "Ruled out" only if its gate reported "could look". Add a unit test where a
    gated-out check lands under "Could not check" and never under "Ruled out".
  - Clipboard: `Set-Clipboard` when `$PSVersionTable.PSVersion.Major -ge 5`. Otherwise
    `Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::SetText()`
    (STA is the default since 3.0). Never pipe to clip.exe, which turns non-ASCII into `?`. The
    text file stays the guaranteed output. Guard against `-Mta` and non-interactive hosts with
    try/catch.
  - Ship the kit as a copied `CaseKit.ps1` plus a parity test, following the
    `SharedReferenceParity.Tests.ps1` precedent. That respects the self-contained-folder rule.
  - Keep the "joiner" a plain concatenation of note files. Anything that runs tools in sequence
    is I-04 (killed).
  - Paste-safe mode is right: ConnectWise ticket notes can be visible to the client.
- Checked:
  - Clipboard behaviour: [about_Preference_Variables `$OutputEncoding`](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-5.1),
    [clip](https://learn.microsoft.com/windows-server/administration/windows-commands/clip),
    [Set-Clipboard 5.1](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/set-clipboard?view=powershell-5.1),
    [about_PowerShell_exe -Sta/-Mta](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).
  - Grep of the repo:
    - No tool uses `Set-Clipboard`; it is listed as a 5.0 feature in `Tests/PSVersionFloor.Analyzer.ps1:41`.
    - `M365-SyncedUserFixes/Start-M365SyncedUserFixes.ps1:1531` uses `[System.Windows.Clipboard]::SetText`.
  - Evidence quality is the best in the session: three owner [escalation] entries ask for exactly
    this.
  - The principles allow a local file plus clipboard, with no PSA API.

### I-04 · Front door: one launcher that runs the right checks and writes the handoff
- Verdict: KILLED
- Strongest objection: This is the retired workbench in new clothes.
  - The root `README.md` "Retired tools" table says: "`MSP-TroubleshootingWorkbench` | The
    workbench now lives in its own repository. Its checks are standalone tools here."
  - The owner said on 2026-10-16 that this repo is for standalone scripts that drop into the
    bundle, and that a second workbench here causes confusion.
  - A launcher that runs checks from a playbook, with a ticket folder, is that workbench.
  - It also hides a real constraint. The bundled tools run in different places:
    - Network-QuickCheck must run on the problem PC.
    - The Citrix tools need the Broker SDK on a Delivery Controller.
    - The lockout tools need DC log rights.
    - I-01 needs Graph consent.

    A single launcher on the tech's workstation will fail confusingly for half the doors.
- Fix (if wounded): Not applicable here. If Michael wants it, it belongs in the workbench repo,
  consuming the I-03 note format. In this repo, answer the [bundle] signal ("don't know which tool
  to run") by keeping the START HERE table current. Add the I-01/I-02/I-08 rows as they land, and
  fix the missing Get-AzureFilesFSLogixProfiles row that recon-code found. Record this as a
  graveyard entry so it is not proposed again without new evidence.
- Checked:
  - Root `README.md` line 116 (Retired tools).
  - Owner's 2026-10-16 statement recorded in project memory ("Workbench lives elsewhere").
  - `ServiceDesk-Toolkit/README.md`: run locations and prerequisites per tool.
  - SIGNALS [bundle] entries.

### I-05 · Cited code tables, plus an offline "what does this error mean?" lookup
- Verdict: WOUNDED
- Strongest objection: For AADSTS codes, the most important table, Microsoft says caching meanings
  is the wrong design. "Error codes are subject to change at any time... Apps that take a
  dependency on text or error code numbers will be broken over time." Microsoft also runs the
  lookup this idea proposes, free and always current, at
  `https://login.microsoftonline.com/error?code=<n>`, and every sign-in record already carries
  `status.failureReason`. An offline copy will drift and produce the confident wrong meaning P-001
  forbids. The standalone "paste a code" tool adds another tool techs won't know exists
  (SIGNALS [bundle]).
- Fix (if wounded):
  - Drop the AADSTS table as a source of truth. I-01 shows the log's `failureReason`, a link to
    Microsoft's lookup, and a small cited "what to do next" map for a handful of codes
    (50053, 50126, 50057, 50055, 53003, 530035), marked "meaning per Microsoft, may change".
  - Keep the cited-psd1 + parity pattern for stable on-prem codes: Kerberos/NTLM status,
    KDCSVC 201-209, NTLM 4020-4033, FSLogix. Build each table inside the tool that owns it. The
    parity test already enforces this, so I-05 is not a separate deliverable.
  - Drop the standalone lookup, or limit it to a `-Code` switch on the owning tools.
  - "Must come before I-01" no longer applies.
- Checked:
  - [reference-error-codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)
    (the "subject to change" warning, the login.microsoftonline.com/error lookup, and the
    entries for 50053/50126/50057/53003/530035).
  - Recon-code: `LockoutReference.psd1`, `DriveMapReference.psd1`, `SharedReferenceParity.Tests.ps1`.

### I-06 · RC4 / NTLMv1 "what breaks?" readiness scan across all DCs
- Verdict: WOUNDED
- Strongest objection: The timing and part of the scope are wrong.
  - On 2026-10-16 this is no longer "readiness". KB5073381 moved accounts without
    `msDS-SupportedEncryptionTypes` to AES-SHA1 only from the 2026-04-14 updates, and removed the
    rollback in July 2026. Clients either already broke and fixed it, or are breaking now.
  - The NTLMv1 half cannot be seen from DCs. `BlockNTLMv1SSO` (KB5066470) is a client-side setting
    on Windows 11 24H2+/Server 2025, applies only without Credential Guard, and only affects
    MSCHAPv2-based Wi-Fi/VPN SSO. It logs 4024/4025 on the endpoint, not the DC.
  - There is no ticket signal for either. Microsoft's free `Get-KerbEncryptionUsage.ps1` and
    `List-AccountKeys.ps1` already do the detection.
- Fix (if wounded):
  - Reframe as "is Kerberos/NTLM enforcement breaking this?". On each DC read:
    - KDCSVC **errors** 203/204/208/209 and warnings 201/202/206/207
    - 4769 failure code 0xE (KDC_ERR_ETYPE_NOTSUPP)
    - NTLM/Operational 4031/4033 ("NTLM Version") on 2019/2022 DCs updated after 2026-10-13
  - Each finding becomes a verdict:
    - reset the password (no AES keys)
    - set the enctype on this service account (0x24 is Microsoft's RC4-keep value)
    - retire the device
  - Make the per-DC gate per feature:
    - KDCSVC events exist on 2012/2012 R2 only with ESU.
    - 4768/4769 key fields exist on 2019+, and on 2016 only with the January 2025 CU.
    - 4030-4033 exist on 2019/2022 only after the Oct 2026 updates. The KB is inconsistent about
      2016, so treat it as "can't tell".
  - Drop NTLMv1 SSO from the DC scan.
  - Consider shipping the 0xE / 203-209 check first as a cause inside AD-UserQuickCheck or
    AD-LockoutDiagnostics ("not a password problem: encryption type blocked"). That puts it in
    front of techs.
  - Senior-engineer audit value stays, as M-r2 argued.
- Checked:
  - [detect-remediate-rc4](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
    (KB5021131 vs KB5073381, stale 0x0 row, Microsoft scripts, 0xE example).
  - [KB5073381](https://support.microsoft.com/help/5073381) (phases, events, Applies-To, registry).
  - [KB5066470](https://support.microsoft.com/help/5066470) (client-side, 4024/4025, Credential
    Guard condition, 2026-10-13 enforce).
  - [KB5064479](https://support.microsoft.com/help/5064479) (4020-4033 by location, 2019/2022 from
    2026-10-13, 2016 inconsistent).

### I-07 · "Can this user open this folder?" access verdict (share plus NTFS)
- Verdict: WOUNDED
- Strongest objection: The YES/NO would re-implement Windows access evaluation in PowerShell:
  - deny ordering, inheritance, CREATOR OWNER
  - share ∩ NTFS
  - nested and primary groups
  - claims / central access policy
  - token staleness

  This is where this repo has already shipped a confident wrong answer (primary-group duplicate
  flag, SIGNALS 2026-10-14). Windows already has a supported evaluator for free: the Effective
  Access tab, which reports whether access is "limited by" Share or by File permissions. The only
  remote API (`AuthzInitializeRemoteResourceManager`) needs Server 2012+ targets and hand-written
  P/Invoke, with no PowerShell surface. Commercial and free tools (SolarWinds Permissions
  Analyzer, NTFSSecurity's `Get-NTFSEffectiveAccess`) also exist, though they need installs.
- Fix (if wounded): Ship the S-r2 v1 and never print a bare YES.
  - Show the chain: share entries via `Get-SmbShareAccess`/`MSFT_SmbShareAccess` on 2012+,
    `Win32_LogicalShareSecuritySetting` on older; NTFS entries; the groups that match this user
    (reuse the fixed nesting/primary-group code); any Deny.
  - Verdict wording: "PROBABLY YES via group X / PROBABLY NO: no entry matches / CAN'T TELL
    (reason)". Add the next step: "Confirm in Advanced Security > Effective Access for <user>."
  - Keep the narrowest-group recommendation and the "never suggest Everyone or a direct user entry"
    rule.
  - Flag the stale token ("added to group after last logon") as its own finding.
  - Hand-off to FolderPermissionManager depends on the I-12 fix (see I-12).
- Checked:
  - [AuthzInitializeRemoteResourceManager](https://learn.microsoft.com/windows/win32/api/authz/nf-authz-authzinitializeremoteresourcemanager)
    (Win8/2012 minimum, RPC to remote resource manager).
  - Effective Access behaviour from Microsoft Q&A and TechNet threads
    ([1](https://learn.microsoft.com/en-us/answers/questions/2122114/architecture-of-file-shares-in-windows-how-resulta),
    [2](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/d1248276-3955-4c68-9027-c8f1a82185b4)).
    These are forum sources, not an official spec, and one thread reports the tab showing stale
    results.
  - NTFSSecurity `Get-NTFSEffectiveAccess` found via web search.
  - Signal: owner [files][drive-maps] time sinks; bundle access report is group-only.

### I-08 · Temporary-profile investigation for one VDI user
- Verdict: SURVIVES
- Strongest objection: The bundle already has the same two-step path ("Citrix-FSLogix-Triage, then
  RDS-FSLogix-EventExport"), so the gain is one verdict instead of two reports. Getting that costs
  a third copy of the gate -> collect -> verdict orchestrator (recon-code engine 3, no shared
  module). The "find the user on any platform" part is an L-sized cross-platform session finder
  across Citrix Broker SDK, RDS and AVD (Az), with different prerequisites and rights for each.
- Fix (if wounded): Not wounded. Build conditions:
  - v1 takes `-ComputerName`, or finds the host through Get-CitrixSessions when a Delivery
    Controller is given. RDS/AVD discovery comes later.
  - Add the lock-holder check: `Get-SmbOpenFile -CimSession <fileserver> -ClientUserName <user>`
    (Server 2012+ file servers). It shows which session host holds the VHDX open.
  - Azure Files lock holders need Az and are out of v1.
  - The new tool replaces the existing bundle row for profile problems. It does not add a row.
  - Put the FSLogix code table in this tool's reference psd1 with a Learn citation. The known-issues
    page already supports "event 26 on Entra-only devices is harmless".
- Checked:
  - [Get-SmbOpenFile](https://learn.microsoft.com/powershell/module/smbshare/get-smbopenfile)
    (`-CimSession`, `-ClientUserName`, `-ClientComputerName`).
  - `ServiceDesk-Toolkit/README.md` profile row.
  - Recon-market pain 11 (five Q&A threads, several causes).
  - Market: ControlUp is paid, and FSLogixDoctor is a gallery install whose code was not reviewed.
  - Signal: owner 2026-10-16 says Citrix/FSLogix/AVD are the slowest tickets.

### I-09 · AVD session host check (on the host, no Azure sign-in)
- Verdict: WOUNDED
- Strongest objection: The AVD agent already runs health checks on the host and the portal shows
  which one failed: domain joined, domain trust, SxS stack listener, Geneva monitoring agent, URL
  check, metadata service, App Attach. Microsoft also ships `WVDAgentUrlTool.exe`, and techs
  already use the Azure portal (SIGNALS "Where techs leave the tools"). A host that is Unavailable
  affects every user on it, so it is a senior-engineer incident rather than a tier-1 ticket.
  There is no AVD-specific ticket count.
- Fix (if wounded): Do not create a new folder. Add an AVD check set to Citrix-FSLogix-Triage, which
  is already per-host with CheckId output and already has an AVD deployment mode:
  - RDAgentBootLoader running
  - `HKLM\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered`
  - Application log event 3277 with INVALID_REGISTRATION_TOKEN / EXPIRED_MACHINE_TOKEN /
    INVALID_FORM / ENDPOINT_NOT_FOUND / InstallMsiException
  - events 3703 / 3019 / 3389
  - `qwinsta` rdp-sxs Listen state

  Each finding links to the Learn fix. That covers "AVD host refuses connections" without adding
  a bundle row.
- Checked:
  - [session host statuses and health checks](https://learn.microsoft.com/azure/virtual-desktop/troubleshoot-statuses-checks).
  - [troubleshoot-agent](https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent)
    (event IDs, registry, WVDAgentUrlTool).
  - Recon-code: AVD mode exists in Citrix-FSLogix-Triage.

### I-10 · Leaver check: "Is this leaver fully shut out?" (read-only)
- Verdict: WOUNDED
- Strongest objection: The evidence is speculation. "Offboarding misses are a classic MSP
  liability" is not a SIGNALS entry, and no owner, tech or client report of a missed leaver
  exists. Several items cannot be checked as promised:
  - "No sign-ins since leaving date" needs P1.
  - "Local admin removed" means checking every machine.
  - "Delegates reviewed" hits the same `Get-InboxRule`/Exchange role problem as I-02.

  As a standalone it is L, and every r2 lens already said not to build it standalone.
- Fix (if wounded): Park until I-01, I-02 and I-03 exist. Then add a `-Leaver` mode:
  - account disabled in AD and Entra
  - `signInSessionsValidFromDateTime` after the leave date (sessions revoked)
  - group and directory-role membership
  - licences
  - mailbox type, forwarding and delegates

  Drop the local-admin sweep. Report "could not check" for sign-ins on non-P1 tenants. Write the
  client-readable page using the I-03 stamp. Ask Michael for one real offboarding miss before
  building it.
- Checked:
  - SIGNALS (no leaver entry).
  - `ServiceDesk-Toolkit/README.md` (access report leaves disabled accounts out).
  - Licence facts as in I-01.

### I-11 · Server end-of-support register (and the "quarterly client risk review" bundle)
- Verdict: WOUNDED
- Strongest objection: This is sales and lifecycle reporting. It is not the product's stated
  purpose ("faster troubleshooting and faster, more accurate data collection" for the service
  desk), and the card admits there is no helpdesk ticket signal. AD-Audit already enumerates
  computers and OS, and every RMM reports OS version, so the only new data is the end-of-support
  date and a quarter-to-quarter comparison. Role, task and service discovery means remoting into
  exactly the oldest, least reachable servers.
- Fix (if wounded): Add an "End of support" section to AD-Audit (S). It lists servers by OS with
  Microsoft lifecycle dates, cited to Learn lifecycle pages, and last logon. The CSV can be
  compared later. Leave out the "quarterly review" bundle. Keep "services and tasks running as
  domain accounts" as an optional lockout-tool feature, where it has a troubleshooting use.
  Timing helps: Server 2016 extended support ends 2027-01-12/13, and 2012 R2 ESU Year 3 ended
  2026-10-13/14.
- Checked:
  - [Server 2016 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-server-2016)
    (extended end 1/13/2027 06:59 PT, i.e. end of 2027-01-12).
  - [Server 2012 R2 lifecycle](https://learn.microsoft.com/lifecycle/products/windows-server-2012-r2)
    (ESU Y3 ends 10/14/2026 06:59 PT).
  - PRINCIPLES "Who the product is for".
  - Recon-code: AD-Audit computer and OS enumeration.

### I-12 · Before/after permission receipt, with rollback
- Verdict: KILLED (as a separate tool; the need is real and belongs in BACKLOG)
- Strongest objection: This is not a new tool. Two existing tools fail the project's own
  destructive-operations risk profile, which already requires that "ACLs are exported (Get-Acl /
  SDDL) before Set-Acl" and that "each change is written to a log file with timestamp, target, old
  value and new value". Grep confirms:
  - FolderPermissionManager has no SDDL export, backup or change log.
  - LocalAdminManager has no logging at all (zero matches for Log/Export-Csv/Add-Content/Out-File).

  A separate receipt tool depends on the tech remembering to run it before a change. That is the
  same habit problem SIGNALS [bundle] describes. The restore path also adds a new destructive
  operation.
- Fix (if wounded): File two BACKLOG items:
  1. FolderPermissionManager saves SDDL before every `Set-Acl` and writes a change-log CSV in the
     M365-SyncedUserFixes format.
  2. LocalAdminManager logs every add or remove with the old and new member list.

  Both then feed the I-03 stamp ("Changed anything: Yes, see Logs\Changes_<date>.csv"). Restore can
  come later inside FolderPermissionManager under ShouldProcess, and must refuse to overwrite an
  ACL that changed again since the snapshot.
- Checked:
  - `squad/risks/destructive-operations.md`.
  - Grep of `FolderPermissionManager/` (no Sddl/backup/change log) and `LocalAdminManager/` (no
    logging).
  - `M365-SyncedUserFixes/README.md` change-log precedent.

### I-13 · "Did this policy reach this user?" GPO applied-or-not check
- Verdict: KILLED
- Strongest objection: Windows already gives this answer for free and remotely.
  `Get-GPResultantSetOfPolicy -Computer <pc> -User <user> -ReportType Html` (RSAT GroupPolicy,
  which the bundle setup already installs) and the GPMC "Group Policy Results" wizard both list
  applied and denied GPOs with the reason (security filtering, WMI filter, empty, disabled link).
  The "user hasn't signed in there" case is shown by the RSoP logging timestamp. Only one lens
  proposed it and no round-2 lens took it up. The one symptom with evidence, drive maps, is
  already covered by DriveMap-Diagnostics' GPO-side check.
- Fix (if wounded): If revived, add a "Group Policy result" collector to I-14, or add a sentence to
  the START HERE page telling techs to run `Get-GPResultantSetOfPolicy`. Not a new tool.
- Checked:
  - [Get-GPResultantSetOfPolicy](https://learn.microsoft.com/powershell/module/grouppolicy/get-gpresultantsetofpolicy)
    (`-Computer`, `-User`, `-ReportType Html|Xml`, `-Path`; logging mode only).
  - `ServiceDesk-Toolkit/README.md` setup step 4 installs the GPMC RSAT.
  - Longlist: single source (U-r1).

### I-14 · Workstation check, trimmed to what an RMM doesn't diagnose
- Verdict: KILLED (park until Michael answers the open questions)
- Strongest objection: No evidence supports it. All three r1 cards admit there is no SIGNALS entry.
  The owner's list of ticket drivers names lockouts, drive maps, files, Citrix/FSLogix/AVD and
  M365, not desktops. The RMM already shows the parts techs would look at first, and a second
  tool that disagrees with the RMM creates a trust problem (K-r2). The trimmed scope (secure
  channel, time skew, GP errors, OST size, reachability) is mostly already in DC-Diagnostics,
  Network-QuickCheck and DriveMap-Diagnostics' endpoint evidence.
- Fix (if wounded): Graveyard as "parked". It may come back if Michael's ConnectWise counts show
  desktop tickets are a large share and he names which RMM techs use on desktop tickets.
- Checked:
  - SIGNALS ticket drivers.
  - Longlist "Against it" (NinjaOne pending-reboot docs).
  - Recon-code tool index (DC-Diagnostics secure channel/w32tm, Network-QuickCheck).

### I-15 · Client-data leftovers sweep
- Verdict: KILLED
- Strongest objection: It is speculative and destructive.
  - No signal records a leftover-data incident.
  - It depends on a case manifest (from I-03) that does not exist yet.
  - Deleting client case folders on servers and tech workstations brings in the
    destructive-operations and personal-data profiles at once.
  - A sweep that only deletes folders named in a manifest misses older output, such as
    `C:\ADReports` zips and reports beside the scripts, which is exactly the leftover data it is
    meant to catch.
  - The bundle README already tells techs not to run from a synced folder because reports land
    beside the scripts. That is the real exposure, and it is fixed at write time, not with a later
    sweep.
- Fix (if wounded): Prevent instead of sweep. New and touched tools write under one documented
  output root, add their pattern to `.gitignore` as the personal-data profile requires, and print
  the output path in the I-03 note. If cleanup is still wanted later, make it a report-only list
  inside the case kit, not a deleting tool.
- Checked:
  - `squad/risks/personal-data.md` and `destructive-operations.md`.
  - `ServiceDesk-Toolkit/README.md` one-time setup step 1.
  - Recon-code (C:\ADReports, case folders beside scripts).
  - SIGNALS (no incident entry).

---

## Notes for the scorer

- **Build order the evidence supports:** I-03 (best signal, smallest), then I-01, then I-08. I-02
  waits on the CIPP question and the Exchange role check.
- **Questions for Michael (add to QUESTIONS.md):**
  - Does the MSP run CIPP?
  - Roughly what share of clients have Entra P1 (Business Premium or higher)?
  - Can techs get per-tenant Graph consent through GDAP?
  - Which RMM do techs use, and do they open it on desktop tickets?
  - One real offboarding miss, if any.
- **Graveyard candidates:**
  - I-04: workbench lives in another repo.
  - I-13: built-in RSoP report.
  - I-14: parked pending ticket counts.
  - I-15: speculative and destructive.
- **BACKLOG candidates:** I-12's two conformance fixes to FolderPermissionManager and
  LocalAdminManager.
