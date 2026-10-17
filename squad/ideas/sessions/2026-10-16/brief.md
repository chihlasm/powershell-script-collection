# Ideas brief, session 2026-10-16

Focus: "useful tools that we may not have currently".

## Overview

Michael, six lenses produced 15 ideas. The critic let 3 through cleanly, wounded 7 and killed
5. After applying the critic's fixes and merges, 7 cards remain. The evidence points to one
build order: first the **ticket note** (I-03), which answers all three of your [escalation]
signals and is the smallest item; then the **M365 sign-in and sync check** (I-01), which is the
biggest gap in the bundle; then the **one-user temporary-profile verdict** (I-08), which is in
the slowest ticket area. Everything below those three is either lower-signal (I-07, I-11, I-06)
or waits on your answers (I-02). Two kills are really "not a new tool": the permission receipt
(I-12) is a conformance gap in FolderPermissionManager and LocalAdminManager and should become
two BACKLOG items, and the workstation check (I-14) is parked until you give ticket counts. All
cards respect PRINCIPLES.md. The one real tension is P-003 ("needs no installs") for I-01 and
I-02: they need Microsoft.Graph.Authentication and ExchangeOnlineManagement on the tech
workstation, the same exception Get-M365SecurityEvidence already uses.

Scores: Frequency x2, Time saved x2, Differentiation x1.5, Effort x1 (5 = small), Risk x1.5
(5 = safe). Maximum 40.

## Ranked list

| Rank | Card | Score | One line |
|---|---|---|---|
| 1 | [I-03 Ticket note in every quick check](cards/I-03-ticket-note.md) | 30.5 | Checked / Ruled out / Could not check / Next step, to file and clipboard, with a stamp; "ruled out" only when the check could actually look. S-M. |
| 2 | [I-01 M365 user sign-in and sync check](cards/I-01-m365-user-signin-check.md) | 29.5 | Cloud version of AD-UserQuickCheck with a tenant gate that says what it could not see; sign-in half needs Entra ID P1. M. |
| 3 | [I-08 One-user temporary-profile verdict (+ AVD host checks)](cards/I-08-vdi-temp-profile-verdict.md) | 29 | One ranked cause and the lock holder (`Get-SmbOpenFile`) for a user's FSLogix temp profile; replaces a bundle row. AVD agent checks go into Citrix-FSLogix-Triage. M. |
| 4 | [I-07 Folder access evidence](cards/I-07-folder-access-evidence.md) | 26 | Share + NTFS + group chain with a hedged verdict and the narrowest group; defers the final yes/no to Windows' Effective Access tab. M. |
| 5 | [I-11 End-of-support section in AD-Audit](cards/I-11-end-of-support-in-ad-audit.md) | 25.5 | Cited lifecycle dates per server in an existing audit; 2016 support ends 2027-01-12. S. |
| 6 | [I-06 Kerberos/NTLM enforcement scan](cards/I-06-kerberos-enforcement-check.md) | 24 | Patch-aware, domain-wide verdict on what the 2026 RC4 changes are breaking now; ship the 0xE / KDCSVC cause in the lockout tools first. M. |
| 7 | [I-02 Mailbox check, takeover signs first (+ later leaver mode)](cards/I-02-mailbox-check.md) | 21 | Delegates, rules, forwarding, trace, with "do NOT reset yet, escalate"; needs a write-capable Exchange role, and CIPP may already cover the takeover half. M. |

### Merged, not carded separately

- **I-05 cited code tables and error lookup:** no separate deliverable. The AADSTS table is
  dropped because Microsoft says the codes change at any time; I-01 shows the log's
  `failureReason` and links to `login.microsoftonline.com/error`. The on-prem tables
  (Kerberos/NTLM, KDCSVC, FSLogix) are built inside I-06 and I-08 with the existing parity test.
  The standalone lookup is dropped.
- **I-09 AVD session host check:** becomes an AVD check set in Citrix-FSLogix-Triage; described
  on the I-08 card.
- **I-10 leaver check:** a later `-Leaver` mode over I-01 and I-02, parked until those and I-03
  exist and you give one real offboarding miss; described on the I-02 card.

## Questions for you

These decide the scope of I-01, I-02 and the parked ideas. They should go to QUESTIONS.md for
`/squad:review`.

1. **Does the MSP run CIPP?** If yes, I-02 shrinks to the mailbox facts techs look up by hand,
   with "check CIPP's BEC report" as the next step, and CIPP's per-user view partly overlaps
   I-01.
2. **Roughly what share of clients have Entra ID P1 (Business Premium or higher)?** Without P1,
   I-01 cannot see smart lockout, CA failures or sign-in errors, and I-02 loses its
   sign-in-based takeover signs. Risky user needs P2.
3. **Can techs get per-tenant Graph consent through GDAP?** I-01 needs consent for
   `AuditLog.Read.All`, `Directory.Read.All` and `UserAuthenticationMethod.Read.All` in each
   client tenant.
4. **Which RMM do techs use, and do they open it on desktop tickets?** Plus rough ConnectWise
   ticket counts per area. This decides whether I-14 comes back.
5. **One real offboarding miss, if any.** I-10 has no signal today; one real case would justify
   the leaver mode.

## Worth a look (killed ideas you might overrule)

- **I-12 Before/after permission receipt.** Killed as a tool, but the need is real and the
  critic found a rule breach: `squad/risks/destructive-operations.md` requires an SDDL export
  before `Set-Acl` and a change log with old and new values, and FolderPermissionManager has
  neither while LocalAdminManager logs nothing. Recommend approving two BACKLOG items:
  (1) FolderPermissionManager saves SDDL before every `Set-Acl` and writes a change-log CSV in
  the M365-SyncedUserFixes format; (2) LocalAdminManager logs every add or remove with the old
  and new member list. Both then feed the I-03 "Changed anything: Yes" stamp, and I-07's hand-off
  depends on (1).
- **I-14 Workstation check.** Parked, not dead. Overrule if your ConnectWise counts show desktop
  tickets are a large share for the clients with little or no VDI, and the RMM is not what techs
  open on those tickets.
- **I-04 Front door launcher.** Only if you want it in the workbench repo, where it could consume
  the I-03 note format. In this repo the [bundle] signal is better served by keeping the START
  HERE table current (add I-01/I-08 rows as they land, and the missing
  Get-AzureFilesFSLogixProfiles row recon-code found).

## Graveyard (this session)

- I-2026-10-16-04 · Front door launcher · killed (2026-10-16) by critic: the retired workbench in
  new clothes; the workbench lives in its own repo, and one launcher on a workstation would fail
  confusingly for tools that must run on the PC, a Delivery Controller or a DC.
- I-2026-10-16-12 · Before/after permission receipt with rollback · killed as a tool (2026-10-16)
  by critic: a conformance gap in FolderPermissionManager and LocalAdminManager, not a new tool;
  a separate receipt depends on techs remembering to run it. Move to BACKLOG.
- I-2026-10-16-13 · "Did this GPO reach this user?" · killed (2026-10-16) by critic: the built-in
  `Get-GPResultantSetOfPolicy` / GPMC Group Policy Results report already lists applied and denied
  GPOs with reasons; one lens, no round-2 support.
- I-2026-10-16-14 · Workstation check · parked (2026-10-16) by critic: no signal and RMM overlap;
  the trimmed scope is mostly in DC-Diagnostics, Network-QuickCheck and DriveMap-Diagnostics.
  Returns if ticket counts and the RMM answer support it.
- I-2026-10-16-15 · Client-data leftovers sweep · killed (2026-10-16) by critic: speculative and
  destructive, depends on a manifest that does not exist, and misses older output; prevent at
  write time with one output root and gitignore patterns instead.
