# I-02 · Mailbox check with takeover signs first (and a later leaver mode)
- Champion: user-in-the-moment, manager-or-buyer, architect, newcomer, market-analyst
  (takeover-first: security, plus newcomer, market-analyst r2; leaver mode: newcomer, security)
- Score: 21 (F 3, T 3, D 2, E 3, R 2)

This card also carries I-10, the leaver check. The critic said to build it only as a mode over
I-01 and this check, after both exist, so it is described under Cost and risk and not scored
separately.

## The pitch
Enter one mailbox and get one read-only report: who has Full Access, Send As or Send on Behalf;
forwarding and inbox rules (including hidden ones); size, archive and hold; shared or not; and a
recent message trace. Every run looks for takeover signs first, such as external forwarding,
rules that hide or delete mail, and recently added rules or delegates. If any are found, the
first line becomes "Possible account takeover: do NOT reset the password or delete the rule yet.
Escalate." A `-CaptureEvidence` switch saves a hashed evidence folder.

## A day with it
A client says a supplier never got their invoices. The tech runs the mailbox check on
`accounts@client`. The first line: "Possible account takeover: an inbox rule created 2 days ago
moves mail containing 'invoice' to RSS Feeds and marks it read; external forwarding to a
gmail.com address. Do NOT reset the password or delete the rule yet. Escalate." The tech
escalates with the evidence folder instead of deleting the rule, which would have destroyed the
evidence an insurer will ask for.

## Why us, why now
- **Owner signals:** SIGNALS 2026-10-16 [m365]: mailbox tickets are among the slowest, and
  techs work them by hand in the Exchange admin center.
- **Gap:** recon-code found no `Get-Mailbox`, `Get-InboxRule` or message trace anywhere in the
  repo.
- **Why now:** `Get-MessageTrace` is deprecated in favour of `Get-MessageTraceV2` for worldwide
  tenants from 2025-09-01, so community scripts are breaking
  ([Get-MessageTrace](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetrace)).
- **Takeover-first comes from security r1:** resetting the password first destroys evidence;
  an external forwarding rule is what an insurer asks for (manager-or-buyer r1).
- **Code leverage:** `Connect-ExchangeOnline` handling in `Get-M365SecurityEvidence.ps1`, the
  zip plus SHA-256 evidence pattern in Entra-DeviceActivityTimeline, and the I-01 core (one
  sign-in, one tenant gate).
- **Market:** Hawk is free but collection-only, needs about nine module installs and pulls in
  the PSAppInsights telemetry library, which conflicts with P-003 and the no-telemetry rule
  ([HAWK](https://www.powershellgallery.com/packages/HAWK)). See the objection for CIPP.
- **Weak spot:** no external source for mailbox-permission pain (recon-market pain 14); demand
  rests on the owner's signal.

## The strongest objection
The read-only, least-privilege promise fails on the first cmdlet, and the "nobody gives a free
verdict" claim is wrong. Learn says `Get-InboxRule` "doesn't work for members of View-Only
Organization Management role group in Exchange Online or the Global Reader role in Microsoft
Entra ID"
([Get-InboxRule](https://learn.microsoft.com/powershell/module/exchangepowershell/get-inboxrule)),
so a tech needs a role that can also change mailboxes. The message trace role is still
unverified. And CIPP's free, self-hostable BEC check already runs about 21 checks (rules,
forwarding, MFA methods, app consents, sign-ins, delegations, audit events) with a
Low/Medium/High score, without needing P1
([CIPP BEC](https://docs.cipp.app/user-documentation/identity/administration/users/user/bec)).
If the MSP runs CIPP, the takeover half is already solved, and a second tool that disagrees
with it is a trust problem.

**Answer:** only partly. If the MSP runs CIPP, cut this to the mailbox facts techs look up by
hand (delegates, forwarding, rule list, size, archive, hold, shared or not, recent trace) and
make "Check CIPP's BEC report" the next step on any suspicious signal. Either way the "do NOT
reset yet, escalate" line stays, because that advice is the real value. The Exchange role
problem cannot be argued away; it must be documented and accepted.

## Cost and risk
- **Size:** M, in the same folder as I-01 as a second entry script over one core. Build after
  I-01. The mailbox stage fails on its own, so a Global Reader still gets the I-01 verdict.
- **Build conditions from the critic:**
  - Find and cite the minimum Exchange role, checked in a test tenant with
    `Get-ManagementRole -Cmdlet Get-InboxRule` and `... -Cmdlet Get-MessageTraceV2`.
  - Call `Get-InboxRule -IncludeHidden`.
  - Respect `Get-MessageTraceV2` limits: last 90 days, at most 10 days per query, 5000 results
    at most with no paging, 100 queries per 5 minutes
    ([Get-MessageTraceV2](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetracev2)).
  - "Newly added MFA method" cannot come from the authentication methods endpoint alone, because
    not every method type has a created date
    ([authentication-list-methods](https://learn.microsoft.com/graph/api/authentication-list-methods?view=graph-rest-1.0)).
    Sign-in-based signs need P1. Missing roles or licences give "partly checked", never "no
    signs of takeover".
  - No remediation switches at all.
- **Later: leaver mode (I-10).** Parked until I-01, this check and I-03 exist, and until Michael
  gives one real offboarding miss. Then `-Leaver` checks: disabled in AD and Entra;
  `signInSessionsValidFromDateTime` after the leave date (sessions revoked); group and
  directory-role membership; licences; mailbox type, forwarding and delegates. Sign-ins on
  non-P1 tenants are "could not check". The local-admin sweep is dropped. The client-readable
  page uses the I-03 stamp. Blocking sign-in stays in M365-SyncedUserFixes.
- **What could go wrong:** a false "no signs of takeover" when a role or licence is missing;
  disagreeing with CIPP; a tech holding a write-capable Exchange role during a compromise.
- **Risk profiles:** personal-data applies strongly. Rule conditions can contain client keywords
  and trace output holds addresses: no message bodies, trace limited to sender, recipient, time
  and status, and the paste-safe note redacts rule contents. Read-only in behaviour, but run
  under a role that can write.

## Score reasoning
- Frequency 3: mailbox tickets are a named driver, but the takeover case is rarer than plain
  delegate or forwarding lookups.
- Time saved 3: the EAC lookups are a few clicks each; one report saves perhaps 10 minutes, more
  when it stops a tech destroying evidence.
- Differentiation 2: CIPP's free self-hosted BEC check covers the takeover half; Hawk covers
  collection.
- Effort 3: M on top of the I-01 core, with unverified role and module details.
- Risk 2: needs an Exchange role that can change mailboxes, handles sensitive mail metadata, and
  a wrong all-clear during a compromise is costly.
