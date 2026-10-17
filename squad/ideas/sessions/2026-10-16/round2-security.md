# Round 2: security and compliance lens

Session 2026-10-16. Focus: "useful tools that we may not have currently".
I read all six round-1 lists. Four ideas came up in nearly every lens: the cloud sign-in check,
the mailbox check, the effective folder-access check, and the front door that writes a ticket
note. From this lens the risk is not in whether to build them but in how. These are the tools a
tier-1 tech will run most often, against the most clients, with admin rights. Below are three
entries that change their design. None of them adds a separate security product.

---

### COMBINES Mailbox Quick Check (user, manager, market, architect, newcomer) + Compromised-account first look (security) + Leaver verification (security, newcomer)
- Pitch: Build one read-only mailbox tool, not three. The finding that matters most for
  security, mail forwarded or moved by a rule to an outside address, is also the most common
  answer to "I'm not getting emails". When the tool sees a sign of takeover (external forwarding,
  a new rule that deletes or hides mail, rules created recently, a delegate added recently), it
  changes its verdict to "POSSIBLE COMPROMISE: do not reset or delete anything yet". It then saves
  the evidence (rules, forwarding, delegates, the user's recent sign-ins if Graph is connected)
  into a hashed case folder before anyone acts, and the note tells the tech to escalate. Called
  with `-Leaver`, the same checks become the mailbox half of an offboarding check: forwarding
  set? who still has Full Access? is sign-in blocked?
- Who and when: the first 15 minutes of any mailbox ticket. A tech who sees "mail not arriving"
  on a hacked account usually deletes the bad rule and resets the password, and that destroys
  the evidence the client's insurer will ask for. This tool records the evidence first.
- Evidence: five of six round-1 lenses proposed a mailbox check. SIGNALS 2026-10-16 [m365]
  calls these slow tickets worked by hand in the Exchange admin center. Recon-code found no
  `Get-Mailbox`, `Get-InboxRule` or message trace anywhere in the repo. Manager round 1:
  "a forwarding rule to an outside address is the evidence an insurer or client asks for".
  Newcomer round 1: a new tech "would never think to look" for forwarding as a compromise sign.
  Building it once avoids three tools with overlapping Exchange connections and different rules
  about what counts as suspicious. That divergence is the problem consolidation PRs #11-#16 had
  to clean up (SIGNALS repo-history [bundle]).
- Builds on: the Exchange connection in `Get-M365SecurityEvidence.ps1:557`, the Graph per-user
  `auditLogs/signIns` call (`:1080`), the zip-plus-SHA-256 pattern in
  `Entra-DeviceActivityTimeline`, and the CheckId verdict contract.
- Security guardrails (part of the idea, not extras):
  - Read-only by construction. The tool has no "remove rule" or "disable forwarding" option.
    Fixing stays a separate, deliberate human step. The README lists the least role that is
    enough: an Exchange view-only role plus Global Reader for sign-ins. The exact role names
    and whether `Get-InboxRule` / `Get-MessageTraceV2` work under a view-only role must be
    verified on Learn before build (P-001). If a cmdlet is denied, the tool says "could not
    check rules: role X needed", not "no rules found".
  - A rule's contents can include the attacker's keywords and the user's mail subjects. The
    HTML shows rule conditions and actions only, never message bodies. The message-trace
    section is limited to sender, recipient, time and status.
  - Every report and note header says which tenant was queried and which admin ran it, so an
    MSP tech signed in to the wrong client's tenant sees it before acting.
- Size guess: M (one tool). The leaver mode adds about S on top, and its AD half reuses
  AD-UserQuickCheck.
- Why now / why us: CIPP covers this as a hosted multi-tenant service, which PRINCIPLES rule
  out. A local, read-only tool that saves evidence first fits both the no-cloud rule and the
  owner's "what they checked" ask.

### BUILDS ON Shared case kit (architect) + Ticket Note / Handoff Builder (manager) + front door (manager, architect, newcomer, user)
- Pitch: The case kit that every new tool will copy should hold three safety pieces as well as
  the HTML shell. First, a header stamp on every report and note: client domain or tenant, the
  account that ran the check, the machine, the time, and "Changed anything: No / Yes (see
  receipt)". Second, a case manifest that records where the tool wrote client data. Third, a
  "paste-safe" mode for the ConnectWise note that leaves out raw sign-in IP addresses, rule
  contents, file paths under user profiles and group dumps, and refers to the local evidence
  folder instead. One copy in the kit means every future tool gets all three without anyone
  remembering to add them.
- Who and when: every tech at the moment they paste a note into ConnectWise or escalate. Also
  Michael reviewing an escalation: the stamp shows which client and which account the evidence
  came from, and whether the tech changed anything before escalating.
- Evidence: SIGNALS 2026-10-16 [escalation]: the owner wants a ready-to-paste ConnectWise note.
  That note leaves the machine and goes into a third-party PSA that the whole MSP can read, and
  in many shops clients can read it through the portal. So "output stays local" (PRINCIPLES)
  stops being true for whatever lands in the note. Recon-code: case folders hold client AD and
  tenant data; `FSLogix-Profile-Backup` is flagged personal-data in `squad/squad.config.json`;
  only `M365-SyncedUserFixes` records its own changes. The front-door ideas make one tech run
  many tools against many clients in one sitting. That is exactly when the wrong-tenant or
  wrong-domain paste mistake happens, and a stamp at the top of the note is the cheapest guard
  against it. The case manifest is also what makes my round-1 "client-data leftovers sweep"
  safe. The sweep deletes only folders a manifest names, never wildcard matches, so it shrinks
  from "guess where tools wrote" to "read the manifests" (S).
- Builds on: the architect's `CaseKit.ps1` and its parity test
  (`AD-LockoutDiagnostics/Tests/SharedReferenceParity.Tests.ps1` precedent), the existing
  SUMMARY.txt writers, and the M365-SyncedUserFixes change-log CSV format for the "Changed
  anything" line.
- Size guess: S on top of the case kit (M). It gets cheaper the earlier it lands, because each
  tool that ships before it needs these pieces fitted afterwards.
- Why now / why us: the front door and the ticket note are the bold bet three lenses agree on.
  Adding the stamp and the paste-safe note after techs have pasted six months of notes is too
  late. The note format is effectively fixed the day the first tool emits it.

### CHALLENGES "Can this user open this folder?" effective-access verdict (user, market bold bet; my "Who can get into this folder?")
- Pitch: Build it, but with a different contract. A wrong YES or a careless "add them to group
  X" is how access creep happens across fifty clients. The tool should (1) answer YES only when
  it resolved both share and NTFS permissions, every SID, every nested group and every Deny
  entry, and otherwise say "PROBABLY" or "CAN'T TELL" with the reason (an unresolvable SID,
  access-based enumeration, a claims or central access policy on the folder, a folder the running
  account could not read). (2) When the answer is NO, recommend the narrowest group that already
  grants the needed right on that folder, and warn if that group also grants admin or wide
  access elsewhere, using `Find-PrivilegedAccessPaths` logic. (3) Never suggest adding Everyone,
  Authenticated Users or a direct per-user entry. (4) Hand off to FolderPermissionManager only
  through a before/after permission receipt, so any change the verdict leads to can be proved
  and undone.
- Who and when: the tier-1 tech on "I can't open Finance". Today the easy fix under time
  pressure is to grant the user directly or add them to the first big group that works. Nobody
  sees that until an audit or a leaver investigation.
- Evidence: market round 1 already says "a wrong YES is the costliest failure in this area"
  and sizes it L. SIGNALS 2026-10-14 trust breaker: the access report got primary-group
  membership wrong, which shows group resolution is where this repo has already been
  confidently wrong once. Recon-code: FolderPermissionManager and LocalAdminManager change
  ACLs and groups with no change log. My round-1 permission receipt is the missing safety net
  for the step after this verdict. Whether the verdict can call the Windows access-check API
  instead of re-implementing ACL evaluation in PowerShell (which also requires care over Deny
  ordering and inheritance) must be checked on Learn first. If no supported call works remotely
  on a 3.0 floor, the tool should say so and stay at PROBABLY rather than imitate the API
  (P-001).
- Builds on: AD-GroupMembership-Export nesting resolution with the primary-group fix,
  Find-PrivilegedAccessPaths, my round-1 read-only share/NTFS report (the "who can get in"
  view becomes this tool's evidence tab rather than a separate tool), and the permission
  receipt (S).
- Size guess: L as proposed. M if the first version ships the "who can get in, and through
  which group" evidence plus the narrowest-group recommendation and holds back the single YES
  verdict until the access-check question is answered.
- Why now / why us: every lens wants this tool, so it will be built. The design choice that
  decides whether it reduces risk or spreads it across clients is made now, not after.
