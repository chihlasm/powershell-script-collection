# Round 2: user-in-the-moment (helpdesk tech mid-ticket)

Lens recap: a tier 1/2 tech with a client on the phone. The test for every entry below is the
same as round 1: one name or path in, one plain-English verdict out, no setup on the client's
servers, no added step on the common path, and it replaces a trip to a portal or console.

What round 1 showed: all six lenses proposed the cloud sign-in check, five proposed the
one-user sync check, five proposed the mailbox check, and four proposed a front door. The
convergence is strong evidence. The risk now is that it ships as **more separate tools**,
which is exactly what the owner's adoption signal warns against (SIGNALS 2026-10-16 [bundle]:
"don't know which tools exist or when to use each one"; repo-history: PRs #11-#16 merged
near-duplicates "because it was unclear which one to run"). All three entries below are about
shipping the same value with fewer doors.

---

### COMBINES "M365 user quick check" + "Why isn't this user syncing?" (one-user sync check)
**One cloud sign-in check that answers the sync question itself, instead of two tools.**

- Pitch: The tech types one name and gets one verdict for Microsoft 365: YES / NO / PROBABLY
  NOT, with the reason. When the reason is on the sync side ("this user was never synced",
  "the cloud copy is three days stale", "another account already holds this email address"),
  the same run says so, and only then offers the deeper Entra Connect server look as an
  optional step. The tech never has to decide up front whether the problem is "cloud" or
  "sync". They can't tell from the phone call anyway.
- Who and when: "Outlook keeps asking for my password" / "new starter can't get into Teams" /
  "my new surname isn't showing". The user describes all of these the same way, and the tech
  cannot know which of the two round-1 tools to run. Sync problems look like sign-in problems
  from the phone.
- Evidence:
  - Convergence: cloud check proposed by all 6 lenses, sync check by 5. Every sync card's
    "who and when" is a sign-in or "missing in M365" symptom, which is the cloud check's
    trigger too.
  - SIGNALS 2026-10-16 [entra][m365] slow tickets, "Where techs leave the tools": Entra admin
    center and sign-in logs. Client facts: mostly hybrid. So most cloud sign-in tickets have a
    possible sync cause.
  - **The first sync questions need no Entra Connect server access.** The Graph user object
    already carries `onPremisesSyncEnabled`, `onPremisesLastSyncDateTime` and
    `onPremisesProvisioningErrors` (all need `$select`), alongside `accountEnabled`
    (https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0, read this
    session). The market analyst found `onPremisesProvisioningErrors` reports PropertyConflict
    on UPN/ProxyAddress, which is the duplicate-address case. So "synced? when? sync error?"
    comes from the same Graph sign-in the cloud check already makes. Only the "is the OU in
    scope / which rule filtered them" question needs the Connect server
    (`Get-ADSyncConnector`/`Get-ADSyncRule`, already used read-only-capable in
    `M365-SyncedUserFixes/SyncedUserFixes.Core.ps1`).
  - The AD side for the comparison ("does the user exist in AD, what is its UPN suffix, which
    OU") is already in AD-UserQuickCheck's lookups.
  - `signInActivity` needs Entra ID P1/P2 plus AuditLog.Read.All, and is missing for users who
    never signed in (same Learn page). This gives the tool a free "never signed in to M365"
    line for new starters, and it must say "could not look (no P1)" rather than "never signed
    in" when the licence is absent (P-001).
- Shape that keeps the common path short:
  1. Graph only (default, seconds): account enabled, licence present, recent sign-in failures
     decoded, CA/MFA reason, synced flag, last sync time, provisioning errors. Verdict.
  2. Compare with AD (automatic if the RSAT AD module is present, otherwise "could not
     compare"): user exists on-prem but not in cloud; UPN suffix differs; AD changed after the
     last sync time ("change hasn't synced yet: wait for the next cycle or ask a senior to run
     a delta sync").
  3. Entra Connect server look, **only when steps 1-2 point at sync** and only with
     `-SyncServer` or discovery succeeds: OU in scope, filtering rule, scheduler state.
     If the tech cannot reach it, the verdict stays at "probably out of sync scope: escalate
     with this note" instead of blocking.
- Builds on: Get-M365SecurityEvidence signIns/CA Graph calls; Get-EntraPasswordPolicy per-user
  expiry and smart lockout; AD-UserQuickCheck lookups and verdict wording; SyncedUserFixes.Core
  connector/rule reading; Test-EntraConnectReadiness (staging-mode check: a staging server
  must give "can't tell", not "out of scope").
- Size guess: M (same as the cloud check alone; sync step 3 can come in a second release).
- Why now / why us: Shipping two tools here repeats the near-duplicate problem the owner just
  spent six PRs removing. One tool with a staged look also gives a better handoff note:
  "checked cloud account, checked sync, ruled out licence, found stale sync".

---

### COMBINES "Mailbox quick check" + "Compromised-account first look" (with Security's guardrails kept)
**One mailbox check where the hijack signs rise to the top without the tech asking.**

- Pitch: The tech runs the mailbox check for "I'm not getting emails". If the run finds an
  outside forwarding address, an inbox rule that deletes or moves mail out of sight, or a
  recent sign-in from an unusual country, the first line of the result changes to "Possible
  account takeover: do not reset the password yet. Capture evidence (one switch), then
  escalate". Otherwise it answers the ordinary mailbox question: permissions, full, shared,
  forwarding, recent trace.
- Who and when: The ticket always arrives as "my email is weird" or "a client says they got a
  strange invoice from me". It never arrives as "I am compromised". A tier-1 tech will pick
  the mailbox tool, not a compromise tool they don't know exists. The compromise signs are only
  found if the tool the tech already runs looks for them.
- Evidence:
  - Overlap is near-total: Security's first look checks forwarding rules, inbox rules,
    sign-ins and new MFA methods; four mailbox cards check forwarding and inbox rules, and the
    manager and newcomer cards already say external forwarding is a compromise sign.
  - SIGNALS 2026-10-16 [bundle]: techs don't know which tools exist. A separate compromise
    tool depends on the tech recognising a compromise, which is the escalation knowledge they
    lack (SIGNALS [escalation]: "don't know how to resolve").
  - Recon-code: no mailbox or forwarding check exists anywhere (grep for `Get-Mailbox` /
    `Get-MessageTrace` returned none), so there is no existing tool to fold into.
  - Market analyst: `Get-MessageTrace` is being replaced by `Get-MessageTraceV2`; scripts in
    circulation are breaking. One maintained tool beats two that both have to track this.
- Security's point, kept: resetting first destroys or muddies evidence. So the combined tool
  stays strictly read-only, and the takeover verdict's "What to do" is "don't reset yet; run
  again with `-CaptureEvidence`" (hashed folder, per Entra-DeviceActivityTimeline's zip +
  SHA-256 pattern), then escalate with the note. It prints the tenant and admin it queried at
  the top (Security's cross-client guard). Missing scopes or licence give "could not check
  sign-ins", never "no suspicious sign-ins" (P-001).
- Builds on: Get-M365SecurityEvidence's Connect-ExchangeOnline handling and Graph sign-ins;
  the cloud sign-in check above for the sign-in half (same functions, shipped inside the
  folder); verdict + "What to do" shape.
- Size guess: M (the compromise signals add a few checks to the mailbox tool; the separate
  tool would have re-done the Exchange connection, rule reading and note).
- Why now / why us: One door for every mail ticket. Security's goal, a tier-1 tech catching a
  hijack on the first call, only works if the check sits in the tool the tech already
  reaches for.

---

### CHALLENGES the front-door bold bets ("Start Here", "What's the problem?", "Start a ticket") and BUILDS ON "Ticket Note and Handoff Builder" / "Shared case kit"
**Put the ticket note at the end of every quick check first. Build the router second, keyed on the person, not a symptom menu.**

- Pitch: Before building a launcher, make every quick check (the existing AD-UserQuickCheck,
  Network-QuickCheck and FSLogix triage first, then each new one) finish by writing the same
  "Checked / Ruled out / Found / Next step" note to a text file and to the clipboard. The tech
  pastes it into ConnectWise with no extra step. The front door then becomes a thin launcher
  that asks for the **person** (and optionally the computer), not "what kind of problem", and
  runs the quick checks that apply to that person. Its job is joining the notes, not routing.
- Who and when: Every tech, at the moment they would otherwise write "checked AD, looks fine"
  by hand, which is the moment the owner says reasoning gets lost.
- The challenge, with evidence:
  - **The router only works after the tools exist.** The manager's card says it: "Without
    those, about half of the doors lead nowhere." The architect sequences it as "a menu over
    4 existing tools first". A front door that answers "no tool for this yet" on half the
    symptoms on day one teaches techs it is not worth opening. That is the habit the owner is
    trying to build (SIGNALS [bundle]: "the bundle is new, so it isn't a habit yet").
  - **A symptom menu adds a step the tech can get wrong.** Tickets arrive as "Outlook keeps
    asking for my password" (newcomer's own observation), which could be the cloud account,
    sync, the PC or a lockout. Asking a tier-1 tech to classify it is asking the question they
    escalate over (SIGNALS [escalation]). The one thing the tech always knows within ten
    seconds of the call is **who** is calling. A person-keyed launcher (my round-1 "Look up
    this person") runs the cheap checks for that person in parallel and lets the verdicts
    pick the problem.
  - **The Handoff Builder's end-of-ticket questions add a step.** "What did the user report?
    What did you try?" asked after the fact will be skipped mid-queue. If each tool writes its
    own note block as it runs, the "what was checked" part costs nothing. The builder then only
    joins the blocks already in the ticket's case folder, plus one optional free-text line.
  - **The note is what the owner actually asked for.** SIGNALS 2026-10-16 [escalation], all
    three core-problem entries: handoff summary and ready-to-paste ConnectWise note. Recon-code:
    only the lockout orchestrator writes a SUMMARY.txt "for pasting into a ticket"; nothing
    else does. That gap can be closed one tool at a time, starting this week, with no launcher.
- Concrete first slice (S to M):
  - Architect's case kit carries one `New-TicketNote` function (Checked / Ruled out / Found /
    Next step / evidence path, plus "Could not check: X" lines so P-001's "could not look" is
    visible to the reader), parity-tested like `SharedReferenceParity.Tests.ps1`.
  - Wire it into AD-UserQuickCheck, Network-QuickCheck and Citrix-FSLogix-Triage, which already
    produce verdicts. Clipboard: `Set-Clipboard` is PS 5.0, so the 3.0-floor tools need a
    fallback such as piping to `clip.exe` (verify behaviour and encoding before relying on it;
    the text file is the guaranteed output).
  - An optional `-TicketNumber` puts every tool's note in one folder named after the ticket,
    so a later joiner (or the person-keyed launcher) has something to join.
- Size guess: S to M for notes in three existing tools; the person-keyed launcher stays L and
  comes after the cloud and mailbox checks above exist.
- Why now / why us: It delivers the owner's top request immediately on tools techs can already
  run. It makes every new tool from this session arrive "note-ready", and it keeps the front
  door from shipping as an empty menu.
