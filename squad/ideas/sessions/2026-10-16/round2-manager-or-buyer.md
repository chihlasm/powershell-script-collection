# Round 2: manager-or-buyer lens (the MSP service-desk lead)

What round 1 showed from where I sit: every lens (6 of 6) proposed the cloud sign-in check,
5 of 6 proposed the mailbox check, and 4 of 6 proposed a front door. That much agreement is
a signal in itself, but it also hides a risk. If these ship as separate tools, a tier-1 tech
faces more folders to choose from, which is the exact adoption failure SIGNALS records
(2026-10-16 [bundle]: "don't know which tools exist or when to use each one";
repo-history: consolidation PRs #11-#16 merged near-duplicates for the same reason). The
entries below are about shipping the agreed ideas in a shape that makes the average tech
work like the best one, leaves evidence behind, and gives the lead something to show a
client or an insurer.

---

### One cloud user case: sign-in, mailbox, "was it hacked?" and "is the leaver done?" from one run
`COMBINES` Cloud Sign-in Quick Check (all six lenses), Mailbox Quick Check (manager, user,
market, architect, newcomer), Compromised-account first look (security), Leaver /
offboarding verification (security, newcomer)

- Pitch: One tool, one sign-in to the client's tenant, one user's name, and the tech picks
  the question: "can't sign in", "mail problem", "might be hacked", or "leaver check". All
  four read the same things (the user's account, recent sign-ins, MFA methods, mailbox
  forwarding, inbox rules, delegates, licences), so one tool reads them once and gives a
  verdict for the question that was asked. The other findings are still listed below the
  verdict, so a "can't sign in" ticket that turns up an outside forwarding rule gets escalated
  as a possible compromise.
- Who and when: Any tier-1 tech on any M365 ticket. The lead's payoff is that the hacked
  account gets spotted on the first call, even when the user only reported "Outlook keeps
  asking for my password". Today that only happens if the tech already thinks of
  compromise, and a new tech won't (newcomer round 1 made the same point about forwarding
  rules).
- Evidence: SIGNALS 2026-10-16 [entra][m365]: these tickets "usually take longer than the
  others"; techs work by hand in the Entra, M365 and Exchange admin centers and sign-in logs.
  SIGNALS [bundle]: techs don't know which tool to run, so four cloud tools would make that
  worse. Recon-code: no per-user sign-in lookup, no `Get-Mailbox`, no forwarding check.
  `Get-M365SecurityEvidence` already runs a per-user `auditLogs/signIns` query (architect, line 1080) and
  already handles the Exchange Online connection (line 557). Market: Microsoft's Sign-in
  diagnostic is portal-only, and CIPP needs a hosted backend, which PRINCIPLES rules out.
- What the lead needs built in (non-negotiable from this lens):
  - **Tenant and admin banner at the top of every output** (security round 1). Querying the
    wrong client's tenant and pasting the result into another client's ticket is a real MSP
    failure, and it is the lead who has to explain it to the client.
  - **A "could not look" line for each area** (P-001): no P1 licence for sign-in logs, missing
    scope, no Exchange role. The ticket note must say "sign-in log not checked: tenant has no
    P1", never "no failed sign-ins". An insurer or a client's auditor will read that line.
  - **Read-only and evidence-first**: it captures state before anyone resets a password or
    revokes sessions (security round 1). The hashed evidence folder is what we hand over if
    the incident becomes an insurance claim.
  - **Leaver mode produces a client-readable page**: "J. Smith: access closed on 2026-10-16,
    checked by <tech>" with the list. This is the proof a client asks for after a hostile
    departure, and it answers SIGNALS [reporting] "turning tool output into something a
    client can read".
- Builds on: `Get-M365SecurityEvidence` Graph and EXO plumbing; `AD-UserQuickCheck` verdict
  wording; `M365-SyncedUserFixes` stays the only place that changes anything (block sign-in),
  so this tool's "next step" points there; Entra-DeviceActivityTimeline's zip-and-hash pattern.
- Size guess: L as a whole. Ship it in order of ticket volume: sign-in first (M), then
  mailbox, then the compromise and leaver views, which are mostly new verdicts over data
  already collected.
- Why this beats four tools: one connection to set up, one folder to learn, one consent
  prompt to get approved per client, and the compromise check runs on every M365 ticket
  instead of only when someone suspects it.

### Ship the ticket note before the front door, and make "could not look" part of it
`COMBINES` Ticket Note and Handoff Builder (manager), Shared case kit (architect), and the
front-door bold bets (manager "Start Here", architect "What's the problem?", newcomer
"Start a ticket", user "Look up this person"). It also `CHALLENGES` their sequencing.

- Pitch: Four lenses proposed a front door, and each one is an L that depends on new tools
  that don't exist yet. The owner's top request is not the menu but the note: "a handoff
  summary (checked, ruled out, evidence) and a ready-to-paste ticket note" (SIGNALS
  2026-10-16 [escalation]). So step one is the architect's case kit with one job: every tool
  that already returns the CheckId result shape (Network-QuickCheck, Citrix-FSLogix-Triage)
  and every case-folder tool (lockout, drive maps) writes the same four-part block, Checked /
  Ruled out / Could not check / Next step, plus the tool name, version, tenant or domain, tech
  and time. Step two is a thin menu over the four tools that already give verdicts. The other
  doors are added as each new tool from this session ships.
- Who and when: Every tech at the moment of escalating or closing. The lead reads the same
  four headings on every escalation, whoever the tech is, which is how "consistent answers no
  matter which tech picked up the ticket" becomes something you can see.
- The lead's additions:
  - **"Could not check" is a separate heading, not missing text.** On escalation, the most
    useful thing to know is what the tech did not manage to look at, because that is where the
    senior starts. The repo already has the gate logic (`Test-ADAuditPolicy`, drive-map
    evidence gates). The note just has to show its result.
  - **"Ruled out" comes from passed checks, not from the tech typing it.** The tech adds only
    two free-text lines: what the user reported, and what the tech tried by hand. Everything
    else comes from the tool runs, so the note can't overstate what was checked.
  - **The note links to the full report paths**, so the senior opens the evidence instead of
    re-running the tool.
- Evidence: SIGNALS 2026-10-16 [escalation] (all three core-problem entries). SIGNALS
  [reporting]: Michael spends time explaining reports to techs, and a fixed four-heading note
  cuts that down. Recon-code: SUMMARY.txt "for pasting into a ticket" exists only in the lockout
  orchestrator; CheckId contract exists in two tools; `ConvertTo-HtmlSafe` duplicated in six
  files (architect). `Run-AccessReport.bat` and `Start-LockoutWorkbench.ps1` show the
  plain-English menu works at small scale.
- Builds on: CheckId `-PassThru -Quiet`, SUMMARY.txt writers, SharedReferenceParity test
  pattern for the copied kit, Citrix-PerfTriage child-process runner for step two.
- Size guess: S-M for the note and kit across the existing verdict tools, M for the thin
  menu. The full front door stays the bold bet, but it grows out of these two steps instead
  of waiting for six new tools.
- A challenge for the critic: the workstation quick check (proposed by me, user and
  newcomer) has no SIGNALS entry. Two lenses said so themselves, and RMM tools often already
  show disk, uptime and pending reboots. Don't give it a front-door slot until the open
  question "rough ticket counts per area from ConnectWise" is answered. Every other door
  maps to a named ticket driver.

### Quarterly client risk review: catch next month's tickets and answer the insurer in one run
`COMBINES` NTLMv1/RC4 readiness (manager, market, security, architect), Server
End-of-Support register (manager, market), Client-data leftovers sweep (security)

- Pitch: A once-a-quarter run per client that answers three questions in one client-readable
  page and a CSV for the engineer. Which servers are out of support or will be soon, and what
  runs on them? Which accounts, devices and apps still use NTLMv1 or RC4 and will start
  failing to sign in as Microsoft's enforcement lands? And has our own toolkit left client
  data lying on their servers? Every finding ends with a decision: fix, exempt with a reason,
  retire, or delete.
- Who and when: The service-desk lead or account manager before a quarterly review or a
  cyber-insurance renewal ("do you run unsupported operating systems?", "is legacy
  authentication disabled?"). Also the senior engineer the week after Patch Tuesday.
- Why combine them: each one on its own is a report a senior runs now and then. Together
  they make a standing review the lead can schedule across the client base, and that review
  catches a recurring problem before the phone rings. RC4/NTLMv1 failures show up as "service
  account keeps locking out" and "scanner can't log in" tickets, which the lockout tools could
  misread (market round 1). The same scan also feeds lockout work: services and scheduled
  tasks running as domain accounts on old servers are a classic lockout source (market round 1).
- Evidence: recon-market "Recent moves": `BlockNTLMv1SSO` default moves to Enforce in October
  2026 (KB5066470); enhanced NTLM auditing 4020-4033 on Server 2019/2022 from 2026-10-13; RC4
  KDCSVC events 201-209 per the CVE-2026-20833 KB and Learn "Detect and remediate RC4"
  (market, security); KB numbers and the unset-attribute default conflict, so the
  tool must say "unknown" where the docs disagree (P-001). Server 2012/R2 ESU ended
  2026-10-13 and 2016 ends 2027-01-12 (secondary sources, verify on Learn lifecycle pages).
  Third parties charge $2,950 for an end-of-support assessment, and ADAudit Plus sells RC4
  reporting. SIGNALS 2026-10-14: Server 2012/R2 still turns up. These old servers are also the
  ones that can't write the new audit events, so "could not check" is a likely result there and
  has to be reported as such. SIGNALS [reporting]: turning output into something a client can read.
- The lead's requirements: the client page leads with counts and decisions, not raw events.
  It records the date and who ran it, so the next quarter can show "4 out-of-support servers
  in July, 1 now". That comparison is what a client or an insurer actually values. The
  leftovers sweep stays report-only in this view; deleting stays behind ShouldProcess in its
  own tool.
- Builds on: AD-Audit computer and OS enumeration; AD-LockoutDiagnostics multi-DC
  `Get-WinEvent`, audit gate and reference-data psd1 pattern; Hyper-V/VMware inventory for
  host context; the bundle manifest for known output-folder locations.
- Size guess: M (two engines exist; the new parts are the RC4/NTLM reference table, the
  lifecycle date table with citations, and the client page).
- Why now: the NTLMv1 enforcement date is this month and the 2012 ESU just ended, so every
  client needs this answer this quarter. If we run it first, it's planned work. If we don't,
  it arrives as a Monday full of tickets.
