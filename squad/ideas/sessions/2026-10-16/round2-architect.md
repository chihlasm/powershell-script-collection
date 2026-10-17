# Round 2: architect lens (cross-pollination)

What I see after reading all six lists: the lenses agree on *what* to build. Cloud sign-in,
mailbox, one-user sync, NTLM/RC4, a front door and a handoff note each appear in 4 to 6 lists.
They disagree only on packaging. Built as the separate tools proposed, that becomes about 14
new folders, five of them opening their own Microsoft Graph or Exchange Online connections
and four of them writing their own "what was checked" note. My three entries are about the
seams that make that cluster cheap and consistent.

Concession first: the market analyst's AVD host check (host-local, `-ComputerName`, registry
`RDInfraAgent\IsRegistered`, RDAgentBootLoader, no Az module) beats my round-1 Az-based
version on P-003. Build that one first. The Az host-pool view can come later, as an optional
add-on.

Code facts I checked with grep this round:
- The CheckId result shape exists in only two tools (`Network-QuickCheck`, `Citrix-FSLogix-Triage`).
- `AD-UserQuickCheck` has no `-PassThru` at all, so the best verdict in the bundle cannot be
  read by any other tool today.
- `Connect-MgGraph` / `Connect-ExchangeOnline` appear in only `Get-M365SecurityEvidence.ps1`
  and `Get-EntraPasswordPolicy.ps1`.
- `LockoutReference.psd1` is already split into `EventMeaning`, `StatusCodes`, `LogonTypes`
  and `PolicyGuidance` tables.

---

### Ticket folder + playbooks: one engine behind the front door, the person lookup, the handoff note, the leaver check and the compromise check
- Marked: COMBINES "Start Here / What's the problem? / Start a ticket" front door (manager,
  newcomer, architect), "Look up this person" (user-in-the-moment), "Ticket Note and Handoff
  Builder" (manager), "Leaver / offboarding verification" (security, newcomer),
  "Compromised-account first look" (security)
- Pitch: Every quick check writes its result in one common shape into a ticket folder the tech
  names once (for example the ConnectWise ticket number). The handoff note is then just a
  reader of that folder: "checked / ruled out / found / next step", ready to paste. The
  front door, the person lookup, the leaver check and the compromise check stop being four
  big new tools. Each becomes a *playbook*: a short data file listing which checks to run, in
  what order, and with what inputs.
- Who and when: Every tech, every ticket. Michael gets the same note shape on every
  escalation, whichever tools the tech ran and in whatever order. That includes runs made by
  hand, outside the front door.
- Evidence: SIGNALS 2026-10-16 [escalation]: the owner's top outputs are a handoff summary
  and a pasteable ConnectWise note, and "what they checked and how they ruled things out" is
  not captured. Recon-code: nothing records what was checked. CheckId exists in 2 files.
  AD-UserQuickCheck has no `-PassThru` (grep). The leaver and compromise ideas (security,
  newcomer) already list the same underlying reads as the cloud sign-in, mailbox and
  AD-UserQuickCheck ideas, so as stand-alone L tools they would mostly duplicate those checks.
- Builds on: the CheckId contract (`Network-QuickCheck/Invoke-NetworkQuickCheck.ps1`), PerfTriage's
  child-process runner with time limits, `Resolve-CompanionScript` for finding sibling tools,
  `Run-AccessReport.bat` for the double-click menu, and the case kit from my round 1 (the
  `Write-TicketResult` and note writer live there).
- Build order (each step ships value on its own):
  1. Add `-PassThru` and ticket-folder output to AD-UserQuickCheck, DriveMap and Lockout
     (S each).
  2. Build the handoff note builder, which reads the folder (S).
  3. Add playbooks as `.psd1` data files with a schema test. "Leaver" and "possible
     compromise" become about 30 lines of data each, once the checks exist (S each).
  4. Build the front-door menu that picks a playbook from the symptom (M).
- Size guess: M in total, against roughly 3 L if built as separate tools.
- Why now / why us: Every new tool this session would otherwise invent its own summary. If
  the contract and folder come first, each new check plugs into the note, the menu and every
  playbook for free. If they come last, about ten tools have to be retrofitted. The design is
  local-only: a text file and the clipboard, with no PSA API, so PRINCIPLES are respected.
  The bundle guarantees the sibling folders exist, so the self-contained rule holds.

### One M365 user core with a "what can I see in this tenant?" gate
- Marked: COMBINES "Cloud sign-in check" (all six lenses), "Mailbox quick check" (five
  lenses), "Why isn't this user syncing" (cloud half: `onPremisesProvisioningErrors`, market
  analyst), "Compromised-account first look" (security)
- Pitch: Build one folder (working name `M365-UserCheck`) with a core file, the way
  M365-SyncedUserFixes splits `SyncedUserFixes.Core.ps1` from its UI. The core signs in once,
  prints which tenant and admin it is using (the security lens's wrong-client guard), and then
  probes what it is able to see. Is there an Entra ID P1 licence for sign-in logs? Was
  AuditLog.Read.All consented? Can the role read Conditional Access details? Is Exchange
  Online connected? Is the tenant sovereign, where the message-trace cmdlets differ? The
  sign-in, mailbox and compromise checks are thin verdict layers over that core, and each
  one reads the gate to say "could not look because X" instead of "nothing found".
- Who and when: The tier-1 tech on "Outlook keeps asking for my password" or "I'm not getting
  mail". They run one script with one sign-in, rather than three tools that each prompt for
  consent.
- Evidence: All six lenses proposed cloud sign-in, and five proposed mailbox. Lenses
  independently flag the same traps: the P1 licence for the sign-in log through Graph (market
  analyst cites the Learn signIn resource and the premium-licence troubleshooting page),
  missing CA detail without the right role (user-in-the-moment, newcomer cite signin-list),
  consent and scope errors that confuse techs (security, market pain 5), and the move from
  Get-MessageTrace to V2 (market analyst cites Learn). If each tool handles these
  separately, four tools must get them right four times. Graph connection code lives in only
  2 scripts today (grep), so there is no shared helper to reuse yet.
- Builds on: the Graph REST plumbing via `Invoke-MgGraphRequest` in `Get-M365SecurityEvidence`
  (Microsoft.Graph.Authentication only, signIns call at line 1080), the optional EXO connection
  at line 557, per-user expiry and Smart Lockout from `Get-EntraPasswordPolicy`, the core/UI
  split in M365-SyncedUserFixes, and the evidence-gate pattern from `Test-ADAuditPolicy.ps1`
  (the tenant gate is the cloud version of "is auditing even on?").
- Size guess: M for the core, the gate and the sign-in verdict. Then mailbox is S to M, and the
  compromise playbook is S (sign-ins + inbox rules and forwarding + recently added auth
  methods + OAuth grants, run through the playbook engine above).
- Why now / why us: This is the biggest coverage gap, and every lens sees it. Building it as
  four tools would repeat the Graph-auth sprawl the consolidation rounds (PRs #11 to #16) just
  spent effort removing. PS 5.1 is a legitimate floor here (root CLAUDE.md), and the sync
  check's on-prem half stays its own read-only script on the Connect server, reusing the
  ADSync reads in `SyncedUserFixes.Core.ps1`.

### Cited code tables as shared data: the error decoder comes free with the tools that need tables anyway
- Marked: BUILDS ON "What does this error mean? offline error-code decoder" (newcomer);
  COMBINES with the NTLMv1/RC4 readiness check (four lenses), the cloud sign-in check and the
  FSLogix temp-profile orchestrator
- Pitch: Three of this session's strongest tools can't be built without a cited table of codes
  first: AADSTS sign-in errors (cloud sign-in), KDCSVC 201-209 and NTLM 4020-4033 (RC4/NTLM
  readiness), and FSLogix error codes and event IDs (temp profile). Write each table once, as a
  `.psd1` data file shaped like `LockoutReference.psd1`. Every entry gets a Learn URL, a
  "real failure or harmless?" flag and a "run this tool next" pointer. The owning tool and the
  decoder each ship a copy, and a parity test catches drift. The newcomer's decoder is then
  just a lookup over files that already exist, so it costs S rather than M.
- Who and when: The new tech with "AADSTS50126" or "0xC000006A" in a screenshot, and no idea
  which tool to open. It is also used behind the scenes by every verdict engine that has to
  turn a code into a sentence.
- Evidence: The tables exist today in only two files (`LockoutReference.psd1`,
  `DriveMapReference.psd1`), and the parity test (`SharedReferenceParity.Tests.ps1`) already
  enforces the copy-per-folder model. The lenses cite the documented traps a table must encode:
  4776 `0x0` means success (root CLAUDE.md), FSLogix event 26 can be ignored on Entra-only
  devices (recon-market pain 11), and the RC4 unset-attribute default is contradicted in Q&A
  (security lens), so "unknown" must be a first-class value. FSLogixDoctor sells "decode
  FSLogix codes" as its main pitch (newcomer, recon-market).
- Builds on: the `LockoutReference.psd1` layout (`EventMeaning` / `StatusCodes` /
  `PolicyGuidance`), the parity test pattern, and the bundle builder manifest (copy the tables
  in at build time).
- Size guess: S for the schema, parity test and decoder over the existing two tables. Each new
  table is part of the tool that needs it, not extra work.
- Why now / why us: P-001 is the reason this repo is trusted, and its costliest step is
  verifying codes on Learn. Doing that once per code, storing it as data and reusing it
  across a tool, the decoder and the handoff note's wording is the cheapest way to keep every
  new tool accurate. Being able to say "harmless, ignore this" is as valuable to a new tech as
  finding the real cause.
