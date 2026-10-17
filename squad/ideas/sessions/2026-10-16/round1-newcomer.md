# Round 1: the newcomer lens

Lens: first month on the service desk. I don't know which of 60 folders to open, and I don't
know what "AADSTS50053" or "0xC000006A" means. Focus: new tools the collection doesn't have yet.

What I noticed when I read the START HERE page (`ServiceDesk-Toolkit/README.md`) as a new tech:
- The table covers on-prem tickets well. Then the "Can't sign in" section says a user who
  can sign in to their PC but not to Microsoft 365 "needs a cloud-side check (MFA,
  Conditional Access, cloud password)", and no tool does that check. For the ticket a new
  tech gets most often, the page sends them out of the toolkit and into the Entra portal.
- Every row in the table assumes I already know which kind of problem I have. Tickets don't
  arrive that way. They arrive as "Outlook keeps asking for my password", "my PC is slow", or
  a raw error code.
- There is no row for the user's own PC, the mailbox, AVD, or "is this leaver fully done?".
  Those are the tickets a new tech gets first.

---

### "Can this user sign in to Microsoft 365?" (the cloud twin of AD-UserQuickCheck)
- Pitch: Type a user's email address and get YES / NO / PROBABLY NOT for Microsoft 365
  sign-in, with the reason in plain English: blocked in Entra, locked by smart lockout, wrong
  password, blocked by a Conditional Access policy, MFA not set up, no licence, or the account
  isn't syncing. It reads their last few sign-in attempts and turns each error code into a
  sentence and a next step.
- Who and when: A tier-1 tech with a user on the phone saying "Outlook / Teams keeps asking
  for my password". AD-UserQuickCheck says the on-prem account is fine, and the tech is stuck.
- Evidence: SIGNALS 2026-10-16 [entra][m365] says these tickets "usually take longer than the
  others", and 2026-10-16 "Where techs leave the tools" lists the Entra admin center and
  sign-in logs. `ServiceDesk-Toolkit/README.md` "Can't sign in" sends this case out of the
  toolkit. Recon-code: no per-user cloud sign-in lookup exists; only Get-M365SecurityEvidence
  calls `auditLogs/signIns`, and that is for audits. Recon-market: Microsoft's Sign-in
  diagnostic is portal-only ("no CLI found"). Graph `GET /auditLogs/signIns` needs
  `AuditLog.Read.All` and a role such as Global Reader or Reports Reader. Applied CA policy
  names show up only with a role that can read CA data, such as Global Reader or Security
  Reader (https://learn.microsoft.com/graph/api/signin-list). Unverified: Microsoft's licence
  requirement for reading sign-ins through the API (believed to be Entra ID P1) and the
  retention period. The tool must detect this and report "couldn't look" rather than "no
  failures" (P-001).
- Builds on: AD-UserQuickCheck's verdict and "What to do" shape; Get-M365SecurityEvidence's
  Graph REST calls through `Invoke-MgGraphRequest` (only Microsoft.Graph.Authentication is
  needed); Get-EntraPasswordPolicy's per-user password expiry; the Network-QuickCheck result
  contract (`CheckId`, `Status`, `Evidence`, `RecommendedNextSteps`).
- Size guess: M
- Why now / why us: The START HERE page already promises this check and sends people
  elsewhere for it. The pieces exist in three folders. Every AADSTS code shown must be checked
  against the Learn error-code reference, which this repo already does as standard practice.

### "What does this error mean?": an offline error-code decoder
- Pitch: Paste any error code or message from a ticket, screenshot or event log (an AADSTS
  number, a 0xC000… status, a Kerberos code, an FSLogix error, an event ID). It returns what
  the code means in plain English, whether it signals a real failure, and which tool in the
  bundle to run next. It works with no network and changes nothing.
- Who and when: The first five minutes of a ticket. The user sent a screenshot with
  "0xC000006A", "AADSTS50126" or "FSLogix error 0x0000001F", and the new tech doesn't know
  whether that's a password, a network or a profile problem, so they can't choose a tool.
- Evidence: SIGNALS 2026-10-16 [bundle] says techs "don't know which tools exist or when to
  use each one", and [escalation] says techs escalate "because they don't know how to resolve
  the issue". CLAUDE.md lists confusing status codes as a known bug source: 4776 `0x0` is
  success, not failure, and 4625 SubStatus vs Status. Recon-market pain 11: FSLogix event IDs
  26 and 41 are asked about separately, and Microsoft says event 26 on Entra-only devices can
  be ignored. A decoder that says "harmless, ignore" is as valuable as one that says "this is
  the cause". Recon-market: FSLogixDoctor's main pitch is decoding FSLogix codes into plain
  English, so the demand is real.
- Builds on: `AD-LockoutDiagnostics/LockoutReference.psd1` (event IDs and status codes,
  already cited), `DriveMap-Diagnostics/DriveMapReference.psd1`, and the parity test pattern
  in `SharedReferenceParity.Tests.ps1`. Each entry adds a "run this tool next" pointer at
  bundle rows.
- Size guess: S to start (lockout, Kerberos and NTLM codes already exist), M when it covers
  FSLogix, AADSTS and Citrix.
- Why now / why us: The repo has already done the hardest part, which is verified, cited code
  meanings, but they are locked inside two tools. Every entry carries its Learn URL, so a
  senior can check it. Runs on PS 3.0.

### "Is this PC OK?": a quick check of the user's own workstation
- Pitch: Point it at the user's computer (or run it on that computer) and get a one-screen
  verdict: free disk space, days since the last restart and any restart pending, last Windows
  Update install, domain trust (secure channel) and clock sync, profile size, Outlook
  OST/PST size, and stuck print jobs. Each problem comes with a "What to do".
- Who and when: The "my computer is slow / weird / Outlook won't open" ticket that every new
  tech gets on day one, before they know what to look at. Today they open Task Manager and
  guess.
- Evidence: Recon-code "Gaps": "No tool for: workstation/endpoint health on a user's PC (disk,
  updates, startup, profile size, Outlook/OST, printers beyond defaults…). Only
  Entra-DeviceActivityTimeline and Network-QuickCheck run on an endpoint." SIGNALS has no
  workstation entry, so this rests on the gap and my lens rather than an owner signal. Weight
  it accordingly and ask Michael how many tickets are endpoint tickets (SIGNALS open question
  "Which area is really the largest?").
- Builds on: Network-QuickCheck's endpoint-friendly PS 3.0 design and result contract;
  Citrix-FSLogix-HealthCollector's CIM sampling with DCOM fallback; the pending-updates check
  inside `CitrixVDADiagnostics`; DC-Diagnostics' secure-channel and w32tm checks.
- Size guess: M
- Why now / why us: The collection already has the remote-CIM, verdict and fallback patterns
  for servers. Pointing them at a desktop gives new techs a first move on the most common,
  least specialised ticket.

### "Why can't they get their email / see that mailbox?": mailbox quick check
- Pitch: Give it a mailbox and it answers the common mailbox questions in plain English: does
  the mailbox exist and what type is it, who has Full Access / Send As on it, is mail being
  forwarded or redirected by an inbox rule (and to an outside address?), is it near its size
  limit, and did a test message arrive (message trace). Read-only.
- Who and when: "I can't see the shared mailbox", "emails aren't arriving", "my mail is going
  somewhere weird". A new tech today has to learn the Exchange admin center layout with the
  client on hold.
- Evidence: SIGNALS 2026-10-16 [m365] "mailbox" is listed as a time sink and takes longer;
  "Where techs leave the tools" names the Exchange admin center. Recon-code: grep for
  `Get-Mailbox` / `Get-MessageTrace` found nothing; Exchange appears only as a mailbox-type
  check in Get-M365SecurityEvidence. Recon-market pain 14: no source found for mailbox
  permission pain, so the owner signal is the only support.
- Builds on: Get-M365SecurityEvidence's optional ExchangeOnlineManagement connection; the
  verdict-first report renderers.
- Size guess: M (Exchange cmdlet parameters and message-trace behaviour must be checked on
  Learn; the message-trace cmdlets have changed recently and need verifying, not guessing).
- Why now / why us: External forwarding rules are also a sign that an account has been
  compromised, so the same check catches something a new tech would never think to look
  for.

### "Why isn't this user syncing to Microsoft 365?": one-user Entra Connect check
- Pitch: Name one AD user. It checks the usual reasons they're missing or stale in Microsoft
  365: is their OU in sync scope, does another object in AD already use their UPN or email
  address, is any attribute invalid, did the last sync run, and does Entra Connect show an
  error for this object. It ends with a plain verdict ("this user is outside the synced OUs;
  move them or ask a senior to widen the scope").
- Who and when: New starter created in AD this morning, still no mailbox or licence by
  lunchtime. Also "I changed their surname/mobile in AD and 365 still shows the old one".
- Evidence: Recon-market pain 13: "accounts silently not syncing while health looks green",
  with several Microsoft Q&A threads; causes include OU/attribute filtering, quarantined
  attributes, users moved OU, and DirSyncOverrides. Microsoft's own troubleshooting lists UPN
  mismatch and OU filtering checks and points to IdFix for duplicate UPN/proxy addresses
  (tshoot-connect-objectsync). SIGNALS 2026-10-16: most clients are hybrid; [entra] tickets
  take longer.
- Builds on: `AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1` (connects to the Entra
  Connect server and checks its service and events); M365-SyncedUserFixes' existing reading of
  Entra Connect sync rules; the AD module everywhere.
- Size guess: M
- Why now / why us: The repo already reaches into Entra Connect in two places. A single-user,
  read-only check is the safe slice; changing sync scope stays with seniors.

### "Is this leaver fully done?": offboarding checker (read-only)
- Pitch: Name a leaver and get a checklist marked done / not done: AD account disabled, groups
  removed, Microsoft 365 sign-in blocked, sessions revoked recently, licences removed or kept
  on purpose, mailbox converted or forwarded, still a member of admin roles, still on local
  admin groups. It changes nothing; it shows what was missed.
- Who and when: Leaver tickets are given to new techs because they look routine. A missed step
  becomes a security finding months later, and the tech can't tell whether they finished.
- Evidence: `ServiceDesk-Toolkit/README.md` already lists "offboarding check" under the access
  report and "leavers on their last day" under Block M365, yet notes that "Disabled accounts
  are left out" of the access report. So a disabled leaver's leftover groups can't be seen
  there. SIGNALS [escalation]: Michael wants to see what was checked. A checklist with
  evidence is exactly that for this ticket type.
- Builds on: AD-GroupMembership-Export, Find-PrivilegedAccessPaths (admin paths),
  M365-SyncedUserFixes (block state, change log), Get-M365SecurityEvidence (Graph roles).
- Size guess: M
- Why now / why us: Every piece it reads is already read by some tool. What's missing is one
  answer to "did I finish this?".

### "Which session host is this AVD user on, and is it healthy?": AVD quick check
- Pitch: Give it a user and it finds their Azure Virtual Desktop session and host pool. It
  then reports in plain English whether the host is available, draining, or failing its health
  checks, and points to Citrix-FSLogix-Triage for that host. The AVD equivalent of looking the
  user up in Citrix Director.
- Who and when: "My desktop won't load" at a client on AVD. The new tech doesn't know the
  Azure portal blade path and doesn't know which host to triage.
- Evidence: SIGNALS 2026-10-16 [avd] is a ticket driver and takes longer; "Where techs leave
  the tools" names "the Azure portal for session hosts". Clients run Citrix, AVD and RDS mixed.
  Recon-code: no AVD diagnostics exist; the bundle's DriveMap row tells Citrix users to "look
  it up in Citrix Director or Studio" but has no AVD equivalent.
- Builds on: Get-AzureFilesFSLogixProfiles (already signs in to Azure with Az); Citrix-FSLogix-Triage
  for the follow-up on the host.
- Size guess: M (needs the Az.DesktopVirtualization module: P-003 "no installs" tension, same
  as the existing Az.Storage tool; health-check names verified on Learn).
- Why now / why us: It completes the platform set. A new tech at an AVD client currently has
  no starting tool in the bundle at all.

### Bold bet: "Start a ticket": one front door that asks the questions and writes the note
- Pitch: Double-click one launcher, answer three plain questions (who, which computer, what's
  wrong, picked from the same symptoms as the START HERE table), and it runs the right
  read-only checks in order. It then writes a ConnectWise-ready note: what was checked, what
  was ruled out, the verdict, and the next step. Sysadmins can skip the questions with
  parameters (`-Identity -ComputerName -Symptom`) and get the same note.
- Who and when: Every ticket a new tech opens in their first months. It also covers the
  moment they escalate: Michael gets the note instead of "it's still broken".
- Evidence: SIGNALS 2026-10-16 core problem (three owner entries): techs escalate because they
  don't know how to resolve; Michael wants "what they checked, how they ruled things out";
  the most useful output is "a handoff summary … and a ready-to-paste ticket note".
  [bundle]: techs don't know which tool to run; output is too technical. Recon-code: nothing
  captures what the tech checked. Network-QuickCheck and Citrix-FSLogix-Triage already return
  a shared result shape via `-PassThru -Quiet`. Citrix-PerfTriage already runs sibling tools
  as child processes with time limits.
- Builds on: the result-object contract (engine 1), `-LoadFunctionsOnly` cores (engine 2),
  PerfTriage's child-process orchestration (engine 7), and the bundle's folder layout (engine
  9; it must find siblings the way `Resolve-CompanionScript` does). Output stays a local text
  file to paste, with no ConnectWise API (PRINCIPLES "no cloud backend").
- Size guess: L (each tool it calls must emit the shared result shape; start with three:
  UserQuickCheck, Network-QuickCheck, FSLogix triage).
- Why now / why us: The bundle is new and techs don't have the habit yet (SIGNALS [bundle]).
  The cheapest moment to make one launcher the habit is before they learn twelve separate
  commands. It hides nothing: every underlying tool and its full report stays where it is,
  and the note links to them.
