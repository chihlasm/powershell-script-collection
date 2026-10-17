# Longlist, session 2026-10-16

Focus: "useful tools that we may not have currently".
Inputs: recon-code.md, recon-market.md, round1-* and round2-* from all six lenses
(user-in-the-moment, manager-or-buyer, architect, newcomer, security, market-analyst),
PRINCIPLES.md, SIGNALS.md, GRAVEYARD.md.

Backlog (`squad/BACKLOG.md`) and graveyard are both empty, so nothing was dropped for repeating
them. 15 ideas after merging. They are ordered roughly from strongest support to weakest. This is
not a score; scoring happens after the critic.

Lens abbreviations: **U** user-in-the-moment, **M** manager-or-buyer, **A** architect,
**N** newcomer, **S** security, **K** market-analyst. "r1" and "r2" mean round 1 and round 2.

## How round 2 reshaped round 1

- **Packaging, not content, was the disagreement.** Every lens agreed on the core list. Round 2
  (U, M, A, N, S, K) argued that shipping it as about 14 separate folders would repeat the
  "which tool do I run?" problem that PRs #11-#16 just cleaned up (SIGNALS [bundle],
  repo-history). The merges below follow that consensus.
- **The one-user sync check was folded into I-01.** U-r2 and A-r2 showed that
  `onPremisesSyncEnabled`, `onPremisesLastSyncDateTime` and `onPremisesProvisioningErrors` come
  from the same Graph user read. Only the "OU in scope / which rule filtered them" question needs
  the Entra Connect server, so that part becomes an optional stage of I-01.
- **The compromise first look was folded into the mailbox check (I-02).** U-r2, N-r2, S-r2 and
  K-r2 each made this merge on their own: a tier-1 tech picks the mailbox tool, never a
  "compromise" tool.
- **"Look up this person" and the four front doors became one idea (I-04).** The lenses still
  disagree on whether it should be keyed on the person or on the symptom (see I-04).
- **Leaver verification stays its own idea (I-10)**, but every r2 lens that touched it wants it
  built as a mode or playbook over I-01, I-02 and AD-UserQuickCheck, not as a new standalone
  check.
- **Corrected market claim:** K-r2 found that Microsoft links two free MIT scripts for RC4
  detection, so I-06's value is the domain-wide verdict, not detection itself.
- **Lenses considered and dropped these themselves:** printer diagnostics, certificate expiry,
  and an AD security scanner (K-r1: no demand source; PingCastle, Purple Knight, Testimo and
  AD-Audit already cover the scanner).

---

## I-01 · M365 user check: "Can this user sign in to Microsoft 365, and is it a sync problem?"

- **Sources:** cloud sign-in check from all six lenses in r1 (U, M, A, N, S, K). One-user sync
  check from U, M, A, N, K in r1. U-r2 combined the two. A-r2 added the "one core plus tenant
  gate" design. M-r2 proposed the "one cloud user case" packaging (shared with I-02 and I-10).
- **Pitch:** This is the cloud version of AD-UserQuickCheck. You enter one name and get YES /
  NO / PROBABLY NOT for M365, with the reason and a "What to do" line. The reasons it covers:
  sign-in blocked, Conditional Access failure, no MFA method, smart lockout, risky user, no
  licence, and decoded sign-in failures. When the cause is on the sync side ("never synced",
  "cloud copy three days stale", "another object holds this address"), the same run says so.
  Stages:
  1. Graph only.
  2. Automatic comparison with AD when RSAT is present.
  3. Entra Connect server look (OU scope, filtering rule, scheduler or staging state), only
     when stages 1-2 point at sync and the server can be reached.
- **Design points the lenses agreed on:**
  - A tenant and admin banner at the top, so nobody runs it against the wrong client (S, M-r2).
  - A "what can I see in this tenant?" gate covering the P1 licence for sign-in logs,
    AuditLog.Read.All consent, the role needed for CA detail, and Exchange connection or
    sovereign-cloud status (A-r2).
  - "Could not look" is never reported as "nothing found" (P-001).
  - Read-only, with the least-privilege role stated up front (S).
- **Evidence:**
  - SIGNALS 2026-10-16 [entra][m365]: these tickets are the slowest, and techs work them by hand
    in the admin centers and sign-in logs.
  - Client facts: most clients are hybrid.
  - `ServiceDesk-Toolkit/README.md` "Can't sign in" sends this case to the portal (N-r1).
  - Recon-code: there is no per-user cloud sign-in lookup anywhere.
  - Recon-market: Entra Sign-in diagnostic is portal-only. Recon-market pain 13: sync shows
    healthy while users are missing.
  - Learn sources:
    - signIn list needs AuditLog.Read.All plus a reader role; CA detail needs a role that can
      read CA ([signin-list](https://learn.microsoft.com/graph/api/signin-list)).
    - Sign-in logs need P1/P2 ([signIn resource](https://learn.microsoft.com/graph/api/resources/signin?view=graph-rest-1.0),
      [premium-licence troubleshooting](https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities)).
    - The user resource covers the sync fields and `signInActivity`
      ([user](https://learn.microsoft.com/graph/api/resources/user?view=graph-rest-1.0)).
    - Microsoft's object-sync troubleshooting ([tshoot-connect-objectsync](https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-objectsync)).
  - MSOnline's `Get-MsolUser -HasErrorsOnly` was retired with no replacement (K-r1).
- **Builds on:**
  - `Get-M365SecurityEvidence.ps1`: per-user signIns at line 1080, CA calls,
    `Invoke-MgGraphRequest` with only Microsoft.Graph.Authentication.
  - `Get-EntraPasswordPolicy`: per-user expiry and smart lockout.
  - AD-UserQuickCheck: verdict wording and AD lookups.
  - `SyncedUserFixes.Core.ps1:654,711,931`: `Get-ADSyncRule` / `Get-ADSyncConnector`.
  - `Test-EntraConnectReadiness.ps1:149`: scheduler and staging check.
  - Core/UI split pattern from M365-SyncedUserFixes.
  - CheckId contract.
- **Size:** M for the core, the gate and the sign-in verdict. Stage 3 can follow in a second
  release. PS 5.1 is a legitimate floor here because the tool needs Graph.
- **Open for the critic:**
  - The AADSTS table must be cited on Learn (see I-05).
  - A staging Connect server must give "can't tell", not "out of scope".
  - Should this be one folder with I-02 (M-r2, A-r2) or two?

## I-02 · Mailbox check that puts signs of a takeover first

- **Sources:** mailbox quick check from U, M, A, N, K in r1. Compromised-account first look from
  S-r1. U-r2, N-r2, S-r2 and K-r2 each combined the two. M-r2 included both in "one cloud user
  case".
- **Pitch:** You enter one mailbox and get one read-only report covering:
  - who has Full Access, Send As or Send on Behalf
  - forwarding, and inbox rules that move, delete or mark mail as read
  - size, archive and hold
  - whether it is a shared mailbox
  - a recent message trace

  Every run checks for takeover signs first: external forwarding, rules that hide mail, rules or
  delegates added recently, newly added MFA methods, app consents, and unusual sign-ins when
  Graph and P1 are available. If any are found, the first line becomes "Possible account
  takeover: do NOT reset the password or delete the rule yet. Escalate." The `-CaptureEvidence`
  switch saves a hashed evidence folder.
- **Guardrails from S:**
  - No remediation switches at all.
  - The report shows rule conditions and actions only, never message bodies. Trace output is
    limited to sender, recipient, time and status.
  - The tenant and admin are printed in the header.
  - Missing roles or licences give "partly checked: rules yes, sign-ins could not look", never
    "no signs of takeover".
- **Evidence:**
  - SIGNALS 2026-10-16 [m365]: mailbox tickets are slow and worked by hand in the EAC.
  - Recon-code: no `Get-Mailbox`, `Get-InboxRule` or message trace anywhere in the repo.
  - S-r1: resetting first destroys evidence. M-r1: an external forwarding rule is the evidence
    an insurer asks for.
  - K-r1 and K-r2: `Get-MessageTrace` is deprecated in favour of `Get-MessageTraceV2` from
    2025-09-01 for worldwide tenants, so community scripts are breaking
    ([Get-MessageTrace](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetrace)).
  - K-r2 market check:
    - Hawk is free but collection-only, with no verdict. It needs about nine module installs,
      including the PSAppInsights telemetry library, which conflicts with P-003 and the
      no-telemetry rule ([HAWK](https://www.powershellgallery.com/packages/HAWK)).
    - BEC verdicts are otherwise sold as paid services or SaaS (Kroll, RocketCyber), and CIPP is
      hosted.
  - Recon-market pain 14: there is no external source for mailbox-permission pain, so demand
    rests on the owner's signal.
- **Builds on:**
  - `Connect-ExchangeOnline` handling in `Get-M365SecurityEvidence.ps1:557` and its Graph
    signIns call.
  - The zip plus SHA-256 pattern in `Entra-DeviceActivityTimeline`.
  - The I-01 core (one sign-in, one tenant gate).
  - CheckId contract.
- **Size:** M (one tool replaces two Ms).
- **Open for the critic:**
  - Whether `Get-InboxRule` and `Get-MessageTraceV2` work under a view-only Exchange role is
    unverified (S-r2).
  - The sign-in-based takeover signs need P1.

## I-03 · Ticket note in every tool: "Checked / Ruled out / Could not check / Next step"

- **Sources:** Ticket Note and Handoff Builder (M-r1), Shared case kit (A-r1). U-r2 challenged the
  order: notes first, launcher later. M-r2 made "could not check" its own heading and said
  "ruled out" should come from passed checks. A-r2 added the ticket-folder contract and the
  `-PassThru` gap. S-r2 added a header stamp, a case manifest and paste-safe mode.
- **Pitch:**
  - Every quick check ends by writing the same four-part block to a text file and the clipboard,
    ready to paste into ConnectWise. The parts are Checked, Ruled out (taken from passed checks,
    not typed by the tech), Could not check (the gate results), and Next step. Each note includes
    the evidence paths.
  - An optional `-TicketNumber` collects every tool's note into one ticket folder. A small
    joiner then merges them, adding only two free-text lines: what the user reported and what the
    tech tried by hand.
  - It ships as a copied `CaseKit.ps1` with a parity test. The kit holds `New-TicketNote`, the
    result writer, HTML-safe encoding and the report shell.
  - Every note gets a stamp: tenant or domain, the account that ran it, the machine, the time,
    and "Changed anything: No/Yes".
  - Paste-safe mode leaves out raw IPs, rule contents and profile paths, because ConnectWise is
    readable MSP-wide and sometimes by the client.
  - First slice: AD-UserQuickCheck (which also needs `-PassThru`), Network-QuickCheck and
    Citrix-FSLogix-Triage, then Lockout and DriveMap.
- **Evidence:**
  - SIGNALS 2026-10-16 [escalation]: all three core-problem entries ask for a handoff summary and
    a pasteable ConnectWise note, and say the reasoning is not captured today.
  - SIGNALS [reporting]: Michael spends time explaining reports to techs.
  - Recon-code:
    - Only the lockout orchestrator writes a SUMMARY.txt "for pasting into a ticket".
    - The CheckId shape exists in only 2 tools, and AD-UserQuickCheck has no `-PassThru` (A-r2
      grep).
    - `ConvertTo-HtmlSafe` is redefined in 6-8 files.
    - The parity-test precedent is `SharedReferenceParity.Tests.ps1`.
  - PRINCIPLES: the note is a local file and clipboard, with no PSA API.
- **Size:** S-M across the existing verdict tools, plus S for the joiner.
- **Open for the critic:**
  - `Set-Clipboard` needs PS 5.0. Tools with a 3.0 floor need a `clip.exe` fallback, whose
    behaviour and encoding are unverified. The text file is the guaranteed output.
  - A shared kit must still respect the self-contained-folder rule.

## I-04 · Front door: one launcher that runs the right checks and writes the handoff

- **Sources:**
  - r1: "Start Here" (M), "What's the problem?" (A), "Start a ticket" (N), "Look up this person"
    (U).
  - r2: A-r2 proposed playbooks as `.psd1` data over a ticket folder (leaver and compromise
    become playbooks). N-r2 proposed honest doors with recorded manual steps for symptoms that
    have no tool yet. U-r2 challenged the design: key it on the person, not a symptom menu, and
    build it after I-03.
- **Pitch:** The tech double-clicks one launcher and answers a few plain questions. It runs the
  right read-only checks and leaves a ticket folder with the I-03 note. Where no tool exists yet
  (cloud sign-in, mailbox, AVD, "PC is slow"), it shows a one- or two-line manual portal step,
  asks what the tech found, and records the answer in the note as "checked by hand" (N-r2).
  Seniors can skip the questions with `-Identity -ComputerName -Symptom`. Playbooks are short
  data files listing the checks, so each new tool plugs in without code changes (A-r2).
- **Evidence:**
  - SIGNALS [bundle]: techs don't know which tools exist or when to use them, the output is too
    technical, and the bundle isn't a habit yet. Michael runs most tools himself.
  - Repo-history: consolidation happened because it was unclear which tool to run.
  - SIGNALS [escalation]: the core-problem entries.
  - The pattern already works at small scale: `Run-AccessReport.bat` and
    `Start-LockoutWorkbench.ps1`.
  - The orchestration mechanism exists in `Citrix-PerfTriage` (child processes with time limits).
- **Unresolved conflict between lenses:**
  - U-r2 wants it keyed on the person: the tech always knows who is calling but can't classify
    the symptom, so run the cheap checks in parallel.
  - N-r2 wants it keyed on the symptom: a combined "most likely problem" across six systems is
    the confident wrong answer P-001 forbids.
  - M-r2 says the workstation door should get no slot until ticket counts exist.
- **Size:** M for the first cut over four existing tools plus manual steps (N-r2, A-r2). L for
  the full vision.
- **Depends on:** I-03.

## I-05 · Cited code tables, plus an offline "what does this error mean?" lookup

- **Sources:** error-code decoder (N-r1). A-r2 combined it with the RC4/NTLM, cloud sign-in and
  FSLogix tables. N-r2 made it the single source for verdict wording.
- **Pitch:**
  - Write each code table once as a `.psd1` shaped like `LockoutReference.psd1`. Tables:
    - AADSTS sign-in errors
    - NTLM and Kerberos status codes
    - KDCSVC 201-209 and NTLM 4020-4033
    - FSLogix error codes and event IDs
  - Every entry has a Learn URL, a plain-English meaning, a "real failure or harmless?" flag
    ("unknown" is a valid value), a next step and the bundle tool to run.
  - The owning tools read their verdict wording from these tables, and each ships a copy with a
    parity test.
  - A small lookup lets a tech paste a code from a screenshot and get the same sentence. It works
    offline on PS 3.0.
- **Evidence:**
  - SIGNALS [bundle]: output needs interpreting. [escalation]: techs don't know how to resolve.
    Repo-history: trust breakers all came from wrong meanings (4776 `0x0`, audit-policy wording).
  - Recon-market pain 11: FSLogix event 26 on Entra-only devices is harmless per Learn, so a
    "harmless" verdict has value.
  - FSLogixDoctor's main pitch is decoding codes (recon-market).
  - Only two tables exist today. The parity test already enforces copying a table into each
    folder.
- **Size:** S for the schema, parity test and lookup, seeded from the lockout codes. New tables
  are built as part of the tools that need them (I-01, I-06, I-08).
- **Order note (N-r2):** this has to come before I-01, or the AADSTS meanings get hard-coded into
  I-01.

## I-06 · RC4 / NTLMv1 "what breaks?" readiness scan across all DCs

- **Sources:** M, A, S, K in r1. K-r2 challenged the market claim and narrowed the spec. M-r2
  combined it with I-11 and I-15 into a "quarterly client risk review".
- **Pitch:** One run across every DC lists the accounts, devices and apps still using RC4
  Kerberos or NTLMv1. Each gets a verdict:
  - fix (no AES keys: reset the password)
  - fix the enctype attribute or policy
  - exempt or retire (the device can't do AES)

  A gate per DC answers "can this DC even log it?", so a 2012/R2 DC, or a 2016 DC without the
  January 2025 update, gives "can't tell", never "no RC4". The tool is strictly read-only and
  never writes `msDS-SupportedEncryptionTypes`. It also produces a client-readable page.
- **Evidence:**
  - `BlockNTLMv1SSO` moves to Enforce in October 2026 (KB5066470).
  - Enhanced NTLM auditing (4020-4033) reaches Server 2019/2022 from 2026-10-13 (KB5064479, dates
    tentative).
  - CVE-2026-20833 KB: KDCSVC 201/207 warnings become errors 203/209, and the default for
    undefined enctypes is AES-SHA1 from 2026-04-14 updates. Learn's enctype table still says
    `0x0` defaults to RC4. That conflict means the verdict must depend on each DC's patch level
    (P-001).
  - Learn "Detect and remediate RC4" ([page](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
  - **K-r2 correction:** Microsoft links free MIT scripts (`Get-KerbEncryptionUsage.ps1`,
    `List-AccountKeys.ps1`). They work one DC at a time, print raw rows, give no verdict and
    don't cover NTLMv1. ADAudit Plus sells RC4 reporting. SIGNALS 2026-10-14: 2012/R2 DCs still
    turn up. These failures look like lockouts, which the existing lockout tools could misread
    (K-r1).
- **Builds on:**
  - The lockout engine's multi-DC `Get-WinEvent`.
  - The `Test-ADAuditPolicy` gate.
  - The reference psd1 and parity test (I-05).
  - A proposed parity test that decodes the same sample events as Microsoft's scripts (K-r2).
- **Size:** M.
- **Open for the critic:** the KB-number conflict (KB5021131 vs KB5073381) still needs a source.
  The pitch should say plainly that the value is the domain-wide verdict, not detection.

## I-07 · "Can this user open this folder?" access verdict (share plus NTFS)

- **Sources:** effective access check (U-r1), "Who can get into this folder?" report (S-r1), bold
  bet (K-r1). S-r2 challenged it with a different contract.
- **Pitch:** Enter a user and a path. The tool returns YES / NO / ONLY READ with the exact chain:
  share permission, NTFS entry, which nested group, and any Deny. It also flags a stale token
  ("added to the group after their last sign-in", U-r1). The "who can get in, and through which
  group" view becomes the evidence tab. The read-only report also flags risky grants: Everyone
  with write, broken inheritance, orphaned SIDs, and direct user entries.
- **S-r2 contract:**
  - YES only when the share, NTFS, every SID, every nested group and every Deny are resolved.
    Otherwise PROBABLY or CAN'T TELL with the reason (ABE, claims or central access policy,
    unreadable folder).
  - On NO, recommend the narrowest group that already grants the right, and warn if that group
    is privileged elsewhere (Find-PrivilegedAccessPaths).
  - Never suggest Everyone, Authenticated Users or a direct per-user entry.
  - Hand off to FolderPermissionManager through the I-12 receipt.
- **Evidence:**
  - SIGNALS [files][drive-maps]: these are time sinks.
  - `ServiceDesk-Toolkit/README.md`: the access report is group-only.
  - FolderPermissionManager edits ACLs but gives no verdict.
  - Recon-market pain 8: free auditors gate export behind Pro ($199-$1,249). SolarWinds
    Permissions Analyzer has no ticket output.
  - SIGNALS 2026-10-14 trust breaker: primary-group resolution was wrong once and has since been
    fixed.
  - It is the natural next step after DriveMap-Diagnostics rules out the mapping.
- **Builds on:** AD-GroupMembership-Export nesting with the primary-group fix,
  FolderPermissionManager ACL reading, SMBTest, Find-PrivilegedAccessPaths.
- **Size:** L as a full verdict. M if v1 ships the evidence plus the narrowest-group
  recommendation and holds back the single YES (S-r2).
- **Open for the critic:**
  - Can a supported Windows access-check API be called remotely on a 3.0 floor, instead of
    re-implementing ACL evaluation? Must be checked on Learn.
  - Share permissions via `MSFT_SmbShareAccess` need verification.

## I-08 · Temporary-profile investigation for one VDI user

- **Sources:** FSLogix temp-profile orchestrator (A-r1), one-user VDI finder "where is the session
  and why won't the profile load?" (U-r1). Merged because both are keyed on one user and share
  every collector.
- **Pitch:** Enter a username, with the host optional. It finds where the user is or last was
  across Citrix, RDS or AVD hosts, and their connected, disconnected or stuck sessions. It then
  runs the existing FSLogix triage, log parser, storage-event correlation and event export
  against that host and gives one ranked verdict. Possible causes:
  - profile disk locked by another host or a stuck session
  - share permission (including the computer account)
  - Cloud Cache unreachable
  - frxsvc stopped or crashed
  - an existing local profile
  - disk full

  Output is a case folder with SUMMARY.txt, for example "Jane has a stuck disconnected session on
  CTX-04 holding her disk: log it off, then sign in again."
- **Evidence:**
  - SIGNALS 2026-10-16: Citrix/FSLogix/AVD tickets are the slowest, and techs remote to VDAs and
    use Studio, Director and the Azure portal.
  - Recon-market pain 11: at least five Microsoft Q&A threads with distinct causes.
  - The Learn known-issues page: event 26 is expected on Entra-only devices, and an frxsvc crash
    causes temporary profiles.
  - Recon-market pain 7: the built-in Profile Status tool can't filter by user or time.
  - Recon-code: Citrix-FSLogix-Triage is per-host and Get-CitrixSessions is Citrix-only.
- **Builds on:** Citrix-FSLogix-Triage (CheckId), Parse-FSLogixLogs, Get-FSLogixStorageEvents,
  RDS-FSLogix-EventExport, Get-CitrixSessions, and the gate -> collect -> verdict -> SUMMARY
  orchestrator pattern (lockout, drive maps).
- **Size:** M for the orchestrator over existing collectors (A). L including cross-platform
  session discovery (U).
- **Open for the critic:**
  - This would be the third orchestrator copy (recon-code engine 3).
  - RDS session lookup and "who holds the VHDX open" need Learn verification.
  - The FSLogix code table belongs in I-05.

## I-09 · AVD session host check (on the host, no Azure sign-in)

- **Sources:** K-r1 (host-local version), A-r1 (Az host-pool version), N-r1 ("which host is this
  AVD user on"). A-r2 conceded that K's host-local version should be built first, with the Az
  view added later as an option.
- **Pitch:** Run it against an AVD session host with `-ComputerName`. It checks why the host shows
  Unavailable or refuses connections:
  - RDAgentBootLoader or agent stopped
  - `HKLM\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered` = 0 (token expired or invalid)
  - broken side-by-side stack (Unavailable/Upgrading)
  - ENDPOINT_NOT_FOUND
  - recent agent errors

  It reuses the FSLogix checks because AVD hosts usually run FSLogix, and each finding links to
  Microsoft's documented fix.
- **Evidence:**
  - SIGNALS 2026-10-16: clients run Citrix, AVD and RDS; AVD tickets are slow; techs use the Azure
    portal for session hosts.
  - Recon-code: there are no AVD diagnostics at all.
  - The bundle's DriveMap row has no AVD equivalent of "look it up in Director" (N-r1).
  - Learn [troubleshoot-agent](https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent).
- **Builds on:** Citrix-FSLogix-Triage (per-host shape, CheckId), Citrix-FSLogix-HealthCollector
  fan-out. Optional later: the Az pattern from Get-AzureFilesFSLogixProfiles plus
  Az.DesktopVirtualization for the host-pool view and the "which host is this user on" lookup.
- **Size:** M. It fits P-003 with no Az module.

## I-10 · Leaver check: "Is this leaver fully shut out?" (read-only)

- **Sources:** offboarding checker (N-r1), leaver verification bold bet (S-r1). In r2, M made it a
  mode of the "one cloud user case", A made it a playbook, and S made it a `-Leaver` mode of the
  mailbox tool.
- **Pitch:** Enter a leaver and get a done / not-done list across AD, Entra and Exchange:
  - disabled in both places
  - sessions revoked
  - no sign-ins since the leaving date
  - groups and admin roles removed, including local admin
  - licences removed or kept on purpose
  - mailbox converted, no external forwarding, delegates reviewed

  The output is a client-readable page ("access closed on <date>, checked by <tech>") plus the
  I-03 note. Blocking sign-in stays in M365-SyncedUserFixes.
- **Evidence:**
  - Offboarding misses are a classic MSP liability (S).
  - `ServiceDesk-Toolkit/README.md` lists "offboarding check" under the access report, but that
    report leaves disabled accounts out, so a leaver's leftover groups can't be seen (N-r1).
  - SIGNALS [escalation] (what was checked) and [reporting] (client-readable output).
  - ScubaGear and Maester test the tenant, not one departed user.
- **Builds on:** I-01 and I-02 reads, AD-UserQuickCheck, AD-GroupMembership-Export,
  Find-PrivilegedAccessPaths, M365-SyncedUserFixes block state.
- **Size:** S as a playbook or mode once I-01, I-02 and I-03 exist. L as a standalone tool.

## I-11 · Server end-of-support register (and the "quarterly client risk review" bundle)

- **Sources:** M-r1, K-r1. M-r2 combined it with I-06 and I-15 into one quarterly per-client
  review page.
- **Pitch:** It finds every Windows Server in the domain and lists:
  - OS and support end date
  - last logon
  - what it actually does: roles, shares, scheduled tasks, and services running as domain
    accounts
  - risk order

  The output is a one-page client sheet plus a CSV. Each run records its date and who ran it, so
  the next quarter can compare ("4 unsupported servers in July, 1 now"). Services and tasks
  running as domain accounts also feed lockout work.
- **Evidence:**
  - Server 2012/2012 R2 final ESU ended 2026-10-13; Server 2016 extended support ends 2027-01-12
    (secondary sources; verify on Learn lifecycle pages).
  - Third parties charge $2,950 per assessment (recon-market).
  - SIGNALS 2026-10-14: 2012/R2 still turns up. SIGNALS [reporting]: turning output into
    something a client can read.
  - Insurers ask "do you run unsupported operating systems?" (M).
- **Builds on:** AD-Audit computer and OS enumeration, Hyper-V and VMware inventory, the
  dark-theme HTML renderers, and PS 3.0 floor work.
- **Size:** S (AD-only register, M-r1) to M (with role, task and service discovery, K-r1).
- **Open for the critic:** no helpdesk ticket signal; this is lead- and client-facing value.

## I-12 · Before/after permission receipt, with rollback

- **Sources:** S-r1. S-r2 tied it into I-07 and the I-03 "Changed anything: Yes (see receipt)"
  stamp.
- **Pitch:** Before a tech changes folder permissions or local-admin membership, the tool saves
  a dated snapshot (SDDL and members). Afterwards it produces a before/after diff and a pasteable
  "changed X on Y at Z by T" note. Restoring is ShouldProcess with confirmation unless `-Force`.
  It refuses to restore over an ACL that changed again since the "after" snapshot without
  telling the tech.
- **Evidence:**
  - Recon-code: only M365-SyncedUserFixes logs its own changes. FolderPermissionManager and
    LocalAdminManager change real systems with no change log.
  - SIGNALS [escalation]: Michael wants to see what the tech did.
- **Builds on:** the M365-SyncedUserFixes change-log CSV format and `Get-Acl`/SDDL.
  `ConvertFrom-SddlString` is 5.0, so 3.0 targets need a fallback.
- **Size:** S for snapshot plus diff, M with restore.
- **Risk:** the restore path makes this a destructive-operations tool.

## I-13 · "Did this policy reach this user?" GPO applied-or-not check

- **Sources:** U-r1 only.
- **Pitch:** Enter a user and a computer. It reads the last Group Policy result and says which
  GPOs applied and which were skipped, in plain words: filtered by security group, blocked by
  inheritance, WMI filter false, or the user hasn't signed in there since the change. If no RSoP
  exists it says so rather than guessing.
- **Evidence:**
  - SIGNALS 2026-10-16: techs click through ADUC and GPMC by hand.
  - Recon-market pain 12: user GPO applies on first logon but not later with FSLogix (Microsoft
    Q&A threads).
  - DriveMap-Diagnostics already reads GPO-side evidence, but only for drive maps.
- **Builds on:** AD-GroupPolicy-Audit (GPO XML, links, inheritance), the DriveMap evidence gate,
  and `Get-GPResultantSetOfPolicy -Computer -User` (parameters to verify on Learn).
- **Size:** M.
- **Open for the critic:** only one lens proposed it, and no round-2 lens picked it up.

## I-14 · Workstation check, trimmed to what an RMM doesn't diagnose

- **Sources:** U, M and N in r1 ("Is it this PC?", "Workstation Quick Check", "Is this PC OK?").
  K-r2 challenged it and trimmed the scope. M-r2 challenged it: no front-door slot without
  ticket counts.
- **Pitch (trimmed per K-r2):** Point it at the user's PC by name and check the domain-side
  things an RMM doesn't interpret:
  - secure channel and domain trust
  - time skew against the DC
  - the last Group Policy result and its errors
  - profile and OST size
  - reachability of the user's DC and file server

  It produces the I-03 note. The r1 version also covered disk, uptime, pending reboot, updates,
  crashes and stuck print jobs. K-r2 found that RMMs (NinjaOne, N-able) already show most of
  those.
- **Evidence:**
  - Recon-code gap: no endpoint health tool exists.
  - SIGNALS: some clients have little or no VDI, so desktop tickets are their whole service desk
    (M-r1).
  - **Against it:** all three r1 cards admit there is no SIGNALS entry. NinjaOne documents last
    boot, needs-reboot and patch status
    ([pending reboots](https://www.ninjaone.com/docs/endpoint-management/device-reboots/pending-reboots/)).
    A second tool that disagrees with the RMM creates a trust problem (K-r2).
- **Builds on:** DC-Diagnostics (secure channel, w32tm), DriveMap GPO evidence,
  Citrix-FSLogix-HealthCollector CIM with DCOM fallback, Network-QuickCheck.
- **Size:** S trimmed, M as in r1.
- **Open question for Michael:** which RMM does the MSP use, and do techs open it on desktop
  tickets? Rough ticket counts per area from ConnectWise.

## I-15 · Client-data leftovers sweep

- **Sources:** S-r1. In S-r2, the I-03 case manifest makes it a manifest reader (S). M-r2 put it
  in the quarterly review in report-only form.
- **Pitch:** It lists every report or case folder this toolkit left on a machine or a set of
  servers, with age and data type: AD dumps, sign-in evidence, profile backups with browser data,
  and `C:\ADReports` zips. It offers to delete stale ones. Report-only is the default. Deleting
  is ShouldProcess with confirmation unless `-Force`, uses only folders named in a manifest
  (never wildcards), and writes a deletion log.
- **Evidence:**
  - Recon-code: case folders hold client AD and tenant data. FSLogix-Profile-Backup is flagged
    personal-data in `squad/squad.config.json`. Nothing cleans up output on client servers or
    tech workstations.
  - PRINCIPLES: output stays local, which makes local cleanup the only control.
  - The bundle is about to spread to every tech.
- **Builds on:** the I-03 case manifest, the bundle manifest's known output locations, and the
  DeleteOldFolders pattern.
- **Size:** S.
- **Risk:** deletes files, so the destructive-operations and personal-data profiles apply.
