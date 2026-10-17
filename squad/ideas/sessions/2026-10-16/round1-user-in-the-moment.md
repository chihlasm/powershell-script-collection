# Round 1: user-in-the-moment (helpdesk tech mid-ticket)

Lens: a tier 1/2 tech with a client on the phone. Focus: new tools the collection lacks.
Test applied to every idea: one name or path in, one plain-English verdict out, no setup on the
client's servers, and it replaces a trip to a portal or console the tech makes today
(SIGNALS 2026-10-16, "Where techs leave the tools").

Ordered from quick win to bold bet.

### "Can this user open this folder?" (effective access check)
- Pitch: Type a username and a folder path; the tool answers YES / NO / ONLY READ, names the exact group that grants or blocks it, and says what to do ("add to group X", "user must sign out and back in"). No more clicking through the Security tab, Advanced, Effective Access, and ADUC group lists.
- Who and when: "I can't open the Finance folder" or "the S: drive is there but empty or says access denied", which is the most common follow-up once a drive map has been ruled out.
- Evidence: [files] [drive-maps] are named time sinks (SIGNALS 2026-10-16, Ticket drivers). Recon-code: AD-GroupMembership-Export is group-only, "not folder or share permissions" (`ServiceDesk-Toolkit/README.md`); FolderPermissionManager is an editor GUI that changes ACLs, not a one-question verdict. Market: free NTFS auditors gate export behind Pro (recon-market pain 8) and answer "who has access to this folder", not "why can't this one person get in". A useful verdict the portals cannot give: user was added to the group after their last sign-in, so their token is stale (compare group membership change time against last logon; needs Learn verification of which attribute/metadata to use).
- Builds on: AD-GroupMembership-Export nesting resolution; AD-UserQuickCheck's FakeAD test harness; DriveMap-Diagnostics (natural "next step" when the drive is present but access is denied). Share permission read via CIM on 2012+ (verify MSFT_SmbShareAccess on Learn), NTFS via Get-Acl on the UNC path. Read-only, PS 3.0 possible.
- Size guess: M
- Why now / why us: the repo already resolves nested groups and primary group correctly (after the 2026-10-14 primary-group trust fix), which is the hard part competitors get wrong.

### "Did this policy reach this user?" (GPO applied-or-not check)
- Pitch: Give a user and a computer; the tool reads the last Group Policy result and says in plain words which policies applied, which were skipped and why ("filtered out by security group", "blocked by inheritance", "WMI filter false", "user hasn't signed in there since the change"). Replaces running gpresult by hand and reading GPMC.
- Who and when: "the printer/drive/setting/app shortcut didn't show up for this user", including the FSLogix "user policy applies on first logon, not after" case.
- Evidence: techs click through GPMC by hand (SIGNALS 2026-10-16, "ADUC and GPMC"). Market pain 12 (GPO user settings not applying with FSLogix after first logon, Microsoft Q&A threads). DriveMap-Diagnostics already reads GPO-side evidence but only for drive maps.
- Builds on: AD-GroupPolicy-Audit (GPO XML, links, inheritance, permissions); DriveMap-Diagnostics evidence-gate pattern ("could not look" vs "found nothing"). RSoP via Get-GPResultantSetOfPolicy -Computer -User (GroupPolicy RSAT, verify params on Learn); falls back to "user has no RSoP on that machine" rather than guessing.
- Size guess: M
- Why now / why us: the collection already parses GPO XML; this turns that into the per-user answer a tech actually needs mid-call.

### M365 user quick check ("Can this user sign in to Microsoft 365 and get mail?")
- Pitch: The cloud twin of AD-UserQuickCheck: one name in, YES / NO / PROBABLY NOT out, with a reason and a "What to do" for each: blocked sign-in, no licence, no MFA method registered, last sign-ins failing with a decoded error, Conditional Access blocked them, account not synced or sync stale, mailbox missing. Replaces flipping between the Entra admin center, the M365 admin center and the sign-in log.
- Who and when: "I can't get into Outlook/Teams" on a hybrid client, the longest-running ticket type.
- Evidence: SIGNALS 2026-10-16: M365/Entra/mailbox tickets "usually take longer"; techs check "Entra, M365 and Exchange admin centers, sign-in logs" by hand. Recon-code: "Not found anywhere in the repo: per-user cloud sign-in log lookup ... licensing". Market: Microsoft's Sign-in diagnostic is portal-only, no CLI (recon-market). Graph `GET /auditLogs/signIns` needs AuditLog.Read.All and a reader role such as Global Reader or Reports Reader; CA detail is omitted unless the caller can read CA data (https://learn.microsoft.com/graph/api/signin-list). The tool must say "could not read sign-in log (role or licence)" rather than "no failed sign-ins" (P-001). Sign-in log licensing requirement (Entra ID P1) to be verified on Learn before build.
- Builds on: Get-M365SecurityEvidence (already calls signIns and conditionalAccess via Invoke-MgGraphRequest with Microsoft.Graph.Authentication only); AD-UserQuickCheck verdict shape and "What to do" wording; Get-EntraPasswordPolicy per-user expiry logic. PS 5.1 is legitimate here (Graph module).
- Size guess: M
- Why now / why us: AD-UserQuickCheck already proved the verdict format on-prem; clients are mostly hybrid (SIGNALS client facts), so half of every sign-in ticket currently falls off the tool and into the portal.

### Mailbox quick check ("Why isn't mail arriving / who else can see this mailbox?")
- Pitch: One mailbox in; the tool reports in plain words whether mail is being forwarded away (forwarding address or inbox rule sending outside), whether the mailbox is full, who has Full Access / Send As, whether it is a shared mailbox someone is trying to sign into, and the last day's message trace for that address. Each line ends with what to do.
- Who and when: "I'm not getting emails", "I can't see the shared mailbox", "my boss says emails went missing", and the security-flavoured "someone set up a forwarding rule".
- Evidence: SIGNALS 2026-10-16 names [m365] mailbox tickets as a long-running time sink and the Exchange admin center as a place techs go by hand. Recon-code: "grep for Get-Mailbox, Get-MessageTrace ... returned none"; only mailbox type is collected today (Get-M365SecurityEvidence). Recon-market item 14: mailbox permission pain had no retrieved source, so demand rests on the owner signal alone. Message trace cmdlet choice (Get-MessageTrace vs the newer V2 cmdlet) must be verified on Learn before build.
- Builds on: Get-M365SecurityEvidence's optional ExchangeOnlineManagement connection; the verdict + "What to do" pattern. Read-only.
- Size guess: M
- Why now / why us: the module dependency is already accepted in the repo; the tool fills the one ticket driver with zero coverage.

### "Why is this user missing or wrong in Microsoft 365?" (hybrid sync check for one user)
- Pitch: For a user who exists in AD but not in M365 (or whose change never showed up), the tool checks the usual reasons side by side and names the one that applies: the user's OU is outside the sync scope, UPN suffix is not a verified domain, a duplicate UPN or proxy address collides with another object, the cloud object shows a provisioning error, or the last sync is stale. Replaces IdFix plus the Synchronization Service Manager plus the portal.
- Who and when: new starter "can't sign in to Outlook on day one", name change or new alias "not showing in the GAL", user moved OU and "vanished from Teams".
- Evidence: Recon-market pain 13 (Entra Connect "healthy" while specific users silently don't sync; causes: OU filters, custom rules, quarantined attributes, moved OU, DirSyncOverrides); Microsoft's own checklist names UPN mismatch, OU filtering, and IdFix for duplicates (https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-objectsync). SIGNALS: mostly hybrid clients.
- Builds on: M365-SyncedUserFixes (already inspects Entra Connect sync rules and talks to AD and Entra); AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1 (finds and gates on the Connect server). Read-only; reading the connector's OU scope remotely from the Connect server needs verification of what is readable without changing anything.
- Size guess: M
- Why now / why us: it sits exactly where on-prem and cloud tools meet, which is the seam this repo already straddles and generic M365 tools (CIPP, Maester) ignore.

### "Where is this user's session and why won't their profile load?" (one-user VDI finder)
- Pitch: Type a username; the tool finds every Citrix, RDS or AVD session host they are on or were last on, shows connected / disconnected / stuck sessions, and checks their FSLogix profile on that host: did it attach, did they get a temporary profile, and is their profile disk still locked open by another server. The answer reads like "Jane has a stuck disconnected session on CTX-04 holding her profile disk; log that session off, then have her sign in again."
- Who and when: "I got a temporary profile", "my desktop won't open", "my settings are gone", on a client with any VDI platform. These are the longest tickets (SIGNALS 2026-10-16).
- Evidence: SIGNALS: Citrix/FSLogix/AVD tickets take longer; techs go to Studio, Director and the Azure portal for session hosts; no single platform can be assumed. Recon-market pain 11: temporary profile / profile not loading is repeated across at least five Microsoft Q&A threads with causes including locked files and an existing local profile; built-in FSLogix Profile Status "does not filter by user or time" (pain 7). Recon-code: Citrix-FSLogix-Triage is per-host, not per-user; Get-CitrixSessions is Citrix-only; no AVD diagnostics exist.
- Builds on: Get-CitrixSessions (Broker SDK), Citrix-FSLogix-Triage checks and result-object contract, Parse-FSLogixLogs (attach results per user), Get-FSLogixStorageEvents. RDS session lookup and "who holds the VHDX open" (open-file query on the file server) need Learn verification; AVD session hosts discovered from AD or an explicit list, not Azure, so no setup is needed.
- Size guess: L
- Why now / why us: the collection already owns every piece for one host; techs need it pivoted around the person on the phone, not the server.

### Bold bet: "Look up this person" (one name, every system, one ticket note)
- Pitch: One username in, and a single page comes back covering AD sign-in (AD-UserQuickCheck), cloud sign-in and mailbox (the M365 checks above), current VDI session and profile, and recent lockouts, each with a one-line verdict and a combined "most likely problem" at the top. It finishes with a ConnectWise-pasteable note listing what was checked, what was ruled out, and what was found.
- Who and when: the first two minutes of nearly every user ticket, before the tech even knows which tool to run. It removes the "which tool do I run?" question entirely for user-centric tickets.
- Evidence: SIGNALS core problem (2026-10-16, owner): techs escalate because they don't know how to resolve; Michael wants "what they checked, how they ruled things out"; the most useful outputs are a handoff summary and a pasteable ConnectWise note. Adoption (2026-10-16): techs don't know which tool exists or when to use it. Recon-code: nothing captures what was checked and ruled out; SUMMARY.txt "for pasting into a ticket" exists only in the lockout orchestrator.
- Builds on: the `CheckId/Status/Summary/Evidence/RecommendedNextSteps` result contract (Network-QuickCheck, Citrix-FSLogix-Triage); `-LoadFunctionsOnly` cores; Citrix-PerfTriage as the precedent for an orchestrator over sibling folders (runs them in separate processes with time limits; ships as a kit). Each section must report "could not look" distinctly from "nothing wrong" (P-001), e.g. no Graph sign-in, no Citrix SDK. Output stays local: the note is a text file and clipboard, not a ConnectWise API push.
- Size guess: L
- Why now / why us: only this repo has verdict engines for AD, lockouts, VDI and (soon) cloud under one roof; a person-centred front door turns those into the single habit-forming step techs are missing.

### "Is it this PC?" (user's workstation quick check)
- Pitch: Point it at the user's computer name; it reports in plain words the things a tech asks over the phone every time: when it last restarted and whether a restart is pending, free disk space, whether the PC still trusts the domain, clock drift, last Group Policy refresh result, and the size of the user's profile and Outlook data file. One screen replaces five "can you open... and read me..." requests.
- Who and when: any "my computer is slow / weird / can't connect" ticket on a physical desktop, before remoting in.
- Evidence: Recon-code gap list: "No tool for workstation/endpoint health on a user's PC (disk, updates, startup, profile size, Outlook/OST ...)". Weaker evidence than the others: no SIGNALS entry names endpoints specifically, so this is the idea most worth checking against ConnectWise ticket counts (open question in SIGNALS).
- Builds on: DC-Diagnostics (secure channel, reboot history, w32tm), Citrix-FSLogix-HealthCollector (CIM with DCOM fallback), Network-QuickCheck result contract. Remote via -ComputerName, PS 3.0, read-only; RMM-managed clients may already show some of this, which the critic should weigh.
- Size guess: M
- Why now / why us: CIM fan-out with DCOM fallback is already proven in the repo, so this is mostly verdict wording.
