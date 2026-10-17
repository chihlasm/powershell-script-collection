# Round 1: security and compliance lens

Session 2026-10-16. Focus: "useful tools that we may not have currently".
Lens: protect clients, their data and the systems these tools touch: least privilege, audit
trails, credential handling, blast radius, what a mistake costs across fifty clients.

Every idea below is a NEW tool folder (nothing here re-creates a retired tool; GRAVEYARD and
BACKLOG are empty). Every idea is read-only by default; where one can change anything it says
so and requires `-WhatIf`/ShouldProcess plus confirmation unless `-Force`.

---

### Compromised-account first look (read-only)
- Pitch: When a client says "I think my email was hacked", the tech runs one tool with the
  user's name and gets a plain answer: signs of a takeover found / none found / could not check,
  with the evidence: forwarding rules, new inbox rules, sign-ins from unusual places, MFA
  methods added recently, apps the user granted access to. It changes nothing; it produces an
  evidence folder with SHA-256 hashes and a paste-ready ticket note so the escalation shows
  exactly what was checked and ruled out.
- Who and when: Tier 1/2 tech, first 15 minutes of a "suspicious email / user sent spam /
  client got a weird invoice" ticket, before anyone resets anything and before evidence ages
  out of the logs.
- Evidence: SIGNALS 2026-10-16 [m365][entra] "M365/Entra/mailbox tickets usually take longer"
  and techs check "Entra, M365 and Exchange admin centers, sign-in logs" by hand.
  recon-code: no mailbox/Exchange troubleshooting exists (no `Get-Mailbox`, no message trace,
  no forwarding check); only Get-M365SecurityEvidence touches `auditLogs/signIns`.
  SIGNALS core problem: owner wants "what they checked, how they ruled things out".
  Security reason it is a separate tool: the natural first instinct (reset password, revoke
  sessions) destroys or muddies evidence; a read-first tool that captures state before anyone
  acts protects the client and the MSP.
- Builds on: Graph REST via `Invoke-MgGraphRequest` pattern in
  `Get-M365SecurityEvidence/Get-M365SecurityEvidence.ps1`; optional Exchange Online
  connection already used there; zip + SHA-256 pattern in `Entra-DeviceActivityTimeline`;
  verdict + "What to do" shape from `Network-QuickCheck`.
- Security guardrails: delegated, read-only Graph scopes only (verify each on Learn and list
  them in .NOTES; no `*.ReadWrite.*`); states "could not check" when a scope or licence (P1
  for sign-in logs) is missing rather than "nothing found" (P-001, market pain #3 "scanner
  output can mislead"); remediation is NOT in this tool: the note lists next steps for a
  human. Output folder holds client mail metadata, so it lands in the gitignored case-folder
  location and the README says to attach and delete.
- Size guess: M
- Why now / why us: Hybrid clients everywhere (SIGNALS client facts), the Graph plumbing
  already exists in the repo, and RMM/PSA suites do not do this triage; CIPP does but is a
  hosted multi-tenant service, which PRINCIPLES rules out.

### "Why can't this user sign in to Microsoft 365?" sign-in lookup (least-privilege)
- Pitch: The cloud twin of AD-UserQuickCheck: type a user, get YES / NO / PROBABLY NOT for M365
  sign-in with the reason in plain English (blocked by Conditional Access, MFA not completed,
  account disabled in Entra, password expired/sync issue, smart lockout) and the next step,
  decoded from the user's last sign-in attempts. It asks only for the read permissions it
  needs and tells the tech up front which role is enough, so nobody signs in as Global Admin
  just to read a log.
- Who and when: Tier 1 tech on a "can't get into Outlook/Teams" call with the user waiting,
  instead of hunting through the Entra sign-in log blade.
- Evidence: SIGNALS 2026-10-16 [sign-in][entra] big time sink, techs read sign-in logs in the
  portal by hand. recon-code: "Not found anywhere in the repo: per-user cloud sign-in log
  lookup". recon-market: Microsoft's Sign-in diagnostic is portal-only, no CLI; it is
  reachable at Global Reader, which is the least-privilege bar this tool should advertise.
  Market pain #5: Graph scope/consent errors confuse techs, so the tool must say which scope
  is missing in plain words.
- Builds on: AD-UserQuickCheck verdict shape and "What to do" per reason; Graph calls in
  Get-EntraPasswordPolicy / Get-M365SecurityEvidence; Entra Connect evidence in
  AD-LockoutDiagnostics (PHS/PTA) for the hybrid "password changed on-prem but not in cloud"
  case.
- Security guardrails: read-only scopes (sign-in log listing needs AuditLog.Read.All plus
  Directory.Read.All per the Graph `signIn` list page; verify and cite), no token caching to
  disk, prints the signed-in admin identity and tenant at the top so a tech cannot
  accidentally query the wrong client's tenant (a real cross-client mistake in MSPs).
- Size guess: M
- Why now / why us: Completes the hybrid sign-in story the repo already owns on-prem;
  sign-in is the single most frequent ticket driver named by the owner.

### Who can get into this folder? (effective share + NTFS access report, read-only)
- Pitch: Point it at a share or folder and get a plain list of people who can read, change or
  fully control it, with the reason (which group, which nesting path, share vs NTFS limit),
  and flags for risky grants: Everyone/Authenticated Users with write, broken inheritance,
  orphaned SIDs, direct user grants. Read-only, so it is safe to run before a tech touches
  permissions in FolderPermissionManager.
- Who and when: Tech on "user can't open the S: drive folder" or "why can Bob see HR?"; senior
  admin auditing a client file server before a migration or after a staff departure.
- Evidence: SIGNALS 2026-10-16 [files] ticket driver. recon-code: AD-GroupMembership-Export is
  "Group membership only, not folder or share permissions"; FolderPermissionManager changes
  ACLs but there is no read-only effective-access report. recon-market pain #8: free
  permission auditors gate export behind Pro licences.
- Builds on: nesting expansion and primary-group handling already fixed in
  AD-GroupMembership-Export (SIGNALS 2026-10-14 trust breaker: primary-group members wrongly
  flagged; reuse the corrected logic); tabbed HTML renderer pattern.
- Security guardrails: read-only; caps recursion depth by default so a tech does not crawl a
  multi-terabyte share by accident; reports "could not read" for folders where the running
  account is denied instead of omitting them (P-001).
- Size guess: M
- Why now / why us: It is the missing "look before you change" partner to a tool that
  already changes ACLs, which is exactly where a repeated mistake is most costly.

### Permission snapshot before change (ACL and local-admin "receipt" with rollback)
- Pitch: Before a tech changes folder permissions or local admin membership, this tool saves a
  dated snapshot of the current state and, after the change, produces a before/after
  difference and a paste-ready note: "changed X on Y at time Z by tech T". If the change was a
  mistake, the same snapshot can be put back, with -WhatIf preview and confirmation.
- Who and when: Any tech using FolderPermissionManager or LocalAdminManager mid-ticket, and
  Michael on escalation review wanting proof of what was changed.
- Evidence: recon-code: "only M365-SyncedUserFixes writes an audit CSV of its own changes";
  FolderPermissionManager and LocalAdminManager change real systems with no change log.
  SIGNALS core problem: owner wants to see what the tech did. SQUAD.md: tools that change
  things must be clearly labelled; a receipt makes the change provable after the fact.
- Builds on: the change-log CSV format in M365-SyncedUserFixes (who/when/person/old/new);
  `Get-Acl`/SDDL capture (SDDL text round-trips; `ConvertFrom-SddlString` is 5.0 so use a
  fallback on 3.0 targets per root CLAUDE.md).
- Security guardrails: restore path is ShouldProcess with confirmation unless `-Force`,
  refuses to restore over a folder whose ACL changed since the "after" snapshot without
  telling the tech (prevents trampling someone else's later fix); snapshots hold SIDs and
  paths only, no content.
- Size guess: S (snapshot + diff), M with restore
- Why now / why us: The repo already ships two ACL/group-changing tools; adding the safety
  net is cheaper than any incident caused by an unrecorded permission change across clients.

### Kerberos RC4 / NTLM "will this break?" readiness check (read-only)
- Pitch: Microsoft is switching off old sign-in encryption (RC4 for Kerberos) and tightening
  NTLM in 2026; this tool tells the tech, per client domain, which accounts and services will
  fail when that lands, and whether the domain controllers are already logging the warnings
  that prove it. Verdict first: "ready / N things will break / cannot tell (DC not updated or
  not logging)".
- Who and when: Senior admin during a monthly client review; tier 2 tech on "service account
  suddenly fails after Patch Tuesday" or "old scanner/NAS can't authenticate".
- Evidence: recon-market "Recent moves": RC4 phase-out tied to CVE-2026-20833 with audit then
  enforcement in 2026; NTLMv1 `BlockNTLMv1SSO` default slated to move to Enforce in October
  2026 (support.microsoft.com/help/5066470); enhanced NTLM auditing events 4020-4033 reach
  Server 2019/2022 from 2026-10-13. Microsoft KB for CVE-2026-20833 documents KDCSVC System
  log warnings 201 and 207 that turn into errors 203 and 209 under enforcement
  (https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc),
  and Learn "Detect and Remediate RC4 Usage in Kerberos" shows reading
  msDS-SupportedEncryptionTypes (https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos).
  Note a conflict flagged in Q&A about the unset-attribute default: the tool must cite Learn
  and say "unknown" where docs disagree (P-001). recon-market: ADAudit Plus sells RC4 usage
  reports, so demand is real. SIGNALS: Server 2012/R2 still present, exactly the DCs that
  will not log the new events, so the gate matters.
- Builds on: evidence-gate pattern (`AD-LockoutDiagnostics/Test-ADAuditPolicy.ps1`) for "is
  this DC even capable of logging it"; DC discovery and remote `Get-WinEvent` across DCs
  from lockout tools; reference-data psd1 pattern for event IDs.
- Security guardrails: strictly read-only; does not offer to change encryption types (a
  wrong msDS-SupportedEncryptionTypes value breaks authentication domain-wide); next steps
  point to the Microsoft article.
- Size guess: M
- Why now / why us: Time-boxed: the enforcement dates are this year and NTLM changes land
  this month. A wrong bulk change here is the "mistake repeated across fifty clients" this
  lens exists to prevent.

### Client-data leftovers sweep (finds report folders left on machines)
- Pitch: The tools write client data (AD dumps, sign-in evidence, profile backups with saved
  browser data) to report folders on whatever machine they ran on; this tool lists every such
  folder it can find on a machine or set of servers, how old it is and what kind of data it
  holds, and offers to delete stale ones with -WhatIf preview and confirmation.
- Who and when: Michael or a senior tech at month end, or a tech closing a ticket on a client
  server ("leave no client data behind").
- Evidence: recon-code "Data it collects": case folders hold client AD/tenant data, C:\ADReports
  zips from AD-GroupMembership-Export, FSLogix-Profile-Backup flagged personal-data in
  `squad/squad.config.json`; output is gitignored but nothing cleans it up on client servers
  or tech workstations. PRINCIPLES: output stays local, which makes local hygiene the only
  control.
- Builds on: known output locations from each tool's `-OutputPath` defaults and the bundle
  manifest (`ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`); DeleteOldFolders pattern.
- Security guardrails: changes things (deletes), so ShouldProcess, confirmation unless
  `-Force`, a manifest-matched allow-list of folder patterns only (never wildcard-deletes
  arbitrary paths), and a deletion log. Default mode is report-only.
- Size guess: S
- Why now / why us: Only this collection knows where its own tools put client data; the
  bundle is about to spread to every tech, multiplying where data is left.

### Leaver / offboarding verification (bold bet, read-only)
- Pitch: When someone leaves a client, the tech runs one check and gets a pass/fail list
  across AD, Entra and Exchange: account disabled in both places, sessions revoked, no
  sign-ins since the leaving date, no mail forwarding to outside addresses, mailbox
  delegates and shared access reviewed, removed from privileged and sensitive groups, devices
  and app passwords noted. It proves the account is shut, or says exactly what is still open,
  and gives the client a plain report and the ticket a paste-ready note.
- Who and when: Tech closing an offboarding ticket; senior admin answering a client auditor's
  "prove former staff can't get in"; incident follow-up after a hostile departure.
- Evidence: SIGNALS ticket drivers [sign-in][entra][m365][files]; manual chore "turning tool
  output into something a client can read". recon-code: AD-UserQuickCheck (on-prem state),
  Find-PrivilegedAccessPaths ("why is this user an admin"), M365-SyncedUserFixes (block
  sign-in for synced users), Get-M365SecurityEvidence (Graph sign-ins) each cover a slice; no
  tool joins them into one leaver verdict. Market: ScubaGear/Maester test tenant config, not
  a single departed user.
- Builds on: the four tools above (logic re-shipped inside the folder per the self-contained
  rule), verdict-first HTML and SUMMARY.txt from the case-folder pattern.
- Security guardrails: read-only; the action to block sign-in stays in M365-SyncedUserFixes
  (already has -WhatIf and a change log). Prints which tenant and domain it queried so a
  result cannot be pasted into the wrong client's ticket. Says "could not check" for each
  area it lacked rights or licence for.
- Size guess: L
- Why now / why us: Offboarding failures are the classic MSP liability (a former employee
  still reading mail); the repo already holds every on-prem and cloud piece needed, and a
  local evidence report fits the no-cloud principle where SaaS tools do not.
