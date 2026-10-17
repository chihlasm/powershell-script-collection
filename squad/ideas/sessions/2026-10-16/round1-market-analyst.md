# Round 1: market analyst

Lens: what the paid suites, Microsoft's own portals and the community scripts cover badly,
and what is table stakes for an MSP service desk that this collection lacks. Each idea is a
new tool. None of them re-creates a retired tool or a graveyard entry (the graveyard is empty).

Market framing: the big products split in two. Multi-tenant M365 managers (CIPP, CoreView)
need a hosted backend. AD scanners (PingCastle, Purple Knight) take a point-in-time security
snapshot and limit commercial use (recon-market, pain 2). Neither answers one user's ticket
while the client waits. Microsoft's answers live in portals (Entra sign-in diagnostic is
portal-only, recon-market "Microsoft 365 / Entra ID assessment"). The gap this collection is
built for is a local verdict for one person, one machine or one share, with evidence attached.

---

### 1. "Can this user sign in to Microsoft 365?" (cloud twin of AD-UserQuickCheck)
- Pitch: Type a user's name and get YES / NO / PROBABLY NOT for Microsoft 365, with the reason
  in plain English: wrong password, MFA not finished, blocked by a Conditional Access policy,
  account disabled in the cloud, or the on-prem change hasn't synced yet. It reads the user's
  last sign-ins and decodes the error codes so the tech doesn't have to open the Entra portal.
- Who and when: tier 1/2 tech on the phone with a user who "can't get into Outlook or Teams".
  Today they open the Entra admin center and read sign-in logs by hand.
- Evidence: SIGNALS 2026-10-16 owner [entra][m365]: these tickets "usually take longer", and
  techs check "Entra, M365 and Exchange admin centers, sign-in logs" by hand. Code recon:
  no per-user cloud sign-in lookup exists; only Get-M365SecurityEvidence calls signIns, for
  attestation. Market: Entra Sign-in diagnostic is portal-only, no CLI (recon-market). Caveat
  that shapes the design (P-001): reading sign-in logs through Graph needs Entra ID P1 or P2
  on the tenant; a non-premium tenant returns "tenant doesn't have premium license"
  ([signIn resource](https://learn.microsoft.com/graph/api/resources/signin?view=graph-rest-1.0),
  [troubleshooting](https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities)).
  The tool must say "could not look: no P1 licence" rather than "no failed sign-ins", the
  same gate pattern as Test-ADAuditPolicy.
- Builds on: AD-UserQuickCheck verdict shape and "What to do" lines; Get-M365SecurityEvidence
  Graph REST calls (Invoke-MgGraphRequest, Microsoft.Graph.Authentication only); the
  Network-QuickCheck result-object contract; Test-EntraConnectReadiness for the hybrid half.
- Size guess: M
- Why now / why us: the collection already answers "can they sign in" for on-prem AD, and
  clients are mostly hybrid (SIGNALS client facts), so half the answer is missing. CIPP-style
  tools need a hosted backend this collection rules out; a local delegated-Graph script fits.

### 2. "Why isn't this user syncing to Entra?" (one-user sync check)
- Pitch: For one AD user, check every reason Entra Connect quietly skips them: wrong OU,
  duplicate email or UPN held by another object, attribute conflict reported by the cloud,
  never matched to a cloud account, or simply not synced since the change. The answer names
  the blocking object or setting and what to change.
- Who and when: "I changed her name/email/phone in AD yesterday and Outlook still shows the
  old one", or a new starter who never appears in M365. Sync health looks green, so the tech
  is stuck.
- Evidence: recon-market pain 13: Q&A threads where sync is "healthy" but specific users are
  missing, with causes OU filtering, quarantined attributes, DirSyncOverrides. Microsoft's own
  checklist (UPN mismatch, OU filter) and IdFix advice
  ([tshoot-connect-objectsync](https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-objectsync)).
  Graph exposes per-user `onPremisesProvisioningErrors` (category PropertyConflict on
  UserPrincipalName or ProxyAddress), which must be requested with `$select`; MSOnline's
  `Get-MsolUser -HasErrorsOnly` is retired with no direct replacement
  ([Q&A on Get-MsolUser replacement](https://learn.microsoft.com/answers/questions/2202495/msonline-powershell-module-retirement-replacement)).
  IdFix scans the whole directory; nothing answers for one user.
- Builds on: M365-SyncedUserFixes (it already reads and checks Entra Connect rules),
  Test-EntraConnectReadiness, AD-UserQuickCheck's AD lookups.
- Size guess: M
- Why now / why us: MSOnline retirement removed the one-liner techs used, and hybrid is the
  norm for these clients. The repo already has the Entra Connect knowledge in two tools.

### 3. Mailbox quick check: "who can see it, where does mail go, did it arrive?"
- Pitch: For one mailbox, show in plain English who has access to it, whether mail is being
  forwarded or moved by an inbox rule, how full it is, and what happened to the last few
  messages from a given sender. One report replaces four pages of the Exchange admin center.
- Who and when: "I'm not getting emails from X", "someone else is reading my mail", "my shared
  mailbox disappeared from Outlook". Long tickets where the tech clicks through EAC.
- Evidence: SIGNALS 2026-10-16 owner [m365]: mailbox tickets are a big, slow driver and are
  worked by hand in the Exchange admin center. Code recon: grep for Get-Mailbox and
  Get-MessageTrace found nothing; ExchangeOnlineManagement is used only for mailbox type.
  Market timing: Get-MessageTrace is replaced by Get-MessageTraceV2 and the old cmdlets began
  deprecating 2025-09-01 for worldwide tenants (not GCC/sovereign)
  ([Get-MessageTrace](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetrace),
  [GA announcement](https://techcommunity.microsoft.com/blog/exchange/announcing-general-availability-ga-of-the-new-message-trace-in-exchange-online/4420243)),
  so older community scripts techs might find are now broken. Unverified: no source retrieved
  on how common mailbox-permission pain is (recon-market pain 14).
- Builds on: Get-M365SecurityEvidence's optional Exchange connection; verdict-first HTML.
- Size guess: M
- Why now / why us: the trace cmdlet change breaks the scripts in circulation; a maintained,
  cited tool is worth more than the copy a tech finds online. Must flag sovereign tenants.

### 4. AVD session host check: "why can't users get on this host?"
- Pitch: Run against an AVD session host (no Azure login needed) and get a verdict on the
  things that make a host show Unavailable or refuse connections: agent and boot loader
  stopped, host not registered or token expired, side-by-side stack broken, recent agent
  errors. Each finding comes with the fix Microsoft documents.
- Who and when: tech staring at "Unavailable" in the Azure portal, or users told "couldn't
  connect" while the Citrix-side tools are no help because the client is on AVD.
- Evidence: SIGNALS 2026-10-16 owner: clients run Citrix, AVD and RDS, and techs use "the Azure
  portal for session hosts" by hand. Code recon: no AVD diagnostics exist (grep only hits
  installers and comments). Microsoft documents the host-side checks: RDAgentBootLoader
  service, `HKLM\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered` (0 = token expired/invalid),
  Unavailable/Upgrading meaning a bad stack install, ENDPOINT_NOT_FOUND, WVDAgentUrlTool
  ([troubleshoot-agent](https://learn.microsoft.com/troubleshoot/azure/virtual-desktop/troubleshoot-agent)).
  These are host-local, so the tool reaches them by `-ComputerName` with no Az module, fitting
  P-003.
- Builds on: Citrix-FSLogix-Triage (same per-host shape and result-object contract; FSLogix
  checks reused because AVD hosts usually run FSLogix); Citrix-FSLogix-HealthCollector fan-out.
- Size guess: M
- Why now / why us: the VDI tooling here is Citrix-heavy while clients are mixed; AVD is the
  biggest platform with zero coverage. Microsoft's guidance is scattered across pages, which is
  what a cited verdict tool fixes.

### 5. "What breaks when RC4 and NTLMv1 are switched off?" readiness scan
- Pitch: Scan the domain controllers' logs and AD for accounts and machines that still depend
  on the old RC4 Kerberos encryption or NTLMv1, and list them in plain English with what will
  fail and what to change. It turns Microsoft's 2026 security changes into a named list per
  client before the sign-in tickets arrive.
- Who and when: senior engineer doing a client health review, or right after a wave of "the
  scanner/app/service account suddenly can't log in" tickets.
- Evidence: Microsoft KB: from updates on and after 2026-04-14 the KDC default for accounts
  without explicit `msDS-SupportedEncryptionTypes` changed to AES-SHA1; monitor KDCSVC System
  events 201-209 on DCs (Server 2012 and newer)
  ([CVE-2026-20833 KB](https://support.microsoft.com/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc),
  [Detect and remediate RC4](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
  NTLMv1: `BlockNTLMv1SSO` default slated to move from Audit to Enforce in October 2026, and
  enhanced NTLM auditing (events 4020-4033) reaches Server 2019/2022 from 2026-10-13
  (recon-market "Recent moves", KB5066470 / KB5064479). Market: ManageEngine ADAudit Plus sells
  RC4 usage reports (recon-market). Recon flags the KB-number conflict; P-001 says verify every
  event field on Learn before coding.
- Builds on: AD-LockoutDiagnostics event collection across DCs and its audit gate pattern;
  LockoutReference.psd1 style reference data; AD-Audit's domain-wide reads.
- Size guess: M
- Why now / why us: enforcement dates are this month and last. These failures look like
  lockouts and sign-in failures, which the lockout tools would misread; the collection already
  owns that ticket type. A paid product is the only packaged option found.

### 6. Old-server inventory before end of support
- Pitch: List every Windows server in the domain with its OS, when support ends, what it
  actually does (roles, shares, scheduled tasks, services running as domain accounts), and
  whether it is still in use. It gives the engineer a migration list and the client a
  plain-English page on why it matters.
- Who and when: account manager or senior engineer preparing a client review; the week a
  client asks "do we really need to replace that box?".
- Evidence: Server 2012/2012 R2 final ESU year ended 2026-10-13 and Server 2016 extended
  support ends 2027-01-12; third parties sell fixed-price end-of-support assessments ($2,950
  for up to 25 hosts) (recon-market "Recent moves", secondary sources; verify the dates on
  Microsoft's lifecycle pages). SIGNALS: Server 2012/2012 R2 still turns up at clients; manual
  chore "turning tool output into something a client can read". Side benefit tied to a ticket
  driver: services and scheduled tasks running as domain users are a classic lockout source,
  so the same scan feeds lockout work.
- Builds on: AD-Audit infrastructure section (computer objects, OS attributes), the PS 3.0
  floor work that already runs on these servers, Hyper-V/VMware inventory for host context.
- Size guess: M
- Why now / why us: the deadline just passed for 2012 and is three months out for 2016. An MSP
  that runs this across clients turns a paid third-party service into a repeatable report.

### 7. "Why can't this user open this folder?" effective access verdict (bold bet)
- Pitch: Give a user and a folder path and get a YES / NO answer on whether they can open,
  edit or delete there, with the exact chain that grants or blocks it: share permission, NTFS
  entry, which nested group, any Deny. It is read-only and needs nothing installed on the file
  server.
- Who and when: "I can't get into the Finance folder" or "why can the temp see HR?", which are
  the "files" tickets in the top driver list. Today the tech opens Advanced Security, reads
  ACLs, then ADUC for group nesting, then the share tab, and guesses.
- Evidence: SIGNALS 2026-10-16 owner [files]: file access is a big time sink. Code recon: the
  access report is "group membership only, not folder or share permissions"
  (ServiceDesk-Toolkit/README.md); FolderPermissionManager browses and changes ACLs but gives
  no per-user verdict. Market: free auditors gate export (NTFS Permissions Auditor exports are
  Pro, $199 to $1,249), SolarWinds Permissions Analyzer is a free GUI with no ticket output;
  Netwrix's toolkit is commercial (recon-market "Files and permissions", pain 8). None of these
  produces a verdict plus ticket note for one user and one path.
- Builds on: AD-GroupMembership-Export nesting resolution (including the primary-group fix,
  SIGNALS 2026-10-14 trust breaker), FolderPermissionManager ACL reading, SMBTest share checks.
- Size guess: L (share-plus-NTFS precedence, Deny ordering and token groups must be right per
  P-001; a wrong YES is the costliest failure in this area).
- Why now / why us: it closes the gap between the two access tools the collection already has,
  and both halves of the logic exist. Being wrong here is high-risk, which argues for a
  cited, tested tool over a tech's reading of the Advanced Security dialog.

---

Ideas I considered and dropped: printer and certificate-expiry tools (recon-market pain 14:
no demand source found, and SIGNALS does not list them as drivers); an AD security scanner
(PingCastle/Purple Knight/Testimo already cover it, and AD-Audit exists; no reason this
collection would do it better).
