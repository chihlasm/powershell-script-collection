# Round 2: market analyst

Lens: what free and paid products already do, where they fall short, and what this collection
would do better. Read all six round-1 lists. Most lenses agree on the same core list: cloud
sign-in check, mailbox check, one-user sync check, RC4/NTLM readiness, workstation check and a
front door. That makes the market question sharper. Where a tool already exists, what is the
reason to build ours? New web checks this round are cited inline. One of them corrects my own
round-1 claim (entry 2).

---

### COMBINES Mailbox quick check + Compromised-account first look (+ the forwarding line of Leaver verification)
- Pitch: One read-only tool for one mailbox and its owner. It answers both "mail isn't
  arriving / I can't see the shared mailbox" and "I think I was hacked" from the same reads:
  forwarding, inbox rules, Full Access / Send As, size and hold, recent message trace, recent
  sign-ins and newly added MFA methods. Signs of a takeover always go to the top as "possible
  compromise: stop and escalate". Everything else reads as an ordinary mailbox verdict with a
  next step.
- Who and when: Tier 1/2 tech on any mailbox ticket. The tech often can't tell at first touch
  that "my emails are disappearing" is really a hidden rule left by an attacker. Two separate
  tools would make the tech guess which ticket it is, and that guess is the one they get wrong.
- Evidence: Four lenses proposed a mailbox check and security proposed the compromise look.
  They read the same objects, so building both doubles the Exchange connection and test work.
  SIGNALS 2026-10-16 [m365]: mailbox tickets take longer and are worked by hand in the EAC.
  Market, checked this round:
  - **Hawk** is the free, open-source tool that already exists for this, and it is the one a
    tech would find. It is a forensics collector, and its listing says it "focuses on data
    collection rather than automated detection", so it gives no verdict. v4.0, published
    2025-02-23, needs PS 5.0 plus ExchangeOnlineManagement, six Microsoft.Graph.* modules,
    PSFramework and **PSAppInsights**, an Application Insights telemetry library
    ([PowerShell Gallery: HAWK](https://www.powershellgallery.com/packages/HAWK)). Those
    installs conflict with P-003 on a client machine. The telemetry dependency conflicts with
    the "no telemetry" scope rule unless it is proven off (whether it sends data by default
    is unverified).
  - Paid BEC (business email compromise) investigation is sold as a service or SaaS: Kroll's
    fixed-fee automated report, RocketCyber's M365 login analyzer, Thomas Murray's Cloud BEC
    Hunter, which reviews inbox rules and auth methods per user (search summaries of vendor
    pages, [Kroll](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/business-email-compromise-bec),
    [RocketCyber](https://rocketcyber.com/?p=15422)). CIPP reportedly has BEC checks, but only a
    third-party page says so (not verified on docs.cipp.app). Either way it is hosted, which
    PRINCIPLES rules out.
  - So the gap is real but narrow. Collection exists for free, and verdicts exist for a fee.
    No local, no-install tool gives a verdict for one user, in plain English, with a ticket
    note.
  - Build note (P-001): message trace must use `Get-MessageTraceV2`. The old cmdlet began
    deprecating 2025-09-01 for worldwide tenants
    ([Get-MessageTrace](https://learn.microsoft.com/powershell/module/exchangepowershell/get-messagetrace)).
    Leave out Hawk's hidden-rule search: it used EWS impersonation and is marked BETA
    ([HAWK 1.5.0](https://www.powershellgallery.com/packages/HAWK/1.5.0)).
- Builds on: The Exchange Online connection and Graph REST calls in `Get-M365SecurityEvidence`.
  The SHA-256 evidence zip from `Entra-DeviceActivityTimeline`. The CheckId result contract.
  Security's guardrails (read-only scopes, print the tenant at the top, "could not check" for a
  missing P1 licence).
  The Leaver checker later reuses its forwarding and delegate reads rather than writing them a
  third time.
- Size guess: M (one connection, one set of reads, two verdict orderings).
- Why now / why us: The collection already has the Exchange and Graph plumbing and the
  "could not look vs found nothing" habit, which a compromise verdict needs most. The market
  offers only raw collection (Hawk) or a paid or hosted verdict. We would be the only local,
  free, verdict-first option, and that is a reason to build, not a clone.

### CHALLENGES NTLMv1 / RC4 "will this break?" readiness check (proposed by market, security, architect, manager)
- Pitch: Keep the idea, but correct the market claim behind it and narrow the build to what
  Microsoft's own free scripts don't do. In round 1 I wrote that a paid product (ADAudit Plus)
  was "the only packaged option found". That is wrong. Microsoft's Learn page links two free,
  MIT-licensed scripts for this exact job.
- Who and when: Unchanged. A senior engineer doing client reviews this quarter, and a tier-2
  tech on "the NAS or scanner stopped authenticating after patching".
- Evidence (checked this round):
  - "Detect and Remediate RC4 Usage in Kerberos" (updated 2026-04-13) tells admins to download
    `List-AccountKeys.ps1` and `Get-KerbEncryptionUsage.ps1` (with `-Encryption RC4`) from
    [microsoft/Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto) (MIT). They are
    run "on a domain controller, or connect remotely using Enter-PSSession". They are one DC
    at a time, print raw rows (Time, Requestor, Source, Target, Ticket, SessionKey), and give
    no verdict
    ([Learn page](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)).
  - The same page sets the gate this tool must enforce. RC4 detail appears in 4768/4769 on
    Server 2019 and later, and on Server 2016 only from the January 2025 cumulative update.
    A Server 2012/2012 R2 DC, which SIGNALS 2026-10-14 says still turns up, cannot show this
    detail, so the answer there is "can't tell", never "no RC4".
  - The page also lists the remediation cases a verdict can name in plain words. Account has
    no AES keys: reset the password. Processed msDS-SupportedEncryptionTypes lacks AES: fix
    the account or policy. Device can't do AES: replace it or exempt it explicitly. It also
    says Server 2025 DCs issue no RC4 TGTs at all.
  - The page's enctype table says `0x0` means "Not defined - defaults to RC4_HMAC_MD5". The
    CVE-2026-20833 KB says the KDC default moves to AES-SHA1 for undefined accounts from
    2026-04-14 updates. That is the conflict recon flagged. The verdict therefore has to
    depend on each DC's patch level, not on one hardcoded rule (P-001).
  - Microsoft's scripts don't cover NTLMv1 at all (the `BlockNTLMv1SSO` move to Enforce is
    this month, KB5066470).
- Builds on: Unchanged (lockout engine's multi-DC collection, `Test-ADAuditPolicy` gate,
  reference psd1 + parity test). Add a parity test that decodes the same sample events as
  Microsoft's scripts, so our field decoding is checked against the vendor's own.
- Size guess: M, unchanged. The spec gets narrower: everything that is new compared with
  Microsoft's scripts is the product. That means all DCs in one run, a per-DC "can this DC
  even log it" gate, KDCSVC 201-209, NTLMv1, a fix / exempt / retire verdict per account, and
  a client-readable page.
- Why now / why us: The value is not "nobody detects RC4". Microsoft does, for free. The value
  is turning per-DC raw rows into one domain answer that is honest about old DCs. That is the
  lockout tools' strength, and it is the only reason to build this instead of telling techs to
  run Microsoft's scripts. The pitch to Michael should say that plainly.

### CHALLENGES Workstation quick check / "Is this PC OK?" (proposed by user-in-the-moment, manager, newcomer)
- Pitch: Before building this, find out which RMM the MSP uses. An RMM already shows most of
  what the three cards list for every managed endpoint, and the MSP pays for it per device. If
  it is still built, cut it to what an RMM does not diagnose: domain trust (secure channel),
  time skew against the DC, the last Group Policy result and its errors, profile and OST size,
  and reachability of the user's DC and file server. Ship it as one door of the front door,
  not as a standalone tool.
- Who and when: Same moment ("my PC is slow or weird"), but the tech should look at the RMM
  first, because it is already open on their screen.
- Evidence: NinjaOne documents a Last Boot Time column, a "Needs reboot" filter with a
  pending-reboot notice on the device Overview, and per-device patch status
  ([pending reboots](https://www.ninjaone.com/docs/endpoint-management/device-reboots/pending-reboots/),
  [system uptime](https://www.ninjaone.com/docs/endpoint-management/hardware-inventory/show-system-uptime/),
  [patch dashboard](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/patch-management-dashboard/)).
  I found no doc for a disk-space field on that dashboard, so disk is not proven as covered.
  N-able RMM has dashboard health widgets as well
  ([N-able](https://documentation.n-able.com/remote-management/userguide/Content/Dashboard_Widgets.htm)).
  Restart, pending reboot and patching are table stakes in every RMM that recon priced
  (recon-market RMM rows). A second tool that disagrees with the RMM's reading creates the
  "which one is right?" trust problem SIGNALS records (trust breakers). All three round-1
  cards admit the idea has no SIGNALS entry. Recon-code shows the gap only in this repo, not
  in the tech's day.
- Builds on: The same parts as the round-1 cards. The trimmed checks reuse DC-Diagnostics
  (secure channel, w32tm) and DriveMap-Diagnostics' GPO evidence, which RMMs don't interpret.
- Size guess: S if trimmed to the domain-side checks; M as proposed.
- Why now / why us: An RMM is broad across endpoints but shallow about the domain. It reports
  "reboot pending", but not "this PC lost its trust with the domain" or "the drive-map GPO
  failed here". Only the domain-side half is something this collection would do better. Open
  question for Michael: which RMM is used, and do techs open it on desktop tickets?
