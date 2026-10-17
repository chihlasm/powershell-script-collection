# Round 1: manager-or-buyer lens (the MSP service-desk lead)

Focus: useful tools the collection does not have yet. From this lens, a new tool earns its
place if it does at least one of these: lets the average tech close the ticket at first
touch, leaves evidence of what was checked, or catches a recurring problem across clients
before the client calls. Every idea below ends in a decision a tech or a client has to make.

---

### Cloud Sign-in Quick Check ("can this user sign in to Microsoft 365?")
- Pitch: The cloud version of AD-UserQuickCheck. Type a user's name and get YES / NO / PROBABLY NOT for Microsoft 365, with the reason (blocked, MFA not set up, a Conditional Access policy refused it, no licence, sync broken, account disabled in the cloud) and what to do next.
- Who and when: Tier-1 tech, client on the phone saying "Outlook keeps asking for my password" or "I can't get into Teams". Today the tech opens the Entra admin center, finds the sign-in logs, and has to read error codes alone.
- Evidence: SIGNALS 2026-10-16 [entra] [m365] "take longer than the others"; SIGNALS "Where techs leave the tools": Entra/M365 admin centers and sign-in logs. recon-code "Not found anywhere": no per-user cloud sign-in lookup. recon-market: Microsoft's Sign-in diagnostic is portal-only with no command-line version; MFA state is not one Graph field (registered methods only, report needs Entra P1). Sign-in log access needs Entra P1 per tenant, so the tool must say "this tenant has no sign-in logs to read" instead of "no failures" (P-001).
- Builds on: `Get-M365SecurityEvidence` already calls `auditLogs/signIns`, conditional access and auth-method endpoints with delegated Graph; `AD-UserQuickCheck` verdict shape; the CheckId result contract; `Test-EntraConnectReadiness` for the hybrid half.
- Size guess: M
- Why now / why us: Clients are mostly hybrid, so the on-prem quick check only answers half the question. Pairing the AD verdict and the cloud verdict for the same person in one ticket is something no portal does.

### Mailbox Quick Check ("what is wrong with this mailbox?")
- Pitch: One run against a single mailbox answers the common ticket questions: who else can open it, is mail being forwarded somewhere, are there inbox rules that move or delete mail, is it full, is it on hold. Suspicious items (forwarding to an outside address, rules that delete mail) go to the top as "possible compromise: escalate now".
- Who and when: Tech with "I'm not getting emails", "my mail disappears", or "give Jane access to the sales mailbox" tickets. Also the first five minutes of a suspected compromised account, where the speed of the answer matters.
- Evidence: SIGNALS 2026-10-16 ticket drivers [m365] mailbox, and "Exchange admin center" in the list of places techs check by hand. recon-code: grep for `Get-Mailbox` / `Get-MessageTrace` found nothing; no mailbox troubleshooting tool exists. recon-market item 14: mailbox permissions pain has no tool in the sources checked (an open gap, not evidence that nobody needs it).
- Builds on: `Get-M365SecurityEvidence` already connects to Exchange Online (optional mailbox-type triage), so the connection and module handling exist.
- Size guess: M
- Why now / why us: A forwarding rule to an outside address is the evidence an insurer or client asks for after an incident. The lead wants it found by the tier-1 tech on the first call, not by a senior engineer two days later.

### "Why isn't this user syncing?" Entra Connect object check
- Pitch: For one AD user, show whether Entra Connect should be syncing them and why it isn't: OU out of scope, duplicate UPN or proxy address, attribute value the cloud refuses, user moved OUs, or a sync rule filtering them out. Ends with one plain line, for example "Out of sync scope: this OU is not selected. Ask a senior to add it."
- Who and when: Tech with "new starter has no mailbox" or "user changed name and Teams still shows the old one" at a hybrid client. Today this goes straight to escalation because the Synchronization Service Manager is a senior-only tool.
- Evidence: recon-market pain item 13: several Microsoft Q&A threads where sync shows healthy while specific users are missing; Microsoft's troubleshooting lists OU filtering, UPN mismatch, and duplicate attributes (IdFix). SIGNALS: clients mostly hybrid; techs escalate because they don't know how to resolve the issue.
- Builds on: `M365-SyncedUserFixes` already reads and builds Entra Connect sync rules; `AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1` already checks the server, service and event channels.
- Size guess: M
- Why now / why us: The repo already knows how to talk to the Entra Connect server, so this is the shortest route to a common escalation that currently has no first-touch answer.

### NTLMv1 and RC4 break-risk check (before the October 2026 changes cause sign-in tickets)
- Pitch: Scan a client's domain controllers for sign-ins that still use NTLMv1 or Kerberos RC4 and list the devices, service accounts and apps involved, before Microsoft's enforcement changes turn them into "can't sign in" and lockout tickets. The output is a short list with a decision for each item: fix, exempt, or retire.
- Who and when: Service-desk lead and senior engineer, once per client this quarter, and again after each Patch Tuesday. Catching this early is the difference between a planned change and a Monday of tickets.
- Evidence: recon-market "Recent moves": `BlockNTLMv1SSO` default is set to change from Audit to Enforce in October 2026 (support.microsoft.com/help/5066470); enhanced NTLM auditing events 4020-4033 arrive on Server 2019/2022 in updates from 2026-10-13 (KB5064479, dates labelled tentative); RC4 phase-out timeline from third-party sources (KB number conflicting, must be confirmed on Microsoft Learn per P-001). ManageEngine sells RC4 usage reporting as a paid feature. SIGNALS: lockout and sign-in are top ticket drivers.
- Builds on: `AD-LockoutDiagnostics` already has the DC event-collection engine, the audit-policy gate (P-001 "could not look" vs "found nothing"), and `LockoutReference.psd1` for verified event IDs.
- Size guess: M
- Why now / why us: The date is this month. The audit-gate pattern is exactly right here, because "no NTLMv1 found" means nothing unless the tool confirms the auditing events are being written.

### Server End-of-Support Register (per client, ready for the account review)
- Pitch: Discover every Windows Server in a client's domain and list its OS version, support end date, last sign-in, and what roles it seems to hold (DC, file, RDS, SQL), sorted by risk. This gives the account manager a one-page "these 4 servers are out of support; this is what runs on them" sheet for the client.
- Who and when: Service-desk lead or account manager before a quarterly review, or during a cyber-insurance renewal that asks "do you run unsupported operating systems?".
- Evidence: recon-market: Server 2012/2012 R2 final ESU year ended 2026-10-13, and Server 2016 extended support ends 2027-01-12 (secondary sources; confirm dates on Microsoft Learn lifecycle pages); third parties sell a fixed-price assessment for this ($2,950 for up to 25 hosts). SIGNALS 2026-10-14: Server 2012/2012 R2 still turns up at clients. SIGNALS manual chore: "turning tool output into something a client can read".
- Builds on: `AD-Audit` already enumerates computers and OS attributes; `Hyper-V-Inventory` / `VMware-Inventory` for host context; the existing dark-theme HTML renderers.
- Size guess: S
- Why now / why us: Every client needs this answer within the next three months, and the data is already in AD. It turns the toolkit into something that also produces client-facing value, which a buyer notices.

### Workstation Quick Check ("what is wrong with this user's PC?")
- Pitch: Point it at a user's computer by name and get a verdict on the usual suspects: nearly full disk, a pending reboot, days since restart, recent crashes or unexpected shutdowns, failing Windows updates, a huge profile or Outlook data file, and whether it can reach the domain controller and the file server. It ends with a paste-ready note listing what was checked.
- Who and when: Tier-1 tech with "my computer is slow" or "Outlook is broken" on a physical desktop, which is the most common ticket shape the bundle does not cover today.
- Evidence: recon-code "Gaps": no workstation/endpoint health tool; only Entra-DeviceActivityTimeline and Network-QuickCheck run on an endpoint. SIGNALS core problem: owner wants to see what was checked and ruled out. SIGNALS: some clients have little or no VDI, so desktop tickets are their whole service desk.
- Builds on: `Citrix-FSLogix-HealthCollector` sampled CIM with DCOM fallback and verdict rollup; `Entra-DeviceActivityTimeline` System events 41/6008/1074; `Network-QuickCheck` reachability and CheckId contract.
- Size guess: M
- Why now / why us: The VDI tools are already strong. This applies the same verdict-first pattern to the clients that have no VDI, using parts that already exist.

### Ticket Note and Handoff Builder
- Pitch: A small tool a tech runs at the end of (or during) a ticket. It gathers the SUMMARY / verdict files that every tool run in this session left behind, asks two plain questions ("what did the user report?", "what did you try?"), and writes one ConnectWise-pasteable note: checked, ruled out, found, next step, with the paths to the evidence. Nothing is sent anywhere; the tech copies it.
- Who and when: Any tech, at the moment of escalating or closing. The lead reads it on escalation and sees the reasoning, not just "user still can't log in".
- Evidence: SIGNALS 2026-10-16 owner [escalation], all three "core problem" entries: what the tech checked and how they ruled things out is not captured; the most useful outputs are a handoff summary and a ready-to-paste ConnectWise Manage note. recon-code: tools already write SUMMARY.txt "for pasting into a ticket" and CheckId results, but nothing combines them across tools. PRINCIPLES: no push to the PSA, so the output is a local text block and clipboard only.
- Builds on: CheckId result contract (`Network-QuickCheck`, `Citrix-FSLogix-Triage`), case-folder SUMMARY.txt (`AD-LockoutDiagnostics`, `DriveMap-Diagnostics`).
- Size guess: M
- Why now / why us: This is the owner's stated top request. It is also what makes escalation consistent no matter which tech picked up the ticket.

### Bold bet: "Start Here" symptom-first triage front door
- Pitch: One double-click launcher in the bundle that asks what the user is saying, in their words ("can't sign in", "drive missing", "Citrix slow", "email problem", "PC slow"). It runs the right quick check for that symptom, shows the verdict in plain English, and offers the next deeper tool only if the quick check could not answer. Every run is recorded in a ticket folder, so the Handoff Builder above has a full trail of what was checked.
- Who and when: Every tier-1 tech, at the start of every ticket in the covered areas. It replaces "which of the 60 tools do I run?" with one question the tech can answer.
- Evidence: SIGNALS 2026-10-16 [bundle] adoption: techs don't know which tools exist or when to use each, output is too technical, the bundle isn't a habit; Michael runs most tools himself. SIGNALS repo-history: consolidation rounds happened because it was unclear which tool to run. `AD-GroupMembership-Export/Run-AccessReport.bat` proves the double-click, plain-English menu pattern already works here.
- Builds on: the bundle builder manifest (`ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`), `Citrix-PerfTriage`'s pattern of running sibling tools in separate 5.1 processes with time limits, and the CheckId contract for a common verdict shape.
- Size guess: L
- Why now / why us: The tools are good, but the people they are meant for do not run them. A front door that makes the average tech follow the best tech's path is what a service-desk lead would pay for. It depends on the new quick checks above to cover the cloud, mailbox and desktop symptoms. Without those, about half of the doors lead nowhere.
