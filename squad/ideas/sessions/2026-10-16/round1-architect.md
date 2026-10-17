# Round 1: architect lens

Focus: "useful tools that we may not have currently." From this lens, the question is which
new tools can be built mostly from engines, queries and patterns the repo already has. Then
the next new tool costs days, not weeks, and every new tool produces the "checked / ruled out /
next step" handoff that the owner asked for (SIGNALS 2026-10-16 [escalation]).

Code facts below come from `recon-code.md` unless a file path is given. I confirmed these with grep:
`Get-M365SecurityEvidence/Get-M365SecurityEvidence.ps1:1080` already runs a per-user
`auditLogs/signIns` Graph query. `M365-SyncedUserFixes/SyncedUserFixes.Core.ps1:654,711,931`
already reads `Get-ADSyncRule` / `Get-ADSyncConnector`.
`AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1:149` reads `Get-ADSyncScheduler`. `ConvertTo-HtmlSafe`
is defined again in 6 files, and `Resolve-CompanionScript` exists twice (lockout and drive maps).

---

### Cloud sign-in check: "Can this user sign in to Microsoft 365?"
- Pitch: A twin of AD-UserQuickCheck for the cloud side. Give it a username and it answers YES / NO / PROBABLY NOT for M365, with the reason and what to do: blocked sign-in, a Conditional Access policy that failed, MFA not registered, a risky user, Smart Lockout, a sync conflict, or no licence. It reads the user's last sign-ins so the tech doesn't have to open the Entra portal and decode error codes.
- Who and when: A tier-1 tech on a "can't get into Outlook/Teams" call, with the client waiting. At a hybrid client they can run AD-UserQuickCheck and this together and see both halves.
- Evidence: SIGNALS 2026-10-16 [entra][m365] says these tickets take longer than the others. "Where techs leave the tools" lists Entra sign-in logs and the admin centers. Recon-code says no per-user cloud sign-in lookup exists. Market pain 6 says MFA state is not a single Graph field, so a tool that states what it can and cannot see is worth having. Microsoft's Sign-in diagnostic is portal-only, with no CLI (recon-market, Entra row).
- Builds on: the per-user signIns query and Graph auth/scope handling in `Get-M365SecurityEvidence` (line 1080). Password expiry and Smart Lockout reads from `Get-EntraPasswordPolicy`. The verdict and "What to do" structure of `AD-UserQuickCheck`. The CheckId result contract from `Network-QuickCheck`.
- Size guess: M. Most of the Graph calls already exist. The real work is the sign-in error-code table (it must be cited on Learn, P-001) and the evidence gate that tells "no sign-ins in the window" apart from "no AuditLog.Read.All consent".
- Why now / why us: Every hybrid client needs both halves, and the AD half is already the best-built tool in the bundle. PS 5.1 is a legitimate floor for Graph (root CLAUDE.md), so P-003 is not bent.

### Entra Connect sync check: "Why isn't this user (or attribute) syncing?"
- Pitch: Run it on the Entra Connect server with a username. It says whether the user is in a synced OU, whether a filter or custom rule excludes them, whether the attribute in question is in the connector's inclusion list, whether there is a sync error or duplicate proxyAddress/UPN for them, and when the last sync cycle ran. The answer is "will sync / won't sync because X / can't tell because Y."
- Who and when: A tech whose user exists in AD but is missing or stale in M365 ("new starter can't log in", "mobile number didn't update"). Today this means remoting to the Entra Connect server and opening Synchronization Service Manager.
- Evidence: Market pain 13: users silently not syncing while health looks green, with OU filters, custom rules, quarantine, and the DirSyncOverrides mobile-number case. Microsoft's own troubleshooting walks the same checks (tshoot-connect-objectsync). SIGNALS: clients are mostly hybrid; Entra and M365 tickets are slow.
- Builds on: the `Get-ADSyncRule` / `Get-ADSyncConnector` / AttributeInclusionList reading in `SyncedUserFixes.Core.ps1` (already tested with mocks and real parameter names). The `Get-ADSyncScheduler` staging check in `Test-EntraConnectReadiness.ps1`. The evidence-gate pattern (P-001). Read-only.
- Size guess: M.
- Why now / why us: The repo has already paid to learn the ADSync cmdlets and their quirks (staging mode, inclusion lists) for a tool that changes things. A read-only diagnostic reuses that knowledge at low risk, and it is the third leg (AD + sync + cloud) next to the cloud sign-in check.

### FSLogix "temporary profile" investigation (third case-folder orchestrator)
- Pitch: Give it a username and a session host (or let it find where the user last logged on). It runs the FSLogix triage, log parser, storage-event correlation and event export the repo already has, then gives one ranked verdict: profile locked on another host, share permission (including the computer account), Cloud Cache unreachable, frxsvc not running or crashed, an existing local profile, or a disk full. The output is a case folder with SUMMARY.txt.
- Who and when: A tech on "user got a temp profile / desktop is blank" with a Citrix, RDS or AVD user who is waiting. This is the most repeated FSLogix ticket.
- Evidence: Market pain 11 found at least 5 Microsoft Q&A threads with distinct root causes, and the Learn known-issues page (frxsvc crash, event 26 is expected on Entra-only devices, which is a trust trap the verdict must handle). SIGNALS: Citrix/FSLogix/AVD are the slowest tickets, and techs remote to VDAs to read event logs.
- Builds on: `Citrix-FSLogix-Triage` (CheckId contract), `Parse-FSLogixLogs`, `Get-FSLogixStorageEvents`, `RDS-FSLogix-EventExport`, `Get-CitrixSessions` (where did the user log on), and the gate -> collect -> verdict -> SUMMARY -> tabbed HTML pattern from `Invoke-ADLockoutInvestigation` / `Invoke-DriveMapInvestigation`.
- Size guess: M. Every collector exists. The new work is per-user correlation and the ranked cause table.
- Why now / why us: No new data sources are needed, only a verdict engine over pieces already in the bundle. Platform-neutral (Citrix, RDS, AVD), which matches the "no single platform" client fact.

### Mailbox quick check (Exchange Online, read-only)
- Pitch: Give it a mailbox and get a one-screen answer to the usual mailbox tickets: who has Full Access / Send As / Send on Behalf, whether forwarding or inbox rules redirect mail out, how full the mailbox and archive are, whether it is shared, licensed or on hold, and the last few message-trace results for a given sender. Each finding comes with a plain-English next step.
- Who and when: "I can't see the shared mailbox", "mail isn't arriving", "mailbox full" calls, which today are clicked through the Exchange admin center by hand.
- Evidence: SIGNALS 2026-10-16 lists the Exchange admin center as a place techs leave the tools, and m365/mailbox as a slow ticket driver. Recon-code: grep for `Get-Mailbox` / `Get-MessageTrace` returns nothing. Market item 14 found no tool covering mailbox-permission pain (an open demand signal, not proof).
- Builds on: the `Connect-ExchangeOnline` handling in `Get-M365SecurityEvidence.ps1:557`, the CheckId contract, and the HTML report style.
- Size guess: M. Note for P-001: the message-trace cmdlets have been changing in Exchange Online, so verify the current cmdlet on Learn before building.
- Why now / why us: It closes the biggest blank on the coverage map, and the EXO connection plumbing already exists.

### NTLMv1 / RC4 readiness check (this month's outage source)
- Pitch: A domain-wide scan of the DCs' new NTLM and Kerberos audit events. It lists which machines, accounts and apps still use NTLMv1 or RC4 Kerberos, so they can be fixed before Microsoft's enforcement turns them into sign-in failures. When the auditing isn't on, it says so and shows how to turn it on.
- Who and when: A senior admin doing proactive work at each client this quarter. Also a tier-2 tech facing "an app/scanner/NAS stopped authenticating after patching".
- Evidence: Recon-market, Recent moves: enhanced NTLM auditing (events 4020-4033) reaches Server 2019/2022 in updates from 2026-10-13. The `BlockNTLMv1SSO` default changes to Enforce in October 2026. RC4 audit events 201-209 and the enforcement timeline (third-party sources, so verify on Learn). Sign-in failures are a top ticket driver (SIGNALS).
- Builds on: the lockout engine's multi-DC `Get-WinEvent` collection, the audit-policy gate (`Test-ADAuditPolicy.ps1`), the reference-data file plus parity-test pattern (`LockoutReference.psd1`), and the ranked-by-count domain view from `Get-LockoutHistory`.
- Size guess: M.
- Why now / why us: The deadline is real and dated: enforcement starts now and will cause tickets. The repo already reads DC Security logs across all DCs with a "could not look vs found nothing" gate, which is exactly what this needs. Commercial tools (ADAudit Plus) charge for it.

### AVD session host check
- Pitch: Like Get-CitrixVDAResources, but for Azure Virtual Desktop. It lists every session host in a host pool: available or unavailable, drain mode, which users are on it, last heartbeat, and failed health checks. It ends with a verdict per host and "what to do" (for example "host is in drain mode: users can't land here").
- Who and when: A tech on "can't connect to my AVD desktop" who today opens the Azure portal to find the session host state.
- Evidence: SIGNALS: clients run Citrix, AVD and RDS, AVD tickets are slow, and techs use "the Azure portal for session hosts". Recon-code: no AVD diagnostics exist (grep finds AVD only in installer and comment contexts).
- Builds on: the Az connection pattern in `Get-AzureFilesFSLogixProfiles` (Connect-AzAccount, subscription discovery), the fleet verdict rollup from `Citrix-FSLogix-HealthCollector`, and the output format of `Get-CitrixVDAResources`. Then it feeds the FSLogix temp-profile orchestrator above.
- Size guess: M. It needs the Az.DesktopVirtualization module, so it must handle "module missing" at runtime (try/catch Import-Module) like the other Az tools.
- Why now / why us: Citrix is covered in depth and AVD is not at all, so this closes a platform gap rather than adding depth where there is already plenty.

### Shared case kit: ship one file in every folder to make the next ten tools cheap
- Pitch: One small file (`CaseKit.ps1`) that the bundle builder copies into every tool folder. It holds the pieces each new tool keeps rewriting: HTML-safe encoding, the dark tabbed report shell, the SUMMARY.txt writer, the CheckId result object, and a "ticket note" block (Checked / Ruled out / Found / Next step) ready to paste into ConnectWise. A parity test fails if any folder's copy drifts.
- Who and when: Behind the scenes for whoever builds the next tool. Every tech benefits, because every tool ends with the same paste-ready handoff block.
- Evidence: `ConvertTo-HtmlSafe` is redefined in 6 or more files, `Resolve-CompanionScript` in 2, and about 15 hand-rolled HTML renderers exist (recon-code engine 6). SIGNALS 2026-10-16 [escalation]: the owner's top asks are a handoff summary and a ticket note, and the reasoning is "not captured today". A parity test for copied shared data already exists (`AD-LockoutDiagnostics/Tests/SharedReferenceParity.Tests.ps1`), so the copy-per-folder model has a precedent.
- Builds on: the bundle builder manifest, the SharedReferenceParity test pattern, the CheckId contract, and the existing SUMMARY.txt writers.
- Size guess: M (build the kit and adopt it in the new tools above). Older tools adopt it later, one at a time; this is not a rewrite.
- Why now / why us: The principles say a shared piece is allowed "when it clearly earns its place (one fix reaches many tools)" and still ships inside each folder. This is that case. Six new tools are proposed above, and without the kit each would copy the encoder and report shell again.

### Bold bet: "What's the problem?" front door that routes, runs and writes the handoff
- Pitch: One double-click launcher at the top of the bundle. It asks the tech in plain English what the client is reporting ("locked out", "drive missing", "temp profile", "can't sign in to Outlook"…), asks only for the inputs needed (username, machine), runs the right investigation, and leaves one handoff note: what was checked, what was ruled out, the verdict, and the next step or who to escalate to.
- Who and when: Every tier-1 tech at the start of a ticket, especially when they don't know which tool to use. It also gives Michael a consistent record when the ticket is escalated.
- Evidence: SIGNALS [bundle]: techs don't know which tools exist or when to use them, and the output is too technical. SIGNALS [escalation]: the reasoning behind escalations is not captured. Repo history: the consolidation rounds happened because it was unclear which tool to run. `Run-AccessReport.bat` (plain-English menu) and `Start-LockoutWorkbench.ps1` (menu, no account name needed) show the pattern works on a small scale. `Citrix-PerfTriage` already runs sibling tools in separate 5.1 processes with time limits, so the orchestration mechanism exists.
- Builds on: the CheckId `-PassThru -Quiet` contract (each tool returns Status / Summary / Evidence / RecommendedNextSteps), the PerfTriage child-process runner, the case kit's ticket note, and the bundle layout (siblings are guaranteed to sit beside it inside the bundle, so it doesn't break the self-contained rule).
- Size guess: L overall. It can be built in steps: a menu over 4 existing tools first (lockout, user quick check, drive map, FSLogix triage), then each new tool from this list plugs in as it ships.
- Why now / why us: The repo has the pieces: verdict engines, a common result shape in two tools, a child-process orchestrator, and a bundle that puts everything side by side. What's missing is the front door that matches how techs start a ticket (by symptom, not by tool name). Commercial RMMs sell script libraries, not symptom-led verdicts with a handoff.
