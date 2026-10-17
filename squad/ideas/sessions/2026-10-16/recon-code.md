# Code recon dossier, 2026-10-16

Focus: "useful tools that we may not have currently". Facts only. Paths are relative to the repo root
(C:\Users\micha\source\repos\powershell-script-collection). Items marked (unsure) were not fully verified.

Read for this: squad/SQUAD.md, squad/BACKLOG.md, squad/squad.config.json, squad/DECISIONS.md,
squad/ideas/SIGNALS.md, PRINCIPLES.md, GRAVEYARD.md, lenses/architect.md, root README.md, ServiceDesk-Toolkit/*,
and the READMEs and script headers of the tools named below. I did not read every script body.

## Capabilities today

Coverage map by troubleshooting area (a service-desk "ticket driver" per SIGNALS.md).

### Sign-in and lockout (on-prem AD)
- "Can this user sign in right now?" YES / NO / PROBABLY NOT with reasons and a "What to do" per reason; checks disabled, locked, expired account, expired or must-change password, logon-to / logon-hours restrictions, smart-card-only, per-DC last logon and bad-password counts, large token (many groups). Read-only. `AD-UserQuickCheck/README.md`, `AD-UserQuickCheck/Get-ADUserQuickCheck.ps1`.
- Lockout workbench: scans the domain for who is locking out (menu, no account name needed), then runs a full investigation into a case folder with SUMMARY.txt and tabbed HTML. `AD-LockoutDiagnostics/README.md`, `AD-LockoutDiagnostics/Start-LockoutWorkbench.ps1`, `AD-LockoutDiagnostics/Invoke-ADLockoutInvestigation.ps1`.
- Lockout pieces, each runnable alone: audit-policy gate (are 4740/4625/4771 even logged), domain-wide lockout history ranked by count, per-account deep dive with FGPP-aware policy and Entra Connect (PHS/PTA) evidence, multi-forest forensics via non-replicated badPwdCount, DC Security-log retention sizing (changes DCs only with -Apply), source-device identity, cause ranking ("what do I fix on that machine"), live watcher, source-machine power/lock timeline. `AD-LockoutDiagnostics/README.md` (table of scripts).
- Entra Connect readiness preflight (service, event provider and log-channel checks). `AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1`.
- Privileged access: "why is this user an admin?" (direct, nested, primary group, adminCount, SID history, SPNs, delegated ACLs) and a domain-wide privileged-access CSV. `Find-PrivilegedAccessPaths/README.md`.

### Access and permissions (who has access to what)
- Group membership export plus user-centric HTML report with People / Groups / Overlap / Nesting tabs, duplicate-access flagging, zipped to C:\ADReports; double-click `Run-AccessReport.bat` launcher with plain-English menu. `AD-GroupMembership-Export/README.md`, `AD-GroupMembership-Export/Export-ADGroupMembership.ps1`, `AD-GroupMembership-Export/Start-AccessReport.ps1`. Group membership only, not folder or share permissions (`ServiceDesk-Toolkit/README.md`).
- NTFS permissions browser GUI (changes ACLs). `FolderPermissionManager/FolderPermissionManager-GUI.ps1`, `FolderPermissionManager/README.md`.
- Local Administrators group add/remove (changes). `LocalAdminManager/README.md`.

### Drive maps and logon scripts
- Why is a mapped drive missing: gate on GPP logging, endpoint evidence, GPO-side check, SYSVOL script search, ranked verdict, tabbed HTML case report. `DriveMap-Diagnostics/README.md`, `DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1`.
- Domain-wide GPO drive-map audit with conflicts and dead server paths; SYSVOL logon-script text search; live watcher that catches the disappearance (-Install adds a monitoring task). `DriveMap-Diagnostics/Audit-GPDriveMaps.ps1`, `DriveMap-Diagnostics/Search-SYSVOLScripts.ps1`, `DriveMap-Diagnostics/Watch-DriveMapActivity.ps1`.
- Known blind spot, stated by the tool: the "every other logon" Fast Logon Optimization cause is never confirmed automatically. `DriveMap-Diagnostics/README.md` ("This toolkit cannot confirm this condition").

### Citrix, RDS, FSLogix, AVD
- FSLogix check of one session host: services, Enabled flag, VHDLocations vs CCDLocations, recent events, free disk, profile share reachable. `Citrix-FSLogix-Triage/README.md`.
- Fleet health verdict per host (sampled CPU/memory/disk/queue plus Citrix/RDS/FSLogix events; Healthy/Degraded/Critical/Unreachable). Works with broker discovery or explicit server list. `Citrix-FSLogix-HealthCollector/README.md`.
- Fleet CPU/memory/disk/uptime per VDA from the Delivery Controller. `Get-CitrixVDAResources/README.md`.
- Per-user and per-process RAM on a multi-session server. `Get-RAM-Usage/` (README listed in `ServiceDesk-Toolkit/README.md`).
- RDS and FSLogix event-log export for a time window, many hosts, HTML + CSV. `RDS-FSLogix-EventExport/README.md`.
- FSLogix text-log parser (load/unload durations, re-attach loops, container fill %, compaction, ERROR codes). `Parse-FSLogixLogs/Parse-FSLogixLogs.ps1`.
- FSLogix storage events (SMB/disk) correlated to re-attaches. `Get-FSLogixStorageEvents/Get-FSLogixStorageEvents.ps1` (per `Citrix-PerfTriage/README.md`).
- One-command "Citrix is slow" orchestrator running 7 steps across hosts and Hyper-V hosts, with a portable kit (-CreateKit) and a hand-off package when Hyper-V access is refused. `Citrix-PerfTriage/README.md`, `Citrix-PerfTriage/Invoke-CitrixPerfTriage.ps1`.
- Deep single-VDA diagnostics and storage monitor. `CitrixVDADiagnostics/CitrixVDA-Consolidated.ps1`, `CitrixVDADiagnostics/Monitor-CitrixFSLogixStorage.ps1`.
- Who is logged on to which VDA (Broker SDK). `Get-CitrixSessions/README.md`.
- FSLogix containers on Azure Files with owner/size/last-modified via Azure APIs (read-only). `Get-AzureFilesFSLogixProfiles/README.md`.
- FSLogix VHDX scan and repair (changes); miExcel add-in removal from profiles (changes); VDA storage cleanup (changes); profile-settings backup/restore of bookmarks, Quick Access, taskbar, display, browser passwords. `FSLogix-ProfileDiskRepair/`, `FSLogix-miExcel-Cleanup/`, `Storage Space Clean-up/`, `FSLogix-Profile-Backup/README.md`.
- Install helpers: Teams for Citrix/RDS/AVD (`-DeploymentType`), Nerdio new Teams, Adobe Acrobat replace, Citrix Workspace app clean reinstall. `Install-TeamsOnVirtualDesktop/README.md`, `Migrate-AdobeProducts/`, `CitrixWorkspaceApp_Remediation/VOA_CitrixRemediation.ps1`.
- AVD-specific diagnostics (host pool, session host health, Azure portal checks) were NOT found: grep for AVD / Azure Virtual Desktop in *.ps1 only hits Install-TeamsOnVirtualDesktop, Get-FSLogixStorageEvents, Citrix-FSLogix-Triage (comments or deployment mode). The AVD design docs are `docs/plans/2026-05-20-avd-deployment-mode-design.md` (Teams installer only, unsure of other scope).

### Microsoft 365 and Entra
- Tenant password policy, smart lockout, security defaults, per-user effective password expiry; xlsx or CSV. Graph delegated scopes. `Get-EntraPasswordPolicy/README.md`.
- MFA, Conditional Access policies, password policy, privileged-role hygiene, legacy-auth sign-ins, optional Exchange mailbox-type triage; evidence folder + HTML mapped to attestation control families. Graph REST via Invoke-MgGraphRequest, Microsoft.Graph.Authentication only. `Get-M365SecurityEvidence/Get-M365SecurityEvidence.ps1` (no README found in folder).
- Entra-joined device activity timeline (boot, sleep, wake, lock/unlock, sign-in) run on the device, zip with SHA-256. `Entra-DeviceActivityTimeline/README.md`.
- Block M365 sign-in / hide from GAL for AD-synced users by writing marker attributes (changes AD; log in Logs\Changes_<date>.csv) and checking or building the Entra Connect rule that acts on them. `M365-SyncedUserFixes/README.md`.
- Not found anywhere in the repo: per-user cloud sign-in log lookup, mailbox/Exchange troubleshooting (message trace, permissions, forwarding), licensing, Intune/device compliance, Teams, OneDrive/SharePoint. Evidence: grep for `Get-Mailbox`, `Get-MessageTrace`, `Get-MgDevice` returned none; only Get-M365SecurityEvidence calls signIns/conditionalAccess endpoints (file above). Note SIGNALS.md says M365/Entra/mailbox tickets are a time sink and techs check Entra/Exchange admin centers by hand (`squad/ideas/SIGNALS.md`, "Where techs leave the tools").

### Domain and infrastructure audit
- Whole-domain audit (users, groups, computers, password policy per NIST 800-63B, privileged access, security, infrastructure, OUs, replication) HTML + CSV, with WinForms GUI launcher. `AD-Audit/README.md`.
- GPO audit (duplicates by SHA256, conflicts, empty/unlinked/stale/disabled, permissions, FSLogix settings). `AD-GroupPolicy-Audit/README.md`.
- AD replication plus DFSR / DFS Namespaces health. `ADReplicationDiagnostics/README.md`.
- Single-DC health snapshot run on the DC (dcdiag, repadmin, w32tm, secure channel, reboot history, incident-date windows). `DC-Diagnostics/README.md`.
- DHCP failover audit across authorized servers. `DHCP-Audit/README.md`.
- DNS record search / stale / zone-compare browser GUI. `Search-DNSRecords/README.md`.

### Servers, storage, virtualization
- Disk and folder usage HTML report; diskspd storage benchmark; read-only filesystem corruption and SQL corruption diagnostics; Hyper-V host evidence and inventory; VMware inventory. `Drive-Storage-Report/`, `DiskSpdDiagnostic/README.md`, `Storage-Corruption-Diagnostic/`, `Sql-Corruption-Diagnostic/`, `HyperV-Host-Diagnostics/`, `Hyper-V-Inventory/`, `VMware-Inventory/`.
- File moves and cleanups (change things): robocopy migration GUI, copy file to many servers GUI, delete old folders, schedule a reboot. `RobocopyMigration/`, `CopyFileToServer/`, `DeleteOldFolders/`, `Schedule-Reboot/`.

### Network
- Reachability YES / PARTLY / NO (DNS, ping, TCP ports, gateway), PS 3.0, exit codes. `Network-QuickCheck/README.md`.
- Interactive menu of 12 network commands (ping, tracert, DNS, port, Wi-Fi, SSL cert, MTU, port scan) with transcript logging. `Network-Troubleshooting-Palette/README.md`.
- SMB step-by-step diagnostic (445, sessions, dialect, access, map). `SMBTest/` (root README "SMB Diagnostic" section).
- Juniper console setup GUI, Juniper device manager (work in progress), Python JunOS audit. `Juniper-ConsoleSetup/`, `Juniper-DeviceManager/`, `JunOS - Info/README.md`.

### Software and desktop fixes (change things)
- MSI install from share/URL, Chocolatey install with private repo, printer defaults, invisible cursor fix. `Install-MSI/`, `Install-Chocolatey-VC3/`, `Set-PrinterDefaults/`, `CursorFix/README.md`.

### Gaps visible in the tool index (facts about what has no tool; not recommendations)
- No tool for: workstation/endpoint health on a user's PC (disk, updates, startup, profile size, Outlook/OST, printers beyond defaults, VPN, WiFi history). Only Entra-DeviceActivityTimeline and Network-QuickCheck run on an endpoint. (Based on tool index in `README.md`; unsure about scripts not opened.)
- No tool for: printing diagnostics (only `Set-PrinterDefaults`), certificates expiry (only SSL cert check in the palette), Windows Update/patch state fleet-wide (only a pending-updates check inside `CitrixVDADiagnostics`), backup status, DNS/DHCP troubleshooting from a client view, Outlook/Exchange, Teams, SharePoint/OneDrive, Intune, AVD host pools.
- Nothing captures what a tech checked and ruled out (see Data section).

## Data it collects or can reach

All output is local files under -OutputPath or a Reports\ / case folder beside the script (`squad/ideas/PRINCIPLES.md`, "Scope boundaries"; `squad/SQUAD.md`).

- AD attributes via ActiveDirectory module: account flags, lockout state, badPwdCount, lastLogon per DC, pwdLastSet, group membership and nesting, primaryGroupID, adminCount, SID history, SPNs, ACLs on domain root/OUs, FGPP, GPOs and GPO XML, trusts, sites, FSMO. `AD-UserQuickCheck/README.md`, `Find-PrivilegedAccessPaths/README.md`, `AD-Audit/README.md`, `AD-GroupPolicy-Audit/README.md`.
- Windows event logs (remote, Get-WinEvent): Security 4740/4625/4771/4724/4800-4803/4624/4647/4778-4779; System 12/13/41/42/107/506/507/1074/6008; Kernel-Power; Directory Service, DNS Server, DFS Replication; FSLogix and Remote Desktop channels; Entra Connect ADSync/PTA/PHS events 601-668. `AD-LockoutDiagnostics/README.md`, `DC-Diagnostics/README.md`, `Citrix-FSLogix-Triage/README.md`, `Entra-DeviceActivityTimeline/README.md`.
- Registry/services/CIM on remote hosts: FSLogix keys (HKLM\SOFTWARE\FSLogix\Profiles), frxsvc/frxccds, GPP logging and tracing flags, perf counters, disk, RAM per user. `Citrix-FSLogix-Triage/README.md`, `DriveMap-Diagnostics/README.md`, `Get-RAM-Usage/`.
- Citrix Broker SDK: VDAs, registration state, sessions, delivery groups, catalogs. `Get-CitrixSessions/README.md`, `Get-CitrixVDAResources/README.md`.
- FSLogix log files (Profile-*.log, ODFC-*.log, UTF-16LE). `Parse-FSLogixLogs/Parse-FSLogixLogs.ps1`.
- Microsoft Graph (delegated): organization, domains, groupSettings, security-defaults policy, users, auditLogs/signIns, conditionalAccess policies, directory roles, authentication methods registration. `Get-EntraPasswordPolicy/README.md`, `Get-M365SecurityEvidence/Get-M365SecurityEvidence.ps1` (scopes in .NOTES).
- Exchange Online (optional, mailbox type only). `Get-M365SecurityEvidence/Get-M365SecurityEvidence.ps1`.
- Azure Files via Az.Storage / Azure APIs: subscriptions, storage accounts, shares, container file names, sizes, last-modified. `Get-AzureFilesFSLogixProfiles/README.md`.
- SYSVOL logon scripts and GPP drive-map XML. `DriveMap-Diagnostics/README.md`.
- DNS zones/records, DHCP scopes and failover state, DFSR backlog counts, Hyper-V and VMware inventory. `Search-DNSRecords/README.md`, `DHCP-Audit/README.md`, `ADReplicationDiagnostics/README.md`.
- Browser bookmarks, Quick Access, taskbar, display settings, saved-password export instructions from user profiles / VHDX. `FSLogix-Profile-Backup/README.md` (flagged personal-data in `squad/squad.config.json` riskProfiles).
- Change logs: only M365-SyncedUserFixes writes an audit CSV of its own changes (who/when/person/old/new value). `M365-SyncedUserFixes/README.md`.
- NOT captured anywhere: the tech's own actions, what they checked, or what they ruled out. SIGNALS.md records this as the owner's core request (`squad/ideas/SIGNALS.md`, "The core problem"). The closest artifacts are the per-tool plain-text summaries: SUMMARY.txt "for pasting into a ticket" (`AD-LockoutDiagnostics/Invoke-ADLockoutInvestigation.ps1` lines ~784, ~821), the FSLogix triage and network-check .txt reports (`Citrix-FSLogix-Triage/README.md`, `Network-QuickCheck/README.md`). I found no ConnectWise integration; grep for "ConnectWise" in *.ps1/*.md only hit docs/squad files (count shows hits in squad and docs, none in tool scripts).
- Sensitive output: case folders and reports hold client AD/tenant data; these folders are gitignored and excluded from the bundle (`ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`; `squad/SQUAD.md` "Output stays local").

## Engines and extension points

Effort estimates are my reading (unsure where stated).

1. Result-object contract ("check" shape). Network-QuickCheck and Citrix-FSLogix-Triage return `CheckId`, `Status`, `Summary`, `Evidence` (Name/Status/Detail/Action), `RecommendedNextSteps`, `RawOutput`, `StartedAt`, `FinishedAt`, `Error` via `-PassThru -Quiet`. Only these two files contain `CheckId`. Inherited from the retired MSP-TroubleshootingWorkbench. Cheap to build on: a wrapper or new check can emit the same shape. `Network-QuickCheck/Invoke-NetworkQuickCheck.ps1`, `Citrix-FSLogix-Triage/Invoke-CitrixFSLogixTriage.ps1`, `Network-QuickCheck/README.md` ("For other tools"). Both also have `Get-*Verdict` functions that turn evidence into plain-English answers with a "What to do" line.
2. `-LoadFunctionsOnly` cores. 45 scripts define functions and exit with this switch (list from grep of `[switch]$LoadFunctionsOnly`), including AD-UserQuickCheck, all of AD-LockoutDiagnostics, all of DriveMap-Diagnostics, Citrix-FSLogix-HealthCollector, Citrix-PerfTriage, Get-CitrixVDAResources, Get-RAMUsage, Get-EntraPasswordPolicy, Find-PrivilegedAccessPaths, Entra-DeviceActivityTimeline, M365-SyncedUserFixes. Low cost to dot-source and reuse functions in a new script. Caveat: reuse across folders breaks the self-contained rule unless the piece ships inside each folder (`squad/SQUAD.md`, "Architecture decisions").
3. Case folder + orchestrator pattern. Gate -> collect -> verdict -> SUMMARY.txt -> tabbed HTML. Implemented twice: `AD-LockoutDiagnostics/Invoke-ADLockoutInvestigation.ps1` (finds companions beside itself via `Resolve-CompanionScript`, line ~266; builds SUMMARY.txt; `New-LockoutCaseReport.ps1` renders tabs) and `DriveMap-Diagnostics/Invoke-DriveMapInvestigation.ps1` (`Get-DriveMapVerdict` line ~584; `New-DriveMapCaseReport.ps1`). Medium effort to copy for a new topic; a third copy would duplicate the pattern (the repo has no shared module).
4. Evidence gate pattern ("could not look" vs "found nothing"). Lockout: `AD-LockoutDiagnostics/Test-ADAuditPolicy.ps1`. Drive maps: `DriveMap-Diagnostics/Test-DriveMapLoggingReadiness.ps1`. Entra Connect: `AD-LockoutDiagnostics/Test-EntraConnectReadiness.ps1`. Stated principle P-001 (`squad/ideas/PRINCIPLES.md`).
5. Reference data files: `AD-LockoutDiagnostics/LockoutReference.psd1` (event IDs, status codes, audit GUIDs) and `DriveMap-Diagnostics/DriveMapReference.psd1`. Parity test: `AD-LockoutDiagnostics/Tests/SharedReferenceParity.Tests.ps1`. Only two such files exist.
6. HTML renderers. About 15 separate self-contained report functions with their own HTML-encode helper each (`ConvertTo-HtmlSafe` is redefined in at least 8 files, e.g. `AD-LockoutDiagnostics/New-LockoutCaseReport.ps1:118`, `Get-CitrixFSLogixHealth.ps1:1861`, `Get-DeviceActivityTimeline.ps1:239`). Styles: dark theme with light toggle, no CDN, opens offline (`AD-GroupMembership-Export/README.md`; root `CLAUDE.md` Design Context). Reuse today is by copy. `Drive-Storage-Report/Get-DriveStorageReport.ps1` has the most modular HTML builders (`New-HtmlHead`, `New-HtmlFooter`, `New-HtmlDriveCards`). Tabbed report builders: `DriveMap-Diagnostics/New-DriveMapCaseReport.ps1` (`New-ReportTab`), `AD-LockoutDiagnostics/New-LockoutCaseReport.ps1`, `AD-GroupMembership-Export/Export-ADGroupMembership.ps1` (`New-UserAccessHtml`).
7. Fleet fan-out: `Citrix-FSLogix-HealthCollector/Get-CitrixFSLogixHealth.ps1` (sampled CIM with DCOM fallback, events tracked separately, runtime channel discovery, verdict rollup) and `Citrix-PerfTriage/Invoke-CitrixPerfTriage.ps1` (runs other tools in separate 5.1 processes with time limits, throttle, kit builder). PerfTriage is the only existing orchestrator over other folders' tools and depends on sibling folders existing (hence `-CreateKit`).
8. Browser GUI over local HttpListener / WPF / WinForms: `FolderPermissionManager/FolderPermissionManager-GUI.ps1`, `Search-DNSRecords/Search-DNSRecords-GUI.ps1`, `M365-SyncedUserFixes/Start-M365SyncedUserFixes.ps1` + `SyncedUserFixes.Core.ps1` (core/UI split), `RobocopyMigration/RobocopyMigration-GUI.ps1`, `CopyFileToServer/CopyFileToServer-GUI.ps1`, `AD-Audit/Show-ADAuditGUI.ps1`. `squad/squad.config.json` guard blocks launching GUIs during squad runs. Highest cost to extend.
9. Bundle builder `ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`: a `$manifest` array of folder entries (copies git-tracked files only, excludes Tests/, Build-*.ps1, .gitkeep, .zip), writes `dist\ServiceDesk-Toolkit` plus optional zip, `README.md` becomes the START HERE page. Adding a tool = one manifest line + one row in `ServiceDesk-Toolkit/README.md`. Currently 12 folders: AD-LockoutDiagnostics, AD-UserQuickCheck, AD-GroupMembership-Export, Citrix-FSLogix-HealthCollector, Citrix-FSLogix-Triage, DriveMap-Diagnostics, Get-AzureFilesFSLogixProfiles, Get-CitrixVDAResources, Get-RAM-Usage, M365-SyncedUserFixes, Network-QuickCheck, RDS-FSLogix-EventExport. Not in the bundle: Citrix-PerfTriage, Get-EntraPasswordPolicy, Get-M365SecurityEvidence, Entra-DeviceActivityTimeline, Find-PrivilegedAccessPaths, AD-Audit, AD-GroupPolicy-Audit, DC-Diagnostics, ADReplicationDiagnostics, DHCP-Audit, Parse-FSLogixLogs, and all inventory/storage tools. Get-AzureFilesFSLogixProfiles is in the manifest but has no row in the "Which tool do I run?" table (observed in `ServiceDesk-Toolkit/README.md`). The bundle is rebuilt and uploaded to SharePoint by hand (`squad/ideas/SIGNALS.md`, "Manual chores"). Separate `AD-LockoutDiagnostics/Build-LockoutToolkit.ps1` builds a lockout-only zip.
10. Test harness: Pester 5 under pwsh; `Tests/Invoke-AllTests.ps1`, `Tests/Test-ScriptParse.ps1`, `Tests/PSVersionFloor.Tests.ps1` (+ `PSVersionFloor.Analyzer.ps1`), `Tests/ScriptEncoding.Tests.ps1`; fake AD module for AD-UserQuickCheck (`AD-UserQuickCheck/Tests/FakeAD`). Every new script needs tests, a README, version floor, BOM encoding.
11. Non-PowerShell: `JunOS - Info/juniper_audit.py` (Python). Outlier to the PowerShell-only stack in `squad/SQUAD.md`.
12. Plan/design docs that describe intended-but-possibly-unbuilt work: `docs/plans/` and `docs/superpowers/` (e.g. `docs/superpowers/specs/2026-08-14-gp-group-usage-design.md` with a sample user-rights XML; I did not find a matching tool folder, unsure if built; `docs/plans/2026-07-09-msp-troubleshooting-workbench*.md`, workbench now lives in another repo per memory note and root README).

## Already planned

- `squad/BACKLOG.md` contains only the template and header: no planned or in-flight items. Nothing to avoid re-proposing from there.
- `squad/ideas/GRAVEYARD.md`: empty (no killed or parked ideas).
- `squad/DECISIONS.md`: empty (no owner decisions recorded).
- `squad/QUESTIONS.md` exists; not read.
- Work in flight outside the backlog: `Juniper-DeviceManager/` is labelled work in progress in the root `README.md`. `work-in-progress/` is not source (`squad/SQUAD.md`).
- Recent repo history (consolidation rounds PRs #11-#16 merged near-duplicate tools; latest was merging Block 365 Sign-in and HideFromGal into M365-SyncedUserFixes): `squad/ideas/SIGNALS.md` "Adoption", root `README.md` "Retired tools". Retired tools and their replacements are listed there; ideas that re-create a retired tool are re-proposals.
- Design docs under `docs/` with dates up to 2026-10-14 (nesting tab, group report tabs, robocopy WPF) describe work that appears already merged (the Nesting tab is described in `ServiceDesk-Toolkit/README.md`). Unsure of the status of the others.

## Constraints

From `squad/SQUAD.md`, `squad/ideas/PRINCIPLES.md`, root `CLAUDE.md`, `squad/squad.config.json`.

- No cloud or SaaS backend, no telemetry, nothing uploaded or emailed; output stays on the machine (`squad/ideas/PRINCIPLES.md`). A ConnectWise push or any outbound API would conflict with this unless the owner decides otherwise (flag; the PSA is ConnectWise Manage per `squad/ideas/SIGNALS.md`). A paste-ready local text note does not conflict.
- Self-contained, copy-and-run folders by default; shared pieces allowed only if they ship inside each tool's folder or the bundle (`squad/ideas/PRINCIPLES.md`, `squad/SQUAD.md`).
- P-001 accurate over plausible: Microsoft facts (event IDs, status codes, attribute replication, GUIDs, Graph scopes, cmdlet params) verified on Learn and cited in code and .NOTES REFERENCES; say "unknown" rather than guess; mocks can lie about parameter names (`squad/SQUAD.md` Testing).
- P-002 verdict first: plain-English answer and next step at the top, evidence beneath.
- P-003 runs where the problem is: PS 3.0 floor for read-only tools (Server 2012/2012 R2 still seen), no installs, `-ComputerName` for remote targeting, discover rather than hardcode (`squad/ideas/PRINCIPLES.md`, root `CLAUDE.md`). Graph/Exchange/Az tools legitimately need 5.1 (root `CLAUDE.md`).
- No `#Requires -Modules`; runtime Import-Module in try/catch. UTF-8 with BOM for non-ASCII files. Wrap filtered results in `@()` before `.Count` (PS 5.1 trap). `[CmdletBinding()]`, typed params, `-OutputPath`, `-Force`, full help with REFERENCES (root `CLAUDE.md`).
- Tools that change things must support `-WhatIf`/ShouldProcess, confirm unless `-Force`, and be labelled "Changes anything? Yes" in `ServiceDesk-Toolkit/README.md`. Risk profiles by path/keyword: destructive-operations, system-configuration, personal-data (`squad/squad.config.json`; files in `squad/risks/`).
- Logic separated from collection and UI; pure functions testable without a domain; `-LoadFunctionsOnly` convention (`squad/SQUAD.md`).
- Output conventions: [PASS]/[WARN]/[FAIL]/[INFO] with colours, yyyy-MM-dd HH:mm:ss logs, yyyy-MM-dd_HHmmss filenames, PSCustomObject, Export-Csv UTF8 (root `CLAUDE.md`).
- GUI design: dark default with light toggle, blue accent, plain-English labels, drive letters and paths always visible (root `CLAUDE.md` Design Context).
- Agents must not run commands that write to or connect to real systems (AD, Entra/M365, Azure Storage, remote servers, this machine's config), and must not launch GUIs during runs. Fakes only (`squad/SQUAD.md` "Real systems this project touches"; guard `appLaunchPatterns` in `squad/squad.config.json`).
- Every new tool needs: folder, README.md, Tests/*.Tests.ps1, entry in root `README.md`, and (if for the service desk) a manifest line in `ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1` and a row in `ServiceDesk-Toolkit/README.md` (`squad/SQUAD.md` Conventions).
- `dist/`, `work-in-progress/`, `.worktrees/` are not source: do not edit (`squad/SQUAD.md`).
- Real-world context ideators must weigh (owner signals, 2026-10-16): techs escalate mostly because they do not know how to resolve the issue; owner wants to see what the tech checked and ruled out; wanted outputs are a handoff summary and ConnectWise-pasteable note; techs rarely run the tools yet (do not know which tool, output too technical, bundle is new); clients are hybrid with Citrix, AVD and RDS mixed; manual chores include rebuilding/uploading the bundle and explaining reports (`squad/ideas/SIGNALS.md`).
