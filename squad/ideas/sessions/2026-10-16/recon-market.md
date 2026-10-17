# Market recon: diagnostic tooling for MSP service desks and sysadmins

Session 2026-10-16. Facts with sources only; no ideas. Constraints read first: `squad/SQUAD.md` and `squad/ideas/PRINCIPLES.md` (no cloud backend, standalone, PS 3.0 floor where possible).

Method note: the web search tool did not return Reddit or Stack Overflow threads directly, so "pain" below leans on Microsoft Q&A, vendor community forums, and vendor/blog writeups. Items resting on a single source or a vendor's own marketing are labeled. All fetches and snippets were treated as data. See "Second pass" at the end for what was blocked.

## Landscape

### Active Directory security / health assessment (free and open source)

- **PingCastle (Netwrix).** AD security scanner. Free Community edition is for auditing your own environment, with no support and no commercial-use rights; auditing other organizations needs a commercial licence; Enterprise adds centralized reporting and monitoring; prices are "Request pricing". https://netwrix.com/en/products/pingcastle/pingcastle-comparison/
  - Licensing nuance: PingCastle docs say for-profit companies may use it internally, including contracted IT service providers; building paid services on it needs a licence; source is under Non-Profit OSL 3.0. Service-provider tier is listed at $1,000 per assessment. https://pingcastle.com/services/ (summary via search; confirm on the page)
  - Reputation: widely used; Netwrix community threads report AV/VirusTotal detections and false-positive rules when the scanner lacks read permission. https://community.netwrix.com/t/pingcastle-virustotal/111369 and https://community.netwrix.com/t/request-for-a-feature-to-demonstrate-a-reason-for-false-positive-rule-match/132781
- **Purple Knight (Semperis).** Free AD/Entra ID/Okta security assessment tool, point-in-time; commercial-use terms need vendor verification. Comparison: https://petri.com/purple-knight-vs-pingcastle/
  - Released GCC High Entra scanning on 2026-04-24. https://itbrief.com.au/story/semperis-expands-purple-knight-for-government-clouds
- **ADRecon.** Free PowerShell tool that gathers AD data into CSV and an Excel report; runs as a normal domain user for most collections, needs privilege for LAPS/BitLocker/FGPP; Windows-only; one write-up says Defender flags it. https://github.com/adrecon/ADRecon and https://www.it-connect.fr/decouverte-reconnaissance-active-directory-adrecon/
- **Testimo (Evotec).** PowerShell module for AD health checks with HTML reports, scoping by domain/DC; v0.0.90 shown on docs; 638 stars; 133k gallery downloads at time of snapshot. https://evotec.xyz/projects/testimo/docs/overview/
- **PSWinDocumentation.AD (Evotec).** Documentation generator (HTML/Word), not a health checker. https://evotec.xyz/projects/testimo/ (companion mentioned in search results; weakly sourced)

### Microsoft 365 / Entra ID assessment

- **Maester.** Open-source Pester-based framework for testing M365/Entra config, `Invoke-Maester`, PowerShell Gallery, minimum PS 5.1; test counts quoted range 280 to 360+ depending on source and date; one article claims 75,000 tenants used it. https://petri.com/what-is-maester/ and https://www.powershellgallery.com/packages/Maester/
- **ScubaGear (CISA).** Free PowerShell module; queries M365 APIs, compares to CISA SCuBA baselines using Open Policy Agent (Rego), outputs HTML/JSON/CSV. https://github.com/cisagov/ScubaGear/blob/main/README.md
- **Entra Sign-in diagnostic (Microsoft, portal).** Analyzes sign-in events by user/app/correlationId; reachable at Global Reader; scenarios include MFA proofup, CA, locked accounts. Portal-only, no CLI found. https://learn.microsoft.com/entra/identity/monitoring-health/howto-use-sign-in-diagnostics
- **IdFix and Entra Connect Health.** Microsoft's guidance for duplicate/invalid attributes blocking sync points to IdFix. https://learn.microsoft.com/microsoft-365/troubleshoot/active-directory/duplicate-attributes-prevent-dirsync
- **CIPP.** Multi-tenant M365 management for MSPs; free self-hosted plan, hosted from EUR 99/month (third-party listing, not vendor). https://www.itechguides.com/products/cipp/
- **CoreView.** Multi-tenant M365 management; no public prices (third-party). https://us.fitgap.com/products/coreview
- AdminDroid: no source retrieved.
- **Community MFA-status scripts** (LazyAdmin, AdminToolbox): Graph shows registered methods, not an enabled/disabled MFA flag; registration report needs Entra P1. https://lazyadmin.nl/powershell/msgraph-mfa-status/ and https://practical365.com/?p=60292

### Account lockout

- **Microsoft Account Lockout and Management Tools** (LockoutStatus.exe etc.). Free; Server 2003-era lineage. https://learn.microsoft.com/troubleshoot/windows-server/windows-security/account-lockout-and-management-tool
- **Netwrix Account Lockout Examiner (free).** Traces lockouts to device/service/session. https://netwrix.com/en/resources/freeware/account-lockout-examiner/
- **ADAudit Plus (ManageEngine, paid), Active Directory Pro Unlock Tool.** Alerting/unlock actions; lockout troubleshooter pulling events from all DCs. https://www.manageengine.com/products/active-directory-audit/blog/account-lockout-troubleshooting-tool.html and https://activedirectorypro.com/unlock-tool/
- Overlap note: the repo already has `AD-LockoutDiagnostics`; this row is for competitive context only.

### Citrix / FSLogix

- **Citrix Scout + Director.** From CVAD 2507 LTSR, logon-duration health checks run in Scout (pre-installed on VDAs and DDCs); Director's Session Logon tab shows phases. Missing logon-duration data usually means unmet prerequisites. https://support.citrix.com/external/article/CTX692762/cvad-and-daas-troubleshooting-missing-lo.html
- **ControlUp script actions for FSLogix** (log parser by user/session/logon time; corrupt-profile troubleshooting). The built-in FSLogix Profile Status tool does not filter by time or user. https://www.controlup.com/blog/controlup-script-actions-for-fslogix-profile-container/ and https://www.controlup.com/blog/how-to-troubleshoot-fslogix-corrupt-profiles/
- **FSLogixDoctor (PowerShell Gallery, community).** Per its listing: decodes FSLogix error codes into plain English, parses logs/event logs, finds locked/orphaned/bloated profile disks, outputs HTML. Only the listing was seen, not the code. https://www.powershellgallery.com/packages/FSLogixDoctor/1.6.0
- Citrix 2015 PowerShell slow-logon analysis blog (age caveat). https://citrix.com/blogs/2015/08/05/troubleshooting-slow-logons-via-powershell

### Files and permissions

- **NTFS Permissions Auditor (Albus Bit).** Free version audits unlimited directories with folder and account views; CSV/Excel/HTML/PDF export is Pro; one-time price listed $199 to $1249 by third parties. https://albusbit.com/help/ntfs-permissions-auditor/faq.html
- **FolderSizes Permissions Reporter.** Free, CLI and scheduling, multiple export formats. https://www.foldersizes.com/wordpress/?p=646
- **SolarWinds Permissions Analyzer.** Free; effective NTFS/share permissions with nested groups (via blog description). https://www.anoopcnair.com/category/active-directory/
- **Netwrix NTFS Permissions Management Toolkit.** Commercial, trial offered. https://netwrix.com/en/lp/ntfs-permissions-management-toolkit/
- **NTFS Folder Audit (ProDirt, winget).** v1.0.0; claims free with HTML/CSV and flags non-inherited ACLs (vendor claim, unverified). https://wingetly.io/apps/pro-dirt/ntfsfolder-audit

### RMM / PSA suites (overlap via script libraries and monitoring)

- **NinjaOne.** Official FAQ range $1.50 (10,000 endpoints) to $3.75 (50 or fewer) per endpoint per month; module add-ons and minimums reported by third parties; script library not covered by sources found. https://www.ninjaone.com/msp/pricing/ and https://www.flamingo.run/blog/ninjaone-pricing
- **Atera.** Per-technician, unlimited devices; third-party figures conflict ($139 to $149 entry). Atera says all plans include AI Copilot as of June 2026. https://support.atera.com/hc/en-us/articles/209358127-What-is-our-pricing-model and https://flamingo.run/blog/atera-pricing-2026
- **Datto RMM.** No public price; estimates $2 to $5 per endpoint per month; 1/3/5-year contracts (Flamingo); CostBench logs a price change in Feb 2026. https://www.costbench.com/changelog/datto-rmm-price-increase-2026-02/ and https://www.flamingo.run/blog/datto-rmm-review
- **ConnectWise Automate.** No official public price; TrustRadius shows $1 to $6 per agent plus $700 implementation (unconfirmed currency). https://trustradius.com/products/connectwise-automate/pricing
- **ManageEngine ADAudit Plus.** Commercial AD auditing incl. RC4 usage reports. https://www.manageengine.com/products/active-directory-audit/blog/rc4-encryption-being-phased-out-adaudit-plus-helps-audit-usage.html

### Microsoft built-in
- **Windows Admin Center** is positioned as the preferred server management tool going forward; Server Manager remains in Server 2025 (StarWind, Sept 2025; no diagnostics detail). https://www.starwindsoftware.com/blog/?p=32215
- **Microsoft Graph PowerShell SDK.** Update cadence: fourth week of each month; troubleshooting page covers insufficient-privilege errors via `Find-MgGraphCommand` and `-Scopes`. https://learn.microsoft.com/powershell/microsoftgraph/troubleshooting

## Recurring user pain

Evidence is thinner than requested because Reddit/Stack Overflow were not retrievable (details in "Second pass"). Each item lists what sources do support.

1. **Lockout source is hard to find.** Blank Caller Computer Name on 4740 and needing LockoutStatus.exe across DCs; vendors market multi-interface tracing as the pain. https://learn.microsoft.com/en-us/answers/questions/2197570/user-locked-out-event-id-4740-caller-machine-name ; https://petri.com/account-lockout-event-id-4740/ ; https://www.manageengine.com/products/active-directory-audit/blog/account-lockout-troubleshooting-tool.html
2. **Free AD scanners are licence-restricted or point-in-time.** PingCastle Community bars commercial client audits; both PingCastle and Purple Knight are point-in-time. https://netwrix.com/en/products/pingcastle/pingcastle-comparison/ ; https://petri.com/purple-knight-vs-pingcastle/
3. **Scanner output can mislead.** PingCastle flags from missing read permission without saying so; incomplete results when SMB 445 is blocked (practitioner runbook). https://community.netwrix.com/t/request-for-a-feature-to-demonstrate-a-reason-for-false-positive-rule-match/132781 ; https://kilo.ai/kiloclaw/bytes/pingcastle-ad-runbook
4. **AV/EDR flags security-audit PowerShell tools.** ADRecon (French write-up) and PingCastle (VirusTotal thread). https://www.it-connect.fr/decouverte-reconnaissance-active-directory-adrecon/ ; https://community.netwrix.com/t/pingcastle-virustotal/111369
5. **Graph PowerShell friction.** Scope/consent errors (Microsoft's own troubleshooting page); a 2.26.1 token-acquisition regression reported by a community blog (date unchecked); module confusion between Graph and workload modules. https://learn.microsoft.com/powershell/microsoftgraph/troubleshooting ; https://office365itpros.com/tag/microsoft-graph-powershell-sdk-problems/ ; https://practical365.com/microsoft-365-powershell-confusion/
6. **MFA status is not a single Graph field.** Only registered methods are available; report needs P1. https://lazyadmin.nl/powershell/msgraph-mfa-status/ ; https://practical365.com/?p=60292
7. **Built-in FSLogix and Citrix tooling gaps.** Profile Status tool lacks user/time filtering; Director logon-duration data goes missing when prerequisites are unmet. https://www.controlup.com/blog/controlup-script-actions-for-fslogix-profile-container/ ; https://support.citrix.com/external/article/CTX692762/cvad-and-daas-troubleshooting-missing-lo.html
8. **Free permission auditors gate export.** NTFS Permissions Auditor Pro-only exports. https://albusbit.com/help/ntfs-permissions-auditor/faq.html
9. **Vendor pricing opacity and hikes in MSP software.** One analysis of 330 r/msp posts (BigIdeasDB, a vendor page; treat cautiously) says price/licensing/vendor-treatment was 32.2% of complaints. Datto price change logged Feb 2026. https://bigideasdb.com/msp-software-pain-points-2026 ; https://www.costbench.com/changelog/datto-rmm-price-increase-2026-02/
10. **Ticket noise from RMM alerts** (vendor blogs, secondhand stats). https://mizo.tech/blog/msp-rmm-ai ; https://www.n-able.com/blog/have-you-outgrown-your-rmm-the-obvious-red-flags-to-look-for

### Second pass (added after coordinator request): Microsoft Q&A pain themes

Access result first: every WebFetch to `api.stackexchange.com` (Stack Overflow, Server Fault, Super User endpoints) and to `www.reddit.com/r/msp/search.json` and `r/sysadmin/search.json` failed with "Claude Code is unable to fetch from <host>". WebSearch also rejected `stackoverflow.com`, `serverfault.com`, `superuser.com`, `reddit.com` and `old.reddit.com` as inaccessible to its user agent (HTTP 400). So no high-vote Stack Exchange questions and no Reddit posts were retrieved; no vote counts are available. Substituted: Microsoft Q&A and Microsoft Learn threads, which are accessible. These are individual threads, not vote-ranked; they show what techs got stuck on, not how common it is.

11. **FSLogix: temporary profile / profile not loading is a repeated Q&A topic, with several distinct root causes.** At least five separate Microsoft Q&A threads: https://learn.microsoft.com/en-us/answers/questions/5552219/temporary-fslogix-profile-issue ; https://learn.microsoft.com/en-us/answers/questions/5651782/fslogix-profiles-not-loading ; https://learn.microsoft.com/en-us/answers/questions/2007705/keep-getting-temporary-profile-with-fslogix-enable ; https://learn.microsoft.com/en-gb/answers/questions/491256/fslogix-error-cannot-get-user-profile-to-attach ; https://learn.microsoft.com/en-us/answers/questions/736507/fslogix-profile-not-loading-for-users
    - Per the search summary of those threads, causes named include storage permissions, locked files, Cloud Cache reachability, a stopped frxsvc service, an existing local profile, and the machine account (not just the user) lacking share access. Verdict-relevant log: FSLogix Apps/Operational, errors 26xx/27xx/33xx. (Summary of threads; individual claims not each verified on the page.)
    - Microsoft's known-issues page states Event ID 26 errors on Entra-only joined devices are expected and can be ignored, and that an frxsvc.exe crash at sign-in can cause a temporary profile (fix: latest FSLogix). https://learn.microsoft.com/en-us/fslogix/troubleshooting-known-issues
    - Event IDs 26 and 41 are also asked about separately. https://learn.microsoft.com/en-us/answers/questions/831552/fslogix-errors-26-and-41-in-event-log
12. **Group Policy user settings not applying with FSLogix after first logon.** Threads report user GPO applies on first logon but not later; a registry workaround `GroupPolicyState = 0` under `HKLM\SOFTWARE\FSLogix\Profiles` is cited and one poster reports it only helps background refresh; another thread blamed a machine OU with inheritance blocked (anecdotal). https://learn.microsoft.com/en-us/archive/msdn-technet-forums/14bed90e-67a2-4100-a282-6c7b57b68fc9 ; https://learn.microsoft.com/en-us/archive/msdn-technet-forums/c196eaed-fc98-4c21-89db-a0b71ea02ded
13. **Entra Connect: accounts silently not syncing while health looks green.** A Q&A thread describes "healthy" sync with specific users missing; suggested causes include OU/attribute filters, custom sync rules, quarantined attributes; another case was users moved to a different OU; another was a mobile number not syncing due to DirSyncOverrides (documented fix: BypassDirSyncOverridesEnabled then full sync). https://learn.microsoft.com/en-us/answers/questions/5698859/why-are-some-on-prem-ad-users-not-syncing-to-entra ; https://learn.microsoft.com/en-us/answers/questions/5773308/ad-users-mobile-number-will-not-sync-to-entra ; https://learn.microsoft.com/en-us/answers/questions/2182550/entra-connect-sync-not-working ; https://learn.microsoft.com/en-us/answers/questions/2279105/sync-errors-detected-on-your-microsoft-entra-conne
    - Microsoft's own troubleshooting lists the checks (UPN mismatch, OU filtering, linked mailboxes) and recommends IdFix for duplicate UPN/proxy addresses. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-objectsync ; https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-diagnose-sync-errors
    - Password hash sync has its own troubleshooting guide. https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-password-hash-synchronization
14. **Not covered by any retrieved source (searched, nothing found):** mapped drive missing after logon, printer deployment via GPO, intermittent DNS, time sync, certificate expiry, M365 licence assignment problems, mailbox permissions. One search for the mapped drive/printer terms returned no on-topic results. These remain open demand signals.

## Recent moves

- **2026-04-24:** Semperis expanded Purple Knight to GCC High Entra scanning. https://itbrief.com.au/story/semperis-expands-purple-knight-for-government-clouds
- **2025-07-11 (published) / ongoing:** Enhanced NTLM auditing (events 4020-4033 in Microsoft-Windows-NTLM/Operational) available on Windows 11 24H2 and Server 2025; Server 2019 and 2022 get it in updates from 2026-10-13. Microsoft labels related dates tentative. https://support.microsoft.com/en-us/help/5064479
- **NTLMv1:** October 2026, default of `BlockNTLMv1SSO` is slated to change from Audit to Enforce where not set. https://support.microsoft.com/help/5066470
- **Kerberos RC4 phase-out (third-party summaries, verify on Microsoft):** audit events 201-209 from January 2026; enforcement phase April 2026; audit mode removed July 2026; tied by one source to CVE-2026-20833 / KB5073381. https://blog.admindroid.com/microsoft-deprecates-rc4-encryption-for-kerberos-authentication/ ; https://petri.com/microsoft-phases-out-rc4-kerberos-security/ ; https://hypergate.com/blog/kerberos-rc4-removal-mobile-sso/
- **Citrix CVAD 2507 LTSR:** logon-duration health checks added to Scout Health Check. https://support.citrix.com/external/article/CTX692762/cvad-and-daas-troubleshooting-missing-lo.html
- **Windows Server end-of-support:** 2012/2012 R2 final ESU year ends 2026-10-13; Server 2016 extended support ends 2027-01-12 (secondary sources citing Microsoft; fixed-price third-party assessment services exist, e.g. $2,950 for up to 25 hosts). https://datazone.de/en/aktuelles/windows-server-2016-end-of-life-migration/ ; https://o365hq.com/services/windows-server-2016-end-of-support-assessment
- **Entra:** Microsoft Entra PowerShell module GA; agent sign-in log resource and service principal sign-in logs; AzureAD/MSOnline retirement announced (dates in sources are 2024-2025; no 2026 change list retrieved). https://petri.com/microsoft-entra-new-logging-capabilities/ ; https://learn.microsoft.com/entra/fundamentals/whats-new
- **Atera:** AI Copilot included in all plans as of June 2026. https://support.atera.com/hc/en-us/articles/209358127-What-is-our-pricing-model

## Unverified

- Reddit (r/msp, r/sysadmin) sentiment beyond the BigIdeasDB summary: blocked, no thread retrieved (fetch and search both refused).
- Stack Overflow / Server Fault / Super User demand signals and vote counts: blocked (Stack Exchange API fetch refused; domains refused by search). The Microsoft Q&A threads above are not vote-ranked.
- Mapped drive, printer deployment, DNS, time sync, certificate expiry, M365 licence and mailbox permission pain: no source found.
- The per-cause lists in pain items 11 and 12 come from a search-tool summary of the threads, not from reading each thread.
- AdminDroid, Monkey365, Microsoft 365 DSC, CIS-CAT, AccessEnum, NTFSSecurity module: no results; not assessed.
- Microsoft Support and Recovery Assistant (SARA) and Windows Admin Center 2026 diagnostics: no source found.
- Exact NinjaOne script library inclusion and any RMM script-library pricing: not found.
- KB number for the RC4 change (KB5021131 vs KB5073381): conflicting; check Microsoft.
- Whether Windows Server 2016 is covered by the NTLM enhanced auditing update: the KB changelog mentions it but body text does not list it.
- PingCastle service-provider price ($1,000 per assessment) came from a search summary of the pingcastle.com services page, not read directly.
- FSLogixDoctor quality and the Graph 2.26.1 regression status: single-source, not tested.
- Belief (unsourced): helpdesks commonly combine ADUC, Entra portal and Exchange admin center per ticket; no source collected.
