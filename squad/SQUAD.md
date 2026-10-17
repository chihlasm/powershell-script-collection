# PowerShell Script Collection: project rules for the squad

Written by /squad:setup and maintained with /squad:configure. Every squad agent reads this
alongside the plugin's universal rules. Anything here wins on project-specific matters.
The repo's root `CLAUDE.md` holds the detailed script conventions (help blocks, version floors,
encoding, logging, Microsoft Learn verification); this file does not repeat them. Follow both.

## The product

About 60 standalone PowerShell tools that make troubleshooting faster and data collection
quicker and more accurate for an MSP's service desk. They cover Windows Server, Active
Directory and Group Policy, Citrix/RDS/FSLogix, Microsoft Entra ID and Microsoft 365, files
and permissions, and networking. Most tools diagnose and report (HTML/CSV attached to the
ticket); a few clearly labelled ones change things (AD attributes, permissions, installs,
cleanups). `ServiceDesk-Toolkit` builds the bundle handed to the service desk.

## Who uses it, and when

- **Helpdesk techs (tier 1/2)**, mid-ticket with a client waiting: "can this user sign in?",
  "why does this account keep locking out?", "why is the drive missing?". They need a
  plain-English verdict and next step, not raw data.
- **Senior sysadmins/engineers**, running audits and deep diagnostics across client
  environments. They need density, precision, and evidence they can trust.
- Run on Windows admin workstations or directly on client servers (often old ones), with
  domain-admin or tenant-admin rights. Owner: Michael, who maintains the collection for the team.

## Stack and layout

- PowerShell only. Targets Windows PowerShell 3.0–5.1 on servers; PowerShell 7 is used for
  the test suite. RSAT modules (ActiveDirectory, GroupPolicy, DnsServer, DhcpServer),
  Microsoft.Graph, ExchangeOnlineManagement, Az.Storage, Citrix snap-ins where a tool needs them.
- One folder per tool: main script(s), `README.md`, and `Tests/*.Tests.ps1`. Repo-wide tests
  live in `Tests/`. GUIs are WPF/WinForms windows or a browser UI over a local `HttpListener`
  (e.g. `FolderPermissionManager/FolderPermissionManager-GUI.ps1`,
  `Search-DNSRecords/Search-DNSRecords-GUI.ps1`).
- `dist/` (generated bundles), `work-in-progress/` and `.worktrees/` are not source: never
  edit them, and the build and tests skip them.
- Design and plan documents: `docs/plans/`, `docs/superpowers/`.

## Architecture decisions already made (do not relitigate)

- **Self-contained folders.** A tool folder can be copied to a server and run with nothing
  else installed beyond built-in Windows/RSAT modules (root `CLAUDE.md`, Folder Structure
  Pattern). A shared piece across tools is allowed only when it clearly earns its place, and
  it must still ship inside each tool's folder or the ServiceDesk-Toolkit bundle
  (`ServiceDesk-Toolkit/Build-ServiceDeskToolkit.ps1`).
- **Logic separated from collection and UI.** Pure functions (parsing, ranking, verdicts,
  rendering) are testable without a domain. Scripts expose `-LoadFunctionsOnly` to define
  functions and exit (`AD-Audit/Invoke-ADAudit.ps1`, `AD-LockoutDiagnostics/*.ps1`); GUIs
  load a separate core (`M365-SyncedUserFixes/Start-M365SyncedUserFixes.ps1` →
  `SyncedUserFixes.Core.ps1`).
- **Declare the lowest PowerShell version the code needs** (3.0 default for read-only
  tools), enforced by `Tests/PSVersionFloor.Tests.ps1`; no `#Requires -Modules` (runtime
  `Import-Module` in try/catch instead).
- **Remote by `-ComputerName`, discovery over hardcoding**: query AD for DCs/DHCP/DNS servers.
- **Documented Microsoft facts are verified on Microsoft Learn and cited** next to the code
  and in `.NOTES` REFERENCES (event IDs, status codes, attribute replication, cmdlet params).
- **Tools that change things say so**: `-WhatIf`/`SupportsShouldProcess`, confirmation unless
  `-Force`, and labelled "Changes anything? Yes" in `ServiceDesk-Toolkit/README.md`.
- **Output stays local**: HTML/CSV under `-OutputPath`; no cloud backend or telemetry.
  Client-data output folders are gitignored.

## Testing

- **Framework:** Pester 5 (5.7.1 installed for PowerShell 7). Windows PowerShell 5.1 only has
  Pester 3.4, so suites run under `pwsh`.
- **Build (gate):** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Tests\Test-ScriptParse.ps1`
  parses every script the way Windows PowerShell 5.1 reads it (BOM-less files as ANSI).
- **Tests (gate):** `pwsh -NoProfile -ExecutionPolicy Bypass -File Tests\Invoke-AllTests.ps1`
  runs every `*.Tests.ps1` except `dist/`, `work-in-progress/`, `.worktrees/`, and excludes
  the `Integration` tag. About 2.5 minutes. Narrow while iterating:
  `pwsh -File Tests\Invoke-AllTests.ps1 -Path .\AD-LockoutDiagnostics\Tests`.
- **Integration convention:** any test that touches the real machine or a real environment
  is tagged `-Tag 'Integration'` (see `DiskSpdDiagnostic/Tests/DiskSpdDiagnostic.Tests.ps1`)
  and stays out of the gate.
- **Fakes:** load the script with `-LoadFunctionsOnly` or dot-source its core, then `Mock`
  every external cmdlet: AD (`Get-ADUser`, `Set-ADUser`, …), Graph (`Invoke-MgGraphRequest`,
  `Get-Mg*`), CIM/WMI (`Get-CimInstance`), `Invoke-Command`, `Get-WinEvent`, file-system
  writes (use `$TestDrive`). Where a module isn't installed, define a stub function with the
  real parameter names before mocking.
- **Mocks can lie:** a stub can share a wrong parameter name with the code (this happened:
  `Get-ADUser -ResultSize` vs the real `-ResultSetSize`). Verify every cmdlet parameter on
  Microsoft Learn, and where RSAT is installed, add a test that checks names against the
  real cmdlet via `Get-Command`.
- **Compatibility tests:** tools with a 3.0 floor carry a `Compatibility.Tests.ps1`
  (`AD-GroupMembership-Export/Tests/Compatibility.Tests.ps1`); `Tests/ScriptEncoding.Tests.ps1`
  enforces UTF-8 with BOM for non-ASCII files.
- When documentation contradicts existing code, fix the code and add a regression test.

## Conventions

- Follow root `CLAUDE.md`: `[CmdletBinding()]` typed params with validation, full
  comment-based help (`.SYNOPSIS` … `.NOTES` with REFERENCES), `-OutputPath`, `-Force`.
- Console output: `[PASS]` Green, `[WARN]` Yellow, `[FAIL]` Red, `[INFO]` Cyan, plus the
  same lines to a log file; timestamps `yyyy-MM-dd HH:mm:ss`, filenames `yyyy-MM-dd_HHmmss`.
- Structured data as `[PSCustomObject]`; `Export-Csv -NoTypeInformation -Encoding UTF8`.
- Wrap filtered results in `@()` before `.Count`; per-server try/catch with `continue`.
- Plain-English labels first ("Who has access?", not "ACE"); verdict and next step at the top
  of every report. GUI design context is in root `CLAUDE.md` (dark default, blue accent).
- Every tool folder has a `README.md`; a new tool is added to the root `README.md` index and,
  if it is for the service desk, to `ServiceDesk-Toolkit`.
- Commits: `feat:`/`fix:`/`docs:`/`chore:` prefixes; `Co-Authored-By:` naming the model that
  did the work.

## Real systems this project touches

The squad never touches these outside of fakes in tests. Michael chose no command guard, so
this is enforced by review and by this rule, not by blocked commands: agents do not run
commands that write to or connect to these systems, and do not launch the GUIs during runs.

- **Active Directory** (read across most tools; written by `M365-SyncedUserFixes` via
  `Set-ADUser`, and by LocalAdminManager/FolderPermissionManager on local groups and ACLs).
- **Microsoft Entra ID / Microsoft 365** via Microsoft Graph and Exchange Online
  (`Get-M365SecurityEvidence`, `Get-EntraPasswordPolicy`, `Entra-DeviceActivityTimeline`).
- **Azure Storage** (`Get-AzureFilesFSLogixProfiles`, `Connect-AzAccount`).
- **Remote servers** via `Invoke-Command`/CIM (32 scripts), Citrix VDAs and Delivery
  Controllers, DHCP/DNS servers, SQL Server (`Sql-Corruption-Diagnostic`), Juniper devices.
- **This machine's configuration** (registry, services, installs, network) in the
  system-configuration tools.

Read-only introspection is fine: `Get-Command <cmdlet> -Syntax` / `Get-Help` against an
installed module to verify parameter names.
