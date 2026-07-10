# MSP Troubleshooting Workbench - Design

**Date:** 2026-07-09
**Status:** Approved for implementation planning
**Owner:** Michael Chihlas

## Problem

Daily MSP troubleshooting spans Windows Server, Citrix/RDS, FSLogix, Active
Directory, DNS, DHCP, Hyper-V, SQL, storage, and general networking. The current
repository already contains strong standalone tools, but each script has its own
interface, output style, logging behavior, and report format. That makes it hard
to move quickly during a live ticket and harder to produce complete notes after
the fact.

The missing piece is not another isolated script. It is a workbench that treats a
ticket as a troubleshooting case, captures each check and result, and turns the
process into clear notes and evidence.

## Goal

Build a portable local GUI that helps create a troubleshooting case, run
diagnostic checks, collect evidence, track manual notes, and generate
ticket-ready output. The tool should start as a safe, read-heavy diagnostic
workbench and gradually wrap the best existing scripts as reusable checks.

## Decision

Use a **portable folder app with a small launcher executable**:

```text
MSP-TroubleshootingWorkbench/
  MSPWorkbench.exe
  Start-MSPTroubleshootingWorkbench.ps1
  checks/
  app/
  assets/
  cases/
  exports/
  logs/
  config/
  README.md
```

The launcher executable is only the front door. It starts the PowerShell backend,
chooses or validates a local port, opens the browser GUI, and leaves the
PowerShell scripts inspectable and editable inside the folder. A
`Start-MSPTroubleshootingWorkbench.ps1` fallback remains available for support
and debugging.

## User Experience

The first screen is the actual workbench, not a landing page. It should feel like
internal MSP tooling: dark default, dense but readable, plain-English labels,
clear paths/server names, and strong visual status cues.

Primary flow:

1. Create or open a case.
2. Enter client, ticket number, issue type, affected user, affected device, and
   optional path/IP/service context.
3. Run one or more checks.
4. Review findings and raw evidence.
5. Add manual notes while working.
6. Generate ticket notes.
7. Export an evidence bundle.

## Case Model

Cases are stored as JSON files under `cases/` by default, with exports under
`exports/`. A case contains:

| Field | Purpose |
|-------|---------|
| CaseId | Stable local identifier |
| ClientName | MSP client/customer |
| TicketNumber | PSA/ticket reference |
| IssueType | AD, Citrix/FSLogix, DNS, Network, Storage, Hyper-V, SQL, General |
| AffectedUser | Optional user identity |
| AffectedDevice | Server, workstation, DC, VDA, or host |
| TargetPath | Optional UNC/local path |
| TargetAddress | Optional IP/FQDN |
| CreatedAt / UpdatedAt | Timestamps |
| Checks | Structured check results |
| Notes | Manual timestamped notes |
| GeneratedSummary | Ticket-ready summary |

## Check Contract

Each diagnostic check should return a common object so the GUI, notes engine, and
exports do not need to understand every script's private output format.

```powershell
[PSCustomObject]@{
    CheckId              = 'network.quick'
    Name                 = 'Network Quick Check'
    Category             = 'Network'
    Status               = 'Pass' # Pass, Warn, Fail, Info
    Summary              = 'TCP 445 reachable; DNS resolves to expected address.'
    Evidence             = @()
    RecommendedNextSteps = @()
    RawOutput            = ''
    StartedAt            = '2026-07-09 14:30:00'
    FinishedAt           = '2026-07-09 14:30:12'
    Error                = $null
}
```

V1 checks should be read-only diagnostics. Destructive or corrective actions
must not be exposed until the workbench has a separate remediation design with
confirmation, `-WhatIf`, and `-Force` guardrails.

## V1 Checks

Start with checks that are useful, safe, and easy to normalize:

1. **Network Quick Check**
   - Ping or `Test-Connection`
   - DNS resolution
   - TCP port test
   - Local adapter and route snapshot

2. **AD Lockout Wrapper**
   - Wrap `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`
   - Capture generated HTML path and core verdict
   - Preserve raw report as evidence

3. **Citrix/FSLogix Triage**
   - Session host reachability
   - FSLogix service state
   - FSLogix profile path configuration
   - Recent FSLogix and Terminal Services events
   - Disk free space on local and profile storage locations

4. **Storage Health Summary**
   - Disk free space
   - Recent disk/NTFS events
   - Dirty bit status
   - VSS writer summary

5. **DNS Search Link/Wrapper**
   - Provide a direct launch point for the existing DNS browser GUI
   - Later normalize selected search results into the case

## Notes Engine

V1 notes are template-based and generated from structured case data:

```text
Issue:
Actions Taken:
Findings:
Evidence:
Likely Cause:
Next Steps:
Customer-Facing Summary:
```

The notes engine should produce Markdown first because it is easy to paste into
tickets. HTML export can reuse the same data with stronger formatting.

Optional AI summarization can be added later, but the durable value comes from
capturing structured evidence first.

## Backend

Use a PowerShell 5.1 local `HttpListener` backend because the repository already
has working examples of that pattern. The backend owns:

- Static GUI delivery
- JSON API routes
- Case read/write
- Check execution
- Result normalization
- Export generation
- Logging

The backend should bind to localhost only. It should detect occupied ports and
either select another port or show a clear error.

## Frontend

The GUI should be browser-based with no external web dependencies in v1. Inline
or local CSS/JS is acceptable for portability.

Core screens:

- Case list / create case
- Case workspace
- Check catalog
- Check run detail
- Notes editor
- Export panel
- Settings/about

Design direction:

- Dark default, light mode toggle later
- Plain-English labels
- Icons paired with text labels
- Dense result tables with clear status colors
- Always show active client, ticket, user, server, and path context

## Storage

Default storage is local to the portable folder:

```text
cases/
  CASE-20260709-143000.json
exports/
  CASE-20260709-143000/
    ticket-notes.md
    report.html
    evidence.json
    raw/
logs/
  workbench-2026-07-09.log
```

The user can later configure a different default output path.

## Packaging

V1 should ship as a folder. The launcher executable can be built later with a
small .NET console or Windows app host. The PowerShell fallback should be fully
functional before the executable exists.

Packaging priorities:

1. PowerShell entry point works reliably.
2. App runs from any folder without install.
3. Cases, exports, logs, and config stay inside the portable folder by default.
4. Launcher executable starts the same entry point.
5. Zip distribution preserves the full folder.

## Risks And Mitigations

| Risk | Mitigation |
|------|------------|
| Existing scripts have inconsistent outputs | Normalize only selected v1 checks first |
| Some checks need RSAT/Citrix modules | Add preflight capability checks and clear messages |
| Long-running checks block the GUI | Use background jobs or runspaces for check execution |
| Destructive scripts could be exposed accidentally | V1 catalog only includes read-only checks |
| One giant script becomes hard to maintain | Keep check files separate and use a manifest |
| Antivirus dislikes bundled script executables | Prefer portable folder plus small launcher over script-to-exe bundling |

## Non-Goals For V1

- Central server or multi-user web app
- PSA/ticketing system integration
- AI-generated notes
- Remediation actions
- Full rewrite of every existing script
- Enterprise installer/MSI
- One single embedded executable

## Success Criteria

- Double-click or PowerShell launch opens the workbench locally.
- A case can be created, saved, reopened, and exported.
- At least three diagnostic checks can run and attach structured evidence.
- Generated Markdown notes are useful enough to paste into a ticket with light editing.
- The app is portable as a single folder.
- Existing unrelated scripts are not broken or refactored during v1.

