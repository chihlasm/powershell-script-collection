# MSP Troubleshooting Workbench Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a portable local browser GUI for MSP troubleshooting cases, diagnostic check execution, evidence capture, and ticket-note generation.

**Architecture:** A PowerShell 5.1 `HttpListener` backend serves a local browser UI and JSON API. Cases are stored as JSON files inside a portable folder, checks are separate PowerShell scripts with a shared result contract, and exports generate Markdown, HTML, and raw JSON evidence.

**Tech Stack:** Windows PowerShell 5.1, local `HttpListener`, vanilla HTML/CSS/JavaScript, JSON case files, Pester-style helper tests where practical.

---

### Task 1: Scaffold Portable App Folder

**Files:**
- Create: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1`
- Create: `MSP-TroubleshootingWorkbench/README.md`
- Create: `MSP-TroubleshootingWorkbench/checks/manifest.json`
- Create: `MSP-TroubleshootingWorkbench/app/index.html`
- Create: `MSP-TroubleshootingWorkbench/assets/.gitkeep`
- Create: `MSP-TroubleshootingWorkbench/cases/.gitkeep`
- Create: `MSP-TroubleshootingWorkbench/exports/.gitkeep`
- Create: `MSP-TroubleshootingWorkbench/logs/.gitkeep`
- Create: `MSP-TroubleshootingWorkbench/config/.gitkeep`

**Step 1: Create the folder skeleton**

Use `apply_patch` to add the files above. Keep placeholder files minimal.

**Step 2: Add README quick start**

Include:

````markdown
# MSP Troubleshooting Workbench

Portable local troubleshooting case workbench for MSP Windows infrastructure support.

## Quick Start

Run from an elevated PowerShell session when checks require admin rights:

```powershell
.\Start-MSPTroubleshootingWorkbench.ps1
```
````

**Step 3: Add an empty check manifest**

```json
{
  "schemaVersion": 1,
  "checks": []
}
```

**Step 4: Verify files exist**

Run:

```powershell
Test-Path .\MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1
Test-Path .\MSP-TroubleshootingWorkbench\checks\manifest.json
```

Expected: both return `True`.

**Step 5: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: scaffold troubleshooting workbench"
```

---

### Task 2: Implement Local HTTP Server

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1`
- Modify: `MSP-TroubleshootingWorkbench/app/index.html`

**Step 1: Add script parameters**

```powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    Starts the MSP Troubleshooting Workbench local browser GUI.
.DESCRIPTION
    Runs a localhost-only PowerShell HTTP server for creating troubleshooting
    cases, running diagnostic checks, and exporting ticket notes.
.PARAMETER Port
    TCP port for the local web server. Default is 8275.
.PARAMETER OutputPath
    Portable data root for cases, exports, logs, and config. Defaults to the script folder.
.PARAMETER NoBrowserOpen
    Do not automatically open the browser.
.EXAMPLE
    .\Start-MSPTroubleshootingWorkbench.ps1
.NOTES
    Run elevated when checks require administrative access.
#>
[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8275,

    [string]$OutputPath = $PSScriptRoot,

    [switch]$NoBrowserOpen
)
```

**Step 2: Add helpers**

Implement `Send-Json`, `Send-Html`, `Send-Text`, `Read-RequestBody`, and
`Write-WorkbenchLog`. Use `ConvertTo-Json -Depth 10`.

**Step 3: Add routes**

Implement:

```text
GET /              -> app/index.html
GET /api/status    -> backend status JSON
GET /api/cases     -> empty case list for now
```

**Step 4: Add minimal HTML**

`index.html` should show:

- App title
- Backend status area
- Empty case list area

**Step 5: Run the server**

Run:

```powershell
.\MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1 -Port 8275 -NoBrowserOpen
```

Expected: console shows local URL and waits for requests.

**Step 6: Verify status endpoint**

In another shell:

```powershell
Invoke-RestMethod http://localhost:8275/api/status
```

Expected: JSON object with app name, version, port, and output path.

**Step 7: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add workbench local server"
```

---

### Task 3: Add Case Storage

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1`
- Modify: `MSP-TroubleshootingWorkbench/app/index.html`

**Step 1: Add case helper functions**

Implement:

```powershell
function New-CaseId {
    "CASE-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
}

function Get-CasePath {
    param([string]$CaseId)
    Join-Path (Join-Path $OutputPath 'cases') "$CaseId.json"
}
```

Add `New-WorkbenchCase`, `Get-WorkbenchCases`, `Get-WorkbenchCase`, and
`Save-WorkbenchCase`.

**Step 2: Add API routes**

Implement:

```text
GET  /api/cases
POST /api/cases
GET  /api/cases/{caseId}
POST /api/cases/{caseId}/notes
```

**Step 3: Define case JSON shape**

New cases should include:

```powershell
[PSCustomObject]@{
    CaseId           = $caseId
    ClientName       = $body.clientName
    TicketNumber     = $body.ticketNumber
    IssueType        = $body.issueType
    AffectedUser     = $body.affectedUser
    AffectedDevice   = $body.affectedDevice
    TargetPath       = $body.targetPath
    TargetAddress    = $body.targetAddress
    CreatedAt        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    UpdatedAt        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Checks           = @()
    Notes            = @()
    GeneratedSummary = ''
}
```

**Step 4: Add frontend case creation**

Add a compact form with fields for client, ticket, issue type, user, device, path,
and address. Submit with `fetch('/api/cases', { method: 'POST', ... })`.

**Step 5: Verify persistence**

Run:

```powershell
$body = @{
  clientName = 'Test Client'
  ticketNumber = 'T12345'
  issueType = 'Network'
  affectedUser = ''
  affectedDevice = 'SERVER01'
  targetPath = ''
  targetAddress = 'server01.contoso.local'
} | ConvertTo-Json
Invoke-RestMethod http://localhost:8275/api/cases -Method Post -Body $body -ContentType 'application/json'
```

Expected: a new JSON file appears under `MSP-TroubleshootingWorkbench/cases`.

**Step 6: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add workbench case storage"
```

---

### Task 4: Add Check Manifest And Runner

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/checks/manifest.json`
- Create: `MSP-TroubleshootingWorkbench/checks/Invoke-NetworkQuickCheck.ps1`
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1`
- Modify: `MSP-TroubleshootingWorkbench/app/index.html`

**Step 1: Add network check manifest entry**

```json
{
  "schemaVersion": 1,
  "checks": [
    {
      "checkId": "network.quick",
      "name": "Network Quick Check",
      "category": "Network",
      "script": "Invoke-NetworkQuickCheck.ps1",
      "description": "Ping, DNS, TCP port, and local route snapshot.",
      "readOnly": true,
      "inputs": ["targetAddress", "port"]
    }
  ]
}
```

**Step 2: Create the network check**

The check script should use `[CmdletBinding()]`, accept `-TargetAddress` and
`-Port`, and return the shared check object. Use only read-only commands.

**Step 3: Add check loader**

Implement `Get-CheckCatalog` and validate that manifest script paths stay inside
the `checks` folder.

**Step 4: Add runner API**

Implement:

```text
GET  /api/checks
POST /api/cases/{caseId}/checks/{checkId}/run
```

For v1, run checks synchronously and append the result to the case JSON.

**Step 5: Verify check run**

Create a test case, then run:

```powershell
$body = @{ targetAddress = 'localhost'; port = 445 } | ConvertTo-Json
Invoke-RestMethod http://localhost:8275/api/cases/CASE-ID/checks/network.quick/run -Method Post -Body $body -ContentType 'application/json'
```

Expected: case JSON contains one check result with `CheckId = network.quick`.

**Step 6: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add network quick check"
```

---

### Task 5: Add Notes Generation And Export

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/Start-MSPTroubleshootingWorkbench.ps1`
- Modify: `MSP-TroubleshootingWorkbench/app/index.html`

**Step 1: Add notes generator**

Implement `New-TicketNotesMarkdown` with sections:

```text
Issue:
Actions Taken:
Findings:
Evidence:
Likely Cause:
Next Steps:
Customer-Facing Summary:
```

Use case fields, manual notes, check summaries, evidence, and recommended next
steps.

**Step 2: Add export API**

Implement:

```text
POST /api/cases/{caseId}/generate-notes
POST /api/cases/{caseId}/export
```

Export files:

```text
exports/{caseId}/ticket-notes.md
exports/{caseId}/report.html
exports/{caseId}/evidence.json
```

**Step 3: Add frontend buttons**

Add "Generate Notes" and "Export Evidence" buttons in the case workspace.

**Step 4: Verify export**

Run:

```powershell
Invoke-RestMethod http://localhost:8275/api/cases/CASE-ID/generate-notes -Method Post
Invoke-RestMethod http://localhost:8275/api/cases/CASE-ID/export -Method Post
```

Expected: Markdown, HTML, and JSON files are created under `exports/CASE-ID`.

**Step 5: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add ticket notes export"
```

---

### Task 6: Wrap AD Lockout Diagnostics

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/checks/manifest.json`
- Create: `MSP-TroubleshootingWorkbench/checks/Invoke-ADLockoutCheck.ps1`
- Modify: `MSP-TroubleshootingWorkbench/README.md`

**Step 1: Add manifest entry**

Add `ad.lockout` with inputs `affectedUser`, `daysBack`, and optional
`domainController`.

**Step 2: Create wrapper script**

The wrapper should call:

```powershell
..\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1
```

Pass `-Identity`, `-DaysBack`, and a check-specific output folder. Capture the
HTML report path and return a normalized result.

**Step 3: Add preflight**

If the AD script is missing or the ActiveDirectory module cannot load, return
`Status = 'Warn'` with a clear summary instead of crashing.

**Step 4: Verify wrapper**

Run against a known test account in a domain environment.

Expected: wrapper returns a structured result and evidence path.

**Step 5: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: wrap AD lockout diagnostics"
```

---

### Task 7: Add Citrix/FSLogix Triage Check

**Files:**
- Modify: `MSP-TroubleshootingWorkbench/checks/manifest.json`
- Create: `MSP-TroubleshootingWorkbench/checks/Invoke-CitrixFSLogixTriageCheck.ps1`
- Modify: `MSP-TroubleshootingWorkbench/README.md`

**Step 1: Add manifest entry**

Add `citrix.fslogix.triage` with inputs `affectedDevice` and optional
`affectedUser`.

**Step 2: Implement read-only checks**

Collect:

- Server reachability
- FSLogix service status
- FSLogix profile registry configuration
- Recent FSLogix events
- Recent Terminal Services events
- Local disk free space
- Profile path reachability if configured

**Step 3: Return normalized result**

Summarize the highest-risk finding as `Summary`. Put all detailed rows in
`Evidence`.

**Step 4: Verify on a Citrix/RDS host**

Run the check against a known host. Confirm no changes are made.

**Step 5: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add Citrix FSLogix triage check"
```

---

### Task 8: Add Launcher EXE Prototype

**Files:**
- Create: `MSP-TroubleshootingWorkbench/launcher/MSPWorkbenchLauncher.cs`
- Create: `MSP-TroubleshootingWorkbench/launcher/build.ps1`
- Modify: `MSP-TroubleshootingWorkbench/README.md`

**Step 1: Add C# launcher**

Create a small launcher that starts:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Start-MSPTroubleshootingWorkbench.ps1
```

Use the executable directory as the working directory.

**Step 2: Add build script**

Use `Add-Type` or `csc.exe` if available. If no compiler is available, document
that the PowerShell entry point remains the supported fallback.

**Step 3: Verify launcher**

Run `MSPWorkbench.exe` from the portable folder.

Expected: GUI opens the same way as the PowerShell script.

**Step 4: Commit**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "feat: add workbench launcher prototype"
```

---

### Task 9: Final Verification Pass

**Files:**
- Modify if needed: `MSP-TroubleshootingWorkbench/*`

**Step 1: Parser check**

Run:

```powershell
$files = Get-ChildItem .\MSP-TroubleshootingWorkbench -Recurse -Filter *.ps1
foreach ($file in $files) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  if ($errors) { $errors | Select-Object Message, Extent }
}
```

Expected: no parser errors.

**Step 2: Manual smoke test**

Run:

```powershell
.\MSP-TroubleshootingWorkbench\Start-MSPTroubleshootingWorkbench.ps1
```

Verify:

- Browser opens
- Case can be created
- Case can be reopened
- Network check runs
- Manual note can be added
- Notes can be generated
- Export files are created

**Step 3: Review portability**

Copy `MSP-TroubleshootingWorkbench` to a temporary folder and run from there.

Expected: cases, logs, and exports are created relative to the copied folder.

**Step 4: Commit final fixes**

```powershell
git add MSP-TroubleshootingWorkbench
git commit -m "fix: polish workbench portability"
```
