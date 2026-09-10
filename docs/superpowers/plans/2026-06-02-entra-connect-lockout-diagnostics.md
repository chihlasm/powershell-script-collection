# Entra Connect Lockout Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `Diagnose-ADAccountLockout.ps1` so a synced-user lockout investigation can collect and report Entra Connect / hybrid authentication evidence.

**Architecture:** Keep the script self-contained. Add optional Entra Connect parameters and pure helper functions for interpreting PHS/PTA evidence, then add one domain-bound collector that runs only when `-EntraConnectServer` is supplied. Render the collected rows in a new HTML section and feed them into the verdict helper.

**Tech Stack:** PowerShell 5.1+, Pester 5, `Get-WinEvent`, `Get-Service`, optional `Invoke-Command` against an Entra Connect server.

---

### Task 1: Pin PHS/PTA Diagnostic Interpretation

**Files:**
- Modify: `AD-LockoutDiagnostics/Tests/Diagnose-ADAccountLockout.Tests.ps1`

- [x] **Step 1: Write failing tests for PHS/PTA interpretation**

Add tests for `Get-EntraConnectEventClassification` and `Get-EntraConnectVerdictHints`, covering PHS heartbeat ID `654`, PHS error IDs `611`, `652`, `655`, PTA agent Admin events, and unavailable services.

- [x] **Step 2: Verify tests fail**

Run: `Invoke-Pester -Path .\AD-LockoutDiagnostics\Tests\Diagnose-ADAccountLockout.Tests.ps1 -Output Detailed`

Expected: new tests fail because the helper functions do not exist.

### Task 2: Add Pure Helpers and Verdict Inputs

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

- [x] **Step 1: Implement helper functions**

Add `Get-EntraConnectEventClassification`, `ConvertFrom-EntraConnectEvent`, and `Get-EntraConnectVerdictHints`.

- [x] **Step 2: Extend `Get-LockoutVerdict`**

Add optional `$EntraConnectDiagnostics` and append hybrid-auth findings when present.

- [x] **Step 3: Verify tests pass**

Run: `Invoke-Pester -Path .\AD-LockoutDiagnostics\Tests\Diagnose-ADAccountLockout.Tests.ps1 -Output Detailed`

Expected: all Pester tests pass.

### Task 3: Add Live Collection and Report Rendering

**Files:**
- Modify: `AD-LockoutDiagnostics/Diagnose-ADAccountLockout.ps1`

- [x] **Step 1: Add parameters**

Add `-EntraConnectServer` and `-HybridAuthMode Auto|PHS|PTA|Unknown`.

- [x] **Step 2: Add collector**

Add `Get-EntraConnectDiagnostics` that checks `ADSync`, PTA agent services, Application PHS events, and PTA Admin events.

- [x] **Step 3: Add report section**

Render Entra Connect status/events in the HTML report, with an empty-state message when no server is supplied.

- [x] **Step 4: Verify syntax and tests**

Run:

```powershell
[scriptblock]::Create((Get-Content -Raw '.\AD-LockoutDiagnostics\Diagnose-ADAccountLockout.ps1')) | Out-Null
Invoke-Pester -Path .\AD-LockoutDiagnostics\Tests\Diagnose-ADAccountLockout.Tests.ps1 -Output Detailed
```

Expected: parse succeeds and Pester passes.

---

## Status: complete (2026-08-26)

All three tasks implemented. Verified against Microsoft Learn after the fact, which found
three defects in the original implementation:

1. **653/654 mislabelled.** They are "Start/End of password hash sync ping"; 654 was
   described as "heartbeat was observed" - its role in the troubleshooting task, not its
   documented text. 650/651 are batch, not "cycle", boundaries.
2. **The event table stopped at 655.** The documented table runs to 668. Events 613-623
   and 656-668 fell through to "Unclassified", including 616 (connection to preferred DC
   failed), which bears directly on a lockout investigation.
3. **Event 0 was missing.** The manual troubleshooting steps name `0, 611, 652, 655` as
   the connectivity events; event 0 was unclassified.

A fourth defect was in the heartbeat check itself: it searched the whole `-DaysBack`
window and only reported a problem when the entire window was empty, so on the default
7-day search PHS could have died yesterday and still report healthy. Freshness is now
judged against the documented three-hour window via `Test-PhsHeartbeatFreshness`.

Separately, `Invoke-ADLockoutInvestigation.ps1` never forwarded anything to the
collector, so a full toolkit run silently skipped every hybrid check. It now exposes
`-EntraConnectServer` and `-HybridAuthMode` and says so on the console when hybrid
evidence is *not* collected.

Regression tests: `Tests/EntraConnect-Verified.Tests.ps1` (19) and
`Tests/EntraConnect-Orchestration.Tests.ps1` (8).
