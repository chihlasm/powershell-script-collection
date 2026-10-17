# Squad configuration history

Every change made through /squad:setup and /squad:configure, newest last, so any change can
be understood or undone later. Each entry says what changed, why, and what was inferred.

---

## 2026-10-16 — Setup

Set up by /squad:setup (Squad plugin 2.0.0) with Michael.

**Michael said**
- Owner: Michael, developer. Product: tools for Michael and his MSP team to make
  troubleshooting more efficient and data collection faster and accurate. Users: helpdesk
  techs mid-ticket and senior sysadmins.
- Guard: no command guard (no packs, no custom rules). The squad may work on anything.
- Risk profiles: destructive-operations, system-configuration, personal-data (client data and
  secrets). The AD-specific profile was not chosen.
- Boundaries: no cloud/SaaS backend; self-contained folders with wiggle room for shared
  pieces where it makes sense.
- Rhythm: 8 items per run; plugin not added to the shared `.claude/settings.json`.

**Inferred (approved in the preview)**
- Build: new `Tests/Test-ScriptParse.ps1` under Windows PowerShell 5.1 (the repo has no
  compile step). Tests: new `Tests/Invoke-AllTests.ps1` under pwsh/Pester 5, excluding the
  `Integration` tag and `dist/`, `work-in-progress/`, `.worktrees/`.
- App-launch patterns that block starting the GUI scripts and `.cmd` launchers during runs
  only (they would hang an unattended run). They match invocation, not reading or grepping.
  `guard.mode` is `during-runs` since there are no packs.
- M365-SyncedUserFixes and AD write cmdlets folded into the destructive-operations profile.
- UI paths, `docs/plans` as plan docs, six lenses (including newcomer), principles P-001–P-003.
- Baseline fix: DiskSpdDiagnostic tests loaded a `#Requires -RunAsAdministrator` script and
  failed (66 tests) in a non-elevated shell; changed to load its functions from the AST.
- Verification: baseline green (build 168 scripts parse; tests 1949 passed, 0 failed), plugin
  self-test, guard wiring and gate wiring all pass. The gate check first failed on squad 2.0.0
  (the implementer's hand-back reached the caller before the SubagentStop block;
  chihlasm/claude-plugins#1) and passed on 2.0.1 via the PreToolUse hand-back gate.
