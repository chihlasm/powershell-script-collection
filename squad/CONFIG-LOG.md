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

---

## 2026-10-18 — Configure (review)

**Michael said:** `/squad:configure review`, then approved all six findings.

**Changes (all [inferred], each approved individually)**
- New risk profile `read-only-advisory` (`squad/risks/read-only-advisory.md`, new
  `riskProfiles` entry; paths AD-UserQuickCheck, M365-UserQuickCheck, FolderAccess-Check,
  Network-QuickCheck, Citrix-FSLogix-Triage, TicketNote; keywords Escalate, NextStep,
  Clipboard). Covers advice that leads to changes (D-017), privileged-group recommendations
  and fail-closed privilege checks, the read-only-by-construction AST allowlist (kit files,
  remote script blocks, dynamic invocation, .NET writers), shared kit parity, reading
  production hosts. Source: checklist gaps from SQ-011, SQ-013 and the 2026-10-17 run.
- `personal-data.md`: new sections "Ticket notes and the clipboard" and "Exports, logs and
  returned objects" (CSV formula guard, context-aware encoding, local-storage fallback,
  retention in README, -PassThru minimisation, SID-based matching, secrets in config values,
  credential tests, file-name sanitising, ContextScope). Paths added: TicketNote,
  M365-UserQuickCheck, FolderAccess-Check, AD-UserQuickCheck, Network-QuickCheck,
  Citrix-FSLogix-Triage. Source: gaps from all three runs.
- `destructive-operations.md`: new sections "Right target, right object", "Results that match
  reality", "Tests for destructive tools". Path added: TestLab-Setup (writes to a lab AD).
  Source: gaps from SQ-009, SQ-014 and the 2026-10-17 run.
- `PRINCIPLES.md`: P-004 (tier 1 never gets a destructive or privileged step) and P-005
  (ticket-bound output is paste-safe by default), consolidating D-009, D-013, D-017, D-024,
  D-025, D-033.
- `SQUAD.md` Testing: tests never touch real clipboard/%USERPROFILE%/RSAT modules; backstop
  mocks for write layers; agents do not read this machine while building (SQ-009 incident).

**Verified:** `self-test.ps1 -Part all` passed; config JSON parses.

**Deliberately left unchanged**
- The rule for which reparse points count as links in recursive changes: waits on Q-005.
- system-configuration.md: its gaps (read-only guard scope, FileShare.ReadWrite, sessions
  closed in finally) went into read-only-advisory.md instead.
- Lenses, signals and the graveyard: only one ideation session so far, too early to judge.
- Process suggestions in the 2026-10-18 report (background agents, implementer assumptions
  file, stacked branches): plugin behaviour, not project config.
- Build and test commands, guard (still no packs, per setup), uiPaths, owner.notes.
