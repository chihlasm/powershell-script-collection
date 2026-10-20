# Risk profile: bulk and destructive operations

Applies to deletes, overwrites, bulk updates, file migrations, permission changes, and
directory writes: anything that is hard to undo. In this repo that means DeleteOldFolders,
Storage Space Clean-up, the FSLogix repair and cleanup tools, RobocopyMigration,
CopyFileToServer, FolderPermissionManager, LocalAdminManager, and M365-SyncedUserFixes
(the only tool that writes to Active Directory). These run with admin rights against
client servers and client AD; a bug repeats across every target.

- The user sees the scope before confirming: which servers, how many folders/files/users,
  total size ("this will delete 312 folders, 48 GB, on FS01"). GUIs show it in the
  confirmation dialog; console scripts print it with `[WARN]` before acting.
- Every destructive script or function supports `-WhatIf` (`SupportsShouldProcess`) and calls
  `$PSCmdlet.ShouldProcess` per target, so a dry run shows exactly what would happen.
  Confirmation prompts can be bypassed only with an explicit `-Force` (CLAUDE.md convention).
- Destructive actions are visually distinct in GUIs (destructive button styling, verb in the
  label: "Delete 312 folders", not "OK") and never the default button.
- Work is reversible where possible: ACLs are exported (`Get-Acl` / SDDL) before `Set-Acl`;
  AD attributes are recorded with their previous value before `Set-ADUser -Replace/-Clear`
  (see M365-SyncedUserFixes' change log); robocopy `/MIR` and `/PURGE` are never introduced
  without a preview and an explicit opt-in.
- Each change is written to a log file with timestamp (`yyyy-MM-dd HH:mm:ss`), target, old
  value and new value, enough to audit and undo it.
- Bulk work over many servers or objects is per-target try/catch with `continue`: one
  unreachable server or locked file is recorded and skipped, not fatal. Long migrations stay
  resumable (RobocopyMigration/CopyFileToServer `State/` folders).
- AD writes stay on one domain controller for the whole operation (`-Server` on every
  cmdlet), and verify the cmdlet parameter names against the real RSAT module or Microsoft
  Learn: mocks can share a wrong parameter name with the code.
- Tests cover partial failure, the "zero items" and "all items" edges, and that `-WhatIf`
  performs no change. Every write cmdlet (`Remove-Item`, `Set-Acl`, `Set-ADUser`,
  `Add-/Remove-ADGroupMember`, robocopy) is mocked in Pester; any test that could touch a
  real file share, real AD or the real file system outside `$TestDrive` is a blocker.

## Right target, right object (added 2026-10-18)
- Target names are normalised (FQDN vs short name, IP, empty or null) and never silently
  fall back to the machine the tool runs on. A dotted name is local only if it is this
  machine's own FQDN. A guard built from local env vars (`ProgramFiles` vs `ProgramW6432`
  under WOW64) does not describe a remote server.
- "Already absent / no change" on a remove or revoke is proven by SID, not a string compare.
  A principal that cannot be resolved fails. The change acts on the same identifier it
  matched (the SID), not a name that could resolve differently.
- Paths are canonicalised before any protected-path or scope check: UNC admin shares
  (`ADMIN$`, `X$`), `\?\` and `\.\`, 8.3 names, trailing dots and spaces, subst and mapped
  drives, links or mounted volumes at the top of the target, and server-side junctions on SMB.
  SYSVOL, NETLOGON and print$ count as system folders, and a guard that cannot resolve the
  path fails closed. Reparse points inside a tree are links unless their tag is on the D-040
  allowlist (extended by D-042). A tag added there needs its MS-FSCC value and the cited
  reason it cannot redirect (name-surrogate bit clear), with one test each.
- Recursive actions also guard high-impact roots: C:\Users, System Volume Information and
  $Recycle.Bin on data volumes.
- A leftover dangerous switch in a sibling code path (for example `/D Y`) is grepped for and
  pinned by a test across every call.
- DFS paths are looked up (`NetDfsGetClientInfo`) for the root and for links inside it, every
  target is checked, and a lookup error fails closed. Attributes and `GetFinalPathNameByHandle`
  read through a DFS-redirected path do not reveal the redirect (D-043).
- Typed `.` and `..` segments are refused, or resolved the way Windows does (UNC `..` stops at
  `\\server\share`) before any server-side mapping. A guard never normalises more
  aggressively than the operation it protects.
- Mapped drives are turned into UNC in the shared core, not only in a GUI. When several
  sources map a letter (live CIM, a map passed from another process, remembered
  `HKCU:\Network`), the live mapping wins. Redirected client drives (`\\tsclient\C`) and
  non-admin shares that point at a protected root are recognised.
- "Is this target on this computer?" is decided from the resolved location, not path text.
  A drive letter missing from the drive map, or a local symbolic link or mounted folder at or
  above the target that leads to UNC, is not local. When it cannot be decided, refuse. This
  applies to every use of the answer, including rewriting `.\name` to `PC01\name`.
- The change acts on the exact path form that was checked, or the check runs again just
  before the call. That re-check re-resolves the path (final path, long path, mapped drive,
  server path) and applies every protected-folder rule, for every write path (Copy as well
  as take ownership). Repeating a text-only check is not a re-check.
- Account names are resolved where the ACL lives. `LookupAccountName` searches local accounts
  before the domain, so on a remote target a name that resolves to this workstation's machine
  SID prefix is refused or flagged, and the resolved `DOMAIN\name` is shown before the change.
- A background lookup that timed out discards its late result; it is never used for the change.

## Results that match reality (added 2026-10-18)
- Done/PASS only after reading the result back and finding the intended state. Exit codes
  and English output text of native tools (icacls, takeown, robocopy) are not proof; consider
  localized Windows. Nothing verified means no success.
- When a write throws after it committed (remote timeouts), the logged Result matches the
  re-read state.
- The fail-closed log check opens the exact file that will be written (Excel and share
  locks). When the log write fails after the change, the row and the before-state go to a
  fallback copy, the console says where, and the exit code is non-zero.
- Log writes pass `-Confirm:$false -WhatIf:$false`. `-WhatIf` never writes or claims a log.
- Prompts in non-interactive hosts (`-NonInteractive`, scheduled tasks, RMM) fail cleanly.
  When the scope preview fails, the tool does not go ahead silently under `-Force`.
- The old value logged and backed up is the same read the safety decision used.
- A known-incomplete backup is never a green/PASS result, and every "restore from the
  backup" message names the items it cannot restore.
- Long bulk actions log a "started" record before the irreversible step.
- Items whose owner or ACL could be read neither before nor after the change are Unchecked,
  and Unchecked items never count toward a Done result.
- Summary claims ("none block inheritance", "nothing found") count the items that could not
  be read instead of treating them as clean.

## Tests for destructive tools (added 2026-10-18)
- A backstop mock of the transport, ADSI and write layer catches any call a specific mock
  missed, so one missing mock cannot touch the dev machine.
- Write wrappers are never tested against `$env:COMPUTERNAME` or a real path outside
  `$TestDrive`.
- Native tools are mocked through the wrapper that runs them, not the bare exe name.
- Behaviour that differs under Windows PowerShell 5.1 (for example `Export-Csv -Append` into
  a 0-byte file) has a test that also runs under `powershell.exe`.
- A safety check that relies on how a Win32 API behaves over SMB or DFS cites a source or has
  an Integration-tagged test; a mock that returns the right answer proves only the logic.
- A test that calls a real P/Invoke wrapper proves its input cannot reach the network (guard
  against a UNC `$TestDrive`). New `Add-Type` signatures have a compile check under 5.1.
- A guard helper that is mocked in every suite (for example `Get-DriveLetterType`) gets one
  harmless local test of its real body.
- Pester mocks do not reach runspace pools or other processes. Destructive work run in the
  background is tested directly or through an injected write layer.
- Test isolation covers paths set when a script is loaded (`%LOCALAPPDATA%` error logs,
  settings), not only paths passed in.
- `Remove-Item` on the `Alias:`, `Function:` or `Variable:` drives in test cleanup is not a
  file-system delete and passes.

## Safety rules live in the core (added 2026-10-20)
- A safety rule enforced in one front end (the WPF app) is also enforced in the shared core
  work function, so the CLI and the browser GUI cannot bypass it.
- A guard's "does not apply" branch (a regex that does not match, an empty normalised path,
  an early `return $null`) fails closed or is proven unreachable, with tests for odd
  spellings (trailing or doubled backslash).
- Shared state a guard depends on (protected-root lists, core variables) reaches background
  runspaces, and a missing list makes the guard fail closed.
- Inheritable Add and Copy on a drive, share or high-impact root get the same protected-folder
  and high-impact checks as recursive actions: an inheritable entry on a root reaches the tree.

## Overrides and refusals (added 2026-10-20)
- An override switch is never the suggested next step for "destination could not be
  determined", and one switch does not turn off unrelated guards.
- Refusal text names what was actually found (the reparse tag or kind, the DFS servers), not
  a generic "junction or symbolic link".
- The next step fits the cause (protected folder vs unknown destination vs no link at all),
  told apart by a shared marker constant, not free text. It never sends the tech to a route
  that skips the check that refused (for example an admin-share path).
- Fail-closed allowlists list the common real-world values that will hit the refusal (app
  aliases, Azure File Sync, ProjFS, WCI, AF_UNIX) and decide each one, so false refusals do
  not teach techs to use the override.

## Advice and commands in tools that change things (added 2026-10-20)
- Advice in output, help or README that tells the tech to change something elsewhere ("add it
  on the top folder", "run icacls ...") is reviewed like a write: it states its scope, names
  the exceptions, and gives a safe command for hosts without a GUI.
- Copy-paste commands (icacls `/save`, `/remove`, `/restore`) use a placeholder rather than a
  broad real path, no `/T` by default, and per-item absolute backup names that are not
  overwritten when run again. The restore line is shown to work for a folder, a drive root and
  a share root, and paths are escaped for the shell they are pasted into (cmd `%`).
- When a step is removed, help, README, elevation and prompt texts no longer describe it, and
  the code paths that remain keep their regression tests.
- Warning and confirm text that describes Windows permission semantics (Deny vs explicit
  Allow, how far inheritance reaches) is a documented fact: cited from Learn and tested.

## Elevation, prompts and shutdown (added 2026-10-20)
- Relative paths become absolute before a self-elevating relaunch (the working directory
  becomes System32). Mapped drives and `subst` do not survive UAC elevation, so every path
  handed to the elevated copy is converted or refused.
- Data from the user session passed to an elevated process (a drive map) has its format
  whitelisted, is never truncated while parsing native tool text (`net use`), and every guard
  runs on the resolved path.
- A target resolved from a possibly stale source (remembered mappings, cached ACLs, a map from
  another process) says so where the user confirms and where the undo log is placed.
- Single-instance mutexes in `Global\` use the same canonical key as the protected-path check,
  so two spellings of one log folder cannot both get in.
- A "dry run / nothing changes" mode lists any writes that still happen at startup
  (log-folder probe, settings files).
- Close handlers, `Environment.Exit`, pool stops and crash paths never interrupt or unlock a
  committed-but-unlogged change; the close guard runs before any stop.
- Non-interactive host detection: `Environment.UserInteractive` is unusable (it is false in
  Enter-PSSession and PsExec, where Read-Host works), so remote consoles can still confirm.
  The prompt itself is also wrapped in try/catch with a test where Read-Host throws. A hidden
  console that blocks or an empty redirected answer is not a clean failure, and a declined
  answer under automation does not exit 0. Docs claim scheduled tasks fail cleanly only when
  that was verified on a real task host.

## Read-only tools that match these keywords (added 2026-10-20)
- A tool labelled read-only adds no write-capable call: native tools (`qwinsta.exe`) run with
  query verbs only, and registry keys are opened non-writable.
