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
  path fails closed. (Which reparse points count as links inside a tree waits on Q-005.)
- Recursive actions also guard high-impact roots: C:\Users, System Volume Information and
  $Recycle.Bin on data volumes.
- A leftover dangerous switch in a sibling code path (for example `/D Y`) is grepped for and
  pinned by a test across every call.

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

## Tests for destructive tools (added 2026-10-18)
- A backstop mock of the transport, ADSI and write layer catches any call a specific mock
  missed, so one missing mock cannot touch the dev machine.
- Write wrappers are never tested against `$env:COMPUTERNAME` or a real path outside
  `$TestDrive`.
- Native tools are mocked through the wrapper that runs them, not the bare exe name.
- Behaviour that differs under Windows PowerShell 5.1 (for example `Export-Csv -Append` into
  a 0-byte file) has a test that also runs under `powershell.exe`.
